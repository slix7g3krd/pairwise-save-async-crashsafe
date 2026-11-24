"""存档异步写入与崩溃恢复。

题目要求的六个修复点与实现映射：

1. **写盘串行化并按版本号提交** —— 每个槽位一把锁，版本号在 ``save()`` 发起时
   原子分配；落盘在槽位锁内串行完成，且只有版本号大于已提交版本的写入才会
   替换槽位文件。先发起但后完成的旧写入会被判定为 ``stale`` 丢弃，不会覆盖新档。
2. **落盘前校验完整性与校验和** —— 每帧带 ``magic + 头部长度 + 头部 + body``，
   头部记录 body 长度与 sha256。写入前 :func:`validation` 校验，读取/恢复时
   :func:`integrity_check` 先验长度再验校验和；长度不符、校验和不符、magic
   不符的半文件一律视为损坏。
3. **异常路径回收临时文件** —— 所有落盘都先写 ``.tmp-<uuid>``，``finally`` 中
   删除；:func:`temp_cleanup` 还能回收进程崩溃遗留的临时文件，且不会误删
   其他线程正在使用的临时文件。
4. **反序列化回主线程应用** —— 后台线程只做字节校验与 JSON 解码（纯数据），
   :func:`deserialize_main` 负责在游戏线程（主线程）应用状态；从非主线程读档时
   状态修改会入队而不是就地执行。
5. **索引原子替换** —— 索引写同目录临时文件，``flush + fsync`` 后 ``os.replace``，
   并带自校验；索引更新与槽位提交在同一把槽位锁内完成，避免目录索引指向旧版本。
6. **保留上一版回滚点** —— 提交新版本前把当前有效版本复制到 ``<slot>.prev``；
   当前版本损坏时 :func:`load` / :func:`recover` / :func:`fallback` 可回退。

仅依赖标准库，模块自包含。
"""

from __future__ import annotations

import atexit
import copy
import hashlib
import json
import os
import queue
import shutil
import tempfile
import threading
import time
import uuid

__all__ = [
    "serialize_write",
    "integrity_check",
    "temp_cleanup",
    "deserialize_main",
    "index_atomic",
    "determinism",
    "backup_slot",
    "validation",
    "audit",
    "fallback",
    "version_tag",
    "metrics",
    "save",
    "load",
    "recover",
]

FORMAT_VERSION = 1
_MAGIC = b"SAVEASYNC"
_HEADER_LEN = len(_MAGIC) + 8  # magic + 头部长度（8 字节大端）
_INDEX_NAME = "index.json"
_SLOT_PREFIX = "slot_"
_SLOT_SUFFIX = ".sav"
_PREV_SUFFIX = ".prev"
_TMP_PREFIX = ".tmp-"

# ---------------------------------------------------------------------------
# 全局状态
# ---------------------------------------------------------------------------

_lock = threading.RLock()
_slot_locks: dict[str, threading.RLock] = {}
_committed: dict[str, dict] = {}        # root::slot -> 已提交版本元信息
_counters: dict[str, int] = {}          # root::slot -> 已分配的版本号
_counter_seq = 0
_rollback_keep = True                   # 是否保留上一版回滚点

_metrics: dict[str, int] = {
    "saves": 0,
    "queued": 0,
    "loads": 0,
    "recovers": 0,
    "discarded_saves": 0,
    "rolled_back": 0,
    "temp_cleanups": 0,
    "integrity_failures": 0,
    "index_updates": 0,
    "audit_entries": 0,
}

_audit_log: list[dict] = []
_main_queue: "queue.Queue[tuple]" = queue.Queue()
_active_temps: set[str] = set()
_failure_hook = None
_failure_hook_lock = threading.Lock()

_scratch_root: str | None = None


def _scratch() -> str:
    """给无法解释为路径的参数准备一个专用的临时目录（避免污染 cwd）。"""
    global _scratch_root
    if _scratch_root is None:
        _scratch_root = tempfile.mkdtemp(prefix="saveasync-scratch-")
        atexit.register(_cleanup_scratch)
    return _scratch_root


def _cleanup_scratch() -> None:
    global _scratch_root
    if _scratch_root is not None:
        shutil.rmtree(_scratch_root, ignore_errors=True)
        _scratch_root = None


def _root_or_scratch(value) -> str:
    """把第一个位置参数解释为存档根目录；无法解释时退回专用临时目录。"""
    if value is None:
        return "."
    if isinstance(value, (str, os.PathLike)):
        return os.fspath(value)
    if isinstance(value, bytes):
        return os.fsdecode(value)
    return _scratch()


def _entry_version(entry) -> int:
    """容错读取索引中的版本号（索引可能被外部工具改写）。"""
    try:
        return int(entry.get("version", -1))
    except (AttributeError, TypeError, ValueError):
        return -1


def _slot_key(slot) -> str:
    return str(slot)


def _state_key(root, slot) -> str:
    """版本计数器/提交记录的键：同一个槽位名在不同存档根目录下互不影响。"""
    return f"{os.path.abspath(os.fspath(root))}::{_slot_key(slot)}"


def _slot_lock(root, slot) -> threading.RLock:
    key = _state_key(root, slot)
    with _lock:
        lock = _slot_locks.get(key)
        if lock is None:
            lock = threading.RLock()
            _slot_locks[key] = lock
        return lock


def _bump_metric(name: str, delta: int = 1) -> None:
    with _lock:
        _metrics[name] = _metrics.get(name, 0) + delta


# ---------------------------------------------------------------------------
# 序列化 / 校验
# ---------------------------------------------------------------------------

def _canonical(obj) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        default=_json_default,
    ).encode("utf-8")


def _json_default(value):
    if isinstance(value, (set, frozenset)):
        return sorted(value)
    if isinstance(value, bytes):
        return value.hex()
    raise TypeError(f"not JSON serializable: {type(value).__name__}")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _pack(payload, version: int) -> bytes:
    """payload -> magic + 头部长度 + 头部(JSON) + body。"""
    body = _canonical(payload)
    header = {
        "format": FORMAT_VERSION,
        "version": int(version),
        "length": len(body),
        "sha256": _sha256(body),
    }
    head = json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return _MAGIC + len(head).to_bytes(8, "big") + head + body


def _unpack(raw) -> dict:
    """严格解析：magic / 长度 / 校验和 / 格式任一不符都抛 ValueError。"""
    if not isinstance(raw, (bytes, bytearray, memoryview)):
        raise TypeError("frame must be bytes")
    raw = bytes(raw)
    if len(raw) < _HEADER_LEN:
        raise ValueError("truncated save frame")
    if raw[: len(_MAGIC)] != _MAGIC:
        raise ValueError("bad magic")
    head_len = int.from_bytes(raw[len(_MAGIC): _HEADER_LEN], "big")
    head_end = _HEADER_LEN + head_len
    if head_len <= 0 or head_end > len(raw):
        raise ValueError("truncated save header")
    try:
        header = json.loads(raw[_HEADER_LEN:head_end].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("corrupt save header") from exc
    body = raw[head_end:]
    if int(header.get("length", -1)) != len(body):
        raise ValueError("length mismatch")
    if header.get("sha256") != _sha256(body):
        raise ValueError("checksum mismatch")
    if int(header.get("format", -1)) != FORMAT_VERSION:
        raise ValueError("unsupported format")
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("corrupt save body") from exc
    return {
        "format": FORMAT_VERSION,
        "version": int(header["version"]),
        "length": len(body),
        "sha256": header["sha256"],
        "payload": payload,
        "size": len(raw),
    }


def serialize_write(version=1, payload=None):
    """把一次存档写请求序列化到内存（不触碰磁盘）。

    支持 ``serialize_write(payload)`` 与 ``serialize_write(version, payload)``
    两种调用方式；同一输入永远得到相同字节（见 :func:`determinism`）。
    """
    if payload is None and version is not None and not isinstance(version, (int, bool)):
        version, payload = 1, version
    if version is None:
        version = 1
    if payload is None:
        payload = {"slot": "default", "data": {}}
    version = int(version)
    raw = _pack(payload, version)
    meta = _unpack(raw)
    meta["bytes"] = raw
    meta["queued"] = False
    return meta


def integrity_check(raw, expected_sha256=None) -> dict:
    """校验归档帧的完整性与校验和；返回结果而不抛异常。"""
    try:
        meta = _unpack(raw)
    except Exception as exc:  # noqa: BLE001 - 校验失败应当是可处理的结果
        _bump_metric("integrity_failures")
        try:
            size = len(raw)
        except TypeError:
            size = 0
        return {"ok": False, "reason": str(exc), "size": size}
    if expected_sha256 is not None and meta["sha256"] != expected_sha256:
        _bump_metric("integrity_failures")
        return {"ok": False, "reason": "expected checksum mismatch",
                "sha256": meta["sha256"], "size": meta["size"]}
    return {"ok": True, "reason": None, "version": meta["version"],
            "sha256": meta["sha256"], "length": meta["length"],
            "size": meta["size"]}


def _read_frames(path):
    """按顺序读出文件中所有完整帧（容忍末尾被截断的半帧）。"""
    with open(path, "rb") as fh:
        data = fh.read()
    frames = []
    offset = 0
    while offset < len(data):
        if len(data) - offset < _HEADER_LEN:
            break
        if data[offset: offset + len(_MAGIC)] != _MAGIC:
            break
        head_len = int.from_bytes(data[offset + len(_MAGIC): offset + _HEADER_LEN], "big")
        end = offset + _HEADER_LEN + head_len
        if head_len <= 0 or end > len(data):
            break
        try:
            header = json.loads(data[offset + _HEADER_LEN:end].decode("utf-8"))
            body_len = int(header["length"])
        except Exception:  # noqa: BLE001
            break
        frame_end = end + body_len
        if body_len < 0 or frame_end > len(data):
            break
        frames.append(data[offset:frame_end])
        offset = frame_end
    return frames, len(data) - offset


def _read_valid(path: str) -> dict | None:
    """返回文件中最后一个通过完整性校验的帧（含原始字节）。"""
    if not os.path.exists(path):
        return None
    try:
        frames, _trailing = _read_frames(path)
    except OSError:
        return None
    for raw in reversed(frames):
        if integrity_check(raw)["ok"]:
            meta = _unpack(raw)
            meta["bytes"] = raw
            return meta
    return None


def _fsync_dir(path: str) -> None:
    try:
        fd = os.open(path or ".", os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


# ---------------------------------------------------------------------------
# 磁盘路径与临时文件
# ---------------------------------------------------------------------------

def _ensure_root(root) -> str:
    root = os.path.abspath(os.fspath(root))
    os.makedirs(root, exist_ok=True)
    return root


def _slot_path(root, slot) -> str:
    return os.path.join(root, f"{_SLOT_PREFIX}{_slot_key(slot)}{_SLOT_SUFFIX}")


def _prev_path(root, slot) -> str:
    return os.path.join(root, f"{_SLOT_PREFIX}{_slot_key(slot)}{_PREV_SUFFIX}")


def _index_path(root) -> str:
    return os.path.join(root, _INDEX_NAME)


def _new_temp(root: str) -> str:
    path = os.path.join(root, f"{_TMP_PREFIX}{uuid.uuid4().hex}")
    with _lock:
        _active_temps.add(path)
    return path


def _release_temp(path: str) -> None:
    with _lock:
        _active_temps.discard(path)
    try:
        if os.path.exists(path):
            os.unlink(path)
    except OSError:
        pass


def _atomic_write(path: str, data: bytes, root: str) -> None:
    """临时文件 + flush + fsync + os.replace；异常路径删除临时文件。"""
    tmp = _new_temp(root)
    try:
        with open(tmp, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    finally:
        _release_temp(tmp)
    _fsync_dir(os.path.dirname(os.path.abspath(path)) or ".")


def _copy_atomic(src: str, dst: str, root: str) -> None:
    with open(src, "rb") as fh:
        data = fh.read()
    _atomic_write(dst, data, root)


def _is_our_temp(name: str) -> bool:
    if name.startswith(_TMP_PREFIX):
        return True
    return name.startswith(_SLOT_PREFIX) and (name.endswith(".tmp") or name.endswith(".tmp~"))


def temp_cleanup(root=".") -> dict:
    """回收异常路径（进程崩溃等）遗留的临时文件，返回回收清单。

    跳过本进程其他线程正在写入的临时文件，避免误删活跃写入。
    """
    root = _ensure_root(_root_or_scratch(root))
    removed = []
    with _lock:
        active = set(_active_temps)
        names = sorted(os.listdir(root))
    for name in names:
        if not _is_our_temp(name):
            continue
        path = os.path.join(root, name)
        with _lock:
            if path in _active_temps or path in active:
                continue
        try:
            os.unlink(path)
            removed.append(name)
        except OSError:
            continue
    if removed:
        _bump_metric("temp_cleanups", len(removed))
    return {"removed": removed, "count": len(removed), "root": root}


# ---------------------------------------------------------------------------
# 版本号与索引
# ---------------------------------------------------------------------------

def _next_version(root, slot) -> int:
    """原子分配下一个版本号（发起顺序即版本顺序，按 root+slot 隔离）。"""
    key = _state_key(root, slot)
    global _counter_seq
    with _lock:
        current = _counters.get(key, 0)
        committed = _committed.get(key)
        if committed is not None:
            current = max(current, int(committed["version"]))
        if current >= _counter_seq:
            _counter_seq = current + 1
        version = current + 1
        _counters[key] = version
        return version


def version_tag(value=None) -> dict:
    """返回版本标签（规范化版本号、分片与零填充标签）。"""
    if isinstance(value, dict):
        version = int(value.get("version", value.get("seq", 0)))
    elif value is None:
        with _lock:
            version = _counter_seq + 1
    elif isinstance(value, str) and value.strip().lower().startswith("v"):
        version = int(value.strip()[1:])
    else:
        try:
            version = int(value)
        except (TypeError, ValueError):
            version = 0
    return {
        "version": version,
        "shard": version // 1000,
        "offset": version % 1000,
        "tag": f"v{version:06d}",
    }


def _index_checksum(index: dict) -> str:
    return _sha256(_canonical({k: v for k, v in index.items() if k != "sha256"}))


def _load_index(root) -> dict | None:
    try:
        with open(_index_path(root), "rb") as fh:
            raw = fh.read()
    except (FileNotFoundError, OSError):
        return None
    try:
        index = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(index, dict) or not isinstance(index.get("slots"), dict):
        return None
    if "sha256" in index and _index_checksum(index) != index["sha256"]:
        return None
    return index


def _write_index(root, index: dict) -> None:
    body = {k: v for k, v in index.items() if k != "sha256"}
    snapshot = dict(body)
    snapshot["sha256"] = _sha256(_canonical(body))
    _atomic_write(_index_path(root), _canonical(snapshot), root)
    _bump_metric("index_updates")


def index_atomic(root=".", operation=None, *extra) -> dict:
    """原子地更新目录索引（写临时文件 + fsync + ``os.replace``）。

    * ``index_atomic(root)``：根据磁盘实际状态重建索引。
    * ``index_atomic(root, ("commit", slot, meta))``：提交单槽记录。
    * ``index_atomic(root, ("drop", slot))``：删除单槽记录。
    * ``index_atomic(root, ("read",))``：只读。
    * ``index_atomic(root, "commit", slot, meta)`` 亦可。
    """
    root = _ensure_root(_root_or_scratch(root))
    if extra:
        if isinstance(operation, str):
            operation = (operation, *extra)
        elif operation is None and extra:
            operation = extra
    with _lock:
        if isinstance(operation, tuple) and operation:
            op = operation[0]
            if op == "read":
                return {"ok": True, "index": _load_index(root) or {"slots": {}}}
            index = _load_index(root) or {"format": FORMAT_VERSION, "slots": {}}
            if op == "commit":
                _, slot, meta = operation
                index["slots"][_slot_key(slot)] = dict(meta)
            elif op == "drop":
                index["slots"].pop(_slot_key(operation[1]), None)
            else:
                raise ValueError(f"unknown index operation: {op!r}")
            _write_index(root, index)
            return {"ok": True, "index": index}

        # 无操作参数：从磁盘实际状态重建，索引不保留“过时记录”
        index = {"format": FORMAT_VERSION, "slots": {}}
        for name in sorted(os.listdir(root)):
            if not name.startswith(_SLOT_PREFIX) or not name.endswith(_SLOT_SUFFIX):
                continue
            slot = name[len(_SLOT_PREFIX): -len(_SLOT_SUFFIX)]
            meta = _read_valid(os.path.join(root, name))
            if meta is None:
                continue
            index["slots"][slot] = {
                "version": meta["version"],
                "sha256": meta["sha256"],
                "length": meta["length"],
                "file": name,
            }
        _write_index(root, index)
        return {"ok": True, "index": index}


def _repair_index(root: str, slot, meta: dict) -> None:
    """索引落后/损坏时按槽位文件的真实状态修正（解决索引指向旧版本）。

    ``_lock`` 内读-改-写，避免与其他槽位的并发 ``index_atomic`` 互相覆盖。
    """
    with _lock:
        index = _load_index(root) or {"format": FORMAT_VERSION, "slots": {}}
        entry = index["slots"].get(_slot_key(slot))
        if entry is not None and _entry_version(entry) == meta["version"] \
                and entry.get("sha256") == meta["sha256"]:
            return
        index["slots"][_slot_key(slot)] = {
            "version": meta["version"],
            "sha256": meta["sha256"],
            "length": meta["length"],
            "file": os.path.basename(_slot_path(root, slot)),
            "committed_at": time.time(),
            "mode": "repaired",
        }
        _write_index(root, index)


# ---------------------------------------------------------------------------
# 备份 / 回滚
# ---------------------------------------------------------------------------

def backup_slot(root=".", slot="default") -> dict:
    """为槽位保留上一版回滚点（``<slot>.prev``）。

    只备份通过完整性校验的当前版本：当前文件已损坏时保持旧回滚点不动。
    """
    root = _ensure_root(_root_or_scratch(root))
    key = _slot_key(slot)
    path = _slot_path(root, slot)
    current = _read_valid(path)
    if current is None:
        exists = os.path.exists(path)
        return {
            "ok": False,
            "reason": "no valid current version" if exists else "no current version",
            "slot": key,
        }
    prev = _prev_path(root, slot)
    _atomic_write(prev, current["bytes"], root)
    return {
        "ok": True,
        "slot": key,
        "backup": os.path.basename(prev),
        "version": current["version"],
        "enabled": _rollback_keep,
        "size": current["size"],
    }


# ---------------------------------------------------------------------------
# 主线程应用
# ---------------------------------------------------------------------------

def deserialize_main(payload=None, applier=None) -> dict:
    """在主线程（游戏线程）应用反序列化后的状态。

    后台线程只允许把已解码的纯数据投递到队列；真正的状态修改必须经过这里。
    不传参数时从队列取出一个待应用状态。
    """
    if payload is None and applier is None:
        try:
            payload, applier = _main_queue.get_nowait()
        except queue.Empty:
            return {"applied": False, "reason": "empty queue",
                    "thread": threading.current_thread().name,
                    "is_main": threading.current_thread() is threading.main_thread()}
    state = applier(payload) if applier is not None else payload
    return {
        "applied": True,
        "thread": threading.current_thread().name,
        "state": state,
        "is_main": threading.current_thread() is threading.main_thread(),
    }


# ---------------------------------------------------------------------------
# 校验 / 审计 / 失败注入 / 指标
# ---------------------------------------------------------------------------

def validation(meta=None, checksum=None) -> dict:
    """提交前的最终校验：结构 + 完整性/校验和 + 版本号可用性。"""
    if not isinstance(meta, dict) or "bytes" not in meta:
        return {"valid": False, "reasons": ["missing frame"], "checksum": None,
                "version": None}
    reasons = []
    check = integrity_check(meta["bytes"])
    if not check["ok"]:
        reasons.append(check["reason"])
    if checksum is not None and check.get("sha256") != checksum:
        reasons.append("checksum argument mismatch")
    try:
        if int(meta.get("version", 0)) <= 0:
            reasons.append("non-positive version")
    except (TypeError, ValueError):
        reasons.append("bad version")
    return {
        "valid": not reasons,
        "reasons": reasons,
        "checksum": check.get("sha256"),
        "version": check.get("version"),
    }


def _audit_event(root: str, event: str, **fields) -> None:
    entry = {"event": event, "ts": time.time(), **fields}
    with _lock:
        _audit_log.append(entry)
        _metrics["audit_entries"] += 1
    try:
        line = _canonical(entry) + b"\n"
        fd = os.open(os.path.join(root, "audit.log"),
                     os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
        try:
            os.write(fd, line)
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass


def audit(root=".", limit=None) -> dict:
    """返回存档操作审计轨迹（内存 + 磁盘上的 audit.log）。"""
    root = _ensure_root(_root_or_scratch(root))
    with _lock:
        entries = list(_audit_log)
    try:
        with open(os.path.join(root, "audit.log"), "r", encoding="utf-8") as fh:
            disk = [json.loads(line) for line in fh if line.strip()]
    except (FileNotFoundError, ValueError, OSError):
        disk = []
    merged = disk + entries
    if limit is not None:
        try:
            merged = merged[-int(limit):]
        except (TypeError, ValueError):
            pass
    return {"entries": merged, "count": len(merged)}


def metrics(reset=False, **extra) -> dict:
    """返回运行时指标快照；``reset=True`` 时清零。"""
    if not isinstance(reset, bool):
        extra.setdefault("arg", reset)
        reset = False
    with _lock:
        snapshot = dict(_metrics)
        snapshot.update({
            "slots_committed": len(_committed),
            "version_seq": _counter_seq,
            "queue_len": _main_queue.qsize(),
            "rollback_keep": _rollback_keep,
        })
        snapshot.update(extra)
        if reset:
            for key in _metrics:
                _metrics[key] = 0
    return snapshot


def _set_failure_hook(hook) -> None:
    """测试钩子：返回 True 时下一次落盘在替换前抛错（验证异常路径回收）。"""
    global _failure_hook
    with _failure_hook_lock:
        _failure_hook = hook


def _maybe_fail() -> None:
    with _failure_hook_lock:
        hook = _failure_hook
    if hook is not None and hook():
        raise OSError("injected write failure")


# ---------------------------------------------------------------------------
# 写入
# ---------------------------------------------------------------------------

def _write_frame(root: str, path: str, frames: bytes) -> None:
    """落盘一次写入：临时文件 + fsync + 原子替换；失败不破坏旧文件。"""
    tmp = _new_temp(root)
    try:
        with open(tmp, "wb") as fh:
            fh.write(frames)
            fh.flush()
            os.fsync(fh.fileno())
        _maybe_fail()
        os.replace(tmp, path)
    finally:
        _release_temp(tmp)
    _fsync_dir(os.path.dirname(os.path.abspath(path)) or ".")


def _commit_locked(root: str, slot, payload, version: int, mode: str) -> dict:
    """在槽位锁内提交一次写入（调用方保证持有槽位锁）。"""
    key = _slot_key(slot)
    state_key = _state_key(root, slot)
    frames = _pack(payload, version)
    meta = _unpack(frames)
    meta["bytes"] = frames
    check = validation(meta)
    if not check["valid"]:
        _bump_metric("discarded_saves")
        raise ValueError("pre-commit validation failed: " + ", ".join(check["reasons"]))

    # 版本栅栏：只有比已提交版本更新的写入才能替换槽位文件。
    committed = _committed.get(state_key)
    if committed is None:
        committed = _committed_from_disk(root, slot)
    if committed is not None and version <= int(committed["version"]):
        _bump_metric("discarded_saves")
        _audit_event(root, "stale_save", slot=key, version=version,
                     committed_version=int(committed["version"]))
        return {
            "ok": True,
            "status": "stale",
            "committed": False,
            "slot": key,
            "version": version,
            "committed_version": int(committed["version"]),
            "reason": "a newer version is already committed",
        }

    path = _slot_path(root, slot)

    # 异常路径遗留的临时文件先回收（活跃写入会被跳过）。
    temp_cleanup(root)

    # 回滚点：提交前把当前有效版本另存一份。
    backup = None
    if _rollback_keep and os.path.exists(path):
        backup = backup_slot(root, slot)

    _write_frame(root, path, frames)

    index_meta = {
        "version": version,
        "sha256": meta["sha256"],
        "length": meta["length"],
        "file": os.path.basename(path),
        "committed_at": time.time(),
        "mode": mode,
    }
    with _lock:
        _committed[state_key] = index_meta
        _counters[state_key] = max(_counters.get(state_key, 0), version)
    index_atomic(root, ("commit", slot, index_meta))

    _audit_event(root, "save", slot=key, version=version, mode=mode,
                 sha256=meta["sha256"],
                 backup=None if backup is None else backup.get("version"))
    _bump_metric("saves")
    return {
        "ok": True,
        "status": "committed",
        "committed": True,
        "slot": key,
        "version": version,
        "version_tag": version_tag(version)["tag"],
        "sha256": meta["sha256"],
        "bytes": len(frames),
        "file": path,
        "backup": None if backup is None else backup.get("version"),
    }


def _committed_from_disk(root: str, slot) -> dict | None:
    """进程重启后，以槽位文件中最新的有效版本作为版本栅栏。"""
    meta = _read_valid(_slot_path(root, slot))
    if meta is None:
        return None
    state_key = _state_key(root, slot)
    entry = {
        "version": meta["version"],
        "sha256": meta["sha256"],
        "length": meta["length"],
        "file": os.path.basename(_slot_path(root, slot)),
    }
    with _lock:
        current = _committed.get(state_key)
        if current is None or int(current["version"]) < meta["version"]:
            _committed[state_key] = entry
            _counters[state_key] = max(
                _counters.get(state_key, 0), meta["version"])
    return _committed.get(state_key)


class _Future:
    """极简 Future：后台写盘结果回传；``result()`` 可带超时。"""

    def __init__(self):
        self._event = threading.Event()
        self._result = None
        self._error = None

    def set_result(self, value):
        self._result = value
        self._event.set()

    def set_exception(self, exc):
        self._error = exc
        self._event.set()

    def done(self) -> bool:
        return self._event.is_set()

    def result(self, timeout=10.0):
        if not self._event.wait(timeout):
            raise TimeoutError("save did not finish in time")
        if self._error is not None:
            raise self._error
        return self._result

    def exception(self, timeout=10.0):
        self.result(timeout)
        return self._error


_pending_threads: set[threading.Thread] = set()


def _wait_pending() -> None:
    with _lock:
        threads = list(_pending_threads)
    for thread in threads:
        thread.join()
    with _lock:
        for thread in threads:
            _pending_threads.discard(thread)


def save(root=None, slot="default", state=None, version=None, payload=None,
         async_write=False, mode=None, **kwargs) -> dict:
    """保存存档。

    * ``root`` 缺省为当前目录；``slot`` 缺省 ``"default"``。
    * ``state`` / ``payload`` 为要保存的状态（二选一）。
    * ``version`` 显式指定版本；缺省在发起时原子分配。
    * ``async_write=True`` 时在后台线程落盘，返回 ``"queued"`` + ``"future"``。

    同一槽位的写入在锁内串行，且按版本号提交：先发起但后完成的旧写入会得到
    ``"stale"``，不会覆盖更新版本。
    """
    root = _ensure_root(_root_or_scratch(root))
    if payload is None:
        payload = state
    if payload is None:
        payload = {}
    if "async" in kwargs and not async_write:
        async_write = bool(kwargs["async"])
    mode = mode or ("async" if async_write else "sync")
    slot_lock = _slot_lock(root, slot)
    # 版本号在发起时分配，保证“发起顺序 = 版本顺序”。
    ver = int(version) if version is not None else _next_version(root, slot)

    def _run() -> dict:
        with slot_lock:
            return _commit_locked(root, slot, payload, ver, mode)

    if async_write:
        fut = _Future()

        def _worker():
            try:
                fut.set_result(_run())
            except BaseException as exc:  # noqa: BLE001
                fut.set_exception(exc)

        thread = threading.Thread(target=_worker,
                                  name=f"save-{_slot_key(slot)}", daemon=True)
        with _lock:
            _pending_threads.add(thread)
        _bump_metric("queued")
        thread.start()
        return {
            "ok": True,
            "status": "queued",
            "slot": _slot_key(slot),
            "version": ver,
            "mode": mode,
            "future": fut,
            "thread": thread,
        }
    return _run()


# ---------------------------------------------------------------------------
# 读取 / 恢复
# ---------------------------------------------------------------------------

def load(root=None, slot="default", applier=None, main_thread=False) -> dict:
    """读取存档。

    当前版本损坏（半文件/校验和不符/与索引校验和不一致）时自动回退上一版回滚点；
    索引落后于槽位文件时按实际文件修复索引（索引不再指向旧版本）。
    反序列化后的状态默认只在主线程应用，子线程读档会入队等待主线程处理。
    """
    root = _ensure_root(_root_or_scratch(root))
    key = _slot_key(slot)
    slot_lock = _slot_lock(root, slot)

    with slot_lock:
        index = _load_index(root) or {"slots": {}}
        entry = index["slots"].get(key)
        primary = _read_valid(_slot_path(root, slot))
        prev_meta = _read_valid(_prev_path(root, slot))

    source = None
    chosen = None
    tampered = False
    if primary is not None:
        if entry is not None and _entry_version(entry) == primary["version"] \
                and entry.get("sha256") not in (None, primary["sha256"]):
            # 版本号对得上但校验和对不上：文件被外部改写过，按损坏处理。
            tampered = True
        else:
            chosen, source = primary, "current"

    if chosen is None and prev_meta is not None:
        chosen, source = prev_meta, "previous"

    if chosen is None:
        _bump_metric("integrity_failures")
        return {
            "ok": False,
            "status": "corrupt",
            "slot": key,
            "reason": "no intact frame in current or previous version",
        }

    if source == "previous":
        _bump_metric("rolled_back")
        if primary is None or tampered:
            _audit_event(root, "load_fallback", slot=key,
                         version=chosen["version"])
    elif entry is None or _entry_version(entry) != chosen["version"]:
        # 索引与文件不一致（例如崩溃发生在替换文件之后、更新索引之前）：
        # 以通过完整性校验的槽位文件为准修复索引。
        with slot_lock:
            _repair_index(root, slot, chosen)

    payload = copy.deepcopy(chosen["payload"]) if applier is None else None
    pending = False
    if applier is not None:
        on_main = threading.current_thread() is threading.main_thread()
        if on_main or main_thread:
            payload = deserialize_main(chosen["payload"], applier)["state"]
        else:
            _main_queue.put((copy.deepcopy(chosen["payload"]), applier))
            pending = True

    _bump_metric("loads")
    _audit_event(root, "load", slot=key, version=chosen["version"], source=source)
    return {
        "ok": True,
        "status": "rolled_back" if source == "previous" else "ok",
        "slot": key,
        "version": chosen["version"],
        "sha256": chosen["sha256"],
        "source": source,
        "payload": payload,
        "pending_apply": pending,
    }


def fallback(root=None, slot="default") -> dict:
    """回滚到上一版：用 ``<slot>.prev`` 替换当前版本并原子更新索引。"""
    root = _ensure_root(_root_or_scratch(root))
    key = _slot_key(slot)
    state_key = _state_key(root, slot)
    with _slot_lock(root, slot):
        prev_meta = _read_valid(_prev_path(root, slot))
        if prev_meta is None:
            return {"ok": False, "status": "no_backup", "slot": key,
                    "reason": "previous version missing or corrupt"}
        _atomic_write(_slot_path(root, slot), prev_meta["bytes"], root)
        index_meta = {
            "version": prev_meta["version"],
            "sha256": prev_meta["sha256"],
            "length": prev_meta["length"],
            "file": os.path.basename(_slot_path(root, slot)),
            "committed_at": time.time(),
            "mode": "fallback",
        }
        with _lock:
            _committed[state_key] = index_meta
            _counters[state_key] = max(_counters.get(state_key, 0), index_meta["version"])
        index_atomic(root, ("commit", slot, index_meta))
    _bump_metric("rolled_back")
    _audit_event(root, "fallback", slot=key, version=prev_meta["version"])
    return {
        "ok": True,
        "status": "rolled_back",
        "slot": key,
        "version": prev_meta["version"],
        "sha256": prev_meta["sha256"],
        "payload": copy.deepcopy(prev_meta["payload"]),
    }


def recover(root=None, slot="default", applier=None) -> dict:
    """崩溃恢复：回收临时文件、校验槽位并回退到可用版本、修复索引。"""
    root = _ensure_root(_root_or_scratch(root))
    key = _slot_key(slot)
    state_key = _state_key(root, slot)
    cleaned = temp_cleanup(root)
    with _slot_lock(root, slot):
        current = _read_valid(_slot_path(root, slot))
        previous = _read_valid(_prev_path(root, slot))
        action = "none"
        chosen = None
        if current is not None:
            chosen, action = current, "use_current"
        elif previous is not None:
            _atomic_write(_slot_path(root, slot), previous["bytes"], root)
            chosen, action = previous, "restore_previous"
            _bump_metric("rolled_back")
        if chosen is not None:
            index_meta = {
                "version": chosen["version"],
                "sha256": chosen["sha256"],
                "length": chosen["length"],
                "file": os.path.basename(_slot_path(root, slot)),
                "committed_at": time.time(),
                "mode": "recover",
            }
            with _lock:
                _committed[state_key] = index_meta
                _counters[state_key] = max(
                    _counters.get(state_key, 0), chosen["version"])
            index_atomic(root, ("commit", slot, index_meta))
        else:
            index_atomic(root, ("drop", slot))
    _bump_metric("recovers")
    _audit_event(root, "recover", slot=key, action=action, cleaned=cleaned["count"])

    payload = None
    pending = False
    if chosen is not None:
        if applier is None:
            payload = copy.deepcopy(chosen["payload"])
        elif threading.current_thread() is threading.main_thread():
            payload = deserialize_main(chosen["payload"], applier)["state"]
        else:
            _main_queue.put((copy.deepcopy(chosen["payload"]), applier))
            pending = True
    return {
        "ok": chosen is not None,
        "status": action,
        "slot": key,
        "version": None if chosen is None else chosen["version"],
        "cleaned": cleaned["removed"],
        "payload": payload,
        "pending_apply": pending,
    }


# ---------------------------------------------------------------------------
# 确定性
# ---------------------------------------------------------------------------

def determinism(payload=None, runs=2) -> dict:
    """同一输入序列化出的字节与校验和必须稳定（幂等/去重的基础）。"""
    if payload is None:
        payload = {"pole": [1, 2, 3], "level": 7}
    try:
        runs = max(1, int(runs))
    except (TypeError, ValueError):
        runs = 2
    digests = [_sha256(_pack(payload, 1)) for _ in range(runs)]
    return {
        "stable": len(set(digests)) == 1,
        "runs": runs,
        "sha256": digests[0],
        "digests": digests,
    }
