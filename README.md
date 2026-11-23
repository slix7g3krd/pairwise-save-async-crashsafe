# pairwise-save-async-crashsafe

## 领域

游戏、图形与多媒体

## 主题

存档异步写入与崩溃恢复

## 说明

写盘并发、半文件校验与索引原子替换。

初始状态下 `gameplay/save_async_crashsafe.py` 中所有函数抛出 `NotImplementedError`，测试全部失败。
修复实现后运行：

```bash
python -m pytest -q
```

期望全部通过。
