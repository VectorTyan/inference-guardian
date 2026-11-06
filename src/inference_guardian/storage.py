"""为恢复状态和动作台账提供原子JSON写入与本地进程锁。

所有调用方应使用同一持久目录；本模块不提供跨宿主租约、仲裁或远程fencing。
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile


def atomic_json(path: str | Path, value: object) -> None:
    """在目标同目录写临时文件并fsync，再原子替换目标JSON。

    同目录保证替换不跨文件系统；POSIX额外同步父目录以持久化目录项。
    错误向调用方传播，finally只清理本次临时文件，不删除旧台账。
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    # 必须在目标同目录写临时文件，才能保证replace位于同一文件系统。
    fd, temp = tempfile.mkstemp(prefix=".guardian-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        if os.name != "nt":
            # 文件内容同步不足以保证目录项持久化；Linux再同步父目录。
            dfd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def read_json(path: str | Path, default=None):
    """读取UTF-8 JSON；仅文件不存在时返回default，格式错误和权限错误保持异常。"""
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return default


class FileLock:
    """同一状态目录的非阻塞排他锁；不防止另一宿主或另一状态卷上的控制器竞争。"""
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.file = None

    def acquire(self):
        """使用Windows字节锁或POSIX flock取得排他锁；已有写入者时立即报错。"""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.file = open(self.path, "a+b")
        try:
            if os.name == "nt":
                import msvcrt
                if self.file.seek(0, 2) == 0:
                    self.file.write(b"0")
                    self.file.flush()
                self.file.seek(0)
                msvcrt.locking(self.file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, BlockingIOError):
            self.file.close()
            self.file = None
            raise RuntimeError(f"another writer holds {self.path}") from None
        return self

    def release(self):
        """释放并关闭当前锁文件句柄；尚未取得锁时不执行操作。"""
        if self.file:
            if os.name == "nt":
                import msvcrt
                self.file.seek(0)
                msvcrt.locking(self.file.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.file.fileno(), fcntl.LOCK_UN)
            self.file.close()
            self.file = None

    def __enter__(self):
        return self.acquire()

    def __exit__(self, *args):
        self.release()
