"""只读查看持久日志元数据，不读取日志正文或创建文件。"""
from pathlib import Path
import time
from .log_format import utc8_timestamp


def file_log_status(path):
    path = Path(path)
    result = dict(path=str(path), exists=False, bytes=0)
    if path.is_symlink() or not path.is_file():
        return result
    info = path.stat()
    result.update(exists=True, bytes=info.st_size, modified_at=utc8_timestamp(info.st_mtime),
                  age_seconds=round(max(0, time.time() - info.st_mtime), 1))
    return result
