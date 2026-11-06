"""统一运行日志的UTC+8显示，不依赖宿主TZ、容器时区或tzdata。"""
from datetime import datetime, timedelta, timezone
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path


UTC_PLUS_8 = timezone(timedelta(hours=8))


def utc8_timestamp(timestamp=None):
    """只转换显示时区，不偏移原始Unix时间戳或任何计时器。"""
    instant = (datetime.now(UTC_PLUS_8) if timestamp is None
               else datetime.fromtimestamp(timestamp, UTC_PLUS_8))
    return instant.isoformat(timespec="seconds")


class OperationsFormatter(logging.Formatter):
    def formatTime(self, record, datefmt=None):
        return utc8_timestamp(record.created)


class DurableFileHandler(RotatingFileHandler):
    """Controller恢复记录必须同步到既有宿主卷；错误向调用方传播。"""
    def _open(self):
        fd = os.open(self.baseFilename, os.O_WRONLY | os.O_APPEND | os.O_CREAT
                     | getattr(os, "O_NOFOLLOW", 0), 0o600)
        return os.fdopen(fd, "a", encoding="utf-8")

    def emit(self, record):
        path = Path(self.baseFilename)
        if path.is_symlink() or self.stream is None:
            raise OSError("Controller log unavailable")
        current, opened = path.stat(), os.fstat(self.stream.fileno())
        if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
            raise OSError("Controller log replaced; restore persistence before restarting")
        super().emit(record)
        self.flush()
        os.fsync(self.stream.fileno())

    def doRollover(self):
        for index in range(self.backupCount + 1):
            if Path(self.baseFilename + ("." + str(index) if index else "")).is_symlink():
                raise OSError("Controller log rotation contains a symlink")
        super().doRollover()
        if os.name == "posix":
            fd = os.open(str(Path(self.baseFilename).parent), os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)

    def handleError(self, record):
        raise OSError("Controller log write failed; check host state storage") from None
