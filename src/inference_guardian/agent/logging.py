"""Agent运维日志：独立轮转、受控事件与周期摘要，不替代动作审计台账。"""
from __future__ import annotations

from .._compat import _retain_import_identity

_retain_import_identity(__name__, "inference_guardian.agent_logging")

import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import sys
import threading
import time

from ..observability.log_format import OperationsFormatter, utc8_timestamp


DEFAULTS = {"max_bytes": 10 * 1024 * 1024, "backup_count": 5,
            "status_interval_seconds": 60, "observation_max_age_seconds": 60}


def validate_logging(value):
    """只校验显式配置；不向旧配置注入默认值，保留旧接管指纹。"""
    bounds = {"max_bytes": (1024 * 1024, 1024 * 1024 * 1024), "backup_count": (1, 20),
              "status_interval_seconds": (1, 86400), "observation_max_age_seconds": (1, 86400)}
    if not isinstance(value, dict) or set(value) - set(bounds):
        raise ValueError("Invalid Agent logging fields")
    for key, item in value.items():
        low, high = bounds[key]
        if type(item) is not int or not low <= item <= high:
            raise ValueError("logging.{} must be an integer between {} and {}".format(key, low, high))


class _FileHandler(RotatingFileHandler):
    """运行日志写入失败只报告受控诊断；动作是否允许仍由独立审计决定。"""
    last_error = None
    last_write = None
    write_failed = False

    def emit(self, record):
        self.write_failed = False
        super().emit(record)
        if not self.write_failed:
            self.last_write = time.time()

    def _open(self):
        descriptor = os.open(self.baseFilename, os.O_WRONLY | os.O_APPEND | os.O_CREAT
                             | getattr(os, "O_NOFOLLOW", 0), 0o600)
        return os.fdopen(descriptor, "a", encoding="utf-8")

    def doRollover(self):
        for suffix in [""] + ["." + str(index) for index in range(1, self.backupCount + 1)]:
            if Path(self.baseFilename + suffix).is_symlink():
                raise OSError("Refusing symlink log file")
        super().doRollover()

    def handleError(self, record):
        self.write_failed = True
        now = time.monotonic()
        if self.last_error is None or now - self.last_error >= 60:
            self.last_error = now
            # 不输出原异常/record，避免路径、命令或凭据混入Python的默认诊断。
            try:
                sys.stderr.write(utc8_timestamp() + " ERROR agent_log_write_failed: check state storage permissions and free space\n")
            except Exception:
                pass


class AgentLog:
    def __init__(self, directory, node_id, settings):
        self.settings = dict(DEFAULTS, **settings)
        self.node_id = node_id
        self.logger = logging.Logger("inference_guardian.node_agent", logging.INFO)
        self.logger.propagate = False
        self.stop_event = threading.Event()
        self.thread = None
        self.closed = False
        path = Path(directory) / "inference-guardian.log"
        if path.is_symlink():
            raise ValueError("Refusing symlink log file")
        file_handler = _FileHandler(path, maxBytes=self.settings["max_bytes"],
                                    backupCount=self.settings["backup_count"], encoding="utf-8")
        self.file_handler = file_handler
        formatter = OperationsFormatter("%(asctime)s %(levelname)s %(message)s")
        for handler in (logging.StreamHandler(), file_handler):
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

    def emit(self, event, level=logging.INFO, **fields):
        if not self.closed:
            self.logger.log(level, json.dumps(dict(event=event, node_id=self.node_id, pid=os.getpid(), **fields),
                                             ensure_ascii=False, sort_keys=True))

    def persistence(self):
        """核对正在写入的文件仍是目录中的文件，不把stderr可见当作已持久化。"""
        with self.file_handler.lock:
            return self._persistence()

    def _persistence(self):
        handler = self.file_handler
        result = dict(path=handler.baseFilename, persistent_file_ok=False,
                      last_write_at=utc8_timestamp(handler.last_write) if handler.last_write is not None else None)
        try:
            path = Path(handler.baseFilename)
            info, opened = path.stat(), os.fstat(handler.stream.fileno())
            result.update(bytes=info.st_size, persistent_file_ok=(not path.is_symlink()
                and (info.st_dev, info.st_ino) == (opened.st_dev, opened.st_ino)
                and info.st_size > 0 and not handler.write_failed))
        except (OSError, ValueError, AttributeError):
            pass
        return result

    def start(self, summary):
        """摘要读取已采集的观测，不新增Docker请求或与Controller争抢采集锁。"""
        if self.thread is not None:
            return
        def report():
            while not self.stop_event.is_set():
                try:
                    fields = summary()
                    level = logging.WARNING if fields["attention_required"] else logging.INFO
                    self.emit("agent_status_summary", level=level, **fields)
                except Exception as exc:
                    self.emit("agent_status_summary_failed", level=logging.ERROR, error_type=type(exc).__name__)
                if self.stop_event.wait(self.settings["status_interval_seconds"]):
                    break
        self.thread = threading.Thread(target=report, name="agent-status-summary", daemon=True)
        self.thread.start()

    def stop_reporting(self):
        self.stop_event.set()
        if self.thread is not None and self.thread is not threading.current_thread():
            self.thread.join()

    def close(self):
        self.stop_reporting()
        if not self.closed:
            self.closed = True
            for handler in list(self.logger.handlers):
                self.logger.removeHandler(handler)
                handler.close()
