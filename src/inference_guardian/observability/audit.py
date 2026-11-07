"""以追加式SHA-256哈希链保存操作审计，启动时先验证已有记录。

哈希链只能发现未经同步重算的本地修改，不是签名或外部可信存证。
调用方仍需保护持久卷并将必要审计外送；写入失败后本进程拒绝继续追加。
"""
from __future__ import annotations


from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import threading

ZERO = "0" * 64
SECRET_KEYS = re.compile(r"authorization|password|secret|api.?key|access.?token|bearer", re.I)


def sanitize(value):
    """递归遮盖常见凭据字段及Bearer文本，并限制字符串长度。

    这是尽力脱敏，不能证明任意业务日志都不含敏感信息；调用方应避免传入原始argv或Env。
    """
    if isinstance(value, dict):
        return {k: "[REDACTED]" if SECRET_KEYS.search(str(k)) else sanitize(v)
                for k, v in value.items()}
    if isinstance(value, (tuple, list)):
        return [sanitize(v) for v in value]
    if isinstance(value, str):
        return re.sub(r"(?i)Bearer\s+[^\s,\"']+", "Bearer [REDACTED]", value)[:8192]
    return value


def digest(record):
    """使用固定JSON序列化规则计算记录哈希；待计算记录不应包含自身hash字段。"""
    return hashlib.sha256(json.dumps(record, sort_keys=True, ensure_ascii=False,
                                    separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def verify(directory: str | Path):
    """按文件及行顺序验证序号、前序哈希和内容哈希，返回链头及记录数。

    空目录对应零记录；损坏记录抛ValueError，不跳过或自动修补，以免掩盖审计缺口。
    """
    previous, count = ZERO, 0
    for path in sorted(Path(directory).glob("audit-*.jsonl")):
        with path.open(encoding="utf-8") as stream:
            for number, line in enumerate(stream, 1):
                try:
                    record = json.loads(line)
                    checksum = record.pop("hash")
                    if record["seq"] != count + 1 or record["previous_hash"] != previous:
                        raise ValueError("sequence or predecessor mismatch")
                    if digest(record) != checksum:
                        raise ValueError("checksum mismatch")
                except (ValueError, KeyError, TypeError) as exc:
                    raise ValueError(f"invalid audit chain: {path.name}:{number}: {exc}") from None
                previous, count = checksum, count + 1
    return {"records": count, "head_hash": previous}


class AuditLog:
    """单进程线程安全的审计追加器；跨进程单写入者由外层FileLock保证。"""
    def __init__(self, directory: str | Path):
        """创建目录并核验整条已有审计链，随后从已验证的链头继续追加。"""
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        head = verify(self.directory)
        self.seq, self.previous = head["records"], head["head_hash"]
        self.lock = threading.Lock()
        self.failed = False

    def emit(self, event: str, **fields):
        """先脱敏、写入并fsync，成功后才推进内存序号与链头。

        若写入或同步失败，尾部是否完整已无法确认，置failed使后续写入失败；恢复动作调用方必须传播此错误。
        """
        with self.lock:
            if self.failed:
                raise OSError("audit writer is poisoned; investigate persisted tail before restarting")
            now = datetime.now(timezone.utc)
            record = {"seq": self.seq + 1, "previous_hash": self.previous,
                      "time": now.isoformat(), "event": event, "fields": sanitize(fields)}
            checksum = digest(record)
            record["hash"] = checksum
            # 系统日期回退时沿用最后一个文件名，避免按文件排序核验时打乱哈希链。
            files = sorted(self.directory.glob("audit-*.jsonl"))
            name = f"audit-{now:%Y%m%d}.jsonl"
            if files and files[-1].name > name:
                name = files[-1].name
            try:
                fd = os.open(self.directory / name, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
                with os.fdopen(fd, "a", encoding="utf-8") as stream:
                    stream.write(json.dumps(record, ensure_ascii=False, allow_nan=False) + "\n")
                    stream.flush()
                    os.fsync(stream.fileno())
            except BaseException:
                # 无法确认尾部是否完整时，不继续追加或推进序号；调用方据此停止变更。
                self.failed = True
                raise
            self.seq, self.previous = record["seq"], checksum
            return checksum
