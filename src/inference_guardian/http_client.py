"""探针和节点控制请求共用的短请求 HTTP 客户端。

使用标准库直接连接，不读取环境代理、不自动跟随重定向或重试。
响应在大小上限内完整缓冲；Gateway 的 SSE 透传另有实现。
网络异常交由上层分类，不能单凭超时推断模型死亡或远端动作未执行。
"""

from __future__ import annotations

import http.client
import json
from pathlib import Path
import ssl
import socket
import threading
import time
from urllib.parse import urlsplit


def file_headers(config):
    """从凭据文件组装请求头；token_file 存在时覆盖 Authorization。

    这里只读取凭据并拒绝换行，不打印令牌、请求头或文件内容。
    """
    headers = {}
    for name, path in config.get("header_files", {}).items():
        value = Path(path).read_text(encoding="utf-8").strip()
        if "\r" in value or "\n" in value:
            raise ValueError("invalid header file")
        headers[name] = value
    if config.get("token_file"):
        token = Path(config["token_file"]).read_text(encoding="utf-8").strip()
        if not token or "\r" in token or "\n" in token:
            raise ValueError("invalid token file")
        headers["Authorization"] = "Bearer " + token
    return headers


def request(url, method="GET", payload=None, headers=None, timeout=5, max_bytes=1024 * 1024,
            ca_file=None, cert_file=None, key_file=None):
    """返回状态码、响应头和有限大小的正文，不在此处判定健康状态。

    连接和收发共用单调时钟截止预算；建连后用剩余时间启动定时器，
    避免慢速响应不断刷新读超时。系统 DNS 解析没有独立可取消线程，
    因而不能把本函数描述为覆盖所有解析行为的绝对墙钟上限。
    """
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password:
        raise ValueError("invalid request URL")
    if parsed.scheme == "https":
        context = ssl.create_default_context(cafile=ca_file)
        if cert_file:
            context.load_cert_chain(cert_file, key_file)
        conn = http.client.HTTPSConnection(parsed.hostname, parsed.port, timeout=timeout, context=context)
    else:
        conn = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=timeout)
    body = None if payload is None else json.dumps(payload, allow_nan=False).encode()
    headers = dict(headers or {})
    if body is not None:
        headers["Content-Type"] = "application/json"
    deadline = time.monotonic() + timeout
    timer = None
    try:
        conn.connect()
        transport = conn.sock
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("connect deadline exceeded")
        # 捕获实际 socket：HTTPConnection 之后即使清空 sock，也能中断底层读取。
        def abort():
            try:
                transport.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            transport.close()
        timer = threading.Timer(remaining, abort)
        timer.daemon = True
        timer.start()
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        parts, size = [], 0
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("request deadline exceeded")
            if conn.sock:
                conn.sock.settimeout(remaining)
            chunk = response.read1(min(65536, max_bytes + 1 - size))
            if not chunk:
                break
            size += len(chunk)
            if size > max_bytes:
                raise ValueError("response too large")
            parts.append(chunk)
        if time.monotonic() >= deadline:
            raise TimeoutError("request deadline exceeded")
        length = response.getheader("Content-Length")
        # 有明确长度时拒绝截断的响应，不能把半个 JSON/业务结果交给探针断言。
        if length is not None and int(length) != size:
            raise http.client.IncompleteRead(b"".join(parts), int(length)-size)
        return response.status, dict(response.getheaders()), b"".join(parts)
    finally:
        if timer is not None:
            timer.cancel()
        conn.close()
