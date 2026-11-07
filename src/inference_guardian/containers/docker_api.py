"""通过本地 Unix socket 调用有限的 Docker Engine API。

仅开放 inspect、top、logs、stop/start 和静态配置指定的 exec 操作。
exec 参数由 Node Agent 的本地白名单选择，不能由 HTTP 调用者提交；
此客户端不提供创建/删除容器、更新配置、重启宿主或复位设备的接口。
现场 Docker 20.10 使用配置的 v1.41，通用示例默认 v1.45；不会自动协商版本。
请求有期限和响应大小上限，但传输超时不能证明远端变更没有发生。
https://docs.docker.com/reference/api/engine/version/v1.41/
https://docs.docker.com/reference/api/engine/version/v1.45/
"""

from __future__ import annotations

from .._compat import _retain_import_identity

import http.client
import json
from pathlib import PurePosixPath
import re
import socket
import threading
from urllib.parse import urlencode


MAX_LOG_BYTES = 64 * 1024
MAX_JSON_BYTES = 4 * 1024 * 1024
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_VERSION = re.compile(r"v1\.[0-9]{2,3}\Z")
_FULL_ID = re.compile(r"[0-9a-f]{64}\Z")


class DockerError(RuntimeError):
    """未取得可确认的 Docker 操作结果，由上层按台账处理。"""


class DockerAPIError(DockerError):
    """记录非预期 HTTP 状态码，不携带可能含凭据的 Docker 响应正文。"""

    def __init__(self, status: int):
        self.status = status
        # Docker 错误正文可能包含应用命令或秘密，只向上层暴露状态码。
        super().__init__(f"Docker API returned HTTP {status}")


class DockerTransportError(DockerError):
    """传输或响应格式异常；变更请求可能已被 Docker 执行，不能据此重发。"""

    pass


class _UnixConnection(http.client.HTTPConnection):
    """支持由截止定时器关闭的本地连接，不经过 TCP 或环境代理。"""

    def __init__(self, path: str, timeout: float):
        super().__init__("localhost", timeout=timeout)
        self.unix_path = path
        self._cancelled = threading.Event()

    def connect(self) -> None:
        if self._cancelled.is_set():
            raise TimeoutError("Docker request deadline exceeded")
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock = sock
        sock.settimeout(self.timeout)
        try:
            sock.connect(self.unix_path)
            if self._cancelled.is_set():
                raise TimeoutError("Docker request deadline exceeded")
        except BaseException:
            sock.close()
            self.sock = None
            raise

    def cancel(self) -> None:
        """中断本地等待；关闭连接不等于撤销 Docker 已接受的动作。"""
        self._cancelled.set()
        sock = self.sock
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        self.close()


class DockerClient:
    """供 Agent 使用的受限客户端；每次只发一个请求，不做自动重试。"""

    def __init__(
        self, socket_path: str = "/var/run/docker.sock",
        api_version: str = "v1.45", timeout: float = 15,
    ):
        if not isinstance(socket_path, str) or not socket_path.startswith("/"):
            raise ValueError("docker_socket must be an absolute Unix socket path")
        if not isinstance(api_version, str) or not _VERSION.fullmatch(api_version):
            raise ValueError("docker_api_version must have form v1.45")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 300:
            raise ValueError("Docker timeout must be between 0 and 300 seconds")
        self.socket_path = socket_path
        self.api_version = api_version
        self.timeout = float(timeout)

    @staticmethod
    def _name(name: str) -> str:
        if not isinstance(name, str) or not _NAME.fullmatch(name):
            raise ValueError("Invalid container name or ID")
        return name

    def _request(
        self, method: str, name: str, operation: str, *, query: dict | None = None,
        limit: int = MAX_JSON_BYTES, timeout: float | None = None,
        truncate: bool = False, json_body: dict | None = None,
        expected_statuses: tuple[int, ...] | None = None, exec_endpoint: bool = False,
    ) -> bytes:
        """按接口约定检查返回码，并在固定期限和字节上限内读取响应。"""
        if exec_endpoint and (not isinstance(name, str) or not _FULL_ID.fullmatch(name)):
            raise ValueError("A full exec ID is required")
        resource = "exec" if exec_endpoint else "containers"
        path = f"/{self.api_version}/{resource}/{self._name(name)}/{operation}"
        if query:
            path += "?" + urlencode(query)
        duration = self.timeout if timeout is None else timeout
        connection = _UnixConnection(self.socket_path, duration)
        # 定时器覆盖本次请求，不能让持续小流量把单次读超时无限延后。
        watchdog = threading.Timer(duration, connection.cancel)
        watchdog.daemon = True
        watchdog.start()
        try:
            headers = {"Connection": "close"}
            body = None
            if json_body is not None:
                body = json.dumps(json_body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                if len(body) > MAX_JSON_BYTES:
                    raise ValueError("Docker request exceeded size limit")
                headers["Content-Type"] = "application/json"
            if body is None:
                connection.request(method, path, headers=headers)
            else:
                connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            # stop/start 的 304 表示已在目标状态；exec 的 201/200 由调用方显式指定。
            expected = expected_statuses or ((204, 304) if method == "POST" else (200,))
            if response.status not in expected:
                raise DockerAPIError(response.status)
            data = response.read(limit + 1)
            if connection._cancelled.is_set():
                raise DockerTransportError("Docker request deadline exceeded; outcome unknown")
            if len(data) > limit and not truncate:
                raise DockerTransportError("Docker response exceeded size limit")
            return data[:limit]
        except DockerError:
            raise
        except (OSError, TimeoutError, http.client.HTTPException, ValueError) as exc:
            raise DockerTransportError("Docker transport failed; outcome unknown") from exc
        finally:
            watchdog.cancel()
            connection.close()

    def _json(self, name: str, operation: str, **kwargs) -> dict:
        try:
            data = json.loads(self._request("GET", name, operation, **kwargs))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise DockerTransportError("Docker returned invalid JSON") from exc
        if not isinstance(data, dict):
            raise DockerTransportError("Docker returned a non-object response")
        return data

    def inspect(self, name: str, *, timeout: float | None = None) -> dict:
        """读取容器原始元数据；其中可能含 Env/Cmd，调用者不得直接写入审计。"""
        return self._json(name, "json", timeout=timeout)

    def top(self, name: str) -> dict:
        # -ww避免宿主默认列宽截断长模型路径；固定参数，不接收远程自定义命令。
        return self._json(name, "top", query={"ps_args": "-ww -eo pid,args"})

    def logs(self, name: str, tail: int = 200) -> str:
        """仅读取有行数和字节上限的日志尾部，不使用 follow 持续占用连接。"""
        if isinstance(tail, bool) or not isinstance(tail, int) or not 1 <= tail <= 1000:
            raise ValueError("tail must be between 1 and 1000")
        raw = self._request(
            "GET", name, "logs",
            query={"stdout": "true", "stderr": "true", "follow": "false", "tail": tail},
            limit=MAX_LOG_BYTES, truncate=True,
        )
        return _decode_logs(raw)

    def stop(self, name: str, timeout: int = 30) -> None:
        """等待容器优雅退出；HTTP 期限额外包含客户端通信预算。"""
        if isinstance(timeout, bool) or not isinstance(timeout, int) or not 0 <= timeout <= 120:
            raise ValueError("stop timeout must be between 0 and 120 seconds")
        # Docker 的 t 是发出强制终止前的等待时间，不是 HTTP 请求总期限。
        self._request("POST", name, "stop", query={"t": timeout}, timeout=timeout + self.timeout)

    def start(self, name: str) -> None:
        """启动既有容器；返回成功只说明容器操作完成，不代表模型已就绪。"""
        self._request("POST", name, "start")

    def exec_create(self, container_id: str, argv: list[str], working_dir: str, *, timeout=None) -> str:
        """创建静态命令的 exec 实例并返回完整 ID，此步骤尚未启动命令。

        仅接受完整容器 ID；201 响应中的 exec ID 仍需由 Agent 持久化，
        然后才能进入 exec_start，避免确认丢失后重复执行脚本。
        """
        if not isinstance(container_id, str) or not _FULL_ID.fullmatch(container_id):
            raise ValueError("A full container ID is required for exec")
        if (not isinstance(argv, list) or not 1 <= len(argv) <= 128
                or not isinstance(argv[0], str) or not argv[0]
                or any(not isinstance(arg, str) or len(arg) > 16384 or "\0" in arg for arg in argv)):
            raise ValueError("Invalid static exec arguments")
        if (not isinstance(working_dir, str) or not PurePosixPath(working_dir).is_absolute()
                or any(char in working_dir for char in ("\0", "\n", "\r"))):
            raise ValueError("Exec working directory must be an absolute container path")
        body = {"Cmd": argv, "WorkingDir": working_dir, "AttachStdin": False,
                "AttachStdout": False, "AttachStderr": False, "Tty": False, "Privileged": False}
        try:
            result = json.loads(self._request("POST", container_id, "exec", json_body=body,
                                             expected_statuses=(201,), timeout=timeout))
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise DockerTransportError("Docker returned invalid exec metadata") from None
        identifier = result.get("Id") if isinstance(result, dict) else None
        if not isinstance(identifier, str) or not _FULL_ID.fullmatch(identifier):
            raise DockerTransportError("Docker did not confirm a full exec ID")
        return identifier

    def exec_start(self, exec_id: str, *, timeout=None) -> None:
        """以 detached 方式启动指定 exec；200 不表示脚本已退出或模型已健康。"""
        self._request("POST", exec_id, "start", exec_endpoint=True,
                      json_body={"Detach": True, "Tty": False}, expected_statuses=(200,), timeout=timeout)

    def exec_inspect(self, exec_id: str, *, timeout=None) -> dict:
        """只读查询 exec；Agent 还须核对 ContainerID、启动时间和自身台账。"""
        return self._json(exec_id, "json", exec_endpoint=True, timeout=timeout)


def _decode_logs(raw: bytes) -> str:
    """兼容非 TTY 的多路帧和 TTY 文本；允许诊断日志在字节上限处截断。"""
    if len(raw) < 8 or raw[0] not in (0, 1, 2) or raw[1:4] != b"\x00\x00\x00":
        return raw.decode("utf-8", errors="replace")
    chunks = []
    position = 0
    while position + 8 <= len(raw):
        header = raw[position:position + 8]
        if header[0] not in (0, 1, 2) or header[1:4] != b"\x00\x00\x00":
            break
        length = int.from_bytes(header[4:8], "big")
        position += 8
        chunks.append(raw[position:min(position + length, len(raw))])
        position += length
    return b"".join(chunks).decode("utf-8", errors="replace")


_retain_import_identity(__name__, "inference_guardian.docker_api")
