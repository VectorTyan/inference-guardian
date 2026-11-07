"""Agent管理HTTP分帧、认证、TLS与进程生命周期；不决定恢复策略。"""
from __future__ import annotations
import argparse
import hmac
import json
import logging
from pathlib import Path
import signal
import socket
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from .service import NodeAgent, AgentError, MAX_BODY_BYTES
from ..containers.docker_api import MAX_LOG_BYTES
from ..observability.log_format import utc8_timestamp

class _Server(ThreadingHTTPServer):
    """接收连接时限定 TLS 握手等待，关闭服务时释放 Agent 的状态目录租约。"""

    daemon_threads = True
    block_on_close = False

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(self.agent.timeout)
        if isinstance(connection, ssl.SSLSocket):
            try:
                connection.do_handshake()
            except BaseException:
                connection.close()
                raise
        return connection, address

    def server_close(self):
        super().server_close()
        if hasattr(self, "agent"):
            self.agent.close()


class _Handler(BaseHTTPRequestHandler):
    """提供需认证且有请求大小/读取期限限制的控制面，不承接模型业务流量。"""

    server_version = "InferenceGuardianNode/1"
    sys_version = ""

    def setup(self):
        super().setup()
        self.connection.settimeout(self.server.agent.timeout)
        def expire_headers():
            try:
                self.connection.shutdown(socket.SHUT_RD)
            except OSError:
                pass
        self._header_deadline = threading.Timer(self.server.agent.timeout, expire_headers)
        self._header_deadline.daemon = True
        self._header_deadline.start()

    def finish(self):
        self._header_deadline.cancel()
        super().finish()

    def log_message(self, format, *args):
        # 默认实现会记录原始 URL；这里仅通过专门审计事件记录受控字段。
        pass

    def _read_body(self, length):
        """用独立计时器限制整段请求体读取，防止慢速客户端持续刷新单次读超时。"""
        def expire():
            try:
                self.connection.shutdown(socket.SHUT_RD)
            except OSError:
                pass
        watchdog = threading.Timer(self.server.agent.timeout, expire)
        watchdog.daemon = True
        watchdog.start()
        try:
            return self.rfile.read(length)
        finally:
            self._body_consumed = True
            watchdog.cancel()

    def _send(self, status, value):
        # 拒绝 POST 时先有界读完较小且长度明确的请求体，减少关闭时 TCP reset
        # 丢弃 401/413 响应的风险；大请求或分帧不明确时不排空，读取仍受总期限限制。
        if status >= 400 and self.command == "POST" and not getattr(self, "_body_consumed", False):
            lengths = self.headers.get_all("Content-Length", [])
            if len(lengths) == 1 and lengths[0].isdigit() and not self.headers.get("Transfer-Encoding"):
                length = int(lengths[0])
                if 0 < length <= MAX_LOG_BYTES:
                    try:
                        self._read_body(length)
                    except OSError:
                        pass
        # 成功、缓存和错误响应都绑定当前配置节点，不能沿用结果对象中的其他身份。
        value = {**value, "node_id": self.server.agent.config.get("node_id")}
        data = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)
        self.close_connection = True

    def _authorize(self):
        """只接受一个 Authorization，以恒定时间比较凭据且不输出其内容。"""
        values = self.headers.get_all("Authorization", [])
        supplied = values[0] if len(values) == 1 else ""
        try:
            valid = hmac.compare_digest(supplied, "Bearer " + self.server.agent.token)
        except TypeError:
            valid = False
        if not valid:
            raise AgentError(401, "Bearer authentication required")

    def do_GET(self):
        """/health 只表示 Agent 可响应；模型观测由 /v1/status 提供，均不承诺 ready。"""
        self._header_deadline.cancel()
        try:
            self._authorize()
            if self.path == "/health":
                self._send(200, {"ok": True, "scope": "node_agent", "audit_available": not self.server.agent.audit_failed,
                                 "runtime_logging": self.server.agent.log.persistence()})
            elif self.path == "/v1/status":
                self._send(200, self.server.agent.status())
            else:
                raise AgentError(404, "Unknown endpoint")
        except AgentError as exc:
            self._send(exc.status, {"ok": False, "error": exc.detail})
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            pass
        except Exception:
            self._send(500, {"ok": False, "error": "Node agent request failed"})

    def do_POST(self):
        """接收有界、分帧明确的 JSON 动作请求，不向 Docker 透传任意执行参数。"""
        self._header_deadline.cancel()
        try:
            self._authorize()
            if self.path != "/v1/action":
                raise AgentError(404, "Unknown endpoint")
            lengths = self.headers.get_all("Content-Length", [])
            if self.headers.get("Transfer-Encoding") or len(lengths) != 1:
                raise AgentError(400, "Exactly one Content-Length is required")
            try:
                length = int(lengths[0])
            except ValueError as exc:
                raise AgentError(400, "Invalid Content-Length") from exc
            if not 0 < length <= MAX_BODY_BYTES:
                raise AgentError(413, "Action request exceeds size limit")
            if self.headers.get_content_type() != "application/json":
                raise AgentError(415, "Content-Type must be application/json")
            raw = self._read_body(length)
            if len(raw) != length:
                raise AgentError(400, "Incomplete request body")
            try:
                body = json.loads(raw)
            except (ValueError, UnicodeDecodeError) as exc:
                raise AgentError(400, "Invalid JSON action") from exc
            status, result = self.server.agent.action(body)
            self._send(status, result)
        except AgentError as exc:
            self._send(exc.status, {"ok": False, "error": exc.detail})
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            pass
        except Exception:
            self._send(500, {"ok": False, "error": "Node action failed; inspect journal before retrying"})


def create_server(config: dict, docker_client=None) -> ThreadingHTTPServer:
    """创建 Agent 控制端口；默认要求 TLS，由调用方负责服务循环与关闭清理。"""
    agent = NodeAgent(config, docker_client)
    listen = agent.config["listen"]
    server = None
    try:
        server_class = _Server
        if ":" in listen["host"]:
            class IPv6Server(_Server):
                address_family = socket.AF_INET6
            server_class = IPv6Server
        server = server_class((listen["host"], listen["port"]), _Handler)
        server.agent = agent
        if listen.get("tls_cert_file"):
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(listen["tls_cert_file"], listen["tls_key_file"])
            server.socket = context.wrap_socket(server.socket, server_side=True, do_handshake_on_connect=False)
        return server
    except BaseException as exc:
        agent.log.emit("agent_startup_failed", level=logging.ERROR, error_type=type(exc).__name__)
        if server is not None:
            server.server_close()
        agent.close()
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description="Allowlisted Docker node agent")
    parser.add_argument("--config", required=True, help="Node JSON config file")
    args = parser.parse_args(argv)
    try:
        config = json.loads(Path(args.config).read_text(encoding="utf-8"))
        server = create_server(config)
    except Exception as exc:
        # 初始化日志前也可失败；只输出错误类型，不泄漏凭据或原异常中的内容。
        print(utc8_timestamp() + " ERROR agent_startup_failed error_type=" + type(exc).__name__, file=sys.stderr)
        raise SystemExit(1)
    requested = threading.Event()
    stop_signal = [None]
    failures = []
    previous_handlers = {}
    def stop(signum, _frame):
        stop_signal[0] = signum
        requested.set()
    def serve():
        try:
            server.serve_forever(poll_interval=0.2)
        except Exception as exc:
            failures.append(type(exc).__name__)
        finally:
            requested.set()
    thread = threading.Thread(target=serve, name="agent-http", daemon=True)
    try:
        for sig in (signal.SIGINT, signal.SIGTERM):
            previous_handlers[sig] = signal.signal(sig, stop)
        thread.start()
        server.agent.log.emit("agent_started", listen_host=server.server_address[0],
                              listen_port=server.server_address[1],
                              status_interval_seconds=server.agent.log.settings["status_interval_seconds"],
                              log_file=str(server.agent.directory / "inference-guardian.log"))
        server.agent.log.start(server.agent.status_summary)
        requested.wait()
        server.agent.closing.set()
        if failures:
            server.agent.log.emit("agent_serve_failed", level=logging.ERROR, error_type=failures[0])
        server.agent.log.emit("agent_shutdown_requested", reason=(signal.Signals(stop_signal[0]).name
                              if stop_signal[0] else "server_loop_ended"))
    finally:
        if thread.ident is not None:
            server.shutdown()
            thread.join()
        server.server_close()
        for sig, handler in previous_handlers.items():
            signal.signal(sig, handler)
    if failures or not server.agent.closed:
        raise SystemExit(1)
