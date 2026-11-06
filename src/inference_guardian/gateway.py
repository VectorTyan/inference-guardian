"""可选的固定端口HTTP网关，负责准入与单次转发，不执行推理重试或故障恢复。

默认外部接管方案禁用此监听器，保留原Proxy业务入口；本模块的503/限流能力
不能据此算作外部方案已具备。只有Controller更新就绪状态。token预算依赖
单独配置并验证的分词HTTP适配器，不用字符数代替token数，也不估算真实HBM。
"""

from __future__ import annotations

import http.client
import io
import json
import math
import re
import socket
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit


_TEXT_PATHS = frozenset({"/v1/chat/completions", "/v1/completions"})
_HOP_HEADERS = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade", "proxy-connection",
})
_MANAGEMENT_PATHS = frozenset({
    "/v1/load_lora_adapter", "/v1/unload_lora_adapter", "/v1/scale_elastic_ep",
    "/v1/sleep", "/v1/wake_up", "/v1/pause", "/v1/resume",
    "/v1/start_profile", "/v1/stop_profile", "/v1/reset_prefix_cache",
    "/v1/reset_mm_cache", "/v1/collective_rpc", "/v1/server_info",
})
_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_REJECT_DRAIN_BYTES = 64 * 1024
_REJECT_DRAIN_SECONDS = 1.0


def _positive_int(value, name):
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _json_float(value):
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("nonfinite JSON number")
    return result


def _text_tokenizer_input(payload, path):
    """只接受当前适配器能计数的文本输入，避免把文本token预算冒充多模态预算。"""
    if any(key in payload for key in ("prompt_embeds", "input_embeds", "input_ids", "prompt_token_ids", "multi_modal_data")):
        return False
    if path == "/v1/completions":
        prompt = payload.get("prompt")
        return isinstance(prompt, str) or (isinstance(prompt, list) and all(
            isinstance(token, int) and not isinstance(token, bool) and token >= 0 for token in prompt))
    messages = payload.get("messages")
    if not isinstance(messages, list) or payload.get("modalities", ["text"]) != ["text"] or "audio" in payload:
        return False
    for message in messages:
        if not isinstance(message, dict):
            return False
        if any(key in message for key in ("audio", "image", "video")):
            return False
        content = message.get("content")
        if content is None or isinstance(content, str):
            continue
        if not isinstance(content, list) or not all(isinstance(part, dict) and part.get("type") == "text"
                                                   and isinstance(part.get("text"), str) for part in content):
            return False
    return True


def _url(value):
    parsed = urlsplit(value)
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
            or parsed.fragment):
        raise ValueError("upstream URL must be HTTP(S), without userinfo or fragment")
    # 配置时就校验端口，避免把静态配置错误拖到业务请求阶段才发现。
    parsed.port
    return parsed


def _connection(parsed, timeout):
    cls = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
    return cls(parsed.hostname, parsed.port, timeout=timeout)


def _hop_names(headers):
    """收集逐跳头及Connection显式列出的头，避免把单段连接语义转发给下一跳。"""
    names = set(_HOP_HEADERS)
    for value in headers.get_all("Connection", []):
        names.update(part.strip().lower() for part in value.split(",") if part.strip())
    return names


class GatewayState:
    """在线程间共享路由与准入额度，本对象自身不创建监听器。

    同一把锁保护路由快照和计数，使并发请求不能分别看到可用额度后一起超额。
    流式响应也占用并发/token/长请求额度，直到处理函数结束才归还。
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._routes = []
        self._inflight = {}
        self._inflight_tokens = {}
        self._long_inflight = 0
        self._sequence = 0
        self._tokenizer_available = None

    def set_routes(self, routes: list[dict]):
        """校验并替换可用路由；保留已有请求的计数，交由其结束路径归还。"""
        checked = []
        ids = set()
        for route in routes:
            route_id = route["id"]
            if not isinstance(route_id, str) or not route_id or route_id in ids:
                raise ValueError("route IDs must be unique nonempty strings")
            ids.add(route_id)
            parsed = _url(route["url"])
            if parsed.query:
                raise ValueError("route base URL must not contain a query")
            if not isinstance(route["ready"], bool):
                raise ValueError("route ready must be a boolean")
            expires_at = route.get("expires_at")
            if expires_at is not None and (isinstance(expires_at, bool)
                                          or not isinstance(expires_at, (int, float))
                                          or not math.isfinite(expires_at)):
                raise ValueError("route expires_at must be a finite Unix timestamp")
            token_limit = route.get("max_inflight_tokens")
            if token_limit is not None:
                _positive_int(token_limit, "route max_inflight_tokens")
            headers = dict(route.get("headers", {}))
            for name, value in headers.items():
                if (not isinstance(name, str) or not _HEADER_NAME.fullmatch(name)
                        or name.lower() in _HOP_HEADERS | {"host", "content-length"}
                        or not isinstance(value, str) or "\r" in value or "\n" in value):
                    raise ValueError("invalid fixed upstream header")
            checked.append({
                "id": route_id, "url": route["url"], "ready": route["ready"],
                "max_inflight": _positive_int(route.get("max_inflight", 1), "route max_inflight"),
                "expires_at": expires_at, "max_inflight_tokens": token_limit,
                "headers": headers,
            })
        with self._lock:
            if self._tokenizer_available is False and any(r["max_inflight_tokens"] is not None for r in checked):
                raise ValueError("route token budgets require a configured tokenizer_url")
            self._routes = checked

    @staticmethod
    def _ready(route, now):
        """就绪标记还必须在时效内，避免Controller停更后沿用过期健康证据。"""
        return route["ready"] and (route["expires_at"] is None or route["expires_at"] > now)

    def _configure_tokenizer(self, available):
        with self._lock:
            if not available and any(r["max_inflight_tokens"] is not None for r in self._routes):
                raise ValueError("route token budgets require a configured tokenizer_url")
            self._tokenizer_available = available

    def _route_token_budget(self):
        with self._lock:
            return any(r["max_inflight_tokens"] is not None for r in self._routes)

    def get_snapshot(self):
        """返回不含上游凭据的状态快照；可用槽位是当前计数，不代表后端真实容量。"""
        with self._lock:
            now = time.time()
            routes = [{
                "id": r["id"], "ready": self._ready(r, now), "max_inflight": r["max_inflight"],
                "expires_at": r["expires_at"], "max_inflight_tokens": r["max_inflight_tokens"],
                "inflight": self._inflight.get(r["id"], 0),
                "inflight_tokens": self._inflight_tokens.get(r["id"], 0),
            } for r in self._routes]
            return {
                "routes": routes, "inflight": sum(self._inflight.values()),
                "inflight_tokens": sum(self._inflight_tokens.values()),
                "long_inflight": self._long_inflight,
                "ready_routes": sum(r["ready"] for r in routes),
                "available_slots": sum(max(0, r["max_inflight"] - r["inflight"])
                                       for r in routes if r["ready"]),
            }

    def _reserve(self, global_limit):
        """先预留请求并发槽位：无新鲜就绪路由返回503，额度已满返回429。"""
        with self._lock:
            now = time.time()
            ready = [r for r in self._routes if self._ready(r, now)]
            if not ready:
                return None, 503
            available = [r for r in ready if self._inflight.get(r["id"], 0) < r["max_inflight"]]
            if sum(self._inflight.values()) >= global_limit or not available:
                return None, 429
            # 优先选择占用比例较低的路由；轮换并列顺序，避免持续偏向同一条。
            offset = self._sequence % len(available)
            available = available[offset:] + available[:offset]
            route = min(available, key=lambda r: self._inflight.get(r["id"], 0) / r["max_inflight"])
            self._sequence += 1
            self._inflight[route["id"]] = self._inflight.get(route["id"], 0) + 1
            return dict(route, headers=dict(route["headers"])), 200

    def _reserve_tokens(self, original_route, amount, global_limit):
        """在真正发送推理前复核就绪状态并预留token预算。

        前置并发槽位限制了同时读取请求/分词的工作量。分词期间路由可能失效，
        因此此处可重新选择仍就绪且有额度的路由；尚未发送推理，不属于HTTP重试。
        """
        with self._lock:
            now = time.time()
            ready = [r for r in self._routes if self._ready(r, now)]
            if not ready:
                return None, 503
            if global_limit is not None:
                if amount is None:
                    return None, 503
                if sum(self._inflight_tokens.values()) + amount > global_limit:
                    return None, 429
            candidates = []
            missing_count = False
            for route in ready:
                adjusted_inflight = self._inflight.get(route["id"], 0) - (route["id"] == original_route["id"])
                if adjusted_inflight >= route["max_inflight"]:
                    continue
                limit = route["max_inflight_tokens"]
                if limit is not None:
                    if amount is None:
                        missing_count = True
                        continue
                    if self._inflight_tokens.get(route["id"], 0) + amount > limit:
                        continue
                candidates.append(route)
            if not candidates:
                return None, 503 if missing_count else 429
            route = min(candidates, key=lambda r: (r["id"] != original_route["id"],
                                                   self._inflight.get(r["id"], 0) / r["max_inflight"]))
            if route["id"] != original_route["id"]:
                self._inflight[original_route["id"]] -= 1
                if not self._inflight[original_route["id"]]:
                    self._inflight.pop(original_route["id"])
                self._inflight[route["id"]] = self._inflight.get(route["id"], 0) + 1
            if amount:
                self._inflight_tokens[route["id"]] = self._inflight_tokens.get(route["id"], 0) + amount
            return dict(route, headers=dict(route["headers"])), 200

    def _reserve_long(self, limit):
        """预留全局长请求槽位，避免所有并发都被长上下文请求占满。"""
        with self._lock:
            if self._long_inflight >= limit:
                return False
            self._long_inflight += 1
            return True

    def _release(self, route_id, long_request, tokens=0):
        """归还本次实际预留的额度，即使该路由已从当前就绪列表移除。"""
        with self._lock:
            remaining = self._inflight.get(route_id, 0) - 1
            if remaining > 0:
                self._inflight[route_id] = remaining
            else:
                self._inflight.pop(route_id, None)
            if long_request:
                self._long_inflight -= 1
            if tokens:
                remaining_tokens = self._inflight_tokens.get(route_id, 0) - tokens
                if remaining_tokens > 0:
                    self._inflight_tokens[route_id] = remaining_tokens
                else:
                    self._inflight_tokens.pop(route_id, None)


class _RequestError(Exception):
    """可返回给客户端的受控拒绝；只保存状态码和稳定错误码，不保存请求正文。"""

    def __init__(self, status, code):
        self.status = status
        self.code = code


class _DeadlineReader(io.RawIOBase):
    """每次recv使用同一期限的剩余时间，防止少量持续来包无限延长头/正文读取。"""

    def __init__(self, connection, timeout):
        super().__init__()
        self.connection = connection
        self.deadline = time.monotonic() + timeout

    def readable(self):
        return True

    def readinto(self, buffer):
        """重设的是剩余总时间，不是为每个小分片重新发放完整超时时间。"""
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("request read deadline exceeded")
        self.connection.settimeout(remaining)
        return self.connection.recv_into(buffer)


def validate_config(config: dict) -> dict:
    """只校验并补齐网关配置，不绑定端口，返回独立的配置副本。

    token限额必须配分词适配器；路由级限额还会在GatewayState接收路由时复核，
    包括Controller运行期间发布的新路由。
    """
    cfg = dict(config)
    if type(cfg.get("enabled", True)) is not bool:
        raise ValueError("gateway.enabled must be boolean")
    cfg.setdefault("listen_host", "127.0.0.1")
    cfg.setdefault("listen_port", 18000)
    cfg.setdefault("max_body_bytes", 1048576)
    cfg.setdefault("max_inflight", 8)
    cfg.setdefault("upstream_timeout_seconds", 300)
    cfg.setdefault("client_timeout_seconds", 30)
    cfg.setdefault("request_body_timeout_seconds", cfg["client_timeout_seconds"])
    cfg.setdefault("tokenizer_timeout_seconds", 10)
    cfg.setdefault("max_output_tokens", 256)
    cfg.setdefault("default_output_tokens", cfg["max_output_tokens"])
    cfg.setdefault("max_choices", 1)
    cfg.setdefault("max_long_inflight", 1)
    if not isinstance(cfg["listen_host"], str) or not cfg["listen_host"]:
        raise ValueError("listen_host must be a nonempty string")
    if isinstance(cfg["listen_port"], bool) or not isinstance(cfg["listen_port"], int) or not 0 <= cfg["listen_port"] <= 65535:
        raise ValueError("listen_port must be an integer in 0..65535")
    configured_paths = cfg.get("allowed_paths", ["/v1/chat/completions", "/v1/completions", "/v1/models"])
    if not isinstance(configured_paths, (list, tuple, set)) or not all(isinstance(path, str) for path in configured_paths):
        raise ValueError("allowed_paths must be a list of strings")
    paths = set(configured_paths)
    if not paths or any(not isinstance(p, str) or not p.startswith("/v1/")
                        or "?" in p or "#" in p or "%" in p or ".." in p
                        or p in _MANAGEMENT_PATHS or p.startswith(("/v1/admin", "/v1/internal")) for p in paths):
        raise ValueError("allowed_paths must contain exact /v1 business paths, not management paths")
    for key in ("max_body_bytes", "max_inflight", "max_output_tokens", "default_output_tokens", "max_choices", "max_long_inflight"):
        _positive_int(cfg[key], key)
    if cfg["default_output_tokens"] > cfg["max_output_tokens"]:
        raise ValueError("default_output_tokens must not exceed max_output_tokens")
    token_budget = any(cfg.get(key) is not None for key in
                       ("max_input_tokens", "max_total_tokens", "long_request_tokens", "max_inflight_tokens"))
    for key in ("max_input_tokens", "max_total_tokens", "long_request_tokens", "max_inflight_tokens"):
        if cfg.get(key) is not None:
            _positive_int(cfg[key], key)
    for key in ("upstream_timeout_seconds", "client_timeout_seconds", "tokenizer_timeout_seconds", "request_body_timeout_seconds"):
        if (isinstance(cfg[key], bool) or not isinstance(cfg[key], (int, float))
                or not math.isfinite(cfg[key]) or cfg[key] <= 0):
            raise ValueError(f"{key} must be positive")
    if token_budget and not cfg.get("tokenizer_url"):
        raise ValueError("token budgets require a configured tokenizer_url")
    if cfg.get("tokenizer_url"):
        _url(cfg["tokenizer_url"])
    cfg["allowed_paths"] = sorted(paths)
    return cfg


def create_server(config: dict, state: GatewayState, audit) -> ThreadingHTTPServer:
    """校验并绑定可选网关，调用者随后在线程中运行serve_forever。

    enabled=false时拒绝构造；默认外部模式的启动层不会调用此函数。非文本POST
    只支持字节数/并发限制，不能安全计数的输入在启用token预算时拒绝准入。

    client_timeout_seconds限制完整请求头读取及每次向客户端发送；正文读取使用
    独立的总期限。upstream_timeout_seconds是套接字操作/读取空闲超时，不是整次
    生成或SSE的总时长上限，持续有数据的响应可以更久。转发前须成功记录准入和
    发送审计；审计不记录请求正文或凭据。
    """
    cfg = validate_config(config)
    if cfg.get("enabled", True) is False:
        raise ValueError("Gateway is disabled; no business listener may be constructed")
    paths = set(cfg["allowed_paths"])
    token_budget = any(cfg.get(key) is not None for key in
                       ("max_input_tokens", "max_total_tokens", "long_request_tokens", "max_inflight_tokens"))
    tokenizer_endpoint = _url(cfg["tokenizer_url"]) if cfg.get("tokenizer_url") else None
    state._configure_tokenizer(tokenizer_endpoint is not None)

    class GatewayHandler(BaseHTTPRequestHandler):
        """单请求转发处理器；不自动重放模型请求，流式发送期间持续占用准入额度。"""

        protocol_version = "HTTP/1.1"
        server_version = "InferenceGuardian"
        sys_version = ""

        def setup(self):
            # 使用带总期限的读取器，不能只依赖每次socket.recv的空闲超时。
            super().setup()
            self.rfile.close()
            self.rfile = io.BufferedReader(_DeadlineReader(self.connection, cfg["client_timeout_seconds"]))

        def log_message(self, format, *args):
            pass  # 禁用基类的原始URL日志，避免查询参数或请求内容进入stderr。

        def _audit(self, event, **fields):
            if audit is not None:
                try:
                    audit.emit(event, request_id=self.request_id, **fields)
                except Exception:
                    return False
            return True

        def _json(self, status, code, *, retry=False):
            self._drain_rejected_body()
            self.connection.settimeout(cfg["client_timeout_seconds"])
            body = json.dumps({"error": {"code": code}, "request_id": self.request_id}).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.send_header("X-Guardian-Request-ID", self.request_id)
            if retry:
                self.send_header("Retry-After", "5" if status == 503 else "1")
            self.end_headers()
            self.close_connection = True
            self.wfile.write(body)
            self.wfile.flush()

        def _drain_rejected_body(self):
            """有界排空长度明确的小POST，降低未读TCP数据在关闭时吞掉错误响应的风险。"""
            length = getattr(self, "_unread_body_length", None)
            self._unread_body_length = None
            if self.command != "POST" or length is None or not 0 < length <= _REJECT_DRAIN_BYTES:
                return
            # 只能缩短已建立的正文总期限，不能为拒绝响应或慢速发送者再发一份预算。
            self.rfile.raw.deadline = min(self.rfile.raw.deadline, time.monotonic() + _REJECT_DRAIN_SECONDS)
            try:
                self.rfile.read(length)
            except (OSError, ValueError):
                pass

        def _health(self, path):
            """healthz只表示本监听器可响应；readyz还要求至少一条新鲜就绪路由。"""
            self.connection.settimeout(cfg["client_timeout_seconds"])
            snapshot = state.get_snapshot()
            ready = snapshot["ready_routes"] > 0
            status = 200 if path == "/healthz" or ready else 503
            body = json.dumps({"status": "ok" if status == 200 else "not_ready"}).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            if status == 503:
                self.send_header("Retry-After", "5")
            self.end_headers()
            self.close_connection = True
            self.wfile.write(body)

        def _body_length(self):
            """只接受无歧义的请求长度，拒绝Transfer-Encoding及重复长度声明。"""
            if self.headers.get_all("Transfer-Encoding"):
                raise _RequestError(400, "request_transfer_encoding_unsupported")
            lengths = self.headers.get_all("Content-Length", [])
            if len(lengths) > 1:
                raise _RequestError(400, "ambiguous_content_length")
            if not lengths:
                if self.command == "POST":
                    raise _RequestError(411, "content_length_required")
                return 0
            if not re.fullmatch(r"[0-9]+", lengths[0]):
                raise _RequestError(400, "invalid_content_length")
            try:
                length = int(lengths[0])
            except ValueError:
                raise _RequestError(400, "invalid_content_length") from None
            # 此时仅确认HTTP分帧无歧义；大小/路径/准入拒绝均共享这一份正文期限。
            self._unread_body_length = length
            self.rfile.raw.deadline = time.monotonic() + cfg["request_body_timeout_seconds"]
            if length > cfg["max_body_bytes"]:
                raise _RequestError(413, "request_too_large")
            if self.command == "GET" and length:
                raise _RequestError(400, "get_body_unsupported")
            return length

        def _count_tokens(self, payload, path):
            """调用已配置的模型分词适配器；失败时拒绝请求，不猜测输入token数。"""
            keys = (("model", "messages", "tools", "tool_choice", "documents", "chat_template",
                     "chat_template_kwargs", "add_generation_prompt", "continue_final_message")
                    if path == "/v1/chat/completions" else ("model", "prompt"))
            adapter_body = json.dumps({key: payload[key] for key in keys if key in payload},
                                      ensure_ascii=False, allow_nan=False).encode("utf-8")
            headers = {"Content-Type": "application/json", "Accept": "application/json"}
            connection = None
            try:
                if cfg.get("tokenizer_token_file"):
                    token = Path(cfg["tokenizer_token_file"]).read_text(encoding="utf-8").strip()
                    if not token or "\n" in token or "\r" in token:
                        raise ValueError("invalid tokenizer credential file")
                    headers["Authorization"] = "Bearer " + token
                connection = _connection(tokenizer_endpoint, cfg["tokenizer_timeout_seconds"])
                target = tokenizer_endpoint.path or "/"
                if tokenizer_endpoint.query:
                    target += "?" + tokenizer_endpoint.query
                connection.request("POST", target, adapter_body, headers)
                response = connection.getresponse()
                data = response.read(1048577)
                if response.status != 200 or len(data) > 1048576:
                    raise ValueError("tokenizer response unavailable")
                result = json.loads(data)
                count = result.get("count")
                if isinstance(count, int) and not isinstance(count, bool) and count >= 0:
                    return count
                tokens = result.get("tokens")
                if isinstance(tokens, list) and all(isinstance(t, int) and not isinstance(t, bool)
                                                    and t >= 0 for t in tokens):
                    return len(tokens)
                raise ValueError("tokenizer response lacks a valid count")
            except (OSError, http.client.HTTPException, ValueError, TypeError, AttributeError):
                raise _RequestError(503, "tokenizer_unavailable") from None
            finally:
                if connection is not None:
                    connection.close()

        def _prepare_body(self, raw, path, requires_count):
            """校验文本请求及输出上限，返回转发正文、长请求标记与静态token费用。"""
            if path not in _TEXT_PATHS:
                if requires_count:
                    raise _RequestError(400, "token_budget_unsupported_for_endpoint")
                return raw, False, None
            if self.headers.get("Content-Encoding", "identity").lower() != "identity":
                raise _RequestError(415, "compressed_json_unsupported")
            try:
                payload = json.loads(raw, parse_float=_json_float,
                                     parse_constant=lambda value: (_ for _ in ()).throw(ValueError()))
                if not isinstance(payload, dict):
                    raise ValueError()
            except (ValueError, UnicodeError, RecursionError):
                raise _RequestError(400, "invalid_json") from None
            output_fields = [key for key in ("max_tokens", "max_completion_tokens") if key in payload]
            if len(output_fields) > 1:
                raise _RequestError(400, "ambiguous_output_token_limit")
            if not output_fields:
                # 缺省输出长度与允许的最大值分开，防止未传max_tokens就预留最大额。
                payload["max_tokens"] = cfg["default_output_tokens"]
                output_fields = ["max_tokens"]
            output = payload[output_fields[0]]
            choices = payload.get("n", 1)
            best_of = payload.get("best_of", choices)
            if (isinstance(output, bool) or not isinstance(output, int)
                    or output < 1 or output > cfg["max_output_tokens"]):
                raise _RequestError(400, "output_token_limit_exceeded")
            if (isinstance(choices, bool) or not isinstance(choices, int)
                    or choices < 1 or choices > cfg["max_choices"]
                    or isinstance(best_of, bool) or not isinstance(best_of, int)
                    or best_of < choices or best_of > cfg["max_choices"]):
                raise _RequestError(400, "choice_limit_exceeded")
            long_request = False
            token_cost = None
            if requires_count:
                if not _text_tokenizer_input(payload, path):
                    raise _RequestError(400, "token_budget_unsupported_for_input")
                count = self._count_tokens(payload, path)
                # 预算包含输入和最多best_of份输出；它是准入预留，不是实际生成量
                # 或KV/HBM测量，不能用来证明后端一定不会内存不足。
                token_cost = count + output * best_of
                if cfg.get("max_input_tokens") is not None and count > cfg["max_input_tokens"]:
                    raise _RequestError(400, "input_token_limit_exceeded")
                if cfg.get("max_total_tokens") is not None and count + output * best_of > cfg["max_total_tokens"]:
                    raise _RequestError(400, "total_token_limit_exceeded")
                long_request = cfg.get("long_request_tokens") is not None and count >= cfg["long_request_tokens"]
            return json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8"), long_request, token_cost

        def do_GET(self):
            self._handle()

        def do_POST(self):
            self._handle()

        def _handle(self):
            """一次准入、一次上游发送；所有正常/异常退出最终归还已预留额度。"""
            self.request_id = uuid.uuid4().hex
            self._unread_body_length = None
            route = None
            reserved_long = False
            reserved_tokens = 0
            upstream = None
            started = False
            status = 500
            try:
                parsed = urlsplit(self.path)
                if not self.path.startswith("/") or parsed.scheme or parsed.netloc or parsed.fragment:
                    raise _RequestError(400, "invalid_request_target")
                path = parsed.path
                length = self._body_length()
                if self.command == "GET" and path in {"/healthz", "/readyz"}:
                    self._health(path)
                    return
                if path not in paths:
                    raise _RequestError(404, "path_not_allowed")
                if (path in _TEXT_PATHS and self.command != "POST") or (path == "/v1/models" and self.command != "GET"):
                    raise _RequestError(405, "method_not_allowed")
                route, status = state._reserve(cfg["max_inflight"])
                if route is None:
                    raise _RequestError(status, "service_recovering" if status == 503 else "capacity_exhausted")
                if not self._audit("gateway_request_admitted", route_id=route["id"], method=self.command, path=path):
                    raise _RequestError(503, "audit_unavailable")
                try:
                    # 一旦开始正常读取，异常时不再盲目排空原长度，避免重复等候或多读。
                    self._unread_body_length = None
                    raw = self.rfile.read(length) if length else b""
                except (TimeoutError, socket.timeout):
                    raise _RequestError(408, "request_body_timeout") from None
                if len(raw) != length:
                    raise _RequestError(400, "incomplete_request_body")
                requires_count = token_budget or state._route_token_budget()
                body, is_long, token_cost = (self._prepare_body(raw, path, requires_count)
                                             if self.command == "POST" else (None, False, 0))
                if is_long:
                    if not state._reserve_long(cfg["max_long_inflight"]):
                        raise _RequestError(429, "long_request_capacity_exhausted")
                    reserved_long = True
                admitted_route, status = state._reserve_tokens(route, token_cost, cfg.get("max_inflight_tokens"))
                if admitted_route is None:
                    raise _RequestError(status, "service_recovering" if status == 503 else "token_capacity_exhausted")
                route = admitted_route
                reserved_tokens = token_cost or 0
                if not self._audit("gateway_request_dispatch", route_id=route["id"], method=self.command, path=path):
                    raise _RequestError(503, "audit_unavailable")
                skip = _hop_names(self.headers) | {"host", "content-length", "expect", "x-guardian-request-id"}
                headers = {key.lower(): value for key, value in self.headers.items() if key.lower() not in skip}
                if path in _TEXT_PATHS and self.command == "POST":
                    headers["content-type"] = "application/json"
                for key, value in route["headers"].items():
                    headers[key.lower()] = value
                headers["x-guardian-request-id"] = self.request_id
                headers["connection"] = "close"
                endpoint = _url(route["url"])
                target = endpoint.path.rstrip("/") + path
                if parsed.query:
                    target += "?" + parsed.query
                upstream = _connection(endpoint, cfg["upstream_timeout_seconds"])
                upstream.request(self.command, target, body, headers)
                response = upstream.getresponse()
                if response.status < 200:
                    raise _RequestError(502, "upstream_protocol_unsupported")
                if any(not _HEADER_NAME.fullmatch(key) or "\r" in value or "\n" in value
                       for key, value in response.getheaders()):
                    raise _RequestError(502, "upstream_invalid_headers")
                status = response.status
                self.connection.settimeout(cfg["client_timeout_seconds"])
                self.send_response(status)
                response_skip = _hop_names(response.headers) | {"content-length", "server", "date", "x-guardian-request-id"}
                for key, value in response.getheaders():
                    if key.lower() not in response_skip:
                        self.send_header(key, value)
                no_body = status in {204, 304}
                if not no_body:
                    self.send_header("Transfer-Encoding", "chunked")
                self.send_header("Connection", "close")
                self.send_header("X-Guardian-Request-ID", self.request_id)
                self.end_headers()
                started = True
                self.close_connection = True
                if not no_body:
                    # 按块转发并刷新，SSE不会被攒成完整响应后再发送；槽位也不会
                    # 因收到响应头或首个token而提前释放。
                    while True:
                        chunk = response.read1(65536)
                        if not chunk:
                            if response.length not in (None, 0):
                                raise http.client.IncompleteRead(b"")
                            break
                        self.wfile.write(f"{len(chunk):X}\r\n".encode("ascii") + chunk + b"\r\n")
                        self.wfile.flush()
                    self.wfile.write(b"0\r\n\r\n")
                    self.wfile.flush()
                self._audit("gateway_request_complete", route_id=route["id"], status=status, method=self.command, path=path)
            except _RequestError as exc:
                self._audit("gateway_request_rejected", status=exc.status, code=exc.code)
                if not started:
                    self._json(exc.status, exc.code, retry=exc.status in {429, 503})
                else:
                    self.close_connection = True
            except (OSError, http.client.HTTPException, ValueError) as exc:
                # 已开始响应后不能改写成JSON错误或重试一次推理，只终止该连接；
                # 上游流的语义完整性仍由模型协议/业务验收负责。
                self._audit("gateway_stream_aborted" if started else "gateway_upstream_failed",
                            route_id=route["id"] if route else None, error_type=type(exc).__name__)
                self.close_connection = True
                if not started:
                    try:
                        self._json(504 if isinstance(exc, (TimeoutError, socket.timeout)) else 502,
                                   "upstream_unavailable")
                    except OSError:
                        pass
            finally:
                # 包括分词拒绝、上游异常和客户端断开；只归还本请求已经取得的额度。
                if upstream is not None:
                    upstream.close()
                if route is not None:
                    state._release(route["id"], reserved_long, reserved_tokens)

    class GatewayServer(ThreadingHTTPServer):
        """为显式启用的网关创建连接线程；不参与模型恢复或Controller唯一性控制。"""

        daemon_threads = True

        def get_request(self):
            client, address = super().get_request()
            client.settimeout(cfg["client_timeout_seconds"])
            return client, address

        def handle_error(self, request, client_address):
            # 不输出可能含URL、凭据或请求局部变量的完整异常现场。
            if audit is not None:
                try:
                    audit.emit("gateway_handler_failed")
                except Exception:
                    pass

    return GatewayServer((cfg["listen_host"], cfg["listen_port"]), GatewayHandler)
