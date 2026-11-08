"""P/D metrics relay for a dedicated listener or the P0 Proxy listener."""
import asyncio
import hmac
from ipaddress import ip_address
import json
import os
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

METRICS_PATH = "/metrics/engine"
HEALTH_PATH = "/healthz"
HEALTH_BODY = b"guardian-pd-metrics\n"
TIMEOUT_SECONDS = 5
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_IN_FLIGHT = 16


async def reply(send, status, body=b"", content_type=b"text/plain; charset=utf-8"):
    await send({"type": "http.response.start", "status": status, "headers": [
        (b"content-type", content_type), (b"content-length", str(len(body)).encode("ascii")),
        (b"cache-control", b"no-store"),
    ]})
    await send({"type": "http.response.body", "body": body})


async def standalone_endpoint(scope, receive, send):
    if scope["type"] == "lifespan":
        await receive()
        await send({"type": "lifespan.startup.complete"})
        await receive()
        await send({"type": "lifespan.shutdown.complete"})
    elif scope["type"] == "http":
        if scope["method"] == "GET" and scope["path"] == HEALTH_PATH:
            await reply(send, 200, HEALTH_BODY)
        else:
            await reply(send, 404)
    elif scope["type"] == "websocket":
        await send({"type": "websocket.close"})


def create_app():
    """Standalone Uvicorn factory. It has no inference or Guardian lifecycle routes."""
    return PdMetricsRelay(standalone_endpoint)


class PdMetricsRelay:
    def __init__(self, app):
        self.app = app
        directory = Path(__file__).resolve().parent
        self.allowlist = Path(os.environ.get(
            "GUARDIAN_PD_METRICS_ALLOWLIST", str(directory / "pd-metrics-allowlist.json")))
        credential_dir = Path(os.environ.get("CREDENTIALS_DIRECTORY", str(directory)))
        self.token_file = Path(os.environ.get(
            "GUARDIAN_PD_METRICS_TOKEN_FILE", str(credential_dir / "pd-metrics.token")))
        self.slots = asyncio.Semaphore(MAX_IN_FLIGHT)
        self.client = None

    def resolve_target(self, authorization, target):
        # Read on demand so atomically replaced allowlists and tokens take effect in every worker.
        token = self.token_file.read_bytes().strip()
        if not token or any(byte < 33 or byte > 126 for byte in token):
            return 503, None
        if not hmac.compare_digest(authorization, b"Bearer " + token):
            return 401, None
        routes = json.loads(self.allowlist.read_text(encoding="utf-8"))
        url = routes.get(target)
        if url is None:
            return 404, None
        endpoint = urlsplit(url)
        if (endpoint.scheme != "http" or not endpoint.hostname or not endpoint.port
                or endpoint.username is not None or endpoint.password is not None
                or endpoint.path != "/metrics" or endpoint.query or endpoint.fragment):
            return 503, None
        ip_address(endpoint.hostname)
        return 200, url

    async def fetch(self, url, send):
        import httpx

        async def fetch_response():
            async with self.client.stream("GET", url, headers={
                "Accept": "text/plain; version=0.0.4",
                "Accept-Encoding": "identity",
            }) as upstream:
                content_type = upstream.headers.get("content-type", "")
                if (upstream.status_code != 200
                        or content_type.split(";", 1)[0].strip().lower()
                        not in ("text/plain", "application/openmetrics-text")
                        or upstream.headers.get("content-encoding", "identity").lower() != "identity"):
                    return 502, b"Invalid engine metrics response", b"text/plain"
                body = bytearray()
                async for chunk in upstream.aiter_raw():
                    if len(body) + len(chunk) > MAX_RESPONSE_BYTES:
                        return 502, b"Engine metrics response exceeds limit", b"text/plain"
                    body.extend(chunk)
                return 200, bytes(body), content_type.encode("latin-1")

        try:
            status, body, content_type = await asyncio.wait_for(fetch_response(), TIMEOUT_SECONDS)
        except (asyncio.TimeoutError, httpx.TimeoutException):
            return await reply(send, 504, b"Engine metrics timed out")
        except httpx.HTTPError:
            return await reply(send, 502, b"Engine metrics request failed")
        await reply(send, status, body, content_type)

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            # The relay environment provides HTTPX. Use a separate pool per worker for metrics.
            import httpx

            limits = httpx.Limits(max_connections=MAX_IN_FLIGHT, max_keepalive_connections=MAX_IN_FLIGHT)
            async with httpx.AsyncClient(timeout=TIMEOUT_SECONDS, limits=limits,
                                         trust_env=False, follow_redirects=False) as self.client:
                try:
                    return await self.app(scope, receive, send)
                finally:
                    self.client = None
        if scope["type"] != "http" or scope["path"] != METRICS_PATH:
            return await self.app(scope, receive, send)
        if scope["method"] != "GET":
            return await reply(send, 405)
        headers = [value for key, value in scope["headers"] if key == b"authorization"]
        if len(headers) != 1 or not headers[0].startswith(b"Bearer "):
            return await reply(send, 401)
        try:
            query = parse_qs(scope["query_string"].decode("ascii"), strict_parsing=True, max_num_fields=1)
            target, = query["target"]
        except (ValueError, KeyError):
            return await reply(send, 400, b"Exactly one target ID is required")
        if self.client is None:
            return await reply(send, 503, b"Metrics relay is unavailable")
        if self.slots.locked():
            return await reply(send, 503, b"Metrics relay is busy")
        async with self.slots:
            try:
                status, url = await asyncio.get_running_loop().run_in_executor(
                    None, self.resolve_target, headers[0], target)
            except (OSError, ValueError, TypeError, AttributeError):
                return await reply(send, 503, b"Metrics relay configuration is unavailable")
            if status != 200:
                return await reply(send, status)
            await self.fetch(url, send)
