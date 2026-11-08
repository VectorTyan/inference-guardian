"""Deploy the independent P0 relay and attach the existing BMS Prometheus."""
import argparse
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener

from generate_pd_metrics import ROOT, RELAY_MODULE, make_targets
from inference_guardian.observability.pd_metrics_relay import HEALTH_BODY, HEALTH_PATH, METRICS_PATH
from inference_guardian.storage import FileLock, atomic_json

SERVICE = "inference-guardian-pd-metrics.service"
UNIT_FILE = Path("/etc/systemd/system") / SERVICE
LOCAL_HTTP = build_opener(ProxyHandler({}))


def run(*args, **kwargs):
    return subprocess.run([str(arg) for arg in args], check=True, timeout=kwargs.pop("timeout", 30), **kwargs)


def unit_content(directory, python, port):
    return """[Unit]
Description=Inference Guardian P/D metrics relay
After=network.target

[Service]
Type=simple
DynamicUser=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
LoadCredential=pd-metrics.token:{directory}/pd-metrics.token
ExecStart={python} -B -m uvicorn {module}:create_app --factory --lifespan on --app-dir {directory} --host 127.0.0.1 --port {port}
Restart=on-failure

[Install]
WantedBy=multi-user.target
""".format(directory=directory, python=python, module=RELAY_MODULE, port=port).encode()


def wait_relay(port, token_file):
    origin = "http://127.0.0.1:{}".format(port)
    token = token_file.read_text(encoding="ascii").strip()
    request = Request(origin + METRICS_PATH + "?target=__guardian_readiness__",
                      headers={"Authorization": "Bearer " + token})
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        try:
            with LOCAL_HTTP.open(origin + HEALTH_PATH, timeout=2) as response:
                ready = response.read(len(HEALTH_BODY) + 1) == HEALTH_BODY
            if ready:
                try:
                    with LOCAL_HTTP.open(request, timeout=2):
                        pass
                except HTTPError as error:
                    with error:
                        if error.code == 404:
                            return
        except (OSError, URLError):
            pass
        time.sleep(0.5)
    raise ValueError("Independent metrics relay did not become ready")


def create_file(path, data, mode):
    with os.fdopen(os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode), "wb") as stream:
        os.fchmod(stream.fileno(), mode)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def install_once(path, data, mode):
    if path.is_symlink() or (path.exists() and (not path.is_file() or path.read_bytes() != data)):
        raise ValueError("Existing relay file differs; review it before changing this service: " + str(path))
    if not path.exists():
        create_file(path, data, mode)


def publish_allowlist(path, routes):
    with tempfile.TemporaryDirectory(dir=str(path.parent)) as directory:
        staged = Path(directory) / path.name
        atomic_json(staged, routes)
        staged.chmod(0o644)
        os.replace(str(staged), str(path))


def deploy(args):
    if os.geteuid() != 0:
        raise ValueError("Run on P0 as root to manage the relay and its existing Prometheus")
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    inventory = json.loads(args.inventory.read_text(encoding="utf-8"))
    controller = json.loads(args.controller.read_text(encoding="utf-8")) if args.controller else None
    routes, targets = make_targets(manifest, inventory, controller,
                                   "http://127.0.0.1:{}".format(args.relay_port), args.relay_port)
    p0_ip = next(node["host"] for node in manifest["nodes"] if node["id"] == "p0")
    addresses = run("ip", "-o", "-4", "address", "show", stdout=subprocess.PIPE, universal_newlines=True).stdout
    if p0_ip not in re.findall(r"\binet ([0-9.]+)/", addresses):
        raise ValueError("This host does not own the P0 address in the source manifest")
    directory, python = args.service_dir, args.relay_python
    for path in (directory, python):
        if not path.is_absolute() or ".." in path.parts or not re.fullmatch(r"/[A-Za-z0-9_./-]+", str(path)):
            raise ValueError("Relay paths must be absolute Linux paths without spaces or systemd specifiers")
    if directory.resolve() != directory or not python.is_file():
        raise ValueError("Relay service directory must be a real path and relay Python must exist")
    entry = args.npu_monitor_root / "deploy.sh"
    run("bash", entry, "guardian-metrics", "--help", stdout=subprocess.DEVNULL)
    run(python, "-B", "-c", "import httpx, uvicorn")

    if not directory.exists():
        directory.mkdir(mode=0o755, parents=True)
        directory.chmod(0o755)
    mode = directory.stat().st_mode
    if directory.stat().st_uid != 0 or mode & 0o022 or not mode & 0o001:
        raise ValueError("Relay directory must be root-owned, protected from writes and traversable by its service user")
    lock_path = directory / ".deploy.lock"
    if lock_path.is_symlink():
        raise ValueError("Relay deployment lock cannot be a symlink")
    with FileLock(lock_path):
        relay = (ROOT / "src/inference_guardian/observability/pd_metrics_relay.py").read_bytes()
        install_once(directory / (RELAY_MODULE + ".py"), relay, 0o644)
        token = directory / "pd-metrics.token"
        if token.is_symlink() or (token.exists() and (not token.is_file() or token.stat().st_mode & 0o077)):
            raise ValueError("Relay credential must be a private regular file")
        if not token.exists():
            create_file(token, (secrets.token_urlsafe(32) + "\n").encode(), 0o600)
        install_once(UNIT_FILE, unit_content(directory, python, args.relay_port), 0o644)
        active = subprocess.run(["systemctl", "is-active", "--quiet", SERVICE], timeout=10).returncode == 0
        allowlist, discovery = directory / "pd-metrics-allowlist.json", directory / "targets.json"
        if allowlist.is_symlink() or discovery.is_symlink():
            raise ValueError("Relay discovery files cannot be symlinks")
        previous = json.loads(allowlist.read_text(encoding="utf-8")) if allowlist.exists() else None
        previous_targets = json.loads(discovery.read_text(encoding="utf-8")) if discovery.exists() else None
        started = False
        try:
            publish_allowlist(allowlist, routes)
            atomic_json(discovery, targets)
            if not active:
                run("systemctl", "daemon-reload")
                started = True
                run("systemctl", "start", SERVICE)
            wait_relay(args.relay_port, token)
            run("bash", entry, "guardian-metrics", "--p0-ip", p0_ip,
                "--targets", discovery, "--token-file", token, timeout=180)
        except BaseException:
            if previous is not None:
                publish_allowlist(allowlist, previous)
            if previous_targets is not None:
                atomic_json(discovery, previous_targets)
            if started:
                run("systemctl", "stop", SERVICE)
            raise
        run("systemctl", "enable", SERVICE)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--controller", type=Path)
    parser.add_argument("--relay-port", type=int, required=True)
    parser.add_argument("--relay-python", type=Path, required=True)
    parser.add_argument("--service-dir", type=Path, default=Path("/opt/guardian-pd-metrics"))
    parser.add_argument("--npu-monitor-root", type=Path, default=Path("/data/npu_monitor/npu-metrics-monitor"))
    args = parser.parse_args()
    try:
        deploy(args)
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
        parser.exit(1, "ERROR: {}\n".format(error))


if __name__ == "__main__":
    main()
