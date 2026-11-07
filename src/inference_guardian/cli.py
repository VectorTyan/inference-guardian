"""统一分派守护进程和运维命令，管理本地日志、Controller唯一锁及退出信号。

默认外部部署不监听业务端口；维护命令仅入队，必须由运行中的Controller消费才生效。
"""
from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
import signal
import threading

from .observability.audit import AuditLog, verify
from .control.config import load_config
from .control.service import Controller, queue_command
from .observability.log_format import OperationsFormatter, DurableFileHandler
from .storage import FileLock, read_json


def logging_setup(directory):
    """将INFO及以上日志写到终端和限额轮转文件；运行目录需可写。"""
    directory = Path(directory)
    if directory.is_symlink():
        raise ValueError("Controller log directory cannot be a symlink")
    directory.mkdir(parents=True, exist_ok=True)
    formatter = OperationsFormatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    handlers = [logging.StreamHandler(), DurableFileHandler(
        directory / "inference-guardian.log", maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8")]
    for handler in handlers:
        handler.setFormatter(formatter)
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    for handler in handlers:
        root.addHandler(handler)


def run_controller(config):
    """持有本地唯一锁后启动Controller，并按显式配置决定是否启用可选Gateway。

    外部模式只监测配置中的原入口；收到退出信号后停止调度并清理本进程创建的监听器。
    """
    from .gateway import GatewayState, create_server
    with FileLock(Path(config["state_dir"]) / "controller.lock"):
        logging_setup(config["state_dir"])
        audit = AuditLog(Path(config["state_dir"]) / "audit")
        state = GatewayState()
        controller = Controller(config, state, audit)
        server = None
        thread = None
        # gateway.enabled=false是当前交付默认值，Controller只走管理和探针链路。
        if config["gateway"].get("enabled", True):
            server = create_server(config["gateway"], state, audit)
            thread = threading.Thread(target=server.serve_forever, name="fixed-ingress", daemon=True)
            thread.start()
        else:
            audit.emit("external_monitoring_started", traffic_control=False,
                       note="Existing inference listener retained; Guardian binds no business port")
        def stop(*_):
            controller.stop_event.set()
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, stop)
        try:
            controller.run()
        finally:
            state.set_routes([])
            if server is not None:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)


def main(argv=None):
    """解析角色与运维命令；validate不绑定端口，维护/解隔离仅写持久命令队列。"""
    parser = argparse.ArgumentParser(description="Topology-aware Docker inference recovery")
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("controller", "validate", "status"):
        p = commands.add_parser(command)
        p.add_argument("--config", required=True)
    p = commands.add_parser("agent")
    p.add_argument("--config", required=True)
    p = commands.add_parser("maintenance")
    p.add_argument("--config", required=True)
    p.add_argument("--group", required=True)
    p.add_argument("--state", choices=("on", "off"), required=True)
    p = commands.add_parser("unquarantine")
    p.add_argument("--config", required=True)
    p.add_argument("--group", required=True)
    p = commands.add_parser("audit-verify")
    p.add_argument("--directory", required=True)
    args = parser.parse_args(argv)
    if args.command == "agent":
        from .agent.http import main as agent_main
        return agent_main(["--config", args.config])
    if args.command == "audit-verify":
        print(json.dumps(verify(args.directory), indent=2))
        return
    config = load_config(args.config)
    if args.command == "validate":
        # 配置校验不绑定监听器；可选Gateway字段存在不表示原业务流量被接管。
        from .gateway import validate_config
        validate_config(config["gateway"])
        print(json.dumps({"valid": True, "mode": config["mode"],
                          "groups": [g["id"] for g in config["groups"]]}, indent=2))
    elif args.command == "controller":
        run_controller(config)
    elif args.command == "status":
        from .health.identity import readable_controller_state
        print(json.dumps(readable_controller_state(
            read_json(Path(config["state_dir"]) / "state.json", {"status": "not_started"}), config), indent=2))
    else:
        if args.group not in {g["id"] for g in config["groups"]}:
            parser.error("unknown group")
        action = "maintenance_" + args.state if args.command == "maintenance" else "unquarantine"
        cid = queue_command(config["state_dir"], args.group, action)
        print(json.dumps({"queued": cid, "action": action,
                          "note": "controller must consume command; inspect status/audit for completion"}))


if __name__ == "__main__":
    main()
