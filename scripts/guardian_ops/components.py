"""生成外部守护组件部署描述，并通过原生Docker管理精确的Agent/Controller对象。

模型不是可创建服务；未确认结果不自动重试，固定CID消失不自动重建。
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import subprocess

from inference_guardian.containers.contract import fingerprint

IMAGE = re.compile(r"sha256:[0-9a-f]{64}\Z")
CID = re.compile(r"[0-9a-f]{64}\Z")


def role_security_args(role):
    if role == "agent":
        return ["--privileged"]
    if role == "controller":
        return ["--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true"]
    raise ValueError("invalid Guardian security role")


def document(profile, node, controller, image, architecture, runtime, state, source_hash, *, deployment_id=None, seccomp_unconfined=()):
    """返回只含Agent和可选Controller的JSON兼容YAML描述。

    模型不增加挂载；仅Agent拿Docker socket及特权，Controller只读根文件系统且去除能力。
    持久状态单独读写挂载，配置/凭据只读；部署不依赖Compose执行。
    """
    identity = profile if deployment_id is None else deployment_id
    if not isinstance(identity, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}", identity):
        raise ValueError("safe stable deployment_id required")
    # 显式部署ID将同名目录中的不同实例隔离；旧配置沿用profile，避免静默改名。
    suffix = hashlib.sha256((identity + "/" + node).encode()).hexdigest()[:8]
    project = f"inference-guardian-{identity[:24]}-{node[:24]}-{suffix}"
    services = {}
    roles = ("agent", "controller") if controller else ("agent",)
    if not isinstance(seccomp_unconfined, (list, tuple)) or any(role not in roles for role in seccomp_unconfined):
        raise ValueError("invalid Guardian seccomp role selection")
    for service in roles:
        mounts = [{"type": "bind", "source": str(runtime), "target": "/etc/inference-guardian", "read_only": True},
                  {"type": "bind", "source": str(runtime / "secrets"), "target": "/run/secrets/inference-guardian", "read_only": True},
                  {"type": "bind", "source": str(state / service), "target": f"/var/lib/inference-guardian/{service}", "read_only": False}]
        # Docker写权限只交给本机Agent；Controller通过认证管理接口协调，不直接访问socket。
        if service == "agent":
            mounts.append({"type": "bind", "source": "/var/run/docker.sock", "target": "/var/run/docker.sock", "read_only": False})
        services[service] = {
            "image": image, "platform": "linux/" + architecture, "pull_policy": "never",
            "container_name": project + "-" + service, "network_mode": "host",
            "privileged": service == "agent", "read_only": service == "controller",
            "restart": "unless-stopped", "stop_grace_period": "150s" if service == "controller" else "10s",
            "command": [service, "--config", f"/etc/inference-guardian/{service}.json"],
            "volumes": [dict(mount, bind={"create_host_path": False}) for mount in mounts],
            "labels": {"guardian.deployment-kind": "external-adopt-v1", "guardian.profile": profile,
                       "guardian.node": node, "guardian.component": service, "guardian.source-sha256": source_hash},
            "logging": {"driver": "json-file", "options": {"max-size": "10m", "max-file": "5"}},
        }
        if deployment_id is not None:
            services[service]["labels"]["guardian.deployment-id"] = identity
        if service == "controller":
            services[service].update(cap_drop=["ALL"], security_opt=["no-new-privileges:true"])
        if service in seccomp_unconfined:
            services[service].setdefault("security_opt", []).append("seccomp=unconfined")
    return {"name": project, "services": services}


class GuardianDocker:
    """只允许守护组件的原生Docker适配器，严格核验名称、镜像、入口、挂载、权限及固定指纹。"""

    def __init__(self, desired, runner, audit, contracts=None):
        """校验期望服务与挂载契约；contracts由部署基线传入并维护。"""
        self.desired, self.runner, self.audit = desired, runner, audit
        self.contracts = contracts if contracts is not None else {}
        if set(desired.get("services", {})) not in ({"agent"}, {"agent", "controller"}):
            raise ValueError("only Agent and optional Controller may be deployed")
        for service, spec in desired["services"].items():
            if (not IMAGE.fullmatch(spec.get("image", "")) or spec.get("network_mode") != "host"
                    or spec.get("restart") != "unless-stopped" or spec.get("pull_policy") != "never"
                    or spec.get("platform") not in {"linux/arm64", "linux/amd64"}
                    or spec.get("command") != [service, "--config", f"/etc/inference-guardian/{service}.json"]
                    or spec.get("privileged") is not (service == "agent")):
                raise ValueError("invalid Guardian component contract")
            default_options = ["no-new-privileges:true"] if service == "controller" else []
            if spec.get("security_opt", []) not in (default_options, default_options + ["seccomp=unconfined"]):
                raise ValueError("invalid Guardian security options")
            for mount in spec["volumes"]:
                if (not Path(mount["source"]).is_absolute() or any(c in mount["source"] for c in (",", "\n", "\r", "\0", '"'))
                        or mount.get("type") != "bind" or mount.get("bind") != {"create_host_path": False}):
                    raise ValueError("Guardian bind paths must be absolute existing paths without CSV controls")

    def _run(self, tail, *, capture=True, timeout=30):
        """执行有限时本地Docker调用；错误表示未确认，不自动重复可能已生效的操作。"""
        try:
            result = self.runner(tail, capture=capture, timeout=timeout)
        except (OSError, subprocess.SubprocessError):
            raise ValueError("Docker outcome unknown; inspect before another operation") from None
        if result.returncode:
            raise ValueError("Docker operation unconfirmed; no automatic retry")
        return result

    def _json(self, tail):
        """要求有界且精确的单对象inspect响应，不接受模糊匹配或缺省猜测。"""
        result = self._run(tail)
        if not isinstance(result.stdout, str) or len(result.stdout) > 4 * 1024 * 1024:
            raise ValueError("Docker inspection unavailable or too large")
        try:
            data = json.loads(result.stdout)
        except (ValueError, TypeError):
            raise ValueError("Docker inspection invalid") from None
        if not isinstance(data, list) or len(data) != 1 or not isinstance(data[0], dict):
            raise ValueError("one exact inspected Docker object required")
        return data[0]

    def inspect(self, service, pinned=None):
        """检查守护组件是否符合完整部署契约，并返回稳定created/running/exited状态。

        仅尚未固定CID时确认不存在可返回None；固定后的缺失或差异均报错，不授权重建。
        """
        spec = self.desired["services"][service]
        listing = self._run(["container", "ls", "--all", "--format", "{{.Names}}"])
        if not isinstance(listing.stdout, str) or len(listing.stdout) > 4 * 1024 * 1024:
            raise ValueError("Docker inventory unavailable")
        if spec["container_name"] not in listing.stdout.splitlines():
            if pinned:
                raise ValueError("pinned Guardian component disappeared; replacement is forbidden")
            return None
        info = self._json(["container", "inspect", spec["container_name"]])
        config, host = info.get("Config", {}), info.get("HostConfig", {})
        labels = config.get("Labels") or {}
        mounts = {item.get("Destination"): item for item in info.get("Mounts", [])}
        wanted = {item["target"]: item for item in spec["volumes"]}
        if (not CID.fullmatch(info.get("Id", "")) or (pinned and info["Id"] != pinned)
                or info.get("Name") != "/" + spec["container_name"] or info.get("Image") != spec["image"]
                or any(labels.get(key) != value for key, value in spec["labels"].items())
                or config.get("Entrypoint") != ["python", "-m", "inference_guardian"]
                or config.get("WorkingDir") != "/opt/inference-guardian"
                or config.get("Cmd") != spec["command"]
                or config.get("StopTimeout") != int(spec["stop_grace_period"][:-1])
                or host.get("AutoRemove") is not False or host.get("NetworkMode") != "host"
                or host.get("Privileged") is not spec["privileged"]
                or host.get("ReadonlyRootfs") is not spec["read_only"]
                or host.get("RestartPolicy", {}).get("Name") != "unless-stopped"
                or set(mounts) != set(wanted)
                or any(mounts[target].get("Source") != str(Path(item["source"]))
                       or mounts[target].get("RW") is not (not item["read_only"]) for target, item in wanted.items())):
            raise ValueError("Guardian ownership, image, command, privilege or mounts differ")
        options = host.get("SecurityOpt") or []
        if service == "controller" and (host.get("CapDrop") != ["ALL"]
                or sorted(options) != sorted(spec["security_opt"])):
            raise ValueError("Controller security options differ from the deployment contract")
        # 历史 Agent 按已固定的完整 HostConfig 校验；新探测选择的策略同时核对。
        if service == "agent" and spec.get("security_opt"):
            observed = [opt for opt in options if opt.startswith(("seccomp=", "seccomp:"))]
            if observed != spec.get("security_opt", []):
                raise ValueError("Agent seccomp option differs from the deployment contract")
        # 即便名称/标签相同，也要对完整Config、HostConfig及Mounts作固定指纹校验。
        if service in self.contracts and fingerprint(info) != self.contracts[service]:
            raise ValueError("Guardian configuration differs from its pinned fingerprint")
        state = info.get("State", {})
        if (not isinstance(state.get("Running"), bool) or state.get("Status") not in {"created", "running", "exited"}
                or state["Running"] != (state["Status"] == "running")
                or any(state.get(key) for key in ("Paused", "Restarting", "Dead"))):
            raise ValueError("Guardian component state is not stable")
        return info

    def _change(self, tail, service, *, capture=True, timeout=120):
        """先记审计意图，再执行Docker并记结果；调用失败保留未确认记录。"""
        self.audit.emit("guardian_operation_intent", service=service, operation=tail[:2])
        try:
            result = self._run(tail, capture=capture, timeout=timeout)
        except ValueError:
            self.audit.emit("guardian_operation_unconfirmed", service=service, operation=tail[:2])
            raise
        self.audit.emit("guardian_operation_result", service=service, operation=tail[:2], confirmed=True)
        return result

    def create(self, service):
        """从已固定且本机存在的守护镜像创建停止态组件，不拉取镜像、不创建模型。"""
        spec = self.desired["services"][service]
        image = self._json(["image", "inspect", spec["image"]])
        if (image.get("Id") != spec["image"] or image.get("Os") != "linux"
                or image.get("Architecture") != spec["platform"].split("/")[1]):
            raise ValueError("pinned local Guardian image is unavailable")
        args = ["container", "create", "--name", spec["container_name"], "--pull", "never",
                "--platform", spec["platform"], "--network", "host", "--restart", "unless-stopped",
                "--stop-timeout", spec["stop_grace_period"][:-1]]
        args += role_security_args(service)
        if "seccomp=unconfined" in spec.get("security_opt", []):
            args += ["--security-opt", "seccomp=unconfined"]
        for mount in spec["volumes"]:
            args += ["--mount", "type=bind,source=" + mount["source"] + ",target=" + mount["target"]
                     + (",readonly" if mount["read_only"] else "")]
        for key, value in spec["labels"].items():
            args += ["--label", key + "=" + value]
        args += ["--log-driver", "json-file", "--log-opt", "max-size=10m", "--log-opt", "max-file=5",
                 spec["image"], *spec["command"]]
        self._change(args, service)
        info = self.inspect(service)
        if not info or info["State"]["Running"]:
            raise ValueError("stopped Guardian creation was not confirmed")
        return info

    def transition(self, service, action, pinned):
        """只对核对后的守护CID执行start/stop，再inspect确认目标状态；不操作模型CID。"""
        if action not in {"start", "stop"}:
            raise ValueError("only start/stop Guardian transitions are allowed")
        info = self.inspect(service, pinned)
        if info is None:
            raise ValueError("Guardian component does not exist")
        if info["State"]["Running"] == (action == "start"):
            return info
        seconds = int(self.desired["services"][service]["stop_grace_period"][:-1])
        args = ["container", action, *( ["--time", str(seconds)] if action == "stop" else [] ), info["Id"]]
        self._change(args, service, timeout=max(120, seconds + 20))
        result = self.inspect(service, info["Id"])
        if not result or result["State"]["Running"] != (action == "start"):
            self.audit.emit("guardian_target_unconfirmed", service=service, action=action)
            raise ValueError("Guardian target state unconfirmed; no automatic retry")
        return result

    def logs(self, service, pinned):
        """核对守护组件身份后读取日志，避免同名替换对象被误当成原组件。"""
        info = self.inspect(service, pinned)
        if info is None:
            raise ValueError("Guardian component does not exist")
        return self._run(["container", "logs", "--tail", "200", info["Id"]], capture=False)

    def retire(self, service, cid, name, inspect_container):
        """保留旧CID供人工回退；停用自动拉起并重命名后确认，不重试未知结果。"""
        self._change(['container', 'update', '--restart', 'no', cid], service)
        self._change(['container', 'rename', cid, name], service)
        observed = inspect_container(['container', 'inspect', cid])
        if observed['State']['Running'] or observed['Name'] != '/' + name or observed['HostConfig']['RestartPolicy']['Name'] != 'no':
            raise ValueError('retired Guardian state not confirmed')
        return dict(id=cid, name=name)

    def remove(self, service, cid):
        """只删除核验过的停止态守护CID；不强制停止、不删卷，未知结果不重试。"""
        info = self.inspect(service, cid)
        if not info or info['State']['Running']:
            raise ValueError('Guardian must be confirmed stopped before removal')
        self._change(['container', 'rm', cid], service)
        listing = self._run(['container', 'ls', '--all', '--no-trunc', '--format', '{{.ID}}'])
        ids = listing.stdout.split() if isinstance(listing.stdout, str) else None
        if ids is None or any(not CID.fullmatch(value) for value in ids) or cid in ids:
            raise ValueError('Guardian removal unconfirmed; no automatic retry')
        return dict(removed_id=cid)
