"""宿主机部署CLI：接管既有模型容器，只部署外部Agent与Controller。

安装流程不创建、启停、重命名或exec模型；运行期原脚本执行由Node Agent负责。
源配置、模型身份、守护组件和凭据均固化到基线，差异必须走维护迁移流程。
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import platform
import re
import ssl
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
from .release_files import digest, private_dir
from .profile import Profile, check_startup_contract
from .credentials import remap_secrets, credentials
from .components import CID, IMAGE, GuardianDocker, document
from .preflight import check_local as check_mooncake_local
from .mooncake_contract import DEPLOYMENT_ID, RETIRED_DEPLOYMENT_IDS, PROFILE, node_commands, validate_manifest
from inference_guardian import read_source_version
from inference_guardian.observability.audit import AuditLog
from inference_guardian.control.config import config_hash, validate as validate_controller
from inference_guardian.containers.contract import bootstrap_stage_hashes, fingerprint, simple_shell_pid1
from inference_guardian.agent.client import NodeClient
from inference_guardian.control.service import queue_command
from inference_guardian.gateway import validate_config as validate_gateway
from inference_guardian.agent.config import validate_config as validate_agent
from inference_guardian.health.probes import run_probe
from inference_guardian.health.identity import readable_controller_state
from .probe_config import validate_profile_probes
from inference_guardian.storage import FileLock, atomic_json, read_json
from inference_guardian.control.topology import canary_specs, recovery_steps

NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\Z")
SECRET_ROOT = "/run/secrets/inference-guardian/"
# 名称/挂载变更必须显式迁移旧基线，不能把新默认目录当成无历史的新部署。
NAMING_VERSION = "inference-guardian-v1"
DEFAULT_INSTALL_ROOT = Path("/data/scripts/inference-guardian")
DEFAULT_STATE_ROOT = DEFAULT_INSTALL_ROOT / "state"
DEFAULT_RUNTIME_ROOT = DEFAULT_INSTALL_ROOT / "runtime"
DEFAULT_SECRETS_DIR = DEFAULT_INSTALL_ROOT / "secrets"
PREVIOUS_STATE_ROOT = Path("/data/inference-guardian")
LEGACY_STATE_ROOT = Path("/data/guardian")
FILE_KEYS = {"token_file", "ca_file", "cert_file", "key_file", "tls_cert_file", "tls_key_file",
             "client_token_file", "upstream_token_file", "tokenizer_token_file"}


def default_guardian_image():
    """从本份源码元数据选默认标签；显式image ID仍优先，禁止回退到旧版本。"""
    return f"inference-guardian:{read_source_version(ROOT)}"


# 保留旧导入名称；部署门槛与运行期Agent必须使用同一条窄入口识别规则。
plain_shell = simple_shell_pid1


def host_architecture():
    """要求原生Linux Docker宿主，统一返回arm64或amd64；开发机Windows不能直接部署。"""
    if sys.platform != "linux":
        raise ValueError("native deployment requires a Linux Docker host")
    machine = platform.machine().lower()
    if machine in {"arm64", "aarch64"}:
        return "arm64"
    if machine in {"amd64", "x86_64"}:
        return "amd64"
    raise ValueError("unsupported native host architecture")


def run_command(argv, **kwargs):
    """以参数列表调用本地程序，不启用宿主shell，供测试替身注入同一调用契约。"""
    return subprocess.run(argv, shell=False, **kwargs)


class GuardianDeployment:
    """一次宿主部署/运维操作的上下文：模型只读接管，守护容器受契约管理。

    所有写操作串行持有deployment.lock；配置与对象变化拒绝静默覆盖，以保存历史预算和身份。
    """
    def __init__(self, profile, node, *, controller_node=None, state_root=DEFAULT_STATE_ROOT,
                 runtime_dir=None, runner=run_command, host_check=host_architecture,
                 credential_check=credentials, probe=run_probe, clock=time.time, sleeper=time.sleep,
                 node_client_factory=NodeClient):
        """解析节点角色、模板与持久目录，构造源配置指纹；此阶段不操作Docker。"""
        loaded = Profile(profile, node, controller_node)
        self.profile = loaded.profile
        self.node = loaded.node
        self.controller_source = loaded.controller_source
        self.source_controller = loaded.source_controller
        self.explicit_deployment_id = loaded.explicit_deployment_id
        self.deployment_id = loaded.deployment_id
        self.controller_node = loaded.controller_node
        self.is_controller = loaded.is_controller
        self.agents = loaded.agents
        self.source_manifest = loaded.source_manifest
        self.source_hash = loaded.source_hash
        self.state = Path(state_root).resolve() / self.deployment_id / node
        self.runtime = Path(runtime_dir).resolve() if runtime_dir else DEFAULT_RUNTIME_ROOT.resolve() / self.deployment_id / node
        self.baseline_path = self.runtime / "adoption.json"
        self.runner, self.host_check, self.credential_check = runner, host_check, credential_check
        self.probe, self.clock, self.sleep = probe, clock, sleeper
        self.node_client_factory = node_client_factory

    def _source(self, preferred, fallback):
        """交付统一使用external命名，仍读取旧配置后备名；不创建或迁移输入文件。

        源指纹来自已解析内容而非文件名，仅改Agent文件名不会改变接管身份。
        """
        return self.profile / (preferred if (self.profile / preferred).is_file() else fallback)

    def docker_command(self, tail, *, capture=True, timeout=30):
        """固定访问本机Unix Docker socket，并清除可能改写目标Engine的环境变量。"""
        # 防止运维终端遗留的远程Docker context让本机接管误操作另一台Engine。
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith("COMPOSE_") and key not in {
                           "DOCKER_CONTEXT", "DOCKER_HOST", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "DOCKER_API_VERSION"}}
        return self.runner(["docker", "--host", "unix:///var/run/docker.sock", *tail],
                           env=environment, capture_output=capture, text=True, timeout=timeout)

    def inspect_docker(self, tail):
        """读取单个Docker对象，限制输出大小；列表为空或含多个对象均拒绝猜测。"""
        result = self.docker_command(tail)
        if result.returncode or not isinstance(result.stdout, str) or len(result.stdout) > 4 * 1024 * 1024:
            raise ValueError("local Docker inspection failed")
        data = json.loads(result.stdout)
        if not isinstance(data, list) or len(data) != 1 or not isinstance(data[0], dict):
            raise ValueError("one exact local Docker object required")
        return data[0]

    def inspect_engine(self):
        """核对Linux宿主与Engine架构，从已审阅的1.45/1.41中选Server支持的最高版本。"""
        architecture = self.host_check()
        server = self.inspect_docker(["version", "--format", "[{{json .Server}}]"])
        if architecture not in {"arm64", "amd64"} or server.get("Os") != "linux" or server.get("Arch") != architecture:
            raise ValueError("local Docker Engine and native host architecture differ")
        def version(value):
            if not isinstance(value, str) or not re.fullmatch(r"v?\d+\.\d+", value):
                raise ValueError("Engine API compatibility metadata is unavailable")
            # 宿主Python3.7没有str.removeprefix；前面已限定可选的单个v前缀。
            return tuple(map(int, (value[1:] if value.startswith("v") else value).split(".")))
        low, high = version(server.get("MinAPIVersion")), version(server.get("ApiVersion"))
        selected = next((api for api in ("v1.45", "v1.41") if low <= version(api) <= high), None)
        if selected is None:
            raise ValueError("Engine does not support reviewed Agent API 1.41 or 1.45")
        return architecture, selected

    def inspect_model(self, name):
        """只读核实精确名称的既有模型容器，返回完整CID、image ID及配置指纹。

        禁止AutoRemove及独立自动重启策略，避免stop后对象消失或与Controller竞争；不会修正原配置。
        """
        result = self.docker_command(["container", "ls", "--all", "--format", "{{.Names}}"])
        if result.returncode or not isinstance(result.stdout, str) or len(result.stdout) > 4 * 1024 * 1024:
            raise ValueError("container inventory unavailable; absence is not confirmed")
        if name not in result.stdout.splitlines():
            raise ValueError("every allowlisted model container must already exist")
        info = self.inspect_docker(["container", "inspect", name])
        host = info.get("HostConfig", {})
        if (info.get("Name") != "/" + name or not CID.fullmatch(info.get("Id", ""))
                or not IMAGE.fullmatch(info.get("Image", "")) or host.get("AutoRemove") is not False
                or host.get("RestartPolicy", {}).get("Name") not in {"", "no"}):
            raise ValueError("model identity or stop/start lifecycle is unsafe")
        return info, {"expected_container_id": info["Id"], "expected_image_id": info["Image"],
                      "expected_config_hash": fingerprint(info)}

    def _lock(self):
        """确保私有状态目录存在，返回本节点部署操作的唯一写入锁。"""
        self.require_naming_compatibility()
        private_dir(self.state)
        return FileLock(self.state / "deployment.lock")

    def require_naming_compatibility(self):
        """只读拒绝旧命名基线和默认旧状态残留，不创建空状态或自动搬移历史。"""
        baseline = read_json(self.baseline_path, {})
        if baseline and baseline.get("naming_version") != NAMING_VERSION:
            raise ValueError("legacy naming baseline; explicit maintenance migration is required")
        if baseline and baseline.get("deployment_id", baseline.get("profile")) != self.deployment_id:
            raise ValueError("deployment identity changed; preserve the existing baseline and explicitly migrate")
        if self.deployment_id == DEPLOYMENT_ID:
            # 检查默认和当前自定义根目录；不能将改名理解为可丢弃历史的新安装。
            roots = {self.state.parent.parent, DEFAULT_STATE_ROOT.resolve(), PREVIOUS_STATE_ROOT.resolve(), LEGACY_STATE_ROOT.resolve()}
            for root in roots:
                for previous in RETIRED_DEPLOYMENT_IDS:
                    path = root / previous / self.node
                    if path.exists() or path.is_symlink():
                        raise ValueError("retired deployment state exists; maintenance migration and archival required")
        for root in (PREVIOUS_STATE_ROOT, LEGACY_STATE_ROOT):
            legacy = root.resolve() / self.deployment_id / self.node
            if legacy != self.state and (legacy.exists() or legacy.is_symlink()):
                raise ValueError("legacy state directory exists; preserve journals and explicitly migrate before adoption")
        for profile in {self.profile, DEFAULT_INSTALL_ROOT / "examples/vllm-ascend" / PROFILE}:
            legacy = profile / ".runtime" / self.node
            if legacy != self.runtime and (legacy.exists() or legacy.is_symlink()):
                raise ValueError("legacy runtime directory exists; explicit maintenance migration required")

    def audit_log(self):
        """打开本机部署审计；链验证或持久化失败应阻止后续变更。"""
        return AuditLog(self.state / "deployment-audit")

    def _check_retired_containers(self, names):
        """只读拒绝旧ID组件（含被改名但保留标签的组件），避免启动第二套写入者。"""
        if self.deployment_id != DEPLOYMENT_ID:
            return
        for identity in RETIRED_DEPLOYMENT_IDS:
            suffix = hashlib.sha256((identity + "/" + self.node).encode()).hexdigest()[:8]
            for prefix in ("guardian", "inference-guardian"):
                project = f"{prefix}-{identity[:24]}-{self.node[:24]}-{suffix}"
                if {project + "-agent", project + "-controller"} & set(names):
                    raise ValueError("retired deployment containers exist; explicit maintenance migration required")
            observed = self.docker_command(["container", "ls", "--all", "--filter", "label=guardian.deployment-id=" + identity,
                                  "--filter", "label=guardian.node=" + self.node, "--format", "{{.Names}}"])
            if (observed.returncode or not isinstance(observed.stdout, str) or len(observed.stdout) > 4 * 1024 * 1024):
                raise ValueError("retired deployment inventory unavailable; absence is not confirmed")
            if observed.stdout.strip():
                raise ValueError("retired deployment labels exist; explicit maintenance migration required")

    def inspect_baseline(self):
        """复核接管基线、所有本机模型三项PIN、运行配置与凭据哈希。

        Controller的mode允许通过受控命令改变；其余配置不因重复adopt或up而自动更新。
        """
        self.require_naming_compatibility()
        baseline = read_json(self.baseline_path, {})
        if (baseline.get("version") != 1 or baseline.get("kind") != "external-adopt-v1"
                or baseline.get("profile") != self.profile.name or baseline.get("node") != self.node
                or baseline.get("deployment_id", baseline.get("profile")) != self.deployment_id
                or baseline.get("source_hash") != self.source_hash or baseline.get("runtime") != str(self.runtime)
                or baseline.get("state") != str(self.state) or baseline.get("controller_node") != self.controller_node):
            raise ValueError("adopt first; source, role or deployment paths must match the pinned baseline")
        for name, expected in baseline["models"].items():
            _, actual = self.inspect_model(name)
            if actual != expected:
                raise ValueError("adopted model identity, image or configuration changed")
        agent = validate_agent(read_json(self.runtime / "agent.json"))
        if digest(agent) != baseline["agent_hash"]:
            raise ValueError("runtime Agent configuration differs from adoption baseline")
        if self.is_controller:
            controller = validate_controller(read_json(self.runtime / "controller.json"))
            if digest({key: value for key, value in controller.items() if key != "mode"}) != baseline["controller_hash"]:
                raise ValueError("runtime Controller configuration differs from adoption baseline")
        for name, checksum in baseline["secret_hashes"].items():
            path = self.runtime / "secrets" / name
            if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != checksum:
                raise ValueError("runtime credentials differ from adoption baseline")
        return baseline

    def component_manager(self, baseline, audit):
        """构造只含Agent/Controller的期望部署及受控Docker适配器。"""
        desired = document(self.profile.name, self.node, self.is_controller, baseline["guardian_image"],
                           baseline["architecture"], self.runtime, self.state, self.source_hash,
                           deployment_id=self.deployment_id if self.explicit_deployment_id else None,
                           seccomp_unconfined=baseline.get("seccomp_unconfined", ()))
        return GuardianDocker(desired, self._run, audit, baseline.setdefault("component_hashes", {}))


    def validate_startup_contract(self):
        """兼容既有调用；校验逻辑集中在配置模块。"""
        return check_startup_contract(self.agents, self.source_controller, self.source_manifest)

    def _local_startup_contract(self):
        """拒绝缺少静态启动阶段的空闲Shell容器，避免start后只有Bash而没有模型。"""
        for entry in self.agents[self.node]["containers"]:
            info, _ = self.inspect_model(entry["name"])
            self.validate_model_files(info)
            if plain_shell(info) and not entry.get("bootstrap_commands"):
                raise ValueError("an existing Bash/sh container requires static bootstrap commands before auto mode")

    def validate_model_files(self, info):
        """当前场景在接管和本地启用auto前核对/data挂载与启动配置引用，不运行脚本。"""
        if self.source_manifest is not None:
            # 当前场景清单已在构造期强制验证并计入接管指纹，不能因缺失静默跳过。
            check_mooncake_local(info, self.node, self.source_manifest)

    def prepare_adoption(self, secrets_dir, guardian_image):
        """只读构造候选基线；升级器须先验证旧基线及维护屏障才可发布。"""
        architecture, api = self.inspect_engine()
        self.validate_startup_contract()
        image = self.inspect_docker(["image", "inspect", guardian_image])
        if (not IMAGE.fullmatch(image.get("Id", "")) or image.get("Os") != "linux" or image.get("Architecture") != architecture
                or image.get("Config", {}).get("Entrypoint") != ["python", "-m", "inference_guardian"]
                or image.get("Config", {}).get("WorkingDir") != "/opt/inference-guardian"
                or (image.get("Config", {}).get("Labels") or {}).get("guardian.external-contract") != "1"):
            raise ValueError("Guardian image must be local, native and match the delivered entrypoint and working directory")
        agent = copy.deepcopy(self.agents[self.node])
        models = {}
        for entry in agent["containers"]:
            info, pin = self.inspect_model(entry["name"])
            self.validate_model_files(info)
            for key, value in pin.items():
                if key in entry and entry[key] != value:
                    raise ValueError("source Agent pin differs from the existing model")
            entry.update(pin)
            models[entry["name"]] = pin
        agent.update(node_id=self.node, docker_api_version=api, state_dir="/var/lib/inference-guardian/agent")
        references = {}
        agent = validate_agent(remap_secrets(agent, references))
        controller = None
        if self.is_controller:
            controller = copy.deepcopy(self.source_controller)
            controller.update(mode="observe", state_dir="/var/lib/inference-guardian/controller")
            # 将每个节点的完整启动契约纳入Controller运行配置，供持续监测而非仅切auto时复核。
            for identifier, node in controller["nodes"].items():
                node["expected_bootstrap_stage_hashes"] = {
                    entry["name"]: bootstrap_stage_hashes(entry.get("bootstrap_commands", {}))
                    for entry in self.agents[identifier]["containers"]}
            controller = validate_controller(remap_secrets(controller, references))
            if controller["gateway"].get("enabled", True):
                validate_gateway(controller["gateway"])
        secret_data = self.credential_check(Path(secrets_dir), references, agent)
        if set(secret_data) != set(references) or any(not isinstance(value, bytes) or not value for value in secret_data.values()):
            raise ValueError("credential checker must return exactly the referenced nonempty files")
        baseline = {"version": 1, "kind": "external-adopt-v1", "naming_version": NAMING_VERSION,
                    "profile": self.profile.name, "node": self.node,
                    "deployment_id": self.deployment_id,
                    "controller_node": self.controller_node, "source_hash": self.source_hash, "models": models,
                    "runtime": str(self.runtime), "state": str(self.state), "architecture": architecture,
                    "guardian_image": image["Id"], "agent_hash": digest(agent),
                    "controller_hash": digest({key: value for key, value in controller.items() if key != "mode"}) if controller else None,
                    "secret_hashes": {name: hashlib.sha256(data).hexdigest() for name, data in secret_data.items()}}
        return baseline, agent, controller, secret_data

    def adopt(self, secrets_dir, guardian_image=None, *, seccomp_unconfined=()):
        """只读接管模型，固定身份与配置，生成守护组件运行配置和最小凭据副本。

        已有基线时只允许一致的重复接管；凭据轮换、镜像变化和配置升级须显式维护。
        生成inference-guardian-node.yaml仅用于查看/校验，安装不运行模型脚本，也不启动守护容器。
        """
        # 第一阶段只读检查：Engine、守护镜像、原模型及静态配置先全部核对。
        if guardian_image is None:
            guardian_image = default_guardian_image()
        self.require_naming_compatibility()
        architecture, api = self.inspect_engine()
        # 防止源码/runtime目录被搬走后，在仍有旧守护容器的宿主上启动第二套写入者。
        suffix = hashlib.sha256((self.deployment_id + "/" + self.node).encode()).hexdigest()[:8]
        legacy_project = f"guardian-{self.deployment_id[:24]}-{self.node[:24]}-{suffix}"
        inventory = self.docker_command(["container", "ls", "--all", "--format", "{{.Names}}"])
        if (inventory.returncode or not isinstance(inventory.stdout, str)
                or len(inventory.stdout) > 4 * 1024 * 1024):
            raise ValueError("container inventory unavailable; legacy deployment absence is not confirmed")
        if {legacy_project + "-agent", legacy_project + "-controller"} & set(inventory.stdout.splitlines()):
            raise ValueError("legacy Guardian containers exist; explicit maintenance migration is required")
        self._check_retired_containers(inventory.stdout.splitlines())
        baseline, agent, controller, secret_data = self.prepare_adoption(secrets_dir, guardian_image)
        if seccomp_unconfined:
            baseline["seccomp_unconfined"] = list(seccomp_unconfined)
        models, api = baseline["models"], agent["docker_api_version"]
        # 第二阶段在本机唯一锁下落盘；旧基线不一致时拒绝覆盖和清空历史。
        with self._lock():
            old = read_json(self.baseline_path, {})
            if old:
                previous = {"deployment_id": old.get("profile"), **old}
                if any(previous.get(key) != value for key, value in baseline.items()):
                    raise ValueError("adoption baseline changed; explicit maintenance migration is required")
                self.inspect_baseline()
                baseline = old
                if controller:
                    controller = validate_controller(read_json(self.runtime / "controller.json"))
            audit = self.audit_log()
            backend = self.component_manager(baseline, audit)
            if any(spec["container_name"] in models for spec in backend.desired["services"].values()):
                raise ValueError("Guardian names must not collide with adopted model names")
            for service in backend.desired["services"]:
                backend.inspect(service, baseline.get("components", {}).get(service))
            audit.emit("models_adopted", node=self.node, source_hash=self.source_hash, models=models,
                       guardian_image=baseline["guardian_image"], agent_api=api)
            private_dir(self.runtime)
            private_dir(self.runtime / "secrets")
            for service in backend.desired["services"]:
                private_dir(self.state / service)
            for name, data in secret_data.items():
                target = self.runtime / "secrets" / name
                if target.is_symlink() or (target.exists() and target.read_bytes() != data):
                    raise ValueError("credential rotation requires explicit maintenance")
                if target.exists():
                    continue
                descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
            atomic_json(self.runtime / "agent.json", agent)
            if controller:
                atomic_json(self.runtime / "controller.json", controller)
            # JSON属于YAML兼容子集；描述只含守护组件，CLI仍通过原生Docker执行。
            atomic_json(self.runtime / "inference-guardian-node.yaml", backend.desired)
            atomic_json(self.baseline_path, baseline)
        return {"adopted": list(models), "node": self.node, "mode": controller["mode"] if controller else None,
                "agent_api": api, "model_mutations": 0, "runtime": str(self.runtime)}

    def _controller(self, baseline, backend, require_running=True):
        """限制运维命令在选定Controller节点执行，并复核固定守护容器的身份及状态。"""
        if not self.is_controller:
            raise ValueError("this command belongs on the configured Controller node")
        info = backend.inspect("controller", baseline.get("components", {}).get("controller"))
        if not info or (require_running and not info["State"]["Running"]):
            raise ValueError("Controller component is not running")
        return info, validate_controller(read_json(self.runtime / "controller.json"))

    def controller_state(self):
        """读取Controller已发布的持久状态；不存在时按空状态处理，不伪造就绪。"""
        return read_json(self.state / "controller" / "state.json", {})

    def _quiet(self, config, target):
        """要求没有进行中的恢复；从auto重载observe时还需已消费的维护屏障及空命令队列。"""
        state = self.controller_state()
        runtimes = [state.get("groups", {}).get(group["id"], {}) for group in config["groups"]]
        if any(runtime.get("recovery_inflight") or runtime.get("phase") in {"DRAINING", "SNAPSHOT", "STOPPING", "STARTING", "VALIDATING"} for runtime in runtimes):
            raise ValueError("group recovery is in flight")
        if target == "observe" and (config["mode"] == "auto" or state.get("config_hash") != config_hash(config)):
            if (any(runtime.get("maintenance") is not True or runtime.get("phase") != "MAINTENANCE" for runtime in runtimes)
                    or any((self.state / "controller" / "commands").glob("*.json"))):
                raise ValueError("observe reload requires consumed maintenance and no pending commands")

    def probe_passes(self, spec, timeout):
        """把模板凭据重映射到本机副本后执行探针，只接受明确pass。"""
        local = remap_secrets(spec, {}, directory=self.runtime / "secrets")
        return self.probe(local, timeout).state == "pass"

    def require_clear_journals(self, config, *, require_startup=False):
        """逐节点核实变更台账清晰；启用auto时还需每个容器的启动契约标志完整。"""
        for identifier, node in config["nodes"].items():
            check = {key: value for key, value in node.items() if key in FILE_KEYS or key == "allow_insecure_http"}
            check.update(url=node["url"].rstrip("/") + "/v1/status", timeout_seconds=20,
                         json_checks=[{"path": "mutation_journal_clear", "op": "equals", "value": True}])
            local = remap_secrets(check, {}, directory=self.runtime / "secrets")
            result = self.probe(local, 20)
            if result.state != "pass":
                raise ValueError("node mutation journal is busy, unknown or unavailable")
            if not isinstance(result.data, dict) or result.data.get("node_id") != identifier:
                raise ValueError("node mutation journal identity is unavailable or differs from the profile")
            if require_startup:
                containers = result.data.get("containers")
                expected = {entry["name"] for entry in self.agents[identifier]["containers"]}
                if not isinstance(containers, dict) or set(containers) != expected:
                    raise ValueError("remote model startup contracts are unavailable or differ from the profile")
                for entry in self.agents[identifier]["containers"]:
                    status = containers[entry["name"]]
                    if (not isinstance(status, dict) or type(status.get("requires_bootstrap")) is not bool
                            or type(status.get("bootstrap_configured")) is not bool
                            or (status["requires_bootstrap"] and not status["bootstrap_configured"])):
                        raise ValueError("remote model requires static bootstrap commands before auto mode")
                    # 比较全部阶段及规范化命令摘要；布尔标志不能证明远端部署了同一启动契约。
                    expected_hashes = bootstrap_stage_hashes(entry.get("bootstrap_commands", {}))
                    if (not isinstance(status.get("bootstrap_stage_hashes"), dict)
                            or status["bootstrap_stage_hashes"] != expected_hashes
                            or status["bootstrap_configured"] is not bool(expected_hashes)):
                        raise ValueError("remote model bootstrap stage hashes differ from the profile")

    def require_fresh_readiness(self, config):
        """验证当前配置下每组的新鲜轻检查与canary证据，过期或维护状态不能用来启用auto。"""
        state, now = self.controller_state(), self.clock()
        if state.get("config_hash") != config_hash(config):
            raise ValueError("fresh readiness requires the current Controller config hash")
        for group in config["groups"]:
            runtime = state.get("groups", {}).get(group["id"], {})
            if (runtime.get("phase") not in {"READY", "RAMP_UP"} or runtime.get("maintenance")
                    or runtime.get("recovery_inflight") or runtime.get("canary_ok") is not True):
                raise ValueError("fresh complete readiness is required")
            if group.get("process_exit_detection") and runtime.get("process_exit_armed") is not True:
                raise ValueError("verified engine process identity baseline is required before acceptance or auto mode")
            for field, limit in (("last_observed_at", "readiness_ttl_seconds"), ("last_canary", "canary_max_age_seconds")):
                value = runtime.get(field)
                if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= now - value <= config["policy"][limit]:
                    raise ValueError("fresh complete readiness is required")

    def up(self):
        """创建缺失且尚未固定身份的守护组件并启动；已固定组件消失时拒绝替换。

        回写组件CID与配置指纹供后续核对，不触及模型生命周期。
        """
        self.host_check()
        with self._lock():
            baseline = self.inspect_baseline()
            backend = self.component_manager(baseline, self.audit_log())
            observed = {service: backend.inspect(service, baseline.get("components", {}).get(service))
                        for service in backend.desired["services"]}
            if self.is_controller:
                config = validate_controller(read_json(self.runtime / "controller.json"))
                if config["mode"] != "observe":
                    raise ValueError("manual Guardian startup requires observe mode")
                if observed["controller"] and observed["controller"]["State"]["Running"]:
                    self._quiet(config, "observe")
                    if self.controller_state().get("config_hash") != config_hash(config):
                        raise ValueError("running Controller config has not converged")
            for service, info in observed.items():
                info = info or backend.create(service)
                baseline.setdefault("components", {})[service] = info["Id"]
                baseline["component_hashes"][service] = fingerprint(info)
                atomic_json(self.baseline_path, baseline)
                backend.transition(service, "start", info["Id"])
        return {"started": list(observed), "models_untouched": True, "mode": "observe" if self.is_controller else None}

    def set_mode(self, mode):
        """按受控门槛重载Controller模式，只启停Controller、不启停模型。

        auto要求启动契约、所有健康和真实canary、全部台账以及新鲜状态；探针后再次核对，避免等待期间状态变化。
        """
        if mode not in {"observe", "auto"}:
            raise ValueError("mode must be observe or auto")
        self.host_check()
        with self._lock():
            baseline = self.inspect_baseline()
            audit = self.audit_log()
            backend = self.component_manager(baseline, audit)
            info, config = self._controller(baseline, backend, require_running=mode == "auto")
            running = info["State"]["Running"]
            if running and config["mode"] == mode and self.controller_state().get("config_hash") == config_hash(config):
                return {"mode": mode, "changed": False}
            if running:
                self._quiet(config, mode)
                self.require_clear_journals(config, require_startup=mode == "auto")
            if mode == "auto":
                self.validate_startup_contract()
                self._local_startup_contract()
                self.require_fresh_readiness(config)
                for group in config["groups"]:
                    if not all(self.probe_passes(check, 5) for check in [*group["health_checks"], *canary_specs(group)]):
                        raise ValueError("every engine and real canary must pass before auto")
                gateway = config["gateway"]
                if gateway.get("enabled", True):
                    host = gateway["listen_host"]
                    host = "127.0.0.1" if host in {"0.0.0.0", "::"} else host
                    if not self.probe_passes({"url": f"http://{host}:{gateway['listen_port']}/readyz"}, 5):
                        raise ValueError("Gateway readiness must pass before auto")
                self.require_clear_journals(config, require_startup=True)
                self.require_fresh_readiness(config)
            if running:
                self._quiet(config, mode)
            audit.emit("controller_mode_change", previous=config["mode"], mode=mode)
            backend.transition("controller", "stop", info["Id"])
            config["mode"] = mode
            atomic_json(self.runtime / "controller.json", config)
            backend.transition("controller", "start", info["Id"])
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                observed = backend.inspect("controller", info["Id"])
                if observed and observed["State"]["Running"] and self.controller_state().get("config_hash") == config_hash(config):
                    break
                self.sleep(0.1)
            else:
                raise ValueError("Controller loaded configuration was not confirmed")
        return {"mode": mode, "changed": True, "models_untouched": True}

    def maintenance(self, state):
        """审计并入队所有组的维护命令；queued不代表已消费，必须再检查Controller状态。

        退出维护前验证健康和canary；外部模式的维护不阻断原Proxy业务流量。
        """
        if state not in {"on", "off"}:
            raise ValueError("maintenance must be on or off")
        self.host_check()
        with self._lock():
            baseline = self.inspect_baseline()
            audit = self.audit_log()
            backend = self.component_manager(baseline, audit)
            _, config = self._controller(baseline, backend)
            if state == "off":
                for group in config["groups"]:
                    if not all(self.probe_passes(check, 5) for check in [*group["health_checks"], *canary_specs(group)]):
                        raise ValueError("restore all engines and real canaries before leaving maintenance")
            queued = []
            for group in config["groups"]:
                audit.emit("maintenance_intent", group=group["id"], state=state)
                identifier = queue_command(self.state / "controller", group["id"], "maintenance_" + state)
                audit.emit("maintenance_queued", group=group["id"], state=state, command_id=identifier)
                queued.append(identifier)
        return {"queued": queued, "maintenance": state, "note": "queueing is not confirmation; inspect consumed state"}

    def require_resolution_maintenance(self, config, group):
        """要求当前配置、已消费维护、无在途恢复及无待消费命令，形成手工对账屏障。"""
        state = self.controller_state()
        runtime = state.get("groups", {}).get(group["id"], {})
        if (state.get("config_hash") != config_hash(config) or runtime.get("maintenance") is not True
                or runtime.get("phase") != "MAINTENANCE" or runtime.get("recovery_inflight") is not False
                or any((self.state / "controller" / "commands").glob("*.json"))):
            raise ValueError("resolution requires consumed maintenance, matching config, no in-flight recovery and no pending commands")

    def _resolution_models(self, client, group, config):
        """绕过短缓存，逐节点重新读取全组停止状态和固定身份；不派发任何模型动作。"""
        observed = {}
        for node in {member["node"] for member in group["members"]}:
            # 人工解除Unknown必须取新鲜观测，不能沿用此前节点状态短缓存。
            response = client.call(node, "/v1/status", timeout=config["nodes"][node].get("status_timeout_seconds", 20))
            containers = response.get("containers") if isinstance(response, dict) else None
            if not isinstance(containers, dict):
                raise ValueError("every group member must have a fresh confirmed stopped observation")
            observed[node] = containers
        identities = {}
        for member in group["members"]:
            status = observed[member["node"]].get(member["container"])
            if (not isinstance(status, dict) or status.get("running") is not False
                    or status.get("configuration_ok") is not True
                    or not CID.fullmatch(status.get("container_id", ""))
                    or not IMAGE.fullmatch(status.get("image_id", ""))):
                raise ValueError("all group models must be stopped with confirmed pinned identities before resolution")
            identities[member["id"]] = {"node": member["node"], "container": member["container"],
                                         "container_id": status["container_id"], "image_id": status["image_id"]}
        return identities

    def resolve_bootstrap(self, group_id, reason, operation_id=None):
        """仅人工解除全组已确认停止后的bootstrap不确定记录，不执行模型变更。

        operation_id固定成员action ID、身份与reason哈希；部分失败须用原operation_id及原reason续接。
        每次节点派发前重查维护及全组停止，接收端Agent再次核验三PIN；不清台账或恢复预算。
        """
        if not isinstance(reason, str) or not 1 <= len(reason) <= 256 or not reason.isprintable():
            raise ValueError("resolution reason must contain 1-256 printable characters")
        operation_id = operation_id or uuid.uuid4().hex
        if not isinstance(operation_id, str) or not NAME.fullmatch(operation_id):
            raise ValueError("operation ID must be a safe identifier of at most 80 characters")
        reason_hash = hashlib.sha256(reason.encode("utf-8")).hexdigest()
        self.host_check()
        with self._lock():
            baseline = self.inspect_baseline()
            audit = self.audit_log()
            backend = self.component_manager(baseline, audit)
            info, config = self._controller(baseline, backend)
            group = next((entry for entry in config["groups"] if entry["id"] == group_id), None)
            if group is None:
                raise ValueError("unknown recovery group")
            self.require_resolution_maintenance(config, group)
            nodes = remap_secrets(config["nodes"], {}, directory=self.runtime / "secrets")
            client = self.node_client_factory(nodes, config["policy"]["request_timeout_seconds"])
            identities = self._resolution_models(client, group, config)
            private_dir(self.state / "resolutions")
            path = self.state / "resolutions" / (operation_id + ".json")
            if path.is_symlink():
                raise ValueError("resolution manifests may not be symlinks")
            manifest = read_json(path)
            invariant = {"version": 1, "operation_id": operation_id, "group": group_id,
                         "config_hash": config_hash(config), "reason_hash": reason_hash, "models": identities}
            if manifest:
                if any(manifest.get(key) != value for key, value in invariant.items()):
                    raise ValueError("resolution operation must retain its original group, reason, configuration and model identities")
            else:
                generation = max(time.time_ns(), self.controller_state().get("generation", 0) + 1)
                manifest = {**invariant, "generation": generation, "members": {
                    member["id"]: {"action_id": "manual-resolve-" + operation_id + "-" +
                                    hashlib.sha256(member["id"].encode()).hexdigest()[:16], "confirmed": False}
                    for member in group["members"]}}
                audit.emit("bootstrap_resolution_prepared", operation_id=operation_id, group=group_id,
                           generation=generation, reason_hash=reason_hash, members=list(identities))
                atomic_json(path, manifest)
            if (type(manifest.get("generation")) is not int or not 0 <= manifest["generation"] <= 2**63 - 1
                    or not isinstance(manifest.get("members"), dict) or set(manifest["members"]) != set(identities)):
                raise ValueError("resolution manifest is invalid; preserve it for investigation")
            def outcome(complete, detail=None):
                result = {"operation_id": operation_id, "group": group_id, "complete": complete,
                          "resolved": sum(item.get("confirmed") is True for item in manifest["members"].values()),
                          "count": len(group["members"]), "model_mutations": 0,
                          "resolved_records": sum(item.get("resolved_count", 0) for item in manifest["members"].values())}
                if detail:
                    result["detail"] = detail
                    result["resume"] = "repeat resolve-bootstrap with the same group, reason and --operation-id " + operation_id
                return result
            for member in group["members"]:
                record = manifest["members"][member["id"]]
                expected_action = "manual-resolve-" + operation_id + "-" + hashlib.sha256(member["id"].encode()).hexdigest()[:16]
                if record.get("action_id") != expected_action or type(record.get("confirmed")) is not bool:
                    raise ValueError("resolution member manifest is invalid")
                if record["confirmed"]:
                    continue
                try:
                    # 每个派发前重查整组维护和停止；接收端再核验本机三PIN与停止状态。
                    current = backend.inspect("controller", info["Id"])
                    if not current or current["State"]["Running"] is not True:
                        raise ValueError("Controller is no longer running")
                    self.require_resolution_maintenance(config, group)
                    if self._resolution_models(client, group, config) != identities:
                        raise ValueError("group model identities changed during resolution")
                    audit.emit("bootstrap_resolution_intent", operation_id=operation_id, group=group_id,
                               member=member["id"], action_id=record["action_id"], reason_hash=reason_hash)
                    response = client.call(member["node"], "/v1/action", {
                        "action": "resolve_bootstrap_stopped", "action_id": record["action_id"],
                        "node_id": member["node"],
                        "container": member["container"], "generation": manifest["generation"],
                        "recovery_group": group_id, "reason": reason},
                        timeout=config["nodes"][member["node"]].get("action_timeout_seconds", 120))
                    result = response.get("result") if isinstance(response, dict) else None
                    if (not isinstance(response, dict) or response.get("ok") is not True
                            or response.get("action_id") != record["action_id"] or not isinstance(result, dict)
                            or result.get("state") != "stopped" or result.get("container_id") != identities[member["id"]]["container_id"]
                            or result.get("canceled_by_confirmed_stop") is not True
                            or type(result.get("resolved_count")) is not int or result["resolved_count"] < 0):
                        raise ValueError("Node did not confirm bootstrap resolution")
                    audit.emit("bootstrap_resolution_confirmed", operation_id=operation_id, group=group_id,
                               member=member["id"], action_id=record["action_id"], reason_hash=reason_hash)
                    record["confirmed"] = True
                    record["resolved_count"] = result["resolved_count"]
                    atomic_json(path, manifest)
                except Exception:
                    # 人工续接必须沿用成员action ID，丢响应不创建新操作或重放模型脚本。
                    return outcome(False, "resolution is incomplete or unconfirmed; no automatic retry")
            return outcome(True)

    def status(self):
        """复核基线并返回本机守护组件及Controller持久状态，不把容器running当作推理就绪。"""
        self.host_check()
        with self._lock():
            baseline = self.inspect_baseline()
            backend = self.component_manager(baseline, self.audit_log())
            components = {}
            for service in backend.desired["services"]:
                info = backend.inspect(service, baseline.get("components", {}).get(service))
                components[service] = {"id": info["Id"], "running": info["State"]["Running"]} if info else None
            state = (readable_controller_state(self.controller_state(), validate_controller(read_json(self.runtime / "controller.json")))
                     if self.is_controller else None)
        from inference_guardian.observability.log_state import file_log_status
        log_files = {role: file_log_status(self.state / role / "inference-guardian.log")
                     for role in (["agent", "controller"] if self.is_controller else ["agent"])}
        return {"node": self.node, "models": baseline["models"], "components": components, "log_files": log_files,
                "runtime_dir": str(self.runtime), "state_dir": str(self.state), "controller_state": state}

    def logs(self, service):
        """只读取本机已核对的Agent或Controller日志，不代替原脚本重定向的模型日志。"""
        self.host_check()
        with self._lock():
            baseline = self.inspect_baseline()
            backend = self.component_manager(baseline, self.audit_log())
            if service not in backend.desired["services"]:
                raise ValueError("only local Guardian component logs are available")
            backend.logs(service, baseline.get("components", {}).get(service))

    # 兼容旧部署调用；新调用使用明确的核验/操作接口。
    _engine = inspect_engine
    _model = inspect_model
    _baseline = inspect_baseline
    _backend = component_manager
    _bootstrap_matches = validate_startup_contract
    _mooncake_contract = validate_model_files
    _check_naming_migration = require_naming_compatibility
    _audit = audit_log
    _state = controller_state
    _journals = require_clear_journals
    _fresh = require_fresh_readiness
    _probe = probe_passes
    _resolution_maintenance = require_resolution_maintenance
    _run = docker_command
    _json = inspect_docker

    def for_existing_installation(self, runtime, state, source_hash):
        """绑定已核验旧基线的路径视图；不重新读取新模板或改动原上下文。"""
        existing = copy.copy(self)
        existing.runtime, existing.state = runtime, state
        existing.baseline_path = runtime / "adoption.json"
        existing.source_hash = source_hash
        return existing


def main(argv=None):
    """分派原生Docker部署/运维命令；未知结果或部分对账失败返回非零，供运维脚本识别。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--node", required=True)
    parser.add_argument("--controller-node")
    parser.add_argument("--state-root", type=Path, default=DEFAULT_STATE_ROOT)
    parser.add_argument("--runtime-dir", type=Path)
    parser.add_argument("--backend", choices=["docker"], default="docker")
    subparsers = parser.add_subparsers(dest="action", required=True)
    adopt = subparsers.add_parser("adopt")
    adopt.add_argument("--secrets-dir", type=Path, default=DEFAULT_SECRETS_DIR,
                       help="Token source directory (default: /data/scripts/inference-guardian/secrets)")
    adopt.add_argument("--guardian-image", help="Image name or ID; defaults to inference-guardian:<project.version>")
    for action in ("up", "status"):
        subparsers.add_parser(action)
    logs = subparsers.add_parser("logs")
    logs.add_argument("service", choices=["agent", "controller"])
    mode = subparsers.add_parser("mode")
    mode.add_argument("value", choices=["observe", "auto"])
    maintenance = subparsers.add_parser("maintenance")
    maintenance.add_argument("value", choices=["on", "off"])
    resolution = subparsers.add_parser("resolve-bootstrap")
    resolution.add_argument("--group", required=True)
    resolution.add_argument("--reason", required=True)
    resolution.add_argument("--operation-id")
    args = parser.parse_args(argv)
    try:
        deployment = GuardianDeployment(args.profile, args.node, controller_node=args.controller_node,
                                        state_root=args.state_root, runtime_dir=args.runtime_dir)
        if args.action == "adopt":
            result = deployment.adopt(args.secrets_dir, args.guardian_image)
        elif args.action == "mode":
            result = deployment.set_mode(args.value)
        elif args.action == "maintenance":
            result = deployment.maintenance(args.value)
        elif args.action == "resolve-bootstrap":
            result = deployment.resolve_bootstrap(args.group, args.reason, args.operation_id)
        elif args.action == "logs":
            deployment.logs(args.service)
            return 0
        else:
            result = getattr(deployment, args.action)()
        print(json.dumps(result, ensure_ascii=False, indent=2))
        if args.action == "resolve-bootstrap" and result.get("complete") is not True:
            return 1
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        detail = str(exc) if isinstance(exc, ValueError) and not isinstance(exc, json.JSONDecodeError) else type(exc).__name__
        print("Guardian deployment refused: " + detail, file=sys.stderr)
        return 1
    return 0
