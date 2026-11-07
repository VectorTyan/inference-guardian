"""已审阅配置集的加载、规范化和交叉校验；不接管、不落盘。"""
from pathlib import Path
import json
import re
from .release_files import digest
from .mooncake_contract import MIXED_EXAMPLES, SUPPORTED_DEPLOYMENTS, manifest_deployment_id, MIXED_PROFILE, is_mixed, DEPLOYMENT_ID, RETIRED_DEPLOYMENT_IDS, PROFILE, validate_manifest, node_commands
from .probe_config import validate_profile_probes
from inference_guardian.control.config import validate as validate_controller
from inference_guardian.agent.config import validate_config as validate_agent
from inference_guardian.storage import read_json
from inference_guardian.control.topology import recovery_steps

NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\Z")


class Profile:
    """配置文件及其规范化身份；路径选择沿用原部署器契约。"""
    def __init__(self, profile, node, controller_node=None):
        self.profile = Path(profile).resolve()
        if not NAME.fullmatch(self.profile.name) or not NAME.fullmatch(node):
            raise ValueError("safe profile and node identifiers required")
        self.node = node
        self.controller_source = self._source("controller-external.json", "controller.json")
        self.source_controller = validate_controller(read_json(self.controller_source))
        if node not in self.source_controller["nodes"]:
            raise ValueError("selected node is absent from controller profile")
        deployment = read_json(self._source("deployment-external.json", "deployment.json"), {})
        self.explicit_deployment_id = "deployment_id" in deployment
        self.deployment_id = deployment.get("deployment_id", self.profile.name)
        if not isinstance(self.deployment_id, str) or not NAME.fullmatch(self.deployment_id):
            raise ValueError("safe stable deployment_id required")
        if self.deployment_id in RETIRED_DEPLOYMENT_IDS:
            raise ValueError("retired deployment_id; use the installed release for maintenance and explicitly migrate")
        self.controller_node = (controller_node or deployment.get("controller_node") or deployment.get("controllerNode")
                                or next(iter(self.source_controller["nodes"])))
        if self.controller_node not in self.source_controller["nodes"]:
            raise ValueError("controller node is absent from profile")
        self.is_controller = self.node == self.controller_node
        self.agents = {}
        for identifier in self.source_controller["nodes"]:
            source = self._source(f"agent-external-{identifier}.json", f"agent-{identifier}.json")
            agent = validate_agent(read_json(source))
            if agent.get("node_id", identifier) != identifier or agent["listen"]["port"] == 0:
                raise ValueError("Agent node or listening port is invalid")
            if agent["docker_socket"] != "/var/run/docker.sock":
                raise ValueError("adoption targets the fixed local Docker socket")
            self.agents[identifier] = agent
        source = {"controller": self.source_controller, "agents": self.agents,
                  "controller_node": self.controller_node}
        self.source_manifest = None
        if self.profile.name in (PROFILE, MIXED_PROFILE) or self.deployment_id in SUPPORTED_DEPLOYMENTS:
            self.source_manifest = read_json(self.profile / "source-manifest.json")
            declared = validate_manifest(self.source_manifest)
            if (is_mixed(self.source_manifest) != (self.deployment_id in MIXED_EXAMPLES)
                    or (is_mixed(self.source_manifest)
                        and self.deployment_id != manifest_deployment_id(self.source_manifest))
                    or set(declared) != set(self.agents)):
                raise ValueError("deployment identity or agent membership differs from topology")
            source["source_manifest"] = self.source_manifest
            settings = read_json(self.profile / "probe-settings.json")
            validate_profile_probes(self.source_controller, self.agents, self.source_manifest, settings)
            source["probe_settings"] = settings
        # 未声明ID时保留旧指纹与命名；显式引入/更改ID必须触发维护迁移，不能重置历史。
        if self.explicit_deployment_id:
            source["deployment_id"] = self.deployment_id
        self.source_hash = digest(source)

    def _source(self, preferred, fallback):
        """交付统一使用external命名，仍读取旧配置后备名；不创建或迁移输入文件。

        源指纹来自已解析内容而非文件名，仅改Agent文件名不会改变接管身份。
        """
        return self.profile / (preferred if (self.profile / preferred).is_file() else fallback)


def check_startup_contract(agents, controller, manifest):
    """核对恢复组成员、Agent白名单与每个静态启动阶段一一对应，拒绝未替换占位符。"""
    text = json.dumps({"agents": agents, "controller": controller})
    if "CHANGE_ME" in text.upper() or "REPLACE_ME" in text.upper():
        raise ValueError("replace all profile placeholders before adoption")
    expected = set()
    for group in controller["groups"]:
        members = {member["id"]: member for member in group["members"]}
        for step in recovery_steps(group):
            if step["action"] != "bootstrap":
                continue
            for mid in step["members"]:
                member = members[mid]
                expected.add((member["node"], member["container"], step["stage"]))
    declared, model_members = set(), set()
    for group in controller["groups"]:
        model_members.update((member["node"], member["container"]) for member in group["members"])
    for node, agent in agents.items():
        for container in agent["containers"]:
            if (node, container["name"]) not in model_members:
                raise ValueError("Agent allowlist container has no recovery-group owner")
            if (manifest is not None
                    and container.get("bootstrap_commands") != node_commands(manifest, node)):
                raise ValueError("Mooncake bootstrap commands must match the configured stages, names and paths")
            declared.update((node, container["name"], stage) for stage in container.get("bootstrap_commands", {}))
    if declared != expected:
        raise ValueError("bootstrap steps must match every static Agent command exactly")
    actual_members = {(node, container["name"]) for node, agent in agents.items() for container in agent["containers"]}
    if actual_members != model_members:
        raise ValueError("all recovery members must match Agent allowlists")
