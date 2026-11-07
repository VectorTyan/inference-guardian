"""Generate P0 metrics relay configuration and Prometheus discovery for a PD deployment."""
import argparse
import ast
from ipaddress import ip_address
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from guardian_ops.mooncake_contract import is_mixed, manifest_group_id, validate_manifest
from inference_guardian.observability.pd_metrics_relay import METRICS_PATH
from inference_guardian.storage import atomic_json

RELAY_MODULE = "guardian_pd_metrics_relay"


def identifier(value, label):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}", value):
        raise ValueError("invalid " + label)
    return value


def instance_layout(manifest, nodes, controller):
    if controller is None:
        instances = [
            {"id": role + "-01", "role": role, "members": [
                member for member, node in nodes.items() if node["role"] == role
            ]}
            for role in ("prefill", "decode")
        ]
    else:
        groups = [group for group in controller["groups"] if group["id"] == manifest_group_id(manifest)]
        if len(groups) != 1 or groups[0]["topology"] != "pd_disaggregated":
            raise ValueError("controller must describe the same PD recovery group as the source manifest")
        group = groups[0]
        members = {(item["id"], item["node"], item["container"]) for item in group["members"]}
        if len(group["members"]) != len(nodes) or members != {
            (member, member, node["container"]) for member, node in nodes.items()
        }:
            raise ValueError("controller members do not match the source manifest")
        instances = group["instances"]

    assigned, ids = {}, set()
    for instance in instances:
        instance_id = identifier(instance["id"], "inference_instance")
        if instance_id in ids or not instance["members"]:
            raise ValueError("duplicate or empty inference instance")
        ids.add(instance_id)
        for member in instance["members"]:
            if member in assigned or member not in nodes or nodes[member]["role"] != instance["role"]:
                raise ValueError("duplicate, unknown or role-mismatched instance member: " + str(member))
            assigned[member] = instance_id
    if set(assigned) != set(nodes):
        raise ValueError("each member requires an inference instance")
    return assigned


def make_targets(manifest, inventory, controller=None, proxy_url=None):
    if not isinstance(manifest, dict) or is_mixed(manifest):
        raise ValueError("PD source manifest required")
    if manifest.get("version") not in (5, 6):
        raise ValueError("PD metrics requires a v5 or v6 manifest; legacy manifests pin the Proxy source hash")
    nodes = validate_manifest(manifest)
    instances = instance_layout(manifest, nodes, controller)
    cluster = identifier(inventory["cluster"], "cluster")
    deployment = identifier(inventory.get("deployment", manifest_group_id(manifest)), "deployment")
    servers = inventory["servers"]
    if set(servers) != set(nodes):
        raise ValueError("inventory servers must match the source manifest member IDs")

    p0_ip = ip_address(nodes["p0"]["host"])
    p0_host = "[" + str(p0_ip) + "]" if p0_ip.version == 6 else str(p0_ip)
    listener = urlsplit(proxy_url or "http://{}:{}".format(p0_host, manifest["external_port"]))
    if (listener.scheme not in ("http", "https") or not listener.hostname or not listener.port
            or listener.username is not None or listener.password is not None
            or listener.path not in ("", "/") or listener.query or listener.fragment
            or any(char.isspace() for char in listener.netloc)):
        raise ValueError("proxy URL requires http(s), host and port")

    routes, targets = {}, []
    server_ids = set()
    for member, node in nodes.items():
        server = servers[member]
        server_id = identifier(server["server_id"], "server_id")
        if server_id in server_ids:
            raise ValueError("four-node manifest requires distinct server IDs")
        server_ids.add(server_id)
        resource_pool = identifier(server["resource_pool"], "resource_pool")
        node_ip = ip_address(node["host"])
        if "node_ip" in server and ip_address(server["node_ip"]) != node_ip:
            raise ValueError("inventory node_ip does not match the source manifest: " + member)
        host = "[" + str(node_ip) + "]" if node_ip.version == 6 else str(node_ip)
        for offset in range(node["local_dp"]):
            rank = node["rank"] + offset
            target_id = "{}-dp{}".format(member, rank)
            routes[target_id] = "http://{}:{}/metrics".format(host, node["api_port"] + offset)
            targets.append({
                "targets": [listener.netloc],
                "labels": {
                    "__scheme__": listener.scheme,
                    "__param_target": target_id,
                    "instance": deployment + "/" + target_id,
                    "cluster": cluster,
                    "deployment": deployment,
                    "role": node["role"],
                    "inference_instance": instances[member],
                    "member_id": member,
                    "metrics_target_id": target_id,
                    "metric_scope": "engine_local",
                    "dp_rank": str(rank),
                    "server_id": server_id,
                    "resource_pool": resource_pool,
                    "node_ip": str(node_ip),
                },
            })
    return routes, targets


def adapt_proxy(source):
    """Add one route to the existing FastAPI app and preserve the launch entry point."""
    if RELAY_MODULE in source:
        raise ValueError("use the original Proxy source")
    tree = ast.parse(source)
    assignments = [
        node for node in tree.body
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name) and node.value.func.id == "FastAPI"
        and any(isinstance(target, ast.Name) and target.id == "app" for target in node.targets)
    ]
    if len(assignments) != 1:
        raise ValueError("expected one top-level app = FastAPI(...) in the original Proxy source")
    launch_guard = ast.dump(ast.parse('__name__ == "__main__"', mode="eval").body)
    guards = [node.lineno for node in tree.body if isinstance(node, ast.If)
              and ast.dump(node.test) == launch_guard]
    if len(guards) != 1 or guards[0] <= assignments[0].lineno:
        raise ValueError("expected the original Proxy script launch guard")
    lines = source.splitlines(keepends=True)
    position = guards[0] - 1
    lines[position:position] = [
        "\nfrom " + RELAY_MODULE + " import PdMetricsRelay\n",
        "app.add_middleware(PdMetricsRelay)\n",
        "\n\n",
    ]
    updated = "".join(lines)
    compile(updated, "<metrics-enabled Proxy>", "exec")
    return updated


def prometheus_config(target_file, scrape_token_file, aom_url=None, aom_token_file=None):
    config = {
        "scrape_configs": [{
            "job_name": "vllm-pd-via-proxy",
            "metrics_path": METRICS_PATH,
            "scrape_interval": "30s",
            "scrape_timeout": "8s",
            "follow_redirects": False,
            "authorization": {"type": "Bearer", "credentials_file": scrape_token_file},
            "file_sd_configs": [{"files": [target_file]}],
        }],
    }
    if aom_url:
        url = urlsplit(aom_url)
        if (url.scheme != "https" or not url.hostname or url.username is not None
                or url.password is not None or url.query or url.fragment or not url.path.strip("/")):
            raise ValueError("AOM requires its HTTPS Remote Write URL")
        config["remote_write"] = [{
            "url": aom_url,
            "authorization": {"type": "Bearer", "credentials_file": aom_token_file},
            "follow_redirects": False,
        }]
    return config


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--controller", type=Path, help="Use explicit instance IDs from this Controller configuration")
    parser.add_argument("--proxy-source", type=Path, help="Also emit a metrics-enabled copy of the original P0 script")
    parser.add_argument("--proxy-url", help="Override the scrape URL with an existing trusted HTTP(S) ingress")
    parser.add_argument("--target-file", default="/etc/prometheus/pd-metrics/targets.json")
    parser.add_argument("--scrape-token-file", default="/etc/prometheus/secrets/pd-metrics.token")
    parser.add_argument("--aom-url", help="Optional AOM Remote Write URL for standalone Prometheus")
    parser.add_argument("--aom-token-file", default="/etc/prometheus/secrets/aom.token")
    parser.add_argument("--output-dir", type=Path, required=True, help="A new directory for generated files")
    args = parser.parse_args()
    try:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        inventory = json.loads(args.inventory.read_text(encoding="utf-8"))
        controller = json.loads(args.controller.read_text(encoding="utf-8")) if args.controller else None
        routes, targets = make_targets(manifest, inventory, controller, args.proxy_url)
        config = prometheus_config(args.target_file, args.scrape_token_file, args.aom_url, args.aom_token_file)
        if args.proxy_source:
            if (not args.proxy_source.stem.isidentifier() or args.proxy_source.suffix != ".py"
                    or args.proxy_source.stem == RELAY_MODULE):
                raise ValueError("Proxy source must have an importable Python module filename")
            adapted = adapt_proxy(args.proxy_source.read_text(encoding="utf-8"))
            relay = (ROOT / "src/inference_guardian/observability/pd_metrics_relay.py").read_bytes()
        args.output_dir.mkdir(parents=True)
        proxy_dir = args.output_dir / "p0"
        atomic_json(proxy_dir / "pd-metrics-allowlist.json", routes)
        atomic_json(args.output_dir / "targets.json", targets)
        atomic_json(args.output_dir / "prometheus.json", config)
        if args.proxy_source:
            (proxy_dir / (RELAY_MODULE + ".py")).write_bytes(relay)
            (proxy_dir / args.proxy_source.name).write_text(adapted, encoding="utf-8")
    except (OSError, ValueError, KeyError, TypeError, SyntaxError) as error:
        parser.error(str(error))
    print("Generated {} engine targets in {}".format(len(targets), args.output_dir))


if __name__ == "__main__":
    main()
