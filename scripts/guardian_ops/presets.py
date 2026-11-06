"""发布时选择的示例和旧配置身份。数据路径只相对于本发行包。"""
import json as _json
from pathlib import Path as _Path

_catalog = _json.loads((_Path(__file__).resolve().parents[2] / "deploy/presets.json").read_text(encoding="utf-8"))
PROFILE = "pd_1p1d_4node"
V4_EXAMPLE = _catalog["V4_EXAMPLE"]
V41_EXAMPLE = _catalog["V41_EXAMPLE"]
DEPLOYMENT_ID = _catalog["DEPLOYMENT_ID"]
MIXED_EXAMPLE = _catalog["MIXED_EXAMPLE"]
MIXED_SCENARIO = "mixed2node"
MIXED_ID = _catalog["MIXED_ID"]
MIXED_PROFILE = "mixed_2node"
MIXED_W8A8_EXAMPLE = _catalog["MIXED_W8A8_EXAMPLE"]
MIXED_W8A8_ID = _catalog["MIXED_W8A8_ID"]
MIXED_EXAMPLES = {MIXED_ID: MIXED_EXAMPLE, MIXED_W8A8_ID: MIXED_W8A8_EXAMPLE}
SUPPORTED_DEPLOYMENTS = (DEPLOYMENT_ID, *MIXED_EXAMPLES)
PACKAGED_EXAMPLES = (V4_EXAMPLE, V41_EXAMPLE, *MIXED_EXAMPLES.values())
LEGACY_MIXED_EXAMPLE = _catalog["LEGACY_MIXED_EXAMPLE"]
LEGACY_CONTAINER = _catalog["LEGACY_CONTAINER"]
LEGACY_GROUP = _catalog["LEGACY_GROUP"]
RETIRED_DEPLOYMENT_IDS = tuple(_catalog["RETIRED_DEPLOYMENT_IDS"])
SCRIPT_DIRECTORY = _catalog["SCRIPT_DIRECTORY"]
SCENARIO = "1P1D4node_withMooncake"
MODEL = _catalog["MODEL"]
LAYOUT = {node: tuple(layout) for node, layout in _catalog["LAYOUT"].items()}
LEGACY_DIRECTORY_LABEL = _catalog["directory_label"]
