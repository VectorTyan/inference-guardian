"""内置示例与旧配置身份。导入此模块不读取文件或访问节点。"""

PROFILE = "pd_1p1d_4node"  # 冻结目录及历史接管标识，不随交付示例改名。
V4_EXAMPLE = "example-pd-dp2tp8"
V41_EXAMPLE = "example-pd-dp4tp4"
DEPLOYMENT_ID = "example-pd"
MIXED_EXAMPLE = "example-mixed-a"
MIXED_SCENARIO = "mixed2node"
MIXED_ID = "example-mixed-a"
MIXED_PROFILE = "mixed_2node"
MIXED_W8A8_EXAMPLE = "example-mixed-b"
MIXED_W8A8_ID = "example-mixed-b"
MIXED_EXAMPLES = {MIXED_ID: MIXED_EXAMPLE, MIXED_W8A8_ID: MIXED_W8A8_EXAMPLE}
SUPPORTED_DEPLOYMENTS = (DEPLOYMENT_ID, *MIXED_EXAMPLES)
PACKAGED_EXAMPLES = (V4_EXAMPLE, V41_EXAMPLE, *MIXED_EXAMPLES.values())
LEGACY_MIXED_EXAMPLE = 'example-mixed'
LEGACY_CONTAINER = "example-model-a"
LEGACY_GROUP = "example-chat-a"

# 仅供旧基线/组件残留检查使用，不再作为新部署身份。
RETIRED_DEPLOYMENT_IDS = ("example-retired-pd",)
SCRIPT_DIRECTORY = "/data/scripts/example-pd-a"
SCENARIO = "1P1D4node_withMooncake"
MODEL = "/data/models/example-model-a"
# v3/v4的完整历史布局；v5只固定节点角色、host和master，允许改变并行参数。
LAYOUT = {
    "p0": ("prefill", "192.0.2.11", 2, 8, 1, 0, "192.0.2.11"),
    "p1": ("prefill", "192.0.2.12", 2, 8, 1, 1, "192.0.2.11"),
    "d0": ("decode", "192.0.2.21", 16, 1, 8, 0, "192.0.2.21"),
    "d1": ("decode", "192.0.2.22", 16, 1, 8, 8, "192.0.2.21"),
}
