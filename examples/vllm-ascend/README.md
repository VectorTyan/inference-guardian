# vLLM Ascend 配置示例

| 示例 | 拓扑 | P/D 并行参数或混部参数 |
| --- | --- | --- |
| [example-pd-dp2tp8](example-pd-dp2tp8/source-manifest.json) | 四节点 P/D | P DP2/TP8，D DP16/TP1 |
| [example-pd-dp4tp4](example-pd-dp4tp4/source-manifest.json) | 四节点 P/D | P DP4/TP4，D DP8/TP2 |
| [example-mixed-a](example-mixed-a/source-manifest.json) | 两节点 | DP2/TP8，每机 local DP1 |
| [example-mixed-b](example-mixed-b/source-manifest.json) | 两节点 | DP2/TP8，每机 local DP1 |

两机示例采用独立部署 ID，只有 p0 暴露业务 API。四节点示例共用本目录的 probe-settings.json。首次部署前核对每个容器内已有的启动脚本、权重路径和 served_model_name。示例使用 192.0.2.0/24 和 198.51.100.0/24 文档地址。
