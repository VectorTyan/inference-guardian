# Inference Guardian

Inference Guardian 在管理节点运行 Controller，在每台模型宿主运行 Agent。它接管已有的 Docker 推理服务，记录健康检查、生成探测和恢复动作。observe 模式只观察，recovery 模式允许按已验收的启动清单执行恢复。Agent 持有宿主 Docker socket，需要在可信管理网络中部署。

## 本地检查

从仓库根目录运行以下只读命令，Python 使用标准库。

```bash
python3 -B scripts/generate_external_profiles.py --check
python3 -B scripts/check_vllm_status_readonly.py --self-test
```

[四套配置示例](examples/vllm-ascend/README.md)使用文档专用 IP 和虚构服务名称。清单描述已存在的服务及其脚本；示例名称、地址和路径需要在部署前核对。四节点配置校验指定的节点角色、主节点及地址，修改部署地址时请同步核对宿主工具的布局表。项目对外提供的 Python 服务包是 `src/inference_guardian`，宿主部署入口是 `scripts/install_guardian.py`。

有本地交付材料时，维护者从本仓库根目录运行 `python3 -B local/validation/run_tests.py` 验证当前代码，再用 `python3 -B scripts/make_bundle.py --delivery-dir local/delivery` 生成站点交付包。全新 Git 克隆中使用上面的公开示例检查。

服务包用恢复组维护故障状态和预算，用成员关联节点与容器。Controller 的单组观测独立处理证据，Agent 的回执查询集中核对容器、恢复组、代次和启动周期。后续扩展单机多模型时可复用这些职责划分。当前服务层允许不同恢复组使用同一节点上的不同容器，同一个容器只归一个恢复组，恢复事务仍由 Controller 串行协调。标准安装清单目前提供两节点和四节点场景。

代码维护和 Python 调用统一使用 `src/inference_guardian/` 下的 `control/`、`agent/`、`health/`、`containers/` 和 `observability/`。自 v0.30.0 起，旧的 `inference_guardian.controller` 等平铺导入路径已移除，调用方需按部署说明迁移到新路径。`storage.py`、`http_client.py` 和可选 `gateway.py` 继续独立维护，`node_agent.py` 仅承担原命令行启动入口。

[部署与打包](docs/operations.md) · [恢复与演练](docs/recovery.md) · [版本说明](docs/release-notes.md)

P/D 部署可[通过 P0 独立转发引擎指标并写入 AOM](docs/pd-metrics.md)。
