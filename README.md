# Inference Guardian

Inference Guardian 在管理节点运行 Controller，在每台模型宿主运行 Agent。它接管已有的 Docker 推理服务，记录健康检查、生成探测和恢复动作。observe 模式只观察，recovery 模式允许按已验收的启动清单执行恢复。Agent 持有宿主 Docker socket，需要在可信管理网络中部署。

## 本地检查

从仓库根目录运行以下只读命令，Python 使用标准库。

```bash
python3 -B scripts/generate_external_profiles.py --check
python3 -B scripts/check_vllm_status_readonly.py --self-test
```

[四套配置示例](examples/vllm-ascend/README.md)使用文档专用 IP 和虚构服务名称。清单描述已存在的服务及其脚本；示例名称、地址和路径需要在部署前核对。四节点配置校验指定的节点角色、主节点及地址，修改部署地址时请同步核对宿主工具的布局表。项目对外提供的 Python 服务包是 `src/inference_guardian`，宿主部署入口是 `scripts/install_guardian.py`。

[部署与打包](docs/operations.md) · [恢复与演练](docs/recovery.md) · [版本说明](docs/release-notes.md)
