# 部署与打包

在 Linux 上构建离线包。准备可信的 Linux/ARM64 `python:3.12-slim-bookworm`，检查架构与标签，再将该标签用 Docker save 导出并用 xz 压缩，放在 `deploy/python-3.12-slim-bookworm-arm64.tar.xz`。此文件是发行构建输入，由发布者自行核验来源。运行：

```bash
python3 -B scripts/make_bundle.py
```

将 dist 中源码包、同名 SHA256SUMS、install_guardian.py 复制到管理节点的 `/data/scripts/inference-guardian/packages/`。从示例复制一份 source-manifest.json 到受管根目录的 config/，根据实际服务维护节点、容器、权重路径与启动脚本。自定义 probe-settings.json 与清单同目录保存。模型应已运行，Agent 管理端口仅对可信网络开放。示例启用 HTTP，运维需保障管理流量和 Token 的机密性。主控通过 SSH 连接工作节点。默认构建使用本地 ARM64 基础镜像或已核验的随包归档。

```bash
cd /data/scripts/inference-guardian
python3 -B packages/install_guardian.py --manifest config/source-manifest.json --mode observe
```

输出 `passed=true` 后查看验收报告，核对模型、节点、健康检查和真实生成。`--ssh-password` 在交互终端读取共用 SSH 密码。站点配置与私钥在部署端保管。

`upgrade --mode observe` 会归档记录、重新部署 Guardian 并重置恢复预算及代次。升级前关闭进行中的演练并对账未知动作。使用与目标部署相同的身份和现场输入；新的示例身份适用于独立验证环境。日常只读复查使用 verify。Controller 采用只读根文件系统、cap-drop ALL 和 no-new-privileges。符合条件的启动错误只允许一次 seccomp 兼容对比，通过固定版本自检后记录实际角色策略。

[恢复演练](recovery.md)
