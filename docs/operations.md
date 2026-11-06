# 部署与打包

在 Linux 上构建离线包。准备可信的 Linux/ARM64 `python:3.12-slim-bookworm`，检查架构与标签，再将该标签用 Docker save 导出并用 xz 压缩，放在 `deploy/python-3.12-slim-bookworm-arm64.tar.xz`。此文件是发行构建输入，由发布者自行核验来源。运行：

```bash
python3 -B scripts/make_bundle.py
```

### 从外部目录打包

同一个 Git 工作目录可用于公开示例和自有站点交付。站点使用独立目录维护 `deploy/presets.json`、已审阅的基础镜像和 `examples/vllm-ascend/` 下的四套清单及探针策略。发布前核对目录清单内的部署 ID、旧配置身份与站点基线。设 DELIVERY_DIR 为该目录的绝对路径：

```bash
python3 -B scripts/make_bundle.py --delivery-dir "$DELIVERY_DIR"
```

现场交付物写入 `$DELIVERY_DIR/dist/`。打包器只选择指定数据文件，源码、安装入口与 Dockerfile 均取自 Git 仓库；站点的 Token、私钥、site.json、状态目录和测试资料独立保管。维护 `presets.json` 时同步核对两个四节点示例的 host/master 与旧布局；原部署应保留其原部署 ID。公开示例包可用 `--base-archive /absolute/path/to/base.tar.xz` 指向外部镜像，输出到仓库的 dist。相同版本的两种产物应分别存放并使用各自的 SHA256SUMS。

### 选择全新部署的示例

公开版使用自己的部署 ID、容器名和文档地址。请在独立环境首次安装；已有私有部署应继续使用其原发行包、原身份和原回执进行维护。直接使用公开示例升级私有部署会导致接管身份不匹配。

四节点 P/D 示例的地址校验使用宿主工具内置的布局表。为自己的节点打包时，同时更新对应 `deploy/presets.json` 的 `LAYOUT` 和选定清单中的 `nodes[].host/master`，再执行 `python3 -B scripts/generate_external_profiles.py --check`。两个 P/D 示例共享这张布局表，打包全部示例时两份清单须同步。两节点混部的地址取自所选清单。

将 dist 中源码包、同名 SHA256SUMS、install_guardian.py 复制到管理节点的 `/data/scripts/inference-guardian/packages/`。从示例复制一份 source-manifest.json 到受管根目录的 config/，根据实际服务维护节点、容器、权重路径与启动脚本。自定义 probe-settings.json 与清单同目录保存。模型应已运行，Agent 管理端口仅对可信网络开放。示例启用 HTTP，运维需保障管理流量和 Token 的机密性。主控通过 SSH 连接工作节点。默认构建使用本地 ARM64 基础镜像或已核验的随包归档。

```bash
cd /data/scripts/inference-guardian
python3 -B packages/install_guardian.py --manifest config/source-manifest.json --mode observe
```

输出 `passed=true` 后查看验收报告，核对模型、节点、健康检查和真实生成。`--ssh-password` 在交互终端读取共用 SSH 密码。站点配置与私钥在部署端保管。

`upgrade --mode observe` 会归档记录、重新部署 Guardian 并重置恢复预算及代次。升级前关闭进行中的演练并对账未知动作。使用与目标部署相同的身份和现场输入；新的示例身份适用于独立验证环境。日常只读复查使用 verify。Controller 采用只读根文件系统、cap-drop ALL 和 no-new-privileges。符合条件的启动错误只允许一次 seccomp 兼容对比，通过固定版本自检后记录实际角色策略。

[恢复演练](recovery.md)
