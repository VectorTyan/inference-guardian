# 部署与打包

在 Linux 上构建离线包。准备可信的 Linux/ARM64 `python:3.12-slim-bookworm`，检查架构与标签，再将该标签用 Docker save 导出并用 xz 压缩，放在 `deploy/python-3.12-slim-bookworm-arm64.tar.xz`。此文件是发行构建输入，由发布者自行核验来源。运行：

```bash
python3 -B scripts/make_bundle.py
```

### 服务代码目录

| 实现目录 | 职责 | 当前导入模块（inference_guardian. 前缀） |
| --- | --- | --- |
| src/inference_guardian/control/ | Controller、配置、拓扑、恢复范围和 canary 调度 | control.service、control.config、control.topology、control.recovery_scope、control.canary |
| src/inference_guardian/agent/ | 节点服务、管理协议、观测、回执、管理客户端和 Agent 日志 | agent.service、agent.http、agent.config、agent.observation、agent.receipts、agent.client、agent.logging |
| src/inference_guardian/health/ | 探针执行、故障判定、进程证据和探针显示名称 | health.probes、health.policy、health.process_evidence、health.identity |
| src/inference_guardian/containers/ | Docker 客户端和容器配置契约 | containers.docker_api、containers.contract |
| src/inference_guardian/observability/ | 审计追加、日志格式和日志落盘状态 | observability.audit、observability.log_format、observability.log_state |

包内部使用实现路径。control 通过 agent.client 访问节点，并依赖 health 和 observability；Agent 服务依赖 containers、health 和 observability。health 和 agent.client 使用共用的 http_client。storage 和可选 gateway 继续在包根目录维护。实现子包初始化保持轻量。

v0.30.0 已移除旧平铺 Python 导入路径与动态映射。Python 调用方需把 controller.Controller 改为 control.service.Controller，把 node_agent.NodeAgent 改为 agent.service.NodeAgent，把 probes.ProbeResult 改为 health.probes.ProbeResult，并按上表迁移其余导入。以上名称均带 inference_guardian. 前缀。新类型使用其真实模块身份，旧类型 pickle 数据需由旧版调用方处理。Guardian 持久状态采用既有 JSON 协议。

根目录 node_agent.py 仅提供 python -m inference_guardian.node_agent 命令，标准入口仍为 python -m inference_guardian。运维日志的固定分类继续使用 inference_guardian.controller 和 inference_guardian.node_agent。Agent 专用台账写入与 storage 的通用写入分别维护各自的权限和序列化契约。

打包器递归收集 src，Dockerfile 复制完整 src 目录。升级使用完整源码包和已有 install_guardian.py 入口，保持宿主工具与服务包同版本。将本次三份交付文件复制到主控 packages/，把 ARCHIVE 设为该源码包路径，再执行以下命令。现有配置与 Token 继续作为部署输入，旧记录按既有重部署流程归档，恢复状态重置。

```bash
cd /data/scripts/inference-guardian
python3 -B packages/install_guardian.py upgrade \
  --archive "$ARCHIVE" --config config/site.json --ssh-password --mode observe
```

验收报告 passed=true 后按恢复演练文档操作。密钥 SSH 场景可省略 --ssh-password。

复用发布目录时若报告 `unexpected release source`，按错误中的相对路径核对 src/scripts 内清单外的内容，恢复该发布目录后重试。正常 `__pycache__` 可以保留。镜像准备自检会加载实际启动入口及所需模块，并核对版本；依赖缺失会在停止旧 Guardian 前中止准备。

### 续接旧版本未完成的升级收尾

若升级停在 `p0-redeploy-finish`，其节点回执和协调器回执仍为 `in_progress` 或 `unconfirmed`，先保留原事务、原源码包和 SHA256SUMS。模型恢复健康后，将修复版三份交付物放入 packages，使用补丁工具完成原事务。下面以原请求为 recovery 为例，mode 必须与原请求一致。

```bash
cd /data/scripts/inference-guardian
python3 -B packages/install_guardian.py upgrade --resume-finish \
  --archive packages/inference-guardian-source-0.31.1.tar.gz \
  --config config/site.json --ssh-password --mode recovery
```

此命令核验补丁包后，按 `operations/redeploy.json` 的摘要查找原源码包，使用原冻结配置和节点请求。不会运行构建、停止、重置、归档、接管和启动阶段；仅对账收尾、完成健康验收和原 current 指针发布。验收报告版本仍为原部署版本，运行镜像也仍为原版本。普通升级到补丁镜像是独立的后续操作。

重试继续使用同一命令。原进程仍持有集群、节点或部署锁时会立即停止；回执的 in_progress 本身不代表进程还在。实际 Controller 已运行并加载目标配置时不重复 stop/start。组件停止、配置尚未加载、模型动作未知、审计损坏或停止/启动结果无法确认时仍会阻断，须先核对原回执、部署审计和实际 Docker 状态。不要删除 operations、手改 complete、放宽容器 PIN 或替换原归档来绕过保护。完成条件为验收报告 passed=true、redeploy.json 为 complete，且 Controller 内部模式符合原请求（recovery 对应 auto）。

### 从外部目录打包

同一个 Git 工作目录可用于公开示例和自有站点交付。站点使用独立目录维护 `deploy/presets.json`、已审阅的基础镜像和 `examples/vllm-ascend/` 下的四套清单及探针策略。发布前核对目录清单内的部署 ID、旧配置身份与站点基线。在本地维护时，将这些材料放到代码仓的 `local/delivery/`，测试套件放到 `local/validation/`。整个 `local/` 由 Git 和 Docker 构建上下文排除。在仓库根目录执行以下命令。

```bash
python3 -B scripts/make_bundle.py --delivery-dir local/delivery
```

现场交付物写入 `local/delivery/dist/`。打包器只选择指定数据文件，源码、安装入口与 Dockerfile 均取自 Git 仓库；站点的 Token、私钥、site.json、状态目录和测试资料独立保管。维护 `presets.json` 时同步核对两个四节点示例的 host/master 与旧布局；原部署应保留其原部署 ID。公开示例包可用 `--base-archive /absolute/path/to/base.tar.xz` 指向外部镜像，输出到仓库的 dist。相同版本的两种产物应分别存放并使用各自的 SHA256SUMS。

### 选择全新部署的示例

公开版使用自己的部署 ID、容器名和文档地址。请在独立环境首次安装；已有私有部署应继续使用其原发行包、原身份和原回执进行维护。直接使用公开示例升级私有部署会导致接管身份不匹配。

四节点 P/D 示例的地址校验使用宿主工具内置的布局表。为自己的节点打包时，同时更新对应 `deploy/presets.json` 的 `LAYOUT` 和选定清单中的 `nodes[].host/master`，再执行 `python3 -B scripts/generate_external_profiles.py --check`。两个 P/D 示例共享这张布局表，打包全部示例时两份清单须同步。两节点混部的地址取自所选清单。

将 dist 中源码包、同名 SHA256SUMS、install_guardian.py 复制到管理节点的 `/data/scripts/inference-guardian/packages/`。从示例复制一份 source-manifest.json 到受管根目录的 config/，根据实际服务维护节点、容器、权重路径与启动脚本。自定义 probe-settings.json 与清单同目录保存。模型应已运行，Agent 管理端口仅对可信网络开放。示例启用 HTTP，运维需保障管理流量和 Token 的机密性。主控通过 SSH 连接工作节点。默认构建使用本地 ARM64 基础镜像或已核验的随包归档。

```bash
cd /data/scripts/inference-guardian
python3 -B packages/install_guardian.py --manifest config/source-manifest.json --mode observe
```

输出 `passed=true` 后查看验收报告，核对模型、节点、健康检查和真实生成。`--ssh-password` 在交互终端读取共用 SSH 密码。站点配置与私钥在部署端保管。

`observe` 安装以接管已运行模型为前提。它安装或更新 Guardian 的 Controller/Agent，读取模型状态并发起健康及生成探针。标准 P/D 配置关闭 Guardian 的可选 Gateway，站点自定义配置接管既有 Proxy 时也应设置 `gateway.enabled=false`。完成 `observe` 验收后，可另择窗口启用 `recovery`，该模式会在确认故障时执行恢复动作。

[P/D 指标转发](pd-metrics.md)使用独立进程和监控端口，可先于或晚于 Controller/Agent 部署。停止独立转发服务时，现有业务 Proxy 和自愈组件各自继续运行。

`upgrade --mode observe` 会归档记录、重新部署 Guardian 并重置恢复预算及代次。升级前关闭进行中的演练并对账未知动作。使用与目标部署相同的身份和现场输入；新的示例身份适用于独立验证环境。日常只读复查使用 verify。Controller 采用只读根文件系统、cap-drop ALL 和 no-new-privileges。符合条件的启动错误只允许一次 seccomp 兼容对比，通过固定版本自检后记录实际角色策略。

[恢复演练](recovery.md)
