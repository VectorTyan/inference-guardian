# P/D 引擎指标通过 P0 上报 AOM

Guardian 从已审阅的四机 P/D 部署清单生成 P0 转发允许列表和 Prometheus 文件发现目标。Prometheus 请求 `GET /metrics/engine?target=<id>`，转发服务将每次抓取转发给一个引擎的 `/metrics`。单个引擎失败时，对应目标产生 `up=0`。

指标转发可在自愈 Controller/Agent 安装前或安装后独立部署。对正在运行的推理服务，使用 P0 的独立监控端口。转发进程只读取配置并请求引擎指标，启停由独立的进程管理单元负责。启用自愈时，单独按 [Guardian 部署与验收流程](operations.md) 先进入 `observe`，再按现场安排启用 `recovery`。

## 生成采集文件

使用与现场部署一致的 `source-manifest.json`。服务器资产文件示例适用于公开四机示例，现场将 `server_id` 替换为资产系统中的稳定 ID。

```json
{
  "cluster": "a2-prod",
  "deployment": "example-chat-b-prod",
  "servers": {
    "p0": {"server_id": "bms-011", "resource_pool": "bms"},
    "p1": {"server_id": "bms-012", "resource_pool": "bms"},
    "d0": {"server_id": "bms-021", "resource_pool": "bms"},
    "d1": {"server_id": "bms-022", "resource_pool": "bms"}
  }
}
```

```bash
python3 -B scripts/generate_pd_metrics.py \
  --manifest examples/vllm-ascend/example-pd-dp4tp4/source-manifest.json \
  --inventory /path/to/pd-server-inventory.json \
  --relay-port 19191 \
  --output-dir local/pd-metrics-v1
```

公开 DP4/TP4 示例产出 4 个 Prefill 端点和 8 个 Decode 端点。引擎端口由各成员的 `api_port` 加本地 DP 偏移得到。Prometheus 默认访问清单中的 P0 地址与 `--relay-port`。已有监控专用 HTTPS 入口时，可用 `--scrape-url https://p0-monitor.example:443` 让 Prometheus 访问该入口。

## 独立启动 P0 转发服务

1. 在 P0 上，将输出目录的 `p0/` 内容复制到单独的指标服务目录，例如 `/opt/guardian-pd-metrics`。在该目录放置仅转发用户可读的 `pd-metrics.token`。Prometheus 挂载相同内容。使用独立 Python 环境，其中安装 Uvicorn 和 HTTPX。
2. 确认监控端口空闲，使用非特权账号启动独立进程。将 `$P0_MONITOR_IP` 替换为 Prometheus 可达的 P0 监控地址。可将命令登记到单独的 systemd 服务，使用独立的 CPU、内存限额。转发用户只需要读取该目录和访问目标引擎网络。

```bash
/opt/guardian-pd-metrics/venv/bin/python -m uvicorn \
  guardian_pd_metrics_relay:create_app --factory --lifespan on \
  --app-dir /opt/guardian-pd-metrics --host "$P0_MONITOR_IP" --port 19191
```

绑定地址与拓扑中的 P0 地址不同时，用 `--scrape-url` 指定可达地址。将监控端口限制在可信网络，跨共享网络时使用 HTTPS 并校验证书。可用 `GUARDIAN_PD_METRICS_ALLOWLIST` 和 `GUARDIAN_PD_METRICS_TOKEN_FILE` 覆盖文件路径。独立模式的启停和回退均无需重启原 Proxy。

## 接入 Prometheus

### 复用 P0 已安装的 BMS Prometheus

在 P0 安装含 `deploy.sh guardian-metrics` 的 `npu-metrics-monitor` 代码后，从 Guardian 源码目录运行以下命令。转发使用 Linux systemd 的 `LoadCredential`，并需要独立 Python 环境预装 Uvicorn 和 HTTPX。

```bash
sudo python3 -B scripts/deploy_pd_metrics.py \
  --manifest /path/to/source-manifest.json \
  --inventory /path/to/pd-server-inventory.json \
  --relay-port 19191 \
  --relay-python /opt/guardian-metrics-venv/bin/python
```

命令校验当前主机是清单中的 P0，创建独立 systemd 服务并绑定 `127.0.0.1`。随后调用本机 `npu-metrics-monitor` 的专用入口，向已运行的 host 网络 Prometheus 发布发现文件与独立采集令牌，使用现有容器内的 `promtool` 校验。首次接入经 `SIGHUP` 热加载并核对进程启动时间与加载状态。保留现场 AOM 的 Remote Write、写入规则和访问凭据。业务 Proxy、自愈组件和硬件采集容器独立运行。

更新拓扑时用新清单重跑相同命令。固定 job 已加载时，更新目标文件即可。当前每台 P0 支持一个联动部署，端口与服务目录需保持一致。定制 `write_relabel_configs` 的站点需要确认 AOM 能收到新 job，验收查询为 `up{job="vllm-pd-via-proxy"}`。

### 手工接入已有或独立 Prometheus

1. 将 `targets.json` 放到 Prometheus 可读的 `/etc/prometheus/pd-metrics/targets.json`，采集凭据默认位于 `/etc/prometheus/secrets/pd-metrics.token`。可通过 `--target-file` 和 `--scrape-token-file` 调整。向现有 Prometheus 的 `scrape_configs` 合并生成的 job，核对现有 AOM 写入规则允许该 job。已有任务覆盖同一批引擎时，按部署切换为一个采集任务。
2. 独立 Prometheus 可在生成时加 `--aom-url "$AOM_REMOTE_WRITE_URL" --aom-token-file /etc/prometheus/secrets/aom.token`，直接使用输出的 `prometheus.json` 作为配置。AOM Access Code 与 P0 采集令牌分别挂载。运行 `promtool check config`，再启动或重载 Prometheus。最后在目标 AOM 实例查询 `up{job="vllm-pd-via-proxy"}` 和实际引擎指标。

维护资产或引擎端口映射时，重新生成到新目录。先在 P0 侧原子替换允许列表，再在 Prometheus 侧原子替换发现文件。转发进程在每次抓取时读取本地配置。回退时还原已验收的文件，退出独立模式时停用该采集任务并停止转发进程。

## 可选的 Proxy 同端口模式

把生成命令中的 `--relay-port` 替换为 `--proxy-source /path/to/load_balance_proxy_server_example.py`。此模式要求 v5/v6 清单，生成的采集地址默认是原 Proxy 业务端口。将生成的适配版 Proxy 脚本和同目录的转发模块、允许列表及令牌放到原启动入口可读的位置。在维护窗口重启 Proxy 加载适配代码，切回原脚本时也需要重启。若现场已有独立前置代理并支持热加载路由，可由前置代理将指标路径分流到独立转发服务，原业务 Proxy 可继续运行。

## 标签和故障判定

| 标签 | 含义 |
| --- | --- |
| `cluster`、`deployment` | 部署的稳定归属。建议显式设置部署 ID，省略时使用 Guardian 的恢复组 ID。 |
| `role` | `prefill` 或 `decode`。 |
| `inference_instance` | 逻辑实例 ID，默认分别为 `prefill-01` 和 `decode-01`。使用 `--controller` 时从对应恢复组的 `instances[].id` 读取显式 ID，允许同角色下有多个实例。 |
| `member_id`、`dp_rank`、`metrics_target_id` | 清单成员、该角色内的 DP rank、逐端点标识。Prometheus 的 `instance` 为 `deployment/metrics_target_id`。 |
| `server_id`、`resource_pool`、`node_ip` | 承载引擎的服务器资产 ID、资源池和清单内的引擎宿主 IP。 |
| `metric_scope` | 此处为 `engine_local`，用于清单约定的逐本地 DP 引擎端点。现场接入前逐端点确认样本范围。 |

一个逻辑实例可包含多个成员。`role="decode", inference_instance="decode-01", member_id="d0"` 描述三个独立维度。采集配置可以表达同角色多实例，当前生成入口使用 Guardian 已支持的四机 P/D 清单格式。

P0 转发服务拒绝未授权请求和清单外目标。每个 worker 使用独立的监控连接池，最多并发 16 路转发。单次后端请求限时 5 秒，响应上限 4 MiB。后端 HTTP 错误和连接失败返回 502，超时返回 504。单目标故障可按 `metrics_target_id` 定位。若所有目标同时失败，检查转发服务和监控链路。

在隔离环境停止一个 Decode 引擎的指标端点。等待两个抓取周期，核对该目标变为 `up=0`，其他目标仍为 `up=1` 且引擎样本持续更新。恢复端点后核对目标自动回到 `up=1`。现场验收同时观察推理延迟与 AOM 样本到达时间。
