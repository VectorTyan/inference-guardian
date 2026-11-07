# P/D 引擎指标通过 P0 上报 AOM

Guardian 从已审阅的四机 P/D 部署清单生成 P0 转发允许列表和 Prometheus 文件发现目标。Prometheus 访问 P0 原有端口的 `GET /metrics/engine?target=<id>`，P0 将每次抓取转发给一个引擎的 `/metrics`。部署拓扑和资产映射在管理节点合并。单个引擎失败时，对应目标产生 `up=0`。

## 生成采集文件

使用与现场部署一致的 v5 或 v6 `source-manifest.json` 和未适配的 Proxy Python 源码。v3/v4 清单固定了 Proxy 源文件摘要，应先通过 Guardian 的既有升级流程迁移。服务器资产文件示例适用于公开四机示例，现场将 `server_id` 替换为资产系统中的稳定 ID。

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
  --proxy-source /path/to/load_balance_proxy_server_example.py \
  --output-dir local/pd-metrics-v1
```

公开 DP4/TP4 示例产出 4 个 Prefill 端点和 8 个 Decode 端点。引擎端口与 Guardian 健康探针遵循同一规则，由每个成员的 `api_port` 加本地 DP 偏移得到。Proxy 抓取地址默认使用清单中 P0 的地址和 `external_port`。已有监控专用 HTTPS 入口时，使用 `--proxy-url https://p0-monitor.example:443` 指向该入口。

## 启用 P0 和 Prometheus

1. 将输出目录 `p0/` 下的同名适配版 Proxy 脚本、`guardian_pd_metrics_relay.py` 和 `pd-metrics-allowlist.json` 放入同一个受控目录，确保 Proxy 容器可读。使用现场现有的 Proxy 启动命令、参数和监听端口，从该目录启动适配后的同名脚本。启用时需要在维护窗口重启 Proxy。
2. 在同一目录放置仅 Proxy 运行用户可读的 `pd-metrics.token`，Prometheus 挂载相同内容。可用 `GUARDIAN_PD_METRICS_ALLOWLIST` 和 `GUARDIAN_PD_METRICS_TOKEN_FILE` 为 P0 指定容器内路径。将指标路由限制在可信监控网络内。经过共享或非可信网络时使用受控 HTTPS 入口并校验 TLS，网关业务路由应仅发布业务路径。
3. 将 `targets.json` 放到 Prometheus 可读的 `/etc/prometheus/pd-metrics/targets.json`，采集凭据默认位于 `/etc/prometheus/secrets/pd-metrics.token`。可通过 `--target-file` 和 `--scrape-token-file` 调整。向现有 Prometheus 的 `scrape_configs` 合并生成的 job，核对现有 AOM 写入规则允许该 job。已有直采任务覆盖同一批引擎时，按部署切换为一个采集任务。
4. 独立 Prometheus 可在生成时加 `--aom-url "$AOM_REMOTE_WRITE_URL" --aom-token-file /etc/prometheus/secrets/aom.token`，直接使用输出的 `prometheus.json` 作为配置。AOM Access Code 与 P0 采集令牌分别挂载。运行 `promtool check config`，再启动或重载 Prometheus。最后在目标 AOM 实例查询 `up{job="vllm-pd-via-proxy"}` 和实际引擎指标。

维护端口或资产映射时，重新生成到新目录。先在 P0 侧原子替换允许列表，再在 Prometheus 侧原子替换发现文件。Proxy 在每次抓取时读取本地配置，文件发现负责目标变更。回退时还原已验收的文件，退出该采集模式时切回原 Proxy 脚本和旧抓取任务。

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

P0 拒绝未授权请求和清单外目标。每个 worker 使用独立的监控连接池，最多并发 16 路转发。单次后端请求限时 5 秒，响应上限 4 MiB。后端 HTTP 错误和连接失败返回 502，超时返回 504。单目标故障可按 `metrics_target_id` 定位。若所有目标同时失败，检查 P0 本身和监控链路。

在隔离环境停止一个 Decode 引擎的指标端点。等待两个抓取周期，核对该目标变为 `up=0`，其他目标仍为 `up=1` 且引擎样本持续更新。恢复端点后核对目标自动回到 `up=1`。现场验收同时观察推理延迟与 AOM 样本到达时间。
