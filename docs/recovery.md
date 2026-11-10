# 故障恢复与演练

四机 P/D 分离场景中，确认 P 故障且 D 健康时只重启 P 组。确认 D 故障时恢复 P+D。Mooncake 和 Proxy 只在 p0 的既有模型容器内启动，Proxy 等待所有配置的引擎健康。两机混部按整组恢复。单机多卡只恢复 p0 的指定模型容器：stop → start → 执行服务脚本 → 等待健康及真实生成，不调用容器创建脚本。未知动作保留回执，后续操作需先对账。

以下命令在主控的部署根目录运行，使用同一个已验收包和清单。为防止误操作，先审阅计划，再在维护窗口执行注入。命令会中断模型服务。

```bash
ig() { python3 -B packages/install_guardian.py "$@" --archive "$ARCHIVE" --manifest config/source-manifest.json; }
# ARCHIVE 指向已部署版本的完整源码包，PLAN 指向上一步输出的 plan_file。
ig verify --mode observe
ig exercise-plan --node p1 --fault container-stop --mode observe
ig exercise --plan-file "$PLAN" --wait-seconds 900
ig exercise-report --plan-file "$PLAN"
ig exercise-restore --plan-file "$PLAN"
```

选择节点：四机 P 组用 p1、D 组用 d1；两机混部用 p1；单机多卡用 p0。验证进程退出时，将上面的 `--fault container-stop` 改为 `--fault process-exit`，沿用同一报告和人工恢复命令。若通过 site.json 安装，把函数里的 `--manifest config/source-manifest.json` 换为 `--config config/site.json`。单机无需 SSH 参数，命令均在模型宿主执行。前台服务脚本的人工恢复同样后台派发并等待就绪；等待中断后沿用原计划查询和续接，不再派发已确认的脚本。

observe 检测通过时报告为 detected_restore_required，Controller 模型动作数为 0。人工恢复通过时报告为 closed、passed=true 且 manual_restore.self_check=passed。四机 D 组选择 d1 并创建独立计划。在人工验收关闭后，可执行 `ig upgrade --mode recovery`。自动恢复验收需要新的 recovery 模式计划。中断后先查原计划的 exercise-report，未知动作不重放。日志、审计、计划及验收报告保存在部署端。

若升级尚停留在 p0-redeploy-finish，按[升级收尾续接](operations.md#续接旧版本未完成的升级收尾)直接使用新包执行 upgrade。程序先对账旧事务再完成新版本部署，无需旧压缩包或单独收尾命令。最后的新版本报告 passed=true 后，将下面的 ARCHIVE 指向该新包。未知动作未确认前不要执行故障注入。

对于已完成 recovery 验收的四机 P/D 部署，按 P1、D1 顺序分别执行 process-exit 演练。每次只执行一个计划，第一组报告 closed、passed=true 后再开始下一组。PLAN 使用该次 exercise-plan 输出的 plan_file，不复用旧计划。

```bash
ig verify --mode recovery
ig exercise-plan --node p1 --fault process-exit --mode recovery
ig exercise --plan-file "$PLAN" --wait-seconds 900
ig exercise-report --plan-file "$PLAN"
# 第一组验收关闭后，创建 D1 的独立计划并将 PLAN 更新为新 plan_file。
ig exercise-plan --node d1 --fault process-exit --mode recovery
ig exercise --plan-file "$PLAN" --wait-seconds 900
ig exercise-report --plan-file "$PLAN"
```

900 秒只控制本次报告轮询等待，适用于预计约十分钟加载权重的演练；它不改变升级健康等待或模型启动超时。超时或终端中断后先重跑原计划的 exercise-report，不重复发送注入。确认 P 故障且 D 健康时报告应仅包含 P 组恢复，确认 D 故障时应包含 P+D；恢复完成后检查真实 canary、自检结果及宿主审计。自动恢复失败时先核对未知动作，能够对账后使用原计划的 `ig exercise-restore --plan-file "$PLAN"`。
