# 故障恢复与演练

四机 P/D 分离场景中，确认 P 故障且 D 健康时只重启 P 组。确认 D 故障时恢复 P+D。Mooncake 和 Proxy 只在 p0 的既有模型容器内启动，Proxy 等待所有配置的引擎健康。两机混部按整组恢复。未知动作保留回执，后续操作需先对账。

以下命令在主控的部署根目录运行，使用同一个已验收包和清单。为防止误操作，先审阅计划，再在维护窗口执行注入。命令会中断模型服务。

```bash
ig() { python3 -B packages/install_guardian.py "$@" --archive "$ARCHIVE" --manifest config/source-manifest.json; }
# ARCHIVE 指向已部署版本的完整源码包，PLAN 指向上一步输出的 plan_file。
ig verify --mode observe
ig exercise-plan --node p1 --fault container-stop --mode observe
ig exercise --plan-file "$PLAN" --wait-seconds 600
ig exercise-report --plan-file "$PLAN"
ig exercise-restore --plan-file "$PLAN"
```

observe 检测通过时报告为 detected_restore_required，Controller 模型动作数为 0。人工恢复通过时报告为 closed、passed=true 且 manual_restore.self_check=passed。四机 D 组选择 d1 并创建独立计划。在人工验收关闭后，可执行 `ig upgrade --mode recovery`。自动恢复验收需要新的 recovery 模式计划。中断后先查原计划的 exercise-report，未知动作不重放。日志、审计、计划及验收报告保存在部署端。
