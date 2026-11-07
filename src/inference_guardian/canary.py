"""每组单在途canary任务；结果绑定代次，线程只投递结果，不修改恢复状态。"""
import queue
import threading

def poll_or_start(tasks, group, runtime, needed, run_canaries, stop_event, audit):
    """每组最多一个有超时的canary任务；工作线程只投递结果，不改状态机。

    结果绑定恢复代次和人工命令修订号。旧任务结束前不叠加新请求，结束后若
    代次已变化则丢弃，避免迟到的成功结果覆盖维护或新一轮恢复状态。
    """
    gid = group["id"]
    key = (runtime["generation"], runtime["canary_revision"])
    task = tasks.get(gid)
    if task is not None:
        try:
            result = task["results"].get_nowait()
        except queue.Empty:
            return None
        del tasks[gid]
        if task["key"] == key and not runtime["maintenance"] and not stop_event.is_set():
            result._guardian_key = task["key"]
            return result
        audit.emit("stale_canary_discarded", group=gid)
    if needed and not runtime["maintenance"] and not stop_event.is_set():
        results = queue.Queue(maxsize=1)
        def execute():
            from .health.probes import ProbeResult
            try:
                result = run_canaries(group)
            except Exception as exc:
                result = ProbeResult("unknown", reason=type(exc).__name__)
            results.put(result)
        task = {"key": key, "results": results}
        tasks[gid] = task
        threading.Thread(target=execute, name="canary-" + gid, daemon=True).start()
    return None

