"""只读查询已加载的动作回执，不发送 Docker 请求或修改持久台账。"""
from __future__ import annotations


def _completed_action(record, payload, container_id, action):
    previous = record["payload"]
    return (previous["action"] == action
            and previous["container"] == payload["container"]
            and previous["generation"] == payload["generation"]
            and previous["recovery_group"] == payload["recovery_group"]
            and record.get("container_id") == container_id
            and record["phase"] == "complete"
            and record.get("response", {}).get("ok") is True)


def completed_stop(records, payload, container_id):
    """返回同容器、恢复组和代次的最近成功 stop，时间相同保留原记录顺序。"""
    candidates = (record for record in records
                  if _completed_action(record, payload, container_id, "stop"))
    return max(candidates, key=lambda record: record.get("created_at", 0), default=None)


def bootstrap_start_confirmed(records, payload, container_id, started_at):
    """只承认 start 明确关联的成功 stop，并绑定当前容器启动周期。"""
    for record in records.values():
        if (not _completed_action(record, payload, container_id, "start")
                or record.get("started_at") != started_at):
            continue
        stop = records.get(record.get("preceding_stop_action_id"))
        if stop and _completed_action(stop, payload, container_id, "stop"):
            return True
    return False
