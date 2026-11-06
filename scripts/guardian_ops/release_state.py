"""发布事务的配置、文件快照和确认记录；运行状态与发行源码分离。"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
import time

from .release_files import INSTALL_ROOT, file_hash, safe_directory, tree_manifest, snapshot, write_private
from .release_files import digest, private_dir
from .site import load_site
from inference_guardian.storage import atomic_json, read_json

NODES = ('p0', 'p1', 'd0', 'd1')


class RolloutError(ValueError):
    """可跨SSH传递的受控诊断，不包含凭据、Env或完整Docker响应。"""
    def __init__(self, code, message, details=None):
        self.code = code
        self.details = details or {}
        super().__init__(message)


def error_record(error):
    return dict(code=getattr(error, 'code', 'DEPLOYMENT_CHECK_FAILED'),
                error=str(error), details=getattr(error, 'details', {}))


def require_state_history(state, *, controller=False):
    """只读验证既有历史，必须先于会创建父目录的FileLock；不修建或补零。

    从未执行变更的observe节点可以没有generations.json；已有变更记录时，
    对应代次必须存在且未倒退。目录全被人为重建为空的丢失不能仅凭此格式识别。
    """
    state = Path(state)
    for path in (state, state / 'agent', state / 'agent/actions', state / 'agent/audit',
                 state / 'deployment-audit'):
        if path.is_symlink() or not path.is_dir():
            raise ValueError('existing state history directory missing or unsafe: ' + str(path))
    generations_path = state / 'agent/generations.json'
    if generations_path.is_symlink() or (generations_path.exists() and not generations_path.is_file()):
        raise ValueError('unsafe generation history')
    generations = read_json(generations_path, {})
    if not isinstance(generations, dict) or any(not isinstance(name, str) or type(value) is not int
            or not 0 <= value <= 2**63 - 1 for name, value in generations.items()):
        raise ValueError('invalid generation history')
    for path in (state / 'agent/actions').glob('*.json'):
        if path.is_symlink() or not path.is_file():
            raise ValueError('unsafe action history')
        record = read_json(path)
        payload = record.get('payload') if isinstance(record, dict) else None
        if not isinstance(payload, dict):
            raise ValueError('invalid action history')
        if payload.get('action') != 'snapshot':
            generation, container = payload.get('generation'), payload.get('container')
            if (type(generation) is not int or not 0 <= generation <= 2**63 - 1
                    or not isinstance(container, str) or container not in generations
                    or generations[container] < generation):
                raise ValueError('generation history missing or behind persisted action')
    audits = [state / 'deployment-audit']
    if controller:
        directory, path = state / 'controller', state / 'controller/state.json'
        if directory.is_symlink() or not directory.is_dir() or path.is_symlink() or not path.is_file():
            raise ValueError('existing Controller state history missing or unsafe')
        value = read_json(path)
        if (not isinstance(value, dict) or value.get('version') != 1 or not isinstance(value.get('groups'), dict)
                or not value['groups'] or any(not isinstance(group, dict) for group in value['groups'].values())):
            raise ValueError('existing Controller state history is invalid')
        audits.append(directory / 'audit')
    # adoption和Controller state均在首次审计落盘之后写入，空审计不是合法既有历史。
    # 活动服务可继续追加；此处只确认文件存在，停止写入后由clear_journals校验完整哈希链。
    for directory in audits:
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError('existing audit history directory missing or unsafe: ' + str(directory))
        files = list(directory.glob('audit-*.jsonl'))
        if (not files or any(path.is_symlink() or not path.is_file() for path in files)
                or not any(path.stat().st_size > 0 for path in files)):
            raise ValueError('existing audit history is empty or unsafe: ' + str(directory))









class Receipts:
    """先持久化执行意图；确认完成才允许后续阶段，未知结果不重放。"""
    def __init__(self, directory, identity):
        self.directory = Path(directory)
        private_dir(self.directory)
        self.identity = identity

    def path(self, step):
        if not re.fullmatch(r'[a-z0-9_-]{1,64}', step):
            raise ValueError('invalid release step')
        return self.directory / (step + '.json')

    def get(self, step):
        value = read_json(self.path(step), {})
        if value and value.get('identity') != self.identity:
            raise ValueError('release receipt identity mismatch')
        return value

    def execute(self, step, operation, *, retry_safe=False):
        prior = self.get(step)
        if prior:
            if prior.get('status') == 'complete':
                return prior['result']
            if not retry_safe:
                raise ValueError('unconfirmed release step requires reconciliation: ' + step)
        record = dict(identity=self.identity, step=step, status='in_progress', started=time.time())
        if prior:
            record['previous_attempt'] = prior
        atomic_json(self.path(step), record)
        try:
            result = operation()
        except Exception as exc:
            record.update(status='unconfirmed', error_type=type(exc).__name__)
            atomic_json(self.path(step), record)
            raise
        record.update(status='complete', result=result, completed=time.time())
        atomic_json(self.path(step), record)
        return result
