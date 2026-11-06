"""资料已丢失时的显式重新接管：只删除计划中已停止的Guardian，绝不清理目录。"""
from pathlib import Path
import re

from .deployment import DEFAULT_STATE_ROOT, PREVIOUS_STATE_ROOT, LEGACY_STATE_ROOT
from .components import document
from inference_guardian.container_contract import fingerprint
from .release_state import RolloutError


def guardian_inventory(deploy):
    result = deploy.docker_command(['container', 'ls', '--all', '--no-trunc', '--filter',
                         'label=guardian.deployment-id=' + deploy.deployment_id, '--format', '{{.ID}}'])
    if result.returncode:
        raise RolloutError('DOCKER_INVENTORY_UNAVAILABLE', 'Docker容器清单查询失败，不能确认旧部署是否存在')
    ids = result.stdout.split()
    if len(ids) > 256 or len(set(ids)) != len(ids) or any(not re.fullmatch('[0-9a-f]{64}', cid) for cid in ids):
        raise RolloutError('DOCKER_INVENTORY_INVALID', 'Docker容器清单格式异常')
    rows = []
    for cid in sorted(ids):
        info = deploy.inspect_docker(['container', 'inspect', cid])
        if info.get('Id') != cid:
            raise RolloutError('GUARDIAN_ID_CHANGED', 'Guardian容器身份发生变化')
        config, state = info.get('Config', {}), info.get('State', {})
        labels = config.get('Labels') or {}
        rows.append(dict(id=cid, name=info.get('Name', '').lstrip('/'), image=info.get('Image'),
                         node=labels.get('guardian.node'), component=labels.get('guardian.component'),
                         deployment_id=labels.get('guardian.deployment-id'),
                         deployment_kind=labels.get('guardian.deployment-kind'), profile=labels.get('guardian.profile'),
                         guardian_entrypoint=config.get('Entrypoint') == ['python', '-m', 'inference_guardian'],
                         guardian_command=config.get('Cmd') == [labels.get('guardian.component'), '--config',
                             '/etc/inference-guardian/' + str(labels.get('guardian.component')) + '.json'],
                         running=state.get('Running'), status=state.get('Status'),
                         paused=state.get('Paused'), restarting=state.get('Restarting'), dead=state.get('Dead'),
                         exit_code=state.get('ExitCode'), oom_killed=state.get('OOMKilled'),
                         started_at=state.get('StartedAt'), finished_at=state.get('FinishedAt'),
                         fingerprint=fingerprint(info),
                         mounts=[dict(source=m.get('Source'), target=m.get('Destination'), writable=m.get('RW'))
                                 for m in info.get('Mounts', [])]))
    return rows


def data_paths(release, containers=()):
    deploy = release.deploy
    paths = {deploy.runtime, deploy.state, release.root / 'secrets', Path('/data/inference-guardian-secrets')}
    paths.update(path.parent for path in release.baseline_candidates())
    paths.update(root / deploy.deployment_id / release.node for root in
                 (DEFAULT_STATE_ROOT, PREVIOUS_STATE_ROOT, LEGACY_STATE_ROOT))
    for item in containers:
        for mount in item['mounts']:
            if mount['target'] != '/var/run/docker.sock' and isinstance(mount['source'], str):
                paths.add(Path(mount['source']))
    return [dict(path=str(path), exists=path.exists(), symlink=path.is_symlink()) for path in sorted(paths)]


class Recommission:
    def __init__(self, release):
        self.release = release
        self.deploy = release.deploy

    def absent_paths(self, containers):
        paths = data_paths(self.release, containers)
        if any(p['exists'] or p['symlink'] for p in paths):
            raise RolloutError('DEPLOYMENT_DATA_PRESENT', '仍有配置、状态或Token目录，必须先对账，禁止清空历史',
                               dict(paths=paths, containers=containers))
        return paths

    def survey(self, *, allow_removed=False):
        r, d = self.release, self.deploy
        models = r.model_inventory()
        if r.installed()[0] is not None:
            raise RolloutError('ADOPTION_PRESENT', '发现接管基线，应使用正常升级，不能重新接管')
        d.require_naming_compatibility()
        containers = guardian_inventory(d)
        paths = self.absent_paths(containers)
        desired = document(d.profile.name, r.node, d.is_controller, 'sha256:' + '0' * 64,
                           'arm64', d.runtime, d.state, d.source_hash, deployment_id=d.deployment_id)
        names = {spec['container_name']: role for role, spec in desired['services'].items()}
        if not containers and allow_removed:
            return dict(node=r.node, models=models, containers=[], paths=paths)
        if {c['name'] for c in containers} != set(names) or len(containers) != len(names):
            raise RolloutError('GUARDIAN_SET_MISMATCH', '旧Guardian数量或名称与本节点角色不一致',
                               dict(expected_names=sorted(names), containers=containers))
        for item in containers:
            if (item['node'] != r.node or item['component'] != names[item['name']]
                    or item['deployment_kind'] != 'external-adopt-v1' or item['profile'] != d.profile.name
                    or not item['guardian_entrypoint'] or not item['guardian_command']):
                raise RolloutError('GUARDIAN_IDENTITY_MISMATCH', '旧Guardian标签或入口不匹配，拒绝移除', dict(container=item))
            if (item['status'] != 'exited' or item['running'] is not False
                    or any(item[k] for k in ('paused', 'restarting', 'dead'))):
                raise RolloutError('GUARDIAN_NOT_STOPPED', '只能移除明确已停止的旧Guardian，不能强制停止或删除', dict(container=item))
            if item['id'] in {pin['expected_container_id'] for pin in models.values()}:
                raise RolloutError('MODEL_ID_COLLISION', '模型与Guardian身份冲突')
        return dict(node=r.node, models=models, containers=containers, paths=paths)

    def check(self):
        r = self.release
        expected = r.request.get('recommission')
        if r.request['mode'] != 'observe' or not isinstance(expected, dict):
            raise RolloutError('RECOMMISSION_PLAN_REQUIRED', '重新接管必须绑定observe计划')
        receipt = r.receipts.get('recommission-remove')
        complete = receipt.get('status') == 'complete'
        if receipt and not complete:
            raise RolloutError('RECOMMISSION_UNCONFIRMED', '旧Guardian移除结果未确认，禁止自动重发；请核对节点回执')
        current = self.survey(allow_removed=complete)
        if complete:
            # 容器移除后也继续核对计划中的挂载源，不能因Docker不再列出挂载而漏查。
            self.absent_paths(expected['containers'])
            if current['containers'] or current['models'] != expected['models']:
                raise RolloutError('RECOMMISSION_DRIFT', '已确认清理后出现新容器或模型身份变化')
            wanted = sorted(c['id'] for c in expected['containers'])
            if receipt['result'].get('removed_ids') != wanted:
                raise RolloutError('RECOMMISSION_RECEIPT_MISMATCH', '移除回执与计划不一致')
        elif current != expected:
            raise RolloutError('RECOMMISSION_DRIFT', '容器、配置指纹、模型或文件状态已变化，请重新审阅计划')
        return current

    def remove(self):
        # execute()已在取得节点锁后完成check；写入意图后再次复核全部实时证据。
        r, d = self.release, self.deploy
        expected = r.request['recommission']
        if r.request['mode'] != 'observe' or self.survey() != expected:
            raise RolloutError('RECOMMISSION_DRIFT', '移除前实时证据与计划不一致')
        removed = []
        for item in expected['containers']:
            self.absent_paths(expected['containers'])
            current = {c['id']: c for c in guardian_inventory(d)}
            if current.get(item['id']) != item:
                raise RolloutError('GUARDIAN_ID_CHANGED', '移除前旧Guardian身份或状态变化')
            # 不使用-f/-v，不接受名称通配符，不删除镜像、卷或宿主目录。
            result = d.docker_command(['container', 'rm', item['id']])
            if result.returncode:
                raise RolloutError('GUARDIAN_REMOVE_UNCONFIRMED', 'Docker移除失败或结果不确定，检查回执后再处理')
            removed.append(item['id'])
        self.absent_paths(expected['containers'])
        if guardian_inventory(d) or r.model_inventory() != expected['models']:
            raise RolloutError('RECOMMISSION_POSTCHECK_FAILED', '移除后的容器清单或模型身份验证未通过')
        return dict(node=r.node, removed_ids=sorted(removed), history_preserved=False,
                    old_containers_archived=False, model_mutations=0)
