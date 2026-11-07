"""有基线的Guardian卸载与保留数据校验；不清理目录、镜像或模型容器。"""
from contextlib import ExitStack
import json
import re

from .release_files import digest, file_hash, private_dir, safe_directory, snapshot, tree_manifest, write_private
from .release_state import Receipts, require_state_history
from .recommission import guardian_inventory
from inference_guardian.observability.audit import AuditLog
from inference_guardian.storage import FileLock, atomic_json, read_json
from inference_guardian.observability.log_format import utc8_timestamp


def marker_path(root, node=None):
    return root / 'operations' / ((node + '-uninstall.json') if node else 'uninstall.json')


def read_marker(root, node=None):
    value = read_json(safe_directory(marker_path(root, node)), {})
    if value and (value.get('version') != 1 or not re.fullmatch('[0-9a-f]{20}', value.get('operation', ''))
                  or not re.fullmatch('[0-9a-f]{64}', value.get('plan_id', ''))
                  or value.get('status') not in {'in_progress', 'removed', 'complete', 'restored'}):
        raise ValueError('invalid uninstall record; reconcile before deployment')
    return value


def scope(rollout, operation):
    rollout.operation = operation
    # 安装根来自协调器的已校验work，避免依赖源码路径层数。
    rollout.work = rollout.lifecycle_root / 'operations' / operation
    rollout.journal = Receipts(rollout.work / 'coordinator', operation)


def plan_uninstall(rollout):
    nodes = rollout.collect('uninstall-survey')
    # 正常服务与整组已停服务均可卸载；部分停止需先对账，不能猜测剩余写入者。
    states = {running for item in nodes.values() for running in item['running'].values()}
    if len(states) != 1:
        raise ValueError('mixed running/stopped Guardians require reconciliation before uninstall')
    plan = dict(version=1, kind='guardian-uninstall', inputs=rollout.input_digest,
                archive_sha256=rollout.checksum, nodes=nodes, data_preserved=True, model_mutations=0)
    plan['plan_id'] = digest(plan)
    plan['operation'] = digest(dict(uninstall=plan['plan_id']))[:20]
    path = rollout.lifecycle_root / 'reports' / plan['operation'] / 'uninstall-plan.json'
    write_private(path, (json.dumps(plan, ensure_ascii=False, indent=2) + '\n').encode('utf-8'))
    print(json.dumps(dict(plan_file=str(path), operation=plan['operation'],
        containers_to_remove={n: nodes[n]['components'] for n in rollout.nodes}, data_preserved=True,
        model_mutations=0), ensure_ascii=False, indent=2))
    return 0


def execute_uninstall(rollout, path):
    plan = read_json(path)
    if not isinstance(plan, dict):
        raise ValueError('uninstall requires a reviewed JSON plan')
    body = {k: v for k, v in plan.items() if k not in {'plan_id', 'operation'}}
    if (plan.get('version') != 1 or plan.get('kind') != 'guardian-uninstall'
            or plan.get('inputs') != rollout.input_digest or plan.get('archive_sha256') != rollout.checksum
            or plan.get('plan_id') != digest(body)
            or plan.get('operation') != digest(dict(uninstall=plan.get('plan_id')))[:20]
            or set(plan.get('nodes', {})) != set(rollout.nodes)):
        raise ValueError('uninstall plan differs from the selected package, site or profile')
    prior = read_marker(rollout.lifecycle_root)
    if prior and prior['status'] != 'restored' and prior['plan_id'] != plan['plan_id']:
        raise ValueError('another uninstall must be reconciled or restored first')
    if prior and prior['plan_id'] == plan['plan_id'] and prior['status'] == 'restored':
        raise ValueError('this uninstall was restored; generate a new plan for current container IDs')
    rollout.uninstall_plan = plan
    scope(rollout, plan['operation'])
    write_private(rollout.work / 'uninstall-approved.json',
                  (json.dumps(plan, ensure_ascii=False, sort_keys=True) + '\n').encode('utf-8'))
    rollout.collect('uninstall-check')
    marker = dict(version=1, operation=plan['operation'], plan_id=plan['plan_id'],
                  status='in_progress', time=utc8_timestamp())
    if not prior or prior['plan_id'] != plan['plan_id']:
        atomic_json(marker_path(rollout.lifecycle_root), marker)
    for node in rollout.nodes:
        rollout.step(node, 'uninstall-prepare')
    rollout.step('p0', 'uninstall-freeze')
    for node in rollout.nodes:
        rollout.step(node, 'uninstall-stop')
    # 四节点停止、台账清晰且备份全部完成后，才允许第一条rm。
    rollout.collect('uninstall-stopped')
    for node in rollout.nodes:
        rollout.step(node, 'uninstall-backup')
    for node in rollout.nodes:
        rollout.step(node, 'uninstall-remove')
    reports = rollout.collect('uninstall-verify')
    atomic_json(marker_path(rollout.lifecycle_root), dict(marker, status='complete', completed=utc8_timestamp()))
    report = rollout.lifecycle_root / 'reports' / rollout.operation / 'uninstall-complete.json'
    atomic_json(report, dict(time=utc8_timestamp(), operation=rollout.operation, nodes=reports,
                             data_preserved=True, model_mutations=0, passed=True))
    print(json.dumps(dict(uninstalled=True, report=str(report), data_preserved=True,
                          next_action='apply --mode observe', model_mutations=0), ensure_ascii=False, indent=2))
    return 0


class UninstallNode:
    def __init__(self, release):
        self.release = release

    def survey(self):
        r = self.release
        models = r.model_inventory()
        old, baseline = r.installed()
        if old is None:
            raise ValueError('uninstall requires the retained adoption baseline; use diagnosis for missing history')
        require_state_history(old.state, controller=old.is_controller)
        backend = old.component_manager(baseline, AuditLog(r.work / 'audit'))
        if set(baseline.get('components', {})) != set(backend.desired['services']):
            raise ValueError('incomplete Guardian adoption blocks uninstall')
        running = {}
        for service, cid in baseline['components'].items():
            info = backend.inspect(service, cid)
            if cid in {pin['expected_container_id'] for pin in models.values()}:
                raise ValueError('Guardian and model IDs collide')
            running[service] = info['State']['Running']
        self.no_other_writers(old, baseline)
        return dict(node=r.node, adoption=str(old.baseline_path), adoption_sha256=file_hash(old.baseline_path),
                    state=str(old.state), runtime=str(old.runtime), source_hash=baseline['source_hash'],
                    components=baseline['components'], models=models, running=running)

    @staticmethod
    def no_other_writers(old, baseline):
        for item in guardian_inventory(old):
            if item['id'] not in baseline['components'].values():
                info = old.inspect_docker(['container', 'inspect', item['id']])
                if (item['running'] is not False or item['status'] not in {'created', 'exited'}
                        or any(item[k] for k in ('paused', 'restarting', 'dead'))
                        or info.get('HostConfig', {}).get('RestartPolicy', {}).get('Name') != 'no'):
                    raise ValueError('additional Guardian writer or automatic restart blocks uninstall')

    def expected(self):
        expected = self.release.request.get('uninstall')
        if not isinstance(expected, dict) or not re.fullmatch('[0-9a-f]{64}', self.release.request.get('uninstall_plan_id', '')):
            raise ValueError('node uninstall requires an exact reviewed plan')
        return expected

    def check(self):
        r = self.release
        self.expected()
        receipt = r.receipts.get('uninstall-remove')
        if receipt:
            if receipt['status'] != 'complete':
                raise ValueError('uninstall removal unconfirmed; never replay rm automatically')
            return self.verify()
        return self.planned_survey()

    def planned_survey(self):
        expected = self.expected()
        current = self.survey()
        if {k: v for k, v in current.items() if k != 'running'} != {k: v for k, v in expected.items() if k != 'running'}:
            raise ValueError('uninstall plan drift; inspect current identities and generate a new plan')
        return current

    def prepare(self):
        result = self.check()
        if result.get('running') != self.expected()['running']:
            raise ValueError('Guardian running state changed since uninstall plan')
        atomic_json(self.release.work / 'discovery.json', dict(result, kind='upgrade'))
        return dict(prepared=True)

    def freeze(self):
        r = self.release
        current = self.check()
        if r.node != 'p0':
            raise ValueError('only p0 can stop the Controller')
        if current['running']['controller']:
            return r.freeze()
        old, _ = r.old()
        self.quiet(old)
        return dict(controller_stopped=True, already_stopped=True, model_mutations=0)

    def stop(self):
        self.check()
        return self.release.stop_agent()

    def quiet(self, old):
        require_state_history(old.state, controller=old.is_controller)
        self.release.clear_journals(old.state)
        if old.is_controller:
            groups = old.controller_state().get('groups', {})
            if not groups or any(g.get('recovery_inflight') is not False or g.get('phase') in
                    {'DRAINING', 'SNAPSHOT', 'STOPPING', 'STARTING', 'VALIDATING'} for g in groups.values()):
                raise ValueError('Controller recovery state is unfinished or unavailable')

    def stopped(self):
        current = self.check()
        if current.get('removed'):
            return current
        if any(current['running'].values()):
            raise ValueError('all Guardian writers must be stopped before uninstall')
        old, _ = self.release.old()
        self.quiet(old)
        return dict(stopped=True)

    def locks(self, old):
        require_state_history(old.state, controller=old.is_controller)
        locks = ExitStack()
        try:
            locks.enter_context(FileLock(old.state / 'deployment.lock'))
            locks.enter_context(FileLock(old.state / 'agent/agent.lock'))
            if old.is_controller:
                locks.enter_context(FileLock(old.state / 'controller/controller.lock'))
        except BaseException:
            locks.close()
            raise
        return locks

    def backup(self):
        r = self.release
        self.stopped()
        old, _ = r.old()
        with self.locks(old):
            self.quiet(old)
            backup = safe_directory(r.root / 'backups' / r.operation / r.node)
            private_dir(backup)
            state_files = snapshot(old.state, backup / 'state')
            runtime_files = snapshot(old.runtime, backup / 'runtime')
            retained = dict(version=1, operation=r.operation, plan_id=r.request['uninstall_plan_id'],
                            status='removed', expected=self.expected(), state_files=state_files,
                            runtime_files=runtime_files, backup=str(backup))
            atomic_json(r.work / 'retained.json', retained)
        return dict(backup=str(backup), data_preserved=True)

    def remove(self):
        r = self.release
        # 此时本次rm意图已落盘；复核实时证据，不把自己的in_progress当成可重放回执。
        if any(self.planned_survey()['running'].values()):
            raise ValueError('all Guardian writers must be stopped before uninstall')
        old, baseline = r.old()
        retained = read_json(r.work / 'retained.json')
        with self.locks(old):
            self.quiet(old)
            self.retained_files(old, retained)
            backend = old.component_manager(baseline, AuditLog(r.work / 'audit'))
            removed = []
            for service in ('controller', 'agent'):
                if service in baseline['components']:
                    cid = baseline['components'][service]
                    backend.remove(service, cid)
                    removed.append(cid)
            self.absent(old, baseline)
            if r.model_inventory() != self.expected()['models']:
                raise ValueError('model identity changed during uninstall')
            self.retained_files(old, retained)
            atomic_json(marker_path(r.root, r.node), retained)
        return dict(removed_ids=sorted(removed), model_mutations=0, data_preserved=True)

    @staticmethod
    def retained_files(old, retained):
        if (tree_manifest(old.state) != retained['state_files']
                or tree_manifest(old.runtime) != retained['runtime_files']):
            raise ValueError('retained state or runtime changed after uninstall backup')

    def absent(self, old, baseline):
        backend = old.component_manager(baseline, AuditLog(self.release.work / 'audit'))
        for service in baseline['components']:
            if backend.inspect(service) is not None:
                raise ValueError('uninstalled Guardian name has reappeared')
        # 查询全量CID，不将inspect失败或标签变化当作已删除。
        result = old.docker_command(['container', 'ls', '--all', '--no-trunc', '--format', '{{.ID}}'])
        ids = result.stdout.split() if isinstance(result.stdout, str) else None
        if (result.returncode or ids is None or len(ids) != len(set(ids))
                or any(not re.fullmatch('[0-9a-f]{64}', cid) for cid in ids)):
            raise ValueError('complete Docker inventory is unavailable')
        if set(ids) & set(baseline['components'].values()):
            raise ValueError('uninstalled Guardian CID still exists')
        self.no_other_writers(old, baseline)

    def verify(self):
        r = self.release
        receipt = r.receipts.get('uninstall-remove')
        expected = self.expected()
        if (receipt.get('status') != 'complete'
                or receipt['result']['removed_ids'] != sorted(expected['components'].values())):
            raise ValueError('confirmed removal receipt required')
        retained = read_marker(r.root, r.node)
        if (retained.get('operation') != r.operation or retained.get('plan_id') != r.request['uninstall_plan_id']
                or retained.get('status') != 'removed' or retained.get('expected') != expected):
            raise ValueError('uninstall retention record differs from plan')
        old, baseline = r.installed(expected)
        if not old or file_hash(old.baseline_path) != expected['adoption_sha256']:
            raise ValueError('retained adoption changed')
        self.absent(old, baseline)
        self.retained_files(old, retained)
        if r.model_inventory() != expected['models']:
            raise ValueError('model identity changed since uninstall')
        return dict(removed=True, removed_ids=receipt['result']['removed_ids'],
                    data_preserved=True, model_mutations=0, backup=retained['backup'])


def restore_record(release, old, baseline):
    """只允许完整卸载回执对应的重新部署，绝不因固定CID缺失而自动重建。"""
    operation = release.request.get('restore_uninstall')
    if not operation:
        return None
    retained = read_marker(release.root, release.node)
    if retained.get('operation') != operation or retained.get('status') != 'removed':
        raise ValueError('matching completed uninstall record required to restore')
    expected = retained['expected']
    if (str(old.baseline_path) != expected['adoption'] or file_hash(old.baseline_path) != expected['adoption_sha256']
            or baseline['components'] != expected['components']):
        raise ValueError('retained adoption differs; automatic restoration forbidden')
    # 回执身份由原请求固定；取回原请求后验证，而非给缺失CID开通用例外。
    requests = list((release.root / 'operations' / operation / release.node).glob('request-*.json'))
    matching = [read_json(path) for path in requests]
    matching = [r for r in matching if r.get('uninstall_plan_id') == retained['plan_id'] and r.get('uninstall') == expected]
    if len(matching) != 1:
        raise ValueError('original uninstall request is missing or ambiguous')
    receipts = Receipts(release.root / 'operations' / operation / release.node / 'receipts', digest(matching[0]))
    result = receipts.get('uninstall-remove')
    if result.get('status') != 'complete' or result['result']['removed_ids'] != sorted(baseline['components'].values()):
        raise ValueError('uninstall removal was never confirmed')
    helper = UninstallNode(release)
    helper.absent(old, baseline)
    helper.retained_files(old, retained)
    helper.quiet(old)
    return retained
