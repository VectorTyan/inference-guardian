"""单节点发布工序：守护组件重建/保留状态部署；模型不启停，凭据复用。"""
from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import re
import shutil
import sys
import time

from .deployment import (GuardianDeployment, DEFAULT_INSTALL_ROOT, DEFAULT_RUNTIME_ROOT,
                            DEFAULT_STATE_ROOT, PREVIOUS_STATE_ROOT, LEGACY_STATE_ROOT,
                            digest, private_dir, validate_controller, validate_agent)
from .components import document, pending_operations
from .image import probe_startup
from inference_guardian import __version__
from .release_files import file_hash, safe_directory
from .mooncake_contract import SUPPORTED_DEPLOYMENTS, DEPLOYMENT_ID, PROFILE, path_only_command_upgrade
from .release_state import NODES, Receipts, RolloutError, error_record, snapshot, tree_manifest, write_private, require_state_history
from .release_state import REDEPLOY_STAGES
from .recommission import Recommission, guardian_inventory, data_paths
from inference_guardian.observability.audit import AuditLog, verify as verify_audit
from inference_guardian.containers.contract import bootstrap_stage_hashes
from inference_guardian.storage import FileLock, atomic_json, read_json
from inference_guardian.observability.log_format import utc8_timestamp
from .verification import verify_deployment
from .uninstall import UninstallNode, restore_record, marker_path
from inference_guardian.control.config import config_hash


class NodeRelease:
    def __init__(self, request):
        self.request = request
        self.node = request['node']
        self.operation = request['operation']
        if self.node not in NODES or not re.fullmatch(r'[0-9a-f]{20}', self.operation):
            raise ValueError('invalid release node or operation')
        self.root = DEFAULT_INSTALL_ROOT
        self.profile = safe_directory(Path(request['profile']))
        self.deploy = GuardianDeployment(self.profile, self.node)
        if self.deploy.deployment_id not in SUPPORTED_DEPLOYMENTS or self.deploy.controller_node != 'p0':
            raise ValueError('unsupported deployment identity or coordinator')
        self.work = safe_directory(self.root / 'operations' / self.operation / self.node)
        self.receipts = Receipts(self.work / 'receipts', digest(request))

    def redeploy_paths(self):
        """只清理本部署、本节点的运行目录；配置输入、Token源和模型文件不在范围内。"""
        states = {self.deploy.state}
        states.update(root / self.deploy.deployment_id / self.node for root in
                      (DEFAULT_STATE_ROOT, PREVIOUS_STATE_ROOT, LEGACY_STATE_ROOT))
        runtimes = {path.parent for path in self.baseline_candidates()}
        return {kind: [str(safe_directory(path, path.parent.parent)) for path in sorted(paths)]
                for kind, paths in (('state', states), ('runtime', runtimes))}

    def redeploy_survey(self):
        models = self.model_inventory()
        containers = guardian_inventory(self.deploy)
        for item in containers:
            if (item['node'] != self.node or item['component'] not in {'agent', 'controller'}
                    or (item['component'] == 'controller' and self.node != 'p0')
                    or not item['guardian_entrypoint'] or not item['guardian_command']
                    or item['id'] in {m['expected_container_id'] for m in models.values()}):
                raise ValueError('container is not a Guardian owned by this node')
        return dict(node=self.node, models=models, containers=containers, paths=self.redeploy_paths(),
                    recovery_state='reset', old_records='archive_only', model_mutations=0)

    def probe_security(self):
        roles = ['agent', 'controller'] if self.node == 'p0' else ['agent']
        selected = []
        for role in roles:
            try:
                policy = probe_startup(self.request['image_id'], __version__, role)
            except ValueError as exc:
                raise ValueError(f'{self.node}/{role} startup probe: {exc}') from exc
            if policy == 'unconfined':
                selected.append(role)
        return selected

    def redeploy_prepare(self):
        discovery = self.redeploy_survey()
        # 凭据已从p0现有文件分发，全部节点准备成功后才停止任何守护服务。
        self.deploy.prepare_adoption(self.work / 'secrets', self.request['image_id'])
        discovery['seccomp_unconfined'] = self.probe_security()
        atomic_json(self.work / 'redeploy-discovery.json', discovery)
        return discovery

    def redeploy_current(self):
        expected = read_json(self.work / 'redeploy-discovery.json')
        current = self.redeploy_survey()
        if current['models'] != expected['models'] or current['paths'] != expected['paths']:
            raise ValueError('model or managed paths changed during redeployment')
        pinned = {item['id']: item for item in expected['containers']}
        for item in current['containers']:
            if item['id'] not in pinned or item['fingerprint'] != pinned[item['id']]['fingerprint']:
                raise ValueError('Guardian changed during redeployment')
        return current

    def redeploy_stop(self):
        current = self.redeploy_current()
        # p0先停Controller再停Agent；协调器随后停止其余节点，未调用模型启停。
        for item in sorted(current['containers'], key=lambda c: c['component'] != 'controller'):
            if item['running']:
                result = self.deploy.docker_command(['container', 'stop', '--time', '30', item['id']], timeout=120)
                if result.returncode:
                    raise ValueError('Guardian stop outcome unconfirmed')
        if any(item['running'] for item in self.redeploy_current()['containers']):
            raise ValueError('Guardian stop not confirmed')
        return dict(stopped=True, model_mutations=0)

    def redeploy_reset(self):
        """用户明确选择重置：旧状态/动作仅归档，不解析为成功，也不重放。"""
        current = self.redeploy_current()
        if any(item['running'] for item in current['containers']):
            raise ValueError('stop all Guardians before resetting deployment')
        archive = safe_directory(self.root / 'logs/archive' / self.operation / self.node)
        private_dir(archive)
        # 宿主文件日志和完整旧恢复记录先可靠存档，再删除活动状态。
        for index, name in enumerate(current['paths']['state']):
            path = Path(name)
            if path.exists():
                snapshot(path, archive / ('state-' + str(index)))
        for item in current['containers']:
            result = self.deploy.docker_command(['container', 'logs', '--timestamps', item['id']], timeout=120)
            if result.returncode:
                raise ValueError('could not archive Guardian container logs')
            write_private(archive / (item['component'] + '-' + item['id'][:12] + '.log'),
                          (result.stdout + (getattr(result, 'stderr', '') or '')).encode('utf-8'))
        atomic_json(archive / 'reset.json', dict(time=utc8_timestamp(), operation=self.operation, node=self.node,
                    previous_records='archive_only_not_replayed', recovery_state_reset=True,
                    paths=current['paths'], model_mutations=0))
        # 删除精确的停止态Guardian；不使用-f/-v，不删除模型、镜像或卷。
        for item in self.redeploy_current()['containers']:
            if item['running']:
                raise ValueError('Guardian restarted before removal')
            if self.deploy.docker_command(['container', 'rm', item['id']]).returncode:
                raise ValueError('Guardian removal outcome unconfirmed')
        if self.redeploy_current()['containers']:
            raise ValueError('Guardian removal not confirmed')
        for paths in current['paths'].values():
            for name in paths:
                path = safe_directory(Path(name), Path(name).parent.parent)
                if path.exists():
                    shutil.rmtree(path)
        # 旧日志视图可能指向旧路径；只解除视图，实际文件已在上面归档。
        views = safe_directory(self.root / 'logs' / self.node)
        for role in ('agent', 'controller'):
            view = views / (role + '.log')
            if view.is_symlink():
                view.unlink()
            elif view.is_file():
                write_private(archive / (role + '-local.log'), view.read_bytes())
                view.unlink()
        return dict(reset=True, archive=str(archive), recovery_state_reset=True, model_mutations=0)

    def redeploy_adopt(self):
        self.redeploy_current()
        roles = read_json(self.work / 'redeploy-discovery.json').get('seccomp_unconfined', [])
        result = self.deploy.adopt(self.work / 'secrets', self.request['image_id'], seccomp_unconfined=roles)
        baseline = read_json(self.deploy.baseline_path)
        baseline['release'] = dict(operation=self.operation, archive_sha256=self.request['archive_sha256'],
                                   recovery_state_reset=True)
        atomic_json(self.deploy.baseline_path, baseline)
        return result

    def redeploy_archive_records(self):
        """旧发布/演练回执仅归档，当前重新部署回执继续用于中断续接。"""
        archive = safe_directory(self.root / 'logs/archive' / self.operation / self.node / 'deployment-records')
        private_dir(archive)
        for path in sorted((self.root / 'operations').iterdir()):
            if path.name in {self.operation, 'redeploy.json'} or path.name.endswith('.lock'):
                continue
            safe_directory(path)
            target = archive / path.name
            if path.is_dir():
                # 阻止链接指向管理目录外，临时凭据不是日志，不进入归档。
                tree_manifest(path)
                shutil.copytree(str(path), str(target), ignore=shutil.ignore_patterns('secrets'))
                shutil.rmtree(path)
            elif path.is_file():
                write_private(target, path.read_bytes())
                path.unlink()
        return dict(archive=str(archive), previous_operations='archive_only_not_replayed')

    def host(self):
        if os.geteuid() != 0 or platform.machine().lower() not in {'aarch64', 'arm64'}:
            raise ValueError('field release requires root on native ARM64')
        architecture, _ = self.deploy.inspect_engine()
        if architecture != 'arm64':
            raise ValueError('Docker must use native ARM64')
        # 比较配置监听IP与实际本机IPv4，避免SSH目标填错后接管另一台节点。
        import subprocess
        result = subprocess.run(['ip', '-4', '-o', 'addr', 'show'], check=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=10)
        addresses = re.findall(r'\binet\s+([^/\s]+)/', result.stdout)
        if self.deploy.agents[self.node]['listen']['host'] not in addresses:
            raise ValueError('SSH destination does not own the configured node address')

    def baseline_candidates(self):
        if self.deploy.deployment_id != DEPLOYMENT_ID:
            return [self.deploy.baseline_path]
        return [self.deploy.baseline_path,
                self.root / 'examples/vllm-ascend' / PROFILE / '.runtime' / self.node / 'adoption.json']

    def installed(self, discovery=None):
        """以已固定旧基线构造受限视图；仍复核模型PIN、运行文件及完整容器指纹。"""
        candidates = self.baseline_candidates()
        if discovery:
            candidates = [Path(discovery['adoption'])]
        existing = [p for p in candidates if p.exists() or p.is_symlink()]
        if not existing:
            return None, None
        if len(existing) != 1:
            raise ValueError('multiple adoption baselines found; reconcile before release')
        path = safe_directory(existing[0])
        baseline = read_json(path)
        if (baseline.get('node') != self.node or baseline.get('deployment_id') != self.deploy.deployment_id
                or baseline.get('controller_node') != 'p0' or baseline.get('naming_version') != 'inference-guardian-v1'
                or baseline.get('profile') != self.deploy.profile.name or Path(baseline.get('runtime', '')) != path.parent):
            raise ValueError('only the verified v0.3.0-or-later stable adoption can be upgraded')
        allowed_states = {root / self.deploy.deployment_id / self.node for root in
                          (DEFAULT_STATE_ROOT, PREVIOUS_STATE_ROOT, LEGACY_STATE_ROOT)}
        state = Path(baseline['state'])
        if state not in allowed_states:
            raise ValueError('custom legacy state path requires a reviewed migration')
        safe_directory(state, state.parent.parent)
        old = self.deploy.for_existing_installation(path.parent, state, baseline['source_hash'])
        old.inspect_baseline()
        require_state_history(old.state, controller=old.is_controller)
        return old, baseline

    def model_inventory(self):
        self.host()
        self.deploy.validate_startup_contract()
        models = {}
        for model in self.deploy.agents[self.node]['containers']:
            info, pin = self.deploy.inspect_model(model['name'])
            self.deploy.validate_model_files(info)
            if (info['State']['Running'] is not True or info['State'].get('Status') != 'running'
                    or any(info['State'].get(k) for k in ('Paused', 'Restarting', 'Dead'))):
                raise ValueError('model must already be running; installer never starts a model')
            models[model['name']] = dict(pin, started_at=info['State'].get('StartedAt'))
        return models

    @staticmethod
    def upgrade_component(old, baseline, backend, service):
        """升级允许已删除/同配置重建的Guardian；Docker不可用不等于容器不存在。"""
        result = old.docker_command(['container', 'ls', '--all', '--no-trunc', '--format', '{{.ID}}'])
        ids = result.stdout.split() if result.returncode == 0 and isinstance(result.stdout, str) else None
        if ids is None or any(not re.fullmatch(r'[0-9a-f]{64}', cid) for cid in ids):
            raise ValueError('Guardian container inventory unavailable')
        pinned = baseline['components'][service]
        # 同名已被重建时，仍核对这是本项目的Guardian及原挂载，不碰模型或其它容器。
        return backend.inspect(service, pinned if pinned in ids else None)

    def existing_component(self, old, baseline, backend, service):
        if not self.request.get('rebuild_guardians'):
            return backend.inspect(service, baseline['components'][service])
        info = self.upgrade_component(old, baseline, backend, service)
        discovery = read_json(self.work / 'discovery.json')
        expected = discovery.get('component_ids', baseline['components'])[service]
        if (info['Id'] if info else None) != expected:
            raise ValueError('Guardian changed during upgrade; retry after inspecting the current operation')
        return info

    def survey(self):
        self.model_inventory()
        old, baseline = self.installed()
        if old is None:
            containers = guardian_inventory(self.deploy)
            if containers:
                raise RolloutError('ADOPTION_MISSING_WITH_GUARDIANS',
                    '未找到接管基线，但仍有旧Guardian容器；先核对配置/状态/Token，资料确认丢失时使用显式重新接管流程',
                    dict(node=self.node, adoption_candidates=[str(p) for p in self.baseline_candidates()],
                         paths=data_paths(self, containers), containers=containers))
            self.deploy.require_naming_compatibility()
            if self.deploy.runtime.exists() or self.deploy.state.exists():
                raise ValueError('unowned runtime or state exists; not a first installation')
            return dict(kind='install', node=self.node)
        backend = old.component_manager(baseline, AuditLog(self.work / 'audit'))
        services = set(backend.desired['services'])
        if set(baseline.get('components', {})) != services:
            raise ValueError('existing install is incomplete; finish or reconcile it before upgrading')
        retained = restore_record(self, old, baseline)
        component_ids, rebuild = {}, False
        for service in (() if retained else services):
            info = self.upgrade_component(old, baseline, backend, service)
            component_ids[service] = info['Id'] if info else None
            rebuild = rebuild or not info or info['State']['Running'] is not True or info['Id'] != baseline['components'][service]
        listing = old.docker_command(['container', 'ls', '--all', '--no-trunc', '--filter',
                            'label=guardian.deployment-id=' + self.deploy.deployment_id, '--format', '{{.ID}}'])
        if listing.returncode:
            raise ValueError('complete Guardian writer inventory is unavailable')
        for cid in listing.stdout.splitlines():
            if (cid not in baseline['components'].values() and cid not in component_ids.values()
                    and old.inspect_docker(['container', 'inspect', cid])['State']['Running']):
                raise ValueError('additional running Guardian writer blocks release')
        old_agent = validate_agent(read_json(old.runtime / 'agent.json'))
        old_commands = {m['name']: bootstrap_stage_hashes(m.get('bootstrap_commands', {})) for m in old_agent['containers']}
        new_commands = {m['name']: bootstrap_stage_hashes(m.get('bootstrap_commands', {})) for m in self.deploy.agents[self.node]['containers']}
        if old_commands != new_commands:
            old_by_name = {m['name']: m.get('bootstrap_commands', {}) for m in old_agent['containers']}
            new_by_name = {m['name']: m.get('bootstrap_commands', {}) for m in self.deploy.agents[self.node]['containers']}
            if (set(old_by_name) != set(new_by_name) or not self.deploy.source_manifest
                    or not all(path_only_command_upgrade(old_by_name[name], commands,
                                   self.deploy.source_manifest, self.node) for name, commands in new_by_name.items())):
                raise ValueError('model startup path or command differs beyond supported legacy hash/Mooncake migration')
        return dict(kind='upgrade', node=self.node, adoption=str(old.baseline_path),
                    adoption_sha256=file_hash(old.baseline_path), state=str(old.state), runtime=str(old.runtime),
                    source_hash=baseline['source_hash'], guardian_image=baseline['guardian_image'],
                    **(dict(rebuild_guardians=True, component_ids=component_ids) if rebuild else {}),
                    **(dict(restore_uninstall=retained['operation']) if retained else {}))

    def prepare(self):
        result = self.survey()
        old, baseline = self.installed(result if result['kind'] == 'upgrade' else None)
        secrets = old.runtime / 'secrets' if old else self.root / 'secrets'
        prepared = self.deploy.prepare_adoption(secrets, self.request['image_id'])
        if old and (prepared[0]['models'] != baseline['models'] or prepared[0]['secret_hashes'] != baseline['secret_hashes']):
            raise ValueError('automatic software upgrade must preserve model identities and credential hashes')
        if old:
            required = sum(p.stat().st_size for base in (old.state, old.runtime) for p in base.rglob('*') if p.is_file())
            if shutil.disk_usage(self.root).free < 2 * required + 256 * 1024 * 1024:
                raise ValueError('insufficient space for verified state/runtime backups')
        result['seccomp_unconfined'] = self.probe_security()
        result['unchanged'] = bool(old and result['seccomp_unconfined'] == baseline.get('seccomp_unconfined', [])
                                   and not result.get('restore_uninstall') and not result.get('rebuild_guardians')
                                   and old.runtime == self.deploy.runtime and old.state == self.deploy.state
                                   and baseline['source_hash'] == self.deploy.source_hash
                                   and baseline.get('release', {}).get('archive_sha256') == self.request['archive_sha256']
                                   and baseline['guardian_image'] == prepared[0]['guardian_image'])
        atomic_json(self.work / 'discovery.json', result)
        return result

    def old(self):
        discovery = read_json(self.work / 'discovery.json')
        if discovery['kind'] != 'upgrade':
            raise ValueError('no prior adoption in this release transaction')
        old, baseline = self.installed(discovery)
        if not old or file_hash(old.baseline_path) != discovery['adoption_sha256']:
            raise ValueError('old adoption changed since preparation')
        return old, baseline

    def wait(self, check, description):
        started = time.monotonic()
        deadline, next_note = started + self.request['readiness_timeout_seconds'], started + 15
        while time.monotonic() < deadline:
            if check():
                return
            if time.monotonic() >= next_note:
                print('[' + self.node + '] waiting: ' + description, file=sys.stderr, flush=True)
                next_note = time.monotonic() + 15
            time.sleep(3)
        raise ValueError('timed out: ' + description)

    @staticmethod
    def maintenance_consumed(deploy, enabled):
        state = deploy.controller_state()
        groups = state.get('groups', {})
        return bool(groups) and not any((deploy.state / 'controller/commands').glob('*.json')) and all(
            g.get('maintenance') is enabled and g.get('recovery_inflight') is False
            and (not enabled or g.get('phase') == 'MAINTENANCE') for g in groups.values())

    def freeze(self):
        if self.node != 'p0':
            raise ValueError('only p0 can freeze the recovery writer')
        old, baseline = self.old()
        if self.request.get('rebuild_guardians'):
            # Agent缺失时无法走远端健康握手。先停唯一Controller写入者，随后各节点
            # stop-agent从宿主台账确认无未知模型动作；完整备份后统一创建observe组件。
            backend = old.component_manager(baseline, AuditLog(self.work / 'audit'))
            info = self.existing_component(old, baseline, backend, 'controller')
            if info:
                backend.transition('controller', 'stop', info['Id'])
            self.clear_journals(old.state)
            groups = old.controller_state().get('groups', {})
            if not groups or any(g.get('recovery_inflight') is not False for g in groups.values()):
                raise ValueError('unfinished model recovery must be reconciled before Guardian replacement')
            return dict(controller_stopped=True, maintenance=False, rebuild_guardians=True, model_mutations=0)
        config = validate_controller(read_json(old.runtime / 'controller.json'))
        old.require_clear_journals(config, require_startup=True)
        old.maintenance('on')
        self.wait(lambda: self.maintenance_consumed(old, True), 'old Controller maintenance consumption')
        old.set_mode('observe')
        config = validate_controller(read_json(old.runtime / 'controller.json'))
        old.require_resolution_maintenance(config, config['groups'][0])
        old.require_clear_journals(config, require_startup=True)
        backend = old.component_manager(baseline, AuditLog(self.work / 'audit'))
        backend.transition('controller', 'stop', baseline['components']['controller'])
        return dict(controller_stopped=True, maintenance=True, model_mutations=0)

    def stop_agent(self):
        old, baseline = self.old()
        backend = old.component_manager(baseline, AuditLog(self.work / 'audit'))
        if self.node == 'p0':
            controller = self.existing_component(old, baseline, backend, 'controller')
            if controller and controller['State']['Running']:
                raise ValueError('Controller must be stopped before any Agent migration')
        agent = self.existing_component(old, baseline, backend, 'agent')
        if agent:
            backend.transition('agent', 'stop', agent['Id'])
        self.clear_journals(old.state)
        return dict(agent_stopped=True, model_mutations=0)

    @staticmethod
    def clear_journals(state):
        for path in (state / 'agent/actions').glob('*.json'):
            record = read_json(path)
            if record.get('phase') != 'complete' and record.get('payload', {}).get('action') != 'snapshot':
                raise ValueError('unfinished or unknown model action blocks migration')
        if any((state / 'controller/commands').glob('*.json')):
            raise ValueError('pending Controller commands block migration')
        if any((state / 'agent/actions').glob('*.tmp')):
            raise ValueError('uncommitted action file requires reconciliation')
        for role in ('agent', 'controller'):
            verify_audit(state / role / 'audit')
        verify_audit(state / 'deployment-audit')

    def activate(self):
        discovery = read_json(self.work / 'discovery.json')
        if discovery['kind'] == 'install':
            result = self.deploy.adopt(self.root / 'secrets', self.request['image_id'],
                                       seccomp_unconfined=discovery.get('seccomp_unconfined', []))
            baseline = read_json(self.deploy.baseline_path)
            baseline['release'] = dict(operation=self.operation, archive_sha256=self.request['archive_sha256'])
            atomic_json(self.deploy.baseline_path, baseline)
            return result
        old, baseline = self.old()
        backend = old.component_manager(baseline, AuditLog(self.work / 'audit'))
        retained = restore_record(self, old, baseline)
        components = {}
        for service in (() if retained else backend.desired['services']):
            components[service] = self.existing_component(old, baseline, backend, service)
            if components[service] and components[service]['State']['Running']:
                raise ValueError('all local Guardian writers must be stopped before migration')
        require_state_history(old.state, controller=old.is_controller)
        # 原状态锁须确已释放；绝不复制仍在写入的动作台账。
        from contextlib import ExitStack
        with ExitStack() as locks:
            locks.enter_context(FileLock(old.state / 'deployment.lock'))
            locks.enter_context(FileLock(old.state / 'agent/agent.lock'))
            if old.is_controller:
                locks.enter_context(FileLock(old.state / 'controller/controller.lock'))
            require_state_history(old.state, controller=old.is_controller)
            self.clear_journals(old.state)
            prepared = self.deploy.prepare_adoption(old.runtime / 'secrets', self.request['image_id'])
            if prepared[0]['models'] != baseline['models'] or prepared[0]['secret_hashes'] != baseline['secret_hashes']:
                raise ValueError('model or credential identity changed during migration')
            backup = safe_directory(self.root / 'backups' / self.operation / self.node)
            private_dir(backup)
            state_files = snapshot(old.state, backup / 'state')
            runtime_files = snapshot(old.runtime, backup / 'runtime')
            atomic_json(backup / 'inventory.json', dict(state=state_files, runtime=runtime_files,
                        adoption_sha256=file_hash(old.baseline_path), old_state=str(old.state), old_runtime=str(old.runtime)))
            retired = {}
            for service, cid in ([] if retained else baseline['components'].items()):
                if components[service] is None:
                    retired[service] = dict(previous_id=cid, already_missing=True)
                    continue
                cid = components[service]['Id']
                # 保留原CID用于人工回退；先禁用自动拉起，再重命名停止态守护组件。
                name = backend.desired['services'][service]['container_name'] + '-retired-' + self.operation[:8]
                retired[service] = backend.retire(service, cid, name, old.inspect_docker)
            atomic_json(backup / 'retired-components.json', retired)
            if old.state != self.deploy.state:
                safe_directory(self.deploy.state)
                if self.deploy.state.exists():
                    raise ValueError('new state directory already exists')
                self.deploy.state.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                snapshot(old.state, self.deploy.state)
                # 留存完整备份后将旧活动目录移出旧命名空间，防止再次启动旧写入者。
                os.rename(str(old.state), str(backup / 'old-active-state'))
            os.rename(str(old.runtime), str(backup / 'old-active-runtime'))
            new_baseline, agent, controller, secrets = prepared
            if discovery.get('seccomp_unconfined', []):
                new_baseline['seccomp_unconfined'] = discovery.get('seccomp_unconfined', [])
            private_dir(self.deploy.runtime)
            private_dir(self.deploy.runtime / 'secrets')
            for name, raw in secrets.items():
                write_private(self.deploy.runtime / 'secrets' / name, raw)
                write_private(self.root / 'secrets' / name, raw)
            atomic_json(self.deploy.runtime / 'agent.json', agent)
            if controller:
                atomic_json(self.deploy.runtime / 'controller.json', controller)
            new_baseline['release'] = dict(operation=self.operation, previous_adoption_sha256=discovery['adoption_sha256'],
                                           archive_sha256=self.request['archive_sha256'], backup=str(backup))
            atomic_json(self.deploy.runtime / 'inference-guardian-node.yaml', document(
                self.deploy.profile.name, self.node, self.deploy.is_controller, new_baseline['guardian_image'],
                new_baseline['architecture'], self.deploy.runtime, self.deploy.state,
                self.deploy.source_hash, deployment_id=self.deploy.deployment_id,
                seccomp_unconfined=discovery.get('seccomp_unconfined', [])))
            atomic_json(self.deploy.baseline_path, new_baseline)
            if tree_manifest(self.deploy.state) != state_files:
                raise ValueError('migrated state differs before new writer startup')
            if retained:
                atomic_json(marker_path(self.root, self.node), dict(retained, status='restored',
                            restored_by=self.operation))
        self.deploy.audit_log().emit('release_upgrade_committed', operation=self.operation,
                                  previous_adoption=discovery['adoption_sha256'], backup=str(backup))
        return dict(upgraded=True, backup=str(backup), model_mutations=0, state_preserved=True)

    def start(self):
        result = self.deploy.up()
        # 固定运维视图指向原持久文件；不搬迁状态或复制日志。
        directory = safe_directory(self.root / 'logs' / self.node)
        private_dir(directory)
        for role in (['agent', 'controller'] if self.deploy.is_controller else ['agent']):
            link = directory / (role + '.log')
            target = self.deploy.state / role / 'inference-guardian.log'
            if link.is_symlink():
                if os.readlink(str(link)) != str(target):
                    raise ValueError('log view points to a different state file')
            elif link.exists():
                raise ValueError('log view conflicts with an existing file')
            else:
                link.symlink_to(target)
        return result

    def ready(self):
        config = validate_controller(read_json(self.deploy.runtime / 'controller.json'))
        def fresh():
            try:
                self.deploy.require_fresh_readiness(config)
                return True
            except ValueError:
                return False
        self.wait(fresh, 'fresh observe readiness and canary')

    def finish(self):
        if self.node != 'p0':
            raise ValueError('mode selection belongs to p0')
        config = validate_controller(read_json(self.deploy.runtime / 'controller.json'))
        target = 'auto' if self.request['mode'] == 'recovery' else 'observe'
        if config['mode'] == 'auto' and target == 'observe':
            self.deploy.maintenance('on')
            self.wait(lambda: self.maintenance_consumed(self.deploy, True), 'mode maintenance')
            self.deploy.set_mode('observe')
        if any(g.get('maintenance') for g in self.deploy.controller_state().get('groups', {}).values()):
            self.deploy.maintenance('off')
            self.wait(lambda: self.maintenance_consumed(self.deploy, False), 'maintenance exit')
        self.ready()
        report = verify_deployment(self.deploy, with_canary=True)
        if not report['passed']:
            atomic_json(self.work / 'failed-verification.json', report)
            raise ValueError('full verification failed; target recovery mode not enabled')
        self.deploy.set_mode(target)
        atomic_json(self.work / 'mode-selection.json', dict(mode=self.request['mode'], internal_mode=target,
                                                           mode_change_confirmed=True))
        self.ready()
        return dict(mode=self.request['mode'], internal_mode=target, canary_executed=True, recovery_exercised=False)

    def reconcile_finish(self):
        """仅续接已启动的收尾；先核对实际状态，绝不把未知Docker动作当作可重试。"""
        prior = self.receipts.get('redeploy-finish')
        if self.node != 'p0' or not prior:
            raise ValueError('an existing p0 redeploy-finish receipt is required')
        if prior.get('status') == 'complete':
            return prior['result']
        if prior.get('status') not in {'in_progress', 'unconfirmed'}:
            raise ValueError('invalid finish receipt status; preserve it for inspection')
        self.deploy.host_check()
        with self.deploy._lock():
            baseline = self.deploy.inspect_baseline()
            release = baseline.get('release', {})
            if (release.get('operation') != self.operation
                    or release.get('archive_sha256') != self.request['archive_sha256']
                    or baseline.get('guardian_image') != self.request['image_id']):
                raise ValueError('finish request differs from the adopted release')
            require_state_history(self.deploy.state, controller=True)
            audit = self.deploy.audit_log()
            backend = self.deploy.component_manager(baseline, audit)
            if set(baseline.get('components', {})) != {'agent', 'controller'}:
                raise ValueError('both pinned Guardian components are required to resume finish')
            components = {}
            for role, cid in baseline['components'].items():
                components[role] = backend.inspect(role, cid)
                if not components[role]['State']['Running']:
                    raise ValueError('Guardian stopped during finish; inspect its mode transition before resuming')
            config = validate_controller(read_json(self.deploy.runtime / 'controller.json'))
            state = self.deploy.controller_state()
            if state.get('config_hash') != config_hash(config):
                raise ValueError('Controller loaded configuration is unconfirmed; wait and inspect before resuming')
            target = 'auto' if self.request['mode'] == 'recovery' else 'observe'
            selection = read_json(self.work / 'mode-selection.json')
            if selection is not None and (selection != dict(mode=self.request['mode'], internal_mode=target,
                    mode_change_confirmed=True) or config['mode'] != target):
                raise ValueError('mode selection differs from the running Controller')
            self.deploy._quiet(config, target)
            if any((self.deploy.state / 'controller/commands').glob('*.json')):
                raise ValueError('Controller command is still pending; wait before resuming finish')
            self.deploy.require_clear_journals(config, require_startup=target == 'auto')
            # 审计链由audit_log核验。意图后的进程退出不能通过缺少mode-selection判定未执行。
            records = (json.loads(line)
                       for path in sorted((self.deploy.state / 'deployment-audit').glob('audit-*.jsonl'))
                       for line in path.read_text(encoding='utf-8').splitlines())
            pending = pending_operations(records)
            for role, intent in pending.items():
                # 只确认已经加载目标配置且健康的Controller启动；不补发stop/start。
                if (role != 'controller' or intent['fields']['operation'] != ['container', 'start']
                        or config['mode'] != target):
                    raise ValueError('unconfirmed Guardian operation requires inspection; no replay')
                self.deploy.require_fresh_readiness(config)
                started = re.fullmatch(r'(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?Z',
                                       components[role]['State'].get('StartedAt', ''))
                if not started:
                    raise ValueError('Controller startup epoch is unconfirmed; no replay')
                epoch = datetime.strptime(started[1], '%Y-%m-%dT%H:%M:%S').replace(tzinfo=timezone.utc).timestamp()
                epoch += float('0.' + (started[2] or '0'))
                if any(state['groups'][group['id']].get(field, 0) < epoch for group in config['groups']
                       for field in ('last_observed_at', 'last_canary')):
                    raise ValueError('Controller readiness predates its current startup; wait before resuming')
                audit.emit('guardian_operation_reconciled', service=role, intent_seq=intent['seq'],
                           component_id=baseline['components'][role], config_hash=state['config_hash'],
                           operation=self.operation, observed_running=True, replayed=False)
            audit.emit('release_finish_reconciled', operation=self.operation, receipt_status=prior['status'],
                       target_mode=target, helper_version=__version__, model_mutations=0)
        # 只有上述证据通过才重新等待健康；原回执嵌入previous_attempt，未知动作仍保留。
        return self.receipts.execute('redeploy-finish', self.finish, retry_safe=True)

    def verify(self):
        # 配置指纹跨软件版本可相同；健康不能替代目标源码包/镜像的发布验收。
        baseline = self.deploy.inspect_baseline()
        expected = self.request['archive_sha256']
        if baseline.get('release', {}).get('archive_sha256') != expected:
            raise ValueError('installed release archive differs from requested package; use the installed archive for verify')
        if self.request.get('image_id') and baseline['guardian_image'] != self.request['image_id']:
            raise ValueError('installed Guardian image differs from the requested release')
        report = verify_deployment(self.deploy, with_canary=self.node == 'p0')
        report['seccomp_unconfined'] = baseline.get('seccomp_unconfined', [])
        atomic_json(self.work / ('verification-' + str(time.time_ns()) + '.json'), report)
        if not report['passed']:
            raise ValueError('node verification failed; see protected operation report')
        if self.node == 'p0':
            mode = read_json(self.deploy.runtime / 'controller.json')['mode']
            if mode != ('auto' if self.request['mode'] == 'recovery' else 'observe'):
                raise ValueError('installed mode differs from requested mode')
        return report

    def execute(self, action):
        if action == 'redeploy-survey':
            return self.redeploy_survey()
        if action in {'uninstall-survey', 'uninstall-check', 'uninstall-stopped', 'uninstall-verify'}:
            return getattr(UninstallNode(self), action[len('uninstall-'):].replace('-', '_'))()
        if action == 'recommission-survey':
            return Recommission(self).survey()
        if action == 'recommission-check':
            return Recommission(self).check()
        if action == 'survey':
            return self.survey()
        if action == 'verify':
            return self.verify()
        if action.startswith('receipt-'):
            return self.receipts.get(action[8:])
        if action == 'reconcile-redeploy-finish':
            with FileLock(self.root / 'operations' / (self.node + '.lock')):
                return self.reconcile_finish()
        methods = {'prepare': self.prepare, 'freeze': self.freeze, 'stop-agent': self.stop_agent,
                   'activate': self.activate, 'start': self.start, 'finish': self.finish,
                   'recommission-remove': lambda: Recommission(self).remove()}
        methods.update({'redeploy-prepare': self.redeploy_prepare, 'redeploy-stop': self.redeploy_stop,
                        'redeploy-reset': self.redeploy_reset, 'redeploy-adopt': self.redeploy_adopt,
                        'redeploy-records': self.redeploy_archive_records,
                        'redeploy-start': self.start, 'redeploy-finish': self.finish})
        methods.update({'uninstall-' + name: getattr(UninstallNode(self), name)
                        for name in ('prepare', 'freeze', 'stop', 'backup', 'remove')})
        if action not in methods:
            raise ValueError('unknown release action')
        with FileLock(self.root / 'operations' / (self.node + '.lock')):
            if action == 'recommission-remove':
                Recommission(self).check()
            retry_safe = action == 'prepare' or REDEPLOY_STAGES.get(action, {}).get('retry_safe', False)
            return self.receipts.execute(action, methods[action], retry_safe=retry_safe)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request', type=Path, required=True)
    parser.add_argument('--action', required=True)
    args = parser.parse_args(argv)
    try:
        result = NodeRelease(read_json(args.request)).execute(args.action)
        print(json.dumps(result, ensure_ascii=False))
        return 0
    except Exception as exc:
        print(json.dumps(dict(error_type=type(exc).__name__, **error_record(exc)), ensure_ascii=False), file=sys.stderr)
        return 1
