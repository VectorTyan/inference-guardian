"""p0集群发布编排：预检、一次构建、分发、受控升级及目标模式验收。"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time

from .deployment import GuardianDeployment
from .release_files import private_dir, digest
from .transport import command, Transport
from .image import prepare_image
from .profile_generation import generate, check_profile, upgrade_profile, compile_service_manifest
from .tokens import generate as generate_tokens
from .credentials import remap_secrets
from .release_files import INSTALL_ROOT, file_hash, safe_directory
from .mooncake_contract import MIXED_PROFILE, MIXED_EXAMPLES, SUPPORTED_DEPLOYMENTS, manifest_deployment_id, is_mixed, validate_manifest, PROFILE, V4_EXAMPLE, DEPLOYMENT_ID
from .node_release import NodeRelease
from .uninstall import read_marker, marker_path, plan_uninstall, execute_uninstall
from .release_state import NODES, Receipts, RolloutError, error_record, load_site, tree_manifest, write_private
from inference_guardian import read_source_version
from inference_guardian.storage import FileLock, atomic_json, read_json
from inference_guardian.log_format import utc8_timestamp


def freeze_profile(source, site, *, migrate=False):
    examples = source / 'examples/vllm-ascend'
    profile = Path(site['profile_directory']) if site['profile_directory'] else examples / V4_EXAMPLE
    pending = read_json(INSTALL_ROOT / 'operations/redeploy.json', {})
    from .inspection import active_identity
    active = active_identity(INSTALL_ROOT)
    if not site['profile_directory'] and pending.get('status') == 'in_progress' and pending.get('profile'):
        profile = safe_directory(Path(pending['profile']), INSTALL_ROOT)
    elif not site['profile_directory'] and active:
        from .inspection import installed
        # 这里只按原接管摘要定位输入；节点预检/事务续接仍负责核对实际状态。
        profile = installed(source, INSTALL_ROOT, verify=False).profile
    names = ['controller-external.json', 'deployment-external.json', 'source-manifest.json', 'probe-settings.json']
    raw = {}
    manifest_path = profile / 'source-manifest.json'
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise ValueError('complete regular-file profile required: source-manifest.json')
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    mixed = is_mixed(manifest)
    identity = manifest_deployment_id(manifest)
    if active and identity != active:
        raise ValueError('this dedicated host already manages a different model deployment')
    names += ['agent-external-' + n + '.json' for n in validate_manifest(manifest)]
    standalone = (manifest.get('version') == 6 and
                  not any((profile/n).exists() or (profile/n).is_symlink() for n in names
                          if n not in {'source-manifest.json', 'probe-settings.json'}))
    for name in ([] if standalone else names):
        path = profile / name
        if path.is_symlink() or not path.is_file():
            raise ValueError('complete regular-file profile required: ' + name)
        raw[name] = path.read_bytes()
    # 仅在六份输出与目标拓扑不同时按需查找旧布局。快照不提供策略或命令。
    def previous_layouts():
        for path in sorted((INSTALL_ROOT / 'config/profiles').glob('*/' + PROFILE + '/source-manifest.json')):
            yield read_json(safe_directory(path, INSTALL_ROOT))
    if standalone:
        base = None
        if pending.get('status') == 'in_progress' and pending.get('profile'):
            base = safe_directory(Path(pending['profile']), INSTALL_ROOT)
        elif active:
            from .inspection import installed
            base = installed(source, INSTALL_ROOT, verify=False).profile
        if base is not None and manifest_deployment_id(read_json(base/'source-manifest.json')) != identity:
            raise ValueError('cannot inherit settings from another deployment topology')
        inherited = upgrade_profile(base) if base is not None else None
        policy = profile / 'probe-settings.json'
        if policy.is_symlink() or (policy.exists() and not policy.is_file()):
            raise ValueError('regular probe settings file required')
        settings = policy.read_bytes() if policy.exists() else None
        selected = settings
        # 内置示例旁的策略只是首次安装默认值。升级沿用已验收策略；
        # 独立可编辑目录里的显式策略仍按现场输入处理。
        if inherited is not None and profile in [examples / name for name in MIXED_EXAMPLES.values()]:
            selected = None
        if selected is None and inherited is None:
            defaults = (examples/MIXED_EXAMPLES[identity] if mixed else examples)/'probe-settings.json'
            if defaults.is_symlink() or not defaults.is_file():
                raise ValueError('regular shared probe defaults required for first installation')
            selected = defaults.read_bytes()
        raw = compile_service_manifest(profile, manifest_bytes, inherited, selected)
        if (not migrate and base is not None and active
                and any(json.loads(data) != read_json(base/name) for name, data in raw.items())):
            raise ValueError('model service manifest differs from installed profile; use upgrade --mode observe')
        if (manifest_path.is_symlink() or manifest_path.read_bytes() != manifest_bytes or policy.is_symlink()
                or (policy.read_bytes() if policy.exists() else None) != settings
                or any((profile/n).exists() or (profile/n).is_symlink() for n in names
                       if n not in {'source-manifest.json', 'probe-settings.json'})):
            raise ValueError('profile changed during compilation; no candidate may be published')
    elif migrate:
        raw = upgrade_profile(profile, previous_manifests=previous_layouts())
    elif site['profile_directory'] and active:
        from .inspection import installed
        current = installed(source, INSTALL_ROOT, verify=False).profile
        # 升级后site仍可指向未覆盖的旧输入。卸载/重新部署仅在其兼容迁移结果
        # 与已接管快照完全一致时复用快照；现场另改的配置不能被忽略。
        candidate = upgrade_profile(profile, previous_manifests=previous_layouts())
        if all(json.loads(candidate[name]) == read_json(current/name) for name in names):
            raw = {name: (current/name).read_bytes() for name in names}
    elif site['profile_directory'] and json.loads(raw['source-manifest.json'])['version'] == 5:
        raw = upgrade_profile(profile, previous_manifests=previous_layouts(), add_missing_exit_policy=False)
    revision = digest({name:__import__('hashlib').sha256(data).hexdigest() for name,data in raw.items()})
    target = INSTALL_ROOT / 'config/profiles' / revision / (MIXED_PROFILE if mixed else PROFILE)
    for name, data in raw.items():
        write_private(target / name, data)
    check_profile(target)
    GuardianDeployment(target, 'p0').validate_startup_contract()
    return target, revision


class Rollout:
    nodes = NODES
    deployment_id = DEPLOYMENT_ID

    def __init__(self, archive, checksum, source, site, migrate=False, *, reset=False, ssh_password=None):
        self.archive, self.checksum, self.source, self.site = archive, checksum, source, site
        self.version = read_source_version(source)
        self.profile, revision = freeze_profile(source, site, migrate=migrate)
        manifest = read_json(self.profile / 'source-manifest.json')
        self.nodes = tuple(validate_manifest(manifest))
        self.deployment_id = manifest_deployment_id(manifest)
        self.transport = Transport(site, {n['id']:n['host'] for n in manifest['nodes']},
                                   **({'password': ssh_password} if ssh_password is not None else {}))
        self.input_digest = digest(dict(archive=checksum, site=site, profile_revision=revision))
        self.lifecycle_root = INSTALL_ROOT
        self.uninstalled = {} if reset else read_marker(INSTALL_ROOT)
        self.operation = (digest(dict(inputs=self.input_digest, after_uninstall=self.uninstalled['operation']))[:20]
                          if self.uninstalled else self.input_digest[:20])
        self.work = INSTALL_ROOT / 'operations' / self.operation
        self.journal = Receipts(self.work / 'coordinator', self.operation)
        self.package = INSTALL_ROOT / 'packages' / archive.name
        self.image_id = None

    def request(self, node):
        request = dict(operation=self.operation, node=node, profile=str(self.profile), mode=self.site['mode'],
                    image_id=self.image_id, archive_sha256=self.checksum,
                    readiness_timeout_seconds=self.site['readiness_timeout_seconds'])
        if getattr(self, 'rebuild_guardians', False):
            request['rebuild_guardians'] = True
        if getattr(self, 'recommission_plan', None):
            request['recommission'] = self.recommission_plan['nodes'][node]
        if getattr(self, 'uninstall_plan', None):
            request['uninstall'] = self.uninstall_plan['nodes'][node]
            request['uninstall_plan_id'] = self.uninstall_plan['plan_id']
        elif getattr(self, 'uninstalled', {}).get('status') == 'complete':
            request['restore_uninstall'] = self.uninstalled['operation']
        return request

    def replacement_cycle(self, *, create=False):
        """同版本已完成后仍可重建缺失组件；保留旧成功回执，不拿它重放新一轮。"""
        if create:
            next_operation = digest(dict(previous=self.operation, inputs=self.input_digest))[:20]
            write_private(self.work / 'replacement.json', (json.dumps(dict(previous=self.operation,
                          inputs=self.input_digest, operation=next_operation), sort_keys=True)+'\n').encode())
        seen = set()
        while (self.work / 'replacement.json').exists():
            if self.operation in seen:
                raise ValueError('invalid Guardian replacement history')
            seen.add(self.operation)
            record = read_json(self.work / 'replacement.json')
            following = digest(dict(previous=self.operation, inputs=self.input_digest))[:20]
            if record != dict(previous=self.operation, inputs=self.input_digest, operation=following):
                raise ValueError('Guardian replacement record differs from this release')
            self.operation = following
            self.work = self.lifecycle_root / 'operations' / self.operation
            self.journal = Receipts(self.work / 'coordinator', self.operation)

    def stage(self):
        """分发经过校验的发行包与配置快照，不改活动源码、Token或状态。"""
        bootstrap = self.source / 'scripts/install_guardian.py'
        remote_bootstrap = INSTALL_ROOT / 'packages' / ('install-' + self.checksum[:16] + '.py')
        program = ("import hashlib,runpy,sys; "
                   "assert hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest()==sys.argv[2]; "
                   "m=runpy.run_path(sys.argv[1]); p,_=m['extract_release'](sys.argv[3],sys.argv[4]); print(p)")
        for node in self.nodes:
            self.progress('prepare release files', node)
            self.transport.copy(node, self.archive, self.package)
            if node != 'p0':
                self.transport.copy(node, bootstrap, remote_bootstrap)
                extracted = self.transport.run(node, ['python3', '-B', '-c', program, str(remote_bootstrap),
                    file_hash(bootstrap), str(self.package), self.checksum], timeout=300).strip()
                if extracted != str(self.source):
                    raise ValueError('remote release directory differs from local release')
                for name, checksum in tree_manifest(self.profile).items():
                    if checksum is not None:
                        self.transport.copy(node, self.profile / name, self.profile / name)

    def call(self, node, action):
        request = self.request(node)
        path = self.work / node / ('request-' + digest(request)[:16] + '.json')
        private_dir(path.parent)
        existing = read_json(path)
        if existing is not None and existing != request:
            raise ValueError('release request differs from previous operation')
        atomic_json(path, request)
        if node == 'p0':
            return NodeRelease(request).execute(action)
        self.transport.copy(node, path, path)
        output = self.transport.run(node, ['python3', '-B', str(self.source / 'scripts/rollout_node.py'),
            '--request', str(path), '--action', action], timeout=self.site['readiness_timeout_seconds'] + 600)
        return json.loads(output)

    def step(self, node, action):
        self.progress(action, node)
        key = node + '-' + action
        previous = self.journal.get(key)
        if previous and previous['status'] != 'complete' and action not in {'prepare', 'redeploy-prepare'}:
            # SSH响应丢失时只查询远端确认记录，不重发变更动作。
            receipt = self.call(node, 'receipt-' + action)
            if receipt.get('status') == 'complete':
                atomic_json(self.journal.path(key), dict(previous, status='complete', result=receipt['result']))
                return receipt['result']
            raise ValueError('unconfirmed remote step; inspect receipts before continuing: ' + key)
        return self.journal.execute(key, lambda:self.call(node, action), retry_safe=action in {'prepare', 'redeploy-prepare'})

    def redeploy_tokens(self):
        """已有Token复用，缺少的标准节点Token自动补齐；重试复用本轮已持久化凭据。"""
        deployment = GuardianDeployment(self.profile, 'p0')
        sources = [self.work / 'secrets', deployment.runtime / 'secrets', INSTALL_ROOT / 'secrets']
        if self.deployment_id == DEPLOYMENT_ID:
            sources += [INSTALL_ROOT / 'examples/vllm-ascend' / PROFILE / '.runtime/p0/secrets',
                        Path('/data/inference-guardian-secrets')]
        references = {}
        roles = {}
        for node in self.nodes:
            refs = {}
            remap_secrets(deployment.agents[node], refs)
            if node == 'p0':
                remap_secrets(deployment.source_controller, refs)
            roles[node] = refs
            references.update(refs)
        selected = {}
        for name in references:
            for source in sources:
                path = safe_directory(source / name, source)
                if path.is_file():
                    selected[name] = path
                    break
        node_tokens = {node + '.token' for node in self.nodes}
        missing = set(references) - set(selected)
        if missing - node_tokens:
            raise ValueError('existing credential files missing: ' + ','.join(sorted(missing - node_tokens)))
        # 工作目录只保存本轮部署所需凭据；日志归档排除此目录。
        for name, source in selected.items():
            write_private(self.work / 'secrets' / name, source.read_bytes())
        created = generate_tokens(self.profile, self.work / 'secrets', missing_only=True)['count'] if missing else 0
        # 凭据源独立于可清理的部署记录；更换包或重建后仍可复用，不覆盖已有文件。
        for name in node_tokens:
            target = safe_directory(INSTALL_ROOT / 'secrets' / name)
            if not target.exists():
                write_private(target, (self.work / 'secrets' / name).read_bytes())
        for node, refs in roles.items():
            for name in refs:
                self.transport.copy(node, self.work / 'secrets' / name, self.work / node / 'secrets' / name)
        return dict(reused=bool(selected), generated=created, rotated=False, nodes=list(self.nodes))

    def redeploy(self, *, plan=False):
        """每次已完成的upgrade开启新部署；同一未完成操作只续接，不重放未知动作。"""
        marker = INSTALL_ROOT / 'operations/redeploy.json'
        previous = read_json(marker, {})
        if previous.get('status') == 'in_progress' and previous.get('inputs') != self.input_digest:
            directory = INSTALL_ROOT / 'operations' / previous['operation'] / 'coordinator'
            if any(directory.glob('*-redeploy-stop.json')):
                raise ValueError('redeployment already started; resume with the same archive and parameters')
        if previous.get('status') == 'in_progress' and previous.get('inputs') == self.input_digest:
            self.operation = previous['operation']
        else:
            self.operation = digest(dict(redeploy=1, inputs=self.input_digest, previous=previous.get('operation')))[:20]
        self.work = INSTALL_ROOT / 'operations' / self.operation
        self.journal = Receipts(self.work / 'coordinator', self.operation)
        NodeRelease(self.request('p0')).host()
        if not plan:
            atomic_json(marker, dict(operation=self.operation, inputs=self.input_digest, status='in_progress',
                                     profile=str(self.profile), archive_sha256=self.checksum))
        self.stage()
        if plan:
            survey = self.collect('redeploy-survey')
            print(json.dumps(dict(operation=self.operation, mode=self.site['mode'], nodes=survey,
                                  recovery_state='reset', old_records='archive_only', model_mutations=0), ensure_ascii=False))
            return 0
        self.journal.execute('inventory', lambda:self.collect('redeploy-survey'), retry_safe=True)
        image = self.journal.execute('image', self.image, retry_safe=True)
        self.image_id = image['image_id']
        for node in self.nodes[1:]:
            self.journal.execute(node + '-image', lambda node=node:self.distribute_image(node, image), retry_safe=True)
        self.journal.execute('tokens', self.redeploy_tokens, retry_safe=True)
        for node in self.nodes:
            self.step(node, 'redeploy-prepare')
        for node in self.nodes:
            self.step(node, 'redeploy-stop')
        for node in self.nodes:
            self.step(node, 'redeploy-reset')
        for node in self.nodes:
            self.step(node, 'redeploy-records')
        for node in self.nodes:
            self.step(node, 'redeploy-adopt')
        for node in self.nodes[1:] + ('p0',):
            self.step(node, 'redeploy-start')
        self.step('p0', 'redeploy-finish')
        result = self.verify()
        self.journal.execute('pointers', self.pointers)
        atomic_json(marker, dict(operation=self.operation, inputs=self.input_digest, status='complete',
                                 completed_at=utc8_timestamp(), mode=self.site['mode'],
                                 profile=str(self.profile), archive_sha256=self.checksum))
        return result

    @staticmethod
    def progress(stage, node='p0'):
        print(utc8_timestamp() + ' [' + node + '] ' + stage, file=sys.stderr, flush=True)

    def collect(self, action):
        """逐节点收集结果，完整报告四台故障；诊断文件不含凭据和原始Docker配置。"""
        result, errors = {}, {}
        for node in self.nodes:
            self.progress(action, node)
            try:
                result[node] = self.call(node, action)
            except Exception as exc:
                errors[node] = error_record(exc)
        path = INSTALL_ROOT / 'reports' / self.operation / (action + '-preflight.json')
        atomic_json(path, dict(time=utc8_timestamp(), operation=self.operation, action=action,
                               version=self.version, mode=self.site['mode'], nodes=result, errors=errors,
                               passed=not errors, model_mutations=0))
        if errors:
            summary = '; '.join(node + ': ' + e['code'] + ' — ' + e['error'] for node, e in errors.items())
            raise RolloutError('PREFLIGHT_FAILED', summary + '; report=' + str(path), dict(report=str(path)))
        return result

    def inventory(self):
        result = self.collect('survey')
        kinds = {item['kind'] for item in result.values()}
        if len(kinds) != 1:
            raise ValueError('mixed fresh/existing nodes require reconciliation; no controller stopped')
        return result

    def plan_recommission(self):
        nodes = self.collect('recommission-survey')
        plan = dict(version=1, kind='guardian-recommission', operation=self.operation,
                    deployment_id=self.deployment_id, archive_sha256=self.checksum, mode='observe',
                    profile=str(self.profile), nodes=nodes, history_preserved=False, old_containers_archived=False)
        plan['plan_id'] = digest(plan)
        path = INSTALL_ROOT / 'reports' / self.operation / ('recommission-plan-' + plan['plan_id'][:16] + '.json')
        write_private(path, (json.dumps(plan, ensure_ascii=False, indent=2) + '\n').encode('utf-8'))
        print(json.dumps(dict(plan_file=str(path), plan_id=plan['plan_id'], mode='observe',
                              containers_to_remove=[dict(node=n, id=c['id'], name=c['name'])
                                for n in self.nodes for c in nodes[n]['containers']],
                              history_preserved=False, old_containers_archived=False), ensure_ascii=False, indent=2))
        return 0

    def recommission(self, path):
        plan = read_json(path)
        if not isinstance(plan, dict):
            raise RolloutError('RECOMMISSION_PLAN_INVALID', '重新接管计划必须为JSON对象')
        body = {key: value for key, value in plan.items() if key != 'plan_id'}
        if (plan.get('plan_id') != digest(body) or plan.get('version') != 1
                or plan.get('kind') != 'guardian-recommission' or plan.get('operation') != self.operation
                or plan.get('deployment_id') != self.deployment_id or plan.get('archive_sha256') != self.checksum
                or plan.get('profile') != str(self.profile) or plan.get('mode') != 'observe'
                or self.site['mode'] != 'observe' or set(plan.get('nodes', {})) != set(self.nodes)):
            raise RolloutError('RECOMMISSION_PLAN_INVALID', '重新接管计划不匹配当前源码、参数或四节点身份')
        self.recommission_plan = plan
        write_private(self.work / 'recommission-approved.json',
                      (json.dumps(plan, ensure_ascii=False, sort_keys=True) + '\n').encode('utf-8'))
        # 所有节点先完成第二次只读复核；任一变化都在第一条删除命令前阻断。
        self.collect('recommission-check')
        barrier = INSTALL_ROOT / 'operations/recommission-observe-required.json'
        previous = read_json(barrier, {})
        if previous and not previous.get('observe_verified') and previous.get('plan_id') != plan['plan_id']:
            raise RolloutError('RECOMMISSION_PENDING', '另一份重新接管计划尚未完成observe验收')
        atomic_json(barrier, dict(plan_id=plan['plan_id'], operation=self.operation,
                                 history_preserved=False, observe_verified=False, deployment_id=self.deployment_id, time=utc8_timestamp()))
        for node in self.nodes:
            self.step(node, 'recommission-remove')
        self.collect('recommission-check')
        print(json.dumps(dict(operation=self.operation, cleanup_complete=True, next_action='apply --mode observe',
                              history_preserved=False, old_containers_archived=False, model_mutations=0), ensure_ascii=False))
        return 0


    def image(self):
        """协调器保留阶段日志；镜像文件与身份校验集中在image模块。"""
        self.progress('build or import Guardian image')
        return prepare_image(self.source, self.site['image'], self.version, self.checksum, INSTALL_ROOT)

    def distribute_image(self, node, image):
        path = Path(image['archive'])
        self.transport.copy(node, path, path)
        result = self.transport.run(node, ['docker', '--host', 'unix:///var/run/docker.sock', 'load', '--input', str(path)], timeout=1800)
        info = json.loads(self.transport.run(node, ['docker', '--host', 'unix:///var/run/docker.sock', 'image', 'inspect', image['image_id']]))[0]
        if info['Id'] != image['image_id'] or info['Architecture'] != 'arm64':
            raise ValueError('distributed image identity differs')
        # 兼容旧版按ID导出的无标签归档；只补显示标签，不改变接管镜像身份。
        tag = 'inference-guardian:' + self.version + '-' + self.checksum[:16]
        self.transport.run(node, ['docker', '--host', 'unix:///var/run/docker.sock', 'tag', image['image_id'], tag])
        tagged = json.loads(self.transport.run(node, ['docker', '--host', 'unix:///var/run/docker.sock', 'image', 'inspect', tag]))[0]
        if tagged['Id'] != image['image_id']:
            raise ValueError('distributed image tag identity differs')
        return dict(image_id=info['Id'])

    def tokens(self):
        target = safe_directory(INSTALL_ROOT / 'secrets', INSTALL_ROOT)
        if not target.exists():
            with tempfile.TemporaryDirectory(prefix='.tokens-', dir=str(INSTALL_ROOT)) as temporary:
                staging = Path(temporary) / 'secrets'
                generate_tokens(self.profile, staging)
                os.rename(str(staging), str(target))
        expected = [target / (node + '.token') for node in self.nodes]
        if any(p.is_symlink() or not p.is_file() for p in expected):
            raise ValueError('partial token set cannot be regenerated or rotated')
        if len({p.read_bytes().strip() for p in expected}) != len(self.nodes):
            raise ValueError('node tokens must be independent')
        for node in self.nodes[1:]:
            self.transport.copy(node, target / (node + '.token'), target / (node + '.token'))
        return dict(independent_tokens=len(self.nodes), rotated=False)

    def pointers(self):
        for node in self.nodes:
            program = ("import pathlib,os,sys; r=pathlib.Path(sys.argv[1]); t=pathlib.Path(sys.argv[2]); "
                       "p=r/'current'; q=r/'.current-next'; assert r/'releases' in t.parents; "
                       "assert not p.exists() or p.is_symlink(); assert not q.exists() and not q.is_symlink(); "
                       "q.symlink_to(t); os.replace(str(q),str(p))")
            self.transport.run(node, ['python3', '-c', program, str(INSTALL_ROOT), str(self.source)])
        return dict(current=str(self.source))

    def verify(self):
        reports = {node:self.call(node, 'verify') for node in self.nodes[1:] + ('p0',)}
        result = dict(version=self.version, operation=self.operation, mode=self.site['mode'],
                      profile=str(self.profile), source=str(self.source),
                      passed=True, canary_executed=True, recovery_exercised=False, nodes=reports)
        manifest = read_json(self.profile/'source-manifest.json')
        if manifest.get('version') == 6:
            result['served_model_name'] = manifest['served_model_name']
        directory = safe_directory(INSTALL_ROOT / 'reports' / self.operation, INSTALL_ROOT)
        private_dir(directory)
        path = directory / ('acceptance-' + str(time.time_ns()) + '.json')
        atomic_json(path, result)
        print(json.dumps(dict(version=self.version, operation=self.operation, mode=self.site['mode'],
                              passed=True, report=str(path)), ensure_ascii=False, indent=2))
        return 0

    def apply(self, *, require_existing=False):
        inventory = self.journal.execute('inventory', self.inventory, retry_safe=True)
        self.rebuild_guardians = any(item.get('rebuild_guardians') for item in inventory.values())
        if require_existing and (any(item['kind'] != 'upgrade' for item in inventory.values())
                                 or any(item.get('restore_uninstall') for item in inventory.values())):
            raise ValueError('upgrade requires an existing installation on all nodes; use apply for installation/restoration')
        image = self.journal.execute('image', self.image, retry_safe=True)
        self.image_id = image['image_id']
        for node in self.nodes[1:]:
            self.journal.execute(node + '-image', lambda node=node:self.distribute_image(node, image), retry_safe=True)
        if inventory['p0']['kind'] == 'install':
            self.journal.execute('tokens', self.tokens, retry_safe=True)
        prepared = {node:self.step(node, 'prepare') for node in self.nodes}
        if not all(v['unchanged'] for v in prepared.values()):
            if inventory['p0']['kind'] == 'upgrade' and not inventory['p0'].get('restore_uninstall'):
                self.step('p0', 'freeze')
                for node in self.nodes:
                    self.step(node, 'stop-agent')
            for node in self.nodes:
                self.step(node, 'activate')
            for node in self.nodes[1:] + ('p0',):
                self.step(node, 'start')
        self.step('p0', 'finish')
        result = self.verify()
        self.journal.execute('pointers', self.pointers)
        return result


def run(action, archive, checksum, source, config, mode, *, plan_file=None, ssh_password=None):
    auth = {'ssh_password': ssh_password} if ssh_password is not None else {}
    recommission = action in {'recommission-plan', 'recommission'}
    uninstall = action in {'uninstall-plan', 'uninstall'}
    if uninstall and mode is not None:
        raise ValueError('uninstall cannot select a deployment mode')
    if recommission and mode not in (None, 'observe'):
        raise ValueError('recommission only supports observe mode')
    site = load_site(config, 'observe' if recommission or uninstall else mode)
    with FileLock(safe_directory(INSTALL_ROOT / 'operations/cluster.lock', INSTALL_ROOT)):
        if action in {'upgrade', 'upgrade-plan'}:
            rollout = Rollout(archive, checksum, source, site, True, reset=True, **auth)
            return rollout.redeploy(plan=action == 'upgrade-plan')
        redeployment = read_json(INSTALL_ROOT / 'operations/redeploy.json', {})
        if redeployment.get('status') == 'in_progress' and action in {'apply', 'uninstall', 'recommission', 'verify'}:
            raise ValueError('finish the current upgrade before another deployment operation')
        exercise = read_json(INSTALL_ROOT / 'operations/exercise.json', {})
        if exercise and exercise.get('status') != 'closed' and action in {'apply', 'upgrade', 'uninstall', 'recommission'}:
            raise ValueError('open fault exercise blocks deployment; inspect its report and restore/reconcile first')
        barrier = INSTALL_ROOT / 'operations/recommission-observe-required.json'
        history_loss = read_json(barrier, {})
        if history_loss and not history_loss.get('observe_verified') and site['mode'] != 'observe':
            raise RolloutError('OBSERVE_ACCEPTANCE_REQUIRED', '重新接管后必须先完成observe部署验收，之后才可显式启用recovery')
        if history_loss and not history_loss.get('observe_verified') and action in {'plan', 'apply', 'upgrade-plan', 'upgrade', 'verify'}:
            cleanup = history_loss.get('operation', '')
            if not re.fullmatch('[0-9a-f]{20}', cleanup):
                raise RolloutError('RECOMMISSION_INCOMPLETE', '重新接管操作记录不完整')
            identity = history_loss.get('deployment_id', DEPLOYMENT_ID)
            if identity not in SUPPORTED_DEPLOYMENTS:
                raise ValueError('unknown deployment in recommission record')
            for node in (('p0', 'p1') if identity in MIXED_EXAMPLES else NODES):
                receipt = read_json(INSTALL_ROOT / 'operations' / cleanup / 'coordinator'
                                    / (node + '-recommission-remove.json'), {})
                if receipt.get('status') != 'complete':
                    raise RolloutError('RECOMMISSION_INCOMPLETE', node + '的移除结果尚未确认，先核对原重新接管回执')
        rollout = Rollout(archive, checksum, source, site, action in {'upgrade-plan', 'upgrade', 'verify'}, **auth)
        if action == 'verify' and redeployment.get('status') == 'complete':
            rollout.operation = redeployment['operation']
            rollout.work = INSTALL_ROOT / 'operations' / rollout.operation
            rollout.journal = Receipts(rollout.work / 'coordinator', rollout.operation)
        if action in {'plan', 'apply', 'upgrade-plan', 'upgrade', 'verify'}:
            rollout.replacement_cycle()
        lifecycle = rollout.uninstalled
        if lifecycle and lifecycle['status'] not in {'complete', 'restored'} and action in {'apply', 'upgrade', 'recommission'}:
            raise ValueError('incomplete uninstall blocks deployment; reconcile the original plan and receipts')
        if lifecycle and lifecycle['status'] == 'complete' and action in {'upgrade', 'upgrade-plan'}:
            raise ValueError('deployment was uninstalled; use apply to restore retained history')
        def accepted(result):
            if (result == 0 and lifecycle.get('status') == 'complete'
                    and rollout.journal.get('pointers').get('status') == 'complete'):
                atomic_json(marker_path(INSTALL_ROOT), dict(lifecycle, status='restored',
                            restored_by=rollout.operation, restored_at=utc8_timestamp()))
            if result == 0 and history_loss and not history_loss.get('observe_verified'):
                atomic_json(barrier, dict(history_loss, observe_verified=True, acceptance_operation=rollout.operation,
                                         verified_at=utc8_timestamp()))
            return result
        selected = read_json(plan_file, {}) if action == 'uninstall' and plan_file else {}
        for path in (INSTALL_ROOT / 'operations').glob('*/coordinator/*.json'):
            if path.parent.parent.name == (selected.get('operation') if action == 'uninstall' else rollout.operation):
                continue
            record = read_json(path)
            critical = path.stem == 'pointers' or path.stem.startswith('restore-') or any(path.stem.endswith('-' + step) for step in
                           ('freeze', 'stop-agent', 'activate', 'start', 'finish', 'recommission-remove',
                            'uninstall-prepare', 'uninstall-freeze', 'uninstall-stop', 'uninstall-backup', 'uninstall-remove',
                            'exercise-inject'))
            if action in {'apply', 'upgrade', 'uninstall', 'recommission'} and record.get('status') != 'complete' and critical:
                raise ValueError('another incomplete release must be reconciled first: ' + path.parent.parent.name)
        # 先确认执行宿主确为p0，再向其他节点上传任何材料。
        NodeRelease(rollout.request('p0')).host()
        # 成功部署后的重复apply只做最新验收；确认记录不会授权重放变更。
        if action in {'plan', 'apply', 'upgrade-plan', 'upgrade'} and rollout.journal.get('pointers').get('status') == 'complete':
            inventory = rollout.inventory()
            if any(item.get('rebuild_guardians') for item in inventory.values()):
                rollout.replacement_cycle(create=True)
        if action == 'verify' or (action in {'apply', 'upgrade'} and rollout.journal.get('pointers').get('status') == 'complete'):
            image = rollout.journal.get('image').get('result', {})
            rollout.image_id = image.get('image_id')
            return accepted(rollout.verify())
        rollout.stage()
        if action == 'uninstall-plan':
            return plan_uninstall(rollout)
        if action == 'uninstall':
            return execute_uninstall(rollout, plan_file)
        if action == 'recommission-plan':
            return rollout.plan_recommission()
        if action == 'recommission':
            return rollout.recommission(plan_file)
        if action in {'plan', 'upgrade-plan'}:
            inventory = rollout.inventory()
            if action == 'upgrade-plan' and any(item['kind'] != 'upgrade' or item.get('restore_uninstall')
                                              for item in inventory.values()):
                raise ValueError('upgrade requires an existing installation on all nodes')
            print(json.dumps(dict(operation=rollout.operation, action=inventory['p0']['kind'], mode=site['mode'],
                                  version=rollout.version, nodes=inventory, model_mutations=0,
                                  profile=str(rollout.profile)), ensure_ascii=False, indent=2))
            return 0
        return accepted(rollout.apply(require_existing=True) if action == 'upgrade' else rollout.apply())
