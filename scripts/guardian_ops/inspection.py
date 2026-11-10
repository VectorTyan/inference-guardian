"""固定运维入口：默认只读；显式演练注入或人工恢复按计划与持久回执执行。"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
from .deployment import GuardianDeployment, remap_secrets
from .transport import Transport
from .release_files import INSTALL_ROOT, safe_directory, digest, write_private
from .mooncake_contract import DEPLOYMENT_ID, SUPPORTED_DEPLOYMENTS, is_single
from .presets import deployment_nodes, deployment_profile
from .release_state import NODES, load_site, Receipts
from .verification import agent_get, verify_deployment
from inference_guardian.observability.audit import AuditLog, verify as verify_audit
from inference_guardian.containers.contract import container_config_hash
from inference_guardian.control.config import config_hash
from inference_guardian.observability.log_format import utc8_timestamp
from inference_guardian.http_client import file_headers
from inference_guardian.storage import read_json, atomic_json, FileLock


# 固定注入程序只发送SIGTERM给配置规则完整匹配的进程。模型参数不输出到报告。
# 只用于显式exercise操作，不进入Agent恢复API，也不落地额外脚本文件。
PROCESS_EXIT = r'''
import os, signal, sys, shlex
from pathlib import Path
pattern, minimum = shlex.split(sys.argv[1]), int(sys.argv[2])
if not pattern or minimum < 1: raise SystemExit('invalid process selection')
def matches(pid):
    try: args=(Path('/proc')/str(pid)/'cmdline').read_bytes().decode().split('\0')
    except (FileNotFoundError, ProcessLookupError): return False
    return any((args[i]==pattern[0] or ('/' not in pattern[0] and Path(args[i]).name==pattern[0]))
               and args[i+1:i+len(pattern)]==pattern[1:] for i in range(len(args)-len(pattern)+1))
pids=[int(p.name) for p in Path('/proc').iterdir()
      if p.name.isdigit() and int(p.name)>1 and int(p.name)!=os.getpid() and matches(int(p.name))]
if len(pids)!=minimum: raise SystemExit('ambiguous process selection; no signal sent')
for pid in pids:
    if not matches(pid): raise SystemExit('process changed; outcome requires inspection')
    os.kill(pid,signal.SIGTERM)
print('signal_sent_count='+str(len(pids)))
'''


class RecoveryExercise:
    """现有运维入口的显式故障演练；计划固定身份，一次派发，后续仅收集报告。"""
    def __init__(self, deployment, site, checksum, root=INSTALL_ROOT, *, ssh_password=None):
        self.deployment, self.checksum, self.root = deployment, checksum, Path(root)
        hosts = {n['id']: n['host'] for n in deployment.source_manifest['nodes']}
        self.transport = Transport(site, hosts, **({'password': ssh_password} if ssh_password is not None else {}))
        self.readiness_timeout = site['readiness_timeout_seconds']
        self.marker = self.root/'operations/exercise.json'
        self.audit = deployment.state/'controller/audit'

    def docker(self, node, *argv):
        return self.transport.run(node, ['docker', '--host', 'unix:///var/run/docker.sock', *argv], timeout=180)

    def models(self):
        result = {}
        observed = inspect_status(self.deployment)['agents']
        form = '{"id":{{json .Id}},"started_at":{{json .State.StartedAt}},"running":{{json .State.Running}},"pid_mode":{{json .HostConfig.PidMode}}}'
        for node in self.deployment.source_manifest['nodes']:
            info = json.loads(self.docker(node['id'], 'inspect', '--format', form, node['container']))
            status = observed[node['id']]['containers'][node['container']]
            if info['id'] != status.get('container_id') or status.get('configuration_ok') is not True:
                raise ValueError('model identity/contract unavailable during exercise')
            result[node['id']] = dict(info, container=node['container'])
        return result

    def config(self):
        return read_json(self.deployment.runtime/'controller.json')

    def clear_operations(self):
        if read_json(self.root / 'operations/redeploy.json', {}).get('status') == 'in_progress':
            raise ValueError('unfinished redeployment blocks exercise; resume the original upgrade')
        critical = ('freeze', 'stop-agent', 'activate', 'start', 'finish', 'recommission-remove',
                    'uninstall-prepare', 'uninstall-freeze', 'uninstall-stop', 'uninstall-backup', 'uninstall-remove',
                    'exercise-inject')
        for path in (self.root/'operations').glob('*/coordinator/*.json'):
            if (path.stem == 'pointers' or path.stem.startswith('restore-')
                    or any(path.stem.endswith('-'+s) for s in critical)):
                if read_json(path).get('status') != 'complete':
                    raise ValueError('unknown operation blocks injection; inspect original receipts')

    def ready(self, mode):
        if self.config()['mode'] != ('auto' if mode == 'recovery' else 'observe'):
            raise ValueError('exercise mode must match running Controller; exercise never changes mode')
        if self.deployment.inspect_baseline().get('release', {}).get('archive_sha256') != self.checksum:
            raise ValueError('exercise archive must match installed release')
        self.deployment.require_clear_journals(self.config(), require_startup=True)
        report = verify_deployment(self.deployment, with_canary=True)
        if not report['passed']:
            raise ValueError('exercise requires complete fresh acceptance and persisted logs')
        return report

    def budget(self, mode):
        if mode == 'recovery':
            policy=self.config()['policy'];now=time.time()
            for group in self.deployment.controller_state()['groups'].values():
                if (group['incident_attempts'] >= policy['max_attempts'] or
                        sum(now-t < policy['attempt_window_seconds'] for t in group['attempts']) >= policy['max_attempts_per_window']):
                    raise ValueError('recovery budget exhausted; wait for the configured reset/window, never clear history')

    def exercise_nodes(self):
        groups = self.deployment.source_controller['groups']
        return {'p0'} if len(groups) == 1 and groups[0]['topology'] == 'single_node_mixed' else {'p1', 'd1'}

    def plan(self, node, fault, mode):
        if node not in self.exercise_nodes() or fault not in {'process-exit', 'container-stop'} or mode not in {'observe', 'recovery'}:
            raise ValueError('unsupported exercise case')
        if read_json(self.marker, {}).get('status', 'closed') != 'closed':
            raise ValueError('previous exercise still open; collect its report and restore first')
        self.clear_operations()
        self.budget(mode)
        acceptance = self.ready(mode)
        groups = self.config()['groups']
        if len(groups) != 1 or not ('partial_recovery' in groups[0] or groups[0]['topology'] in {'multi_node_mixed', 'single_node_mixed'}):
            raise ValueError('exercise requires one reviewed recovery group')
        group = groups[0]
        member = next((m for m in group['members'] if m['node'] == node), None)
        if member is None:
            raise ValueError('node is absent from the installed profile')
        partial = member['id'] in group.get('partial_recovery', {}).get('members', [])
        current = self.models()
        if fault == 'process-exit' and (not group.get('process_exit_detection') or current[node]['pid_mode']):
            raise ValueError('process exercise requires enabled PID evidence and a private container PID namespace')
        state = self.deployment.controller_state()
        plan = dict(version=1, kind='recovery-exercise', archive=self.checksum,
                    source_hash=self.deployment.source_hash, node=node, member=member['id'], fault=fault, mode=mode,
                    scope='partial' if partial else 'full', group=group['id'], models=current,
                    controller_hash=config_hash(self.config()),
                    generation=state['generation'], audit_seq=verify_audit(self.audit)['records'],
                    created_at=utc8_timestamp(), created_epoch=time.time())
        plan['id'] = digest(plan)[:20]
        directory = self.root/'reports'/('exercise-'+plan['id'])
        write_private(directory/'plan.json', (json.dumps(plan, ensure_ascii=False, indent=2)+'\n').encode())
        atomic_json(directory/'before.json', acceptance)
        return dict(plan_file=str(directory/'plan.json'), mode=mode, scope=plan['scope'], node=node, fault=fault,
                    warning='injection interrupts inference; observe requires manual restoration')

    def load(self, path):
        path = safe_directory(Path(path), self.root/'reports')
        plan = read_json(path)
        content = dict(plan);identifier = content.pop('id')
        if (plan.get('kind') != 'recovery-exercise' or digest(content)[:20] != identifier
                or path != self.root/'reports'/('exercise-'+identifier)/'plan.json'
                or plan['archive'] != self.checksum or plan['source_hash'] != self.deployment.source_hash
                or plan['node'] not in self.exercise_nodes() or plan['fault'] not in {'container-stop','process-exit'}
                or plan['mode'] not in {'observe','recovery'}):
            raise ValueError('exercise plan identity/configuration mismatch')
        return plan

    def inject(self, plan):
        receipts = Receipts(self.root/'operations'/('exercise-'+plan['id'])/'coordinator', plan['id'])
        step = plan['node']+'-exercise-inject'
        prior = receipts.get(step)
        if prior:
            if prior['status'] != 'complete':
                raise ValueError('injection outcome unknown; report only, never resend')
            return
        marker = read_json(self.marker, {})
        if marker.get('status', 'closed') != 'closed' and marker.get('id') != plan['id']:
            raise ValueError('another exercise is still open')
        self.clear_operations()
        if not 0 <= time.time() - plan['created_epoch'] <= 900:
            raise ValueError('unused exercise plan expired; re-plan after acceptance')
        self.budget(plan['mode'])
        self.ready(plan['mode'])
        if (self.models() != plan['models'] or self.deployment.controller_state()['generation'] != plan['generation']
                or config_hash(self.config()) != plan['controller_hash']):
            raise ValueError('model epoch or recovery generation changed since plan')
        audit_seq = verify_audit(self.audit)['records']
        atomic_json(self.marker, dict(id=plan['id'], status='active', audit_seq=audit_seq))
        def send():
            node = plan['node']; model = plan['models'][node]
            form = '{"started_at":{{json .State.StartedAt}},"running":{{json .State.Running}},"pid_mode":{{json .HostConfig.PidMode}}}'
            fresh = json.loads(self.docker(node, 'inspect', '--format', form, model['id']))
            if fresh != {key:model[key] for key in ('started_at','running','pid_mode')}:
                raise ValueError('target container epoch changed before dispatch')
            if plan['fault'] == 'container-stop':
                timeout = str(self.config()['policy']['stop_timeout_seconds'])
                self.docker(node, 'stop', '--time', timeout, model['id'])
            else:
                group = next(g for g in self.config()['groups'] if g['id'] == plan['group'])
                rule_id = group['process_exit_detection']['members'][plan['member']]['rule_id']
                container = next(c for c in self.deployment.agents[node]['containers'] if c['name']==model['container'])
                rule = next(r for r in container['required_processes'] if r['id']==rule_id)
                self.docker(node, 'exec', model['id'], 'python3', '-c', PROCESS_EXIT, rule['pattern'], str(rule['min_count']))
            return dict(dispatched_at=utc8_timestamp(), node=node, fault=plan['fault'], audit_seq=audit_seq)
        receipts.execute(step, send)

    def restore_steps(self, plan):
        """人工恢复只使用既有组计划和静态命令，不推断或扩大演练范围。"""
        if self.deployment.source_manifest['version'] not in (5, 6):
            raise ValueError('manual restore requires the deployed path-only v5/v6 startup configuration')
        config = self.config()
        group = next(g for g in config['groups'] if g['id'] == plan['group'])
        partial = group.get('partial_recovery', {})
        expected = 'partial' if plan['member'] in partial.get('members', []) else 'full'
        if plan['scope'] != expected or plan['mode'] != 'observe':
            raise ValueError('manual restore requires the original observe scope')
        members = {m['id']: m for m in group['members']}
        selected = partial['members'] if expected == 'partial' else list(members)
        steps = [dict(action='stop', members=selected, checks=[])]
        steps += partial['recovery_steps'] if expected == 'partial' else group['recovery_steps']
        batches = []
        for step in steps:
            batch = []
            for mid in step['members']:
                member = members[mid]
                stage = step.get('stage')
                name = 'restore-' + step['action'] + '-' + member['node'] + ('-' + stage if stage else '')
                batch.append(dict(name=name, node=member['node'], action=step['action'], stage=stage))
            batches.append((batch, step.get('checks', [])))
        preserved = partial['preserved_checks'] if expected == 'partial' else []
        return batches, [p for p in group['health_checks'] if p['id'] in preserved]

    def restore_receipts(self, plan):
        return Receipts(self.root/'operations'/('exercise-'+plan['id'])/'coordinator', plan['id'])

    def restore_progress(self, plan):
        """只读回执摘要；未知人工动作也必须阻止报告关闭及下一轮。"""
        receipts = self.restore_receipts(plan)
        records = {p.stem: receipts.get(p.stem) for p in sorted(receipts.directory.glob('restore-*.json'))}
        if not records:
            return None
        unknown = [name for name, record in records.items() if record.get('status') != 'complete']
        batches, _ = self.restore_steps(plan)
        expected = {'restore-begin', 'restore-accepted'} | {item['name'] for batch, _ in batches for item in batch}
        actions = expected - {'restore-begin', 'restore-accepted'}
        unknown += sorted(set(records) - expected)
        if 'restore-accepted' in records:
            unknown += sorted(expected - set(records))
        begin = records.get('restore-begin', {}).get('result', {})
        accepted = records.get('restore-accepted', {}).get('result', {})
        chain = verify_audit(receipts.directory.parent/'audit')
        if accepted and not chain['records']:
            raise ValueError('manual restore audit history missing')
        result = dict(status='unconfirmed' if unknown else ('complete' if accepted else 'in_progress'),
                      scope=plan['scope'], fault=plan['fault'], fault_injected_at=begin.get('fault_injected_at'),
                      started_at=begin.get('started_at'), completed_at=accepted.get('completed_at'),
                      duration_seconds=accepted.get('duration_seconds'), unknown_steps=unknown,
                      expected_model_actions=len(actions),
                      confirmed_model_actions=sum(records.get(name, {}).get('status') == 'complete' for name in actions),
                      steps=[dict(step=name, status=r.get('status'),
                                  started_at=utc8_timestamp(r['started']) if 'started' in r else None,
                                  completed_at=utc8_timestamp(r['completed']) if 'completed' in r else None)
                             for name, r in records.items()],
                      self_check=accepted.get('self_check', 'pending'),
                      acceptance=accepted.get('acceptance'),
                      audit_directory=str(receipts.directory.parent/'audit'))
        return result

    def restore_model(self, node, model):
        """精确CID的即时状态/配置指纹，不记录Docker原始参数或环境变量。"""
        items = json.loads(self.docker(node, 'inspect', model['id']))
        if not isinstance(items, list) or len(items) != 1:
            raise ValueError('exact model inspection required')
        info = items[0]; state = info['State']; host = info['HostConfig']
        if (info['Id'] != model['id'] or info['Name'] != '/' + model['container']
                or type(state.get('Running')) is not bool
                or state.get('Status') not in ({'running'} if state['Running'] else {'exited', 'created'})
                or any(state.get(k) for k in ('Paused', 'Restarting', 'Dead'))
                or host.get('AutoRemove') is not False or host.get('RestartPolicy', {}).get('Name') not in {'', 'no'}
                or host.get('PidMode', '') != model['pid_mode']):
            raise ValueError('unsafe or changed model lifecycle during manual restore')
        return dict(id=info['Id'], running=state['Running'], started_at=state['StartedAt'],
                    image=info['Image'], config_hash=container_config_hash(info))

    def restore_guard(self, plan, receipts, preserved):
        self.clear_operations()
        config = self.config()
        state = self.deployment.controller_state()
        group = state['groups'][plan['group']]
        marker = read_json(self.marker, {})
        if (marker.get('id') != plan['id'] or marker.get('status') != 'active'
                or config['mode'] != 'observe' or config_hash(config) != plan['controller_hash']
                or state['generation'] != plan['generation'] or group.get('recovery_inflight') is not False
                or group.get('maintenance') or any((self.deployment.state/'controller/commands').glob('*.json'))):
            raise ValueError('exercise, mode, configuration or Controller state changed; restore stopped')
        if self.deployment.inspect_baseline().get('release', {}).get('archive_sha256') != self.checksum:
            raise ValueError('manual restore archive differs from installed release')
        self.deployment.validate_startup_contract()
        self.deployment.require_clear_journals(config, require_startup=True)
        observed = self.models()  # Agent核对全组接管身份；进程缺失不阻止显式人工恢复。
        begin = receipts.get('restore-begin').get('result', {})
        current = {}
        for node, model in plan['models'].items():
            info = self.restore_model(node, model)
            started = receipts.get('restore-start-'+node).get('result', {}).get('model')
            stopped = receipts.get('restore-stop-'+node).get('result', {}).get('model')
            expected = started or stopped or dict(model, running=(False if
                node == plan['node'] and plan['fault'] == 'container-stop' else model['running']))
            if (any(info[k] != expected[k] for k in ('id', 'running', 'started_at'))
                    or any(observed[node][k] != info[k] for k in ('id', 'running', 'started_at'))
                    or (begin and any(info[k] != begin['models'][node][k] for k in ('image', 'config_hash')))):
                raise ValueError('model identity/epoch differs from confirmed restore receipts: '+node)
            current[node] = info
        if not all(self.deployment.probe_passes(p, 3) for p in preserved):
            raise ValueError('preserved D health unknown or failed; manual restore never expands scope')
        return current

    def restore_action(self, plan, item, before, audit):
        """调用方已持久化意图；命令或确认失败均留下未知回执，禁止重试。"""
        node, action, stage = item['node'], item['action'], item['stage']
        model = plan['models'][node]
        if self.restore_model(node, model) != before:
            raise ValueError('model changed immediately before restore dispatch')
        audit.emit('exercise_restore_action_intent', exercise=plan['id'], node=node, action=action,
                   stage=stage, time_local=utc8_timestamp())
        print('['+utc8_timestamp()+'] '+node+': restore '+action+(' '+stage if stage else ''),
              file=sys.stderr, flush=True)
        if action == 'stop':
            self.docker(node, 'stop', '--time', str(self.config()['policy']['stop_timeout_seconds']), model['id'])
        elif action == 'start':
            self.docker(node, 'start', model['id'])
        else:
            container = next(c for c in self.deployment.agents[node]['containers'] if c['name'] == model['container'])
            command = container['bootstrap_commands'][stage]
            detached = command['wait_for_exit'] is False and is_single(self.deployment.source_manifest)
            if command['wait_for_exit'] is not True and not detached:
                raise ValueError('manual restore requires confirmed foreground bootstrap completion')
            self.transport.run(node, ['docker', '--host', 'unix:///var/run/docker.sock', 'exec',
                               *(['-d'] if detached else []), '-w', command['working_dir'], model['id'], *command['argv']],
                               timeout=command['timeout_seconds'])
        after = self.restore_model(node, model)
        if (any(after[k] != before[k] for k in ('id', 'image', 'config_hash'))
                or after['running'] is not (action != 'stop')
                or (action == 'start' and after['started_at'] == before['started_at'])
                or (action != 'start' and after['started_at'] != before['started_at'])):
            raise ValueError('restore command returned but model result is not confirmed')
        audit.emit('exercise_restore_action_confirmed', exercise=plan['id'], node=node, action=action,
                   stage=stage, time_local=utc8_timestamp())
        return dict(model=after)

    def restore(self, plan):
        """显式observe人工恢复；同计划续接已确认步骤，健康等待可重试，未知动作不可重放。"""
        batches, preserved = self.restore_steps(plan)
        receipts = self.restore_receipts(plan)
        if receipts.get(plan['node']+'-exercise-inject').get('status') != 'complete':
            raise ValueError('manual restore requires a confirmed injection; reconcile original receipt')
        self.clear_operations()
        progress = self.restore_progress(plan)
        if progress and progress['status'] == 'unconfirmed':
            raise ValueError('restore receipt sequence incomplete or unknown; reconcile original history')
        if progress and progress['status'] == 'complete':
            return self.report(plan)
        previous = read_json(self.root/'reports'/('exercise-'+plan['id'])/'report.json', {})
        if previous.get('status') in {'closed', 'closed_failed'}:
            return self.report(plan)
        # 任何后续阶段已有回执但前序不完整，都不能通过重放前序动作补齐历史。
        missing = False
        for batch, checks in batches:
            recorded = [receipts.get(item['name']) for item in batch]
            if missing and any(recorded):
                raise ValueError('restore receipt sequence incomplete; reconcile, never reconstruct history')
            missing = missing or not all(recorded)
        if progress and not receipts.get('restore-begin'):
            raise ValueError('restore begin receipt missing; preserve action history')
        before = self.restore_guard(plan, receipts, preserved)
        audit = AuditLog(receipts.directory.parent/'audit')
        begin = receipts.execute('restore-begin', lambda: dict(started_at=utc8_timestamp(),
                    started_epoch=time.time(), scope=plan['scope'], fault=plan['fault'], models=before,
                    fault_injected_at=utc8_timestamp(receipts.get(plan['node']+'-exercise-inject')['completed'])))
        audit.emit('exercise_restore_started_or_resumed', exercise=plan['id'], scope=plan['scope'],
                   fault=plan['fault'], fault_injected_at=begin['fault_injected_at'],
                   started_at=begin['started_at'], time_local=utc8_timestamp())
        deadline = time.monotonic() + self.config()['policy']['startup_timeout_seconds']
        try:
            for batch, checks in batches:
                current = self.restore_guard(plan, receipts, preserved)
                pending = [item for item in batch if not receipts.get(item['name'])]
                if pending and time.monotonic() >= deadline:
                    raise ValueError('restore startup deadline exceeded; resume with the same plan')
                # 同阶段跨节点并发；收齐所有回执后才允许下一阶段。
                with ThreadPoolExecutor(max_workers=max(1, len(pending))) as pool:
                    futures = [pool.submit(receipts.execute, item['name'],
                               lambda item=item: self.restore_action(plan, item, current[item['node']], audit))
                               for item in pending]
                    for future in futures:
                        future.result()
                print('['+utc8_timestamp()+'] confirming '+batch[0]['name'], file=sys.stderr, flush=True)
                while True:
                    self.restore_guard(plan, receipts, preserved)
                    passed = [dict(id=p['id'], passed=self.deployment.probe_passes(p, 3)) for p in checks]
                    if all(p['passed'] for p in passed):
                        audit.emit('exercise_restore_stage_ready', exercise=plan['id'], step=batch[0]['name'],
                                   checks=passed, time_local=utc8_timestamp())
                        break
                    if time.monotonic() >= deadline:
                        audit.emit('exercise_restore_stage_wait_timeout', exercise=plan['id'],
                                   checks=passed, time_local=utc8_timestamp())
                        raise ValueError('restore health wait timed out; resume confirmed steps with the same plan')
                    time.sleep(5)
            deadline = time.monotonic() + self.readiness_timeout
            print('['+utc8_timestamp()+'] waiting for full observe acceptance', file=sys.stderr, flush=True)
            while True:
                self.restore_guard(plan, receipts, preserved)
                try:
                    acceptance = self.ready('observe')
                    break
                except ValueError:
                    if time.monotonic() >= deadline:
                        raise ValueError('restore final acceptance timed out; retry the same plan, not startup scripts')
                    time.sleep(5)
            self.restore_guard(plan, receipts, preserved)
            result = dict(completed_at=utc8_timestamp(), duration_seconds=max(0, time.time()-begin['started_epoch']),
                          self_check='passed', acceptance=acceptance)
            audit.emit('exercise_restore_completed', exercise=plan['id'], **result)
            # 仅落盘已完成的只读验收，不派发外部动作；中断后可重新验收再落盘。
            atomic_json(receipts.path('restore-accepted'), dict(identity=plan['id'], status='complete', result=result))
        except Exception as exc:
            audit.emit('exercise_restore_interrupted', exercise=plan['id'], error_type=type(exc).__name__,
                       reason=str(exc) if type(exc) is ValueError else 'action_or_persistence_result_unconfirmed',
                       time_local=utc8_timestamp())
            raise
        return self.report(plan)

    def report(self, plan):
        path=self.root/'reports'/('exercise-'+plan['id'])/'report.json'
        previous=read_json(path, {})
        if previous.get('status') in {'closed','closed_failed'}:
            return self.save_report(plan, previous)
        receipts = Receipts(self.root/'operations'/('exercise-'+plan['id'])/'coordinator', plan['id'])
        receipt = receipts.get(plan['node']+'-exercise-inject')
        report = dict(id=plan['id'], mode=plan['mode'], fault=plan['fault'], node=plan['node'], scope=plan['scope'],
                      time=utc8_timestamp(), passed=False, recovery_exercised=False,
                      injection_status=receipt.get('status', 'not_started'), status='waiting')
        if receipt.get('status') != 'complete':
            report['status'] = 'unconfirmed' if receipt else 'not_started'
            return self.save_report(plan, report)
        manual = self.restore_progress(plan)
        if manual:
            report['manual_restore'] = manual
            if manual['status'] != 'complete':
                report['status'] = 'unconfirmed' if manual['status'] == 'unconfirmed' else 'restore_in_progress'
                return self.save_report(plan, report)
        verify_audit(self.audit)
        events = []
        for path in sorted(self.audit.glob('audit-*.jsonl')):
            for line in path.read_text(encoding='utf-8').splitlines():
                event = json.loads(line)
                if event['seq'] > receipt['result']['audit_seq'] and event['fields'].get('group') == plan['group']:
                    events.append(event)
        group = next(g for g in self.config()['groups'] if g['id'] == plan['group'])
        expected_mode = 'auto' if plan['mode'] == 'recovery' else 'observe'
        if self.config()['mode'] != expected_mode or config_hash(self.config()) != plan['controller_hash']:
            raise ValueError('Controller mode changed during exercise')
        report['controller_phase'] = self.deployment.controller_state()['groups'][plan['group']]['phase']
        cause = 'confirmed_engine_process_exit' if plan['fault']=='process-exit' else 'container_confirmed_stopped'
        if plan['mode'] == 'observe':
            proposals = [e for e in events if e['event']=='recovery_proposed' and e['fields'].get('reason')==cause
                         and e['fields'].get('scope')==plan['scope'] and e['fields'].get('scope_blocked') is None]
            mutations = [e for e in events if e['event']=='action_intent' and e['fields'].get('action')!='snapshot']
            unchanged = self.deployment.controller_state()['generation']==plan['generation'] and not mutations
            report.update(passed=bool(proposals) and unchanged, proposal_observed=bool(proposals), model_actions=len(mutations))
            if report['passed']:
                report['status']='detected_restore_required'
            current = self.models()
            restored = (all(current[n]['id']==old['id'] for n,old in plan['models'].items())
                        and current[plan['node']]['started_at']!=plan['models'][plan['node']]['started_at'])
            if report['passed'] or restored:
                try:
                    self.ready('observe')
                except ValueError:
                    pass
                else:
                    report['status']='closed' if report['passed'] else 'closed_failed'
        else:
            starts = [e for e in events if e['event']=='recovery_started']
            if starts:
                start=starts[-1]['fields'];generation=start['generation']
                same=[e for e in events if e['fields'].get('generation')==generation or
                      str(generation) in str(e['fields'].get('action_id',''))]
                selected = group['partial_recovery']['members'] if plan['scope']=='partial' else [m['id'] for m in group['members']]
                steps = group['partial_recovery']['recovery_steps'] if plan['scope']=='partial' else group['recovery_steps']
                wanted = {('stop', m, None) for m in selected}
                wanted.update((s['action'],m,s.get('stage')) for s in steps for m in s['members'])
                intents = [e for e in same if e['event']=='action_intent' and e['fields'].get('action')!='snapshot']
                actual = {(e['fields']['action'],e['fields']['member'],e['fields'].get('stage')) for e in intents}
                confirmed = {e['fields']['action_id'] for e in same if e['event']=='action_result' and e['fields'].get('ok') is True}
                order = {('stop', m, None):0 for m in selected}
                for index, step in enumerate(steps,1):
                    order.update({(step['action'],m,step.get('stage')):index for m in step['members']})
                ranks = [order.get((e['fields']['action'],e['fields']['member'],e['fields'].get('stage')), -1) for e in intents]
                result_seq = {e['fields']['action_id']:e['seq'] for e in same
                              if e['event']=='action_result' and e['fields'].get('ok') is True}
                ordered = ranks==sorted(ranks) and all(
                    e['fields']['action_id'] in result_seq and e['seq'] < result_seq[e['fields']['action_id']]
                    and all(result_seq[e['fields']['action_id']] < later['seq']
                            for j,later in enumerate(intents) if ranks[j]>ranks[i]) for i,e in enumerate(intents))
                final = [e for e in same if e['event']=='recovery_validated' and e['fields'].get('self_check')=='passed']
                checks = [e['fields'] for e in same if e['event']=='recovery_self_check']
                post = [c for c in checks if c.get('phase')=='post_canary']
                canary = any(c.get('phase')=='canary' and c['checks'] and all(p['state']=='pass' for p in c['checks']) for c in checks)
                all_ids = {p['id'] for p in group['health_checks']}
                checked = bool(post) and {p['id'] for p in post[-1]['checks'] if p['state']=='pass'}==all_ids
                model_state = self.models()
                preserved = group['partial_recovery']['preserved_members'] if plan['scope']=='partial' else []
                nodes = {m['id']:m['node'] for m in group['members']}
                kept = all(model_state[nodes[m]]==plan['models'][nodes[m]] for m in preserved)
                pinned = all(model_state[n]['id']==old['id'] for n,old in plan['models'].items())
                restarted = all(model_state[nodes[m]]['running'] and
                                model_state[nodes[m]]['started_at']!=plan['models'][nodes[m]]['started_at'] for m in selected)
                valid = (generation>plan['generation'] and start.get('reason')==cause and start.get('scope')==plan['scope']
                         and actual==wanted and len(intents)==len(wanted) and all(e['fields']['action_id'] in confirmed for e in intents)
                         and bool(final) and checked and canary and kept and pinned and restarted and ordered)
                report.update(generation=generation, model_actions=len(intents), expected_actions=len(wanted),
                              preserved_members_unchanged=kept, final_checks_passed=checked, canary_passed=canary,
                              action_order_confirmed=ordered, model_ids_preserved=pinned, selected_members_restarted=restarted)
                if valid:
                    report['acceptance']=self.ready('recovery')
                    report.update(passed=True, recovery_exercised=True, status='closed', recovery=final[-1]['fields']['summary'])
        report['audit_records'] = [dict(seq=e['seq'], event=e['event'], fields=e['fields']) for e in events]
        return self.save_report(plan, report)

    def save_report(self, plan, report):
        path=self.root/'reports'/('exercise-'+plan['id'])/'report.json'
        previous=read_json(path, {})
        if previous.get('status') in {'closed','closed_failed'}:
            report=previous
        else:
            atomic_json(path, report)
        marker=read_json(self.marker, {})
        if (report['status'] in {'closed','closed_failed'} and marker.get('id')==plan['id']
                and marker.get('status')!='closed'):
            atomic_json(self.marker, dict(id=plan['id'], status='closed', closed_at=utc8_timestamp()))
        return dict(report, report_file=str(path))

    def close_failed(self, plan):
        receipts=Receipts(self.root/'operations'/('exercise-'+plan['id'])/'coordinator',plan['id'])
        if receipts.get(plan['node']+'-exercise-inject').get('status')!='complete':
            raise ValueError('unknown/unstarted injection cannot be closed; reconcile its original receipt')
        manual = self.restore_progress(plan)
        if manual and manual['status'] != 'complete':
            raise ValueError('unfinished manual restore cannot be closed; inspect its original receipts')
        acceptance=self.ready(plan['mode'])
        report=self.report(plan)
        if report['status'] in {'closed','closed_failed'}:
            return report
        report.update(passed=False,status='closed_failed',manually_closed=True,acceptance=acceptance,
                      recovery_exercised=False,closure='healthy_after_manual_review_not_automatic_recovery_acceptance')
        return self.save_report(plan,report)


def run_exercise(action, source, checksum, config, node=None, fault=None, mode=None, plan_file=None, wait_seconds=0, close=False, *, ssh_password=None):
    """只在显式exercise派发一次注入；重复调用及exercise-report仅核验回执和报告。"""
    with FileLock(safe_directory(INSTALL_ROOT/'operations/cluster.lock', INSTALL_ROOT)):
        deployment=installed(source)
        deployment.host_check()
        exercise=RecoveryExercise(deployment, load_site(config), checksum,
                                  **({'ssh_password': ssh_password} if ssh_password is not None else {}))
        if action=='exercise-plan':
            result=exercise.plan(node,fault,mode)
        else:
            plan=exercise.load(plan_file)
            if action == 'exercise-restore':
                try:
                    result = exercise.restore(plan)
                except Exception as exc:
                    result = exercise.report(plan)
                    result.update(restore_error_type=type(exc).__name__,
                                  restore_error=str(exc) if type(exc) is ValueError else 'Inspect restore receipts; never replay unknown actions')
                    print(json.dumps(result, ensure_ascii=False, indent=2))
                    return 1
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0 if result.get('status') == 'closed' and result.get('passed') else 1
            if close:
                result=exercise.close_failed(plan)
                print(json.dumps(result,ensure_ascii=False,indent=2))
                return 0 if result.get('passed') else 1
            if action=='exercise':
                try:
                    exercise.inject(plan)
                except Exception as exc:
                    result=exercise.save_report(plan, dict(id=plan['id'], time=utc8_timestamp(), passed=False,
                        status='injection_blocked_or_unconfirmed', error_type=type(exc).__name__, recovery_exercised=False,
                        detail=str(exc) if type(exc) is ValueError else 'Inspect the original injection receipt and node state; do not resend'))
                    print(json.dumps(result,ensure_ascii=False,indent=2))
                    return 1
            deadline=time.monotonic()+wait_seconds
            while True:
                try:
                    result=exercise.report(plan)
                except Exception as exc:
                    result=exercise.save_report(plan, dict(id=plan['id'], time=utc8_timestamp(), passed=False,
                        status='unconfirmed', error_type=type(exc).__name__, recovery_exercised=False,
                        detail=str(exc) if type(exc) is ValueError else 'Read-only evidence unavailable; keep original plan and receipts'))
                if (result.get('passed') or result['status']=='closed_failed'
                        or result.get('manual_restore', {}).get('status') == 'unconfirmed'
                        or result.get('injection_status') in {'not_started','in_progress','unconfirmed'} or time.monotonic()>=deadline):
                    break
                time.sleep(min(5,max(0,deadline-time.monotonic())))
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if action=='exercise-plan' or result.get('passed') else 1


def active_identity(root):
    active = [identity for identity in SUPPORTED_DEPLOYMENTS
              if (root/'runtime'/identity/'p0/adoption.json').is_file()]
    if len(active) > 1:
        raise ValueError("multiple active deployments on this execution host")
    return active[0] if active else None


def paths(node, root=INSTALL_ROOT):
    identity = active_identity(root) or DEPLOYMENT_ID
    return dict(deployment_id=identity, node=node,
        site=str(root/'config/site.json'), releases=str(root/'releases'), current=str(root/'current'),
        profiles=str(root/'config/profiles'), runtime=str(root/'runtime'/identity/node),
        state=str(root/'state'/identity/node), logs=str(root/'logs'/node),
        agent_log=str(root/'state'/identity/node/'agent/inference-guardian.log'),
        controller_log=str(root/'state'/identity/'p0/controller/inference-guardian.log'),
        packages=str(root/'packages'), reports=str(root/'reports'), operations=str(root/'operations'))


def installed(source, root=INSTALL_ROOT, *, verify=True):
    """以原接管指纹定位冻结配置；兼容旧深层布局，不能拿新模板冒充已部署配置。"""
    identity = active_identity(root) or DEPLOYMENT_ID
    profile_name = deployment_profile(identity)
    runtime = root/'runtime'/identity/'p0'
    baseline = read_json(runtime/'adoption.json', {})
    if not baseline:
        raise ValueError('p0 adoption missing; use paths and the deployment diagnosis guide')
    candidates = [source/'examples/vllm-ascend'/profile_name]
    # 旧版手工接管可能直接使用安装根中的完整示例，没有新式冻结副本。
    if root != source:
        candidates.append(root/'examples/vllm-ascend'/profile_name)
    directory = root/'config/profiles'
    candidates += sorted(directory.glob('*/' + profile_name))
    candidates += sorted(directory.glob('*/examples/vllm-ascend/' + profile_name))
    if len(candidates) > 257:
        raise ValueError('too many profile snapshots; select and review the installed profile manually')
    for profile in candidates:
        if not profile.is_dir():
            continue
        safe_directory(profile, root if root in profile.parents else source)
        try:
            deployment = GuardianDeployment(profile, 'p0', state_root=root/'state', runtime_dir=runtime)
        except ValueError:
            continue
        if deployment.source_hash == baseline.get('source_hash'):
            if verify:
                deployment.inspect_baseline()
            return deployment
    raise ValueError('no profile matches the installed adoption; do not overwrite runtime with new templates')


def inspect_status(deployment, node=None):
    result = deployment.status()
    result['profile'] = str(deployment.profile)
    result['agents'] = {}
    specs = remap_secrets(deployment.source_controller['nodes'], {}, directory=deployment.runtime/'secrets')
    for identifier, spec in specs.items():
        if node and identifier != node:
            continue
        try:
            status, body = agent_get(spec, '/v1/status', file_headers(spec))
            data = json.loads(body)
            if status != 200 or data.get('node_id') != identifier:
                raise ValueError('Agent identity mismatch')
            result['agents'][identifier] = {key:data.get(key) for key in
                ('containers', 'mutation_journal_clear', 'runtime_logging')}
        except Exception as exc:
            result['agents'][identifier] = dict(state='unknown', error_type=type(exc).__name__)
    return result


def run(action, source, config, node=None, service='agent', lines=200, root=INSTALL_ROOT, *, ssh_password=None):
    selected = node or 'p0'
    if selected not in NODES or service not in {'agent','controller'} or not 1 <= lines <= 2000:
        raise ValueError('invalid node, service or line count')
    if action == 'paths':
        view = paths(selected, root)
        if selected not in deployment_nodes(view['deployment_id']):
            raise ValueError('node is absent from the installed profile')
        print(json.dumps(view, ensure_ascii=False, indent=2))
        return 0
    deployment = installed(source, root)
    if selected not in deployment.agents:
        raise ValueError('node is absent from the installed profile')
    if action == 'status':
        print(json.dumps(inspect_status(deployment, node), ensure_ascii=False, indent=2))
        return 0
    if action != 'logs' or (service == 'controller' and selected != 'p0'):
        raise ValueError('controller logs exist only on p0')
    # 使用已核对的模型节点地址和固定日志路径，不远程执行可变Shell文本。
    site = load_site(config)
    hosts = {entry['id']:entry['host'] for entry in deployment.source_manifest['nodes']}
    path = root/'state'/deployment.deployment_id/selected/service/'inference-guardian.log'
    text = Transport(site, hosts, **({'password': ssh_password} if ssh_password is not None else {})).run(selected, ['tail','-n',str(lines),'--',str(path)])
    print(text, end='')
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('status','logs','paths'))
    parser.add_argument('--config', type=Path, default=INSTALL_ROOT/'config/site.json')
    parser.add_argument('--node', choices=NODES)
    parser.add_argument('--service', choices=('agent','controller'), default='agent')
    parser.add_argument('--lines', type=int, default=200)
    args=parser.parse_args(argv)
    try:
        return run(args.action, ROOT, args.config, args.node, args.service, args.lines)
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1
