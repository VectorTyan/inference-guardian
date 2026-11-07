"""独立部署入口：校验源码包，在p0解包版本目录后调用集群安装/升级器。"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import sys
import tarfile
import tempfile

INSTALL_ROOT = Path('/data/scripts/inference-guardian')


def file_hash(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def safe_directory(path, root=INSTALL_ROOT):
    """所有受管理目录必须在指定根内；逐层拒绝符号链接。"""
    path, root = Path(os.path.abspath(str(path))), Path(os.path.abspath(str(root)))
    if path != root and root not in path.parents:
        raise ValueError('path is outside the managed installation root')
    for entry in (path, *path.parents):
        if entry.is_symlink():
            raise ValueError('managed paths cannot traverse symlinks')
    return path


def verify_package(archive, expected):
    if not re.fullmatch(r'[0-9a-f]{64}', expected or '') or file_hash(archive) != expected:
        raise ValueError('source archive SHA256 mismatch')
    with tarfile.open(archive, 'r:gz') as bundle:
        members = bundle.getmembers()
        if len(members) > 4096 or sum(m.size for m in members) > 128 * 1024 * 1024:
            raise ValueError('source archive is too large')
        seen = set()
        for member in members:
            path = PurePosixPath(member.name)
            if (path.is_absolute() or '..' in path.parts or not path.parts or path.parts[0] != 'inference-guardian'
                    or member.name in seen or not (member.isdir() or member.isfile())
                    or member.mode != (0o755 if member.isdir() else 0o644)):
                raise ValueError('unsafe source archive member')
            seen.add(member.name)
        manifest = json.load(bundle.extractfile('inference-guardian/MANIFEST.json'))
        version = manifest.get('version', '')
        if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version):
            raise ValueError('source version must be a stable numeric release')
        expected_files = {'inference-guardian/MANIFEST.json'}
        for item in manifest['files']:
            name = 'inference-guardian/' + item['path']
            if name in expected_files:
                raise ValueError('duplicate manifest file')
            expected_files.add(name)
            raw = bundle.extractfile(name).read()
            if len(raw) != item['bytes'] or hashlib.sha256(raw).hexdigest() != item['sha256']:
                raise ValueError('manifest content differs: ' + item['path'])
        if {m.name for m in members if m.isfile()} != expected_files:
            raise ValueError('archive contains unlisted files')
    return manifest


def check_extracted(directory, manifest):
    for item in manifest['files']:
        path = safe_directory(directory / item['path'], directory)
        if not path.is_file() or file_hash(path) != item['sha256']:
            raise ValueError('existing release source has drifted: ' + item['path'])
    if json.loads((directory / 'MANIFEST.json').read_text(encoding='utf-8')) != manifest:
        raise ValueError('existing release manifest differs')
    # 复用源码时也核对新增内容，避免已移除的旧模块被重新导入或带入镜像。
    # 正常解释器缓存允许保留；配置、Token和状态均位于源码树之外。
    listed = {item['path'] for item in manifest['files']}
    allowed = listed | {parent.as_posix() for name in listed for parent in PurePosixPath(name).parents}
    for name in ('src', 'scripts'):
        source = safe_directory(directory / name, directory)
        for path in source.rglob('*'):
            relative = path.relative_to(directory)
            if path.is_symlink() or ('__pycache__' not in relative.parts and relative.as_posix() not in allowed):
                raise ValueError('unexpected release source: ' + relative.as_posix())


def extract_release(archive, expected, root=INSTALL_ROOT):
    """只发布新版本目录；既有目录逐文件复核，不覆盖源码或运行状态。"""
    manifest = verify_package(archive, expected)
    parent = safe_directory(Path(root) / 'releases', root)
    parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    target = safe_directory(parent / (manifest['version'] + '-' + expected[:16]), root)
    if target.exists():
        check_extracted(target, manifest)
        return target, manifest
    with tempfile.TemporaryDirectory(prefix='.extract-', dir=str(parent)) as temporary:
        stage = Path(temporary) / 'source'
        stage.mkdir()
        with tarfile.open(archive, 'r:gz') as bundle:
            for member in bundle.getmembers():
                parts = PurePosixPath(member.name).parts[1:]
                path = stage.joinpath(*parts)
                if member.isdir():
                    path.mkdir(parents=True, exist_ok=True)
                else:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    with path.open('xb') as stream:
                        shutil.copyfileobj(bundle.extractfile(member), stream)
                path.chmod(member.mode)
        check_extracted(stage, manifest)
        os.rename(str(stage), str(target))
    return target, manifest


def archive_checksum(archive):
    path = Path(str(archive)[:-7] + '.SHA256SUMS')
    lines = path.read_text(encoding='ascii').splitlines()
    if len(lines) != 1:
        raise ValueError('one source checksum entry required')
    parts = lines[0].split()
    if len(parts) != 2 or parts[1].lstrip('*') != Path(archive).name:
        raise ValueError('checksum filename differs from selected source archive')
    return parts[0]


def select_archive(directory):
    """自动选择标准文件名中的最高稳定版本；摘要仍需独立校验，显式--archive可覆盖。"""
    choices = []
    for path in Path(directory).glob('inference-guardian-source-*.tar.gz'):
        match = re.fullmatch(r'inference-guardian-source-([0-9]+)\.([0-9]+)\.([0-9]+)\.tar\.gz', path.name)
        if match:
            choices.append((tuple(int(part) for part in match.groups()), path))
    if not choices:
        raise ValueError('no source archive in packages; copy the archive and matching SHA256SUMS first')
    version = max(item[0] for item in choices)
    matches = [path for value,path in choices if value == version]
    if len(matches) != 1 or matches[0].is_symlink() or not matches[0].is_file():
        raise ValueError('ambiguous or unsafe source archive; select --archive explicitly')
    return matches[0]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', nargs='?', choices=('plan', 'apply', 'upgrade-plan', 'upgrade', 'uninstall-plan', 'uninstall',
                                          'verify', 'recommission-plan', 'recommission', 'status', 'logs', 'paths',
                                          'exercise-plan', 'exercise', 'exercise-report', 'exercise-restore'))
    parser.add_argument('--archive', type=Path)
    parser.add_argument('--package-dir', type=Path, default=INSTALL_ROOT/'packages')
    parser.add_argument('--config', type=Path, help='Site configuration; --config FILE alone runs apply')
    parser.add_argument('--ssh-password', action='store_true', help='Prompt once for the common remote root password; requires sshpass')
    parser.add_argument('--manifest', type=Path, help='Use a local source-manifest.json; defaults to observe installation')
    parser.add_argument('--node', choices=('p0','p1','d0','d1'))
    parser.add_argument('--service', choices=('agent','controller'), default='agent')
    parser.add_argument('--lines', type=int, default=200)
    parser.add_argument('--mode', choices=('observe', 'recovery'))
    parser.add_argument('--fault', choices=('process-exit', 'container-stop'))
    parser.add_argument('--wait-seconds', type=int, default=0, help='Exercise report polling only, 0..7200 seconds')
    parser.add_argument('--close-exercise', action='store_true', help='Close a confirmed but failed exercise after healthy manual restoration; never resolves unknown injection')
    parser.add_argument('--plan-file', type=Path, help='Reviewed uninstall, recommission or exercise JSON; binds exact container IDs')
    parser.add_argument('--accept-history-loss', action='store_true', help='Confirm no recoverable baseline/state backup')
    parser.add_argument('--discard-stopped-guardians', action='store_true', help='Remove planned stopped Guardians without archiving them')
    args = parser.parse_args(argv)
    if args.action is None:
        if args.config is None and args.manifest is None:
            parser.error('specify an action, --config FILE or --manifest FILE for installation')
        args.action = 'apply'
    if args.config is None and args.manifest is None:
        args.config = INSTALL_ROOT/'config/site.json'
    exercise = args.action in {'exercise-plan', 'exercise', 'exercise-report', 'exercise-restore'}
    if args.action == 'exercise-restore' and args.wait_seconds:
        parser.error('exercise-restore uses configured startup/readiness timeouts; no --wait-seconds')
    if args.close_exercise and args.action != 'exercise-report':
        parser.error('--close-exercise is only allowed with exercise-report')
    if (not exercise and (args.fault or args.wait_seconds)) or not 0 <= args.wait_seconds <= 7200:
        parser.error('fault/wait options are for exercise actions; wait must be 0..7200')
    if exercise and (args.service != 'agent' or args.lines != 200 or args.accept_history_loss or args.discard_stopped_guardians):
        parser.error('exercise cannot use service/log or history-loss flags')
    if exercise:
        if args.action == 'exercise-plan':
            if args.node not in {'p1', 'd1'} or not args.fault or not args.mode or args.plan_file or args.wait_seconds:
                parser.error('exercise-plan requires --node p1|d1 --fault --mode, and no plan/wait')
        elif not args.plan_file or args.node or args.fault or args.mode:
            parser.error('exercise/exercise-report/exercise-restore require --plan-file, without node/fault/mode overrides')
    if not exercise and args.action not in {'status','logs','paths'} and (args.node or args.service != 'agent' or args.lines != 200):
        parser.error('node/service/lines options apply only to inspection')
    if args.action in {'status','logs','paths'} and args.mode:
        parser.error('inspection cannot change mode')
    if args.action == 'recommission':
        if not (args.plan_file and args.accept_history_loss and args.discard_stopped_guardians):
            parser.error('recommission requires --plan-file, --accept-history-loss and --discard-stopped-guardians')
    elif args.action == 'uninstall':
        if not args.plan_file or args.accept_history_loss or args.discard_stopped_guardians:
            parser.error('uninstall requires --plan-file and always preserves deployment data')
    elif not exercise and (args.plan_file or args.accept_history_loss or args.discard_stopped_guardians):
        parser.error('recommission approval flags cannot be used with other actions')
    if args.action.startswith('uninstall') and args.mode:
        parser.error('uninstall cannot select a deployment mode')
    if args.action.startswith('recommission') and args.mode not in (None, 'observe'):
        parser.error('recommission only supports --mode observe')
    try:
        if sys.platform != 'linux' or os.geteuid() != 0 or sys.version_info < (3, 7, 9):
            raise ValueError('run as root on Linux p0 with Python >= 3.7.9')
        args.archive = args.archive or select_archive(args.package_dir)
        checksum = archive_checksum(args.archive)
        source, manifest = extract_release(args.archive, checksum)
        sys.path[:0] = [str(source / 'scripts'), str(source / 'src')]
        if args.manifest is not None:
            from guardian_ops.site import site_for_manifest
            config = site_for_manifest(args.manifest, args.config)
        else:
            config = args.config.resolve()
        auth = {}
        if args.ssh_password:
            from guardian_ops.transport import prompt_password
            auth['ssh_password'] = prompt_password()
        if exercise:
            from guardian_inspect import run_exercise
            return run_exercise(args.action, source, checksum, config, args.node, args.fault,
                                args.mode, args.plan_file, args.wait_seconds, args.close_exercise, **auth)
        if args.action in {'status','logs','paths'}:
            from guardian_inspect import run as inspect_run
            return inspect_run(args.action, source, config, args.node, args.service, args.lines, **auth)
        from guardian_rollout import run
        options = dict(plan_file=args.plan_file.resolve()) if args.plan_file else {}
        return run(args.action, args.archive.resolve(), checksum, source, config, args.mode, **options, **auth)
    except Exception as exc:
        print('Deployment stopped: ' + str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
