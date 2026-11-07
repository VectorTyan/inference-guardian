"""Guardian镜像的构建/导入、已验证缓存及归档；不更改模型容器。"""
import json
import os
from .release_files import safe_directory, private_dir, file_hash
from .components import role_security_args
from .transport import command, OCIStartupDenied, SeccompInitError
from inference_guardian.storage import read_json, atomic_json

def probe_startup(image_id, version, role=None):
    """在隔离临时容器中加载启动入口并核对版本，不读取运行配置或启动服务。"""
    docker = ['docker', '--host', 'unix:///var/run/docker.sock']
    args = docker + ['run', '--rm', '--network', 'none'] + (role_security_args(role) if role else [])
    program = ['--entrypoint', 'python', image_id, '-c',
               'from inference_guardian import __version__; '
               'import inference_guardian.__main__, inference_guardian.node_agent; '
               'from inference_guardian.gateway import GatewayState, create_server; '
               'print(__version__)']
    try:
        output = command(args + program, startup_probe=True)
        policy = 'default'
    except (SeccompInitError, OCIStartupDenied):
        options = json.loads(command(docker + ['info', '--format', '{{json .SecurityOptions}}']))
        profiles = [opt for opt in options if opt.split(',')[0] == 'name=seccomp'] if isinstance(options, list) else []
        if profiles not in (['name=seccomp,profile=default'], ['name=seccomp,profile=builtin']):
            raise ValueError('Guardian seccomp probe requires a confirmed Docker default profile') from None
        output = command(args + ['--security-opt', 'seccomp=unconfined'] + program)
        policy = 'unconfined'
    if output.strip() != version:
        raise ValueError('Guardian runtime version differs from source package')
    return policy


def prepare_image(source_directory, image_settings, version, checksum, root):
    """p0仅构建或导入一次；镜像源码摘要和运行版本都要与当前归档一致。"""
    directory = safe_directory(root / 'images' / (version + '-' + checksum[:16]), root)
    private_dir(directory)
    tag = 'inference-guardian:' + version + '-' + checksum[:16]
    source = image_settings
    docker = ['docker', '--host', 'unix:///var/run/docker.sock']
    tar = directory / 'guardian-image.tar'
    cached = read_json(directory / 'image.json')
    if cached and tar.exists() and file_hash(tar) == cached['sha256']:
        try:
            info = json.loads(command(docker + ['image', 'inspect', cached['image_id']]))[0]
        except ValueError:
            command(docker + ['load', '--input', str(tar)], timeout=1800, log=directory / 'reload.log')
            info = json.loads(command(docker + ['image', 'inspect', cached['image_id']]))[0]
    elif source['source'] == 'build':
        try:
            base = json.loads(command(docker + ['image', 'inspect', source['base_image']]))[0]
        except ValueError:
            # 默认基础镜像随已校验源码包交付；仅缺失时导入，不替换现场自定义镜像。
            if source['base_image'] != 'python:3.12-slim-bookworm':
                raise
            archive = source_directory / 'deploy/python-3.12-slim-bookworm-arm64.tar.xz'
            if archive.is_symlink() or not archive.is_file():
                raise ValueError('local base image unavailable and bundled ARM64 base archive missing')
            command(docker + ['load', '--input', str(archive)], timeout=1800, log=directory / 'base-load.log')
            base = json.loads(command(docker + ['image', 'inspect', source['base_image']]))[0]
        if base['Os'] != 'linux' or base['Architecture'] != 'arm64':
            raise ValueError('trusted local ARM64 base image required; automatic pulls are disabled')
        command(docker + ['build', '--platform', 'linux/arm64', '--pull=false', '--build-arg',
                'BASE_IMAGE=' + source['base_image'], '--build-arg', 'RELEASE_SHA256=' + checksum,
                '-f', str(source_directory / 'deploy/Dockerfile'), '-t', tag, str(source_directory)],
                timeout=3600, log=directory / 'build.log')
        info = json.loads(command(docker + ['image', 'inspect', tag]))[0]
    else:
        if file_hash(source['archive']) != source['sha256']:
            raise ValueError('imported image archive SHA256 mismatch')
        command(docker + ['load', '--input', source['archive']], timeout=1800, log=directory / 'load.log')
        ids = command(docker + ['image', 'ls', '--no-trunc', '--quiet', '--filter',
                     'label=guardian.release-sha256=' + checksum]).splitlines()
        if len(set(ids)) != 1:
            raise ValueError('one image matching this source archive label required')
        info = json.loads(command(docker + ['image', 'inspect', ids[0]]))[0]
    if (info['Os'] != 'linux' or info['Architecture'] != 'arm64'
            or info.get('Config', {}).get('Labels', {}).get('guardian.release-sha256') != checksum):
        raise ValueError('Guardian image architecture or source label differs')
    policy = probe_startup(info['Id'], version)
    (directory / 'smoke.log').write_text(version + '\n', encoding='utf-8')
    # 以ID导出的旧缓存不含仓库标签；校验后补标签，身份仍以完整ID为准。
    command(docker + ['tag', info['Id'], tag])
    tagged = json.loads(command(docker + ['image', 'inspect', tag]))[0]
    if tagged['Id'] != info['Id']:
        raise ValueError('Guardian image tag identity differs')
    if tar.exists():
        prior = read_json(directory / 'image.json')
        if not prior or prior['image_id'] != info['Id'] or prior['sha256'] != file_hash(tar):
            raise ValueError('existing image export differs; preserve it for reconciliation')
    else:
        temporary = tar.with_suffix('.upload')
        if temporary.is_symlink():
            raise ValueError('image export staging path is a symlink')
        command(docker + ['save', '--output', str(temporary), tag], timeout=1800)
        os.rename(str(temporary), str(tar))
    result = dict(image_id=info['Id'], archive=str(tar), sha256=file_hash(tar))
    if policy == 'unconfined':
        result['smoke_seccomp'] = policy
    atomic_json(directory / 'image.json', result)
    return result
