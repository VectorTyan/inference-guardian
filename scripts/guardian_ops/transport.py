"""本地命令与SSH/SCP传输；固定目标、限时调用、受控错误。"""
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import shutil
import getpass
import warnings
from contextlib import ExitStack
from .release_state import RolloutError
from .release_files import safe_directory, file_hash, write_private


def password_bytes(password):
    data = password.encode('utf-8')
    if not data or len(data) > 2048 or any(c in data for c in (0, 10, 13)):
        raise ValueError('SSH password must be a nonempty single line of at most 2048 UTF-8 bytes')
    return data


def prompt_password():
    if not shutil.which('sshpass'):
        raise ValueError('sshpass is required on the coordinator for --ssh-password')
    # 无可隐藏输入的终端时拒绝退回有回显的 stdin。
    with warnings.catch_warnings():
        warnings.simplefilter('error', getpass.GetPassWarning)
        try:
            password = getpass.getpass('Common root password for all remote model nodes: ')
        except (getpass.GetPassWarning, EOFError):
            raise ValueError('SSH password requires an interactive terminal with hidden input') from None
    password_bytes(password)
    return password


class SeccompInitError(ValueError):
    """Docker 明确报告 OCI 初始化 seccomp 失败，可对一次性自检尝试兼容策略。"""


class OCIStartupDenied(ValueError):
    """OCI 在进程启动阶段报告权限错误，根因需由调用方对比探测。"""


# 只接受 OCI 创建/启动链以无具体操作的 permission denied 结束。
# 挂载、设备、可执行文件和 socket 的权限诊断应交给现场按原错误处理。
_OCI_START_DENIED = re.compile(
    r'\boci runtime (?:create|start) failed:\s*'
    r'(?:runc (?:create|start) failed:\s*)?(?:container_linux\.go:\d+:\s*)?'
    r'(?:unable to start container process:\s*)?(?:error during container init:\s*)?'
    r'(?:starting container process caused:?\s*)?(?:"permission denied"|permission denied)'
    r'(?:: unknown)?\.?$'
)


# 旧 libcontainer 可直接在 stderr 输出该行并返回 1，行号随构建变化。
_LIBCONTAINER_SECCOMP_DENIED = re.compile(r'standard_init_linux\.go:[0-9]+: init seccomp caused "permission denied"')


def command(argv, *, timeout=180, log=None, ssh_password=None, startup_probe=False):
    environment = {k:v for k,v in os.environ.items() if k not in
                   {'DOCKER_CONTEXT', 'DOCKER_HOST', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH', 'DOCKER_API_VERSION', 'SSHPASS'}}
    environment['DOCKER_BUILDKIT'] = '0'
    with ExitStack() as resources:
        options = {}
        if ssh_password is not None:
            if not argv or argv[0] not in {'ssh', 'scp'} or log:
                raise ValueError('password authentication is only supported for SSH/SCP')
            helper = shutil.which('sshpass')
            if not helper:
                raise ValueError('sshpass is required on the coordinator for --ssh-password')
            data = password_bytes(ssh_password)
            reader, writer = os.pipe()
            resources.callback(os.close, reader)
            resources.callback(os.close, writer)
            os.write(writer, data + b'\n')
            argv = [helper, '-d', str(reader), *argv]
            options['pass_fds'] = (reader,)
        if log:
            stream = resources.enter_context(Path(log).open('wb'))
            result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=stream, stderr=subprocess.STDOUT,
                                    env=environment, timeout=timeout, **options)
        else:
            result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    universal_newlines=True, env=environment, timeout=timeout, **options)
    if ssh_password is not None and result.returncode:
        result.stderr = result.stderr.replace(ssh_password, '<redacted>')
    if result.returncode:
        detail = ''
        if not log:
            local_run = argv[:4] == ['docker', '--host', 'unix:///var/run/docker.sock', 'run']
            if startup_probe and local_run and result.returncode == 1:
                if any(_LIBCONTAINER_SECCOMP_DENIED.fullmatch(line.strip()) for line in result.stderr.splitlines()):
                    raise SeccompInitError('libcontainer seccomp initialization permission denied')
            if local_run and result.returncode in (125, 126):
                for line in result.stderr.lower().splitlines():
                    if not line.startswith('docker: error response from daemon:'):
                        continue
                    if _OCI_START_DENIED.search(line.rstrip()):
                        raise OCIStartupDenied('Docker OCI container startup permission denied')
                    if (('oci runtime create failed' in line or 'container init' in line)
                            and re.search(r'error (?:loading|adding|applying|initializing) seccomp (?:filter|profile|rule)|'
                                          r'(?:unable|failed) to (?:init|initialize|load|apply|set up) (?:the )?seccomp\b', line)):
                        raise SeccompInitError('Docker OCI seccomp initialization failed')
            # SSH登录横幅可能与节点JSON共用stderr；逐行读取最后一条结构化诊断。
            for line in reversed(result.stderr.splitlines()):
                try:
                    response = json.loads(line)
                    if isinstance(response, dict) and isinstance(response.get('error'), str):
                        raise RolloutError(response.get('code', 'REMOTE_CHECK_FAILED'),
                                           response['error'], response.get('details', {}))
                except (json.JSONDecodeError, TypeError):
                    continue
            for marker in ('Permission denied', 'Host key verification failed',
                           'REMOTE HOST IDENTIFICATION HAS CHANGED', 'Connection refused',
                           'Connection timed out', 'No route to host', 'Could not resolve hostname'):
                if marker in result.stderr:
                    detail = '; SSH: ' + marker
                    break
        raise ValueError('command failed: ' + Path(argv[0]).name + ' (exit ' + str(result.returncode) + ')'
                         + ('; see ' + str(log) if log else detail))
    return result.stdout if not log else ''


class Transport:
    def __init__(self, site, hosts, *, password=None):
        self.site, self.hosts = site, hosts
        self.password = password

    def options(self, scp=False):
        ssh = self.site['ssh']
        options = ['-o', 'BatchMode=no' if self.password is not None else 'BatchMode=yes',
                   '-o', 'StrictHostKeyChecking=accept-new' if self.password is not None else 'StrictHostKeyChecking=yes', '-o',
                   'ConnectTimeout=' + str(ssh['connect_timeout_seconds']), '-P' if scp else '-p', str(ssh['port'])]
        if self.password is not None:
            options += ['-o', 'PreferredAuthentications=password', '-o', 'PubkeyAuthentication=no',
                        '-o', 'PasswordAuthentication=yes', '-o', 'NumberOfPasswordPrompts=1']
        elif ssh['identity_file']:
            options += ['-o', 'IdentitiesOnly=yes', '-i', ssh['identity_file']]
        return options

    def run(self, node, argv, timeout=180):
        if argv and argv[0] == 'python3':
            # 校验子进程不继承PYTHONOPTIMIZE/PYTHONPATH等现场环境覆盖。
            argv = [argv[0], '-E', *argv[1:]]
        if node == 'p0':
            return command(argv, timeout=timeout)
        remote = ' '.join(shlex.quote(str(arg)) for arg in argv)
        return self.remote(['ssh', *self.options(), 'root@' + self.hosts[node], remote], timeout=timeout)

    def remote(self, argv, *, timeout):
        options = {'ssh_password': self.password} if self.password is not None else {}
        return command(argv, timeout=timeout, **options)

    def mkdir(self, node, path):
        safe_directory(path)
        program = ("import pathlib,sys; p=pathlib.Path(sys.argv[1]); "
                   "assert not any(x.is_symlink() for x in (p,*p.parents)); "
                   "p.mkdir(parents=True,exist_ok=True,mode=0o700)")
        self.run(node, ['python3', '-c', program, str(path)])

    def copy(self, node, source, target):
        """上传到临时文件，校验后排他发布；既有同名内容必须相同。"""
        source, target = Path(source), safe_directory(target)
        checksum = file_hash(source)
        if node == 'p0':
            if source.resolve() != target:
                write_private(target, source.read_bytes())
            return
        self.mkdir(node, target.parent)
        temporary = str(target) + '.upload'
        self.run(node, ['python3', '-c',
            'import pathlib,sys; p=pathlib.Path(sys.argv[1]); assert not p.is_symlink(); assert not p.exists() or p.is_file()', temporary])
        self.remote(['scp', *self.options(True), str(source), 'root@' + self.hosts[node] + ':' + temporary], timeout=1800)
        program = ("import pathlib,hashlib,sys,os; s=pathlib.Path(sys.argv[1]); t=pathlib.Path(sys.argv[2]); "
                   "assert not s.is_symlink() and not t.is_symlink(); "
                   "assert hashlib.sha256(s.read_bytes()).hexdigest()==sys.argv[3]; "
                   "assert not t.exists() or hashlib.sha256(t.read_bytes()).hexdigest()==sys.argv[3]; "
                   "s.chmod(0o600); os.replace(str(s),str(t))")
        self.run(node, ['python3', '-c', program, temporary, str(target), checksum], timeout=1800)
