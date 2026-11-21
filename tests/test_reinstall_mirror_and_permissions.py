"""回归测试：reinstall-debian13.sh 镜像 URL 校验、数值规范化、wget 超时与日志/脚本最小权限。"""

import os
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'reinstall-debian13.sh'
SH = shutil.which('sh') or shutil.which('bash')


def _validation_region(src: str) -> str:
    start = src.index('# ── 默认值')
    end = src.index('# 初始化日志', start)
    return src[start:end]


def _run_validation(src: str, cli=(), env=None) -> subprocess.CompletedProcess:
    full = {k: v for k, v in os.environ.items()
            if k not in ('PORT', 'PASSWORD', 'DISK', 'MIRROR', 'RELEASE', 'SWAP_MB', 'NET_MODE', 'LOG')}
    if env:
        full.update(env)
    args = ' '.join("'" + a.replace("'", "'\"'\"'") + "'" for a in cli)
    body = (
        'die() { echo "DIE:$*" >&2; exit 1; }\n'
        'err() { echo "$*" >&2; }\n'
        + (f'set -- {args}\n' if cli else 'set --\n')
        + _validation_region(src)
        + 'echo "OK"\n'
    )
    return subprocess.run(
        [SH, '-c', body],
        capture_output=True,
        text=True,
        encoding='utf-8',
        errors='replace',
        env=full,
        timeout=20,
    )


@unittest.skipUnless(SH, '需要 sh 环境')
class ReinstallMirrorAndPermissionsTests(unittest.TestCase):
    def test_rejects_invalid_mirror_and_malformed_numbers(self):
        """非法 MIRROR 协议/元字符、前导零端口与 0 号版本必须在前置校验阶段被拦下。"""
        src = SCRIPT.read_text(encoding='utf-8').replace('\r\n', '\n')
        bad_cases = [
            ('ftp 镜像', ('--mirror', 'ftp://mirror.example/debian/')),
            ('前导短横线镜像', ('--mirror', '-evil')),
            ('带空格与注入字符镜像', ('--mirror', 'http://deb.debian.org/debian/ $(id)')),
            ('前导零端口', ('--port', '022')),
            ('版本号为 0', ('--release', '0')),
        ]
        for label, cli in bad_cases:
            with self.subTest(label=label):
                res = _run_validation(src, cli=cli)
                self.assertNotEqual(res.returncode, 0, f'{label} 应被拒绝，实际通过: {res.stdout}')

    def test_accepts_valid_mirror_and_parameters(self):
        """合法镜像地址与标准端口/版本/swap 参数应正常放行。"""
        src = SCRIPT.read_text(encoding='utf-8').replace('\r\n', '\n')
        res = _run_validation(src, cli=('--mirror', 'https://deb.debian.org/debian/', '--port', '2222', '--release', '13', '--swap', '0'))
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn('OK', res.stdout)

    def test_log_init_and_installnet_download_enforce_timeout_and_least_privilege(self):
        """init_log 须私有创建日志文件，download_installnet 的 wget 须设超时，落地脚本须 700 权限。"""
        src = SCRIPT.read_text(encoding='utf-8').replace('\r\n', '\n')
        init_log = src[src.index('init_log() {'):src.index('\n}\n', src.index('init_log() {')) + 3]
        self.assertIn('umask 077', init_log)
        dl_fn = src[src.index('download_installnet() {'):src.index('\n}\n', src.index('download_installnet() {')) + 3]
        self.assertIn('wget -qO "$IN_FILE" -T 120 "$_u"', dl_fn)
        self.assertNotIn('chmod a+x "$IN_FILE"', src)
        self.assertIn('chmod 700 "$IN_FILE"', src)


if __name__ == '__main__':
    unittest.main()
