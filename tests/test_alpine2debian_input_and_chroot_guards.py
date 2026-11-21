"""回归测试：alpine2debian.sh 参数注入/非法 SWAP_MB 前置拦截，以及 chroot 明文密码清理、UUID 判空与 SSH 登录兜底。"""

import os
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'alpine2debian.sh'
SH = shutil.which('sh') or shutil.which('bash')


def _setup_region(src: str) -> str:
    return src[src.index('# ── 默认值'):src.index('# ── 第 1 步')]


def _run_setup(src: str, cli=(), env=None) -> subprocess.CompletedProcess:
    full = {k: v for k, v in os.environ.items()
            if k not in ('MIRROR', 'SECURITY_MIRROR', 'DEBIAN_SUITE', 'HOSTNAME', 'TIMEZONE', 'SWAP_MB')}
    if env:
        full.update(env)
    args = ' '.join("'" + a.replace("'", "'\"'\"'") + "'" for a in cli)
    body = (f'set -- {args}\n' if cli else 'set --\n') + _setup_region(src) + 'echo "OK"\n'
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
class Alpine2DebianGuardsTests(unittest.TestCase):
    def test_rejects_invalid_swap_and_injection_inputs_before_disk_stage(self):
        """非法 SWAP_MB 与带 shell 元字符的 suite/mirror/hostname/timezone 必须在第 1 步前被拒绝。"""
        src = SCRIPT.read_text(encoding='utf-8').replace('\r\n', '\n')
        bad_cases = [
            ('非数字 SWAP_MB', (), {'SWAP_MB': 'abc'}),
            ('负数 SWAP_MB', (), {'SWAP_MB': '-10'}),
            ('命令注入 HOSTNAME', (), {'HOSTNAME': 'node$(id)'}),
            ('路径穿越 TIMEZONE', (), {'TIMEZONE': '../../etc/passwd'}),
            ('非法字符 DEBIAN_SUITE', ('--suite', 'bookworm;id'), None),
            ('非 http/https MIRROR', ('--mirror', 'ftp://evil.example/debian'), None),
            ('带空白/注入字符 MIRROR', ('--mirror', 'http://a.example/debian $(id)'), None),
        ]
        for label, cli, env in bad_cases:
            with self.subTest(label=label):
                res = _run_setup(src, cli=cli, env=env)
                self.assertNotEqual(res.returncode, 0, f'{label} 应被前置拦截，但实际通过: {res.stdout}')

    def test_accepts_valid_inputs(self):
        """合法参数组合应正常通过前置校验。"""
        src = SCRIPT.read_text(encoding='utf-8').replace('\r\n', '\n')
        res = _run_setup(
            src,
            cli=('--suite', 'trixie', '--mirror', 'https://deb.debian.org/debian'),
            env={'HOSTNAME': 'de-node-01.example', 'TIMEZONE': 'Asia/Shanghai', 'SWAP_MB': '512'},
        )
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn('OK', res.stdout)

    def test_chroot_guards_uuid_sshd_append_and_rootpw_cleanup(self):
        """chroot 块必须校验 ROOT_UUID 非空、无匹配行时追加 sshd 配置、失败时仍删除 _rootpw。"""
        src = SCRIPT.read_text(encoding='utf-8').replace('\r\n', '\n')
        chroot_part = src[src.index('# ── 第 7 步：chroot 配置'):src.index('# ── 第 8 步：网络配置')]
        self.assertIn('[ -n "\\${ROOT_UUID}" ] ||', chroot_part)
        self.assertIn('grep -qE', chroot_part)
        self.assertIn('PermitRootLogin yes', chroot_part)
        self.assertIn('PasswordAuthentication yes', chroot_part)
        # 无论 chroot 成功还是失败都必须先清理 /tmp/_rootpw 再退出
        self.assertRegex(chroot_part, r'chroot\s+"\$MOUNT_DIR"\s+/bin/sh\s+/tmp/_setup\.sh\s*\|\|')
        self.assertIn('rm -f "$MOUNT_DIR/tmp/_setup.sh" "$MOUNT_DIR/tmp/_rootpw"', chroot_part)


if __name__ == '__main__':
    unittest.main()
