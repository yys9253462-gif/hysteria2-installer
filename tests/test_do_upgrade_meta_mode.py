"""do_upgrade.sh 自愈重写 client_meta.json 时必须保持 0600（2026-11-03）。

client_meta.json 里有 auth_password 与 obfs_password。生成的 do_upgrade.sh 没有设
umask，由门户服务或手工 shell（umask 022）调用时，自愈用 jq 写出的新文件是 0644，
mv 覆盖原来的 0600 文件后，任何本地用户都能读到节点主密码。

这里把生成的 do_upgrade.sh 里的 repair-config.sh 段原样取出，在 umask 022 的 shell 里
跑它的证书信任模型自愈，HY2_DIR 指向临时目录；不碰 systemd、不联网。
"""
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL = (ROOT / 'install.sh').read_text(encoding='utf-8')


def generated_script():
    return INSTALL.split('cat > "$HY2_DIR/do_upgrade.sh" <<\'EOUG\'\n', 1)[1].split('\nEOUG\n', 1)[0]


def trust_heal_block():
    repair = generated_script().split("<<'PORTALREPAIR'\n", 1)[1].split('\nPORTALREPAIR\n', 1)[0]
    start = repair.index('        # 证书信任模型自愈')
    end = repair.index('        # 证书自愈单元自愈安装')
    return repair[start:end]


@unittest.skipUnless(all(shutil.which(t) for t in ('bash', 'jq', 'openssl')), 'needs bash + jq + openssl')
class DoUpgradeMetaModeTests(unittest.TestCase):
    def test_generated_script_sets_private_umask_before_writing(self):
        head = generated_script().split('\n')
        umask_line = next(i for i, line in enumerate(head) if line.strip() == 'umask 077')
        target_line = next(i for i, line in enumerate(head) if line.startswith('TARGET='))
        self.assertLess(umask_line, target_line, 'umask 必须在任何写文件之前')

    def test_trust_heal_rewrite_keeps_meta_private_under_umask_022(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / 'cert').mkdir()
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt',
                            'ec_paramgen_curve:prime256v1', '-nodes', '-subj', '/CN=node.example.com',
                            '-days', '2', '-keyout', str(root / 'cert/server.key'),
                            '-out', str(root / 'cert/server.crt')],
                           check=True, capture_output=True, timeout=30)
            (root / 'config.yaml').write_text('listen: :443\ntls:\n  cert: cert/server.crt\n  key: cert/server.key\n',
                                              encoding='utf-8')
            meta = root / 'client_meta.json'
            # 与证书不一致的旧信任模型，迫使自愈重写文件。
            meta.write_text(json.dumps({'cert_type': 'acme', 'server_name': 'old.example.com',
                                        'is_insecure': False, 'pin_sha256': '',
                                        'auth_password': 'master-secret'}), encoding='utf-8')
            meta.chmod(0o600)
            prelude = generated_script().split('\n')
            umask = 'umask 077' if 'umask 077' in (line.strip() for line in prelude[:12]) else ':'
            script = 'set -u\numask 022\n%s\nHY2_DIR=%s\n%s' % (umask, root, trust_heal_block())
            result = subprocess.run(['bash', '-c', script], capture_output=True, text=True, timeout=60)
            self.assertIn('证书信任模型已自愈', result.stdout + result.stderr)
            self.assertEqual(json.loads(meta.read_text(encoding='utf-8'))['server_name'], 'node.example.com')
            mode = stat.S_IMODE(meta.stat().st_mode)
            self.assertEqual(mode, 0o600, '自愈后 client_meta.json 权限是 %o，主密码对本地用户可读' % mode)

    def heal_with_sans(self, sans, cn, current):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / 'cert').mkdir()
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt',
                            'ec_paramgen_curve:prime256v1', '-nodes', '-subj', '/CN=' + cn,
                            '-addext', 'subjectAltName=' + ','.join('DNS:' + s for s in sans),
                            '-days', '2', '-keyout', str(root / 'cert/server.key'),
                            '-out', str(root / 'cert/server.crt')],
                           check=True, capture_output=True, timeout=30)
            (root / 'config.yaml').write_text('listen: :443\ntls:\n  cert: cert/server.crt\n  key: cert/server.key\n',
                                              encoding='utf-8')
            meta = root / 'client_meta.json'
            meta.write_text(json.dumps({'cert_type': 'acme', 'server_name': current,
                                        'is_insecure': False, 'pin_sha256': ''}), encoding='utf-8')
            script = 'set -u\nHY2_DIR=%s\n%s' % (root, trust_heal_block())
            subprocess.run(['bash', '-c', script], capture_output=True, text=True, timeout=60)
            return json.loads(meta.read_text(encoding='utf-8'))['server_name']

    def test_multi_san_certificate_keeps_the_current_server_name(self):
        """与 portal.sync_cert_trust 一致：当前 SNI 仍在证书里就不换（2026-11-03）。"""
        self.assertEqual(self.heal_with_sans(['a.example.com', 'b.example.com'], 'a.example.com',
                                             'b.example.com'), 'b.example.com')

    def test_wildcard_first_san_still_heals_to_a_concrete_name(self):
        self.assertEqual(self.heal_with_sans(['*.example.com', 'node.example.com'], '*.example.com',
                                             'gone.example.org'), 'node.example.com')


if __name__ == '__main__':
    unittest.main()
