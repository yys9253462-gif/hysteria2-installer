"""install.sh 生成的 toggle_warp.sh（2026-11-04 修）。

旧版本把 9 条 warp_socks(域名) 规则写在 direct_ipv4(all) 之后：Hysteria ACL 首条命中即停，
它们永远不生效；切换时直接 systemctl restart，流量超额停用期间也会把服务拉起来。
从 install.sh 里摘出真实脚本内容，配置路径与 systemctl / jq 换成临时文件和桩。
"""
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which('bash')
SRC = (ROOT / 'install.sh').read_text(encoding='utf-8').replace('\r\n', '\n')
TOGGLE = re.search(r"cat > \"\$HY2_DIR/toggle_warp.sh\" <<'EOTW'\n(.*?)\nEOTW\n", SRC, re.S).group(1)

BASE = """listen: :443
outbounds:
  - name: direct_ipv4
    type: direct
acl:
  inline:
    - reject(10.0.0.0/8)
    - direct_ipv4(all)
obfs:
  type: salamander
"""


@unittest.skipUnless(BASH, 'requires bash')
class ToggleWarpTests(unittest.TestCase):
    def run_toggle(self, action, suspended=False, config_text=BASE):
        with tempfile.TemporaryDirectory() as td:
            t = Path(td)
            cfg = t / 'config.yaml'
            cfg.write_text(config_text, encoding='utf-8')
            (t / 'portal.json').write_text('{"traffic_suspend": {"suspended": %s}}' % ('true' if suspended else 'false'))
            script = (TOGGLE.replace('/etc/hysteria/config.yaml', cfg.as_posix())
                            .replace('/etc/hysteria/portal.json', (t / 'portal.json').as_posix()))
            stubs = ('systemctl() { echo "SYS $*" >> %s/calls; }\n'
                     'curl() { return 0; }\n') % t.as_posix()
            if not shutil.which('jq'):
                stubs += 'jq() { grep -q \'"suspended": true\' "$3" && echo true || echo false; }\n'
            subprocess.run([BASH, '-c', stubs + script.replace('#!/usr/bin/env bash\n', '', 1), 'x', action],
                           capture_output=True, text=True, timeout=30)
            calls = (t / 'calls').read_text() if (t / 'calls').exists() else ''
            return cfg.read_text(), calls

    def test_enable_puts_every_warp_rule_before_the_catch_all(self):
        text, _ = self.run_toggle('1')
        acl = text[text.index('acl:'):]
        catch_all = acl.index('direct_ipv4(all)')
        self.assertNotIn('warp_socks(', acl[catch_all:], 'direct_ipv4(all) 之后还有永远不生效的规则')
        self.assertIn('warp_socks(suffix:openai.com)', acl)
        self.assertIn('obfs:', text, 'obfs 段被删掉了')

    def test_restart_resets_the_start_limit(self):
        _, calls = self.run_toggle('1')
        self.assertIn('SYS reset-failed hysteria-server', calls)
        self.assertNotIn('SYS restart hysteria-server', calls)

    def test_suspended_node_is_not_started(self):
        _, calls = self.run_toggle('1', suspended=True)
        self.assertNotIn('start hysteria-server', calls)

    def test_noop_disable_with_obfs_after_acl_does_not_restart(self):
        """obfs 段排在 acl 段之后时，规则本身无变化不应因为段落顺序变化而误重启。"""
        unchanged = """listen: :443
outbounds:
  - name: direct_ipv4
    type: direct
acl:
  inline:
    - reject(127.0.0.0/8)
    - reject(10.0.0.0/8)
    - reject(172.16.0.0/12)
    - reject(192.168.0.0/16)
    - reject(169.254.0.0/16)
    - reject(100.64.0.0/10)
    - reject(0.0.0.0/8)
    - reject(::1/128)
    - reject(fc00::/7)
    - reject(fe80::/10)
    - direct_ipv4(all)
obfs:
  type: salamander
"""
        text, calls = self.run_toggle('0', config_text=unchanged)
        self.assertIn('obfs:', text)
        self.assertEqual(calls.strip(), '', f'规则无变化却触发了重启：{calls}')


if __name__ == '__main__':
    unittest.main()
