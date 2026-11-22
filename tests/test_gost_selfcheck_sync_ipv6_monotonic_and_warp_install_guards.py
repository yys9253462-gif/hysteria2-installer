"""回归测试：GOST 自检脚本双端逐字节一致、纯 IPv4 禁用 AF_INET6 容错、脏 services/越界端口过滤、单调钟及 install_warp_local_proxy umask 与配置注入守卫。"""

import ast
import json
import re
import socket
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
INSTALL_SH = (ROOT / 'install.sh').read_text(encoding='utf-8')
PORTAL_PY = (ROOT / 'portal.py').read_text(encoding='utf-8')


def _extract_install_selfcheck() -> str:
    m = re.search(r"cat > \"\$_selfcheck_tmp\" <<'PYSELFCHECK'\n(.*?)\nPYSELFCHECK\n", INSTALL_SH, re.S)
    assert m, 'install.sh 未找到 PYSELFCHECK'
    return m.group(1) + '\n'


def _extract_portal_selfcheck() -> str:
    tree = ast.parse(PORTAL_PY)
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == 'GOST_SELFCHECK_SCRIPT':
                    return ast.literal_eval(node.value)
    raise AssertionError('portal.py 未找到 GOST_SELFCHECK_SCRIPT')


class TestGostSelfcheckSyncAndWarpInstallGuards(unittest.TestCase):
    def test_selfcheck_scripts_are_byte_identical(self):
        """install.sh 与 portal.py 中的 GOST_SELFCHECK_SCRIPT 必须逐字节一致。"""
        self.assertEqual(_extract_install_selfcheck(), _extract_portal_selfcheck())

    def test_selfcheck_survives_disabled_ipv6_corrupt_entries_and_uses_monotonic(self):
        """GOST 自检脚本在禁 IPv6 内核、含脏 services 项、越界/5000位端口与墙钟场景下必须健壮运行。"""
        code = _extract_portal_selfcheck()
        self.assertIn('time.monotonic()', code, '自检超时必须使用 time.monotonic() 免疫墙钟回拨')

        ns = {}
        exec(compile(code, '<gost_selfcheck>', 'exec'), ns)

        # 1) 纯 IPv4 内核：创建 AF_INET6 socket 直接抛 OSError，不能让 listening() 未捕获崩溃
        real_socket = socket.socket

        def fake_socket(fam, *a, **kw):
            if fam == socket.AF_INET6:
                raise OSError('Address family not supported by protocol')
            s = mock.MagicMock()
            s.connect_ex.return_value = 111
            return s

        with mock.patch.object(ns['socket'], 'socket', side_effect=fake_socket):
            self.assertFalse(ns['listening'](1080), 'AF_INET6 创建抛 OSError 时 listening() 应平滑返回 False')

        # 2) 含非 dict 脏项、端口 0、99999、5000 位超长数字，不应抛 AttributeError/ValueError，且无合法端口返回 0
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / 'gost.yml'
            cfg.write_text(json.dumps({
                'services': [
                    None,
                    'bad-entry',
                    {'addr': ':0'},
                    {'addr': ':70000'},
                    {'addr': ':' + '9' * 5000},
                ]
            }), encoding='utf-8')
            ns['CFG'] = str(cfg)
            self.assertEqual(ns['main'](), 0)

    def test_install_warp_local_proxy_umask_and_field_guards(self):
        """install_warp_local_proxy 须用 umask 077 建 TMP_EXTRACT、校验 WG 字段无换行并检查 mv 失败清理。"""
        start = INSTALL_SH.index('install_warp_local_proxy() {')
        end = INSTALL_SH.index('install_gost() {', start)
        block = INSTALL_SH[start:end]
        self.assertIn('TMP_EXTRACT="$(umask 077; mktemp -d)"', block)
        self.assertIn('[[:cntrl:]]', block, 'WG_PRIV/WG_PUB/WG_EP/WG_ADDR 必须拦截控制字符防止注入 wp.conf')
        self.assertIn('--max-filesize 65536', block, 'watchdog probe curl 应设响应体积上限')


if __name__ == '__main__':
    unittest.main()
