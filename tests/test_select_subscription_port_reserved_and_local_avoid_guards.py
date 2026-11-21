"""回归测试：select_subscription_port 避让计量回环端口与托管端口，以及 PORTAL_LOCAL_PORT 防撞车。"""

import json
import re
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL_SH = (ROOT / 'install.sh').read_text(encoding='utf-8').replace('\r\n', '\n')


def _extract_fn(name):
    m = re.search(rf'^{re.escape(name)}\(\)\s*\{{.*?^\}}', INSTALL_SH, re.M | re.S)
    if not m:
        raise AssertionError(f'install.sh 中未找到函数 {name}()')
    return m.group(0)


class SelectSubscriptionPortReservedAndLocalAvoidGuardsTests(unittest.TestCase):
    def test_subscription_port_reserves_meter_ports_and_uses_context_manager(self):
        """订阅端口挑选必须保留 19996/19997 计量端口并用 with open() 读 portal.json。"""
        body = re.search(
            r"HY2_SUB_PORT=\$\(python3 - \"\$HY2_DIR/portal\.json\" <<'PYPORT'\n(.*?)\nPYPORT",
            INSTALL_SH, re.S,
        )
        self.assertIsNotNone(body)
        code = body.group(1)
        self.assertIn('19996', code, '订阅端口保留集合必须包含 Hy2 计量端口 19996')
        self.assertIn('19997', code, '订阅端口保留集合必须包含 Xray 计量端口 19997')
        self.assertIn('with open(', code, '读取 portal.json 应使用 with 上下文管理器释放文件描述符')

    def test_portal_local_port_avoids_reserved_meter_and_managed_ports(self):
        """PORTAL_LOCAL_PORT 分配必须避开 19898/19996/19997、20000-40000 跳跃区间及托管协议端口。"""
        fn = _extract_fn('select_subscription_port')
        m = re.search(r"PORTAL_LOCAL_PORT=\$\(python3 .*?<<'PYPORT'\n(.*?)\nPYPORT", fn, re.S)
        self.assertIsNotNone(m, '未找到 PORTAL_LOCAL_PORT 的 Python 片段')
        code = m.group(1)
        for p in ('19898', '19996', '19997'):
            self.assertIn(p, code, f'PORTAL_LOCAL_PORT 必须避开系统保留端口 {p}')

        # 用受控桩验证：若系统先分配 19996、25000、45111（托管端口）和订阅端口 15555，必须全部跳过选到 15666
        with tempfile.TemporaryDirectory() as td:
            pj = Path(td) / 'portal.json'
            pj.write_text(json.dumps({'anytls_config': {'port': 45111, 'enabled': False}}), encoding='utf-8')
            harness = (
                'import socket\n'
                '_ports = iter([19996, 19997, 25000, 45111, 15555, 15666])\n'
                'class _FakeSock:\n'
                '    def __enter__(self): return self\n'
                '    def __exit__(self, *a): pass\n'
                '    def bind(self, addr): self._p = next(_ports)\n'
                '    def getsockname(self): return ("127.0.0.1", self._p)\n'
                'socket.socket = _FakeSock\n'
            ) + code
            proc = subprocess.run(
                [sys.executable, '-c', harness, '15555', str(pj)],
                capture_output=True, text=True, timeout=20,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout.strip(), '15666', proc.stdout + proc.stderr)

    def test_setup_ports_and_obfs_validates_api_key_and_password_controls(self):
        """setup_ports_and_obfs 应对 NODE_API_KEY 与 AUTH_PASSWORD 做前置控制字符/格式拦截。"""
        fn = _extract_fn('setup_ports_and_obfs')
        self.assertIn('NODE_API_KEY', fn)
        self.assertIn('必须是不含空白和控制字符的纯 ASCII 字符串', fn)


if __name__ == '__main__':
    unittest.main()
