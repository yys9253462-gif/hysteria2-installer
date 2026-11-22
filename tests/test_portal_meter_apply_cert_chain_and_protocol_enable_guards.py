"""回归测试：apply_xray_config_with_meter、_vmess_certificate、_apply_vmess_enable、_apply_vlessenc_enable 与 _apply_anytls_enable 的端口/不可哈希配置、符号链接/体积上限及精确证书链计数守卫。"""

import ast
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import portal

PORTAL_SRC = (ROOT / 'portal.py').read_text(encoding='utf-8')


def _method_src(name: str) -> str:
    tree = ast.parse(PORTAL_SRC)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(PORTAL_SRC, node)
    raise AssertionError(f'未找到方法 {name}')


class TestPortalMeterApplyCertChainAndProtocolEnableGuards(unittest.TestCase):
    def test_apply_xray_config_with_meter_rejects_huge_port_leading_zero_and_oversized_file(self):
        """apply_xray_config_with_meter 必须拒绝超 5 位端口、前导零端口与超 1 MiB 计量配置文件。"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cfg_path = root / 'xray.json'
            meter_path = root / 'usage-meter-config.json'

            # 1) 5000 位端口字符串：应报 ValueError('统计接口端口非法')，而非触发 4300 位 int() 崩溃
            meter_path.write_text(json.dumps({'reality': {'address': '127.0.0.1:' + '9' * 5000}}), encoding='utf-8')
            with self.assertRaisesRegex(ValueError, '端口非法|端口越界'):
                portal.apply_xray_config_with_meter({'inbounds': []}, cfg_path, meter_path, root)

            # 2) 前导零端口 '010085' 应被拒绝
            meter_path.write_text(json.dumps({'reality': {'address': '127.0.0.1:010085'}}), encoding='utf-8')
            with self.assertRaisesRegex(ValueError, '端口非法|端口越界'):
                portal.apply_xray_config_with_meter({'inbounds': []}, cfg_path, meter_path, root)

            # 3) 超过 1 MiB 计量配置应被拒绝
            meter_path.write_text(json.dumps({'pad': 'x' * (1024 * 1024 + 64)}), encoding='utf-8')
            with self.assertRaisesRegex(ValueError, '上限'):
                portal.apply_xray_config_with_meter({'inbounds': []}, cfg_path, meter_path, root)

    def test_vmess_certificate_uses_exact_pem_header_and_bounds_file_read(self):
        """_vmess_certificate 必须精确匹配 -----BEGIN CERTIFICATE-----（不误计 CSR）并限制证书读盘 <= 4 MiB。"""
        src = _method_src('_vmess_certificate')
        self.assertIn('-----BEGIN CERTIFICATE-----', src, '不能用宽泛的 BEGIN CERTIFICATE 误把 CSR 当证书链')
        self.assertNotIn("count('BEGIN CERTIFICATE')", src)
        self.assertIn('4 * 1024 * 1024', src, '读取证书 PEM 必须施加 4 MiB 上限')
        self.assertIn("errors='replace'", src, 'openssl x509 子进程须补 errors=replace')

    def test_vmess_vlessenc_and_anytls_enable_guard_unhashable_ports_and_dirty_secrets(self):
        """VMess/VLESS-Enc 启用不得把未校验的脏端口直接塞进 set，且须拒绝非字典 xray.json 及脏密钥。"""
        vm_src = _method_src('_apply_vmess_enable')
        self.assertNotIn('blocked.add(reality_port)', vm_src,
                         '未校验的 reality_port 若为 list 会抛 TypeError: unhashable type')
        self.assertIn('isinstance(original_config, dict)', vm_src)

        vl_src = _method_src('_apply_vlessenc_enable')
        self.assertNotIn("m.get('listen_port'), m.get('subscription_port'),", vl_src,
                         '直接构造 set 字面量遇到 list/dict 脏端口会抛 TypeError: unhashable type')
        self.assertIn('isinstance(original_config, dict)', vl_src)
        self.assertIn('isinstance(decryption, str)', vl_src)

        an_src = _method_src('_apply_anytls_enable')
        self.assertIn("isinstance(old.get('secret'), str)", an_src,
                      '_apply_anytls_enable 必须校验复用的 secret 为非空合法字符串')
        self.assertIn('4 * 1024 * 1024', an_src)


if __name__ == '__main__':
    unittest.main()
