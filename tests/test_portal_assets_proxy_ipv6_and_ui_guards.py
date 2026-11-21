"""回归测试：portal_assets.py 代理列表 IPv6 主机方括号格式化、uninstallCore 恢复按钮与 checkBbrStatus 空字段容错。"""

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = (ROOT / 'portal_assets.py').read_text(encoding='utf-8')


class PortalAssetsProxyIpv6AndUiGuardsTests(unittest.TestCase):
    def test_load_proxy_services_brackets_ipv6_host_and_validates_array(self):
        start = SRC.index('async function loadProxyServices()')
        end = SRC.index('loadProxyServices();', start)
        body = SRC[start:end]
        self.assertIn('Array.isArray(json.services)', body,
                      'loadProxyServices 应对非数组 services 容错，避免 .map 抛错')
        self.assertIn("proxyHostPart", body,
                      'loadProxyServices 应对纯 IPv6 主机补方括号，与后端 URI 口径一致')
        self.assertNotIn('@${curProxyServerHost}:${s.port}', body,
                         '不应直接拼接裸 curProxyServerHost 到代理链接，否则纯 IPv6 链接不可解析')

    def test_uninstall_core_restores_button_state_in_finally(self):
        start = SRC.index('async function uninstallCore(core, btn)')
        end = SRC.index('function gotoTarget(target)', start)
        body = SRC[start:end]
        self.assertIn('const orig = btn.textContent;', body,
                      'uninstallCore 必须记录按钮原文字以便在 finally 恢复')
        self.assertIn('btn.disabled = false;', body,
                      'uninstallCore 必须在 finally 恢复 btn.disabled，防止按钮永久锁死')
        self.assertIn('btn.textContent = orig;', body,
                      'uninstallCore 必须在 finally 恢复按钮原文字')

    def test_check_bbr_status_guards_missing_configured_or_current_strings(self):
        start = SRC.index('async function checkBbrStatus()')
        end = SRC.index('const certBadge =', start)
        body = SRC[start:end]
        self.assertNotIn('json.configured.toUpperCase()', body,
                         'json.configured 缺失时直接 .toUpperCase() 会抛 TypeError 覆盖整个 BBR 卡片')
        self.assertNotIn('json.current.toUpperCase()', body,
                         'json.current 应先转为字符串再 .toUpperCase()')


if __name__ == '__main__':
    unittest.main()
