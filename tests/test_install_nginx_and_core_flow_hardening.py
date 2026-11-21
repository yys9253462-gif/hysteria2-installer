"""回归测试：setup_cert_via_nginx 原子写配置与私钥掩码；uninstall_all 锁释放陷阱与 flow_update_core 私有备份。"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL = ROOT / 'install.sh'


class InstallNginxAndCoreFlowHardeningTests(unittest.TestCase):
    def _func(self, name):
        src = INSTALL.read_text(encoding='utf-8').replace('\r\n', '\n')
        m = re.search(r'^%s\(\) \{\n.*?^\}' % name, src, re.S | re.M)
        self.assertIsNotNone(m, f'未找到 {name}')
        return m.group(0)

    def test_setup_cert_via_nginx_writes_conf_atomically_and_protects_key_umask(self):
        src = INSTALL.read_text(encoding='utf-8').replace('\r\n', '\n')
        start = src.index('setup_cert_via_nginx() {')
        end = src.index('setup_cert_via_dns_api() {', start)
        body = src[start:end]
        self.assertNotIn('cat > "$conf" <<EOF', body, 'setup_cert_via_nginx 不应非原子直写 Nginx 配置')
        self.assertIn('mktemp "${conf}.XXXXXX"', body)
        self.assertIn('umask 077', body, 'setup_cert_via_nginx 复制私钥与创建归属标记需在 umask 077 下执行')

    def test_uninstall_all_and_flow_update_core_guard_locks_and_private_rollback(self):
        un = self._func('uninstall_all')
        self.assertIn("trap 'if declare -F release_installer_core_lock", un,
                      'uninstall_all 持锁后缺少 RETURN 释放陷阱')
        up = self._func('flow_update_core')
        self.assertIn('umask 077; mktemp "${HY2_BIN}.rollback.XXXXXX"', up,
                      'flow_update_core 的回滚副本未在 umask 077 下创建')


if __name__ == '__main__':
    unittest.main()
