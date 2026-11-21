"""回归测试：install.sh 的 install_binary tag 校验与随机暂存、DNS API/自签证书私钥 umask 077 原子落盘及 cron 提示路径修正。"""

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL_SH = ROOT / 'install.sh'
SRC = INSTALL_SH.read_text(encoding='utf-8')


class InstallBinaryAndCertHardeningTests(unittest.TestCase):
    def _fn_body(self, name: str) -> str:
        start = SRC.index(f'{name}() {{')
        end = SRC.index('\n}\n', start) + 3
        return SRC[start:end]

    def test_install_binary_validates_tag_and_uses_random_staging_file(self):
        body = self._fn_body('install_binary')
        self.assertNotIn('"${HY2_BIN}.new"', body,
                         'install_binary 不应使用固定临时路径 ${HY2_BIN}.new，应改为同目录随机 mktemp')
        self.assertIn('mktemp "$(dirname "$HY2_BIN")/', body,
                      'install_binary 必须在目标二进制同目录创建随机临时文件以保证同分区原子替换')
        self.assertIn('^(app/)?v?[0-9A-Za-z][0-9A-Za-z._-]{0,63}$', body,
                      'install_binary 必须对远端 LATEST_TAG 做安全格式校验')

    def test_setup_cert_via_dns_api_installs_key_under_umask_077(self):
        body = self._fn_body('setup_cert_via_dns_api')
        self.assertIn('(umask 077;', body,
                      'DNS API 安装证书时应在 umask 077 下生成私钥，消除默认 0644 暴露窗口')

    def test_generate_self_signed_cert_uses_umask_077_temp_pair_and_atomic_swap(self):
        body = self._fn_body('generate_self_signed_cert')
        self.assertNotIn('-out "$KEY_FILE"', body,
                         'generate_self_signed_cert 不应直接覆写目标私钥文件，应先写同目录私有临时文件')
        self.assertNotIn('-out "$CERT_FILE"', body,
                         'generate_self_signed_cert 不应直接覆写目标证书文件，应校验生成成功后再原子替换')
        self.assertIn('umask 077', body)
        self.assertIn('mktemp', body)
        self.assertIn('mv -f', body)

    def test_setup_acme_certificate_uses_home_for_cron_hint(self):
        body = self._fn_body('setup_acme_certificate')
        self.assertNotIn('${acct:-/root/.acme.sh/acme.sh}', body,
                         'setup_acme_certificate 中未定义 acct，应直接使用 ${HOME}/.acme.sh/acme.sh')
        self.assertIn('${HOME}/.acme.sh/acme.sh --cron --home ${HOME}/.acme.sh', body)


if __name__ == '__main__':
    unittest.main()
