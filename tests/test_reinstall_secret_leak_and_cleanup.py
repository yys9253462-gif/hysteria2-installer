"""回归测试：reinstall-debian13 不把自动生成的明文 root 密码写入日志、alpine2debian 设陷阱清理明文密码文件、LOGIN_SCRIPT 判空。"""

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RD13_SRC = (ROOT / 'reinstall-debian13.sh').read_text(encoding='utf-8')
A2D_SRC = (ROOT / 'alpine2debian.sh').read_text(encoding='utf-8')
ASSETS_SRC = (ROOT / 'portal_assets.py').read_text(encoding='utf-8')


class ReinstallSecretLeakAndCleanupTests(unittest.TestCase):
    def test_reinstall_debian13_never_logs_generated_plaintext_password_via_warn(self):
        self.assertNotIn('warn "已自动生成 root 密码：$PASSWORD"', RD13_SRC,
                         'warn() 会把内容写入 $LOG，不得通过 warn 打印明文随机密码导致日志泄漏')
        self.assertIn('已自动生成随机 root 密码（已省略明文）', RD13_SRC)

    def test_alpine2debian_installs_signal_trap_to_clean_chroot_rootpw_file(self):
        start = A2D_SRC.index('printf \'%s\\n\' "$BODY" > "$MOUNT_DIR/tmp/_setup.sh"') - 150
        end = A2D_SRC.index('ok "chroot 配置完成"', start)
        block = A2D_SRC[start:end]
        self.assertIn('trap ', block, '写明文 _rootpw 前必须注册 EXIT/INT/TERM 清理陷阱防中断残留密码文件')
        self.assertIn('_rootpw', block)

    def test_login_script_toggle_secret_guards_missing_element(self):
        start = ASSETS_SRC.index('LOGIN_SCRIPT = r"""')
        end = ASSETS_SRC.index('"""', start + len('LOGIN_SCRIPT = r"""'))
        block = ASSETS_SRC[start:end]
        self.assertIn('if (!el) return;', block,
                      'toggleSecret 应对缺失的 input 元素判空，避免抛 TypeError')


if __name__ == '__main__':
    unittest.main()
