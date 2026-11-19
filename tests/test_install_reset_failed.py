"""安装脚本重启核心服务前先清理失败计数回归测试。

当主服务、门户或入站代理此前因崩溃撞上 systemd 启动频率上限时，
即便重装写好了完好配置，直接重启仍会被拒绝；重启前必须先清理失败计数。
"""
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

SRC = (Path(__file__).resolve().parents[1] / 'install.sh').read_text(encoding='utf-8').replace('\r\n', '\n')
BASH = shutil.which('bash')


def extract_function(src, name):
    marker = f'{name}() {{'
    start = src.index(marker)
    end = src.index('\n}\n', start) + 3
    return src[start:end]


@unittest.skipUnless(BASH, 'requires bash')
class InstallResetFailedTests(unittest.TestCase):
    def _run_bash(self, body):
        return subprocess.run(
            [BASH, '-euo', 'pipefail', '-c', body],
            capture_output=True, text=True, encoding='utf-8', timeout=30,
        )

    def test_setup_service_clears_start_limit_before_restart(self):
        start = SRC.index('    systemctl daemon-reload\n    systemctl enable hysteria-server')
        end = SRC.index('\n}\n', start)
        snippet = SRC[start:end]
        script = f"""
log_info() {{ :; }}
log_err() {{ echo "ERR:$*" >&2; }}
sleep() {{ :; }}
RESET_DONE=0
STARTED=0
systemctl() {{
    case "$1" in
        reset-failed) [[ "$2" == "hysteria-server" ]] && RESET_DONE=1; return 0 ;;
        restart) [[ "$RESET_DONE" == "1" ]] || return 1; STARTED=1; return 0 ;;
        is-active) [[ "$STARTED" == "1" ]]; return $? ;;
        *) return 0 ;;
    esac
}}
run_snippet() {{
{snippet}
}}
run_snippet
"""
        res = self._run_bash(script)
        self.assertEqual(res.returncode, 0, res.stderr)

    def test_setup_portal_clears_start_limit_before_restart(self):
        start = SRC.index('    systemctl daemon-reload\n    systemctl enable hysteria-portal')
        end = SRC.index('    setup_cert_selfheal', start)
        snippet = SRC[start:end]
        script = f"""
log_err() {{ echo "ERR:$*" >&2; }}
sleep() {{ :; }}
RESET_DONE=0
STARTED=0
systemctl() {{
    case "$1" in
        reset-failed) [[ "$2" == "hysteria-portal" ]] && RESET_DONE=1; return 0 ;;
        restart) [[ "$RESET_DONE" == "1" ]] || return 1; STARTED=1; return 0 ;;
        is-active) [[ "$STARTED" == "1" ]]; return $? ;;
        *) return 0 ;;
    esac
}}
run_snippet() {{
{snippet}
}}
run_snippet
"""
        res = self._run_bash(script)
        self.assertEqual(res.returncode, 0, res.stderr)

    def test_install_gost_and_rollback_clear_start_limit_before_restart(self):
        # 主安装路径重启前清理失败计数
        main_start = SRC.index('    if ! systemctl daemon-reload || ! systemctl enable gost')
        main_end = SRC.index('    # 核实服务真的在跑', main_start)
        # 向前多取几行以覆盖前置 reset-failed
        block_start = SRC.rindex('\n    fi\n', 0, main_start) + 1
        main_snippet = SRC[block_start:main_end]

        main_body = main_snippet.split('    fi\n', 1)[1]
        script_main = f"""
log_err() {{ echo "ERR:$*" >&2; }}
_restore_gost_install() {{ echo "RESTORED"; }}
RESET_DONE=0
systemctl() {{
    case "$1" in
        reset-failed) [[ "$2" == "gost" ]] && RESET_DONE=1; return 0 ;;
        restart) [[ "$RESET_DONE" == "1" ]] || return 1; return 0 ;;
        *) return 0 ;;
    esac
}}
run_main() {{
{main_body}
}}
run_main
"""
        res_main = self._run_bash(script_main)
        self.assertEqual(res_main.returncode, 0, res_main.stderr)
        self.assertNotIn('RESTORED', res_main.stdout)

        # 回滚路径重启前同样清理失败计数
        rb_start = SRC.index('    _restore_gost_install() {')
        rb_end = SRC.index('    }\n    _finish_gost_install()', rb_start) + 6
        rb_snippet = SRC[rb_start:rb_end]
        with tempfile.TemporaryDirectory() as td:
            d = Path(td).as_posix()
            script_rb = f"""
had_gost=1; had_unit=0; had_check=0; had_owner=0; had_config=0; had_cert=0; had_key=0
old_active=1; old_enabled=1
old_gost="{d}/old_gost"; : > "$old_gost"
old_unit=""; old_check=""; old_owner=""; old_config=""; old_cert=""; old_key=""
GOST_BIN="{d}/gost"; GOST_UNIT="{d}/gost.service"; GOST_CONFIG="{d}/gost.yml"; HY2_DIR="{d}"
mkdir -p "{d}/gost-cert"
RESET_DONE=0
RESTART_OK=0
systemctl() {{
    case "$1" in
        reset-failed) [[ "$2" == "gost" ]] && RESET_DONE=1; return 0 ;;
        restart) [[ "$RESET_DONE" == "1" ]] && RESTART_OK=1; return 0 ;;
        *) return 0 ;;
    esac
}}
{rb_snippet}
_restore_gost_install
[[ "$RESTART_OK" == "1" ]]
"""
            res_rb = self._run_bash(script_rb)
            self.assertEqual(res_rb.returncode, 0, res_rb.stderr)


if __name__ == '__main__':
    unittest.main()
