"""回归测试：awgctl.sh meta 读写防符号链接与对象守卫、download_binaries 符号链接与 RETURN 陷阱重挂、uninstall 符号链接与 -- 隔离、resync 多余参数拦截与 parse_name_endpoint 拒绝空/横杠值。"""

import os
import re
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AWGCTL_SH = (ROOT / 'awgctl.sh').read_text(encoding='utf-8').replace('\r\n', '\n')


def _find_bash():
    for cand in (r'C:\Program Files\Git\bin\bash.exe', '/bin/bash', '/usr/bin/bash'):
        if Path(cand).is_file():
            return cand
    return shutil.which('bash')


BASH = _find_bash()


def _extract_fn(name: str) -> str:
    m = re.search(rf'^{re.escape(name)}\(\)\s*\{{.*?^\}}', AWGCTL_SH, re.M | re.S)
    if not m:
        raise AssertionError(f'awgctl.sh 中未找到函数 {name}()')
    return m.group(0)


def _run_bash(script: str):
    env = os.environ.copy()
    if os.name == 'nt':
        env['PATH'] = r'C:\Program Files\Git\bin;C:\Program Files\Git\usr\bin;' + env.get('PATH', '')
    return subprocess.run(
        [BASH, '-s'],
        input=script,
        capture_output=True,
        text=True,
        encoding='utf-8',
        timeout=20,
        env=env,
    )


class TestAwgctlMetaDownloadTrapUninstallResyncAndParseGuards(unittest.TestCase):
    def test_meta_get_and_set_reject_symlinks_and_guard_non_object_json(self):
        """meta_get 与 meta_set 必须拒绝符号链接，且 meta_get 须校验顶层为 JSON 对象防数组崩溃。"""
        mg = _extract_fn('meta_get')
        ms = _extract_fn('meta_set')
        self.assertIn('-L "$AWG_META_FILE"', mg, 'meta_get 必须拒绝符号链接 meta 文件')
        self.assertIn('if type=="object"', mg, 'meta_get 须在 jq 中判定 object 类型防非对象报错')
        self.assertIn('-L "$AWG_DIR"', ms, 'meta_set 必须拒绝符号链接 $AWG_DIR')
        self.assertIn('-L "$AWG_META_FILE"', ms, 'meta_set 必须拒绝符号链接 $AWG_META_FILE')

    def test_download_binaries_guards_args_symlinks_nf2_and_rearms_return_trap(self):
        """download_binaries 必须校验 line/arch、要求 SHA256SUMS 严格双列 NF==2、拒绝符号链接二进制并重挂 RETURN 清理陷阱。"""
        body = _extract_fn('download_binaries')
        self.assertIn('NF != 2', body, 'SHA256SUMS 解析必须要求严格双列 NF == 2')
        self.assertIn('-L "$f"', body, '替换二进制前必须拒绝符号链接目标')
        self.assertGreaterEqual(
            body.count('trap "$_dl_trap" RETURN'),
            2,
            'download_binaries 调用 awg_atomic_install_bin 后必须重挂 RETURN 清理陷阱防残留 tmpd/bakd',
        )

    def test_cmd_uninstall_guards_symlink_awg_dir_and_uses_double_dash(self):
        """cmd_uninstall 必须拒绝符号链接 $AWG_DIR 并对 rm 命令补 -- 参数隔离。"""
        body = _extract_fn('cmd_uninstall')
        self.assertIn('-L "$AWG_DIR"', body, 'cmd_uninstall 删除配置目录前必须拒绝符号链接 $AWG_DIR')
        self.assertIn('rm -rf -- "$AWG_DIR"', body, 'rm -rf $AWG_DIR 必须带 --')
        self.assertIn('rm -f -- "$AWG_SERVICE"', body, 'rm -f $AWG_SERVICE 必须带 --')

    @unittest.skipUnless(BASH, 'requires bash')
    def test_cmd_resync_rejects_extra_args_and_parse_name_endpoint_rejects_dash_value(self):
        """cmd_resync 必须拒绝多余参数；parse_name_endpoint 必须拒绝 --endpoint 后紧跟空值或 --flag。"""
        resync_body = _extract_fn('cmd_resync')
        parse_body = _extract_fn('parse_name_endpoint')
        self.assertIn('$# -eq 0', resync_body, 'cmd_resync 必须拦截多余参数')

        script = f'''set -uo pipefail
die() {{ echo "DIE: $*"; exit 1; }}
{parse_body}
if ( parse_name_endpoint alice --endpoint --bogus ) >/dev/null 2>&1; then
    echo "ACCEPTED_DASH_EP"
    exit 2
fi
if ( parse_name_endpoint alice --endpoint "" ) >/dev/null 2>&1; then
    echo "ACCEPTED_EMPTY_EP"
    exit 3
fi
echo "PARSE_OK"
'''
        proc = _run_bash(script)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn('PARSE_OK', proc.stdout)


if __name__ == '__main__':
    unittest.main()
