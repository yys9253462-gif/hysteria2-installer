"""回归测试：install.sh 下载体积上限、临时文件 umask/RETURN 清理、awg_fetch_ctl 原子替换与 trafficStats 缺 secret 自愈。"""

import hashlib
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL_SH = (ROOT / 'install.sh').read_text(encoding='utf-8')


def _find_bash():
    for cand in (r'C:\Program Files\Git\bin\bash.exe', '/bin/bash', '/usr/bin/bash'):
        if Path(cand).is_file():
            return cand
    return shutil.which('bash')


BASH = _find_bash()


def _extract_fn(name):
    m = re.search(rf'^{re.escape(name)}\(\)\s*\{{.*?^\}}', INSTALL_SH, re.M | re.S)
    if not m:
        raise AssertionError(f'install.sh 中未找到函数 {name}()')
    return m.group(0)


def _run_bash(script):
    env = os.environ.copy()
    if os.name == 'nt':
        git_usr_bin = r'C:\Program Files\Git\usr\bin'
        git_bin = r'C:\Program Files\Git\bin'
        env['PATH'] = f'{git_bin};{git_usr_bin};' + env.get('PATH', '')
    return subprocess.run(
        [BASH, '-c', script],
        capture_output=True,
        text=True,
        encoding='utf-8',
        timeout=30,
        env=env,
    )


class InstallDownloadBoundsAwgAtomicAndMeterRepairGuardsTests(unittest.TestCase):
    def test_install_binary_bounds_download_and_uses_umask_return_cleanup(self):
        """install_binary 必须带 --max-filesize、umask 077 与 RETURN 清理陷阱。"""
        body = _extract_fn('install_binary')
        self.assertIn('--max-filesize ', body, 'install_binary 下载必须限制最大体积防止写爆磁盘')
        self.assertIn('umask 077; mktemp -d', body, 'install_binary 临时目录必须使用 umask 077 创建')
        self.assertRegex(body, r"trap\s+'.*'\s+RETURN", 'install_binary 必须注册 RETURN 清理临时文件')

    def test_portal_fetch_and_blob_shas_bound_download_sizes(self):
        """portal_fetch_files / portal_remote_blob_shas / portal_fetch_py 必须全部带 --max-filesize 上限。"""
        for fn_name in ('portal_fetch_files', 'portal_remote_blob_shas', 'portal_fetch_py'):
            body = _extract_fn(fn_name)
            self.assertIn('--max-filesize ', body, f'{fn_name} 必须对 curl 施加 --max-filesize 限制')
        self.assertRegex(_extract_fn('portal_remote_blob_shas'), r"trap\s+'.*'\s+RETURN",
                         'portal_remote_blob_shas 必须注册 RETURN 清理临时 json')

    @unittest.skipUnless(BASH, 'requires bash')
    def test_awg_fetch_ctl_replaces_target_atomically_and_handles_non_dict_json(self):
        """awg_fetch_ctl 必须通过同目录暂存原子替换目标文件，且面对非对象 JSON 返回不得崩溃。"""
        body = _extract_fn('awg_fetch_ctl')
        self.assertIn('--max-filesize ', body, 'awg_fetch_ctl 必须限制下载体积')
        self.assertIn('mv -f "$staged" "$out"', body, 'awg_fetch_ctl 必须先写同目录暂存再 mv -f 原子替换 $out')
        self.assertIn('umask 077; mktemp', body, 'awg_fetch_ctl 临时文件必须使用 umask 077')
        self.assertIn('umask 077; mktemp', _extract_fn('awg_ensure_ctl'),
                      'awg_ensure_ctl 下载临时文件也应使用 umask 077')

        # 真跑 bash：验证 JSON 返回 [] 时干净返回 1（而非 python Traceback 漏出），且正常 blob 时原子落盘
        helpers = _extract_fn('hy2_git_blob_sha')
        content = '#!/bin/bash\n# hy2-awgctl ok\n'
        blob = hashlib.sha1(f'blob {len(content.encode())}\x00'.encode() + content.encode()).hexdigest()
        with tempfile.TemporaryDirectory() as td:
            out_posix = (Path(td) / 'hy2-awgctl').as_posix()
            script = f'''set -euo pipefail
AWG_REPO="example/repo"
log_warn() {{ :; }}; log_err() {{ echo "ERR: $*"; }}
{helpers}
{body}
curl() {{
  local url="" dest=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -o) dest="$2"; shift 2;;
      --max-time|-H) shift 2;;
      http*) url="$1"; shift;;
      *) shift;;
    esac
  done
  if [[ "$CASE" == "array" ]]; then
    printf '[]'
    return 0
  fi
  if [[ -n "$dest" ]]; then
    printf '%s' "{content}" > "$dest"
    return 0
  fi
  case "$url" in
    */commits/main) printf '{{"sha":"1111111111111111111111111111111111111111"}}';;
    */contents/awgctl.sh*) printf '{{"sha":"{blob}"}}';;
  esac
}}
CASE=array
if awg_fetch_ctl "{out_posix}"; then echo "UNEXPECTED_OK"; exit 1; fi
CASE=good
awg_fetch_ctl "{out_posix}"
echo "GOOD_OK"
'''
            proc = _run_bash(script)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn('GOOD_OK', proc.stdout)
            self.assertEqual((Path(td) / 'hy2-awgctl').read_text(encoding='utf-8'), content)

    @unittest.skipUnless(BASH, 'requires bash')
    def test_portal_write_meter_config_repairs_traffic_stats_block_missing_secret(self):
        """config.yaml 已存在 trafficStats: 段但缺失 secret 时，portal_write_meter_config 必须自动补齐 secret。"""
        body_write = _extract_fn('portal_write_meter_config')
        body_secret = _extract_fn('traffic_stats_secret')
        self.assertIn('python3 -I - "$HY2_CONFIG"', body_write, '补写 config.yaml 应使用 python3 -I 隔离环境')
        self.assertIn("python3 -I -c 'import json", body_write, '写 usage-meter-config.json 应使用 python3 -I 隔离环境')

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cfg = root / 'config.yaml'
            cfg.write_text(
                'listen: :443\ntrafficStats:\n  listen: 127.0.0.1:19996\nmasquerade:\n  type: proxy\n',
                encoding='utf-8',
            )
            script = f'''set -euo pipefail
HY2_DIR="{root.as_posix()}"
HY2_CONFIG="{cfg.as_posix()}"
METER_SECRET="deadbeef0123456789abcdef01234567"
log_info() {{ :; }}; log_warn() {{ :; }}; log_err() {{ echo "ERR: $*"; }}
{body_secret}
{body_write}
portal_write_meter_config "{root.as_posix()}"
'''
            proc = _run_bash(script)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            updated_cfg = cfg.read_text(encoding='utf-8')
            self.assertIn('secret: deadbeef0123456789abcdef01234567', updated_cfg)
            meter_json = (root / 'usage-meter-config.json').read_text(encoding='utf-8')
            self.assertIn('deadbeef0123456789abcdef01234567', meter_json)


if __name__ == '__main__':
    unittest.main()
