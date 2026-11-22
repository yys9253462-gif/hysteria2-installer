"""回归测试：install.sh 的邮箱防选项注入、多源公网 IP 坏值回退、域名解析防注入、port_owner 精确本地列匹配、证书编号防八进制及自愈路径防注入。"""

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL = ROOT / 'install.sh'


def _bash():
    git_bash = Path(r'C:\Program Files\Git\bin\bash.exe')
    if git_bash.is_file():
        return str(git_bash)
    return shutil.which('bash')


def _extract(src: str, name: str) -> str:
    m = re.search(rf'^{re.escape(name)}\(\) \{{\n.*?^\}}', src, re.M | re.S)
    if not m:
        raise AssertionError(f'未找到函数 {name}()')
    return m.group(0) + '\n'


LOG_STUBS = """
log_err(){ printf 'ERR: %s\\n' "$*" >&2; }
log_warn(){ printf 'WARN: %s\\n' "$*"; }
log_info(){ printf 'INFO: %s\\n' "$*"; }
log_step(){ :; }
"""


class InstallEmailPublicIpResolvePortOwnerAndSelfhealGuardsTests(unittest.TestCase):
    def setUp(self):
        self.bash = _bash()
        if not self.bash:
            self.skipTest('需要 bash 环境')
        self.src = INSTALL.read_text(encoding='utf-8').replace('\r\n', '\n')

    def _run(self, script: str, env=None) -> subprocess.CompletedProcess:
        full_env = os.environ.copy()
        if env:
            full_env.update(env)
        with tempfile.TemporaryDirectory(prefix='hy2-inst-guard-') as td:
            p = Path(td) / 'run.sh'
            p.write_text('set -eo pipefail\n' + LOG_STUBS + script, encoding='utf-8', newline='\n')
            return subprocess.run(
                [self.bash, str(p)],
                cwd=td,
                env=full_env,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=30,
            )

    def test_is_valid_email_rejects_leading_hyphen(self):
        """is_valid_email 应拒绝以 - 开头的本地部分，防给 acme.sh 注入 CLI 选项。"""
        body = (
            _extract(self.src, 'is_valid_domain')
            + _extract(self.src, 'is_valid_email')
            + """
is_valid_email "-evil@example.com" && exit 10
is_valid_email "user-ok@example.com" || exit 11
echo OK
"""
        )
        r = self._run(body)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn('OK', r.stdout)

    def test_get_public_ip_falls_through_on_private_or_out_of_range_first_source(self):
        """第一个源返回回环/私有或 >255 非法 IP 时，get_public_ip 必须继续尝试下一个源而非提前中止，并拦截 224+ 保留段。"""
        stub = r'''
curl() {
    case "$*" in
        *ipify*)     printf '%s\n' "$FIRST_IP" ;;
        *icanhazip*) printf '%s\n' "$SECOND_IP" ;;
        *ipinfo*)    printf '%s\n' "$THIRD_IP" ;;
    esac
}
'''
        body = (
            stub
            + _extract(self.src, 'get_public_ip')
            + """
FIRST_IP='127.0.0.1' SECOND_IP='999.999.999.999' THIRD_IP='1.1.1.1'
get_public_ip || exit 21
[[ "$PUBLIC_IP" == "1.1.1.1" ]] || exit 22

FIRST_IP='224.0.0.1' SECOND_IP='240.0.0.1' THIRD_IP='255.255.255.255'
if get_public_ip; then exit 23; fi
echo OK
"""
        )
        r = self._run(body)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn('OK', r.stdout)

    def test_resolve_domain_ips_rejects_option_injection_and_blank(self):
        """resolve_domain_ips 必须拒绝空串、以 - 开头或含空白/控制字符的域名，不得调用 getent/dig。"""
        body = (
            """
getent(){ echo "CALLED_GETENT:$*"; return 0; }
dig(){ echo "CALLED_DIG:$*"; return 0; }
nslookup(){ echo "CALLED_NSLOOKUP:$*"; return 0; }
host(){ echo "CALLED_HOST:$*"; return 0; }
"""
            + _extract(self.src, 'resolve_domain_ips')
            + """
out1="$(resolve_domain_ips "-bad.example.com" || true)"
[[ -z "$out1" ]] || { echo "LEAK1:$out1"; exit 31; }
out2="$(resolve_domain_ips "a.com b.com" || true)"
[[ -z "$out2" ]] || { echo "LEAK2:$out2"; exit 32; }
out3="$(resolve_domain_ips "" || true)"
[[ -z "$out3" ]] || { echo "LEAK3:$out3"; exit 33; }
echo OK
"""
        )
        r = self._run(body)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn('OK', r.stdout)

    def test_port_owner_validates_port_and_matches_local_column_only(self):
        """port_owner 须拒绝非法端口/正则元字符，且仅检查 ss 第 4 列本地端口，不被远端端口或参数误命中。"""
        body = (
            """
ss() {
    printf 'UNCONN 0 0 0.0.0.0:9999 1.2.3.4:443 users:(("other",pid=1,fd=3))\n'
    printf 'LISTEN 0 128 0.0.0.0:8080 0.0.0.0:* users:(("caddy",pid=2,fd=4))\n'
}
python3() { return 1; }
"""
            + _extract(self.src, 'port_owner')
            + """
# 正则通配符 .* 必须被拒收返回空
r_regex="$(port_owner tcp '.*')"
[[ -z "$r_regex" ]] || { echo "REGEX_HIT:$r_regex"; exit 41; }
# 远端列是 1.2.3.4:443，本地列不是 443，不得误报被占
r_peer="$(port_owner udp 443)"
[[ -z "$r_peer" ]] || { echo "PEER_HIT:$r_peer"; exit 42; }
# 本地列 0.0.0.0:8080 必须准确命中 caddy
r_local="$(port_owner tcp 8080)"
[[ "$r_local" == "caddy" ]] || { echo "LOCAL_MISS:$r_local"; exit 43; }
echo OK
"""
        )
        r = self._run(body)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn('OK', r.stdout)

    def test_select_local_certificate_and_portal_selfheal_guards(self):
        """select_local_certificate 拒前导零与使用 multiline CN；setup_portal 有清理陷阱；setup_cert_selfheal 拦换行路径。"""
        sel = _extract(self.src, 'select_local_certificate')
        self.assertIn('^[1-9][0-9]{0,5}$', sel)
        self.assertIn('-nameopt multiline', sel)

        sp = _extract(self.src, 'setup_portal')
        self.assertIn('trap ', sp)
        self.assertIn('umask 077', sp)

        sc = _extract(self.src, 'setup_cert_selfheal')
        self.assertIn('[[:cntrl:]]', sc)


if __name__ == '__main__':
    unittest.main()
