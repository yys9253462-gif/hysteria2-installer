"""借 Nginx 签发证书（2026-10-29）的回归测试。

真实的 Nginx + Pebble（Let's Encrypt 测试 CA）端到端验证在 SE 上跑过；这里用假的
nginx / acme.sh 锁住三条不能回退的行为：
  * 已有站点识别必须覆盖「server_name 写在一行里」的写法 —— 漏判会新建同名
    server 块，把原网站顶成 404（SE 实测踩到）；
  * 用 $(...) 捕获时只能拿到 "cert|key"，日志不能混进去；
  * 签发失败要撤掉本次新增的验证配置。
"""
import re
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which('bash')
SRC = (ROOT / 'install.sh').read_text(encoding='utf-8').replace('\r\n', '\n')


def extract(name):
    if name == 'setup_cert_via_nginx':
        # 函数里的 heredoc 有顶格的 }，只能匹配到函数末尾的 return 0。
        return re.search(r'^setup_cert_via_nginx\(\) \{\n.*?\n    return 0\n\}', SRC, re.S | re.M).group(0)
    m = re.search(r'^%s\(\)\s*\{[^\n]*\}$' % name, SRC, re.M) or \
        re.search(r'^%s\(\) \{\n.*?^\}' % name, SRC, re.S | re.M)
    return m.group(0)


def bash_path(path):
    cygpath = shutil.which('cygpath')
    if cygpath:
        return subprocess.run([cygpath, '-u', str(path)], capture_output=True, text=True).stdout.strip()
    return Path(path).as_posix()


PRELUDE = 'RED= GREEN= YELLOW= BLUE= CYAN= PLAIN=\n' + '\n'.join(
    extract(n) for n in ('log_info', 'log_warn', 'log_err', 'log_step',
                         'nginx_has_server_name', 'nginx_name_conflict', 'nginx_reload_checked'))


@unittest.skipUnless(BASH, 'requires bash')
class NginxServerNameTest(unittest.TestCase):
    def has(self, config, domain):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            (td / 'nginx.conf').write_text(config, encoding='utf-8')
            fake = td / 'bin'
            fake.mkdir()
            (fake / 'nginx').write_text('#!/usr/bin/env bash\ncat "%s"\n' % bash_path(td / 'nginx.conf'),
                                        encoding='utf-8')
            (fake / 'nginx').chmod(0o755)
            script = 'PATH="%s:$PATH"\n%s\nnginx_has_server_name "%s" && echo YES || echo NO\n' % (
                bash_path(fake), PRELUDE, domain)
            return subprocess.run([BASH, '-c', script], capture_output=True, text=True,
                                  timeout=20).stdout.strip().endswith('YES')

    def test_one_line_server_block_is_detected(self):
        self.assertTrue(self.has('server { listen 80; server_name site.example.com; location / { return 200; } }\n',
                                 'site.example.com'))

    def test_multi_line_and_multiple_names(self):
        conf = 'server {\n    listen 80;\n    server_name a.example.com\n        www.example.com;\n}\n'
        self.assertTrue(self.has(conf, 'a.example.com'))
        self.assertTrue(self.has(conf, 'www.example.com'))

    def test_no_false_positive_on_substring(self):
        conf = 'server { server_name www.site.example.com; }\n# server_name site.example.com in a comment;\n'
        self.assertFalse(self.has('server { server_name www.site.example.com; }\n', 'site.example.com'))
        self.assertFalse(self.has(conf.split('#')[0], 'example.com'))


@unittest.skipUnless(BASH, 'requires bash')
class SetupCertViaNginxTest(unittest.TestCase):
    """假 nginx（配置检查恒通过）+ 假 acme.sh，跑完整函数。"""

    def run_fn(self, acme_ok):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            fake = td / 'bin'
            fake.mkdir()
            confd = td / 'conf.d'
            confd.mkdir()
            # nginx -T 把 conf.d 里的文件全部吐出来（附带文件名注释，函数靠它确认被 include）
            (fake / 'nginx').write_text(textwrap.dedent('''\
                #!/usr/bin/env bash
                if [[ "$1" == -T ]]; then for f in %s/*.conf; do [ -f "$f" ] && { echo "# configuration file $f:"; cat "$f"; }; done; fi
                exit 0
                ''') % bash_path(confd), encoding='utf-8')
            (fake / 'systemctl').write_text('#!/bin/sh\nexit 0\n', encoding='utf-8')
            home = td / 'home'
            acme_dir = home / '.acme.sh'
            acme_dir.mkdir(parents=True)
            (acme_dir / 'acme.sh').write_text(textwrap.dedent('''\
                #!/usr/bin/env bash
                echo "acme.sh noisy output on stdout"
                d=""; while [ $# -gt 0 ]; do case "$1" in -d) d="$2"; shift;; --fullchain-file) fc="$2"; shift;; --key-file) kf="$2"; shift;; esac; shift; done
                case " $* " in *) ;; esac
                if [ -n "$fc" ]; then cp "$HOME/.acme.sh/${d}_ecc/fullchain.cer" "$fc"; cp "$HOME/.acme.sh/${d}_ecc/${d}.key" "$kf"; exit 0; fi
                %s
                mkdir -p "$HOME/.acme.sh/${d}_ecc"; echo CERT > "$HOME/.acme.sh/${d}_ecc/fullchain.cer"; echo KEY > "$HOME/.acme.sh/${d}_ecc/${d}.key"
                ''') % ('' if acme_ok else 'exit 1'), encoding='utf-8')
            for f in (fake / 'nginx', fake / 'systemctl', acme_dir / 'acme.sh'):
                f.chmod(0o755)
            fn = extract('setup_cert_via_nginx').replace('/etc/nginx/conf.d', bash_path(confd))
            script = '\n'.join([
                'PATH="%s:$PATH"' % bash_path(fake), 'HOME="%s"' % bash_path(home),
                'HY2_CERT_DIR="%s"' % bash_path(td / 'cert'),
                'HY2_ACME_WEBROOT="%s"' % bash_path(td / 'webroot'),
                PRELUDE, 'port_owner() { echo nginx; }', 'hy2_acme_ensure() { return 0; }', fn,
                'pair="$(setup_cert_via_nginx new.example.com me@example.com 2>/dev/null)"; rc=$?',
                'echo "RC=$rc"; echo "PAIR=$pair"; ls "%s"' % bash_path(confd)])
            out = subprocess.run([BASH, '-c', script], capture_output=True, text=True, timeout=30).stdout
            return out

    def test_success_returns_only_cert_pair(self):
        out = self.run_fn(acme_ok=True)
        self.assertIn('RC=0', out)
        pair = re.search(r'^PAIR=(.*)$', out, re.M).group(1)
        self.assertRegex(pair, r'^[^|\n]*/acme-new\.example\.com\.crt\|[^|\n]*/acme-new\.example\.com\.key$',
                         '捕获结果里混进了日志或 acme.sh 输出')
        self.assertIn('hy2-acme-new.example.com.conf', out, '续期还要用验证配置，成功后必须保留')

    def test_failure_removes_added_config(self):
        out = self.run_fn(acme_ok=False)
        self.assertIn('RC=1', out)
        self.assertNotIn('hy2-acme-new.example.com.conf', out, '签发失败后应撤掉新增的验证配置')


if __name__ == '__main__':
    unittest.main(verbosity=2)
