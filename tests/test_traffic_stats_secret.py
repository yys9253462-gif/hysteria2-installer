"""trafficStats.secret 按原值读取，不再删掉非十六进制字符（2026-11-04 修）。

旧实现 `awk ... gsub(/[^0-9a-f]/,"")`：手工改成 `AbCd-Efgh_123456` 的 secret 被截成
`bdf123456`（SE 上实测），写进 usage-meter-config.json 后与 Hysteria 实际用的 secret
对不上，计量每次都 401。install.sh 的 traffic_stats_secret 与生成的 do_upgrade.sh
里内联的那一段都要验。
"""
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which('bash')
SRC = (ROOT / 'install.sh').read_text(encoding='utf-8').replace('\r\n', '\n')

CASES = {
    'secret: AbCd-Efgh_123456\n': 'AbCd-Efgh_123456',
    'secret: "quoted-Secret_99"\n': 'quoted-Secret_99',
    "secret: 'single9876543'  \n": 'single9876543',
    'secret: 0123abcdef0123abcdef  # 注释\n': '0123abcdef0123abcdef',
    'secret: "bad\\"quote1234"\n': '',
    'secret: short\n': '',
}


def bash_path(path):
    cygpath = shutil.which('cygpath')
    if cygpath:
        return subprocess.run([cygpath, '-u', str(path)], capture_output=True, text=True).stdout.strip()
    return Path(path).as_posix()


@unittest.skipUnless(BASH and shutil.which('python3'), 'requires bash and python3')
class TrafficStatsSecretTests(unittest.TestCase):
    def config(self, td, secret_line):
        cfg = Path(td) / 'config.yaml'
        cfg.write_text('listen: :443\ntrafficStats:\n  listen: 127.0.0.1:19996\n  ' + secret_line
                       + 'masquerade:\n  type: proxy\n  secret: not-this-one-123\n', encoding='utf-8')
        return cfg

    def test_install_helper_keeps_the_value(self):
        fn = re.search(r'^traffic_stats_secret\(\) \{\n.*?^\}', SRC, re.S | re.M).group(0)
        for line, want in CASES.items():
            with self.subTest(line=line), tempfile.TemporaryDirectory() as td:
                cfg = self.config(td, line)
                out = subprocess.run([BASH, '-c', fn + '\ntraffic_stats_secret "%s"' % bash_path(cfg)],
                                     capture_output=True, text=True, encoding='utf-8', timeout=20).stdout.strip()
                self.assertEqual(out, want)

    def test_do_upgrade_inline_copy_matches(self):
        body = SRC.split('cat > "$HY2_DIR/do_upgrade.sh" <<\'EOUG\'\n', 1)[1].split('\nEOUG\n', 1)[0]
        snippet = re.search(r'(_upd_secret="\$\(python3 -I - "\$HY2_DIR/config\.yaml" .*?\n\)" \|\| _upd_secret="")',
                            body, re.S).group(1)
        for line, want in CASES.items():
            with self.subTest(line=line), tempfile.TemporaryDirectory() as td:
                self.config(td, line)
                script = 'HY2_DIR="%s"\n%s\nprintf %%s "$_upd_secret"' % (bash_path(td), snippet)
                out = subprocess.run([BASH, '-c', script], capture_output=True, text=True,
                                     encoding='utf-8', timeout=20).stdout
                self.assertEqual(out, want)


if __name__ == '__main__':
    unittest.main()
