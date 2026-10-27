"""真执行安装/更新校验：旧计量缓存不能与新面板混装。"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASH = (r'C:\Program Files\Git\bin\bash.exe' if os.name == 'nt' else shutil.which('bash'))
FILES = ['portal.py', 'portal_assets.py'] + [p.name for p in ROOT.glob('usage-meter-*-v1.py')]


@unittest.skipUnless(BASH and Path(BASH).exists(), 'requires bash')
class MeterBundleGuardTests(unittest.TestCase):
    def run_shell(self, script, root):
        path = root / 'test.sh'
        path.write_text(script, encoding='utf-8', newline='\n')
        return subprocess.run([BASH, str(path)], cwd=root, capture_output=True,
                              text=True, encoding='utf-8', errors='replace')

    def test_installer_rejects_old_runtime_and_old_core(self):
        source = (ROOT / 'install.sh').read_text(encoding='utf-8')
        function = source.split('portal_files_ok() {', 1)[1].split('\n}\n', 1)[0]
        for stale in ('', 'usage-meter-runtime-20261007-v1.py', 'usage-meter-core-20261007-v1.py'):
            with self.subTest(stale=stale), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                for name in FILES:
                    shutil.copyfile(ROOT / name, root / name)
                if stale:
                    p = root / stale
                    p.write_text(p.read_text(encoding='utf-8').replace('2026-10-12-real-usage-v2', 'old'), encoding='utf-8')
                result = self.run_shell('PORTAL_FILES="portal.py portal_assets.py"\nMETER_FILES="' +
                    ' '.join(f for f in FILES if f.startswith('usage-meter')) +
                    '"\nportal_files_ok() {' + function + '\n}\nportal_files_ok "$PWD"\n', root)
                self.assertEqual(result.returncode == 0, not bool(stale), result.stderr)

    def test_terminal_upgrade_is_all_or_nothing_when_cache_is_stale(self):
        source = (ROOT / 'install.sh').read_text(encoding='utf-8')
        start = source.index('    REPO="yys9253462-gif/hysteria2-installer"', source.index('elif [[ "$TARGET" == "portal" ]]'))
        end = source.index('        # 计量配置自愈', start)
        block = source[start:end] + '\nfi\n'
        for stale in (False, True):
            with self.subTest(stale=stale), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                fixture = root / 'fixture'; fixture.mkdir()
                target = root / 'target'; target.mkdir()
                for name in FILES:
                    shutil.copyfile(ROOT / name, fixture / name)
                    (target / name).write_text('original-' + name)
                if stale:
                    p = fixture / 'usage-meter-runtime-20261007-v1.py'
                    p.write_text(p.read_text(encoding='utf-8').replace('2026-10-12-real-usage-v2', 'old'), encoding='utf-8')
                # 不触网，不调用 systemctl；只测试实际下载+落地代码段。
                # 目录列表 JSON：文件名 -> fixture 内容的 git blob 身份。
                # 门户取文件现在除了 marker/语法，还要比对 blob 身份（2026-10-27）。
                import hashlib as _h
                entries = []
                for name in FILES:
                    data = (fixture / name).read_bytes()
                    blob = _h.sha1(b'blob ' + str(len(data)).encode() + b'\x00' + data).hexdigest()
                    entries.append('{"name":"%s","sha":"%s"}' % (name, blob))
                listing = '[' + ','.join(entries) + ']'
                stub = '''HY2_DIR="$PWD/target"
LISTING=''' + '\'' + listing + '\'' + '''
curl() {
  local url='' dest=''
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -o) dest="$2"; shift 2;;
      --max-time|-H) shift 2;;
      http*) url="$1"; shift;;
      *) shift;;
    esac
  done
  if [[ "$url" == */commits/main ]]; then
    printf '{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}'
    return
  fi
  # 目录列表（contents/?ref=<sha>）与单文件 JSON（contents/<name>?ref=<sha>）都要答
  if [[ "$url" == */contents/\?ref=* ]]; then
    printf '%s' "$LISTING" > "$dest"
    return
  fi
  if [[ "$url" == */contents/*\?ref=* ]]; then
    local n="${url#*/contents/}"; n="${n%%\?*}"
    printf '%s' "$LISTING" | python3 -c 'import json,sys; n=sys.argv[1]; print(json.dumps({"sha": next((i["sha"] for i in json.load(sys.stdin) if i["name"]==n), "")}))' "$n"
    return
  fi
  [[ "$url" == *aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa* ]] || return 9
  local file="${url##*/}"; file="${file%%\\?*}"
  cp "$PWD/fixture/$file" "$dest"
}
'''
                result = self.run_shell(stub + block, root)
                self.assertEqual(result.returncode == 0, not stale, result.stderr)
                for name in FILES:
                    expected = ('original-' + name).encode() if stale else (fixture / name).read_bytes()
                    self.assertEqual((target / name).read_bytes(), expected)

    def test_installer_pins_snapshot_and_rejects_unresolvable_ref(self):
        source = (ROOT / 'install.sh').read_text(encoding='utf-8')
        body = source.split('portal_fetch_py() {', 1)[1].split('\n}\n', 1)[0]
        for resolve in (True, False):
            with self.subTest(resolve=resolve), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                script = '''AWG_REPO=owner/repo
curl() { printf '%s' 'PAYLOAD'; }
portal_fetch_files() {
  [[ "$PORTAL_FETCH_REF" == aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ]] || return 7
  [[ "$2" != *'@main'* && "$2" != */main ]] || return 8
  printf '%s' "$PORTAL_FETCH_REF" > "$1/pinned"
}
portal_files_ok() { return 0; }
portal_remote_blob_shas() { [[ "$1" == aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ]] || return 1; echo "x aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; }
portal_verify_blobs() { return 0; }
'''.replace('PAYLOAD', '{"sha":"' + 'a' * 40 + '"}' if resolve else '{}')
                result = self.run_shell(script + 'portal_fetch_py() {' + body +
                                        '\n}\nportal_fetch_py "$PWD"\n', root)
                self.assertEqual(result.returncode == 0, resolve, result.stderr)
                self.assertEqual((root / 'pinned').exists(), resolve)

    def test_generated_upgrade_script_syntax(self):
        source = (ROOT / 'install.sh').read_text(encoding='utf-8')
        body = source.split("<<'EOUG'\n", 1)[1].split('\nEOUG', 1)[0]
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'upgrade.sh'
            path.write_text(body, encoding='utf-8', newline='\n')
            result = subprocess.run([BASH, '-n', str(path)], capture_output=True,
                                    text=True, encoding='utf-8', errors='replace')
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_runtime_rejects_old_core(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for name in FILES:
                shutil.copyfile(ROOT / name, root / name)
            core = root / 'usage-meter-core-20261007-v1.py'
            core.write_text(core.read_text(encoding='utf-8').replace('2026-10-12-real-usage-v2', 'old'), encoding='utf-8')
            result = subprocess.run([sys.executable, str(root / 'usage-meter-runtime-20261007-v1.py')],
                                    capture_output=True, text=True, encoding='utf-8', errors='replace')
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('usage_meter_core_revision_mismatch', result.stderr)


if __name__ == '__main__':
    unittest.main()
