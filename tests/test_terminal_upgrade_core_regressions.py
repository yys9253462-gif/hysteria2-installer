"""Exercise the generated terminal updater against temporary fake binaries only."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
OLD = b'#!/bin/sh\necho old\n'
NEW = b'#!/bin/sh\necho new\n'


class TerminalCoreRegressions(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='hy2-core-regression-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.hy = self.root / 'hy'
        self.hy.mkdir()
        self.binary = self.root / 'hysteria'
        self.binary.write_bytes(OLD)
        self.binary.chmod(0o755)
        (self.hy / 'portal.json').write_text('{"traffic_suspend":{"suspended":false}}')
        self.fake = self.root / 'bin'
        self.fake.mkdir()
        self.payload = self.root / 'payload'
        self.payload.write_bytes(NEW)
        (self.root / 'hashes').write_text(hashlib.sha256(NEW).hexdigest() + '  hysteria-linux-amd64\n')
        self._command('uname', '#!/bin/sh\necho x86_64\n')
        self._command('systemctl', '''#!/bin/sh
printf '%s\n' "$*" >> "$TEST_ROOT/calls"
if [ "${FAIL_FIRST:-0}" = 1 ] && [ ! -f "$TEST_ROOT/failed-once" ]; then
  touch "$TEST_ROOT/failed-once"; exit 1
fi
exit 0
''')
        self._command('curl', '''#!/bin/sh
out=; url=
while [ "$#" -gt 0 ]; do
  case "$1" in -o) shift; out="$1";; https://*) url="$1";; esac
  shift
done
case "$url" in
  */releases/latest) printf '%s' '{"tag_name":"app/v1.2.3"}';;
  */hashes.txt) [ "${FAIL_HASH:-0}" = 1 ] && exit 22; cp "$TEST_ROOT/hashes" "$out";;
  */hysteria-linux-amd64) [ "${FAIL_DOWNLOAD:-0}" = 1 ] && exit 22; cp "$TEST_ROOT/payload" "$out";;
  *) echo "unexpected URL" >&2; exit 99;;
esac
''')
        source = (ROOT / 'install.sh').read_text(encoding='utf-8')
        match = re.search(r'cat > "\$HY2_DIR/do_upgrade\.sh" <<\'EOUG\'\n(.*?)\nEOUG\n', source, re.S)
        self.assertIsNotNone(match)
        code = match.group(1).replace('/etc/hysteria', str(self.hy)).replace('/usr/local/bin/hysteria', str(self.binary))
        self.script = self.root / 'upgrade.sh'
        self.script.write_text(code, encoding='utf-8')
        self.env = dict(os.environ, TEST_ROOT=str(self.root), PATH=str(self.fake) + ':' + os.environ.get('PATH', ''))

    def _command(self, name, body):
        p = self.fake / name
        p.write_text(body)
        p.chmod(0o755)

    def invoke(self, *args, **env):
        return subprocess.run(['bash', str(self.script), *args], env=self.env | env,
                              capture_output=True, text=True, timeout=15)

    def calls(self):
        p = self.root / 'calls'
        return p.read_text().splitlines() if p.exists() else []

    def test_invalid_and_missing_target_fail(self):
        for args in [(), ('invalid',)]:
            with self.subTest(args=args):
                self.assertNotEqual(self.invoke(*args).returncode, 0)
                self.assertEqual(self.binary.read_bytes(), OLD)
                self.assertEqual(self.calls(), [])

    def test_failed_download_cannot_install_stale_file(self):
        (self.root / 'hy2_update_amd64').write_bytes(b'stale')
        self.assertNotEqual(self.invoke('core', FAIL_DOWNLOAD='1').returncode, 0)
        self.assertEqual(self.binary.read_bytes(), OLD)
        self.assertEqual(self.calls(), [])

    def test_missing_or_bad_hash_never_installs(self):
        self.assertNotEqual(self.invoke('core', FAIL_HASH='1').returncode, 0)
        (self.root / 'hashes').write_text('0' * 64 + '  hysteria-linux-amd64\n')
        self.assertNotEqual(self.invoke('core').returncode, 0)
        self.assertEqual(self.binary.read_bytes(), OLD)
        self.assertEqual(self.calls(), [])

    def test_valid_hash_but_invalid_binary_is_rejected(self):
        self.payload.write_bytes(b'not a binary')
        (self.root / 'hashes').write_text(hashlib.sha256(self.payload.read_bytes()).hexdigest() + '  hysteria-linux-amd64\n')
        self.assertNotEqual(self.invoke('core').returncode, 0)
        self.assertEqual(self.binary.read_bytes(), OLD)
        self.assertEqual(self.calls(), [])

    def test_restart_failure_restores_previous_binary(self):
        result = self.invoke('core', FAIL_FIRST='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.binary.read_bytes(), OLD)
        self.assertEqual(self.calls(), ['restart hysteria-server', 'restart hysteria-server'])

    def test_suspended_server_is_never_restarted(self):
        (self.hy / 'portal.json').write_text(json.dumps({'traffic_suspend': {'suspended': True}}))
        result = self.invoke('core')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.binary.read_bytes(), NEW)
        self.assertEqual(self.calls(), [])


if __name__ == '__main__':
    unittest.main()
