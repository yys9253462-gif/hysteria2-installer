"""Offline behavior tests for the actual generated do_upgrade.sh portal path."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which("bash")
FILES = ("portal.py", "portal_assets.py", "usage-meter-core-20261007-v1.py",
         "usage-meter-readers-20261007-v1.py", "usage-meter-runtime-20261007-v1.py",
         "usage-meter-xray-config-20261007-v1.py")

# Only this isolated child patches system effects. File publication/rollback and
# process locking execute the extracted production code against real temp files.
INJECTOR = r'''
import io, json, os, pathlib, shutil, subprocess, sys, time, types, urllib.request
sys.stdout.reconfigure(encoding="utf-8")
sys.stderr.reconfigure(encoding="utf-8")
base = pathlib.Path(os.environ["DEST"])
files = json.loads(os.environ["FILES"])
case = os.environ.get("CASE", "success")
def log(event):
    with (base / "calls").open("a", encoding="utf-8") as out:
        out.write(json.dumps(event) + "\n")
def version():
    return (base / "portal.py").read_text(encoding="utf-8").splitlines()[0]
def service(args):
    log({"service": args, "version": version()})
    if args == ["restart", "hysteria-server"]:
        (base / "server-state").write_text("running")
    if args == ["restart", "hysteria-portal"]:
        if os.environ.get("HOLD") == "1" and os.environ.get("HOLD_VERSION", "new") in version():
            (base / "entered").touch()
            deadline = time.monotonic() + 20
            while not (base / "release").exists():
                if time.monotonic() > deadline: raise RuntimeError("barrier timed out")
                time.sleep(.02)
        if case == "restart_failure" and "new" in version(): return 1
    return 0
if sys.argv[1] == "service":
    sys.exit(service(sys.argv[2:]))
if sys.argv[1] == "-c":
    code = sys.argv[2]; sys.argv = ["-c"] + sys.argv[3:]
else:
    code = sys.stdin.buffer.read().decode("utf-8"); sys.argv = ["-"] + sys.argv[2:]
# Production uses Linux flock. The Windows-only adapter lets the same tests
# exercise exclusion between real child processes without adding a dependency.
if os.name == "nt":
    import msvcrt
    def flock(fd, operation):
        os.lseek(fd, 0, 0)
        try: msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        except OSError as exc: raise BlockingIOError("update lock busy") from exc
    sys.modules["fcntl"] = types.SimpleNamespace(flock=flock, LOCK_EX=2, LOCK_NB=4)
real_run = subprocess.run
def run(args, **kwargs):
    if args[0] == "systemctl": return subprocess.CompletedProcess(args, service(args[1:]))
    if args[0] == 'bash' and pathlib.Path(args[1]).name == 'repair-config.sh':
        # Native Windows Python resolves bare bash to WSL and cannot carry
        # exported Bash functions. Install stubs in a temporary wrapper only.
        wrapper = base / 'repair-stub.sh'
        wrapper.write_text('python3(){ [[ "$1" != -I ]] || shift; "$PYTHON_EXE" -I "$INJECTOR" "$@"; }\n'
                           'systemctl(){ "$PYTHON_EXE" -I "$INJECTOR" service "$@"; }\n'
                           + pathlib.Path(args[1]).read_text(encoding='utf-8'), encoding='utf-8')
        return real_run([os.environ['BASH_EXE'], str(wrapper)], **kwargs)
    raise AssertionError("unexpected subprocess: " + repr(args))
subprocess.run = run
class Response:
    status = 200
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def read(self, *args): return b'{"ok": true}'
def urlopen(url, **kwargs):
    assert str(url).startswith("http://127.0.0.1:18080/api/health"), url
    current = version()
    log({"health": current})
    if case in ("health_failure", "old_unhealthy") and "new" in current:
        raise OSError("new portal unhealthy")
    if case == "old_unhealthy": raise OSError("old portal unhealthy")
    return Response()
urllib.request.urlopen = urlopen
time.sleep = lambda seconds: None
real_replace, real_copy2 = os.replace, shutil.copy2
count = 0
def replace(src, dst):
    global count
    if pathlib.Path(dst).name in files:
        count += 1
        if case == "write_failure" and count == int(os.environ["FAIL_AT"]):
            raise OSError("injected publication failure")
    return real_replace(src, dst)
def copy2(src, dst, *args, **kwargs):
    if case == "backup_failure" and "backups" in pathlib.Path(dst).parts:
        raise OSError("injected backup failure")
    return real_copy2(src, dst, *args, **kwargs)
os.replace, shutil.copy2 = replace, copy2
exec(compile(code, "extracted-upgrade", "exec"))
'''


@unittest.skipUnless(BASH, "requires Bash")
class TerminalPortalTransactionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hy2-terminal-portal-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.dest = self.base / "dest"
        self.dest.mkdir()
        self.fixture = self.base / "fixture"
        self.fixture.mkdir()
        self.before = {}
        rows = []
        for i, name in enumerate(FILES):
            old = ('VERSION = "old"\n# ' + name + '\n').encode()
            path = self.dest / name
            path.write_bytes(old)
            path.chmod(0o600 if i % 2 else 0o640)
            self.before[name] = (old, stat.S_IMODE(path.stat().st_mode))
            text = 'VERSION = "new"\ndef fixture(): pass\n'
            if name == "portal.py": text += 'def page_html(): pass\n'
            if name == "portal_assets.py": text += 'SCRIPT = r"fixture"\n'
            if name.startswith(("usage-meter-core-", "usage-meter-runtime-")):
                text += 'ACCOUNTING_REVISION = "2026-10-12-real-usage-v2"\n'
            data = text.encode()
            (self.fixture / name).write_bytes(data)
            rows.append({"name": name, "sha": hashlib.sha1(
                b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()})
        (self.fixture / "map.json").write_text(json.dumps(rows), encoding="utf-8")
        (self.fixture / "commit.json").write_text(json.dumps({"sha": "a" * 40}))
        self.data = {"port": 18080, "users": {"alice": {"quota": 123}},
                     "traffic_suspend": {"suspended": False}}
        self.save_data()
        (self.dest / "usage-meter-config.json").write_text('{"original":true}')
        (self.dest / "config.yaml").write_text("listen: :443\nmasquerade:\n  type: proxy\n")
        (self.dest / "server-state").write_text("stopped")
        self.injector = self.base / "inject.py"
        self.injector.write_text(INJECTOR, encoding="utf-8")
        source = (ROOT / "install.sh").read_text(encoding="utf-8")
        body = re.search(r"cat > \"\$HY2_DIR/do_upgrade\.sh\" <<'EOUG'\n(.*?)\nEOUG\n",
                         source, re.S).group(1)
        body = body.replace('/etc/hysteria', self.dest.as_posix())
        body = body.replace('/usr/local/bin', (self.base / 'bin').as_posix())
        body = body.replace('/etc/systemd/system', (self.base / 'units').as_posix())
        prelude = r'''
python3(){
    [[ "$1" != -I ]] || shift
    "$PYTHON_EXE" -I "$INJECTOR" "$@"
}
systemctl(){ "$PYTHON_EXE" -I "$INJECTOR" service "$@"; }
export -f python3 systemctl
curl(){
    local url="" output="" name
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -o) output="$2"; shift 2 ;;
            https://*) url="$1"; shift ;;
            *) shift ;;
        esac
    done
    case "$url" in
        */commits/main) command cat "$FIXTURE/commit.json" ;;
        */contents/\?ref=*) command cp "$FIXTURE/map.json" "$output" ;;
        */contents/*\?ref=*) name="${url##*/}"; name="${name%%\?*}"; command cp "$FIXTURE/$name" "$output" ;;
        *) printf 'UNEXPECTED_NETWORK: %s\n' "$url" >&2; return 99 ;;
    esac
}
'''
        self.script = self.base / "upgrade.sh"
        self.script.write_text(prelude + body, encoding="utf-8", newline="\n")

    def save_data(self):
        (self.dest / "portal.json").write_text(json.dumps(self.data), encoding="utf-8")

    def launch(self, case="success", **extra):
        env = dict(os.environ, DEST=self.dest.as_posix(), FIXTURE=self.fixture.as_posix(),
                   INJECTOR=self.injector.as_posix(), PYTHON_EXE=Path(sys.executable).as_posix(),
                   FILES=json.dumps(FILES), BASH_EXE=BASH, CASE=case, **extra)
        return subprocess.Popen([BASH, str(self.script), "portal"], cwd=self.base,
                                env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def finish(self, child):
        out, err = child.communicate(timeout=40)
        text = (out + err).decode("utf-8", errors="replace")
        self.assertNotIn("UNEXPECTED_", text)
        return child.returncode, text

    def events(self):
        path = self.dest / "calls"
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()] if path.exists() else []

    def assert_original(self):
        for name, (data, mode) in self.before.items():
            self.assertEqual((self.dest / name).read_bytes(), data, name)
            self.assertEqual(stat.S_IMODE((self.dest / name).stat().st_mode), mode, name)
        self.assertEqual(json.loads((self.dest / "portal.json").read_text()), self.data)

    def assert_backup(self):
        backups = list((self.dest / "backups").glob("portal-bundle-*"))
        self.assertEqual(len(backups), 1)
        for name, (data, mode) in self.before.items():
            self.assertEqual((backups[0] / name).read_bytes(), data)
            self.assertEqual(stat.S_IMODE((backups[0] / name).stat().st_mode), mode)

    def test_success_preserves_data_and_complete_backup(self):
        rc, text = self.finish(self.launch())
        self.assertEqual(rc, 0, text)
        for name in FILES:
            self.assertEqual((self.dest / name).read_bytes(), (self.fixture / name).read_bytes())
        self.assert_backup()
        self.assertTrue(any("health" in e for e in self.events()))
        self.assertEqual(json.loads((self.dest / "portal.json").read_text()), self.data)
        self.assertEqual((self.dest / "usage-meter-config.json").read_text(), '{"original":true}')
        self.assertFalse(list(self.dest.glob(".portal-bundle-*")))

    def check_failed_start(self, case):
        rc, text = self.finish(self.launch(case))
        self.assertNotEqual(rc, 0, text)
        self.assert_original()
        self.assert_backup()
        self.assertTrue(any("old" in e.get("health", "") for e in self.events()), text)
        self.assertEqual(sum(e.get("service") == ["restart", "hysteria-portal"] for e in self.events()), 2)
        return text

    def test_restart_failure_restores_and_verifies_old_portal(self):
        self.check_failed_start("restart_failure")

    def test_successful_restart_but_failed_health_rolls_back(self):
        self.check_failed_start("health_failure")

    def test_old_portal_failure_is_reported(self):
        text = self.check_failed_start("old_unhealthy")
        self.assertIn("旧门户", text)
        self.assertIn("失败", text)

    def test_suspended_node_only_repairs_config(self):
        self.data["traffic_suspend"] = {"suspended": True, "units": ["hysteria-server"]}
        self.save_data()
        (self.dest / "usage-meter-config.json").unlink()
        rc, text = self.finish(self.launch())
        self.assertEqual(rc, 0, text)
        self.assertNotIn(["restart", "hysteria-server"], [e.get("service") for e in self.events()])
        self.assertEqual((self.dest / "server-state").read_text(), "stopped")
        config = json.loads((self.dest / "usage-meter-config.json").read_text())
        self.assertIn(config["hysteria"]["secret"], (self.dest / "config.yaml").read_text(encoding="utf-8"))
        self.assertEqual(json.loads((self.dest / "portal.json").read_text()), self.data)

    def test_each_publication_failure_restores_bundle(self):
        for i in range(1, len(FILES) + 1):
            with self.subTest(file=FILES[i - 1]):
                # Each subcase gets a fresh backup collection.
                shutil.rmtree(self.dest / "backups", ignore_errors=True)
                rc, text = self.finish(self.launch("write_failure", FAIL_AT=str(i)))
                self.assertNotEqual(rc, 0, text)
                self.assert_original()
                self.assert_backup()

    def test_invalid_port_does_not_publish(self):
        for port in (True, 18080.5, 0, 65536, "18080"):
            with self.subTest(port=port):
                self.data['port'] = port
                self.save_data()
                rc, text = self.finish(self.launch())
                self.assertNotEqual(rc, 0, text)
                self.assert_original()
                self.assertFalse(self.events())

    def test_backup_failure_does_not_publish(self):
        rc, text = self.finish(self.launch("backup_failure"))
        self.assertNotEqual(rc, 0, text)
        self.assert_original()
        self.assertFalse(self.events())

    def test_rollback_removes_only_newly_created_modules(self):
        missing = FILES[-1]
        (self.dest / missing).unlink()
        del self.before[missing]
        rc, text = self.finish(self.launch("health_failure"))
        self.assertNotEqual(rc, 0, text)
        self.assert_original()
        self.assertFalse((self.dest / missing).exists())

    def test_concurrent_upgrade_rejected_until_validation_finishes(self):
        self.check_concurrent()

    def test_lock_covers_old_portal_recovery_validation(self):
        self.check_concurrent(rollback=True)

    def check_concurrent(self, rollback=False):
        first = self.launch("health_failure" if rollback else "success",
                            HOLD="1", HOLD_VERSION="old" if rollback else "new")
        try:
            deadline = time.monotonic() + 25
            while not (self.dest / "entered").exists():
                if first.poll() is not None or time.monotonic() > deadline:
                    self.fail("first upgrade never entered restart")
                time.sleep(.02)
            second_rc, second_text = self.finish(self.launch())
            self.assertNotEqual(second_rc, 0, second_text)
            self.assertEqual(len(list((self.dest / "backups").glob("portal-bundle-*"))), 1)
            # The installer publisher must obey the very same inode, rather
            # than merely serializing terminal upgrades with one another.
            source = (ROOT / 'install.sh').read_text(encoding='utf-8')
            installer = source.split("<<'PYINSTALLBUNDLE'\n", 1)[1].split('\nPYINSTALLBUNDLE', 1)[0]
            env = dict(os.environ, DEST=self.dest.as_posix(), FILES=json.dumps(FILES), CASE='success')
            result = subprocess.run([sys.executable, '-I', str(self.injector), '-',
                                     str(self.dest), str(self.fixture), *FILES],
                                    input=installer.encode('utf-8'), env=env,
                                    capture_output=True, timeout=10)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(len(list((self.dest / "backups").glob("portal-bundle-*"))), 1)
        finally:
            (self.dest / "release").touch()
            first_rc, first_text = self.finish(first)
        self.assertEqual(first_rc == 0, not rollback, first_text)
        if rollback:
            self.assert_original()
        self.assertTrue(any("health" in e for e in self.events()))
        # The persistent inode is reusable after the owner has exited.
        rc, text = self.finish(self.launch())
        self.assertEqual(rc, 0, text)


if __name__ == "__main__":
    unittest.main()
