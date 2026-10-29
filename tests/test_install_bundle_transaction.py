"""Offline failure injection for portal_ensure_py's six-file publication."""

import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "install.sh").read_text(encoding="utf-8")
BASH = shutil.which("bash") or r"C:\Program Files\Git\bin\bash.exe"
FILES = sum((re.search(r'^' + name + r'="(.*)"$', SOURCE, re.M).group(1).split()
             for name in ("PORTAL_FILES", "METER_FILES")), [])


def function(name):
    match = re.search(r'^' + name + r'\(\) \{\n.*?^\}', SOURCE, re.M | re.S)
    if not match:
        raise AssertionError(name)
    return match.group(0)


def fixture(directory, version):
    directory.mkdir(parents=True, exist_ok=True)
    for index, name in enumerate(FILES):
        text = f'VERSION = "{version}-{index}"\n'
        if name == "portal.py":
            text += 'def page_html(): pass\n'
        elif name == "portal_assets.py":
            text += 'SCRIPT = r"fixture"\n'
        if name.startswith(("usage-meter-core-", "usage-meter-runtime-")):
            text += 'ACCOUNTING_REVISION = "2026-10-12-real-usage-v2"\n'
        (directory / name).write_text(text, encoding="utf-8")
        (directory / name).chmod(0o600 if index % 2 else 0o640)


def snapshot(directory):
    return {name: ((directory / name).read_bytes(), stat.S_IMODE((directory / name).stat().st_mode))
            for name in FILES if (directory / name).exists()}


@unittest.skipUnless(Path(BASH).is_file(), "requires Bash")
class InstallBundleTransactionTests(unittest.TestCase):
    def probe(self, fail_kind="", fail_at=0, installed=True, same_source=False,
              corrupt_stage=False):
        with tempfile.TemporaryDirectory(prefix="hy2-bundle-") as temp:
            base = Path(temp)
            dest, source = base / "dest", base / "source"
            dest.mkdir()
            if installed:
                fixture(dest, "old")
            if same_source:
                source = dest
            else:
                fixture(source, "new")
            before = snapshot(dest)
            expected = {name: (source / name).read_bytes() for name in FILES}
            config = dest / "config.yaml"
            config.write_text("trafficStats:\n  secret: abcdef1234\n", encoding="utf-8")
            config_before = config.read_bytes()
            meter_config = dest / "usage-meter-config.json"
            meter_config.write_text("original-config", encoding="utf-8")
            # Patch only the Python process executing the extracted transaction.
            # All bytes still copy/rename on a temporary filesystem; no services run.
            injector = base / "inject.py"
            injector.write_text('''import os, shutil, sys
if os.name == "nt":
    import msvcrt, types
    def flock(fd, operation):
        os.lseek(fd, 0, 0)
        try: msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        except OSError as exc: raise BlockingIOError("update lock busy") from exc
    sys.modules["fcntl"] = types.SimpleNamespace(flock=flock, LOCK_EX=2, LOCK_NB=4)
kind, fail_at = os.environ.get("FAIL_KIND"), int(os.environ.get("FAIL_AT", "0"))
real_replace = os.replace
count = 0
def replace(src, dst):
    global count
    if os.path.basename(str(dst)) in os.environ["BUNDLE_FILES"].split():
        count += 1
        if kind == "replace" and count == fail_at:
            raise OSError("injected publication failure")
    return real_replace(src, dst)
os.replace = replace
real_copy2 = shutil.copy2
copy_count = 0
def copy2(src, dst, *args, **kwargs):
    global copy_count
    copy_count += 1
    if kind == "backup" and copy_count == fail_at:
        raise OSError("injected backup failure")
    return real_copy2(src, dst, *args, **kwargs)
shutil.copy2 = copy2
code = sys.stdin.buffer.read().decode("utf-8")
sys.argv = ["transaction"] + sys.argv[1:]
exec(compile(code, "bundle-transaction", "exec"))
''', encoding="utf-8")
            script = source / "probe.sh"
            script.write_text(
                "set -eo pipefail\n"
                "HY2_DIR=\"$DEST\"; HY2_CONFIG=\"$DEST/config.yaml\"\n"
                "log_info(){ :; }; log_warn(){ :; }; log_err(){ printf '%s\\n' \"$*\" >&2; }\n"
                "curl(){ printf 'UNEXPECTED_NETWORK\\n' >&2; return 99; }\n"
                "systemctl(){ printf 'UNEXPECTED_SERVICE\\n' >&2; return 99; }\n"
                "portal_fetch_py(){ printf 'UNEXPECTED_FETCH\\n' >&2; return 99; }\n"
                "python3(){\n"
                " if [[ \"$1\" == -I ]]; then shift; fi\n"
                " if [[ \"$1\" == - ]]; then shift; \"$PYTHON_EXE\" -I \"$INJECTOR\" \"$@\";\n"
                " else \"$PYTHON_EXE\" -I \"$@\"; fi\n}\n"
                "install_count=0\n"
                "install(){\n"
                " install_count=$((install_count+1))\n"
                " if [[ \"$FAIL_KIND\" == install && \"$install_count\" == \"$FAIL_AT\" ]]; then return 1; fi\n"
                " command install \"$@\" || return $?\n"
                " if [[ \"$CORRUPT_STAGE\" == 1 && \"$install_count\" == 2 ]]; then printf 'def broken(:' > \"${@: -1}\"; fi\n"
                "}\n"
                + "\n".join(re.search(r'^' + name + r'=".*"$', SOURCE, re.M).group(0)
                              for name in ("PORTAL_FILES", "METER_FILES")) + "\n"
                + function("portal_files_ok") + "\n" + function("portal_ensure_py") + "\n"
                + "portal_ensure_py\n", encoding="utf-8", newline="\n")
            env = dict(os.environ, DEST=dest.as_posix(), PYTHON_EXE=Path(sys.executable).as_posix(),
                       INJECTOR=injector.as_posix(), FAIL_KIND=fail_kind, FAIL_AT=str(fail_at),
                       BUNDLE_FILES=" ".join(FILES), CORRUPT_STAGE=str(int(corrupt_stage)))
            result = subprocess.run([BASH, str(script)], cwd=base, env=env,
                                    stdin=subprocess.DEVNULL, capture_output=True,
                                    text=True, encoding="utf-8", errors="replace", timeout=30)
            self.assertNotIn("UNEXPECTED_", result.stderr)
            failed = bool(fail_at or corrupt_stage)
            if failed:
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(snapshot(dest), before, result.stdout + result.stderr)
                self.assertEqual(meter_config.read_text(), "original-config")
            else:
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual({name: data[0] for name, data in snapshot(dest).items()}, expected)
                if os.name != "nt":
                    self.assertTrue(all(mode == 0o644 for _, mode in snapshot(dest).values()))
            self.assertEqual(config.read_bytes(), config_before)
            if fail_kind == "replace" or not failed:
                backups = list((dest / "backups").glob("portal-bundle-*"))
                self.assertEqual(len(backups), 1)
                self.assertEqual(snapshot(backups[0]), before)
            self.assertFalse(list(dest.glob(".portal-bundle-*")))

    def test_preparation_failure_does_not_mix_installed_bundle(self):
        self.probe("install", 2)

    def test_each_publication_failure_restores_bytes_modes_and_keeps_backup(self):
        for index in range(1, len(FILES) + 1):
            with self.subTest(file=FILES[index - 1]):
                self.probe("replace", index)

    def test_backup_failure_does_not_start_publication(self):
        self.probe("backup", 3)

    def test_first_install_failure_removes_all_new_bundle_files(self):
        self.probe("replace", 4, installed=False)

    def test_staged_bundle_is_validated_before_publication(self):
        self.probe(corrupt_stage=True)

    def test_success_replaces_complete_bundle_and_keeps_backup(self):
        self.probe()

    def test_same_source_and_destination_is_safe(self):
        self.probe(same_source=True)

    def test_same_source_failure_restores_original_bundle(self):
        self.probe("replace", 3, same_source=True)


if __name__ == "__main__":
    unittest.main()
