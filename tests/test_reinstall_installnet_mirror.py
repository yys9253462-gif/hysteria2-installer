"""reinstall-debian13.sh 下载 InstallNET 时的镜像回退（2026-11-12 修）。

旧实现的 INSTALLNET_MIRROR 与主源是同一个 raw 地址且从未被使用：
raw.githubusercontent.com 一断（或返回报错网页），重装就只能失败。
整个脚本需要 root 与真磁盘；这里摘出真实函数，在 sh 里用假的 wget / curl 模拟网络状况。
"""
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

SRC = (Path(__file__).resolve().parents[1] / 'reinstall-debian13.sh').read_text(encoding='utf-8').replace('\r\n', '\n')
SH = shutil.which('sh') or shutil.which('bash')


def _line(prefix):
    start = SRC.index(prefix)
    return SRC[start:SRC.index('\n', start) + 1]


def _func(name):
    start = SRC.index(name + '() {')
    return SRC[start:SRC.index('\n}\n', start) + 3]


PREAMBLE = _line('INSTALLNET_URL=') + _line('INSTALLNET_MIRROR=')

# 假下载器：按主机决定行为。MODE_RAW / MODE_CDN 取值 fail | html | script。
FAKE = r'''
_pad() { i=0; while [ $i -lt 2000 ]; do echo "$1"; i=$((i+1)); done; }
_mode_of() {
    case "$1" in
        *raw.githubusercontent.com*) echo "$MODE_RAW" ;;
        *cdn.jsdelivr.net*) echo "$MODE_CDN" ;;
        *) echo fail ;;
    esac
}
wget() {
    for _a; do _last="$_a"; done
    echo "$_last" >> "$CALLS"
    _m="$(_mode_of "$_last")"
    if [ "$1" = "-qO" ]; then
        case "$_m" in
            fail) return 4 ;;
            html) { echo '<!DOCTYPE html><html>'; _pad 'blocked page padding line'; } > "$2" ;;
            script) { echo '#!/bin/bash'; _pad '# installer body padding line'; } > "$2" ;;
        esac
        return 0
    fi
    [ "$_m" != fail ]
}
curl() { return 7; }
'''


def run(script):
    return subprocess.run([SH, '-c', script], capture_output=True, text=True, timeout=30)


@unittest.skipUnless(SH, 'requires sh')
class InstallNetMirrorTests(unittest.TestCase):
    def _download(self, mode_raw, mode_cdn):
        with tempfile.TemporaryDirectory() as td:
            script = ('IN_FILE=%s/InstallNET.sh\nCALLS=%s/calls\n: > "$CALLS"\n' % (td, td)
                      + 'MODE_RAW=%s\nMODE_CDN=%s\n' % (mode_raw, mode_cdn)
                      + PREAMBLE + FAKE + _func('installnet_looks_valid') + _func('download_installnet')
                      + 'download_installnet; echo "RC=$?"\n'
                      + 'if [ -f "$IN_FILE" ]; then head -n 1 "$IN_FILE"; else echo NOFILE; fi\n')
            r = run(script)
            calls = Path(td, 'calls').read_text(encoding='utf-8').split()
        return r.stdout, calls

    def test_primary_down_falls_back_to_jsdelivr(self):
        out, calls = self._download('fail', 'script')
        self.assertIn('RC=0', out)
        self.assertIn('#!/bin/bash', out)
        self.assertTrue(any('cdn.jsdelivr.net' in c for c in calls), calls)

    def test_error_page_from_primary_is_rejected_and_mirror_used(self):
        out, calls = self._download('html', 'script')
        self.assertIn('RC=0', out)
        self.assertIn('#!/bin/bash', out)
        self.assertNotIn('<!DOCTYPE', out)

    def test_working_primary_never_touches_mirror(self):
        out, calls = self._download('script', 'fail')
        self.assertIn('RC=0', out)
        self.assertFalse(any('cdn.jsdelivr.net' in c for c in calls), calls)

    def test_both_sources_bad_fails_and_leaves_no_file(self):
        out, calls = self._download('html', 'fail')
        self.assertIn('RC=1', out)
        self.assertIn('NOFILE', out)

    def test_reachability_check_tries_mirror_when_primary_is_down(self):
        with tempfile.TemporaryDirectory() as td:
            script = ('CALLS=%s/calls\n: > "$CALLS"\nMODE_RAW=fail\nMODE_CDN=script\n' % td
                      + PREAMBLE + FAKE + _func('installnet_reachable')
                      + 'installnet_reachable; echo "RC=$?"\n')
            out = run(script).stdout
        self.assertIn('RC=0', out)


if __name__ == '__main__':
    unittest.main()
