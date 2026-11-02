"""Xray 核心安装：坏的新二进制不能覆盖正在用的旧核心；配置失败时说清核心已换（2026-11-03）。

install_xray_binary 旧实现解压后直接 os.replace：新文件跑不起来时（架构不对、包被截断
但摘要碰巧对上不可能，常见的是 noexec / 依赖缺失）旧核心已被覆盖，正在跑的 Reality /
VMess / VLESS-Enc 下一次重启全挂。下载、摘要、zip 都打桩，二进制写在临时目录。
"""
import io
import os
import shutil
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal  # noqa: E402


def zip_with_xray(content):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as zf:
        zf.writestr('xray', content)
    return buf.getvalue()


class XrayInstallVerifyTests(unittest.TestCase):
    def run_install(self, new_runs):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            target = root / 'xray'
            target.write_bytes(b'OLD-XRAY')
            real_path = Path

            def fake_path(value):
                value = str(value)
                if value.startswith('/usr/local/bin/xray'):
                    return real_path(str(root) + value[len('/usr/local/bin'):])
                return real_path(value)

            payload = zip_with_xray(b'NEW-XRAY')

            def fake_version(binary='/usr/local/bin/xray', run=None):
                data = real_path(fake_path(binary)).read_bytes() if real_path(fake_path(binary)).exists() else b''
                if data == b'OLD-XRAY':
                    return '26.3.27'
                return '26.3.27' if new_runs else ''

            class Resp(io.BytesIO):
                def __enter__(self):
                    return self

                def __exit__(self, *a):
                    return False

            real_replace = os.replace
            with mock.patch.object(portal, 'Path', side_effect=fake_path), \
                 mock.patch.object(portal, '_xray_version', side_effect=fake_version), \
                 mock.patch.object(portal, 'fetch_expected_sha256', return_value='0' * 64), \
                 mock.patch.object(portal, 'verify_sha256', return_value=True), \
                 mock.patch.object(portal.platform, 'machine', return_value='x86_64'), \
                 mock.patch.object(portal.urllib.request, 'urlopen', side_effect=lambda *a, **k: Resp(payload)), \
                 mock.patch.object(portal.os, 'replace',
                                   side_effect=lambda a, b: real_replace(str(fake_path(a)), str(fake_path(b)))):
                ok, msg = portal.install_xray_binary()
            return ok, msg, target.read_bytes(), sorted(p.name for p in root.iterdir())

    def test_new_binary_that_cannot_run_never_replaces_the_working_one(self):
        ok, msg, current, files = self.run_install(new_runs=False)
        self.assertFalse(ok, msg)
        self.assertEqual(current, b'OLD-XRAY', '跑不起来的新核心覆盖了正在用的旧核心')
        self.assertNotIn('xray.new', files)

    def test_working_new_binary_is_installed(self):
        ok, msg, current, files = self.run_install(new_runs=True)
        self.assertTrue(ok, msg)
        self.assertEqual(current, b'NEW-XRAY')


if __name__ == '__main__':
    unittest.main()
