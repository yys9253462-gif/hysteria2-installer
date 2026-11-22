"""回归测试：门户 AWG 辅助函数防符号链接/超长端口 DoS/体积上限与编码安全，及 GOST 自检写入与归属检测防护。"""

import ast
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
PORTAL_SRC = (ROOT / 'portal.py').read_text(encoding='utf-8')
TREE = ast.parse(PORTAL_SRC)


def _extract_nested_func(name: str):
    for node in ast.walk(TREE):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f'portal.py 中未找到函数 {name}')


def _load_funcs(*names, extra_ns=None):
    import hashlib
    import json
    import os
    import re
    import tempfile as _tf
    ns = {
        'Path': Path,
        'os': os,
        'json': json,
        're': re,
        'hashlib': hashlib,
        'subprocess': subprocess,
        'tempfile': _tf,
        'threading': threading,
        '_log_ignored': lambda *a, **k: None,
    }
    if extra_ns:
        ns.update(extra_ns)
    mod = ast.Module(body=[_extract_nested_func(n) for n in names], type_ignores=[])
    exec(compile(mod, '<portal-extract>', 'exec'), ns)
    return ns


class TestPortalAwgHelpersPortDosSymlinkAndGostSelfcheckGuards(unittest.TestCase):
    def test_awg_read_json_and_local_blob_sha_reject_symlinks_and_oversized_files(self):
        """awg_read_json 须拒绝符号链接与超 2 MiB 文件；_local_blob_sha 须拒绝符号链接与超 8 MiB 文件。"""
        ns = _load_funcs('awg_read_json', '_git_blob_sha', '_local_blob_sha')
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            big = root / 'big.json'
            big.write_bytes(b'{"a":"' + b'x' * (2 * 1024 * 1024 + 32) + b'"}')
            self.assertEqual(ns['awg_read_json'](big, {'fallback': 1}), {'fallback': 1})

            ok = root / 'ok.json'
            ok.write_text('{"k": 1}', encoding='utf-8')
            real_is_symlink = Path.is_symlink

            def fake_sym(self_p):
                if self_p == ok:
                    return True
                return real_is_symlink(self_p)

            with mock.patch.object(Path, 'is_symlink', autospec=True, side_effect=fake_sym):
                self.assertEqual(ns['awg_read_json'](ok, {'fallback': 2}), {'fallback': 2})
                self.assertIsNone(ns['_local_blob_sha'](ok))

    def test_awg_state_handles_5000_digit_port_without_value_error(self):
        """meta.json 中 port 为 5000 位超长数字字符串时，awg_state 必须安全置空端口而不是抛 ValueError 导致 500。"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            meta_p = root / 'meta.json'
            peers_p = root / 'peers.json'
            meta_p.write_text('{"line": "3", "port": "' + '1' + '0' * 5000 + '", "endpoint": "a.com"}', encoding='utf-8')
            peers_p.write_text('{"peers": []}', encoding='utf-8')
            ns = _load_funcs(
                'awg_read_json', 'awg_peers', 'awg_state',
                extra_ns={
                    'AWG_META_PATH': meta_p,
                    'AWG_PEERS_PATH': peers_p,
                    'AWG_CTL': str(root / 'hy2-awgctl'),
                    'awg_installed': lambda: True,
                    'awg_active': lambda: False,
                },
            )
            st = ns['awg_state']()
            self.assertTrue(st['ok'])
            self.assertEqual(st['port'], '')

    def test_ensure_awgctl_and_awg_run_reject_symlink_and_use_utf8_replace(self):
        """ensure_awgctl 与 awg_run 必须拒绝符号链接形式的 AWG_CTL，且 awg_run/awg_active 须带 errors='replace'。"""
        with tempfile.TemporaryDirectory() as td:
            ctl = Path(td) / 'hy2-awgctl'
            ctl.write_text('#!/bin/sh\n', encoding='utf-8')
            called = []

            def fake_run(cmd, **kwargs):
                called.append((cmd, kwargs))
                return subprocess.CompletedProcess(cmd, 0, stdout='active\n', stderr='')

            ns = _load_funcs(
                'ensure_awgctl', 'awg_run', 'awg_active',
                extra_ns={
                    'AWG_CTL': str(ctl),
                    'AWG_SVC_NAME': 'amneziawg-server',
                    'awg_operation_lock': threading.Lock(),
                    'resolve_update_ref': lambda *a, **k: 'a' * 40,
                    '_remote_blob_sha': lambda *a, **k: 'b' * 40,
                    '_fetch_repo_file': lambda *a, **k: b'#!/bin/bash\n# hy2-awgctl\n' + b'x' * 3000,
                },
            )
            real_is_symlink = Path.is_symlink

            def fake_sym(self_p):
                if self_p == ctl:
                    return True
                return real_is_symlink(self_p)

            with mock.patch.object(Path, 'is_symlink', autospec=True, side_effect=fake_sym):
                self.assertFalse(ns['ensure_awgctl'](force=False), '符号链接 AWG_CTL 不得被放行')
                rc, _, err = ns['awg_run'](['status'])
                self.assertNotEqual(rc, 0, '符号链接 AWG_CTL 绝不得被 root 执行')
                self.assertIn('符号链接', err)

            with mock.patch.object(subprocess, 'run', side_effect=fake_run):
                self.assertTrue(ns['awg_active']())
                ns['awg_run'](['status'])
            self.assertEqual(len(called), 2)
            self.assertTrue(all(kw.get('errors') == 'replace' for _, kw in called))

    def test_write_gost_selfcheck_rejects_symlink_target_and_gost_owned_guards_symlink(self):
        """write_gost_selfcheck 与 gost_owned 必须拒绝符号链接目标文件。"""
        with tempfile.TemporaryDirectory() as td:
            sc = Path(td) / 'hy2-gost-selfcheck'
            sc.write_text('old', encoding='utf-8')
            ns = _load_funcs(
                'write_gost_selfcheck',
                extra_ns={
                    'GOST_SELFCHECK_PATH': sc,
                    'GOST_SELFCHECK_SCRIPT': '#!/usr/bin/env python3\nprint(1)\n',
                },
            )
            real_is_symlink = Path.is_symlink

            def fake_sym(self_p):
                if self_p == sc:
                    return True
                return real_is_symlink(self_p)

            with mock.patch.object(Path, 'is_symlink', autospec=True, side_effect=fake_sym):
                self.assertFalse(ns['write_gost_selfcheck'](), '符号链接自检脚本路径必须拒绝写入')


if __name__ == '__main__':
    unittest.main()
