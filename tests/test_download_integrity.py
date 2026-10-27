#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""下载校验链的离线回归（2026-10-27）。

覆盖的都是"失败路径必须 fail-closed"的不变量，全部离线、不下载任何真实产物、
不执行任何被下载的二进制：

  * 正确摘要 -> 通过
  * hash 不匹配 -> 拒绝
  * 清单缺失 / 空 / 畸形 / 同一资产重名 -> 拒绝（AWG 缺摘要不可用任何开关或
    环境变量绕过：既没有 CLI 选项，也不读 ALLOW_MISSING_SUMS）
  * 上游下载失败 / 校验失败 -> 现有产物不被覆盖、临时文件被清理
  * 版本与架构映射（hysteria armv7 -> arm、Xray armv7 -> arm32-v7a）
  * git blob 身份（必须含 `blob <len>\\0` 头，不等于文件 sha1）
  * tar/zip 成员约束（绝对路径、`..`、重名）
  * 嵌入副本（portal.py 内嵌的 WARP 安装脚本）与 install.sh 同步
"""

import base64
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PORTAL = ROOT / 'portal.py'
INSTALL = ROOT / 'install.sh'
AWGCTL = ROOT / 'awgctl.sh'
BASH = shutil.which('bash')


def load_portal():
    """以模块方式加载 portal.py（只读，不启动服务）。"""
    spec = importlib.util.spec_from_file_location('portal_under_test', PORTAL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ManifestParsingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.portal = load_portal()

    def test_exact_asset_match(self):
        text = ('a' * 64 + '  gost_3.3.1_linux_amd64.tar.gz\n'
                + 'b' * 64 + '  gost_3.3.1_linux_arm64.tar.gz\n')
        self.assertEqual(self.portal.parse_checksum_manifest(text, 'gost_3.3.1_linux_arm64.tar.gz'), 'b' * 64)

    def test_prefix_names_do_not_match(self):
        # amd64 不能匹配到 amd64v3，反之亦然（旧实现只取"第一条"，会串味）
        text = ('a' * 64 + '  gost_3.3.1_linux_amd64v3.tar.gz\n'
                + 'b' * 64 + '  gost_3.3.1_linux_amd64.tar.gz\n')
        self.assertEqual(self.portal.parse_checksum_manifest(text, 'gost_3.3.1_linux_amd64.tar.gz'), 'b' * 64)
        self.assertIsNone(self.portal.parse_checksum_manifest(text, 'gost_3.3.1_linux_amd64v4.tar.gz'))

    def test_build_prefix_and_crlf_and_star(self):
        text = 'c' * 64 + '  build/hysteria-linux-amd64\r\n'
        self.assertEqual(self.portal.parse_checksum_manifest(text, 'hysteria-linux-amd64'), 'c' * 64)
        self.assertEqual(self.portal.parse_checksum_manifest('d' * 64 + ' *wireproxy_linux_amd64.tar.gz\n',
                                                             'wireproxy_linux_amd64.tar.gz'), 'd' * 64)

    def test_duplicate_asset_is_rejected(self):
        text = 'a' * 64 + '  gost.tar.gz\n' + 'b' * 64 + '  gost.tar.gz\n'
        self.assertIsNone(self.portal.parse_checksum_manifest(text, 'gost.tar.gz'))

    def test_malformed_digest_is_rejected(self):
        self.assertIsNone(self.portal.parse_checksum_manifest('nothex  gost.tar.gz\n', 'gost.tar.gz'))
        self.assertIsNone(self.portal.parse_checksum_manifest('abc  gost.tar.gz\n', 'gost.tar.gz'))

    def test_empty_or_missing_manifest(self):
        self.assertIsNone(self.portal.parse_checksum_manifest('', 'gost.tar.gz'))
        self.assertIsNone(self.portal.parse_checksum_manifest(None, 'gost.tar.gz'))
        self.assertIsNone(self.portal.parse_checksum_manifest('a' * 64 + '  other\n', 'gost.tar.gz'))

    def test_fetch_expected_returns_none_on_failure(self):
        def boom(*a, **k):
            raise OSError('network down')
        old = self.portal.fetch_text
        try:
            self.portal.fetch_text = boom
            self.assertIsNone(self.portal.fetch_expected_sha256('http://x/checksums.txt', 'a.tar.gz'))
        finally:
            self.portal.fetch_text = old

    def test_xray_dgst_only_sha2_256(self):
        text = ('MD5= ee4e2ff74948a9b464624b1cabc44409\n'
                'SHA1= b55b06e74e89083b9cedfdecf0d68b579cd2af72\n'
                'SHA2-256= ' + 'f' * 64 + '\n'
                'SHA2-512= ' + 'e' * 128 + '\n')
        self.assertEqual(self.portal.parse_xray_dgst(text), 'f' * 64)
        # 只有 MD5/SHA1 时绝不能被当成校验依据
        self.assertIsNone(self.portal.parse_xray_dgst(text.split('SHA2-256')[0]))
        self.assertIsNone(self.portal.parse_xray_dgst(''))
        # 重复的 SHA2-256 也要拒绝
        self.assertIsNone(self.portal.parse_xray_dgst(text + 'SHA2-256= ' + 'a' * 64 + '\n'))


class VerifyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.portal = load_portal()

    def test_verify_sha256(self):
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(b'payload')
            path = fh.name
        try:
            good = hashlib.sha256(b'payload').hexdigest()
            self.assertTrue(self.portal.verify_sha256(path, good))
            self.assertFalse(self.portal.verify_sha256(path, '0' * 64))
            self.assertFalse(self.portal.verify_sha256(path, 'not-a-digest'))
            self.assertFalse(self.portal.verify_sha256(path, ''))
            self.assertFalse(self.portal.verify_sha256('/nonexistent/x', good))
        finally:
            os.unlink(path)

    def test_git_blob_sha_includes_blob_header(self):
        data = b'hello world\n'
        expect = hashlib.sha1(b'blob 12\x00' + data).hexdigest()
        self.assertEqual(self.portal.git_blob_sha(data), expect)
        self.assertNotEqual(self.portal.git_blob_sha(data), hashlib.sha1(data).hexdigest())


class ArchMappingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.portal = load_portal()

    def test_hysteria_armv7_uses_arm_asset(self):
        # 上游没有 hysteria-linux-armv7（实测 404），必须映射到 arm
        self.assertEqual(self.portal.hysteria_asset_arch('armv7l'), 'arm')
        self.assertEqual(self.portal.hysteria_asset_arch('x86_64'), 'amd64')
        self.assertEqual(self.portal.hysteria_asset_arch('aarch64'), 'arm64')
        self.assertIsNone(self.portal.hysteria_asset_arch('mips'))

    def test_install_sh_core_arch_mapping(self):
        src = INSTALL.read_text(encoding='utf-8')
        body = src.split('hy2_core_asset_arch() {', 1)[1].split('\n}\n', 1)[0]
        script = 'hy2_core_asset_arch() {' + body + '\n}\n' + \
                 'for a in amd64 arm64 armv7 mips; do printf "%s=%s\\n" "$a" "$(hy2_core_asset_arch "$a" || echo FAIL)"; done\n'
        out = run_bash(script)
        self.assertIn('amd64=amd64', out)
        self.assertIn('arm64=arm64', out)
        self.assertIn('armv7=arm', out)
        self.assertIn('mips=FAIL', out)

    def test_xray_armv7_not_silently_amd64(self):
        src = PORTAL.read_text(encoding='utf-8')
        # 旧实现是 `else '64'`：除 aarch64 外全当 amd64，armv7 会被静默装错架构
        self.assertNotIn("xarch = 'arm64-v8a' if ('aarch64' in machine or 'arm64' in machine) else '64'", src)
        self.assertIn("xarch = 'arm32-v7a'", src)
        self.assertIn('不支持的 CPU 架构，无法选择 Xray 资产', src)


class MemberSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.portal = load_portal()

    def test_tar_member_rejects_traversal(self):
        with self.assertRaises(ValueError):
            self.portal.safe_tar_members(['../evil', 'gost'], 'gost')
        with self.assertRaises(ValueError):
            self.portal.safe_tar_members(['/etc/passwd', 'gost'], 'gost')
        with self.assertRaises(ValueError):
            self.portal.safe_tar_members(['a/../../b', 'gost'], 'gost')

    def test_tar_member_requires_unique_exact_match(self):
        self.assertEqual(self.portal.safe_tar_members(['./gost'], 'gost'), './gost')
        self.assertEqual(self.portal.safe_tar_members(['gost'], 'gost'), 'gost')
        with self.assertRaises(ValueError):
            self.portal.safe_tar_members(['gost', 'sub/gost'], 'gost')
        with self.assertRaises(ValueError):
            self.portal.safe_tar_members(['gost2'], 'gost')

    def test_zip_member(self):
        self.assertEqual(self.portal.safe_zip_members(['xray'], 'xray'), 'xray')
        with self.assertRaises(ValueError):
            self.portal.safe_zip_members(['../xray'], 'xray')
        with self.assertRaises(ValueError):
            self.portal.safe_zip_members([], 'xray')


def run_bash(script, cwd=None, env=None):
    """写文件再 `bash <file>`（不走 -c：MSYS 会做路径转换）。"""
    fd, path = tempfile.mkstemp(suffix='.sh')
    os.close(fd)
    try:
        Path(path).write_text(script, encoding='utf-8', newline='\n')
        e = dict(os.environ)
        if env:
            e.update(env)
        r = subprocess.run([BASH, path], cwd=cwd, capture_output=True, text=True,
                           encoding='utf-8', errors='replace', env=e)
        return r.stdout + r.stderr
    finally:
        os.unlink(path)


def extract_install_fn(name):
    text = INSTALL.read_text(encoding='utf-8')
    i = text.index(name + '() {')
    j = text.index('{', i)
    depth = 0
    for k in range(j, len(text)):
        if text[k] == '{':
            depth += 1
        elif text[k] == '}':
            depth -= 1
            if depth == 0:
                return text[i:k + 1]
    raise AssertionError('unbalanced braces: ' + name)


INSTALL_HELPERS = ('hy2_sha256_file', 'hy2_verify_sha256', 'hy2_manifest_sha256',
                   'hy2_dgst_sha256', 'hy2_fetch_manifest', 'hy2_expected_sha256',
                   'hy2_git_blob_sha', 'hy2_tar_listing_safe', 'hy2_tar_find_member',
                   'hy2_core_asset_arch')


@unittest.skipUnless(BASH, 'requires bash')
class InstallHelperTests(unittest.TestCase):
    def helper_prelude(self):
        return '\n'.join(extract_install_fn(n) for n in INSTALL_HELPERS) + '\n'

    def test_manifest_helpers(self):
        with tempfile.TemporaryDirectory() as td:
            m = Path(td) / 'sums'
            m.write_text('a' * 64 + '  gost_1_linux_amd64.tar.gz\n'
                         + 'b' * 64 + '  build/hysteria-linux-arm\n', encoding='utf-8')
            script = self.helper_prelude() + f'''
set -u
echo "exact=$(hy2_manifest_sha256 "{m}" gost_1_linux_amd64.tar.gz || echo FAIL)"
echo "prefix=$(hy2_manifest_sha256 "{m}" gost_1_linux_amd64 || echo FAIL)"
echo "base=$(hy2_manifest_sha256 "{m}" hysteria-linux-arm || echo FAIL)"
echo "missing=$(hy2_manifest_sha256 "{m}" nope || echo FAIL)"
echo "badpath=$(hy2_manifest_sha256 "{td}/nofile" gost_1_linux_amd64.tar.gz || echo FAIL)"
'''
            out = run_bash(script)
            self.assertIn('exact=' + 'a' * 64, out)
            self.assertIn('prefix=FAIL', out)
            self.assertIn('base=' + 'b' * 64, out)
            self.assertIn('missing=FAIL', out)
            self.assertIn('badpath=FAIL', out)

    def test_manifest_duplicate_and_malformed(self):
        with tempfile.TemporaryDirectory() as td:
            dup = Path(td) / 'dup'
            dup.write_text('a' * 64 + '  x.tar.gz\n' + 'b' * 64 + '  x.tar.gz\n', encoding='utf-8')
            bad = Path(td) / 'bad'
            bad.write_text('zzz  x.tar.gz\n', encoding='utf-8')
            script = self.helper_prelude() + f'''
echo "dup=$(hy2_manifest_sha256 "{dup}" x.tar.gz || echo FAIL)"
echo "bad=$(hy2_manifest_sha256 "{bad}" x.tar.gz || echo FAIL)"
'''
            out = run_bash(script)
            self.assertIn('dup=FAIL', out)
            self.assertIn('bad=FAIL', out)

    def test_dgst_helper(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td) / 'x.dgst'
            d.write_text('MD5= 11\nSHA1= 22\nSHA2-256= ' + 'F' * 64 + '\n', encoding='utf-8')
            only_md5 = Path(td) / 'm.dgst'
            only_md5.write_text('MD5= 11\nSHA1= 22\n', encoding='utf-8')
            script = self.helper_prelude() + f'''
echo "sha=$(hy2_dgst_sha256 "{d}" || echo FAIL)"
echo "nope=$(hy2_dgst_sha256 "{only_md5}" || echo FAIL)"
'''
            out = run_bash(script)
            self.assertIn('sha=' + 'f' * 64, out)
            self.assertIn('nope=FAIL', out)

    def test_git_blob_sha_matches_api_formula(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / 'a.txt'
            f.write_bytes(b'hello\n')
            script = self.helper_prelude() + f'hy2_git_blob_sha "{f}"\n'
            got = run_bash(script).strip().splitlines()[-1]
            expect = hashlib.sha1(b'blob 6\x00hello\n').hexdigest()
            self.assertEqual(got, expect)
            self.assertNotEqual(got, hashlib.sha1(b'hello\n').hexdigest())

    def test_tar_helpers(self):
        with tempfile.TemporaryDirectory() as td:
            good = Path(td) / 'good.tgz'
            with tarfile.open(good, 'w:gz') as tf:
                p = Path(td) / 'wireproxy'
                p.write_bytes(b'bin')
                tf.add(p, arcname='wireproxy')
            evil = Path(td) / 'evil.tgz'
            with tarfile.open(evil, 'w:gz') as tf:
                p2 = Path(td) / 'e'
                p2.write_bytes(b'x')
                info = tf.gettarinfo(str(p2), arcname='../escape')
                with open(p2, 'rb') as fh:
                    tf.addfile(info, fh)
            script = self.helper_prelude() + f'''
echo "safe=$(hy2_tar_listing_safe "{good}" && echo YES || echo NO)"
echo "evil=$(hy2_tar_listing_safe "{evil}" && echo YES || echo NO)"
echo "member=$(hy2_tar_find_member "{good}" wireproxy || echo FAIL)"
echo "nope=$(hy2_tar_find_member "{good}" gost || echo FAIL)"
'''
            out = run_bash(script)
            self.assertIn('safe=YES', out)
            self.assertIn('evil=NO', out)
            self.assertIn('member=wireproxy', out)
            self.assertIn('nope=FAIL', out)


@unittest.skipUnless(BASH, 'requires bash')
class DownloadFailureDoesNotClobberTests(unittest.TestCase):
    """下载/校验失败时，现有产物必须保持原样，临时文件被清理。"""

    def test_install_binary_rejects_bad_hash_and_keeps_existing(self):
        fn = extract_install_fn('install_binary')
        helpers = '\n'.join(extract_install_fn(n) for n in INSTALL_HELPERS)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            bindir = root / 'bin'
            bindir.mkdir()
            existing = bindir / 'hysteria'
            existing.write_bytes(b'OLD-BINARY')
            stub = f'''set -eo pipefail
HY2_ARCH=amd64
HY2_BIN="{existing}"
log_info() {{ :; }}; log_warn() {{ :; }}; log_err() {{ echo "ERR: $*"; }}; log_step() {{ :; }}
{helpers}
# curl 桩：API 返回 tag；hashes.txt 返回一个与内容不符的摘要；二进制写入假内容。
curl() {{
  local url='' dest='' out=''
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -o) dest="$2"; shift 2;;
      --max-time|--connect-timeout|--retry|--retry-delay) shift 2;;
      -fL|--progress-bar|-fsSL|-fsSIL|-s|-sS|-I) shift;;
      -H) shift 2;;
      http*) url="$1"; shift;;
      *) shift;;
    esac
  done
  case "$url" in
    *api.github.com*releases/latest*) printf '{{"tag_name":"app/v9.9.9"}}'; return 0;;
    *hashes.txt*) printf '%s  hysteria-linux-amd64\\n' "$(printf '0%.0s' {{1..64}})" > "$dest"; return 0;;
    *hysteria-linux-amd64*) printf 'EVIL' > "$dest"; return 0;;
  esac
  return 1
}}
''' + fn + '''
install_binary
'''
            out = run_bash(stub)
            self.assertIn('校验失败', out, out)
            self.assertEqual(existing.read_bytes(), b'OLD-BINARY', '校验失败时不得覆盖现有二进制')
            leftovers = [p.name for p in bindir.iterdir() if p.name != 'hysteria']
            self.assertEqual(leftovers, [], '失败后不应残留临时文件: %r' % leftovers)

    def test_install_binary_rejects_missing_manifest(self):
        fn = extract_install_fn('install_binary')
        helpers = '\n'.join(extract_install_fn(n) for n in INSTALL_HELPERS)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            existing = root / 'hysteria'
            existing.write_bytes(b'OLD')
            stub = f'''set -eo pipefail
HY2_ARCH=amd64
HY2_BIN="{existing}"
log_info() {{ :; }}; log_warn() {{ :; }}; log_err() {{ echo "ERR: $*"; }}; log_step() {{ :; }}
{helpers}
curl() {{
  local url='' dest=''
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -o) dest="$2"; shift 2;;
      --max-time|--connect-timeout|--retry|--retry-delay) shift 2;;
      -fL|--progress-bar|-fsSL|-fsSIL|-s|-sS|-I) shift;;
      -H) shift 2;;
      http*) url="$1"; shift;;
      *) shift;;
    esac
  done
  case "$url" in
    *api.github.com*releases/latest*) printf '{{"tag_name":"app/v9.9.9"}}'; return 0;;
  esac
  return 22
}}
''' + fn + '''
install_binary
'''
            out = run_bash(stub)
            self.assertIn('校验清单', out, out)
            self.assertEqual(existing.read_bytes(), b'OLD')
            self.assertFalse((root / 'hysteria.new').exists())

    def test_install_binary_happy_path(self):
        fn = extract_install_fn('install_binary')
        helpers = '\n'.join(extract_install_fn(n) for n in INSTALL_HELPERS)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            existing = root / 'hysteria'
            existing.write_bytes(b'OLD')
            payload = b'#!/bin/sh\necho "Version: v9.9.9"\n'
            digest = hashlib.sha256(payload).hexdigest()
            payload_b64 = base64.b64encode(payload).decode()
            stub = f'''set -eo pipefail
PAYLOAD_B64='{payload_b64}'
HY2_ARCH=armv7
HY2_BIN="{existing}"
log_info() {{ :; }}; log_warn() {{ :; }}; log_err() {{ echo "ERR: $*"; }}; log_step() {{ :; }}
{helpers}
curl() {{
  local url='' dest=''
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -o) dest="$2"; shift 2;;
      --max-time|--connect-timeout|--retry|--retry-delay) shift 2;;
      -fL|--progress-bar|-fsSL|-fsSIL|-s|-sS|-I) shift;;
      -H) shift 2;;
      http*) url="$1"; shift;;
      *) shift;;
    esac
  done
  case "$url" in
    *api.github.com*releases/latest*) printf '{{"tag_name":"app/v9.9.9"}}'; return 0;;
    *hashes.txt*) printf '{digest}  build/hysteria-linux-arm\\n' > "$dest"; return 0;;
    *hysteria-linux-arm) printf '%s' "$PAYLOAD_B64" | base64 -d > "$dest"; return 0;;
  esac
  return 1
}}
''' + fn + '''
install_binary
'''
            out = run_bash(stub)
            self.assertNotIn('ERR:', out, out)
            self.assertTrue(existing.read_bytes().startswith(b'#!/bin/sh'))
            self.assertEqual(existing.read_bytes(), payload)


@unittest.skipUnless(BASH, 'requires bash')
class AwgctlFetchTests(unittest.TestCase):
    """awgctl.sh 获取：必须 pin commit + 比对 git blob 身份。"""

    def prelude(self):
        helpers = '\n'.join(extract_install_fn(n) for n in ('hy2_git_blob_sha',))
        return helpers + '\nAWG_REPO="owner/repo"\nlog_err() { echo "ERR: $*"; }\nlog_warn() { echo "WARN: $*"; }\n'

    def test_rejects_content_not_matching_blob(self):
        fn = extract_install_fn('awg_fetch_ctl')
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / 'awgctl.sh'
            script = self.prelude() + fn + f'''
curl() {{
  local url='' dest=''
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -o) dest="$2"; shift 2;;
      --max-time) shift 2;;
      -H) shift 2;;
      http*) url="$1"; shift;;
      *) shift;;
    esac
  done
  case "$url" in
    */commits/main) printf '{{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}'; return 0;;
    */contents/awgctl.sh\\?ref=*) printf '{{"sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}'; return 0;;
    *) printf '#!/bin/bash\\n# hy2-awgctl evil\\n' > "$dest"; return 0;;
  esac
}}
awg_fetch_ctl "{out}"
'''
            result = run_bash(script)
            self.assertIn('ERR:', result, result)
            self.assertFalse(out.exists(), 'blob 身份不符时不得写出 awgctl.sh')

    def test_accepts_matching_blob_and_uses_pinned_ref(self):
        fn = extract_install_fn('awg_fetch_ctl')
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / 'awgctl.sh'
            content = '#!/bin/bash\n# hy2-awgctl good\n'
            blob = hashlib.sha1(b'blob ' + str(len(content.encode())).encode() + b'\x00'
                                + content.encode()).hexdigest()
            script = self.prelude() + fn + f'''
URLS=""
curl() {{
  local url='' dest=''
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -o) dest="$2"; shift 2;;
      --max-time) shift 2;;
      -H) shift 2;;
      http*) url="$1"; shift;;
      *) shift;;
    esac
  done
  URLS="$URLS $url"
  if [[ -n "$dest" ]]; then printf '%s' "{content}" > "$dest"; return 0; fi
  case "$url" in
    */commits/main) printf '{{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}'; return 0;;
    */contents/awgctl.sh*) printf '{{"sha":"{blob}"}}'; return 0;;
  esac
  return 1
}}
awg_fetch_ctl "{out}" || {{ echo FAILED; exit 1; }}
echo "URLS:$URLS"
'''
            result = run_bash(script)
            self.assertNotIn('FAILED', result, result)
            self.assertTrue(out.exists())
            self.assertEqual(out.read_text(encoding='utf-8'), content)
            urls = result.split('URLS:', 1)[1]
            self.assertIn('a' * 40, urls)
            # 不允许出现浮动 main 的引用
            self.assertNotIn('@main', urls)
            self.assertNotRegex(urls, r'ref=main\b')
            self.assertNotIn('/main/awgctl.sh', urls)

    def test_unresolvable_ref_aborts(self):
        fn = extract_install_fn('awg_fetch_ctl')
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / 'awgctl.sh'
            script = self.prelude() + fn + f'''
curl() {{
  local url='' dest=''
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -o) dest="$2"; shift 2;;
      --max-time) shift 2;;
      -H) shift 2;;
      http*) url="$1"; shift;;
      *) shift;;
    esac
  done
  printf '{{}}'
  return 0
}}
awg_fetch_ctl "{out}" && echo UNEXPECTED-OK || echo REJECTED
'''
            result = run_bash(script)
            self.assertIn('REJECTED', result, result)
            self.assertNotIn('UNEXPECTED-OK', result)
            self.assertFalse(out.exists())


@unittest.skipUnless(BASH, 'requires bash')
class AwgSumsTests(unittest.TestCase):
    """AWG 清单缺失必须硬失败；重名/畸形也要拒绝。"""

    def prelude(self):
        return ('AWG_REPO="owner/repo"\nAWG_RELEASE_TAG="awg-binaries"\n'
                'AWG_DIR="$(mktemp -d)"\nAWG_GO_BIN="$AWG_DIR/amneziawg-go"\n'
                'AWG_BIN="$AWG_DIR/awg"\nAWG_QUICK_BIN="$AWG_DIR/awg-quick"\n'
                'log_info() { :; }; log_warn() { echo "WARN: $*"; }; log_err() { echo "ERR: $*"; }; log_step() { :; }\n')

    def run_download(self, td, curl_body):
        fn = extract_install_fn_awg('download_binaries')
        script = self.prelude() + f'curl() {{ {curl_body} }}\n' + fn + '\ndownload_binaries 3 amd64\n'
        return run_bash(script, cwd=td)

    def test_missing_sums_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            body = '''
  local url='' dest=''
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -o) dest="$2"; shift 2;;
      --connect-timeout|--retry|--retry-delay) shift 2;;
      -fL|-fsSL) shift;;
      http*) url="$1"; shift;;
      *) shift;;
    esac
  done
  case "$url" in
    *SHA256SUMS) return 22;;
    *awg3.tar.gz) printf 'x' > "$dest"; return 0;;
  esac
  return 22
'''
            out = self.run_download(td, body)
            self.assertIn('未取到', out, out)
            self.assertIn('ERR:', out, out)

    def test_missing_sums_not_bypassable_via_env(self):
        """缺 SHA256SUMS 必须硬失败：任何环境变量都不得把它变成"跳过校验"。"""
        with tempfile.TemporaryDirectory() as td:
            body = '''
  local url='' dest=''
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -o) dest="$2"; shift 2;;
      --connect-timeout|--retry|--retry-delay) shift 2;;
      -fL|-fsSL) shift;;
      http*) url="$1"; shift;;
      *) shift;;
    esac
  done
  case "$url" in
    *SHA256SUMS) return 22;;
    *awg3.tar.gz) printf 'x' > "$dest"; return 0;;
  esac
  return 22
'''
            fn = extract_install_fn_awg('download_binaries')
            script = self.prelude() + f'curl() {{ {body} }}\n' + \
                     'ALLOW_MISSING_SUMS=yes\n' + fn + \
                     '\ndownload_binaries 3 amd64 || echo "RC=$?"\n'
            out = run_bash(script, cwd=td)
            self.assertIn('RC=', out, out)
            self.assertNotIn('WARN:', out, out)
            self.assertIn('ERR:', out, out)

    def test_bad_hash_fails(self):
        with tempfile.TemporaryDirectory() as td:
            body = '''
  local url='' dest=''
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -o) dest="$2"; shift 2;;
      --connect-timeout|--retry|--retry-delay) shift 2;;
      -fL|-fsSL) shift;;
      http*) url="$1"; shift;;
      *) shift;;
    esac
  done
  case "$url" in
    *SHA256SUMS) printf '%064d  amneziawg-linux-amd64-awg3.tar.gz\\n' 0 > "$dest"; return 0;;
    *awg3.tar.gz) printf 'x' > "$dest"; return 0;;
  esac
  return 22
'''
            out = self.run_download(td, body)
            self.assertIn('校验失败', out, out)


def extract_install_fn_awg(name):
    text = AWGCTL.read_text(encoding='utf-8')
    i = text.index(name + '() {')
    j = text.index('{', i)
    depth = 0
    for k in range(j, len(text)):
        if text[k] == '{':
            depth += 1
        elif text[k] == '}':
            depth -= 1
            if depth == 0:
                return text[i:k + 1]
    raise AssertionError('unbalanced braces: ' + name)


@unittest.skipUnless(BASH, 'requires bash')
class PortalFetchBlobTests(unittest.TestCase):
    """install.sh 的门户取文件必须比对 blob 身份。"""

    def test_blob_verify_helper(self):
        helpers = '\n'.join(extract_install_fn(n) for n in ('hy2_git_blob_sha', 'portal_verify_blobs'))
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            (d / 'portal.py').write_bytes(b'portal')
            (d / 'portal_assets.py').write_bytes(b'assets')
            b1 = hashlib.sha1(b'blob 6\x00portal').hexdigest()
            b2 = hashlib.sha1(b'blob 6\x00assets').hexdigest()
            good = f'portal.py {b1}\nportal_assets.py {b2}'
            bad = f'portal.py {b2}\nportal_assets.py {b2}'
            script = f'PORTAL_FILES="portal.py portal_assets.py"\nMETER_FILES=""\n' + helpers + f'''
echo "good=$(portal_verify_blobs "{d}" $'{good}' && echo YES || echo NO)"
echo "bad=$(portal_verify_blobs "{d}" $'{bad}' && echo YES || echo NO)"
echo "empty=$(portal_verify_blobs "{d}" "" && echo YES || echo NO)"
'''
            out = run_bash(script)
            self.assertIn('good=YES', out, out)
            self.assertIn('bad=NO', out, out)
            self.assertIn('empty=NO', out, out)

    def test_portal_fetch_py_rejects_content_not_matching_blob(self):
        """端到端反例：取回内容含 marker 且语法合法，但与所 pin commit 的
        blob 身份不符 → 必须整体失败，不得写出半成品。

        这条用**真实的** portal_verify_blobs（不 stub），因为
        tests/test_meter_bundle_guard.py 里的桩把 blob 校验替换成了恒真，
        只靠那个桩无法证明校验真的生效。
        """
        fns = ('hy2_git_blob_sha', 'portal_remote_blob_shas', 'portal_verify_blobs',
               'portal_files_ok', 'portal_fetch_files', 'portal_fetch_py')
        helpers = '\n'.join(extract_install_fn(n) for n in fns)
        body = 'def page_html():\n    return "ok"\n'
        assets = 'SCRIPT = r"""x"""\n'
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            # 真实内容与 listing 里声明的 sha 故意不一致
            (root / 'portal.py').write_text(body, encoding='utf-8')
            (root / 'portal_assets.py').write_text(assets, encoding='utf-8')
            # portal_files_ok 会硬性检查四个计量模块；这里给足，让唯一的失败点
            # 落在 blob 身份比对上（否则测到的是"缺文件"而不是"内容不符"）。
            meters = ('usage-meter-core-20261007-v1.py',
                      'usage-meter-readers-20261007-v1.py',
                      'usage-meter-runtime-20261007-v1.py',
                      'usage-meter-xray-config-20261007-v1.py')
            for m in meters:
                (root / m).write_text(
                    'ACCOUNTING_REVISION = "2026-10-12-real-usage-v2"\n'
                    'def read_hysteria():\n    pass\n'
                    'def add_stats():\n    pass\n', encoding='utf-8')
            meter_list = ' '.join(meters)
            listing = '[' + ','.join('{"name":"%s","sha":"%s"}' % (n, 'b' * 40)
                                    for n in ('portal.py', 'portal_assets.py') + meters) + ']'
            out_dir = root / 'out'
            out_dir.mkdir()
            script = f'''
PORTAL_FILES="portal.py portal_assets.py"
METER_FILES="{meter_list}"
AWG_REPO="owner/repo"
log_err() {{ echo "ERR: $*"; }}; log_info() {{ :; }}; log_warn() {{ :; }}
{helpers}
PORTAL_FETCH_REF=""
curl() {{
  local url='' dest=''
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -o) dest="$2"; shift 2;;
      --max-time|--connect-timeout|--retry|--retry-delay) shift 2;;
      -H) shift 2;;
      -fL|--progress-bar|-fsSL|-s|-sS|-I) shift;;
      http*) url="$1"; shift;;
      *) shift;;
    esac
  done
  case "$url" in
    */commits/main) printf '{{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}'; return 0;;
    */contents/\\?ref=*)
        printf '%s' '{listing}' > "$dest"; return 0;;
    *) cp "{root}/$(basename "${{url%%\\?*}}")" "$dest" 2>/dev/null || return 22; return 0;;
  esac
}}
if portal_fetch_py "{out_dir}"; then echo "RESULT=OK"; else echo "RESULT=FAIL"; fi
echo "VERIFY=$PORTAL_FETCH_ALL_VERIFY_FAILED"
echo "WHY=[$PORTAL_FETCH_ERR]"
'''
            out = run_bash(script)
            self.assertIn('RESULT=FAIL', out, out)
            self.assertIn('VERIFY=1', out, out)
            # 逐源原因在 PORTAL_FETCH_ERR 里（由脚本打印成 WHY=[...]），不在 stdout 常规输出
            self.assertIn('文件身份不符', out, out)
            # portal_fetch_py 的契约是"往给定目录写、失败返回 1"；
            # 不落地半成品由调用方 portal_ensure_py 用 mktemp -d + rm -rf 保证
            # （tests/portal-py-fetch-smoke.sh 第 1 项覆盖这一点）。
            self.assertFalse((out_dir / 'portal.py').read_bytes() == b'',
                             '失败时不应写出空文件')



class EmbeddedCopySyncTests(unittest.TestCase):
    """嵌入副本：portal.py 里的 WARP 安装脚本必须与 install.sh 同一套校验。"""

    def warp_body(self):
        src = PORTAL.read_text(encoding='utf-8')
        m = re.search(r"install_warp_sh = r?'''", src)
        self.assertIsNotNone(m, 'portal.py 里找不到内嵌的 WARP 安装脚本')
        start = m.end()
        j = src.index("\n'''", start)
        return src[start:j]

    def test_embedded_warp_verifies_checksums(self):
        body = self.warp_body()
        for needle in ('checksums.txt', 'manifest_sha256', 'verify_sha', 'wireproxy_linux_${WP_A}',
                       'tar_member wireproxy'):
            self.assertIn(needle, body, '内嵌 WARP 脚本缺少 %s' % needle)
        # 不允许再出现"取第一个可执行文件"的兜底
        self.assertNotIn('find "$TMP_EX" -type f -executable', body)
        self.assertNotIn('SRC=$(find', body)

    def test_embedded_warp_has_no_empty_tag_url(self):
        body = self.warp_body()
        # 旧回退拼出 .../download//wireproxy_...（404）：URL 里不能出现 download//
        self.assertNotIn('download//', body)
        self.assertNotIn('download/${TAG}//', body)
        self.assertIn('case "$TAG" in ""|null) TAG="v1.1.3" ;; esac', body)

    def test_install_sh_wireproxy_fallback_uses_tag(self):
        src = INSTALL.read_text(encoding='utf-8')
        self.assertNotIn('download/${WP_TAG}/wireproxy_linux', src.replace('releases/download/${WP_TAG}/wireproxy_linux', 'OK'))
        self.assertIn('if [[ -z "$WP_TAG" || "$WP_TAG" == "null" ]]; then\n            WP_TAG="v1.1.3"', src)

    def test_install_sh_and_portal_share_arch_mapping(self):
        inst = INSTALL.read_text(encoding='utf-8')
        port = PORTAL.read_text(encoding='utf-8')
        # 两处都必须把 wireproxy 的 armv7 映射成 arm
        self.assertIn('armv7)  WGCF_ARCH="armv7";  WP_ARCH="arm"', inst)
        self.assertIn('armv7l|armv7)   WG_A="armv7"; WP_A="arm"', port)


@unittest.skipUnless(BASH, 'requires bash')
class AcmeInstallTests(unittest.TestCase):
    """acme.sh 获取链：pin commit + 官方 tree blob 身份 + 先验后装。

    全部离线：curl 是桩，jq 用真实二进制（解析官方 JSON 格式）。
    """

    ACME_HELPERS = ('hy2_git_blob_sha', 'hy2_acme_path_safe', 'hy2_acme_pin_commit',
                    'hy2_acme_tree_json', 'hy2_acme_blob_for_path',
                    'hy2_acme_fetch_verified', 'hy2_acme_disable_auto_upgrade',
                    'hy2_acme_shebang_safe', 'hy2_acme_same_except_shebang',
                    'hy2_acme_verify_existing', 'hy2_acme_check_existing',
                    'hy2_acme_install_verified', 'hy2_acme_record_pin',
                    'hy2_acme_read_pin')

    # 假的上游安装器：把自身（改掉 shebang）装到 --home，并写一份带
    # AUTO_UPGRADE="1" 的 account.conf —— 与上游 install() 的关键行为一致。
    MOCK_INSTALLER = """#!/usr/bin/env sh
# mock acme.sh installer
if [ "$1" = "--install" ]; then
  shift
  home=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --home) home="$2"; shift ;;
    esac
    shift
  done
  [ -n "$home" ] || exit 3
  mkdir -p "$home" || exit 4
  sed '1s|.*|#!/bin/bash|' "$0" > "$home/acme.sh" || exit 5
  chmod +x "$home/acme.sh"
  mkdir -p "$home/dnsapi" || exit 6
  for f in dnsapi/*.sh; do cp "$f" "$home/dnsapi/" || exit 7; done
  printf 'AUTO_UPGRADE="1"\\n' > "$home/account.conf"
  [ -n "$MOCK_INSTALL_MARK" ] && printf 'ran\\n' > "$MOCK_INSTALL_MARK"
  exit 0
fi
exit 0
"""

    def prelude(self):
        src = INSTALL.read_text(encoding='utf-8')
        repo = re.search(r'^HY2_ACME_REPO="([^"]+)"', src, re.M).group(1)
        files = re.search(r'^HY2_ACME_FILES="([^"]+)"', src, re.M).group(1)
        pin = re.search(r'^HY2_ACME_PIN_NAME="([^"]+)"', src, re.M).group(1)
        helpers = '\n'.join(extract_install_fn(n) for n in self.ACME_HELPERS)
        return (f'HY2_ACME_REPO="{repo}"\nHY2_ACME_FILES="{files}"\nHY2_ACME_PIN_NAME="{pin}"\n'
                'log_info() { echo "INF: $*"; }; log_warn() { echo "WRN: $*"; }\n'
                'log_err() { echo "ERR: $*"; }; log_step() { :; }\n' + helpers + '\n')

    @staticmethod
    def blob(data):
        return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\x00' + data).hexdigest()

    def make_tree(self, entries):
        return json.dumps({'sha': 'a' * 40, 'truncated': False, 'tree': [
            {'path': p, 'mode': m, 'type': t, 'sha': s} for (p, m, t, s) in entries]})

    def run_install(self, td, files_map, tree_json, commit_json=None,
                    fetch_fail=None, home=None, call='install', existing_files=None):
        """files_map: path -> bytes；fetch_fail: 返回 1 的路径集合。

        existing_files: call='existing' 时，预先写进 home 的已有安装内容。
        """
        root = Path(td)
        home = Path(home) if home else root / 'home'
        if existing_files:
            for p, data in existing_files.items():
                fp = home / p
                fp.parent.mkdir(parents=True, exist_ok=True)
                fp.write_bytes(data)
                fp.chmod(0o755)
        mark = root / 'install-ran'
        work_tmp = root / 'tmpwork'
        work_tmp.mkdir(exist_ok=True)
        commit = 'a' * 40
        commit_json = commit_json if commit_json is not None else json.dumps({'sha': commit})
        # 把桩内容写进文件，由 curl 桩读出来（避免 heredoc 转义地狱）
        mapping = {}
        for i, (p, data) in enumerate(files_map.items()):
            (root / f'blob{i}').write_bytes(data)
            mapping[p] = f'blob{i}'
        mapping_src = '\n'.join(f'MAP["{p}"]="{v}"' for p, v in mapping.items())
        fail_src = ' '.join(sorted(fetch_fail or []))
        (root / 'tree.json').write_text(tree_json, encoding='utf-8')
        (root / 'commit.json').write_text(commit_json, encoding='utf-8')

        script = self.prelude() + f'''
export TMPDIR="{work_tmp}"
declare -A MAP
MAP=()
{mapping_src}
FETCH_FAIL="{fail_src}"
ROOT="{root}"
COMMIT="{commit}"
export MOCK_INSTALL_MARK="{mark}"
curl() {{
  local url='' dest=''
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -o) dest="$2"; shift 2;;
      --connect-timeout|--max-time|--retry|--retry-delay) shift 2;;
      -H) shift 2;;
      http*) url="$1"; shift;;
      *) shift;;
    esac
  done
  printf '%s\n' "$url" >> "$ROOT/urls.log"
  case "$url" in
    *api.github.com*commits/master*)
        if [[ -n "$dest" ]]; then cat "$ROOT/commit.json" > "$dest"; else cat "$ROOT/commit.json"; fi
        return 0;;
    *api.github.com*git/trees/*)
        if [[ -n "$dest" ]]; then cat "$ROOT/tree.json" > "$dest"; else cat "$ROOT/tree.json"; fi
        return 0;;
    *raw.githubusercontent.com*)
        local p="${{url#*raw.githubusercontent.com/*/*/*/}}"
        for f in $FETCH_FAIL; do [[ "$p" == "$f" ]] && return 22; done
        [[ -n "${{MAP[$p]:-}}" ]] || return 22
        cp "$ROOT/${{MAP[$p]}}" "$dest"; return 0;;
  esac
  return 22
}}
if [[ "{call}" == "existing" ]]; then
  hy2_acme_check_existing "{home}"
else
  hy2_acme_install_verified "{home}"
fi
'''
        out = run_bash(script)
        return out, home, mark, work_tmp

    def ok_files(self):
        main = self.MOCK_INSTALLER.encode()
        return {
            'acme.sh': main,
            'dnsapi/dns_cf.sh': b'# dns_cf\n',
            'dnsapi/dns_ali.sh': b'# dns_ali\n',
            'dnsapi/dns_dp.sh': b'# dns_dp\n',
        }

    def ok_tree(self, files):
        return self.make_tree([(p, '100755' if p == 'acme.sh' else '100644', 'blob',
                                self.blob(d)) for p, d in files.items()])

    def test_happy_path_installs_and_disables_auto_upgrade(self):
        with tempfile.TemporaryDirectory() as td:
            files = self.ok_files()
            out, home, mark, work_tmp = self.run_install(td, files, self.ok_tree(files))
            self.assertIn('INF:', out, out)
            self.assertNotIn('ERR:', out, out)
            self.assertTrue((home / 'acme.sh').exists(), out)
            self.assertTrue(mark.exists(), '验证通过后必须执行安装器')
            conf = (home / 'account.conf').read_text(encoding='utf-8')
            self.assertIn("AUTO_UPGRADE='0'", conf)
            # 续期计划不能被误删：安装器产生的 cron 配置不在本项目职责内，
            # 这里确认只改 AUTO_UPGRADE，未清空其它内容
            self.assertIn('AUTO_UPGRADE', conf)
            # 临时目录必须清理干净
            self.assertEqual(list(work_tmp.iterdir()), [], '成功路径不得残留临时工作目录')

    def test_metadata_fetch_failure_aborts_before_install(self):
        with tempfile.TemporaryDirectory() as td:
            files = self.ok_files()
            out, home, mark, work_tmp = self.run_install(td, files, self.ok_tree(files),
                                               commit_json='{}')
            self.assertIn('ERR:', out, out)
            self.assertIn('commit', out, out)
            self.assertFalse(mark.exists(), '元数据失败时绝不能执行安装器')
            self.assertFalse((home / 'acme.sh').exists())

    def test_content_mismatch_aborts_before_install(self):
        with tempfile.TemporaryDirectory() as td:
            files = self.ok_files()
            tree = self.ok_tree(files)
            # 官方 tree 声明的是另一份内容 -> 下载内容与预期 blob 不符
            tree = tree.replace(self.blob(files['dnsapi/dns_cf.sh']), 'b' * 40)
            out, home, mark, work_tmp = self.run_install(td, files, tree)
            self.assertIn('ERR:', out, out)
            self.assertIn('blob', out, out)
            self.assertFalse(mark.exists(), '内容不符时绝不能执行安装器')
            self.assertFalse((home / 'acme.sh').exists())

    def test_symlink_or_missing_member_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            files = self.ok_files()
            entries = [(p, '100755' if p == 'acme.sh' else '100644', 'blob',
                        self.blob(d)) for p, d in files.items()]
            # 把 dnsapi/dns_cf.sh 改成符号链接（mode 120000）
            entries = [(p, '120000' if p == 'dnsapi/dns_cf.sh' else m, t, s)
                       for (p, m, t, s) in entries]
            out, home, mark, work_tmp = self.run_install(td, files, self.make_tree(entries))
            self.assertIn('ERR:', out, out)
            self.assertFalse(mark.exists())
            self.assertFalse((home / 'acme.sh').exists())

    def test_missing_member_or_fetch_failure_aborts(self):
        with tempfile.TemporaryDirectory() as td:
            files = self.ok_files()
            # 官方 tree 里缺 dnsapi/dns_dp.sh
            tree = self.make_tree([(p, '100755' if p == 'acme.sh' else '100644', 'blob',
                                    self.blob(d)) for p, d in files.items()
                                   if p != 'dnsapi/dns_dp.sh'])
            out, home, mark, _ = self.run_install(td, files, tree)
            self.assertIn('ERR:', out, out)
            self.assertIn('dnsapi/dns_dp.sh', out)
            self.assertFalse(mark.exists())
            self.assertFalse((home / 'acme.sh').exists())

        with tempfile.TemporaryDirectory() as td:
            files = self.ok_files()
            out, home, mark, _ = self.run_install(td, files, self.ok_tree(files),
                                                 fetch_fail={'dnsapi/dns_ali.sh'})
            self.assertIn('ERR:', out, out)
            self.assertIn('dnsapi/dns_ali.sh', out)
            self.assertFalse(mark.exists(), '任一插件取不到时绝不能安装')
            self.assertFalse((home / 'acme.sh').exists())

    def test_truncated_tree_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            files = self.ok_files()
            tree = json.loads(self.ok_tree(files))
            tree['truncated'] = True
            out, home, mark, _ = self.run_install(td, files, json.dumps(tree))
            self.assertIn('ERR:', out, out)
            self.assertIn('文件树', out)
            self.assertFalse(mark.exists())
            self.assertFalse((home / 'acme.sh').exists())

    def test_path_safety_helper(self):
        script = self.prelude() + '''
for p in acme.sh dnsapi/dns_cf.sh ../evil /etc/passwd a/../../b ./acme.sh 'a//b' '-rf'; do
  if hy2_acme_path_safe "$p"; then echo "SAFE:$p"; else echo "BAD:$p"; fi
done
'''
        out = run_bash(script)
        self.assertIn('SAFE:acme.sh', out)
        self.assertIn('SAFE:dnsapi/dns_cf.sh', out)
        for bad in ('../evil', '/etc/passwd', 'a/../../b', './acme.sh', 'a//b', '-rf'):
            self.assertIn('BAD:' + bad, out)

    def test_install_failure_cleans_new_home_and_keeps_existing(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            files = self.ok_files()
            # 安装器返回非 0
            bad = self.MOCK_INSTALLER.replace('exit 0\nfi', 'exit 7\nfi').encode()
            files['acme.sh'] = bad
            out, home, mark, work_tmp = self.run_install(td, files, self.ok_tree(files))
            self.assertIn('ERR:', out, out)
            self.assertFalse((home / 'acme.sh').exists(), '安装失败后不得留下半成品')

            # 已有 home 时，安装失败不得删除原有数据
            existing = root / 'existing'
            existing.mkdir()
            (existing / 'keep.txt').write_text('keep', encoding='utf-8')
            out2, home2, _, _ = self.run_install(td, files, self.ok_tree(files), home=existing)
            self.assertIn('ERR:', out2, out2)
            self.assertTrue((existing / 'keep.txt').exists(), '失败时原有数据必须保持')

    def test_existing_install_verified_is_kept_and_not_overwritten(self):
        """已有安装且身份与官方一致：不重装、不覆盖，仅关自动升级。"""
        with tempfile.TemporaryDirectory() as td:
            files = self.ok_files()
            # 上游安装器落地的形态：首行 shebang 被改写，其余与官方一致
            installed = {'acme.sh': self.MOCK_INSTALLER.replace(
                '#!/usr/bin/env sh', '#!/bin/bash', 1).encode(),
                'dnsapi/dns_cf.sh': files['dnsapi/dns_cf.sh'],
                'dnsapi/dns_ali.sh': files['dnsapi/dns_ali.sh'],
                'dnsapi/dns_dp.sh': files['dnsapi/dns_dp.sh']}
            home = Path(td) / 'home'
            home.mkdir()
            (home / 'account.conf').write_text('#AUTO_UPGRADE="1"\nCF_Token="x"\n', encoding='utf-8')
            (home / 'hy2.test.com_ecc').mkdir()
            (home / 'hy2.test.com_ecc' / 'fullchain.cer').write_text('CERT', encoding='utf-8')
            out, _, mark, _ = self.run_install(td, files, self.ok_tree(files), home=home,
                                              call='existing', existing_files=installed)
            self.assertNotIn('ERR:', out, out)
            self.assertIn('来源可确认', out, out)
            for p, data in installed.items():
                self.assertEqual((home / p).read_bytes(), data, f'已有 {p} 不得被改写')
            self.assertFalse(mark.exists(), '已有安装时不得执行安装器')
            conf = (home / 'account.conf').read_text(encoding='utf-8')
            self.assertIn("AUTO_UPGRADE='0'", conf)
            self.assertIn('CF_Token="x"', conf, '只改 AUTO_UPGRADE，其它配置必须保留')
            self.assertEqual((home / 'hy2.test.com_ecc' / 'fullchain.cer').read_text(encoding='utf-8'),
                             'CERT', '已有证书不得被动')

            # 安装器本身也必须拒绝覆盖已有文件（双重保险）
            out2, _, mark2, _ = self.run_install(td, files, self.ok_tree(files), home=home,
                                                existing_files=installed)
            self.assertIn('ERR:', out2, out2)
            self.assertIn('拒绝覆盖', out2)
            self.assertFalse(mark2.exists())
            self.assertEqual((home / 'acme.sh').read_bytes(), installed['acme.sh'])

    def _existing_case(self, td, mutate_main=None, mutate_plugin=None, commit_json=None,
                       fetch_fail=None, pin=None):
        """构造"已有安装 + 官方元数据"的完整场景，返回 (out, home, files)。

        pin: 预先写进 home/.hy2-pinned-commit 的内容（None = 旧安装，无记录）。
        """
        files = self.ok_files()
        installed = {'acme.sh': self.MOCK_INSTALLER.replace(
            '#!/usr/bin/env sh', '#!/bin/bash', 1).encode(),
            'dnsapi/dns_cf.sh': files['dnsapi/dns_cf.sh'],
            'dnsapi/dns_ali.sh': files['dnsapi/dns_ali.sh'],
            'dnsapi/dns_dp.sh': files['dnsapi/dns_dp.sh']}
        if mutate_main is not None:
            installed['acme.sh'] = mutate_main
        if mutate_plugin is not None:
            installed['dnsapi/dns_cf.sh'] = mutate_plugin
        home = Path(td) / 'home'
        home.mkdir()
        (home / 'account.conf').write_text('AUTO_UPGRADE="1"\nCF_Token="x"\n', encoding='utf-8')
        (home / 'hy2.test.com_ecc').mkdir()
        (home / 'hy2.test.com_ecc' / 'fullchain.cer').write_text('CERT', encoding='utf-8')
        (home / 'hy2.test.com_ecc' / 'hy2.test.com.key').write_text('KEY', encoding='utf-8')
        if pin is not None:
            (home / '.hy2-pinned-commit').write_text(pin, encoding='utf-8')
        out, _, mark, _ = self.run_install(td, files, self.ok_tree(files),
                                          commit_json=commit_json, fetch_fail=fetch_fail,
                                          home=home, call='existing', existing_files=installed)
        return out, home, installed

    def _assert_blocked_and_untouched(self, out, home, installed):
        self.assertIn('ERR:', out, out)
        self.assertIn('已阻止', out, out)
        # 不写配置、不调用禁升级命令
        self.assertEqual((home / 'account.conf').read_text(encoding='utf-8'),
                         'AUTO_UPGRADE="1"\nCF_Token="x"\n', '核验失败时不得写其配置')
        self.assertFalse((home / 'account.conf.hy2-bak').exists(),
                         '核验失败时不得改动/备份其配置')
        self.assertFalse((home / '.hy2-pinned-commit').exists(), '核验失败时不得写固定 commit 记录')
        # 不执行、不删除、不覆盖任何已有文件
        for p, data in installed.items():
            self.assertEqual((home / p).read_bytes(), data, f'核验失败时 {p} 必须原样保留')
        self.assertEqual((home / 'hy2.test.com_ecc' / 'fullchain.cer').read_text(encoding='utf-8'), 'CERT')
        self.assertEqual((home / 'hy2.test.com_ecc' / 'hy2.test.com.key').read_text(encoding='utf-8'), 'KEY')

    def test_existing_main_mismatch_blocks_before_any_execution(self):
        """已有主脚本内容与官方不符：硬失败，且零执行（即使它本身会写标记）。"""
        with tempfile.TemporaryDirectory() as td:
            evil = b'#!/bin/bash\necho EXECUTED > "$(dirname "$0")/EXECUTED"\n# tampered\n'
            out, home, installed = self._existing_case(td, mutate_main=evil)
            self._assert_blocked_and_untouched(out, home, installed)
            self.assertFalse((home / 'EXECUTED').exists(), '核验失败时绝不能执行已有脚本')

    def test_existing_dns_plugin_mismatch_blocks(self):
        """DNS 插件与官方不符：同样硬失败（校验范围 == 执行范围）。"""
        with tempfile.TemporaryDirectory() as td:
            out, home, installed = self._existing_case(
                td, mutate_plugin=b'# dns_cf TAMPERED\n')
            self._assert_blocked_and_untouched(out, home, installed)
            self.assertIn('dnsapi/dns_cf.sh', out)

    def test_existing_missing_plugin_blocks(self):
        """已有安装缺某个会被 source 的插件：无法确认将执行的内容 → 阻止。"""
        with tempfile.TemporaryDirectory() as td:
            files = self.ok_files()
            installed = {'acme.sh': self.MOCK_INSTALLER.replace(
                '#!/usr/bin/env sh', '#!/bin/bash', 1).encode(),
                'dnsapi/dns_cf.sh': files['dnsapi/dns_cf.sh']}
            home = Path(td) / 'home'
            for p, data in installed.items():
                fp = home / p
                fp.parent.mkdir(parents=True, exist_ok=True)
                fp.write_bytes(data)
            (home / 'account.conf').write_text('AUTO_UPGRADE="1"\n', encoding='utf-8')
            out, _, _, _ = self.run_install(td, files, self.ok_tree(files), home=home,
                                           call='existing', existing_files=installed)
            self.assertIn('ERR:', out, out)
            self.assertIn('缺少', out, out)
            self.assertEqual((home / 'account.conf').read_text(encoding='utf-8'),
                             'AUTO_UPGRADE="1"\n')

    def test_existing_metadata_unavailable_blocks(self):
        """API/元数据不可用：无法取得可信预期 → 阻止，且不得用待验证文件自算摘要。"""
        with tempfile.TemporaryDirectory() as td:
            out, home, installed = self._existing_case(td, commit_json='{}')
            self._assert_blocked_and_untouched(out, home, installed)
            self.assertIn('commit', out, out)

        with tempfile.TemporaryDirectory() as td:
            # 官方 tree 取不到（下载失败）
            out, home, installed = self._existing_case(
                td, fetch_fail={'acme.sh'})
            self._assert_blocked_and_untouched(out, home, installed)

    def test_existing_tree_truncated_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            files = self.ok_files()
            tree = json.loads(self.ok_tree(files))
            tree['truncated'] = True
            installed = {'acme.sh': self.MOCK_INSTALLER.replace(
                '#!/usr/bin/env sh', '#!/bin/bash', 1).encode()}
            home = Path(td) / 'home'
            for p, data in installed.items():
                fp = home / p
                fp.parent.mkdir(parents=True, exist_ok=True)
                fp.write_bytes(data)
            out, _, _, _ = self.run_install(td, files, json.dumps(tree), home=home,
                                           call='existing', existing_files=installed)
            self.assertIn('ERR:', out, out)

    # ── 固定 commit 记录（2026-10-27）：核验对比本机记录的 commit，而不是浮动 master ──

    def test_install_records_pinned_commit(self):
        with tempfile.TemporaryDirectory() as td:
            files = self.ok_files()
            out, home, _, _ = self.run_install(td, files, self.ok_tree(files))
            self.assertNotIn('ERR:', out, out)
            pin = home / '.hy2-pinned-commit'
            self.assertEqual(pin.read_text(encoding='utf-8').strip(), 'a' * 40, out)
            self.assertEqual(pin.stat().st_mode & 0o777, 0o600)

    def test_pinned_install_survives_upstream_master_moving(self):
        """上游 master 前进后，按记录的 commit 核验仍通过，且根本不去问 master。"""
        pinned = 'c' * 40
        with tempfile.TemporaryDirectory() as td:
            out, home, installed = self._existing_case(
                td, pin=pinned + '\n', commit_json=json.dumps({'sha': 'd' * 40}))
            self.assertNotIn('ERR:', out, out)
            self.assertIn('来源可确认', out, out)
            urls = (Path(td) / 'urls.log').read_text(encoding='utf-8')
            self.assertNotIn('commits/master', urls, '有记录时不得再解析浮动 master')
            self.assertIn(f'git/trees/{pinned}', urls)
            self.assertIn(f'/{pinned}/acme.sh', urls)
            self.assertEqual((home / '.hy2-pinned-commit').read_text(encoding='utf-8').strip(), pinned)

    def test_pinned_install_tampered_is_blocked_without_master_fallback(self):
        """有记录但内容对不上：必须阻断，不能退回去对比 master 碰运气。"""
        with tempfile.TemporaryDirectory() as td:
            out, home, installed = self._existing_case(
                td, mutate_plugin=b'# dns_cf TAMPERED\n', pin='c' * 40 + '\n')
            self.assertIn('已阻止', out, out)
            for p, data in installed.items():
                self.assertEqual((home / p).read_bytes(), data)
            self.assertEqual((home / 'account.conf').read_text(encoding='utf-8'),
                             'AUTO_UPGRADE="1"\nCF_Token="x"\n')
            urls = (Path(td) / 'urls.log').read_text(encoding='utf-8')
            self.assertNotIn('commits/master', urls)

    def test_invalid_pin_record_blocks(self):
        for bad in ('not-a-commit\n', '', 'A' * 40 + '\n', 'c' * 39 + '\n'):
            with tempfile.TemporaryDirectory() as td:
                out, home, installed = self._existing_case(td, pin=bad)
                self.assertIn('已阻止', out, out)
                self.assertIn('内容非法', out, out)
                self.assertEqual((home / '.hy2-pinned-commit').read_text(encoding='utf-8'), bad,
                                 '非法记录不得被自动改写')

    def test_legacy_install_gets_pinned_after_master_check(self):
        """没有记录的旧安装：对比 master 通过、关掉自动升级后补写记录。"""
        with tempfile.TemporaryDirectory() as td:
            out, home, installed = self._existing_case(td)
            self.assertNotIn('ERR:', out, out)
            self.assertIn('旧安装', out, out)
            self.assertEqual((home / '.hy2-pinned-commit').read_text(encoding='utf-8').strip(), 'a' * 40)

    def test_install_binary_fallback_keeps_app_tag_prefix(self):
        """API 不可用、只能从下载站解析版本时，必须拼回 `app/` 前缀。

        下载站给的是裸 `vX.Y.Z`，GitHub 的 release tag 是 `app/vX.Y.Z`。
        实测裸版本号的 hashes.txt 与资产都是 404 —— 不补前缀，回退路径恒失败。
        """
        fn = extract_install_fn('install_binary')
        helpers = '\n'.join(extract_install_fn(n) for n in INSTALL_HELPERS)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            existing = root / 'hysteria'
            existing.write_bytes(b'OLD')
            payload = b'#!/bin/sh\necho "Version: v9.9.9"\n'
            digest = hashlib.sha256(payload).hexdigest()
            payload_b64 = base64.b64encode(payload).decode()
            stub = f'''set -eo pipefail
PAYLOAD_B64='{payload_b64}'
HY2_ARCH=amd64
HY2_BIN="{existing}"
: > "{root}/urls.log"
log_info() {{ :; }}; log_warn() {{ :; }}; log_err() {{ echo "ERR: $*"; }}; log_step() {{ :; }}
{helpers}
curl() {{
  local url='' dest='' head=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -o) dest="$2"; shift 2;;
      --max-time|--connect-timeout|--retry|--retry-delay) shift 2;;
      -H) shift 2;;
      -fL|--progress-bar|-fsSL|-s|-sS|-I) shift;;
      -fsSIL|-fsSI) head=1; shift;;
      http*) url="$1"; shift;;
      *) shift;;
    esac
  done
  printf '%s\n' "$url" >> "{root}/urls.log"
  # 下载站的 latest 是 302：只回 Location，不给内容
  if [[ "$head" == "1" ]]; then
    printf 'HTTP/2 302\\r\\nlocation: https://download.hysteria.network/app/v9.9.9/hysteria-linux-amd64\\r\\n'
    return 0
  fi
  case "$url" in
    *api.github.com*releases/latest*) return 22;;
    *app/v9.9.9/hashes.txt*) printf '{digest}  build/hysteria-linux-amd64\\n' > "$dest"; return 0;;
    *app/v9.9.9/hysteria-linux-amd64) printf '%s' "$PAYLOAD_B64" | base64 -d > "$dest"; return 0;;
  esac
  return 22
}}
'''
            stub = stub + fn + '\necho "INSTALL_RC_START"\ninstall_binary; echo "RC=$?"\n'
            out = run_bash(stub)
            self.assertIn('RC=0', out, out)
            self.assertNotIn('ERR:', out, out)
            # curl 在命令替换的子 shell 里跑，变量收不到；用文件记录全部请求 URL
            urls = (root / 'urls.log').read_text(encoding='utf-8')
            self.assertIn('app/v9.9.9/hashes.txt', urls, out)
            self.assertIn('app/v9.9.9/hysteria-linux-amd64', urls, out)
            # 不允许拼出裸版本号的 GitHub URL（实测 404）
            self.assertNotIn('download/v9.9.9/', urls, out)
            self.assertEqual(existing.read_bytes(), payload)

    def test_do_upgrade_and_portal_keep_app_tag_prefix(self):
        """同一处版本归一化在 do_upgrade.sh 与 portal.py 里也必须补 app/ 前缀。"""
        inst = INSTALL.read_text(encoding='utf-8')
        self.assertIn('TAG="app/${BASH_REMATCH[1]}"', inst)
        self.assertNotIn('TAG="${BASH_REMATCH[1]}"', inst)
        port = PORTAL.read_text(encoding='utf-8')
        self.assertIn("tag = ('app/' + m.group(1)) if m else ''", port)
        self.assertNotIn("tag = m.group(1) if m else ''", port)

    def test_shebang_exception_is_not_a_bypass(self):
        """只允许安全 shebang；带参数/元字符的 shebang 一律视为内容不符。"""
        safe = self.prelude() + '''
for s in '#!/bin/bash' '#!/bin/sh' '#!/usr/bin/env bash' '#!/usr/bin/env sh' \\
         '#!/usr/local/bin/bash'; do
  hy2_acme_shebang_safe "$s" && echo "OK:$s" || echo "BAD:$s"
done
for s in '#!/bin/sh -c "curl x | sh"' '#!/usr/bin/env -S bash -c id' \\
         '#!/bin/bash; id' '#!/usr/bin/env python3' '#!/bin/zsh' '#!'; do
  hy2_acme_shebang_safe "$s" && echo "OK:$s" || echo "BAD:$s"
done
# 同 basename 但不在标准系统目录下的解释器路径不得被信任
for s in '#!/tmp/evil/bash' '#!/opt/x/bin/bash' '#!/home/u/sh' \\
         '#!../bash' '#!/root/.local/bin/sh'; do
  hy2_acme_shebang_safe "$s" && echo "OK:$s" || echo "BAD:$s"
done
'''
        out = run_bash(safe)
        for s in ('#!/bin/bash', '#!/bin/sh', '#!/usr/bin/env bash', '#!/usr/bin/env sh',
                  '#!/usr/local/bin/bash'):
            self.assertIn('OK:' + s, out, out)
        for s in ('#!/bin/sh -c "curl x | sh"', '#!/usr/bin/env -S bash -c id',
                  '#!/bin/bash; id', '#!/usr/bin/env python3', '#!/bin/zsh', '#!',
                  '#!/tmp/evil/bash', '#!/opt/x/bin/bash', '#!/home/u/sh',
                  '#!../bash', '#!/root/.local/bin/sh'):
            self.assertIn('BAD:' + s, out, out)

        # 端到端：已有脚本被改成带命令的 shebang，其余字节与官方一致 → 仍必须阻止
        with tempfile.TemporaryDirectory() as td:
            files = self.ok_files()
            evil = b'#!/bin/sh -c "echo EXECUTED > /tmp/hy2-acme-pwned"\n' + \
                self.MOCK_INSTALLER.split('\n', 1)[1].encode()
            out, home, installed = self._existing_case(td, mutate_main=evil)
            self._assert_blocked_and_untouched(out, home, installed)

    def test_dns_api_install_failure_returns_error_without_shell(self):
        """setup_cert_via_dns_api：校验安装失败时返回 1，绝不退回 curl|sh。"""
        fn = extract_install_fn('setup_cert_via_dns_api')
        src = INSTALL.read_text(encoding='utf-8')
        self.assertNotRegex(fn, r'get\.acme\.sh[^\n]*\|\s*(sh|bash)')
        with tempfile.TemporaryDirectory() as td:
            script = f'''
HOME="{td}/home"
mkdir -p "$HOME"
HY2_CF_TOKEN="tok"; HY2_CF_EMAIL="a@b.c"
log_info() {{ echo "INF: $*"; }}; log_warn() {{ echo "WRN: $*"; }}
log_err() {{ echo "ERR: $*"; }}; log_step() {{ :; }}
hy2_acme_install_verified() {{ echo "INSTALLER-CALLED"; return 1; }}
{fn}
setup_cert_via_dns_api example.com || echo "RC=$?"
'''
            out = run_bash(script)
            self.assertIn('INSTALLER-CALLED', out, out)
            self.assertIn('RC=1', out, out)
            self.assertIn('ERR:', out, out)
            # 安装失败后不得继续调用 acme.sh 签发
            self.assertNotIn('使用 Cloudflare DNS API 签发', out)

    def test_existing_acme_is_checked_not_reinstalled(self):
        """已有 acme.sh 且核验通过：走 check_existing，绝不调用安装器，继续签发。"""
        fn = extract_install_fn('setup_cert_via_dns_api')
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            (home / '.acme.sh').mkdir(parents=True)
            (home / '.acme.sh' / 'acme.sh').write_text('#!/bin/sh\n', encoding='utf-8')
            (home / '.acme.sh' / 'acme.sh').chmod(0o755)
            script = f'''
HOME="{home}"
HY2_CF_TOKEN="tok"; HY2_CF_EMAIL="a@b.c"
log_info() {{ echo "INF: $*"; }}; log_warn() {{ echo "WRN: $*"; }}
log_err() {{ echo "ERR: $*"; }}; log_step() {{ :; }}
hy2_acme_install_verified() {{ echo "INSTALLER-CALLED"; return 0; }}
hy2_acme_check_existing() {{ echo "CHECK-EXISTING"; return 0; }}
{fn}
setup_cert_via_dns_api example.com || true
'''
            out = run_bash(script)
            self.assertIn('CHECK-EXISTING', out, out)
            self.assertNotIn('INSTALLER-CALLED', out, out)
            self.assertIn('使用 Cloudflare DNS API 签发', out)

    def test_existing_acme_verification_failure_blocks_issue(self):
        """已有 acme.sh 核验失败：setup_cert_via_dns_api 必须返回 1 且不签发。"""
        fn = extract_install_fn('setup_cert_via_dns_api')
        with tempfile.TemporaryDirectory() as td:
            home = Path(td) / 'home'
            (home / '.acme.sh').mkdir(parents=True)
            acct = home / '.acme.sh' / 'acme.sh'
            acct.write_text('#!/bin/sh\n# UNKNOWN\n', encoding='utf-8')
            acct.chmod(0o755)
            script = f'''
HOME="{home}"
HY2_CF_TOKEN="tok"; HY2_CF_EMAIL="a@b.c"
log_info() {{ echo "INF: $*"; }}; log_warn() {{ echo "WRN: $*"; }}
log_err() {{ echo "ERR: $*"; }}; log_step() {{ :; }}
hy2_acme_install_verified() {{ echo "INSTALLER-CALLED"; return 0; }}
hy2_acme_check_existing() {{ echo "CHECK-EXISTING"; return 1; }}
{fn}
rc=0; setup_cert_via_dns_api example.com || rc=$?
echo "RC=$rc"
'''
            out = run_bash(script)
            self.assertIn('CHECK-EXISTING', out, out)
            self.assertNotIn('INSTALLER-CALLED', out, out)
            self.assertIn('RC=1', out, out)
            self.assertNotIn('使用 Cloudflare DNS API 签发', out, '核验失败时绝不能签发')
            self.assertEqual(acct.read_text(encoding='utf-8'), '#!/bin/sh\n# UNKNOWN\n')

    def test_existing_acme_wiring_uses_verification_and_hard_fails(self):
        """控制流反例：调用点不得再用 `|| true` 吞掉核验失败。"""
        fn = extract_install_fn('setup_cert_via_dns_api')
        self.assertRegex(fn, r'if\s*!\s*hy2_acme_check_existing')
        self.assertNotRegex(fn, r'hy2_acme_check_existing[^\n]*\|\|\s*true')
        # 核验失败必须在签发（"使用 ... DNS API 签发"）之前返回
        self.assertLess(fn.index('hy2_acme_check_existing'), fn.index('使用 ${provider} DNS API 签发'))
        # 检查函数自身必须是 fail-closed 且核验失败时不写配置
        chk = extract_install_fn('hy2_acme_check_existing')
        self.assertIn('hy2_acme_verify_existing', chk)
        self.assertLess(chk.index('hy2_acme_verify_existing'), chk.index('hy2_acme_disable_auto_upgrade'))
        self.assertNotIn('|| true', chk)
        # 不得用待验证文件自算摘要当预期（旧实现的 got==blob 自证）
        self.assertNotIn('got="$(hy2_git_blob_sha "$acct"', chk)

    def test_disable_auto_upgrade_variants(self):
        helper = extract_install_fn('hy2_acme_disable_auto_upgrade')
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cases = {
                'missing.conf': None,
                'enabled.conf': 'AUTO_UPGRADE="1"\nCF_Token="t"\n',
                'commented.conf': '#AUTO_UPGRADE="1"\nCF_Token="t"\n',
                'absent.conf': 'CF_Token="t"\n',
            }
            for name, body in cases.items():
                p = root / name
                if body is not None:
                    p.write_text(body, encoding='utf-8')
            script = helper + f'''
for f in missing.conf enabled.conf commented.conf absent.conf; do
  hy2_acme_disable_auto_upgrade "{root}/$f" || echo "FAIL:$f"
done
'''
            out = run_bash(script)
            self.assertNotIn('FAIL:', out, out)
            for name in cases:
                conf = (root / name).read_text(encoding='utf-8')
                self.assertIn("AUTO_UPGRADE='0'", conf, name)
                self.assertNotIn('AUTO_UPGRADE="1"', conf, name)
                if cases[name] and 'CF_Token' in cases[name]:
                    self.assertIn('CF_Token="t"', conf, name)
            # 原有文件必须留备份
            self.assertTrue((root / 'enabled.conf.hy2-bak').exists())
            self.assertEqual((root / 'enabled.conf.hy2-bak').read_text(encoding='utf-8'),
                             cases['enabled.conf'])

    def test_no_pipe_to_shell_in_acme_path(self):
        # 只看可执行语句（去掉整行注释），注释里提到旧写法是允许的
        code = [ln for ln in INSTALL.read_text(encoding='utf-8').splitlines()
                if not ln.lstrip().startswith('#')]
        body = '\n'.join(code)
        self.assertNotRegex(body, r'get\.acme\.sh[^\n]*\|\s*(sh|bash)')
        self.assertNotIn('| sh -s --home', body)
        # DNS API 路径必须调用校验安装器
        self.assertIn('hy2_acme_install_verified', body)


if __name__ == '__main__':
    unittest.main()
