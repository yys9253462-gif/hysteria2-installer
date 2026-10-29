"""GitHub API token（2026-10-28）：只给 api.github.com 加，别的主机一律不带。"""
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import urllib.request
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import portal  # noqa: E402

TOKEN = 'github_pat_' + 'A1' * 20
BASH = shutil.which('bash')


def bash_path(path):
    """PATH 里不能出现 Windows 盘符的冒号；Git Bash 下转成 /c/... 形式。"""
    cygpath = shutil.which('cygpath')
    if cygpath:
        return subprocess.run([cygpath, '-u', str(path)], capture_output=True, text=True).stdout.strip()
    return Path(path).as_posix()


class PortalTokenTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.file = Path(self.tmp.name) / 'github-token'
        patcher = mock.patch.object(portal, 'GITHUB_TOKEN_FILE', self.file)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.tmp.cleanup)
        portal._github_token_cache.update(mtime=None, token='')

    def write_token(self, value):
        """写 token 文件并设成 600 —— 生产要求的最小权限。

        portal 会拒绝权限过宽的文件（POSIX），测试必须按真实部署来写。
        """
        self.file.write_text(value, encoding='utf-8')
        try:
            self.file.chmod(0o600)
        except OSError:
            pass

    def auth_for(self, url):
        req = urllib.request.Request(url)
        portal.GitHubTokenHandler().https_request(req)
        return req.unredirected_hdrs.get('Authorization')

    def test_only_api_github_gets_token(self):
        self.write_token(TOKEN + '\n')
        self.assertEqual(self.auth_for('https://api.github.com/repos/a/b/commits/main'), 'Bearer ' + TOKEN)
        for url in ('https://github.com/a/b/releases/download/v1/x.tar.gz',
                    'https://ghfast.top/https://api.github.com/repos/a/b',
                    'https://raw.githubusercontent.com/a/b/main/x',
                    'https://api.github.com.evil.example/repos'):
            with self.subTest(url=url):
                self.assertIsNone(self.auth_for(url), url + ' 不应带上 token')

    def test_token_is_not_forwarded_on_redirect(self):
        """unredirected header：GitHub 跳转到下载主机时不能把 token 一起带过去。"""
        self.write_token(TOKEN)
        req = urllib.request.Request('https://api.github.com/repos/a/b/tarball')
        portal.GitHubTokenHandler().https_request(req)
        self.assertNotIn('Authorization', req.headers)
        self.assertIn('Authorization', req.unredirected_hdrs)

    def test_missing_or_malformed_token_is_ignored(self):
        self.assertIsNone(self.auth_for('https://api.github.com/x'))
        for bad in ('', 'short', TOKEN + '\r\nX-Evil: 1', 'tok en' + 'a' * 30):
            with self.subTest(bad=bad):
                self.write_token(bad)
                os.utime(self.file, (1, len(bad) + 1))  # 强制 mtime 变化
                self.assertIsNone(self.auth_for('https://api.github.com/x'))

    def test_installed_opener_uses_handler(self):
        opener = urllib.request._opener
        # 按类名判断：别的测试会从文件再加载一份 portal 模块，重新装上的是同名的另一个类对象。
        self.assertTrue(any(type(h).__name__ == 'GitHubTokenHandler' for h in opener.handlers))

    @unittest.skipUnless(os.name == 'posix', 'POSIX 权限位')
    def test_world_readable_token_file_is_ignored(self):
        """权限过宽的 token 文件等同于凭据泄露，必须拒绝使用。"""
        self.file.write_text(TOKEN, encoding='utf-8')
        self.file.chmod(0o644)
        self.assertIsNone(self.auth_for('https://api.github.com/x'))
        self.file.chmod(0o600)
        os.utime(self.file, (2, 2))  # 触发重新读取
        self.assertEqual(self.auth_for('https://api.github.com/x'), 'Bearer ' + TOKEN)


@unittest.skipUnless(BASH, 'requires bash')
class UpdateRefFallbackTest(unittest.TestCase):
    """自更新锁定 commit：API 被限流时必须退回 atom，而不是直接失败。"""

    def test_falls_back_to_atom_when_api_is_rate_limited(self):
        sha = 'b' * 40
        calls = []

        class Resp:
            def __init__(self, body):
                self.body = body
            def __enter__(self):
                return self
            def __exit__(self, *a):
                return False
            def read(self):
                return self.body

        def fake_urlopen(req, timeout=8):
            url = req.full_url if hasattr(req, 'full_url') else str(req)
            calls.append(url)
            if 'api.github.com' in url:
                raise urllib.error.HTTPError(url, 403, 'rate limited', None, None)
            return Resp(('<feed><entry><id>tag:github.com,2008:Grit::Commit/%s</id>'
                         '<link href="https://github.com/x/y/commit/%s"/></entry></feed>'
                         % (sha, sha)).encode())

        with mock.patch.object(portal.urllib.request, 'urlopen', fake_urlopen):
            self.assertEqual(portal.resolve_update_ref('main'), sha)
        self.assertTrue(any('api.github.com' in c for c in calls))
        self.assertTrue(any('commits/main.atom' in c for c in calls))

    def test_pinned_ref_is_returned_verbatim(self):
        sha = 'c' * 40
        self.assertEqual(portal.resolve_update_ref(sha), sha)


class InstallShTokenTest(unittest.TestCase):
    """install.sh 的 curl 包装：只给 api.github.com 加，且 token 不出现在参数里。"""

    def run_wrapper(self, url, token=TOKEN):
        src = (ROOT / 'install.sh').read_text(encoding='utf-8')
        func = re.search(r'^curl\(\) \{.*?^\}', src, re.S | re.M).group(0)
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            (td / 'github-token').write_text(token, encoding='utf-8')
            fake = td / 'bin'
            fake.mkdir()
            # 假 curl：打印参数，并把 -H @文件 的内容展开打印。
            (fake / 'curl').write_text(
                '#!/usr/bin/env bash\n'
                'for a in "$@"; do echo "ARG:$a"; done\n'
                'prev=""; for a in "$@"; do if [[ $prev == -H && $a == @* ]]; then '
                'echo "HDR:$(cat "${a#@}")"; fi; prev=$a; done\n', encoding='utf-8')
            (fake / 'curl').chmod(0o755)
            script = td / 's.sh'
            script.write_text(
                'PATH="%s:$PATH"\nHY2_GITHUB_TOKEN_FILE="%s"\n%s\ncurl -fsSL "%s"\n'
                % (bash_path(fake), (td / 'github-token').as_posix(), func, url), encoding='utf-8')
            return subprocess.run([BASH, str(script)], capture_output=True, text=True, timeout=20).stdout

    def test_api_github_gets_header_without_token_in_args(self):
        out = self.run_wrapper('https://api.github.com/repos/a/b/commits/main')
        self.assertIn('HDR:Authorization: Bearer ' + TOKEN, out)
        args = [line for line in out.splitlines() if line.startswith('ARG:')]
        self.assertFalse(any(TOKEN in a for a in args), 'token 出现在 curl 参数里，ps 能看到')

    def test_other_hosts_get_no_header(self):
        for url in ('https://raw.githubusercontent.com/a/b/main/x',
                    'https://ghfast.top/https://api.github.com/repos/a/b'):
            with self.subTest(url=url):
                self.assertNotIn('HDR:', self.run_wrapper(url))

    def test_malformed_token_is_ignored(self):
        out = self.run_wrapper('https://api.github.com/x', token='bad token')
        self.assertNotIn('HDR:', out)


if __name__ == '__main__':
    unittest.main(verbosity=2)
