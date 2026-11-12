"""WARP / Reality 卡片丢弃晚到的旧状态回包（2026-11-04 修）。

轮询发出的状态请求比开关后的查询晚返回时，旧实现把卡片刷回切换之前的状态。
从 portal.SCRIPT 摘出真实的 checkXxxStatus，用 node 让两次请求倒序返回。
"""
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal  # noqa: E402

NODE = shutil.which('node')

HARNESS = r"""
const assert = require('assert');
const mk = () => new Proxy({style: {}, dataset: {}, classList: {add(){}, remove(){}, toggle(){}}}, {
  get: (t, k) => (k in t ? t[k] : (k === 'querySelectorAll' ? () => [] : (k === 'addEventListener' ? () => {} : ''))),
  set: (t, k, v) => { t[k] = v; return true; }});
globalThis.document = {getElementById: () => mk(), querySelectorAll: () => []};
const location = {pathname: '/t/'};
const pending = [];
globalThis.fetch = () => new Promise(r => pending.push(r));
const reply = on => new Response(JSON.stringify({ok: true, installed: true, enabled: on, active: on,
  config: on ? {uri: 'vless://x', port: 1, sni: 's', uuid: 'u', qr_svg: ''} : null,
  rules: [], rule_count: 0}));
function renderWarpRules() {}
"""

CHECKS = r"""
(async () => {
  const older = FN();
  const newer = FN();
  pending[1](reply(false)); await newer;
  const after = JSON.stringify(BADGE);
  pending[0](reply(true)); await older;
  assert.strictEqual(JSON.stringify(BADGE), after, 'stale reply overwrote the newer state');
})().catch(e => { console.error(e); process.exitCode = 1; });
"""

NAMES = ('warpBadge', 'btnInstallWarp', 'btnToggleWarp', 'warpRulesBox', 'warpIpVal', 'warpContentBox',
         'realityBadge', 'realityQrBox', 'realityUriVal', 'realitySniVal', 'realityUuidVal',
         'realityContentBox', 'btnToggleReality', 'btnResetRealityKeys', 'btnInstallXray')


@unittest.skipUnless(NODE, 'requires node')
class StatusCardStaleReplyTests(unittest.TestCase):
    def run_card(self, fname, seq_name, badge):
        script = portal.SCRIPT
        fstart = script.index('async function %s()' % fname)
        decl_at = script.find('let %s = 0;' % seq_name, max(0, fstart - 400), fstart)
        start = decl_at if decl_at >= 0 else fstart
        end = script.index('\n}\n', fstart) + 3
        body = script[start:end]
        helper_at = script.find('function markStatusUnknown(')
        helper = script[helper_at:script.index('\n}\n', helper_at) + 3] if helper_at >= 0 else ''
        decl = ''.join('var %s = mk();\n' % n for n in NAMES if n in body)
        checks = CHECKS.replace('FN', fname).replace('BADGE', badge)
        return subprocess.run([NODE, '-e', HARNESS + decl + helper + body + checks],
                              capture_output=True, text=True, encoding='utf-8', timeout=30)

    def test_warp_card(self):
        r = self.run_card('checkWarpStatus', 'warpStatusSeq', 'warpBadge')
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_reality_card(self):
        r = self.run_card('checkRealityStatus', 'realityStatusSeq', 'realityBadge')
        self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == '__main__':
    unittest.main()
