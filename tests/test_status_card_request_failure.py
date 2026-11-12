"""状态卡片查询失败、「重置 WARP 规则」失败时都要给出反馈（2026-11-12 修）。

旧实现：状态接口报错、回 ok:false 或网络中断时直接 return，徽章永远停在「检测中...」；
重置 WARP 规则失败时毫无反应，成功后也不刷新状态（WARP 生效中仍显示「N 个已配置」）。
从 portal.SCRIPT 摘出真实函数，用 node 模拟三种失败。
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
"""

CARD_CHECK = r"""
const MODES = {
  http500: () => Promise.resolve(new Response('<html>Internal Server Error</html>', {status: 500})),
  okfalse: () => Promise.resolve(new Response(JSON.stringify({ok: false, error: '磁盘已满'}))),
  network: () => Promise.reject(new TypeError('Failed to fetch')),
};
(async () => {
  for (const [mode, impl] of Object.entries(MODES)) {
    BADGE.textContent = '检测中...';
    BADGE.title = '';
    globalThis.fetch = impl;
    await FN();
    assert.strictEqual(BADGE.textContent, '● 状态未知（请求失败）', mode + ': badge stuck at ' + BADGE.textContent);
    if (mode === 'okfalse') assert.strictEqual(BADGE.title, '磁盘已满', 'server error not kept in title');
  }
})().catch(e => { console.error(e); process.exitCode = 1; });
"""

RESET_CHECK = r"""
const alerts = [];
globalThis.alert = m => alerts.push(String(m));
globalThis.confirm = () => true;
globalThis.showConfirm = async () => true;
let handler = null;
var btnResetWarpRules = {addEventListener: (ev, fn) => { handler = fn; }};
let statusChecks = 0, rendered = null;
async function checkWarpStatus() { statusChecks++; }
function renderWarpRules(rules) { rendered = rules; }
BLOCK
(async () => {
  globalThis.fetch = () => Promise.resolve(new Response(
    JSON.stringify({ok: false, error: 'OSError: No space left'}), {status: 500}));
  await handler();
  assert.strictEqual(alerts.length, 1, 'failed reset was silent');
  assert.ok(alerts[0].includes('OSError: No space left'), alerts[0]);
  globalThis.fetch = () => Promise.resolve(new Response('<html>Bad Gateway</html>', {status: 502}));
  await handler();
  assert.strictEqual(alerts.length, 2, 'non-JSON failure was silent');
  assert.ok(alerts[1].includes('502'), alerts[1]);
  globalThis.fetch = () => Promise.resolve(new Response(JSON.stringify({ok: true, rules: ['openai.com']})));
  await handler();
  assert.strictEqual(alerts.length, 2, 'successful reset raised an alert: ' + alerts[2]);
  assert.deepStrictEqual(rendered, ['openai.com']);
  assert.strictEqual(statusChecks, 1, 'status card not refreshed after reset');
})().catch(e => { console.error(e); process.exitCode = 1; });
"""

CARDS = (
    ('checkWarpStatus', 'warpBadge', 'warpStatusSeq'),
    ('checkRealityStatus', 'realityBadge', 'realityStatusSeq'),
    ('checkVmessStatus', 'vmessBadge', 'vmessStatusSeq'),
    ('checkVlessencStatus', 'vlessencBadge', 'vlessencStatusSeq'),
    ('checkAnytlsStatus', 'anytlsBadge', 'anytlsStatusSeq'),
    ('checkTuicStatus', 'tuicBadge', 'tuicStatusSeq'),
    ('checkBbrStatus', 'bbrBadge', None),
    ('loadProxyServices', 'gostBadge', None),
    ('loadAwgState', 'awgBadge', None),
)


def _block(header):
    script = portal.SCRIPT
    start = script.index(header)
    return script[start:script.index('\n}\n', start) + 3]


SHARED_HELPERS = ('function markStatusUnknown(', 'function markLoadFailed(', 'function obEsc(',
                  'function markWarpRulesFailed(', 'function markBbrFailed(')
# 卡片函数在失败路径上还会碰到的页面元素（只声明，内容为空即不触发替换）。
EXTRA_ELEMENTS = ('proxyTbody', 'warpRulesCount', 'warpTagsCloud', 'bbrCurrentText')

BBR_TEXT_CHECK = r"""
const MODES = {
  http500: () => Promise.resolve(new Response('<html>Internal Server Error</html>', {status: 500})),
  okfalse: () => Promise.resolve(new Response(JSON.stringify({ok: false, error: '磁盘已满'}))),
  network: () => Promise.reject(new TypeError('Failed to fetch')),
};
(async () => {
  for (const [mode, impl] of Object.entries(MODES)) {
    bbrCurrentText.textContent = '读取中...';
    globalThis.fetch = impl;
    await checkBbrStatus();
    assert.strictEqual(bbrCurrentText.textContent, '读取失败', mode + ': stuck at ' + bbrCurrentText.textContent);
  }
  bbrCurrentText.textContent = 'bbr';
  globalThis.fetch = MODES.http500;
  await checkBbrStatus();
  assert.strictEqual(bbrCurrentText.textContent, 'bbr', 'a later failure wiped the shown algorithm');
})().catch(e => { console.error(e); process.exitCode = 1; });
"""


def _helpers():
    return ''.join(_block(h) for h in SHARED_HELPERS if h in portal.SCRIPT)


def run_node(source):
    return subprocess.run([NODE, '-e', source], capture_output=True, text=True, encoding='utf-8', timeout=30)


@unittest.skipUnless(NODE, 'requires node')
class StatusCardRequestFailureTests(unittest.TestCase):
    def test_every_status_card_reports_a_failed_query(self):
        for fname, badge, seq in CARDS:
            with self.subTest(card=fname):
                body = _block('async function %s()' % fname)
                decl = 'var %s = mk();\n' % badge
                decl += ''.join('var %s = mk();\n' % name for name in EXTRA_ELEMENTS
                                if name in body or name in _helpers())
                if seq:
                    decl += 'let %s = 0;\n' % seq
                check = CARD_CHECK.replace('BADGE', badge).replace('FN', fname)
                r = run_node(HARNESS + decl + _helpers() + body + check)
                self.assertEqual(r.returncode, 0, r.stderr)

    def test_bbr_algorithm_text_reports_a_failed_query(self):
        """「当前内核拥塞控制」不停在「读取中...」（2026-11-12 修）。"""
        decl = 'var bbrBadge = mk(); var bbrCurrentText = {textContent: ""};\n'
        r = run_node(HARNESS + decl + _helpers() + _block('async function checkBbrStatus()') + BBR_TEXT_CHECK)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_reset_warp_rules_reports_failure_and_refreshes_status(self):
        check = RESET_CHECK.replace('BLOCK', _block('if (btnResetWarpRules) {'))
        r = run_node(HARNESS + check)
        self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == '__main__':
    unittest.main()
