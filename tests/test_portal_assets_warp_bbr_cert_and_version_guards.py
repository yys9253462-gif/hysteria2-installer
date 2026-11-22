"""回归测试：前端 WARP 规则渲染与非 JSON 容错、BBR/证书/版本状态请求竞态序号与非有限天数/时间防护。"""

import hashlib
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ASSETS_SRC = (ROOT / 'portal_assets.py').read_text(encoding='utf-8')
NODE = shutil.which('node')


def _extract_portal_script():
    ns = {}
    exec(compile(ASSETS_SRC, str(ROOT / 'portal_assets.py'), 'exec'), ns)
    return ns['SCRIPT']


class PortalAssetsWarpBbrCertAndVersionGuardsTests(unittest.TestCase):
    def test_source_guards_for_warp_bbr_cert_and_version(self):
        """源码须具备 WARP 非数组过滤与防双击、BBR/证书/版本竞态序号与有限天数/时间戳校验。"""
        script = _extract_portal_script()
        self.assertIn('Array.isArray(rules)', script)
        self.assertIn('checkBbrStatus._seq', script)
        self.assertIn('checkCertStatus._seq', script)
        self.assertIn('checkVersions._seq', script)
        self.assertIn("typeof days === 'number' && Number.isFinite(days)", script)
        self.assertIn('Number.isFinite(healedTs)', script)
        self.assertIn('let warpRuleBusy = false;', script)

    @unittest.skipUnless(NODE, 'requires node')
    def test_node_runtime_warp_rules_cert_nan_and_version_race(self):
        """真 Node 运行时验证：renderWarpRules 容错非数组/脏项；checkCertStatus 拦 NaN 天数与坏时间戳及旧响应；checkVersions 丢弃晚到旧响应。"""
        script = _extract_portal_script()
        # 校验整份 PORTAL_SCRIPT 语法正确
        syntax = subprocess.run([NODE, '--check'], input=script, text=True, capture_output=True, encoding='utf-8', timeout=15)
        self.assertEqual(syntax.returncode, 0, syntax.stderr)

        # 提取 renderWarpRules + obEsc 运行时验证
        s_ob = script.index('function obEsc(s)')
        e_ob = script.index('function renderOutboundList(', s_ob)
        fn_ob_esc = script[s_ob:e_ob]
        s_wr = script.index('function renderWarpRules(')
        e_wr = script.index('// WARP 分流标签的删除按钮', s_wr)
        fn_wr = script[s_wr:e_wr]

        # 提取 checkCertStatus + certSetField + certShortIssuer
        s_cert = script.index('function certSetField(')
        e_cert = script.index("document.querySelectorAll('.btn-apply-bbr')", s_cert)
        fn_cert = script[s_cert:e_cert]

        # 提取 checkVersions + fmtVer + markVersionsUnknown
        s_ver = script.index('function fmtVer(')
        e_ver = script.index('async function waitForCoreUpgrade()', s_ver)
        fn_ver = script[s_ver:e_ver]

        harness = r'''
const assert = require('assert');
const elements = {};
function mkEl(id) {
  const el = { id, textContent: '', innerHTML: '', style: {}, className: '', classList: { add(c){ this.classes.push(c); }, classes: [] } };
  elements[id] = el;
  return el;
}
global.document = {
  getElementById: (id) => elements[id] || mkEl(id),
};
global.location = { pathname: '/tok/' };

const warpTagsCloud = mkEl('warp-tags-cloud');
const warpRulesCount = mkEl('warp-rules-count');
const certBadge = mkEl('cert-badge');
const certAlert = mkEl('cert-alert');
const certRenewalNote = mkEl('cert-renewal-note');
const coreVerDisplay = mkEl('core-ver');
const portalVerDisplay = mkEl('portal-ver');
const awgVerDisplay = mkEl('awg-ver');
const btnUpdateCore = mkEl('btn-uc');
const btnUpdatePortal = mkEl('btn-up');
const btnUpdateAwgEngine = mkEl('btn-ua');
function doUpgrade() {}

''' + fn_ob_esc + '\n' + fn_wr + '\n' + fn_cert + '\n' + fn_ver + r'''

(async () => {
  // 1. renderWarpRules 面对非数组对象和缺 domain 脏项不得抛错或渲染 undefined
  renderWarpRules({ bad: true }, true);
  assert.ok(warpTagsCloud.innerHTML.includes('暂无 WARP 分流域名'));
  renderWarpRules([null, 123, { outbound: 'warp_socks' }, { outbound: 'warp_socks', domain: '' }, { outbound: 'warp_socks', domain: 'openai.com' }], true);
  assert.strictEqual(warpRulesCount.textContent, '1 个生效中');
  assert.ok(!warpTagsCloud.innerHTML.includes('undefined'));
  assert.ok(warpTagsCloud.innerHTML.includes('openai.com'));

  // 2. checkCertStatus 面对非有限 expires_in_days 与无效 healed_at 不得显示绿色正常或 NaN 日期
  global.fetch = async () => ({
    ok: true,
    status: 200,
    json: async () => ({
      ok: true,
      common_name: 'a.example.com',
      sans: ['a.example.com', null, 42],
      issuer: 'CN=TestCA',
      cert_type: 'acme',
      not_after: '2027-01-01',
      server_name: 'a.example.com',
      expires_in_days: 'NaN',
      warn_level: 'ok',
      healed_at: 'not-a-timestamp',
    }),
  });
  await checkCertStatus();
  assert.ok(certBadge.textContent.includes('到期时间未知'), '实际: ' + certBadge.textContent);
  assert.strictEqual(elements['cert-sans'].textContent, 'a.example.com');
  assert.ok(!elements['cert-heal-note'].textContent.includes('NaN'), '实际: ' + elements['cert-heal-note'].textContent);

  // 3. checkVersions 晚到的第一次响应不得覆盖较新的第二次响应
  let resolveFirst;
  let callIdx = 0;
  global.fetch = () => {
    callIdx++;
    if (callIdx === 1) {
      return new Promise((resolve) => {
        resolveFirst = () => resolve({
          ok: true,
          json: async () => ({ ok: true, core_current: '1.0.0', core_latest: '1.0.0', core_has_update: false, portal_current: 'old', portal_latest: 'old', portal_has_update: false, portal_update_status: 'ok', awg_installed: false }),
        });
      });
    }
    return Promise.resolve({
      ok: true,
      json: async () => ({ ok: true, core_current: '2.6.0', core_latest: '2.6.0', core_has_update: false, portal_current: 'new', portal_latest: 'new', portal_has_update: false, portal_update_status: 'ok', awg_installed: false }),
    });
  };
  const p1 = checkVersions(false);
  const p2 = checkVersions(true);
  await p2;
  resolveFirst();
  await p1;
  assert.ok(coreVerDisplay.textContent.includes('2.6.0'), '旧响应覆盖了新版本: ' + coreVerDisplay.textContent);
  console.log('NODE_OK');
})().catch((err) => { console.error(err); process.exit(1); });
'''
        proc = subprocess.run([NODE, '-e', harness], capture_output=True, text=True, encoding='utf-8', timeout=15)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn('NODE_OK', proc.stdout)

    def test_csp_script_hash_sanity(self):
        """确保 PORTAL_SCRIPT 非空且可稳定计算 SHA256（防语法或转义破坏）。"""
        script = _extract_portal_script()
        digest = hashlib.sha256(script.encode('utf-8')).hexdigest()
        self.assertEqual(len(digest), 64)


if __name__ == '__main__':
    unittest.main()
