"""回归测试：BBR 切换、服务器重启、证书状态与核心管理页在非 JSON 502 错误页与坏字段下的前端容错。"""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
from test_hash_routing import NODE, page_model, run_portal_page  # noqa: E402

NODE_VERIFY = r"""
async ({els, tick, sandbox, setRespond}) => {
  const alerts = [];
  const toasts = [];
  sandbox.alert = msg => alerts.push(String(msg));
  sandbox.showToast = (msg, kind) => toasts.push({msg: String(msg), kind});

  // 1) checkCertStatus 收到 502 HTML 错误页时不得暴露 Unexpected token，应提示 502
  setRespond(url => {
    if (url.endsWith('cert-status')) return new Response('<html>502 Bad Gateway</html>', {status: 502});
    return new Response(JSON.stringify({ok: true}));
  });
  await sandbox.checkCertStatus();
  const cert502Note = els['cert-renewal-note'].textContent;

  // 2) checkCertStatus 收到非字符串 issuer / pin_sha256 时不得抛 TypeError
  setRespond(url => {
    if (url.endsWith('cert-status')) {
      return new Response(JSON.stringify({
        ok: true,
        common_name: 'example.com',
        issuer: 12345,
        is_insecure: true,
        pin_sha256: 987654321012345678,
        expires_in_days: 30,
        warn_level: 'ok',
      }));
    }
    return new Response(JSON.stringify({ok: true}));
  });
  await sandbox.checkCertStatus();
  const certBadIssuerBadge = els['cert-badge'].textContent;

  // 3) loadCores 收到 502 HTML 错误页时应提示 HTTP 502 而非 SyntaxError
  let replacedCoreNodes = [];
  els['core-grid'].replaceChildren = (...nodes) => { replacedCoreNodes = nodes; };
  setRespond(url => {
    if (url.endsWith('cores-status')) return new Response('<html>502 Bad Gateway</html>', {status: 502});
    return new Response(JSON.stringify({ok: true}));
  });
  await sandbox.loadCores();
  const coreGridText = replacedCoreNodes.map(n => n.textContent || '').join(' ');

  // 4) btnRebootServer 收到 502 HTML 错误页时应给出清晰错误并恢复按钮，不得报 SyntaxError
  setRespond(url => {
    if (url.endsWith('reboot-server')) return new Response('<html>502 Bad Gateway</html>', {status: 502});
    return new Response(JSON.stringify({ok: true}));
  });
  const rebootBtn = els['btn-reboot-server'];
  rebootBtn.disabled = false;
  rebootBtn.textContent = '🔄 立即重启服务器生效';
  const beforeAlerts = alerts.length;
  rebootBtn.click();
  await tick();
  els['confirm-btn-ok'].click();
  await tick();
  const rebootAlert = alerts[beforeAlerts] || '';

  return {
    cert502Note,
    certBadIssuerBadge,
    coreGridText,
    rebootAlert,
    rebootDisabled: rebootBtn.disabled,
  };
}
"""


class PortalAssetsBbrCertCoresResilienceTests(unittest.TestCase):
    def test_source_guards_for_bbr_cert_reboot_and_cores(self):
        src = (ROOT / 'portal_assets.py').read_text(encoding='utf-8').replace('\r\n', '\n')
        self.assertIn("String(issuer)", src)
        self.assertIn("String(json.pin_sha256)", src)
        self.assertIn("配置失败（HTTP ' + res.status", src)

    @unittest.skipUnless(NODE, 'requires node')
    def test_runtime_resilience_in_node_sandbox(self):
        report = run_portal_page(page_model(), after=NODE_VERIFY)
        self.assertEqual(report['errors'], [])
        res = report['after']
        self.assertIn('502', res['cert502Note'])
        self.assertNotIn('Unexpected token', res['cert502Note'])
        self.assertIn('正常', res['certBadIssuerBadge'])
        self.assertIn('502', res['coreGridText'])
        self.assertNotIn('Unexpected token', res['coreGridText'])
        self.assertIn('502', res['rebootAlert'])
        self.assertNotIn('Unexpected token', res['rebootAlert'])
        self.assertFalse(res['rebootDisabled'])


if __name__ == '__main__':
    unittest.main()
