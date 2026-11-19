"""用户专属连接弹窗展示服务端具体中文报错，且出站管理在锁内清洗坏容器并回中文提示。"""
import ast
import base64
import copy
import io
import json
import shutil
import subprocess
import sys
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
from urllib.parse import urlencode

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal  # noqa: E402
from test_portal_auth_surface import EndpointAuthTest  # noqa: E402
from test_user_modal_singbox import modal_block  # noqa: E402

NODE = shutil.which('node')


class OutboundCorruptAndChineseErrorTest(unittest.TestCase):
    def test_global_mode_rejects_corrupt_custom_outbounds(self):
        """custom_outbounds 被改坏成非空坏条目（如 [7] 或 123）时不能允许切到全局出口。"""
        tree = ast.parse(Path(portal.__file__).read_text(encoding='utf-8'))
        node = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == '_ob_manage')
        data = {'custom_outbounds': [7], 'warp_rules': [], 'outbound_mode': 'rules'}
        save_data = Mock()
        ns = dict(portal.__dict__, data=data, data_lock=threading.RLock(), save_data=save_data)
        mod = ast.Module(body=[copy.deepcopy(node)], type_ignores=[])
        exec(compile(ast.fix_missing_locations(mod), '<ob-manage>', 'exec'), ns)
        ob_manage = ns['_ob_manage']

        replies = []
        raw = urlencode({'action': 'mode', 'mode': 'global'}).encode('utf-8')
        handler = SimpleNamespace(
            is_authenticated=lambda: True,
            headers={'Content-Length': str(len(raw))},
            rfile=io.BytesIO(raw),
            reply_json=lambda code, payload: replies.append((code, payload)),
            _reply_with_egress_apply=lambda payload, kind='outbound': replies.append((200, payload)),
        )
        ob_manage(handler)
        self.assertEqual(replies[0][0], 400, replies)
        self.assertIn('新增一个出站', replies[0][1]['error'])
        self.assertEqual(data['outbound_mode'], 'rules')
        save_data.assert_not_called()

    def test_user_config_and_outbound_errors_are_chinese_over_http(self):
        suite = EndpointAuthTest('test_manage_outbounds_rejects_unknown_target')
        EndpointAuthTest.setUpClass()
        try:
            auth = 'Basic ' + base64.b64encode(
                f"{suite.access['username']}:{suite.access['password']}".encode()).decode()
            for query, want_code, phrase in (
                ('user_id=bad%20id', 400, '格式不合法'),
                ('user_id=no_such_user', 404, '可能已被删除'),
            ):
                status, body = suite.request('GET', f'{suite.prefix}user-config?{query}', auth=auth)
                self.assertEqual(status, want_code, body)
                err_msg = json.loads(body)['error']
                self.assertIn(phrase, err_msg)
        finally:
            EndpointAuthTest.tearDownClass()

    @unittest.skipUnless(NODE, '需要 node 环境')
    def test_user_modal_surfaces_server_chinese_error_on_404_503_and_429(self):
        prelude = portal.SCRIPT[:portal.SCRIPT.index('// 全局高颜值 Promise 确认框与 Toast 机制')]
        js = r"""
const mk = () => ({textContent: '', innerHTML: '', classList: {add() {}, remove() {}}, querySelectorAll: () => []});
const uModal = mk(), uModalBody = mk(), uModalTitle = mk(), uModalSub = mk(), uModalClose = mk();
const location = {origin: 'https://h.example.com:8443'};
const btn = {dataset: {uid: 'alice', token: 'tok', key: 'kkk'}, addEventListener(type, fn) { this.onclick = fn; }};
const document = {querySelectorAll: sel => (sel === '.btn-user-connect' ? [btn] : [])};
let reply;
globalThis.fetch = async () => reply();
%s
%s
(async () => {
  reply = () => new Response(JSON.stringify({ok: false, error: '该用户不存在（可能已被删除），请刷新页面'}), {status: 404});
  await btn.onclick();
  const missing = uModalBody.innerHTML;
  reply = () => new Response(JSON.stringify({ok: false, error: '该账号的密码为空或已损坏，请先重置密码再导出配置'}), {status: 503});
  await btn.onclick();
  const corruptPwd = uModalBody.innerHTML;
  reply = () => new Response('Too Many Requests', {status: 429});
  await btn.onclick();
  const rateLimited = uModalBody.innerHTML;
  console.log(JSON.stringify({missing, corruptPwd, rateLimited}));
})();
""" % (prelude, modal_block(portal.SCRIPT))
        run = subprocess.run([NODE, '-e', js], capture_output=True, text=True, encoding='utf-8', timeout=30)
        self.assertEqual(run.returncode, 0, run.stderr)
        r = json.loads(run.stdout.strip().splitlines()[-1])
        self.assertIn('可能已被删除', r['missing'], r['missing'])
        self.assertIn('密码为空或已损坏', r['corruptPwd'], r['corruptPwd'])
        self.assertIn('请求太频繁', r['rateLimited'], r['rateLimited'])
        self.assertNotIn('HTTP 404', r['missing'])
        self.assertNotIn('HTTP 503', r['corruptPwd'])


if __name__ == '__main__':
    unittest.main()
