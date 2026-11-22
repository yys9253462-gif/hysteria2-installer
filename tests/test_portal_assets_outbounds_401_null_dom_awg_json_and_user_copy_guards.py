"""回归测试：portal_assets.py 出站三接口 401 置位与非串 IP、快速填写空 DOM 判空、AWG 回调判空及客户分享页复制防重入。"""

import shutil
import subprocess
import unittest

import portal_assets

NODE = shutil.which('node')


def _slice_block(src: str, start_marker: str, end_marker: str) -> str:
    i = src.index(start_marker)
    j = src.index(end_marker, i)
    return src[i:j]


class TestPortalAssetsOutbounds401NullDomAwgJsonAndUserCopyGuards(unittest.TestCase):
    def test_outbounds_remaining_endpoints_set_session_expired_on_401_and_guard_ip_type(self):
        """waitForEgressApply / loadOutbounds / obTestForm 遇 401 均须置位 portalSessionExpired，且 obTestForm 校验字符串 ip。"""
        s = portal_assets.SCRIPT
        wfe = _slice_block(s, 'async function waitForEgressApply()', 'async function obApi(')
        lo = _slice_block(s, 'async function loadOutbounds()', 'async function probeOutbound(')
        otf = _slice_block(s, 'async function obTestForm()', "document.querySelectorAll('[data-ob-type]')")

        for name, body in (('waitForEgressApply', wfe), ('loadOutbounds', lo), ('obTestForm', otf)):
            with self.subTest(fn=name):
                self.assertIn('res.status === 401', body, f'{name} 缺少 401 判断')
                self.assertIn('portalSessionExpired = true', body, f'{name} 遇 401 未置位 portalSessionExpired')

        self.assertIn("typeof json.ip === 'string'", otf, 'obTestForm 必须校验 json.ip 为字符串防渲染 [object Object]')

    def test_ob_apply_quick_and_btn_eye_guard_null_dom_elements(self):
        """obApplyQuick 与密码显隐按钮在部分 DOM 元素缺失时不得抛 TypeError。"""
        s = portal_assets.SCRIPT
        body = _slice_block(s, 'function obApplyQuick()', '// 用表单当前填写的参数探测出口 IP')
        self.assertNotIn('if (!obEls.quickBox.hidden)', body, '访问 obEls.quickBox.hidden 前必须先判空 obEls.quickBox')
        self.assertIn('if (obEls.socksAddr)', body, '写入 obEls.socksAddr 前必须判空')
        self.assertIn('if (obEls.httpUrl)', body, '写入 obEls.httpUrl 前必须判空')

        bind_blk = _slice_block(s, "if (obEls.btnEye)", 'if (obEls.btnTest)')
        self.assertIn('if (obEls.socksPass)', bind_blk, 'btnEye 点击读取 obEls.socksPass.type 前必须判空')

    def test_awg_action_callbacks_guard_null_json_and_user_script_guards_reentry(self):
        """AWG 操作回调须判空 json && json.ok；USER_SCRIPT 复制按钮须防并发重入。"""
        s = portal_assets.SCRIPT
        awg_tail = s[s.index('awgPeerTbody.querySelectorAll(\'[data-awg-del]\')'):]
        self.assertNotIn('if (json.ok)', awg_tail, 'AWG 回调不得裸读 json.ok，必须先判 json && json.ok')
        self.assertIn('copyBusy', portal_assets.USER_SCRIPT, 'USER_SCRIPT 复制点击须防异步并发重入')

    @unittest.skipUnless(NODE, 'requires node')
    def test_ob_apply_quick_survives_partial_dom_at_runtime(self):
        """Node 实跑 obApplyQuick：缺失 quickBox/quickHint/socksUser 等 DOM 元素时必须平稳执行不抛异常。"""
        s = portal_assets.SCRIPT
        decode_src = _slice_block(s, 'function obDecode(s)', '// 识别常见代理写法')
        parse_src = _slice_block(s, 'function obParseLink(raw)', 'function obSuggestName(')
        apply_src = _slice_block(s, 'function obApplyQuick()', '// 用表单当前填写的参数探测出口 IP')
        js = f'''
const OB_QUICK_HINT = 'hint';
const obEls = {{ quick: {{ value: 'socks5://u:p@1.2.3.4:1080' }}, type: {{ value: '' }}, quickBox: null, quickHint: null, socksAddr: null, socksUser: null, socksPass: null, httpUrl: null, httpInsecure: null }};
function obTypeSwitch() {{}}
function obAutoName() {{}}
{decode_src}
{parse_src}
{apply_src}
obApplyQuick();
obEls.quick.value = 'invalid-raw-link';
obApplyQuick();
obEls.quick.value = '';
obApplyQuick();
console.log('RUNTIME_OK');
'''
        proc = subprocess.run([NODE, '-e', js], capture_output=True, text=True, encoding='utf-8', timeout=15)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn('RUNTIME_OK', proc.stdout)


if __name__ == '__main__':
    unittest.main()
