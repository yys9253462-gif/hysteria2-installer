"""门户内嵌前端资源（JS / CSS）的完整性与语法测试。

这个文件的诞生原因是一次真实事故：**更新后 Web 面板的菜单整个点不动**。

根因是 `SCRIPT` 常量当时写成了普通三引号字符串（不是原始字符串），
于是源码里为 JS 字符串准备的 `\\n` 被 Python 在解析阶段转成了**真实换行**，
塞进 JS 的单引号字符串里 —— JS 语法错误。

后果不是"某个按钮失灵"，而是**整段脚本无法解析**：页面上的标签页切换、
所有按钮、轮询全部失效。而当时的测试只验了 HTML 渲染和 CSP 哈希，
**从来没有真正执行过 JS**，所以完全没拦住。

本文件补的就是这道缺口：
  1. 用 node --check 对每个内嵌 JS 常量做真正的语法检查；
  2. 校验 JS 常量没有被 Python 的转义处理动过（根因层防护）；
  3. 校验页面里的 script 块都来自常量（不出现会被 CSP 拦掉的游离内联脚本）。
"""
import ast
import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal

REPO_ROOT = Path(portal.__file__).parent
NODE = shutil.which('node')

JS_CONSTANTS = ('SCRIPT', 'LOGIN_SCRIPT', 'USER_SCRIPT')

# 前端资源常量已从 portal.py 拆到 portal_assets.py（portal.py 用 import 引入，
# 所以 portal.SCRIPT 这些名字照常可用）。查源码字面量时两个文件都要找。
SOURCE_FILES = ('portal.py', 'portal_assets.py')


class SavedOutboundProbeTests(unittest.TestCase):
    @unittest.skipUnless(NODE, 'requires node')
    def test_editing_direct_outbound_preserves_address_family_mode(self):
        script = portal.SCRIPT
        code = script[script.index('function obFillForm'):script.index('async function setOutboundMode')]
        save_start = script.index("obEls.btnSave.addEventListener('click'")
        save_end = script.index("if (obEls.list)", save_start)
        save = script[save_start:save_end]
        harness = r'''
const assert = require('assert');
const elements = {};
const control = id => elements[id] ||= {value:'', hidden:false, classList:{toggle:()=>{}},
 setAttribute:()=>{}, addEventListener:()=>{}, scrollIntoView:()=>{}, focus:()=>{},
 className:'', readOnly:false, textContent:''};
const document = {getElementById:control, querySelectorAll:()=>[]};
const window = {confirm:()=>true}; const OB_TYPE_LABEL={direct:{hint:'direct'}};
const OB_QUICK_HINT='quick'; let sent;
const obApi = async (action, params) => {sent={action,params}; return {ok:true};};
const obMsg=()=>{}; const loadOutbounds=async()=>{};
const obSetModeUI=()=>{}; const obNameLock=()=>{}; const obShowPass=()=>{};
const obTypeSwitch=()=>{}; const obOpenForm=()=>{}; const obResetForm=()=>{};
let obNameAuto=false; let saveHandler;
const obEls={name:control('name'),type:control('type'),socksAddr:control('addr'),
 socksUser:control('user'),socksPass:control('pass'),httpUrl:control('url'),
 httpInsecure:control('insecure'),directMode:control('directMode'),formTitle:control('title'),
 quickBox:{hidden:false},formCard:{hidden:false},btnSave:{disabled:false},btnCancel:null,
 quick:null,socksPass:{type:'password'},btnEye:null,msg:null,status:null};
'''
        checks = r'''
(async()=>{
obEls.type.value='direct'; obEls.directMode.value='4';
obFillForm({name:'direct_ipv4',type:'direct',mode:'4'});
assert.strictEqual(obEls.directMode.value,'4');
obEls.btnSave = {disabled:false, addEventListener:(event,fn)=>saveHandler=fn};
'''
        # Call the production save handler through its generated listener setup.
        save_body = save[save.index('    obMsg(\'保存中'):save.rindex('  });')]
        checks += 'const saveListener = async () => {\n' + save_body + '\n};\n' + r'''
await saveListener();
assert.strictEqual(sent.params.mode,'4');
})().catch(e=>{console.error(e);process.exitCode=1});
'''
        result = subprocess.run([NODE,'-e',harness+code+checks],capture_output=True,
                                text=True,encoding='utf-8')
        self.assertEqual(result.returncode,0,result.stderr)

    @unittest.skipUnless(NODE, 'requires node')
    def test_saved_http_proxy_probe_respects_insecure_setting(self):
        script = portal.SCRIPT
        self.assertIn('只检测所选出站端点的可达性，不代表已配置分流规则的实际出口',
                      portal.page_html({'server_name':'node.example','public_ip':'127.0.0.1',
                          'listen_port':443,'auth_password':'synthetic','obfs_password':'',
                          'is_insecure':False}, 'h://', 's', '{}', '{}', users={}, token='t',
                          session_secret='s'))
        code = script[script.index('function renderOutboundList'):script.index('function renderOutboundRules')]
        probe = script[script.index('async function probeOutbound'):script.index('function obResetForm')]

        harness = r'''
const assert = require('assert');
const nodes = {};
const list = {innerHTML:'', addEventListener:(kind, fn) => nodes.click=fn};
const ip = {textContent:'', offsetTop:300};
const note = {textContent:''};
const probeKind = {value:''}; const probeAddr = {value:'', hidden:false};
const document = {getElementById:id=>({'ob-list':list,'ob-outbound-ip':ip,
 'ob-outbound-ip-note':note,'ob-probe-kind':probeKind,'ob-probe-addr':probeAddr}[id] || null)};
const window = {scrollTo:()=>{}}; let captured;
const location = {pathname:'/token/'};
const fetch = async (url, opts) => {captured=opts; return {json:async()=>({ok:true,ip:'203.0.113.1'})};};
const obEls = {list,ip,ipNote:note,probeKind,probeAddr};
const OB_TYPE_LABEL={http:{label:'HTTP',cls:''}};
const obEsc = s=>String(s);
const obMetaOf = ()=>'';
'''
        checks = r'''
(async()=>{
renderOutboundList([{name:'tls-proxy',type:'http',url:'https://proxy.example:8080',insecure:true}]);
assert(list.innerHTML.includes('data-ob-insecure="true"'));
'''
        # Execute the real row-click listener and prove it forwards the saved flag.
        click = script[script.index("if (obEls.list) {"):script.index('if (obEls.rulesList)')]
        checks += r'''
''' + click + r'''
await nodes.click({target:{closest:selector => selector === '[data-ob-test]' ? {
  getAttribute:key=>({'data-ob-kind':'http','data-ob-addr':'https://proxy.example:8080',
                      'data-ob-insecure':'true'}[key] || '')
} : null}, preventDefault:()=>{}});
assert.strictEqual(captured.method,'POST');
const body = new URLSearchParams(captured.body);
assert.strictEqual(body.get('insecure'),'true');
assert(!captured.body.includes('username') && !captured.body.includes('password'));
})().catch(e=>{console.error(e);process.exitCode=1});
'''
        result = subprocess.run([NODE,'-e',harness+code+probe+checks],capture_output=True,
                                text=True,encoding='utf-8')
        self.assertEqual(result.returncode,0,result.stderr)


class AwgPeerPopupBehaviorTests(unittest.TestCase):
    @unittest.skipUnless(NODE, 'requires node')
    def test_peer_add_opens_config_tab_during_click_and_closes_on_failure(self):
        script = portal.SCRIPT
        start = script.index('if (btnAddAwgPeer) {')
        end = script.index('\n}', start) + 2
        code = script[start:end]
        harness = r'''
const assert = require('assert');
let handler, nextTab = {location:'about:blank', closed:false, close(){this.closed=true;}};
let resolvePost; const opened=[]; const alerts=[]; const toasts=[];
const btnAddAwgPeer={disabled:false,addEventListener:(event,fn)=>handler=fn};
const awgPeerName={value:'peer-1'}, awgPeerEndpoint={value:'vpn.example:51820'};
const window={open:(url,target)=>{opened.push([url,target]);return nextTab;}};
const location={pathname:'/token/'};
const alert=text=>alerts.push(text); const showToast=(...args)=>toasts.push(args);
const loadAwgState=()=>{};
let response={ok:true};
const awgPost=(...args)=>new Promise(resolve=>{resolvePost=()=>resolve(response);});
'''
        checks = r'''
(async()=>{
const pending=handler();
assert.deepStrictEqual(opened,[['about:blank','_blank']]);
assert.strictEqual(btnAddAwgPeer.disabled,true);
response={ok:true}; resolvePost(); await pending;
assert.strictEqual(nextTab.location,'/token/awg-conf?name=peer-1&endpoint=vpn.example%3A51820');
assert.strictEqual(btnAddAwgPeer.disabled,false);
assert.strictEqual(awgPeerName.value,'');
assert.strictEqual(toasts.length,1);
const failedTab={location:'about:blank',closed:false,close(){this.closed=true;}};
nextTab=failedTab; awgPeerName.value='peer-2';
response={ok:false,error:'rejected'};
const failed=handler(); resolvePost(); await failed;
assert.strictEqual(failedTab.closed,true, 'failure should close the pre-opened tab');
assert(alerts.includes('rejected'), 'failure should be reported');
assert.strictEqual(btnAddAwgPeer.disabled,false, 'button should be restored');
})().catch(e=>{console.error(e);process.exitCode=1});
'''
        result = subprocess.run([NODE, '-e', harness + code + checks], capture_output=True,
                                text=True, encoding='utf-8')
        self.assertEqual(result.returncode, 0, result.stderr)


class VersionUiBehaviorTests(unittest.TestCase):
    @unittest.skipUnless(NODE, 'requires node')
    def test_production_version_check_four_states(self):
        script = portal.SCRIPT
        code = script[script.index('// 版本检测与一键更新交互'):script.index('async function waitForCoreUpgrade')]
        harness = r'''
const assert = require('assert');
const elements = {};
const document = {getElementById: id => elements[id] ||= {style: {}, textContent: ''}};
const location = {pathname: '/fixture/'};
let payload;
const fetch = async () => ({ok:true, json:async () => payload});
const doUpgrade = () => {};
'''
        checks = r'''
(async () => {
  for (const state of ['current', 'update', 'unknown', 'partial']) {
    payload = {ok:true, core_current:'2.6.4', core_latest:'2.6.4',
      portal_current:'aaaaaaa', portal_latest:state === 'current' ? 'aaaaaaa' : state === 'update' ? 'bbbbbbb' : '',
      portal_has_update:['update','partial'].includes(state),
      portal_update_status:state === 'unknown' ? 'unknown' : state === 'current' ? 'up_to_date' : 'update_available',
      awg_installed:false};
    assert.strictEqual(await checkVersions(), true);
    const text = elements['portal-ver-display'].textContent;
    assert.strictEqual(elements['btn-update-portal'].style.display,
      payload.portal_has_update ? 'inline-flex' : 'none');
    if (state === 'current') assert(text.includes('（最新）'));
    if (state === 'unknown') {assert(text.includes('无法确认')); assert(!text.includes('（最新）'));}
    if (payload.portal_has_update) assert(text.includes('有新版本'));
    if (state === 'partial') assert(text.includes('部分文件'));
  }
})().catch(e => {console.error(e); process.exitCode = 1;});
'''
        result = subprocess.run([NODE, '-e', harness + code + checks], capture_output=True,
                                text=True, encoding='utf-8')
        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(NODE, 'requires node')
    def test_production_vmess_card_states(self):
        """VMess 卡片的三态：未装核心、已关闭、运行中。

        重点不是文案，而是「不能把状态说反」：
          * 没装 Xray 不能显示成「已关闭」（否则用户以为点一下就能开）；
          * 运行中必须显示端口与直链，且开关文案是「点击关闭」。
        """
        script = portal.SCRIPT
        code = script[script.index('const vmessBadge'):script.index('// BBR 状态获取')]
        harness = r'''
const assert = require('assert');
const elements = {};
const document = {getElementById: id => elements[id] ||= {
  style: {}, textContent: '', value: '', disabled: false,
  addEventListener: () => {}, className: ''}};
const location = {pathname: '/fixture/'};
const navigator = {clipboard: {writeText: async () => {}}};
let payload;
const fetch = async () => ({ok:true, json:async () => payload});
const alert = m => {throw new Error('unexpected alert: ' + m)};
const setTimeout = () => {};
'''
        checks = r'''
(async () => {
  const badge = elements['vmess-badge'];
  const toggle = elements['btn-toggle-vmess'];
  const box = elements['vmess-content-box'];

  payload = {ok:true, installed:false, active:false, config:{}};
  await checkVmessStatus();
  assert(badge.textContent.includes('未安装'), badge.textContent);
  assert.strictEqual(toggle.style.display, 'none');
  assert.strictEqual(box.style.display, 'none');

  payload = {ok:true, installed:true, active:false, config:{}};
  await checkVmessStatus();
  assert(badge.textContent.includes('已关闭'), badge.textContent);
  assert(toggle.textContent.includes('点击开启'), toggle.textContent);
  assert.strictEqual(box.style.display, 'none');

  payload = {ok:true, installed:true, active:true, config:{port:2087,
    domain:'node.example.com', sni:'node.example.com', uuid:'u-1',
    ws_path:'/AbCdEf123456', uri:'vmess://abc', qr_svg:'<svg></svg>'}};
  await checkVmessStatus();
  assert(badge.textContent.includes('2087'), badge.textContent);
  assert(toggle.textContent.includes('点击关闭'), toggle.textContent);
  assert.strictEqual(box.style.display, 'block');
  assert.strictEqual(elements['vmess-uri-val'].value, 'vmess://abc');
  assert.strictEqual(elements['vmess-path-val'].textContent, '/AbCdEf123456');
})().catch(e => {console.error(e); process.exitCode = 1;});
'''
        result = subprocess.run([NODE, '-e', harness + code + checks], capture_output=True,
                                text=True, encoding='utf-8')
        self.assertEqual(result.returncode, 0, result.stderr)


def _find_literal(name):
    """在两个源文件里找常量定义，返回 (文件路径, 源码字面量原文)。"""
    for fname in SOURCE_FILES:
        path = REPO_ROOT / fname
        if not path.exists():
            continue
        src = path.read_text(encoding='utf-8')
        for node in ast.parse(src).body:
            if (isinstance(node, ast.Assign)
                    and isinstance(node.value, ast.Constant)
                    and isinstance(node.value.value, str)
                    and isinstance(node.targets[0], ast.Name)
                    and node.targets[0].id == name):
                return path, ast.get_source_segment(src, node.value)
    return None, None


def _source_literal(name):
    return _find_literal(name)[1]


def _literal_body(segment):
    """去掉三引号，返回 (是否原始字符串, 字面量内部原文)。"""
    m = re.match(r'^([rRbB]{0,2})("""|\'\'\')', segment)
    if not m:
        return False, segment
    prefix, quote = m.group(1), m.group(2)
    return ('r' in prefix.lower()), segment[len(m.group(0)):-len(quote)]


class JsAssetTest(unittest.TestCase):
    """内嵌 JS 的语法与转义完整性。"""

    def test_constants_are_raw_strings(self):
        """JS 常量必须写成原始字符串（r\"\"\"）。

        这是根因层防护：只要用了原始字符串，源码里写的 \\n 就会原样进到 JS，
        不会再被 Python 悄悄转成真实换行。
        """
        for name in JS_CONSTANTS:
            seg = _source_literal(name)
            self.assertIsNotNone(seg, f'找不到常量 {name} 的源码字面量')
            is_raw, _ = _literal_body(seg)
            self.assertTrue(
                is_raw,
                f'{name} 必须写成原始字符串（r"""）。否则源码里的 \\n 会被 Python '
                f'解析成真实换行塞进 JS 字符串，造成语法错误 —— 整段脚本都会失效。')

    def test_no_python_escape_processing(self):
        """JS 常量的求值结果必须与源码字面量逐字符相同。

        等价于「Python 没有对内容做任何转义处理」。任何差异都意味着有 \\n / \\t 之类
        的序列被吃掉了 —— 这正是那次事故的成因。
        """
        for name in JS_CONSTANTS:
            seg = _source_literal(name)
            _, body = _literal_body(seg)
            value = getattr(portal, name)
            if body != value:
                # 定位第一处差异，便于排查
                i = next((k for k in range(min(len(body), len(value)))
                          if body[k] != value[k]), min(len(body), len(value)))
                ctx = repr(body[max(0, i - 40):i + 20])
                self.fail(f'{name} 的内容被 Python 转义处理过（首个差异在第 {i} 字符附近: {ctx}）。'
                          f'请把该常量写成原始字符串 r"""。')

    @unittest.skipUnless(NODE, '需要 node 才能做 JS 语法检查（CI 的 runner 自带）')
    def test_js_syntax_with_node(self):
        """用 node --check 做真正的 JS 语法检查。

        这是唯一能拦住「语法错误导致整段脚本失效」的手段 ——
        只验 HTML 渲染和 CSP 哈希是拦不住的。
        """
        import tempfile
        for name in JS_CONSTANTS:
            code = getattr(portal, name)
            with tempfile.NamedTemporaryFile('w', suffix='.js', delete=False,
                                             encoding='utf-8', newline='\n') as fh:
                fh.write(code)
                path = fh.name
            try:
                proc = subprocess.run([NODE, '--check', path],
                                      capture_output=True, text=True, timeout=60)
                self.assertEqual(
                    proc.returncode, 0,
                    f'{name} 存在 JS 语法错误（整段脚本都会失效，页面按钮全部失灵）:\n'
                    f'{(proc.stderr or proc.stdout)[:800]}')
            finally:
                Path(path).unlink(missing_ok=True)

    def test_page_has_no_stray_inline_script(self):
        """页面里的 <script> 块必须全部来自常量。

        门户的 CSP 是「脚本内容的 sha256 白名单」，游离的内联 <script>
        没有对应哈希，会被浏览器直接拒绝执行。
        """
        meta = {'public_ip': '1.2.3.4', 'server_name': 'h.example.com',
                'subscription_port': 8443, 'listen_port': 1, 'hop_port_range': '',
                'auth_password': 'p', 'obfs_password': '', 'cert_type': 'acme',
                'is_insecure': False, 'pin_sha256': ''}
        page = portal.page_html(meta, 'hysteria2://x@h:1/', '#s', 'c', '{}',
                                users={}, api_key=None, token='t', session_secret='s')
        blocks = re.findall(r'<script[^>]*>(.*?)</script>', page, re.S)
        known = {getattr(portal, n).strip() for n in JS_CONSTANTS}
        for i, block in enumerate(blocks, 1):
            self.assertIn(block.strip(), known,
                          f'页面第 {i} 个 <script> 块不是任何已知常量 —— '
                          f'它没有 CSP 哈希，浏览器会拒绝执行。')

    def test_csp_hash_covers_every_script_constant(self):
        """CSP 必须为每个会被内联注入的脚本常量提供 sha256。"""
        import base64
        import hashlib
        policy = portal.content_policy()
        for name in JS_CONSTANTS:
            digest = base64.b64encode(
                hashlib.sha256(getattr(portal, name).encode()).digest()).decode()
            self.assertIn('sha256-' + digest, policy,
                          f'CSP 缺少 {name} 的 sha256，该脚本会被浏览器拒绝执行')
        script_src = policy.split('script-src', 1)[1].split(';', 1)[0]
        self.assertNotIn('unsafe-inline', script_src)
        # 内联 style 属性必须被放行：哈希只覆盖 <style> 块，页面大量用
        # style="..." 做颜色/宽度，不放行会静默丢样式（2026-10-29 实测）。
        self.assertIn("style-src-attr 'unsafe-inline'", policy)


class SourceHygieneTest(unittest.TestCase):
    """portal.py 源码层面的卫生检查（下面每条都是真实踩过的坑）。"""

    def test_no_function_level_imports(self):
        """禁止**函数内** import。

        Python 的作用域规则：只要函数体里**任何位置**出现 `import X`，
        整个函数内的 `X` 都被当作局部名；若在 import 语句执行之前使用它，
        就会抛 UnboundLocalError。

        真实事故：`install-gost` 分支用了 `os.chmod`，而 `import os` 只出现在
        `do_POST` 的另一个分支（do-upgrade）里 —— 于是"一键安装 gost"必然失败，
        而且报错被后续下载源的错误覆盖，只显示一个无关的 DNS 失败，极难定位。
        把 import 全部提到模块级可以从根上消除这类 bug。

        ⚠️ 只针对**函数内**：模块级的 `try: import x except ImportError:` 是
        合法且必要的写法（用于给出人话错误），不能一并算作违规 —— 这里靠
        追踪每个 import 的最近函数祖先把两者区分开。
        """
        offenders = []
        for fname in SOURCE_FILES:
            path = REPO_ROOT / fname
            if not path.exists():
                continue
            src = path.read_text(encoding='utf-8')
            tree = ast.parse(src)

            def walk(node, in_function):
                for child in ast.iter_child_nodes(node):
                    now = in_function or isinstance(
                        child, (ast.FunctionDef, ast.AsyncFunctionDef))
                    if isinstance(child, (ast.Import, ast.ImportFrom)) and now:
                        offenders.append((fname, child.lineno,
                                          ast.get_source_segment(src, child)))
                    walk(child, now)

            walk(tree, False)

        self.assertEqual(
            offenders, [],
            '发现函数内 import（必须提到模块级，否则会造成 UnboundLocalError）:\n' +
            '\n'.join('  %s 第 %d 行: %s' % (f, ln, seg) for f, ln, seg in offenders))

    def test_core_modules_are_module_level(self):
        """os / shutil / platform / tempfile 等必须在模块级导入。

        这些是各处理器共用的基础模块；只在个别分支里导入，就会形成
        「某分支能用、另一分支报 UnboundLocalError」的隐蔽差异。
        """
        src = Path(portal.__file__).read_text(encoding='utf-8')
        tree = ast.parse(src)
        names = set()
        for node in tree.body:
            if isinstance(node, ast.Import):
                for a in node.names:
                    names.add((a.asname or a.name).split('.')[0])
            elif isinstance(node, ast.ImportFrom):
                for a in node.names:
                    names.add(a.asname or a.name)
        for mod in ('os', 'shutil', 'platform', 'tempfile', 'urllib', 'hashlib',
                    'tarfile', 'zipfile', 'uuid'):
            self.assertIn(mod, names, f'{mod} 必须在模块级导入')


if __name__ == '__main__':
    unittest.main()
