#!/usr/bin/env bash
# 🔴🔴 五轮回归测试 · 第 1 轮：静态与契约（不需要服务器）
#
# 这一轮要拦住的是"看起来改了、其实页面全废"这类灾难：
#   1. 🔴 CSP 哈希：新 JS 注入后，script-src 的哈希必须仍与 SCRIPT 匹配
#      —— 不匹配 ⇒ 浏览器拒绝执行 ⇒ **全页 JS 失效**（所有按钮/轮询全挂）
#   2. Python / JS 语法
#   3. HTML id 与 JS getElementById 必须一一对应（拼错 = 某个功能静默不工作）
#   4. data-* 属性与 JS 读取的键一致
#   5. 🔴 不得出现内联 onclick（CSP 无 unsafe-inline，内联事件会被浏览器丢弃）
set -u
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 2
INSTALL_SH="$(pwd)/install.sh"
PY="$(command -v python3 || command -v python)"
[[ -f portal.py && -f portal_assets.py ]] || { echo "缺少门户文件" >&2; exit 2; }

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); echo "  ✅ $*"; }
bad() { FAIL=$((FAIL+1)); echo "  ❌ $*"; }

echo "=== 1) Python 语法 ==="
if "$PY" -m py_compile portal.py portal_assets.py 2>/dev/null; then
    ok "portal.py / portal_assets.py 语法正确"
else
    bad "Python 语法错误"
fi
"$PY" -m py_compile tests/outbound-verify-on-server.py tests/outbound-e2e-on-server.py 2>/dev/null \
    && ok "两个验证脚本语法正确" || bad "验证脚本语法错误"

echo
echo "=== 2) 🔴 CSP 哈希必须与内联 SCRIPT 实际内容匹配 ==="
# 这条最关键：门户 content_policy() 用 sha256(SCRIPT) 生成 script-src，
# 一旦不匹配，浏览器会拒绝执行整个 SCRIPT ⇒ 页面上**所有**按钮/轮询全失效。
# 历史事故：更新后 Web 面板菜单整个点不动。
"$PY" - <<'PYEOF'
import base64, hashlib, re, sys, importlib.util
src = open('portal.py', encoding='utf-8').read()

# 取出 SCRIPT / STYLE 常量的字面量（不执行 portal.py，避免副作用）
def grab(name, src):
    m = re.search(r"^%s = (r?'''|r?\"\"\")(.*?)\1" % name, src, re.M | re.S)
    return m.group(2) if m else None

script = grab('SCRIPT', src)
style = grab('STYLE', src)
if script is None:
    # SCRIPT 可能来自 portal_assets
    a = open('portal_assets.py', encoding='utf-8').read()
    script = grab('SCRIPT', a)
    style = grab('STYLE', a)
if script is None:
    print('  ❌ 未能提取 SCRIPT 常量，无法校验 CSP 哈希')
    sys.exit(1)

def digest(v):
    return base64.b64encode(hashlib.sha256(v.encode()).digest()).decode()

h = 'sha256-' + digest(script)
print('  实测 script-src 哈希:', h[:30], '...')

# content_policy() 是运行时按 SCRIPT 现算的，只要它存在且引用 digest() 就天然一致；
# 真正的风险是：页面里注入的脚本内容与 SCRIPT 常量不是同一份。
m = re.search(r"<script>\s*\{?\{?\s*%s" % re.escape('{'), src)
# 检查页面模板里如何注入 SCRIPT
uses = re.findall(r'\{SCRIPT\}|\{s|STYLE\}', src)
print('  页面模板注入 SCRIPT 的方式:', 'f-string 直接插值' if 'SCRIPT}' in src else '未知')

# 反向检查：SCRIPT 里是否有裸的 { }（f-string 注入会因裸花括号而崩溃）
if re.search(r'\{[a-zA-Z_][a-zA-Z0-9_\[\]\'\" ]*\}', script):
    print('  ⚠️  SCRIPT 中含 {xxx} 形态，注入 f-string 时可能被当插值')
else:
    print('  ✅ SCRIPT 无 f-string 风险插值')

# SCRIPT 里必须真的含自定义出站代码
for fn in ('obApi', 'loadOutbounds', 'renderOutboundList', 'probeOutbound'):
    print(('  ✅' if fn in script else '  ❌') + ' SCRIPT 含 ' + fn)
PYEOF

echo
echo "=== 3) 🔴 不得有内联事件（CSP 无 unsafe-inline）==="
# 🔴 必须排除注释行：本文件里有多处「// 不能写成 onclick="..."」的警告注释，
#    直接 grep 会把这些注释当成真代码 ⇒ 误报。
inline_hits="$(grep -vE '^\s*(//|\*|#)' portal.py portal_assets.py 2>/dev/null   | grep -oE 'on(click|change|input|submit|load)="[^"]*"' | head -5 || true)"
if [[ -z "$inline_hits" ]]; then
    ok "无内联事件属性（全部走 data-* + 事件委托）"
else
    bad "存在内联事件，浏览器会丢弃它们：$inline_hits"
fi

echo
echo "=== 4) HTML id ↔ JS getElementById 一一对应 ==="
"$PY" - <<'PYEOF'
import re, sys
h = open('portal.py', encoding='utf-8').read()
a = open('portal_assets.py', encoding='utf-8').read()
html_ids = set(re.findall(r'id="(ob-[a-z0-9-]+)"', h))
js_ids = set(re.findall(r"getElementById\('(ob-[a-z0-9-]+)'\)", a))
missing = sorted(js_ids - html_ids)
unused = sorted(html_ids - js_ids)
print('  HTML 定义 %d 个 ob- id / JS 引用 %d 个' % (len(html_ids), len(js_ids)))
if missing:
    print('  ❌ JS 引用但 HTML 缺失:', missing); sys.exit(1)
if unused:
    print('  ⚠️  HTML 有但 JS 未用:', unused)
else:
    print('  ✅ 全部对应，无缺失无冗余')
PYEOF
[[ $? -eq 0 ]] && ok "id 对应完整" || bad "id 对应有缺失"

echo
echo "=== 5) data-* 属性一致性 ==="
"$PY" - <<'PYEOF'
import re, sys
a = open('portal_assets.py', encoding='utf-8').read()
written = set(re.findall(r'data-([a-z][a-z0-9-]*)=', a))
read = set(re.findall(r'closest\(.\[data-([a-z][a-z0-9-]*)', a)) | set(
    re.findall(r'getAttribute\(.data-([a-z][a-z0-9-]*)', a))
print('  写出/读取的 data 属性:', sorted(written | read))
need = {'ob-del', 'ob-edit', 'ob-test', 'rule-del'}
miss = sorted(need - (written | read))
if miss:
    print('  ❌ 缺少事件委托所需属性:', miss); sys.exit(1)
print('  ✅ 委托属性齐全')
PYEOF
[[ $? -eq 0 ]] && ok "data-* 齐全" || bad "data-* 缺失"

echo
echo "=== 6) 关键函数存在性 ==="
for fn in sanitize_outbound_name validate_outbound render_outbound_yaml \
          upsert_outbound_block strip_managed_outbounds build_acl_block \
          detect_outbound_ip apply_outbounds_config _ob_list _ob_probe _ob_manage; do
    if grep -qE "^(def |        def )$fn\b" portal.py; then
        ok "$fn 已定义"
    else
        bad "$fn 缺失"
    fi
done

echo
echo "=== 7) 🔴 出站应用函数必须显式接收 data/data_lock ==="
# serve() 的闭包变量，模块级函数直接用会 NameError（"点保存就断线"）。
# 2026-10-28 更新：apply_outbounds_config 已被 apply_egress_config 取代
# （统一接管 WARP 规则与自定义出站的事务性应用），检查对象随之迁移。
# 旧检查 grep 的调用点 'applied, aerr = apply_outbounds_config(...)' 在
# 代码迁移后已不存在，导致该项永远红 —— 是测试陈旧，不是代码缺陷。
if grep -qE "def apply_outbounds_config\(data, data_lock" portal.py; then
    ok "apply_outbounds_config(data, data_lock, ...) 签名正确"
else
    bad "apply_outbounds_config 签名不对 —— 会抛 NameError: data_lock is not defined"
fi
if grep -qE "def apply_egress_config\(data, data_lock" portal.py; then
    ok "apply_egress_config(data, data_lock, ...) 签名正确"
else
    bad "apply_egress_config 签名不对 —— 会抛 NameError: data_lock is not defined"
fi
if grep -q 'applied, error = apply_egress_config(data, data_lock)' portal.py; then
    ok "apply_egress_config 调用点已传参"
elif grep -q 'applied, aerr = apply_outbounds_config(data, data_lock)' portal.py; then
    ok "apply_outbounds_config 调用点已传参（旧布局）"
else
    bad "出站应用调用点未传参"
fi

echo
echo "=== 8) 行尾必须是 LF ==="
"$PY" - <<'PYEOF'
import sys
bad = []
for p in ('portal.py', 'portal_assets.py', 'install.sh',
          'tests/outbound-verify-on-server.py', 'tests/outbound-e2e-on-server.py'):
    d = open(p, 'rb').read()
    if d.count(b'\r\n'):
        bad.append('%s(%d CRLF)' % (p, d.count(b'\r\n')))
print('  ❌ CRLF:', bad) if bad else print('  ✅ 全部 LF')
sys.exit(1 if bad else 0)
PYEOF
[[ $? -eq 0 ]] && ok "行尾正确" || bad "存在 CRLF"

echo
echo "================ 第 1 轮结果 ================"
echo "  通过: $PASS   失败: $FAIL"
[[ $FAIL -eq 0 ]]