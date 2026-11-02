#!/usr/bin/env bash
# 验证 ACME 前置的端口占用检测与证书复用逻辑。
#
#🔴 这条路径要解决的是 2026-10-08 真实遇到的问题：
#   机器上已跑 Caddy（占TCP 80/443 + UDP 443），Hysteria 内置 ACME
#   的两种验证方式（HTTP-01 需 80、tls-alpn 需 443）全部不可用 ⇒ 签发必然失败
#   ⇒ 退回自签证书 ⇒ 客户端必须开"跳过证书校验"，表现为"装好了但连不上"。
#
# 本测试必须证明：
#   1. 端口占用能被检出，且报出占用者进程名
#   2. 🔴 ss 解析失败时**不能静默报"空闲"**（这是实现里真实踩过的坑）
#   3. 空闲端口不误报占用
#   4. 只含叶证书的 .crt 不算可复用（Go 系客户端会报 unknown authority）
#   5. setup_acme_certificate 在端口被占时**不再直接走内置 ACME**，
#      而是给出可执行的替代路径
set -u

# 🔴 定位 install.sh：**必须用相对当前目录的路径**。
# 之前写死 `/f/github/hysteria2-installer/install.sh`（开发机的 Windows 路径），
# 在服务器/CI 上跑时 sed 直接失败 → 函数没被 source → `port_owner: command not found`
# → 变量为空 → 被误判成"端口空闲"。
# 更糟的是：**被测代码完全没被执行**，用例却报了一个像模像样的失败结论。
cd "$(dirname "${BASH_SOURCE[0]}")/.." || { echo "无法定位仓库根目录" >&2; exit 2; }
INSTALL_SH="$(pwd)/install.sh"
if [[ ! -f "$INSTALL_SH" ]]; then
    echo "❌ 找不到 install.sh（当前期望位置: $INSTALL_SH）" >&2
    exit 2
fi
# 🔴 从 install.sh 抽取指定函数的完整定义。
#
# 🔴🔴 绝对不能用 `sed -n '/^fn() {/,/^}/p'`：
# 函数体内的 case 分支、多行条件里也有 `}`，sed 会在那里提前截断，
# 抽出来的是**残缺函数**，表现为满屏 `command not found`，
# 而用例却会拿空函数得出看似合理的结论。
# 2026-10-08 实测踩到：给 find_cert_in_webserver 加了内层循环后，
# 本文件从16 项全绿变成 15 项（静默失效）—— 没有报错，只是悄悄少测一项。
#
# 用 awk 做花括号配平：从函数头开始，直到该函数自己的 } 为止。
extract_fn() {
    awk -v want="$1" '
        index($0, want "() {") == 1 { inside = 1; depth = 0 }
        inside {
            print
            n = gsub(/\{/, "{"); depth += n
            m = gsub(/\}/, "}"); depth -= m
            if (depth == 0) { exit }
        }
    ' "$INSTALL_SH"
}

for fn in port_owner detect_webserver_squatting find_cert_in_webserver \
          pem_cert_count _accept_cert_pair _nginx_cert_candidates; do
    _f="$(extract_fn "$fn")"
    if [[ -z "$_f" ]]; then
        echo "❌ 未能从 install.sh 提取到函数 $fn（脚本结构变了？）" >&2
        exit 2
    fi
    eval "$_f"
    # 🔴 提取后必须确认真的定义出来了，否则会拿着空函数得出"全绿"假结论
    if ! declare -F "$fn" >/dev/null; then
        echo "❌ 函数 $fn 提取后无法加载" >&2
        exit 2
    fi
done
log_warn() { echo "  [WRN] $*"; }

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); echo "  ✅ $*"; }
bad() { FAIL=$((FAIL+1)); echo "  ❌ $*"; }

echo "=== 1) 端口占用检测 ==="
own80="$(port_owner tcp 80)"
if [[ -n "$own80" ]]; then
    ok "TCP 80 检出占用者: $own80"
else
    echo "  ⚠️本机 80 空闲，跳过占用检测用例（正常，检测函数仍会被求值）"
fi

echo
echo "=== 2) 🔴 空闲端口不得误报 ==="
# 用一个几乎不可能被占的高位端口做反向验证
_free_port=45999
if [[ -z "$(port_owner tcp $_free_port)" ]]; then
    ok "空闲端口 $_free_port 正确报为空"
else
    bad "空闲端口 $_free_port 被误报占用: $(port_owner tcp $_free_port)"
fi

echo
echo "=== 3) 🔴 ss 不可用时不能静默报空闲（回归测试）==="
# 把 ss 屏蔽掉，模拟 iproute2 缺命令/参数不认的情况。
# 正确行为：退到 python3 bind 探测，仍能识别出"被占"。
# 真实坑：`ss -H -"${proto}"ln` 里 proto=tcp 会拼成 `-tcln`，
# iproute2 直接报错退出、被 2>/dev/null 吞掉 ⇒ 明明被占却报空闲。
_tmpbin="$(mktemp -d)"
cat > "$_tmpbin/ss" <<'EOF'
#!/bin/sh
echo "ss: invalid option -- 'x'" >&2
exit 1
EOF
chmod +x "$_tmpbin/ss"
# ⚠️ 不能只靠 80 端口验证：CI/开发机上 80 往往空闲，那样本用例恒绿 = 没测。
# 这里自己占一个端口来制造"确实被占"，与运行环境无关。
#占位程序写成独立文件而不是 python3 -c：内层引号嵌套极易把
# 转义序列（如 \n）提前变成真实换行，直接把 Python 语法写崩、
# 进程秒退、端口随之释放，于是用例测的其实是"空闲端口"→ 恒绿或恒红皆无意义。
_hold_port=45987
_holdscript="$(mktemp -d)/hold.py"
cat > "$_holdscript" <<'PYEOF'
import socket, sys, time
s = socket.socket()
s.bind(("0.0.0.0", int(sys.argv[1])))
s.listen(1)
sys.stderr.write("held\n")
sys.stderr.flush()
time.sleep(60)
PYEOF
python3 "$_holdscript" "$_hold_port" 2>/tmp/_hold.log &
_holder=$!
for _i in $(seq 1 30); do
    grep -q held /tmp/_hold.log 2>/dev/null && break
    sleep 0.3
done
if ! kill -0 "$_holder" 2>/dev/null; then
    bad "占位进程已退出（测试自身问题，非被测代码问题），无法执行本用例"
elif ! grep -q held /tmp/_hold.log 2>/dev/null; then
    bad "未能占用测试端口 $_hold_port，本用例无法执行"
else
    # 🔴 确认端口真的被占住了 —— 前提不成立就别往下测，否则测的是空气
    if [[ -z "$(ss -tln 2>/dev/null | grep ":${_hold_port} ")" ]]; then
        bad "占位进程声称已 bind，但 ss 看不到 ${_hold_port}，本用例跳过"
    else
    # 🔴 不再用 `bash -c "source ... <<X"` 起子shell 测：
    #    source 失败时函数未定义，但后面的 port_owner 照样执行，
    #    `command not found` 被 2>/dev/null 吞掉 ⇒变量为空 ⇒ 误判"空闲"。
    #    那种写法测的是"子shell 能不能起"，不是"被测代码对不对"。
    #    现在直接在当前 shell 调用，并先自证函数确实存在。
    if ! declare -F port_owner >/dev/null; then
        bad "port_owner() 未被正确加载，用例无法验证被测代码（测试自身问题）"
    else
    # 端口被真占着，且 ss 被屏蔽 => 只能靠 python3 兜底识别
    _prev_path="$PATH"; PATH="$_tmpbin:$PATH"
    who="$(port_owner tcp "$_hold_port")"
    free_out="$(port_owner tcp 45998)"
    PATH="$_prev_path"
    if [[ -n "$who" ]]; then
        ok "ss 失效时仍检出 ${_hold_port} 被占（python3 兜底，报 $who）"
    else
        bad "ss 失效时把「被占」误报成「空闲」—— ACME 会走上必然失败的路"
    fi
    if [[ -z "$free_out" ]]; then
        ok "ss 失效时空闲端口 45998 仍正确报空（无误报）"
    else
        bad "ss 失效时把空闲端口误报为占用: $free_out"
    fi
    fi # 内层：确认端口确实被占
    fi # 函数已加载
fi
kill "$_holder" 2>/dev/null || true
wait "$_holder" 2>/dev/null || true
rm -rf "$_tmpbin" "$(dirname "$_holdscript")" /tmp/_hold.log

echo
echo "=== 4) 证书复用：必须含完整链（>=2 张）==="
_probe="$(mktemp -d)"
# 用 CADDY_CERT_ROOT 注入，指向真实布局：<root>/<ca>/<domain>/<domain>.crt
_chain="$_probe/acme-v02.example.org-dir/hy2.test.com"
mkdir -p "$_chain"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$_chain/hy2.test.com.key" \
    -out "$_chain/hy2.test.com.crt" -days 1 -subj "/CN=hy2.test.com" >/dev/null 2>&1

export CADDY_CERT_ROOT="$_probe"
# 单张（叶证书）不应被采纳
if find_cert_in_webserver hy2.test.com >/dev/null 2>&1; then
    bad "只有叶证书（1 张）竟被当成可复用的完整链 —— Go 系客户端会握手失败"
else
    ok "仅叶证书被正确拒绝"
fi
# 补上中间证书 -> 应被采纳
cat "$_chain/hy2.test.com.crt" "$_chain/hy2.test.com.crt" > "$_chain/tmp2" && mv "$_chain/tmp2" "$_chain/hy2.test.com.crt"
if find_cert_in_webserver hy2.test.com >/dev/null 2>&1; then
    ok "含完整链（2 张）时被正确识别为可复用"
else
    bad "完整链仍未被识别"
fi
# 只有 crt 没有 key 时不可复用（缺私钥没法用）
rm -f "$_chain/hy2.test.com.key"
if find_cert_in_webserver hy2.test.com >/dev/null 2>&1; then
    bad "缺私钥时仍被判为可复用"
else
    ok "缺私钥时正确拒绝"
fi
unset CADDY_CERT_ROOT
rm -rf "$_probe"

echo
echo "=== 5) 🔴 端口被占时 setup_acme_certificate 必须绕开内置 ACME ==="
_src="$(sed -n '/^setup_acme_certificate() {/,/^}/p' "$INSTALL_SH")"
if grep -q 'detect_webserver_squatting' <<<"$_src"; then
    ok "setup_acme_certificate 内含端口占用预检"
else
    bad "setup_acme_certificate 仍完全不管端口占用 —— 真实机器上必然失败"
fi
# 预检必须排在 DNS 校验之前：端口被占时，再怎么校验 DNS 都没意义
_pre_line="$(grep -n 'detect_webserver_squatting' <<<"$_src" | head -1 | cut -d: -f1)"
_dns_line="$(grep -n 'verify_domain_resolves_to_this_host' <<<"$_src" | head -1 | cut -d: -f1)"
if [[ -n "$_pre_line" && -n "$_dns_line" && "$_pre_line" -lt "$_dns_line" ]]; then
    ok "端口预检排在 DNS 校验之前（顺序正确）"
else
    bad "端口预检位置不对（pre=${_pre_line:-无} dns=${_dns_line:-无}）"
fi
# 复用成功后必须设SNI 为真实域名，且 insecure=false
if grep -q 'SERVER_NAME="\$SERVER_NAME"' <<<"$_src" && grep -q 'IS_INSECURE="false"' <<<"$_src"; then
    ok "复用证书时 SNI 设为真实域名且 insecure=false"
else
    bad "复用分支未正确设置 SNI / IS_INSECURE（客户端仍会要求跳过校验）"
fi

echo
echo "=== 6) 🔴 复用失败后不得滑回内置 ACME（必须走 DNS API 兜底）==="
# 背景：端口被占时内置 ACME 必然失败。早期实现签发失败后直接继续往下走
# 内置 ACME，白白浪费一轮，末尾报错还会把用户引向"检查网络"的错误方向。
_acme_src="$(sed -n '/^setup_acme_certificate() {/,/^}/p' "$INSTALL_SH")"
if grep -qE '继续尝试内置 ACME|大概率失败' <<<"$_acme_src"; then
    bad "复用失败后仍在提示「继续尝试内置 ACME」—— 明知必然失败还去试"
else
    ok "复用失败后不再滑回内置 ACME"
fi
# 必须存在 DNS API 兜底
if grep -q 'setup_cert_via_dns_api' <<<"$_acme_src"; then
    ok "存在 DNS API 兜底调用"
else
    bad "端口被占且借反代失败后没有任何兜底路径，只能退回自签"
fi
# DNS API 必须早于自签回落
_dns_pos="$(grep -n 'setup_cert_via_dns_api "\$SERVER_NAME"' <<<"$_acme_src" | head -1 | cut -d: -f1)"
_ss_pos="$(grep -n 'generate_self_signed_cert' <<<"$_acme_src" | head -1 | cut -d: -f1)"
if [[ -n "$_dns_pos" && -n "$_ss_pos" && "$_dns_pos" -lt "$_ss_pos" ]]; then
    ok "DNS API 兜底排在自签回落之前"
else
    bad "顺序不对（dns=${_dns_pos:-无} selfsigned=${_ss_pos:-无}）"
fi
# 回落自签前必须让用户明确同意，绝不静默降级
if grep -q '仍要继续退回自签证书吗' <<<"$_acme_src"; then
    ok "退回自签前有用户确认，不会静默降级"
else
    bad "会静默退回自签证书 —— 用户根本不知道客户端要开 insecure"
fi

echo
echo "=== 7) 🔴 setup_cert_via_dns_api 的返回值必须能被区分 ==="
# 返回码语义：0=成功；1=真失败；2=无凭据（走不了）
# 若统一返回 1，就无法区分"缺凭据"与"签发报错"，也拿不到针对性的提示。
if grep -qE 'return 2' install.sh && grep -qE '_dnsres -eq 2' <<<"$_acme_src"; then
    ok "无凭据(return 2)与签发失败(return 1)被区分，对应给出不同提示"
else
    bad "未区分「无凭据」与「签发失败」，用户会看到误导性提示"
fi
# 缺凭据时必须打印对应的环境变量名，否则用户不知道要导出什么
if grep -q 'HY2_CF_TOKEN' install.sh && grep -q 'HY2_ALICLOUD_KEY' install.sh; then
    ok "缺凭据提示里指明了具体环境变量"
else
    bad "缺凭据提示未说明需要哪些环境变量"
fi

echo
echo "================ 结果 ================"
echo "  通过: $PASS   失败: $FAIL"
[[ $FAIL -eq 0 ]]