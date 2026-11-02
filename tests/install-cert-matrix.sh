#!/usr/bin/env bash
# 🔴🔴 安装成功率矩阵测试 —— 真跑证书流程，验证**产出的证书真的能用**。
#
# 为什么单独一个文件（而不是并进 acme-port-guard-smoke.sh）：
# 那份测的是"检测函数是否正确"；这份测的是**用户最终拿到的证书到底能不能用**。
# 两者关注的失败面不同：函数全对、但某个场景的证书落不了地，用户照样连不上。
#
# 🔴 核心验收原则：**不看日志措辞，只看证书本身**
#   1. 落地的文件必须存在、非空、语法合法
#   2. 公私钥必须配对
#   3. 正式证书必须是真链（>=2 张），且 CN/SAN 匹配用户给的域名
#   4. 自签必须 IS_INSECURE=true；正式证书必须 IS_INSECURE=false 且 SNI 为真实域名
#   5. 🔴 真实握手验证：用 openssl s_server + s_client 起一次真实 TLS 握手，
#      比对指纹 —— 这一步能抓出"文件对了但没真被用上"
#   6. 🔴 绝不允许"日志说签发成功、实际落地的是自签"这种静默降级
set -u

cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 2
INSTALL_SH="$(pwd)/install.sh"
[[ -f "$INSTALL_SH" ]] || { echo "❌ 找不到 install.sh" >&2; exit 2; }

# --- 颜色/日志桩（install.sh 顶部定义，这里自给自足）---
GREEN=""; RED=""; YELLOW=""; CYAN=""; BLUE=""; PLAIN=""
log_info()  { echo "    [INF] $*"; }
log_warn()  { echo "    [WRN] $*"; }
log_err()   { echo "    [ERR] $*"; }
log_step()  { echo "    [STP] $*"; }

# 🔴 从 install.sh 抽取指定函数的完整定义。
#
# 🔴🔴 绝对不能用 `sed -n '/^fn() {/,/^}/p'`：
# 函数体内的 case 分支、多行条件里也有 `}`，sed 会在那里提前截断，
# 抽出来的是**残缺函数**，表现为满屏 `command not found`。
# 2026-10-08 实测踩到：给某个函数加了多行 case 之后，
# 原有的 acme-port-guard-smoke.sh 从 16 项全绿变成 15 项（静默失效）。
#
# 这里用 awk 做花括号配平：遇到函数头就开始，直到该函数自己的 } 为止。
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
          pem_cert_count _accept_cert_pair _cert_matches_domain _nginx_cert_candidates \
          is_valid_domain is_valid_email \
          setup_cert_via_dns_api generate_self_signed_cert setup_acme_certificate; do
    _f="$(extract_fn "$fn")"
    if [[ -z "$_f" ]]; then
        echo "❌ 未能从 install.sh 提取到函数 $fn（脚本结构变了？）" >&2
        exit 2
    fi
    eval "$_f"
    # 提取后必须确认真的定义出来了 —— 否则测试会拿着空函数得出"全绿"的假结论
    if ! declare -F "$fn" >/dev/null; then
        echo "❌ 函数 $fn 提取后无法加载" >&2
        exit 2
    fi
done

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); echo "    ✅ $*"; }
bad() { FAIL=$((FAIL+1)); echo "    ❌ $*"; }

# 每个场景独立的临时 HOME/证书目录，互不污染
SCEN_NO=0
new_scenario() {
    SCEN_NO=$((SCEN_NO+1))
    SCEN_DIR="$(mktemp -d)"
    HY2_CERT_DIR="${SCEN_DIR}/cert"
    HY2_DIR="${SCEN_DIR}/hy2"
    HY2_CONFIG="${SCEN_DIR}/config.yaml"
    HY2_SUB_PORT="11080"
    HY2_PORT="19999"
    HOME="${SCEN_DIR}/home"
    mkdir -p "$HY2_CERT_DIR" "$HY2_DIR" "$HOME"
    # 每个场景都从"什么都没配"开始。
    # 🔴 场景间共享环境变量会互相污染：函数里的 export（如 SKIP_ACME_SH_UPGRADE）
    #    会影响后续场景，让测出来的结论是假的。
    unset CERT_TYPE CERT_FILE KEY_FILE SERVER_NAME IS_INSECURE ACME_EMAIL
    unset HY2_CF_TOKEN HY2_CF_EMAIL HY2_ALICLOUD_KEY HY2_ALICLOUD_SECRET HY2_DP_TOKEN
    unset HY2_DOMAIN HY2_CERT_TYPE SKIP_ACME_SH_UPGRADE ACME_SH_ACCOUNT
    CADDY_CERT_ROOT="${SCEN_DIR}/caddy-nonexistent"   # 默认找不到任何反代证书
}

# 🔴 验收 1：产出的证书文件本身必须自洽且可用
verify_cert_artifact() {
    local name="$1" expect_type="$2" expect_cn="$3"
    local cf="$CERT_FILE" kf="$KEY_FILE"

    [[ -s "$cf" ]] || { bad "$name: 证书文件为空/不存在 ($cf)"; return 1; }
    [[ -s "$kf" ]] || { bad "$name: 私钥文件为空/不存在 ($kf)"; return 1; }

    # 公私钥必须配对（不配对 = 客户端握手必失败）
    local a b
    a="$(openssl x509 -in "$cf" -noout -pubkey 2>/dev/null | openssl sha256 2>/dev/null | awk '{print $NF}')"
    b="$(openssl pkey -in "$kf" -pubout 2>/dev/null | openssl sha256 2>/dev/null | awk '{print $NF}')"
    if [[ -z "$a" || -z "$b" ]]; then
        bad "$name: 证书或私钥无法解析（openssl 报错）"
        return 1
    fi
    [[ "$a" == "$b" ]] || { bad "$name: 🔴 公私钥不配对，客户端必然握手失败"; return 1; }
    ok "$name: 公私钥配对"

    local cn
    cn="$(openssl x509 -in "$cf" -noout -subject 2>/dev/null | sed 's/.*CN *= *//;s/,.*//')"
    if [[ "$cn" == "$expect_cn" ]]; then
        ok "$name: CN 正确（$cn）"
    else
        bad "$name: CN 不符，期望 [$expect_cn] 实际 [$cn]"
        return 1
    fi

    # 正式证书必须含完整链（Go 系客户端不补中间证书）
    local n
    n="$(grep -c 'BEGIN CERTIFICATE' "$cf" 2>/dev/null || echo 0)"
    if [[ "$expect_type" == "self_signed" ]]; then
        [[ "$n" -ge 1 ]] && ok "$name: 自签证书（单张属正常，n=$n）"
    elif [[ "$n" -ge 2 ]]; then
        ok "$name: 含完整证书链（$n 张）"
    else
        bad "$name: 🔴 正式证书只有 $n 张，缺中间证书 ⇒ Go 系客户端报 unknown authority"
        return 1
    fi
    return 0
}

# 🔴 验收 2：insecure 标志必须与证书类型匹配
verify_insecure_flag() {
    local name="$1" expect_type="$2"
    case "$expect_type" in
        self_signed)
            [[ "${IS_INSECURE:-}" == "true" ]] \
                && ok "$name: 自签 → IS_INSECURE=true（客户端会开跳过校验）" \
                || bad "$name: 🔴 自签证书但 IS_INSECURE 不是 true，客户端会因校验失败而连不上"
            ;;
        custom|acme)
            [[ "${IS_INSECURE:-}" == "false" ]] \
                && ok "$name: 正式证书 → IS_INSECURE=false（客户端零设置）" \
                || bad "$name: 🔴 正式证书但 IS_INSECURE 不是 false，客户端仍在开跳过校验"
            # 🔴 SNI 必须等于真实域名：自签模式下它被伪装成 www.bing.com，
            #    若被后续流程沿用，客户端会拿bing 的 SNI 去连真实域名 ⇒ 握手失败
            if [[ "$SERVER_NAME" == "www.bing.com" ]]; then
                bad "$name: 🔴 用了正式证书却残留伪装 SNI（www.bing.com），必然握手失败"
                return 1
            fi
            ok "$name: SNI 为真实域名（$SERVER_NAME）"
            ;;
    esac
}

# 🔴 验收 3：真实握手 —— 证明证书真的被服务用上了
verify_real_handshake() {
    local name="$1" port="$2"
    if ! command -v openssl >/dev/null 2>&1; then
        echo "    ⚠️  $name: 无 openssl，跳过握手验证"
        return 0
    fi
    # 🔴 三个条件缺一就取不到指纹（每条都实测踩过）：
    #   1. s_server 必须加 -quiet：否则会话内容混进 stdout，管道解析出空指纹
    #   2. 必须 sleep 2 秒：用 /dev/tcp 轮询端口虽不消耗连接，
    #      但 s_server 起来后需要时间才能真正 accept，实测 0.4 秒不够
    #   3. 起服务与取指纹必须分开两条命令：塞进同一个 $(...) 会死锁 ——
    #      命令替换要等所有子进程结束，而 s_server 要等一个连接才退出
    openssl s_server -accept "$port" -cert "$CERT_FILE" -key "$KEY_FILE" \
        -naccept 1 -quiet >/dev/null 2>&1 &
    local srv=$!
    sleep 2
    local live want
    live="$(timeout 8 openssl s_client -connect "127.0.0.1:${port}" </dev/null 2>/dev/null \
             | openssl x509 -noout -fingerprint -sha256 2>/dev/null \
             | sed -n 's/.*Fingerprint=//p')"
    kill "$srv" 2>/dev/null
    wait "$srv" 2>/dev/null || true
    want="$(openssl x509 -in "$CERT_FILE" -noout -fingerprint -sha256 2>/dev/null \
             | sed -n 's/.*Fingerprint=//p')"

    if [[ -z "$live" || -z "$want" ]]; then
        bad "$name: 握手验证无法完成（live=${live:-无} want=${want:-无}）—— 工具链问题"
        return 1
    fi
    if [[ "$live" == "$want" ]]; then
        ok "$name: 🔴 真实握手呈现的证书与配置一致"
        return 0
    fi
    bad "$name: 🔴 握手拿到的证书与配置不符（live=$live want=$want）"
    return 1
}

echo "═══════════════════════════════════════════════════════"
echo " 安装成功率矩阵测试"
echo " 验收标准：证书自洽 + 配对 + 链完整 + insecure 正确 + SNI 正确 + 真实握手"
echo "═══════════════════════════════════════════════════════"

echo
echo "【场景 1】有域名、端口状态未知 → 决策不得静默产生自签"
new_scenario
HY2_DOMAIN="hy2-test.example.com"
HY2_CERT_TYPE="3"
ACME_EMAIL="a@example.com"
export PUBLIC_IP="1.2.3.4"
# 子进程隔离：setup_acme_certificate 读一堆 HY2_* 变量，留在主 shell 会串味
rc1=0
( setup_acme_certificate </dev/null >/dev/null 2>&1 ) || rc1=$?
if [[ $rc1 -eq 0 && "${CERT_TYPE:-}" == "acme" ]]; then
    ok "场景1: 决策=acme（DNS 通过时才会真正签发）"
elif [[ "${CERT_TYPE:-}" == "self_signed" ]]; then
    # DNS 不指向本机 ⇒ 用户不同意就中止；同意才回落自签。这是安全的。
    verify_cert_artifact "场景1" "self_signed" "www.bing.com"
    verify_insecure_flag "场景1" "self_signed"
else
    ok "场景1: 中止或等待输入，未错误地静默产生证书（CERT_TYPE=${CERT_TYPE:-未设}）"
fi

echo
echo "【场景 2】端口被占 + Caddy 已有该域名证书 → 必须复用，不能退回自签"
new_scenario
CAD="$SCEN_DIR/caddy-certificates/acme-v02.example.org-dir"
mkdir -p "$CAD/hy2-test.example.com"
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$CAD/hy2-test.example.com/hy2-test.example.com.key" \
    -out "$CAD/leaf.pem" -days 30 -subj "/CN=hy2-test.example.com" >/dev/null 2>&1
cat "$CAD/leaf.pem" "$CAD/leaf.pem" > "$CAD/hy2-test.example.com/hy2-test.example.com.crt"
rm -f "$CAD/leaf.pem"
export CADDY_CERT_ROOT="$SCEN_DIR/caddy-certificates"
found="$(find_cert_in_webserver hy2-test.example.com || true)"
if [[ -n "$found" ]]; then
    ok "场景2: 找到了 Caddy 已有证书"
    CERT_FILE="${found%%|*}"; KEY_FILE="${found#*|}"
    IS_INSECURE="false"; SERVER_NAME="hy2-test.example.com"; CERT_TYPE="custom"
    verify_cert_artifact "场景2" "custom" "hy2-test.example.com"
    verify_insecure_flag "场景2" "custom"
    verify_real_handshake "场景2" 21431
else
    bad "场景2: 未能发现 Caddy 已签发的证书 —— 复用链路坏了"
fi
unset CADDY_CERT_ROOT

echo
echo "【场景 2b】🔴 Nginx/certbot 布局的证书也必须能被识别"
# Nginx 装机量远大于 Caddy，且布局完全不同（不是 <ca>/<domain>/<domain>.crt）
new_scenario
_p="$(mktemp -d)/live/nginx.test.com"; mkdir -p "$_p"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$_p/privkey.pem" \
    -out "$_p/leaf.pem" -days 30 -subj "/CN=nginx.test.com" >/dev/null 2>&1
cat "$_p/leaf.pem" "$_p/leaf.pem" > "$_p/fullchain.pem"; rm -f "$_p/leaf.pem"
if _accept_cert_pair "$_p/fullchain.pem" "$_p/privkey.pem"; then
    ok "场景2b: certbot 布局的 fullchain 被接受"
else
    bad "场景2b: 完整链被拒"
fi
if _cert_matches_domain "$_p/fullchain.pem" "nginx.test.com"; then
    ok "场景2b: SAN/CN 匹配识别正确"
else
    bad "场景2b: 域名匹配失败"
fi
if _cert_matches_domain "$_p/fullchain.pem" "other.test.com"; then
    bad "场景2b: 不该匹配别的域名"
else
    ok "场景2b: 不会误匹配其他域名"
fi
# 🔴 公私钥不配对必须被拒 —— 装上去握手 100% 失败，且报错极难定位
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$_p/other.key"     -out "$_p/other.crt" -days 30 -subj "/CN=nginx.test.com" >/dev/null 2>&1
cat "$_p/other.crt" "$_p/other.crt" > "$_p/mismatch.pem"
if _accept_cert_pair "$_p/mismatch.pem" "$_p/privkey.pem"; then
    bad "场景2b: 🔴 公私钥不配对竟被接受（装上去必然握手失败）"
else
    ok "场景2b: 公私钥不配对被正确拒绝"
fi

# 叶证书（单张）必须被拒 —— 这是 Go 系客户端连不上的经典原因
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$_p/leaf.key" \
    -out "$_p/leaf.crt" -days 30 -subj "/CN=nginx.test.com" >/dev/null 2>&1
if _accept_cert_pair "$_p/leaf.crt" "$_p/leaf.key"; then
    bad "场景2b: 🔴 仅含叶证书的 .crt 被当成完整链接受了"
else
    ok "场景2b: 仅叶证书被正确拒绝"
fi

echo
echo "【场景 3】端口被占 + 无 Caddy 证书 + 无 DNS 凭据 → 必须明确中止"
new_scenario
r=0
( unset HY2_CF_TOKEN HY2_CF_EMAIL HY2_ALICLOUD_KEY HY2_DP_TOKEN
  setup_cert_via_dns_api hy2-test.example.com >/dev/null 2>&1 ) || r=$?
if [[ $r -eq 2 ]]; then
    ok "场景3: 正确返回「无 DNS 凭据」(2)，未误报为签发失败"
else
    bad "场景3: 期望返回 2（无凭据），实际 $r —— 提示语会误导用户"
fi
if [[ -n "${CERT_FILE:-}" ]]; then
    bad "场景3: 🔴 无凭据时不该设置 CERT_FILE（暗示证书已就绪）"
else
    ok "场景3: 未谎报证书已就绪"
fi

echo
echo "【场景 4】用户选自签 → 必须自签 + insecure=true + SNI 与 CN 一致"
new_scenario
generate_self_signed_cert >/dev/null 2>&1
verify_cert_artifact "场景4" "self_signed" "www.bing.com"
verify_insecure_flag "场景4" "self_signed"
[[ "${CERT_TYPE:-}" == "self_signed" ]] && ok "场景4: CERT_TYPE=self_signed" \
                                    || bad "场景4: CERT_TYPE 不对"
verify_real_handshake "场景4" 21432

echo
echo "【场景 5】用户传了坏路径 → 必须回落自签且不中断"
new_scenario
[[ ! -f "/nonexistent/fullchain.pem" ]] || bad "场景5: 测试前提错误"
generate_self_signed_cert >/dev/null 2>&1
verify_cert_artifact "场景5" "self_signed" "www.bing.com"

echo
echo "【场景 6】🔴 端口探测失败绝不能被当成空闲（否则会走上必然失败的签发）"
new_scenario
_ssdir="$(mktemp -d)"; printf '#!/bin/sh\nexit 1\n' > "$_ssdir/ss"; chmod +x "$_ssdir/ss"
_hold=45981
python3 -c '
import socket, sys, time
s = socket.socket(); s.bind(("0.0.0.0", int(sys.argv[1]))); s.listen(1)
sys.stderr.write("h\n"); sys.stderr.flush(); time.sleep(30)
' "$_hold" 2>/tmp/_mx.log &
_h=$!
for _i in $(seq 1 20); do grep -q h /tmp/_mx.log 2>/dev/null && break; sleep 0.3; done
if kill -0 "$_h" 2>/dev/null; then
    _old="$PATH"; PATH="$_ssdir:$PATH"
    who="$(port_owner tcp "$_hold")"
    PATH="$_old"
    [[ -n "$who" ]] && ok "场景6: ss 失效仍检出端口被占（$who）" \
                      || bad "场景6: 🔴 ss 失效即误报空闲 → 会去走必然失败的 ACME"
else
    bad "场景6: 无法占用测试端口，用例未执行"
fi
kill "$_h" 2>/dev/null; wait "$_h" 2>/dev/null || true
rm -rf "$_ssdir" /tmp/_mx.log

echo
echo "═══════════════════════════════════════════════════════"
echo " 通过: $PASS   失败: $FAIL"
echo "═══════════════════════════════════════════════════════"
[[ $FAIL -eq 0 ]]