#!/usr/bin/env bash
# ==============================================================================
# awgctl.sh 的纯逻辑测试
#
# 只覆盖不需要 root、不需要真是 Linux 的部分：
#   1. 混淆参数生成是否满足上游全部硬约束
#   2. 端口校验是否正确避让 Hysteria2 的端口跳跃区间
#   3. 服务端与客户端配置里的混淆参数是否【逐字节一致】（连不通的头号原因）
#   4. 3.x 头部保护密钥的有无是否随协议线正确切换
#
# 外部命令（awg/systemctl/ip）全部用桩替代，可在任意平台运行（含 Windows Git Bash）。
#
# 用法: bash tests/test_awgctl.sh
# ==============================================================================

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AWGCTL="${REPO_ROOT}/awgctl.sh"

# 迭代轮数可调：CI 在 Linux 上跑高位（子进程开销约 1ms），
# 本地 Windows/Git Bash 每次 awg_rand 都要起一个 od 子进程（约 100ms），
# 用 AWG_TEST_ROUNDS 调低即可。约束是结构性的，几十轮足以发现问题。
ROUNDS="${AWG_TEST_ROUNDS:-1500}"
PORT_ROUNDS=$(( ROUNDS / 10 )); (( PORT_ROUNDS < 10 )) && PORT_ROUNDS=10

PASS=0
FAIL=0
declare -a FAILURES=()

ok()   { PASS=$(( PASS + 1 )); }
bad()  { FAIL=$(( FAIL + 1 )); FAILURES+=("$1"); printf '  \033[0;31m✗ %s\033[0m\n' "$1"; }
check_eq()   { if [[ "$2" == "$3" ]]; then ok; else bad "$1 (期望 [$3] 实际 [$2])"; fi; }
check_ne()   { if [[ "$2" != "$3" ]]; then ok; else bad "$1 (不应等于 [$3])"; fi; }

section() { printf '\n\033[0;36m== %s ==\033[0m\n' "$1"; }

# ------------------------------------------------------------------ 环境准备
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# 桩：awg 二进制
mkdir -p "$WORK/bin"
cat > "${WORK}/bin/awg" <<'STUB'
#!/usr/bin/env bash
case "${1:-}" in
    genkey|genpsk) head -c 32 /dev/urandom | base64 ;;
    pubkey)        head -c 32 /dev/urandom | base64 ;;
    show)          exit 0 ;;
    set)           exit 0 ;;
    --version)     echo "awg stub" ;;
    *)             exit 0 ;;
esac
STUB
chmod +x "${WORK}/bin/awg"

# 桩：python3 端口探测用的真实 python3 已在 PATH；这里只需要 jq 存在
if ! command -v jq >/dev/null 2>&1; then
    echo "错误: 测试需要 jq。请安装 jq 后重试，或把 jq 放进 PATH。"
    exit 2
fi

# 加载 awgctl.sh 的函数定义（去掉末尾的 main 调用）
MAIN_LINE="$(grep -n '^main "\$@"' "$AWGCTL" | tail -1 | cut -d: -f1)"
if [[ -z "$MAIN_LINE" ]]; then
    echo "错误: 在 awgctl.sh 中找不到 main 调用行"
    exit 2
fi
LIB="${WORK}/awgctl_lib.sh"
head -n $(( MAIN_LINE - 1 )) "$AWGCTL" > "$LIB"
# shellcheck disable=SC1090
source "$LIB"

# 覆盖路径到临时目录，并停掉需要 root / systemd 的部分
AWG_DIR="${WORK}/awgconf"
mkdir -p "$AWG_DIR"
AWG_CONFIG="${AWG_DIR}/awg0.conf"
AWG_META_FILE="${AWG_DIR}/awg_meta.json"
AWG_PEERS_FILE="${AWG_DIR}/awg_peers.json"
AWG_VERSION_FILE="${AWG_DIR}/binaries.VERSION"
AWG_BIN="${WORK}/bin/awg"
AWG_GO_BIN="${WORK}/bin/amneziawg-go"
AWG_QUICK_BIN="${WORK}/bin/awg-quick"

require_root() { :; }
systemctl() { return 0; }
detect_wan_iface() { echo "eth0"; }

# ==============================================================================
section "1. 混淆参数生成：上游硬约束"
# ==============================================================================

for line in 2 3; do
    n_jc_bad=0; n_s_bad=0; n_jminmax_bad=0; n_h_bad=0; n_h_dup=0; n_s4_bad=0
    rounds="$ROUNDS"
    for (( i = 0; i < rounds; i++ )); do
        gen_obfs_params "$line"

        # Jc 官方范围 1~128，推荐 4~12
        (( AWG_JC < 4 || AWG_JC > 12 )) && n_jc_bad=$(( n_jc_bad + 1 ))
        # Jmin=8 / Jmax=80 且 0 <= Jmin < Jmax < 1280
        (( AWG_JMIN < 0 || AWG_JMIN >= AWG_JMAX || AWG_JMAX >= 1280 )) && n_jminmax_bad=$(( n_jminmax_bad + 1 ))
        # S1/S2/S3 推荐 15~150
        for v in "$AWG_S1" "$AWG_S2" "$AWG_S3"; do
            (( v < 15 || v > 150 )) && n_s_bad=$(( n_s_bad + 1 ))
        done
        # S1 + 56 != S2
        (( AWG_S1 + 56 == AWG_S2 )) && n_s_bad=$(( n_s_bad + 1 ))
        # S4：3.x 头部保护要求 >=12；2.x 允许 0~32
        if [[ "$line" == "3" ]]; then
            (( AWG_S4 < 12 || AWG_S4 > 32 )) && n_s4_bad=$(( n_s4_bad + 1 ))
        else
            (( AWG_S4 < 0 || AWG_S4 > 32 )) && n_s4_bad=$(( n_s4_bad + 1 ))
        fi
        # H1~H4 取值域 + 两两互不相同
        for h in "$AWG_H1" "$AWG_H2" "$AWG_H3" "$AWG_H4"; do
            (( h < 5 || h > 2147483647 )) && n_h_bad=$(( n_h_bad + 1 ))
        done
        if [[ "$AWG_H1" == "$AWG_H2" || "$AWG_H1" == "$AWG_H3" || "$AWG_H1" == "$AWG_H4" \
           || "$AWG_H2" == "$AWG_H3" || "$AWG_H2" == "$AWG_H4" || "$AWG_H3" == "$AWG_H4" ]]; then
            n_h_dup=$(( n_h_dup + 1 ))
        fi
    done

    printf '  协议线 AWG %s.x (%s 轮):\n' "$line" "$rounds"
    check_eq "  Jc 落在 4~12"                 "$n_jc_bad" "0"
    check_eq "  Jmin<Jmax<1280"               "$n_jminmax_bad" "0"
    check_eq "  S1/S2/S3 合法且 S1+56!=S2"    "$n_s_bad" "0"
    check_eq "  S4 区间正确"                  "$n_s4_bad" "0"
    check_eq "  H1~H4 落在 5..2147483647"     "$n_h_bad" "0"
    check_eq "  H1~H4 两两不重复"             "$n_h_dup" "0"
done

# H1~H4 必须天然有序（四分带取值 ⇒ 永不重叠）
gen_obfs_params 3
if (( AWG_H1 < AWG_H2 && AWG_H2 < AWG_H3 && AWG_H3 < AWG_H4 )); then
    ok
else
    bad "H1~H4 应按四分带递增（保证范围不重叠）: $AWG_H1 $AWG_H2 $AWG_H3 $AWG_H4"
fi

# ==============================================================================
section "2. 端口校验：必须避让 Hysteria2 的端口跳跃区间"
# ==============================================================================

port_should_pass() {
    if validate_port "$1" 2>/dev/null; then ok; else bad "端口 $1 应通过校验但被拒绝"; fi
}
port_should_fail() {
    if validate_port "$1" 2>/dev/null; then bad "端口 $1 应被拒绝但通过了"; else ok; fi
}

port_should_fail 20000
port_should_fail 25000
port_should_fail 30000
port_should_fail 40000
port_should_pass 19999
port_should_pass 40001
port_should_pass 50000
port_should_pass 58999
port_should_pass 51820      # 允许但会告警（WireGuard 默认端口是弱指纹）
port_should_fail 0
port_should_fail 65536
port_should_fail "abc"

# 自动选端口：不得落在跳跃区间，也不得等于 Hysteria2 的端口
hy2_port=51234
bad_auto=0
for (( i = 0; i < PORT_ROUNDS; i++ )); do
    p="$(pick_port "$hy2_port")" || { bad_auto=1; break; }
    if (( p >= 20000 && p <= 40000 )); then bad_auto=1; break; fi
    if (( p == hy2_port )); then bad_auto=1; break; fi
done
check_eq "自动选端口避让跳跃区间与 Hysteria 端口" "$bad_auto" "0"

# ==============================================================================
section "3. 服务端 / 客户端配置：混淆参数必须逐字节一致"
# ==============================================================================

# 从配置文本里取某个键的值
conf_get() {
    local text="$1" key="$2"
    printf '%s\n' "$text" | awk -v k="$key" '
        {
            pos = index($0, "=")
            if (pos == 0) next
            key = substr($0, 1, pos-1); val = substr($0, pos+1)
            gsub(/^[ \t]+|[ \t]+$/, "", key); gsub(/^[ \t]+|[ \t]+$/, "", val)
            if (key == k) { print val; exit }
        }
    '
}

for line in 2 3; do
    printf '  协议线 AWG %s.x:\n' "$line"

    rm -f "$AWG_META_FILE" "$AWG_PEERS_FILE"
    echo '{}' > "$AWG_META_FILE"
    echo '{"peers":[]}' > "$AWG_PEERS_FILE"

    gen_obfs_params "$line"
    meta_set line "$line"
    meta_set port "52341"
    meta_set server_private_key "$(head -c 32 /dev/urandom | base64)"
    meta_set server_public_key  "$(head -c 32 /dev/urandom | base64)"
    meta_set endpoint "vpn.example.com"
    meta_set Jc "$AWG_JC";     meta_set Jmin "$AWG_JMIN"; meta_set Jmax "$AWG_JMAX"
    meta_set S1 "$AWG_S1";     meta_set S2 "$AWG_S2"
    meta_set S3 "$AWG_S3";     meta_set S4 "$AWG_S4"
    meta_set H1 "$AWG_H1";     meta_set H2 "$AWG_H2"
    meta_set H3 "$AWG_H3";     meta_set H4 "$AWG_H4"
    if [[ "$line" == "3" ]]; then
        meta_set HeaderProtectionKey "$(head -c 32 /dev/urandom | base64)"
    fi

    # 加一个客户端
    jq '.peers += [{name:"phone", address:"10.66.66.2",
                    private_key:"CPRIV", public_key:"CPUB", preshared_key:"CPSK",
                    created_at:"2026-01-01T00:00:00Z", enabled:true}]' \
       "$AWG_PEERS_FILE" > "${AWG_PEERS_FILE}.tmp" && mv "${AWG_PEERS_FILE}.tmp" "$AWG_PEERS_FILE"

    render_server_config
    CLIENT_TEXT="$(render_client_config "phone" "vpn.example.com")"
    SERVER_TEXT="$(cat "$AWG_CONFIG")"

    # 9 个必须对齐的混淆参数
    for k in Jc Jmin Jmax S1 S2 S3 S4 H1 H2 H3 H4; do
        sv="$(conf_get "$SERVER_TEXT" "$k")"
        cv="$(conf_get "$CLIENT_TEXT" "$k")"
        if [[ -z "$sv" ]]; then
            bad "  服务端配置缺少 $k"
        elif [[ "$sv" != "$cv" ]]; then
            bad "  $k 两端不一致 (服务端[$sv] 客户端[$cv])"
        else
            ok
        fi
    done
    printf '    - 11 个参数两端一致\n'

    # 3.x 必须有 HeaderProtectionKey，且两端一致；2.x 必须没有
    shp="$(conf_get "$SERVER_TEXT" "HeaderProtectionKey")"
    chp="$(conf_get "$CLIENT_TEXT" "HeaderProtectionKey")"
    if [[ "$line" == "3" ]]; then
        if [[ -n "$shp" && "$shp" == "$chp" ]]; then ok; else bad "  3.x 应两端都有且一致 HeaderProtectionKey"; fi
    else
        if [[ -z "$shp" && -z "$chp" ]]; then ok; else bad "  2.x 不应出现 HeaderProtectionKey"; fi
    fi

    # MTU 必须两端一致，且等于 1420 - S4
    smtu="$(conf_get "$SERVER_TEXT" "MTU")"
    cmtu="$(conf_get "$CLIENT_TEXT" "MTU")"
    expect_mtu=$(( 1420 - $(conf_get "$SERVER_TEXT" "S4") ))
    check_eq "  MTU 两端一致" "$smtu" "$cmtu"
    check_eq "  MTU = 1420 - S4" "$smtu" "$expect_mtu"

    # 服务端必备项
    check_eq "  服务端含 Address" "$(conf_get "$SERVER_TEXT" "Address")" "10.66.66.1/24"
    check_eq "  服务端含 ListenPort" "$(conf_get "$SERVER_TEXT" "ListenPort")" "52341"
    check_eq "  服务端含 Peer 段" "$(printf '%s' "$SERVER_TEXT" | grep -c '^\[Peer\]')" "1"
    check_eq "  服务端含 AllowedIPs" "$(printf '%s' "$SERVER_TEXT" | grep -c 'AllowedIPs = 10.66.66.2/32')" "1"
    check_eq "  服务端含 NAT 转发(PostUp)" "$(printf '%s' "$SERVER_TEXT" | grep -c '^PostUp = .*MASQUERADE')" "1"
    check_eq "  服务端含 NAT 清理(PostDown)" "$(printf '%s' "$SERVER_TEXT" | grep -c '^PostDown = .*MASQUERADE')" "1"

    # 客户端必备项
    check_eq "  客户端 Address 为 /32" "$(conf_get "$CLIENT_TEXT" "Address")" "10.66.66.2/32"
    check_eq "  客户端 Endpoint 带端口" "$(conf_get "$CLIENT_TEXT" "Endpoint")" "vpn.example.com:52341"
    check_eq "  客户端 AllowedIPs 全流量" "$(conf_get "$CLIENT_TEXT" "AllowedIPs")" "0.0.0.0/0"
    check_eq "  客户端含 PresharedKey" "$(conf_get "$CLIENT_TEXT" "PresharedKey")" "CPSK"
done

# ==============================================================================
section "4. peer 生命周期"
# ==============================================================================

rm -f "$AWG_META_FILE" "$AWG_PEERS_FILE"
echo '{}' > "$AWG_META_FILE"
peers_init
meta_set port "52341"
meta_set S1 23; meta_set S2 41; meta_set S3 37; meta_set S4 20
meta_set H1 100000; meta_set H2 200000; meta_set H3 300000; meta_set H4 400000
meta_set Jc 5; meta_set Jmin 8; meta_set Jmax 80
meta_set server_private_key "SPRIV"
meta_set server_public_key  "SPUB"

peers_init
# 直接构造 peer，绕开 genkey（桩只保证格式，这里只测地址分配与去重）
add_fake_peer() {
    local name="$1" addr
    addr="$(next_peer_address)"
    jq --arg n "$name" --arg a "$addr" \
       '.peers += [{name:$n,address:$a,private_key:"p",public_key:("pub-"+$n),preshared_key:"k",created_at:"t",enabled:true}]' \
       "$AWG_PEERS_FILE" > "${AWG_PEERS_FILE}.tmp" && mv "${AWG_PEERS_FILE}.tmp" "$AWG_PEERS_FILE"
    echo "$addr"
}

a1="$(add_fake_peer one)"
a2="$(add_fake_peer two)"
a3="$(add_fake_peer three)"
check_eq "首个客户端地址为 .2" "$a1" "10.66.66.2"
check_eq "第二个客户端地址为 .3" "$a2" "10.66.66.3"
check_eq "第三个客户端地址为 .4" "$a3" "10.66.66.4"

# 删除中间一个后，地址应被回收复用
jq '.peers |= map(select(.name != "two"))' "$AWG_PEERS_FILE" > "${AWG_PEERS_FILE}.tmp" \
    && mv "${AWG_PEERS_FILE}.tmp" "$AWG_PEERS_FILE"
a4="$(add_fake_peer four)"
check_eq "删除后地址被复用" "$a4" "10.66.66.3"

check_eq "peer 数量正确" "$(jq '[.peers[]?]|length' "$AWG_PEERS_FILE")" "3"

# peer-list --json 不得泄露私钥
JSON_OUT="$(cmd_peer_list --json)"
if printf '%s' "$JSON_OUT" | grep -q 'private_key'; then
    bad "peer-list --json 泄露了 private_key"
else
    ok
fi
if printf '%s' "$JSON_OUT" | grep -q '"name"'; then ok; else bad "peer-list --json 未输出 name 字段"; fi

# 渲染出的服务端配置应包含全部 peer
render_server_config
check_eq "服务端配置含 3 个 Peer 段" "$(grep -c '^\[Peer\]' "$AWG_CONFIG")" "3"
check_eq "服务端配置含全部 3 个客户端注释" "$(grep -cE '^# (one|three|four)$' "$AWG_CONFIG")" "3"

# ==============================================================================
section "5. meta 读写"
# ==============================================================================

rm -f "$AWG_META_FILE"
meta_set line "3"
meta_set port "54321"
check_eq "meta 读回 line" "$(meta_get line)" "3"
check_eq "meta 读回 port" "$(meta_get port)" "54321"
check_eq "meta 读不存在的键返回空" "$(meta_get nonexistent)" ""
meta_set port "55555"
check_eq "meta 覆盖写" "$(meta_get port)" "55555"
check_eq "meta 写入后仍只有 2 个键" "$(jq 'keys|length' "$AWG_META_FILE")" "2"

# version_line 默认值
rm -f "$AWG_META_FILE"
check_eq "无 meta 时协议线默认 3" "$(version_line)" "3"
meta_set line "2"
check_eq "meta 指定后协议线为 2" "$(version_line)" "2"
meta_set line "9"
check_eq "非法协议线回退为 3" "$(version_line)" "3"

# ==============================================================================
section "6. 随机数工具"
# ==============================================================================

bad_rand=0
for (( i = 0; i < ROUNDS; i++ )); do
    r="$(awg_rand 5 10)"
    (( r < 5 || r > 10 )) && { bad_rand=1; break; }
done
check_eq "awg_rand 落在闭区间内" "$bad_rand" "0"

# 大区间（H1 需要覆盖 21 亿量级）
big_ok=1
r="$(awg_rand 5 2147483647)"
if (( r >= 5 && r <= 2147483647 )); then big_ok=0; fi
check_eq "awg_rand 支持 21 亿量级区间" "$big_ok" "0"

# 单点区间
check_eq "awg_rand 单点区间" "$(awg_rand 42 42)" "42"

# ==============================================================================
section "7. 命令行参数解析"
# ==============================================================================

# parse_name_endpoint 用 die 表达错误，这里用一个能捕获退出的方式测试
try_parse() {
    local rc=0
    ( parse_name_endpoint "$@" ) >/dev/null 2>&1 || rc=$?
    echo "$rc"
}

# 合法形式
parse_name_endpoint phone --endpoint vpn.example.com
check_eq "名称 + --endpoint" "$PARSED_NAME|$PARSED_ENDPOINT" "phone|vpn.example.com"

parse_name_endpoint --endpoint vpn.example.com phone
check_eq "--endpoint 在前也可解析" "$PARSED_NAME|$PARSED_ENDPOINT" "phone|vpn.example.com"

parse_name_endpoint phone
check_eq "只给名称时 endpoint 为空" "$PARSED_NAME|$PARSED_ENDPOINT" "phone|"

# 非法形式必须非零退出（否则会带着残缺参数继续往下跑）
check_eq "--endpoint 缺值被拒"     "$(try_parse phone --endpoint)" "1"
check_eq "--endpoint 在末尾被拒"   "$(try_parse --endpoint)" "1"
check_eq "两个名称被拒"            "$(try_parse a b)" "1"
check_eq "未知选项被拒"            "$(try_parse --bogus x)" "1"
check_eq "未知短选项被拒"          "$(try_parse -x)" "1"

# ==============================================================================
printf '\n\033[0;36m================ 结果 ================\033[0m\n'
printf '通过: \033[0;32m%d\033[0m   失败: \033[0;31m%d\033[0m\n' "$PASS" "$FAIL"
if (( FAIL > 0 )); then
    printf '\n失败项:\n'
    for f in "${FAILURES[@]}"; do printf '  - %s\n' "$f"; done
    exit 1
fi
printf '\033[0;32m全部通过\033[0m\n'
exit 0
