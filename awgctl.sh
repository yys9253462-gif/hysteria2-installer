#!/usr/bin/env bash
# ==============================================================================
# hy2-awgctl —— AmneziaWG (AWG) 服务端控制工具
#
# 隶属项目: hysteria2-installer
# GitHub:   https://github.com/yys9253462-gif/hysteria2-installer
#
# 为什么是独立脚本：
#   install.sh 的菜单（命令行）和 portal.py（Web 门户）都要管理 AmneziaWG。
#   把引擎收敛到这一个文件，两边都只做调用，避免同一套配置生成逻辑写两遍。
#
# 部署形态：用户态（amneziawg-go），不编译内核模块、不引入 Docker。
#   理由见 install.sh 中 AmneziaWG 段落顶部注释。
#
# 重要约束（改这个文件前务必读完）：
#   1. S1-S4 / H1-H4 / HeaderProtectionKey 必须与客户端【逐字节一致】，
#      任何一端改动都会导致完全连不上。改这里 = 改所有已发放的客户端配置。
#   2. 监听端口必须避开 Hysteria2 的端口跳跃区间 20000-40000，否则入站 UDP
#      会被 iptables REDIRECT 到 Hysteria 主端口，AWG 收不到任何握手包。
#   3. H1~H4 之间不得重叠（官方硬性要求），本脚本用四分带取值天然满足。
#   4. AWG 3.x 的头部保护要求 S1-S4 全部 >= 12。
# ==============================================================================

set -euo pipefail

VERSION="1.0.0"

# ------------------------------------------------------------------ 常量
AWG_DIR="/etc/amnezia/amneziawg"
AWG_LINK="awg0"
AWG_CONFIG="${AWG_DIR}/${AWG_LINK}.conf"
AWG_GO_BIN="/usr/local/bin/amneziawg-go"
AWG_BIN="/usr/local/bin/awg"
AWG_QUICK_BIN="/usr/local/bin/awg-quick"
AWG_SERVICE_NAME="amneziawg-server"
AWG_SERVICE="/etc/systemd/system/${AWG_SERVICE_NAME}.service"
AWG_META_FILE="${AWG_DIR}/awg_meta.json"
AWG_PEERS_FILE="${AWG_DIR}/awg_peers.json"
AWG_VERSION_FILE="${AWG_DIR}/binaries.VERSION"

AWG_REPO="${AWG_REPO:-yys9253462-gif/hysteria2-installer}"
AWG_RELEASE_TAG="${AWG_RELEASE_TAG:-awg-binaries}"

AWG_SUBNET="10.66.66"
# 规避 Hysteria2 端口跳跃区间(20000-40000) 与 WireGuard 默认端口(51820)
AWG_PORT_MIN=50000
AWG_PORT_MAX=59000

# 颜色（非终端时自动关闭）
if [[ -t 1 ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
    BLUE='\033[0;34m'; CYAN='\033[0;36m'; PLAIN='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; PLAIN=''
fi

log_info() { echo -e "${GREEN}[INFO]${PLAIN} $*" >&2; }
log_warn() { echo -e "${YELLOW}[WARN]${PLAIN} $*" >&2; }
log_err()  { echo -e "${RED}[ERROR]${PLAIN} $*" >&2; }
log_step() { echo -e "${CYAN}==>${PLAIN} ${BLUE}$*${PLAIN}" >&2; }

die() { log_err "$*"; exit 1; }

require_root() {
    [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "本工具必须以 root 运行。"
}

require_jq() {
    command -v jq >/dev/null 2>&1 || die "缺少 jq，请先安装：apt-get install -y jq"
}

# ==============================================================================
# 基础工具
# ==============================================================================

# [min,max] 闭区间随机整数。用 /dev/urandom 而非 $RANDOM —— 后者只有 15 位，
# 覆盖不了 H1~H4 需要的 5..2147483647 区间。
awg_rand() {
    local min="$1" max="$2" span r
    span=$(( max - min + 1 ))
    r=$(od -An -N4 -tu4 /dev/urandom | tr -d ' \n')
    echo $(( min + r % span ))
}

# 读取 meta 字段
meta_get() {
    local key="$1"
    if [[ ! -f "$AWG_META_FILE" ]]; then
        echo ""
        return 0
    fi
    jq -r --arg k "$key" '.[$k] // empty' "$AWG_META_FILE" 2>/dev/null || echo ""
}

# 写入 meta 字段（原子替换）
meta_set() {
    local key="$1" value="$2" tmp
    mkdir -p "$AWG_DIR"
    chmod 700 "$AWG_DIR"
    [[ -f "$AWG_META_FILE" ]] || echo '{}' > "$AWG_META_FILE"
    tmp="$(mktemp "${AWG_DIR}/.meta.XXXXXX")"
    if jq --arg k "$key" --arg v "$value" '.[$k] = $v' "$AWG_META_FILE" > "$tmp" 2>/dev/null; then
        chmod 600 "$tmp"
        mv -f "$tmp" "$AWG_META_FILE"
    else
        rm -f "$tmp"
        die "写入 meta 失败 (key=${key})"
    fi
}

is_installed() {
    [[ -x "$AWG_GO_BIN" && -x "$AWG_BIN" && -x "$AWG_QUICK_BIN" && -f "$AWG_CONFIG" ]]
}

service_active() {
    systemctl is-active --quiet "$AWG_SERVICE_NAME" 2>/dev/null
}

# 协议线：2 = AWG 2.x，3 = AWG 3.x
version_line() {
    local v
    v="$(meta_get line)"
    if [[ "$v" == "2" || "$v" == "3" ]]; then
        echo "$v"
    else
        echo "3"
    fi
}

# 默认出口网卡（用于 MASQUERADE）
detect_wan_iface() {
    local wan
    wan="$(ip -4 route show default 2>/dev/null \
        | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
    echo "${wan:-eth0}"
}

# 找一个可用的 UDP 端口（必须避开 Hysteria2 的端口跳跃区间）
pick_port() {
    local hy2_port="${1:-}" port
    port="$(python3 - "$AWG_PORT_MIN" "$AWG_PORT_MAX" "$hy2_port" <<'PY'
import secrets, socket, sys
lo, hi = int(sys.argv[1]), int(sys.argv[2])
hy2 = sys.argv[3]
for _ in range(500):
    p = lo + secrets.randbelow(hi - lo + 1)
    if hy2.isdigit() and int(hy2) == p:
        continue
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.bind(('0.0.0.0', p))
        except OSError:
            continue
        print(p)
        break
else:
    raise SystemExit('no-free-udp-port')
PY
)" || true
    [[ -n "$port" ]] || return 1
    echo "$port"
}

# 端口合规校验。返回 0 通过；非 0 时把原因打到 stderr。
validate_port() {
    local port="$1"
    [[ "$port" =~ ^[0-9]+$ ]] || { log_err "端口必须是数字: ${port}"; return 1; }
    [[ "$port" -ge 1 && "$port" -le 65535 ]] || { log_err "端口超出范围 1-65535: ${port}"; return 1; }
    if [[ "$port" -ge 20000 && "$port" -le 40000 ]]; then
        log_err "端口 ${port} 落在 Hysteria2 的端口跳跃区间 20000-40000 内。"
        log_err "该区间的 UDP 已被 iptables REDIRECT 到 Hysteria 主端口，AmneziaWG 将收不到任何握手包。"
        log_err "请改用区间外的端口（推荐 50000-59000）。"
        return 1
    fi
    if [[ "$port" -eq 51820 ]]; then
        log_warn "端口 51820 是 WireGuard 的默认端口，本身就是一个弱指纹，建议改用其他端口。"
    fi
    return 0
}

# ==============================================================================
# 二进制获取
# ==============================================================================

download_binaries() {
    local line="$1" arch="$2"
    local url tmpd

    url="https://github.com/${AWG_REPO}/releases/download/${AWG_RELEASE_TAG}/amneziawg-linux-${arch}-awg${line}.tar.gz"
    log_step "下载 AmneziaWG 二进制 (协议线 AWG ${line}.x / 架构 ${arch})"
    log_info "来源: ${url}"

    tmpd="$(mktemp -d)"
    if ! curl -fL --connect-timeout 20 --retry 2 --retry-delay 2 \
            -o "${tmpd}/awg.tar.gz" "$url" 2>/dev/null; then
        rm -rf "$tmpd"
        log_err "下载失败。可能原因："
        log_err "  1) 仓库 Release 尚未构建 —— 请在 GitHub Actions 中手动运行"
        log_err "     'Build AmneziaWG binaries' 工作流，它会产出标签 ${AWG_RELEASE_TAG}"
        log_err "  2) 本机无法访问 github.com"
        return 1
    fi

    if ! tar -xzf "${tmpd}/awg.tar.gz" -C "$tmpd" 2>/dev/null; then
        rm -rf "$tmpd"; log_err "解压失败（包可能已损坏）"; return 1
    fi

    local f
    for f in amneziawg-go awg awg-quick; do
        if [[ ! -f "${tmpd}/${f}" ]]; then
            rm -rf "$tmpd"; log_err "包内缺少组件: ${f}"; return 1
        fi
    done

    mkdir -p "$AWG_DIR"
    install -m 0755 "${tmpd}/amneziawg-go" "$AWG_GO_BIN"
    install -m 0755 "${tmpd}/awg"          "$AWG_BIN"
    install -m 0755 "${tmpd}/awg-quick"    "$AWG_QUICK_BIN"
    if [[ -f "${tmpd}/VERSION" ]]; then
        cp -f "${tmpd}/VERSION" "$AWG_VERSION_FILE"
        chmod 600 "$AWG_VERSION_FILE"
    fi
    rm -rf "$tmpd"
    log_info "已安装: ${AWG_GO_BIN} / ${AWG_BIN} / ${AWG_QUICK_BIN}"
}

# 二进制完整性预检。
# 必要性：awg-quick 在"内核模块不可用 + PATH 里找不到 amneziawg-go"时会直接静默退出，
# 退出码来自 `ip link add` 的失败，报错完全看不出真正原因。这里提前拦住。
preflight_binaries() {
    local missing=0 b
    for b in "$AWG_GO_BIN" "$AWG_BIN" "$AWG_QUICK_BIN"; do
        if [[ ! -x "$b" ]]; then
            log_err "缺少可执行文件或权限不足: $b"
            missing=1
        fi
    done
    [[ "$missing" -eq 0 ]] || return 1

    if [[ -e /sys/module/amneziawg ]]; then
        log_info "检测到 amneziawg 内核模块，awg-quick 将优先使用内核态（性能更好）"
    else
        log_info "未检测到内核模块，使用用户态 amneziawg-go（本项目默认形态）"
    fi
    return 0
}

# ==============================================================================
# 密钥与混淆参数
# ==============================================================================

genkey() { "$AWG_BIN" genkey; }
pubkey_of() { printf '%s' "$1" | "$AWG_BIN" pubkey; }
genpsk() { "$AWG_BIN" genpsk; }

# 生成一组随机混淆参数并写入全局变量。
#
# 参数约束来源：amneziawg-linux-kernel-module README + amneziawg-go README
#   Jc      1 ~ 128（官方推荐 4~12）
#   Jmin/Jmax  0 <= Jmin < Jmax < 1280（官方推荐 8 / 80）
#   S1      <= 1132 = 1280 - 148     S2 <= 1188 = 1280 - 92
#           S1 + 56 != S2
#           官方推荐区间 15~150
#   H1~H4   官方推荐 5 ~ 2147483647，且四者必须互不相同、范围不得重叠
#   AWG 3.x 头部保护要求 S1~S4 全部 >= 12
AWG_JC=""; AWG_JMIN=""; AWG_JMAX=""
AWG_S1=""; AWG_S2=""; AWG_S3=""; AWG_S4=""
AWG_H1=""; AWG_H2=""; AWG_H3=""; AWG_H4=""

gen_obfs_params() {
    local line="$1"

    AWG_JC=$(( RANDOM % 9 + 4 ))     # 4~12
    AWG_JMIN=8
    AWG_JMAX=80

    # S4 是 Data 包的随机填充。3.x 的头部保护硬性要求 >= 12。
    if [[ "$line" == "3" ]]; then
        AWG_S4="$(awg_rand 12 32)"
    else
        AWG_S4="$(awg_rand 0 32)"
    fi

    while :; do
        AWG_S1="$(awg_rand 15 150)"
        AWG_S2="$(awg_rand 15 150)"
        # S1 + 56 != S2 是官方硬约束（否则会与 Response 包的基准长度撞车）
        [[ $(( AWG_S1 + 56 )) -ne "$AWG_S2" ]] && break
    done
    AWG_S3="$(awg_rand 15 150)"

    # H1~H4：把整个取值空间四等分，各取一段。
    # 这样即使将来把单值改写成范围，也天然满足"范围不得重叠"的硬要求。
    local band h1 h2 h3 h4
    band=$(( (2147483647 - 5) / 4 ))
    h1="$(awg_rand 5 "$band")"
    h2="$(awg_rand $(( band + 1 )) $(( band * 2 )))"
    h3="$(awg_rand $(( band * 2 + 1 )) $(( band * 3 )))"
    h4="$(awg_rand $(( band * 3 + 1 )) 2147483647)"
    AWG_H1="$h1"; AWG_H2="$h2"; AWG_H3="$h3"; AWG_H4="$h4"
}

# ==============================================================================
# 配置渲染
# ==============================================================================

# 生成服务端配置。以 meta + peers 为唯一事实来源，本函数只做渲染。
render_server_config() {
    require_jq

    local line port priv wan mtu hp s4v
    line="$(version_line)"
    port="$(meta_get port)"
    priv="$(meta_get server_private_key)"
    hp="$(meta_get HeaderProtectionKey)"
    wan="$(detect_wan_iface)"

    [[ -n "$port" ]] || die "meta 中缺少 port，无法渲染配置"
    [[ -n "$priv" ]] || die "meta 中缺少 server_private_key，无法渲染配置"

    # MTU 必须扣掉 S4：S4 是每个 Data 包的随机填充，不扣掉外层会分片。
    # 基准 1420 = 1500 - 20(IP) - 8(UDP) - 32(WG 数据包头+认证标签) - 20(预留)。
    s4v="$(meta_get S4)"; s4v="${s4v:-0}"
    mtu=$(( 1420 - s4v ))

    local tmp
    tmp="$(mktemp "${AWG_DIR}/.conf.XXXXXX")"
    {
        echo "# ============================================================"
        echo "# AmneziaWG 服务端配置 —— 由 hy2-awgctl 自动生成，请勿手工编辑"
        echo "# 协议线: AWG ${line}.x    监听: UDP ${port}    出口网卡: ${wan}"
        echo "#"
        echo "# ⚠️ S1~S4 / H1~H4 / HeaderProtectionKey 必须与客户端逐字节一致。"
        echo "#    改这里等于让所有已发放的客户端配置立即失效。"
        echo "# 如需调整，请用: hy2-awgctl resync"
        echo "# ============================================================"
        echo "[Interface]"
        echo "PrivateKey = ${priv}"
        echo "Address = ${AWG_SUBNET}.1/24"
        echo "ListenPort = ${port}"
        echo "MTU = ${mtu}"
        echo "Jc = $(meta_get Jc)"
        echo "Jmin = $(meta_get Jmin)"
        echo "Jmax = $(meta_get Jmax)"
        echo "S1 = $(meta_get S1)"
        echo "S2 = $(meta_get S2)"
        echo "S3 = $(meta_get S3)"
        echo "S4 = $(meta_get S4)"
        echo "H1 = $(meta_get H1)"
        echo "H2 = $(meta_get H2)"
        echo "H3 = $(meta_get H3)"
        echo "H4 = $(meta_get H4)"
        # HeaderProtectionKey 只有 3.x 支持
        if [[ "$line" == "3" && -n "$hp" ]]; then
            echo "HeaderProtectionKey = ${hp}"
        fi
        echo "PostUp = sysctl -qw net.ipv4.ip_forward=1; iptables -I FORWARD -i ${AWG_LINK} -j ACCEPT; iptables -t nat -A POSTROUTING -o ${wan} -j MASQUERADE"
        echo "PostDown = iptables -D FORWARD -i ${AWG_LINK} -j ACCEPT; iptables -t nat -D POSTROUTING -o ${wan} -j MASQUERADE"

        if [[ -s "$AWG_PEERS_FILE" ]]; then
            jq -r '
                .peers[]? |
                "\n[Peer]\n# \(.name)\nPublicKey = \(.public_key)\nPresharedKey = \(.preshared_key)\nAllowedIPs = \(.address)/32"
            ' "$AWG_PEERS_FILE"
        fi
    } > "$tmp"

    chmod 600 "$tmp"
    mv -f "$tmp" "$AWG_CONFIG"
}

# 生成客户端配置文本
render_client_config() {
    local name="$1" endpoint="$2"
    require_jq

    [[ -f "$AWG_PEERS_FILE" ]] || die "尚无任何客户端，请先执行 peer-add"

    local line port hp mtu priv pub psk addr s4v
    line="$(version_line)"
    port="$(meta_get port)"
    hp="$(meta_get HeaderProtectionKey)"
    pub="$(meta_get server_public_key)"
    s4v="$(meta_get S4)"; s4v="${s4v:-0}"
    mtu=$(( 1420 - s4v ))

    priv="$(jq -r --arg n "$name" '.peers[]? | select(.name==$n) | .private_key' "$AWG_PEERS_FILE")"
    psk="$(jq  -r --arg n "$name" '.peers[]? | select(.name==$n) | .preshared_key' "$AWG_PEERS_FILE")"
    addr="$(jq -r --arg n "$name" '.peers[]? | select(.name==$n) | .address' "$AWG_PEERS_FILE")"

    [[ -n "$priv" ]] || die "找不到客户端: ${name}"

    echo "# AmneziaWG 客户端配置 (AWG ${line}.x) —— ${name}"
    echo "# ⚠️ 下方 S1~S4 / H1~H4 等混淆参数必须与服务端完全一致，请勿改动。"
    echo "[Interface]"
    echo "PrivateKey = ${priv}"
    echo "Address = ${addr}/32"
    echo "DNS = 1.1.1.1"
    echo "MTU = ${mtu}"
    echo "Jc = $(meta_get Jc)"
    echo "Jmin = $(meta_get Jmin)"
    echo "Jmax = $(meta_get Jmax)"
    echo "S1 = $(meta_get S1)"
    echo "S2 = $(meta_get S2)"
    echo "S3 = $(meta_get S3)"
    echo "S4 = $(meta_get S4)"
    echo "H1 = $(meta_get H1)"
    echo "H2 = $(meta_get H2)"
    echo "H3 = $(meta_get H3)"
    echo "H4 = $(meta_get H4)"
    if [[ "$line" == "3" && -n "$hp" ]]; then
        echo "HeaderProtectionKey = ${hp}"
    fi
    echo ""
    echo "[Peer]"
    echo "PublicKey = ${pub}"
    echo "PresharedKey = ${psk}"
    echo "Endpoint = ${endpoint}:${port}"
    echo "AllowedIPs = 0.0.0.0/0"
    echo "PersistentKeepalive = 25"
}

# ==============================================================================
# systemd 服务
# ==============================================================================

write_service() {
    cat > "$AWG_SERVICE" <<EOF
[Unit]
Description=AmneziaWG Server (userspace daemon via awg-quick)
Documentation=https://github.com/${AWG_REPO}
After=network-online.target nss-lookup.target
Wants=network-online.target nss-lookup.target
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=oneshot
RemainAfterExit=yes
# 显式指定用户态实现，避免 awg-quick 依赖 PATH 查找而静默失败
Environment=WG_QUICK_USERSPACE_IMPLEMENTATION=${AWG_GO_BIN}
Environment=WG_ENDPOINT_RESOLUTION_RETRIES=infinity
ExecStart=${AWG_QUICK_BIN} up ${AWG_LINK}
ExecStop=${AWG_QUICK_BIN} down ${AWG_LINK}
ExecReload=/bin/bash -c 'exec ${AWG_BIN} syncconf ${AWG_LINK} <(exec ${AWG_QUICK_BIN} strip ${AWG_LINK})'
TimeoutStopSec=20
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
    chmod 644 "$AWG_SERVICE"
    systemctl daemon-reload
}

# ==============================================================================
# 防火墙放行
# ==============================================================================

allow_firewall() {
    local port="$1"
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
        ufw allow "${port}/udp" >/dev/null 2>&1 || true
        log_info "已放行 UFW: ${port}/udp"
    fi
    if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active firewalld >/dev/null 2>&1; then
        firewall-cmd --zone=public --add-port="${port}/udp" --permanent >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
        log_info "已放行 firewalld: ${port}/udp"
    fi
    return 0
}

# ==============================================================================
# Peer（客户端）管理
# ==============================================================================

peers_init() {
    if [[ ! -f "$AWG_PEERS_FILE" ]]; then
        mkdir -p "$AWG_DIR"
        echo '{"peers":[]}' > "$AWG_PEERS_FILE"
        chmod 600 "$AWG_PEERS_FILE"
    fi
}

peer_exists() {
    local name="$1" n
    [[ -f "$AWG_PEERS_FILE" ]] || return 1
    n="$(jq -r --arg n "$name" '[.peers[]? | select(.name==$n)] | length' "$AWG_PEERS_FILE")"
    [[ "$n" != "0" && -n "$n" ]]
}

# 分配下一个隧道内网地址（.2 起，.1 留给服务端）
next_peer_address() {
    local used n
    used="$(jq -r '[.peers[]?.address] | join(" ")' "$AWG_PEERS_FILE" 2>/dev/null || echo "")"
    for n in $(seq 2 254); do
        if [[ " ${used} " != *" ${AWG_SUBNET}.${n} "* ]]; then
            echo "${AWG_SUBNET}.${n}"
            return 0
        fi
    done
    return 1
}

# 把 peer 热加入运行中的接口（不重启服务，不断其他客户端）
peer_apply_live_add() {
    local pub="$1" psk="$2" addr="$3"
    service_active || return 0
    local pskf
    pskf="$(mktemp)"
    printf '%s\n' "$psk" > "$pskf"
    "$AWG_BIN" set "$AWG_LINK" peer "$pub" preshared-key "$pskf" allowed-ips "${addr}/32" 2>/dev/null || true
    rm -f "$pskf"
    return 0
}

peer_apply_live_del() {
    local pub="$1"
    service_active || return 0
    "$AWG_BIN" set "$AWG_LINK" peer "$pub" remove 2>/dev/null || true
    return 0
}

cmd_peer_add() {
    local name="${1:-}" endpoint="${2:-}"
    require_root
    require_jq
    is_installed || die "AmneziaWG 尚未安装，请先执行: hy2-awgctl install"

    [[ -n "$name" ]] || die "用法: hy2-awgctl peer-add <名称> [--endpoint HOST]"
    [[ "$name" =~ ^[A-Za-z0-9_.-]{1,32}$ ]] || die "客户端名称只允许字母/数字/._- 且不超过 32 字符"

    if peer_exists "$name"; then
        die "客户端已存在: ${name}"
    fi

    peers_init
    [[ -n "$endpoint" ]] || endpoint="$(meta_get endpoint)"

    local priv pub psk addr tmp
    priv="$(genkey)"
    pub="$(pubkey_of "$priv")"
    psk="$(genpsk)"
    addr="$(next_peer_address)" || die "隧道地址池已满（10.66.66.0/24 上限 253 个客户端）"

    tmp="$(mktemp "${AWG_DIR}/.peers.XXXXXX")"
    jq --arg n "$name" --arg ip "$addr" --arg priv "$priv" \
       --arg pub "$pub" --arg psk "$psk" --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
       '.peers += [{name:$n, address:$ip, private_key:$priv, public_key:$pub,
                    preshared_key:$psk, created_at:$ts, enabled:true}]' \
       "$AWG_PEERS_FILE" > "$tmp"
    chmod 600 "$tmp"
    mv -f "$tmp" "$AWG_PEERS_FILE"

    render_server_config
    peer_apply_live_add "$pub" "$psk" "$addr"

    log_info "客户端已创建: ${name}  (隧道地址 ${addr})"
    if [[ -n "$endpoint" ]]; then
        echo ""
        render_client_config "$name" "$endpoint"
    else
        log_warn "未记录连接地址(Endpoint)，如需输出客户端配置请执行:"
        log_warn "  hy2-awgctl client-conf ${name} --endpoint <域名或公网IP>"
    fi
}

cmd_peer_del() {
    local name="${1:-}"
    require_root
    require_jq
    peers_init
    [[ -n "$name" ]] || die "用法: hy2-awgctl peer-del <名称>"
    peer_exists "$name" || die "客户端不存在: ${name}"

    local pub tmp
    pub="$(jq -r --arg n "$name" '.peers[]? | select(.name==$n) | .public_key' "$AWG_PEERS_FILE")"

    tmp="$(mktemp "${AWG_DIR}/.peers.XXXXXX")"
    jq --arg n "$name" '.peers |= map(select(.name != $n))' "$AWG_PEERS_FILE" > "$tmp"
    chmod 600 "$tmp"
    mv -f "$tmp" "$AWG_PEERS_FILE"

    render_server_config
    peer_apply_live_del "$pub"
    log_info "客户端已删除: ${name}"
}

cmd_peer_list() {
    require_jq
    if [[ ! -f "$AWG_PEERS_FILE" ]]; then
        if [[ "${1:-}" == "--json" ]]; then
            echo '[]'
        else
            log_warn "尚无任何客户端。"
        fi
        return 0
    fi

    if [[ "${1:-}" == "--json" ]]; then
        # 不输出私钥，避免门户页面泄露
        jq '[.peers[]? | {name, address, public_key, created_at, enabled}]' "$AWG_PEERS_FILE"
        return 0
    fi

    local count
    count="$(jq '[.peers[]?] | length' "$AWG_PEERS_FILE")"
    if [[ "$count" == "0" ]]; then
        log_warn "尚无任何客户端。"
        return 0
    fi

    # 用单条 awk 管道拼表：避免把 while 放进子 shell，也避免在循环里踩 set -e
    local transfer_data=""
    if service_active && [[ -x "$AWG_BIN" ]]; then
        transfer_data="$("$AWG_BIN" show "$AWG_LINK" transfer 2>/dev/null || true)"
    fi

    {
        printf '%-20s %-16s %-20s %s\n' "名称" "隧道地址" "创建时间" "流量(下行/上行)"
        printf -- '--------------------------------------------------------------------------------\n'
        jq -r '.peers[]? | [.name, .address, .created_at, .public_key] | @tsv' "$AWG_PEERS_FILE"
    } | awk -F'\t' -v tr="$transfer_data" '
        BEGIN {
            n = split(tr, lines, "\n")
            for (i = 1; i <= n; i++) {
                if (split(lines[i], f, /[ \t]+/) >= 3) { rx[f[1]] = f[2]; tx[f[1]] = f[3] }
            }
        }
        NF < 4 { print; next }
        {
            if ($4 in rx) {
                printf "%-20s %-16s %-20s ↓%.1fMB / ↑%.1fMB\n", $1, $2, $3, rx[$4]/1048576, tx[$4]/1048576
            } else {
                printf "%-20s %-16s %-20s %s\n", $1, $2, $3, "-"
            }
        }
    '
}

cmd_client_conf() {
    local name="${1:-}" endpoint="${2:-}"
    require_root
    require_jq
    is_installed || die "AmneziaWG 尚未安装。"
    [[ -n "$name" ]] || die "用法: hy2-awgctl client-conf <名称> [--endpoint HOST]"
    peer_exists "$name" || die "客户端不存在: ${name}"

    if [[ -z "$endpoint" ]]; then
        endpoint="$(meta_get endpoint)"
    fi
    [[ -n "$endpoint" ]] || die "未指定连接地址，请加 --endpoint <域名或公网IP>"

    render_client_config "$name" "$endpoint"
}

# ==============================================================================
# 安装 / 卸载 / 状态 / 更新
# ==============================================================================

cmd_install() {
    local line="" port="" endpoint="" client="" server_name=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --line)      line="$2"; shift 2 ;;
            --port)      port="$2"; shift 2 ;;
            --endpoint)  endpoint="$2"; shift 2 ;;
            --client)    client="$2"; shift 2 ;;
            --server-name) server_name="$2"; shift 2 ;;
            *) die "install 未知参数: $1" ;;
        esac
    done

    require_root
    require_jq
    command -v ip >/dev/null 2>&1 || die "缺少 ip 命令，请安装 iproute2"
    command -v python3 >/dev/null 2>&1 || die "缺少 python3（用于端口探测与随机数）"
    # iptables 是本配置 PostUp/PostDown 的硬依赖（做 FORWARD 放行与 MASQUERADE）。
    # 缺它时 awg-quick up 会在执行 hook 时失败，而报错只会显示 hook 的退出码，
    # 完全看不出是缺 iptables —— 所以在这里提前拦。
    command -v iptables >/dev/null 2>&1 || die "缺少 iptables（PostUp/PostDown 需要它做 NAT 转发），请先安装：apt-get install -y iptables"

    # 协议线：显式指定 > 已有 meta > 默认 3
    if [[ -z "$line" ]]; then
        line="$(version_line)"
    fi
    [[ "$line" == "2" || "$line" == "3" ]] || die "协议线只能是 2 或 3，收到: ${line}"

    # 架构
    local arch
    case "$(uname -m)" in
        x86_64|amd64)   arch="amd64" ;;
        aarch64|arm64)  arch="arm64" ;;
        armv7l|armhf)   arch="armv7" ;;
        *) die "不支持的 CPU 架构: $(uname -m)" ;;
    esac

    local existing=0
    is_installed && existing=1
    if [[ "$existing" == "1" ]]; then
        log_warn "检测到已有 AmneziaWG 安装，将保留现有密钥与客户端，只刷新二进制与配置。"
        log_warn "如需更换协议线，原有客户端配置会失效，必须重新导出。"
    fi

    # 端口
    local hy2_port=""
    if [[ -f /etc/hysteria/client_meta.json ]]; then
        hy2_port="$(jq -r '.listen_port // empty' /etc/hysteria/client_meta.json 2>/dev/null || true)"
    fi
    if [[ -z "$port" ]]; then
        if [[ "$existing" == "1" ]]; then
            port="$(meta_get port)"
        fi
        if [[ -z "$port" ]]; then
            port="$(pick_port "$hy2_port")" || die "无法找到空闲的 UDP 端口（${AWG_PORT_MIN}-${AWG_PORT_MAX}）"
            log_info "自动选择监听端口: ${port}"
        fi
    fi
    validate_port "$port" || exit 1

    log_step "安装 AmneziaWG（协议线 AWG ${line}.x，架构 ${arch}，UDP ${port}）"

    download_binaries "$line" "$arch"
    preflight_binaries || exit 1

    # 服务端密钥（已存在则保留，避免让全部客户端失效）
    local priv pub
    priv="$(meta_get server_private_key)"
    if [[ -z "$priv" ]]; then
        priv="$(genkey)"
        log_info "已生成服务端密钥对"
    else
        log_info "沿用已有服务端密钥"
    fi
    pub="$(pubkey_of "$priv")"

    meta_set line "$line"
    meta_set port "$port"
    meta_set server_private_key "$priv"
    meta_set server_public_key "$pub"
    meta_set arch "$arch"
    if [[ -n "$server_name" ]]; then
        meta_set server_name "$server_name"
    fi

    # 混淆参数（已存在则保留 —— 否则所有客户端立刻失效）
    if [[ -z "$(meta_get S1)" ]]; then
        gen_obfs_params "$line"
        meta_set Jc "$AWG_JC";     meta_set Jmin "$AWG_JMIN"; meta_set Jmax "$AWG_JMAX"
        meta_set S1 "$AWG_S1";     meta_set S2 "$AWG_S2"
        meta_set S3 "$AWG_S3";     meta_set S4 "$AWG_S4"
        meta_set H1 "$AWG_H1";     meta_set H2 "$AWG_H2"
        meta_set H3 "$AWG_H3";     meta_set H4 "$AWG_H4"
        log_info "已生成随机混淆参数 (Jc=${AWG_JC} S=[${AWG_S1},${AWG_S2},${AWG_S3},${AWG_S4}])"
    else
        log_info "沿用已有混淆参数"
    fi

    # 3.x 头部保护密钥
    if [[ "$line" == "3" && -z "$(meta_get HeaderProtectionKey)" ]]; then
        meta_set HeaderProtectionKey "$(genkey)"
        log_info "已生成 3.x 头部保护密钥 (HeaderProtectionKey)"
    fi

    if [[ -n "$endpoint" ]]; then
        meta_set endpoint "$endpoint"
    fi

    peers_init
    render_server_config

    # 落盘前做一次自检：服务端与客户端必须共享同一组混淆参数
    local chk
    chk="$(grep -cE '^(S[1-4]|H[1-4]) = ' "$AWG_CONFIG" || true)"
    if [[ "$chk" -ne 8 ]]; then
        die "服务端配置自检失败：期望 8 个混淆参数(S1-S4/H1-H4)，实际 ${chk} 个"
    fi

    write_service
    systemctl enable "$AWG_SERVICE_NAME" >/dev/null 2>&1 || true

    # 接口已存在时先拆掉，避免 awg-quick 报 "already exists"
    if ip link show dev "$AWG_LINK" >/dev/null 2>&1; then
        log_info "清理已存在的 ${AWG_LINK} 接口..."
        "$AWG_QUICK_BIN" down "$AWG_LINK" >/dev/null 2>&1 || ip link delete dev "$AWG_LINK" 2>/dev/null || true
    fi

    log_step "启动 AmneziaWG 服务..."
    if ! systemctl restart "$AWG_SERVICE_NAME"; then
        log_err "服务启动失败，最近日志："
        journalctl -u "$AWG_SERVICE_NAME" -n 25 --no-pager >&2 || true
        exit 1
    fi
    sleep 2

    if ! service_active; then
        log_err "服务未处于 active 状态，最近日志："
        journalctl -u "$AWG_SERVICE_NAME" -n 25 --no-pager >&2 || true
        exit 1
    fi
    ip link show dev "$AWG_LINK" >/dev/null 2>&1 \
        || die "服务显示 active 但 ${AWG_LINK} 接口不存在，请检查 journalctl -u ${AWG_SERVICE_NAME}"

    allow_firewall "$port"

    # 首个客户端
    local ep
    if [[ -z "$client" ]]; then
        client="client1"
    fi
    ep="${endpoint:-$(meta_get endpoint)}"
    if ! peer_exists "$client"; then
        if [[ -n "$ep" ]]; then
            log_step "创建首个客户端: ${client}"
            if ! cmd_peer_add "$client" "$ep"; then
                log_warn "自动创建首个客户端失败，请手动执行:"
                log_warn "  hy2-awgctl peer-add ${client} --endpoint ${ep}"
            fi
        else
            log_warn "未提供客户端连接地址（Endpoint），已跳过首个客户端创建。"
            log_warn "请手动执行: hy2-awgctl peer-add ${client} --endpoint <域名或公网IP>"
        fi
    fi

    log_info "AmneziaWG 安装完成。"
    log_info "别忘了在云厂商安全组放行 UDP ${port}。"
    echo ""
    cmd_status
}

cmd_uninstall() {
    local keep_binaries=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --keep-binaries) keep_binaries=1; shift ;;
            *) die "uninstall 未知参数: $1" ;;
        esac
    done

    require_root

    log_step "停止并移除 AmneziaWG 服务..."
    systemctl stop "$AWG_SERVICE_NAME" 2>/dev/null || true
    systemctl disable "$AWG_SERVICE_NAME" 2>/dev/null || true

    # awg-quick down 会执行 PostDown，顺带清掉 FORWARD 与 MASQUERADE 规则
    if command -v ip >/dev/null 2>&1 && ip link show dev "$AWG_LINK" >/dev/null 2>&1; then
        if [[ -x "$AWG_QUICK_BIN" ]]; then
            "$AWG_QUICK_BIN" down "$AWG_LINK" >/dev/null 2>&1 || true
        fi
        ip link delete dev "$AWG_LINK" 2>/dev/null || true
    fi
    rm -f "$AWG_SERVICE"
    systemctl daemon-reload 2>/dev/null || true

    if [[ "$keep_binaries" != "1" ]]; then
        rm -f "$AWG_GO_BIN" "$AWG_BIN" "$AWG_QUICK_BIN"
        log_info "已移除二进制"
    fi

    rm -rf "$AWG_DIR"
    log_info "已移除配置目录 ${AWG_DIR}"
    log_info "AmneziaWG 已彻底卸载。"
    log_warn "云安全组里为该端口放行的 UDP 规则需要你自行清理。"
}

cmd_status() {
    local installed="no" active="no" line port peers_count="" go_tag="" tools_tag=""

    is_installed && installed="yes"
    service_active && active="yes"
    line="$(version_line)"
    port="$(meta_get port)"

    if [[ -f "$AWG_PEERS_FILE" ]]; then
        peers_count="$(jq -r '[.peers[]?] | length' "$AWG_PEERS_FILE" 2>/dev/null || echo "")"
    fi
    if [[ -f "$AWG_VERSION_FILE" ]]; then
        go_tag="$(awk -F= '/^amneziawg-go=/{print $2}' "$AWG_VERSION_FILE" 2>/dev/null || true)"
        tools_tag="$(awk -F= '/^amneziawg-tools=/{print $2}' "$AWG_VERSION_FILE" 2>/dev/null || true)"
    fi

    if [[ "$installed" != "yes" ]]; then
        echo "AmneziaWG: 未安装"
        return 0
    fi

    echo "=============== AmneziaWG 运行状态 ==============="
    printf '协议线      : AWG %s.x\n' "$line"
    printf '服务状态    : %s\n' "$([[ "$active" == "yes" ]] && echo "运行中" || echo "未运行")"
    printf '监听端口    : UDP %s\n' "${port:-未知}"
    printf '隧道网段    : %s.0/24\n' "$AWG_SUBNET"
    printf '客户端数量  : %s\n' "${peers_count:-0}"
    printf '数据面      : %s\n' "$([[ -e /sys/module/amneziawg ]] && echo "内核模块" || echo "用户态 amneziawg-go")"
    if [[ -n "$go_tag" ]]; then
        printf '二进制版本  : amneziawg-go %s / tools %s\n' "$go_tag" "${tools_tag:-未知}"
    fi
    printf '二进制来源  : %s @ %s\n' "$AWG_REPO" "$AWG_RELEASE_TAG"

    if [[ "$active" == "yes" ]] && [[ -x "$AWG_BIN" ]]; then
        echo "--------------------------------------------------"
        "$AWG_BIN" show "$AWG_LINK" 2>/dev/null || true
    fi
    echo "=================================================="
    return 0
}

# 更新二进制（保持协议线与全部参数不变，客户端无需重新导入）
cmd_update() {
    local line=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --line) line="$2"; shift 2 ;;
            *) die "update 未知参数: $1" ;;
        esac
    done
    require_root
    is_installed || die "AmneziaWG 尚未安装，请先执行 install"

    local arch
    case "$(uname -m)" in
        x86_64|amd64)  arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        armv7l|armhf)  arch="armv7" ;;
        *) die "不支持的 CPU 架构: $(uname -m)" ;;
    esac

    if [[ -z "$line" ]]; then
        line="$(version_line)"
    fi
    [[ "$line" == "2" || "$line" == "3" ]] || die "协议线只能是 2 或 3"

    local old_line
    old_line="$(version_line)"

    download_binaries "$line" "$arch"
    preflight_binaries || exit 1
    meta_set arch "$arch"

    if [[ "$old_line" != "$line" ]]; then
        # 跨协议线切换：参数体系不同，必须重新生成混淆参数并让客户端重新导入
        log_warn "协议线由 AWG ${old_line}.x 切换为 AWG ${line}.x"
        log_warn "参数体系不同，将重新生成混淆参数 —— 所有已发放的客户端配置都会失效！"
        meta_set line "$line"
        if [[ "$line" == "3" ]]; then
            # 3.x 要求 S1~S4 >= 12，2.x 的 S4 可能是 0~11，必须重生成
            local s4
            s4="$(meta_get S4)"
            if [[ "${s4:-0}" -lt 12 ]]; then
                log_warn "旧 S4=${s4} 不满足 3.x 头部保护的 >=12 要求，正在重新生成全部混淆参数"
                gen_obfs_params "$line"
                meta_set Jc "$AWG_JC"; meta_set Jmin "$AWG_JMIN"; meta_set Jmax "$AWG_JMAX"
                meta_set S1 "$AWG_S1"; meta_set S2 "$AWG_S2"
                meta_set S3 "$AWG_S3"; meta_set S4 "$AWG_S4"
                meta_set H1 "$AWG_H1"; meta_set H2 "$AWG_H2"
                meta_set H3 "$AWG_H3"; meta_set H4 "$AWG_H4"
            fi
        fi
        if [[ "$line" == "3" && -z "$(meta_get HeaderProtectionKey)" ]]; then
            meta_set HeaderProtectionKey "$(genkey)"
        fi
        render_server_config
        log_warn "⚠️ 请立即为所有客户端重新导出配置（旧配置已全部失效）:"
        log_warn "  hy2-awgctl peer-list"
        log_warn "  hy2-awgctl client-conf <名称> --endpoint <域名或公网IP>"
    else
        log_info "协议线未变 (AWG ${line}.x)，配置与客户端均不受影响。"
    fi

    systemctl restart "$AWG_SERVICE_NAME"
    sleep 2
    if service_active; then
        log_info "更新完成，服务运行正常。"
    else
        log_err "更新后服务启动失败："
        journalctl -u "$AWG_SERVICE_NAME" -n 25 --no-pager >&2 || true
        exit 1
    fi
}

# 依 meta 重新渲染服务端配置并热重载（不中断现有连接）
cmd_resync() {
    require_root
    require_jq
    is_installed || die "AmneziaWG 尚未安装。"
    render_server_config
    systemctl restart "$AWG_SERVICE_NAME"
    sleep 2
    service_active && log_info "配置已重新同步，服务正常。" || die "重载后服务异常"
}

# ==============================================================================
# 输出辅助
# ==============================================================================

cmd_qr() {
    local name="${1:-}" endpoint="${2:-}"
    is_installed || die "AmneziaWG 尚未安装。"
    [[ -n "$name" ]] || die "用法: hy2-awgctl qr <名称> [--endpoint HOST]"
    if ! command -v qrencode >/dev/null 2>&1; then
        die "缺少 qrencode，请先安装：apt-get install -y qrencode"
    fi
    render_client_config "$name" "${endpoint:-$(meta_get endpoint)}" | qrencode -t ANSIUTF8
}

# 解析 "名称 [--endpoint HOST]" 形式的参数。
# 之所以抽出来：直接在 case 里写 `shift 2` 时，--endpoint 后面缺值会因参数
# 越界在 set -u 下直接报错退出，报错信息也看不出真正原因。
PARSED_NAME=""
PARSED_ENDPOINT=""
parse_name_endpoint() {
    PARSED_NAME=""
    PARSED_ENDPOINT=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --endpoint)
                if [[ $# -lt 2 ]]; then
                    die "--endpoint 缺少取值（应形如 --endpoint vpn.example.com）"
                fi
                PARSED_ENDPOINT="$2"
                shift 2
                ;;
            -*)
                die "未知参数: $1"
                ;;
            *)
                if [[ -n "$PARSED_NAME" ]]; then
                    die "只能指定一个客户端名称，多余参数: $1"
                fi
                PARSED_NAME="$1"
                shift
                ;;
        esac
    done
}

show_help() {
    cat <<'EOF'
hy2-awgctl —— AmneziaWG (AWG) 服务端控制工具

用法:
  hy2-awgctl <命令> [参数]

安装与维护:
  install    [--line 2|3] [--port N] [--endpoint HOST] [--client NAME]
             安装或重装。--endpoint 是客户端连接地址（域名或公网 IP）。
  update     [--line 2|3]
             更新二进制。切换协议线会重新生成混淆参数，客户端必须重新导入。
  uninstall  [--keep-binaries]
             彻底卸载，同时清理接口与 NAT 规则。
  status     查看运行状态。
  resync     依 meta 重新渲染服务端配置并重启服务。

客户端管理:
  peer-add   <名称> [--endpoint HOST]    新建客户端并打印其 .conf
  peer-del   <名称>                      删除客户端（立即断开该客户端）
  peer-list  [--json]                    列出客户端
  client-conf <名称> [--endpoint HOST]   输出客户端 .conf 文本
  qr         <名称> [--endpoint HOST]    直接在终端显示二维码

环境变量:
  AWG_REPO          二进制来源仓库，默认 yys9253462-gif/hysteria2-installer
  AWG_RELEASE_TAG   二进制所在 Release 标签，默认 awg-binaries

退出码:
  0 成功   1 失败（含参数错误、服务启动失败）
EOF
}

# ==============================================================================
# 入口
# ==============================================================================
main() {
    local cmd="${1:-}"
    [[ $# -gt 0 ]] && shift || true

    case "$cmd" in
        install)     cmd_install "$@" ;;
        update)      cmd_update "$@" ;;
        uninstall)   cmd_uninstall "$@" ;;
        status)      cmd_status "$@" ;;
        resync)      cmd_resync "$@" ;;
        peer-add)    parse_name_endpoint "$@"; cmd_peer_add "$PARSED_NAME" "$PARSED_ENDPOINT" ;;
        peer-del)    cmd_peer_del "${1:-}" ;;
        peer-list)   cmd_peer_list "${1:-}" ;;
        client-conf) parse_name_endpoint "$@"; cmd_client_conf "$PARSED_NAME" "$PARSED_ENDPOINT" ;;
        qr)          parse_name_endpoint "$@"; cmd_qr "$PARSED_NAME" "$PARSED_ENDPOINT" ;;
        version|--version|-V) echo "hy2-awgctl ${VERSION}" ;;
        help|--help|-h|"")    show_help ;;
        *)           log_err "未知命令: ${cmd}"; echo ""; show_help; exit 1 ;;
    esac
}

main "$@"
