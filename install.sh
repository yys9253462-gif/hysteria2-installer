#!/usr/bin/env bash
# ==============================================================================
# Hysteria 2 全功能生产级一键部署与管理脚本
# GitHub: https://github.com/yys9253462-gif/hysteria2-installer
# Author: Yanshan (yys9253462-gif)
# ==============================================================================

set -eo pipefail
umask 077

# 终端色彩
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
PLAIN='\033[0m'

HY2_DIR="/etc/hysteria"
HY2_CONFIG="${HY2_DIR}/config.yaml"
HY2_BIN="/usr/local/bin/hysteria"
HY2_SERVICE="/etc/systemd/system/hysteria-server.service"
HY2_CERT_DIR="${HY2_DIR}/cert"
HY2_META_FILE="${HY2_DIR}/client_meta.json"
HY2_SUB_PORT="8443"

# ---- AmneziaWG (AWG) ----
# 引擎逻辑全部在 awgctl.sh 里，本脚本只做交互封装。
AWG_REPO="yys9253462-gif/hysteria2-installer"
AWG_RELEASE_TAG="awg-binaries"
AWG_CTL_BIN="/usr/local/bin/hy2-awgctl"
AWG_DIR="/etc/amnezia/amneziawg"
AWG_LINK="awg0"
AWG_CONFIG="${AWG_DIR}/${AWG_LINK}.conf"
AWG_META_FILE="${AWG_DIR}/awg_meta.json"
AWG_PEERS_FILE="${AWG_DIR}/awg_peers.json"
AWG_SERVICE="/etc/systemd/system/amneziawg-server.service"
# 规避 Hysteria2 端口跳跃区间(20000-40000) 与 WireGuard 默认端口(51820)
AWG_PORT_MIN=50000
AWG_PORT_MAX=59000

log_info() { echo -e "${GREEN}[INFO]${PLAIN} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${PLAIN} $1"; }
log_err()  { echo -e "${RED}[ERROR]${PLAIN} $1"; }
log_step() { echo -e "${CYAN}==>${PLAIN} ${BLUE}$1${PLAIN}"; }

# 1. 基础环境检查
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_err "本脚本必须以 root 权限运行！请使用 sudo 或切换至 root 用户。"
        exit 1
    fi
}

check_arch() {
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64|amd64)
            HY2_ARCH="amd64"
            ;;
        aarch64|arm64)
            HY2_ARCH="arm64"
            ;;
        armv7l|armhf)
            HY2_ARCH="armv7"
            ;;
        *)
            log_err "暂不支持的 CPU 架构: ${ARCH}"
            exit 1
            ;;
    esac
}

get_public_ip() {
    PUBLIC_IP=$(curl -4 -s --max-time 5 https://api.ipify.org || \
                curl -4 -s --max-time 5 https://icanhazip.com || \
                curl -4 -s --max-time 5 https://ipinfo.io/ip || \
                echo "127.0.0.1")
}

# 解析域名 A/AAAA 记录(三重后备: getent -> dig -> nslookup + 系统解析器)
# 输出: 第一行 stdout 为 DNS 返回的 IPv4 列表(空格分隔); 失败则返回非 0 且 stdout 为空。
resolve_domain_ips() {
    local domain="$1" ips=""
    # 1) getent (glibc NSS, 走 /etc/resolv.conf)
    ips=$(getent ahostsv4 "$domain" 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ' ')
    if [[ -z "$ips" ]] && command -v dig >/dev/null 2>&1; then
        ips=$(dig +short +time=3 +tries=2 A "$domain" 2>/dev/null | grep -E '^[0-9.]+$' | sort -u | tr '\n' ' ')
    fi
    if [[ -z "$ips" ]] && command -v nslookup >/dev/null 2>&1; then
        ips=$(nslookup -timeout=3 "$domain" 2>/dev/null | awk '/^Address: /{print $2}' | grep -E '^[0-9.]+$' | sort -u | tr '\n' ' ')
    fi
    if [[ -z "$ips" ]] && command -v host >/dev/null 2>&1; then
        ips=$(host -W 3 "$domain" 2>/dev/null | awk '/has address/{print $NF}' | sort -u | tr '\n' ' ')
    fi
    # 4) 最后兜底: 用 python3 走系统解析器(总有一个能用)
    if [[ -z "$ips" ]] && command -v python3 >/dev/null 2>&1; then
        ips=$(python3 -c "import socket,sys;
try:
    addrs=sorted(set(a[4][0] for a in socket.getaddrinfo(sys.argv[1], None, socket.AF_INET)))
    print(' '.join(addrs))
except Exception:
    pass" "$domain" 2>/dev/null)
    fi
    [[ -n "$ips" ]] || return 1
    echo "$ips"
}

# 校验 ACME 域名是否已正确解析到本机公网 IP。
# 返回 0 = 通过(包含本机 IP); 1 = 未解析; 2 = 解析到了别的 IP。
verify_domain_resolves_to_this_host() {
    local domain="$1"
    local my_ip="${PUBLIC_IP:-}"
    local resolved_ips resolved_display

    if [[ -z "$my_ip" || "$my_ip" == "127.0.0.1" ]]; then
        log_warn "未能识别本机公网 IP，跳过 DNS 解析预校验（请手动确认 A 记录）。"
        return 0
    fi

    resolved_ips=$(resolve_domain_ips "$domain") || resolved_ips=""
    resolved_display="${resolved_ips:-<未返回任何 A 记录>}"

    if [[ -z "$resolved_ips" ]]; then
        log_err "============================================================"
        log_err " DNS 解析失败: ${domain} 没有返回任何 A 记录"
        log_err "============================================================"
        log_err " 可能原因:"
        log_err "   1) 域名还没添加到 DNS 解析，或 A 记录尚未生效"
        log_err "   2) 域名拼写错误（本脚本无法替你判断拼写正确性）"
        log_err "   3) 本机 DNS 配置异常（检查 /etc/resolv.conf）"
        log_err "   4) DNS 污染（少数地区/网络下 8.8.8.8 被劫持）"
        log_err ""
        log_err " 本机公网 IP: ${my_ip}"
        log_err " 建议先把 ${domain} 的 A 记录指向 ${my_ip}，再重新运行本脚本。"
        return 1
    fi

    if [[ " $resolved_ips " == *" $my_ip "* ]]; then
        log_info "DNS 解析校验通过: ${domain} -> ${resolved_ips}（含本机公网 IP ${my_ip}）"
        return 0
    fi

    log_err "============================================================"
    log_err " DNS 解析警告: ${domain} 当前解析到 ${resolved_display}"
    log_err " 但本机公网 IP 是 ${my_ip}"
    log_err "============================================================"
    log_err " Let's Encrypt 的 HTTP-01 验证将无法通过，证书申请必然失败。"
    log_err " 请到 DNS 服务商把 ${domain} 的 A 记录改成 ${my_ip}，等 TTL 生效后再来。"
    return 2
}

install_dependencies() {
    log_step "检查并安装基础依赖 (curl, wget, jq, openssl, iptables, tar)..."
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq && apt-get install -y -qq curl wget jq openssl iptables tar ca-certificates qrencode python3
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y curl wget jq openssl iptables tar ca-certificates qrencode python3
    elif command -v yum >/dev/null 2>&1; then
        yum install -y curl wget jq openssl iptables tar ca-certificates qrencode python3
    elif command -v apk >/dev/null 2>&1; then
        apk add --no-cache curl wget jq openssl iptables tar ca-certificates bash qrencode python3
    else
        log_warn "未识别的包管理器，请确认已安装 curl, wget, jq, openssl, iptables"
    fi
}

# 2. 安装与更新官方核心二进制
install_binary() {
    log_step "获取 Hysteria 2 官方最新版本..."
    LATEST_TAG=$(curl -s --max-time 10 https://api.github.com/repos/apernet/hysteria/releases/latest | jq -r '.tag_name // empty')
    
    if [[ -z "$LATEST_TAG" || "$LATEST_TAG" == "null" ]]; then
        log_warn "从 GitHub API 获取版本失败，尝试直接下载官方最新发布版..."
        DOWNLOAD_URL="https://download.hysteria.network/app/latest/hysteria-linux-${HY2_ARCH}"
        LATEST_TAG="latest"
    else
        DOWNLOAD_URL="https://github.com/apernet/hysteria/releases/download/${LATEST_TAG}/hysteria-linux-${HY2_ARCH}"
    fi

    log_info "目标版本: ${LATEST_TAG} (${HY2_ARCH})"
    log_step "下载二进制文件至 ${HY2_BIN}..."
    
    if curl -fL --progress-bar "$DOWNLOAD_URL" -o "${HY2_BIN}.tmp"; then
        mv "${HY2_BIN}.tmp" "$HY2_BIN"
        chmod +x "$HY2_BIN"
        log_info "Hysteria 2 二进制安装成功！版本信息: $($HY2_BIN version 2>&1 | grep -E '^Version:' | head -n1 || echo '未知')"
    else
        rm -f "${HY2_BIN}.tmp"
        log_err "下载失败，请检查网络连接。"
        exit 1
    fi
}

# 3. 证书处理模块（自签名 / 自有证书 / ACME 域名证书）
setup_certificates() {
    mkdir -p "$HY2_CERT_DIR"
    
    echo -e "\n${CYAN}------------------------------------------------------------${PLAIN}"
    echo -e "${GREEN}TLS 证书配置方式：${PLAIN}"
    echo -e "  ${YELLOW}1.${PLAIN} 使用自动生成的自签名证书 (最简单快捷，客户端需开启 skip-cert-verify / insecure)"
    echo -e "  ${YELLOW}2.${PLAIN} 自定义已有证书文件路径 (例如 acme.sh / certbot 已签发的 fullchain.pem 与 privkey.pem)"
    echo -e "  ${YELLOW}3.${PLAIN} 绑定域名并自动申请 Let's Encrypt 证书 (推荐)"
    echo -e "  ${YELLOW}4.${PLAIN} 自动扫描并使用本机已有证书 (Let's Encrypt / acme.sh)"
    echo -e "${CYAN}------------------------------------------------------------${PLAIN}"
    read -rp "请选择证书类型 [默认: 1]: " cert_choice
    cert_choice=${cert_choice:-1}

    if [[ "$cert_choice" == "2" ]]; then
        read -rp "请输入证书公钥文件完整路径 (fullchain.pem/cert.crt): " input_cert
        read -rp "请输入证书私钥文件完整路径 (privkey.pem/private.key): " input_key
        if [[ ! -f "$input_cert" || ! -f "$input_key" ]]; then
            log_err "指定的文件不存在，将回退为自签名证书！"
            generate_self_signed_cert
        else
            # 证书链自检：文件里只有 1 张证书 = 叶证书，缺中间证书会让 Go 系客户端连不上。
            local chain_ok=1 sibling
            if [[ "$(grep -c 'BEGIN CERTIFICATE' "$input_cert" 2>/dev/null || echo 0)" -lt 2 ]]; then
                sibling="$(dirname "$input_cert")/fullchain.cer"
                [[ -f "$sibling" ]] || sibling="$(dirname "$input_cert")/fullchain.pem"
                if [[ -f "$sibling" ]]; then
                    log_info "证书文件仅含叶证书，自动改用同目录的 $(basename "$sibling") 以携带完整证书链。"
                    input_cert="$sibling"
                else
                    log_err "警告：$(basename "$input_cert") 仅含叶证书，缺少中间证书。"
                    log_err "v2rayNG/Xray/hysteria 会报 'certificate signed by unknown authority' 而无法连接。"
                    read -rp "仍要继续使用该证书吗？(y/N): " force_leaf
                    [[ "$force_leaf" =~ ^[Yy]$ ]] || chain_ok=0
                fi
            fi
            if [[ "$chain_ok" == "1" ]]; then
                CERT_TYPE="custom"
                CERT_FILE="$input_cert"
                KEY_FILE="$input_key"
                read -rp "请输入证书绑定的域名 (SNI): " SERVER_NAME
                SERVER_NAME=${SERVER_NAME:-$PUBLIC_IP}
                IS_INSECURE="false"
            else
                log_err "已取消，回退为自签名证书。"
                generate_self_signed_cert
            fi
        fi
    elif [[ "$cert_choice" == "3" ]]; then
        setup_acme_certificate
    elif [[ "$cert_choice" == "4" ]]; then
        select_local_certificate
    else
        generate_self_signed_cert
    fi
}

select_local_certificate() {
    local certs=() cert key i choice dir
    # 只接受【完整证书链】文件：fullchain.pem (certbot) / fullchain.cer (acme.sh)。
    # 不能收 <domain>.cer —— 那是仅含叶证书的文件；Go 系客户端 (v2rayNG/Xray/hysteria)
    # 不会通过 AIA 补齐中间证书，缺链会直接报 `x509: certificate signed by unknown authority`。
    # 旧实现扫 `*.cer` 会把叶证书收进来，且给 fullchain.cer 配错 key(fullchain.key) 后丢弃，
    # 结果只剩叶证书 —— 这正是节点"能连上握手、却验证失败"的根因。
    while IFS= read -r cert; do
        dir="$(dirname "$cert")"
        case "$(basename "$cert")" in
            fullchain.pem) key="$dir/privkey.pem" ;;
            fullchain.cer) key="$(find "$dir" -maxdepth 1 -name '*.key' -type f 2>/dev/null | head -1)" ;;
            *) continue ;;
        esac
        [[ -f "$key" ]] && certs+=("$cert|$key")
    done < <(find /etc/letsencrypt/live /root/.acme.sh /home -type f \( -name fullchain.pem -o -name fullchain.cer \) 2>/dev/null)
    if [[ ${#certs[@]} -eq 0 ]]; then
        log_err "未发现含完整证书链的证书 (fullchain.pem / fullchain.cer)。"
        log_err "仅含叶证书的 <domain>.cer 已被跳过，请选择其他证书方式。"
        return 1
    fi
    echo -e "${GREEN}发现以下本机证书：${PLAIN}"
    for i in "${!certs[@]}"; do echo -e "  ${YELLOW}$((i+1)).${PLAIN} ${certs[$i]%%|*}"; done
    read -rp "请选择证书编号: " choice
    [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#certs[@]} )) || { log_err "无效选择。"; return 1; }
    cert="${certs[$((choice-1))]%%|*}"; key="${certs[$((choice-1))]#*|}"
    CERT_TYPE="custom"; CERT_FILE="$cert"; KEY_FILE="$key"; IS_INSECURE="false"
    read -rp "请输入证书绑定的域名 (SNI): " SERVER_NAME
    [[ -n "$SERVER_NAME" ]] || { log_err "域名不能为空。"; return 1; }
}

setup_acme_certificate() {
    echo -e "${YELLOW}申请 ACME 证书前，请确认域名 A/AAAA 记录已指向本机，且云安全组与本机防火墙允许 TCP 80。${PLAIN}"
    read -rp "请输入要绑定的域名 (例如 hy2.example.com): " SERVER_NAME
    if [[ -z "$SERVER_NAME" || "$SERVER_NAME" == *"/"* || "$SERVER_NAME" == *":"* ]]; then
        log_err "域名不能为空，且不能包含协议、路径或端口。"
        return 1
    fi
    read -rp "请输入 ACME 通知邮箱: " ACME_EMAIL
    if [[ -z "$ACME_EMAIL" || "$ACME_EMAIL" != *"@"* ]]; then
        log_err "请输入有效的通知邮箱。"
        return 1
    fi

    # DNS 解析预校验：避免 Let's Encrypt HTTP-01 必然失败导致服务反复重启
    log_step "正在校验 ${SERVER_NAME} 的 DNS A 记录是否指向本机公网 IP ${PUBLIC_IP:-<未知>}..."
    verify_domain_resolves_to_this_host "$SERVER_NAME"
    local dns_rc=$?
    if [[ $dns_rc -eq 1 ]]; then
        # 完全没解析到任何记录 — 强烈不建议继续
        echo -e "${RED}若继续，Let's Encrypt HTTP-01 验证几乎必然失败，Hysteria 服务将反复重启。${PLAIN}"
        read -rp "仍要继续申请 ACME 证书吗? [y/N, 默认 N]: " force_continue
        force_continue=${force_continue:-N}
        if [[ ! "$force_continue" =~ ^[Yy]$ ]]; then
            log_err "已中止 ACME 证书申请。请先把 DNS A 记录指向本机 IP 后再重试。"
            return 1
        fi
        log_warn "已忽略 DNS 解析失败警告，将继续（你已被警告过一次）。"
    elif [[ $dns_rc -eq 2 ]]; then
        # 解析到了别的 IP — 同样不推荐继续
        echo -e "${RED}域名当前指向的不是本机，Let's Encrypt 验证必然失败。${PLAIN}"
        read -rp "仍要继续申请 ACME 证书吗? [y/N, 默认 N]: " force_continue
        force_continue=${force_continue:-N}
        if [[ ! "$force_continue" =~ ^[Yy]$ ]]; then
            log_err "已中止 ACME 证书申请。请先把 DNS A 记录修正为本机 IP 后再重试。"
            return 1
        fi
        log_warn "已忽略 DNS 解析不一致警告，将继续（你已被警告过一次）。"
    fi

    CERT_TYPE="acme"
    IS_INSECURE="false"
    log_info "将为 ${SERVER_NAME} 自动申请 Let's Encrypt 证书。"
}

generate_self_signed_cert() {
    CERT_TYPE="self_signed"
    SERVER_NAME="www.bing.com"
    CERT_FILE="${HY2_CERT_DIR}/server.crt"
    KEY_FILE="${HY2_CERT_DIR}/server.key"
    IS_INSECURE="true"

    log_step "正在生成高拟真自签名 ECC 证书 (伪装 SNI: ${SERVER_NAME})..."
    openssl ecparam -genkey -name prime256v1 -out "$KEY_FILE"
    openssl req -new -x509 -days 3650 -key "$KEY_FILE" -out "$CERT_FILE" -subj "/CN=${SERVER_NAME}" >/dev/null 2>&1
    chmod 600 "$KEY_FILE"
    log_info "自签名证书生成成功。"
}

# 4. 端口与网络配置 (支持端口跳跃)
setup_ports_and_obfs() {
    echo -e "\n${CYAN}------------------------------------------------------------${PLAIN}"
    echo -e "${GREEN}服务端口与端口跳跃配置：${PLAIN}"
    echo -e "${CYAN}------------------------------------------------------------${PLAIN}"
    
    DEFAULT_PORT=$((RANDOM % 40000 + 10000))
    read -rp "请输入主监听 UDP 端口 [1-65535, 默认: ${DEFAULT_PORT}]: " LISTEN_PORT
    LISTEN_PORT=${LISTEN_PORT:-$DEFAULT_PORT}

    # 密码生成
    RANDOM_PASS=$(openssl rand -hex 16)
    read -rsp "请输入连接认证密码 [回车自动生成]: " AUTH_PASSWORD; echo
    AUTH_PASSWORD=${AUTH_PASSWORD:-$RANDOM_PASS}

    # 运行模式选择 (单机私密 vs 商城集群 Agent 模式)
    echo -e "\n请选择当前 Hysteria 2 节点的运行模式："
    echo -e "  ${GREEN}1.${PLAIN} 单机私密模式 (默认：单用户/自用，提供 Web 信息中心)"
    echo -e "  ${GREEN}2.${PLAIN} 商城集群 Agent 模式 (开启 REST API 接口，支持动态开户/续费，对接商城)"
    read -rp "请输入选项 [1-2, 默认 1]: " node_mode_choice
    node_mode_choice=${node_mode_choice:-1}

    if [[ "$node_mode_choice" == "2" ]]; then
        NODE_MODE="agent"
        RANDOM_API_KEY="hy2_sec_$(openssl rand -hex 16)"
        read -rsp "请设置节点通信 API Key [回车自动生成]: " NODE_API_KEY; echo
        NODE_API_KEY=${NODE_API_KEY:-$RANDOM_API_KEY}
        log_info "当前已选：商城集群 Agent 模式 (Node API Key 已生成)"
    else
        NODE_MODE="standalone"
        NODE_API_KEY=""
    fi

    # 端口跳跃 (默认全自动开启，免询问)
    clear_all_hopping_rules
    HOP_START=20000
    HOP_END=40000
    HOP_PORT_RANGE="${HOP_START}-${HOP_END}"
    setup_iptables_port_hopping "$LISTEN_PORT" "$HOP_START" "$HOP_END"
    log_info "端口跳跃已默认自动启用: UDP ${HOP_PORT_RANGE} -> ${LISTEN_PORT}"

    # Salamander 混淆 (默认全自动开启并生成高熵密钥，免询问)
    OBFS_PASSWORD=$(openssl rand -hex 16)
    log_info "Salamander 混淆已默认自动启用 (抗深度包检测 GFW 免疫)"
}

setup_system_firewall() {
    local port="$1"
    local s_port="$2"
    local e_port="$3"
    
    log_step "自动放行系统内部防火墙 (ufw / firewalld / iptables)..."
    if command -v ufw >/dev/null 2>&1 && ufw status | grep -q '^Status: active'; then
        ufw allow "${HY2_SUB_PORT}/tcp" >/dev/null 2>&1 || true
        ufw allow "${port}/udp" >/dev/null 2>&1 || true
        if [[ "$CERT_TYPE" == "acme" ]]; then
            ufw allow 80/tcp >/dev/null 2>&1 || true
            ufw allow "${HY2_SUB_PORT}/tcp" >/dev/null 2>&1 || true
        fi
        if [[ -n "$s_port" && -n "$e_port" ]]; then
            ufw allow "${s_port}:${e_port}/udp" >/dev/null 2>&1 || true
        fi
        log_info "已放行 UFW 防火墙端口。"
    fi
    if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active firewalld >/dev/null 2>&1; then
        firewall-cmd --zone=public --add-port="${HY2_SUB_PORT}/tcp" --permanent >/dev/null 2>&1 || true
        firewall-cmd --zone=public --add-port="${port}/udp" --permanent >/dev/null 2>&1 || true
        if [[ "$CERT_TYPE" == "acme" ]]; then
            firewall-cmd --zone=public --add-port="80/tcp" --permanent >/dev/null 2>&1 || true
            firewall-cmd --zone=public --add-port="${HY2_SUB_PORT}/tcp" --permanent >/dev/null 2>&1 || true
        fi
        if [[ -n "$s_port" && -n "$e_port" ]]; then
            firewall-cmd --zone=public --add-port="${s_port}-${e_port}/udp" --permanent >/dev/null 2>&1 || true
        fi
        firewall-cmd --reload >/dev/null 2>&1 || true
        log_info "已放行 firewalld 端口。"
    fi
}

select_subscription_port() {
    # bind 实际验证 IPv4 TCP 端口；不解析 ss 标题，不进行无限循环。
    HY2_SUB_PORT=$(python3 - <<'PYPORT'
import socket, secrets
for i in range(100):
    port = 8443 if i == 0 else 10000 + secrets.randbelow(50000)
    with socket.socket() as sock:
        try:
            sock.bind(('0.0.0.0', port))
        except OSError:
            continue
        print(port)
        break
else:
    raise SystemExit('无法找到可用 TCP 端口')
PYPORT
)
    PORTAL_LOCAL_PORT=$(python3 - <<'PYPORT'
import socket
with socket.socket() as sock:
    sock.bind(('127.0.0.1', 0))
    print(sock.getsockname()[1])
PYPORT
)
}

clear_all_hopping_rules() {
    # 彻底扫描并清理所有历史残留的 REDIRECT 到 hysteria 端口的 iptables 规则，防止旧端口重定向死循环
    # BUGFIX #12: 同时清理 PREROUTING + OUTPUT 链
    while iptables -t nat -L PREROUTING -n --line-numbers 2>/dev/null | grep -q "REDIRECT.*udp"; do
        local line_num=$(iptables -t nat -L PREROUTING -n --line-numbers | grep "REDIRECT.*udp" | head -n 1 | awk '{print $1}')
        [ -n "$line_num" ] && iptables -t nat -D PREROUTING "$line_num" 2>/dev/null || break
    done
    while iptables -t nat -L OUTPUT -n --line-numbers 2>/dev/null | grep -q "REDIRECT.*udp"; do
        local line_num=$(iptables -t nat -L OUTPUT -n --line-numbers | grep "REDIRECT.*udp" | head -n 1 | awk '{print $1}')
        [ -n "$line_num" ] && iptables -t nat -D OUTPUT "$line_num" 2>/dev/null || break
    done
    if command -v ip6tables >/dev/null 2>&1; then
        while ip6tables -t nat -L PREROUTING -n --line-numbers 2>/dev/null | grep -q "REDIRECT.*udp"; do
            local line_num=$(ip6tables -t nat -L PREROUTING -n --line-numbers | grep "REDIRECT.*udp" | head -n 1 | awk '{print $1}')
            [ -n "$line_num" ] && ip6tables -t nat -D PREROUTING "$line_num" 2>/dev/null || break
        done
        while ip6tables -t nat -L OUTPUT -n --line-numbers 2>/dev/null | grep -q "REDIRECT.*udp"; do
            local line_num=$(ip6tables -t nat -L OUTPUT -n --line-numbers | grep "REDIRECT.*udp" | head -n 1 | awk '{print $1}')
            [ -n "$line_num" ] && ip6tables -t nat -D OUTPUT "$line_num" 2>/dev/null || break
        done
    fi
    systemctl disable --now hy2-iptables.service >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/hy2-iptables.service >/dev/null 2>&1 || true
}

setup_iptables_port_hopping() {
    local l_port="$1"
    local s_port="$2"
    local e_port="$3"
    
    log_step "配置 iptables 端口跳跃转发规则 (${s_port}-${e_port} -> ${l_port})..."
    
    clear_all_hopping_rules
    
    # 注入新规则 (IPv4 + IPv6)
    # BUGFIX #12: 同时加 PREROUTING + OUTPUT 链, 这样本机 loopback 拨测也能跳到主监听端口
    iptables -t nat -A PREROUTING -p udp --dport "${s_port}:${e_port}" -j REDIRECT --to-ports "${l_port}"
    iptables -t nat -A OUTPUT     -p udp --dport "${s_port}:${e_port}" -j REDIRECT --to-ports "${l_port}"
    if command -v ip6tables >/dev/null 2>&1; then
        ip6tables -t nat -A PREROUTING -p udp --dport "${s_port}:${e_port}" -j REDIRECT --to-ports "${l_port}" 2>/dev/null || true
        ip6tables -t nat -A OUTPUT     -p udp --dport "${s_port}:${e_port}" -j REDIRECT --to-ports "${l_port}" 2>/dev/null || true
    fi

    # 保存规则持久化（兼顾 netfilter-persistent 与原生 systemd 自愈守护）
    if command -v netfilter-persistent >/dev/null 2>&1; then
        netfilter-persistent save >/dev/null 2>&1 || true
    elif command -v service >/dev/null 2>&1 && service iptables status >/dev/null 2>&1; then
        service iptables save >/dev/null 2>&1 || true
    fi

    # 兜底部署 systemd 端口跳跃自愈守护服务，保证开机/重启 100% 自动恢复规则
    cat > /etc/systemd/system/hy2-iptables.service <<EOF
[Unit]
Description=Hysteria 2 Port Hopping iptables persistence
After=network.target
Before=hysteria-server.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash -c "iptables -t nat -C PREROUTING -p udp --dport ${s_port}:${e_port} -j REDIRECT --to-ports ${l_port} 2>/dev/null || iptables -t nat -A PREROUTING -p udp --dport ${s_port}:${e_port} -j REDIRECT --to-ports ${l_port}; iptables -t nat -C OUTPUT -p udp --dport ${s_port}:${e_port} -j REDIRECT --to-ports ${l_port} 2>/dev/null || iptables -t nat -A OUTPUT -p udp --dport ${s_port}:${e_port} -j REDIRECT --to-ports ${l_port}"

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl enable hy2-iptables.service >/dev/null 2>&1 || true

    log_info "端口跳跃 iptables 规则与开机持久化守护已生效 (PREROUTING + OUTPUT 双链)."
}

# 5. 生成服务端配置文件与 Systemd 服务
generate_server_config() {
    log_step "生成 Hysteria 2 服务端配置: ${HY2_CONFIG}..."
    mkdir -p "$HY2_DIR"
    command -v python3 >/dev/null && command -v qrencode >/dev/null || install_dependencies
    python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else "需要 Python 3.9+")'
    local systemd_version
    systemd_version=$(systemctl --version | awk 'NR==1 {print $2}')
    if [[ ! "$systemd_version" =~ ^[0-9]+$ ]] || (( systemd_version < 247 )); then
        log_err "私密网页需要 systemd 247+ 的凭据隔离功能。"
        return 1
    fi
    select_subscription_port

    cat > "$HY2_CONFIG" <<EOF
# Hysteria 2 Server Configuration
# Generated by hysteria2-installer
listen: :${LISTEN_PORT}
EOF

    if [[ "$CERT_TYPE" == "acme" ]]; then
        cat >> "$HY2_CONFIG" <<EOF
acme:
  domains:
    - ${SERVER_NAME}
  email: ${ACME_EMAIL}
  type: http
EOF
    else
        cat >> "$HY2_CONFIG" <<EOF
tls:
  cert: ${CERT_FILE}
  key: ${KEY_FILE}
EOF
    fi

    if [[ "$NODE_MODE" == "agent" ]]; then
        cat >> "$HY2_CONFIG" <<EOF
auth:
  type: http
  http:
    url: http://127.0.0.1:${PORTAL_LOCAL_PORT}/auth
EOF
    else
        cat >> "$HY2_CONFIG" <<EOF
auth:
  type: password
  password: $(jq -Rn --arg value "$AUTH_PASSWORD" '$value')
EOF
    fi

    cat >> "$HY2_CONFIG" <<EOF

masquerade:
  type: proxy
  proxy:
    url: http://127.0.0.1:${PORTAL_LOCAL_PORT}/
    rewriteHost: false
  listenHTTPS: :${HY2_SUB_PORT}

ignoreClientBandwidth: false
disableUDP: false

bandwidth:
  up: 1 gbps
  down: 1 gbps

# Some IPv4-only VPS instances still receive IPv6 DNS answers but have no IPv6
# default route. Use the default direct outbound over IPv4 so those answers do
# not break requests to dual-stack sites such as YouTube.
outbounds:
  - name: direct_ipv4
    type: direct
    direct:
      mode: "4"
  - name: warp_socks
    type: socks5
    socks5:
      addr: 127.0.0.1:19898
EOF

    # 写入 toggle_warp.sh 控制脚本，供 portal.py 或命令行无感知调用
    cat > "$HY2_DIR/toggle_warp.sh" <<'EOTW'
#!/usr/bin/env bash
ACTION="$1" # 1: enable, 0: disable
CONFIG="/etc/hysteria/config.yaml"
[[ -f "$CONFIG" ]] || exit 1

# 记录改动前的 acl 段，供收尾判断是否需要重启
BEFORE_ACL=$(sed -n '/^acl:/,$p' "$CONFIG")

# 清理旧 acl 段
sed -i "/^acl:/,\$d" "$CONFIG"

if [[ "$ACTION" == "1" ]]; then
    # 统一走 wgcf + wireproxy 出口（不再依赖官方 warp-cli）：探活失败则拉起 wireproxy
    if ! curl --proxy "socks5h://127.0.0.1:19898" --silent --fail --max-time 6 https://api4.ipify.org >/dev/null 2>&1; then
        systemctl restart wireproxy >/dev/null 2>&1 || true
        sleep 2
    fi
    cat >> "$CONFIG" <<'EOF'
acl:
  inline:
    - warp_socks(suffix:ipify.org)
    - warp_socks(suffix:cloudflare.com)
    - warp_socks(suffix:openai.com)
    - warp_socks(suffix:chatgpt.com)
    - warp_socks(suffix:oaistatic.com)
    - warp_socks(suffix:oaiusercontent.com)
    - warp_socks(suffix:ai.com)
    - warp_socks(suffix:anthropic.com)
    - warp_socks(suffix:claude.ai)
    - warp_socks(suffix:gemini.google.com)
    - warp_socks(suffix:aistudio.google.com)
    - warp_socks(suffix:generativelanguage.googleapis.com)
    - warp_socks(suffix:alkalimakersuite-pa.clients6.google.com)
    - direct_ipv4(all)
    - warp_socks(chatgpt.com)
    - warp_socks(oaistatic.com)
    - warp_socks(oaiusercontent.com)
    - warp_socks(ai.com)
    - warp_socks(gemini.google.com)
    - warp_socks(aistudio.google.com)
    - warp_socks(generativelanguage.googleapis.com)
    - warp_socks(anthropic.com)
    - warp_socks(claude.ai)
EOF
fi

# acl 段无实际变化时不重启，避免无谓掐断所有在线用户
if [[ "${BEFORE_ACL:-}" != "$(sed -n '/^acl:/,$p' "$CONFIG")" ]]; then
    systemctl restart hysteria-server 2>/dev/null || true
fi
EOTW
    chmod +x "$HY2_DIR/toggle_warp.sh"

    # 写入 do_upgrade.sh 供 Web 控制台在线升级官方核心或面板
    cat > "$HY2_DIR/do_upgrade.sh" <<'EOUG'
#!/usr/bin/env bash
TARGET="$1" # 'core' or 'portal'
HY2_DIR="/etc/hysteria"
HY2_BIN="/usr/local/bin/hysteria"

if [[ "$TARGET" == "core" ]]; then
    # 自动识别架构下载官方最新发布版
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64) HY_ARCH="amd64" ;;
        aarch64|arm64) HY_ARCH="arm64" ;;
        armv7l) HY_ARCH="armv7" ;;
        *) exit 1 ;;
    esac
    TMP_FILE="/tmp/hy2_update_${HY_ARCH}"
    curl -fsSL "https://github.com/apernet/hysteria/releases/latest/download/hysteria-linux-${HY_ARCH}" -o "$TMP_FILE"
    if [[ -s "$TMP_FILE" ]]; then
        chmod +x "$TMP_FILE"
        mv -f "$TMP_FILE" "$HY2_BIN"
        systemctl restart hysteria-server 2>/dev/null || true
    fi
elif [[ "$TARGET" == "portal" ]]; then
    # 从主仓库拉取最新 portal.py 并热重启 portal 服务
    TMP_PORTAL="/tmp/portal_latest.py"
    curl -fsSL "https://raw.githubusercontent.com/yys9253462-gif/hysteria2-installer/main/portal.py" -o "$TMP_PORTAL"
    if [[ -s "$TMP_PORTAL" ]]; then
        mv -f "$TMP_PORTAL" "$HY2_DIR/portal.py"
        chmod 644 "$HY2_DIR/portal.py"
        systemctl restart hysteria-portal 2>/dev/null || true
    fi
fi
EOUG
    chmod +x "$HY2_DIR/do_upgrade.sh"

    # 写入混淆（如果有）
    if [[ -n "$OBFS_PASSWORD" ]]; then
        cat >> "$HY2_CONFIG" <<EOF

obfs:
  type: salamander
  salamander:
    password: $(jq -Rn --arg value "$OBFS_PASSWORD" '$value')
EOF
    fi

    # 提取证书 SHA-256 指纹：必须是【纯 HEX 64 位】—— 客户端(v2rayNG/v2rayN)会把它直接填进
    # Xray 的 pinnedPeerCertSha256，写 base64 会触发 `encoding/hex: invalid byte`。
    PIN_SHA256=""
    if [[ -f "$CERT_FILE" ]]; then
        PIN_SHA256=$(openssl x509 -in "$CERT_FILE" -outform DER 2>/dev/null | openssl dgst -sha256 2>/dev/null | awk '{print $NF}' | tr 'A-F' 'a-f' || true)
        [[ "$PIN_SHA256" =~ ^[0-9a-f]{64}$ ]] || PIN_SHA256=""
    fi

    jq -n --arg public_ip "$PUBLIC_IP" --arg server_name "$SERVER_NAME" \
        --arg auth_password "$AUTH_PASSWORD" --arg obfs_password "$OBFS_PASSWORD" \
        --arg hop_port_range "$HOP_PORT_RANGE" --arg cert_type "$CERT_TYPE" \
        --arg pin_sha256 "$PIN_SHA256" \
        --argjson listen_port "$LISTEN_PORT" --argjson is_insecure "$IS_INSECURE" \
        --argjson subscription_port "$HY2_SUB_PORT" \
        '$ARGS.named' > "$HY2_META_FILE"
    setup_portal
    log_info "配置文件写入完成。"
}

setup_systemd() {
    log_step "配置 systemd 系统守护服务: ${HY2_SERVICE}..."
    
    # 系统内核网络与 UDP 缓冲优化 (BUGFIX #13: 同时持久化到 /etc/sysctl.d/)
    cat > /etc/sysctl.d/99-hysteria2.conf <<EOF
# Hysteria 2 内核网络与 UDP 缓冲调优 (由 hysteria2-installer 自动生成)
net.core.rmem_max = 8388608
net.core.wmem_max = 8388608
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.core.netdev_max_backlog = 5000
net.ipv4.udp_mem = 102400 873800 16777216
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192
EOF
    sysctl -p /etc/sysctl.d/99-hysteria2.conf >/dev/null 2>&1 || true
    
    cat > "$HY2_SERVICE" <<EOF
[Unit]
Description=Hysteria 2 Server Service
Documentation=https://v2.hysteria.network/
After=network.target network-online.target
Wants=network-online.target
After=hysteria-portal.service
Wants=hysteria-portal.service
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=simple
User=root
WorkingDirectory=${HY2_DIR}
ExecStart=${HY2_BIN} server -c ${HY2_CONFIG}
Restart=on-failure
RestartSec=10
LimitNOFILE=65535
LimitNPROC=65535
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable hysteria-server >/dev/null 2>&1
    systemctl restart hysteria-server
    
    sleep 2
    if systemctl is-active hysteria-server >/dev/null 2>&1; then
        log_info "Hysteria 2 服务启动成功！"
    else
        log_err "Hysteria 2 服务启动异常，请运行 'journalctl -u hysteria-server -e' 查看日志！"
        return 1
    fi
}

# 6. 显示私密信息页的访问凭据，节点数据只在认证后提供。
show_client_configs() {
    if [[ ! -f "$HY2_DIR/portal-access.json" ]]; then
        log_err "尚未生成信息页，请重新配置。"
        return 1
    fi
    jq -r '"私密信息页: " + .url, "用户名: " + .username, "密码: " + .password' "$HY2_DIR/portal-access.json"
    local key=$(jq -r '.api_key // empty' "$HY2_DIR/portal-access.json")
    if [[ -n "$key" ]]; then
        echo -e "${YELLOW}节点通信 API Key (供商城集群对接): ${GREEN}${key}${PLAIN}"
    fi
    local pin=$(jq -r '.pin_sha256 // empty' "$HY2_META_FILE" 2>/dev/null)
    if [[ -n "$pin" ]]; then
        echo -e "${YELLOW}自签证书 SHA-256 指纹 (HEX，已写入直链 pinSHA256): ${GREEN}${pin}${PLAIN}"
    fi
    log_info "请在云安全组放行信息页 URL 中的 TCP 端口。"
    log_warn "自签证书模式已在直链中附带 pinSHA256(HEX) + insecure=1；生产环境强烈推荐改用有效域名证书，可免去全部指纹维护。"
}

write_portal_program() {
    cat > "$HY2_DIR/portal.py" <<'PYPORTAL'
"""仅监听回环地址；公网 TLS 由 Hysteria 的 masquerade proxy 提供。
采用现代轻奢 Tab 导航系统，解耦节点连接、多用户管理（支持 IP 限制与实时流量统计）与集群 API 凭据。
"""
import base64
import hashlib
import hmac
import html
import json
import random
import re
import secrets
import socket
import subprocess
import sys
import threading
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from socketserver import ThreadingMixIn
from urllib.parse import parse_qs, quote, urlencode


STYLE = """
:root{color-scheme:light;--ink:#122b31;--muted:#667c81;--line:#dce7e6;--accent:#087f74;--accent-hover:#066960;--danger:#cf3c3c;--danger-bg:#fdf2f2;--brand-bg:#eaf5ef;--card-bg:#ffffff}
*{box-sizing:border-box}body{margin:0;background:#f3f7f6;color:var(--ink);font:15px/1.6 system-ui,-apple-system,"Segoe UI","Microsoft YaHei",sans-serif}
main{max-width:1160px;margin:auto;padding:32px 28px 48px}.topbar{display:flex;justify-content:space-between;align-items:center;padding-bottom:24px}
.brand{font-weight:800;letter-spacing:.04em;display:flex;gap:10px;align-items:center}.logo{background:var(--ink);color:white;border-radius:12px;padding:7px 12px;font-size:17px}.private{font-size:12px;color:var(--accent);border:1px solid #c3ddd5;border-radius:30px;padding:5px 12px;background:#eaf5ef}
.eyebrow{font-size:11px;letter-spacing:.16em;font-weight:750;color:var(--accent)}h1{font-size:32px;letter-spacing:-.04em;margin:6px 0}h2{font-size:18px;margin:0 0 4px}p{margin:0;color:var(--muted)}.hero{margin-bottom:24px}.hero p{font-size:14px}

/* Tab 导航容器 */
.tab-bar{display:flex;gap:8px;border-bottom:2px solid var(--line);margin-bottom:26px;overflow-x:auto;padding-bottom:2px}
.tab-btn{display:inline-flex;align-items:center;gap:8px;padding:11px 18px;border:none;background:none;color:var(--muted);font-size:14px;font-weight:700;cursor:pointer;border-radius:10px 10px 0 0;position:relative;transition:all .18s ease;white-space:nowrap}
.tab-btn:hover{color:var(--ink);background:#ebf3f1}
.tab-btn.active{color:var(--accent);background:#fff}
.tab-btn.active:after{content:'';position:absolute;bottom:-2px;left:0;right:0;height:2px;background:var(--accent)}
.tab-pane{display:none}
.tab-pane.active{display:block;animation:fadeIn .2s ease-out}
@keyframes fadeIn{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:translateY(0)}}

/* 卡片与网格 */
.layout{display:grid;grid-template-columns:320px minmax(0,1fr);gap:22px;align-items:start}
.card{background:#fff;border:1px solid var(--line);border-radius:20px;padding:24px;box-shadow:0 5px 22px #183f3505}
.qr-card{text-align:center}.qr-frame{background:#fff;border:1px solid var(--line);border-radius:16px;padding:14px;margin:20px 0}.qr-frame img{display:block;width:100%;height:auto}
.hint{font-size:12px}.tags{display:flex;gap:6px;justify-content:center;flex-wrap:wrap;margin-top:18px}.tag{background:#f0f5f4;color:#526a70;border-radius:6px;padding:3px 8px;font-size:11px}
.stack{display:grid;gap:18px}.card-head{display:flex;gap:14px;align-items:center;margin-bottom:16px}.step{display:grid;place-items:center;flex:0 0 38px;height:38px;border-radius:11px;background:#e8f4f0;color:var(--accent);font-weight:750}.card-head p{font-size:12px}
textarea{display:block;width:100%;min-width:0;border:1px solid var(--line);background:#f7faf9;border-radius:12px;padding:14px;color:#35545c;font:12px/1.7 ui-monospace,SFMono-Regular,Consolas,monospace;resize:vertical;overflow-wrap:anywhere}
textarea.link{height:92px}textarea.config{height:290px;margin-top:18px}textarea:focus{outline:2px solid #65b3a5;outline-offset:2px}
.actions{display:flex;gap:10px;align-items:center;margin-top:14px;flex-wrap:wrap}
.button{display:inline-flex;align-items:center;justify-content:center;gap:6px;border:1px solid var(--line);background:white;border-radius:9px;padding:9px 15px;color:var(--ink);text-decoration:none;font:600 12px/1.5 inherit;cursor:pointer}
.button.primary{background:var(--accent);color:white;border-color:var(--accent)}.button.danger{background:var(--danger);color:white;border-color:var(--danger)}.button:hover{filter:brightness(.94)}
.note{font-size:12px;margin-top:12px}.advanced{margin-top:24px}.advanced-title{display:flex;align-items:center;justify-content:space-between;margin-bottom:12px}.advanced-title p{font-size:12px}.config-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}
summary{cursor:pointer;font-weight:650;list-style-position:inside}summary span{font-size:11px;font-weight:400;color:var(--muted);margin-left:10px}
.security{margin-top:24px;padding:15px 18px;border:1px solid #d8e6df;border-radius:12px;background:#eaf2ed;color:#4f6a60;font-size:12px}
footer{display:flex;justify-content:space-between;margin-top:32px;color:#879996;font-size:11px}.status{font-size:12px;color:var(--accent)}

/* 多用户与集群专属卡片样式 */
.user-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:18px;flex-wrap:wrap;gap:12px}
.badge-count{background:var(--brand-bg);color:var(--accent);border:1px solid #c3ddd5;border-radius:20px;padding:4px 12px;font-size:12px;font-weight:700}
.switch-box{display:flex;align-items:center;gap:12px;background:#f8fbfb;border:1px solid var(--line);border-radius:14px;padding:16px 20px;margin-bottom:20px;justify-content:space-between;flex-wrap:wrap}
.switch-info{display:flex;flex-direction:column;gap:4px}
.switch-title{font-size:14px;font-weight:700;color:var(--ink);display:flex;align-items:center;gap:8px}
.switch-desc{font-size:12px;color:var(--muted)}
.toggle-btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;padding:8px 18px;border-radius:10px;font-size:13px;font-weight:700;cursor:pointer;border:1px solid transparent;transition:all .15s ease}
.toggle-btn.on{background:var(--accent);color:#fff;border-color:var(--accent)}
.toggle-btn.off{background:#fff;color:var(--muted);border-color:var(--line)}
.toggle-btn:hover{filter:brightness(.92)}
.user-table-wrap{width:100%;overflow-x:auto;border:1px solid var(--line);border-radius:14px;background:#fff}
.user-table{width:100%;border-collapse:collapse;text-align:left;font-size:13px}
.user-table th{background:#f8fbfb;padding:12px 14px;color:var(--muted);font-weight:700;border-bottom:1px solid var(--line);white-space:nowrap}
.user-table td{padding:12px 14px;border-bottom:1px solid var(--line);vertical-align:middle;white-space:nowrap}
.user-table tr:last-child td{border-bottom:none}
.status-pill{display:inline-block;padding:2px 8px;border-radius:20px;font-size:11px;font-weight:700}
.status-pill.active{background:#eafaf3;color:#0b8650}
.status-pill.expired{background:#fff1f0;color:#cf3c3c}
.traffic-bar{height:6px;width:90px;background:#e6edec;border-radius:4px;overflow:hidden;margin-top:5px}
.traffic-fill{height:100%;background:var(--accent);border-radius:4px}
.traffic-fill.danger{background:var(--danger)}
.speed-badge{display:inline-flex;align-items:center;gap:4px;background:#eef6f5;color:var(--accent);border-radius:6px;padding:2px 6px;font-size:11px;font-weight:700;font-family:ui-monospace,SFMono-Regular,Consolas,monospace}
.speed-badge.active{background:#e1f5ee;color:#085041}
.speed-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:18px}
.speed-card{background:#fff;border:1px solid var(--line);border-radius:12px;padding:14px 16px;display:flex;align-items:center;justify-content:space-between}
.speed-card .val{font-size:20px;font-weight:800;letter-spacing:-.02em;color:var(--ink);font-family:ui-monospace,SFMono-Regular,Consolas,monospace}
.speed-card .lbl{font-size:11px;color:var(--muted);font-weight:700;text-transform:uppercase}
.proxy-card{border-left:4px solid #534AB7}
.proxy-table{width:100%;border-collapse:collapse;text-align:left;font-size:13px}
.proxy-table th{background:#f8fbfb;padding:10px 12px;color:var(--muted);font-weight:700;border-bottom:1px solid var(--line);white-space:nowrap}
.proxy-table td{padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:middle}
.proxy-table tr:last-child td{border-bottom:none}
.proxy-type{display:inline-block;padding:2px 8px;border-radius:6px;font-size:11px;font-weight:700;font-family:ui-monospace,SFMono-Regular,Consolas,monospace}
.proxy-type.socks5{background:#EEEDFE;color:#3C3489}
.proxy-type.http{background:#E6F1FB;color:#0C447C}
.proxy-type.https{background:#E1F5EE;color:#085041}
.api-box{background:#f7faf9;border:1px solid var(--line);border-radius:12px;padding:16px;margin-bottom:16px;display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}
.api-key-code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:13px;color:#284d56;word-break:break-all;margin-top:4px}
.modal-form{display:grid;grid-template-columns:1fr 1fr;gap:16px 20px;background:#f8fbfb;border:1px solid var(--line);border-radius:14px;padding:22px;margin-bottom:20px}
.form-field{display:flex;flex-direction:column;gap:6px}
.form-field-full{grid-column:1/-1}
.form-field label{font-size:13px;font-weight:700;color:var(--ink);display:flex;justify-content:space-between;align-items:center}
.form-field label span{font-weight:400;color:var(--muted);font-size:12px}
.form-field input{height:42px;padding:0 12px;border:1px solid var(--line);border-radius:9px;font-size:13px;background:#fff;outline:none;transition:border-color .15s}
.form-field input:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(8,127,116,0.12)}
.form-field small{font-size:11px;color:var(--muted);line-height:1.4;margin-top:2px}
.input-with-action{display:flex;gap:8px}
.input-with-action input{flex:1;min-width:0}
.btn-mini{padding:0 12px;height:42px;background:#eaf5ef;border:1px solid #c3ddd5;color:var(--accent);border-radius:9px;font-size:12px;font-weight:700;cursor:pointer;white-space:nowrap;display:inline-flex;align-items:center;justify-content:center;transition:background .15s}
.btn-mini:hover{background:#dbeef7}

@media(max-width:760px){
  main{padding:20px 16px 32px}.topbar{padding-bottom:20px}.layout,.config-grid{grid-template-columns:1fr}.qr-frame{max-width:248px;margin:18px auto}.card{padding:20px}h1{font-size:26px}.advanced-title{display:block}footer{gap:15px;flex-direction:column}.private{font-size:10px}.brand{font-size:13px}
  .login-card{padding:28px 20px;border-radius:20px}
  .tab-btn{padding:9px 12px;font-size:13px}
  .modal-form{grid-template-columns:1fr;gap:14px;padding:16px}
}

/* 登录样式 */
.login-wrap{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px 16px;background:radial-gradient(ellipse at top,#eef5f3 0%,#f3f7f6 100%)}
.login-card{width:100%;max-width:420px;background:#fff;border:1px solid var(--line);border-radius:24px;padding:36px 30px;box-shadow:0 12px 36px rgba(18,43,49,0.06)}
.login-brand{text-align:center;margin-bottom:28px}
.login-logo{display:inline-flex;align-items:center;justify-content:center;width:60px;height:60px;background:var(--accent);color:#fff;border-radius:18px;font-size:26px;font-weight:800;box-shadow:0 6px 16px rgba(8,127,116,0.22);margin-bottom:14px}
.login-badge{display:inline-block;font-size:11px;letter-spacing:.14em;font-weight:750;color:var(--accent);text-transform:uppercase;margin-bottom:6px}
.login-title{font-size:24px;letter-spacing:-.03em;color:var(--ink);margin:0 0 6px;font-weight:700}
.login-sub{font-size:13px;color:var(--muted);margin:0}
.login-form{display:grid;gap:18px}
.field-group{display:grid;gap:7px}
.field-label{font-size:13px;font-weight:650;color:var(--ink);display:flex;justify-content:space-between;align-items:center}
.field-input{width:100%;height:44px;padding:0 14px;border:1px solid var(--line);border-radius:11px;background:#f7faf9;color:var(--ink);font-size:14px;transition:all .15s ease}
.field-input:focus{outline:none;border-color:var(--accent);background:#fff;box-shadow:0 0 0 3px rgba(8,127,116,0.12)}
.field-pwd{position:relative}
.field-pwd input{padding-right:68px}
.toggle-pwd{position:absolute;right:8px;top:50%;transform:translateY(-50%);background:none;border:none;color:var(--muted);font-size:12px;font-weight:600;padding:6px 8px;cursor:pointer;border-radius:6px}
.toggle-pwd:hover{color:var(--accent);background:#eef5f3}
.remember-row{display:flex;align-items:center;gap:8px;margin-top:2px}
.remember-row input{accent-color:var(--accent);cursor:pointer;width:15px;height:15px}
.remember-row label{font-size:13px;color:var(--muted);cursor:pointer;user-select:none}
.btn-submit{width:100%;height:46px;background:var(--accent);color:#fff;border:none;border-radius:12px;font-size:14px;font-weight:700;cursor:pointer;transition:all .15s;margin-top:6px;display:flex;align-items:center;justify-content:center}
.btn-submit:hover{background:var(--accent-hover);box-shadow:0 4px 12px rgba(8,127,116,0.2)}
.btn-submit:active{transform:scale(0.99)}
.error-tip{padding:10px 14px;border-radius:10px;background:var(--danger-bg);color:var(--danger);font-size:13px;font-weight:550;display:flex;align-items:center;gap:8px;border:1px solid #f6cfcf}
.login-footer{margin-top:24px;padding-top:18px;border-top:1px solid #edf2f1;font-size:12px;color:var(--muted);line-height:1.6;text-align:center}
.login-footer code{background:#eef4f2;color:#33565f;padding:2px 6px;border-radius:4px;font-family:ui-monospace,SFMono-Regular,Consolas,monospace}

@media(max-width:760px){
  main{padding:20px 16px 32px}.topbar{padding-bottom:20px}.layout,.config-grid{grid-template-columns:1fr}.qr-frame{max-width:248px;margin:18px auto}.card{padding:20px}h1{font-size:26px}.advanced-title{display:block}footer{gap:15px;flex-direction:column}.private{font-size:10px}.brand{font-size:13px}
  .login-card{padding:28px 20px;border-radius:20px}
  .tab-btn{padding:9px 12px;font-size:13px}
}

/* 专属连接弹窗与独立页面样式 */
.modal-backdrop{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(18,43,49,0.48);backdrop-filter:blur(5px);display:none;align-items:center;justify-content:center;z-index:9999;padding:16px}
.modal-backdrop.show{display:flex;animation:fadeIn .15s ease-out}
.modal-card{width:100%;max-width:700px;background:#fff;border:1px solid var(--line);border-radius:22px;padding:26px;box-shadow:0 20px 48px rgba(18,43,49,0.18);max-height:90vh;overflow-y:auto;display:flex;flex-direction:column;gap:16px}
.modal-head{display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid var(--line);padding-bottom:14px}
.modal-close{background:none;border:none;font-size:24px;color:var(--muted);cursor:pointer;padding:4px 8px;border-radius:6px;line-height:1}
.modal-close:hover{background:#f0f5f4;color:var(--ink)}
.user-connect-grid{display:grid;grid-template-columns:250px minmax(0,1fr);gap:18px;align-items:start}
@media(max-width:660px){.user-connect-grid{grid-template-columns:1fr}}
.user-meta-bar{display:flex;gap:12px;align-items:center;flex-wrap:wrap;background:#f7faf9;padding:10px 14px;border-radius:10px;border:1px solid var(--line);font-size:12px}

/* 代理成功专属弹窗高颜值设计 */
.pm-card{width:100%;max-width:650px;background:#fff;border:1px solid var(--line);border-radius:24px;padding:26px;box-shadow:0 24px 60px rgba(18,43,49,0.2);max-height:92vh;overflow-y:auto;display:flex;flex-direction:column;gap:16px}
.pm-banner{background:linear-gradient(135deg,#f0f8f6 0%,#f6faf9 100%);border:1.5px solid #cce8e1;border-radius:16px;padding:14px 18px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px}
.pm-host-box{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.pm-host-val{font-size:17px;font-weight:800;color:var(--ink);font-family:ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:-.02em}
.pm-port-val{color:var(--accent);font-weight:850}
.pm-status-tag{display:inline-flex;align-items:center;gap:4px;background:#e1f5ee;color:#085041;font-size:11px;font-weight:700;border-radius:20px;padding:3px 10px;border:1px solid #b7ebd8}
.pm-cred-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.pm-cred-card{background:#f8fbfb;border:1px solid var(--line);border-radius:12px;padding:12px 14px;display:flex;justify-content:space-between;align-items:center}
.pm-cred-lbl{font-size:11px;color:var(--muted);font-weight:700;margin-bottom:3px}
.pm-cred-val{font-size:13px;font-weight:750;color:var(--ink);font-family:ui-monospace,SFMono-Regular,Consolas,monospace;word-break:break-all}
.pm-main-grid{display:grid;grid-template-columns:140px minmax(0,1fr);gap:16px;align-items:center;background:#fafcfb;border:1px solid var(--line);border-radius:14px;padding:14px}
@media(max-width:560px){.pm-main-grid{grid-template-columns:1fr;justify-items:center}.pm-cred-grid{grid-template-columns:1fr}}
.pm-qr-frame{background:#fff;border:1px solid var(--line);border-radius:10px;padding:6px;display:flex;justify-content:center;align-items:center;width:130px;height:130px;box-shadow:0 3px 10px rgba(0,0,0,0.03)}
.pm-qr-frame svg{display:block;width:100%;height:100%}
.pm-links-stack{display:flex;flex-direction:column;gap:10px;min-width:0;width:100%}
.pm-code-box{display:flex;gap:6px;align-items:center;background:#fff;border:1px solid var(--line);border-radius:8px;padding:4px 6px 4px 10px;transition:border-color .15s}
.pm-code-box:focus-within{border-color:var(--accent);box-shadow:0 0 0 2px rgba(8,127,116,0.1)}
.pm-code-input{flex:1;min-width:0;border:none;background:transparent;font:11px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace;color:#284d56;outline:none}

/* WARP 与自定义分流模块高阶专业排版 */
.warp-section { margin-top: 10px; }
.warp-switch-card { background: #f6faf9; border: 1px solid #d3e7e2; border-radius: 14px; padding: 16px 20px; margin-bottom: 20px; }
.warp-desc-title { font-size: 13.5px; font-weight: 750; color: #11342d; display: flex; align-items: center; gap: 8px; margin-bottom: 4px; }
.warp-desc-text { font-size: 12.5px; color: #496861; line-height: 1.6; margin: 0; }

.warp-rules-card { background: #ffffff; border: 1px solid var(--line); border-radius: 16px; padding: 22px; box-shadow: 0 4px 16px rgba(18, 43, 49, 0.03); }
.warp-rules-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; flex-wrap: wrap; gap: 10px; }
.warp-rules-title-box { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.warp-rules-title { font-size: 14px; font-weight: 800; color: var(--ink); margin: 0; }
.warp-count-badge { background: #eaf5ef; color: var(--accent); border: 1px solid #c0ded4; border-radius: 20px; padding: 3px 10px; font-size: 11.5px; font-weight: 700; }
.warp-reset-btn { background: #fff; border: 1px solid var(--line); color: var(--muted); border-radius: 8px; padding: 5px 12px; font-size: 12px; font-weight: 600; cursor: pointer; transition: all .15s ease; }
.warp-reset-btn:hover { background: #f0f5f4; color: var(--ink); border-color: #b0d0c8; }

.warp-add-form { display: flex; gap: 10px; margin-bottom: 14px; }
@media(max-width: 600px) { .warp-add-form { flex-direction: column; } }
.warp-domain-input { flex: 1; height: 42px; padding: 0 14px; border: 1.5px solid var(--line); border-radius: 10px; font-size: 13px; color: var(--ink); background: #fdfefe; outline: none; transition: all .15s ease; }
.warp-domain-input:focus { border-color: var(--accent); background: #fff; box-shadow: 0 0 0 3px rgba(8, 127, 116, 0.12); }
.warp-add-btn { height: 42px; padding: 0 20px; font-size: 13px; font-weight: 700; border-radius: 10px; background: var(--accent); color: #fff; border: none; cursor: pointer; white-space: nowrap; transition: all .15s ease; }
.warp-add-btn:hover { filter: brightness(0.92); }

.warp-presets-bar { display: flex; align-items: center; gap: 8px; margin-bottom: 18px; flex-wrap: wrap; font-size: 12px; color: var(--muted); }
.warp-preset-chip { display: inline-flex; align-items: center; gap: 4px; background: #f3f7f6; color: #2e554d; border: 1px solid #d4e5e1; border-radius: 14px; padding: 3px 10px; text-decoration: none; font-size: 11.5px; font-weight: 600; transition: all .15s ease; }
.warp-preset-chip:hover { background: #e6f3ef; border-color: var(--accent); color: var(--accent); transform: translateY(-1px); }

.warp-tags-wrap { display: flex; flex-wrap: wrap; gap: 8px; padding: 14px; background: #fafcfb; border: 1px solid var(--line); border-radius: 12px; min-height: 48px; align-items: center; }
.warp-tag-item { display: inline-flex; align-items: center; gap: 6px; background: #ffffff; border: 1.5px solid #cfe0dc; color: #184239; border-radius: 20px; padding: 5px 12px; font-size: 12.5px; font-weight: 650; box-shadow: 0 2px 6px rgba(18, 43, 49, 0.03); transition: all .15s ease; }
.warp-tag-item:hover { border-color: #a8cfc6; box-shadow: 0 3px 8px rgba(18, 43, 49, 0.06); }
.warp-tag-text { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; letter-spacing: -0.01em; }
.warp-tag-del { color: #d64545; text-decoration: none; font-size: 15px; line-height: 1; padding: 0 2px; font-weight: 800; cursor: pointer; border-radius: 50%; }
.warp-tag-del:hover { color: #a82020; transform: scale(1.2); }

/* BBR 拥塞控制模块全局专属高质感样式 */
.bbr-section { margin-top: 24px; border-left: 4px solid var(--accent); }
.bbr-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin-top: 14px; }
@media(max-width: 860px) { .bbr-grid { grid-template-columns: 1fr; } }
.bbr-card { background: #ffffff; border: 1.5px solid var(--line); border-radius: 16px; padding: 20px; display: flex; flex-direction: column; justify-content: space-between; gap: 14px; box-shadow: 0 4px 14px rgba(18, 43, 49, 0.03); transition: all .18s ease; }
.bbr-card:hover { border-color: #a8cfc6; transform: translateY(-2px); box-shadow: 0 6px 20px rgba(18, 43, 49, 0.06); }
.bbr-card-head { display: flex; align-items: center; justify-content: space-between; margin-bottom: 6px; }
.bbr-card-title { font-size: 14.5px; font-weight: 800; color: var(--ink); }
.bbr-card-desc { font-size: 12px; color: var(--muted); margin: 0; line-height: 1.6; }
.bbr-btn { width: 100%; height: 42px; font-size: 13px; font-weight: 750; border-radius: 10px; cursor: pointer; display: inline-flex; align-items: center; justify-content: center; transition: all .15s ease; border: 1px solid transparent; }
.bbr-btn.v1 { background: var(--accent); color: #fff; }
.bbr-btn.v1:hover { filter: brightness(0.92); }
.bbr-btn.v2 { background: #f6ffed; border-color: #b7eb8f; color: #237804; }
.bbr-btn.v2:hover { background: #d9f7be; }
.bbr-btn.v3 { background: #fff0f6; border-color: #ffd6e7; color: #c41d7f; }
.bbr-btn.v3:hover { background: #ffadd2; }

.bbr-info-bar { background: #f8fbfb; border: 1px solid var(--line); border-radius: 14px; padding: 16px 20px; margin-bottom: 18px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; }
.bbr-stat-val { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; color: var(--accent); font-weight: 800; font-size: 14px; }
.bbr-sub-text { font-size: 12px; color: var(--muted); margin-top: 3px; }

/* 全局自定义高颜值确认弹窗与 Toast 样式 */
.confirm-card { width: 100%; max-width: 440px; background: #ffffff; border: 1.5px solid var(--line); border-radius: 20px; padding: 24px; box-shadow: 0 20px 50px rgba(18, 43, 49, 0.22); animation: scaleUp .18s cubic-bezier(0.16, 1, 0.3, 1); }
@keyframes scaleUp { from { opacity: 0; transform: scale(0.94); } to { opacity: 1; transform: scale(1); } }
.confirm-icon-box { width: 48px; height: 48px; border-radius: 14px; background: #eaf5ef; color: var(--accent); display: flex; align-items: center; justify-content: center; font-size: 24px; margin-bottom: 14px; }
.confirm-icon-box.danger { background: #fdf2f2; color: var(--danger); }
.confirm-icon-box.warn { background: #fff8e6; color: #d46b08; }
.confirm-title { font-size: 17px; font-weight: 800; color: var(--ink); margin-bottom: 8px; }
.confirm-text { font-size: 13px; color: var(--muted); line-height: 1.6; margin-bottom: 22px; }
.confirm-actions { display: flex; gap: 10px; justify-content: flex-end; }
.confirm-btn { height: 40px; padding: 0 18px; border-radius: 10px; font-size: 13px; font-weight: 700; cursor: pointer; transition: all .15s ease; border: 1px solid transparent; }
.confirm-btn.cancel { background: #f3f7f6; color: var(--ink); border-color: #d8e5e2; }
.confirm-btn.cancel:hover { background: #e5eeec; }
.confirm-btn.primary { background: var(--accent); color: #fff; }
.confirm-btn.primary:hover { filter: brightness(0.92); }
.confirm-btn.danger { background: var(--danger); color: #fff; }
.confirm-btn.danger:hover { filter: brightness(0.92); }

/* 全局 Toast 通知栏 */
.toast-container { position: fixed; top: 24px; right: 24px; z-index: 99999; display: flex; flex-direction: column; gap: 10px; pointer-events: none; }
.toast-item { background: #122b31; color: #ffffff; border-radius: 12px; padding: 12px 20px; font-size: 13px; font-weight: 650; box-shadow: 0 10px 30px rgba(0,0,0,0.18); display: flex; align-items: center; gap: 10px; pointer-events: auto; animation: toastIn .2s cubic-bezier(0.16, 1, 0.3, 1); }
.toast-item.success { background: #087f74; }
.toast-item.error { background: #cf3c3c; }
@keyframes toastIn { from { opacity: 0; transform: translateY(-10px); } to { opacity: 1; transform: translateY(0); } }

/* ===== AmneziaWG 抗 DPI 协议卡片 ===== */
.awg-card { background: #ffffff; border: 1px solid var(--line); border-radius: 16px; padding: 22px; box-shadow: 0 4px 16px rgba(18, 43, 49, 0.03); }
.awg-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; flex-wrap: wrap; gap: 10px; }
.awg-title-box { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.awg-title { font-size: 15px; font-weight: 800; color: var(--ink); margin: 0; }
.awg-desc { font-size: 12.5px; color: var(--muted); line-height: 1.7; margin: 0 0 14px; }
.awg-meta { display: flex; gap: 10px; flex-wrap: wrap; font-size: 12px; color: var(--muted); margin-bottom: 16px; }
.awg-meta span { background: #f3f7f6; border: 1px solid #d4e5e1; border-radius: 12px; padding: 4px 11px; font-weight: 650; }
.awg-install-box { background: #f8fbfa; border: 1px solid #d9ebe6; border-radius: 14px; padding: 16px 18px; margin-bottom: 18px; }
.awg-label { display: block; font-size: 12px; font-weight: 700; color: var(--muted); margin: 12px 0 5px; }
.awg-label:first-child { margin-top: 0; }
.awg-input, .awg-select { width: 100%; height: 40px; padding: 0 12px; border: 1.5px solid var(--line); border-radius: 10px; font-size: 13px; color: var(--ink); background: #fdfefe; outline: none; box-sizing: border-box; }
.awg-input:focus, .awg-select:focus { border-color: var(--accent); background: #fff; box-shadow: 0 0 0 3px rgba(8, 127, 116, 0.12); }
.awg-warn { font-size: 11.5px; color: #993c1d; background: #faece7; border: 1px solid #f5c4b3; border-radius: 10px; padding: 9px 12px; line-height: 1.6; margin: 12px 0 0; }
.awg-add-form { display: flex; gap: 10px; margin-bottom: 16px; flex-wrap: wrap; }
.awg-add-form .awg-input { flex: 1; min-width: 150px; width: auto; }
.awg-table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
.awg-table th { text-align: left; font-size: 11.5px; color: var(--muted); font-weight: 700; padding: 8px 10px; border-bottom: 1px solid var(--line); white-space: nowrap; }
.awg-table td { padding: 10px; border-bottom: 1px solid #f0f4f3; color: var(--ink); vertical-align: middle; }
.awg-foot { display: flex; gap: 10px; margin-top: 16px; flex-wrap: wrap; }
.awg-hint { font-size: 11.5px; color: var(--muted); margin: 10px 0 0; line-height: 1.6; }
@media(max-width: 600px) { .awg-add-form { flex-direction: column; } .awg-add-form .awg-input { width: 100%; } }



"""

SCRIPT = """

// 全局高颜值 Promise 确认框与 Toast 机制
function showToast(msg, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) { alert(msg); return; }
  const toast = document.createElement('div');
  toast.className = 'toast-item ' + type;
  const icon = type === 'success' ? '✓ ' : (type === 'error' ? '✕ ' : 'ℹ ');
  toast.textContent = icon + msg;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.transition = 'all .25s ease';
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(-8px)';
    setTimeout(() => toast.remove(), 250);
  }, 2800);
}

function showConfirm(options = {}) {
  return new Promise((resolve) => {
    const modal = document.getElementById('custom-confirm-modal');
    const titleEl = document.getElementById('confirm-title');
    const textEl = document.getElementById('confirm-text');
    const iconEl = document.getElementById('confirm-icon');
    const okBtn = document.getElementById('confirm-btn-ok');
    const cancelBtn = document.getElementById('confirm-btn-cancel');

    if (!modal || !titleEl || !textEl || !okBtn || !cancelBtn) {
      resolve(confirm(options.text || '确定执行吗？'));
      return;
    }

    titleEl.textContent = options.title || '操作确认';
    textEl.textContent = options.text || '确定要继续执行吗？';
    if (iconEl) {
      iconEl.textContent = options.icon || '💡';
      iconEl.className = 'confirm-icon-box ' + (options.isDanger ? 'danger' : (options.isWarn ? 'warn' : ''));
    }

    okBtn.textContent = options.confirmText || '确定执行';
    okBtn.className = 'confirm-btn ' + (options.isDanger ? 'danger' : 'primary');

    modal.classList.add('show');

    function cleanup(result) {
      modal.classList.remove('show');
      okBtn.removeEventListener('click', onOk);
      cancelBtn.removeEventListener('click', onCancel);
      resolve(result);
    }

    function onOk() { cleanup(true); }
    function onCancel() { cleanup(false); }

    okBtn.addEventListener('click', onOk);
    cancelBtn.addEventListener('click', onCancel);
  });
}

function switchTab(tabId) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
  const btn = document.querySelector('[data-tab="' + tabId + '"]');
  const pane = document.getElementById('pane-' + tabId);
  if (btn && pane) {
    btn.classList.add('active');
    pane.classList.add('active');
    history.replaceState(null, null, '#' + tabId);
  }
}

document.querySelectorAll('[data-tab]').forEach(btn => {
  btn.addEventListener('click', () => switchTab(btn.dataset.tab));
});

if (location.hash) {
  const hash = location.hash.substring(1);
  if (document.getElementById('pane-' + hash)) {
    switchTab(hash);
  }
}

function genRandom(targetId, prefix='') {
  const el = document.getElementById(targetId);
  if (!el) return;
  const rand = Array.from(crypto.getRandomValues(new Uint8Array(8))).map(b => b.toString(16).padStart(2, '0')).join('');
  el.value = prefix ? (prefix + '_' + rand.substring(0, 8)) : rand;
}

document.querySelectorAll('[data-gen]').forEach(btn => {
  btn.addEventListener('click', () => {
    genRandom(btn.dataset.gen, btn.dataset.prefix || '');
  });
});

document.querySelectorAll('[data-copy]').forEach(button => {
  button.addEventListener('click', async () => {
    const field = document.getElementById(button.dataset.copy);
    const status = document.getElementById('copy-status');
    try {
      const val = field.value || field.textContent || '';
      await navigator.clipboard.writeText(val);
      if (status) status.textContent = '已复制到剪贴板 ✓';
      button.textContent = '已复制 ✓';
      setTimeout(() => { button.textContent = button.dataset.orig || '复制'; }, 1800);
    } catch (_) {
      if (field.select) { field.focus(); field.select(); }
      if (status) status.textContent = '已选中，请按 Ctrl+C 复制';
    }
  });
});

// 专属连接弹窗逻辑
const uModal = document.getElementById('user-modal');
const uModalTitle = document.getElementById('um-title');
const uModalSub = document.getElementById('um-sub');
const uModalBody = document.getElementById('um-body');
const uModalClose = document.getElementById('um-close');

// WARP 状态与一键安装与自定义分流交互
const warpBadge = document.getElementById('warp-badge');
const btnToggleWarp = document.getElementById('btn-toggle-warp');
const btnInstallWarp = document.getElementById('btn-install-warp');
const warpTagsCloud = document.getElementById('warp-tags-cloud');
const warpRulesCount = document.getElementById('warp-rules-count');
const formAddWarpRule = document.getElementById('form-add-warp-rule');
const inputWarpDomain = document.getElementById('input-warp-domain');
const btnResetWarpRules = document.getElementById('btn-reset-warp-rules');

function renderWarpRules(rules) {
  if (!warpTagsCloud) return;
  if (warpRulesCount) warpRulesCount.textContent = rules.length + ' 个生效中';
  if (rules.length === 0) {
    warpTagsCloud.innerHTML = '<span style="font-size:12px;color:var(--muted)">暂无分流域名，上方输入即可快速添加</span>';
    return;
  }
  warpTagsCloud.innerHTML = rules.map(d => {
    return `<span class="warp-tag-item">
      <span class="warp-tag-text">${d}</span>
      <a href="javascript:void(0)" class="warp-tag-del" onclick="delWarpRule('${d}')" title="移除此域名">×</a>
    </span>`;
  }).join('');
}

async function addWarpRule(domain) {
  if (!domain) return;
  try {
    const res = await fetch(location.pathname + 'manage-warp', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'action=add_rule&domain=' + encodeURIComponent(domain)
    });
    const json = await res.json();
    if (json.ok) {
      if (inputWarpDomain) inputWarpDomain.value = '';
      if (Array.isArray(json.rules)) renderWarpRules(json.rules);
    } else {
      alert(json.error || '添加失败');
    }
  } catch (e) {
    alert('请求异常: ' + e.message);
  }
}

async function delWarpRule(domain) {
  if (!confirm('确定将 ' + domain + ' 从 WARP 分流列表中移除吗？')) return;
  try {
    const res = await fetch(location.pathname + 'manage-warp', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'action=del_rule&domain=' + encodeURIComponent(domain)
    });
    const json = await res.json();
    if (json.ok && Array.isArray(json.rules)) {
      renderWarpRules(json.rules);
    }
  } catch (e) {
    alert('请求异常: ' + e.message);
  }
}
window.delWarpRule = delWarpRule;

async function checkWarpStatus() {
  if (!warpBadge) return;
  try {
    const res = await fetch(location.pathname + 'warp-status', { credentials: 'same-origin' });
    if (!res.ok) return;
    const json = await res.json();
    if (!json.ok) return;

    if (btnInstallWarp) {
      if (!json.installed) {
        btnInstallWarp.style.display = 'inline-flex';
      } else {
        btnInstallWarp.style.display = 'none';
      }
    }

    if (!json.installed) {
      warpBadge.textContent = '● 未安装 WARP 客户端';
      warpBadge.style.background = '#fff1f0';
      warpBadge.style.color = '#cf3c3c';
      if (btnToggleWarp) btnToggleWarp.style.display = 'none';
      return;
    } else {
      if (btnToggleWarp) btnToggleWarp.style.display = 'inline-flex';
    }

    if (json.enabled) {
      warpBadge.textContent = json.connected ? ('● 运行中 (' + (json.ip || '已连通') + ')') : '● 正在连接 / 异常';
      warpBadge.style.background = json.connected ? '#eaf3de' : '#fff1f0';
      warpBadge.style.color = json.connected ? '#27500a' : '#cf3c3c';
      if (btnToggleWarp) {
        btnToggleWarp.textContent = '已开启 (点击关闭)';
        btnToggleWarp.className = 'toggle-btn on';
      }
    } else {
      warpBadge.textContent = '○ 已停用 (直连模式)';
      warpBadge.style.background = '#f1efe8';
      warpBadge.style.color = '#5f5e5a';
      if (btnToggleWarp) {
        btnToggleWarp.textContent = '已关闭 (点击开启)';
        btnToggleWarp.className = 'toggle-btn off';
      }
    }

    if (Array.isArray(json.rules)) {
      renderWarpRules(json.rules);
    }
  } catch (_) {}
}

if (btnToggleWarp) {
  btnToggleWarp.addEventListener('click', async () => {
    btnToggleWarp.disabled = true;
    btnToggleWarp.textContent = '切换中...';
    try {
      const res = await fetch(location.pathname + 'manage-warp', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'action=toggle'
      });
      const json = await res.json();
      if (!json.ok) alert(json.error || '切换失败');
    } catch (e) {
      alert('操作失败: ' + e.message);
    } finally {
      btnToggleWarp.disabled = false;
      await checkWarpStatus();
    }
  });
}

if (btnInstallWarp) {
  btnInstallWarp.addEventListener('click', async () => {
    if (!confirm("确定要在服务器上一键部署 Cloudflare WARP 本地出口吗？将自动安装 wgcf + wireproxy，并启用 127.0.0.1:19898 的 socks5 出口。")) return;
    btnInstallWarp.disabled = true;
    const origText = btnInstallWarp.textContent;
    btnInstallWarp.textContent = '⏳ 正在安装 WARP (耗时约 30 秒)...';
    try {
      const res = await fetch(location.pathname + 'install-warp', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
      });
      if (!res.ok) {
        const errText = await res.text();
        showToast('安装失败 (HTTP ' + res.status + '): ' + errText, 'error');
        return;
      }
      const json = await res.json();
      if (json.ok) {
        showToast(json.message || 'Cloudflare WARP 安装成功！服务已自动就绪。', 'success');
        await checkWarpStatus();
      } else {
        showToast(json.error || '安装失败，请检查网络', 'error');
      }
    } catch (e) {
      showToast('安装请求异常: ' + e.message, 'error');
    } finally {
      btnInstallWarp.disabled = false;
      btnInstallWarp.textContent = origText;
    }
  });
}

if (formAddWarpRule) {
  formAddWarpRule.addEventListener('submit', (e) => {
    e.preventDefault();
    if (inputWarpDomain) addWarpRule(inputWarpDomain.value.trim());
  });
}

document.querySelectorAll('.preset-rule').forEach(el => {
  el.addEventListener('click', () => {
    const dom = el.getAttribute('data-domain');
    if (dom) addWarpRule(dom);
  });
});

if (btnResetWarpRules) {
  btnResetWarpRules.addEventListener('click', async () => {
    if (!confirm('确定重置为系统默认推荐的 AI 域名规则列表吗？')) return;
    try {
      const res = await fetch(location.pathname + 'manage-warp', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'action=reset_rules'
      });
      const json = await res.json();
      if (json.ok && Array.isArray(json.rules)) {
        renderWarpRules(json.rules);
      }
    } catch (e) {
      alert('请求异常: ' + e.message);
    }
  });
}

checkWarpStatus();

// VLESS-Reality 客户端与状态交互
const realityBadge = document.getElementById('reality-badge');
const btnInstallXray = document.getElementById('btn-install-xray');
const btnToggleReality = document.getElementById('btn-toggle-reality');
const realityContentBox = document.getElementById('reality-content-box');
const realityUriVal = document.getElementById('reality-uri-val');
const realityQrBox = document.getElementById('reality-qr-box');
const realitySniVal = document.getElementById('reality-sni-val');
const realityUuidVal = document.getElementById('reality-uuid-val');
const realityPubkeyVal = document.getElementById('reality-pubkey-val');
const realityFlowVal = document.getElementById('reality-flow-val');
const btnCopyRealityUri = document.getElementById('btn-copy-reality-uri');
const btnResetRealityKeys = document.getElementById('btn-reset-reality-keys');

async function checkRealityStatus() {
  if (!realityBadge) return;
  try {
    const res = await fetch(location.pathname + 'reality-status', { credentials: 'same-origin' });
    if (!res.ok) return;
    const json = await res.json();
    if (!json.ok) return;

    if (!json.installed) {
      realityBadge.textContent = '● 未安装 Xray 核心';
      realityBadge.style.background = '#fff1f0';
      realityBadge.style.color = '#cf3c3c';
      if (btnInstallXray) btnInstallXray.style.display = 'inline-flex';
      if (btnToggleReality) btnToggleReality.style.display = 'none';
      if (realityContentBox) realityContentBox.style.display = 'none';
      return;
    }

    if (btnInstallXray) btnInstallXray.style.display = 'none';
    if (btnToggleReality) btnToggleReality.style.display = 'inline-flex';

    if (json.active) {
      realityBadge.textContent = '● 运行中 (TCP 443 端口)';
      realityBadge.style.background = '#eaf3de';
      realityBadge.style.color = '#27500a';
      btnToggleReality.textContent = '已开启 (点击关闭)';
      btnToggleReality.className = 'toggle-btn on';
      if (realityContentBox) realityContentBox.style.display = 'block';
    } else {
      realityBadge.textContent = '○ 已停止';
      realityBadge.style.background = '#f1efe8';
      realityBadge.style.color = '#5f5e5a';
      btnToggleReality.textContent = '已关闭 (点击开启)';
      btnToggleReality.className = 'toggle-btn off';
      if (realityContentBox) realityContentBox.style.display = 'none';
    }

    if (json.config) {
      const cfg = json.config;
      if (realityUriVal) realityUriVal.value = cfg.uri || '';
      if (realityQrBox && cfg.qr_svg) realityQrBox.innerHTML = cfg.qr_svg;
      if (realitySniVal) realitySniVal.textContent = (cfg.sni || 'www.apple.com') + ':' + (cfg.port || 443);
      if (realityUuidVal) realityUuidVal.textContent = cfg.uuid || '-';
      if (realityPubkeyVal) realityPubkeyVal.textContent = cfg.pub_key || '-';
      if (realityFlowVal) realityFlowVal.textContent = (cfg.short_id || '') + ' · ' + (cfg.flow || 'xtls-rprx-vision');
    }
  } catch (_) {}
}

if (btnInstallXray) {
  btnInstallXray.addEventListener('click', async () => {
    if (!confirm("确定要一键安装 Xray 官方核心并部署 VLESS-Reality 节点吗？")) return;
    btnInstallXray.disabled = true;
    const orig = btnInstallXray.textContent;
    btnInstallXray.textContent = '⏳ 正在下载并配置 Xray (约 20-30 秒)...';
    try {
      const res = await fetch(location.pathname + 'install-xray', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
      });
      const json = await res.json();
      if (json.ok) {
        alert(json.message || 'Xray-core 安装并启动成功！');
        await checkRealityStatus();
      } else {
        alert(json.error || '安装失败');
      }
    } catch (e) {
      alert('请求异常: ' + e.message);
    } finally {
      btnInstallXray.disabled = false;
      btnInstallXray.textContent = orig;
    }
  });
}

if (btnToggleReality) {
  btnToggleReality.addEventListener('click', async () => {
    btnToggleReality.disabled = true;
    btnToggleReality.textContent = '切换中...';
    try {
      const res = await fetch(location.pathname + 'manage-reality', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'action=toggle'
      });
      const json = await res.json();
      if (!json.ok) alert(json.error || '切换失败');
      await checkRealityStatus();
    } catch (e) {
      alert('请求异常: ' + e.message);
    } finally {
      btnToggleReality.disabled = false;
    }
  });
}

if (btnResetRealityKeys) {
  btnResetRealityKeys.addEventListener('click', async () => {
    if (!confirm("确定要重新生成 UUID 与 Reality 密钥对吗？旧客户端连接凭据将失效。")) return;
    try {
      const res = await fetch(location.pathname + 'manage-reality', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'action=reset'
      });
      const json = await res.json();
      if (json.ok) {
        alert('密钥与 UUID 已重新生成并生效！');
        await checkRealityStatus();
      } else {
        alert(json.error || '重置失败');
      }
    } catch (e) {
      alert('请求异常: ' + e.message);
    }
  });
}

if (btnCopyRealityUri) {
  btnCopyRealityUri.addEventListener('click', () => {
    if (realityUriVal && realityUriVal.value) {
      navigator.clipboard.writeText(realityUriVal.value).then(() => {
        const orig = btnCopyRealityUri.textContent;
        btnCopyRealityUri.textContent = '✓ 已复制直链';
        setTimeout(() => btnCopyRealityUri.textContent = orig, 1500);
      });
    }
  });
}

checkRealityStatus();

// BBR 状态获取与一键切换交互
const bbrBadge = document.getElementById('bbr-badge');
const bbrCurrentText = document.getElementById('bbr-current-text');
const bbrQdiscText = document.getElementById('bbr-qdisc-text');
const bbrKernelText = document.getElementById('bbr-kernel-text');
const bbrRebootTip = document.getElementById('bbr-reboot-tip');
const btnRebootServer = document.getElementById('btn-reboot-server');

async function checkBbrStatus() {
  if (!bbrBadge) return;
  try {
    const res = await fetch(location.pathname + 'bbr-status', { credentials: 'same-origin' });
    if (!res.ok) return;
    const json = await res.json();
    if (!json.ok) return;

    if (bbrCurrentText) bbrCurrentText.textContent = json.current || 'cubic';
    if (bbrQdiscText) bbrQdiscText.textContent = json.qdisc || 'fq_codel';
    if (bbrKernelText) bbrKernelText.textContent = json.kernel || '--';

    const isBbrActive = (json.current && json.current.includes('bbr'));
    if (bbrBadge) {
      if (isBbrActive) {
        bbrBadge.textContent = '● 已开启 ' + json.current.toUpperCase();
        bbrBadge.style.background = '#eaf3de';
        bbrBadge.style.color = '#27500a';
      } else {
        bbrBadge.textContent = '○ 未开启 BBR (' + json.current + ')';
        bbrBadge.style.background = '#f1efe8';
        bbrBadge.style.color = '#5f5e5a';
      }
    }

    if (bbrRebootTip && btnRebootServer) {
      if (json.need_reboot) {
        bbrRebootTip.style.display = 'block';
        bbrRebootTip.textContent = '⚠️ 已成功配置 ' + json.configured.toUpperCase() + '，需要重启服务器后生效！';
        btnRebootServer.style.display = 'inline-flex';
      } else {
        bbrRebootTip.style.display = 'none';
        btnRebootServer.style.display = 'none';
      }
    }
  } catch (_) {}
}

document.querySelectorAll('.btn-apply-bbr').forEach(btn => {
  btn.addEventListener('click', async () => {
    const ver = btn.getAttribute('data-version') || 'v1';
    const label = { v1: 'BBR V1 (经典官方)', v2: 'BBR V2 (低丢包)', v3: 'BBR V3 (极限吞吐)' }[ver];
    const confirmed = await showConfirm({
      title: '开启 ' + label + ' 加速引擎',
      text: '系统将自动将拥塞控制与排队规则写入 Linux 内核持久化配置（/etc/sysctl.d/99-bbr.conf）。配置后可能需要安全重启服务器以完成生效。',
      icon: '🚀',
      confirmText: '立即开启 ' + ver.toUpperCase()
    });
    if (!confirmed) return;

    btn.disabled = true;
    const orig = btn.textContent;
    btn.textContent = '正在配置...';
    try {
      const res = await fetch(location.pathname + 'set-bbr', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'version=' + encodeURIComponent(ver)
      });
      const json = await res.json();
      if (json.ok) {
        showToast(json.message || '配置成功！', 'success');
        await checkBbrStatus();
      } else {
        showToast(json.error || '配置失败', 'error');
      }
    } catch (e) {
      alert('请求异常: ' + e.message);
    } finally {
      btn.disabled = false;
      btn.textContent = orig;
    }
  });
});

if (btnRebootServer) {
  btnRebootServer.addEventListener('click', async () => {
    const confirmed = await showConfirm({
      title: '安全重启服务器',
      text: '确定要立即重启服务器以完成新 BBR 内核网络参数生效吗？服务器将在 10 秒内安全完成重启，页面将自动发起 25 秒倒计时并在就绪后重连。',
      icon: '🔄',
      confirmText: '确定立即重启',
      isWarn: true
    });
    if (!confirmed) return;
    btnRebootServer.disabled = true;
    btnRebootServer.textContent = '⏳ 重启指令已发送...';
    try {
      const res = await fetch(location.pathname + 'reboot-server', {
        method: 'POST',
        credentials: 'same-origin'
      });
      alert("服务器正在重启中，系统将在 25 秒后自动刷新页面！");
      let countdown = 25;
      const timer = setInterval(() => {
        countdown--;
        btnRebootServer.textContent = '正在重启中 (' + countdown + 's)...';
        if (countdown <= 0) {
          clearInterval(timer);
          location.reload();
        }
      }, 1000);
    } catch (e) {
      alert("重启请求已发出: " + e.message);
    }
  });
}

checkBbrStatus();

// 版本检测与一键更新交互
const coreVerDisplay = document.getElementById('core-ver-display');
const portalVerDisplay = document.getElementById('portal-ver-display');
const btnUpdateCore = document.getElementById('btn-update-core');
const btnUpdatePortal = document.getElementById('btn-update-portal');
const updateStatusMsg = document.getElementById('update-status-msg');

async function checkVersions() {
  if (!coreVerDisplay || !portalVerDisplay) return;
  try {
    const res = await fetch(location.pathname + 'check-version', { credentials: 'same-origin' });
    if (!res.ok) return;
    const json = await res.json();
    if (!json.ok) return;

    // 核心展示
    coreVerDisplay.textContent = json.core_current + (json.core_has_update ? (' → 可升级至 ' + json.core_latest) : ' (最新)');
    if (json.core_has_update && btnUpdateCore) {
      btnUpdateCore.style.display = 'inline-flex';
      btnUpdateCore.onclick = () => doUpgrade('core');
    }

    // 面板展示
    portalVerDisplay.textContent = json.portal_current + (json.portal_has_update ? (' → 发现新版本') : ' (最新)');
    if (json.portal_has_update && btnUpdatePortal) {
      btnUpdatePortal.style.display = 'inline-flex';
      btnUpdatePortal.onclick = () => doUpgrade('portal');
    }
  } catch (_) {}
}

async function doUpgrade(target) {
  const btn = target === 'core' ? btnUpdateCore : btnUpdatePortal;
  if (!confirm(`确定要升级 ${target === 'core' ? 'Hysteria 2 官方核心' : '控制面板自身'} 吗？`)) return;
  if (btn) { btn.disabled = true; btn.textContent = '升级中...'; }
  if (updateStatusMsg) updateStatusMsg.textContent = '正在下载并应用更新，请稍候约 5-10 秒...';
  try {
    const res = await fetch(location.pathname + 'do-upgrade', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'target=' + target
    });
    const json = await res.json();
    if (json.ok) {
      if (updateStatusMsg) updateStatusMsg.textContent = '升级已触发！5 秒后将自动刷新页面...';
      setTimeout(() => location.reload(), 5000);
    } else {
      alert(json.error || '升级失败');
      if (btn) { btn.disabled = false; btn.textContent = '重试升级'; }
    }
  } catch (e) {
    alert('升级请求异常: ' + e.message);
    if (btn) { btn.disabled = false; btn.textContent = '重试升级'; }
  }
}

checkVersions();

// 实时吞吐量与网速轮询 (每 2 秒更新一次)
const speedRxEl = document.getElementById('node-speed-rx');
const speedTxEl = document.getElementById('node-speed-tx');
const rxTagEl = document.getElementById('rx-active-tag');
const txTagEl = document.getElementById('tx-active-tag');

function fmtSpeed(bytesPerSec) {
  if (bytesPerSec < 1024) return bytesPerSec.toFixed(0) + ' B/s';
  if (bytesPerSec < 1024 * 1024) return (bytesPerSec / 1024).toFixed(1) + ' KB/s';
  return (bytesPerSec / (1024 * 1024)).toFixed(2) + ' MB/s';
}

async function pollTrafficSpeed() {
  try {
    const res = await fetch(location.pathname + 'traffic-speed', { credentials: 'same-origin' });
    if (!res.ok) return;
    const json = await res.json();
    if (!json.ok) return;

    if (speedRxEl) speedRxEl.textContent = fmtSpeed(json.node_rx || 0);
    if (speedTxEl) speedTxEl.textContent = fmtSpeed(json.node_tx || 0);

    if (rxTagEl) rxTagEl.className = (json.node_rx > 1024) ? 'speed-badge active' : 'speed-badge';
    if (txTagEl) txTagEl.className = (json.node_tx > 1024) ? 'speed-badge active' : 'speed-badge';

    // 更新各个用户的实时速率标签
    if (json.users) {
      document.querySelectorAll('[data-user-speed]').forEach(badge => {
        const uid = badge.dataset.userSpeed;
        const u = json.users[uid];
        if (u && (u.rx > 0 || u.tx > 0)) {
          badge.textContent = '↓ ' + fmtSpeed(u.rx) + ' · ↑ ' + fmtSpeed(u.tx);
          badge.className = 'speed-badge active';
        } else {
          badge.textContent = '↓ 0 B/s · ↑ 0 B/s';
          badge.className = 'speed-badge';
        }
      });
    }
  } catch (_) {}
}

setInterval(pollTrafficSpeed, 2000);
pollTrafficSpeed();

// 入站代理服务管理 (gost 驱动)
const gostBadge = document.getElementById('gost-badge');
const proxyTbody = document.getElementById('proxy-tbody');
const btnInstallGost = document.getElementById('btn-install-gost');
const proxyModal = document.getElementById('proxy-modal');
const pmClose = document.getElementById('pm-close');
const resPType = document.getElementById('res-ptype');
const resPHost = document.getElementById('res-phost');
const resPPort = document.getElementById('res-pport');
const resPUser = document.getElementById('res-puser');
const resPPass = document.getElementById('res-ppass');
const resPUrl = document.getElementById('res-purl');
const resPFmt = document.getElementById('res-pfmt');
const btnCopyPUrl = document.getElementById('btn-copy-purl');
const btnCopyPFmt = document.getElementById('btn-copy-pfmt');

let curProxyServerHost = location.hostname;

function closeProxyModal() {
  if (proxyModal) proxyModal.classList.remove('show');
}
if (pmClose) pmClose.addEventListener('click', closeProxyModal);
if (proxyModal) {
  proxyModal.addEventListener('click', (e) => {
    if (e.target === proxyModal) closeProxyModal();
  });
}

const resPTypeBadge = document.getElementById('res-ptype-badge');
const resPQr = document.getElementById('res-pqr');

function showProxyResult(data) {
  if (!proxyModal) return;
  const host = data.host || curProxyServerHost;
  const ptype = data.type || 'socks5';
  const url = data.url || (ptype + '://' + data.username + ':' + data.password + '@' + host + ':' + data.port);
  const fmt = data.format || (host + ':' + data.port + ':' + data.username + ':' + data.password);

  if (resPTypeBadge) {
    resPTypeBadge.textContent = ptype.toUpperCase();
    resPTypeBadge.className = 'proxy-type ' + ptype;
  }
  if (resPHost) resPHost.textContent = host;
  if (resPPort) resPPort.textContent = data.port;
  if (resPUser) resPUser.textContent = data.username;
  if (resPPass) resPPass.textContent = data.password;
  if (resPUrl) resPUrl.value = url;
  if (resPFmt) resPFmt.value = fmt;

  if (resPQr && data.qr) {
    resPQr.innerHTML = data.qr;
  }

  if (btnCopyPUrl) {
    btnCopyPUrl.onclick = async () => {
      try {
        await navigator.clipboard.writeText(url);
        btnCopyPUrl.textContent = '已复制 ✓';
        setTimeout(() => { btnCopyPUrl.textContent = '复制 URL'; }, 1800);
      } catch (_) { alert('复制失败，请手动选择复制'); }
    };
  }

  if (btnCopyPFmt) {
    btnCopyPFmt.onclick = async () => {
      try {
        await navigator.clipboard.writeText(fmt);
        btnCopyPFmt.textContent = '已复制 ✓';
        setTimeout(() => { btnCopyPFmt.textContent = '复制格式'; }, 1800);
      } catch (_) { alert('复制失败，请手动选择复制'); }
    };
  }

  document.querySelectorAll('[data-copy-field]').forEach(b => {
    b.onclick = async () => {
      const el = document.getElementById(b.dataset.copyField);
      if (el) {
        try {
          await navigator.clipboard.writeText(el.textContent);
          const orig = b.textContent;
          b.textContent = '✓';
          setTimeout(() => { b.textContent = orig; }, 1500);
        } catch (_) {}
      }
    };
  });

  proxyModal.classList.add('show');
}

// 绑定秒级一键生成按钮
document.querySelectorAll('.btn-quick-proxy').forEach(btn => {
  btn.addEventListener('click', async () => {
    const ptype = btn.dataset.ptype;
    const cPortEl = document.getElementById('custom-proxy-port');
    const customPort = cPortEl ? cPortEl.value.trim() : '';
    btn.disabled = true;
    const origText = btn.textContent;
    btn.textContent = '⚡ 正在生成...';
    try {
      let body = 'action=create&type=' + encodeURIComponent(ptype);
      if (customPort) body += '&port=' + encodeURIComponent(customPort);

      const res = await fetch(location.pathname + 'manage-proxy', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: body
      });
      const json = await res.json();
      if (json.ok) {
        if (cPortEl) cPortEl.value = '';
        showProxyResult(json);
        loadProxyServices();
      } else {
        alert(json.error || '生成失败');
      }
    } catch (e) {
      alert('生成异常: ' + e.message);
    } finally {
      btn.disabled = false;
      btn.textContent = origText;
    }
  });
});

if (btnInstallGost) {
  btnInstallGost.addEventListener('click', async () => {
    if (!confirm("确定要一键安装或更新 GOST 代理服务吗？系统将自动匹配架构并配置自启。")) return;
    btnInstallGost.disabled = true;
    const origText = btnInstallGost.textContent;
    btnInstallGost.textContent = '⏳ 正在安装 GOST...';
    try {
      const res = await fetch(location.pathname + 'install-gost', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
      });
      const json = await res.json();
      if (json.ok) {
        alert(json.message || 'GOST 安装成功！服务已就绪。');
        loadProxyServices();
      } else {
        alert(json.error || '安装失败，请检查服务器网络或日志');
      }
    } catch (e) {
      alert('安装请求异常: ' + e.message);
    } finally {
      btnInstallGost.disabled = false;
      btnInstallGost.textContent = origText;
    }
  });
}

async function loadProxyServices() {
  if (!proxyTbody) return;
  try {
    const res = await fetch(location.pathname + 'proxy-services', { credentials: 'same-origin' });
    if (!res.ok) return;
    const json = await res.json();
    if (!json.ok) return;

    if (gostBadge) {
      if (!json.gost_installed) {
        gostBadge.textContent = '● 未安装 gost';
        gostBadge.style.background = '#fff1f0';
        gostBadge.style.color = '#cf3c3c';
        if (btnInstallGost) {
          btnInstallGost.style.display = 'inline-flex';
          btnInstallGost.textContent = '⚡ 一键安装 GOST';
        }
      } else if (json.gost_active) {
        gostBadge.textContent = '● gost 运行中';
        gostBadge.style.background = '#eaf3de';
        gostBadge.style.color = '#27500a';
        if (btnInstallGost) {
          btnInstallGost.style.display = 'none';
        }
      } else {
        gostBadge.textContent = '● gost 未启动';
        gostBadge.style.background = '#f1efe8';
        gostBadge.style.color = '#5f5e5a';
        if (btnInstallGost) {
          btnInstallGost.style.display = 'inline-flex';
          btnInstallGost.textContent = '🔄 重启/修复 GOST';
        }
      }
    }

    const services = json.services || [];
    if (services.length === 0) {
      proxyTbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--muted);padding:24px">暂无代理服务，点击上方「添加代理服务」创建</td></tr>';
      return;
    }
    if (json.host) curProxyServerHost = json.host;
    const typeLabel = { socks5: 'SOCKS5', http: 'HTTP', https: 'HTTPS' };
    proxyTbody.innerHTML = services.map(s => {
      const fullUrl = `${s.type}://${s.username}:${s.password}@${curProxyServerHost}:${s.port}`;
      return `
      <tr>
        <td><span class="proxy-type ${s.type}">${typeLabel[s.type] || s.type}</span></td>
        <td><code style="font-size:12px;font-weight:700;color:var(--accent)">:${s.port}</code></td>
        <td><code style="font-size:12px">${s.username}</code></td>
        <td><code style="font-size:12px">${s.password}</code></td>
        <td>
          <div style="display:flex;align-items:center;gap:6px">
            <code style="font-size:11px;background:#f5f8f7;padding:2px 6px;border-radius:4px;word-break:break-all">${s.type}://${s.username}:****@${curProxyServerHost}:${s.port}</code>
            <button class="button" style="padding:2px 8px;font-size:11px;white-space:nowrap" type="button" data-copy-link="${fullUrl}">复制链接</button>
          </div>
        </td>
        <td><button class="button danger" style="padding:4px 10px;font-size:11px" type="button" data-proxy-del="${s.id}">删除</button></td>
      </tr>`;
    }).join('');

    proxyTbody.querySelectorAll('[data-copy-link]').forEach(btn => {
      btn.addEventListener('click', async () => {
        try {
          await navigator.clipboard.writeText(btn.dataset.copyLink);
          const orig = btn.textContent;
          btn.textContent = '已复制 ✓';
          setTimeout(() => { btn.textContent = orig; }, 1800);
        } catch (_) { alert('复制失败'); }
      });
    });
    proxyTbody.querySelectorAll('[data-proxy-del]').forEach(btn => {
      btn.addEventListener('click', async () => {
        if (!confirm('确定删除该代理服务？')) return;
        const res = await fetch(location.pathname + 'manage-proxy', {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: 'action=delete&id=' + encodeURIComponent(btn.dataset.proxyDel)
        });
        const json = await res.json();
        if (json.ok) loadProxyServices();
        else alert(json.error || '删除失败');
      });
    });
  } catch (_) {}
}

// proxyForm replaced with instant buttons

loadProxyServices();

function closeUserModal() {
  if (uModal) uModal.classList.remove('show');
}
if (uModalClose) uModalClose.addEventListener('click', closeUserModal);
if (uModal) {
  uModal.addEventListener('click', (e) => {
    if (e.target === uModal) closeUserModal();
  });
}

document.querySelectorAll('.btn-user-connect').forEach(btn => {
  btn.addEventListener('click', async () => {
    const uid = btn.dataset.uid;
    const token = btn.dataset.token;
    const userKey = btn.dataset.key;
    if (!uModal || !uModalBody) return;
    
    uModalTitle.textContent = '用户专属连接: ' + uid;
    uModalSub.textContent = '正在获取专属配置与独立连接页...';
    uModalBody.innerHTML = '<div style="text-align:center;padding:36px;color:var(--muted)">加载专属数据中...</div>';
    uModal.classList.add('show');
    
    try {
      const res = await fetch('/' + token + '/user-config?user_id=' + encodeURIComponent(uid), { credentials: 'same-origin' });
      if (res.status === 401) {
        throw new Error('登录状态已失效，请刷新页面重新登录');
      }
      if (!res.ok) {
        throw new Error('网络请求异常 (HTTP ' + res.status + ')');
      }
      const json = await res.json();
      if (!json.ok) throw new Error(json.error || '加载失败');
      
      uModalSub.textContent = json.note ? ('备注: ' + json.note) : '专属独立配置与下载链接';
      
      const shareUrl = location.origin + '/' + token + '/u/' + encodeURIComponent(uid) + '?k=' + userKey;
      
      let trafficText = (json.traffic_limit > 0) 
        ? ((json.traffic_used / (1024**2)).toFixed(1) + ' MB / ' + (json.traffic_limit / (1024**3)).toFixed(1) + ' GB')
        : ((json.traffic_used / (1024**2)).toFixed(1) + ' MB (不限)');
      let expireText = (json.expires_at < 2000000000) ? new Date(json.expires_at * 1000).toLocaleString() : '永久有效';
      let ipText = (json.ip_limit > 0) ? (json.ip_limit + ' IP') : '不限';
      
      uModalBody.innerHTML = `
        <div class="user-meta-bar">
          <span>📅 到期: <b>${expireText}</b></span>
          <span>📊 流量: <b>${trafficText}</b></span>
          <span>📱 IP限制: <b>${ipText}</b></span>
        </div>
        
        <div style="background:#eaf5ef;border:1px solid #c3ddd5;border-radius:12px;padding:12px 14px">
          <div style="font-size:12px;font-weight:700;color:var(--accent);margin-bottom:6px">🌐 专属独立连接页面 (可直接发给客户):</div>
          <div class="input-with-action">
            <input type="text" id="um-share-url" value="${shareUrl}" readonly style="font-size:12px;height:38px">
            <button class="button primary" style="padding:0 12px;height:38px;font-size:12px" type="button" data-modal-copy="um-share-url">复制页面链接</button>
            <a class="button" style="padding:0 12px;height:38px;font-size:12px" href="${shareUrl}" target="_blank">打开页面 ↗</a>
          </div>
        </div>

        <div class="user-connect-grid">
          <div style="text-align:center;background:#fff;border:1px solid var(--line);border-radius:14px;padding:14px">
            <div style="font-size:12px;font-weight:700;color:var(--ink);margin-bottom:8px">专属二维码扫码导入</div>
            <div class="qr-frame" style="margin:0 auto;max-width:210px;padding:8px">${json.qr_svg || '<p style="color:var(--muted)">二维码生成中...</p>'}</div>
            <div style="font-size:11px;color:var(--muted);margin-top:8px">Shadowrocket / v2rayNG / Nekobox</div>
          </div>
          <div style="display:flex;flex-direction:column;gap:12px">
            <div>
              <div style="font-size:12px;font-weight:700;color:var(--ink);margin-bottom:4px">专属节点直链 (URI):</div>
              <textarea id="um-uri" class="link" style="height:65px;font-size:11px" readonly>${json.uri}</textarea>
              <div style="margin-top:6px;display:flex;gap:8px">
                <button class="button primary" style="padding:6px 14px;font-size:11px" type="button" data-modal-copy="um-uri">复制直链</button>
              </div>
            </div>
            <div>
              <div style="font-size:12px;font-weight:700;color:var(--ink);margin-bottom:4px">Clash / Mihomo 专属订阅链接:</div>
              <div class="input-with-action">
                <input type="text" id="um-clash-sub" value="${location.origin}/${token}/u/${encodeURIComponent(uid)}/clash.yaml?k=${userKey}" readonly style="font-size:11px;height:36px">
                <button class="button primary" style="padding:0 12px;height:36px;font-size:11px" type="button" data-modal-copy="um-clash-sub">复制订阅</button>
                <a class="button" style="padding:0 10px;height:36px;font-size:11px" href="/${token}/u/${encodeURIComponent(uid)}/clash.yaml?k=${userKey}" download="clash-${uid}.yaml">下载 ↓</a>
              </div>
              <details style="margin-top:6px">
                <summary style="font-size:11px;color:var(--muted)">查看/复制配置文本</summary>
                <textarea id="um-clash" class="link" style="height:65px;font-size:10px;margin-top:4px" readonly>${json.clash}</textarea>
                <div style="margin-top:4px"><button class="button" style="padding:2px 8px;font-size:10px" type="button" data-modal-copy="um-clash">复制文本</button></div>
              </details>
            </div>
          </div>
        </div>
      `;
      
      uModalBody.querySelectorAll('[data-modal-copy]').forEach(b => {
        b.addEventListener('click', async () => {
          const target = document.getElementById(b.dataset.modalCopy);
          if (!target) return;
          const text = target.value || target.textContent || '';
          await navigator.clipboard.writeText(text);
          const orig = b.textContent;
          b.textContent = '已复制 ✓';
          setTimeout(() => { b.textContent = orig; }, 1800);
        });
      });
      
    } catch (err) {
      uModalBody.innerHTML = `<div style="text-align:center;padding:24px;color:var(--danger)">加载失败: ${err.message}</div>`;
    }
  });
});

/* ==================== AmneziaWG 抗 DPI 协议管理 ==================== */
const awgBadge = document.getElementById('awg-badge');
const awgInstallBox = document.getElementById('awg-install-box');
const btnInstallAwg = document.getElementById('btn-install-awg');
const btnDoInstallAwg = document.getElementById('btn-do-install-awg');
const awgLineSelect = document.getElementById('awg-line-select');
const awgEndpointInput = document.getElementById('awg-endpoint-input');
const awgMetaBox = document.getElementById('awg-meta');
const awgMetaLine = document.getElementById('awg-meta-line');
const awgMetaPort = document.getElementById('awg-meta-port');
const awgMetaPeers = document.getElementById('awg-meta-peers');
const awgMetaChip = document.getElementById('awg-meta-chip');
const awgPanel = document.getElementById('awg-panel');
const awgPeerTbody = document.getElementById('awg-peer-tbody');
const awgPeerName = document.getElementById('awg-peer-name');
const awgPeerEndpoint = document.getElementById('awg-peer-endpoint');
const btnAddAwgPeer = document.getElementById('btn-add-awg-peer');
const btnSwitchAwgLine = document.getElementById('btn-switch-awg-line');
const btnUpdateAwg = document.getElementById('btn-update-awg');
let awgCurrentEndpoint = '';
let awgCurrentLine = '3';

function awgPost(endpoint, params) {
  return fetch(location.pathname + endpoint, {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(params).toString()
  }).then(r => r.json()).catch(e => ({ ok: false, error: '请求异常: ' + e.message }));
}

function setAwgBadge(text, bg, color) {
  if (!awgBadge) return;
  awgBadge.textContent = text;
  awgBadge.style.background = bg;
  awgBadge.style.color = color;
}

async function loadAwgState() {
  if (!awgBadge) return;
  try {
    const res = await fetch(location.pathname + 'awg-state', { credentials: 'same-origin' });
    if (!res.ok) return;
    const json = await res.json();
    if (!json.ok) return;

    awgCurrentEndpoint = json.endpoint || '';
    awgCurrentLine = json.line || '3';
    if (awgEndpointInput && !awgEndpointInput.value) awgEndpointInput.value = awgCurrentEndpoint;
    if (awgPeerEndpoint && !awgPeerEndpoint.value) awgPeerEndpoint.value = awgCurrentEndpoint;
    if (awgMetaChip) awgMetaChip.textContent = json.installed ? ('AWG ' + awgCurrentLine + '.x') : '未安装';

    if (!json.installed) {
      setAwgBadge('● 未安装 AmneziaWG', '#fff1f0', '#cf3c3c');
      if (awgMetaBox) awgMetaBox.style.display = 'none';
      if (awgPanel) awgPanel.style.display = 'none';
      if (awgInstallBox) awgInstallBox.style.display = 'none';
      if (btnInstallAwg) { btnInstallAwg.style.display = 'inline-flex'; btnInstallAwg.textContent = '⚡ 一键安装 AmneziaWG'; }
      return;
    }

    if (awgLineSelect && awgCurrentLine) awgLineSelect.value = awgCurrentLine;

    if (json.active) {
      setAwgBadge('● AmneziaWG 运行中', '#eaf3de', '#27500a');
    } else {
      setAwgBadge('● AmneziaWG 已安装未运行', '#f1efe8', '#5f5e5a');
    }
    if (btnInstallAwg) btnInstallAwg.style.display = 'none';
    if (awgInstallBox) awgInstallBox.style.display = 'none';
    if (awgMetaBox) awgMetaBox.style.display = 'flex';
    if (awgMetaLine) awgMetaLine.textContent = '协议线 AWG ' + awgCurrentLine + '.x';
    if (awgMetaPort) awgMetaPort.textContent = 'UDP ' + (json.port || '未知');
    if (awgMetaPeers) awgMetaPeers.textContent = '客户端 ' + (json.peer_count || 0) + ' 个';
    if (awgPanel) awgPanel.style.display = 'block';

    renderAwgPeers(json.peers || []);
  } catch (e) { /* 静默失败，不打扰主界面 */ }
}

function renderAwgPeers(peers) {
  if (!awgPeerTbody) return;
  if (!peers.length) {
    awgPeerTbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:var(--muted);padding:20px">暂无客户端，用上方表单新增</td></tr>';
    return;
  }
  awgPeerTbody.innerHTML = peers.map(p => {
    const enc = encodeURIComponent(p.name);
    const bs = 'padding:3px 10px;font-size:11px';
    return '<tr>'
      + '<td><strong>' + p.name + '</strong></td>'
      + '<td>' + p.address + '</td>'
      + '<td style="color:var(--muted);font-size:11.5px">' + (p.created_at || '-') + '</td>'
      + '<td style="white-space:nowrap">'
      + '<button class="button" type="button" data-awg-conf="' + enc + '" style="' + bs + '">下载配置</button> '
      + '<button class="button" type="button" data-awg-qr="' + enc + '" style="' + bs + '">二维码</button> '
      + '<button class="button" type="button" data-awg-del="' + enc + '" style="' + bs + ';color:#cf3c3c">删除</button>'
      + '</td></tr>';
  }).join('');

  awgPeerTbody.querySelectorAll('[data-awg-conf]').forEach(b => {
    b.addEventListener('click', () => {
      window.open(location.pathname + 'awg-conf?name=' + b.getAttribute('data-awg-conf'), '_blank');
    });
  });
  awgPeerTbody.querySelectorAll('[data-awg-qr]').forEach(b => {
    b.addEventListener('click', () => {
      window.open(location.pathname + 'awg-qr.svg?name=' + b.getAttribute('data-awg-qr'), '_blank');
    });
  });
  awgPeerTbody.querySelectorAll('[data-awg-del]').forEach(b => {
    b.addEventListener('click', async () => {
      const n = decodeURIComponent(b.getAttribute('data-awg-del'));
      if (!confirm('确认删除客户端「' + n + '」？该客户端会立即断开连接。')) return;
      const json = await awgPost('manage-amneziawg', { action: 'peer_del', name: n });
      if (json.ok) { showToast('已删除客户端 ' + n, 'success'); loadAwgState(); }
      else { alert(json.error || '删除失败'); }
    });
  });
}

if (btnInstallAwg) {
  btnInstallAwg.addEventListener('click', () => {
    if (!awgInstallBox) return;
    awgInstallBox.style.display = (awgInstallBox.style.display === 'none') ? 'block' : 'none';
  });
}

if (btnDoInstallAwg) {
  btnDoInstallAwg.addEventListener('click', async () => {
    const line = awgLineSelect ? awgLineSelect.value : '3';
    const endpoint = awgEndpointInput ? awgEndpointInput.value.trim() : '';
    if (!endpoint) { alert('请填写客户端连接地址（域名或公网 IP）'); return; }
    if (!confirm('确认安装 AmneziaWG（协议线 AWG ' + line + '.x）？\n\n会下载自建静态二进制并启动独立服务，不影响现有的 Hysteria 2。')) return;
    btnDoInstallAwg.disabled = true;
    const orig = btnDoInstallAwg.textContent;
    btnDoInstallAwg.textContent = '⏳ 安装中，请稍候...';
    try {
      const json = await awgPost('install-amneziawg', { line: line, endpoint: endpoint });
      if (json.ok) { showToast(json.message || '安装完成', 'success'); loadAwgState(); }
      else { alert(json.error || '安装失败'); }
    } finally {
      btnDoInstallAwg.disabled = false;
      btnDoInstallAwg.textContent = orig;
    }
  });
}

if (btnAddAwgPeer) {
  btnAddAwgPeer.addEventListener('click', async () => {
    const name = awgPeerName ? awgPeerName.value.trim() : '';
    const endpoint = (awgPeerEndpoint && awgPeerEndpoint.value.trim()) || awgCurrentEndpoint;
    if (!name) { alert('请填写客户端名称'); return; }
    if (!/^[A-Za-z0-9_.-]{1,32}$/.test(name)) { alert('名称只允许字母、数字、点、下划线、连字符，且不超过 32 字符'); return; }
    if (!endpoint) { alert('请填写连接地址'); return; }
    btnAddAwgPeer.disabled = true;
    try {
      const json = await awgPost('manage-amneziawg', { action: 'peer_add', name: name, endpoint: endpoint });
      if (json.ok) {
        if (awgPeerName) awgPeerName.value = '';
        showToast('已新增客户端 ' + name + '，正在打开配置', 'success');
        window.open(location.pathname + 'awg-conf?name=' + encodeURIComponent(name), '_blank');
        loadAwgState();
      } else { alert(json.error || '新增失败'); }
    } finally {
      btnAddAwgPeer.disabled = false;
    }
  });
}

if (btnSwitchAwgLine) {
  btnSwitchAwgLine.addEventListener('click', async () => {
    const target = prompt('切换 AmneziaWG 协议线\n\n2 = AWG 2.x（参数体系稳定）\n3 = AWG 3.x（含头部保护与抗行为分析）\n\n⚠️ 切换会重新生成全部混淆参数，已发放的客户端配置会立即失效，必须重新导出。\n\n请输入目标协议线：', awgCurrentLine === '3' ? '2' : '3');
    if (target !== '2' && target !== '3') return;
    if (target === awgCurrentLine) { alert('已经是 AWG ' + awgCurrentLine + '.x，无需切换。'); return; }
    if (!confirm('确认切换到 AWG ' + target + '.x？所有已发放的客户端配置都会失效。')) return;
    const json = await awgPost('manage-amneziawg', { action: 'set_line', line: target });
    if (json.ok) { showToast(json.message || '已切换协议线', 'success'); loadAwgState(); }
    else { alert(json.error || '切换失败'); }
  });
}

if (btnUpdateAwg) {
  btnUpdateAwg.addEventListener('click', async () => {
    if (!confirm('确认更新 AmneziaWG 二进制？协议线与混淆参数保持不变，客户端无需重新导入。')) return;
    const json = await awgPost('manage-amneziawg', { action: 'update' });
    if (json.ok) { showToast(json.message || '更新完成', 'success'); loadAwgState(); }
    else { alert(json.error || '更新失败'); }
  });
}

loadAwgState();
"""

LOGIN_SCRIPT = """
function toggleSecret(id, btn) {
  const el = document.getElementById(id);
  if (el.type === 'password') {
    el.type = 'text';
    btn.textContent = '隐藏';
  } else {
    el.type = 'password';
    btn.textContent = '显示';
  }
}
"""

USER_SCRIPT = """
document.querySelectorAll('[data-copy]').forEach(button => {
  button.addEventListener('click', async () => {
    const field = document.getElementById(button.dataset.copy);
    try {
      const val = field.value || field.textContent || '';
      await navigator.clipboard.writeText(val);
      const orig = button.textContent;
      button.textContent = '已复制 ✓';
      setTimeout(() => { button.textContent = orig; }, 1800);
    } catch (_) {
      if (field.select) { field.focus(); field.select(); }
    }
  });
});
"""


def user_view_key(secret, user_id):
    return hmac.new(str(secret).encode(), f'uv:{user_id}'.encode(), hashlib.sha256).hexdigest()[:16]


def format_bytes(b):
    if b < 1024:
        return f"{b} B"
    elif b < 1024**2:
        return f"{b/1024:.1f} KB"
    elif b < 1024**3:
        return f"{b/1024**2:.2f} MB"
    else:
        return f"{b/1024**3:.2f} GB"


def page_html(m, uri, subscription, clash, sing, users=None, api_key=None, token="", session_secret=""):
    def field(identifier, value, kind="link"):
        return f'<textarea id="{identifier}" class="{kind}" aria-label="{identifier}" readonly spellcheck="false">{html.escape(value)}</textarea>'
    def copy(identifier):
        return f'<button class="button primary" type="button" data-copy="{identifier}" data-orig="复制">复制</button>'
    
    is_insecure = m.get("is_insecure", False)
    server_name = m.get("server_name") or m.get("public_ip", "localhost")
    public_ip = m.get("public_ip", server_name)
    host = public_ip if is_insecure else server_name
    sub_port = m.get("subscription_port", 8443)
    _raw_pin = (m.get("pin_sha256") or "").strip().lower()
    pin_sha256 = _raw_pin if (is_insecure and len(_raw_pin) == 64
                              and all(c in "0123456789abcdef" for c in _raw_pin)) else ""
    pin_block = (f'<div class="api-box"><div><div style="font-size:11px;color:var(--muted);font-weight:700">'
                 f'自签证书 SHA-256 指纹 (HEX · 已写入直链 pinSHA256 / Xray 的 pinnedPeerCertSha256)</div>'
                 f'<div class="api-key-code" id="api-pin-val">{html.escape(pin_sha256)}</div></div>'
                 f'<button class="button" type="button" data-copy="api-pin-val" data-orig="复制指纹">复制指纹</button></div>') if pin_sha256 else ''
    listen_port = m.get("listen_port", 19984)
    obfs_pw = m.get("obfs_password", "")
    users = users or {}
    now_ts = int(time.time())
    
    user_rows = []
    active_count = 0
    total_used_bytes = 0

    for uid, u in sorted(users.items(), key=lambda x: x[1].get("created_at", 0), reverse=True):
        used_bytes = int(u.get("used_bytes", 0))
        limit_bytes = int(u.get("limit_bytes", 0))
        total_used_bytes += used_bytes

        is_traffic_ok = limit_bytes == 0 or used_bytes < limit_bytes
        is_time_ok = u.get("expires_at", 0) >= now_ts
        is_active = u.get("status") == "active" and is_time_ok and is_traffic_ok

        if is_active:
            active_count += 1

        if not is_traffic_ok:
            status_html = '<span class="status-pill expired">流量超额</span>'
        elif not is_time_ok:
            status_html = '<span class="status-pill expired">已到期</span>'
        elif u.get("status") != "active":
            status_html = '<span class="status-pill expired">已停用</span>'
        else:
            status_html = '<span class="status-pill active">正常</span>'

        expires_str = time.strftime("%Y-%m-%d %H:%M", time.localtime(u.get("expires_at", 0))) if u.get("expires_at", 0) < 2000000000 else "永久有效"
        ip_limit = u.get("ip_limit", 0)
        ip_limit_str = f"{ip_limit} IP" if ip_limit > 0 else "不限"
        online_ips = len(u.get("online_ips", {}))
        online_str = f'<span class="badge-count" style="font-size:11px;">{online_ips} 在线</span>' if online_ips > 0 else '<span style="color:var(--muted)">0</span>'
        
        # 流量展示与进度条
        if limit_bytes > 0:
            percent = min(round((used_bytes / limit_bytes) * 100), 100)
            bar_class = "danger" if percent >= 90 else ""
            traffic_display = f"""<div>{format_bytes(used_bytes)} / {format_bytes(limit_bytes)} <span style="font-size:11px;color:var(--muted)">({percent}%)</span></div>
            <div class="traffic-bar"><div class="traffic-fill {bar_class}" style="width:{percent}%"></div></div>"""
        else:
            traffic_display = f"""<div>{format_bytes(used_bytes)} <span style="font-size:11px;color:var(--muted)">(不限)</span></div>"""

        note = u.get("note") or "-"
        user_key = user_view_key(session_secret, uid) if session_secret else ""
        
        user_rows.append(f"""<tr>
          <td><strong>{html.escape(uid)}</strong><div style="font-size:11px;color:var(--muted)">{html.escape(note)}</div></td>
          <td>{status_html}</td>
          <td>{ip_limit_str} ({online_str})</td>
          <td>
            {traffic_display}
            <div style="margin-top:4px"><span class="speed-badge" data-user-speed="{html.escape(uid)}">↓ 0 B/s · ↑ 0 B/s</span></div>
          </td>
          <td>{expires_str}</td>
          <td><code style="font-size:11px">{html.escape(u.get("password","")[:4] + "****" + u.get("password","")[-4:])}</code></td>
          <td>
            <button class="button primary btn-user-connect" style="padding:4px 10px;font-size:11px;margin-right:6px" type="button" data-uid="{html.escape(uid)}" data-token="{token}" data-key="{user_key}">专属连接</button>
            <form method="POST" action="/{token}/manage-user" style="display:inline" onsubmit="return confirm('确定注销此用户？')">
              <input type="hidden" name="action" value="delete">
              <input type="hidden" name="user_id" value="{html.escape(uid)}">
              <button class="button danger" style="padding:4px 10px;font-size:11px" type="submit">删除</button>
            </form>
          </td>
        </tr>""")

    users_table_html = "".join(user_rows) or '<tr><td colspan="7" style="text-align:center;color:var(--muted);padding:24px">暂无多用户数据</td></tr>'
    obfs_badge = "Salamander" if obfs_pw else "QUIC"
    field_hy2 = field("hy2-link", uri)
    copy_hy2 = copy("hy2-link")
    field_sub = field("clash-subscription", subscription)
    copy_sub = copy("clash-subscription")
    field_clash_cfg = field("clash-config", clash, "config")
    copy_clash_cfg = copy("clash-config")
    field_sing_cfg = field("sing-config", sing, "config")
    copy_sing_cfg = copy("sing-config")

    return f"""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>HY2 · 节点与集群中心</title><style>{STYLE}</style></head><body><main>
<nav class="topbar" aria-label="页面标识"><div class="brand"><span class="logo">H₂</span> HYSTERIA <span> / 控制中心</span></div><span class="private">● 集群运行中</span></nav>
<header class="hero"><div class="eyebrow">HYSTERIA 2 NODE DASHBOARD</div><h1>{html.escape(server_name)}</h1><p>官方核心驱动 · 极速 QUIC 代理 · 多用户开户与流量/IP限制</p></header>

<!-- 顶部 Tab 导航栏 -->
<div class="tab-bar">
  <button class="tab-btn active" data-tab="connect">🚀 节点导入 (Connect)</button>
  <button class="tab-btn" data-tab="users">👥 多用户管理 ({active_count}/{len(users)})</button>
  <button class="tab-btn" data-tab="proxies">🌐 入站代理 & WARP</button>
  <button class="tab-btn" data-tab="reality">🛡️ VLESS-Reality (备用)</button>
  <button class="tab-btn" data-tab="cluster">🔑 通用 REST API 对接</button>
  <button class="tab-btn" data-tab="configs">⚙️ 高级配置</button>
</div>

<!-- Tab 1: 节点连接视图 -->
<div class="tab-pane active" id="pane-connect">
  <div class="layout">
    <section class="card qr-card">
      <div class="eyebrow">QUICK CONNECT</div>
      <h2>主管理员扫码</h2>
      <p class="hint">适用于支持 Hysteria 2 的客户端</p>
      <div class="qr-frame"><img src="qr.svg" alt="HY2 节点导入二维码" width="260" height="260"></div>
      <p class="hint">打开客户端扫描二维码直接导入</p>
      <div class="tags"><span class="tag">Hysteria 2</span><span class="tag">TLS</span><span class="tag">{obfs_badge}</span></div>
    </section>
    <div class="stack">
      <section class="card">
        <div class="card-head"><span class="step">01</span><div><h2>节点直链 (URI)</h2><p>v2rayN / Nekobox / Shadowrocket</p></div></div>
        {field_hy2}
        <div class="actions">{copy_hy2}</div>
        <p class="note">{html.escape(host)} · UDP {int(listen_port)}</p>
      </section>
      <section class="card">
        <div class="card-head"><span class="step">02</span><div><h2>Clash 订阅</h2><p>适用于 Clash Meta / Mihomo 内核</p></div></div>
        {field_sub}
        <div class="actions">{copy_sub}<a class="button" href="clash.yaml" download="clash.yaml">下载配置 ↓</a></div>
        <p class="note">在客户端添加订阅链接即可自动同步。</p>
      </section>
    </div>
  </div>
</div>

<!-- Tab 2: 多用户与流量/IP 限制视图 -->
<div class="tab-pane" id="pane-users">
  <section class="card">
    <div class="user-header">
      <div><h2>多用户、流量与 IP 限制管理</h2><p style="font-size:13px">实时监控当前节点有效用户、到期时间、实时流量消耗与在线 IP 限制</p></div>
      <div class="user-stats">
        <span class="badge-count">有效用户: {active_count} / {len(users)}</span>
        <span class="badge-count" style="background:#f0f7f6">总已用流量: {format_bytes(total_used_bytes)}</span>
      </div>
    </div>

    <!-- 节点实时并发网速仪表卡片 (动态轮询更新) -->
    <div class="speed-grid">
      <div class="speed-card">
        <div>
          <div class="lbl">⚡ 节点实时下行吞吐 (Download)</div>
          <div class="val" id="node-speed-rx" style="color:var(--accent)">0.0 KB/s</div>
        </div>
        <span class="speed-badge active" id="rx-active-tag">● 实时监听</span>
      </div>
      <div class="speed-card">
        <div>
          <div class="lbl">⬆️ 节点实时上行吞吐 (Upload)</div>
          <div class="val" id="node-speed-tx" style="color:#284d56">0.0 KB/s</div>
        </div>
        <span class="speed-badge" id="tx-active-tag">● 实时监听</span>
      </div>
    </div>

    <!-- 手动添加用户卡片 (结构化字段 + 随机生成辅助) -->


    <details style="margin-bottom:18px">
      <summary class="button" style="margin-bottom:12px;list-style:none">＋ 手动添加/开通新用户</summary>
      <form class="modal-form" method="POST" action="/{token}/manage-user">
        <input type="hidden" name="action" value="create">
        
        <div class="form-field">
          <label for="f_uid">用户标识 (User ID) <span>必填</span></label>
          <div class="input-with-action">
            <input id="f_uid" name="user_id" placeholder="例如: user_01" required>
            <button type="button" class="btn-mini" data-gen="f_uid" data-prefix="user">🎲 随机生成</button>
          </div>
          <small>客户端节点命名或用户唯一标识</small>
        </div>

        <div class="form-field">
          <label for="f_pwd">连接认证密码 <span>留空随机</span></label>
          <div class="input-with-action">
            <input id="f_pwd" name="password" placeholder="留空提交时自动生成">
            <button type="button" class="btn-mini" data-gen="f_pwd">🎲 随机密码</button>
          </div>
          <small>买家或客户端用于握手的秘密连接密钥</small>
        </div>

        <div class="form-field">
          <label for="f_days">服务有效期 (天) <span>默认 30</span></label>
          <input id="f_days" name="duration_days" type="number" min="1" max="3650" value="30" placeholder="默认 30 天">
          <small>从创建时间起算的有效天数</small>
        </div>

        <div class="form-field">
          <label for="f_traffic">流量限额 (GB) <span>0 为不限</span></label>
          <input id="f_traffic" name="traffic_gb" type="number" step="0.5" min="0" value="0" placeholder="输入例如 100">
          <small>达到限额后系统将自动阻断连接</small>
        </div>

        <div class="form-field">
          <label for="f_iplimit">同时在线 IP 限制 <span>0 为不限</span></label>
          <input id="f_iplimit" name="ip_limit" type="number" min="0" max="100" value="0" placeholder="例如填 1 或 2">
          <small>限制单人或单家庭设备同时使用</small>
        </div>

        <div class="form-field">
          <label for="f_note">备注信息 <span>选填</span></label>
          <input id="f_note" name="note" placeholder="例如: 客户小明 / 微信购买">
          <small>便于你在控制台快速区分订单来源</small>
        </div>

        <div class="form-field-full" style="margin-top:6px">
          <button class="button primary" style="width:100%;height:44px;font-size:14px" type="submit">立即创建并开通用户 →</button>
        </div>
      </form>
    </details>

    <div class="user-table-wrap">
      <table class="user-table">
        <thead><tr><th>用户标识</th><th>状态</th><th>IP 限制 (实时)</th><th>已用流量 / 配额</th><th>到期时间</th><th>连接密码</th><th>操作</th></tr></thead>
        <tbody>{users_table_html}</tbody>
      </table>
    </div>
  </section>
</div>

<!-- Tab 3: 入站代理与 WARP 扩展服务视图 (独立专区) -->
<div class="tab-pane" id="pane-proxies">
  <!-- 区块 1: 入站代理服务 (GOST 驱动) -->
  <section class="card" style="margin-bottom:22px">
    <div class="user-header">
      <div>
        <h2>🌐 入站代理服务 (GOST 驱动)</h2>
        <p style="font-size:13px">让服务器额外提供独立 SOCKS5 / HTTP / HTTPS 代理端口，普通客户端直连即可使用</p>
      </div>
      <div style="display:flex;gap:10px;align-items:center">
        <span class="status-pill" id="gost-badge" style="background:#f1efe8;color:#5f5e5a">检测中...</span>
        <button class="button primary" id="btn-install-gost" type="button" style="padding:6px 14px;font-size:12px;display:none">⚡ 一键安装 GOST</button>
      </div>
    </div>

    <!-- 极速一键生成按钮专区 -->
    <div style="background:#f8fbfb;border:1px solid var(--line);border-radius:14px;padding:18px;margin-bottom:18px">
      <div style="font-size:13px;font-weight:700;margin-bottom:12px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px">
        <span>⚡ 秒级一键生成入站代理服务 (自动分配空闲端口与安全密码)</span>
        <details style="display:inline-block">
          <summary style="font-size:12px;color:var(--accent);cursor:pointer;font-weight:600">高级指定端口 ▾</summary>
          <div style="margin-top:8px;background:#fff;border:1px solid var(--line);border-radius:10px;padding:12px;display:flex;gap:8px;align-items:center">
            <input id="custom-proxy-port" type="number" min="1" max="65535" placeholder="输入自定义端口(留空则随机)" style="width:200px;height:34px;padding:0 10px;border:1px solid var(--line);border-radius:6px;font-size:12px">
            <span style="font-size:11px;color:var(--muted)">选填，留空自动分配</span>
          </div>
        </details>
      </div>
      <div style="display:flex;gap:12px;flex-wrap:wrap">
        <button class="button primary btn-quick-proxy" data-ptype="socks5" type="button" style="height:44px;padding:0 22px;font-size:13px;border-radius:10px">⚡ 一键生成 SOCKS5 代理</button>
        <button class="button btn-quick-proxy" data-ptype="http" type="button" style="height:44px;padding:0 22px;font-size:13px;border-radius:10px;background:#fff;border-color:#badcd5">⚡ 一键生成 HTTP 代理</button>
        <button class="button btn-quick-proxy" data-ptype="https" type="button" style="height:44px;padding:0 22px;font-size:13px;border-radius:10px;background:#fff;border-color:#badcd5">⚡ 一键生成 HTTPS 代理</button>
      </div>
    </div>



    <div class="user-table-wrap">
      <table class="proxy-table">
        <thead><tr><th>类型</th><th>端口</th><th>账号</th><th>密码</th><th>完整直连地址 (可复制)</th><th>操作</th></tr></thead>
        <tbody id="proxy-tbody"><tr><td colspan="6" style="text-align:center;color:var(--muted);padding:24px">正在加载代理服务...</td></tr></tbody>
      </table>
    </div>
  </section>

  <!-- 区块 2: Cloudflare WARP 智能分流出口 -->
  <section class="card warp-section">
    <div class="user-header">
      <div>
        <h2>⚡ Cloudflare WARP 智能分流出口 (AI 加速)</h2>
        <p style="font-size:13px">智能分流主流 AI 大模型流量（ChatGPT、Claude、Gemini），普通网页直连保持原生高速</p>
      </div>
      <div style="display:flex;gap:10px;align-items:center">
        <span class="status-pill" id="warp-badge" style="background:#eaf3de;color:#27500a">检测中...</span>
        <button class="button primary" id="btn-install-warp" type="button" style="padding:6px 14px;font-size:12px;display:none">⚡ 一键安装 WARP</button>
        <button class="toggle-btn off" id="btn-toggle-warp" type="button">切换中...</button>
      </div>
    </div>

    <div class="warp-switch-card">
      <div class="warp-desc-title">🛡️ 出口路由与防封号保护机制</div>
      <p class="warp-desc-text">
        开启后，名单内的目标网站出站流量将由 Cloudflare WARP 干净网络出口分流，有效避开数据中心 IP 拦截与高频验证码挑战；其余全球网站维持原生网卡直连。
      </p>
    </div>

    <div class="warp-rules-card">
      <div class="warp-rules-head">
        <div class="warp-rules-title-box">
          <span class="warp-rules-title">🎯 自定义分流域名列表 (走 WARP 出口)</span>
          <span class="warp-count-badge" id="warp-rules-count">加载中...</span>
        </div>
        <button class="warp-reset-btn" id="btn-reset-warp-rules" type="button" title="恢复为系统推荐的常用 AI 域名规则">恢复预设</button>
      </div>

      <form class="warp-add-form" id="form-add-warp-rule">
        <input class="warp-domain-input" id="input-warp-domain" type="text" placeholder="输入要走 WARP 的域名，例如 netflix.com / bing.com" required>
        <button class="warp-add-btn" type="submit">＋ 添加分流域名</button>
      </form>

      <div class="warp-presets-bar">
        <span>常用推荐快捷添加:</span>
        <a href="javascript:void(0)" class="warp-preset-chip preset-rule" data-domain="netflix.com">+ Netflix</a>
        <a href="javascript:void(0)" class="warp-preset-chip preset-rule" data-domain="disneyplus.com">+ Disney+</a>
        <a href="javascript:void(0)" class="warp-preset-chip preset-rule" data-domain="spotify.com">+ Spotify</a>
        <a href="javascript:void(0)" class="warp-preset-chip preset-rule" data-domain="bing.com">+ Bing/Copilot</a>
        <a href="javascript:void(0)" class="warp-preset-chip preset-rule" data-domain="twitter.com">+ Twitter/X</a>
      </div>

      <div class="warp-tags-wrap" id="warp-tags-cloud">
        <span style="font-size:12px;color:var(--muted)">正在拉取规则...</span>
      </div>
    </div>
  </section>

  <!-- 区块 3: AmneziaWG 抗 DPI 协议 (用户态 WireGuard 分支) -->
  <section class="card awg-card" style="margin-top:22px">
    <div class="awg-head">
      <div class="awg-title-box">
        <h2 class="awg-title">🛡️ AmneziaWG (抗 DPI 的 WireGuard 分支)</h2>
        <span class="status-pill" id="awg-badge" style="background:#f1efe8;color:#5f5e5a">检测中...</span>
        <span class="status-pill" id="awg-meta-chip" style="background:#f3f7f6;color:#2e554d">—</span>
      </div>
      <button class="button primary" id="btn-install-awg" type="button" style="padding:6px 14px;font-size:12px;display:none">⚡ 一键安装 AmneziaWG</button>
    </div>

    <p class="awg-desc">
      WireGuard 的抗审查分支：密码学内核（Curve25519 / ChaCha20-Poly1305 / Noise_IK）完全不变，只把数据包的头部、长度与时序特征随机化，让 DPI 无法按固定指纹识别。
      本项目采用<strong>用户态 amneziawg-go</strong>部署，不需要编译内核模块，也不引入 Docker，与其他服务互不干扰。
    </p>

    <div class="awg-meta" id="awg-meta" style="display:none">
      <span id="awg-meta-line">协议线 —</span>
      <span id="awg-meta-port">UDP —</span>
      <span id="awg-meta-peers">客户端 —</span>
    </div>

    <!-- 安装表单（未安装或需要重装时展开） -->
    <div class="awg-install-box" id="awg-install-box" style="display:none">
      <label class="awg-label" for="awg-line-select">协议线</label>
      <select class="awg-select" id="awg-line-select">
        <option value="3">AWG 3.x — 最新，含头部保护与抗连接行为分析</option>
        <option value="2">AWG 2.x — 参数体系成熟，生态验证更充分</option>
      </select>

      <label class="awg-label" for="awg-endpoint-input">客户端连接地址（域名或公网 IP）</label>
      <input class="awg-input" id="awg-endpoint-input" type="text" placeholder="例如 vpn.example.com" autocomplete="off" spellcheck="false">

      <p class="awg-hint">监听端口自动从 50000-59000 中选取空闲端口，以避开 Hysteria 2 的端口跳跃区间 20000-40000。</p>

      <button class="button primary" id="btn-do-install-awg" type="button" style="margin-top:14px;padding:9px 20px;font-size:13px">开始安装</button>
    </div>

    <!-- 已安装后的客户端管理面板 -->
    <div id="awg-panel" style="display:none">
      <div class="awg-add-form">
        <input class="awg-input" id="awg-peer-name" type="text" placeholder="新客户端名称（字母/数字/._-）" autocomplete="off" spellcheck="false">
        <input class="awg-input" id="awg-peer-endpoint" type="text" placeholder="连接地址（默认沿用已保存的地址）" autocomplete="off" spellcheck="false">
        <button class="button primary" id="btn-add-awg-peer" type="button" style="white-space:nowrap">＋ 新增客户端</button>
      </div>

      <table class="awg-table">
        <thead><tr><th>名称</th><th>隧道地址</th><th>创建时间</th><th>操作</th></tr></thead>
        <tbody id="awg-peer-tbody"><tr><td colspan="4" style="text-align:center;color:var(--muted);padding:20px">正在加载客户端...</td></tr></tbody>
      </table>

      <div class="awg-foot">
        <button class="button" id="btn-switch-awg-line" type="button" style="padding:6px 14px;font-size:12px">切换协议线</button>
        <button class="button" id="btn-update-awg" type="button" style="padding:6px 14px;font-size:12px">更新二进制</button>
      </div>

      <p class="awg-hint">
        「下载配置」按钮会生成标准 .conf 文件，可直接导入 AmneziaWG 官方客户端或 WG Tunnel；「二维码」用于手机端扫码导入。
        提醒：服务端与客户端的 S1-S4 / H1-H4 混淆参数必须逐字节一致，请勿手工修改 .conf 中的这些字段。
      </p>
    </div>
  </section>
</div>

<!-- Tab 4: VLESS-Reality 独立备用专区 -->
<div class="tab-pane" id="pane-reality">
  <section class="card" style="margin-bottom:22px">
    <div class="user-header">
      <div>
        <h2>🛡️ VLESS-Reality 应急抗封锁备用节点</h2>
        <p style="font-size:13px">采用 TCP + TLS 1.3 偷取大厂证书真实握手伪装（借尸还魂），彻底免疫 UDP 丢包限制与 QoS 扼杀</p>
      </div>
      <div style="display:flex;gap:10px;align-items:center">
        <span class="status-pill" id="reality-badge" style="background:#f1efe8;color:#5f5e5a">检测中...</span>
        <button class="button primary" id="btn-install-xray" type="button" style="padding:6px 14px;font-size:12px;display:none">⚡ 一键安装 Xray 核心</button>
        <button class="toggle-btn off" id="btn-toggle-reality" type="button" style="display:none">切换中...</button>
      </div>
    </div>

    <div class="warp-switch-card" style="background:#f7f9fc;border-color:#d7e2ee">
      <div class="warp-desc-title" style="color:#1a365d">💡 双引擎容灾保障哲学</div>
      <p class="warp-desc-text" style="color:#4a5568">
        Hysteria 2 是 UDP 极速王者，而 VLESS-Reality 是 TCP 终极伪装。当前节点直接借用 Apple 官方服务器 (www.apple.com:443) 真实 TLS 握手，无需自己购买域名与申请证书，在任何限制 UDP 的校园网/公司内网或晚高峰 UDP 劣化的网络环境下作为不掉线的坚固备用通道。
      </p>
    </div>

    <div id="reality-content-box" style="display:none">
      <div class="layout" style="margin-top:10px">
        <section class="card qr-card" style="background:#fbfcfd;border-color:var(--line)">
          <div class="eyebrow" style="color:#2563eb">REALITY CONNECT</div>
          <h2>Reality 节点扫码</h2>
          <p class="hint">适用于 v2rayN / Shadowrocket / sing-box</p>
          <div class="qr-frame" style="max-width:220px;margin:16px auto;padding:10px"><div id="reality-qr-box" style="width:100%;height:auto"></div></div>
          <p class="hint">客户端直接扫码即可一键导入</p>
          <div class="tags"><span class="tag">VLESS</span><span class="tag">Reality</span><span class="tag">Vision</span><span class="tag">TCP 443</span></div>
        </section>

        <div class="stack">
          <section class="card" style="border-color:#d7e2ee">
            <div class="card-head"><span class="step" style="background:#eff6ff;color:#2563eb">01</span><div><h2>VLESS 直链 (URI)</h2><p>支持一键导入主流现代客户端</p></div></div>
            <textarea class="link" id="reality-uri-val" readonly style="height:86px;font-size:11.5px"></textarea>
            <div class="actions" style="margin-top:12px;display:flex;justify-content:space-between;align-items:center">
              <button class="button primary" id="btn-copy-reality-uri" type="button">复制 Reality 直链</button>
              <button class="button" id="btn-reset-reality-keys" type="button" style="font-size:11px;color:var(--muted)" title="重置将重新生成 UUID 与密钥对">🔄 重新生成密钥对</button>
            </div>
          </section>

          <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px">
            <div style="background:#fbfcfd;border:1px solid var(--line);border-radius:12px;padding:12px">
              <div style="font-size:11px;color:var(--muted);font-weight:700;margin-bottom:2px">目标伪装域名 (SNI)</div>
              <div style="font-size:13px;font-weight:750;color:var(--ink);font-family:monospace" id="reality-sni-val">www.apple.com:443</div>
            </div>
            <div style="background:#fbfcfd;border:1px solid var(--line);border-radius:12px;padding:12px">
              <div style="font-size:11px;color:var(--muted);font-weight:700;margin-bottom:2px">用户 UUID</div>
              <div style="font-size:12px;font-weight:750;color:var(--ink);font-family:monospace;word-break:break-all" id="reality-uuid-val">-</div>
            </div>
            <div style="background:#fbfcfd;border:1px solid var(--line);border-radius:12px;padding:12px">
              <div style="font-size:11px;color:var(--muted);font-weight:700;margin-bottom:2px">公钥 (Public Key)</div>
              <div style="font-size:12px;font-weight:750;color:var(--ink);font-family:monospace;word-break:break-all" id="reality-pubkey-val">-</div>
            </div>
            <div style="background:#fbfcfd;border:1px solid var(--line);border-radius:12px;padding:12px">
              <div style="font-size:11px;color:var(--muted);font-weight:700;margin-bottom:2px">Short ID / Flow</div>
              <div style="font-size:13px;font-weight:750;color:var(--ink);font-family:monospace" id="reality-flow-val">-</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </section>

  <!-- 区块: TCP 拥塞控制加速引擎 (BBR V1 / V2 / V3) -->
  <section class="card bbr-section">
    <div class="user-header">
      <div>
        <h2>🚀 TCP 拥塞控制与网络加速引擎 (BBR)</h2>
        <p style="font-size:13px">针对 VLESS-Reality 等 TCP 节点提供内核级单边加速，显著降低长距离握手延迟与弱网丢包率</p>
      </div>
      <div style="display:flex;gap:10px;align-items:center">
        <span class="status-pill" id="bbr-badge" style="background:#eaf5ef;color:var(--accent)">检测中...</span>
        <button class="button danger" id="btn-reboot-server" type="button" style="display:none;padding:5px 12px;font-size:11.5px">🔄 立即重启服务器生效</button>
      </div>
    </div>

    <!-- 内核状态横幅 -->
    <div class="bbr-info-bar">
      <div>
        <div style="font-size:13px;font-weight:750;color:var(--ink);margin-bottom:2px">
          当前内核拥塞控制: <span class="bbr-stat-val" id="bbr-current-text">读取中...</span>
        </div>
        <div class="bbr-sub-text">排队规则: <span id="bbr-qdisc-text" style="font-family:monospace">--</span> · 系统内核: <span id="bbr-kernel-text" style="font-family:monospace">--</span></div>
      </div>
      <div id="bbr-reboot-tip" style="display:none;background:#fff8e6;border:1px solid #ffd591;color:#d46b08;padding:6px 14px;border-radius:8px;font-size:12px;font-weight:700">
        ⚠️ 新配置已写入，需要重启服务器后生效
      </div>
    </div>

    <!-- 横向三列高质感卡片布局 (彻底消灭挤压堆叠) -->
    <div class="bbr-grid">
      <div class="bbr-card">
        <div>
          <div class="bbr-card-head">
            <span class="bbr-card-title">BBR V1 经典稳定版</span>
            <span class="status-pill" style="font-size:11px;background:#f0f5f4">免换内核</span>
          </div>
          <p class="bbr-card-desc">Google 官方首代拥塞控制算法，成熟极其稳定，原生内核直接支持，即开即用。</p>
        </div>
        <button class="bbr-btn v1 btn-apply-bbr" data-version="v1" type="button">⚡ 一键开启 BBR V1</button>
      </div>

      <div class="bbr-card">
        <div>
          <div class="bbr-card-head">
            <span class="bbr-card-title">BBR V2 平衡抗丢包版</span>
            <span class="status-pill" style="font-size:11px;background:#e6f4ff;color:#0958d9">更低延迟</span>
          </div>
          <p class="bbr-card-desc">针对多流竞争与队列膨胀优化，加入 ECN 显式拥塞通知，公平性好、延迟更低。</p>
        </div>
        <button class="bbr-btn v2 btn-apply-bbr" data-version="v2" type="button">⚡ 一键开启 BBR V2</button>
      </div>

      <div class="bbr-card">
        <div>
          <div class="bbr-card-head">
            <span class="bbr-card-title">BBR V3 旗舰性能版</span>
            <span class="status-pill" style="font-size:11px;background:#fff0f6;color:#c41d7f">极限吞吐</span>
          </div>
          <p class="bbr-card-desc">Google 最新迭代版，彻底优化丢包退避机制，跨国高延迟长链路吞吐提升显著。</p>
        </div>
        <button class="bbr-btn v3 btn-apply-bbr" data-version="v3" type="button">⚡ 一键开启 BBR V3</button>
      </div>
    </div>
  </section>
</div>

<!-- Tab 3: 集群与通用 REST API 对接视图 -->
<div class="tab-pane" id="pane-cluster">
  <section class="card" style="border-left:4px solid var(--accent)">
    <div class="card-head"><span class="step">API</span><div><h2>通用 REST API 接口与集群对接凭据</h2><p>支持接入任何自动化发卡商城、用户控制中心或第三方管理系统</p></div></div>
    
    <div class="api-box">
      <div>
        <div style="font-size:11px;color:var(--muted);font-weight:700">API 基础地址 (Base URL)</div>
        <div class="api-key-code" id="api-base-val">https://{host}:{sub_port}</div>
      </div>
      <button class="button" type="button" data-copy="api-base-val" data-orig="复制地址">复制地址</button>
    </div>
    
    <div class="api-box">
      <div>
        <div style="font-size:11px;color:var(--muted);font-weight:700">通信鉴权密钥 (Bearer API Key)</div>
        <div class="api-key-code" id="api-key-val">{html.escape(api_key or "")}</div>
      </div>
      <button class="button primary" type="button" data-copy="api-key-val" data-orig="复制 Key">复制 Key</button>
    </div>

    {pin_block}

    <!-- 标准 REST API 接口调用规范与示例 -->
    <div style="margin-top:24px">
      <h3 style="font-size:15px;margin:0 0 12px;color:var(--ink)">📋 标准 REST API 接口规范与代码示例</h3>

      <div style="display:grid;gap:14px">
        <details class="card" style="padding:16px;box-shadow:none;border-color:#d7e5e2">
          <summary style="font-size:13px;color:#1e4c56"><strong>1. 创建/开通用户 (支持流量与IP配额)</strong> <code>POST /api/v1/users/create</code></summary>
          <div style="margin-top:12px;font-size:12px;color:var(--muted)">
            <p style="margin-bottom:6px"><strong>请求 Header：</strong> <code>Authorization: Bearer &lt;API_KEY&gt;</code> &nbsp;|&nbsp; <code>Content-Type: application/json</code></p>
            <p style="margin-bottom:6px"><strong>请求 Body 参数：</strong></p>
            <pre style="background:#f4f8f7;padding:10px;border-radius:8px;overflow-x:auto;color:#284850">{{"user_id": "buyer_01", "password": "custom_password", "duration_days": 30, "traffic_gb": 100, "ip_limit": 1, "note": "客户订单"}}</pre>
            <p style="margin:8px 0 6px"><strong>响应内容：</strong> 包含 <code>ok: true</code>, 专属 <code>uri</code> 节点直链与 <code>clash</code> 配置片段。</p>
          </div>
        </details>

        <details class="card" style="padding:16px;box-shadow:none;border-color:#d7e5e2">
          <summary style="font-size:13px;color:#1e4c56"><strong>2. 延长有效期 (续费)</strong> <code>POST /api/v1/users/renew</code></summary>
          <div style="margin-top:12px;font-size:12px;color:var(--muted)">
            <pre style="background:#f4f8f7;padding:10px;border-radius:8px;overflow-x:auto;color:#284850">{{"user_id": "buyer_01", "extend_days": 30, "add_traffic_gb": 100}}</pre>
          </div>
        </details>

        <details class="card" style="padding:16px;box-shadow:none;border-color:#d7e5e2">
          <summary style="font-size:13px;color:#1e4c56"><strong>3. 注销/删除用户</strong> <code>POST /api/v1/users/delete</code></summary>
          <div style="margin-top:12px;font-size:12px;color:var(--muted)">
            <pre style="background:#f4f8f7;padding:10px;border-radius:8px;overflow-x:auto;color:#284850">{{"user_id": "buyer_01"}}</pre>
          </div>
        </details>

        <details class="card" style="padding:16px;box-shadow:none;border-color:#d7e5e2">
          <summary style="font-size:13px;color:#1e4c56"><strong>4. 节点健康状态与用户数</strong> <code>GET /api/v1/node/meta</code></summary>
          <div style="margin-top:12px;font-size:12px;color:var(--muted)">
            <p>返回当前节点的端口、公网 IP/域名、混淆模式以及当前有效用户数与总流量统计。</p>
          </div>
        </details>
      </div>

      <div style="margin-top:16px;padding:14px;background:#f3f7f6;border-radius:10px;font-size:12px;color:#456972">
        💡 <strong>通用性说明：</strong>任何自动化系统（如发卡商城、WHMCS、Telegram 机器人、自建 Python/Node.js/Go 后端）只需发送标准 HTTP POST 请求携带 Bearer Token，即可实现全自动集群开户、流量限制与到期停用。
      </div>
    </div>
  </section>
</div>

<!-- Tab 4: 高级配置与版本更新视图 -->
<div class="tab-pane" id="pane-configs">
  <!-- 版本检测与一键更新卡片 -->
  <section class="card" style="margin-bottom:20px;border-left:4px solid var(--accent)">
    <div class="card-head"><span class="step">UP</span><div><h2>系统版本与一键升级</h2><p>支持在线比对并升级 Hysteria 2 官方内核与控制面板自身</p></div></div>
    
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px">
      <!-- 核心版本 -->
      <div class="api-box" style="margin-bottom:0">
        <div>
          <div style="font-size:11px;color:var(--muted);font-weight:700">Hysteria 2 官方核心版本</div>
          <div style="font-size:14px;font-weight:700;margin-top:4px" id="core-ver-display">检测中...</div>
        </div>
        <button class="button primary" id="btn-update-core" type="button" style="display:none">一键升级核心</button>
      </div>
      <!-- 面板版本 -->
      <div class="api-box" style="margin-bottom:0">
        <div>
          <div style="font-size:11px;color:var(--muted);font-weight:700">控制面板与安装脚本</div>
          <div style="font-size:14px;font-weight:700;margin-top:4px" id="portal-ver-display">检测中...</div>
        </div>
        <button class="button primary" id="btn-update-portal" type="button" style="display:none">一键更新面板</button>
      </div>
    </div>
    <div id="update-status-msg" style="font-size:12px;color:var(--muted)"></div>
  </section>

  <section class="advanced" style="margin-top:0">
    <div class="advanced-title"><h2>完整配置文件片段</h2><p>支持手动复制或下载独立配置文件。</p></div>
    <div class="config-grid">
      <div class="card">
        <div class="card-head"><span class="step">C</span><div><h2>Clash / Mihomo</h2><p>完整配置文件</p></div></div>
        {field_clash_cfg}
        <div class="actions">{copy_clash_cfg}<a class="button" href="clash.yaml" download="clash.yaml">下载 ↓</a></div>
      </div>
      <div class="card">
        <div class="card-head"><span class="step">S</span><div><h2>Sing-box</h2><p>出站 Outbounds JSON</p></div></div>
        {field_sing_cfg}
        <div class="actions">{copy_sing_cfg}<a class="button" href="sing-box.json" download="sing-box.json">下载 ↓</a></div>
      </div>
    </div>
  </section>
</div>

<div class="security">私密提示 · 链接和二维码包含连接凭据，请勿公开分享或发送截图给他人。</div>
<p id="copy-status" class="status" role="status" aria-live="polite"></p>

<!-- 入站代理创建成功高颜值模态框 (现代轻奢 + 二维码) -->
<div class="modal-backdrop" id="proxy-modal">
  <div class="pm-card">
    <div class="modal-head">
      <div>
        <h2 style="margin:0;font-size:19px;color:var(--accent);display:flex;align-items:center;gap:6px">
          <span>🎉 入站代理服务创建成功</span>
        </h2>
        <p style="font-size:12px;margin-top:2px;color:var(--muted)">GOST 核心已秒级热载入并监听，可直接配置或扫码导入使用</p>
      </div>
      <button class="modal-close" type="button" id="pm-close">&times;</button>
    </div>

    <!-- 顶部主连接节点 Banner -->
    <div class="pm-banner">
      <div class="pm-host-box">
        <span class="proxy-type" id="res-ptype-badge">SOCKS5</span>
        <div class="pm-host-val"><span id="res-phost">usntt.teyir.com</span> :<span class="pm-port-val" id="res-pport">28412</span></div>
      </div>
      <span class="pm-status-tag">● 实时监听中</span>
    </div>

    <!-- 中间对称凭据卡片 (告别孤立留白) -->
    <div class="pm-cred-grid">
      <div class="pm-cred-card">
        <div>
          <div class="pm-cred-lbl">👤 认证用户名 (Username)</div>
          <div class="pm-cred-val" id="res-puser">user_123</div>
        </div>
        <button class="button" type="button" style="padding:4px 8px;font-size:11px" data-copy-field="res-puser">复制</button>
      </div>
      <div class="pm-cred-card">
        <div>
          <div class="pm-cred-lbl">🔑 认证密码 (Password)</div>
          <div class="pm-cred-val" id="res-ppass">pwd_456</div>
        </div>
        <button class="button" type="button" style="padding:4px 8px;font-size:11px" data-copy-field="res-ppass">复制</button>
      </div>
    </div>

    <!-- 二维码与链接复合展示区 (左侧扫码 · 右侧直链) -->
    <div class="pm-main-grid">
      <div style="display:flex;flex-direction:column;align-items:center;gap:6px">
        <div class="pm-qr-frame" id="res-pqr">
          <span style="font-size:11px;color:var(--muted)">生成中...</span>
        </div>
        <span style="font-size:11px;color:var(--muted);font-weight:600">📱 客户端扫码导入</span>
      </div>

      <div class="pm-links-stack">
        <div>
          <div style="font-size:11px;font-weight:700;color:var(--muted);margin-bottom:4px">标准直连 URL (URI)</div>
          <div class="pm-code-box">
            <input class="pm-code-input" id="res-purl" readonly value="">
            <button class="button primary" id="btn-copy-purl" type="button" style="padding:4px 12px;font-size:11px;white-space:nowrap">复制 URL</button>
          </div>
        </div>
        <div>
          <div style="font-size:11px;font-weight:700;color:var(--muted);margin-bottom:4px">通用爬虫/软件格式 (Host:Port:User:Pass)</div>
          <div class="pm-code-box">
            <input class="pm-code-input" id="res-pfmt" readonly value="">
            <button class="button" id="btn-copy-pfmt" type="button" style="padding:4px 12px;font-size:11px;white-space:nowrap">复制格式</button>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>


<!-- 全局高颜值自定义确认弹窗 -->
<div class="modal-backdrop" id="custom-confirm-modal">
  <div class="confirm-card">
    <div class="confirm-icon-box" id="confirm-icon">🚀</div>
    <div class="confirm-title" id="confirm-title">请确认操作</div>
    <div class="confirm-text" id="confirm-text">确定要执行此操作吗？</div>
    <div class="confirm-actions">
      <button class="confirm-btn cancel" id="confirm-btn-cancel" type="button">取消</button>
      <button class="confirm-btn primary" id="confirm-btn-ok" type="button">确定执行</button>
    </div>
  </div>
</div>
<div class="toast-container" id="toast-container"></div>

<!-- 专属用户连接模态框 -->
<div class="modal-backdrop" id="user-modal">
  <div class="modal-card">
    <div class="modal-head">
      <div>
        <h2 id="um-title" style="margin:0;font-size:18px">专属用户连接</h2>
        <p id="um-sub" style="font-size:12px;margin-top:2px;color:var(--muted)"></p>
      </div>
      <button class="modal-close" type="button" id="um-close">&times;</button>
    </div>
    <div id="um-body"></div>
  </div>
</div>

<footer><span>HYSTERIA 2 / CLUSTER AGENT PORTAL</span><span>配置由你的服务器动态生成</span></footer>
</main><script>{SCRIPT}</script></body></html>"""


def login_html(token, error_msg=None):
    error_banner = f'<div class="error-tip" role="alert"><span>⚠</span><span>{html.escape(error_msg)}</span></div>' if error_msg else ''
    return f'''<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>验证访问 · Hysteria 2 节点中心</title><style>{STYLE}</style></head><body>
<div class="login-wrap"><div class="login-card">
<div class="login-brand"><div class="login-logo">H₂</div><div class="login-badge">HYSTERIA 2 GATEWAY</div><h1 class="login-title">私密身份认证</h1><p class="login-sub">请输入服务器生成的专属凭据以进入节点中心</p></div>
<form class="login-form" method="POST" action="/{token}/login">
{error_banner}
<div class="field-group"><label class="field-label" for="username">用户名 (Username)</label><input class="field-input" id="username" name="username" type="text" autocomplete="username" required autofocus placeholder="输入随机生成的用户名"></div>
<div class="field-group"><div class="field-label"><label for="password">密码 (Password)</label></div><div class="field-pwd"><input class="field-input" id="password" name="password" type="password" autocomplete="current-password" required placeholder="输入访问密钥"><button type="button" class="toggle-pwd" onclick="toggleSecret('password', this)">显示</button></div></div>
<div class="remember-row"><input type="checkbox" id="remember" name="remember" value="1" checked><label for="remember">在此浏览器保持登录（30天）</label></div>
<button class="btn-submit" type="submit">立即进入私密中心 →</button>
</form>
<div class="login-footer">如果遗忘凭据，随时在服务器终端执行<br><code>bash install.sh info</code> 找回账号密码</div>
</div></div>
<script>{LOGIN_SCRIPT}</script></body></html>'''


def user_page_html(server_name, host, listen_port, obfs_badge, uid, uinfo, uri, clash, sing, qr_svg, token, user_key):
    used_bytes = int(uinfo.get("used_bytes", 0))
    limit_bytes = int(uinfo.get("limit_bytes", 0))
    now_ts = int(time.time())
    is_traffic_ok = limit_bytes == 0 or used_bytes < limit_bytes
    is_time_ok = uinfo.get("expires_at", 0) >= now_ts
    is_active = uinfo.get("status") == "active" and is_time_ok and is_traffic_ok

    if not is_traffic_ok:
        status_html = '<span class="status-pill expired">流量已超额</span>'
    elif not is_time_ok:
        status_html = '<span class="status-pill expired">服务已到期</span>'
    elif uinfo.get("status") != "active":
        status_html = '<span class="status-pill expired">账号已停用</span>'
    else:
        status_html = '<span class="status-pill active">运行正常</span>'

    expires_str = time.strftime("%Y-%m-%d %H:%M", time.localtime(uinfo.get("expires_at", 0))) if uinfo.get("expires_at", 0) < 2000000000 else "永久有效"
    ip_limit = uinfo.get("ip_limit", 0)
    ip_limit_str = f"{ip_limit} 台设备" if ip_limit > 0 else "不限制"

    if limit_bytes > 0:
        percent = min(round((used_bytes / limit_bytes) * 100), 100)
        bar_class = "danger" if percent >= 90 else ""
        traffic_display = f"""<div>{format_bytes(used_bytes)} / {format_bytes(limit_bytes)} <span style="font-size:12px;color:var(--muted)">({percent}%)</span></div>
        <div class="traffic-bar" style="width:100%;height:8px"><div class="traffic-fill {bar_class}" style="width:{percent}%"></div></div>"""
    else:
        traffic_display = f"""<div>{format_bytes(used_bytes)} <span style="font-size:12px;color:var(--muted)">(不限制总流量)</span></div>"""

    note = uinfo.get("note") or "-"
    sub_port = uinfo.get("subscription_port") or 8443
    clash_sub_url = f"https://{host}:{sub_port}/{token}/u/{quote(uid)}/clash.yaml?k={user_key}"

    return f"""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>个人专属连接 · {html.escape(uid)}</title><style>{STYLE}</style></head><body><main style="max-width:860px">
<nav class="topbar"><div class="brand"><span class="logo">H₂</span> HYSTERIA <span> / 个人连接中心</span></div><div>{status_html}</div></nav>
<header class="hero"><div class="eyebrow">HYSTERIA 2 CLIENT ACCESS</div><h1>{html.escape(uid)}</h1><p>专属节点连接凭据与客户端配置 · 备注: {html.escape(note)}</p></header>

<!-- 配额用量卡片 -->
<section class="card" style="margin-bottom:22px">
  <div class="user-header" style="margin-bottom:12px">
    <h2>账号服务状态</h2>
    <div>{status_html}</div>
  </div>
  <div class="user-meta-bar" style="font-size:13px;padding:14px;background:#f8fbfb">
    <div style="flex:1;min-width:180px">📅 有效期至: <b>{expires_str}</b></div>
    <div style="flex:1;min-width:180px">📱 同时在线限制: <b>{ip_limit_str}</b></div>
    <div style="flex:2;min-width:220px">📊 流量消耗: {traffic_display}</div>
  </div>
</section>

<div class="layout" style="grid-template-columns:300px minmax(0,1fr)">
  <!-- 扫码卡片 -->
  <section class="card qr-card" style="margin-top:0">
    <div class="eyebrow">QUICK CONNECT</div>
    <h2>扫码快速导入</h2>
    <p class="hint">支持 v2rayNG / Shadowrocket / Nekobox</p>
    <div class="qr-frame" style="margin:16px 0">{qr_svg}</div>
    <p class="hint">在客户端点击右上角扫描即可直接接入</p>
    <div class="tags"><span class="tag">Hysteria 2</span><span class="tag">专属认证</span><span class="tag">{obfs_badge}</span></div>
  </section>

  <!-- 直链与客户端配置 -->
  <div class="stack">
    <section class="card">
      <div class="card-head"><span class="step">01</span><div><h2>节点直链 (URI)</h2><p>全平台通用直链 (点击一键导入/剪贴板导入)</p></div></div>
      <textarea id="u-hy2-uri" class="link" readonly>{html.escape(uri)}</textarea>
      <div class="actions">
        <button class="button primary" type="button" data-copy="u-hy2-uri">复制直链</button>
      </div>
      <p class="note">{html.escape(host)} · UDP {int(listen_port)}</p>
    </section>

    <section class="card">
      <div class="card-head"><span class="step">02</span><div><h2>Clash / Mihomo 专属订阅</h2><p>适用于 Clash Verge / Clash.Meta 核心客户端 (一键订阅同步)</p></div></div>
      <textarea id="u-clash-sub" class="link" style="height:68px" readonly>{html.escape(clash_sub_url)}</textarea>
      <div class="actions">
        <button class="button primary" type="button" data-copy="u-clash-sub">复制订阅链接</button>
        <a class="button" href="/{token}/u/{quote(uid)}/clash.yaml?k={user_key}" download="clash-{uid}.yaml">下载 clash.yaml ↓</a>
      </div>
      <details style="margin-top:10px">
        <summary style="font-size:11px;color:var(--muted)">查看/复制原始配置源码 (备用)</summary>
        <textarea id="u-clash-cfg" class="config" style="height:110px;margin-top:6px" readonly>{html.escape(clash)}</textarea>
        <div style="margin-top:4px"><button class="button" type="button" data-copy="u-clash-cfg" style="padding:4px 10px;font-size:11px">复制配置文本</button></div>
      </details>
    </section>

    <section class="card">
      <div class="card-head"><span class="step">03</span><div><h2>Sing-box 出站配置</h2><p>适用 SFI / SFA / Sing-box 客户端</p></div></div>
      <textarea id="u-sing-cfg" class="config" style="height:140px" readonly>{html.escape(sing)}</textarea>
      <div class="actions">
        <button class="button primary" type="button" data-copy="u-sing-cfg">复制配置</button>
        <a class="button" href="/{token}/u/{quote(uid)}/sing-box.json?k={user_key}" download="sing-box-{uid}.json">下载 sing-box.json ↓</a>
      </div>
    </section>
  </div>
</div>

<div class="security">私密提示 · 该页面为你的个人节点专属连接页面，包含连接密钥，请妥善保管。</div>
<footer><span>HYSTERIA 2 / PERSONAL PORTAL</span><span>由你的专属服务器动态生成</span></footer>
</main><script>{USER_SCRIPT}</script></body></html>"""


def content_policy(extra_script=None):
    def digest(value):
        return base64.b64encode(hashlib.sha256(value.encode()).digest()).decode()
    scripts = ["'sha256-" + digest(SCRIPT) + "'", "'sha256-" + digest(LOGIN_SCRIPT) + "'", "'sha256-" + digest(USER_SCRIPT) + "'"]
    if extra_script:
        scripts.append("'sha256-" + digest(extra_script) + "'")
    return ("default-src 'none'; connect-src 'self'; img-src 'self' data:; style-src 'sha256-" + digest(STYLE)
            + "'; script-src " + " ".join(scripts)
            + "; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")


def get_cert_pin_sha256(root_path):
    """SHA-256 of the certificate DER, as plain lowercase HEX.

    v2rayNG/v2rayN (Xray core) copy the hysteria2 URI's `pinSHA256` straight into
    Xray's `pinnedPeerCertSha256`, which is a HEX field - a base64 value there makes
    Xray abort with `encoding/hex: invalid byte`.
    """
    cert_file = Path(root_path) / 'cert' / 'server.crt'
    if not cert_file.exists():
        return ''
    try:
        p1 = subprocess.Popen(['openssl', 'x509', '-in', str(cert_file), '-outform', 'DER'],
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        p2 = subprocess.Popen(['openssl', 'dgst', '-sha256'], stdin=p1.stdout,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        p1.stdout.close()
        out = p2.communicate()[0].decode().strip()
        hexval = out.rsplit('=', 1)[-1].strip().lower()
        return hexval if len(hexval) == 64 and all(c in '0123456789abcdef' for c in hexval) else ''
    except Exception:
        return ''


def artifacts(m, auth_override=None, name_override=None):
    is_insecure = m.get('is_insecure', False)
    server_name = m.get('server_name') or m.get('public_ip', 'localhost')
    public_ip = m.get('public_ip', server_name)
    host = public_ip if is_insecure else server_name
    name = name_override or ('Hy2-' + host)
    password = auth_override or m.get('auth_password', '')
    listen_port = m.get('listen_port', 19984)
    obfs_password = m.get('obfs_password', '')
    hop_port_range = m.get('hop_port_range', '')
    # 证书信任策略（已逐条对照 v2rayNG 源码 / Xray 内核行为对齐）：
    #   * 公网可信证书：直链不带任何 pin / insecure，全客户端开箱即用；
    #   * 自签证书：同时带 pinSHA256(<HEX64>) 与 insecure=1 ——
    #       v2rayNG/v2rayN 把 pinSHA256 直接塞进 Xray 的 pinnedPeerCertSha256，该字段必须是【纯 HEX】，
    #       写 base64 会触发 `encoding/hex: invalid byte` 导致配置构建失败（这正是上一版扫码连不上的根因）；
    #       v2rayNG 源码仅在 pin 为空时才输出 allowInsecure，故两者并存既不报错，又能让只认 insecure 的
    #       sing-box / NekoBox / Clash / 官方 hysteria 正常跳过校验。
    raw_pin = (m.get('pin_sha256') or '').strip().lower()
    pin_sha256 = raw_pin if len(raw_pin) == 64 and all(c in '0123456789abcdef' for c in raw_pin) else ''
    params = {'sni': server_name}
    if is_insecure:
        params['insecure'] = '1'
        if pin_sha256:
            params['pinSHA256'] = pin_sha256
    if obfs_password:
        params.update({'obfs': 'salamander', 'obfs-password': obfs_password})
    if hop_port_range:
        params['mport'] = hop_port_range
    uri = f"hysteria2://{quote(password, safe='')}@{host}:{listen_port}?{urlencode(params)}#{quote(name)}"
    
    proxy = dict(name=name, type='hysteria2', server=host, port=listen_port,
                 password=password, sni=server_name, **{'skip-cert-verify': is_insecure})
    sing = dict(type='hysteria2', tag=name, server=host, server_port=listen_port,
                password=password, tls=dict(enabled=True, server_name=server_name, insecure=is_insecure))
    if hop_port_range:
        proxy['ports'] = str(listen_port) + ',' + hop_port_range
        sing['server_ports'] = [str(listen_port), hop_port_range.replace('-', ':')]
        del sing['server_port']
    if obfs_password:
        proxy.update({'obfs': 'salamander', 'obfs-password': obfs_password})
        sing['obfs'] = dict(type='salamander', password=obfs_password)
    clash = {'mixed-port': 7890, 'allow-lan': False, 'mode': 'rule', 'proxies': [proxy],
             'proxy-groups': [{'name': 'PROXY', 'type': 'select', 'proxies': [name, 'DIRECT']}],
             'rules': ['MATCH,PROXY']}
    return uri, json.dumps(clash, ensure_ascii=False, indent=2), json.dumps({'outbounds': [sing]}, ensure_ascii=False, indent=2)


def sync_pin(m, root, meta_path):
    """Align client_meta.json's pin_sha256 with the node's trust model.

    Trusted cert  -> pin wiped entirely (a stale/base64 value must never linger:
                     Xray reads pinSHA256 as HEX and a base64 char aborts the build).
    Self-signed   -> a valid lowercase HEX64 pin, recomputed from cert/server.crt
                     whenever it is missing or malformed.
    """
    if m.get('is_insecure'):
        cur = (m.get('pin_sha256') or '').strip().lower()
        if len(cur) != 64 or any(c not in '0123456789abcdef' for c in cur):
            new = get_cert_pin_sha256(root)
            if new != m.get('pin_sha256'):
                m['pin_sha256'] = new
                Path(meta_path).write_text(json.dumps(m, ensure_ascii=False))
    elif m.get('pin_sha256'):
        m['pin_sha256'] = ''
        Path(meta_path).write_text(json.dumps(m, ensure_ascii=False))


def prepare(meta_path, port, node_api_key=None):
    root = Path(meta_path).parent
    m = json.loads(Path(meta_path).read_text())
    sync_pin(m, root, meta_path)

    uri, clash, sing = artifacts(m)
    qr = subprocess.run(['qrencode', '-t', 'SVG', '-o', '-'], input=uri.encode(), capture_output=True, check=True).stdout
    user, password, token = secrets.token_hex(8), secrets.token_urlsafe(32), secrets.token_hex(32)
    host = m['public_ip'] if m['is_insecure'] else m['server_name']
    base = f"https://{host}:{m['subscription_port']}/{token}/"
    subscription = f"https://{user}:{password}@{host}:{m['subscription_port']}/{token}/clash.yaml"
    session_secret = secrets.token_hex(32)
    api_key = node_api_key or secrets.token_hex(24)

    users = {
        'admin_master': {
            'password': m['auth_password'],
            'expires_at': 2085974400,
            'ip_limit': 0,
            'limit_bytes': 0,
            'used_bytes': 0,
            'status': 'active',
            'created_at': int(time.time()),
            'note': 'Master Admin'
        }
    }
    page = page_html(m, uri, subscription, clash, sing, users=users, api_key=api_key, token=token, session_secret=session_secret)
    auth = base64.b64encode(f'{user}:{password}'.encode())

    data = dict(port=int(port), token=token, auth_hash=hashlib.sha256(auth).hexdigest(),
                session_secret=session_secret, api_key=api_key, users=users,
                proxy_services=[], page=page, qr=qr.decode(), clash=clash, sing=sing)
    for filename, value in [('portal.json', data), ('portal-access.json', dict(url=base, username=user, password=password, api_key=api_key))]:
        path = root / filename
        path.write_text(json.dumps(value, ensure_ascii=False))
        path.chmod(0o600)


def refresh(meta_path):
    root = Path(meta_path).parent
    m = json.loads(Path(meta_path).read_text())
    sync_pin(m, root, meta_path)

    access = json.loads((root / 'portal-access.json').read_text())
    path = root / 'portal.json'
    data = json.loads(path.read_text())
    uri, clash, sing = artifacts(m)
    host = m['public_ip'] if m['is_insecure'] else m['server_name']
    subscription = f"https://{access['username']}:{access['password']}@{host}:{m['subscription_port']}/{data['token']}/clash.yaml"
    
    if 'session_secret' not in data:
        data['session_secret'] = secrets.token_hex(32)
    if 'api_key' not in data:
        data['api_key'] = access.get('api_key') or secrets.token_hex(24)
        access['api_key'] = data['api_key']
        (root / 'portal-access.json').write_text(json.dumps(access, ensure_ascii=False))
    if 'users' not in data:
        data['users'] = {
            'admin_master': {
                'password': m['auth_password'],
                'expires_at': 2085974400,
                'ip_limit': 0,
                'limit_bytes': 0,
                'used_bytes': 0,
                'status': 'active',
                'created_at': int(time.time()),
                'note': 'Master Admin'
            }
        }
    if 'proxy_services' not in data:
        data['proxy_services'] = []
    data['page'] = page_html(m, uri, subscription, clash, sing, users=data['users'], api_key=data['api_key'], token=data['token'], session_secret=data.get('session_secret', ''))
    
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(data, ensure_ascii=False))
    temporary.chmod(0o600)
    temporary.replace(path)


def serve(path):
    portal_path = Path(path)
    data = json.loads(portal_path.read_text())
    session_secret = data.get('session_secret', data['auth_hash'])
    meta_path = portal_path.parent / 'client_meta.json'

    data_lock = threading.RLock()
    ip_tracker = {}
    IP_TIMEOUT_SECONDS = 180
    VALID_USER_ID_RE = re.compile(r'^[a-zA-Z0-9_\-\.]{1,64}$')
    # AmneziaWG 客户端名称：与 awgctl.sh 中的校验保持一致
    VALID_AWG_NAME_RE = re.compile(r'^[A-Za-z0-9_.\-]{1,32}$')

    # 实时速率计算滑动窗口数据结构: {uid: [(timestamp, total_bytes_tx, total_bytes_rx)]}
    speed_tracker = {}

    def save_data():
        with data_lock:
            try:
                temp = portal_path.with_suffix('.tmp')
                temp.write_text(json.dumps(data, ensure_ascii=False))
                temp.chmod(0o600)
                temp.replace(portal_path)
            except OSError:
                disk_path = Path('/etc/hysteria/portal.json')
                if disk_path.exists():
                    disk_temp = disk_path.with_suffix('.tmp')
                    disk_temp.write_text(json.dumps(data, ensure_ascii=False))
                    disk_temp.chmod(0o600)
                    disk_temp.replace(disk_path)

    def write_gost_config():
        """根据 proxy_services 动态生成 gost.yml 配置并触发热重载。"""
        gost_cfg_path = portal_path.parent / 'gost.yml'
        cert_dir = portal_path.parent / 'gost-cert'
        services = []
        with data_lock:
            for idx, svc in enumerate(data.get('proxy_services', [])):
                ptype = svc.get('type', 'socks5')
                port = int(svc.get('port', 0))
                if port <= 0 or port > 65535:
                    continue
                handler_type = 'socks5' if ptype == 'socks5' else 'http'
                entry = {
                    'name': f'proxy-{idx}',
                    'addr': f':{port}',
                    'handler': {
                        'type': handler_type,
                        'auth': {
                            'username': svc.get('username', ''),
                            'password': svc.get('password', ''),
                        },
                    },
                    'listener': {'type': 'tcp'},
                }
                if ptype == 'https':
                    entry['listener'] = {
                        'type': 'tls',
                        'tls': {
                            'certFile': str(cert_dir / 'cert.pem'),
                            'keyFile': str(cert_dir / 'key.pem'),
                        },
                    }
                services.append(entry)

        cfg = {'services': services}
        try:
            tmp = gost_cfg_path.with_suffix('.tmp')
            tmp.write_text(json.dumps(cfg, ensure_ascii=False, indent=2))
            tmp.chmod(0o644)
            tmp.replace(gost_cfg_path)
        except OSError:
            pass

    def reload_gost():
        """通过 systemctl reload 或 SIGHUP 平滑重载 gost 配置. 未安装 gost 时静默跳过.
        关键: reload 必须异步执行 (Popen + 短 timeout), 避免 gost 卡住导致 portal do_POST 永久挂起."""
        if not gost_status():
            return
        write_gost_config()
        # 异步触发 reload, 进程退出/超时都不阻塞 portal HTTP 响应
        def _do_reload():
            try:
                subprocess.run(['systemctl', 'reload', 'gost'],
                               capture_output=True, timeout=2)
            except Exception:
                try:
                    r = subprocess.run(['systemctl', 'show', '-p', 'MainPID', '--value', 'gost'],
                                       capture_output=True, text=True, timeout=2)
                    pid = r.stdout.strip()
                    if pid.isdigit():
                        subprocess.run(['kill', '-HUP', pid], capture_output=True, timeout=2)
                except Exception:
                    try:
                        subprocess.run(['systemctl', 'restart', 'gost'],
                                       capture_output=True, timeout=3)
                    except Exception:
                        pass
        threading.Thread(target=_do_reload, daemon=True).start()

    def gost_status():
        """检测 gost 服务运行状态。"""
        try:
            out = subprocess.run(['systemctl', 'is-active', 'gost'], capture_output=True, text=True, timeout=3).stdout.strip()
            return out == 'active'
        except Exception:
            return False

    # ------------------------------------------------------------------
    # AmneziaWG (AWG) 支持
    #
    # 设计取舍：门户不重新实现 AWG 的配置生成逻辑，而是调用 shell 侧的
    # /usr/local/bin/hy2-awgctl（由 install.sh 安装）。这样命令行菜单与 Web
    # 门户共用同一套实现，不会出现两份逻辑漂移 —— 考虑到 S1-S4/H1-H4 必须
    # 两端逐字节一致，重复实现的风险太高。
    # ------------------------------------------------------------------
    AWG_CTL = '/usr/local/bin/hy2-awgctl'
    AWG_REPO = 'yys9253462-gif/hysteria2-installer'
    AWG_DIR_PATH = Path('/etc/amnezia/amneziawg')
    AWG_META_PATH = AWG_DIR_PATH / 'awg_meta.json'
    AWG_PEERS_PATH = AWG_DIR_PATH / 'awg_peers.json'
    AWG_CONF_PATH = AWG_DIR_PATH / 'awg0.conf'
    AWG_GO_PATH = Path('/usr/local/bin/amneziawg-go')
    AWG_SVC_NAME = 'amneziawg-server'

    def awg_read_json(path, default):
        try:
            if path.exists():
                return json.loads(path.read_text())
        except Exception:
            pass
        return default

    def awg_installed():
        return AWG_CONF_PATH.exists() and AWG_GO_PATH.exists()

    def awg_active():
        try:
            out = subprocess.run(['systemctl', 'is-active', AWG_SVC_NAME],
                                 capture_output=True, text=True, timeout=3).stdout.strip()
            return out == 'active'
        except Exception:
            return False

    def ensure_awgctl():
        """确保 hy2-awgctl 可用；缺失时从主仓库拉取（与 install.sh 的策略一致）。"""
        if Path(AWG_CTL).exists():
            return True
        try:
            import os
            import shutil
            import tempfile
            import urllib.request
            url = 'https://raw.githubusercontent.com/' + AWG_REPO + '/main/awgctl.sh'
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=30) as resp:
                content = resp.read()
            # 太小说明拿到的是错误页而不是脚本
            if len(content) < 2048 or b'hy2-awgctl' not in content:
                return False
            fd, tmp_name = tempfile.mkstemp(prefix='hy2-awgctl-', suffix='.sh')
            os.close(fd)
            with open(tmp_name, 'wb') as fh:
                fh.write(content)
            os.chmod(tmp_name, 0o755)
            shutil.move(tmp_name, AWG_CTL)
            os.chmod(AWG_CTL, 0o755)
            return True
        except Exception:
            return False

    def awg_run(args, timeout=420):
        """调用 hy2-awgctl。返回 (returncode, stdout, stderr)。"""
        proc = subprocess.run([AWG_CTL] + args, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout, proc.stderr

    def awg_err_tail(rc, out, err, limit=700):
        text = (err or '').strip() or (out or '').strip()
        return text[-limit:] if text else '退出码 ' + str(rc)

    def awg_state():
        meta = awg_read_json(AWG_META_PATH, {})
        peers_raw = awg_read_json(AWG_PEERS_PATH, {}).get('peers', []) or []
        line = str(meta.get('line', '3') or '3')
        if line not in ('2', '3'):
            line = '3'
        return {
            'ok': True,
            'installed': awg_installed(),
            'active': awg_active(),
            'line': line,
            'port': str(meta.get('port', '') or ''),
            'endpoint': str(meta.get('endpoint', '') or ''),
            'peer_count': len(peers_raw),
            'ctl': Path(AWG_CTL).exists(),
            # 注意：只回传非敏感字段，私钥与预共享密钥绝不下发到前端
            'peers': [{'name': p.get('name', ''), 'address': p.get('address', ''),
                       'created_at': p.get('created_at', '')} for p in peers_raw],
        }

    def regenerate_page():
        m = json.loads(meta_path.read_text()) if meta_path.exists() else {}
        uri, clash, sing = artifacts(m)
        root = portal_path.parent
        access_file = root / 'portal-access.json'
        access = json.loads(access_file.read_text()) if access_file.exists() else {}
        host = m.get('public_ip', '127.0.0.1') if m.get('is_insecure') else m.get('server_name', 'localhost')
        subscription = f"https://{access.get('username','')}:{access.get('password','')}@{host}:{m.get('subscription_port',8443)}/{data['token']}/clash.yaml"
        
        now_ts = int(time.time())
        display_users = {}
        with data_lock:
            # 清理离线已久的 ip_tracker 键
            dead_uids = [u for u, tr in ip_tracker.items() if not any(now_ts - t < IP_TIMEOUT_SECONDS for t in tr.values())]
            for du in dead_uids:
                del ip_tracker[du]

            for uid, uinfo in data.get('users', {}).items():
                u_copy = dict(uinfo)
                user_ips = {ip: t for ip, t in ip_tracker.get(uid, {}).items() if now_ts - t < IP_TIMEOUT_SECONDS}
                u_copy['online_ips'] = user_ips
                display_users[uid] = u_copy

            data['page'] = page_html(m, uri, subscription, clash, sing, users=display_users, api_key=data.get('api_key'), token=data['token'], session_secret=session_secret)
        save_data()

    def sign_session(token):
        sig = hmac.new(session_secret.encode(), f'sess:{token}'.encode(), hashlib.sha256).hexdigest()
        return f'{token}.{sig}'

    def verify_session(cookie_header):
        if not cookie_header:
            return False
        cookies = SimpleCookie()
        try:
            cookies.load(cookie_header)
        except Exception:
            return False
        if 'hy2_session' not in cookies:
            return False
        raw = cookies['hy2_session'].value
        if '.' not in raw:
            return False
        t, sig = raw.split('.', 1)
        expected = hmac.new(session_secret.encode(), f'sess:{t}'.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(t, data['token']) and hmac.compare_digest(sig, expected)

    class Handler(BaseHTTPRequestHandler):
        def _generate_and_apply_reality(self, restart=True):
            import uuid as uuid_mod, secrets
            new_uuid = str(uuid_mod.uuid4())

            priv_key = ''
            pub_key = ''
            try:
                p = subprocess.run(['/usr/local/bin/xray', 'x25519'], capture_output=True, text=True, timeout=5)
                for line in p.stdout.splitlines():
                    if 'PrivateKey:' in line:
                        priv_key = line.split('PrivateKey:')[1].strip()
                    elif 'Password (PublicKey):' in line or 'PublicKey:' in line:
                        pub_key = line.split(':')[1].strip()
            except Exception:
                pass

            if not priv_key or not pub_key:
                priv_key = 'SKHsyFDGviRODhpQJQLAxAU-qRBBWjKjntbVXp8KW10'
                pub_key = '2uyjYiLgv9SAjn6eVC21EywA55xyiebI-wg03rgBH2g'

            short_id = secrets.token_hex(4)
            dest_sni = 'www.apple.com'
            listen_port = 443

            m = json.loads(meta_path.read_text()) if meta_path.exists() else {}
            public_ip = m.get('public_ip', '127.0.0.1')
            server_name = m.get('server_name') or public_ip

            vless_link = f"vless://{new_uuid}@{public_ip}:{listen_port}?security=reality&encryption=none&pbk={pub_key}&headerType=none&fp=chrome&type=tcp&flow=xtls-rprx-vision&sni={dest_sni}&sid={short_id}#%E8%8F%B2%E5%BE%8B%E5%AE%BE-VLESS-Reality"

            with data_lock:
                data['reality_config'] = {
                    'uuid': new_uuid,
                    'private_key': priv_key,
                    'public_key': pub_key,
                    'short_id': short_id,
                    'dest_sni': dest_sni,
                    'port': listen_port,
                    'uri': vless_link
                }
            save_data()

            xray_json = {
                "log": {"loglevel": "warning"},
                "inbounds": [
                    {
                        "port": listen_port,
                        "protocol": "vless",
                        "settings": {
                            "clients": [{"id": new_uuid, "flow": "xtls-rprx-vision"}],
                            "decryption": "none"
                        },
                        "streamSettings": {
                            "network": "tcp",
                            "security": "reality",
                            "realitySettings": {
                                "show": False,
                                "dest": f"{dest_sni}:443",
                                "xver": 0,
                                "serverNames": [dest_sni],
                                "privateKey": priv_key,
                                "shortIds": [short_id]
                            }
                        },
                        "sniffing": {
                            "enabled": True,
                            "destOverride": ["http", "tls", "quic"]
                        }
                    }
                ],
                "outbounds": [{"protocol": "freedom"}]
            }
            Path('/etc/hysteria/xray.json').write_text(json.dumps(xray_json, indent=2), encoding='utf-8')
            if restart:
                subprocess.run(['systemctl', 'restart', 'xray'], capture_output=True, timeout=5)

        server_version = 'Gateway'
        sys_version = ''
        def setup(self):
            super().setup()
            self.connection.settimeout(5)
        def log_message(self, *args):
            pass

        def verify_api_key(self):
            auth_header = self.headers.get('Authorization', '')
            expected = 'Bearer ' + data.get('api_key', '')
            return hmac.compare_digest(auth_header, expected)

        def is_authenticated(self):
            auth = self.headers.get('Authorization', '')
            if auth.startswith('Basic '):
                digest = hashlib.sha256(auth.removeprefix('Basic ').encode()).hexdigest()
                if hmac.compare_digest(digest, data['auth_hash']):
                    return True
            return verify_session(self.headers.get('Cookie', ''))

        def reply_json(self, code, payload):
            body = json.dumps(payload, ensure_ascii=False).encode('utf-8')
            self.send_response(code)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            # BUGFIX portal hang: 强制短连接避免 keepalive 导致 server 端等待 client 下一请求挂死
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(body)
            try:
                self.wfile.flush()
            except Exception:
                pass
            try:
                # 显式关闭 TCP, 防止 HTTP server keepalive 阻塞后续请求
                self.connection.shutdown(socket.SHUT_WR)
            except Exception:
                pass

        def check_rate_limit(self, bucket='web'):
            now = time.monotonic()
            with data_lock:
                if bucket == 'api':
                    self.server.api_requests[:] = [t for t in self.server.api_requests if now - t < 1]
                    if len(self.server.api_requests) >= 50:
                        return False
                    self.server.api_requests.append(now)
                    return True
                else:
                    self.server.requests[:] = [t for t in self.server.requests if now - t < 1]
                    self.server.failures[:] = [t for t in self.server.failures if now - t < 60]
                    if len(self.server.requests) >= 50 or len(self.server.failures) >= 60:
                        return False
                    self.server.requests.append(now)
                    return True

        def record_failure(self):
            now = time.monotonic()
            with data_lock:
                self.server.failures.append(now)

        def do_POST(self):
            # 1. Hysteria 2 本地 HTTP 动态鉴权、实时流量统计与 IP 限额拦截端点 (来自 127.0.0.1 豁免限流)
            if self.path == '/auth':
                try:
                    length = int(self.headers.get('Content-Length', 0))
                    body = self.rfile.read(length).decode('utf-8')
                    req_data = json.loads(body)
                    client_auth = req_data.get('auth', '').strip()
                    client_addr = req_data.get('addr', '')
                    # tx (客户端上行/服务器接收), rx (客户端下行/服务器发送) 流量增量统计
                    tx_bytes = int(req_data.get('tx', 0))
                    rx_bytes = int(req_data.get('rx', 0))
                    delta_traffic = tx_bytes + rx_bytes
                    client_ip = client_addr.rsplit(':', 1)[0].strip('[]') if client_addr else ''
                except Exception:
                    return self.reply_json(200, {'ok': False, 'msg': 'Bad auth request'})

                now_ts = int(time.time())
                with data_lock:
                    users = data.get('users', {})
                    matched_uid, matched_user = None, None
                    for uid, uinfo in users.items():
                        if uinfo.get('password') == client_auth:
                            matched_uid, matched_user = uid, uinfo
                            break

                    if not matched_user:
                        return self.reply_json(200, {'ok': False, 'msg': 'User not found'})

                    if matched_user.get('status') != 'active':
                        return self.reply_json(200, {'ok': False, 'msg': 'User account inactive'})

                    if matched_user.get('expires_at', 0) < now_ts:
                        return self.reply_json(200, {'ok': False, 'msg': 'User account expired'})

                    # -------- 流量限额检查与增量累加 -------- #
                    limit_bytes = int(matched_user.get('limit_bytes', 0))
                    used_bytes = int(matched_user.get('used_bytes', 0)) + delta_traffic
                    matched_user['used_bytes'] = used_bytes

                    # 记录实时速率滑动窗口样本 (保留最近 10 秒)
                    samples = speed_tracker.setdefault(matched_uid, [])
                    cur_mono = time.monotonic()
                    samples.append((cur_mono, tx_bytes, rx_bytes))
                    # 淘汰超过 10 秒的陈旧样本
                    speed_tracker[matched_uid] = [(t, tx, rx) for (t, tx, rx) in samples if cur_mono - t <= 10]

                    if limit_bytes > 0 and used_bytes >= limit_bytes:
                        # 流量超额，阻断拒绝连接
                        return self.reply_json(200, {'ok': False, 'msg': 'Traffic quota exceeded'})

                    # -------- 同时在线 IP 限制检查 -------- #
                    ip_limit = int(matched_user.get('ip_limit', 0))
                    if ip_limit > 0 and client_ip:
                        tracker = ip_tracker.setdefault(matched_uid, {})
                        active_ips = {ip: t for ip, t in tracker.items() if now_ts - t < IP_TIMEOUT_SECONDS}
                        ip_tracker[matched_uid] = active_ips

                        if client_ip not in active_ips and len(active_ips) >= ip_limit:
                            return self.reply_json(200, {'ok': False, 'msg': f'Concurrent IP limit exceeded ({ip_limit} max)'})
                        active_ips[client_ip] = now_ts
                    elif client_ip:
                        tracker = ip_tracker.setdefault(matched_uid, {})
                        tracker[client_ip] = now_ts

                return self.reply_json(200, {'ok': True, 'id': matched_uid})

            # 2. REST API 接口通道 (独立 API 速率桶)
            if self.path.startswith('/api/v1/'):
                if not self.check_rate_limit(bucket='api'):
                    return self.reply(429, b'Too many requests')

                if not self.verify_api_key():
                    return self.reply_json(401, {'ok': False, 'error': 'Unauthorized API key'})

                try:
                    length = int(self.headers.get('Content-Length', 0))
                    body = self.rfile.read(length).decode('utf-8') if length > 0 else '{}'
                    params = json.loads(body)
                except Exception:
                    return self.reply_json(400, {'ok': False, 'error': 'Invalid JSON body'})

                sub = self.path[len('/api/v1/'):]
                now_ts = int(time.time())

                # 动态开户 (支持 duration_days, ip_limit, traffic_gb)
                if sub == 'users/create':
                    user_id = (params.get('user_id') or ('hy2_' + secrets.token_hex(6))).strip()
                    if not VALID_USER_ID_RE.match(user_id):
                        return self.reply_json(400, {'ok': False, 'error': 'Invalid user_id format: only 1-64 alphanumeric, dash, dot and underscore characters allowed'})

                    pwd = params.get('password') or secrets.token_hex(16)
                    days = int(params.get('duration_days', 30))
                    ip_limit = int(params.get('ip_limit', 0))
                    traffic_gb = float(params.get('traffic_gb', 0))
                    limit_bytes = int(traffic_gb * (1024**3)) if traffic_gb > 0 else 0
                    expires = int(params.get('expires_at', now_ts + days * 86400))
                    note = str(params.get('note', '')).strip()[:200]

                    with data_lock:
                        data.setdefault('users', {})[user_id] = {
                            'password': pwd,
                            'expires_at': expires,
                            'ip_limit': ip_limit,
                            'limit_bytes': limit_bytes,
                            'used_bytes': 0,
                            'status': 'active',
                            'created_at': now_ts,
                            'note': note
                        }
                    regenerate_page()

                    m = json.loads(meta_path.read_text()) if meta_path.exists() else {}
                    uri, clash_yaml, sing_json = artifacts(m, auth_override=pwd, name_override=f"Teyir-Hy2-{user_id}")
                    with data_lock:
                        rcfg = dict(data.get('reality_config', {}))
                    reality_uri = rcfg.get('uri', '')
                    return self.reply_json(200, {
                        'ok': True,
                        'user_id': user_id,
                        'password': pwd,
                        'ip_limit': ip_limit,
                        'traffic_gb': traffic_gb,
                        'expires_at': expires,
                        'uri': uri,
                        'reality_uri': reality_uri,
                        'clash': clash_yaml,
                        'sing_box': sing_json
                    })

                elif sub == 'users/renew':
                    user_id = str(params.get('user_id', '')).strip()
                    if not VALID_USER_ID_RE.match(user_id):
                        return self.reply_json(400, {'ok': False, 'error': 'Invalid user_id format'})
                    days = int(params.get('extend_days', 30))
                    add_traffic_gb = float(params.get('add_traffic_gb', 0))
                    with data_lock:
                        u = data.get('users', {}).get(user_id)
                        if not u:
                            return self.reply_json(404, {'ok': False, 'error': 'User not found'})
                        base_time = max(u.get('expires_at', 0), now_ts)
                        u['expires_at'] = base_time + days * 86400
                        if add_traffic_gb > 0:
                            u['limit_bytes'] = int(u.get('limit_bytes', 0)) + int(add_traffic_gb * (1024**3))
                        u['status'] = 'active'
                        exp_at = u['expires_at']
                        lim_b = u.get('limit_bytes', 0)
                    regenerate_page()
                    return self.reply_json(200, {'ok': True, 'user_id': user_id, 'expires_at': exp_at, 'limit_bytes': lim_b})

                elif sub == 'users/delete':
                    user_id = str(params.get('user_id', '')).strip()
                    if not VALID_USER_ID_RE.match(user_id):
                        return self.reply_json(400, {'ok': False, 'error': 'Invalid user_id format'})
                    with data_lock:
                        if user_id in data.get('users', {}):
                            del data['users'][user_id]
                            if user_id in ip_tracker:
                                del ip_tracker[user_id]
                            deleted = True
                        else:
                            deleted = False
                    if deleted:
                        regenerate_page()
                        return self.reply_json(200, {'ok': True, 'message': 'User deleted'})
                    return self.reply_json(404, {'ok': False, 'error': 'User not found'})

                elif sub == 'users/list':
                    # BUGFIX #10: 商城节点对账用, 列出所有动态用户 (脱敏不返回 password)
                    now_ts = int(time.time())
                    users_out = []
                    with data_lock:
                        for uid, info in data.get('users', {}).items():
                            entry = {
                                'user_id': uid,
                                'expires_at': info.get('expires_at', 0),
                                'active': info.get('expires_at', 0) > now_ts,
                                'traffic_limit_bytes': info.get('limit_bytes', 0),
                                'traffic_used_bytes': info.get('used_bytes', 0),
                                'ip_limit': info.get('ip_limit', 0),
                                'created_at': info.get('created_at', now_ts),
                            }
                            users_out.append(entry)
                    return self.reply_json(200, {'ok': True, 'count': len(users_out), 'users': users_out})

                elif sub == 'proxy-services/add':
                    # BUGFIX #9: 商城/agent 程序化添加 gost 入站代理账号
                    ptype = (params.get('protocol') or params.get('type') or 'socks5').lower()
                    if ptype not in ('socks5', 'http', 'https'):
                        return self.reply_json(400, {'ok': False, 'error': 'Invalid protocol (socks5|http|https)'})
                    try:
                        port = int(params.get('port', 0))
                    except Exception:
                        return self.reply_json(400, {'ok': False, 'error': 'Invalid port'})
                    username = (params.get('username') or '').strip() or secrets.token_hex(4)
                    password = (params.get('password') or '').strip() or secrets.token_urlsafe(16)
                    note = (params.get('note') or '').strip()

                    with data_lock:
                        existing_ports = set(s.get('port') for s in data.get('proxy_services', []))
                    if port <= 0 or port > 65535:
                        # BUGFIX: 不再用 socket bind 做端口探测 (在某些环境会卡住),
                        # 改为纯随机选 + 跳过已知占用端口. 若用户没传 port 则强制要求传.
                        allocated = None
                        attempts = 0
                        while attempts < 50:
                            attempts += 1
                            cand = random.randint(30000, 50000)
                            if 20000 <= cand <= 40000 or cand in existing_ports or cand in (8443, 19898, 40000, 22, 80, 443):
                                continue
                            allocated = cand
                            break
                        if not allocated:
                            return self.reply_json(500, {'ok': False, 'error': '请显式指定可用端口 (port), 自动分配失败'})
                        port = allocated
                    else:
                        if port in existing_ports:
                            return self.reply_json(400, {'ok': False, 'error': f'端口 {port} 已被其他代理服务占用'})

                    proxy_id = secrets.token_hex(6)
                    now_ts = int(time.time())
                    with data_lock:
                        data.setdefault('proxy_services', []).append({
                            'id': proxy_id,
                            'type': ptype,
                            'port': port,
                            'username': username,
                            'password': password,
                            'created_at': now_ts,
                            'note': note,
                        })
                        save_data()
                    reload_gost()

                    m = json.loads(meta_path.read_text()) if meta_path.exists() else {}
                    host = m.get('public_ip', '127.0.0.1') if m.get('is_insecure') else m.get('server_name', 'localhost')
                    uri_link = f"{ptype}://{username}:{password}@{host}:{port}"
                    return self.reply_json(200, {
                        'ok': True, 'id': proxy_id, 'type': ptype, 'host': host, 'port': port,
                        'username': username, 'password': password, 'note': note,
                        'url': uri_link, 'format': f"{host}:{port}:{username}:{password}"
                    })

                elif sub == 'proxy-services/list':
                    with data_lock:
                        items = list(data.get('proxy_services', []))
                    # 不脱敏 password, 调用方是受信 API key
                    return self.reply_json(200, {'ok': True, 'count': len(items), 'services': items})

                elif sub == 'proxy-services/delete':
                    proxy_id = (params.get('id') or '').strip()
                    if not proxy_id:
                        return self.reply_json(400, {'ok': False, 'error': 'Missing id'})
                    with data_lock:
                        services = data.get('proxy_services', [])
                        new_services = [s for s in services if s.get('id') != proxy_id]
                        if len(new_services) == len(services):
                            return self.reply_json(404, {'ok': False, 'error': 'Proxy service not found'})
                        data['proxy_services'] = new_services
                    save_data()
                    reload_gost()
                    return self.reply_json(200, {'ok': True, 'message': 'Proxy service deleted'})

                return self.reply_json(404, {'ok': False, 'error': 'API endpoint not found'})

            # 普通 Web 请求限流
            if not self.check_rate_limit(bucket='web'):
                return self.reply(429, b'Too many requests')

            # 3. Web 网页版管理通道 (用户管理 / WARP 开关 / 触发升级)
            prefix = '/' + data['token'] + '/'
            if self.path == prefix + 'do-upgrade':
                if not self.is_authenticated():
                    return self.reply_json(401, {'ok': False, 'error': 'Unauthorized'})
                try:
                    length = int(self.headers.get('Content-Length', 0))
                    body = self.rfile.read(length).decode('utf-8')
                    form = parse_qs(body)
                    target = form.get('target', [''])[0]
                    if target not in ('core', 'portal'):
                        return self.reply_json(400, {'ok': False, 'error': 'Invalid target'})

                    # 异步执行系统升级脚本
                    subprocess.Popen(['bash', '/etc/hysteria/do_upgrade.sh', target],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    return self.reply_json(200, {'ok': True, 'target': target})
                except Exception as e:
                    return self.reply_json(500, {'ok': False, 'error': str(e)})

            if self.path == prefix + 'manage-proxy':
                if not self.is_authenticated():
                    return self.reply_json(401, {'ok': False, 'error': 'Unauthorized'})
                try:
                    length = int(self.headers.get('Content-Length', 0))
                    body = self.rfile.read(length).decode('utf-8')
                    form = parse_qs(body)
                    action = form.get('action', [''])[0]
                    now_ts = int(time.time())

                    if action == 'create':
                        ptype = form.get('type', ['socks5'])[0]
                        if ptype not in ('socks5', 'http', 'https'):
                            return self.reply_json(400, {'ok': False, 'error': 'Invalid proxy type'})

                        raw_port = form.get('port', [''])[0].strip()
                        port = 0
                        if raw_port:
                            try:
                                port = int(raw_port)
                            except Exception:
                                return self.reply_json(400, {'ok': False, 'error': 'Invalid port'})

                        with data_lock:
                            existing_ports = set(s.get('port') for s in data.get('proxy_services', []))

                        # 若未指定端口或端口无效，自动在 12000-58000 寻找空闲可用端口（避开 Hysteria 20000-40000 端口跳跃段及常见端口）
                        if port <= 0 or port > 65535:
                            allocated = None
                            for _ in range(100):
                                cand = random.randint(12000, 58000)
                                if 20000 <= cand <= 40000 or cand in existing_ports or cand in (8443, 40000, 56195):
                                    continue
                                try:
                                    probe = socket.socket()
                                    probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                                    probe.bind(('0.0.0.0', cand))
                                    probe.close()
                                    allocated = cand
                                    break
                                except OSError:
                                    continue
                            if not allocated:
                                return self.reply_json(500, {'ok': False, 'error': '系统未能找到空闲可用端口，请尝试手动指定端口'})
                            port = allocated
                        else:
                            # 真实端口占用检测（避免与已有服务冲突）
                            if port in existing_ports:
                                return self.reply_json(400, {'ok': False, 'error': f'端口 {port} 已被其他代理服务占用'})
                            try:
                                probe = socket.socket()
                                probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                                probe.bind(('0.0.0.0', port))
                                probe.close()
                            except OSError:
                                return self.reply_json(400, {'ok': False, 'error': f'端口 {port} 已被系统其他进程占用'})

                        username = form.get('username', [''])[0].strip()[:64] or ('user_' + secrets.token_hex(4))
                        password = form.get('password', [''])[0].strip() or secrets.token_hex(12)
                        note = form.get('note', [''])[0].strip()[:200]

                        with data_lock:
                            proxy_id = 'proxy_' + secrets.token_hex(6)
                            data.setdefault('proxy_services', []).append({
                                'id': proxy_id,
                                'type': ptype,
                                'port': port,
                                'username': username,
                                'password': password,
                                'created_at': now_ts,
                                'note': note,
                            })
                        save_data()
                        reload_gost()

                        # 获取主机域名或 IP 以输出完整连接格式
                        m = json.loads(meta_path.read_text()) if meta_path.exists() else {}
                        host = m.get('public_ip', '127.0.0.1') if m.get('is_insecure') else m.get('server_name', 'localhost')

                        uri_link = f"{ptype}://{username}:{password}@{host}:{port}"
                        qr_svg = ''
                        try:
                            qr_res = subprocess.run(['qrencode', '-t', 'SVG', '-o', '-'],
                                                    input=uri_link.encode('utf-8'),
                                                    capture_output=True, timeout=3)
                            if qr_res.returncode == 0:
                                qr_svg = qr_res.stdout.decode('utf-8')
                        except Exception:
                            qr_svg = ''

                        return self.reply_json(200, {
                            'ok': True,
                            'id': proxy_id,
                            'type': ptype,
                            'host': host,
                            'port': port,
                            'username': username,
                            'password': password,
                            'note': note,
                            'url': uri_link,
                            'format': f"{host}:{port}:{username}:{password}",
                            'qr': qr_svg
                        })

                    elif action == 'delete':
                        proxy_id = form.get('id', [''])[0].strip()
                        with data_lock:
                            services = data.get('proxy_services', [])
                            new_services = [s for s in services if s.get('id') != proxy_id]
                            if len(new_services) == len(services):
                                return self.reply_json(404, {'ok': False, 'error': 'Proxy service not found'})
                            data['proxy_services'] = new_services
                        save_data()
                        reload_gost()
                        return self.reply_json(200, {'ok': True, 'message': 'Proxy service deleted'})

                    return self.reply_json(400, {'ok': False, 'error': 'Invalid action'})
                except Exception as e:
                    return self.reply_json(500, {'ok': False, 'error': str(e)})

            if self.path == prefix + 'install-gost':
                if not self.is_authenticated():
                    return self.reply_json(401, {'ok': False, 'error': 'Unauthorized'})
                try:
                    import platform, urllib.request, tarfile, tempfile, shutil
                    machine = platform.machine().lower()
                    if 'x86_64' in machine or 'amd64' in machine:
                        arch = 'linux_amd64'
                    elif 'aarch64' in machine or 'arm64' in machine:
                        arch = 'linux_arm64'
                    elif 'armv7' in machine:
                        arch = 'linux_armv7'
                    else:
                        arch = 'linux_amd64'

                    # 动态探测最新版本
                    tag = 'v3.3.0'
                    try:
                        req = urllib.request.Request('https://api.github.com/repos/go-gost/gost/releases/latest', headers={'User-Agent': 'Mozilla/5.0'})
                        with urllib.request.urlopen(req, timeout=8) as r:
                            rel_data = json.loads(r.read().decode())
                            if rel_data.get('tag_name'):
                                tag = rel_data['tag_name']
                    except Exception:
                        tag = 'v3.3.0'

                    ver = tag.lstrip('v')
                    pkg_name = f"gost_{ver}_{arch}.tar.gz"

                    download_urls = [
                        f"https://github.com/go-gost/gost/releases/download/{tag}/{pkg_name}",
                        f"https://ghfast.top/https://github.com/go-gost/gost/releases/download/{tag}/{pkg_name}",
                        f"https://github.moeyy.xyz/https://github.com/go-gost/gost/releases/download/{tag}/{pkg_name}"
                    ]

                    installed = False
                    last_err = ''
                    with tempfile.TemporaryDirectory() as tmpdir:
                        archive_path = Path(tmpdir) / 'gost.tar.gz'
                        for u in download_urls:
                            try:
                                req = urllib.request.Request(u, headers={'User-Agent': 'Mozilla/5.0'})
                                with urllib.request.urlopen(req, timeout=30) as resp, open(archive_path, 'wb') as out_f:
                                    shutil.copyfileobj(resp, out_f)
                                if archive_path.stat().st_size > 1024 * 1024 and tarfile.is_tarfile(str(archive_path)):
                                    with tarfile.open(str(archive_path), 'r:gz') as tar:
                                        tar.extractall(path=tmpdir)
                                    src_bin = Path(tmpdir) / 'gost'
                                    if src_bin.exists():
                                        shutil.move(str(src_bin), '/usr/local/bin/gost')
                                        os.chmod('/usr/local/bin/gost', 0o755)
                                        installed = True
                                        break
                            except Exception as e:
                                last_err = str(e)

                    if not installed:
                        return self.reply_json(500, {'ok': False, 'error': f'下载或解压 GOST 失败: {last_err}'})

                    # 确保 systemd 服务存在
                    service_content = '''[Unit]
Description=GOST Proxy Service (SOCKS5/HTTP/HTTPS inbound)
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/gost -C /etc/hysteria/gost.yml
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
'''
                    Path('/etc/systemd/system/gost.service').write_text(service_content)
                    subprocess.run(['systemctl', 'daemon-reload'], capture_output=True)
                    subprocess.run(['systemctl', 'enable', 'gost'], capture_output=True)

                    # 重新生成 gost.yml 并启动服务
                    write_gost_config()
                    subprocess.run(['systemctl', 'restart', 'gost'], capture_output=True, timeout=10)

                    return self.reply_json(200, {'ok': True, 'message': f'GOST {tag} 官方核心安装成功，服务已自动配置并启动！'})
                except Exception as e:
                    return self.reply_json(500, {'ok': False, 'error': f'执行异常: {str(e)}'})

            # ---------------- AmneziaWG (AWG) ----------------
            if self.path == prefix + 'install-amneziawg':
                if not self.is_authenticated():
                    return self.reply_json(401, {'ok': False, 'error': 'Unauthorized'})
                try:
                    length = int(self.headers.get('Content-Length', 0))
                    body = self.rfile.read(length).decode('utf-8')
                    form = parse_qs(body)
                    # 先去空白再取默认值：写成 (value or '3').strip() 的话，
                    # 纯空格能通过 or 判定、再被 strip 成空串，导致误判为非法协议线。
                    line = (form.get('line', [''])[0] or '').strip() or '3'
                    endpoint = (form.get('endpoint', [''])[0] or '').strip()
                    port = (form.get('port', [''])[0] or '').strip()

                    if line not in ('2', '3'):
                        return self.reply_json(400, {'ok': False, 'error': '协议线只能是 2 或 3'})
                    if not endpoint:
                        return self.reply_json(400, {'ok': False, 'error': '必须提供客户端连接地址（域名或公网 IP）'})
                    # 端口若由用户指定，提前拦掉会与 Hysteria2 端口跳跃冲突的取值
                    if port:
                        if not port.isdigit() or not (1 <= int(port) <= 65535):
                            return self.reply_json(400, {'ok': False, 'error': '端口必须是 1-65535 的数字'})
                        if 20000 <= int(port) <= 40000:
                            return self.reply_json(400, {'ok': False, 'error': '该端口落在 Hysteria2 的端口跳跃区间 20000-40000 内，会导致 AWG 收不到握手包，请改用 50000-59000'})
                    if not ensure_awgctl():
                        return self.reply_json(500, {'ok': False, 'error': '无法获取 hy2-awgctl（服务器可能无法访问 github.com），请手动执行 install.sh 的 AmneziaWG 菜单'})

                    args = ['install', '--line', line, '--endpoint', endpoint]
                    if port:
                        args += ['--port', port]
                    rc, out, err = awg_run(args, timeout=420)
                    if rc != 0:
                        return self.reply_json(500, {'ok': False, 'error': '安装失败：' + awg_err_tail(rc, out, err)})
                    return self.reply_json(200, {'ok': True, 'message': f'AmneziaWG（协议线 AWG {line}.x）安装成功，服务已启动。'})
                except subprocess.TimeoutExpired:
                    return self.reply_json(500, {'ok': False, 'error': '安装超时（超过 420 秒），请查看服务器上的 journalctl -u amneziawg-server'})
                except Exception as e:
                    return self.reply_json(500, {'ok': False, 'error': f'执行异常: {str(e)}'})

            if self.path == prefix + 'manage-amneziawg':
                if not self.is_authenticated():
                    return self.reply_json(401, {'ok': False, 'error': 'Unauthorized'})
                try:
                    length = int(self.headers.get('Content-Length', 0))
                    body = self.rfile.read(length).decode('utf-8')
                    form = parse_qs(body)
                    action = (form.get('action', [''])[0] or '').strip()

                    if action == 'state':
                        return self.reply_json(200, awg_state())

                    # 先校验动作名再检查安装状态 —— 否则未知动作会拿到
                    # "尚未安装" 这种误导性的报错，排障时容易被带偏。
                    known_actions = ('peer_add', 'peer_del', 'set_line', 'update',
                                     'start', 'stop', 'restart')
                    if action not in known_actions:
                        return self.reply_json(400, {'ok': False, 'error': '未知操作: ' + (action or '(空)')})

                    if not awg_installed():
                        return self.reply_json(400, {'ok': False, 'error': 'AmneziaWG 尚未安装'})
                    if not ensure_awgctl():
                        return self.reply_json(500, {'ok': False, 'error': 'hy2-awgctl 不可用'})

                    if action == 'peer_add':
                        name = (form.get('name', [''])[0] or '').strip()
                        endpoint = (form.get('endpoint', [''])[0] or '').strip()
                        if not VALID_AWG_NAME_RE.match(name):
                            return self.reply_json(400, {'ok': False, 'error': '客户端名称只允许字母、数字、点、下划线、连字符，长度 1-32'})
                        if not endpoint:
                            return self.reply_json(400, {'ok': False, 'error': '必须提供连接地址'})
                        rc, out, err = awg_run(['peer-add', name, '--endpoint', endpoint], timeout=90)
                        if rc != 0:
                            return self.reply_json(500, {'ok': False, 'error': '创建失败：' + awg_err_tail(rc, out, err, 400)})
                        return self.reply_json(200, {'ok': True, 'message': f'客户端 {name} 已创建'})

                    if action == 'peer_del':
                        name = (form.get('name', [''])[0] or '').strip()
                        if not VALID_AWG_NAME_RE.match(name):
                            return self.reply_json(400, {'ok': False, 'error': '客户端名称非法'})
                        rc, out, err = awg_run(['peer-del', name], timeout=90)
                        if rc != 0:
                            return self.reply_json(500, {'ok': False, 'error': '删除失败：' + awg_err_tail(rc, out, err, 400)})
                        return self.reply_json(200, {'ok': True, 'message': f'客户端 {name} 已删除'})

                    if action == 'set_line':
                        target = (form.get('line', [''])[0] or '').strip()
                        if target not in ('2', '3'):
                            return self.reply_json(400, {'ok': False, 'error': '协议线只能是 2 或 3'})
                        if target == awg_state()['line']:
                            return self.reply_json(200, {'ok': True, 'message': f'已经是 AWG {target}.x，无需切换。'})
                        rc, out, err = awg_run(['update', '--line', target], timeout=420)
                        if rc != 0:
                            return self.reply_json(500, {'ok': False, 'error': '切换失败：' + awg_err_tail(rc, out, err)})
                        return self.reply_json(200, {'ok': True, 'message': f'已切换到 AWG {target}.x。⚠️ 所有客户端必须重新导入配置。'})

                    if action == 'update':
                        rc, out, err = awg_run(['update'], timeout=420)
                        if rc != 0:
                            return self.reply_json(500, {'ok': False, 'error': '更新失败：' + awg_err_tail(rc, out, err)})
                        return self.reply_json(200, {'ok': True, 'message': '二进制已更新，协议线与参数保持不变，客户端无需重新导入。'})

                    if action in ('start', 'stop', 'restart'):
                        label = {'start': '启动', 'stop': '停止', 'restart': '重启'}.get(action, action)
                        proc = subprocess.run(['systemctl', action, AWG_SVC_NAME],
                                              capture_output=True, text=True, timeout=30)
                        if proc.returncode != 0:
                            return self.reply_json(500, {'ok': False, 'error': '服务' + label + '失败：' + (proc.stderr or '').strip()[-400:]})
                        return self.reply_json(200, {'ok': True, 'message': '服务已' + label})
                except subprocess.TimeoutExpired:
                    return self.reply_json(500, {'ok': False, 'error': '操作超时，请查看服务器日志'})
                except Exception as e:
                    return self.reply_json(500, {'ok': False, 'error': f'执行异常: {str(e)}'})

            if self.path == prefix + 'manage-warp':
                if not self.is_authenticated():
                    return self.reply_json(401, {'ok': False, 'error': 'Unauthorized'})
                try:
                    length = int(self.headers.get('Content-Length', 0))
                    body = self.rfile.read(length).decode('utf-8') if length > 0 else ''
                    form = parse_qs(body)
                    action = form.get('action', ['toggle'])[0]

                    DEFAULT_WARP_DOMAINS = [
                        'ipify.org', 'cloudflare.com',
                        'openai.com', 'chatgpt.com', 'oaistatic.com', 'oaiusercontent.com', 'ai.com',
                        'anthropic.com', 'claude.ai',
                        'gemini.google.com', 'aistudio.google.com', 'generativelanguage.googleapis.com'
                    ]

                    with data_lock:
                        if 'warp_rules' not in data:
                            data['warp_rules'] = list(DEFAULT_WARP_DOMAINS)

                        if action == 'toggle':
                            curr = data.get('warp_enabled', False)
                            data['warp_enabled'] = not curr
                        elif action == 'add_rule':
                            raw_domain = form.get('domain', [''])[0].strip().lower()
                            cleaned = re.sub(r'^[a-zA-Z]+://', '', raw_domain).split('/')[0].split(':')[0].strip('.')
                            if cleaned and cleaned not in data['warp_rules'] and re.match(r'^[a-zA-Z0-9.\-]+$', cleaned):
                                data['warp_rules'].append(cleaned)
                        elif action == 'del_rule':
                            target_domain = form.get('domain', [''])[0].strip().lower()
                            if target_domain in data['warp_rules']:
                                data['warp_rules'].remove(target_domain)
                        elif action == 'reset_rules':
                            data['warp_rules'] = list(DEFAULT_WARP_DOMAINS)

                        new_state = data.get('warp_enabled', False)
                        current_rules = list(data.get('warp_rules', []))

                    save_data()

                    def apply_hy2_acl():
                        cfg_path = Path('/etc/hysteria/config.yaml')
                        if not cfg_path.exists():
                            return
                        lines = cfg_path.read_text(encoding='utf-8').splitlines()
                        clean_lines = []
                        in_acl = False
                        for line in lines:
                            if line.strip().startswith('acl:'):
                                in_acl = True
                                continue
                            if not in_acl:
                                clean_lines.append(line)

                        cfg_text = '\n'.join(clean_lines)
                        if new_state:
                            if 'name: warp_socks' not in cfg_text:
                                warp_outbound = "\n  - name: warp_socks\n    type: socks5\n    socks5:\n      addr: 127.0.0.1:19898"
                                if 'outbounds:' in cfg_text:
                                    cfg_text = cfg_text.replace('outbounds:', 'outbounds:' + warp_outbound)
                                else:
                                    cfg_text += '\noutbounds:' + warp_outbound

                            acl_block = '\nacl:\n  inline:\n'
                            for d in current_rules:
                                acl_block += f'    - warp_socks(suffix:{d})\n'
                            acl_block += '    - direct_ipv4(all)\n'
                            cfg_text += acl_block

                        cfg_path.write_text(cfg_text.strip() + '\n', encoding='utf-8')
                        subprocess.run(['systemctl', 'restart', 'hysteria-server'], capture_output=True, timeout=10)

                    threading.Thread(target=apply_hy2_acl, daemon=True).start()

                    return self.reply_json(200, {
                        'ok': True,
                        'enabled': new_state,
                        'rules': current_rules
                    })
                except Exception as e:
                    return self.reply_json(500, {'ok': False, 'error': str(e)})

            if self.path == prefix + 'install-xray':
                if not self.is_authenticated():
                    return self.reply_json(401, {'ok': False, 'error': 'Unauthorized'})
                try:
                    import os, platform, urllib.request, zipfile, tempfile, shutil
                    machine = platform.machine().lower()
                    xarch = 'arm64-v8a' if ('aarch64' in machine or 'arm64' in machine) else '64'
                    dl_urls = [
                        f"https://ghfast.top/https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-linux-{xarch}.zip",
                        f"https://github.moeyy.xyz/https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-linux-{xarch}.zip",
                        f"https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-linux-{xarch}.zip"
                    ]
                    installed = False
                    with tempfile.TemporaryDirectory() as tmpdir:
                        zpath = Path(tmpdir) / 'xray.zip'
                        for u in dl_urls:
                            try:
                                req = urllib.request.Request(u, headers={'User-Agent': 'Mozilla/5.0'})
                                with urllib.request.urlopen(req, timeout=45) as resp, open(zpath, 'wb') as out_f:
                                    shutil.copyfileobj(resp, out_f)
                                if zpath.stat().st_size > 5 * 1024 * 1024 and zipfile.is_zipfile(str(zpath)):
                                    with zipfile.ZipFile(zpath, 'r') as zf:
                                        zf.extract('xray', path=tmpdir)
                                    bin_path = Path(tmpdir) / 'xray'
                                    if bin_path.exists():
                                        shutil.move(str(bin_path), '/usr/local/bin/xray')
                                        os.chmod('/usr/local/bin/xray', 0o755)
                                        installed = True
                                        break
                            except Exception:
                                pass

                    if not installed:
                        return self.reply_json(500, {'ok': False, 'error': '下载或解压 Xray 核心失败'})

                    service_content = '''[Unit]
Description=Xray Service (VLESS-Reality)
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/xray run -c /etc/hysteria/xray.json
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
'''
                    Path('/etc/systemd/system/xray.service').write_text(service_content)
                    subprocess.run(['systemctl', 'daemon-reload'], capture_output=True)
                    subprocess.run(['systemctl', 'enable', 'xray'], capture_output=True)
                    self._generate_and_apply_reality(True)

                    return self.reply_json(200, {'ok': True, 'message': 'Xray-core 安装成功，VLESS-Reality 节点已在 TCP 443 端口就绪！'})
                except Exception as e:
                    return self.reply_json(500, {'ok': False, 'error': f'安装执行异常: {str(e)}'})

            if self.path == prefix + 'manage-reality':
                if not self.is_authenticated():
                    return self.reply_json(401, {'ok': False, 'error': 'Unauthorized'})
                try:
                    length = int(self.headers.get('Content-Length', 0))
                    body = self.rfile.read(length).decode('utf-8') if length > 0 else ''
                    form = parse_qs(body)
                    action = form.get('action', ['toggle'])[0]

                    if action == 'toggle':
                        out = subprocess.run(['systemctl', 'is-active', 'xray'], capture_output=True, text=True, timeout=3).stdout.strip()
                        if out == 'active':
                            subprocess.run(['systemctl', 'stop', 'xray'], capture_output=True, timeout=5)
                            new_active = False
                        else:
                            if not Path('/etc/hysteria/xray.json').exists():
                                self._generate_and_apply_reality(True)
                            else:
                                subprocess.run(['systemctl', 'restart', 'xray'], capture_output=True, timeout=5)
                            new_active = True
                        return self.reply_json(200, {'ok': True, 'active': new_active})

                    elif action == 'reset':
                        self._generate_and_apply_reality(True)
                        return self.reply_json(200, {'ok': True, 'message': '已重置密钥并重启生效'})

                    return self.reply_json(400, {'ok': False, 'error': 'Invalid action'})
                except Exception as e:
                    return self.reply_json(500, {'ok': False, 'error': str(e)})

            if self.path == prefix + 'set-bbr':
                if not self.is_authenticated():
                    return self.reply_json(401, {'ok': False, 'error': 'Unauthorized'})
                try:
                    length = int(self.headers.get('Content-Length', 0))
                    body = self.rfile.read(length).decode('utf-8') if length > 0 else ''
                    form = parse_qs(body)
                    ver = form.get('version', ['v1'])[0].lower()

                    Path('/etc/modules-load.d/bbr.conf').write_text('tcp_bbr\n', encoding='utf-8')
                    subprocess.run(['modprobe', 'tcp_bbr'], capture_output=True)

                    target_algo = 'bbr'
                    qdisc = 'fq'
                    if ver == 'v2':
                        avail = subprocess.run(['sysctl', '-n', 'net.ipv4.tcp_available_congestion_control'],
                                               capture_output=True, text=True).stdout
                        target_algo = 'bbr2' if 'bbr2' in avail else 'bbr'
                    elif ver == 'v3':
                        avail = subprocess.run(['sysctl', '-n', 'net.ipv4.tcp_available_congestion_control'],
                                               capture_output=True, text=True).stdout
                        target_algo = 'bbr3' if 'bbr3' in avail else 'bbr'

                    bbr_sysctl = f'''# TCP 拥塞控制 BBR {ver.upper()} 深度优化
net.core.default_qdisc = {qdisc}
net.ipv4.tcp_congestion_control = {target_algo}
net.ipv4.tcp_notsent_lowat = 16384
net.ipv4.tcp_slow_start_after_idle = 0
'''
                    Path('/etc/sysctl.d/99-bbr.conf').write_text(bbr_sysctl, encoding='utf-8')
                    subprocess.run(['sysctl', '-p', '/etc/sysctl.d/99-bbr.conf'], capture_output=True, text=True)
                    
                    with data_lock:
                        data['bbr_target_version'] = ver
                    save_data()

                    curr = subprocess.run(['sysctl', '-n', 'net.ipv4.tcp_congestion_control'],
                                          capture_output=True, text=True).stdout.strip()
                    
                    if curr == target_algo:
                        return self.reply_json(200, {'ok': True, 'message': f'恭喜！BBR {ver.upper()} 算法已立即热生效（当前算法: {curr}）！'})
                    else:
                        return self.reply_json(200, {'ok': True, 'message': f'BBR {ver.upper()} 配置已成功保存！需要重启服务器后完成内核级生效。'})
                except Exception as e:
                    return self.reply_json(500, {'ok': False, 'error': str(e)})

            if self.path == prefix + 'reboot-server':
                if not self.is_authenticated():
                    return self.reply_json(401, {'ok': False, 'error': 'Unauthorized'})
                try:
                    subprocess.Popen(['bash', '-c', 'sleep 1 && reboot'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    return self.reply_json(200, {'ok': True, 'message': '服务器正在重启中'})
                except Exception as e:
                    return self.reply_json(500, {'ok': False, 'error': str(e)})

            if self.path == prefix + 'manage-user':
                if not self.is_authenticated():
                    return self.reply(401, b'Unauthorized')
                try:
                    length = int(self.headers.get('Content-Length', 0))
                    body = self.rfile.read(length).decode('utf-8')
                    form = parse_qs(body)
                    action = form.get('action', [''])[0]
                    user_id = form.get('user_id', [''])[0].strip()
                    now_ts = int(time.time())

                    if not VALID_USER_ID_RE.match(user_id):
                        return self.reply(400, b'Invalid user_id format')

                    if action == 'create' and user_id:
                        pwd = form.get('password', [''])[0].strip() or secrets.token_hex(16)
                        days = int(form.get('duration_days', ['30'])[0] or 30)
                        ip_limit = int(form.get('ip_limit', ['0'])[0] or 0)
                        traffic_gb = float(form.get('traffic_gb', ['0'])[0] or 0)
                        limit_bytes = int(traffic_gb * (1024**3)) if traffic_gb > 0 else 0
                        note = form.get('note', [''])[0].strip()[:200]
                        with data_lock:
                            data.setdefault('users', {})[user_id] = {
                                'password': pwd,
                                'expires_at': now_ts + days * 86400,
                                'ip_limit': ip_limit,
                                'limit_bytes': limit_bytes,
                                'used_bytes': 0,
                                'status': 'active',
                                'created_at': now_ts,
                                'note': note
                            }
                    elif action == 'delete' and user_id:
                        with data_lock:
                            if user_id in data.get('users', {}):
                                del data['users'][user_id]
                                if user_id in ip_tracker:
                                    del ip_tracker[user_id]

                    regenerate_page()
                    self.send_response(302)
                    self.send_header('Location', prefix + '#users')
                    self.end_headers()
                    return
                except Exception:
                    return self.reply(400, b'Bad request')

            # 4. Web 表单登录
            if self.path == prefix + 'login':
                try:
                    length = int(self.headers.get('Content-Length', 0))
                    if length > 4096:
                        return self.reply(400, b'Bad request')
                    body = self.rfile.read(length).decode('utf-8', errors='ignore')
                    params = parse_qs(body)
                    user = params.get('username', [''])[0]
                    pwd = params.get('password', [''])[0]
                    remember = params.get('remember', ['0'])[0] == '1'
                except Exception:
                    return self.reply(400, b'Bad request')

                submitted_auth = base64.b64encode(f'{user}:{pwd}'.encode())
                submitted_digest = hashlib.sha256(submitted_auth).hexdigest()

                if not hmac.compare_digest(submitted_digest, data['auth_hash']):
                    self.record_failure()
                    page = login_html(data['token'], error_msg='用户名或密码不正确，请重新输入')
                    return self.reply(200, page.encode('utf-8'), 'text/html; charset=utf-8')

                sess_val = sign_session(data['token'])
                max_age = '; Max-Age=2592000' if remember else ''
                cookie = f'hy2_session={sess_val}; Path=/{data["token"]}/; HttpOnly; SameSite=Strict; Secure{max_age}'
                self.send_response(302)
                self.send_header('Location', prefix)
                self.send_header('Set-Cookie', cookie)
                self.send_header('Cache-Control', 'no-store')
                self.end_headers()
                return

            if self.path == prefix + 'install-warp':
                if not self.is_authenticated():
                    return self.reply_json(401, {'ok': False, 'error': 'Unauthorized'})
                try:
                    install_warp_sh = '''
set -eo pipefail
export DEBIAN_FRONTEND=noninteractive
WARP_SOCKS_ADDR="127.0.0.1:19898"
WGCF_BIN="/usr/local/bin/wgcf"
WP_BIN="/usr/local/bin/wireproxy"
WG_DIR="/etc/wireguard"
WGCF_ACCT="${WG_DIR}/wgcf-account.toml"
WGCF_CONF="${WG_DIR}/wgcf.conf"
WP_CFG="${WG_DIR}/wp.conf"
HY2_CONF="/etc/hysteria/config.yaml"
log() { echo "[warp] $*"; }

for t in curl jq; do
    command -v "$t" >/dev/null 2>&1 && continue
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq >/dev/null 2>&1 || true
        apt-get install -y -qq "$t" >/dev/null 2>&1 || true
    elif command -v yum >/dev/null 2>&1; then
        yum install -y "$t" >/dev/null 2>&1 || true
    fi
done
command -v curl >/dev/null 2>&1 || { echo "缺少 curl，无法继续" >&2; exit 1; }

ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64)   WG_A="amd64"; WP_A="amd64" ;;
    aarch64|arm64)  WG_A="arm64"; WP_A="arm64" ;;
    armv7l|armv7)   WG_A="armv7"; WP_A="arm"   ;;
    *) echo "不支持的 CPU 架构: $ARCH" >&2; exit 1 ;;
esac

if [ ! -x "$WGCF_BIN" ]; then
    log "下载 wgcf 二进制..."
    RAW=$(curl -fsSL --max-time 20 https://api.github.com/repos/ViRb3/wgcf/releases/latest 2>/dev/null || true)
    if command -v jq >/dev/null 2>&1; then
        TAG=$(printf '%s' "$RAW" | jq -r '.tag_name // empty' 2>/dev/null || true)
    else
        TAG=$(printf '%s' "$RAW" | grep -o '"tag_name": *"[^"]*"' | head -1 | cut -d'"' -f4)
    fi
    VER="${TAG#v}"
    case "$VER" in ""|null) VER="2.3.0" ;; esac
    if ! curl -fsSL --max-time 90 -o "${WGCF_BIN}.tmp" "https://github.com/ViRb3/wgcf/releases/download/v${VER}/wgcf_${VER}_linux_${WG_A}"; then
        rm -f "${WGCF_BIN}.tmp"
        echo "wgcf 下载失败 (v${VER}/${WG_A})" >&2
        exit 1
    fi
    install -m 755 "${WGCF_BIN}.tmp" "$WGCF_BIN"
    rm -f "${WGCF_BIN}.tmp"
fi

if [ ! -x "$WP_BIN" ]; then
    log "下载 wireproxy 二进制..."
    RAW=$(curl -fsSL --max-time 20 https://api.github.com/repos/whyvl/wireproxy/releases/latest 2>/dev/null || true)
    if command -v jq >/dev/null 2>&1; then
        TAG=$(printf '%s' "$RAW" | jq -r '.tag_name // empty' 2>/dev/null || true)
    else
        TAG=$(printf '%s' "$RAW" | grep -o '"tag_name": *"[^"]*"' | head -1 | cut -d'"' -f4)
    fi
    case "$TAG" in ""|null) TAG="v1.1.3" ;; esac
    TMP_TGZ=$(mktemp)
    TMP_EX=$(mktemp -d)
    if ! curl -fsSL --max-time 90 -o "$TMP_TGZ" "https://github.com/whyvl/wireproxy/releases/download/${TAG}/wireproxy_linux_${WP_A}.tar.gz"; then
        rm -f "$TMP_TGZ"; rm -rf "$TMP_EX"
        echo "wireproxy 下载失败 (${TAG}/${WP_A})" >&2
        exit 1
    fi
    tar -xzf "$TMP_TGZ" -C "$TMP_EX" 2>/dev/null || true
    SRC=$(find "$TMP_EX" -name wireproxy -type f -executable 2>/dev/null | head -1)
    [ -z "$SRC" ] && SRC=$(find "$TMP_EX" -type f -executable 2>/dev/null | head -1)
    if [ -z "$SRC" ]; then
        rm -f "$TMP_TGZ"; rm -rf "$TMP_EX"
        echo "wireproxy 解压失败，未找到可执行文件" >&2
        exit 1
    fi
    install -m 755 "$SRC" "$WP_BIN"
    rm -f "$TMP_TGZ"; rm -rf "$TMP_EX"
fi

mkdir -p "$WG_DIR"
if [ ! -f "$WGCF_ACCT" ]; then
    log "匿名注册 Cloudflare WARP 设备..."
    if ! "$WGCF_BIN" --config "$WGCF_ACCT" register --accept-tos >/tmp/wgcf-register.log 2>&1; then
        echo "WARP 匿名注册失败，详见 /tmp/wgcf-register.log" >&2
        exit 1
    fi
fi
if [ ! -f "$WGCF_CONF" ]; then
    if ! ( cd "$WG_DIR" && "$WGCF_BIN" --config "$WGCF_ACCT" generate >/tmp/wgcf-generate.log 2>&1 ); then
        echo "WARP 配置生成失败，详见 /tmp/wgcf-generate.log" >&2
        exit 1
    fi
fi
[ -f "${WG_DIR}/wgcf-profile.conf" ] && [ ! -f "$WGCF_CONF" ] && mv -f "${WG_DIR}/wgcf-profile.conf" "$WGCF_CONF"
[ -f /root/wgcf-profile.conf ] && [ ! -f "$WGCF_CONF" ] && mv -f /root/wgcf-profile.conf "$WGCF_CONF"
if [ ! -f "$WGCF_CONF" ]; then
    echo "未找到 wgcf 生成的 WireGuard 配置" >&2
    exit 1
fi

WG_PRIV=$(awk '/^PrivateKey/{print $3; exit}' "$WGCF_CONF")
WG_PUB=$(awk -F'= ' '/^PublicKey/{print $2; exit}' "$WGCF_CONF")
WG_EP=$(awk -F'= ' '/^Endpoint/{print $2; exit}' "$WGCF_CONF")
if [ -z "$WG_PRIV" ] || [ -z "$WG_PUB" ] || [ -z "$WG_EP" ]; then
    echo "WireGuard 配置解析失败 (PrivateKey/PublicKey/Endpoint 缺失)" >&2
    exit 1
fi

cat > "$WP_CFG" <<WPEOF
# wireproxy config (managed by hysteria2-installer, do not edit)
[Interface]
Address = 172.16.0.2/32
PrivateKey = ${WG_PRIV}
DNS = 1.1.1.1

[Peer]
PublicKey = ${WG_PUB}
Endpoint = ${WG_EP}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25

[Socks5]
BindAddress = ${WARP_SOCKS_ADDR}
WPEOF
chmod 600 "$WP_CFG"

cat > /etc/systemd/system/wireproxy.service <<'WPSVCEOF'
[Unit]
Description=WireProxy (Cloudflare WARP SOCKS5)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/wireproxy -c /etc/wireguard/wp.conf
Restart=on-failure
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
WPSVCEOF
systemctl daemon-reload
systemctl enable wireproxy >/dev/null 2>&1 || true
systemctl restart wireproxy >/dev/null 2>&1 || true
sleep 3

if ! curl --proxy "socks5h://${WARP_SOCKS_ADDR}" --silent --fail --max-time 10 https://api4.ipify.org >/dev/null 2>&1; then
    echo "wireproxy 已启动但 WARP socks5 探活失败（上游可能受限或被封禁）" >&2
    exit 1
fi
log "WARP socks5 探活成功"

if [ -f "$HY2_CONF" ]; then
    sed -i "s|addr: 127.0.0.1:40000|addr: ${WARP_SOCKS_ADDR}|g" "$HY2_CONF"
fi

if systemctl list-unit-files 2>/dev/null | grep -q '^warp-svc'; then
    log "检测到旧的 cloudflare-warp 客户端，已停用（统一走 wireproxy 出口）"
    systemctl disable --now warp-svc >/dev/null 2>&1 || true
fi

cat > /usr/local/bin/hy2-warp-watchdog.sh <<'WDE'
#!/usr/bin/env bash
set -u
if ! curl --proxy socks5h://127.0.0.1:19898 --silent --fail --max-time 6 https://api4.ipify.org >/dev/null 2>&1; then
    logger -t hy2-warp-watchdog "WARP local proxy failed. Restarting wireproxy..."
    systemctl restart wireproxy >/dev/null 2>&1 || true
fi
WDE
chmod 755 /usr/local/bin/hy2-warp-watchdog.sh

cat > /etc/systemd/system/hy2-warp-watchdog.service <<'WDSE'
[Unit]
Description=Cloudflare WARP Watchdog for Hysteria 2
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/hy2-warp-watchdog.sh
WDSE

cat > /etc/systemd/system/hy2-warp-watchdog.timer <<'WDTE'
[Unit]
Description=Run WARP Watchdog every 3 minutes

[Timer]
OnBootSec=1min
OnUnitActiveSec=3min
Unit=hy2-warp-watchdog.service

[Install]
WantedBy=timers.target
WDTE
systemctl daemon-reload
systemctl enable --now hy2-warp-watchdog.timer >/dev/null 2>&1 || true
log "Cloudflare WARP Local Proxy (wgcf + wireproxy) 部署完成"
'''
                    res = subprocess.run(['bash', '-c', install_warp_sh], capture_output=True, text=True, timeout=180)
                    if res.returncode != 0:
                        err_detail = (res.stderr or res.stdout or '安装失败').strip()
                        return self.reply_json(500, {'ok': False, 'error': f'安装失败: {err_detail}'})

                    # 自动开启 WARP 并热重载
                    with data_lock:
                        data['warp_enabled'] = True
                    save_data()
                    try:
                        subprocess.run(['/etc/hysteria/toggle_warp.sh', 'enable'], capture_output=True, timeout=10)
                    except Exception:
                        pass

                    return self.reply_json(200, {'ok': True, 'message': 'Cloudflare WARP 客户端安装成功并已就绪！'})
                except Exception as e:
                    return self.reply_json(500, {'ok': False, 'error': f'执行异常: {str(e)}'})


            return self.reply(404, b'Not found')

        def do_GET(self):
            if self.path.startswith('/api/v1/'):
                if not self.check_rate_limit(bucket='api'):
                    return self.reply(429, b'Too many requests')
                if not self.verify_api_key():
                    return self.reply_json(401, {'ok': False, 'error': 'Unauthorized API key'})
                sub = self.path[len('/api/v1/'):]
                if sub == 'node/meta':
                    m = json.loads(meta_path.read_text()) if meta_path.exists() else {}
                    with data_lock:
                        users_count = len(data.get('users', {}))
                    return self.reply_json(200, {'ok': True, 'meta': m, 'users_count': users_count, 'time': int(time.time())})
                if sub == 'users/list':
                    # BUGFIX #10: 商城节点对账用, 列出所有动态用户 (脱敏不返回 password)
                    now_ts = int(time.time())
                    users_out = []
                    with data_lock:
                        for uid, info in data.get('users', {}).items():
                            users_out.append({
                                'user_id': uid,
                                'expires_at': info.get('expires_at', 0),
                                'active': info.get('expires_at', 0) > now_ts,
                                'traffic_limit_bytes': info.get('limit_bytes', 0),
                                'traffic_used_bytes': info.get('used_bytes', 0),
                                'ip_limit': info.get('ip_limit', 0),
                                'created_at': info.get('created_at', now_ts),
                                'status': info.get('status', 'active'),
                            })
                    return self.reply_json(200, {'ok': True, 'count': len(users_out), 'users': users_out})
                if sub == 'proxy-services/list':
                    with data_lock:
                        items = list(data.get('proxy_services', []))
                    return self.reply_json(200, {'ok': True, 'count': len(items), 'services': items})
                return self.reply_json(404, {'ok': False, 'error': 'API endpoint not found'})

            if not self.check_rate_limit(bucket='web'):
                return self.reply(429, b'Too many requests')

            prefix = '/' + data['token'] + '/'
            if not self.path.startswith(prefix):
                return self.reply(404, b'Not found')

            subpath = self.path[len(prefix):]
            auth_header = self.headers.get('Authorization', '')
            is_client_api = subpath in ('clash.yaml', 'sing-box.json') or auth_header.startswith('Basic ')

            # 1. 专属用户独立页面与客户端直连下载路由 (可免管理员登录凭证，支持 ?k= 访问)
            if subpath.startswith('u/'):
                user_rest = subpath[2:].split('?', 1)[0]
                parts = user_rest.split('/', 1)
                target_uid = parts[0]
                action_file = parts[1] if len(parts) > 1 else ''

                if not VALID_USER_ID_RE.match(target_uid):
                    return self.reply(400, b'Invalid user_id format')

                with data_lock:
                    u = data.get('users', {}).get(target_uid)
                    if not u:
                        return self.reply(404, b'User not found')
                    u_copy = dict(u)

                query = parse_qs(self.path.split('?', 1)[1]) if '?' in self.path else {}
                k_val = query.get('k', [''])[0]
                expected_k = user_view_key(session_secret, target_uid)

                if not self.is_authenticated() and not (k_val and hmac.compare_digest(k_val, expected_k)):
                    return self.reply(403, b'Access denied: invalid key')

                m = json.loads(meta_path.read_text()) if meta_path.exists() else {}
                pwd = u_copy.get('password', '')
                uri, clash_yaml, sing_json = artifacts(m, auth_override=pwd, name_override=f"Hy2-{target_uid}")

                if action_file == 'clash.yaml':
                    return self.reply(200, clash_yaml.encode('utf-8'), 'application/yaml')
                elif action_file == 'sing-box.json':
                    return self.reply(200, sing_json.encode('utf-8'), 'application/json')
                elif action_file == 'qr.svg':
                    try:
                        qr_bytes = subprocess.run(['qrencode', '-t', 'SVG', '-o', '-'], input=uri.encode(), capture_output=True, check=True).stdout
                        return self.reply(200, qr_bytes, 'image/svg+xml')
                    except Exception:
                        return self.reply(500, b'QR generation failed')
                elif action_file == '':
                    try:
                        qr_svg = subprocess.run(['qrencode', '-t', 'SVG', '-o', '-'], input=uri.encode(), capture_output=True, check=True).stdout.decode('utf-8')
                    except Exception:
                        qr_svg = ''
                    server_name = m.get('server_name') or m.get('public_ip', 'localhost')
                    host = m.get('public_ip', server_name) if m.get('is_insecure') else server_name
                    listen_port = m.get('listen_port', 19984)
                    obfs_badge = "Salamander" if m.get('obfs_password') else "QUIC"
                    page = user_page_html(server_name, host, listen_port, obfs_badge, target_uid, u_copy, uri, clash_yaml, sing_json, qr_svg, data['token'], expected_k)
                    return self.reply(200, page.encode('utf-8'), 'text/html; charset=utf-8')
                else:
                    return self.reply(404, b'Not found')

            # 2. 版本检查与更新 API
            if subpath == 'traffic-speed':
                if not self.is_authenticated():
                    return self.reply_json(401, {'ok': False, 'error': 'Unauthorized'})
                cur_mono = time.monotonic()
                total_rx_speed = 0.0
                total_tx_speed = 0.0
                user_speeds = {}

                with data_lock:
                    for uid, samples in list(speed_tracker.items()):
                        # 过滤 6 秒内的样本
                        recent = [(t, tx, rx) for (t, tx, rx) in samples if cur_mono - t <= 6]
                        speed_tracker[uid] = recent
                        if not recent:
                            user_speeds[uid] = {'tx': 0, 'rx': 0}
                            continue

                        sum_tx = sum(tx for _, tx, _ in recent)
                        sum_rx = sum(rx for _, _, rx in recent)
                        dt = max(recent[-1][0] - recent[0][0], 1.0) if len(recent) > 1 else 3.0
                        u_tx_speed = sum_tx / dt
                        u_rx_speed = sum_rx / dt

                        total_tx_speed += u_tx_speed
                        total_rx_speed += u_rx_speed
                        user_speeds[uid] = {'tx': u_tx_speed, 'rx': u_rx_speed}

                return self.reply_json(200, {
                    'ok': True,
                    'node_tx': total_tx_speed,
                    'node_rx': total_rx_speed,
                    'users': user_speeds
                })

            if subpath == 'proxy-services':
                if not self.is_authenticated():
                    return self.reply_json(401, {'ok': False, 'error': 'Unauthorized'})
                with data_lock:
                    services = list(data.get('proxy_services', []))
                m = json.loads(meta_path.read_text()) if meta_path.exists() else {}
                host = m.get('public_ip', '127.0.0.1') if m.get('is_insecure') else m.get('server_name', 'localhost')
                return self.reply_json(200, {
                    'ok': True,
                    'gost_installed': Path('/usr/local/bin/gost').exists(),
                    'gost_active': gost_status(),
                    'host': host,
                    'services': services
                })

            if subpath == 'check-version':
                if not self.is_authenticated():
                    return self.reply_json(401, {'ok': False, 'error': 'Unauthorized'})
                import urllib.request
                core_curr = '未知'
                core_latest = '未知'
                core_has_update = False
                portal_curr = '2026.09.21'
                portal_has_update = False

                try:
                    # 获取本地核心版本 (按行精确匹配 Version: 前缀，避免被字符艺术 LOGO 干扰)
                    out = subprocess.run(['/usr/local/bin/hysteria', 'version'], capture_output=True, text=True, timeout=2).stdout
                    if out:
                        for line in out.splitlines():
                            if line.strip().startswith('Version:'):
                                core_curr = line.split(':', 1)[1].strip().lstrip('v')
                                break
                except Exception:
                    pass

                try:
                    # 从 GitHub 获取官方最新版本
                    req = urllib.request.Request('https://api.github.com/repos/apernet/hysteria/releases/latest',
                                                 headers={'User-Agent': 'hysteria2-installer'})
                    with urllib.request.urlopen(req, timeout=3) as resp:
                        if resp.status == 200:
                            rel = json.loads(resp.read().decode('utf-8'))
                            core_latest = rel.get('tag_name', '').lstrip('app/v').lstrip('v')
                            if core_curr != '未知' and core_latest and core_curr != core_latest:
                                core_has_update = True
                except Exception:
                    pass

                try:
                    # 检查面板是否有新提交
                    req2 = urllib.request.Request('https://api.github.com/repos/yys9253462-gif/hysteria2-installer/commits/main',
                                                  headers={'User-Agent': 'hysteria2-installer'})
                    with urllib.request.urlopen(req2, timeout=3) as resp2:
                        if resp2.status == 200:
                            commit_info = json.loads(resp2.read().decode('utf-8'))
                            remote_sha = commit_info.get('sha', '')[:7]
                            local_sha = data.get('portal_sha', '')
                            if local_sha and remote_sha and local_sha != remote_sha:
                                portal_has_update = True
                except Exception:
                    pass

                return self.reply_json(200, {
                    'ok': True,
                    'core_current': core_curr,
                    'core_latest': core_latest,
                    'core_has_update': core_has_update,
                    'portal_current': portal_curr,
                    'portal_has_update': portal_has_update
                })

            if subpath == 'reality-status':
                if not self.is_authenticated():
                    return self.reply_json(401, {'ok': False, 'error': 'Unauthorized'})
                is_installed = Path('/usr/local/bin/xray').exists()
                is_active = False
                if is_installed:
                    try:
                        out = subprocess.run(['systemctl', 'is-active', 'xray'], capture_output=True, text=True, timeout=3).stdout.strip()
                        is_active = (out == 'active')
                    except Exception:
                        is_active = False

                with data_lock:
                    rcfg = dict(data.get('reality_config', {}))
                
                qr_svg = ''
                if rcfg.get('uri'):
                    try:
                        qr_res = subprocess.run(['qrencode', '-t', 'SVG', '-o', '-'],
                                                input=rcfg['uri'].encode('utf-8'), capture_output=True, timeout=3)
                        if qr_res.returncode == 0:
                            qr_svg = qr_res.stdout.decode('utf-8')
                    except Exception:
                        qr_svg = ''

                return self.reply_json(200, {
                    'ok': True,
                    'installed': is_installed,
                    'active': is_active,
                    'config': {
                        'uri': rcfg.get('uri', ''),
                        'uuid': rcfg.get('uuid', ''),
                        'pub_key': rcfg.get('public_key', ''),
                        'short_id': rcfg.get('short_id', ''),
                        'flow': 'xtls-rprx-vision',
                        'sni': rcfg.get('dest_sni', 'www.apple.com'),
                        'port': rcfg.get('port', 443),
                        'qr_svg': qr_svg
                    }
                })

            if subpath == 'bbr-status':
                if not self.is_authenticated():
                    return self.reply_json(401, {'ok': False, 'error': 'Unauthorized'})
                try:
                    import platform
                    kernel_ver = platform.release()
                    cc_out = subprocess.run(['sysctl', '-n', 'net.ipv4.tcp_congestion_control'],
                                            capture_output=True, text=True, timeout=2).stdout.strip()
                    qdisc_out = subprocess.run(['sysctl', '-n', 'net.core.default_qdisc'],
                                              capture_output=True, text=True, timeout=2).stdout.strip()
                    
                    conf_path = Path('/etc/sysctl.d/99-bbr.conf')
                    configured_bbr = ''
                    if conf_path.exists():
                        c_text = conf_path.read_text(encoding='utf-8')
                        for line in c_text.splitlines():
                            if 'tcp_congestion_control' in line and '=' in line:
                                configured_bbr = line.split('=')[1].strip()

                    need_reboot = False
                    if configured_bbr and configured_bbr != cc_out:
                        need_reboot = True

                    with data_lock:
                        target_ver = data.get('bbr_target_version', '')

                    return self.reply_json(200, {
                        'ok': True,
                        'current': cc_out or 'cubic',
                        'qdisc': qdisc_out or 'fq_codel',
                        'kernel': kernel_ver,
                        'configured': configured_bbr or target_ver or cc_out,
                        'need_reboot': need_reboot
                    })
                except Exception as e:
                    return self.reply_json(500, {'ok': False, 'error': str(e)})

            if subpath == 'warp-status':
                if not self.is_authenticated():
                    return self.reply_json(401, {'ok': False, 'error': 'Unauthorized'})
                with data_lock:
                    enabled = data.get('warp_enabled', False)
                    rules = list(data.get('warp_rules', [
                        'ipify.org', 'cloudflare.com',
                        'openai.com', 'chatgpt.com', 'oaistatic.com', 'oaiusercontent.com', 'ai.com',
                        'anthropic.com', 'claude.ai',
                        'gemini.google.com', 'aistudio.google.com', 'generativelanguage.googleapis.com'
                    ]))
                import shutil
                # 统一到 wgcf + wireproxy(127.0.0.1:19898)；同时兼容尚未升级、
                # 仍跑官方 cloudflare-warp(127.0.0.1:40000) 的旧节点，避免误报「未安装」
                is_installed = (shutil.which('wireproxy') is not None
                                or shutil.which('warp-cli') is not None
                                or Path('/etc/systemd/system/wireproxy.service').exists())
                connected = False
                outbound_ip = ''
                if is_installed and enabled:
                    for warp_addr in ('127.0.0.1:19898', '127.0.0.1:40000'):
                        try:
                            import urllib.request
                            proxy_handler = urllib.request.ProxyHandler({'http': 'socks5h://' + warp_addr,
                                                                         'https': 'socks5h://' + warp_addr})
                            opener = urllib.request.build_opener(proxy_handler)
                            req = urllib.request.Request('https://api4.ipify.org', headers={'User-Agent': 'curl/7.88.1'})
                            with opener.open(req, timeout=3) as resp:
                                if resp.status == 200:
                                    outbound_ip = resp.read().decode('utf-8').strip()
                                    connected = True
                                    break
                        except Exception:
                            connected = False
                return self.reply_json(200, {
                    'ok': True,
                    'installed': is_installed,
                    'enabled': enabled,
                    'connected': connected,
                    'ip': outbound_ip,
                    'rules': rules
                })

            if subpath == 'user-config' or subpath.startswith('user-config?'):
                if not self.is_authenticated():
                    return self.reply_json(401, {'ok': False, 'error': 'Unauthorized'})
                query = parse_qs(self.path.split('?', 1)[1]) if '?' in self.path else {}
                target_uid = query.get('user_id', [''])[0].strip()
                if not VALID_USER_ID_RE.match(target_uid):
                    return self.reply_json(400, {'ok': False, 'error': 'Invalid user_id format'})
                with data_lock:
                    u = data.get('users', {}).get(target_uid)
                    if not u:
                        return self.reply_json(404, {'ok': False, 'error': 'User not found'})
                    u_copy = dict(u)

                m = json.loads(meta_path.read_text()) if meta_path.exists() else {}
                pwd = u_copy.get('password', '')
                uri, clash_yaml, sing_json = artifacts(m, auth_override=pwd, name_override=f"Hy2-{target_uid}")
                qr_svg = ""
                try:
                    qr_svg = subprocess.run(['qrencode', '-t', 'SVG', '-o', '-'], input=uri.encode(), capture_output=True, check=True).stdout.decode('utf-8')
                except Exception:
                    pass

                return self.reply_json(200, {
                    'ok': True,
                    'user_id': target_uid,
                    'note': u_copy.get('note', ''),
                    'uri': uri,
                    'clash': clash_yaml,
                    'sing_box': sing_json,
                    'qr_svg': qr_svg,
                    'expires_at': u_copy.get('expires_at', 0),
                    'traffic_used': u_copy.get('used_bytes', 0),
                    'traffic_limit': u_copy.get('limit_bytes', 0),
                    'ip_limit': u_copy.get('ip_limit', 0),
                })

            # ---------------- AmneziaWG (AWG) ----------------
            if subpath == 'awg-state':
                if not self.is_authenticated():
                    return self.reply_json(401, {'ok': False, 'error': 'Unauthorized'})
                return self.reply_json(200, awg_state())

            # 注意：这里的 subpath 是含查询串的（门户上游就是这么切分的），
            # 所以必须先剥掉 ?query 再比对，否则带 ?name= 的路由永远匹配不上。
            awg_route = subpath.split('?', 1)[0]
            if awg_route in ('awg-conf', 'awg-qr.svg'):
                if not self.is_authenticated():
                    return self.reply(401, b'Authentication required', www_auth=True)
                query = parse_qs(self.path.split('?', 1)[1]) if '?' in self.path else {}
                name = (query.get('name', [''])[0] or '').strip()
                if not VALID_AWG_NAME_RE.match(name):
                    return self.reply(400, b'Invalid client name')
                if not awg_installed():
                    return self.reply(404, b'AmneziaWG is not installed')
                if not ensure_awgctl():
                    return self.reply(500, b'hy2-awgctl unavailable')

                # 连接地址优先用查询参数，其次用安装时记录的 endpoint
                endpoint = (query.get('endpoint', [''])[0] or '').strip() or awg_state()['endpoint']
                if not endpoint:
                    return self.reply(400, b'Endpoint not configured; re-run install with an endpoint')

                try:
                    rc, out, err = awg_run(['client-conf', name, '--endpoint', endpoint], timeout=60)
                except Exception as exc:
                    return self.reply(500, ('error: ' + str(exc)).encode('utf-8'))
                if rc != 0 or not out.strip():
                    return self.reply(500, awg_err_tail(rc, out, err, 400).encode('utf-8'))

                if awg_route == 'awg-conf':
                    body = out.encode('utf-8')
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/plain; charset=utf-8')
                    self.send_header('Content-Disposition', 'attachment; filename="' + name + '.conf"')
                    self.send_header('Content-Length', str(len(body)))
                    self.send_header('Cache-Control', 'no-store')
                    self.send_header('X-Content-Type-Options', 'nosniff')
                    self.send_header('X-Robots-Tag', 'noindex, nofollow, noarchive')
                    self.send_header('Connection', 'close')
                    self.end_headers()
                    self.wfile.write(body)
                    try:
                        self.wfile.flush()
                    except Exception:
                        pass
                    try:
                        self.connection.shutdown(socket.SHUT_WR)
                    except Exception:
                        pass
                    return

                # 二维码走与门户其它二维码相同的实现（qrencode 直接输出 SVG）
                try:
                    qr_bytes = subprocess.run(['qrencode', '-t', 'SVG', '-o', '-'],
                                              input=out.encode('utf-8'),
                                              capture_output=True, check=True, timeout=20).stdout
                except Exception:
                    return self.reply(500, b'qrencode is not available on this server')
                return self.reply(200, qr_bytes, 'image/svg+xml')

            if not self.is_authenticated():
                if is_client_api:
                    self.record_failure()
                    return self.reply(401, b'Authentication required', www_auth=True)
                page = login_html(data['token'])
                return self.reply(200, page.encode('utf-8'), 'text/html; charset=utf-8')

            if subpath == '':
                regenerate_page()

            routes = {'': ('page', 'text/html; charset=utf-8'), 'qr.svg': ('qr', 'image/svg+xml'),
                      'clash.yaml': ('clash', 'application/yaml'), 'sing-box.json': ('sing', 'application/json')}
            route = routes.get(subpath)
            if route is None:
                return self.reply(404, b'Not found')
            key, mime = route
            with data_lock:
                content = data[key].encode()
            self.reply(200, content, mime)

        def reply(self, code, body, mime='text/plain', www_auth=False):
            self.send_response(code)
            self.send_header('Content-Type', mime)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('X-Frame-Options', 'DENY')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.send_header('X-Robots-Tag', 'noindex, nofollow, noarchive')
            self.send_header('Content-Security-Policy', content_policy())
            # BUGFIX portal hang: 强制 Connection: close, HTTP server 处理完即关闭 TCP
            self.send_header('Connection', 'close')
            if www_auth:
                self.send_header('WWW-Authenticate', 'Basic realm="Private", charset="UTF-8"')
            if code == 429:
                self.send_header('Retry-After', '60')
            self.end_headers()
            self.wfile.write(body)
            try:
                self.wfile.flush()
            except Exception:
                pass
            try:
                self.connection.shutdown(socket.SHUT_WR)
            except Exception:
                pass

    class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
        daemon_threads = True

    server = ThreadingHTTPServer(('127.0.0.1', data['port']), Handler)
    server.requests, server.failures, server.api_requests = [], [], []
    server.serve_forever()


if __name__ == '__main__':
    if sys.argv[1] == 'prepare':
        api_key = sys.argv[4] if len(sys.argv) > 4 else None
        prepare(sys.argv[2], sys.argv[3], api_key)
    elif sys.argv[1] == 'refresh':
        refresh(sys.argv[2])
    else:
        serve(sys.argv[2])
PYPORTAL
}

refresh_portal() {
    [[ -f "$HY2_DIR/portal.json" && -f "$HY2_DIR/portal-access.json" ]] || { log_err "未找到已有网页配置，请先安装。"; return 1; }
    write_portal_program
    chmod 644 "$HY2_DIR/portal.py"
    python3 "$HY2_DIR/portal.py" refresh "$HY2_META_FILE"
    systemctl restart hysteria-portal
    log_info "网页已更新，节点参数和登录凭据保持不变。"
}

setup_portal() {
    write_portal_program
    python3 "$HY2_DIR/portal.py" prepare "$HY2_META_FILE" "$PORTAL_LOCAL_PORT" "$NODE_API_KEY"
    cat > /etc/systemd/system/hysteria-portal.service <<EOF
[Unit]
Description=Private HY2 information page (loopback only)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${HY2_DIR}
ExecStart=/usr/bin/python3 ${HY2_DIR}/portal.py serve ${HY2_DIR}/portal.json
Restart=always
RestartSec=3
UMask=0077

[Install]
WantedBy=multi-user.target
EOF
    chmod 755 "$HY2_DIR"
    chmod 644 "$HY2_DIR/portal.py"
    chmod 600 "$HY2_DIR/portal.json" "$HY2_DIR/portal-access.json" "$HY2_META_FILE" "$HY2_CONFIG"
    systemctl daemon-reload
    systemctl enable hysteria-portal >/dev/null
    systemctl restart hysteria-portal
    sleep 1
    systemctl is-active --quiet hysteria-portal || { log_err "信息页服务启动失败"; return 1; }
}

# 7. 服务状态与管理命令
install_warp_local_proxy() {
    # BUGFIX #7/#8: Cloudflare 官方 cloudflare-warp 包在 Debian 12 / bookworm 因 signed-by
    # apt keyring 解析 bug 永远装不上，且失败会残留无效 apt 源。改为直接从 GitHub release
    # 拉 wgcf + wireproxy 二进制，匿名注册 Warp 设备，wireproxy 起 socks5 监听，配置
    # hysteria outbound 复用。整个流程无需 apt / 任何用户交互，失败时清理临时文件。
    log_step "准备安装 Cloudflare WARP Local Proxy (wgcf + wireproxy · socks5 端口 19898)..."

    if ! command -v curl >/dev/null 2>&1 || ! command -v jq >/dev/null 2>&1; then
        install_dependencies
    fi

    case "$HY2_ARCH" in
        # 注意 wireproxy 的 armv7 asset 实际叫 wireproxy_linux_arm.tar.gz（不是 armv7）
        amd64)  WGCF_ARCH="amd64";  WP_ARCH="amd64"  ;;
        arm64)  WGCF_ARCH="arm64";  WP_ARCH="arm64"  ;;
        armv7)  WGCF_ARCH="armv7";  WP_ARCH="arm"    ;;
        *) log_err "WARP 不支持当前 CPU 架构: ${HY2_ARCH}"; return 1 ;;
    esac

    WGCF_BIN="/usr/local/bin/wgcf"
    WGCF_DIR="/etc/wireguard"
    WGCF_CONF="${WGCF_DIR}/wgcf.conf"
    WGCF_ACCT="${WGCF_DIR}/wgcf-account.toml"
    WP_BIN="/usr/local/bin/wireproxy"
    WARP_SOCKS_PORT=19898
    WARP_SOCKS_ADDR="127.0.0.1:${WARP_SOCKS_PORT}"

    # 1. 下载 wgcf (匿名注册 WARP 设备)
    if [[ ! -x "$WGCF_BIN" ]]; then
        log_step "下载 wgcf 二进制..."
        # 动态探测最新 release + asset 名 (避免硬编码版本号失效)
        RAW=$(curl -fsSL --max-time 20 https://api.github.com/repos/ViRb3/wgcf/releases/latest 2>/dev/null || true)
        if command -v jq >/dev/null 2>&1; then
            WGCF_TAG=$(printf '%s' "$RAW" | jq -r '.tag_name // empty' 2>/dev/null || true)
        else
            WGCF_TAG=$(printf '%s' "$RAW" | grep -o '"tag_name": *"[^"]*"' | head -1 | cut -d'"' -f4)
        fi
        WGCF_VER="${WGCF_TAG#v}"
        [[ -z "$WGCF_VER" || "$WGCF_VER" == "null" ]] && WGCF_VER="2.3.0"
        WGCF_DL="wgcf_${WGCF_VER}_linux_${WGCF_ARCH}"
        WGCF_URL="https://github.com/ViRb3/wgcf/releases/download/v${WGCF_VER}/${WGCF_DL}"
        log_info "目标 wgcf 版本: v${WGCF_VER}"
        if ! curl -fsSL -o "$WGCF_BIN.tmp" "$WGCF_URL"; then
            rm -f "$WGCF_BIN.tmp"
            log_err "wgcf 下载失败 ($WGCF_URL), 请检查网络或版本号"
            return 1
        fi
        install -m 755 "$WGCF_BIN.tmp" "$WGCF_BIN"
        rm -f "$WGCF_BIN.tmp"
    fi

    # 2. 下载 wireproxy (把 WireGuard 配置转成 socks5 代理)
    if [[ ! -x "$WP_BIN" ]]; then
        log_step "下载 wireproxy 二进制..."
        RAW=$(curl -fsSL --max-time 20 https://api.github.com/repos/whyvl/wireproxy/releases/latest 2>/dev/null || true)
        if command -v jq >/dev/null 2>&1; then
            WP_TAG=$(printf '%s' "$RAW" | jq -r '.tag_name // empty' 2>/dev/null || true)
        else
            WP_TAG=$(printf '%s' "$RAW" | grep -o '"tag_name": *"[^"]*"' | head -1 | cut -d'"' -f4)
        fi
        WP_VER="${WP_TAG#v}"
        [[ -z "$WP_VER" || "$WP_VER" == "null" ]] && WP_VER="1.1.3"
        # wireproxy 不同版本命名约定不同 (有的 wireproxy-VER-linux-ARCH, 有的 wireproxy_linux_ARCH.tar.gz)
        # 优先尝试 tar.gz 格式 (因为 wireproxy 实际是单文件 + 不会变)
        WP_URL="https://github.com/whyvl/wireproxy/releases/download/${WP_TAG}/wireproxy_linux_${WP_ARCH}.tar.gz"
        log_info "目标 wireproxy 版本: ${WP_TAG}"
        TMP_TGZ=$(mktemp)
        if ! curl -fsSL -o "$TMP_TGZ" "$WP_URL"; then
            rm -f "$TMP_TGZ"
            log_err "wireproxy 下载失败 ($WP_URL)"
            return 1
        fi
        TMP_EXTRACT=$(mktemp -d)
        tar -xzf "$TMP_TGZ" -C "$TMP_EXTRACT" 2>/dev/null
        WP_SRC=$(find "$TMP_EXTRACT" -name wireproxy -type f -executable 2>/dev/null | head -1)
        if [[ -z "$WP_SRC" ]]; then
            # 兜底: 如果解压出来的不是 wireproxy 而是 wireproxy_linux_amd64 等
            WP_SRC=$(find "$TMP_EXTRACT" -type f -executable 2>/dev/null | head -1)
        fi
        if [[ -z "$WP_SRC" ]]; then
            log_err "wireproxy 解压失败，找不到可执行文件"
            rm -rf "$TMP_TGZ" "$TMP_EXTRACT"
            return 1
        fi
        install -m 755 "$WP_SRC" "$WP_BIN"
        rm -rf "$TMP_TGZ" "$TMP_EXTRACT"
    fi

    # 3. 匿名注册 WARP 设备 (一次性)
    mkdir -p "$WGCF_DIR"
    # BUGFIX: wgcf generate 输出的 wgcf-profile.conf 总是写到 $HOME 不受 --config 控制,
    # 必须先 cd 到目标目录再用相对路径生成
    if [[ ! -f "$WGCF_ACCT" ]]; then
        log_step "匿名注册 Cloudflare WARP 设备 (无邮件/验证码)..."
        if ! "$WGCF_BIN" --config "$WGCF_ACCT" register --accept-tos >/tmp/wgcf-register.log 2>&1; then
            log_err "WARP 匿名注册失败，请查看 /tmp/wgcf-register.log"
            return 1
        fi
    fi
    if [[ ! -f "$WGCF_CONF" ]]; then
        # cd 到 /etc/wireguard/ 后, generate 输出的 wgcf-profile.conf 也会在这里
        if ! (cd "$WGCF_DIR" && "$WGCF_BIN" --config "$WGCF_ACCT" generate >/tmp/wgcf-generate.log 2>&1); then
            log_err "WARP 配置生成失败，请查看 /tmp/wgcf-generate.log"
            return 1
        fi
    fi
    # 把 $HOME 残留的 wgcf-profile.conf 移过来 (兼容老版本 wgcf 行为)
    if [[ ! -f "$WGCF_CONF" && -f "/root/wgcf-profile.conf" ]]; then
        mv /root/wgcf-profile.conf "$WGCF_CONF"
    fi
    # 兜底: generate 输出文件名是 wgcf-profile.conf, 重命名为 wgcf.conf 便于脚本后续解析
    if [[ -f "${WGCF_DIR}/wgcf-profile.conf" && ! -f "$WGCF_CONF" ]]; then
        mv "${WGCF_DIR}/wgcf-profile.conf" "$WGCF_CONF"
    fi

    # 4. 生成 wireproxy 配置 (只暴露 socks5 在 127.0.0.1)
    WP_CFG="/etc/wireguard/wp.conf"
    WG_PRIV=$(awk '/^PrivateKey/{print $3; exit}' "$WGCF_CONF")
    WG_PUB=$(awk -F'= ' '/^PublicKey/{print $2; exit}' "$WGCF_CONF" | tr -d '
')
    WG_EP=$(awk -F'= ' '/^Endpoint/{print $2; exit}' "$WGCF_CONF" | tr -d '
')
    cat > "$WP_CFG" <<EOF
# wireproxy config (managed by hysteria2-installer, do not edit)
[Interface]
Address = 172.16.0.2/32
PrivateKey = ${WG_PRIV}
DNS = 1.1.1.1

[Peer]
PublicKey = ${WG_PUB}
Endpoint = ${WG_EP}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25

[Socks5]
BindAddress = 127.0.0.1:${WARP_SOCKS_PORT}
EOF
    chmod 600 "$WP_CFG"

    # 5. wireproxy systemd 守护
    cat > /etc/systemd/system/wireproxy.service <<EOF
[Unit]
Description=WireProxy (Cloudflare WARP SOCKS5)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${WP_BIN} -c ${WP_CFG}
Restart=on-failure
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now wireproxy >/dev/null 2>&1 || true
    sleep 3

    # 6. 探活 wireproxy socks5
    if curl --proxy socks5h://"$WARP_SOCKS_ADDR" --silent --fail --max-time 8 https://api4.ipify.org >/dev/null 2>&1; then
        log_info "WARP socks5 探活成功 (上游出口 IP 已切换)"
    else
        log_warn "WARP socks5 探活失败 (可能上游封禁或 NAT 类型受限), 服务已启动但需手动验证"
    fi

    # 7. 把 hysteria config.yaml 的 outbound warp_socks 端口同步到 19898
    if [[ -f "$HY2_CONFIG" ]]; then
        sed -i "s|addr: 127.0.0.1:40000|addr: ${WARP_SOCKS_ADDR}|g" "$HY2_CONFIG"
        systemctl restart hysteria-server 2>/dev/null || true
    fi

    # 8. Watchdog (走 WARP socks5 探活, 失败则重启 wireproxy)
    cat > /usr/local/bin/hy2-warp-watchdog.sh <<EOWD
#!/usr/bin/env bash
set -u
TEST_URL="https://api4.ipify.org"
if ! curl --proxy socks5h://${WARP_SOCKS_ADDR} --silent --fail --max-time 6 "\$TEST_URL" >/dev/null 2>&1; then
    logger -t hy2-warp-watchdog "WARP local proxy failed. Restarting wireproxy..."
    systemctl restart wireproxy >/dev/null 2>&1 || true
fi
EOWD
    chmod 755 /usr/local/bin/hy2-warp-watchdog.sh

    cat > /etc/systemd/system/hy2-warp-watchdog.service <<EOF
[Unit]
Description=Cloudflare WARP Watchdog for Hysteria 2
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/hy2-warp-watchdog.sh
EOF

    cat > /etc/systemd/system/hy2-warp-watchdog.timer <<EOF
[Unit]
Description=Run WARP Watchdog every 3 minutes

[Timer]
OnBootSec=1min
OnUnitActiveSec=3min
Unit=hy2-warp-watchdog.service

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable --now hy2-warp-watchdog.timer >/dev/null 2>&1 || true

    # 统一出口：机器上若还残留官方 cloudflare-warp 客户端，停用避免两套 WARP 并存打架
    if systemctl list-unit-files 2>/dev/null | grep -q '^warp-svc'; then
        log_info "检测到旧的 cloudflare-warp (warp-svc)，已停用并禁用（统一走 wireproxy 19898）"
        systemctl disable --now warp-svc >/dev/null 2>&1 || true
    fi

    log_info "Cloudflare WARP Local Proxy (wgcf+wireproxy) 与 3 分钟探活 Watchdog 安装完成！"
    log_info "你现在可以在 Web 控制台一键启闭 AI 专线分流。"
}

# 安装 gost 入站代理引擎 (SOCKS5 / HTTP / HTTPS 三种协议)
install_gost() {
    log_step "准备安装 gost 入站代理引擎 (SOCKS5/HTTP/HTTPS)..."
    GOST_BIN="/usr/local/bin/gost"
    GOST_CONFIG="${HY2_DIR}/gost.yml"

    # 获取最新版本
    GOST_LATEST=$(curl -s --max-time 15 https://api.github.com/repos/go-gost/gost/releases/latest | jq -r '.tag_name // empty')
    if [[ -z "$GOST_LATEST" || "$GOST_LATEST" == "null" ]]; then
        GOST_LATEST="v3.3.0"
    fi
    GOST_VER="${GOST_LATEST#v}"

    # gost 资产命名固定为 gost_<版本号>_linux_<架构>.tar.gz
    case "$HY2_ARCH" in
        amd64) GOST_ASSET="linux_amd64" ;;
        arm64) GOST_ASSET="linux_arm64" ;;
        armv7) GOST_ASSET="linux_armv7" ;;
        *) log_err "gost 暂不支持当前 CPU 架构: ${HY2_ARCH}"; return 1 ;;
    esac

    DOWNLOAD_URL="https://github.com/go-gost/gost/releases/download/${GOST_LATEST}/gost_${GOST_VER}_${GOST_ASSET}.tar.gz"
    log_info "目标版本: ${GOST_LATEST} (${GOST_ASSET})"
    log_step "下载并解压 gost 二进制..."
    TMP_DIR=$(mktemp -d)
    if ! curl -fL --progress-bar "$DOWNLOAD_URL" -o "$TMP_DIR/gost.tar.gz"; then
        rm -rf "$TMP_DIR"
        log_err "gost 下载失败，请检查网络连接。"
        return 1
    fi
    tar -xzf "$TMP_DIR/gost.tar.gz" -C "$TMP_DIR"
    find "$TMP_DIR" -name gost -type f -exec install -m 755 {} "$GOST_BIN" \;
    rm -rf "$TMP_DIR"
    if [[ ! -f "$GOST_BIN" ]]; then
        log_err "gost 二进制解压失败。"
        return 1
    fi

    # 生成 HTTPS 代理专用自签证书 (若不存在)
    GOST_CERT_DIR="${HY2_DIR}/gost-cert"
    mkdir -p "$GOST_CERT_DIR"
    if [[ ! -f "$GOST_CERT_DIR/cert.pem" ]]; then
        openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
            -keyout "$GOST_CERT_DIR/key.pem" -out "$GOST_CERT_DIR/cert.pem" \
            -days 3650 -subj "/CN=gost-proxy" >/dev/null 2>&1
    fi

    # 生成初始配置（services 由 Web 控制台动态管理）
    if [[ ! -f "$GOST_CONFIG" ]]; then
        cat > "$GOST_CONFIG" <<'EOF'
# gost 入站代理配置（由 Web 控制台动态管理，勿手动编辑）
services: []
EOF
    fi

    # 创建 systemd 守护服务（支持 SIGHUP 热重载）
    cat > /etc/systemd/system/gost.service <<EOF
[Unit]
Description=GOST Proxy Service (SOCKS5/HTTP/HTTPS inbound)
After=network.target

[Service]
Type=simple
ExecStart=${GOST_BIN} -C ${GOST_CONFIG}
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable gost >/dev/null 2>&1
    systemctl restart gost
    sleep 1
    if systemctl is-active --quiet gost; then
        log_info "gost 入站代理引擎安装成功！现在可在 Web 控制台添加 SOCKS5/HTTP/HTTPS 代理账号。"
    else
        log_warn "gost 已安装，服务暂未启动（尚无代理配置，添加代理账号后自动生效）。"
    fi
}

# ==============================================================================
# AmneziaWG (AWG) —— 抗 DPI 的 WireGuard 分支
# ------------------------------------------------------------------------------
# 本项目坚持"下载静态二进制 + systemd"的部署模型，因此 AmneziaWG 走【用户态】路线：
# 不编译内核模块、不引入 Docker。数据面用上游 amneziawg-go，工具用 amneziawg-tools，
# 二者由本仓库的 GitHub Actions 交叉编译后发布到 Release（见
# .github/workflows/build-awg.yml），amd64 / arm64 / armv7 全架构静态链接。
#
# 为什么不用内核模块：
#   1. 官方 PPA 只发布 Ubuntu 包，Debian 上要强塞 Ubuntu 源，脏且易碎；
#   2. 手工编译模块要求 5.6+ 内核提供【完整内核源码树】（不是 headers）；
#   3. 内核模块在宿主内核升级后需要 DKMS 重建，失败会影响系统启动。
#
# ⚠️ 端口必须避开 Hysteria2 的端口跳跃区间 20000-40000 —— 那段 UDP 已被
#    iptables REDIRECT 到 Hysteria 主端口，落在里面的 AWG 端口收不到握手包。
#    同时避开 51820（WireGuard 默认端口本身就是个弱指纹）。
#
# 具体逻辑全部收敛在 awgctl.sh（安装为 /usr/local/bin/hy2-awgctl），
# 这样命令行菜单与 Web 门户共用同一套实现，不会出现两份配置生成逻辑漂移。
# ==============================================================================

# 确保 hy2-awgctl 就位。优先用与 install.sh 同目录的 awgctl.sh（本地克隆场景），
# 否则从仓库拉取。注意本脚本常以 `bash <(curl ...)` 方式运行，此时 BASH_SOURCE
# 指向 /dev/fd/NN，不是真实文件，所以必须做存在性判断。
awg_ensure_ctl() {
    if [[ -x "$AWG_CTL_BIN" ]]; then
        return 0
    fi

    local src="" dir=""
    if [[ -n "${BASH_SOURCE[0]:-}" && -f "${BASH_SOURCE[0]}" ]]; then
        dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)" || dir=""
        if [[ -n "$dir" && -f "${dir}/awgctl.sh" ]]; then
            src="${dir}/awgctl.sh"
        fi
    fi

    local tmp=""
    if [[ -z "$src" ]]; then
        tmp="$(mktemp)"
        if curl -fsSL --max-time 30 \
             "https://raw.githubusercontent.com/${AWG_REPO}/main/awgctl.sh" -o "$tmp" 2>/dev/null; then
            src="$tmp"
        else
            rm -f "$tmp"
            log_err "无法获取 awgctl.sh（本地不存在，且从仓库下载失败）"
            return 1
        fi
    fi

    if ! install -m 0755 "$src" "$AWG_CTL_BIN"; then
        if [[ -n "$tmp" ]]; then
            rm -f "$tmp"
        fi
        log_err "安装 ${AWG_CTL_BIN} 失败"
        return 1
    fi
    if [[ -n "$tmp" ]]; then
        rm -f "$tmp"
    fi
    log_info "已安装 AmneziaWG 控制工具: ${AWG_CTL_BIN}"
    return 0
}

# 推断客户端连接地址。
# 自签证书模式下的 server_name 是伪装用的 SNI（如 www.bing.com），
# 绝不能拿来当连接地址，必须回退到公网 IP。
awg_suggest_endpoint() {
    local sn="" ip="" insecure=""
    if [[ -f "$HY2_META_FILE" ]]; then
        sn="$(jq -r '.server_name // empty'  "$HY2_META_FILE" 2>/dev/null || true)"
        ip="$(jq -r '.public_ip // empty'    "$HY2_META_FILE" 2>/dev/null || true)"
        insecure="$(jq -r '.is_insecure // empty' "$HY2_META_FILE" 2>/dev/null || true)"
    fi
    if [[ -z "$ip" ]]; then
        ip="${PUBLIC_IP:-}"
    fi
    if [[ "$insecure" == "true" ]]; then
        echo "$ip"
        return 0
    fi
    if [[ -n "$sn" && "$sn" != "$ip" && "$sn" != "www.bing.com" ]]; then
        echo "$sn"
    else
        echo "$ip"
    fi
}

# 读取当前已安装的协议线
awg_current_line() {
    local v="3"
    if [[ -f "$AWG_META_FILE" ]]; then
        v="$(jq -r '.line // "3"' "$AWG_META_FILE" 2>/dev/null || echo 3)"
    fi
    if [[ "$v" != "2" && "$v" != "3" ]]; then
        v="3"
    fi
    echo "$v"
}

awg_is_installed() {
    [[ -f "$AWG_CONFIG" && -x /usr/local/bin/amneziawg-go ]]
}

# ------------------------------------------------ 交互式安装
install_amneziawg() {
    check_root
    check_arch
    echo -e "\n${CYAN}------------------------------------------------------------${PLAIN}"
    echo -e "${GREEN}AmneziaWG (AWG) 安装配置：${PLAIN}"
    echo -e "${CYAN}------------------------------------------------------------${PLAIN}"
    echo -e "AmneziaWG 是 WireGuard 的抗 DPI 分支：密码学内核不变，"
    echo -e "只把数据包的头部、长度、时序特征随机化，让审查设备无法指纹识别。"
    echo ""

    if ! command -v curl >/dev/null 2>&1 || ! command -v jq >/dev/null 2>&1; then
        install_dependencies
    fi
    if ! awg_ensure_ctl; then
        return 1
    fi

    local already="no"
    if awg_is_installed; then
        already="yes"
        local cur
        cur="$(awg_current_line)"
        log_warn "检测到本机已安装 AmneziaWG（当前协议线 AWG ${cur}.x）。"
        log_warn "重装会保留现有密钥与客户端列表；但如果更换协议线，"
        log_warn "所有已发放的客户端配置都会失效，必须重新导出。"
        echo ""
    fi

    # --- 协议线 ---
    local def_line cur_line line_choice line
    cur_line="$(awg_current_line)"
    if [[ "$already" == "yes" ]]; then
        def_line="$cur_line"
    else
        def_line="3"
    fi
    echo -e "请选择 AmneziaWG 协议线："
    echo -e "  ${GREEN}1.${PLAIN} AWG 3.x  (最新：头部保护 + 时序随机化，抗连接行为分析)"
    echo -e "  ${GREEN}2.${PLAIN} AWG 2.x  (生态验证更充分，参数体系稳定)"
    if [[ "$def_line" == "2" ]]; then
        read -rp "请输入选项 [1-2, 默认 2]: " line_choice
        line_choice="${line_choice:-2}"
    else
        read -rp "请输入选项 [1-2, 默认 1]: " line_choice
        line_choice="${line_choice:-1}"
    fi
    case "$line_choice" in
        1|3) line="3" ;;
        2)   line="2" ;;
        *)   log_err "无效选项，已中止。"; return 1 ;;
    esac

    # --- 端口 ---
    local port=""
    echo ""
    echo -e "${YELLOW}端口说明：${PLAIN}必须避开 Hysteria2 的端口跳跃区间 20000-40000，"
    echo -e "          否则入站 UDP 会被 REDIRECT 到 Hysteria，AWG 收不到握手包。"
    read -rp "请输入监听 UDP 端口 [回车自动选择 ${AWG_PORT_MIN}-${AWG_PORT_MAX} 内的空闲端口]: " port
    port="${port// /}"
    if [[ -n "$port" ]]; then
        if ! [[ "$port" =~ ^[0-9]+$ ]] || [[ "$port" -lt 1 || "$port" -gt 65535 ]]; then
            log_err "端口必须是 1-65535 的数字。"
            return 1
        fi
        if [[ "$port" -ge 20000 && "$port" -le 40000 ]]; then
            log_err "端口 ${port} 落在 Hysteria2 端口跳跃区间 20000-40000 内，会导致 AWG 无法收到握手包。"
            log_err "请改用区间外的端口，推荐 ${AWG_PORT_MIN}-${AWG_PORT_MAX}。"
            return 1
        fi
    fi

    # --- 连接地址 ---
    local endpoint suggestion
    suggestion="$(awg_suggest_endpoint)"
    if [[ -z "$suggestion" ]]; then
        get_public_ip
        suggestion="${PUBLIC_IP:-}"
    fi
    echo ""
    echo -e "${YELLOW}连接地址用于生成客户端的 Endpoint，填域名或公网 IP 均可。${PLAIN}"
    if [[ -n "$suggestion" ]]; then
        read -rp "请输入客户端连接地址 [默认: ${suggestion}]: " endpoint
        endpoint="${endpoint:-$suggestion}"
    else
        read -rp "请输入客户端连接地址（域名或公网 IP）: " endpoint
    fi
    if [[ -z "$endpoint" ]]; then
        log_warn "未提供连接地址，将跳过首个客户端创建，之后可手动补。"
    fi

    # --- 首个客户端 ---
    local client="client1"
    if [[ -n "$endpoint" ]]; then
        local has_peers="0"
        if [[ -f "$AWG_PEERS_FILE" ]]; then
            has_peers="$(jq -r '[.peers[]?]|length' "$AWG_PEERS_FILE" 2>/dev/null || echo 0)"
        fi
        if [[ "$has_peers" == "0" ]]; then
            echo ""
            read -rp "请为首个客户端命名 [默认: client1]: " client
            client="${client:-client1}"
        fi
    fi

    # --- 执行 ---
    echo ""
    local args=(install --line "$line")
    if [[ -n "$port" ]]; then
        args+=(--port "$port")
    fi
    if [[ -n "$endpoint" ]]; then
        args+=(--endpoint "$endpoint")
    fi

    # 已有客户端时不重复创建，避免报"客户端已存在"
    local peer_count="0"
    if [[ -f "$AWG_PEERS_FILE" ]]; then
        peer_count="$(jq -r '[.peers[]?]|length' "$AWG_PEERS_FILE" 2>/dev/null || echo 0)"
    fi
    if [[ "$peer_count" == "0" ]]; then
        args+=(--client "$client")
    fi

    if ! "$AWG_CTL_BIN" "${args[@]}"; then
        log_err "AmneziaWG 安装失败，请查看上方日志。"
        return 1
    fi

    echo ""
    log_info "云厂商安全组记得放行对应的 UDP 端口。"
    log_info "客户端配置请用 'AmneziaWG 管理' 菜单导出（含二维码）。"
    return 0
}

awg_menu_add_peer() {
    check_root
    if ! awg_ensure_ctl; then return 1; fi

    local name endpoint suggestion
    read -rp "请输入新客户端名称（字母/数字/._-）: " name
    name="${name// /}"
    if [[ -z "$name" ]]; then
        log_err "名称不能为空。"
        return 1
    fi
    if ! [[ "$name" =~ ^[A-Za-z0-9_.-]{1,32}$ ]]; then
        log_err "名称只允许字母、数字、点、下划线、连字符，且不超过 32 字符。"
        return 1
    fi

    suggestion="$(awg_suggest_endpoint)"
    read -rp "客户端连接地址 [默认: ${suggestion:-需手动输入}]: " endpoint
    endpoint="${endpoint:-$suggestion}"
    if [[ -z "$endpoint" ]]; then
        log_err "必须提供连接地址才能生成客户端配置。"
        return 1
    fi

    echo ""
    if ! "$AWG_CTL_BIN" peer-add "$name" --endpoint "$endpoint"; then
        return 1
    fi

    echo ""
    log_info "以下二维码可直接用 AmneziaWG 官方客户端扫描导入："
    if command -v qrencode >/dev/null 2>&1; then
        "$AWG_CTL_BIN" client-conf "$name" --endpoint "$endpoint" 2>/dev/null | qrencode -t ANSIUTF8 || true
    else
        log_warn "未安装 qrencode，跳过二维码。安装后可执行:"
        log_warn "  hy2-awgctl qr ${name} --endpoint ${endpoint}"
    fi
    return 0
}

awg_menu_del_peer() {
    check_root
    if ! awg_ensure_ctl; then return 1; fi

    echo ""
    "$AWG_CTL_BIN" peer-list || true
    echo ""
    local name
    read -rp "请输入要删除的客户端名称: " name
    if [[ -z "$name" ]]; then
        log_err "名称不能为空。"
        return 1
    fi

    local confirm
    read -rp "确认删除客户端 '${name}'？该客户端将立即断线 [y/N]: " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        log_info "已取消。"
        return 0
    fi
    "$AWG_CTL_BIN" peer-del "$name"
}

awg_menu_switch_line() {
    check_root
    if ! awg_ensure_ctl; then return 1; fi
    if ! awg_is_installed; then
        log_err "AmneziaWG 尚未安装。"
        return 1
    fi

    local cur target
    cur="$(awg_current_line)"
    if [[ "$cur" == "3" ]]; then
        target="2"
    else
        target="3"
    fi

    echo ""
    log_warn "当前协议线: AWG ${cur}.x  →  目标协议线: AWG ${target}.x"
    log_warn "两个协议线的参数体系不同，切换会重新生成混淆参数，"
    log_warn "所有已发放的客户端配置都会立刻失效，必须全部重新导出！"
    echo ""
    local confirm
    read -rp "确认切换协议线？[y/N]: " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        log_info "已取消。"
        return 0
    fi

    if ! "$AWG_CTL_BIN" update --line "$target"; then
        return 1
    fi
    echo ""
    log_warn "请立即为所有客户端重新导出配置："
    "$AWG_CTL_BIN" peer-list || true
}

uninstall_amneziawg() {
    check_root
    if ! awg_ensure_ctl; then return 1; fi

    echo ""
    log_warn "即将彻底卸载 AmneziaWG：停止服务、删除网卡与 NAT 规则、"
    log_warn "删除全部密钥与客户端配置（不可恢复）。"
    local confirm
    read -rp "确认卸载？[y/N]: " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        log_info "已取消。"
        return 0
    fi

    "$AWG_CTL_BIN" uninstall || true
    rm -f "$AWG_CTL_BIN"
    log_info "AmneziaWG 已卸载，控制工具也已移除。"
    return 0
}

status_amneziawg() {
    if ! awg_ensure_ctl; then
        return 1
    fi
    "$AWG_CTL_BIN" status
}

update_amneziawg() {
    check_root
    check_arch
    if ! awg_ensure_ctl; then return 1; fi
    "$AWG_CTL_BIN" update
}

# ------------------------------------------------ AmneziaWG 子菜单
menu_amneziawg() {
    check_root
    if ! awg_ensure_ctl; then
        log_err "AmneziaWG 控制工具不可用，请检查网络后重试。"
        return 1
    fi

    local sub
    while true; do
        clear 2>/dev/null || true
        echo -e "${CYAN}================================================================${PLAIN}"
        echo -e "${GREEN}                    AmneziaWG 管理控制台                          ${PLAIN}"
        echo -e "${BLUE}       GitHub: https://github.com/${AWG_REPO}    ${PLAIN}"
        echo -e "${CYAN}================================================================${PLAIN}"
        "$AWG_CTL_BIN" status 2>/dev/null | sed 's/^/  /' || true
        echo -e "${CYAN}----------------------------------------------------------------${PLAIN}"
        echo -e "  ${GREEN}1.${PLAIN} 安装 / 重装 AmneziaWG"
        echo -e "  ${GREEN}2.${PLAIN} 新增客户端并导出配置"
        echo -e "  ${GREEN}3.${PLAIN} 查看所有客户端"
        echo -e "  ${GREEN}4.${PLAIN} 删除客户端"
        echo -e "  ${GREEN}5.${PLAIN} 更新二进制到最新版"
        echo -e "  ${GREEN}6.${PLAIN} 切换协议线 (AWG 2.x <-> 3.x)"
        echo -e "  ${GREEN}7.${PLAIN} 重新同步配置并重启服务"
        echo -e "  ${GREEN}8.${PLAIN} 卸载 AmneziaWG"
        echo -e "${CYAN}----------------------------------------------------------------${PLAIN}"
        echo -e "  ${GREEN}0.${PLAIN} 返回主菜单"
        echo -e "${CYAN}================================================================${PLAIN}"
        read -rp "请输入选项 [0-8]: " sub

        case "$sub" in
            1) install_amneziawg || true ;;
            2) awg_menu_add_peer || true ;;
            3) echo ""; "$AWG_CTL_BIN" peer-list || true ;;
            4) awg_menu_del_peer || true ;;
            5)
                if awg_is_installed; then
                    update_amneziawg || true
                else
                    log_err "AmneziaWG 尚未安装。"
                fi
                ;;
            6) awg_menu_switch_line || true ;;
            7)
                if awg_is_installed; then
                    "$AWG_CTL_BIN" resync || true
                else
                    log_err "AmneziaWG 尚未安装。"
                fi
                ;;
            8)
                if awg_is_installed; then
                    uninstall_amneziawg || true
                else
                    log_err "AmneziaWG 尚未安装。"
                fi
                ;;
            0) return 0 ;;
            *) log_err "无效选项，请重新选择！" ;;
        esac

        echo ""
        read -rp "按回车返回 AmneziaWG 菜单..." _
    done
}

status_service() {
    if [[ ! -f "$HY2_BIN" ]]; then
        log_err "Hysteria 2 未安装！"
        return
    fi
    echo -e "\n${CYAN}--- Hysteria 2 运行状态 ---${PLAIN}"
    systemctl status hysteria-server --no-pager || true
}

start_service() {
    log_step "启动 Hysteria 2 服务..."
    systemctl start hysteria-server
    log_info "已执行启动命令。"
}

stop_service() {
    log_step "停止 Hysteria 2 服务..."
    systemctl stop hysteria-server
    log_info "已执行停止命令。"
}

restart_service() {
    log_step "重启 Hysteria 2 服务..."
    systemctl restart hysteria-server
    log_info "已执行重启命令。"
}

view_logs() {
    echo -e "${CYAN}正在查看 Hysteria 2 实时日志 (Ctrl+C 退出)...${PLAIN}"
    journalctl -u hysteria-server -f -n 50
}

uninstall_all() {
    # AmneziaWG 是独立协议，单独询问再删 —— 避免"卸载 Hysteria 2"顺带删掉
    # 用户并不想删的客户端配置。
    local awg_confirm="N"
    if [[ -f "$AWG_SERVICE" || -f "$AWG_CONFIG" ]]; then
        echo ""
        log_warn "检测到本机还安装了 AmneziaWG。"
        read -rp "是否也要一并卸载 AmneziaWG（含全部客户端配置）？[y/N]: " awg_confirm
    fi

    read -rp "确定要彻底卸载 Hysteria 2 服务及所有配置文件吗？[y/N]: " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        log_step "正在停止并删除系统服务..."
        systemctl stop hysteria-server 2>/dev/null || true
        systemctl disable hysteria-server 2>/dev/null || true
        systemctl disable --now hysteria-portal 2>/dev/null || true
        systemctl disable --now gost 2>/dev/null || true
        # BUGFIX: 卸载时同时清理 WARP 相关服务与配置
        systemctl disable --now wireproxy 2>/dev/null || true
        systemctl disable --now hy2-warp-watchdog.timer 2>/dev/null || true
        systemctl disable --now hy2-warp-watchdog.service 2>/dev/null || true
        rm -f /etc/systemd/system/hysteria-portal.service
        rm -f /etc/systemd/system/gost.service
        rm -f /etc/systemd/system/wireproxy.service
        rm -f /etc/systemd/system/hy2-warp-watchdog.service
        rm -f /etc/systemd/system/hy2-warp-watchdog.timer
        clear_all_hopping_rules
        rm -f "$HY2_SERVICE"
        systemctl daemon-reload

        log_step "清理二进制与配置目录..."
        rm -f "$HY2_BIN"
        rm -f /usr/local/bin/gost
        rm -f /usr/local/bin/wgcf
        rm -f /usr/local/bin/wireproxy
        rm -f /usr/local/bin/hy2-warp-watchdog.sh
        rm -rf "$HY2_DIR"
        rm -rf /etc/wireguard

        # AmneziaWG 清理（按上面的确认结果决定）
        if [[ "$awg_confirm" =~ ^[Yy]$ ]]; then
            log_step "正在卸载 AmneziaWG..."
            awg_ensure_ctl 2>/dev/null || true
            if [[ -x "$AWG_CTL_BIN" ]]; then
                "$AWG_CTL_BIN" uninstall >/dev/null 2>&1 || true
                rm -f "$AWG_CTL_BIN"
            else
                # 控制工具不可用时的兜底清理，保证不留下半截状态
                systemctl disable --now amneziawg-server 2>/dev/null || true
                rm -f "$AWG_SERVICE"
                rm -rf "$AWG_DIR"
                systemctl daemon-reload 2>/dev/null || true
            fi
            log_info "AmneziaWG 已卸载。"
        elif [[ -f "$AWG_CONFIG" ]]; then
            log_info "已保留 AmneziaWG（如需卸载：主菜单选 8，或执行 hy2-awgctl uninstall）。"
        fi

        log_info "Hysteria 2 已彻底卸载完成！"
    else
        log_info "已取消卸载。"
    fi
}

# 主控制台菜单
menu() {
    clear 2>/dev/null || true
    echo -e "${CYAN}================================================================${PLAIN}"
    echo -e "${GREEN}       Hysteria 2 全功能生产级管理脚本 (${HY2_ARCH:-$(uname -m)})         ${PLAIN}"
    echo -e "${BLUE}       GitHub: https://github.com/yys9253462-gif/hysteria2-installer    ${PLAIN}"
    echo -e "${CYAN}================================================================${PLAIN}"
    
    if [[ -f "$HY2_BIN" ]] && systemctl is-active hysteria-server >/dev/null 2>&1; then
        echo -e "核心状态: ${GREEN}运行中 (Active)${PLAIN} | 版本: $($HY2_BIN version 2>/dev/null | grep -E '^Version:' | head -n1 || echo '未知')"
    elif [[ -f "$HY2_BIN" ]]; then
        echo -e "核心状态: ${RED}已停止 (Inactive)${PLAIN} | 版本: $($HY2_BIN version 2>/dev/null | grep -E '^Version:' | head -n1 || echo '未知')"
    else
        echo -e "核心状态: ${YELLOW}未安装 (Not Installed)${PLAIN}"
    fi
    # AmneziaWG 状态：仅在本机装了 AWG 时显示，避免干扰原有主流程
    if [[ -f "$AWG_CONFIG" ]]; then
        local _awg_port
        _awg_port="$(jq -r '.port // "?"' "$AWG_META_FILE" 2>/dev/null || echo '?')"
        if systemctl is-active --quiet amneziawg-server 2>/dev/null; then
            echo -e "AWG 状态 : ${GREEN}运行中${PLAIN} | 协议线: AWG $(awg_current_line).x | UDP ${_awg_port}"
        else
            echo -e "AWG 状态 : ${YELLOW}已安装但未运行${PLAIN} | 协议线: AWG $(awg_current_line).x"
        fi
    fi
    echo -e "${CYAN}----------------------------------------------------------------${PLAIN}"
    echo -e "  ${GREEN}1.${PLAIN} 全新安装 Hysteria 2"
    echo -e "  ${GREEN}2.${PLAIN} 更新 Hysteria 2 核心至最新版"
    echo -e "  ${GREEN}3.${PLAIN} 查看私密信息页地址和登录凭据"
    echo -e "  ${GREEN}4.${PLAIN} 重新修改配置 (端口/密码/证书/域名/混淆)"
    echo -e "  ${GREEN}5.${PLAIN} 一键安装并配置 Cloudflare WARP 出口 (AI解锁)"
    echo -e "  ${GREEN}6.${PLAIN} 一键安装 gost 入站代理引擎 (SOCKS5/HTTP/HTTPS)"
    echo -e "${CYAN}----------------------------------------------------------------${PLAIN}"
    echo -e "  ${GREEN}7.${PLAIN} 一键安装 AmneziaWG (抗 DPI · 用户态 WireGuard)"
    echo -e "  ${GREEN}8.${PLAIN} AmneziaWG 管理 (客户端 / 版本切换 / 更新 / 卸载)"
    echo -e "${CYAN}----------------------------------------------------------------${PLAIN}"
    echo -e "  ${GREEN}9.${PLAIN} 启动服务"
    echo -e "  ${GREEN}10.${PLAIN} 停止服务"
    echo -e "  ${GREEN}11.${PLAIN} 重启服务"
    echo -e "  ${GREEN}12.${PLAIN} 查看实时运行日志"
    echo -e "  ${GREEN}13.${PLAIN} 彻底卸载 Hysteria 2"
    echo -e "  ${GREEN}0.${PLAIN} 退出脚本"
    echo -e "${CYAN}================================================================${PLAIN}"
    read -rp "请输入选项 [0-13]: " choice

    case "$choice" in
        1)
            check_root
            check_arch
            install_dependencies
            get_public_ip || exit 1
            install_binary
            setup_certificates
            setup_ports_and_obfs
            generate_server_config
            setup_system_firewall "$LISTEN_PORT" "$HOP_START" "$HOP_END"
            setup_systemd
            show_client_configs
            ;;
        2)
            check_root
            check_arch
            install_binary
            restart_service
            ;;
        3)
            show_client_configs
            ;;
        4)
            check_root
            install_dependencies
            get_public_ip || exit 1
            setup_certificates
            setup_ports_and_obfs
            generate_server_config
            setup_system_firewall "$LISTEN_PORT" "$HOP_START" "$HOP_END"
            setup_systemd
            show_client_configs
            ;;
        5)
            check_root
            install_warp_local_proxy
            ;;
        6)
            check_root
            install_gost
            ;;
        7)
            # AmneziaWG 安装入口。用 || true 兜住失败，避免 set -e 把整个菜单打断，
            # 让用户能看到报错后返回菜单重试。
            install_amneziawg || true
            echo ""
            read -rp "按回车返回主菜单..." _
            ;;
        8)
            menu_amneziawg || true
            ;;
        9)
            start_service
            ;;
        10)
            stop_service
            ;;
        11)
            restart_service
            ;;
        12)
            view_logs
            ;;
        13)
            check_root
            uninstall_all
            ;;
        0)
            exit 0
            ;;
        *)
            log_err "无效选项，请重新选择！"
            sleep 1
            menu
            ;;
    esac
}

# 命令行直通参数 (如: ./install.sh install / update / status / info)
check_root
check_arch

if [[ $# -gt 0 ]]; then
    case "$1" in
        install)
            install_dependencies
            get_public_ip || exit 1
            install_binary
            setup_certificates
            setup_ports_and_obfs
            generate_server_config
            setup_system_firewall "$LISTEN_PORT" "$HOP_START" "$HOP_END"
            setup_systemd
            show_client_configs
            ;;
        update)
            install_binary
            restart_service
            ;;
        info)
            show_client_configs
            ;;
        refresh-page)
            refresh_portal
            ;;
        status)
            status_service
            ;;
        restart)
            restart_service
            ;;
        uninstall)
            uninstall_all
            ;;
        # ---- AmneziaWG (AWG) ----
        # 带参数时直接透传给底层工具，可完全非交互：
        #   ./install.sh awg-install --line 3 --endpoint vpn.example.com --client phone
        awg-install)
            check_root
            check_arch
            awg_ensure_ctl || exit 1
            shift
            if [[ $# -gt 0 ]]; then
                exec "$AWG_CTL_BIN" install "$@"
            fi
            install_amneziawg
            ;;
        awg-menu)
            menu_amneziawg
            ;;
        awg-status)
            status_amneziawg
            ;;
        awg-update)
            update_amneziawg
            ;;
        awg-uninstall)
            uninstall_amneziawg
            ;;
        awg)
            # 任意底层命令透传，例如: ./install.sh awg peer-list --json
            awg_ensure_ctl || exit 1
            shift
            exec "$AWG_CTL_BIN" "$@"
            ;;
        *)
            menu
            ;;
    esac
else
    menu
fi
