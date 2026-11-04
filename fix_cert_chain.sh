#!/usr/bin/env bash
# fix_cert_chain.sh — 修复 Hysteria 2 节点的「TLS 证书链不完整」问题
#
# 症状：
#   * 节点进程正常、端口在监听，客户端也能建立 QUIC 连接；
#   * 但客户端立即报 `x509: certificate signed by unknown authority`
#     （v2rayNG / v2rayN / Xray / 官方 hysteria 客户端都一样）；
#   * 服务端日志类似 sni guard / failed to verify certificate。
#
# 根因：
#   config.yaml 的 tls.cert 指向仅含【叶证书】的 <domain>.cer，
#   而不是携带中间证书的 fullchain。Go 系客户端不会通过 AIA 自动补链，
#   于是验证不到受信任根。把 tls.cert 换成 fullchain(.cer/.pem) 即可。
#
# 用法：
#   sudo bash fix_cert_chain.sh                 # 自动修复并重启
#   sudo bash fix_cert_chain.sh --dry-run       # 只检查，不改动、不重启
#   sudo bash fix_cert_chain.sh --config /etc/hysteria/config.yaml
#
set -uo pipefail

CONFIG="/etc/hysteria/config.yaml"
DRY_RUN=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=1; shift ;;
        # 缺值时 shift 2 失败而 $1 不变，旧实现在这里死循环（2026-11-04 修）
        --config)  [[ $# -ge 2 ]] || { echo "--config 需要取值"; exit 2; }; CONFIG="$2"; shift 2 ;;
        -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
        *) echo "未知参数: $1"; exit 2 ;;
    esac
done

c_red=$'\033[31m'; c_grn=$'\033[32m'; c_ylw=$'\033[33m'; c_cyn=$'\033[36m'; c_rst=$'\033[0m'
info(){ echo "${c_cyn}[*]${c_rst} $*"; }
ok(){   echo "${c_grn}[✓]${c_rst} $*"; }
warn(){ echo "${c_ylw}[!]${c_rst} $*"; }
err(){  echo "${c_red}[✗]${c_rst} $*"; }

cert_of () {   # 从 config.yaml 取出 tls.cert 路径
    # install.sh 写的是 `cert: "/path"`（带引号）：引号与行尾注释都要去掉，
    # 否则拿 "\"/path\"" 去找文件，必然报「证书文件不存在」（2026-11-03 修）。
    awk '/^tls:[[:space:]]*$/{f=1;next} /^[^[:space:]]/{f=0}
         f && /^[[:space:]]+cert:/{
             sub(/^[[:space:]]+cert:[[:space:]]*/,"")
             if ($0 ~ /^"/) { sub(/^"/,""); sub(/".*$/,"") }
             else if ($0 ~ /^\047/) { sub(/^\047/,""); sub(/\047.*$/,"") }
             else { sub(/[[:space:]]+#.*$/,""); sub(/[[:space:]]+$/,"") }
             print; exit
         }' "$1"
}
n_certs () { local n; n="$(grep -c 'BEGIN CERTIFICATE' "$1" 2>/dev/null)" || true; echo "${n:-0}"; }
# 证书文件第一张证书（叶证书）的公钥指纹
leaf_pub () { openssl x509 -in "$1" -noout -pubkey 2>/dev/null | openssl sha256 2>/dev/null | awk '{print $NF}'; }
# 只改 tls: 段里的 cert: 行，按字面替换（2026-11-04 修）：旧实现 sed 全文替换且把路径当
# 正则，key: "/x/a.cer.key" 这种同前缀路径会一起被改坏，hysteria 随即起不来。
set_tls_cert () {   # $1=config $2=new path
    local tmp; tmp="$(mktemp "${1}.XXXXXX")" || return 1
    NEW_CERT="$2" awk '
        /^tls:[[:space:]]*$/ {f=1; print; next}
        /^[^[:space:]]/ {f=0}
        f && !done && /^[[:space:]]+cert:/ {
            match($0, /^[[:space:]]+cert:/); print substr($0, 1, RLENGTH) " \"" ENVIRON["NEW_CERT"] "\""
            done=1; next
        }
        {print}' "$1" > "$tmp" || { rm -f "$tmp"; return 1; }
    chmod --reference="$1" "$tmp" 2>/dev/null || true
    mv -f "$tmp" "$1"
}

[[ -f "$CONFIG" ]] || { err "找不到配置文件：$CONFIG"; exit 1; }
if [[ "$DRY_RUN" != "1" && "${EUID:-$(id -u)}" -ne 0 ]]; then
    err "需要 root 运行（要改 $CONFIG 并重启服务）；只检查请加 --dry-run。"; exit 1
fi

CERT_FILE="$(cert_of "$CONFIG")"

if [[ -z "$CERT_FILE" ]]; then
    if grep -qE '^acme:' "$CONFIG"; then
        ok "配置使用 hysteria 内置 ACME（acme: 段），由服务端自动下发完整链，无需修复。"
    else
        warn "未找到 tls.cert，也没有 acme: 段 —— 请人工确认证书配置。"
    fi
    exit 0
fi

info "当前证书文件：$CERT_FILE"
[[ -f "$CERT_FILE" ]] || { err "证书文件不存在：$CERT_FILE"; exit 1; }

COUNT="$(n_certs "$CERT_FILE")"
info "该文件包含证书数量：$COUNT"
FINAL_CERT="$CERT_FILE"
CHANGED=0

if [[ "$COUNT" -ge 2 ]]; then
    ok "证书文件已包含完整链（$COUNT 张），无需修改。"
else
    warn "仅 1 张证书 = 只有叶证书，缺少中间证书。开始查找同目录的 fullchain。"

    DIR="$(dirname "$CERT_FILE")"
    FULL=""
    # 候选链的叶证书必须就是当前这张（2026-11-04 修）：多域名机器上上级目录的
    # fullchain 可能属于别的域名，旧实现照单全收，服务端随即出示错的证书。
    _want="$(leaf_pub "$CERT_FILE")"
    for cand in "$DIR/fullchain.cer" "$DIR/fullchain.pem" "$DIR/../fullchain.cer" "$DIR/../fullchain.pem"; do
        if [[ -f "$cand" ]] && [[ "$(n_certs "$cand")" -ge 2 ]] \
                && [[ -n "$_want" && "$(leaf_pub "$cand")" == "$_want" ]]; then
            FULL="$cand"; break
        fi
    done

    if [[ -z "$FULL" ]]; then
        err "未找到可用的 fullchain 文件。请重新签发包含中间证书的证书链，"
        err "或改用 hysteria 内置 ACME（把 config.yaml 的 tls: 段换成 acme: 段）。"
        exit 1
    fi
    ok "找到完整链文件：$FULL"

    if [[ "$DRY_RUN" == "1" ]]; then
        info "[dry-run] 将把 tls.cert：$CERT_FILE"
        info "[dry-run]        改为：$FULL"
        info "[dry-run] 然后重启 hysteria-server。"
        exit 0
    fi

    BK="${CONFIG}.bak.$(date +%Y%m%d%H%M%S)"
    cp -a "$CONFIG" "$BK" || { err "备份配置失败，未做任何修改。"; exit 1; }
    info "已备份原配置：$BK"

    set_tls_cert "$CONFIG" "$FULL" || { cp -a "$BK" "$CONFIG"; err "写入配置失败，已恢复备份。"; exit 1; }
    NEW="$(cert_of "$CONFIG")"
    ok "tls.cert 已更新为：$NEW"
    FINAL_CERT="$FULL"
    CHANGED=1
fi

if [[ "$DRY_RUN" == "1" ]]; then
    info "[dry-run] 当前配置无需改动，未重启任何服务。"
    exit 0
fi

if [[ "$CHANGED" == "1" ]]; then
    info "重启 hysteria-server ..."
    systemctl restart hysteria-server 2>/dev/null || true
    sleep 3
    # 起不来就恢复原配置（2026-11-04 修）：旧实现留着改坏的配置，节点直接掉线。
    if ! systemctl is-active --quiet hysteria-server 2>/dev/null; then
        err "新配置下 hysteria-server 未能启动，已恢复原配置：$BK"
        cp -a "$BK" "$CONFIG"
        systemctl restart hysteria-server 2>/dev/null || true
        exit 1
    fi
fi
systemctl is-active --quiet hysteria-server 2>/dev/null || { warn "hysteria-server 当前不是 active，请人工确认。"; }

SUB_PORT="$(awk '/listenHTTPS:/{sub(/^.*listenHTTPS:[[:space:]]*:?/,"");print;exit}' "$CONFIG")"
[[ -n "$SUB_PORT" ]] || SUB_PORT=8443
SNI="$(openssl x509 -in "$FINAL_CERT" -noout -subject 2>/dev/null | sed -n 's/.*CN *= *//p' | tr -d ' ')"

if command -v openssl >/dev/null 2>&1; then
    info "验证 127.0.0.1:${SUB_PORT} 服务出的证书链 (SNI=${SNI:-localhost}) ..."
    CHAIN="$(echo | timeout 8 openssl s_client -connect "127.0.0.1:${SUB_PORT}" -servername "${SNI:-localhost}" 2>/dev/null \
             | grep -E 's:|i:|Verify return code')"
    echo "$CHAIN" | sed 's/^/    /'
    if echo "$CHAIN" | grep -q 'Verify return code: 0'; then
        ok "证书链完整，客户端可正常校验。完成。"
    else
        warn "验证未通过（可能 SNI 不匹配或链仍不完整），请人工复查。"
    fi
fi
