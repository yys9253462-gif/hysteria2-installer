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
HY2_SUB_PORT=""   # 由 select_subscription_port() 动态分配；空值表示"尚未确定"

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

# ---- GitHub API token（可选）----
# 匿名 API 每 IP 每小时 60 次，同机其它程序会耗光它。存在 token 文件时，
# 只给发往 https://api.github.com/ 的 curl 加 Authorization；token 经进程替换
# 以 `-H @文件` 传入，不出现在命令行参数里（ps 看不到）。镜像与下载站不带。
HY2_GITHUB_TOKEN_FILE="${HY2_DIR}/github-token"
curl() {
    local _a _tok=""
    for _a in "$@"; do
        case "$_a" in
            https://api.github.com/*)
                [[ -r "$HY2_GITHUB_TOKEN_FILE" ]] && _tok="$(tr -d '[:space:]' < "$HY2_GITHUB_TOKEN_FILE")"
                break ;;
        esac
    done
    if [[ "$_tok" =~ ^[A-Za-z0-9_]{20,255}$ ]]; then
        command curl -H @<(printf 'Authorization: Bearer %s\n' "$_tok") "$@"
    else
        command curl "$@"
    fi
}

log_info() { echo -e "${GREEN}[INFO]${PLAIN} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${PLAIN} $1"; }
log_err()  { echo -e "${RED}[ERROR]${PLAIN} $1"; }
log_step() { echo -e "${CYAN}==>${PLAIN} ${BLUE}$1${PLAIN}"; }

# ==============================================================================
# 下载完整性校验（2026-10-27）
# ------------------------------------------------------------------------------
# 下载任何上游二进制/脚本的固定顺序：
#   1) 先解析出**确定的版本**与**确定的架构**（不依赖浮动 latest 下载）；
#   2) 从该版本的**官方**发布取校验清单（hashes.txt / checksums.txt / *.dgst）；
#   3) 按**精确资产名**解析出唯一 SHA256；
#   4) 下载到私有临时目录（mktemp -d），先校验、再解包/替换/执行。
#
# 下面这些情况一律 fail-closed（返回非 0，绝不"跳过校验继续装"）：
#   * 清单取不到 / 清单为空 / 清单里没有该资产；
#   * 同一资产在清单里匹配到多条（可能被人为注入）；
#   * 摘要不是 64 位十六进制；
#   * 下载内容与摘要不一致。
#
# 第三方镜像**不能**提供可信摘要：只有先从官方取得预期摘要，才允许把镜像
# 当作传输候选，且内容必须与官方摘要逐字节一致。
# 同源摘要只能证明"与官方发布一致"，不构成独立签名，挡不住官方发布本身被替换。
# ==============================================================================

# 计算文件 SHA256（小写十六进制）；文件不可读返回 1。
hy2_sha256_file() {
    [[ -f "${1:-}" ]] || return 1
    sha256sum "$1" 2>/dev/null | awk '{print $1}'
}

# 校验文件 SHA256 是否等于预期值；预期值格式非法即失败。
hy2_verify_sha256() {
    local got
    [[ "${2:-}" =~ ^[0-9a-f]{64}$ ]] || return 1
    got="$(hy2_sha256_file "$1")" || return 1
    [[ -n "$got" && "$got" == "$2" ]]
}

# 从 `<sha256>  <name>` 形式的清单里取唯一匹配资产的摘要。
# 兼容：行尾 CRLF、`*name`、`./name`、`build/name`（按 basename 兜底匹配）。
# 无匹配 / 多条匹配 / 摘要畸形 => 返回 1。
hy2_manifest_sha256() {
    local manifest="${1:-}" asset="${2:-}"
    local line digest name base count=0 found=""
    [[ -n "$asset" && -f "$manifest" && -r "$manifest" ]] || return 1
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%$'\r'}"
        [[ -z "${line//[[:space:]]/}" ]] && continue
        [[ "$line" == \#* ]] && continue
        [[ "$line" == *[[:space:]]* ]] || continue          # 畸形行：缺少分隔符
        digest="${line%%[[:space:]]*}"
        name="${line#*[[:space:]]}"
        name="${name#"${name%%[![:space:]]*}"}"             # 去掉前导空白
        name="${name%$'\r'}"
        name="${name#\*}"
        name="${name#./}"
        base="${name##*/}"
        [[ "$name" == "$asset" || "$base" == "$asset" ]] || continue
        digest="$(printf '%s' "$digest" | tr 'A-F' 'a-f')"
        [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || return 1        # 匹配到但摘要畸形
        count=$((count + 1))
        found="$digest"
    done < "$manifest"
    [[ $count -eq 1 && -n "$found" ]] || return 1
    printf '%s\n' "$found"
}

# 从 Xray 的 `.dgst` 里取 SHA2-256（格式：`SHA2-256= <hex>`）。
# 只认 SHA2-256，绝不拿 MD5/SHA1 当校验依据；缺失或重复 => 返回 1。
hy2_dgst_sha256() {
    local dgst="${1:-}" line key value digest count=0 found=""
    [[ -f "$dgst" && -r "$dgst" ]] || return 1
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%$'\r'}"
        [[ "$line" == *=* ]] || continue
        key="${line%%=*}"
        value="${line#*=}"
        key="$(printf '%s' "$key" | tr -d '[:space:]' | tr 'a-z' 'A-Z')"
        [[ "$key" == "SHA2-256" || "$key" == "SHA2_256" ]] || continue
        digest="$(printf '%s' "$value" | tr -d '[:space:]' | tr 'A-F' 'a-f')"
        [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || return 1
        count=$((count + 1))
        found="$digest"
    done < "$dgst"
    [[ $count -eq 1 && -n "$found" ]] || return 1
    printf '%s\n' "$found"
}

# 下载校验清单到 $2（仅取文本，不做任何执行）。
hy2_fetch_manifest() {
    curl -fsSL --connect-timeout 15 --max-time 30 --retry 2 --retry-delay 2 \
        -o "${2:-}" "${1:-}" 2>/dev/null
}

# 下载清单并解析出资产摘要：$1=清单 URL $2=精确资产名 $3=临时工作目录。
hy2_expected_sha256() {
    local out="${3:-}/.checksums"
    [[ -n "${3:-}" && -d "$3" ]] || return 1
    hy2_fetch_manifest "$1" "$out" || return 1
    hy2_manifest_sha256 "$out" "$2"
}

# 计算 git blob sha1（`sha1("blob <len>\0" + content)`）。
# GitHub contents API 返回的 sha 就是这个值 —— 注意它**不等于**文件的 sha1，
# 少写 blob 头会永远对不上。
hy2_git_blob_sha() {
    local f="${1:-}" size
    [[ -f "$f" ]] || return 1
    size="$(wc -c < "$f" | tr -d '[:space:]')"
    [[ "$size" =~ ^[0-9]+$ ]] || return 1
    { printf 'blob %s\0' "$size"; cat -- "$f"; } | sha1sum | awk '{print $1}'
}

# 拒绝含绝对路径或 `..` 的 tar 包（防路径穿越以 root 写出临时目录）。
hy2_tar_listing_safe() {
    local member listing
    [[ -f "${1:-}" ]] || return 1
    # 从 stdin 读包：GNU tar 会把带冒号的路径（如 Windows 盘符）当成远程主机。
    # 读不出清单必须判为不安全（fail-closed），否则损坏或异常的包会被放行。
    listing="$(tar -tzf - <"$1" 2>/dev/null)" || return 1
    while IFS= read -r member; do
        member="${member%$'\r'}"
        case "$member" in
            /*|..|../*|*/../*|*/..) return 1 ;;
        esac
    done <<<"$listing"
    return 0
}

# 在包内查找与 $2 同名的成员，输出**包内实际成员名**（可能是 ./name）。
hy2_tar_find_member() {
    local member
    [[ -f "${1:-}" ]] || return 1
    while IFS= read -r member; do
        member="${member%$'\r'}"
        [[ "${member#./}" == "$2" ]] && { printf '%s\n' "$member"; return 0; }
    done < <(tar -tzf - <"$1" 2>/dev/null)
    return 1
}

# 把 HY2_ARCH 映射成 Hysteria 官方资产后缀。
# ⚠️ 上游**没有** hysteria-linux-armv7，armv7 机器要用 hysteria-linux-arm
#    （实测 armv7 的 URL 404，arm 存在）。旧的 armv7 映射是已证实的缺陷。
hy2_core_asset_arch() {
    case "${1:-}" in
        amd64) echo amd64 ;;
        arm64) echo arm64 ;;
        armv7) echo arm ;;
        *) return 1 ;;
    esac
}

# ==============================================================================
# acme.sh 获取与校验（2026-10-27）
# ------------------------------------------------------------------------------
# 旧实现是 `curl https://get.acme.sh | sh`：下载即执行，没有任何内容校验，
# 而 get.acme.sh 自己还会再去 raw 拉 master 分支的 acme.sh 执行 —— 整条链路
# 全是"浮动的、未校验的远程代码"。
#
# 现在的做法（信任根 = GitHub 官方 API + raw 的 TLS，且固定到 commit）：
#   1) GitHub API 解析 acmesh-official/acme.sh 的 master 为 **40 位 commit**；
#   2) 取该 commit 的 **官方 git tree**（recursive），逐路径得到预期 blob 身份；
#   3) 只下载**本次真正会执行/安装**的文件到私有临时目录：
#        acme.sh、dnsapi/dns_cf.sh、dnsapi/dns_ali.sh、dnsapi/dns_dp.sh
#      每个文件都必须满足 sha1("blob <len>\0"+content) == 官方 tree 里的 blob；
#   4) 全部通过后，才在临时目录里执行 `./acme.sh --install` 安装。
#
# 为什么是逐文件而不是下 tar.gz：
#   * 归档解包要额外防路径穿越/链接/危险成员，且"只验入口"会放过 dnsapi 等
#     真正会被 source 的代码；逐文件校验天然不存在解包面。
#   * 只取 4 个文件，校验范围与执行范围一致（不多验、也不少验）。
# 不提供任何镜像/无摘要 fallback；任何一步失败都直接失败并给出可读原因。
# 上游 acme.sh 没有独立签名（无 cosign/minisign），同源元数据挡不住
# GitHub 仓库/账号本身被替换 —— 这是本方案明确的边界。
# ==============================================================================

HY2_ACME_REPO="acmesh-official/acme.sh"
# 只包含本项目会执行的入口与三个 DNS 插件（dns_cf / dns_ali / dns_dp）。
HY2_ACME_FILES="acme.sh dnsapi/dns_cf.sh dnsapi/dns_ali.sh dnsapi/dns_dp.sh"
# 已有安装核验通过后记录实际比对的 commit（仅用于日志/后续提示，不参与校验）。
HY2_ACME_VERIFIED_COMMIT=""
# 本机记录"这份 acme.sh 是按哪个 commit 校验安装的"，位于 acme.sh home 内。
# 自动升级已关闭，所以安装后文件不会再变；以后核验必须对比**这个** commit，
# 而不是当时的上游 master —— master 一前进，旧安装就永远对不上了。
HY2_ACME_PIN_NAME=".hy2-pinned-commit"

# 把校验所用 commit 写进 $1/.hy2-pinned-commit（原子替换，600）。
hy2_acme_record_pin() {
    local home="${1:-}" commit="${2:-}" tmp
    [[ -n "$home" && -d "$home" ]] || return 1
    [[ "$commit" =~ ^[0-9a-f]{40}$ ]] || return 1
    tmp="$(mktemp "${home}/${HY2_ACME_PIN_NAME}.XXXXXX")" || return 1
    printf '%s
' "$commit" > "$tmp" && chmod 600 "$tmp" && mv -f "$tmp" "${home}/${HY2_ACME_PIN_NAME}" || {
        rm -f "$tmp"; return 1; }
}

# 读 $1/.hy2-pinned-commit；文件不存在返回 2（旧安装），内容非法返回 1。
hy2_acme_read_pin() {
    local f="${1:-}/${HY2_ACME_PIN_NAME}" commit
    [[ -e "$f" ]] || return 2
    [[ -f "$f" && ! -L "$f" ]] || return 1
    commit="$(head -n1 "$f" 2>/dev/null | tr -d '[:space:]')"
    [[ "$commit" =~ ^[0-9a-f]{40}$ ]] || return 1
    printf '%s
' "$commit"
}

# 路径必须是仓库内相对路径：拒绝绝对路径、`..`/`.` 组件、反斜杠、空段、以 `-` 开头。
hy2_acme_path_safe() {
    local p="${1:-}"
    [[ -n "$p" ]] || return 1
    [[ "$p" != /* ]] || return 1
    [[ "$p" != *\\* ]] || return 1
    [[ "$p" != -* ]] || return 1
    [[ "$p" != *//* ]] || return 1
    [[ "/$p/" != *"/../"* ]] || return 1
    [[ "/$p/" != *"/./"* ]] || return 1
    [[ "$p" =~ ^[A-Za-z0-9._/-]+$ ]] || return 1
    return 0
}

# 解析 acme.sh 的 master 为固定 40 位 commit；失败返回 1（绝不回退浮动分支）。
hy2_acme_pin_commit() {
    local json sha
    command -v jq >/dev/null 2>&1 || return 1
    json="$(curl -fsSL --connect-timeout 15 --max-time 30 --retry 2 \
        -H 'Accept: application/vnd.github+json' \
        "https://api.github.com/repos/${HY2_ACME_REPO}/commits/master" 2>/dev/null)" || return 1
    sha="$(printf '%s' "$json" | jq -r '.sha // empty' 2>/dev/null)" || return 1
    [[ "$sha" =~ ^[0-9a-f]{40}$ ]] || return 1
    printf '%s\n' "$sha"
}

# 取固定 commit 的官方递归 tree（JSON）；truncated 视为失败（列表不完整）。
hy2_acme_tree_json() {
    local commit="${1:-}" json
    [[ "$commit" =~ ^[0-9a-f]{40}$ ]] || return 1
    command -v jq >/dev/null 2>&1 || return 1
    json="$(curl -fsSL --connect-timeout 15 --max-time 60 --retry 2 \
        -H 'Accept: application/vnd.github+json' \
        "https://api.github.com/repos/${HY2_ACME_REPO}/git/trees/${commit}?recursive=1" 2>/dev/null)" || return 1
    [[ "$(printf '%s' "$json" | jq -r '.truncated // false' 2>/dev/null)" == "false" ]] || return 1
    printf '%s\n' "$json"
}

# 从 tree JSON 取某个路径的预期 blob；路径必须唯一、type=blob、mode 是普通文件。
# 拒绝 submodule（type=commit）与符号链接（mode 120000）。
hy2_acme_blob_for_path() {
    local json="${1:-}" path="${2:-}" line type mode sha
    [[ -n "$json" && -n "$path" ]] || return 1
    hy2_acme_path_safe "$path" || return 1
    command -v jq >/dev/null 2>&1 || return 1
    line="$(printf '%s' "$json" | jq -r --arg p "$path" '
        [ .tree[]? | select(.path == $p) ] as $m
        | if ($m | length) == 1
          then ($m[0].type + " " + ($m[0].mode | tostring) + " " + $m[0].sha)
          else "" end' 2>/dev/null)" || return 1
    [[ -n "$line" ]] || return 1
    read -r type mode sha <<<"$line"
    [[ "$type" == "blob" ]] || return 1
    [[ "$mode" == "100644" || "$mode" == "100755" ]] || return 1
    [[ "$sha" =~ ^[0-9a-f]{40}$ ]] || return 1
    printf '%s\n' "$sha"
}

# 下载固定 commit 的单个文件并比对 git blob 身份；不匹配则删除并返回 1。
hy2_acme_fetch_verified() {
    local repo="${1:-}" commit="${2:-}" path="${3:-}" expect="${4:-}" dest="${5:-}" got
    [[ "$commit" =~ ^[0-9a-f]{40}$ ]] || return 1
    [[ "$expect" =~ ^[0-9a-f]{40}$ ]] || return 1
    hy2_acme_path_safe "$path" || return 1
    [[ -n "$dest" ]] || return 1
    mkdir -p "$(dirname "$dest")" || return 1
    curl -fsSL --connect-timeout 15 --max-time 60 --retry 2 \
        -o "$dest" "https://raw.githubusercontent.com/${repo}/${commit}/${path}" 2>/dev/null || {
        rm -f "$dest"; return 1; }
    got="$(hy2_git_blob_sha "$dest")" || { rm -f "$dest"; return 1; }
    if [[ "$got" != "$expect" ]]; then
        rm -f "$dest"
        return 1
    fi
    return 0
}

# 关闭 acme.sh 自身的在线自动升级（cron 里 AUTO_UPGRADE=1 时会先 upgrade 再续期，
# 那等于后台定期执行未校验的新代码）。只改这一个配置项，先备份 account.conf。
# ⚠️ 不关闭 cron 本身：证书续期仍由 `--cron` 完成。
hy2_acme_disable_auto_upgrade() {
    local conf="${1:-}" tmp
    [[ -n "$conf" ]] || return 1
    mkdir -p "$(dirname "$conf")" || return 1
    if [[ ! -f "$conf" ]]; then
        printf "AUTO_UPGRADE='0'\n" > "$conf" || return 1
        chmod 600 "$conf" 2>/dev/null || true
        return 0
    fi
    cp -a "$conf" "${conf}.hy2-bak" || return 1
    tmp="$(mktemp)" || return 1
    if grep -qE '^AUTO_UPGRADE=' "$conf"; then
        sed "s|^AUTO_UPGRADE=.*|AUTO_UPGRADE='0'|" "$conf" > "$tmp" || { rm -f "$tmp"; return 1; }
    elif grep -qE '^#AUTO_UPGRADE=' "$conf"; then
        sed "s|^#AUTO_UPGRADE=.*|AUTO_UPGRADE='0'|" "$conf" > "$tmp" || { rm -f "$tmp"; return 1; }
    else
        cp -a "$conf" "$tmp" || { rm -f "$tmp"; return 1; }
        printf "\nAUTO_UPGRADE='0'\n" >> "$tmp" || { rm -f "$tmp"; return 1; }
    fi
    cat "$tmp" > "$conf" || { rm -f "$tmp"; return 1; }
    rm -f "$tmp"
    grep -qE "^AUTO_UPGRADE='0'$" "$conf" || return 1
    return 0
}

# 下载 → 逐文件校验 → 安装。任何一步失败都返回 1，且不执行任何未校验内容。
# $1 = acme.sh 工作目录（默认 $HOME/.acme.sh）。
hy2_acme_install_verified() {
    local home="${1:-$HOME/.acme.sh}"
    local commit tree_json work path blob dest had_home=0
    local acct="${home}/acme.sh"

    if ! command -v jq >/dev/null 2>&1; then
        log_err "缺少 jq，无法校验 acme.sh 的官方元数据，已放弃安装。"
        return 1
    fi
    # 已存在的安装一律不覆盖：证书/账号数据都在同一个 home 下，
    # 重装既无必要也可能破坏已有账号。调用方应走 hy2_acme_check_existing。
    if [[ -e "$acct" ]]; then
        log_err "已存在 ${acct}，本函数拒绝覆盖；请用 hy2_acme_check_existing 处理现有安装。"
        return 1
    fi
    if ! commit="$(hy2_acme_pin_commit)"; then
        log_err "无法从 GitHub 官方 API 解析 ${HY2_ACME_REPO} 的 commit（可能是网络/限流）。"
        log_err "未认证请求限额 60 次/小时/IP。为不执行未校验代码，已放弃安装 acme.sh。"
        return 1
    fi
    if ! tree_json="$(hy2_acme_tree_json "$commit")"; then
        log_err "取不到 ${HY2_ACME_REPO}@${commit} 的官方文件树（或返回被截断）。"
        log_err "为不执行未校验代码，已放弃安装 acme.sh。"
        return 1
    fi

    work="$(mktemp -d)" || { log_err "无法创建临时目录，已放弃安装 acme.sh。"; return 1; }

    for path in $HY2_ACME_FILES; do
        if ! blob="$(hy2_acme_blob_for_path "$tree_json" "$path")"; then
            log_err "官方文件树里 ${path} 缺失/不唯一/类型不安全（链接或子模块），已放弃安装。"
            rm -rf "$work"
            return 1
        fi
        dest="${work}/${path}"
        if ! hy2_acme_fetch_verified "$HY2_ACME_REPO" "$commit" "$path" "$blob" "$dest"; then
            log_err "${path} 下载失败或内容与官方 tree 的 blob 身份不符，已放弃安装。"
            rm -rf "$work"
            return 1
        fi
    done

    # 全部校验通过后才允许执行安装器（安装器本身也是刚校验过的 acme.sh）。
    chmod +x "${work}/acme.sh" || { rm -rf "$work"; log_err "无法设置可执行位，已放弃安装。"; return 1; }
    had_home=0
    if [[ -d "$home" ]]; then had_home=1; fi
    if ! ( cd "$work" && ./acme.sh --install --home "$home" ); then
        log_err "acme.sh 安装器执行失败（文件已通过校验，失败发生在安装阶段）。"
        if [[ $had_home -eq 0 ]]; then
            rm -rf "$home"
            log_err "已清理本次新建的 ${home}，原有环境未改动。"
        fi
        rm -rf "$work"
        return 1
    fi

    # 安装后复核：落地的文件除首行 shebang 外必须与已校验内容逐字节一致。
    # 上游 install() 会把 shebang 改成 `#!<bash 路径>`，这是唯一允许的差异。
    for path in $HY2_ACME_FILES; do
        if ! hy2_acme_same_except_shebang "${work}/${path}" "${home}/${path}"; then
            log_err "安装后的 ${path} 与已校验内容不一致（除 shebang 外），已放弃使用。"
            rm -rf "$work"
            if [[ $had_home -eq 0 ]]; then rm -rf "$home"; fi
            return 1
        fi
    done
    rm -rf "$work"

    if ! hy2_acme_disable_auto_upgrade "${home}/account.conf"; then
        log_err "无法关闭 acme.sh 的自动升级（account.conf 写入失败），已放弃使用。"
        return 1
    fi
    if ! hy2_acme_record_pin "$home" "$commit"; then
        log_err "无法记录 acme.sh 的固定 commit（${home}/${HY2_ACME_PIN_NAME}），以后将无法核验这份安装，已放弃使用。"
        return 1
    fi
    log_info "acme.sh 已固定到 commit ${commit} 并通过逐文件 blob 校验；自动升级已关闭，续期 cron 保留。"
    return 0
}

# shebang 只允许"单个解释器路径"或 `/usr/bin/env sh|bash` 这一种带空格的形态。
# 绝不接受带参数/元字符的 shebang（例如 `#!/bin/sh -c '...'`、
# `#!/usr/bin/env -S bash -c ...`）—— 那会让"只差 shebang"变成任意代码执行口子。
hy2_acme_shebang_safe() {
    local line="${1:-}" interp base
    [[ "$line" == '#!'* ]] || return 1
    interp="${line#\#\!}"
    [[ -n "$interp" ]] || return 1
    if [[ "$interp" =~ ^[A-Za-z0-9._/-]+$ ]]; then
        base="${interp##*/}"
        [[ "$base" == "sh" || "$base" == "bash" ]] || return 1
        # 🔴 必须是**标准系统目录**下的绝对路径。`#!/tmp/evil/bash`、
        #    `#!/opt/x/bash` 这类同 basename 的任意路径不能因为"看起来像 bash"
        #    就被信任 —— 否则"只允许 shebang 不同"等于允许执行任意程序。
        [[ "$interp" == /* ]] || return 1
        case "${interp%/*}" in
            /bin|/usr/bin|/usr/local/bin|/sbin|/usr/sbin|/usr/local/sbin) return 0 ;;
        esac
        return 1
    fi
    [[ "$interp" =~ ^/usr/bin/env\ (sh|bash)$ ]] || return 1
    return 0
}

# 比较两个文件：完全相同，或**仅首行 shebang**不同且该 shebang 是安全形态；
# 允许 shebang 差异是因为上游 install() 会把所有 .sh 的首行改成 `#!<bash 路径>`。
hy2_acme_same_except_shebang() {
    local src="${1:-}" dst="${2:-}"
    [[ -f "$src" && -f "$dst" ]] || return 1
    cmp -s "$src" "$dst" && return 0
    hy2_acme_shebang_safe "$(head -n1 "$src" 2>/dev/null)" || return 1
    hy2_acme_shebang_safe "$(head -n1 "$dst" 2>/dev/null)" || return 1
    cmp -s <(tail -n +2 "$src") <(tail -n +2 "$dst")
}

# 已有安装的身份核验：本项目会执行的 4 个文件（acme.sh + 三个 DNS 插件）
# 必须全部与**官方固定 commit 的内容**一致，只允许上游安装器改写的 shebang 差异。
# 预期内容取自官方 tree 的 blob 身份，绝不用待验证文件自算摘要充当预期。
# 本函数**只读**：不写配置、不执行任何脚本、不删除/移动任何文件。
hy2_acme_verify_existing() {
    local home="${1:-$HOME/.acme.sh}"
    local commit tree_json work path blob inst

    if ! command -v jq >/dev/null 2>&1; then
        log_err "缺少 jq，无法校验已有 acme.sh 的官方身份。"
        return 1
    fi
    work="$(mktemp -d)" || { log_err "无法创建临时目录，无法校验已有 acme.sh。"; return 1; }
    # 优先对比本机记录的固定 commit（本项目装的 / 已核验过的安装）。
    # 记录存在时**绝不**回退到上游 master：对不上就是被改过，必须阻断。
    # 没有记录的旧安装（get.acme.sh 装的）只能对比当前 master，核验通过后再补记录。
    local pin_rc=0
    commit="$(hy2_acme_read_pin "$home")" || pin_rc=$?
    if [[ $pin_rc -eq 1 ]]; then
        log_err "${home}/${HY2_ACME_PIN_NAME} 内容非法（不是 40 位 commit），无法确认这份安装的来源。"
        rm -rf "$work"; return 1
    elif [[ $pin_rc -eq 2 ]]; then
        if ! commit="$(hy2_acme_pin_commit)"; then
            log_err "无法从 GitHub 官方 API 解析 ${HY2_ACME_REPO} 的 commit（网络/限流）。"
            rm -rf "$work"; return 1
        fi
        log_warn "这份 acme.sh 没有固定 commit 记录（旧安装），改为对比上游当前 master ${commit:0:7}。"
    fi
    if ! tree_json="$(hy2_acme_tree_json "$commit")"; then
        log_err "取不到 ${HY2_ACME_REPO}@${commit} 的官方文件树（或返回被截断）。"
        rm -rf "$work"; return 1
    fi
    for path in $HY2_ACME_FILES; do
        inst="${home}/${path}"
        if [[ ! -f "$inst" ]]; then
            log_err "已有安装缺少 ${path}，无法确认它将要执行的内容。"
            rm -rf "$work"; return 1
        fi
        if ! blob="$(hy2_acme_blob_for_path "$tree_json" "$path")"; then
            log_err "官方文件树里 ${path} 缺失/不唯一/类型不安全。"
            rm -rf "$work"; return 1
        fi
        if ! hy2_acme_fetch_verified "$HY2_ACME_REPO" "$commit" "$path" "$blob" "${work}/${path}"; then
            log_err "无法取得 ${path} 的可信预期内容（下载失败或与官方 tree 不符）。"
            rm -rf "$work"; return 1
        fi
        # 只允许首行 shebang 不同；其余任何字节差异都不放过。
        if ! hy2_acme_same_except_shebang "${work}/${path}" "$inst"; then
            log_err "已有 ${inst} 与官方 ${commit} 的内容不一致（除 shebang 外）。"
            rm -rf "$work"; return 1
        fi
    done
    rm -rf "$work"
    HY2_ACME_VERIFIED_COMMIT="$commit"
    return 0
}

# 已存在的 acme.sh：**不重装、不覆盖、不删除**。
#   1) 先做身份核验；**核验不通过就硬失败**，绝不在任何执行/签发前放行；
#   2) 只有核验通过才关闭它自身的在线自动升级（cron 会定期执行新代码）。
# 核验失败时：不执行 acme.sh、不签发、不写 account.conf、不调用禁升级命令，
# 现有证书/账号/脚本原样保留，并给出"保留数据"的修复办法。
hy2_acme_check_existing() {
    local home="${1:-$HOME/.acme.sh}"
    local acct="${home}/acme.sh"

    log_warn "检测到已安装的 acme.sh（${acct}），本次不覆盖、不重装。"
    if ! hy2_acme_verify_existing "$home"; then
        log_err "已阻止：现有 acme.sh 的身份无法确认（与官方固定 commit 不一致，或元数据取不到）。"
        log_err "本次不执行该脚本、不调用它签发证书，也没有改动它的任何配置。"
        log_err "现有证书、账号与脚本均原样保留（未删除、未覆盖、未关闭其自动升级）。"
        log_err "已有历史版本不等于恶意；但身份无法验证时不能拿它去执行或签发。"
        log_err "修复办法（保留数据）："
        log_err "  1) 整体备份：cp -a ${home} ${home}.bak.\$(date +%s)"
        log_err "  2) 把 ${acct} 与 dnsapi/ 下不一致的插件**移出**（mv，不要直接删）到备份目录；"
        log_err "  3) 重跑本脚本 —— 会重新 pin 官方 commit 并逐文件校验后安装；"
        log_err "     证书目录与 account.conf 保持不动，不影响已有证书与账号。"
        return 1
    fi
    log_info "现有 acme.sh 与官方 ${HY2_ACME_VERIFIED_COMMIT} 逐文件一致（除 shebang），来源可确认。"
    if hy2_acme_disable_auto_upgrade "${home}/account.conf"; then
        log_info "已关闭现有 acme.sh 的在线自动升级（AUTO_UPGRADE=0），续期 cron 保留。"
        # 自动升级关掉后文件不会再变，这时才补记录：以后都对比这个 commit。
        # 记录失败不影响本次使用，只是下次仍按"旧安装"对比 master。
        hy2_acme_record_pin "$home" "$HY2_ACME_VERIFIED_COMMIT" ||
            log_warn "未能写入 ${home}/${HY2_ACME_PIN_NAME}，下次仍会对比上游 master。"
    else
        log_warn "未能关闭现有 acme.sh 的自动升级，请手工在 ${home}/account.conf 设 AUTO_UPGRADE='0'。"
    fi
    return 0
}

# 端口合法性：1-65535 的纯数字。
# 抽成公共函数，保证「交互输入」和「环境变量传入」走同一套校验 ——
# 之前交互路径不校验、环境变量路径更不校验，输错会一路写进配置，
# 表现是「显示安装成功但服务起不来」，新手完全想不到是自己打错了。
is_valid_port() {
    [[ "$1" =~ ^[0-9]+$ ]] && (( $1 >= 1 && $1 <= 65535 ))
}

# ==============================================================================
# 交互环境自愈（必须在所有交互之前）
# ------------------------------------------------------------------------------
# 必须区分两种"stdin 不是终端"的情况，处置方式完全相反：
#
#   A) 脚本本身来自 stdin —— curl … | bash、cat install.sh | bash
#      特征：BASH_SOURCE[0] 为空（bash 直接把 stdin 当脚本来读）。
#      此时脚本里每一条 read 都会去读【脚本体】，表现为「菜单一闪而过 /
#      装到一半卡住 / 选项莫名乱跳」，而且没有任何有意义的报错，新手无从自查。
#      → 把 stdin 接到终端，交互恢复正常。
#
#   B) 脚本是文件、只是"答案"来自 stdin —— printf '1\n\n' | bash install.sh
#      特征：BASH_SOURCE[0] 是脚本路径。
#      这是正常的脚本化/自动化用法，**绝不能**劫持它的 stdin。
# ==============================================================================
if [[ -z "${BASH_SOURCE[0]:-}" ]]; then
    if { true </dev/tty; } 2>/dev/null; then
        # 有可用终端：把 stdin 接到终端，交互恢复正常
        exec </dev/tty
    elif [[ $# -eq 0 ]]; then
        # 既没有终端、又没带子命令 —— 接下来必然要弹交互菜单，无法进行
        log_err "检测到脚本是从 stdin 读入的（典型的 'curl … | bash' 用法）。"
        log_err "这样运行时脚本里的交互提问会把脚本自身读掉，导致菜单乱跳或卡住。"
        echo
        echo -e "  请改用下面任一方式重新执行："
        echo -e "    ${GREEN}bash <(curl -fsSL <脚本URL>)${PLAIN}                    # 推荐"
        echo -e "    ${GREEN}curl -fsSL <脚本URL> -o install.sh && bash install.sh${PLAIN}"
        echo
        echo -e "  或改用免交互方式（不需要终端）："
        echo -e "    ${GREEN}HY2_CERT_TYPE=3 HY2_DOMAIN=hy2.example.com HY2_EMAIL=me@example.com bash install.sh install${PLAIN}"
        exit 1
    fi
    # 带子命令且确实没有终端：允许继续（子命令本身可能不需要输入）
fi

# 免交互环境变量：提前校验，别等装到一半才报错
if [[ -n "${HY2_PORT:-}" ]] && ! is_valid_port "$HY2_PORT"; then
    log_err "环境变量 HY2_PORT='${HY2_PORT}' 不是合法端口（需为 1-65535 的整数）。"
    exit 1
fi
if [[ -n "${HY2_CERT_TYPE:-}" ]] && [[ ! "${HY2_CERT_TYPE}" =~ ^[1-4]$ ]]; then
    log_err "环境变量 HY2_CERT_TYPE='${HY2_CERT_TYPE}' 无效，只能是 1 / 2 / 3 / 4。"
    exit 1
fi
# 本项目只提供商城版（Agent）节点，单机私密模式已移除。
# 旧脚本里的 HY2_NODE_MODE=1 不再静默改成商城版 —— 那会让 Teyir 节点
# 「看起来装好了但 API 没开」，所以直接报错并说明如何继续。
if [[ -n "${HY2_NODE_MODE:-}" ]] && [[ "${HY2_NODE_MODE}" != "2" ]]; then
    log_err "环境变量 HY2_NODE_MODE='${HY2_NODE_MODE}' 无效：本项目仅提供商城版（Agent）节点。"
    log_err "请留空或设置 HY2_NODE_MODE=2；单机私密模式已移除。"
    exit 1
fi
if [[ "${HY2_CERT_TYPE:-}" == "3" && -z "${HY2_DOMAIN:-}" ]]; then
    log_err "HY2_CERT_TYPE=3 需要同时提供 HY2_DOMAIN=<你的域名>。"
    exit 1
fi

# 中断保护：Ctrl+C 时明确告知状态，别让用户对着半成品不知所措
on_interrupt() {
    echo
    log_warn "已中断（Ctrl+C）。已完成的步骤不会回滚，重新运行脚本即可从当前状态继续。"
    exit 130
}
trap on_interrupt INT

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
    # ⚠️ 原来三个源全失败时兜底 `echo "127.0.0.1"`（2026-10-09 修）：
    #   1) 函数**永远返回 0**，所以所有调用点的 `get_public_ip || exit 1` 都是死代码；
    #   2) 更糟的是它会把 127.0.0.1 当成真实公网 IP 一路写进 client_meta.json、
    #      印在信息页 URL 上、还拿去做 DNS 校验。用户的节点会「看起来装好了」，
    #      但生成的订阅/二维码指向 127.0.0.1，客户端永远连不上 —— 且毫无提示。
    # 现在：取不到就返回非 0，让调用点那条 `|| exit 1` 真正生效。
    PUBLIC_IP=$(curl -4 -s --max-time 5 https://api.ipify.org 2>/dev/null || true)
    if [[ -z "$PUBLIC_IP" ]]; then
        PUBLIC_IP=$(curl -4 -s --max-time 5 https://icanhazip.com 2>/dev/null || true)
    fi
    if [[ -z "$PUBLIC_IP" ]]; then
        PUBLIC_IP=$(curl -4 -s --max-time 5 https://ipinfo.io/ip 2>/dev/null || true)
    fi
    # 清洗：去掉空白与换行，并校验「像一个可用的公网 IPv4」
    PUBLIC_IP="$(printf '%s' "$PUBLIC_IP" | tr -d '[:space:]')"
    if ! [[ "$PUBLIC_IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        log_err "无法获取本机公网 IP（已尝试 api.ipify.org / icanhazip.com / ipinfo.io）。"
        log_err "常见原因：服务器没有公网出口、出口被防火墙拦截、或 DNS 异常。"
        log_err "若这台机器本就在 NAT 后面，请确认已配置端口转发，或改用 Cloudflare WARP 出口。"
        return 1
    fi
    # ⚠️ 回环/私有地址必须显式拒绝（2026-10-09 补）：上面那个正则只验「像不像 IPv4」，
    # 而 127.0.0.1 / 10.x / 192.168.x 全都合法通过 —— 于是某些出口（本地代理、
    # docker0、SSRF 跳转）会把回环地址当成公网 IP 写进 client_meta.json，
    # 生成的订阅与二维码指向 127.0.0.1，客户端永远连不上。
    # 之前是靠 `echo "127.0.0.1"` 兜底，现在兜底没了，这条检查是最后一道闸。
    # 每一段必须在 0-255 内：正则只验形状，999.999.999.999 也能通过。
    local _octet _decimal _normalized=""
    for _octet in ${PUBLIC_IP//./ }; do
        # 显式十进制，避免 008 报八进制错误；规范化后再做地址范围判断。
        _decimal=$((10#${_octet}))
        if (( _decimal > 255 )); then
            log_err "取到的「公网 IP」不是合法地址（${PUBLIC_IP}）。"
            return 1
        fi
        _normalized+="${_normalized:+.}${_decimal}"
    done
    PUBLIC_IP="$_normalized"
    case "$PUBLIC_IP" in
        # CGNAT 为 100.64.0.0/10，基准测试网为 198.18.0.0/15。
        127.*|10.*|192.168.*|169.254.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|0.*|100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*|198.1[89].*)
            log_err "取到的「公网 IP」是回环或私有地址（${PUBLIC_IP}），不能用于对外服务。"
            log_err "若这台机器确实有公网出口，请检查出口网络/代理设置；"
            log_err "若本就在 NAT 后面，请确认已配置端口转发，或改用 Cloudflare WARP 出口。"
            return 1
            ;;
    esac
    return 0
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
        apt-get update -qq && apt-get install -y -qq curl wget jq openssl iptables tar ca-certificates qrencode python3 || true
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y curl wget jq openssl iptables tar ca-certificates qrencode python3 || true
    elif command -v yum >/dev/null 2>&1; then
        yum install -y curl wget jq openssl iptables tar ca-certificates qrencode python3 || true
    elif command -v apk >/dev/null 2>&1; then
        apk add --no-cache curl wget jq openssl iptables tar ca-certificates bash qrencode python3 || true
    else
        log_warn "未识别的包管理器，请确认已安装 curl, wget, jq, openssl, iptables"
    fi

    # ⚠️ 安装后必须逐个校验（2026-10-09 修）：
    #   包管理器命令失败时不立刻中断（Alpine 上 `apk add iptables` 常因
    #   iptables/nftables 分包而整体失败），但装完必须确认**关键**依赖真的在。
    #   原来完全不校验，于是「jq 没装上」这种致命问题要等到几百行之后
    #   第一次调用 jq 时才炸，用户看到的是完全看不出所以然的报错。
    #   缺 jq / openssl / python3 直接中止；qrencode 只影响二维码，降级继续。
    local missing_critical=() missing_soft=()
    local bin
    for bin in curl jq openssl python3; do
        command -v "$bin" >/dev/null 2>&1 || missing_critical+=("$bin")
    done
    for bin in iptables tar; do
        command -v "$bin" >/dev/null 2>&1 || missing_soft+=("$bin")
    done
    if (( ${#missing_critical[@]} > 0 )); then
        log_err "以下关键依赖缺失：${missing_critical[*]}"
        log_err "缺少它们门户与证书逻辑无法工作。请手动安装后重试，例如："
        log_err "  Debian/Ubuntu : apt-get update && apt-get install -y ${missing_critical[*]}"
        log_err "  CentOS/RHEL   : yum install -y ${missing_critical[*]}"
        log_err "  Alpine        : apk add ${missing_critical[*]}"
        return 1
    fi
    if (( ${#missing_soft[@]} > 0 )); then
        log_warn "以下可选依赖缺失：${missing_soft[*]} —— 相关功能可能不可用。"
    fi
    if ! command -v qrencode >/dev/null 2>&1; then
        log_warn "未安装 qrencode：节点二维码将不可用（可改用「节点直链 (URI)」导入）。"
    fi
    return 0
}

# 2. 安装与更新官方核心二进制
#
# 顺序固定为「先定版本 → 取官方摘要 → 下载 → 校验 → 才替换」。
# 旧实现直接下 latest 再 `version` 试跑就覆盖：`version` 是被下载的二进制自己
# 执行的，植入后门完全可以正常打印版本号，等于没有完整性校验。
install_binary() {
    log_step "获取 Hysteria 2 官方最新版本..."
    # ⚠️ 必须 `|| LATEST_TAG=""`（2026-10-09 修）：命令替换里的 curl 失败会因
    # `set -eo pipefail` 让整个赋值语句失败退出，于是下面那个 fallback 分支
    # 永远执行不到 —— 实测 api.github.com 不可达时 exit=6 直接死掉。
    # 而「api.github.com 被墙/限流」恰恰是本工具用户最常见的处境，
    # 为此专门写的 download.hysteria.network 直链回退形同虚设。
    LATEST_TAG=$(curl -s --max-time 10 https://api.github.com/repos/apernet/hysteria/releases/latest | jq -r '.tag_name // empty') || LATEST_TAG=""

    local asset_arch asset tmpdir expected got
    if ! asset_arch="$(hy2_core_asset_arch "$HY2_ARCH")"; then
        log_err "Hysteria 2 不支持当前 CPU 架构: ${HY2_ARCH}"
        return 1
    fi
    asset="hysteria-linux-${asset_arch}"

    if [[ -z "$LATEST_TAG" || "$LATEST_TAG" == "null" ]]; then
        log_warn "从 GitHub API 获取版本失败，尝试从官方下载站解析最新版本..."
        # 用固定版本目录而不是 `latest/`：`latest` 是浮动指针，下载与取摘要之间
        # 可能已经切换版本，导致摘要与资产对不上（或更糟：对上了另一个版本）。
        local resolved
        resolved="$(curl -fsSIL --max-time 20 "https://download.hysteria.network/app/latest/${asset}" 2>/dev/null |
            awk 'tolower($1)=="location:"{print $2}' | tr -d '\r' | tail -n1)"
        if [[ "$resolved" =~ /app/(v[0-9][^/]*)/${asset}$ ]]; then
            # 下载站只给出裸版本号（v2.13.0），而 GitHub 的 release tag 是
            # `app/v2.13.0`。用裸版本号拼 GitHub URL 实测 404（hashes.txt 与资产
            # 都是），回退路径会因此永远失败，必须补回 app/ 前缀。
            LATEST_TAG="app/${BASH_REMATCH[1]}"
        fi
        if [[ -z "$LATEST_TAG" || "$LATEST_TAG" == "null" ]]; then
            log_err "无法确定 Hysteria 2 版本，已放弃安装（不做无校验下载）。"
            return 1
        fi
    fi

    log_info "目标版本: ${LATEST_TAG} (${asset})"
    log_step "下载二进制文件至 ${HY2_BIN}..."

    tmpdir="$(mktemp -d)"
    # 官方同版本的 hashes.txt；hysteria 的 tag 形如 app/v2.13.0，路径要原样保留。
    if ! expected="$(hy2_expected_sha256 \
            "https://github.com/apernet/hysteria/releases/download/${LATEST_TAG}/hashes.txt" \
            "$asset" "$tmpdir")"; then
        rm -rf "$tmpdir"
        log_err "取不到 Hysteria ${LATEST_TAG} 的官方校验清单（hashes.txt）或其中没有 ${asset}。"
        log_err "无法验证下载内容，已放弃安装，现有二进制未改动。"
        return 1
    fi

    if ! curl -fL --progress-bar --max-time 300 \
            "https://github.com/apernet/hysteria/releases/download/${LATEST_TAG}/${asset}" \
            -o "${tmpdir}/${asset}"; then
        rm -rf "$tmpdir"
        log_err "下载失败，请检查网络连接。现有二进制未改动。"
        return 1
    fi
    got="$(hy2_sha256_file "${tmpdir}/${asset}")" || got=""
    if [[ -z "$got" || "$got" != "$expected" ]]; then
        rm -rf "$tmpdir"
        log_err "Hysteria 二进制校验失败：SHA256 与官方 hashes.txt 不一致。"
        log_err "  期望: ${expected}"
        log_err "  实际: ${got:-<无法读取>}"
        log_err "已放弃安装，现有二进制未改动。"
        return 1
    fi
    chmod +x "${tmpdir}/${asset}"
    # 摘要通过后再跑一次 version 作为附加检查（不替代摘要）。
    if ! "${tmpdir}/${asset}" version >/dev/null 2>&1; then
        rm -rf "$tmpdir"
        log_err "校验通过但二进制无法运行（架构不匹配？），已放弃安装。"
        return 1
    fi
    if ! install -m 0755 "${tmpdir}/${asset}" "${HY2_BIN}.new"; then
        rm -rf "$tmpdir"
        log_err "写入 ${HY2_BIN}.new 失败，现有二进制未改动。"
        return 1
    fi
    rm -rf "$tmpdir"
    if ! mv -f "${HY2_BIN}.new" "$HY2_BIN"; then
        rm -f "${HY2_BIN}.new"
        log_err "替换 ${HY2_BIN} 失败，现有二进制未改动。"
        return 1
    fi
    log_info "Hysteria 2 二进制安装成功！版本信息: $($HY2_BIN version 2>&1 | grep -E '^Version:' | head -n1 || echo '未知')"
}

# 3. 证书处理模块（自签名 / 自有证书 / ACME 域名证书）
# 已装机时从现有 config.yaml 还原证书配置，供 CLI 重装（bash install.sh install）复用。
#
# 🔴 为什么必须有（2026-10-29 修）：`install` 子命令不询问证书方式，旧实现
# 在无终端时 read 走默认 1 → 重新生成自签证书并把 SNI 改成 www.bing.com，
# 端口也重新随机。一次「升级」就把正式证书降级成自签、换掉端口，
# 已发放的客户端配置全部失效，而脚本一路显示正常完成。
reuse_existing_cert_config() {
    [[ -f "$HY2_CONFIG" ]] || return 1
    local txt cert key dom email mt insecure
    txt="$(cat "$HY2_CONFIG" 2>/dev/null || true)"
    [[ -n "$txt" ]] || return 1
    mt="$(jq -r '.cert_type // empty' "$HY2_META_FILE" 2>/dev/null || true)"
    insecure="$(jq -r '.is_insecure // empty' "$HY2_META_FILE" 2>/dev/null || true)"

    if grep -q '^acme:' <<<"$txt"; then
        dom="$(awk '/^acme:/{f=1;next} /^[^ ]/{f=0} f&&/^[[:space:]]*-[[:space:]]/{sub(/^[[:space:]]*-[[:space:]]*/,"");gsub(/"/,"");print;exit}' <<<"$txt")"
        email="$(awk '/^[[:space:]]*email:/{sub(/^[[:space:]]*email:[[:space:]]*/,"");gsub(/"/,"");print;exit}' <<<"$txt")"
        CERT_TYPE="acme"
        SERVER_NAME="${SERVER_NAME:-$dom}"
        ACME_EMAIL="${ACME_EMAIL:-$email}"
        IS_INSECURE="false"
    else
        cert="$(awk '/^tls:/{f=1;next} /^[^ ]/{f=0} f&&/^[[:space:]]*cert:/{sub(/^[[:space:]]*cert:[[:space:]]*/,"");gsub(/^"|"$/,"");print;exit}' <<<"$txt")"
        key="$(awk '/^tls:/{f=1;next} /^[^ ]/{f=0} f&&/^[[:space:]]*key:/{sub(/^[[:space:]]*key:[[:space:]]*/,"");gsub(/^"|"$/,"");print;exit}' <<<"$txt")"
        [[ -n "$cert" && -n "$key" && -f "$cert" && -f "$key" ]] || return 1
        CERT_FILE="$cert"
        KEY_FILE="$key"
        if [[ "$mt" == "self_signed" || "$insecure" == "true" ]]; then
            CERT_TYPE="self_signed"
            IS_INSECURE="true"
        else
            CERT_TYPE="custom"
            IS_INSECURE="false"
        fi
    fi
    if [[ -z "${SERVER_NAME:-}" ]]; then
        SERVER_NAME="$(jq -r '.server_name // empty' "$HY2_META_FILE" 2>/dev/null || true)"
    fi
    return 0
}

setup_certificates() {
    # CLI 重装且未显式指定 HY2_CERT_TYPE 时，调用方会先 restore 现有配置并置位。
    if [[ "${HY2_CERT_REUSE:-0}" == "1" ]]; then
        log_info "沿用现有证书配置（${CERT_TYPE}${SERVER_NAME:+ · ${SERVER_NAME}}），不重新签发。"
        return 0
    fi
    mkdir -p "$HY2_CERT_DIR"
    # 迁移准备阶段复用已验证的证书，不提前切换DNS来申请新证书。
    if [[ -n "${HY2_CUSTOM_CERT_FILE:-}" || -n "${HY2_CUSTOM_KEY_FILE:-}" ]]; then
        [[ -r "${HY2_CUSTOM_CERT_FILE:-}" && -r "${HY2_CUSTOM_KEY_FILE:-}" ]] || { log_err "迁移证书文件不可读"; return 1; }
        openssl x509 -in "$HY2_CUSTOM_CERT_FILE" -noout -checkend 3600 >/dev/null || { log_err "迁移证书无效或即将过期"; return 1; }
        openssl pkey -in "$HY2_CUSTOM_KEY_FILE" -noout >/dev/null 2>&1 || { log_err "迁移私钥无效"; return 1; }
        local cert_pub key_pub
        cert_pub=$(openssl x509 -in "$HY2_CUSTOM_CERT_FILE" -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum | cut -d' ' -f1)
        key_pub=$(openssl pkey -in "$HY2_CUSTOM_KEY_FILE" -pubout -outform DER | sha256sum | cut -d' ' -f1)
        [[ "$cert_pub" == "$key_pub" ]] || { log_err "迁移证书与私钥不匹配"; return 1; }
        CERT_TYPE="custom"
        CERT_FILE="$HY2_CUSTOM_CERT_FILE"
        KEY_FILE="$HY2_CUSTOM_KEY_FILE"
        SERVER_NAME="${HY2_DOMAIN:-$PUBLIC_IP}"
        IS_INSECURE="${HY2_CUSTOM_INSECURE:-false}"
        log_info "已复用迁移证书，未改动DNS。"
        return
    fi

    
    echo -e "\n${CYAN}------------------------------------------------------------${PLAIN}"
    echo -e "${GREEN}TLS 证书配置方式：${PLAIN}"
    echo -e "  ${YELLOW}1.${PLAIN} 自签名证书 —— 最快，但客户端必须开「跳过证书校验」，个别客户端不支持"
    echo -e "  ${YELLOW}2.${PLAIN} 使用已有证书文件 (acme.sh / certbot 签发的 fullchain.pem + privkey.pem)"
    echo -e "  ${YELLOW}3.${PLAIN} 绑定域名自动申请 Let's Encrypt —— ${GREEN}已有域名的话强烈建议选这个${PLAIN}"
    echo -e "  ${YELLOW}4.${PLAIN} 自动扫描本机已装证书 (Let's Encrypt / acme.sh)"
    echo -e "${CYAN}------------------------------------------------------------${PLAIN}"
    echo -e "  ${YELLOW}怎么选：有域名 → 选 3（客户端零额外设置）；没域名 → 选 1（记得客户端开 insecure）。${PLAIN}"
    if [[ -n "${HY2_CERT_TYPE:-}" ]]; then
        cert_choice="$HY2_CERT_TYPE"
        log_info "已使用环境变量 HY2_CERT_TYPE=${cert_choice} 选择证书方式。"
    else
        read -rp "请选择证书类型 [默认: 1]: " cert_choice || true
        cert_choice=${cert_choice:-1}
    fi
    if [[ "$cert_choice" == "1" ]]; then
        log_info "已选自签名证书：客户端需开启「跳过证书校验 / insecure」。"
        log_info "本脚本生成的客户端直链已自动附带 pinSHA256 + insecure=1，按直链导入即可。"
    fi

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
        # ⚠️ 失败必须回退自签，不能裸调用（2026-10-09 修）：
        # select_local_certificate 会 return 1（本机没扫到完整证书链 / 选错编号 /
        # 域名留空）。原先是裸调用 + set -e，直接终止整个安装 —— 而菜单里
        # 自签本来就是一个合法选项，用户选了 4 却被迫重跑整个脚本才能退回去。
        # 现在回退到自签并说明原因。
        if ! select_local_certificate; then
            log_warn "未能使用本机已有证书（未找到完整证书链、或选择无效）。"
            log_warn "将回退为自签名证书 —— 客户端需开启「跳过证书校验 / insecure」。"
            generate_self_signed_cert
        fi
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
    done < <(find -L /etc/letsencrypt/live /root/.acme.sh /home -type f \( -name fullchain.pem -o -name fullchain.cer \) 2>/dev/null)
    if [[ ${#certs[@]} -eq 0 ]]; then
        log_err "未发现含完整证书链的证书 (fullchain.pem / fullchain.cer)。"
        log_err "仅含叶证书的 <domain>.cer 已被跳过，请选择其他证书方式。"
        return 1
    fi
    echo -e "${GREEN}发现以下本机证书：${PLAIN}"
    for i in "${!certs[@]}"; do echo -e "  ${YELLOW}$((i+1)).${PLAIN} ${certs[$i]%%|*}"; done
    # 只有一张证书时无需询问 —— README 把 type 4 列为可用于免交互部署，
    # 但旧实现在无终端时会卡在两次 read 上（第二处还没有容错，
    # set -e 下会直接终止整个脚本）。
    if [[ ${#certs[@]} -eq 1 ]]; then
        choice=1
    else
        read -rp "请选择证书编号: " choice || true   # EOF 时走下面的无效选择分支
    fi
    [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#certs[@]} )) || { log_err "无效选择。"; return 1; }
    cert="${certs[$((choice-1))]%%|*}"; key="${certs[$((choice-1))]#*|}"
    CERT_TYPE="custom"; CERT_FILE="$cert"; KEY_FILE="$key"; IS_INSECURE="false"
    # SNI 能直接从证书 SAN/CN 推出来时不必再问（无人值守路径的关键）。
    if [[ -z "${SERVER_NAME:-}" ]]; then
        SERVER_NAME="$(openssl x509 -in "$cert" -noout -ext subjectAltName 2>/dev/null | grep -oE 'DNS:[A-Za-z0-9*._-]+' | head -1 | sed 's/^DNS://')"
        [[ -z "$SERVER_NAME" ]] && SERVER_NAME="$(openssl x509 -in "$cert" -noout -subject 2>/dev/null | sed -n 's/.*CN *= *\([^,]*\).*/\1/p')"
    fi
    if [[ -z "${SERVER_NAME:-}" ]]; then
        read -rp "请输入证书绑定的域名 (SNI): " SERVER_NAME || true
    fi
    [[ -n "$SERVER_NAME" ]] || { log_err "域名不能为空。"; return 1; }
}

# 🔴 检查某个 TCP/UDP 端口是否已被占用，并报告占用者（供 ACME 前置检查用）
# 输出：空=空闲；否则是进程名（如 caddy）。
# ⚠️ 不用 `ss -H -tlnp --sport N`：iproute2 6.1.0 既不认 `--sport`，
#    而 `ss -t` 传错会让 ss 直接报错退出、被 2>/dev/null 吞掉，
#    结果是"明明被占却报空闲"—— 静默失败最危险，必须用 grep 兜底。
port_owner() {
    local proto="$1" port="$2" flag line pname
    case "$proto" in
        tcp) flag="-tlnp" ;;
        udp) flag="-ulnp" ;;
        *)   return 0 ;;
    esac
    line="$(ss -H $flag 2>/dev/null | grep -E "[:.]${port}[[:space:]]" | head -1)"
    # 再用 python3 bind 兜底：ss 解析不出来时以实际能否绑定为准
    if [[ -z "$line" ]] && command -v python3 >/dev/null 2>&1; then
        if python3 -c '
import socket,sys
p=sys.argv[1];t=sys.argv[2]
s=socket.socket(socket.AF_INET, socket.SOCK_STREAM if t=="tcp" else socket.SOCK_DGRAM)
try:
    s.bind(("0.0.0.0",int(p))); sys.exit(1)
except OSError: sys.exit(0)
finally: s.close()
' "$port" "$proto" 2>/dev/null; then
            # 绑不上 = 确实被占，但 ss 没能报出是谁
            echo "unknown"
            return 0
        fi
        return 0
    fi
    [[ -z "$line" ]] && return 0
    pname="$(sed -n 's/.*users:((\"\([^\"]*\)\".*/\1/p' <<<"$line")"
    echo "${pname:-unknown}"
}

# 🔴🔴 检测本机 80/443 是否被占用，据此决定 ACME 该怎么签。
#
#背景：Let's Encrypt 只有两种验证方式，**都要求端口空闲**：
#   - HTTP-01    : 需要 TCP 80
#   - TLS-ALPN-01: 需要 TCP 443
# 在已经跑了 Caddy / Nginx 的机器上（绝大多数生产机）这两个端口都被占，
# 而 Hysteria 内置的 ACME 客户端**没有任何办法绕过**——
# 于是自动签发必然失败，用户只能退回去签证书，表现就是
# 「装好了但客户端连不上（还得开跳过证书校验）」。
#
# 结论：这时唯一干净的路是**让已在跑的反代（通常就是 Caddy）去签**，
# 它自己就是那个占着端口的程序，签完把 fullchain 交给 Hysteria复用即可。
# 两者完全可以共存：Hysteria 主监听是 **UDP** 端口，
# 与反代的 TCP/UDP 443 通常不冲突。
detect_webserver_squatting() {
    local occupied=() who80 who443
    who80="$(port_owner tcp 80)"
    who443="$(port_owner tcp 443)"
    [[ -n "$who80" ]]  && occupied+=("TCP 80 (${who80})")
    [[ -n "$who443" ]] && occupied+=("TCP 443 (${who443})")
    if [[ ${#occupied[@]} -eq 0 ]]; then
        ACRE_PORT_BLOCKER=""
        return 1   # 空闲：可以自己签
    fi
    ACRE_PORT_BLOCKER="$(printf '%s、' "${occupied[@]}")"; ACRE_PORT_BLOCKER="${ACRE_PORT_BLOCKER%、}"
    return 0       # 被占：需要复用
}

#🔴 从Caddy / Nginx 的存储里找出本机已签发的、匹配域名的【完整证书链】。
# 输出 "cert|key"（找到）或空串（没找到）。
find_cert_in_webserver() {
    local domain="$1" c k
    # 优先搜 Caddy 2.x：/var/lib/caddy/.local/share/caddy/certificates/<ca>/<domain>/
    # 🔴 CADDY_CERT_ROOT 可覆盖根路径：不同发行版/运行用户路径不同，
    #    同时留出测试注入点 —— 否则本函数无法被测试覆盖。
    local -a croots=()
    if [[ -n "${CADDY_CERT_ROOT:-}" ]]; then
        croots=("${CADDY_CERT_ROOT}")
    else
        croots=(/var/lib/caddy/.local/share/caddy/certificates
                /var/lib/caddy/certificates
                /root/.local/share/caddy/certificates)
    fi
    for r in "${croots[@]}"; do
        for c in "$r"/*/"$domain"/"$domain".crt; do
            k="${c%.crt}.key"
            _accept_cert_pair "$c" "$k" || continue
            echo "$c|$k"; return 0
        done
    done

    # 🔴 Nginx（certbot 签发）：布局完全不同，且路径由配置决定，不能硬编码。
    # Nginx 装机量远大于 Caddy，缺了这条会让大量用户仍退回自签。
    for c in $(_nginx_cert_candidates); do
        k="${c%.crt}.key"; [[ -s "$k" ]] || k="${c%.fullchain.pem}.privkey.pem"
        _accept_cert_pair "$c" "$k" || continue
        if _cert_matches_domain "$c" "$domain"; then
            echo "$c|$k"; return 0
        fi
    done
    return 1
}

# 判断证书文件与其私钥是否构成一对可用组合
# 传入证书路径；私钥路径由调用方给出（不同布局命名不同：.key / privkey.pem）
_accept_cert_pair() {
    local c="$1" k="${2:-}"
    [[ -s "$c" ]] || return 1
    [[ -n "$k" ]] || return 1
    [[ -s "$k" ]] || return 1
    # 正式证书必须含完整链（>1 张）；只有 1 张说明是叶证书，
    # Go 系客户端（v2rayNG/Xray/hysteria）不会通过 AIA 补齐中间证书，
    # 会直接报 x509: certificate signed by unknown authority
    [[ "$(grep -c 'BEGIN CERTIFICATE' "$c" 2>/dev/null || echo 0)" -ge 2 ]] || return 1
    # 🔴 公私钥必须配对：不配对的证书装上去，握手 100% 失败。
    # 与其等到用户连不上才发现，不如在这里就拒掉。
    local pub prv
    pub="$(openssl x509 -in "$c" -noout -pubkey 2>/dev/null | openssl sha256 2>/dev/null | awk '{print $NF}')"
    prv="$(openssl pkey -in "$k" -pubout 2>/dev/null | openssl sha256 2>/dev/null | awk '{print $NF}')"
    [[ -n "$pub" && "$pub" == "$prv" ]] || return 1
    return 0
}

# 列出 Nginx/certbot 可能存放的证书文件
_nginx_cert_candidates() {
    local d
    for d in /etc/letsencrypt/live/*/ /etc/nginx/certs/ /etc/nginx/ssl/ \
             /var/lib/letsencrypt/live/*/ /usr/local/nginx/conf/ssl/; do
        [[ -d "$d" ]] || continue
        find "$d" -maxdepth 1 -type f \( -name 'fullchain.pem' -o -name '*.crt' -o -name '*.pem' \) 2>/dev/null
    done
}

# 证书的 CN 或 SAN 是否命中目标域名
_cert_matches_domain() {
    local c="$1" domain="$2" txt
    txt="$(openssl x509 -in "$c" -noout -subject -ext subjectAltName 2>/dev/null)"
    [[ -n "$txt" ]] || return 1
    grep -qiE "(^|[^a-zA-Z0-9.-])${domain//./\\.}([^a-zA-Z0-9.-]|$)" <<<"$txt"
}

# ------------------------------------------------------------------------------
# 对外占位页（防主动探测）
#
# 🔴 以前借 Caddy 签证书时追加的站点块是 `respond "hy2 cert holder" 200` ——
#    任何人打开这个域名都能看到「这是 hy2 节点」，主动探测一眼就能认出来。
#    现在只返回一个普通的「建设中」占位页：标题是域名本身，不含任何代理、
#    协议、软件名字样，看上去和无数停放中的域名一样。
# ------------------------------------------------------------------------------
caddy_decoy_directives() {
    local domain="$1"
    # Caddyfile 的反引号字符串可以多行、不做转义；正文里不能出现反引号。
    cat <<DEOF
	header Content-Type "text/html; charset=utf-8"
	header -Server
	respond \`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${domain}</title><style>body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;font:16px/1.6 -apple-system,Segoe UI,Helvetica,Arial,sans-serif;color:#444;background:#fafafa}main{text-align:center;padding:24px}h1{font-weight:500;font-size:22px;margin:0 0 8px}p{margin:0;color:#888}</style></head><body><main><h1>${domain}</h1><p>This site is under construction.</p></main></body></html>\` 200
DEOF
}

# 把老装机遗留的 `respond "hy2 cert holder" 200` 换成占位页。
# 备份 → 替换 → caddy validate → reload；任何一步失败都回滚，绝不留下坏配置。
scrub_caddy_identity() {
    local cf="/etc/caddy/Caddyfile" bak tmp domain
    [[ -f "$cf" ]] || return 0
    grep -q 'respond "hy2 cert holder"' "$cf" 2>/dev/null || return 0
    command -v caddy >/dev/null 2>&1 || return 0
    bak="${cf}.bak-scrub-$(date +%Y%m%d-%H%M%S)"
    cp -a "$cf" "$bak" || return 1
    tmp="$(mktemp)"
    # 逐行处理：遇到自报身份的 respond 行，用它所在站点块的域名生成占位页。
    domain=""
    while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ "$line" =~ ^([A-Za-z0-9.-]+)[[:space:]]*\{[[:space:]]*$ ]]; then
            domain="${BASH_REMATCH[1]}"
        fi
        if [[ "$line" == *'respond "hy2 cert holder"'* ]]; then
            caddy_decoy_directives "${domain:-localhost}" >>"$tmp"
            continue
        fi
        if [[ "$line" == "# Hysteria 2 节点证书专用站点（由 install.sh 自动追加）" ]]; then
            line="# 证书签发站点（由 install.sh 自动追加）"
        fi
        printf '%s\n' "$line" >>"$tmp"
    done <"$cf"
    cat "$tmp" >"$cf"; rm -f "$tmp"
    if ! caddy validate --config "$cf" --adapter caddyfile >/dev/null 2>&1; then
        cp -a "$bak" "$cf"
        log_warn "Caddy 占位页替换后校验不通过，已回滚（备份 ${bak}）"
        return 1
    fi
    systemctl reload caddy 2>/dev/null || systemctl restart caddy 2>/dev/null || true
    log_info "已把 Caddy 上自报身份的证书站点换成普通占位页（备份 ${bak}）"
}

# 🔴 让已占端口的 Caddy 为某域名签一张证书（复用它的自动签发能力）。
# 不改动用户已有的 Caddyfile 逻辑，只**追加**一个极小的站点块，
# 签完证书由 Caddy 保管、Hysteria 只读，续期也由 Caddy 负责。
setup_cert_via_existing_caddy() {
    local domain="$1"
    local certdir="/var/lib/caddy/.local/share/caddy/certificates"
    command -v caddy >/dev/null 2>&1 || { log_err "未找到 caddy 命令。"; return 1; }

    log_step "检测到本机 Caddy，正尝试让它为 ${domain} 签发证书..."
    # 先看它手里有没有现成的（含自动续期签过的）
    if find_cert_in_webserver "$domain" >/dev/null 2>&1; then
        log_info "Caddy 已有 ${domain} 的证书，直接复用。"
        return 0
    fi

    # 备份后追加站点块
    local cf="/etc/caddy/Caddyfile" bak
    [[ -f "$cf" ]] || { log_err "找不到 /etc/caddy/Caddyfile。"; return 1; }
    bak="${cf}.bak-hy2-$(date +%Y%m%d-%H%M%S)"
    cp -a "$cf" "$bak" || { log_err "备份 Caddyfile 失败。"; return 1; }
    log_info "已备份 Caddyfile -> ${bak}"

    # 幂等：已存在该域名块就不重复追加
    if ! grep -qE "^[[:space:]]*${domain//./\\.}([[:space:]]|\{)" "$cf"; then
        cat >> "$cf" <<CEOF

# 证书签发站点（由 install.sh 自动追加）
# 用途：本机 80/443 已被 Caddy 占用，内置 ACME 无法自行签发，
# 故借 Caddy 之手签发并保管证书。对外只返回一个普通的占位页。
${domain} {
$(caddy_decoy_directives "$domain")
}
CEOF
    fi
    if ! caddy validate --config "$cf" >/dev/null 2>&1; then
        log_err "追加后的 Caddyfile 校验不通过，已回滚。"
        cp -a "$bak" "$cf"
        return 1
    fi
    # reload 而非 restart：保住现有线上连接（Caddy 2 在跑生产站点）
    if ! systemctl reload caddy 2>/dev/null; then
        systemctl restart caddy 2>/dev/null || true
    fi
    sleep 3
    # 触发签发
    curl -s -o /dev/null -m 15 "http://${domain}/" 2>/dev/null || true

    log_info "等待 Caddy 完成 ACME 签发（通常 5~30 秒）..."
    local i
    for i in $(seq 1 12); do
        if find_cert_in_webserver "$domain" >/dev/null 2>&1; then
            log_info "Caddy 签发成功: ${certdir}"
            return 0
        fi
        sleep 5
    done
    log_err "等待 60 秒仍未拿到证书。请查看: journalctl -u caddy -n 50"
    return 1
}

# 确保 acme.sh 可用：已有安装先做身份核验，没有就按固定 commit 校验后安装。
# DNS API 与借 Nginx 签发两条路共用（2026-10-29 从 setup_cert_via_dns_api 抽出）。
hy2_acme_ensure() {
    local acct="${HOME}/.acme.sh/acme.sh"
    if [[ -x "$acct" ]]; then
        # 已有安装：不重装、不覆盖；**身份核验不通过就硬失败**，
        # 绝不在执行该脚本 / 调用它签发之前放行。
        if ! hy2_acme_check_existing "$HOME/.acme.sh"; then
            log_err "已有 acme.sh 未通过身份核验，已停止：本次不执行它、不签发证书。"
            log_err "现有证书/账号/脚本均未被改动；按上面的修复办法处理后重跑。"
            return 1
        fi
    else
        log_step "正在安装 acme.sh ..."
        # 🔴 绝不把 get.acme.sh 的内容直接管道给 shell：那是下载即执行，
        # 而且 get.acme.sh 自己还会再去拉浮动 master 的 acme.sh。这里改成
        # pin commit + 逐文件 blob 身份校验，只有全部通过才执行安装器；
        # 任何失败都保持原环境不变。
        if ! hy2_acme_install_verified "$HOME/.acme.sh"; then
            log_err "acme.sh 安装失败或未通过校验。"
            log_err "本项目不再执行未校验的远程安装脚本；请确认本机可访问 GitHub API 后重试。"
            return 1
        fi
    fi
    [[ -x "$acct" ]] || { log_err "acme.sh 不可用。"; return 1; }
}

# 借本机 Nginx 完成 HTTP-01 签发（2026-10-29）。
#
# 80 被 Nginx 占着时，Hysteria 内置 ACME 无法监听 80；但 HTTP-01 只要求
# http://<域名>/.well-known/acme-challenge/<token> 能取到文件 —— 让 Nginx 来回答即可：
#   * Nginx 里已有该域名的站点：用 acme.sh 的 --nginx 模式，它临时往那个
#     server 块里插入验证路径、签完还原，不碰站点其它配置；
#   * 没有：新增 conf.d/hy2-acme-<域名>.conf，只回答验证路径、其余一律 404。
#     这个文件要保留 —— 以后 acme.sh 自动续期还要用它。
# 任何对 Nginx 配置的改动都先 `nginx -t`，不通过立即撤销，绝不能把现有网站弄挂。
# 输出 "cert|key"；返回 1 表示这条路走不通（调用方继续走 DNS API 兜底）。
HY2_ACME_WEBROOT="/var/lib/hy2-acme-webroot"

nginx_has_server_name() {
    # nginx -T 输出全部生效配置。先按 ; { } 切成单条指令再找 server_name ——
    # 不能只认行首：`server { listen 80; server_name a.com; }` 这种写在一行里的
    # 站点会被漏掉，随后新建的同名 server 块会把原网站顶成 404（SE 实测踩到）。
    # 先去注释、并成一行：server_name 的多个域名可以跨行书写。
    nginx -T 2>/dev/null | sed 's/#.*//' | tr '\n' ' ' | tr ';{}' '\n\n\n' \
        | sed -nE 's/^[[:space:]]*server_name[[:space:]]+//p' | tr -s ' \t' '\n\n' | grep -qxF "$1"
}

nginx_name_conflict() {
    # 同名 server 块并存时 nginx 只给警告、仍能加载，但先加载的那个会接管该域名。
    nginx -t 2>&1 | grep -qF "conflicting server name \"$1\""
}

nginx_reload_checked() {
    nginx -t >/dev/null 2>&1 || return 1
    systemctl reload nginx >/dev/null 2>&1 || nginx -s reload >/dev/null 2>&1
}

setup_cert_via_nginx() {
    local domain="$1" email="$2"
    # 调用方用 $(...) 取 "cert|key"：日志与 acme.sh 输出全部改走 stderr，
    # 只有最后那一行结果写到 fd 3（原 stdout）。
    exec 3>&1 1>&2
    command -v nginx >/dev/null 2>&1 || return 1
    [[ "$(port_owner tcp 80)" == *nginx* ]] || { log_warn "TCP 80 不是 Nginx 在监听，无法借 Nginx 签发。"; return 1; }
    if ! nginx -t >/dev/null 2>&1; then
        log_warn "Nginx 现有配置自检 (nginx -t) 未通过，为避免影响现有网站，不借 Nginx 签发。"
        return 1
    fi
    hy2_acme_ensure || return 1
    local acct="${HOME}/.acme.sh/acme.sh" conf="" rc=0
    export SKIP_ACME_SH_UPGRADE=1

    if nginx_has_server_name "$domain"; then
        log_step "Nginx 已有 ${domain} 的站点，用 acme.sh --nginx 模式临时插入验证路径..."
        "$acct" --issue --nginx -d "$domain" --server letsencrypt \
            --accountemail "$email" --keylength ec-256 || rc=$?
    else
        conf="/etc/nginx/conf.d/hy2-acme-${domain}.conf"
        if [[ ! -d /etc/nginx/conf.d ]]; then
            log_warn "找不到 /etc/nginx/conf.d，无法为 ${domain} 新增验证配置。"
            return 1
        fi
        log_step "为 ${domain} 新增只响应 ACME 验证路径的 Nginx 配置: ${conf}"
        mkdir -p "$HY2_ACME_WEBROOT/.well-known/acme-challenge"
        chmod 755 "$HY2_ACME_WEBROOT" "$HY2_ACME_WEBROOT/.well-known" "$HY2_ACME_WEBROOT/.well-known/acme-challenge"
        local listen6="    listen [::]:80;"
        [[ -f /proc/net/if_inet6 ]] || listen6=""
        cat > "$conf" <<EOF
# 由 hysteria2-installer 生成：只用于 Let's Encrypt 签发与续期 ${domain}，请勿删除。
server {
    listen 80;
${listen6}
    server_name ${domain};
    location ^~ /.well-known/acme-challenge/ {
        root ${HY2_ACME_WEBROOT};
        default_type text/plain;
        try_files \$uri =404;
    }
    location / {
        return 404;
    }
}
EOF
        chmod 644 "$conf"
        if ! nginx_reload_checked; then
            # IPv6 监听不可用时再试一次只监听 IPv4。
            sed -i '/listen \[::\]:80;/d' "$conf"
            if ! nginx_reload_checked; then
                rm -f "$conf"
                nginx_reload_checked || true
                log_warn "新增的 Nginx 配置未通过 nginx -t，已撤销，现有网站不受影响。"
                return 1
            fi
        fi
        if ! nginx -T 2>/dev/null | grep -qF "$conf"; then
            rm -f "$conf"
            nginx_reload_checked || true
            log_warn "Nginx 主配置没有包含 /etc/nginx/conf.d/*.conf，无法借 Nginx 签发。"
            return 1
        fi
        # 最后一道保险：检测漏掉了已有的同名站点时，新块会抢走这个域名，立即撤销。
        if nginx_name_conflict "$domain"; then
            rm -f "$conf"
            nginx_reload_checked || true
            log_warn "Nginx 里已有 ${domain} 的站点，新增配置会与它冲突，已撤销。"
            return 1
        fi
        "$acct" --issue -w "$HY2_ACME_WEBROOT" -d "$domain" --server letsencrypt \
            --accountemail "$email" --keylength ec-256 || rc=$?
    fi

    local certdir="$HOME/.acme.sh/${domain}_ecc"
    # acme.sh 返回 2 表示「证书仍有效、本次跳过」，同样算成功。
    if [[ ( $rc -ne 0 && $rc -ne 2 ) || ! -s "$certdir/fullchain.cer" || ! -s "$certdir/${domain}.key" ]]; then
        # 签发失败就撤掉本次新增的验证配置，不在 Nginx 里留下无用的 server 块。
        if [[ -n "$conf" ]]; then
            rm -f "$conf"
            nginx_reload_checked || true
        fi
        log_err "借 Nginx 签发失败（acme.sh 返回 ${rc}）。常见原因：域名没解析到本机、云安全组没放行 TCP 80。"
        return 1
    fi
    # 复制到 /etc/hysteria/cert 并登记续期后的重启命令：Hysteria / Xray / sing-box
    # 都只在启动时读证书，续期后不重启就一直用旧证书，到期即全部握手失败。
    local out_cert="${HY2_CERT_DIR}/acme-${domain}.crt" out_key="${HY2_CERT_DIR}/acme-${domain}.key"
    mkdir -p "$HY2_CERT_DIR"
    if ! "$acct" --install-cert -d "$domain" --ecc \
            --fullchain-file "$out_cert" --key-file "$out_key" \
            --reloadcmd "systemctl try-restart hysteria-server xray hy2-anytls hy2-tuic" >/dev/null; then
        log_err "证书已签发，但复制到 ${HY2_CERT_DIR} 失败。"
        return 1
    fi
    chmod 600 "$out_key"
    log_info "借 Nginx 签发成功；续期由 acme.sh 定时任务自动完成，续期后自动重启相关服务。"
    echo "$out_cert|$out_key" >&3
    return 0
}

# 🔴 兜底路线：在 80/443 被占、且无法借反代签发时，用 **acme.sh 的 DNS API**签发。
#
# 为什么这是端口冲突下唯一还走得通的路：
#   HTTP-01 要 80、TLS-ALPN-01 要 443 —— 两个都被占就彻底没辙。
#   而 DNS-01 验证走的是 **DNS 查询**（往 _acme-challenge.<域名> 写一条 TXT），
#   **完全不碰任何端口**，因此与端口占用彻底解耦。
#
# 代价：需要 DNS 服务商的 API 凭据。凭据从环境变量读，不落仓库：
#   HY2_CF_TOKEN + HY2_CF_EMAIL   （Cloudflare）
#   HY2_ALICLOUD_KEY              （阿里云）
#   HY2_DP_TOKEN+ HY2_DP_ID       （DuckDNS）
# 拿不到凭据就明确告诉用户怎么办，而不是静默退回自签。
setup_cert_via_dns_api() {
    local domain="$1"
    # 调用方用 $(...) 取 "cert|key"：日志与 acme.sh 输出全部改走 stderr，
    # 只有最后那一行结果写到 fd 3（原 stdout）。此前日志混进结果，CERT_FILE
    # 会变成「一大段日志 + 路径」，Hysteria 读不到证书（2026-10-29 修）。
    exec 3>&1 1>&2

    # 🔴🔴 必须【先选凭据、后装 acme.sh】。
    # 旧顺序是「先装 acme.sh → 再看有没有凭据」，两个后果：
    #   1. 没凭据时白装一次（下载+解压几十 MB），纯属浪费；
    #   2. 更糟：HOME 不可写或网络受限时会在安装步骤 return 1，
    #      把「没有凭据」误报成「acme.sh 安装失败」——
    #      用户会去查网络/目录权限，而真正该做的是导出凭据。2026-10-08 实测命中。
    local provider="" prov_env=""
    if [[ -n "${HY2_CF_TOKEN:-}" && -n "${HY2_CF_EMAIL:-}" ]]; then
        provider="Cloudflare"; prov_env="HY2_CF_TOKEN + HY2_CF_EMAIL"
    elif [[ -n "${HY2_ALICLOUD_KEY:-}" ]]; then
        provider="阿里云";    prov_env="HY2_ALICLOUD_KEY"
    elif [[ -n "${HY2_DP_TOKEN:-}" ]]; then
        provider="DuckDNS";   prov_env="HY2_DP_TOKEN"
    else
        log_warn "没有可用的 DNS API 凭据，跳过 DNS API 签发。"
        return 2      # 2 = 无凭据（不是失败，是"这条路走不了"）
    fi

    local acct="${HOME}/.acme.sh/acme.sh"
    hy2_acme_ensure || return 1

    log_info "使用 ${provider} DNS API 签发..."
    # 注意：上游 acme.sh **没有** SKIP_ACME_SH_UPGRADE 这个开关（grep 全文件 0 次命中），
    # 真正生效的是 account.conf 里的 AUTO_UPGRADE='0'（安装/检查时已写入）。
    # 这里保留导出只是为了兼容旧脚本行为，不要指望它阻止升级。
    export SKIP_ACME_SH_UPGRADE=1
    local ok=0
    case "$provider" in
        Cloudflare)
            "$acct" --issue --dns dns_cf -d "$domain" \
                --dns_cf_token "$HY2_CF_TOKEN" --dns_cf_email "$HY2_CF_EMAIL" || ok=1
            ;;
        阿里云)
            "$acct" --issue --dns dns_ali -d "$domain" \
                --dns_ali_key "$HY2_ALICLOUD_KEY" --dns_ali_secret "${HY2_ALICLOUD_SECRET:-}" || ok=1
            ;;
        DuckDNS)
            "$acct" --issue --dns dns_dp -d "$domain" \
                --dns_dp_token "$HY2_DP_TOKEN" || ok=1
            ;;
    esac

    if [[ $ok -ne 0 ]]; then
        log_err "${provider} DNS API 签发失败（凭据来源：${prov_env}）。"
        log_err "常见原因：token 权限不足 / 域名未托管在该 DNS 服务商下。"
        return 1
    fi

    # acme.sh 的输出布局：$HOME/.acme.sh/<domain>_ecc/
    local certdir="$HOME/.acme.sh/${domain}_ecc"
    if [[ ! -s "$certdir/fullchain.cer" ]]; then
        log_err "acme.sh 未产出 fullchain.cer，请检查上方报错。"
        return 1
    fi
    log_info "acme.sh 签发成功。"
    echo "$certdir/fullchain.cer|$certdir/${domain}.key" >&3
    return 0
}

setup_acme_certificate() {
    echo -e "${YELLOW}申请 ACME 证书前，请确认域名 A/AAAA 记录已指向本机，且云安全组与本机防火墙允许 TCP 80。${PLAIN}"
    if [[ -n "${HY2_DOMAIN:-}" ]]; then
        SERVER_NAME="$HY2_DOMAIN"
        log_info "已使用环境变量 HY2_DOMAIN=${SERVER_NAME} 指定域名。"
    else
        read -rp "请输入要绑定的域名 (例如 hy2.example.com): " SERVER_NAME || true
    fi
    if [[ -z "$SERVER_NAME" || "$SERVER_NAME" == *"/"* || "$SERVER_NAME" == *":"* ]]; then
        log_err "域名不能为空，且不能包含协议、路径或端口。"
        return 1
    fi
    if [[ -n "${HY2_EMAIL:-}" ]]; then
        ACME_EMAIL="$HY2_EMAIL"
        log_info "已使用环境变量 HY2_EMAIL 指定通知邮箱。"
    else
        read -rp "请输入 ACME 通知邮箱: " ACME_EMAIL || true
    fi
    if [[ -z "$ACME_EMAIL" || "$ACME_EMAIL" != *"@"* ]]; then
        log_err "请输入有效的通知邮箱。"
        return 1
    fi

    # 🔴🔴 端口占用预检：**放在 DNS 校验之前**，因为端口被占时
    # 内置 ACME 根本没有可用验证方式，再怎么校验 DNS 都是白费。
    if detect_webserver_squatting; then
        log_warn "============================================================"
        log_warn " 检测到本机 ${ACRE_PORT_BLOCKER} 已被其他服务占用"
        log_warn "============================================================"
        log_warn " Let's Encrypt 只有两种验证方式，都要求端口空闲："
        log_warn "   HTTP-01 (TCP 80) / TLS-ALPN-01 (TCP 443)"
        log_warn " Hysteria 内置 ACME 无法在这种环境下自行签发，"
        log_warn " 强行尝试只会反复失败，然后退回自签证书（客户端必须开跳过校验）。"
        log_warn ""
        log_warn " ✅ 正确做法：让已占用这些端口的反代（通常是 Caddy）去签，"
        log_warn "    Hysteria 直接复用它的证书。"
        log_warn ""
        log_warn " 说明：这不会影响 ${ACRE_PORT_BLOCKER} 上现有的服务，"
        log_warn "    Hysteria 主监听是 UDP 端口，与反代互不冲突。"
        log_warn ""

        local existing_pair
        if existing_pair="$(find_cert_in_webserver "$SERVER_NAME")" && [[ -n "$existing_pair" ]]; then
            CERT_TYPE="custom"
            CERT_FILE="${existing_pair%%|*}"
            KEY_FILE="${existing_pair#*|}"
            IS_INSECURE="false"
            log_info "已找到 Caddy/Nginx 为 ${SERVER_NAME} 签发的证书，直接复用。"
            return 0
        elif command -v caddy >/dev/null 2>&1; then
            read -rp "是否让本机 Caddy 为 ${SERVER_NAME} 自动签发证书? [Y/n]: " use_caddy || true
            use_caddy="${use_caddy:-Y}"
            if [[ "$use_caddy" =~ ^[Yy]$ ]]; then
                if setup_cert_via_existing_caddy "$SERVER_NAME"; then
                    local ck
                    ck="$(find_cert_in_webserver "$SERVER_NAME")" || ck=""
                    if [[ -n "$ck" ]]; then
                        CERT_TYPE="custom"
                        CERT_FILE="${ck%%|*}"
                        KEY_FILE="${ck#*|}"
                        IS_INSECURE="false"
                        # SERVER_NAME 在 setup_acme_certificate 开头已置为真实域名；
                        # 这里不再做无意义的自赋值（旧代码的 SERVER_NAME="$SERVER_NAME"
                        # 是死代码，注释描述的「自签伪装」在当前顺序下不会发生）。
                        log_info "已改为使用 Caddy 签发的正式证书: ${CERT_FILE}"
                        log_info "SNI: ${SERVER_NAME}（客户端无需再开跳过证书校验）"
                        return 0
                    fi
                fi
                log_err "Caddy 签发失败。可手动执行：caddy reload && journalctl -u caddy -f"
            fi
        else
            # 🔴 占端口的不是 Caddy。常见是 Nginx，而 Nginx **不会自动签发**，
            # 所以不能像 Caddy 那样"借它一签"——必须说清差异，
            # 否则用户会以为脚本还能自动搞定，转而去折腾 Nginx 配置。
            _hog="$(port_owner tcp 80) $(port_owner tcp 443)"
            _hog="${_hog% }"; _hog="${_hog# }"   # 只留非空的那几个
            log_warn "占用 ${ACRE_PORT_BLOCKER} 的服务不是 Caddy（检测到: ${_hog:-未知}）。"
            if [[ "${_hog}" == *nginx* ]]; then
                log_step "检测到 Nginx，尝试借 Nginx 完成 HTTP-01 验证签发..."
                _ngres=0
                _ngpair="$(setup_cert_via_nginx "$SERVER_NAME" "$ACME_EMAIL")" || _ngres=$?
                if [[ $_ngres -eq 0 && -n "$_ngpair" ]]; then
                    CERT_TYPE="custom"
                    CERT_FILE="${_ngpair%%|*}"
                    KEY_FILE="${_ngpair#*|}"
                    IS_INSECURE="false"
                    # SERVER_NAME 已是真实域名（见 setup_acme_certificate 开头）。
                    log_info "已使用借 Nginx 签发的正式证书: ${CERT_FILE}"
                    log_info "SNI: ${SERVER_NAME}（客户端无需再开跳过证书校验）"
                    return 0
                fi
                log_warn "借 Nginx 签发未成功，继续尝试 DNS API。"
            fi
        fi

        # 🔴🔴 兜底：借反代也签不出来时，改用 DNS API 签发。
        #
        # 关键认知：**绝不能在这里滑回内置 ACME**。端口已被占，
        # 内置 ACME 的两种验证方式都用不了，回去试只是明知必然失败还浪费一轮，
        # 最后的报错还会把用户引向错误的排查方向（正是本次要消灭的问题）。
        # DNS-01 走 DNS 查询、不碰任何端口，是端口冲突下唯一还走得通的路。
        log_step "借反代签发未成功，改用 DNS API 签发（不占用任何端口）..."
        _dnsres=0
        _dnspair="$(setup_cert_via_dns_api "$SERVER_NAME")" || _dnsres=$?
        if [[ $_dnsres -eq 0 && -n "$_dnspair" ]]; then
            CERT_TYPE="custom"
            CERT_FILE="${_dnspair%%|*}"
            KEY_FILE="${_dnspair#*|}"
            IS_INSECURE="false"
            # SERVER_NAME 已是真实域名（见 setup_acme_certificate 开头）。
            log_info "已使用 DNS API 签发的正式证书: ${CERT_FILE}"
            log_info "SNI: ${SERVER_NAME}（客户端无需再开跳过证书校验）"
            log_info "续期：acme.sh --cron 需常驻，建议 crontab -e 加入："
            log_info "  ${acct:-/root/.acme.sh/acme.sh} --cron --home ${HOME}/.acme.sh > /dev/null 2>&1"
            return 0
        elif [[ $_dnsres -eq 2 ]]; then
            log_err "============================================================"
            log_err " 无法自动签发正式证书：缺少 DNS API 凭据"
            log_err "============================================================"
            log_err " 端口 ${ACRE_PORT_BLOCKER} 被占 → 内置 ACME 必然失败；"
            log_err " 借 Caddy 签发也未成功 → 剩下唯一自动可行的路是 DNS API。"
            log_err ""
            log_err " 三选一（按你的 DNS 服务商）："
            log_err "   Cloudflare : export HY2_CF_TOKEN=xxx HY2_CF_EMAIL=xxx@yyy.com"
            log_err "   阿里云     : export HY2_ALICLOUD_KEY=xxx HY2_ALICLOUD_SECRET=xxx"
            log_err "   DuckDNS    : export HY2_DP_TOKEN=xxx"
            log_err " 然后重新运行本脚本即可。"
            log_err ""
            log_err " 或手动准备证书后：菜单第 4 项 → 证书方式 2（使用已有证书文件）"
            log_err " 或腾出端口：停掉占用 ${ACRE_PORT_BLOCKER} 的服务后重试。"
            log_err ""
            log_err " ⚠️ 若继续，将退回【自签证书】，客户端必须开启"
            log_err "「跳过证书校验 / insecure」，个别客户端干脆不支持。"
            echo ""
            read -rp "仍要继续退回自签证书吗? [y/N, 默认 N]: " fallback_selfsigned || true
            fallback_selfsigned=${fallback_selfsigned:-N}
            if [[ ! "$fallback_selfsigned" =~ ^[Yy]$ ]]; then
                log_err "已中止。请按上述方式提供 DNS API 凭据，或手动准备证书。"
                return 1
            fi
        else
            log_err "DNS API 签发也失败了。"
            log_warn "⚠️ 若继续，将退回【自签证书】，客户端必须开启「跳过证书校验」。"
            read -rp "仍要继续退回自签证书吗? [y/N, 默认 N]: " fallback_selfsigned || true
            fallback_selfsigned=${fallback_selfsigned:-N}
            if [[ ! "$fallback_selfsigned" =~ ^[Yy]$ ]]; then
                log_err "已中止。"
                return 1
            fi
        fi
        # 只有用户明确同意才落到这里 => 生成自签
        generate_self_signed_cert
        return 0
    fi

    # DNS 解析预校验：避免 Let's Encrypt HTTP-01 必然失败导致服务反复重启
    log_step "正在校验 ${SERVER_NAME} 的 DNS A 记录是否指向本机公网 IP ${PUBLIC_IP:-<未知>}..."
    # ⚠️ 必须写成 `|| dns_rc=$?`，不能是裸调用（2026-10-09 修）：
    # verify_domain_resolves_to_this_host 返回 1（无 A 记录）/ 2（指向别的 IP），
    # 而本脚本开头是 `set -eo pipefail`。裸调用在 set -e 下**当场终止整个安装**，
    # 下面那句「仍要继续申请 ACME 证书吗? [y/N]」根本执行不到 ——
    # 实测 exit=2，"captured rc" 那行永远打不出来。
    # 后果最恶劣：新手域名刚买、A 记录还没生效（本该是最常见的场景），
    # 看到红色 DNS 报错后脚本直接静默退出，除了重装没有别的出路。
    local dns_rc=0
    verify_domain_resolves_to_this_host "$SERVER_NAME" || dns_rc=$?
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
    
    # 默认端口避开 20000-40000：那是端口跳跃区间，主监听端口落在里面会与
    # 跳跃的 REDIRECT 规则互相干扰（本项目 AWG 选端口也是刻意避开该区间的）。
    DEFAULT_PORT=$((RANDOM % 40000 + 10000))
    while (( DEFAULT_PORT >= 20000 && DEFAULT_PORT <= 40000 )); do
        DEFAULT_PORT=$((RANDOM % 40000 + 10000))
    done
    # 已装机的节点沿用现有端口作为默认值（2026-10-29 修）：
    # 旧实现给的是随机新端口，用户只想改证书、在端口提示处直接回车，
    # 端口就被换掉，所有已发放的客户端配置当场失效。
    if [[ -z "${HY2_PORT:-}" && -f "$HY2_META_FILE" ]]; then
        local _cur_port
        _cur_port="$(jq -r '.listen_port // empty' "$HY2_META_FILE" 2>/dev/null || true)"
        if is_valid_port "${_cur_port:-}"; then
            DEFAULT_PORT="$_cur_port"
        fi
    fi

    # 端口合法性校验：原来不做任何校验，输错（abc / 99999 / 0）会一路写进配置，
    # 装完表现为「显示安装成功但服务起不来」，新手根本想不到是自己打错了。
    if [[ -n "${HY2_PORT:-}" ]]; then
        if ! is_valid_port "$HY2_PORT"; then
            log_err "环境变量 HY2_PORT='${HY2_PORT}' 不是合法端口（需为 1-65535 的整数）。"
            exit 1
        fi
        LISTEN_PORT="$HY2_PORT"
        log_info "已使用环境变量 HY2_PORT=${LISTEN_PORT} 指定监听端口。"
    else
        while true; do
            read -rp "请输入主监听 UDP 端口 [1-65535, 默认: ${DEFAULT_PORT}]: " LISTEN_PORT || true
            LISTEN_PORT=${LISTEN_PORT:-$DEFAULT_PORT}
            if is_valid_port "$LISTEN_PORT"; then
                break
            fi
            log_err "端口必须是 1-65535 之间的整数，请重新输入。"
        done
    fi
    if is_valid_port "$LISTEN_PORT" && (( LISTEN_PORT >= 20000 && LISTEN_PORT <= 40000 )); then
        log_warn "所选端口 ${LISTEN_PORT} 落在端口跳跃区间 20000-40000 内。"
        log_warn "该区间会被 REDIRECT 到主监听端口，两者重叠时行为容易混乱，建议换区间外的端口。"
    fi

    # 密码生成
    # ⚠️ 菜单 4「重新修改配置」会走到这里。原先无条件重新随机，等于用户只想
    # 改个端口、结果 auth 密码和 obfs 密码一起被换掉 —— 所有已发放的客户端配置
    # 立刻失效，且 portal.json 里的机主/子账号也被 prepare() 重建（见菜单 4 的告警）。
    # 正确做法：**已装机时沿用旧密码**，只有「明确要换」时才生成新的。
    if [[ -f "$HY2_META_FILE" ]] && [[ -z "${HY2_PASSWORD:-}" ]]; then
        _old_pass="$(jq -r '.auth_password // empty' "$HY2_META_FILE" 2>/dev/null || true)"
        if [[ -n "$_old_pass" ]]; then
            RANDOM_PASS="$_old_pass"
            log_info "已保留现有认证密码（菜单 4 默认不换密码，避免已发放的客户端失效）。"
        else
            RANDOM_PASS=$(openssl rand -hex 16)
            log_warn "旧密码读取失败，已生成新密码 —— 已发放的客户端配置需要重新导出。"
        fi
    else
        RANDOM_PASS=$(openssl rand -hex 16)
    fi
    unset _old_pass
    if [[ -n "${HY2_PASSWORD:-}" ]]; then
        AUTH_PASSWORD="$HY2_PASSWORD"
        log_info "已使用环境变量 HY2_PASSWORD 指定认证密码。"
    else
        read -rsp "请输入机主账号连接密码 [回车自动生成]: " AUTH_PASSWORD || true; echo
        AUTH_PASSWORD=${AUTH_PASSWORD:-$RANDOM_PASS}
    fi

    # 运行模式：本项目只提供商城版（Agent）节点。
    # 这里不再询问模式，只沿用/生成节点通信 API Key。已装机时**必须**沿用旧 Key，
    # 否则 Teyir 控制台保存的凭据立刻失效，控制台开的用户全部连不上。
    NODE_MODE="agent"
    _cur_api_key="$(jq -r '.api_key // empty' "$HY2_DIR/portal.json" 2>/dev/null || true)"
    echo -e "\n${CYAN}商城版节点（Agent 模式）${PLAIN}：开启 REST API，支持动态开户 / 续费 / 对接商城。"
    if [[ -n "${HY2_NODE_MODE:-}" ]]; then
        log_info "已确认商城版节点（HY2_NODE_MODE=2）。"
    fi
    if [[ -n "$_cur_api_key" ]]; then
        read -rsp "请设置节点通信 API Key [回车沿用现有 Key，控制台无需改动]: " NODE_API_KEY || true; echo
        NODE_API_KEY=${NODE_API_KEY:-$_cur_api_key}
        log_info "已沿用现有 API Key。"
    else
        RANDOM_API_KEY="hy2_sec_$(openssl rand -hex 16)"
        read -rsp "请设置节点通信 API Key [回车自动生成]: " NODE_API_KEY || true; echo
        NODE_API_KEY=${NODE_API_KEY:-$RANDOM_API_KEY}
        log_info "已生成新的节点通信 API Key。"
    fi

    # ⚠️ 主监听端口占用检测（2026-10-09 修）：
    # 脚本本来就有现成的 port_owner()（80/443 检测在用），但主监听端口从没查过。
    # 撞上已占用端口时 hysteria bind 失败 → 服务反复重启，
    # 而用户看到的报错完全指不到「你选的这个端口被别人占了」。
    # 这里提前拦下，并报出占用者进程名；已装的机器（服务本就在跑）跳过。
    if [[ -n "${LISTEN_PORT:-}" ]] && is_valid_port "$LISTEN_PORT" \
       && ! systemctl is-active --quiet hysteria-server 2>/dev/null; then
        _port_user="$(port_owner udp "$LISTEN_PORT")"
        if [[ -n "$_port_user" ]]; then
            log_err "所选主监听 UDP 端口 ${LISTEN_PORT} 已被占用（占用进程: ${_port_user}）。"
            log_err "Hysteria 将无法绑定该端口，服务会反复重启。"
            read -rp "换一个端口？[y/N]: " _port_retry || true
            if [[ ! "$_port_retry" =~ ^[Yy]$ ]]; then
                log_err "已中止安装。请释放该端口或重跑本脚本换一个端口。"
                return 1
            fi
            log_info "请重新运行本脚本并指定其他端口。"
            return 1
        fi
    fi

    # 端口跳跃 (默认全自动开启，免询问)
    clear_all_hopping_rules
    HOP_START=20000
    HOP_END=40000
    HOP_PORT_RANGE="${HOP_START}-${HOP_END}"
    setup_iptables_port_hopping "$LISTEN_PORT" "$HOP_START" "$HOP_END"
    if [[ -n "$HOP_PORT_RANGE" ]]; then
        log_info "端口跳跃已默认自动启用: UDP ${HOP_PORT_RANGE} -> ${LISTEN_PORT}"
    fi

    # Salamander 混淆 (默认全自动开启并生成高熵密钥，免询问)
    # 与 auth 密码同理：菜单 4 保留旧 obfs 密钥，否则所有客户端的 obfs-password
    # 一起变错、握手直接失败（同一个混淆密码必须与服务端一致）。
    if [[ -f "$HY2_META_FILE" ]]; then
        _old_obfs="$(jq -r '.obfs_password // empty' "$HY2_META_FILE" 2>/dev/null || true)"
    else
        _old_obfs=""
    fi
    if [[ -n "$_old_obfs" ]]; then
        OBFS_PASSWORD="$_old_obfs"
        log_info "已保留现有 Salamander 混淆密钥（菜单 4 默认不换，避免客户端失效）。"
    else
        OBFS_PASSWORD=$(openssl rand -hex 16)
    fi
    unset _old_obfs
    log_info "Salamander 混淆已默认自动启用 (抗深度包检测 GFW 免疫)"
}

setup_system_firewall() {
    local port="$1"
    local s_port="$2"
    local e_port="$3"
    
    log_step "自动放行系统内部防火墙 (ufw / firewalld / nftables / iptables)..."
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
    # BUGFIX: nftables。只跑 nft 的机器（没有 ufw / firewalld 的
    # iptables-nft 兜底也会漏掉 INPUT 放行）此前完全不被覆盖——
    # 表现为「服务 active、本机连得上、公网连不上」。
    # 关键点：UDP 主监听端口必须放行！客户端订阅里的 `port: <listen>` 是
    # 直连主端口的，不走端口跳跃；只放行跳跃段 20000-40000 的话，
    # 直连会超时（面板测试 -1 / 客户端连不上）。
    # 只在确有一条 hook input + policy drop 的 base chain 时才动它，
    # 避免误伤默认放行的机器。
    if command -v nft >/dev/null 2>&1 && ! { command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; } \
       && ! { command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active firewalld >/dev/null 2>&1; }; then
        # 用 list ruleset 的层级结构解析（格式在所有 nft 版本间稳定）：
        # 先记下当前所在的 table（"table <family> <name>"）/ chain，
        # 遇到 "hook input ... policy drop" 就输出 "<family> <table> <chain>"。
        local nft_input
        nft_input=$(nft list ruleset 2>/dev/null | awk '
            /^table /            { tbl=$2" "$3; chain="" }
            /^[[:space:]]*chain /{ chain=$2; sub(/\{.*/,"",chain); sub(/:$/,"",chain) }
            /hook input/ && /policy drop/ && chain != "" { print tbl " " chain; exit }
        ')
        if [[ -n "$nft_input" ]]; then
            # nft_input = "<family> <table> <chain>"，正好是 nft 命令需要的三个参数。
            # 用 read 拆分而不是 set --，避免覆盖函数自身的位置参数（$1/$2/$3）。
            local nft_fam nft_tbl nft_chain
            read -r nft_fam nft_tbl nft_chain <<<"$nft_input"
            # 幂等判据必须**逐条规则**判断。旧实现只在「主 UDP 端口已放行」时
            # 整体跳过，于是 TCP 订阅端口、端口跳跃区间、ACME 的 80 都不会补 ——
            # 重装后订阅端口重新随机时面板公网打不开，日志却写着「已跳过」
            # （2026-10-29 修）。用「数字边界」正则避免 14617 命中 146170。
            local _nft_rules _changed=0
            _nft_rules="$(nft list chain "$nft_fam" "$nft_tbl" "$nft_chain" 2>/dev/null)"
            _nft_has() { grep -qE "(^|[^0-9])$1([^0-9]|$)" <<<"$2"; }
            _nft_ensure() {   # $1=proto $2=dport 表达式 $3=匹配串
                _nft_has "$3" "$_nft_rules" && return 0
                nft add rule "$nft_fam" "$nft_tbl" "$nft_chain" "$1" dport "$2" accept >/dev/null 2>&1 || true
                _changed=1
            }
            _nft_ensure udp "${port}" "udp dport ${port}"
            if [[ -n "$s_port" && -n "$e_port" ]]; then
                _nft_ensure udp "${s_port}-${e_port}" "${s_port}-${e_port}"
            fi
            _nft_ensure tcp "${HY2_SUB_PORT}" "tcp dport ${HY2_SUB_PORT}"
            if [[ "$CERT_TYPE" == "acme" ]]; then
                _nft_ensure tcp 80 "tcp dport 80"
            fi
            if [[ "$_changed" == "1" ]]; then
                log_info "nftables ($nft_fam $nft_tbl/$nft_chain) 已放行 tcp ${HY2_SUB_PORT} + udp ${port}$([[ -n "$s_port" ]] && echo " + udp ${s_port}-${e_port}")。"
                log_warn "注意：nft 规则默认不持久化。若本机有 /etc/nftables.conf 或自建加载服务，请同步写入以防重启丢失。"
            else
                log_info "nftables 规则已齐备（udp ${port} / tcp ${HY2_SUB_PORT}），跳过。"
            fi
            unset -f _nft_has _nft_ensure
        fi
    fi
    # 裸 iptables 兜底（既无 ufw/firewalld，也无 nft 的情况）。
    # 注意：这里处理的是 filter/INPUT 的放行，与端口跳跃的 nat/REDIRECT 无关。
    if command -v iptables >/dev/null 2>&1 \
       && ! { command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; } \
       && ! { command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active firewalld >/dev/null 2>&1; } \
       && ! command -v nft >/dev/null 2>&1; then
        local chain_policy
        chain_policy=$(iptables -L INPUT -n 2>/dev/null | head -n1 | grep -o 'policy [A-Z]*' | awk '{print $2}')
        if [[ "$chain_policy" == "DROP" ]]; then
            iptables -C INPUT -p udp --dport "${port}" -j ACCEPT >/dev/null 2>&1 \
                || iptables -I INPUT -p udp --dport "${port}" -j ACCEPT >/dev/null 2>&1 || true
            iptables -C INPUT -p tcp --dport "${HY2_SUB_PORT}" -j ACCEPT >/dev/null 2>&1 \
                || iptables -I INPUT -p tcp --dport "${HY2_SUB_PORT}" -j ACCEPT >/dev/null 2>&1 || true
            if [[ -n "$s_port" && -n "$e_port" ]]; then
                iptables -C INPUT -p udp --dport "${s_port}:${e_port}" -j ACCEPT >/dev/null 2>&1 \
                    || iptables -I INPUT -p udp --dport "${s_port}:${e_port}" -j ACCEPT >/dev/null 2>&1 || true
            fi
            if [[ "$CERT_TYPE" == "acme" ]]; then
                iptables -C INPUT -p tcp --dport 80 -j ACCEPT >/dev/null 2>&1 \
                    || iptables -I INPUT -p tcp --dport 80 -j ACCEPT >/dev/null 2>&1 || true
            fi
            log_info "已放行 iptables INPUT (udp ${port} + tcp ${HY2_SUB_PORT})。"
            if command -v netfilter-persistent >/dev/null 2>&1; then
                netfilter-persistent save >/dev/null 2>&1 || true
            fi
        fi
    fi
}

# 重装/改配置前的凭据快照（2026-10-09 修）。
# 🔴 为什么必须有：菜单 1 与菜单 4 都会**整体重写** client_meta.json，
#    而 prepare() 会按只剩机主的 users 表重建 portal.json。也就是说
#    「重新修改配置」这个看起来无害的操作，能把商城开的账号、已发放的凭据、
#    已记录的订阅端口一并抹掉 —— 而修复前脚本全程没有任何 .bak（实测全仓库无一处）。
#    出事后用户唯一能做的事是手工翻备份目录，而他根本不知道备份存在哪。
# 这里在动手之前把四个关键文件各留一份带时间戳的快照，并在菜单里告知位置。
backup_state_before_reconfigure() {
    local ts saved=0 f
    ts="$(date +%Y%m%d-%H%M%S)"
    # 每个文件只保留最近 5 份快照：portal.json 含全部用户密码与 API Key，
    # 每次重装都留一份会让 /etc/hysteria 无限增长（也扩大泄露面，2026-10-29 修）。
    # 只清理本函数生成的那四种 *.bak-<时间戳>，不碰其它备份（如手工部署的
    # portal.py.bak-*）。
    local _old
    for f in "$HY2_META_FILE" "${HY2_DIR}/portal.json" "${HY2_DIR}/portal-access.json" "$HY2_CONFIG"; do
        while IFS= read -r _old; do
            [[ -n "$_old" ]] && rm -f "$_old" 2>/dev/null || true
        done < <(ls -1t "${f}".bak-* 2>/dev/null | tail -n +6)
    done
    for f in "$HY2_META_FILE" "${HY2_DIR}/portal.json" "${HY2_DIR}/portal-access.json" "$HY2_CONFIG"; do
        [[ -f "$f" ]] || continue
        if cp -a "$f" "${f}.bak-${ts}" 2>/dev/null; then
            saved=$((saved + 1))
        fi
    done
    if (( saved > 0 )); then
        log_info "已备份 ${saved} 个关键文件（后缀 .bak-${ts}），改配置出问题可回滚。"
    else
        log_warn "关键文件备份失败（可能是首次安装），请自行确认原数据已无价值。"
    fi
}

select_subscription_port() {
    # bind 实际验证 IPv4 TCP 端口；不解析 ss 标题，不进行无限循环。
    # 🔴 不要优先尝试 8443：它是常见 Web 端口，且本项目在门户的端口分配里
    # 已把它列为**黑名单**成员（生成代理/AWG 服务时主动避开）。若这里优先
    # 选中它，就会出现"订阅端口用了黑名单端口"的自相矛盾，也与
    # 门户侧 `resolve_subscription_port` 的取值意图不符。
    # 直接从高位随机端口里挑，并用 bind 验证真实可用性。
    #
    # 沿用现有门户时两个端口都不能换：订阅端口是 Teyir 保存的门户地址和
    # 每个客户订阅链接的一部分；门户本地端口写在 config.yaml 的 auth.url 里。
    # （旧端口此刻正被运行中的服务占着，bind 检测必然失败，所以直接沿用。）
    if [[ "${PRESERVE_PORTAL:-0}" == "1" ]]; then
        local _old_sub _old_local
        _old_sub="$(jq -r '.subscription_port // empty' "$HY2_META_FILE" 2>/dev/null || true)"
        _old_local="$(jq -r '.port // empty' "$HY2_DIR/portal.json" 2>/dev/null || true)"
        if is_valid_port "$_old_sub" && is_valid_port "$_old_local"; then
            HY2_SUB_PORT="$_old_sub"
            PORTAL_LOCAL_PORT="$_old_local"
            log_info "沿用现有订阅端口 ${HY2_SUB_PORT} 与门户本地端口 ${PORTAL_LOCAL_PORT}。"
            return 0
        fi
    fi
    HY2_SUB_PORT=$(python3 - <<'PYPORT'
import socket, secrets
RESERVED = {8443, 19898, 22, 80, 443, 40000, 56195}
for _ in range(100):
    port = 10000 + secrets.randbelow(50000)
    if port in RESERVED or 20000 <= port <= 40000:
        continue        # 20000-40000 是 Hysteria 的端口跳跃区间，必须避开
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
    ) || HY2_SUB_PORT=""
    # ⚠️ 必须显式判空（2026-10-09 修）：python3 缺失、或 100 次都撞上占用端口时
    # 会 raise SystemExit，命令替换失败在 set -e 下直接终止并把 traceback 甩给用户；
    # 而若侥幸留下空值，后面会写出 `listenHTTPS: :` 与 `ufw allow "/tcp"` 这种
    # 无效配置 —— 装完必然起不来。现在给出明确报错并中止。
    if ! is_valid_port "${HY2_SUB_PORT:-}"; then
        log_err "无法自动选出可用的私密信息页端口（100 次随机尝试均被占用，或 python3 不可用）。"
        log_err "请释放部分端口后重试，或检查 python3 是否已安装。"
        return 1
    fi
    # 本地端口必须避开刚选中的订阅端口：上一个 bind 成功后 socket 已关闭，
    # 内核完全可能把同一个端口再分给 127.0.0.1 的绑定。那样 Hysteria 的
    # masquerade 与门户会抢同一个端口，装完直接起不来（2026-10-29 修）。
    PORTAL_LOCAL_PORT=$(python3 - "${HY2_SUB_PORT}" <<'PYPORT'
import socket, sys
avoid = {int(sys.argv[1])} if sys.argv[1].isdigit() else set()
for _ in range(20):
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    if port not in avoid:
        print(port)
        break
else:
    raise SystemExit('no free loopback port')
PYPORT
    ) || PORTAL_LOCAL_PORT=""
    if ! is_valid_port "${PORTAL_LOCAL_PORT:-}"; then
        log_err "无法分配门户本地监听端口（python3 不可用或 bind 失败）。"
        return 1
    fi
}

# 删掉一条链里所有 Hy2 端口跳跃规则。
# 只匹配 Hy2 自己的规则形态「UDP 端口区间 → REDIRECT 到单个端口」，
# 不能按 "REDIRECT.*udp" 一把删：同机 Docker / 其他软件的 UDP 转发也会被误删。
_clear_hop_chain() {
    local bin="$1" chain="$2" rule rules
    # 先把规则清单**完整**读出来再逐条删。
    # 旧实现 `grep ... | head -n 1` 在 set -o pipefail 下会让 grep 收到 SIGPIPE
    # 返回 141，while 条件第一次就为假 —— 规则多时只删掉一条、其余残留
    # （2026-10-29 修）。清单是一次性快照，边删边遍历也没有问题。
    rules=$("$bin" -t nat -S "$chain" 2>/dev/null         | grep -E -- '-p udp .*--dport [0-9]+:[0-9]+ .*-j REDIRECT --to-ports [0-9]+$' || true)
    [ -n "$rules" ] || return 0
    while IFS= read -r rule; do
        [ -n "$rule" ] || continue
        # shellcheck disable=SC2086  # -S 输出就是参数列表，按空白拆分是有意的
        "$bin" -t nat ${rule/#-A /-D } 2>/dev/null || true
    done <<< "$rules"
}

clear_all_hopping_rules() {
    # 彻底清理所有历史残留的 Hy2 端口跳跃规则，防止旧端口重定向死循环
    # BUGFIX #12: 同时清理 PREROUTING + OUTPUT 链
    _clear_hop_chain iptables PREROUTING
    _clear_hop_chain iptables OUTPUT
    if command -v ip6tables >/dev/null 2>&1; then
        _clear_hop_chain ip6tables PREROUTING
        _clear_hop_chain ip6tables OUTPUT
    fi
    systemctl disable --now hy2-iptables.service >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/hy2-iptables.service >/dev/null 2>&1 || true
}

setup_iptables_port_hopping() {
    local l_port="$1"
    local s_port="$2"
    local e_port="$3"
    
    # 没有 iptables 命令（极简镜像 / 纯 nftables 主机）时直接跳过：
    # 旧实现会在 set -e 下以 127 退出，安装停在「二进制与证书已就位、
    # 配置与门户还没写」的半成品状态，还会留下一个开机必失败的
    # hy2-iptables.service（2026-10-29 修）。
    if ! command -v iptables >/dev/null 2>&1; then
        log_warn "本机没有 iptables 命令，跳过端口跳跃（${s_port}-${e_port} -> ${l_port}）。"
        log_warn "如需端口跳跃，请安装 iptables 后重新执行，或自行用 nftables 配置等价的 UDP 重定向。"
        log_warn "其余功能（Hy2 / Reality / VMess / AnyTLS 等）不受影响。"
        # 不把未配置转发的范围写入订阅元数据或交给防火墙放行。
        HOP_START=""
        HOP_END=""
        HOP_PORT_RANGE=""
        systemctl disable --now hy2-iptables.service >/dev/null 2>&1 || true
        rm -f /etc/systemd/system/hy2-iptables.service >/dev/null 2>&1 || true
        return 0
    fi

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
    # 只在缺 python3 时重装依赖（缺它门户起不来）。qrencode 缺失只影响
    # 二维码，旧写法会让每次生成配置都跑一遍 apt-get update（2026-10-29 修）。
    command -v python3 >/dev/null 2>&1 || install_dependencies
    command -v qrencode >/dev/null 2>&1 || log_warn "未安装 qrencode，二维码将不可用（其余功能正常）。"
    python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else "需要 Python 3.9+")'
    local systemd_version
    # 非 systemd 环境（容器/极简镜像）下 systemctl 不存在，直接取会让
    # set -e 终止，用户看不到下面那条「需要 systemd 247+」的说明。
    systemd_version=$(systemctl --version 2>/dev/null | awk 'NR==1 {print $2}') || systemd_version="" 
    if [[ ! "$systemd_version" =~ ^[0-9]+$ ]] || (( systemd_version < 247 )); then
        log_err "私密网页需要 systemd 247+ 的凭据隔离功能。"
        return 1
    fi
    select_subscription_port || { log_err "订阅端口分配失败，安装中止。"; return 1; }

    # 真实计量的 secret：hysteria trafficStats 与 usage-meter-config.json 必须一致。
    # 缺失则计量模块启动即 FileNotFoundError，用量永远「未开始计量」（静默降级）。
    if [[ -z "${METER_SECRET:-}" ]]; then
        METER_SECRET="$(openssl rand -hex 16)"
    fi

    cat > "$HY2_CONFIG" <<EOF
# Hysteria 2 Server Configuration
# Generated by hysteria2-installer
listen: :${LISTEN_PORT}
EOF

    if [[ "$CERT_TYPE" == "acme" ]]; then
        # ⚠️ SERVER_NAME / ACME_EMAIL 必须加引号（2026-10-09 修）：
        # 域名/邮箱里出现空格或 '#' 时，未加引号的裸值会被 YAML 解析成
        # 另一个值、或把 '#' 之后整行当注释吃掉 —— hysteria 随后报一个
        # 语法错，现象是「装完服务反复重启」，而错误信息完全指不到输入框。
        cat >> "$HY2_CONFIG" <<EOF
acme:
  domains:
    - "${SERVER_NAME}"
  email: "${ACME_EMAIL}"
  type: http
EOF
    else
        cat >> "$HY2_CONFIG" <<EOF
tls:
  cert: "${CERT_FILE}"
  key: "${KEY_FILE}"
EOF
    fi

    # 商城版固定走门户鉴权：门户按用户/到期/流量/IP 限制逐连接判定。
    # 单机固定密码模式已移除（HY2_NODE_MODE 只接受 2）。
    cat >> "$HY2_CONFIG" <<EOF
auth:
  type: http
  http:
    url: http://127.0.0.1:${PORTAL_LOCAL_PORT}/auth
EOF

    cat >> "$HY2_CONFIG" <<EOF

masquerade:
  type: proxy
  proxy:
    url: http://127.0.0.1:${PORTAL_LOCAL_PORT}/
    rewriteHost: false
    # 给经伪装代理进来的公网请求打上 X-Forwarded-For，门户据此拒绝公网直打 /auth
    # （否则任何人都能刷满 /auth 的全局失败计数，让整个节点无法登录）。v2.8.0+ 支持，旧核心忽略。
    xForwarded: true
  listenHTTPS: :${HY2_SUB_PORT}

# 真实计量：/traffic 只读端点，供 usage-meter 采集。必须回环监听，
# 且 secret 与 usage-meter-config.json 的 hysteria.secret 逐字符一致。
trafficStats:
  listen: 127.0.0.1:19996
  secret: $(jq -Rn --arg value "$METER_SECRET" '$value')

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

# 安全：禁止代理用户访问节点本机/内网/云元数据
acl:
  inline:
    - reject(127.0.0.0/8)
    - reject(10.0.0.0/8)
    - reject(172.16.0.0/12)
    - reject(192.168.0.0/16)
    - reject(169.254.0.0/16)
    - reject(100.64.0.0/10)
    - reject(0.0.0.0/8)
    - reject(::1/128)
    - reject(fc00::/7)
    - reject(fe80::/10)
    - direct_ipv4(all)
EOF

    # 写入 toggle_warp.sh 控制脚本，供 portal.py 或命令行无感知调用
    cat > "$HY2_DIR/toggle_warp.sh" <<'EOTW'
#!/usr/bin/env bash
ACTION="$1" # 1: enable, 0: disable
CONFIG="/etc/hysteria/config.yaml"
[[ -f "$CONFIG" ]] || exit 1

# 记录改动前的 acl 段，供收尾判断是否需要重启
BEFORE_ACL=$(sed -n '/^acl:/,$p' "$CONFIG")

# 清理旧 acl 段：只删 acl 块本身，obfs 等排在其后的顶格段落必须保留
awk 'BEGIN{d=0} /^acl:/{d=1;next} d && /^[^ \t#]/{d=0} !d' "$CONFIG" > "$CONFIG.tmp" && cat "$CONFIG.tmp" > "$CONFIG" && rm -f "$CONFIG.tmp"

if [[ "$ACTION" == "1" ]]; then
    # 统一走 wgcf + wireproxy 出口（不再依赖官方 warp-cli）：探活失败则拉起 wireproxy
    if ! curl --proxy "socks5h://127.0.0.1:19898" --silent --fail --max-time 6 https://api4.ipify.org >/dev/null 2>&1; then
        systemctl restart wireproxy >/dev/null 2>&1 || true
        sleep 2
    fi
    cat >> "$CONFIG" <<'EOF'
acl:
  inline:
    - reject(127.0.0.0/8)
    - reject(10.0.0.0/8)
    - reject(172.16.0.0/12)
    - reject(192.168.0.0/16)
    - reject(169.254.0.0/16)
    - reject(100.64.0.0/10)
    - reject(0.0.0.0/8)
    - reject(::1/128)
    - reject(fc00::/7)
    - reject(fe80::/10)
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

if ! grep -q '^acl:' "$CONFIG"; then
    # 关闭 WARP 时也保留内网拦截
    cat >> "$CONFIG" <<'EOF'
acl:
  inline:
    - reject(127.0.0.0/8)
    - reject(10.0.0.0/8)
    - reject(172.16.0.0/12)
    - reject(192.168.0.0/16)
    - reject(169.254.0.0/16)
    - reject(100.64.0.0/10)
    - reject(0.0.0.0/8)
    - reject(::1/128)
    - reject(fc00::/7)
    - reject(fe80::/10)
    - direct_ipv4(all)
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
TARGET="${1:-}" # 'core' or 'portal'
HY2_DIR="/etc/hysteria"
HY2_BIN="/usr/local/bin/hysteria"

if [[ "$TARGET" == "core" ]]; then
    # 自动识别架构下载官方最新发布版
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64) HY_ARCH="amd64" ;;
        aarch64|arm64) HY_ARCH="arm64" ;;
        armv7l) HY_ARCH="arm" ;;   # 上游没有 armv7 资产，armv7 用 arm（旧映射是 404）
        *) echo "不支持的架构: $ARCH" >&2; exit 1 ;;
    esac
    ASSET="hysteria-linux-${HY_ARCH}"

    # 先定版本，再取该版本的官方 hashes.txt —— 绝不拿浮动 latest 的字节当依据。
    TAG=$(curl -s --max-time 10 https://api.github.com/repos/apernet/hysteria/releases/latest \
          | jq -r '.tag_name // empty' 2>/dev/null) || TAG=""
    if [[ -z "$TAG" || "$TAG" == "null" ]]; then
        _loc=$(curl -fsSIL --max-time 20 "https://download.hysteria.network/app/latest/${ASSET}" 2>/dev/null \
               | awk 'tolower($1)=="location:"{print $2}' | tr -d '\r' | tail -n1)
        if [[ "$_loc" =~ /app/(v[0-9][^/]*)/${ASSET}$ ]]; then
            # 下载站给的是裸版本号，GitHub 的 tag 是 `app/vX.Y.Z`；不补前缀会 404。
            TAG="app/${BASH_REMATCH[1]}"
        fi
    fi
    if [[ -z "$TAG" || "$TAG" == "null" ]]; then
        echo "无法确定 Hysteria 版本，已放弃更新（不做无校验下载）" >&2
        exit 1
    fi

    SUMDIR="$(mktemp -d)"
    trap 'rm -rf "$SUMDIR"; rm -f "$TMP_FILE"' EXIT
    if ! curl -fsSL --max-time 30 --retry 2 \
            "https://github.com/apernet/hysteria/releases/download/${TAG}/hashes.txt" \
            -o "${SUMDIR}/hashes.txt" 2>/dev/null; then
        echo "取不到 ${TAG} 的官方 hashes.txt，已放弃更新，现有核心未改动" >&2
        exit 1
    fi
    # 精确资产名解析唯一 SHA256；空/重复/畸形一律失败。
    WANT="$(awk -v a="$ASSET" '{n=$2; sub(/^\.\//,"",n); sub(/^\*/,"",n); if (n==a || n ~ ("/" a "$")) print $1}' \
            "${SUMDIR}/hashes.txt" | tr 'A-F' 'a-f' | sort -u)"
    if [[ ! "$WANT" =~ ^[0-9a-f]{64}$ ]]; then
        echo "hashes.txt 中 ${ASSET} 的摘要缺失或不唯一（实际: [${WANT}]），已放弃更新" >&2
        exit 1
    fi

    # mktemp 而不是固定的 /tmp/hy2_update_*：root 写可预测路径会被符号链接劫持。
    TMP_FILE="$(mktemp "${HY2_BIN}.update.XXXXXX")"
    curl -fsSL --max-time 300 "https://github.com/apernet/hysteria/releases/download/${TAG}/${ASSET}" -o "$TMP_FILE" || {
        echo "下载失败，现有核心未改动" >&2; exit 1; }
    GOT="$(sha256sum "$TMP_FILE" | awk '{print $1}')"
    if [[ "$GOT" != "$WANT" ]]; then
        echo "校验失败：SHA256 与官方 hashes.txt 不一致，已放弃更新" >&2
        echo "  期望: $WANT" >&2
        echo "  实际: $GOT" >&2
        exit 1
    fi
    chmod +x "$TMP_FILE"
    # 摘要之后再跑一次作为附加检查；坏包直接覆盖会让服务起不来、所有客户端断线。
    if ! "$TMP_FILE" version >/dev/null 2>&1; then
        echo "下载的 Hysteria 二进制无法运行，已放弃更新" >&2
        exit 1
    fi
    # 本次快照独占路径，绝不覆盖或消费用户已有的 .bak。
    ROLLBACK_FILE="$(mktemp "${HY2_BIN}.rollback.XXXXXX")" || {
        echo "创建核心备份失败，现有核心未改动" >&2; exit 1; }
    if ! cp -p "$HY2_BIN" "$ROLLBACK_FILE"; then
        rm -f "$ROLLBACK_FILE"
        echo "备份核心失败，已放弃更新，现有核心未改动" >&2
        exit 1
    fi
    if ! mv -f "$TMP_FILE" "$HY2_BIN"; then
        rm -f "$ROLLBACK_FILE"
        echo "替换核心失败，现有核心未改动" >&2
        exit 1
    fi
    # 老装机补上 masquerade.proxy.xForwarded（见安装模板的注释）。放在核心升级里做，
    # 是因为这里本来就要重启 Hy2，不会为改配置额外断一次所有用户。
    if [[ -f "$HY2_DIR/config.yaml" ]] && ! grep -qE '^[[:space:]]+xForwarded:' "$HY2_DIR/config.yaml"; then
        sed -i -E 's/^([[:space:]]+)rewriteHost:(.*)$/&\n\1xForwarded: true/' "$HY2_DIR/config.yaml" || true
    fi
    if [[ "$(jq -r '.traffic_suspend.suspended // false' "$HY2_DIR/portal.json" 2>/dev/null)" == "true" ]]; then
        rm -f "$ROLLBACK_FILE"
        echo "核心已更新；节点因流量超额被停用，暂不重启"
        exit 0
    fi
    if ! systemctl restart hysteria-server 2>/dev/null; then
        if ! mv -f "$ROLLBACK_FILE" "$HY2_BIN"; then
            echo "新版本启动失败，回滚失败；本次旧核心保留在 ${ROLLBACK_FILE}" >&2
            exit 1
        fi
        if [[ "$(jq -r '.traffic_suspend.suspended // false' "$HY2_DIR/portal.json" 2>/dev/null)" == "true" ]]; then
            echo "新版本启动失败，已恢复本次旧核心；节点已停用，暂不重启" >&2
            exit 1
        fi
        if ! systemctl restart hysteria-server 2>/dev/null; then
            echo "已恢复本次旧核心，但旧版本重启仍失败，请检查服务日志" >&2
            exit 1
        fi
        echo "新版本启动失败，已回滚到本次旧版本" >&2
        exit 1
    fi
    rm -f "$ROLLBACK_FILE"
elif [[ "$TARGET" == "portal" ]]; then
    # 从主仓库拉取最新 portal.py 并重启 portal 服务。
    # ⚠️ 不能只用 raw.githubusercontent.com：它有 CDN 缓存，push 后数分钟仍返回旧内容，
    # 而且不把查询串算进缓存键（加 ?cb=<时间戳> 无效）。按 API → jsDelivr → raw 回退。
    # 说明：Web 控制台的面板自更新已不走本脚本（它在 portal.py 内部用同一套回退
    # 取文件并原子替换），这里保留是为了手工调用 do_upgrade.sh portal 的场景。
    REPO="yys9253462-gif/hysteria2-installer"
    # 固定一次提交后，所有回退源都读取相同快照。
    _bundle_ref="$(curl -fsSL --max-time 15 "https://api.github.com/repos/${REPO}/commits/main" |
        python3 -c 'import json,re,sys; s=json.load(sys.stdin).get("sha", ""); assert re.fullmatch("[0-9a-f]{40}", s); print(s)')" || exit 1
    [[ "$_bundle_ref" =~ ^[0-9a-f]{40}$ ]] || { echo "无法固定门户版本，保留全部旧文件" >&2; exit 1; }
    _bundle_dir="$(mktemp -d)"
    _bundle_files="portal.py portal_assets.py usage-meter-core-20261007-v1.py usage-meter-readers-20261007-v1.py usage-meter-runtime-20261007-v1.py usage-meter-xray-config-20261007-v1.py"
    # 本脚本是独立生成的文件，不能依赖 install.sh 里的函数：内联 git blob 身份计算。
    # blob sha = sha1("blob <len>\0" + content)，与 GitHub contents API 的 sha 一致，
    # 注意它**不等于**文件的 sha1。
    _blob_sha() {
        local _f="$1" _n
        _n="$(wc -c < "$_f" | tr -d '[:space:]')"
        [[ "$_n" =~ ^[0-9]+$ ]] || return 1
        { printf 'blob %s\0' "$_n"; cat -- "$_f"; } | sha1sum | awk '{print $1}'
    }
    # 该 commit 下每个文件的 git blob 身份（contents API 一次取回全部 sha）。
    # 只有内容与该身份一致才算通过 —— 只校验 marker 挡不住 CDN 返回与所 pin
    # commit 不符的内容。
    _bundle_map="$(mktemp)"
    if ! curl -fsSL --max-time 20 -H "Accept: application/vnd.github+json" \
            "https://api.github.com/repos/${REPO}/contents/?ref=${_bundle_ref}" -o "$_bundle_map" 2>/dev/null; then
        rm -rf "$_bundle_dir" "$_bundle_map"
        echo "无法取得 ${_bundle_ref:0:7} 的文件身份，保留全部旧文件" >&2
        exit 1
    fi
    # 全部先下载并检查；旧缓存、缺文件或语法错误不允许半更新。
    for _m in $_bundle_files; do
        case "$_m" in
            portal.py) _marker='def page_html' ;;
            portal_assets.py) _marker='SCRIPT = r' ;;
            usage-meter-core-*|usage-meter-runtime-*) _marker='ACCOUNTING_REVISION = "2026-10-12-real-usage-v2"' ;;
            *) _marker='def ' ;;
        esac
        _want_sha="$(python3 -c '
import json, re, sys
try:
    items = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception:
    sys.exit(1)
for it in items if isinstance(items, list) else []:
    if isinstance(it, dict) and it.get("name") == sys.argv[2]:
        s = it.get("sha") or ""
        if re.fullmatch(r"[0-9a-f]{40}", s):
            print(s)
        break
' "$_bundle_map" "$_m" 2>/dev/null)" || _want_sha=""
        if [[ ! "$_want_sha" =~ ^[0-9a-f]{40}$ ]]; then
            rm -rf "$_bundle_dir" "$_bundle_map"
            echo "无法取得 ${_m}@${_bundle_ref:0:7} 的预期身份，保留全部旧文件" >&2
            exit 1
        fi
        _tmp_m="$_bundle_dir/$_m"
        _file_ok=0
        for _url in "https://api.github.com/repos/${REPO}/contents/${_m}?ref=${_bundle_ref}" \
                    "https://cdn.jsdelivr.net/gh/${REPO}@${_bundle_ref}/${_m}" \
                    "https://raw.githubusercontent.com/${REPO}/${_bundle_ref}/${_m}"; do
            if curl -fsSL --max-time 30 -H "Accept: application/vnd.github.raw" "$_url" -o "$_tmp_m" 2>/dev/null &&
               grep -Fq "$_marker" "$_tmp_m" &&
               python3 -c 'import ast,sys; ast.parse(open(sys.argv[1],encoding="utf-8").read())' "$_tmp_m" 2>/dev/null &&
               [[ "$(_blob_sha "$_tmp_m")" == "$_want_sha" ]]; then
                _file_ok=1; break
            fi
        done
        if [[ "$_file_ok" != "1" ]]; then
            rm -rf "$_bundle_dir" "$_bundle_map"
            echo "门户整包校验失败: ${_m}（内容与 ${_bundle_ref:0:7} 不符或语法不通），保留全部旧文件" >&2
            exit 1
        fi
    done
    rm -f "$_bundle_map"
    if [[ "$_file_ok" == "1" ]]; then
        # 配置自愈在持有跨进程锁的事务内执行，与发布/验证/回滚串行。
        cat > "$_bundle_dir/repair-config.sh" <<'PORTALREPAIR'
        # 计量配置自愈（2026-10-08）：老装机 / 手工改过的 config.yaml 可能没有
        # trafficStats 段，于是 usage-meter-config.json 从未生成，portal 启动即
        # `真实计量未初始化: FileNotFoundError` —— 换模块也治不好。
        # 这里幂等补写 trafficStats 并重建 usage-meter-config.json。
        if [[ -f "$HY2_DIR/config.yaml" ]] && [[ ! -f "$HY2_DIR/usage-meter-config.json" ]]; then
            _upd_secret="$(awk '/^trafficStats:/{f=1;next} f&&/secret:/{gsub(/[^0-9a-f]/,"",$2); print $2; exit}' "$HY2_DIR/config.yaml" 2>/dev/null || true)"
            if [[ -z "$_upd_secret" ]]; then
                _upd_secret="$(openssl rand -hex 16)"
                python3 - "$HY2_DIR/config.yaml" "$_upd_secret" <<'PYEOF2'
import io, re, sys
path, secret = sys.argv[1], sys.argv[2]
s = io.open(path, encoding='utf-8').read()
block = ("\n# 真实计量：/traffic 只读端点，供 usage-meter 采集。必须回环监听，\n"
         "# 且 secret 与 usage-meter-config.json 的 hysteria.secret 逐字符一致。\n"
         "trafficStats:\n  listen: 127.0.0.1:19996\n  secret: %s\n" % secret)
if not re.search(r'^trafficStats:', s, re.M):
    anchor = 'masquerade:'
    if anchor in s:
        s = s.replace(anchor, block.lstrip('\n') + '\n' + anchor, 1)
    else:
        s = s.rstrip('\n') + '\n' + block
io.open(path, 'w', encoding='utf-8', newline='\n').write(s)
PYEOF2
                chmod 600 "$HY2_DIR/config.yaml"
                # 停用节点只补配置；恢复节点时由正常启动流程加载。
                # 读取失败也不主动拉起 Hy2（不能把坏 JSON 当成未停用）。
                if python3 -I - "$HY2_DIR/portal.json" <<'PYSUSPEND'
import json, sys
with open(sys.argv[1], encoding='utf-8') as handle:
    data = json.load(handle)
sys.exit(1 if (data.get('traffic_suspend') or {}).get('suspended') else 0)
PYSUSPEND
                then
                    echo "已补写 trafficStats 段，重启 hysteria-server 使其生效"
                    systemctl restart hysteria-server 2>/dev/null || true
                else
                    echo "已补写 trafficStats 段；节点停用或状态不可读，暂不重启 hysteria-server"
                fi
            fi
            cat > "$HY2_DIR/usage-meter-config.json" <<METEREOF2
{"hysteria": {"url": "http://127.0.0.1:19996", "secret": "${_upd_secret}"}, "reality": {"binary": "/usr/local/bin/xray", "address": "127.0.0.1:19997"}}
METEREOF2
            chmod 600 "$HY2_DIR/usage-meter-config.json"
            unset _upd_secret
            echo "计量配置已生成（真实计量启用）"
        fi
        # 证书信任模型自愈（2026-10-08）：证书文件被带外替换后，client_meta.json 的
        # cert_type/server_name/is_insecure/pin_sha256 会与真实证书漂移，面板就会把
        # 错误的 sni 发给客户端（CRYPTO_ERROR 0x150）。以证书为唯一事实来源修正。
        if [[ -f "$HY2_DIR/client_meta.json" && -f "$HY2_DIR/config.yaml" ]] && command -v jq >/dev/null 2>&1; then
            _cert="$(awk '/^tls:/{f=1;next} f&&/^[ \t]+cert:/{sub(/^[ \t]*cert:[ \t]*/,"");gsub(/["\x27]/,"");print;exit} f&&/^[^ \t]/{f=0}' "$HY2_DIR/config.yaml" 2>/dev/null || true)"
            # config.yaml 里的 cert 是相对 /etc/hysteria 的路径，必须显式拼回 HY2_DIR。
            if [[ -n "$_cert" && "$_cert" != /* && ! -f "$_cert" ]]; then
                [[ -f "$HY2_DIR/$_cert" ]] && _cert="$HY2_DIR/$_cert"
            fi
            [[ -n "$_cert" && -f "$_cert" ]] || _cert="$HY2_DIR/cert/server.crt"
            if [[ -f "$_cert" ]]; then
                _subj="$(openssl x509 -in "$_cert" -noout -subject 2>/dev/null | sed 's/^subject=//' | sed 's/ *$//')"
                _iss="$(openssl x509 -in "$_cert" -noout -issuer 2>/dev/null | sed 's/^issuer=//' | sed 's/ *$//')"
                _cn="$(openssl x509 -in "$_cert" -noout -subject 2>/dev/null | sed -n 's/.*CN *= *//p' | head -1 | sed 's/ *$//')"
                _san="$(openssl x509 -in "$_cert" -noout -ext subjectAltName 2>/dev/null | tr ',' '\n' | sed -n 's/^ *DNS://p' | head -1)"
                _self="false"; [[ -n "$_subj" && "$_subj" == "$_iss" ]] && _self="true"
                _acme="false"; grep -q '^acme:' "$HY2_DIR/config.yaml" 2>/dev/null && _acme="true"
                _nsn=""
                if [[ -n "$_san" && "$_san" != \** ]]; then _nsn="$_san"; elif [[ -n "$_cn" && "$_cn" != \** ]]; then _nsn="$_cn"; fi
                if [[ -n "$_nsn" ]]; then
                    if [[ "$_self" == "true" ]]; then
                        _nt="self_signed"; _ni="true"
                        _np="$(openssl x509 -in "$_cert" -outform DER 2>/dev/null | openssl dgst -sha256 2>/dev/null | awk '{print $NF}' | tr 'A-F' 'a-f' || true)"
                        [[ "$_np" =~ ^[0-9a-f]{64}$ ]] || _np=""
                    else
                        [[ "$_acme" == "true" ]] && _nt="acme" || _nt="custom"
                        _ni="false"; _np=""
                    fi
                    _ct="$(jq -r '.cert_type // empty' "$HY2_DIR/client_meta.json" 2>/dev/null || true)"
                    _ci="$(jq -r 'if has("is_insecure") then (.is_insecure|tostring) else "" end' "$HY2_DIR/client_meta.json" 2>/dev/null || true)"
                    _cs="$(jq -r '.server_name // empty' "$HY2_DIR/client_meta.json" 2>/dev/null || true)"
                    _cp="$(jq -r '.pin_sha256 // empty' "$HY2_DIR/client_meta.json" 2>/dev/null || true)"
                    if [[ "$_ct" != "$_nt" || "$_ci" != "$_ni" || "$_cs" != "$_nsn" || "$_cp" != "$_np" ]]; then
                        _tmp_meta="$HY2_DIR/client_meta.json.tmp.$$"
                        if jq --arg t "$_nt" --argjson i "$_ni" --arg s "$_nsn" --arg p "$_np" \
                              '.cert_type=$t | .is_insecure=$i | .server_name=$s | .pin_sha256=$p' \
                              "$HY2_DIR/client_meta.json" > "$_tmp_meta" 2>/dev/null && [[ -s "$_tmp_meta" ]]; then
                            mv -f "$_tmp_meta" "$HY2_DIR/client_meta.json"
                            echo "证书信任模型已自愈: cert_type=${_ct:-<空>} -> ${_nt}, server_name=${_cs:-<空>} -> ${_nsn}"
                        else
                            rm -f "$_tmp_meta"
                            echo "证书信任模型自愈失败，client_meta.json 保持不变" >&2
                        fi
                    fi
                fi
            fi
        fi
        # 证书自愈单元自愈安装（2026-10-08）：老装机在线升级后也补齐
        # timer + path 单元，让 Caddy 等外部续期换证后无需人工点刷新即可自动对齐。
        if [[ -f "$HY2_DIR/client_meta.json" ]]; then
            cat > /usr/local/bin/hy2-cert-selfheal.sh <<'EOCS2'
#!/usr/bin/env bash
set -u
HY2_DIR="/etc/hysteria"
if [[ ! -f "$HY2_DIR/portal.py" || ! -f "$HY2_DIR/client_meta.json" ]]; then
    logger -t hy2-cert-selfheal "缺少 portal.py 或 client_meta.json，跳过"
    exit 0
fi
if ! grep -q 'def selfheal(' "$HY2_DIR/portal.py" 2>/dev/null; then
    logger -t hy2-cert-selfheal "当前 portal.py 不支持 selfheal 子命令（版本过旧），请升级门户"
    exit 0
fi
_out="$(python3 "$HY2_DIR/portal.py" selfheal "$HY2_DIR/client_meta.json" 2>&1)"
if [[ -n "$_out" ]]; then
    printf '%s\n' "$_out" | logger -t hy2-cert-selfheal
fi
unset _out
exit 0
EOCS2
            chmod 755 /usr/local/bin/hy2-cert-selfheal.sh
            printf '%s\n' \
              '[Unit]' \
              'Description=Hysteria 2 certificate trust-model self-heal' \
              '' \
              '[Service]' \
              'Type=oneshot' \
              'ExecStart=/usr/local/bin/hy2-cert-selfheal.sh' \
              > /etc/systemd/system/hy2-cert-selfheal.service
            printf '%s\n' \
              '[Unit]' \
              'Description=Run certificate self-heal every 30 minutes' \
              '' \
              '[Timer]' \
              'OnBootSec=2min' \
              'OnUnitActiveSec=30min' \
              'Unit=hy2-cert-selfheal.service' \
              '' \
              '[Install]' \
              'WantedBy=timers.target' \
              > /etc/systemd/system/hy2-cert-selfheal.timer
            _cwd="$HY2_DIR/cert"
            _cc="$(awk '/^tls:/{f=1;next} f&&/^[ \t]+cert:/{sub(/^[ \t]*cert:[ \t]*/,"");gsub(/["\x27]/,"");print;exit} f&&/^[^ \t]/{f=0}' "$HY2_DIR/config.yaml" 2>/dev/null || true)"
            if [[ -n "$_cc" ]]; then
                case "$_cc" in
                    /*) _cwd="$(dirname "$_cc")" ;;
                    *)  _cwd="$(dirname "$HY2_DIR/$_cc")" ;;
                esac
            fi
            [[ -d "$_cwd" ]] || _cwd="$HY2_DIR/cert"
            printf '%s\n' \
              '[Unit]' \
              'Description=Watch certificate dir and self-heal trust model on change' \
              '' \
              '[Path]' \
              "PathChanged=$_cwd" \
              'Unit=hy2-cert-selfheal.service' \
              '' \
              '[Install]' \
              'WantedBy=paths.target' \
              > /etc/systemd/system/hy2-cert-selfheal.path
            systemctl daemon-reload 2>/dev/null || true
            systemctl enable --now hy2-cert-selfheal.timer >/dev/null 2>&1 || true
            systemctl enable --now hy2-cert-selfheal.path  >/dev/null 2>&1 || true
            echo "证书一致性自愈单元已启用"
        fi
PORTALREPAIR
        export HY2_DIR
        python3 -I - "$HY2_DIR" "$_bundle_dir" $_bundle_files <<'PYBUNDLE'
import json, os, pathlib, shutil, subprocess, sys, tempfile, time, urllib.request
import fcntl

dest, download = map(pathlib.Path, sys.argv[1:3])
files = sys.argv[3:]
# 所有更新入口共用且保留同一 inode；锁持有到新版本验证或旧版本恢复验证结束。
lock = open(dest / '.portal-update.lock', 'a+b')
try:
    fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    sys.exit('另一个门户更新正在发布或验证，请稍后重试')

# 校验端口失败必须发生在写入之前；portal.json 与客户数据从不参与回滚。
with (dest / 'portal.json').open(encoding='utf-8') as handle:
    port = json.load(handle)['port']
if type(port) is not int or not 1 <= port <= 65535:
    sys.exit('门户端口无效，保留全部旧文件')

def restart_and_verify():
    try:
        result = subprocess.run(['systemctl', 'restart', 'hysteria-portal'], timeout=30)
        if result.returncode:
            return False
    except (OSError, subprocess.TimeoutExpired):
        return False
    for _ in range(20):
        try:
            with urllib.request.urlopen('http://127.0.0.1:%d/api/health' % port,
                                        timeout=2) as response:
                if json.loads(response.read()).get('ok') is True:
                    return True
        except Exception:
            pass
        time.sleep(1)
    return False

backup_root = dest / 'backups'
backup_root.mkdir(mode=0o700, exist_ok=True)
backup = pathlib.Path(tempfile.mkdtemp(prefix='portal-bundle-', dir=backup_root))
existing = {f: (dest / f).exists() for f in files}
for f in files:
    if existing[f]:
        shutil.copy2(dest / f, backup / f)
print('门户整包备份: ' + str(backup), flush=True)
# 独占 stage 与目标同文件系统，发布和回滚都使用原子 replace。
with tempfile.TemporaryDirectory(prefix='.portal-bundle-', dir=dest) as stage_dir:
    stage = pathlib.Path(stage_dir)
    written = []
    try:
        for f in files:
            shutil.copyfile(download / f, stage / f)
            (stage / f).chmod(0o644)
        for f in files:
            os.replace(stage / f, dest / f)
            written.append(f)
        result = subprocess.run(['bash', str(download / 'repair-config.sh')], timeout=120)
        if result.returncode:
            raise RuntimeError('门户配置自愈失败')
        if not restart_and_verify():
            raise RuntimeError('新门户启动或健康检查失败')
    except Exception as exc:
        print(str(exc) + '，恢复本次旧门户整包', file=sys.stderr)
        try:
            for f in reversed(written):
                if existing[f]:
                    shutil.copy2(backup / f, stage / f)
                    os.replace(stage / f, dest / f)
                else:
                    (dest / f).unlink()
        except Exception as restore_error:
            sys.exit('恢复旧门户整包失败；备份保留在 %s: %s' % (backup, restore_error))
        if written and not restart_and_verify():
            sys.exit('旧门户已恢复但启动验证失败；备份保留在 ' + str(backup))
        sys.exit('更新失败；旧门户已恢复' + ('并通过健康检查' if written else '，文件未改动'))
print('面板、前端与计量模块已整包更新并通过健康检查')
PYBUNDLE
        _write_rc=$?
        rm -rf "$_bundle_dir"
        [[ "$_write_rc" == "0" ]] || exit 1
    fi
else
    echo "无效的升级目标：只能使用 core 或 portal" >&2
    exit 2
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
    # 必须 || true：restart 失败时若被 set -e 直接终止，下面那段
    # 「请看 journalctl」的提示永远到不了用户眼前（2026-10-29 修）。
    systemctl restart hysteria-server || true
    
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

    local url user pass
    url=$(jq -r '.url' "$HY2_DIR/portal-access.json")
    user=$(jq -r '.username' "$HY2_DIR/portal-access.json")
    pass=$(jq -r '.password' "$HY2_DIR/portal-access.json")

    # 原来这里只吐一串凭据就结束了，新手装完完全不知道下一步该做什么。
    # 实际上「装完」只是完成了一半 —— 真正要用起来还需要：打开信息页 → 导入客户端
    # → 确认云安全组放行。这三步是新手卡住最多的地方，所以直接在收尾时讲清楚。
    echo
    echo -e "${CYAN}================================================================${PLAIN}"
    echo -e "${GREEN}                       接下来怎么用？${PLAIN}"
    echo -e "${CYAN}================================================================${PLAIN}"
    echo
    echo -e "${YELLOW}第 1 步 · 打开你的私密信息页${PLAIN}（浏览器访问，会要求输入下面的账号密码）"
    echo -e "    ${GREEN}${url}${PLAIN}"
    echo -e "    用户名: ${GREEN}${user}${PLAIN}"
    echo -e "    密  码: ${GREEN}${pass}${PLAIN}"
    echo
    echo -e "${YELLOW}第 2 步 · 在信息页里把节点导入客户端${PLAIN}"
    echo -e "    「节点导入」标签页里有二维码和节点直链，手机直接扫码、电脑复制直链即可。"
    echo -e "    支持 v2rayN / Nekobox / Shadowrocket / Clash.Meta / Sing-box 等。"
    echo
    echo -e "${YELLOW}第 3 步 · 确认云服务商安全组已放行端口${PLAIN}"
    echo -e "    ${RED}装好了却连不上，十有八九是这里没放行。${PLAIN}"
    local _hop_range_display="${HOP_PORT_RANGE:-}"
    # info 子命令没有经过端口配置，从落盘元数据读取实际启用的范围。
    if [[ ! -v HOP_PORT_RANGE ]]; then
        _hop_range_display="$(jq -r '.hop_port_range // empty' "$HY2_META_FILE" 2>/dev/null || true)"
    fi
    if [[ -n "$_hop_range_display" ]]; then
        echo -e "    ${GREEN}UDP ${_hop_range_display}${PLAIN}   节点连接用的端口跳跃区间（要放行整个区间，不是单个端口）"
    fi
    # ⚠️ 端口为空时不能光打印一个 "TCP"（2026-10-09 修）：菜单 3 / `info` 不会
    # 调 select_subscription_port，此时 HY2_SUB_PORT 就是空的。裸 `${HY2_SUB_PORT}`
    # 会印出「TCP        私密信息页…」—— 新手以为安装漏了东西，其实上面 URL
    # 里就有正确端口。从 URL 里取，取不到才给提示。
    local _sub_port_display="${HY2_SUB_PORT:-}"
    if [[ -z "$_sub_port_display" ]]; then
        _sub_port_display="$(printf '%s' "$url" | sed -n 's#.*:\([0-9]\{1,5\}\)/.*#\1#p')"
    fi
    if [[ -n "$_sub_port_display" ]]; then
        echo -e "    ${GREEN}TCP ${_sub_port_display}${PLAIN}        私密信息页（就是上面那个 URL 的端口）"
    else
        echo -e "    ${YELLOW}私密信息页端口见上方 URL${PLAIN}"
    fi
    if [[ "${CERT_TYPE:-}" == "acme" ]]; then
        echo -e "    ${GREEN}TCP 80${PLAIN}        申请 / 续期 Let's Encrypt 证书用"
    fi

    local key
    key=$(jq -r '.api_key // empty' "$HY2_DIR/portal-access.json" 2>/dev/null) || true
    if [[ -n "$key" ]]; then
        echo
        echo -e "${YELLOW}节点通信 API Key${PLAIN}（商城版 / Teyir 控制台接入使用）"
        echo -e "    ${GREEN}${key}${PLAIN}"
    fi

    local pin
    pin=$(jq -r '.pin_sha256 // empty' "$HY2_META_FILE" 2>/dev/null) || true
    if [[ -n "$pin" ]]; then
        echo
        echo -e "${YELLOW}自签证书 SHA-256 指纹${PLAIN}（已自动写进客户端直链，一般不用手动处理）"
        echo -e "    ${GREEN}${pin}${PLAIN}"
        log_warn "自签证书靠指纹校验客户端；若能给域名签一张正式证书，可彻底免去指纹维护。"
    fi

    echo
    echo -e "${CYAN}----------------------------------------------------------------${PLAIN}"
    echo -e "  以后想再看本节内容，直接执行：  ${GREEN}bash install.sh info${PLAIN}"
    echo -e "  查看服务状态：                  ${GREEN}bash install.sh status${PLAIN}"
    echo -e "${CYAN}================================================================${PLAIN}"
}

# ==============================================================================
# 门户程序 portal.py 的获取
# ------------------------------------------------------------------------------
# 🔴 这里**不再内嵌** portal.py 的源码。它曾经以 heredoc 形式内嵌在本脚本里，
#    占了整个 install.sh 七成行数；每次改 portal.py 都要手动同步一次，
#    漏一次就是"仓库里的门户"和"装到你机器上的门户"不一致。
#
# 改成运行时获取是安全的：本脚本本来就必须联网才能装起来
# （install_binary 要从 GitHub Releases 下载 Hysteria 二进制），
# 所以拉 portal.py 没有引入任何新的前提。
#
# 拿到之后**必须做语法编译校验**再落地 —— 门户同时承担 Hysteria 的 auth 后端
# （config.yaml 里 auth.http.url 指向它），门户写坏 = 所有客户端都连不上。
# ==============================================================================

# 拉取 portal.py：三级回退，理由同 awg_fetch_ctl（GitHub API 权威但限速、
# jsDelivr 无速率限制、raw 最后兜底且可能滞后）
# 门户由【两个文件】组成，必须成对处理：
#   portal.py          后端逻辑（HTTP 服务与各功能端点）
#   portal_assets.py   前端资源（CSS / 内嵌 JS 常量）
# portal.py 通过 `from portal_assets import ...` 引入后者。
#
# 🔴 为什么反复强调"成对"：门户同时是 Hysteria 的鉴权后端，缺任何一个文件都会让
#    **所有客户端连不上**。所以两个文件一起拉、一起校验；任一步失败就整体中止，
#    绝不出现"只更新了 portal.py、前端资源还是旧版"的中间状态。
#
# 三级回退理由同 awg_fetch_ctl：GitHub API 权威但限速 60/h、jsDelivr 无速率限制、
# raw 最后兜底且可能滞后。
PORTAL_FILES="portal.py portal_assets.py"

# 真实计量模块（2026-10-07 上线，portal.py 通过 spec_from_file_location 加载）。
# ⚠️ 必须和 portal.py 一起部署：缺任何一个，portal 都会在启动时
# 打印「真实计量未初始化」并**永久降级**，但安装照样成功——
# 表现为装完一切正常、界面用量永远「未开始计量」，极难察觉。
# 计量文件的版本号写进文件名（-20261007-v1）是有意的：
# 改内容时换文件名，让 portal 的 spec_from_file_location 换模块而不是复用旧实例。
METER_FILES="usage-meter-core-20261007-v1.py usage-meter-readers-20261007-v1.py usage-meter-runtime-20261007-v1.py usage-meter-xray-config-20261007-v1.py"

# 校验一组门户文件是否完整可用（关键标记 + Python 语法编译）
portal_files_ok() {
    local dir="$1"
    [[ -s "${dir}/portal.py" ]] && grep -q 'def page_html' "${dir}/portal.py" 2>/dev/null || return 1
    [[ -s "${dir}/portal_assets.py" ]] && grep -q 'SCRIPT = r' "${dir}/portal_assets.py" 2>/dev/null || return 1
    # 计量模块：缺任何一个都不算通过（理由见 METER_FILES 处的注释）
    local m
    for m in $METER_FILES; do
        [[ -s "${dir}/${m}" ]] || return 1
    done
    # 语法正确不代表兼容：CDN 旧缓存可能把新面板与旧计量模块混装。
    for m in usage-meter-core-20261007-v1.py usage-meter-runtime-20261007-v1.py; do
        grep -q '^ACCOUNTING_REVISION = "2026-10-12-real-usage-v2"$' "${dir}/${m}" || return 1
    done
    # ast.parse 而不是 py_compile —— 后者会在源文件旁边生成 __pycache__
    # 🔴 每个文件都必须带 "${dir}/" 前缀：这里传的是【文件名】而不是【路径】。
    #    校验发生在 mktemp -d / 脚本同目录上，两者几乎永远不等于当前工作目录，
    #    裸文件名会解析成 $PWD/xxx 而 FileNotFoundError => 校验恒失败 =>
    #    三个源全被误判为失败 => 安装报"无法获取门户程序"（网络其实完全正常）。
    #    这是 2026-10-08 计量模块并入时引入的真实故障。
    local -a _pylist=()
    for f in $PORTAL_FILES $METER_FILES; do
        _pylist+=("${dir}/${f}")
    done
    python3 -c '
import ast, sys
for p in sys.argv[1:]:
    ast.parse(open(p, encoding="utf-8").read())
' "${_pylist[@]}" 2>/dev/null || return 1
    return 0
}

# 把门户文件拉到指定目录；任一文件失败即整体失败。
# 🔴 失败详情写进 _fetch_files_err（局部变量）而不是共享的 PORTAL_FETCH_ERR ——
#    两个函数复用同一个变量会互相覆盖，外层已累积的逐源原因会被内层清空，
#    最终报错只剩最后一个源，正是本项目反复踩的"错误被覆盖"坑。
portal_fetch_files() {
    local dir="$1" base="$2" mode="$3" f _fetch_files_err=""
    # 计量文件与门户文件同源同生命周期，一起拉、一起失败
    for f in $PORTAL_FILES $METER_FILES; do
        if [[ "$mode" == "api" ]]; then
            # 逐个文件报错，不要只留最后一个（错误被覆盖会把排查带偏）
            if ! curl -fsSL --max-time 30 -H "Accept: application/vnd.github.raw" \
                 "${base}/${f}?ref=${PORTAL_FETCH_REF}" -o "${dir}/${f}" 2>/dev/null; then
                _fetch_files_err="下载 ${f} 失败"
                return 1
            fi
        else
            if ! curl -fsSL --max-time 30 "${base}/${f}" -o "${dir}/${f}" 2>/dev/null; then
                _fetch_files_err="下载 ${f} 失败"
                return 1
            fi
        fi
    done
    # 成功时也要把细节带出去（调用方在失败分支里读它）
    PORTAL_FETCH_FILES_ERR="${_fetch_files_err}"
    return 0
}

# 取某个 commit 下仓库根目录各文件的 git blob 身份，输出 "name sha" 每行一条。
# 一次目录列表请求即可拿到全部文件（contents API 的 JSON 里就带 sha），
# 比逐文件请求省额度。取不到返回 1 —— 调用方必须 fail-closed。
portal_remote_blob_shas() {
    local ref="${1:-}" json
    [[ "$ref" =~ ^[0-9a-f]{40}$ ]] || return 1
    json="$(mktemp)"
    if ! curl -fsSL --max-time 20 -H "Accept: application/vnd.github+json" \
            "https://api.github.com/repos/${AWG_REPO}/contents/?ref=${ref}" -o "$json" 2>/dev/null; then
        rm -f "$json"
        return 1
    fi
    python3 -c '
import json, re, sys
try:
    items = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception:
    sys.exit(1)
if not isinstance(items, list):
    sys.exit(1)
rows = []
for it in items:
    if not isinstance(it, dict):
        continue
    name, sha = it.get("name"), it.get("sha") or ""
    if name and re.fullmatch(r"[0-9a-f]{40}", sha):
        rows.append(name + " " + sha)
print("\n".join(rows))
' "$json" || { rm -f "$json"; return 1; }
    rm -f "$json"
    return 0
}

# 核对目录里每个文件的内容与预期 blob 身份一致；$2 为 "name sha" 行。
# 任何缺失/不一致都返回 1（不做"部分一致也算过"）。
portal_verify_blobs() {
    local dir="$1" map="$2" name sha got
    [[ -n "$map" ]] || return 1
    for f in $PORTAL_FILES $METER_FILES; do
        sha="$(printf '%s\n' "$map" | awk -v n="$f" '$1==n{print $2; exit}')"
        [[ "$sha" =~ ^[0-9a-f]{40}$ ]] || return 1
        got="$(hy2_git_blob_sha "${dir}/${f}")" || return 1
        [[ "$got" == "$sha" ]] || return 1
    done
    return 0
}

# 每一源的真实失败原因累积在这里，供最终报错逐条展示。
# 🔴 旧实现把「网络拉不到」与「拉到了但本地校验不过」都压成同一个 return 1，
#    最终只报「三个源均失败」+「请确认能访问 GitHub」，于是本地校验 bug
#    被误判成网络故障（2026-10-08 真实发生过，排查方向完全被带偏）。必须分类。
PORTAL_FETCH_ERR=""
PORTAL_FETCH_FILES_ERR=""
PORTAL_FETCH_ALL_VERIFY_FAILED=0

portal_fetch_py() {
    local dir="$1"
    local repo="${AWG_REPO}"
    local spec name base mode why m
    PORTAL_FETCH_ERR=""
    PORTAL_FETCH_FILES_ERR=""
    PORTAL_FETCH_ALL_VERIFY_FAILED=0
    # 只解析一次 main，防止下载过程中 main 前进导致整包跨版本。
    local PORTAL_FETCH_REF
    # 先问 GitHub API；它被限流（匿名每 IP 60 次/小时，共享 IP 极常见）时
    # 退回 jsDelivr 的 resolved 接口 —— 同样给出 main 对应的**具体 commit**，
    # 于是「锁定一次提交、三源取同一份」的保证不变，又不会因为限流装不上。
    PORTAL_FETCH_REF="$(curl -fsSL --max-time 15 "https://api.github.com/repos/${repo}/commits/main" 2>/dev/null |
        python3 -c 'import json,re,sys
try: s=json.load(sys.stdin).get("sha","")
except Exception: s=""
assert re.fullmatch("[0-9a-f]{40}", s); print(s)' 2>/dev/null)" || PORTAL_FETCH_REF=""
    if [[ ! "$PORTAL_FETCH_REF" =~ ^[0-9a-f]{40}$ ]]; then
        # 次选：仓库的 commits Atom feed。它由 github.com 直接提供、不计 API 额度，
        # 且条目里带完整 40 位 commit —— 一样能锁定到具体提交。
        # （jsDelivr 的 resolved 接口对分支名返回 null，不能用作回退。）
        PORTAL_FETCH_REF="$(curl -fsSL --max-time 15 "https://github.com/${repo}/commits/main.atom" 2>/dev/null |
            python3 -c 'import re,sys
m=re.search(r"/commit/([0-9a-f]{40})", sys.stdin.read())
assert m; print(m.group(1))' 2>/dev/null)" || PORTAL_FETCH_REF=""
    fi
    if [[ ! "$PORTAL_FETCH_REF" =~ ^[0-9a-f]{40}$ ]]; then
        PORTAL_FETCH_ERR="  [GitHub API] 无法取得 main 的 commit（通常是匿名 API 被限流）"$'
'
        PORTAL_FETCH_ERR+="  [commits.atom] 无法解析 main 的最新提交"$'
'
        PORTAL_FETCH_ERR+="  [jsDelivr / raw] 缺少可锁定的 commit，未下载"$'
'
        PORTAL_FETCH_ERR+="（提示：把只读 token 放到 /etc/hysteria/github-token 可解除 API 限流）"
        return 1
    fi
    # 该 commit 下每个文件的 git blob 身份：下载后逐文件比对。
    # 🔴 只校验 marker + 语法挡不住"CDN 返回与所 pin commit 不符的内容"：
    #    只要内容里含 marker 且语法合法，就会被写成 root 运行的面板代码。
    local PORTAL_BLOBS
    if ! PORTAL_BLOBS="$(portal_remote_blob_shas "$PORTAL_FETCH_REF")" || [[ -z "$PORTAL_BLOBS" ]]; then
        # 拿不到预期身份就无从核对，三个源一律不采信（fail-closed）。
        # 归为"网络/身份获取类"而不是"校验类"：本地校验逻辑并没有跑过。
        PORTAL_FETCH_ERR="  [GitHub API] 无法取得 ${PORTAL_FETCH_REF:0:7} 的文件身份（contents API）"$'\n'
        PORTAL_FETCH_ERR+="  [jsDelivr] 缺少可核对的预期文件身份，未下载"$'\n'
        PORTAL_FETCH_ERR+="  [raw.githubusercontent] 缺少可核对的预期文件身份，未下载"$'\n'
        return 1
    fi
    # spec 格式：名称|base|模式
    while IFS='|' read -r name base mode; do
        [[ -z "$name" ]] && continue
        # 每轮从干净目录开始，避免上一源的残留被当成本源的成功
        rm -f "${dir}"/portal.py "${dir}"/portal_assets.py 2>/dev/null || true
        for m in $METER_FILES; do
            rm -f "${dir}/${m}" 2>/dev/null || true
        done

        if portal_fetch_files "$dir" "$base" "$mode"; then
            if ! portal_files_ok "$dir"; then
                why="文件已取回，但未通过校验（关键标记缺失或 Python 语法不通）"
                PORTAL_FETCH_ALL_VERIFY_FAILED=1
            elif ! portal_verify_blobs "$dir" "$PORTAL_BLOBS"; then
                why="文件已取回，但内容与所 pin commit ${PORTAL_FETCH_REF:0:7} 的文件身份不符"
                PORTAL_FETCH_ALL_VERIFY_FAILED=1
            else
                return 0
            fi
        else
            why="网络拉取失败（${PORTAL_FETCH_FILES_ERR:-下载失败}）"
        fi
        PORTAL_FETCH_ERR="${PORTAL_FETCH_ERR}  [${name}] ${why}"$'\n'
    done <<EOF
GitHub API|https://api.github.com/repos/${repo}/contents|api
jsDelivr|https://cdn.jsdelivr.net/gh/${repo}@${PORTAL_FETCH_REF}|plain
raw.githubusercontent|https://raw.githubusercontent.com/${repo}/${PORTAL_FETCH_REF}|plain
EOF
    return 1
}

# 确保 $HY2_DIR 下门户的两个文件都就位。
# 优先用与 install.sh 同目录的本地文件（本地克隆 / 开发调试场景），否则从仓库拉取。
# 注意本脚本常以 `bash <(curl ...)` 运行，此时 BASH_SOURCE 指向 /dev/fd/NN
# 而非真实文件，所以必须做存在性判断。
portal_ensure_py() {
    local dest_dir="$HY2_DIR"
    local srcdir="" dir="" tmpdir=""

    # 本地快路径：门户两个文件 + 计量模块都在脚本同目录才用。
    # 少任何一个都说明是残缺的本地树 —— 这种情况宁可走网络拉完整的，也不要写一半进去。
    # ⚠️ 判断条件必须与 portal_files_ok 对齐（同样要求计量模块），
    #    否则本地树残缺时要等到后面落地校验才失败，报错信息更模糊。
    if [[ -n "${BASH_SOURCE[0]:-}" && -f "${BASH_SOURCE[0]}" ]]; then
        dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)" || dir=""
        if [[ -n "$dir" && -f "${dir}/portal.py" && -f "${dir}/portal_assets.py" ]]; then
            local _m _all_present=1
            for _m in $METER_FILES; do
                [[ -s "${dir}/${_m}" ]] || { _all_present=0; break; }
            done
            [[ "$_all_present" == "1" ]] && srcdir="$dir"
        fi
    fi

    if [[ -z "$srcdir" ]]; then
        tmpdir="$(mktemp -d)"
        if portal_fetch_py "$tmpdir"; then
            srcdir="$tmpdir"
        else
            rm -rf "$tmpdir"
            log_err "无法获取门户程序（portal.py + portal_assets.py + 计量模块，三个源均失败）"
            # 🔴 逐源打印真实原因：网络不通与本地校验逻辑坏掉是两回事，
            #    只报一句「请检查网络」会把排查带偏（2026-10-08 真的发生过）。
            while IFS= read -r _line; do
                [[ -n "$_line" ]] && log_err "  ${_line}"
            done <<< "$PORTAL_FETCH_ERR"
            if [[ "$PORTAL_FETCH_ALL_VERIFY_FAILED" == "1" ]]; then
                log_err "三个源都成功取回了文件却都校验不通过 —— 这不是网络问题，"
                log_err "而是本地校验逻辑有 bug，或仓库 main 分支内容已损坏。"
                log_err "请到仓库提 issue，并附上以上逐源原因。"
            else
                log_err "门户同时是 Hysteria 的鉴权后端，缺了它所有客户端都连不上，因此中止安装。"
                log_err "请确认本机能访问 GitHub 或 jsDelivr；也可手动把门户文件"
                log_err "（portal.py / portal_assets.py / 计量模块）放到脚本同目录后重试。"
            fi
            return 1
        fi
    fi

    # 落地前统一校验（本地快路径没走过拉取时的校验）
    if ! portal_files_ok "$srcdir"; then
        [[ -n "$tmpdir" ]] && rm -rf "$tmpdir"
        log_err "门户文件未通过校验（关键标记缺失或 Python 语法不通），已中止 —— 避免把门户写坏。"
        return 1
    fi

    # 先在目标文件系统暂存整包；srcdir == dest_dir 时也不会覆盖输入。
    local stage m
    if ! stage="$(mktemp -d "${dest_dir}/.portal-bundle-XXXXXX")"; then
        [[ -n "$tmpdir" ]] && rm -rf "$tmpdir"
        return 1
    fi
    for m in $PORTAL_FILES $METER_FILES; do
        if ! install -m 0644 "${srcdir}/${m}" "${stage}/${m}"; then
            log_err "暂存门户文件 ${m} 失败，原文件未改动"
            rm -rf "$stage"
            [[ -n "$tmpdir" ]] && rm -rf "$tmpdir"
            return 1
        fi
    done
    if ! portal_files_ok "$stage"; then
        log_err "暂存门户整包校验失败，原文件未改动"
        rm -rf "$stage"
        [[ -n "$tmpdir" ]] && rm -rf "$tmpdir"
        return 1
    fi
    # 与 do_upgrade 的整包事务相同：备齐旧文件后才替换，失败恢复内容和模式。
    # 备份使用唯一目录并保留，避免同秒重试覆盖上一次可恢复的包。
    if ! python3 -I - "$dest_dir" "$stage" $PORTAL_FILES $METER_FILES <<'PYINSTALLBUNDLE'
import fcntl, os, pathlib, shutil, sys, tempfile

dest, stage = map(pathlib.Path, sys.argv[1:3])
files = sys.argv[3:]
# 与终端/Web 更新共享锁，覆盖备份、发布与失败恢复。文件不能删除。
lock = open(dest / '.portal-update.lock', 'a+b')
try:
    fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    sys.exit('另一个门户更新正在发布或验证，请稍后重试')
backup_root = dest / 'backups'
backup_root.mkdir(mode=0o700, exist_ok=True)
backup = pathlib.Path(tempfile.mkdtemp(prefix='portal-bundle-', dir=backup_root))
existing = {f: (dest / f).exists() for f in files}
for f in files:
    if existing[f]:
        shutil.copy2(dest / f, backup / f)
written = []
try:
    for f in files:
        os.replace(stage / f, dest / f)
        written.append(f)
except Exception:
    for f in reversed(written):
        if existing[f]:
            restore = stage / f
            shutil.copy2(backup / f, restore)
            os.replace(restore, dest / f)
        else:
            (dest / f).unlink()
    raise
print('门户整包备份: ' + str(backup))
PYINSTALLBUNDLE
    then
        log_err "写入门户整包失败；原文件备份保留在 ${dest_dir}/backups/portal-bundle-*"
        rm -rf "$stage"
        [[ -n "$tmpdir" ]] && rm -rf "$tmpdir"
        return 1
    fi
    rm -rf "$stage"
    [[ -n "$tmpdir" ]] && rm -rf "$tmpdir"
    # 计量配置：secret 取自本机 config.yaml 的 trafficStats，
    # 绝不写死进仓库 —— 仓库里只放 usage-meter-config.json.example。
    #
    # 🔴 硬约束：这里如果读不到 trafficStats.secret，说明 config.yaml 缺该段
    # （老装机 / 手工改过）。此前的做法是 log_warn 后继续 —— 结果 portal 启动即
    # `[portal] 真实计量未初始化: FileNotFoundError`，usage_meter=None，
    # /traffic-speed 恒 0、users/list 的 measurement_ok 恒 false，
    # 而安装**看起来完全成功**。这是本项目最忌的静默降级。
    # 现在改为：先尝试幂等补写 trafficStats 段；补不上就硬失败返回 1。
    _meter_secret="$(awk '/^trafficStats:/{f=1;next} f&&/secret:/{gsub(/[^0-9a-f]/,"",$2); print $2; exit}' "$HY2_CONFIG" 2>/dev/null || true)"
    if [[ -z "$_meter_secret" ]]; then
        log_warn "config.yaml 缺 trafficStats 段，正在幂等补写以满足真实计量..."
        if [[ -z "${METER_SECRET:-}" ]]; then
            METER_SECRET="$(openssl rand -hex 16)"
        fi
        # 不追加到文件末尾：其他段的位置不影响 hysteria 解析，但保持可读性插入到
        # masquerade 之前；若找不到锚点则追加到末尾（hysteria 对顶层键顺序不敏感）。
        python3 - "$HY2_CONFIG" "$METER_SECRET" <<'PYEOF'
import io, re, sys
path, secret = sys.argv[1], sys.argv[2]
s = io.open(path, encoding='utf-8').read()
block = ("\n# 真实计量：/traffic 只读端点，供 usage-meter 采集。必须回环监听，\n"
         "# 且 secret 与 usage-meter-config.json 的 hysteria.secret 逐字符一致。\n"
         "trafficStats:\n  listen: 127.0.0.1:19996\n  secret: %s\n" % secret)
if not re.search(r'^trafficStats:', s, re.M):
    anchor = 'masquerade:'
    if anchor in s:
        s = s.replace(anchor, block.lstrip('\n') + '\n' + anchor, 1)
    else:
        s = s.rstrip('\n') + '\n' + block
io.open(path, 'w', encoding='utf-8', newline='\n').write(s)
PYEOF
        _meter_secret="$(awk '/^trafficStats:/{f=1;next} f&&/secret:/{gsub(/[^0-9a-f]/,"",$2); print $2; exit}' "$HY2_CONFIG" 2>/dev/null || true)"
    fi
    if [[ -z "$_meter_secret" ]]; then
        log_err "无法在 ${HY2_CONFIG} 中建立 trafficStats.secret —— 真实计量无法启用。"
        log_err "拒绝以静默降级的方式继续安装（界面会永远显示「未开始计量」）。"
        return 1
    fi
    cat > "${dest_dir}/usage-meter-config.json" <<METEREOF
{"hysteria": {"url": "http://127.0.0.1:19996", "secret": "${_meter_secret}"}, "reality": {"binary": "/usr/local/bin/xray", "address": "127.0.0.1:19997"}}
METEREOF
    chmod 600 "${dest_dir}/usage-meter-config.json"
    unset _meter_secret
    log_info "门户程序已就位: ${dest_dir}/portal.py + portal_assets.py + 计量模块"
}

# 证书信任模型自愈（2026-10-08）。
# 🔴 真实 bug：client_meta.json 的 cert_type/server_name/is_insecure/pin_sha256
#    是安装那一刻写死的。证书文件在安装后被带外替换（Caddy 抢证、手工 cp、
#    menu-4 只换证书没重跑 generate_server_config）时，四个字段会同时漂移：
#      config.yaml 用 CN=se.zy3a.com 的正式证书，meta 却还写着
#      cert_type=self_signed / server_name=www.bing.com / is_insecure=true，
#    于是面板把 sni=www.bing.com 发给客户端 → CRYPTO_ERROR 0x150。
#    portal.py 的 sync_cert_trust() 已能以证书为唯一事实来源自愈；这里做同样
#    的事，保证「不通过 portal 初始化」的路径（refresh / 在线升级）也修得到。
sync_cert_meta() {
    [[ -f "$HY2_META_FILE" ]] || return 0
    command -v jq >/dev/null 2>&1 || return 0
    [[ -f "$HY2_CONFIG" ]] || return 0

    # 权威证书路径：config.yaml 的 tls.cert；没有（acme 模式）则退回 server.crt。
    # ⚠️ config.yaml 里写的是 hysteria 的工作目录相对路径（`cert/xxx.pem`），
    #    而 install.sh 可能从任意 CWD 被调起 —— 必须显式相对 $HY2_DIR 解析，
    #    否则 `-f` 判空一定失败，自愈会被静默跳过（2026-10-08 真实踩到）。
    local cert_file
    cert_file="$(awk '/^tls:/{f=1;next} f&&/^[ \t]+cert:/{sub(/^[ \t]*cert:[ \t]*/,"");gsub(/["\x27]/,"");print;exit} f&&/^[^ \t]/{f=0}' "$HY2_CONFIG" 2>/dev/null || true)"
    if [[ -n "$cert_file" && "$cert_file" != /* && ! -f "$cert_file" ]]; then
        [[ -f "${HY2_DIR}/${cert_file}" ]] && cert_file="${HY2_DIR}/${cert_file}"
    fi
    [[ -n "$cert_file" && -f "$cert_file" ]] || cert_file="${HY2_CERT_DIR}/server.crt"
    [[ -f "$cert_file" ]] || return 0

    local cn sans subject issuer self_signed="false" acme_block="false"
    cn="$(openssl x509 -in "$cert_file" -noout -subject 2>/dev/null | sed -n 's/.*CN *= *//p' | head -1 | sed 's/ *$//')"
    # 收集**全部** SAN：一张证书常覆盖多个域名，只取第一个会把 server_name
    # 写成错的（客户端 SNI 对不上 → 握手失败）。具体选哪个在下面决定。
    sans="$(openssl x509 -in "$cert_file" -noout -ext subjectAltName 2>/dev/null | tr ',' '\n' | sed -n 's/^ *DNS://p' | tr '\n' ' ')"
    subject="$(openssl x509 -in "$cert_file" -noout -subject 2>/dev/null | sed 's/^subject=//' | sed 's/ *$//')"
    issuer="$(openssl x509 -in "$cert_file" -noout -issuer 2>/dev/null | sed 's/^issuer=//' | sed 's/ *$//')"
    [[ -n "$subject" && "$subject" == "$issuer" ]] && self_signed="true"
    grep -q '^acme:' "$HY2_CONFIG" 2>/dev/null && acme_block="true"

    # server_name：SAN 优先（现代客户端只认 SAN），CN 兜底；过滤 wildcard。
    local new_sn="" _san
    # 优先本次配置的域名（SERVER_NAME / HY2_DOMAIN 在 SAN 里时用它），
    # 否则取第一个非通配 SAN；都没有才退回 CN。
    local _wanted="${SERVER_NAME:-${HY2_DOMAIN:-}}"
    for _san in $sans; do
        [[ -z "$_san" || "$_san" == \** ]] && continue
        if [[ -n "$_wanted" && "$_san" == "$_wanted" ]]; then new_sn="$_san"; break; fi
        [[ -z "$new_sn" ]] && new_sn="$_san"
    done
    if [[ -z "$new_sn" && -n "$cn" && "$cn" != \** ]]; then
        new_sn="$cn"
    fi
    [[ -n "$new_sn" ]] || new_sn="$(jq -r '.server_name // .public_ip // "localhost"' "$HY2_META_FILE" 2>/dev/null || echo localhost)"

    local new_type new_insecure new_pin=""
    if [[ "$self_signed" == "true" ]]; then
        new_type="self_signed"; new_insecure="true"
        new_pin="$(openssl x509 -in "$cert_file" -outform DER 2>/dev/null | openssl dgst -sha256 2>/dev/null | awk '{print $NF}' | tr 'A-F' 'a-f' || true)"
        [[ "$new_pin" =~ ^[0-9a-f]{64}$ ]] || new_pin=""
    else
        [[ "$acme_block" == "true" ]] && new_type="acme" || new_type="custom"
        new_insecure="false"
    fi

    local cur_type cur_insec cur_sn cur_pin
    cur_type="$(jq -r '.cert_type // empty'   "$HY2_META_FILE" 2>/dev/null || true)"
    # ⚠️ 不能用 `.is_insecure // empty`：jq 的 `//` 把 **false 当成 null**，
    #    于是布尔 false 会被替换成 empty，导致「明明已一致」却每轮都判成漂移、
    #    反复写盘。用 tostring 显式取字符串值（缺失时才回退空串）。
    cur_insec="$(jq -r 'if has("is_insecure") then (.is_insecure|tostring) else "" end' "$HY2_META_FILE" 2>/dev/null || true)"
    cur_sn="$(jq -r '.server_name // empty'   "$HY2_META_FILE" 2>/dev/null || true)"
    cur_pin="$(jq -r '.pin_sha256 // empty'   "$HY2_META_FILE" 2>/dev/null || true)"

    if [[ "$cur_type" == "$new_type" && "$cur_insec" == "$new_insecure" \
          && "$cur_sn" == "$new_sn" && "$cur_pin" == "$new_pin" ]]; then
        return 0
    fi

    log_warn "检测到证书信任模型漂移，正在自愈（证书=${cert_file}）:"
    log_warn "  cert_type: ${cur_type:-<空>} -> ${new_type}"
    log_warn "  is_insecure: ${cur_insec:-<空>} -> ${new_insecure}"
    log_warn "  server_name: ${cur_sn:-<空>} -> ${new_sn}"
    if [[ "$new_pin" != "$cur_pin" ]]; then
        log_warn "  pin_sha256: ${cur_pin:-<空>} -> ${new_pin:-<清空>}"
    fi
    local tmp_meta="${HY2_META_FILE}.tmp.$$"
    if jq --arg t "$new_type" --argjson i "$new_insecure" --arg s "$new_sn" --arg p "$new_pin" \
          '.cert_type=$t | .is_insecure=$i | .server_name=$s | .pin_sha256=$p' \
          "$HY2_META_FILE" > "$tmp_meta" 2>/dev/null && [[ -s "$tmp_meta" ]]; then
        mv -f "$tmp_meta" "$HY2_META_FILE"
        log_info "证书信任模型已自愈。"
    else
        rm -f "$tmp_meta"
        log_err "证书信任模型自愈写盘失败，client_meta.json 保持不变。"
        return 1
    fi
    return 0
}

refresh_portal() {
    # 只要求 portal.json：portal-access.json 丢失时 refresh 会重建一份凭据
    # （保留 token / API Key / 用户），不该让「刷新页面」直接失败（2026-10-30 修）。
    [[ -f "$HY2_DIR/portal.json" ]] || { log_err "未找到已有网页配置，请先安装。"; return 1; }
    portal_ensure_py
    chmod 644 "$HY2_DIR/portal.py"
    # 证书可能已被带外替换（Caddy 续期 / 手工换证），先自愈信任模型再 refresh，
    # 否则 refresh 出来的订阅仍带漂移的 sni。
    sync_cert_meta
    # 老装机此前没有证书自愈单元 —— 借着刷新顺带补齐（幂等，重复调用无副作用）。
    setup_cert_selfheal >/dev/null 2>&1 || true
    python3 "$HY2_DIR/portal.py" refresh "$HY2_META_FILE" || true
    systemctl restart hysteria-portal || true
    if ! systemctl is-active --quiet hysteria-portal; then
        log_err "门户重启失败（Hy2 鉴权后端不可用），请运行 'journalctl -u hysteria-portal -e' 查看日志。"
        return 1
    fi
    log_info "网页已更新，节点参数和登录凭据保持不变。"
}

setup_portal() {
    portal_ensure_py
    # 只要求 portal.json：凭据文件缺失时 adopt 会重建一份（保留用户与
    # API Key），不能因为一个文件丢了就把整个用户表推倒重建（2026-10-30 修）。
    if [[ "${PRESERVE_PORTAL:-0}" == "1" && -f "$HY2_DIR/portal.json" ]]; then
        # 沿用现有门户：token、门户账号密码、API Key、全部用户与代理服务都保留，
        # Teyir 控制台保存的凭据继续有效（见 portal.py adopt）。
        # 检查返回码：prepare/adopt 失败时若被 set -e 打断，脚本会停在
        # 「portal.py 已就位、systemd 单元还没写」的半成品状态，而门户
        # 就是 Hy2 的鉴权后端（2026-10-29 修）。
        if ! python3 "$HY2_DIR/portal.py" adopt "$HY2_META_FILE" "$PORTAL_LOCAL_PORT" "$NODE_API_KEY"; then
            log_err "沿用现有门户失败（portal.py adopt 返回非零），安装中止。"
            log_err "请检查 ${HY2_DIR}/portal.json 是否完整；必要时从备份恢复后重试。"
            return 1
        fi
        log_info "已沿用现有门户的登录凭据、API Key 与全部用户。"
    else
        if ! python3 "$HY2_DIR/portal.py" prepare "$HY2_META_FILE" "$PORTAL_LOCAL_PORT" "$NODE_API_KEY"; then
            log_err "初始化门户失败（portal.py prepare 返回非零），安装中止。"
            log_err "未写入 systemd 单元，现有服务不受影响。"
            return 1
        fi
    fi
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
    # 目录 700：门户与所有配置只允许 root 访问。portal.py 本身是 644，
    # 但目录不可遍历时本机其他用户既列不出也读不到（2026-10-30 修）。
    chmod 700 "$HY2_DIR"
    chmod 644 "$HY2_DIR/portal.py"
    chmod 600 "$HY2_DIR/portal.json" "$HY2_DIR/portal-access.json" "$HY2_META_FILE" "$HY2_CONFIG"
    systemctl daemon-reload
    systemctl enable hysteria-portal >/dev/null
    systemctl restart hysteria-portal
    sleep 1
    systemctl is-active --quiet hysteria-portal || { log_err "信息页服务启动失败"; return 1; }
    setup_cert_selfheal
}

# 证书一致性定时/事件自愈（2026-10-08）。
# 🔴 为什么需要（真实 bug 的下游）：client_meta.json 的信任模型只在安装 / 手动
#    refresh 时对齐。若证书由**外部**程序续期（Caddy 抢证、acme.sh --cron 等），
#    换证当下没有任何本项目的代码被触发 —— 用户不点「刷新」就永远带着旧 sni，
#    表现为换了正式证书后仍 CRYPTO_ERROR 0x150。
# 双保险：
#   1) hy2-cert-selfheal.timer  —— 每 30 分钟兜底扫一次（覆盖任何换证方式）；
#   2) hy2-cert-selfheal.path   —— 监听证书文件本身，inode 一变立刻触发（Caddy
#      续期是 rename 替换，PathChanged 必然命中），做到「换完即修」。
# 执行体是一个只调 `portal.py selfheal` 的脚本：幂等，无漂移时零写入。
setup_cert_selfheal() {
    cat > /usr/local/bin/hy2-cert-selfheal.sh <<'EOCS'
#!/usr/bin/env bash
# 证书信任模型自愈：以 config.yaml 实际使用的证书为唯一事实来源，
# 幂等修正 client_meta.json 的 cert_type/server_name/is_insecure/pin_sha256。
# 无漂移时零写入、不发无谓重启。失败只记日志，不让 timer 报错刷屏。
#
# ⚠️ 输出必须进 journal（不能用 >/dev/null 2>&1 全吞）：旧版 portal.py 没有
#    selfheal 子命令时会把参数当成 serve 启动第二个门户进程，这类失败必须留痕，
#    否则「服务显示成功、其实啥也没修」又是本项目最忌的静默降级。
set -u
HY2_DIR="/etc/hysteria"
if [[ ! -f "$HY2_DIR/portal.py" || ! -f "$HY2_DIR/client_meta.json" ]]; then
    logger -t hy2-cert-selfheal "缺少 portal.py 或 client_meta.json，跳过"
    exit 0
fi
if ! grep -q 'def selfheal(' "$HY2_DIR/portal.py" 2>/dev/null; then
    logger -t hy2-cert-selfheal "当前 portal.py 不支持 selfheal 子命令（版本过旧），请升级门户"
    exit 0
fi
_out="$(python3 "$HY2_DIR/portal.py" selfheal "$HY2_DIR/client_meta.json" 2>&1)"
if [[ -n "$_out" ]]; then
    printf '%s\n' "$_out" | logger -t hy2-cert-selfheal
fi
unset _out
exit 0
EOCS
    chmod 755 /usr/local/bin/hy2-cert-selfheal.sh

    cat > /etc/systemd/system/hy2-cert-selfheal.service <<'EOCU'
[Unit]
Description=Hysteria 2 certificate trust-model self-heal
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/hy2-cert-selfheal.sh
EOCU

    cat > /etc/systemd/system/hy2-cert-selfheal.timer <<'EOCT'
[Unit]
Description=Run certificate self-heal every 30 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=30min
Unit=hy2-cert-selfheal.service

[Install]
WantedBy=timers.target
EOCT

    # path 单元：监听证书目录（config.yaml 里 tls.cert 所在目录）。
    # 用目录而非单文件：Caddy/acme.sh 续期是「写新文件再 rename 覆盖」，
    # 单文件 PathChanged 在 rename 场景下可能因 inode 变化而漏触发，盯目录更稳。
    local cert_watch_dir="$HY2_CERT_DIR"
    local _cc
    _cc="$(awk '/^tls:/{f=1;next} f&&/^[ \t]+cert:/{sub(/^[ \t]*cert:[ \t]*/,"");gsub(/["\x27]/,"");print;exit} f&&/^[^ \t]/{f=0}' "$HY2_CONFIG" 2>/dev/null || true)"
    if [[ -n "$_cc" ]]; then
        if [[ "$_cc" != /* ]]; then
            cert_watch_dir="$(dirname "${HY2_DIR}/${_cc}")"
        else
            cert_watch_dir="$(dirname "$_cc")"
        fi
    fi
    [[ -d "$cert_watch_dir" ]] || cert_watch_dir="$HY2_CERT_DIR"

    cat > /etc/systemd/system/hy2-cert-selfheal.path <<EOCP
[Unit]
Description=Watch certificate dir and self-heal trust model on change

[Path]
PathChanged=${cert_watch_dir}
Unit=hy2-cert-selfheal.service

[Install]
WantedBy=paths.target
EOCP

    systemctl daemon-reload
    systemctl enable --now hy2-cert-selfheal.timer >/dev/null 2>&1 || true
    systemctl enable --now hy2-cert-selfheal.path  >/dev/null 2>&1 || true
    log_info "证书一致性自愈已启用（每 30 分钟 + 证书目录变更即时触发）。"
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
    # 顺序：先解析确定版本 → 取该版本官方 checksums.txt → 下载 → 校验 → 才安装。
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
        TMP_DIR="$(mktemp -d)"
        if ! WGCF_SUM="$(hy2_expected_sha256 \
                "https://github.com/ViRb3/wgcf/releases/download/v${WGCF_VER}/checksums.txt" \
                "$WGCF_DL" "$TMP_DIR")"; then
            rm -rf "$TMP_DIR"
            log_err "取不到 wgcf v${WGCF_VER} 的官方 checksums.txt（或其中没有 ${WGCF_DL}），已放弃安装。"
            return 1
        fi
        if ! curl -fsSL --max-time 120 -o "${TMP_DIR}/${WGCF_DL}" "$WGCF_URL"; then
            rm -rf "$TMP_DIR"
            log_err "wgcf 下载失败 ($WGCF_URL), 请检查网络或版本号"
            return 1
        fi
        if ! hy2_verify_sha256 "${TMP_DIR}/${WGCF_DL}" "$WGCF_SUM"; then
            rm -rf "$TMP_DIR"
            log_err "wgcf 校验失败：SHA256 与官方 checksums.txt 不一致，已放弃安装。"
            return 1
        fi
        if ! install -m 755 "${TMP_DIR}/${WGCF_DL}" "${WGCF_BIN}.new"; then
            rm -rf "$TMP_DIR"
            log_err "安装 wgcf 失败，现有文件未改动。"
            return 1
        fi
        rm -rf "$TMP_DIR"
        mv -f "${WGCF_BIN}.new" "$WGCF_BIN"
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
        # ⚠️ 旧实现回退只改了 WP_VER，拼 URL 却仍用空的 WP_TAG，于是回退分支拼出
        #    `.../download//wireproxy_...`（404），回退形同虚设。现在统一用 WP_TAG。
        if [[ -z "$WP_TAG" || "$WP_TAG" == "null" ]]; then
            WP_TAG="v1.1.3"
        fi
        WP_ASSET="wireproxy_linux_${WP_ARCH}.tar.gz"
        WP_URL="https://github.com/whyvl/wireproxy/releases/download/${WP_TAG}/${WP_ASSET}"
        log_info "目标 wireproxy 版本: ${WP_TAG}"
        TMP_DIR="$(mktemp -d)"
        if ! WP_SUM="$(hy2_expected_sha256 \
                "https://github.com/whyvl/wireproxy/releases/download/${WP_TAG}/checksums.txt" \
                "$WP_ASSET" "$TMP_DIR")"; then
            rm -rf "$TMP_DIR"
            log_err "取不到 wireproxy ${WP_TAG} 的官方 checksums.txt（或其中没有 ${WP_ASSET}），已放弃安装。"
            return 1
        fi
        if ! curl -fsSL --max-time 120 -o "${TMP_DIR}/${WP_ASSET}" "$WP_URL"; then
            rm -rf "$TMP_DIR"
            log_err "wireproxy 下载失败 ($WP_URL)"
            return 1
        fi
        if ! hy2_verify_sha256 "${TMP_DIR}/${WP_ASSET}" "$WP_SUM"; then
            rm -rf "$TMP_DIR"
            log_err "wireproxy 校验失败：SHA256 与官方 checksums.txt 不一致，已放弃安装。"
            return 1
        fi
        if ! hy2_tar_listing_safe "${TMP_DIR}/${WP_ASSET}"; then
            rm -rf "$TMP_DIR"
            log_err "wireproxy 包内含不安全路径成员，已放弃安装。"
            return 1
        fi
        WP_MEMBER="$(hy2_tar_find_member "${TMP_DIR}/${WP_ASSET}" wireproxy)" || WP_MEMBER=""
        if [[ -z "$WP_MEMBER" ]]; then
            rm -rf "$TMP_DIR"
            log_err "wireproxy 包内没有 wireproxy 成员，已放弃安装。"
            return 1
        fi
        TMP_EXTRACT="$(mktemp -d)"
        # 只解出那一个确定成员，不再"取包内第一个可执行文件"当 root 二进制。
        if ! tar -xzf "${TMP_DIR}/${WP_ASSET}" -C "$TMP_EXTRACT" "$WP_MEMBER" 2>/dev/null; then
            rm -rf "$TMP_DIR" "$TMP_EXTRACT"
            log_err "wireproxy 解压失败"
            return 1
        fi
        if ! install -m 755 "${TMP_EXTRACT}/${WP_MEMBER}" "${WP_BIN}.new"; then
            rm -rf "$TMP_DIR" "$TMP_EXTRACT"
            log_err "安装 wireproxy 失败，现有文件未改动。"
            return 1
        fi
        rm -rf "$TMP_DIR" "$TMP_EXTRACT"
        mv -f "${WP_BIN}.new" "$WP_BIN"
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
# 两个探测点都不通才重启：只看 ipify 的话，ipify 自己故障会让 wireproxy 每 3 分钟被白白重启一次。
probe() { curl --proxy socks5h://${WARP_SOCKS_ADDR} --silent --fail --max-time 6 "\$1" >/dev/null 2>&1; }
if ! probe https://api4.ipify.org && ! probe https://www.cloudflare.com/cdn-cgi/trace; then
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
    # ⚠️ 同样要 `|| GOST_LATEST=""`：api.github.com 不可达时 curl 失败会让
    # set -e 直接终止，下面的兜底版本号永远用不上（与 install_binary 同一个坑）。
    GOST_LATEST=$(curl -s --max-time 15 https://api.github.com/repos/go-gost/gost/releases/latest | jq -r '.tag_name // empty') || GOST_LATEST=""
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
    GOST_ASSET_NAME="gost_${GOST_VER}_${GOST_ASSET}.tar.gz"
    log_info "目标版本: ${GOST_LATEST} (${GOST_ASSET})"
    log_step "下载并解压 gost 二进制..."
    TMP_DIR=$(mktemp -d)
    # 先从该版本的官方 checksums.txt 取摘要，再下载校验；取不到就不装。
    if ! GOST_SUM="$(hy2_expected_sha256 \
            "https://github.com/go-gost/gost/releases/download/${GOST_LATEST}/checksums.txt" \
            "$GOST_ASSET_NAME" "$TMP_DIR")"; then
        rm -rf "$TMP_DIR"
        log_err "取不到 gost ${GOST_LATEST} 的官方 checksums.txt（或其中没有 ${GOST_ASSET_NAME}），已放弃安装。"
        return 1
    fi
    if ! curl -fL --progress-bar --max-time 300 -o "$TMP_DIR/$GOST_ASSET_NAME" "$DOWNLOAD_URL"; then
        rm -rf "$TMP_DIR"
        log_err "gost 下载失败，请检查网络连接。"
        return 1
    fi
    if ! hy2_verify_sha256 "$TMP_DIR/$GOST_ASSET_NAME" "$GOST_SUM"; then
        rm -rf "$TMP_DIR"
        log_err "gost 校验失败：SHA256 与官方 checksums.txt 不一致，已放弃安装。"
        return 1
    fi
    if ! hy2_tar_listing_safe "$TMP_DIR/$GOST_ASSET_NAME"; then
        rm -rf "$TMP_DIR"
        log_err "gost 包内含不安全路径成员，已放弃安装。"
        return 1
    fi
    GOST_MEMBER="$(hy2_tar_find_member "$TMP_DIR/$GOST_ASSET_NAME" gost)" || GOST_MEMBER=""
    if [[ -z "$GOST_MEMBER" ]]; then
        rm -rf "$TMP_DIR"
        log_err "gost 包内没有 gost 成员，已放弃安装。"
        return 1
    fi
    if ! tar -xzf "$TMP_DIR/$GOST_ASSET_NAME" -C "$TMP_DIR" "$GOST_MEMBER" 2>/dev/null; then
        rm -rf "$TMP_DIR"
        log_err "gost 解压失败。"
        return 1
    fi
    if ! install -m 755 "$TMP_DIR/$GOST_MEMBER" "${GOST_BIN}.new"; then
        rm -rf "$TMP_DIR"
        log_err "安装 gost 失败，现有文件未改动。"
        return 1
    fi
    rm -rf "$TMP_DIR"
    mv -f "${GOST_BIN}.new" "$GOST_BIN"
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

    # 落盘启动自检脚本 (unit 的 ExecStartPost 会调用它)
    # ⚠️ 内容必须与 portal.py 的 GOST_SELFCHECK_SCRIPT 常量一致
    # (tests/test_portal_gost_reload.py 有断言钉死).
    mkdir -p /usr/local/lib
    cat > /usr/local/lib/hy2-gost-selfcheck <<'PYSELFCHECK'
#!/usr/bin/env python3
"""确认 /etc/hysteria/gost.yml 里声明监听的服务端口都真的在监听.

由 gost.service 的 ExecStartPost 调用. 无代理配置时返回 0 (合法状态).
任何端口 5 秒内未监听 -> 返回 1, 使 systemd 判定本次启动失败并重试,
而不是留下一个 "active 但无监听" 的假健康状态.
"""
import json
import socket
import sys
import time

CFG = '/etc/hysteria/gost.yml'


def listening(port):
    for fam, addr in ((socket.AF_INET, '127.0.0.1'), (socket.AF_INET6, '::1')):
        s = socket.socket(fam, socket.SOCK_STREAM)
        try:
            s.settimeout(1)
            if s.connect_ex((addr, port)) == 0:
                return True
        except OSError:
            pass
        finally:
            s.close()
    return False


def main():
    try:
        with open(CFG, encoding='utf-8') as fh:
            svc = json.load(fh).get('services') or []
    except Exception as exc:                     # 配置读不了 -> 交给 gost 自己报错
        print('selfcheck: 无法读取配置: %s' % exc, file=sys.stderr)
        return 0

    ports = []
    for s in svc:
        addr = str(s.get('addr') or '')
        tail = addr.rsplit(':', 1)[-1]
        if tail.isdigit():
            ports.append(int(tail))
    ports = sorted(set(ports))
    if not ports:
        return 0                                  # 尚无代理, 合法

    deadline = time.time() + 5
    while time.time() < deadline:
        missing = [p for p in ports if not listening(p)]
        if not missing:
            return 0
        time.sleep(0.5)
    print('selfcheck: 端口未监听: %s' % missing, file=sys.stderr)
    return 1


if __name__ == '__main__':
    sys.exit(main())
PYSELFCHECK
    chmod 755 /usr/local/lib/hy2-gost-selfcheck

    # 创建 systemd 守护服务
    # ⚠️ 这份内容必须与 portal.py 的 GOST_UNIT_CONTENT 常量**完全一致**
    # （门户"一键安装 gost"会覆写同一个 unit）。曾经两处不一致 —— install.sh 有
    # ExecReload 而 portal.py 没有 —— 导致门户创建的 gost 无法被 reload，
    # 新加代理的端口一直不监听。tests/test_portal_gost_reload.py 有断言钉死一致性。
    #
    # 三个要点：
    #   ExecReload  —— gost v3 收到 SIGHUP 会重读配置（实测有效）
    #   -R 30s      —— gost 官方周期自动重载，作为兜底（实测 v3.3.0 有效）
    #   ExecStartPost —— 跑自检脚本确认端口真的监听了，把"active 但无监听"
    #                    的静默故障变成启动失败，交给 systemd 重试
    cat > /etc/systemd/system/gost.service <<EOF
[Unit]
Description=GOST Proxy Service (SOCKS5/HTTP/HTTPS inbound)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${GOST_BIN} -C ${GOST_CONFIG} -R 30s
# 平滑重载: gost v3 收到 SIGHUP 会重新读取 -C 指定的配置文件
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=3
LimitNOFILE=65535
# 启动自检: 确认 gost.yml 里声明的端口都真的监听了, 否则视为启动失败
ExecStartPost=/usr/local/lib/hy2-gost-selfcheck

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable gost >/dev/null 2>&1
    systemctl restart gost
    # 核实服务真的在跑（不谎报成功）
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

# 依次尝试多个源获取 awgctl.sh 到指定文件；全部失败返回 1。
#
# ⚠️ 为什么不能只用 raw.githubusercontent.com：
#   实测它 push 之后数分钟仍返回旧内容，而且【不把查询串算进缓存键】——
#   加 ?cb=<时间戳> 也没用（用三个不同的 cb 值请求，返回的是同一份旧文件）。
#   实测（同一时刻、同一台机器）：
#     api.github.com + Accept: application/vnd.github.raw  → 最新内容
#     cdn.jsdelivr.net/gh/<repo>@main/...                  → 最新内容
#     raw.githubusercontent.com/...                        → 旧内容（滞后）
#   所以顺序是：API（权威、始终最新，未认证限 60 次/小时/IP）
#   → jsDelivr（无速率限制）→ raw（最后兜底，接受可能滞后）。
#
# 🔴 2026-10-27：先把 main 解析成 40 位 commit，再取三源，并把内容与
#    GitHub API 给出的 git blob 身份（sha1("blob <len>\0"+content)）比对。
#    旧实现直接用 `?ref=main` / `@main` 且只 grep 一个字符串标记，
#    main 一旦被推入恶意提交就会把 hy2-awgctl 刷成攻击者版本并以 root 执行。
#    注意 blob sha 与「文件 sha1」不同，必须带 blob 头才算得对。
awg_fetch_ctl() {
    local out="$1"
    local ref expected blob tmp

    # 只解析一次，三个源都读同一快照；解析失败就放弃，绝不回退到浮动 main。
    ref="$(curl -fsSL --max-time 15 "https://api.github.com/repos/${AWG_REPO}/commits/main" 2>/dev/null |
        python3 -c 'import json,re,sys; s=json.load(sys.stdin).get("sha",""); assert re.fullmatch("[0-9a-f]{40}", s); print(s)' 2>/dev/null)" || ref=""
    if [[ ! "$ref" =~ ^[0-9a-f]{40}$ ]]; then
        log_err "无法把 main 固定到具体 commit，已放弃获取 awgctl.sh（不回退到浮动 main）"
        return 1
    fi

    # 预期 blob 身份：走 contents API 的 JSON（只回一个 sha，不用下载内容）。
    expected="$(curl -fsSL --max-time 15 -H "Accept: application/vnd.github+json" \
        "https://api.github.com/repos/${AWG_REPO}/contents/awgctl.sh?ref=${ref}" 2>/dev/null |
        python3 -c 'import json,re,sys; s=json.load(sys.stdin).get("sha",""); assert re.fullmatch("[0-9a-f]{40}", s); print(s)' 2>/dev/null)" || expected=""
    if [[ ! "$expected" =~ ^[0-9a-f]{40}$ ]]; then
        log_err "无法取得 awgctl.sh@${ref} 的预期 blob 身份，已放弃获取（不做无身份比对的下载）"
        return 1
    fi

    tmp="$(mktemp)"
    local -a sources=(
        "https://api.github.com/repos/${AWG_REPO}/contents/awgctl.sh?ref=${ref}"
        "https://cdn.jsdelivr.net/gh/${AWG_REPO}@${ref}/awgctl.sh"
        "https://raw.githubusercontent.com/${AWG_REPO}/${ref}/awgctl.sh"
    )
    local url got
    for url in "${sources[@]}"; do
        : > "$tmp"
        if ! curl -fsSL --max-time 30 -H "Accept: application/vnd.github.raw" "$url" -o "$tmp" 2>/dev/null; then
            continue
        fi
        [[ -s "$tmp" ]] && grep -q 'hy2-awgctl' "$tmp" 2>/dev/null || continue
        got="$(hy2_git_blob_sha "$tmp")" || got=""
        if [[ "$got" != "$expected" ]]; then
            log_warn "awgctl.sh 来源 ${url%%\?*} 的内容与 ${ref} 的 blob 身份不一致，换下一个源"
            continue
        fi
        if ! install -m 0755 "$tmp" "$out"; then
            continue
        fi
        rm -f "$tmp"
        return 0
    done
    rm -f "$tmp"
    log_err "awgctl.sh 三个源均未取得与 ${ref} 一致的受信内容"
    return 1
}

# 确保 hy2-awgctl 就位。优先用与 install.sh 同目录的 awgctl.sh（本地克隆场景），
# 否则从仓库拉取。注意本脚本常以 `bash <(curl ...)` 方式运行，此时 BASH_SOURCE
# 指向 /dev/fd/NN，不是真实文件，所以必须做存在性判断。
#
# 传 --refresh 时即使已存在也重新获取，且仅在内容确实变化时才替换。
# 存在的意义：hy2-awgctl 本身也需要能更新，否则已经装过 AWG 的机器会把引擎
# 永久冻结在首次安装的版本上（awg_ensure_ctl 原本一看到文件存在就直接返回）。
#
# 拉取走 awg_fetch_ctl 的多源回退，原因见该函数的注释。
awg_ensure_ctl() {
    local force="no"
    if [[ "${1:-}" == "--refresh" ]]; then
        force="yes"
    fi

    if [[ "$force" != "yes" && -x "$AWG_CTL_BIN" ]]; then
        return 0
    fi

    local src="" dir="" tmp=""
    if [[ -n "${BASH_SOURCE[0]:-}" && -f "${BASH_SOURCE[0]}" ]]; then
        dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)" || dir=""
        if [[ -n "$dir" && -f "${dir}/awgctl.sh" ]]; then
            src="${dir}/awgctl.sh"
        fi
    fi

    if [[ -z "$src" ]]; then
        tmp="$(mktemp)"
        if awg_fetch_ctl "$tmp"; then
            src="$tmp"
        else
            rm -f "$tmp"
            if [[ "$force" == "yes" && -x "$AWG_CTL_BIN" ]]; then
                log_warn "刷新 awgctl.sh 失败（网络问题？），继续沿用现有版本。"
                return 0
            fi
            log_err "无法获取 awgctl.sh（三个源均失败：GitHub API / jsDelivr / raw）"
            return 1
        fi
    fi

    # 内容一致就不动它，避免无意义地改写文件与刷新时间戳
    if [[ "$force" == "yes" && -x "$AWG_CTL_BIN" ]]; then
        local new_sum old_sum
        new_sum="$(sha256sum < "$src" 2>/dev/null | awk '{print $1}')"
        old_sum="$(sha256sum < "$AWG_CTL_BIN" 2>/dev/null | awk '{print $1}')"
        if [[ -n "$new_sum" && "$new_sum" == "$old_sum" ]]; then
            log_info "AmneziaWG 控制工具已是最新，无需更新。"
            if [[ -n "$tmp" ]]; then
                rm -f "$tmp"
            fi
            return 0
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

    if [[ "$force" == "yes" ]]; then
        log_info "已更新 AmneziaWG 控制工具: ${AWG_CTL_BIN}"
    else
        log_info "已安装 AmneziaWG 控制工具: ${AWG_CTL_BIN}"
    fi
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
    # 用 --refresh：安装/重装时本就该用当前版本的引擎，而不是机器上可能残留的旧版
    if ! awg_ensure_ctl --refresh; then
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
    # 先把控制工具自身刷新到最新，否则引擎会被永久冻结在首次安装的版本上
    # （awg_ensure_ctl 默认看到文件已存在就直接返回）
    awg_ensure_ctl --refresh || return 1
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

require_installed() {
    if [[ ! -f "$HY2_BIN" || ! -f "$HY2_CONFIG" ]]; then
        log_err "Hysteria 2 尚未安装，请先选择「1. 全新安装 Hysteria 2」。"
        return 1
    fi
}

# Teyir 控制台的整机流量超额停用是否生效中（门户在 portal.json 里记录）。
traffic_suspended() {
    [[ "$(jq -r '.traffic_suspend.suspended // false' "$HY2_DIR/portal.json" 2>/dev/null)" == "true" ]]
}

refuse_if_suspended() {
    if traffic_suspended; then
        log_warn "本节点正因流量超额被 Teyir 控制台停用，手动拉起服务会绕过流量限额。"
        log_warn "请在控制台调整限额或等新计费周期，节点会自动恢复。"
        return 1
    fi
}

start_service() {
    require_installed || return 1
    refuse_if_suspended || return 1
    log_step "启动 Hysteria 2 服务..."
    systemctl start hysteria-server
    log_info "已启动。"
}

stop_service() {
    require_installed || return 1
    log_step "停止 Hysteria 2 服务..."
    systemctl stop hysteria-server
    log_info "已停止。"
}

restart_service() {
    require_installed || return 1
    refuse_if_suspended || return 1
    log_step "重启 Hysteria 2 服务..."
    systemctl restart hysteria-server || return 1
    log_info "已重启。"
}

restart_portal() {
    require_installed || return 1
    log_step "重启门户（私密信息页 / Hy2 鉴权后端 / 控制台 API）..."
    systemctl restart hysteria-portal
    log_info "已重启。"
}

# 接入 Teyir 控制台要填的四项，和网页上「接入 TEYIR 控制台」卡片里的一致。
show_teyir_access() {
    require_installed || return 1
    local access="$HY2_DIR/portal-access.json"
    [[ -f "$access" ]] || { log_err "未找到门户凭据文件 ${access}。"; return 1; }
    echo -e "\n${CYAN}------------ 接入 Teyir 控制台 ------------${PLAIN}"
    echo -e "门户地址 url     : ${GREEN}$(jq -r '.url // ""' "$access")${PLAIN}"
    echo -e "门户用户名       : ${GREEN}$(jq -r '.username // ""' "$access")${PLAIN}"
    echo -e "门户密码         : ${GREEN}$(jq -r '.password // ""' "$access")${PLAIN}"
    local key; key="$(jq -r '.api_key // ""' "$access")"
    if [[ -n "$key" ]]; then
        echo -e "API Key (Bearer) : ${GREEN}${key}${PLAIN}"
    else
        echo -e "API Key (Bearer) : ${YELLOW}（未找到 API Key，请重新执行第 1 项或第 4 项安装）${PLAIN}"
    fi
    echo -e "${CYAN}--------------------------------------------${PLAIN}"
    echo -e "${YELLOW}以上是节点的管理凭据，请勿外传。${PLAIN}"
}

view_logs() {
    require_installed || return 1
    echo -e "${CYAN}正在查看 Hysteria 2 实时日志 (Ctrl+C 退出日志并返回菜单)...${PLAIN}"
    journalctl -u hysteria-server -f -n 50
}

uninstall_all() {
    # ⚠️ 先问主确认，再问 AWG（2026-10-09 修）：
    #   原顺序是先问「是否一并卸载 AmneziaWG」。于是用户对第一个破坏性问题
    #   回答 n、第二个也回答 n，退出 —— 却已经对一个他根本不想动的组件
    #   做了表态；而且两个 read 都没有 || true，EOF 会中断在提问中间。
    #   现在：主确认在前，只有确实要卸载时才追问 AWG。
    local awg_confirm="N"
    local confirm="N"
    read -rp "确定要彻底卸载 Hysteria 2 服务及所有配置文件吗？[y/N]: " confirm || true
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        log_info "已取消卸载。"
        return 0
    fi
    if [[ -f "$AWG_SERVICE" || -f "$AWG_CONFIG" ]]; then
        echo ""
        log_warn "检测到本机还安装了 AmneziaWG。"
        log_warn "回答 y 会一并删除 AmneziaWG 引擎与**全部客户端配置**（不可恢复）。"
        read -rp "是否也要一并卸载 AmneziaWG？[y/N]: " awg_confirm || true
    fi

    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        log_step "正在停止并删除系统服务..."
        systemctl stop hysteria-server 2>/dev/null || true
        systemctl disable hysteria-server 2>/dev/null || true
        systemctl disable --now hysteria-portal 2>/dev/null || true
        systemctl disable --now gost 2>/dev/null || true
        # Reality 用的 xray 由门户安装（/etc/hysteria/xray.json），也要一起停掉，
        # 否则配置目录删了它还在跑，Reality 用户要到重启后才断。
        systemctl disable --now xray 2>/dev/null || true
        rm -f /etc/systemd/system/xray.service /usr/local/bin/xray
        # AnyTLS / TUIC 的 sing-box 同样由门户安装，配置在 /etc/hysteria/{anytls,tuic}.json。
        local sb_unit
        for sb_unit in hy2-anytls hy2-tuic; do
            if [[ -f /etc/systemd/system/${sb_unit}.service ]]; then
                systemctl disable --now "$sb_unit" 2>/dev/null || true
                rm -f "/etc/systemd/system/${sb_unit}.service"
            fi
        done
        rm -f /usr/local/bin/sing-box
        # BUGFIX: 卸载时同时清理 WARP 相关服务与配置
        systemctl disable --now wireproxy 2>/dev/null || true
        systemctl disable --now hy2-warp-watchdog.timer 2>/dev/null || true
        systemctl disable --now hy2-warp-watchdog.service 2>/dev/null || true
        # 证书自愈定时/事件单元
        systemctl disable --now hy2-cert-selfheal.timer 2>/dev/null || true
        systemctl disable --now hy2-cert-selfheal.path 2>/dev/null || true
        systemctl disable --now hy2-cert-selfheal.service 2>/dev/null || true
        rm -f /etc/systemd/system/hysteria-portal.service
        rm -f /etc/systemd/system/gost.service
        rm -f /etc/systemd/system/wireproxy.service
        rm -f /etc/systemd/system/hy2-warp-watchdog.service
        rm -f /etc/systemd/system/hy2-warp-watchdog.timer
        rm -f /etc/systemd/system/hy2-cert-selfheal.service
        rm -f /etc/systemd/system/hy2-cert-selfheal.timer
        rm -f /etc/systemd/system/hy2-cert-selfheal.path
        rm -f /usr/local/bin/hy2-cert-selfheal.sh
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
        # 只删 wgcf / wireproxy 自己的文件：/etc/wireguard 是系统 WireGuard 的公共目录，
        # 机主自己的 wg0.conf 之类不能被一并删掉。目录空了才移除。
        rm -f /etc/wireguard/wgcf-account.toml /etc/wireguard/wgcf.conf \
              /etc/wireguard/wgcf-profile.conf /etc/wireguard/wp.conf
        rmdir /etc/wireguard 2>/dev/null || true

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
# 菜单里每个动作都放进子 shell 里跑（子 shell 内重新打开 set -e，出错照样立刻停）。
# 原来动作直接跑在菜单所在的 shell 里，set -e 让任何一步失败都把整个脚本带走
# （没装时选 3、服务启动失败、WARP/GOST 下载失败、拿不到公网 IP……），
# 用户直接被甩回 shell。现在失败只结束这一次操作，提示后回到菜单。
run_action() {
    local rc=0
    set +e
    ( set -e; "$@" )
    rc=$?
    set -e
    if (( rc == 130 )); then
        log_warn "操作已中断，已返回主菜单。已完成的步骤不会回滚。"
    elif (( rc != 0 )); then
        log_err "操作未完成（退出码 ${rc}），请查看上面的报错。已返回主菜单。"
    fi
    return 0
}

# 已装机时重装 / 改配置：默认沿用现有门户（登录凭据、API Key、订阅地址、全部用户），
# 否则 Teyir 控制台保存的凭据全部失效、控制台开的用户与代理服务全部丢失。
ask_preserve_portal() {
    PRESERVE_PORTAL=0
    [[ -f "$HY2_DIR/portal.json" && -f "$HY2_DIR/portal-access.json" ]] || return 0
    echo
    echo -e "${YELLOW}是否沿用现有门户？${PLAIN}（登录凭据、API Key、订阅地址、全部用户与代理服务保持不变）"
    echo -e "  已接入 Teyir 控制台或已给客户发过订阅的节点，请务必选 Y。"
    local keep=""
    read -rp "沿用现有门户？[Y/n]: " keep || true
    if [[ "$keep" =~ ^[Nn]$ ]]; then
        log_warn "将重建门户：门户凭据、API Key、订阅地址都会换新，除机主外的用户会被清空。"
    else
        PRESERVE_PORTAL=1
    fi
}

flow_install() {
    check_root
    check_arch
    # 已装机再按「1」会重生成配置、可能换掉端口/密码/证书，
    # 已发放的客户端配置随之失效 —— 必须让用户确认一次。
    if [[ -f "$HY2_CONFIG" ]]; then
        echo
        log_warn "检测到本机已安装 Hysteria 2。"
        log_warn "继续将重新生成服务端配置；若中途更换了端口/密码/证书，"
        log_warn "已发放的客户端配置会失效，需要重新导出。"
        local _reinstall_hint=""
        read -rp "确定要重新安装吗？[y/N]: " _reinstall_hint || true
        if [[ ! "$_reinstall_hint" =~ ^[Yy]$ ]]; then
            log_info "已取消。如需修改端口/密码/证书，请用菜单第 4 项「重新修改配置」。"
            return 0
        fi
        ask_preserve_portal
        backup_state_before_reconfigure
    fi
    install_dependencies
    get_public_ip
    install_binary
    setup_certificates
    setup_ports_and_obfs
    generate_server_config
    setup_system_firewall "$LISTEN_PORT" "$HOP_START" "$HOP_END"
    setup_systemd
    show_client_configs
}

flow_update_core() {
    check_root || return 1
    check_arch || return 1
    require_installed || return 1
    local rollback_file
    rollback_file="$(mktemp "${HY2_BIN}.rollback.XXXXXX")" || {
        log_err "创建核心备份失败，现有二进制未改动。"; return 1; }
    if ! cp -p "$HY2_BIN" "$rollback_file"; then
        rm -f "$rollback_file"
        log_err "备份核心失败，已放弃更新，现有二进制未改动。"
        return 1
    fi
    if ! install_binary; then
        rm -f "$rollback_file"
        return 1
    fi
    if traffic_suspended; then
        rm -f "$rollback_file"
        log_warn "核心已更新；节点正因流量超额被 Teyir 停用，暂不重启，恢复时会自动用上新核心。"
        return 0
    fi
    if ! restart_service; then
        if ! mv -f "$rollback_file" "$HY2_BIN"; then
            log_err "新版本启动失败，回滚失败；本次旧核心保留在 ${rollback_file}。"
            return 1
        fi
        # 再次检查 suspended，避免恢复旧核心时绕过刚生效的停用状态。
        if traffic_suspended; then
            log_err "新版本启动失败，已恢复本次旧核心；节点已停用，暂不重启。"
        elif ! restart_service; then
            log_err "已恢复本次旧核心，但旧版本重启仍失败，请检查服务日志。"
        else
            log_err "新版本启动失败，已回滚到本次旧版本。"
        fi
        return 1
    fi
    rm -f "$rollback_file"
}

flow_reconfigure() {
    check_root
    require_installed
    # 🔴 改配置前必须警告 + 备份（2026-10-09 修）：
    # 这条路径会整体重写 client_meta.json 并重建门户，原先一个字都没提示。
    echo
    log_warn "「重新修改配置」会重新生成服务端配置，请注意："
    log_warn "  · 已发放的客户端配置若端口/证书/域名变化，将需要重新导出"
    log_warn "  · 认证密码与混淆密钥默认保留，不会被随机换掉"
    log_warn "  · 节点通信 API Key 默认保持当前设置（商城版固定启用 Agent 模式）"
    local _reconf_hint=""
    read -rp "确定继续吗？[y/N]: " _reconf_hint || true
    if [[ ! "$_reconf_hint" =~ ^[Yy]$ ]]; then
        log_info "已取消。"
        return 0
    fi
    ask_preserve_portal
    backup_state_before_reconfigure
    install_dependencies
    get_public_ip
    setup_certificates
    setup_ports_and_obfs
    generate_server_config
    setup_system_firewall "$LISTEN_PORT" "$HOP_START" "$HOP_END"
    setup_systemd
    show_client_configs
}

flow_warp() { check_root; install_warp_local_proxy; }
flow_gost() { check_root; install_gost; }
flow_uninstall() { check_root; uninstall_all; }

flow_refresh_portal() {
    check_root
    require_installed
    refresh_portal
}

unit_state_text() {
    if systemctl is-active --quiet "$1" 2>/dev/null; then
        echo -e "${GREEN}运行中${PLAIN}"
    elif systemctl list-unit-files "$1.service" 2>/dev/null | grep -q "^$1.service"; then
        echo -e "${RED}已停止${PLAIN}"
    else
        echo -e "${YELLOW}未安装${PLAIN}"
    fi
}

show_menu_status() {
    local ver
    if [[ -f "$HY2_BIN" ]]; then
        ver="$($HY2_BIN version 2>/dev/null | awk '/^Version:/{print $2; exit}')"
        echo -e "核心状态: $(unit_state_text hysteria-server) | 版本: ${ver:-未知}"
    else
        echo -e "核心状态: ${YELLOW}未安装${PLAIN}"
        return 0
    fi
    # 门户同时是 Hy2 的鉴权后端：它停了，所有用户都连不上，必须一眼看到。
    # 本项目只有商城版；这里仍检测实际 auth 类型 —— 从旧单机版升级上来的机器
    # 在重新安装前仍是固定密码，状态栏要如实提示，而不是一律写「商城版」。
    local mode="商城版（Agent 模式）"
    if ! awk '/^auth:/{f=1;next} /^[^ ]/{f=0} f&&/type: *http/{found=1} END{exit !found}' "$HY2_CONFIG" 2>/dev/null; then
        mode="旧单机模式${YELLOW}（请用第 1 项重装为商城版）${PLAIN}"
    fi
    echo -e "门户状态: $(unit_state_text hysteria-portal) | 运行模式: ${mode}"
    if traffic_suspended; then
        echo -e "流量限额: ${RED}已因流量超额被 Teyir 停用${PLAIN}（控制台恢复前不要手动启动服务）"
    fi
    local extra=""
    # Xray 现在承载三种协议（Reality / VMess / VLESS Encryption），
    # 状态行不能只写 Reality，否则用户会以为只有 Reality 在跑。
    [[ -f /etc/systemd/system/xray.service ]] && extra+="Xray(Reality/VMess/VLESS-Enc): $(unit_state_text xray)  "
    [[ -f /etc/systemd/system/hy2-anytls.service ]] && extra+="AnyTLS: $(unit_state_text hy2-anytls)  "
    [[ -f /etc/systemd/system/hy2-tuic.service ]] && extra+="TUIC: $(unit_state_text hy2-tuic)  "
    [[ -f /usr/local/bin/gost ]] && extra+="GOST: $(unit_state_text gost)  "
    [[ -f /etc/systemd/system/wireproxy.service ]] && extra+="WARP: $(unit_state_text wireproxy)"
    [[ -n "$extra" ]] && echo -e "扩展服务: ${extra}"
    # AmneziaWG 状态：仅在本机装了 AWG 时显示
    if [[ -f "$AWG_CONFIG" ]]; then
        local _awg_port
        _awg_port="$(jq -r '.port // "?"' "$AWG_META_FILE" 2>/dev/null || echo '?')"
        if systemctl is-active --quiet amneziawg-server 2>/dev/null; then
            echo -e "AWG 状态 : ${GREEN}运行中${PLAIN} | 协议线: AWG $(awg_current_line).x | UDP ${_awg_port}"
        else
            echo -e "AWG 状态 : ${YELLOW}已安装但未运行${PLAIN} | 协议线: AWG $(awg_current_line).x"
        fi
    fi
}

menu() {
  while true; do
    clear 2>/dev/null || true
    echo -e "${CYAN}================================================================${PLAIN}"
    echo -e "${GREEN}       Hysteria 2 全功能生产级管理脚本 (${HY2_ARCH:-$(uname -m)})         ${PLAIN}"
    echo -e "${BLUE}       GitHub: https://github.com/yys9253462-gif/hysteria2-installer    ${PLAIN}"
    echo -e "${CYAN}================================================================${PLAIN}"
    show_menu_status
    echo -e "${CYAN}----------------------------------------------------------------${PLAIN}"
    if [[ -f "$HY2_CONFIG" ]]; then
        echo -e "  ${GREEN}1.${PLAIN} 重新安装 Hysteria 2 ${YELLOW}(会覆盖现有配置)${PLAIN}"
    else
        echo -e "  ${GREEN}1.${PLAIN} 全新安装 Hysteria 2"
    fi
    echo -e "  ${GREEN}2.${PLAIN} 更新 Hysteria 2 核心至最新版"
    echo -e "  ${GREEN}3.${PLAIN} 查看私密信息页地址和登录凭据"
    echo -e "  ${GREEN}4.${PLAIN} 重新修改配置 (端口/密码/证书/域名/混淆/API Key)"
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
    echo -e "${CYAN}----------------------------------------------------------------${PLAIN}"
    echo -e "  ${GREEN}14.${PLAIN} 刷新信息页与订阅 (不改任何配置)"
    echo -e "  ${GREEN}15.${PLAIN} 重启门户 (信息页 / 鉴权后端 / 控制台 API)"
    echo -e "  ${GREEN}16.${PLAIN} 显示接入 Teyir 控制台的信息"
    echo -e "  ${GREEN}0.${PLAIN} 退出脚本"
    echo -e "${CYAN}================================================================${PLAIN}"
    # read 失败 = stdin 到 EOF（管道输入用尽，或用户按了 Ctrl+D）。
    # 不显式处理的话会由 set -e 直接以退出码 1 静默结束，用户看不懂发生了什么。
    if ! read -rp "请输入选项 [0-16]: " choice; then
        echo
        log_info "输入已结束（EOF），退出脚本。"
        exit 0
    fi
    choice="$(echo "$choice" | tr -d '[:space:]')"

    case "$choice" in
        1)  run_action flow_install ;;
        2)  run_action flow_update_core ;;
        3)  run_action show_client_configs ;;
        4)  run_action flow_reconfigure ;;
        5)  run_action flow_warp ;;
        6)  run_action flow_gost ;;
        7)  run_action install_amneziawg ;;
        8)  run_action menu_amneziawg ;;
        9)  run_action start_service ;;
        10) run_action stop_service ;;
        11) run_action restart_service ;;
        12)
            # 菜单这一层先忽略 Ctrl+C（子进程恢复默认，所以 journalctl 照样能被 Ctrl+C 结束），
            # 否则全局中断处理会把整个脚本一起退出，回不到菜单。
            trap ':' INT
            run_action view_logs
            trap on_interrupt INT
            ;;
        13) run_action flow_uninstall ;;
        14) run_action flow_refresh_portal ;;
        15) run_action restart_portal ;;
        16) run_action show_teyir_access ;;
        0)  exit 0 ;;
        *)
            log_err "无效选项，请输入 0-16 之间的数字。"
            sleep 1
            continue
            ;;
    esac

    # 操作完成后回到主菜单，而不是把用户直接丢回 shell。
    echo
    # 同上：EOF 时给个明确交代，而不是静默退出码 1
    if ! read -rp "按回车返回主菜单（输入 q 退出脚本）: " _back; then
        echo
        log_info "输入已结束（EOF），退出脚本。"
        exit 0
    fi
    if [[ "$_back" =~ ^[Qq]$ ]]; then
        echo -e "${GREEN}已退出。${PLAIN}"
        exit 0
    fi
  done
}

# 命令行直通参数 (如: ./install.sh install / update / status / info)
check_root
check_arch

if [[ $# -gt 0 ]]; then
    case "$1" in
        install)
            # 免交互重装时默认沿用现有门户（凭据、API Key、订阅地址、用户），
            # 要彻底重建请显式传 HY2_PRESERVE_PORTAL=0。
            if [[ -f "$HY2_DIR/portal.json" ]]; then
                PRESERVE_PORTAL="${HY2_PRESERVE_PORTAL:-1}"
            fi
            install_dependencies
            get_public_ip || exit 1
            install_binary
            # 已装机且没有显式指定证书方式时，沿用现有证书 —— 绝不在
            # 「升级」里把正式证书降级成自签、或换掉端口（2026-10-29 修）。
            if [[ -z "${HY2_CERT_TYPE:-}" ]] && reuse_existing_cert_config; then
                HY2_CERT_REUSE=1
            fi
            setup_certificates
            setup_ports_and_obfs
            generate_server_config
            setup_system_firewall "$LISTEN_PORT" "$HOP_START" "$HOP_END"
            setup_systemd
            show_client_configs
            ;;
        update)
            require_installed || exit 1
            scrub_caddy_identity || true
            install_binary
            traffic_suspended || restart_service
            ;;
        info)
            show_client_configs
            ;;
        refresh-page)
            scrub_caddy_identity || true
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
            awg_ensure_ctl --refresh || exit 1
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
