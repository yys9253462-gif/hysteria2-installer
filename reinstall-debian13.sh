#!/bin/sh
# ===========================================================================
# reinstall-debian13.sh —— Alpine 环境下重装 Debian 13（含 GRUB 修复）
# ===========================================================================
#
# 适用场景
#   系统无法启动 / GRUB 损坏 / Debian 无法进入，需要从 Alpine 救援环境
#   里把机器重装成 Debian 13。
#
# 工作原理
#   本脚本**借道** InstallNET（leitbogioro/Tools）完成实际重装。InstallNET
#   在重装领域久经考验，兼容各种云厂商的救援环境。本脚本负责的是它前面和
#   后面那一圈「保障工作」：
#     · 联网与 DNS 就绪（Alpine 救援模式默认没网、没 DNS）
#     · 网络配置提取与校验（★ 防止重装后失联 —— 这是重装最常见的事故）
#     · 目标磁盘体检（容量够不够、是不是救援盘本身、有没有残留签名）
#     · 把网络参数以**静态 IP**形式传给 InstallNET
#     · 全程日志落盘，出问题可复查
#
# ---------------------------------------------------------------------------
# 用法（Alpine 里，root 身份）
# ---------------------------------------------------------------------------
#
#   # 最简单：一条命令，交互式回答两个问题（SSH 端口 / root 密码）
#   wget -qO- https://raw.githubusercontent.com/yys9253462-gif/hysteria2-installer/main/reinstall-debian13.sh | sh
#
#   # 或者先下载再跑（推荐，能看内容、能存起来复用）
#   wget -O rd13.sh https://raw.githubusercontent.com/yys9253462-gif/hysteria2-installer/main/reinstall-debian13.sh
#   sh rd13.sh
#
#   # 全自动（无人值守）
#   PASSWORD='YourPass123' PORT=22 sh rd13.sh --yes
#
#   # 只做术前体检，不真的重装（★ 强烈建议第一次先跑这个）
#   sh rd13.sh --check
#
#   # 指定磁盘 / 镜像 / 目标版本
#   sh rd13.sh --disk /dev/vda --mirror http://deb.debian.org/debian/ --release 13
#
#   # 强制在救援盘上重装（★ 极不推荐，会破坏救援环境，可能失联）
#   sh rd13.sh --disk /dev/vda --force-rescue-disk
#
# ---------------------------------------------------------------------------
# 可用环境变量（也可用同名命令行参数覆盖）
# ---------------------------------------------------------------------------
#   PORT        新系统 SSH 端口，默认 22
#   PASSWORD    新系统 root 密码，默认随机生成一个（★ 务必记下）
#               只能用字母、数字和 ._@%+=:,~^-，且不能以 - 开头
#   DISK        目标磁盘，默认自动探测
#   MIRROR      镜像站，默认 http://deb.debian.org/debian/
#   RELEASE     Debian 版本号，默认 13
#   SWAP_MB     swap 大小 MB，默认 512
#   NET_MODE    static（默认，推荐）或 dhcp
#   LOG         日志文件，默认 /root/reinstall-debian13.log
#   FORCE_RESCUE_DISK=1  允许在救援系统自己的盘上重装（★ 极危险）
#
# ---------------------------------------------------------------------------
# 警告
# ---------------------------------------------------------------------------
#   ★★★ 本脚本会【彻底清空目标磁盘】，不可恢复。★★★
#   执行前请确认机器上没有需要保留的数据。
#   第一次使用请务必先跑 --check。
# ===========================================================================

set -u

# ── 常量 ─────────────────────────────────────────────────────────────────
INSTALLNET_URL="https://raw.githubusercontent.com/leitbogioro/Tools/master/Linux_reinstall/InstallNET.sh"
# raw.githubusercontent.com 不通或被限速时退回 jsDelivr：同一份文件，同样校验 HTTPS 证书。
# 旧值与主源是同一个 raw 地址且从未被使用，主源一断就只能失败（2026-11-12 修）。
INSTALLNET_MIRROR="https://cdn.jsdelivr.net/gh/leitbogioro/Tools@master/Linux_reinstall/InstallNET.sh"
WORKDIR="$(pwd)"

# ── 默认值 ───────────────────────────────────────────────────────────────
PORT="${PORT:-22}"
PASSWORD="${PASSWORD:-}"
DISK="${DISK:-}"
MIRROR="${MIRROR:-http://deb.debian.org/debian/}"
RELEASE="${RELEASE:-13}"
SWAP_MB="${SWAP_MB:-512}"
NET_MODE="${NET_MODE:-static}"
LOG="${LOG:-/root/reinstall-debian13.log}"

ASSUME_YES=0
CHECK_ONLY=0
DRY_RUN=0
FORCE_RESCUE="${FORCE_RESCUE_DISK:-0}"
[ "$FORCE_RESCUE" = "1" ] || FORCE_RESCUE=0

# ── 输出 ─────────────────────────────────────────────────────────────────
# 颜色：只有在真终端上才开，管道/重定向时自动关掉，避免日志里一堆乱码
if [ -t 1 ]; then
    c_r=$(printf '\033[31m'); c_g=$(printf '\033[32m')
    c_y=$(printf '\033[33m'); c_c=$(printf '\033[36m'); c_0=$(printf '\033[0m')
else
    c_r=""; c_g=""; c_y=""; c_c=""; c_0=""
fi

info() { printf '%s[*]%s %s\n' "$c_c" "$c_0" "$*"; log_line "[*] $*"; }
ok()   { printf '%s[OK]%s %s\n' "$c_g" "$c_0" "$*"; log_line "[OK] $*"; }
warn() { printf '%s[!]%s %s\n' "$c_y" "$c_0" "$*"; log_line "[!] $*"; }
err()  { printf '%s[X]%s %s\n' "$c_r" "$c_0" "$*" >&2; log_line "[X] $*"; }
die()  {
    err "$*"
    [ -n "$LOG" ] && printf '\n%s详情日志：%s%s\n' "$c_y" "$LOG" "$c_0" >&2
    exit 1
}

log_line() {
    [ -n "$LOG" ] || return 0
    printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >> "$LOG" 2>/dev/null || true
}

# 日志文件可能初始化失败（比如 /root 不存在、或目录只读）。
# ★ 踩坑：曾经直接 `: > "$LOG"` 且不接错误处理，一旦失败就整个脚本崩在
#   这里，且错误信息一行 `No such file or directory` 让人摸不着头脑。
#   现在：显式判断目录 → 建目录 → 试写 → 不行就把 LOG 置空（降级为不打日志，
#   而不是让脚本挂掉）。
init_log() {
    [ -n "$LOG" ] || return 0
    _logdir="$(dirname "$LOG")"
    if [ ! -d "$_logdir" ]; then
        mkdir -p "$_logdir" 2>/dev/null || { LOG=""; return 0; }
    fi
    if ! : > "$LOG" 2>/dev/null; then
        LOG=""
        return 0
    fi
    return 0
}

# 交互读取：优先 /dev/tty
#
# ★ 为什么不用 bash 的 `< <(...)` 进程替换：
#   Alpine 默认是 ash，**不支持 bash 的进程替换**。而且本脚本要被管道喂给
#   sh 执行（`wget -qO- url | sh`），此时 stdin 是管道、不是终端 ——
#   所有交互都必须显式从 /dev/tty 读，否则会读到脚本内容自己。
ask() {
    _prompt="$1"; _default="$2"; _val=""
    if [ -r /dev/tty ]; then
        printf '%s' "$_prompt" >/dev/tty
        IFS= read -r _val </dev/tty || _val=""
    fi
    [ -n "$_val" ] || _val="$_default"
    printf '%s' "$_val"
}

# root 密码只收安全字符（2026-11-12 修）：InstallNET 生成哈希时写的是
# `openssl passwd -6 ''$tmpWORD''`，密码其实没加引号 —— 空格被拆成多个参数，
# * ? [ 按当前目录的文件名展开，- 开头被当成选项。磁盘清空后新系统的 root
# 密码就不是输入的那个，SSH 登不上。
PASSWORD_RULE="root 密码只能用字母、数字和 ._@%+=:,~^-，且不能以 - 开头"
password_ok() {
    case "$1" in
        ''|-*|*[!A-Za-z0-9._@%+=:,~^-]*) return 1 ;;
    esac
    return 0
}

# 打印开头整段注释：写死行号会把后面的常量与默认值代码一起打出来（2026-11-12 修）。
print_help() {
    for _f in "$0" rd13.sh; do
        [ -f "$_f" ] && awk 'NR == 1 { next } /^#/ { print; next } { exit }' "$_f" && return 0
    done
    return 1
}

# ── 参数解析 ─────────────────────────────────────────────────────────────
while [ $# -gt 0 ]; do
    case "$1" in
        --yes|-y)      ASSUME_YES=1; shift ;;
        --check|--dry-run) CHECK_ONLY=1; shift ;;
        --port)        PORT="${2:-}";     shift 2 ;;
        --pwd|--password) PASSWORD="${2:-}"; shift 2 ;;
        --disk)        DISK="${2:-}";     shift 2 ;;
        --mirror)      MIRROR="${2:-}";   shift 2 ;;
        --release)     RELEASE="${2:-}";  shift 2 ;;
        --swap)        SWAP_MB="${2:-}";  shift 2 ;;
        --net)         NET_MODE="${2:-}"; shift 2 ;;
        --force-rescue-disk) FORCE_RESCUE=1; shift ;;
        -h|--help)     print_help; exit 0 ;;
        *) die "未知参数：$1（用 --help 看用法）" ;;
    esac
done

# ── 参数合法性校验（★ 放在最前面：参数错就立刻报，不用等跑一半）──────
case "$NET_MODE" in
    static|dhcp) ;;
    *) die "NET_MODE 只能是 static 或 dhcp，当前是：$NET_MODE" ;;
esac

case "$PORT" in
    ''|*[!0-9]*) die "SSH 端口必须是数字，当前是：$PORT" ;;
esac
[ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] || die "SSH 端口超出范围（1-65535）：$PORT"

case "$SWAP_MB" in
    ''|*[!0-9]*) die "swap 大小必须是非负整数（MB），当前是：$SWAP_MB" ;;
esac

case "$RELEASE" in
    ''|*[!0-9]*) die "Debian 版本号必须是数字（如 12 / 13），当前是：$RELEASE" ;;
esac

[ -n "$MIRROR" ] || die "镜像地址不能为空"

if [ -n "$PASSWORD" ] && ! password_ok "$PASSWORD"; then
    die "${PASSWORD_RULE}：InstallNET 不加引号地使用密码，特殊字符会让装好的系统用这个密码登不上"
fi

# 初始化日志（失败会降级为不打日志，不会让脚本挂掉）
init_log
log_line "=== reinstall-debian13 开始 ==="
log_line "参数：PORT=$PORT DISK=$DISK MIRROR=$MIRROR RELEASE=$RELEASE SWAP_MB=$SWAP_MB NET_MODE=$NET_MODE CHECK_ONLY=$CHECK_ONLY"

printf '\n%s========================================%s\n' "$c_c" "$c_0"
printf '%s  Alpine → Debian %s 重装脚本%s\n' "$c_c" "$RELEASE" "$c_0"
printf '%s========================================%s\n\n' "$c_c" "$c_0"

# ── 第 1 步：环境检查 ────────────────────────────────────────────────────
info "第 1/6 步：检查运行环境"

[ "$(id -u)" = "0" ] || die "必须以 root 身份运行（当前 uid=$(id -u)）"

if [ -f /etc/alpine-release ]; then
    ok "当前系统：Alpine $(cat /etc/alpine-release)"
else
    warn "当前系统不是 Alpine（/etc/alpine-release 不存在）"
    warn "本脚本为 Alpine 救援环境设计，其他系统上行为可能不同"
    if [ "$ASSUME_YES" != "1" ] && [ "$CHECK_ONLY" != "1" ]; then
        _c="$(ask '仍要继续？（输入 yes 回车）：' 'no')"
        [ "$_c" = "yes" ] || die "已取消"
    fi
fi

# 内核架构（下面要确认 amd64）
ARCH="$(uname -m)"
ok "架构：$ARCH"
[ "$ARCH" = "x86_64" ] || warn "本脚本按 x86_64 验证过，当前是 $ARCH，请留意兼容性"

# ── 第 2 步：联网 + DNS ──────────────────────────────────────────────────
info "第 2/6 步：检查网络与 DNS"

# Alpine 救援模式网卡默认 DOWN，必须先启起来再 DHCP。
# ★ 实测踩坑：直接 udhcpc 会报 `udhcpc: sendto: Network is down`。
if [ -z "$(ip route show default 2>/dev/null)" ]; then
    warn "没有默认路由，尝试启用网卡并获取地址"

    # 确保必要工具在（救援模式可能只有 busybox）
    if ! command -v udhcpc >/dev/null 2>&1; then
        apk update >/dev/null 2>&1 || true
        apk add --no-cache busybox iproute2 >/dev/null 2>&1 || true
    fi

    for _ifc in /sys/class/net/*; do
        _ifc=${_ifc##*/}
        { [ "$_ifc" = "lo" ] || [ "$_ifc" = "*" ]; } && continue
        info "启用 $_ifc 并尝试 DHCP"
        ip link set "$_ifc" up 2>/dev/null || true
        udhcpc -i "$_ifc" -q -n -t 10 >/dev/null 2>&1 || true
        [ -n "$(ip route show default 2>/dev/null)" ] && break
    done
fi

if [ -z "$(ip route show default 2>/dev/null)" ]; then
    die "仍然没有默认路由，无法联网。请先在 VNC 里手动联网：
       ip link                       # 看网卡名和状态
       ip link set <网卡> up         # 若是 DOWN 先启用
       udhcpc -i <网卡> -q -n        # 再获取地址
       然后重新运行本脚本"
fi
ok "默认路由已就绪"

# DNS：必须先能解析，否则下载全失败。
# ★ 实测踩坑：VNC 粘贴长命令容易被截断，会把 nameserver 写进错的文件名。
#   所以这里一行一个 echo，短命令，不会截断。
if ! nslookup github.com >/dev/null 2>&1; then
    warn "DNS 解析失败，写入公共 DNS"
    echo "nameserver 223.5.5.5"   > /etc/resolv.conf
    echo "nameserver 100.100.2.136" >> /etc/resolv.conf
    echo "nameserver 8.8.8.8"    >> /etc/resolv.conf
    sleep 1
fi

if nslookup github.com >/dev/null 2>&1; then
    ok "DNS 解析正常"
else
    warn "DNS 仍解析不了，但继续尝试（有些环境 nslookup 不可用）"
fi

# 连通性：能下到 InstallNET 才算真的通（主源不通时再试镜像）
installnet_reachable() {
    for _u in "$INSTALLNET_URL" "$INSTALLNET_MIRROR"; do
        if wget -q --spider --timeout=15 "$_u" 2>/dev/null || \
           curl -fsI --max-time 15 "$_u" >/dev/null 2>&1; then
            return 0
        fi
    done
    return 1
}
info "测试到 GitHub 的连通性"
if installnet_reachable; then
    ok "可以访问安装脚本源"
else
    warn "GitHub 与 jsDelivr 镜像都访问失败。若在国内网络，可能需要代理"
fi

# ── 第 3 步：提取网络配置（★ 防失联关键）─────────────────────────────────
info "第 3/6 步：提取网络配置（用于重装后恢复，防止失联）"

MAIN_IFACE="$(ip route show default 2>/dev/null | awk '{print $5}' | head -n1 | tr -d '[:space:]')"
MAIN_IP="$(ip -4 addr show "$MAIN_IFACE" 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1 | tr -d '[:space:]')"
MAIN_GATE="$(ip route show default 2>/dev/null | awk '/default/{print $3}' | head -n1 | tr -d '[:space:]')"
CIDR_NUM="$(ip -4 addr show "$MAIN_IFACE" 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f2 | head -n1 | tr -d '[:space:]')"

if [ -z "$MAIN_IFACE" ] || [ -z "$MAIN_IP" ] || [ -z "$MAIN_GATE" ] || [ -z "$CIDR_NUM" ]; then
    die "网络配置提取失败：
       网卡=[$MAIN_IFACE] IP=[$MAIN_IP] 网关=[$MAIN_GATE] 掩码=[$CIDR_NUM]
       请确认已联网后再运行本脚本"
fi

printf '\n'
printf '   %s网卡%s    %s\n' "$c_c" "$c_0" "$MAIN_IFACE"
printf '   %s地址%s    %s/%s\n' "$c_c" "$c_0" "$MAIN_IP" "$CIDR_NUM"
printf '   %s网关%s    %s\n' "$c_c" "$c_0" "$MAIN_GATE"
printf '\n'
warn "以上三个值会写进新系统的静态网络配置。请记下来，重装后 SSH 用得上。"

# ── 第 4 步：磁盘体检 ────────────────────────────────────────────────────
info "第 4/6 步：检查目标磁盘"

# 自动探测：优先 vda/sda 这类常规系统盘
if [ -z "$DISK" ]; then
    for _cand in /dev/vda /dev/sda /dev/xvda /dev/hda /dev/nvme0n1; do
        [ -b "$_cand" ] && { DISK="$_cand"; break; }
    done
fi
[ -n "$DISK" ] && [ -b "$DISK" ] || die "找不到可用磁盘，请用 --disk /dev/xxx 指定"

DISK_SIZE_MB=$(($(cat "/sys/block/$(basename "$DISK")/size" 2>/dev/null || echo 0) / 2048))
ok "目标磁盘：$DISK（约 ${DISK_SIZE_MB} MB）"

# ── 救援盘识别：三条特征同时命中时【硬拦截】───────────────────────────
# ★ 踩坑实录（2026-10-11 用户真机，血的教训）：
#   某阿里云实例的救援系统自己占着唯一一块 1GB 盘（Alpine 虚拟 ISO 启动，
#   盘上残留 iso9660 签名，被自动挂到 /media/vda）。旧版脚本只给了个警告 +
#   一个「输入 yes 就放行」的确认，用户输入 yes 后：
#     1. 擦掉了 ISO 签名 → 再挂载时显示成 alpine-virt（盘已经废了一半）
#     2. mkfs 报 "apparently in use" 卡死 → 装不下去
#     3. 更危险的是：这块盘是救援系统自己的根，擦它就是自断退路
#   结论：「救援盘」这条路必须【焊死】——警告可以跳过，这个不行。
_iso_signature=0
_disk_devname="$(basename "$DISK")"
if [ -r "/sys/block/${_disk_devname}/device/type" ]; then :; fi
# 特征 A：容量过小（< 4GB，装不下 Debian 且必是救援盘）
_size_suspicious=0
if [ "$DISK_SIZE_MB" -gt 0 ] && [ "$DISK_SIZE_MB" -lt 4000 ]; then
    _size_suspicious=1
fi

# 特征 B：正被挂载（尤其挂在 /media 下 —— Alpine 救援系统的典型行为）
_mounted_at=""
if [ -r /proc/mounts ]; then
    _mounted_at="$(awk -v d="$DISK" '$1 ~ "^"d {print $2}' /proc/mounts 2>/dev/null | head -n1)"
fi
_mounted_suspicious=0
[ -n "$_mounted_at" ] && _mounted_suspicious=1

# 特征 C：盘上带 iso9660 签名（虚拟光驱 / 救援 ISO 的铁证）
_sig=""
if command -v blkid >/dev/null 2>&1; then
    _sig="$(blkid "$DISK" 2>/dev/null || true)"
fi
if [ -n "$_sig" ]; then
    case "$_sig" in
        *iso9660*) _iso_signature=1 ;;
    esac
fi

# 特征 C 补充：盘里的子分区带 iso9660（整盘没了签名、分区还在的情形）
if [ "$_iso_signature" = "0" ] && command -v blkid >/dev/null 2>&1; then
    _subsig="$(blkid "${DISK}"* 2>/dev/null | head -n5 || true)"
    case "$_subsig" in
        *iso9660*) _iso_signature=1 ;;
    esac
fi

# 三条命中两条及以上 → 判定为救援盘，直接拒绝，不给任何「跳过」的余地
_rescue_hits=$((_size_suspicious + _mounted_suspicious + _iso_signature))

if [ "$_rescue_hits" -ge 2 ]; then
    printf '\n'
    err "╔══════════════════════════════════════════════════════════╗"
    err "║  检测到：$DISK 极可能是【救援系统自己的盘】              "
    err "╚══════════════════════════════════════════════════════════╝"
    printf '\n'
    [ "$_size_suspicious"   = "1" ] && warn "  ✗ 容量只有 ${DISK_SIZE_MB} MB（装不下 Debian）"
    [ "$_mounted_suspicious" = "1" ] && warn "  ✗ 正被挂载在 ${_mounted_at}（系统正在用它）"
    [ "$_iso_signature"      = "1" ] && warn "  ✗ 盘上有 iso9660 签名（虚拟光驱/救援 ISO）"
    printf '\n'
    err "已拒绝执行 —— 这是保护措施，不是故障。"
    printf '\n'
    printf '  为什么必须拒绝：\n'
    printf '    · 这块盘装不下 Debian（最小化也要 1GB+，装完几乎没空间）\n'
    printf '    · 它是救援系统的根，擦掉它 = 断掉自己的退路（VNC 会失效）\n'
    printf '    · 实测后果：擦掉 ISO 签名后 mkfs 报 "apparently in use"，装不下去\n'
    printf '\n'
    printf '  正确做法（二选一）：\n'
    printf '    A. 到云控制台给这台实例【挂载一块新云盘】（建议 20GB+），\n'
    printf '       挂好后执行  cat /proc/partitions  确认新盘符（通常 /dev/vdb），\n'
    printf '       再用 --disk /dev/vdb 重跑本脚本。\n'
    printf '    B. 如果这台机器本来就有数据盘（如 /dev/vdb），直接指定它：\n'
    printf '       sh %s --disk /dev/vdb\n' "$(basename "$0")"
    printf '\n'
    printf '  ★ 确实要用这块盘（不推荐，风险自负）：\n'
    printf '     加 --force-rescue-disk 参数可强制继续。\n'
    printf '\n'
    if [ "$FORCE_RESCUE" != "1" ]; then
        exit 2
    else
        warn "已指定 --force-rescue-disk，继续执行（请自行承担风险）"
    fi
fi

# 单独只有容量小 → 只警告（可能是块 3GB 的数据盘，可以放行）
if [ "$_size_suspicious" = "1" ] && [ "$_rescue_hits" -lt 2 ]; then
    warn "磁盘只有 ${DISK_SIZE_MB} MB，装 Debian ${RELEASE} 会非常紧张"
    warn "（最小化安装约需 1GB，建议至少 8GB，否则装完几乎没空间）"
fi

# 单独被挂载 → 只警告
if [ "$_mounted_suspicious" = "1" ] && [ "$_rescue_hits" -lt 2 ]; then
    warn "★ 注意：$DISK 当前被挂载在 $_mounted_at"
    warn "  执行前会先尝试卸载它（卸载失败则中止，避免破坏正在运行的系统）。"
fi

# 残留签名提示
if [ -n "$_sig" ] && [ "$_rescue_hits" -lt 2 ]; then
    warn "磁盘上已有文件系统签名：$_sig"
    warn "  执行前会自动清除（wipefs），避免 mkfs 报 \"apparently in use\""
fi

# ── 真正去解决「盘被占用」：不是甩一句命令让用户跑 ──────────────────────
# ★ 这里做的事：卸载 → 擦除签名 → 复查 → 最多 3 轮。
#   对应实测：Alpine 会自动把带 iso9660 的盘挂到 /media/xxx，不主动卸，
#   mkfs 一定报 "apparently in use"。
release_disk() {
    _d="$1"
    # 1) 按设备名卸（含各分区）
    for _p in "${_d}"*; do
        [ -b "$_p" ] && { umount "$_p" >/dev/null 2>&1 || true; }
    done
    # 2) 按挂载点卸（关键：umount /dev/vda1 有时会漏，得按挂载点来）
    if [ -r /proc/mounts ]; then
        awk -v d="$_d" '$1 ~ "^"d || $1 ~ "^"d"[0-9p]" {print $2}' /proc/mounts 2>/dev/null \
            | sort -r | while IFS= read -r _mp; do
                [ -n "$_mp" ] && umount "$_mp" >/dev/null 2>&1 || true
            done
    fi
    swapoff -a >/dev/null 2>&1 || true
    command -v vgchange >/dev/null 2>&1 && { vgchange -an >/dev/null 2>&1 || true; }
    command -v mdadm    >/dev/null 2>&1 && { mdadm --stop --scan >/dev/null 2>&1 || true; }
    command -v dmsetup  >/dev/null 2>&1 && { dmsetup remove_all >/dev/null 2>&1 || true; }
    sleep 1
    return 0
}

wipe_disk() {
    _d="$1"
    if command -v wipefs >/dev/null 2>&1; then
        wipefs -a "$_d" >/dev/null 2>&1 && return 0
        # 逐个签名擦
        wipefs "$_d" 2>/dev/null | awk 'NR>1 {print $1}' | while IFS= read -r _s; do
            [ -n "$_s" ] && wipefs -o "$_s" "$_d" >/dev/null 2>&1 || true
        done
        return 0
    fi
    return 1
}

# ── 第 5 步：确认参数 ────────────────────────────────────────────────────
info "第 5/6 步：确认重装参数"

if [ -z "$PASSWORD" ]; then
    # 默认密码一律随机生成：原来交互模式回车给的是 rd13+月日，总共约 372 种可能，
    # 而新系统开着 root 密码登录 SSH，装好就会被扫到。
    _random_pwd="$(head -c 18 /dev/urandom | od -An -tx1 | tr -d ' \n' | cut -c1-16)"
    if [ "$ASSUME_YES" = "1" ]; then
        PASSWORD="$_random_pwd"
    else
        PASSWORD="$(ask "新系统 root 密码（字母、数字或 ._@%+=:,~^-）[回车使用随机密码]： " "$_random_pwd")"
    fi
    if [ "$PASSWORD" = "$_random_pwd" ]; then
        warn "已自动生成 root 密码：$PASSWORD"
        warn "★ 请务必记下这个密码，重装后要用它登录！"
    fi
    unset _random_pwd
fi
[ -n "$PASSWORD" ] || die "root 密码不能为空"
password_ok "$PASSWORD" || die "${PASSWORD_RULE}，请重新运行并换一个密码"

printf '\n'
printf '   磁盘      %s\n' "$DISK"
printf '   版本      Debian %s\n' "$RELEASE"
printf '   镜像      %s\n' "$MIRROR"
printf '   SSH 端口  %s\n' "$PORT"
printf '   root 密码 %s\n' "$PASSWORD"
printf '   swap      %s MB\n' "$SWAP_MB"
printf '   网络模式  %s\n' "$NET_MODE"
printf '   日志      %s\n' "$LOG"
printf '\n'

if [ "$CHECK_ONLY" = "1" ]; then
    ok "全部检查通过（--check 模式，未做任何改动）"
    printf '\n下一步：去掉 --check 重新运行即可真正开始重装。\n\n'
    exit 0
fi

warn "即将清空 $DISK 并重装 Debian $RELEASE —— 数据不可恢复"
printf '\n'
if [ "$ASSUME_YES" != "1" ]; then
    _c="$(ask '确认开始？输入 yes 回车：' 'no')"
    [ "$_c" = "yes" ] || die "已取消"
fi

# 清盘必须在用户确认之后（2026-11-04 修）：旧实现在第 5 步确认前就 wipefs，
# 用户看到参数摘要（比如盘选错了）回答 no 时，分区表和文件系统签名已经没了。
# 只有要动这块盘时才清理（CHECK_ONLY 模式只看不动）
if [ "$CHECK_ONLY" != "1" ] && [ "$DRY_RUN" != "1" ]; then
    if [ "$_mounted_suspicious" = "1" ] || [ -n "$_sig" ]; then
        _round=0
        _clean_ok=0
        while [ "$_round" -lt 3 ]; do
            _round=$((_round + 1))
            info "释放磁盘占用 / 清除残留签名（第 $_round 轮）"
            release_disk "$DISK"
            wipe_disk "$DISK" || true
            _left=""
            if [ -r /proc/mounts ]; then
                _left="$(awk -v d="$DISK" '$1 ~ "^"d {print $2}' /proc/mounts 2>/dev/null)"
            fi
            if [ -z "$_left" ]; then _clean_ok=1; break; fi
            warn "仍被挂载：$(printf '%s' "$_left" | tr '\n' ' ') —— 延迟卸载后重试"
            printf '%s\n' "$_left" | sort -r | while IFS= read -r _mp; do
                umount -l "$_mp" >/dev/null 2>&1 || true
            done
            sleep 2
        done
        if [ "$_clean_ok" = "1" ]; then
            ok "磁盘已释放并清除残留签名"
        else
            warn "磁盘仍被占用 —— mkfs 可能失败，届时请手动检查"
        fi
    fi
fi


# ── 第 6 步：下载并执行 InstallNET ───────────────────────────────────────
info "第 6/6 步：下载并执行重装程序"

IN_FILE="$WORKDIR/InstallNET.sh"

# 拿到的必须像个脚本：够大且以 #! 开头。被劫持或拿到报错网页时
# 可能也有几十 KB，只看大小会把一个网页当成脚本以 root 执行。
installnet_looks_valid() {
    _got="$(wc -c < "$IN_FILE" 2>/dev/null | tr -d ' ')"
    [ -n "$_got" ] && [ "$_got" -ge 50000 ] && head -n 1 "$IN_FILE" 2>/dev/null | grep -q '^#!'
}

download_installnet() {
    for _u in "$INSTALLNET_URL" "$INSTALLNET_MIRROR"; do
        rm -f "$IN_FILE"
        if command -v wget >/dev/null 2>&1; then
            # 不能 --no-check-certificate：下载的脚本随后以 root 执行并重装整个系统，
            # 跳过证书校验等于把机器交给任何能做中间人的人。
            wget -qO "$IN_FILE" "$_u" && installnet_looks_valid && return 0
        fi
        rm -f "$IN_FILE"
        if command -v curl >/dev/null 2>&1; then
            curl -fsSL --max-time 120 -o "$IN_FILE" "$_u" && installnet_looks_valid && return 0
        fi
    done
    rm -f "$IN_FILE"
    return 1
}

# 缺 wget/curl 就先补上
if ! command -v wget >/dev/null 2>&1 && ! command -v curl >/dev/null 2>&1; then
    info "安装下载工具"
    apk update >/dev/null 2>&1 || true
    apk add --no-cache wget curl iproute2 gawk ipcalc >/dev/null 2>&1 || true
fi
# 下载要校验 HTTPS 证书，Alpine Live 环境可能缺 CA 根证书包。
if command -v apk >/dev/null 2>&1 && [ ! -s /etc/ssl/certs/ca-certificates.crt ]; then
    apk add --no-cache ca-certificates >/dev/null 2>&1 || true
fi

# ★ 必须确保 bash 存在 —— InstallNET.sh 是 bash 脚本，用 sh 跑会报
#   `sh: bash: not found`（退出码 127）。
#   踩坑实录（2026-10-11 用户真机）：上一版把 bash 混在"没有 wget 时"才装的
#   那个分支里，而 Alpine Live ISO 自带 wget → 该分支被跳过 → bash 从未安装
#   → 脚本跑到最后一步才失败，前面的体检全部白做。
#   现在：无条件检查并安装 bash（以及 InstallNET 依赖的基础工具）。
_missing_tools=""
command -v bash >/dev/null 2>&1 || _missing_tools="$_missing_tools bash"
if [ -n "$_missing_tools" ]; then
    info "安装缺失的基础工具：$_missing_tools"
    apk update >/dev/null 2>&1 || true
    # 分开装，避免某个包名不存在时整批失败
    for _t in $_missing_tools; do
        apk add --no-cache "$_t" >/dev/null 2>&1 || true
    done
fi
if command -v bash >/dev/null 2>&1; then
    ok "bash 已就绪（$(command -v bash)）"
else
    warn "bash 安装失败 —— InstallNET.sh 需要 bash 才能运行"
    warn "如果下面失败，请手动执行：apk add --no-cache bash"
fi

info "下载 InstallNET.sh"
download_installnet || die "下载 InstallNET.sh 失败。请检查网络后重试。"
chmod a+x "$IN_FILE" 2>/dev/null || true

# 校验下载完整性：InstallNET.sh 正常有 270KB 左右
_size="$(wc -c < "$IN_FILE" 2>/dev/null | tr -d ' ')"
if [ -z "$_size" ] || [ "$_size" -lt 50000 ]; then
    die "下载的文件异常（只有 ${_size:-0} 字节，应为 270KB 左右）。
       可能是网络被劫持或返回了错误页面。请重试或检查网络。"
fi
ok "已下载 InstallNET.sh（$_size 字节）"

# 组装参数
set -- -debian "$RELEASE" -port "$PORT" -pwd "$PASSWORD" -mirror "$MIRROR" -swap "$SWAP_MB"

case "$NET_MODE" in
    static)
        # ★ 静态 IP 是最能防失联的方式：DHCP 在重装后可能拿不到地址，
        #   而静态配置直接写死，开机就有网。
        set -- "$@" --ip-addr "$MAIN_IP" --ip-gate "$MAIN_GATE" --ip-mask "$CIDR_NUM"
        info "网络模式：静态（$MAIN_IP/$CIDR_NUM via $MAIN_GATE）"
        ;;
    dhcp)
        info "网络模式：DHCP"
        ;;
esac

set -- "$@" --cloudkernel 0 --bbr --motd

printf '\n'
info "开始执行重装（InstallNET 接管后会自行重启，全程 10~20 分钟）"
# 屏显与日志里遮掉 root 密码（2026-11-04 修）：日志留在 /root/reinstall-debian13.log，
# 旧实现把 -pwd 后的原文写进去，能读到它的人就拿到了 SSH root 密码。
_shown="" _mask=0
for _a in "$@"; do
    if [ "$_mask" = "1" ]; then _a="******"; _mask=0; fi
    [ "$_a" = "-pwd" ] && _mask=1
    _shown="${_shown:+$_shown }$_a"
done
info "执行命令：bash InstallNET.sh $_shown"
printf '\n'
log_line "执行：bash InstallNET.sh $_shown"

# 交给 InstallNET
# ★ 兜底：明确检查 bash 存在，避免只留下一句 `sh: bash: not found`（退出码 127）
if ! command -v bash >/dev/null 2>&1; then
    err "系统里没有 bash —— InstallNET.sh 是 bash 脚本，无法用 sh 运行"
    printf '\n'
    printf '  请先执行：apk add --no-cache bash\n'
    printf '  然后重新运行本脚本。\n\n'
    exit 127
fi

if bash "$IN_FILE" "$@"; then
    printf '\n'
    ok "重装流程已启动"
else
    _rc=$?
    printf '\n'
    err "InstallNET 执行失败（退出码 $_rc）"
    printf '\n'
    printf '常见原因与处理：\n'
    printf '  1. 网络中断      —— 检查网络后重试\n'
    printf '  2. 空间不足      —— 确认磁盘容量（df -h / blkid %s）\n' "$DISK"
    printf '  3. 磁盘被占用    —— 执行 wipefs -a %s 后重试\n' "$DISK"
    printf '  4. 缺 bash       —— 执行 apk add --no-cache bash\n'
    printf '  5. 上游脚本变更  —— 可到 leitbogioro/Tools 仓库查看最新说明\n'
    printf '\n完整日志：%s\n\n' "$LOG"
    exit "$_rc"
fi

cat <<EOF

========================================
  重装已开始
========================================

  接下来：
    1. 机器会在几分钟内自动重启
    2. 等待 10~20 分钟（首次启动会做初始化）
    3. 用新密码登录：ssh -p $PORT root@<你的公网IP>
    4. 验证系统：cat /etc/os-release   应显示 Debian GNU/Linux $RELEASE

  ★ 网络配置（如果连不上，用这些信息排查）：
      地址  $MAIN_IP/$CIDR_NUM
      网关  $MAIN_GATE
      网卡  $MAIN_IFACE

  日志：$LOG
EOF
