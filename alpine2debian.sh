#!/bin/sh
# alpine2debian.sh — 在 Alpine（救援 / 内存模式）里一键把机器刷成 Debian 12 最小化
#
# ─────────────────────────────────────────────────────────────────────────
# 这个脚本解决什么问题
#
#   阿里云部分实例（尤其抢占式 / 活动机型）开机后落在 Alpine 的「救援模式」：
#   整个系统跑在内存里，重启就没了，网卡默认也没配 IP。它本身不是一个能长期
#   使用的系统。传统做法是借道第三方重装脚本（InstallNET 之类），但那是黑盒：
#   你没法审、没法改、出问题没法定位。
#
#   本脚本用 **Debian 官方 debootstrap** 在本地直接释放一个完整的 Debian 12
#   根文件系统到磁盘，然后装内核、装 GRUB、写好网络与 fstab，最后重启。
#   全流程每一步都可读、可改、可单独重跑，**不下载任何第三方安装脚本**。
#
# ─────────────────────────────────────────────────────────────────────────
# 它做了什么（9 步，每步都有回显）
#
#   1. 环境检查：确认是 Alpine、是 root、有可用的目标磁盘
#   2. 联网检查：确认能访问 Debian 镜像站（不通就给出修复提示）
#   3. 抽取当前网络配置：网卡 / IP / 网关 / 掩码 / DNS（★ 防止重启后失联）
#   4. 装工具：sfdisk / mkfs.ext4 / debootstrap 等（★ 必须在分区之前）
#   5. 分区并格式化：单分区 MBR + ext4（对齐阿里云常见形态，不建 swap）
#   6. debootstrap：从官方源释放 Debian 12 bookworm 最小根文件系统
#   7. chroot 配置：装 cloud 内核 + GRUB + ssh，设密码、开 root 登录
#   8. 写 fstab / 网络配置 / DNS / 主机名 / 时区
#   9. 装 GRUB 引导（BIOS 模式）→ 卸载 → 重启
#
# ─────────────────────────────────────────────────────────────────────────
# 用法
#
#   # 交互式（推荐首次使用，会逐项询问并让你确认）
#   sh alpine2debian.sh
#
#   # 非交互（全部走默认值或环境变量，适合自动化）
#   ROOT_PWD='yourpass' sh alpine2debian.sh --yes
#
#   # 只做检查，不动磁盘（★ 强烈建议第一次先跑这个）
#   sh alpine2debian.sh --dry-run
#
#   # 指定磁盘 / 镜像 / 网卡
#   sh alpine2debian.sh --disk /dev/vda --mirror http://mirrors.aliyun.com/debian
#
# ─────────────────────────────────────────────────────────────────────────
# 可用环境变量
#
#   ROOT_PWD     新系统 root 密码（不设则交互询问）
#   DISK         目标磁盘，默认自动探测（/dev/vda → /dev/sda 顺序找）
#   DEBIAN_SUITE Debian 版本代号，默认 bookworm（= Debian 12）
#   MIRROR       镜像站，默认阿里云（国内快）
#   SECURITY_MIRROR 安全更新源，默认跟随 MIRROR（…/debian → …/debian-security）
#   HOSTNAME     主机名，默认 debian
#   TIMEZONE     时区，默认 Asia/Shanghai
#   SWAP_MB      额外建多大 swap 文件（MB），默认 0 = 不建（对齐最小化）
#
# ─────────────────────────────────────────────────────────────────────────
# 警告
#
#   ★★★ 本脚本会【彻底清空】目标磁盘上的所有数据，不可恢复。★★★
#   执行前请确认：机器里没有任何需要保留的东西。
#   第一次使用请务必先跑 --dry-run。
# ─────────────────────────────────────────────────────────────────────────

set -eu

# ── 默认值 ────────────────────────────────────────────────────────────────
ROOT_PWD="${ROOT_PWD:-}"
DISK="${DISK:-}"
DEBIAN_SUITE="${DEBIAN_SUITE:-bookworm}"
MIRROR="${MIRROR:-http://mirrors.aliyun.com/debian}"
SECURITY_MIRROR="${SECURITY_MIRROR:-}"
HOSTNAME="${HOSTNAME:-debian}"
TIMEZONE="${TIMEZONE:-Asia/Shanghai}"
SWAP_MB="${SWAP_MB:-0}"

ASSUME_YES=0
DRY_RUN=0
MOUNT_DIR="/mnt/debian"

# ── 输出工具 ──────────────────────────────────────────────────────────────
c_red=$(printf '\033[31m'); c_grn=$(printf '\033[32m')
c_ylw=$(printf '\033[33m'); c_cyn=$(printf '\033[36m'); c_rst=$(printf '\033[0m')
info() { printf '%s[*]%s %s\n' "$c_cyn" "$c_rst" "$*"; }
ok()   { printf '%s[OK]%s %s\n' "$c_grn" "$c_rst" "$*"; }
warn() { printf '%s[!]%s %s\n' "$c_ylw" "$c_rst" "$*"; }
err()  { printf '%s[X]%s %s\n' "$c_red" "$c_rst" "$*" >&2; }
die()  { err "$*"; exit 1; }

# 统一的「执行或预演」入口：dry-run 时只打印不执行
run() {
    if [ "$DRY_RUN" = "1" ]; then
        printf '    %s[dry-run]%s %s\n' "$c_ylw" "$c_rst" "$*"
    else
        "$@"
    fi
}

# 打印开头整段注释：不写死行号，头部增减说明时不会截掉末尾「先跑 --dry-run」的警告。
usage() { awk 'NR == 1 { next } /^#/ { print; next } { exit }' "$0"; exit 0; }

# 目标必须是整块磁盘而不是分区（2026-11-12 修）：/dev/vda1 也是块设备，旧实现照收，随后
# 在分区里再建分区表、擦掉这个分区的数据，却装不成系统。/sys/block 下只有整块磁盘；
# 先解开符号链接（/dev/disk/by-id/... 指向的是整块磁盘时也要认）。用法：is_whole_disk <设备>
is_whole_disk() {
    [ -d "${SYS_BLOCK:-/sys/block}/$(basename "$(readlink -f "$1" 2>/dev/null || printf '%s' "$1")")" ]
}

# ── 参数解析 ──────────────────────────────────────────────────────────────
while [ $# -gt 0 ]; do
    case "$1" in
        --yes|-y)     ASSUME_YES=1; shift ;;
        --dry-run)    DRY_RUN=1; shift ;;
        --disk)       [ $# -ge 2 ] || die "--disk 缺少取值"; DISK="$2"; shift 2 ;;
        --mirror)     [ $# -ge 2 ] || die "--mirror 缺少取值"; MIRROR="$2"; shift 2 ;;
        --suite)      [ $# -ge 2 ] || die "--suite 缺少取值"; DEBIAN_SUITE="$2"; shift 2 ;;
        --pwd)        [ $# -ge 2 ] || die "--pwd 缺少取值"; ROOT_PWD="$2"; shift 2 ;;
        -h|--help)    usage ;;
        *) die "未知参数: $1（用 --help 看用法）" ;;
    esac
done

# 安全更新源默认跟随主镜像（2026-11-12 修）：旧实现 --mirror 只换主源，debian-security
# 仍固定阿里云。它拉取失败时 chroot 里的 apt-get update 在 set -e 下中止，磁盘已清空、
# 内核与引导却还没装上，重启即失联。
if [ -z "$SECURITY_MIRROR" ]; then
    case "$MIRROR" in
        */debian|*/debian/) SECURITY_MIRROR="${MIRROR%/}-security" ;;
        *) SECURITY_MIRROR="http://security.debian.org/debian-security" ;;
    esac
fi

# ── 第 1 步：环境检查 ────────────────────────────────────────────────────
info "第 1/9 步：检查运行环境"

[ "$(id -u)" = "0" ] || die "必须以 root 运行"

if [ -f /etc/alpine-release ]; then
    ok "当前系统：Alpine $(cat /etc/alpine-release)"
else
    warn "当前系统看起来不是 Alpine（/etc/alpine-release 不存在），继续执行"
fi

# 探测目标磁盘
if [ -z "$DISK" ]; then
    for cand in /dev/vda /dev/sda /dev/xvda /dev/hda; do
        if [ -b "$cand" ]; then DISK="$cand"; break; fi
    done
fi
[ -n "$DISK" ] && [ -b "$DISK" ] || die "找不到可用磁盘，请用 --disk /dev/xxx 指定"
is_whole_disk "$DISK" || die "$DISK 不是整块磁盘（像是分区），请指定整块磁盘，例如 /dev/vda"
# 之后一律用真实设备名（2026-11-13 修）：--disk 给 /dev/disk/by-id/... 链接时，分区名按「盘名 + 1 / p1」
# 推出来的是不存在的路径 —— 分区表已经写完、到格式化这步才失败，盘上数据没了、系统也没装上。
DISK="$(readlink -f "$DISK" 2>/dev/null || printf '%s' "$DISK")"
ok "目标磁盘：$DISK"

DISK_SIZE_MB=$(($(cat "/sys/block/$(basename "$(readlink -f "$DISK")")/size" 2>/dev/null || echo 0) / 2048))
if [ "$DISK_SIZE_MB" -gt 0 ]; then
    ok "磁盘容量：约 ${DISK_SIZE_MB} MB"
    if [ "$DISK_SIZE_MB" -lt 1500 ]; then
        warn "磁盘小于 1.5GB，Debian 12 最小化可能装不下（官方建议 8GB+，勉强可跑约需 1GB）"
    fi
fi

# 收集要交互询问的值
if [ -z "$ROOT_PWD" ]; then
    if [ "$ASSUME_YES" = "1" ]; then
        die "非交互模式必须通过 ROOT_PWD 环境变量或 --pwd 提供 root 密码"
    fi
    printf '%s' "请设置新系统 root 密码（不能含特殊字符以免输入出错）: "
    # set -eu 下 read 读到 EOF 返回 1，脚本会无声退出（2026-11-04 修）；交给下面的空值检查报错。
    if [ -t 0 ]; then read -r ROOT_PWD || ROOT_PWD=""; else read -r ROOT_PWD </dev/tty || ROOT_PWD=""; fi
fi
[ -n "$ROOT_PWD" ] || die "root 密码不能为空"

# ── 第 2 步：联网检查 ────────────────────────────────────────────────────
info "第 2/9 步：检查网络与外网连通性"

# Alpine 救援模式下网卡默认没有 IP，这里先尝试自动获取。
#
# ★ 实测踩坑：网卡默认是 DOWN 状态，直接 udhcpc 会报
#     udhcpc: sendto: Network is down
#   所以必须先 `ip link set <网卡> up` 把网卡启起来，再要 IP。
if ! ip route show default >/dev/null 2>&1 || [ -z "$(ip route show default 2>/dev/null)" ]; then
    warn "尚未获取到默认路由，先启用网卡再尝试 DHCP..."
    for ifc in /sys/class/net/*; do
        ifc=${ifc##*/}
        [ "$ifc" = "lo" ] && continue
        # 先启用网卡（DOWN 状态下 DHCP 一定失败）
        if [ "$DRY_RUN" = "1" ]; then
            printf '    %s[dry-run]%s ip link set %s up\n' "$c_ylw" "$c_rst" "$ifc"
            printf '    %s[dry-run]%s udhcpc -i %s -q -n -t 10\n' "$c_ylw" "$c_rst" "$ifc"
        else
            info "启用 $ifc 并尝试 DHCP"
            ip link set "$ifc" up 2>/dev/null || true
            udhcpc -i "$ifc" -q -n -t 10 2>/dev/null || true
        fi
        # ip route 没有默认路由时也返回 0，必须看输出（2026-11-04 修）
        [ -n "$(ip route show default 2>/dev/null)" ] && break
    done
fi

if [ -z "$(ip route show default 2>/dev/null)" ]; then
    die "仍然没有默认路由。请先在 VNC 里手动联网：
       ip link                    # 看网卡名，确认状态是 DOWN 还是 UP
       ip link set <网卡> up      # ★ DOWN 的话先启用
       udhcpc -i <网卡> -q -n     # 再获取地址
       然后重新运行本脚本"
fi

DNS_HOST=$(printf '%s' "$MIRROR" | sed -E 's#^https?://##; s#/.*$##')
info "测试镜像站连通性：$DNS_HOST"
if ping -c 2 -W 3 "$DNS_HOST" >/dev/null 2>&1; then
    ok "镜像站可达"
else
    warn "ping 不通 $DNS_HOST（可能只是禁 ping），继续尝试 DNS 解析"
fi

# 确保 DNS 可用（否则 apk / debootstrap 都会失败）
if ! nslookup "$DNS_HOST" >/dev/null 2>&1 && ! getent hosts "$DNS_HOST" >/dev/null 2>&1; then
    warn "DNS 解析失败，写入公共 DNS 后重试"
    run sh -c 'printf "nameserver 223.5.5.5\nnameserver 8.8.8.8\n" > /etc/resolv.conf'
fi

# ── 第 3 步：抽取网络配置（★ 防失联的关键）─────────────────────────────
info "第 3/9 步：抽取当前网络配置（重装后用于恢复，防止失联）"

MAIN_IFACE=$(ip route show default 2>/dev/null | awk '{print $5}' | head -n1 | tr -d '[:space:]')
MAIN_IP=$(ip -4 addr show "$MAIN_IFACE" 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1 | tr -d '[:space:]')
MAIN_GATE=$(ip route show default 2>/dev/null | awk '/default/{print $3}' | head -n1 | tr -d '[:space:]')
MAIN_CIDR=$(ip -4 addr show "$MAIN_IFACE" 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f2 | head -n1 | tr -d '[:space:]')

if [ -z "$MAIN_IP" ] || [ -z "$MAIN_GATE" ] || [ -z "$MAIN_CIDR" ]; then
    die "无法抽取网络配置（网卡=$MAIN_IFACE IP=$MAIN_IP 网关=$MAIN_GATE 掩码=$MAIN_CIDR）
       请先确认已联网，或在脚本里手工指定 MAIN_IP / MAIN_GATE / MAIN_CIDR"
fi

ok "网卡：$MAIN_IFACE"
ok "IP：$MAIN_IP/$MAIN_CIDR"
ok "网关：$MAIN_GATE"
info "（这三个值会写进新系统的网络配置，务必记下）"

# ── 确认执行 ─────────────────────────────────────────────────────────────
printf '\n'
warn "即将清空磁盘 ${DISK} 并安装 Debian 12（$DEBIAN_SUITE）"
warn "磁盘上所有数据都会丢失，且不可恢复"
printf '\n'
if [ "$ASSUME_YES" != "1" ] && [ "$DRY_RUN" != "1" ]; then
    printf '确认继续？输入 yes 回车：'
    if [ -t 0 ]; then read -r _ans || _ans=""; else read -r _ans </dev/tty || _ans=""; fi
    [ "$_ans" = "yes" ] || die "已取消"
fi

# ── 第 4 步：先装工具（★ 必须在分区之前）────────────────────────────────
#
# ★ 实测踩坑：最初把 apk add 放在第 5 步（debootstrap 之前），结果第 4 步
#   分区时就报 `sfdisk: not found` —— 因为 Alpine 救援模式是最小系统，
#   sfdisk 属于 util-linux 包，默认没装。工具必须先装再用。
info "第 4/9 步：安装所需工具"

run apk update
run apk add --no-cache debootstrap bash coreutils util-linux e2fsprogs \
    grub grub-bios sfdisk parted openssl

# 装完立刻确认关键命令都在，缺了就直接停下来（不要等到分区时才炸）
if [ "$DRY_RUN" != "1" ]; then
    _missing=""
    for _c in sfdisk fdisk mkfs.ext4 debootstrap chroot blkid; do
        command -v "$_c" >/dev/null 2>&1 || _missing="$_missing $_c"
    done
    if [ -n "$_missing" ]; then
        die "以下命令缺失：$_missing
       请检查网络后重试：apk update && apk add util-linux e2fsprogs debootstrap"
    fi
    ok "工具已就绪（sfdisk / fdisk / mkfs.ext4 / debootstrap 等）"
fi

# ── 第 5 步：分区 + 格式化 ───────────────────────────────────────────────
info "第 5/9 步：分区并格式化 $DISK"

# ── 5.0 彻底释放磁盘占用（★ 这一步不做干净，后面一定失败）───────────────
#
# ★★ 实测踩坑（2026-10-11，用户真机 + Alpine 容器双重复现）：
#   磁盘上如果残留**旧文件系统签名**（尤其 iso9660 —— 阿里云某些救援
#   镜像会把磁盘当"光盘"用），系统会**自动把它挂载起来**。于是：
#     · sfdisk 重读分区表 → `Re-reading the partition table failed: Resource busy`
#     · mkfs.ext4        → `/dev/vda1 is apparently in use by the system;
#                            will not make a filesystem here!`
#   两条路都被堵死，重装就断在这里。**清签名（wipefs）才是根治**，
#   只 umount 不擦签名的话，系统可能立刻又把它挂回去。
#
#   顺序很重要：先解占用 → 再擦签名 → 再分区。反过来 wipefs 也会被拒。
release_disk() {
    _d="$1"

    # (1) 先按分区设备名卸
    for _p in "${_d}"*; do
        [ -b "$_p" ] && { umount "$_p" >/dev/null 2>&1 || true; }
    done

    # (2) 再**按挂载点**卸 —— 关键补充！`umount /dev/vda1` 在设备节点
    #     和挂载源不完全一致时（比如通过 loop / udev 别名挂的）会漏掉，
    #     必须从 /proc/mounts 里把这些设备的所有挂载点全捞出来卸干净。
    if [ -r /proc/mounts ]; then
        awk -v d="$_d" '$1 ~ "^"d || $1 ~ "^"d"[0-9p]" {print $2}' /proc/mounts 2>/dev/null \
            | sort -r | while IFS= read -r _mp; do
                [ -n "$_mp" ] && umount "$_mp" >/dev/null 2>&1 || true
            done
    fi

    # (3) 关 swap（救援模式常把磁盘当 swap 用，会让设备一直"忙"）
    swapoff -a >/dev/null 2>&1 || true

    # (4) 停 LVM / mdraid（同样造成 Resource busy）
    command -v vgchange >/dev/null 2>&1 && { vgchange -an >/dev/null 2>&1 || true; }
    command -v mdadm    >/dev/null 2>&1 && { mdadm --stop --scan >/dev/null 2>&1 || true; }
    command -v dmsetup  >/dev/null 2>&1 && { dmsetup remove_all >/dev/null 2>&1 || true; }

    # (5) 如果是 loop 设备，先 detach（省得还占着底层文件）
    case "$_d" in
        /dev/loop*)
            losetup -d "$_d" >/dev/null 2>&1 || true
            ;;
    esac

    sleep 1
}

# ── 5.1 擦掉磁盘上所有残留签名（★ 根治 Resource busy / in use）──────────
#
# wipefs -a 会把磁盘头部所有已知文件系统签名（iso9660 / ext4 / xfs / LVM /
# RAID / swap...）一次性清掉。**不清的话，系统一发现签名就可能自动挂载，
# 于是 mkfs.ext4 永远说"设备正忙"。**
#
# 注意：部分发行版的 busybox 版 wipefs 不支持 -a，所以要加兼容判断。
wipe_disk() {
    _d="$1"
    if command -v wipefs >/dev/null 2>&1; then
        if wipefs -a "$_d" >/dev/null 2>&1; then
            return 0
        fi
        # busybox 版不支持 -a，退化成逐个签名擦
        wipefs "$_d" 2>/dev/null | awk 'NR>1 {print $1}' | while IFS= read -r _sig; do
            [ -n "$_sig" ] && wipefs -o "$_sig" "$_d" >/dev/null 2>&1 || true
        done
        return 0
    fi
    return 1
}

if [ "$DRY_RUN" = "1" ]; then
    printf '    %s[dry-run]%s 释放 %s 上所有挂载 / swap / LVM\n' "$c_ylw" "$c_rst" "$DISK"
    printf '    %s[dry-run]%s wipefs -a %s   （清掉 iso9660 等残留签名）\n' "$c_ylw" "$c_rst" "$DISK"
else
    # ★★ 关键：清干净要**反复来几轮**，不能只做一次。
    #   实测（2026-10-11 用户真机）：磁盘带 iso9660 签名时，系统会自动
    #   把它挂载成一个"光盘"。此时：
    #     · 只 umount   → 系统可能立刻又挂回去（因为是自动挂载）
    #     · 只 wipefs   → 设备正忙，wipefs 自己也可能被拒
    #   正确顺序是「卸 → 擦 → 复查 → 若又挂回来了就再来一轮」，
    #   直到确认磁盘既没挂载、也没签名为止。最多试 3 轮。
    _round=0
    _clean_ok=0
    while [ "$_round" -lt 3 ]; do
        _round=$((_round + 1))
        info "清理磁盘占用（第 $_round 轮）"

        release_disk "$DISK"
        wipe_disk "$DISK" || true

        # 复查：还有挂载吗？
        _mnt_left=""
        if [ -r /proc/mounts ]; then
            _mnt_left="$(awk -v d="$DISK" '$1 ~ "^"d {print $2}' /proc/mounts 2>/dev/null)"
        fi

        if [ -z "$_mnt_left" ]; then
            _clean_ok=1
            break
        fi

        warn "磁盘仍被挂载：$(printf '%s' "$_mnt_left" | tr '\n' ' ') —— 强制卸载后重试"
        printf '%s\n' "$_mnt_left" | sort -r | while IFS= read -r _mp; do
            umount -l "$_mp" >/dev/null 2>&1 || true   # -l 懒卸载，绕开"设备忙"
        done
        sleep 2
    done

    if [ "$_clean_ok" = "1" ]; then
        ok "磁盘已释放干净（无挂载、无残留签名）"
    else
        warn "仍有挂载残留，但继续尝试分区（下一步格式化时还有一次兜底）"
    fi
fi

# 等设备真正闲置下来
[ "$DRY_RUN" != "1" ] && sleep 1

# 单分区 MBR：一个从 2048 扇区开始、占满整盘的 83 类型分区。
#
# ★ 为什么用 sfdisk 而不是 fdisk：
#   fdisk 的「自动分区」靠往 stdin 喂 `,` 和 `L` 走交互流程，新版 util-linux
#   对它的接受度很不稳定（有时提示序列变了就出错，有时直接静默写错表）。
#   sfdisk 支持**参数化输入**（直接描述分区表），结果确定、可预期，
#   是所有自动化脚本应该用的方式。fdisk 只作为最后的兜底。
#
# ★ 为什么从 2048 扇区开始：这是 1MiB 对齐（2048 × 512B）。
#   老式从 63 扇区开始会破坏 SSD/云盘的 4K 对齐，性能明显下降。
if [ "$DRY_RUN" = "1" ]; then
    printf '    %s[dry-run]%s sfdisk %s  <<< ",,83,*"\n' "$c_ylw" "$c_rst" "$DISK"
else
    # 先清干净旧分区表（防止旧表残留导致 sfdisk 判断成"已存在"而跳过）
    run sh -c "dd if=/dev/zero of='$DISK' bs=512 count=1 conv=notrunc 2>/dev/null || true"

    _parted_ok=0
    if printf ',,83,*\n' | sfdisk --label dos --no-reread "$DISK"; then
        _parted_ok=1
    fi

    if [ "$_parted_ok" = "0" ]; then
        warn "sfdisk 分区失败，尝试 fdisk 兜底"
        # 新版 fdisk 用 `printf` 喂交互序列确实不稳，改用 --no-reread 明确告诉它别去重读
        if printf 'o\nn\np\n1\n2048\n\n\nw\n' | fdisk --no-reread "$DISK"; then
            _parted_ok=1
        fi
    fi

    [ "$_parted_ok" = "1" ] || die "分区失败。请手动执行 fdisk $DISK 分区后再重跑本脚本"
    ok "分区表已写入（MBR，单分区）"

    # ── 让分区设备节点 /dev/xxx1 出现 ────────────────────────────────────
    #
    # ★★ 这是整个脚本**最容易失败**的一步，踩坑记录（2026-10-11 用
    #    Alpine 3.24 容器 + loop 假盘真实复现，不是推演）：
    #
    #   原方案：`partprobe || blockdev --rereadpt || hdparm -z`
    #   实测：sfdisk 写完表后会提示
    #       Re-reading the partition table failed.: Invalid argument
    #       The kernel still uses the old table.
    #   也就是说 —— **内核拒绝重读分区表**，于是 /dev/loop0p1 永远不出现，
    #   脚本在第 5 步 die「分区设备未出现」→ 用户看到的「重装不了」。
    #
    #   更细的实测结论（很重要，和直觉相反）：
    #     · 即使 partprobe **命令存在且返回 0**，节点**依然不出现**。
    #       所以"把工具装全"解决不了这个问题。
    #     · 但 /proc/partitions 和 /sys/class/block/loop0p1/dev **都已经有了**
    #       （内核其实知道这个分区，只是没帮我们建 /dev 节点）。
    #     ⇒ **唯一可靠的办法：自己用 mknod 按 sysfs 里的主:次号把节点造出来。**
    #
    #   因此下面把 mknod 提为**第一优先**，其余手段只是"顺手试一下"，
    #   试完不管成不成都要 fall through 到 mknod。
    mk_partnode() {
        _node="$1"; _disk="$2"; _pnum="$3"
        [ -b "$_node" ] && return 0

        _base="$(basename "$_disk")"
        # 分区节点的 sysfs 路径（两种命名都可能）
        _sysdev="/sys/class/block/${_base}${_pnum}/dev"
        [ -f "$_sysdev" ] || _sysdev="/sys/class/block/${_base}p${_pnum}/dev"

        # ---- 先试"正规"手段，让内核对（走通就省事，走不通也没关系）----
        command -v partprobe >/dev/null 2>&1 && \
            { partprobe "$_disk" >/dev/null 2>&1 || true; }
        command -v partx >/dev/null 2>&1 && \
            { partx -a -n "${_pnum}:${_pnum}" "$_disk" >/dev/null 2>&1 || true; }
        # busybox 的 mdev -s 会按 sysfs 内容补全 /dev 下的设备节点
        command -v mdev >/dev/null 2>&1 && { mdev -s >/dev/null 2>&1 || true; }
        sleep 1
        [ -b "$_node" ] && return 0

        # ---- ★ 真正管用的一招：按 sysfs 的设备号手工 mknod ----
        _maj=""; _min=""
        if [ -f "$_sysdev" ]; then
            _majmin="$(cat "$_sysdev" 2>/dev/null)"
            _maj="${_majmin%%:*}"; _min="${_majmin##*:}"
        fi
        # sysfs 里没有就直接问内核要（/proc/partitions 第 1、2 列）
        if [ -z "$_maj" ] || [ -z "$_min" ]; then
            # shellcheck disable=SC2046  # 有意按空白拆成主/次设备号两个参数
            set -- $(awk -v n="${_base}p${_pnum}" -v m="${_base}${_pnum}" \
                '$4==n || $4==m {print $1, $2; exit}' /proc/partitions 2>/dev/null)
            _maj="${1:-}"; _min="${2:-}"
        fi

        if [ -n "$_maj" ] && [ -n "$_min" ]; then
            # 先删掉可能存在的坏节点，再重建
            [ -e "$_node" ] && rm -f "$_node" 2>/dev/null || true
            if mknod "$_node" b "$_maj" "$_min" 2>/dev/null; then
                chmod 660 "$_node" 2>/dev/null || true
                sleep 1
                [ -b "$_node" ] && return 0
            fi
            # mknod 失败（容器里 /dev 只读等）→ 换 busybox 风格再试一次
            busybox mknod "$_node" b "$_maj" "$_min" 2>/dev/null || true
            sleep 1
            [ -b "$_node" ] && return 0
        fi

        return 1
    }

    # 分区号固定为 1（本脚本就是单分区）
    _nodeprefix="$DISK"
    case "$DISK" in
        *nvme*|*mmcblk*|*loop*) _node="${DISK}p1" ;;
        *)                      _node="${DISK}1"  ;;
    esac

    info "通知内核加载分区表..."
    if mk_partnode "$_node" "$DISK" 1; then
        ok "分区设备已出现：$_node"
    else
        # 再等一会儿（有些云盘/慢设备需要更久）
        _w=0
        while [ ! -b "$_node" ] && [ "$_w" -lt 15 ]; do
            sleep 1; _w=$((_w + 1))
        done
        [ -b "$_node" ] || die "分区设备 $_node 未能创建。
       分区表本身已写入成功，但内核没能识别出新分区。请手动执行：
           partx -a -n 1:1 $DISK     # 若报 Resource busy 就先 umount / swapoff -a
       成功后重新运行本脚本。"
        ok "分区设备已出现：$_node"
    fi
fi

# 确定分区设备名：
#   vdX / sdX / xvdX / hdX  →  X1     （例如 /dev/vda → /dev/vda1）
#   nvmeXnY / mmcblkX / loopX → Xp1   （例如 /dev/nvme0n1 → /dev/nvme0n1p1）
#
# ★ 实测教训：最初漏了 loop —— 在 loop 设备上演练时推导成了 `/dev/loop01`
#   （不存在），导致 mkfs 失败。这类命名规则必须一次列全，不能靠记忆。
case "$DISK" in
    *nvme*|*mmcblk*|*loop*) ROOT_PART="${DISK}p1" ;;
    *)                      ROOT_PART="${DISK}1"  ;;
esac
ok "根分区：$ROOT_PART"

if [ "$DRY_RUN" != "1" ]; then
    # 分区节点的创建在上一段（第 5 步）已经做完了，这里只做最终确认。
    # 之所以再查一次，是因为极慢的云盘可能在"创建成功"之后仍需几秒才真正可用。
    if [ ! -b "$ROOT_PART" ]; then
        _w=0
        while [ ! -b "$ROOT_PART" ] && [ "$_w" -lt 10 ]; do
            sleep 1; _w=$((_w + 1))
        done
    fi
    [ -b "$ROOT_PART" ] || die "分区设备 $ROOT_PART 未就绪，无法继续格式化。
       请手动执行 partx -a -n 1:1 $DISK 后重跑本脚本。"
    ok "分区设备已就绪：$ROOT_PART"
fi

info "格式化 $ROOT_PART 为 ext4"

# ★ 双保险：即使前面已经擦过整盘签名，分区节点**自己**也可能还带着旧签名
#   （分区表是全新的，但扇区里的残留内容不会因为"重新分区"就消失）。
#   mkfs.ext4 见到就会拒绝：
#       /dev/vda1 is apparently in use by the system;
#       will not make a filesystem here!
#   所以格式化之前，先对着**分区**再擦一次签名、再卸一次挂载。
if [ "$DRY_RUN" != "1" ]; then
    umount "$ROOT_PART" >/dev/null 2>&1 || true
    command -v wipefs >/dev/null 2>&1 && { wipefs -a "$ROOT_PART" >/dev/null 2>&1 || true; }

    if ! mkfs.ext4 -F -L debian "$ROOT_PART" 2>&1; then
        warn "格式化失败，可能仍被占用 —— 再尝试一次彻底释放后重做"
        umount "$ROOT_PART" >/dev/null 2>&1 || true
        swapoff -a >/dev/null 2>&1 || true
        command -v wipefs >/dev/null 2>&1 && { wipefs -a "$ROOT_PART" >/dev/null 2>&1 || true; }
        sleep 2
        mkfs.ext4 -F -L debian "$ROOT_PART" || die "格式化 $ROOT_PART 失败。
       请手动执行以下命令后重跑本脚本：
           umount $ROOT_PART
           swapoff -a
           wipefs -a $ROOT_PART
           mkfs.ext4 -F -L debian $ROOT_PART"
    fi
    ok "格式化完成（ext4）"
else
    run mkfs.ext4 -F -L debian "$ROOT_PART"
fi

# ── 第 6 步：debootstrap ─────────────────────────────────────────────────
info "第 6/9 步：释放 Debian 根文件系统"

run mkdir -p "$MOUNT_DIR"
run mount "$ROOT_PART" "$MOUNT_DIR"

info "debootstrap $DEBIAN_SUITE（从 $MIRROR，这一步最慢，请耐心等）"
run debootstrap --arch amd64 --variant=minbase \
    "$DEBIAN_SUITE" "$MOUNT_DIR" "$MIRROR"

ok "根文件系统释放完成"

# ── 决定 DNS（★ chroot 里下载和最终系统都要用，所以提前算好）──────────
# 阿里云内网 DNS 不占公网额度、解析最快；但只有确认处在阿里云内网
# （能 ping 通）时才用，否则退回公共 DNS，避免装完解析不了。
if ping -c 1 -W 2 100.100.2.136 >/dev/null 2>&1; then
    RESOLV_BODY="nameserver 100.100.2.136
nameserver 100.100.2.138"
    info "检测到阿里云内网 DNS，将使用 100.100.2.136 / 100.100.2.138"
else
    RESOLV_BODY="nameserver 223.5.5.5
nameserver 8.8.8.8"
    info "非阿里云内网环境，将使用公共 DNS 223.5.5.5 / 8.8.8.8"
fi

# ── 第 7 步：chroot 配置 ─────────────────────────────────────────────────
info "第 7/9 步：chroot 进新系统做配置"

# 把必要的虚拟文件系统挂进去，chroot 才能正常工作
for fs in dev proc sys; do
    run mount --bind "/$fs" "$MOUNT_DIR/$fs"
done

# 写 DNS，让 chroot 里也能联网下载（用上面算好的值）
if [ "$DRY_RUN" = "1" ]; then
    printf '    %s[dry-run]%s 写入 %s/etc/resolv.conf = %s\n' \
        "$c_ylw" "$c_rst" "$MOUNT_DIR" "$(printf '%s' "$RESOLV_BODY" | tr '\n' ' ')"
else
    printf '%s\n' "$RESOLV_BODY" > "$MOUNT_DIR/etc/resolv.conf"
fi

# chroot 里执行的一整套配置（写成脚本再执行，避免嵌套引号地狱）
BODY=$(cat <<CHROOT_EOF
set -eu
export DEBIAN_FRONTEND=noninteractive
export PATH=/usr/sbin:/usr/bin:/sbin:/bin

# 换镜像源（与 --mirror / MIRROR、SECURITY_MIRROR 一致）
cat > /etc/apt/sources.list <<APT_EOF
deb ${MIRROR} ${DEBIAN_SUITE} main contrib non-free non-free-firmware
deb ${MIRROR} ${DEBIAN_SUITE}-updates main contrib non-free non-free-firmware
deb ${SECURITY_MIRROR} ${DEBIAN_SUITE}-security main contrib non-free non-free-firmware
APT_EOF

apt-get update -qq

# 装最小化所需：cloud 内核 + 引导 + ssh + 基础工具
apt-get install -y --no-install-recommends \\
    linux-image-cloud-amd64 \\
    grub-pc \\
    openssh-server \\
    systemd-sysv \\
    ifupdown \\
    iproute2 \\
    ca-certificates \\
    curl \\
    wget \\
    tzdata

# 时区
ln -snf /usr/share/zoneinfo/${TIMEZONE} /etc/localtime
echo "${TIMEZONE}" > /etc/timezone

# 主机名
echo "${HOSTNAME}" > /etc/hostname
printf '127.0.0.1\\tlocalhost\\n127.0.1.1\\t%s\\n' "${HOSTNAME}" > /etc/hosts

# root 密码 + 允许 root 登录
# 密码不能直接展开进这段脚本：含 \$、反引号或引号时会被当命令执行或设错密码。
# 由外层用 printf 原样写进单独文件，这里只读文件。
chpasswd < /tmp/_rootpw
rm -f /tmp/_rootpw
sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
sed -i 's/^#\\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
[ -f /etc/ssh/sshd_config ] || echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config

# 启用 ssh 开机自启（Debian 用 systemd）
systemctl enable ssh >/dev/null 2>&1 || true

# 生成 fstab
ROOT_UUID=\$(blkid -s UUID -o value "${ROOT_PART}")
cat > /etc/fstab <<FSTAB_EOF
UUID=\${ROOT_UUID} / ext4 defaults,errors=remount-ro 0 1
FSTAB_EOF

apt-get clean
rm -rf /var/lib/apt/lists/*
CHROOT_EOF
)

if [ "$DRY_RUN" = "1" ]; then
    printf '    %s[dry-run]%s chroot 配置脚本内容：\n' "$c_ylw" "$c_rst"
    printf '%s\n' "$BODY" | sed 's/^/        /'
else
    printf '%s\n' "$BODY" > "$MOUNT_DIR/tmp/_setup.sh"
    ( umask 077; printf 'root:%s\n' "$ROOT_PWD" > "$MOUNT_DIR/tmp/_rootpw" )
    chroot "$MOUNT_DIR" /bin/sh /tmp/_setup.sh
    rm -f "$MOUNT_DIR/tmp/_setup.sh" "$MOUNT_DIR/tmp/_rootpw"
    ok "chroot 配置完成"
fi

# ── 第 8 步：网络配置 + swap ─────────────────────────────────────────────
info "第 8/9 步：写网络配置"

# 当前地址不是 DHCP 拿到的（救援系统里手工 ip addr add），新系统写 DHCP 必然失联
# （2026-11-04 修）。ip addr 对 DHCP 地址标 dynamic；没有这个标记就照当前值写静态。
if ip -4 addr show "$MAIN_IFACE" 2>/dev/null | grep 'inet ' | grep -q dynamic; then
    NET_STANZA="iface ${MAIN_IFACE} inet dhcp"
else
    NET_STANZA="iface ${MAIN_IFACE} inet static
    address ${MAIN_IP}/${MAIN_CIDR}
    gateway ${MAIN_GATE}"
    warn "当前 IPv4 不是 DHCP 获得的，新系统写入静态地址 ${MAIN_IP}/${MAIN_CIDR} 网关 ${MAIN_GATE}"
fi

NET_CFG=$(cat <<NET_EOF
# 由 alpine2debian.sh 生成
# 与阿里云官方 Debian 12 镜像保持一致的开头，方便以后往里加接口
source /etc/network/interfaces.d/*

auto lo
iface lo inet loopback

auto ${MAIN_IFACE}
${NET_STANZA}
NET_EOF
)

if [ "$DRY_RUN" = "1" ]; then
    printf '    %s[dry-run]%s /etc/network/interfaces：\n%s\n' "$c_ylw" "$c_rst" "$NET_CFG"
else
    printf '%s\n' "$NET_CFG" > "$MOUNT_DIR/etc/network/interfaces"
    ok "网络配置已写入：$(printf '%s' "$NET_STANZA" | head -n1)"
fi

if [ "$SWAP_MB" -gt 0 ]; then
    info "创建 ${SWAP_MB}MB swap 文件"
    if [ "$DRY_RUN" != "1" ]; then
        dd if=/dev/zero of="$MOUNT_DIR/swapfile" bs=1M count="$SWAP_MB" status=none
        chmod 600 "$MOUNT_DIR/swapfile"
        chroot "$MOUNT_DIR" mkswap /swapfile >/dev/null
        printf '/swapfile none swap sw 0 0\n' >> "$MOUNT_DIR/etc/fstab"
        ok "swap 已创建并写入 fstab"
    fi
else
    info "SWAP_MB=0，不创建 swap（对齐最小化系统）"
fi

# ── 第 9 步：装 GRUB ─────────────────────────────────────────────────────
info "第 9/9 步：安装 GRUB 引导（BIOS 模式）"

if [ "$DRY_RUN" = "1" ]; then
    printf '    %s[dry-run]%s grub-install --target=i386-pc %s\n' "$c_ylw" "$c_rst" "$DISK"
else
    # BIOS 模式装 GRUB 到磁盘 MBR
    chroot "$MOUNT_DIR" grub-install --target=i386-pc --recheck "$DISK" || {
        err "GRUB 安装失败，请检查 $DISK 是否为有效的 BIOS 引导目标"
        die "中止，磁盘已改动但未装引导 —— 请勿重启，先排查"
    }
    chroot "$MOUNT_DIR" update-grub >/dev/null 2>&1 || chroot "$MOUNT_DIR" grub-mkconfig -o /boot/grub/grub.cfg
    ok "GRUB 已安装到 $DISK"
fi

# ── 收尾：卸载 ───────────────────────────────────────────────────────────
info "卸载新系统文件系统"
if [ "$DRY_RUN" != "1" ]; then
    for fs in dev proc sys; do
        umount "$MOUNT_DIR/$fs" 2>/dev/null || true
    done
    sync
    umount "$MOUNT_DIR" 2>/dev/null || true
fi

printf '\n'
ok "全部完成！"
printf '\n'
info "接下来："
printf '    1. 执行 reboot 重启\n'
printf '    2. 等待 3~5 分钟\n'
printf '    3. 用新密码 SSH 登录：ssh root@<公网IP>\n'
printf '    4. 验证：cat /etc/os-release  应显示 Debian GNU/Linux 12 (bookworm)\n'
printf '\n'

if [ "$DRY_RUN" = "1" ]; then
    warn "这是预演模式，未做任何改动。去掉 --dry-run 才会真正执行。"
else
    if [ "$ASSUME_YES" = "1" ]; then
        info "非交互模式，自动重启"
        run reboot
    else
        printf '现在重启吗？输入 reboot 回车立即重启，或直接按 Ctrl+C 稍后手动重启：'
        if [ -t 0 ]; then read -r _rb || _rb=""; else read -r _rb </dev/tty || _rb=""; fi
        if [ "$_rb" = "reboot" ]; then
            info "重启中..."
            reboot
        else
            warn "未自动重启。请手动执行 reboot 使新系统生效。"
        fi
    fi
fi
