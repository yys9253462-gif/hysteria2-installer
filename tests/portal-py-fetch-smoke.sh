#!/usr/bin/env bash
# 验证门户程序的获取逻辑（两个文件：portal.py + portal_assets.py）。
#
# 门户是 Hysteria 的鉴权后端，缺任何一个文件 = 所有客户端连不上，
# 所以这条路径必须能证明：
#   1. 三源全部不可达时明确报错、中止，且**不留下半成品文件**
#   2. 语法不合法的内容被拒绝
#   3. 只有一半文件时判定为不完整
#   4. 正常路径能把两个文件都取回、通过校验，且能协同工作
set -u

# 从 install.sh 里摘出 PORTAL_FILES / METER_FILES 声明与待测函数
# （文件清单是从脚本里读出来的真实值，不是在这里另抄一份 ——
#   否则脚本改了文件清单、测试却还按旧的跑，测试就失去意义了）
PORTAL_FILES="$(sed -n 's/^PORTAL_FILES="\(.*\)"$/\1/p' install.sh | head -1)"
METER_FILES="$(sed -n 's/^METER_FILES="\(.*\)"$/\1/p' install.sh | head -1)"
if [[ -z "$PORTAL_FILES" || -z "$METER_FILES" ]]; then
    echo "❌ 没能从 install.sh 里读到 PORTAL_FILES / METER_FILES" >&2
    exit 2
fi
echo "（从 install.sh 读到 PORTAL_FILES = $PORTAL_FILES）"
echo "（从 install.sh 读到 METER_FILES  = $METER_FILES）"
echo

# 门户取文件现在还要比对 git blob 身份（2026-10-27），这三个辅助函数一并摘出来。
for fn in hy2_git_blob_sha portal_remote_blob_shas portal_verify_blobs \
          portal_files_ok portal_fetch_files portal_fetch_py portal_ensure_py; do
    eval "$(sed -n "/^${fn}() {/,/^}/p" install.sh)"
done

log_err()  { echo "  [ERR] $*"; }
log_info() { echo "  [INF] $*"; }
log_warn() { echo "  [WRN] $*"; }
HY2_DIR="$(mktemp -d)"
# portal_ensure_py 会读 HY2_CONFIG 取trafficStats secret（写计量配置用）；
# 该变量在 install.sh 头部定义，摘函数时没带进来，set -u 下会直接报unbound。
HY2_CONFIG="${HY2_DIR}/config.yaml"
# 🔴 必须造一个**含 trafficStats 段**的 config.yaml。
# portal_ensure_py 会写 usage-meter-config.json，secret 取自
# HY2_CONFIG 的 trafficStats.secret；文件不存在或缺该段时会触发
# install.sh 里的"幂等补写"逻辑，走上一条与本用例无关的代码路径，
# 使本用例以"网络失败"之名误报（2026-10-08 实测踩到：
# 明明传输正常，却报 "config.yaml 缺 trafficStats 段"）。
printf 'listen: :19999\ntrafficStats:\n  listen: 127.0.0.1:19996\n  secret: d2fb62c2c58f21920cb96f45a1e7e34f\n' \
    > "$HY2_CONFIG"

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); echo "  ✅ $*"; }
bad() { FAIL=$((FAIL+1)); echo "  ❌ $*"; }

echo "=== 1) 三源全部不可达时：报错 + 中止 + 不留半成品 ==="
export AWG_REPO="this-repo-does-not-exist-nyaa/nope"
rm -f "$HY2_DIR"/portal.py "$HY2_DIR"/portal_assets.py
out=$(portal_ensure_py 2>&1); rc=$?
[[ $rc -ne 0 ]] && ok "返回非零（rc=$rc）" || bad "竟然返回 0"
echo "$out" | grep -q '无法获取门户程序' && ok "给出了明确原因" || bad "错误信息不明确: $out"
echo "$out" | grep -q '鉴权后端' && ok "说明了后果（客户端会连不上）" || bad "没说明后果"
if [[ ! -f "$HY2_DIR/portal.py" && ! -f "$HY2_DIR/portal_assets.py" ]]; then
    ok "未留下任何半成品文件"
else
    bad "失败时仍留下了文件"
fi

echo
echo "=== 2) 语法不合法的内容必须被拒绝 ==="
bad_src=$(mktemp); printf 'def broken(:\n  pass\n' > "$bad_src"
if python3 -c 'import ast,sys; ast.parse(open(sys.argv[1], encoding="utf-8").read())' "$bad_src" 2>/dev/null; then
    bad "语法校验放过了坏文件"
else
    ok "语法校验能拦住坏文件"
fi
rm -f "$bad_src"

echo
echo "=== 3) 只有一半文件时必须判定为不完整 ==="
onlydir="$(mktemp -d)"
echo "x" > "$onlydir/portal.py"
if portal_files_ok "$onlydir"; then bad "只有 portal.py 也判成了完整"; else ok "只有一半时判定为不完整"; fi
rm -rf "$onlydir"

echo
echo "=== 4)🔴 跨目录校验：cwd ≠ 校验目录时必须仍能通过（2026-10-08 真实故障的回归测试）==="
# 这条是本文件最重要的一条。历史 bug：portal_files_ok 把【文件名】而非【路径】
# 传给 ast.parse，解析成 $PWD/xxx 而 FileNotFoundError ⇒ 校验恒失败 ⇒
# 三个源全被误判为失败 ⇒ 报「无法获取门户程序，请检查网络」，而网络完全正常。
#
# 为什么以前没抓到：旧用例 4是在**仓库根目录**跑的，而校验目标恰好也在那里，
# 裸文件名正好能解析到 ⇒ 假绿。凡是校验"文件路径"的逻辑，
# 都必须在 cwd 与目标目录**不同**的条件下测，否则等于没测。
_cwd_before="$PWD"
_probe="$(mktemp -d)"
cp portal.py portal_assets.py $METER_FILES "$_probe/" 2>/dev/null
mkdir -p "$_probe/sub" && cd "$_probe/sub" || { echo "无法创建探针目录"; exit 2; }
if portal_files_ok "$_probe"; then
    ok "cwd 与校验目录不同时校验通过"
else
    bad "cwd 与校验目录不同时校验失败 —— 又把文件名当路径传了？"
fi
# 反向验证：故意破坏其中一个计量模块的语法，跨目录也必须被拦住
printf 'def broken(:\n  pass\n' > "$_probe/${METER_FILES%% *}"
if portal_files_ok "$_probe"; then
    bad "计量模块语法坏了却判成通过（跨目录场景漏检）"
else
    ok "跨目录下也能拦住计量模块的语法错误"
fi
cd "$_cwd_before" || exit 2
rm -rf "$_probe"

echo
echo "=== 5) 🔴 报错必须区分「网络拉取失败」与「校验不通过」（不能一律说请检查网络）==="
export AWG_REPO="yys9253462-gif/hysteria2-installer"
errdir="$(mktemp -d)"
# 把 portal_files_ok 临时替换成永远失败，以模拟"取回但校验不过"
_real_ok="$(declare -f portal_files_ok)"
eval "portal_files_ok() { return 1; }"
portal_fetch_py "$errdir" >/dev/null 2>&1; rc=$?
eval "$_real_ok"
[[ $rc -ne 0 ]] && ok "校验全失败时返回非零" || bad "校验全失败却返回 0"
[[ "$PORTAL_FETCH_ALL_VERIFY_FAILED" == "1" ]] \
    && ok "被标记为校验类失败（不是网络类）" || bad "未区分校验失败与网络失败"
# 三个源的名字必须都出现在逐源原因里
for _s in "GitHub API" "jsDelivr" "raw.githubusercontent"; do
    [[ "$PORTAL_FETCH_ERR" == *"$_s"* ]] \
        && ok "逐源原因含 [$_s]" || bad "逐源原因缺少 [$_s]：$PORTAL_FETCH_ERR"
done
# 对照组：源不可达时不能被标成校验类失败
PORTAL_FETCH_ALL_VERIFY_FAILED=99
export AWG_REPO="this-repo-does-not-exist-nyaa/nope"
portal_fetch_py "$errdir" >/dev/null 2>&1
[[ "$PORTAL_FETCH_ALL_VERIFY_FAILED" == "0" ]] \
    && ok "网络不可达时被正确归类为网络类（未被误判成校验问题）" \
    || bad "网络不可达却标成校验失败，会把排查带偏"
export AWG_REPO="yys9253462-gif/hysteria2-installer"
rm -rf "$errdir"

echo
echo "=== 6) 正常路径：全部文件都取回、通过校验、能协同工作 ==="
export AWG_REPO="yys9253462-gif/hysteria2-installer"
if out=$(portal_ensure_py 2>&1); then
    ok "获取成功"
    for f in portal.py portal_assets.py; do
        if [[ -s "$HY2_DIR/$f" ]]; then
            ok "$f 已就位（$(wc -c < "$HY2_DIR/$f") 字节）"
        else
            bad "$f 缺失"
        fi
    done
    # 计量模块必须一起落地：缺任何一个，portal 都会永久降级为「未开始计量」，
    # 而安装照样成功 —— 这种静默故障必须在这里拦住
    for f in $METER_FILES; do
        if [[ -s "$HY2_DIR/$f" ]]; then
            ok "$f 已就位（$(wc -c < "$HY2_DIR/$f") 字节）"
        else
            bad "$f 缺失（会让计量永久降级且不报错）"
        fi
    done
    grep -q 'def page_html' "$HY2_DIR/portal.py" \
        && ok "portal.py关键标记在位" || bad "portal.py 内容不对"
    grep -q 'SCRIPT = r' "$HY2_DIR/portal_assets.py" \
        && ok "portal_assets.py 关键标记在位（JS 仍是原始字符串）" || bad "portal_assets.py 内容不对"
    if python3 -c "
import sys; sys.path.insert(0, '${HY2_DIR}')
import portal
assert portal.SCRIPT and portal.STYLE, '常量没引进来'
" 2>/dev/null; then
        ok "两者可以一起 import，常量正常可用"
    else
        bad "两个文件不能协同工作"
    fi
else
    bad "正常路径失败了（网络？）: $out"
    echo "$out" | sed 's/^/      /'
fi

rm -rf "$HY2_DIR"
echo
echo "================ 结果 ================"
echo "  通过: $PASS   失败: $FAIL"
[[ $FAIL -eq 0 ]]
