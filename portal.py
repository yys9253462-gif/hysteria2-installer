"""仅监听回环地址；公网 TLS 由 Hysteria 的 masquerade proxy 提供。
采用现代轻奢 Tab 导航系统，解耦节点连接、多用户管理（支持 IP 限制与实时流量统计）与集群 API 凭据。
"""
import ast
import copy
import base64
import hashlib
import hmac
import html
import json
import math
import importlib.util
import ipaddress
import os
import platform
import random
import re
import secrets
import select
import shlex
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import http.client
import urllib.error
import urllib.request
import uuid
import zipfile
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, HTTPServer
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from socketserver import ThreadingMixIn
from urllib.parse import parse_qs, quote, urlencode

try:
    import fcntl
except ImportError:  # Windows 非服务开发环境；生产部署使用 Linux flock。
    fcntl = None

# 前端资源（CSS / 内嵌 JS）拆到了独立模块 portal_assets.py。
# ⚠️ 部署时门户是**六个文件**：portal.py + portal_assets.py + 四个计量模块
# （见 PORTAL_BUNDLE_FILES）。它们必须整组存在、整组更新 ——
# 见 install.sh 的 portal_ensure_py / portal_files_ok。
# 这里 import 进来后，portal.STYLE / portal.SCRIPT 等名字依然照常可用，
# 所以 content_policy()、page_html() 与既有测试都不需要改。
try:
    from portal_assets import STYLE, SCRIPT, LOGIN_SCRIPT, USER_SCRIPT
except ImportError as _e:      # pragma: no cover - 只在部署缺文件时触发
    raise SystemExit(
        '缺少 portal_assets.py —— 门户由 portal.py、portal_assets.py 与四个计量模块组成，\n'
        '它们必须放在同一目录下（通常都是 /etc/hysteria/）。\n'
        '原始错误: %s\n'
        '修复：重新执行一次安装 / 更新（bash install.sh install 或门户里的「更新」）。' % _e
    ) from _e

# ---- GitHub API token（可选，2026-10-28）----
#
# GitHub 匿名 API 每个公网 IP 每小时只有 60 次，同机其它程序（实测 tokyo 上的
# agent2api 更新检查）会把它耗光，面板的版本检测 / 自更新随之失败。
# 把一个只读 token 放进 GITHUB_TOKEN_FILE 后，所有发往 api.github.com 的请求
# 按账号计额度（5000 次/小时）。只给 api.github.com 加，镜像与下载站一律不带；
# 用 unredirected header，跳转到别的主机时不会被转发。
GITHUB_TOKEN_FILE = Path('/etc/hysteria/github-token')
_github_token_cache = {'mtime': None, 'token': ''}


def github_token():
    """读取 token（按 mtime 缓存）；文件不存在、为空或格式不对时返回空串。"""
    try:
        mtime = GITHUB_TOKEN_FILE.stat().st_mtime
    except OSError:
        _github_token_cache.update(mtime=None, token='')
        return ''
    if mtime != _github_token_cache['mtime']:
        # 权限必须足够严：token 等同于账号凭据，0644 时同机其它用户可以读走。
        # 之前只校验字符集，权限过宽的文件照常被使用（2026-10-29 修）。
        try:
            mode = GITHUB_TOKEN_FILE.stat().st_mode & 0o777
        except OSError:
            mode = 0
        # 只在 POSIX 上检查：Windows 没有对应的权限位语义，
        # stat() 恒返回 0666，照此判断会让所有 Windows 环境都无法使用 token。
        if os.name == 'posix' and mode and mode & 0o077:
            print('[portal] %s 权限为 %o，应改为 600；本次忽略该 token'
                  % (GITHUB_TOKEN_FILE, mode), file=sys.stderr)
            _github_token_cache.update(mtime=mtime, token='')
            return ''
        try:
            value = GITHUB_TOKEN_FILE.read_text(encoding='utf-8').strip()
        except OSError:
            value = ''
        # 只接受 token 字符集，防止把换行等注入到请求头里。
        _github_token_cache.update(mtime=mtime,
                                   token=value if re.fullmatch(r'[A-Za-z0-9_]{20,255}', value) else '')
    return _github_token_cache['token']


class GitHubTokenHandler(urllib.request.BaseHandler):
    """只给发往 api.github.com 的请求加 Authorization。"""
    handler_order = 400

    def https_request(self, req):
        if req.host.split(':')[0].lower() == 'api.github.com' and not req.has_header('Authorization'):
            token = github_token()
            if token:
                req.add_unredirected_header('Authorization', 'Bearer ' + token)
        return req


urllib.request.install_opener(urllib.request.build_opener(GitHubTokenHandler()))

# 机主账号。它的 password 就是 Hysteria 的 auth_password —— /auth 是遍历
# data['users'] 按密码匹配的，这条记录一旦被删，主密码立刻变成 "User not found"，
# 机主本人都会被踢下线且再也连不上（只能重装）。因此全站禁止注销它。
MASTER_USER_ID = 'admin_master'
# 保留名：三种协议的 clients 在「没有任何活跃用户」时都会写一条
# email='placeholder' 的占位记录（Xray 的 clients 为空会拒绝所有连接）。
# 若允许真实用户叫这个名字，其流量会与占位记录聚合到同一 email，
# 统计串号、按 email 收回时也会误伤。与机主账号同样禁止。
RESERVED_USER_IDS = frozenset({MASTER_USER_ID, 'placeholder'})
# user_id 的唯一格式定义。serve() 内沿用同名局部变量指向它，
# 模块级辅助函数（撤销队列清洗等）也用它，避免两套规则漂移。
USER_ID_RE = re.compile(r'^[a-zA-Z0-9_\-\.]{1,64}$')
# 面板自更新与 AWG 资源的来源仓库（模块级：resolve_update_ref 也要用）。
AWG_REPO = 'yys9253462-gif/hysteria2-installer'

# 节点门户的版本号（2026-10-04 加）。
#
# 用途：主控面板要靠它判断「这台节点跑的是新 portal 还是老 portal」——
# 老门户没有 capabilities 端点、没有多用户 Reality，功能表现完全不同。
# 之前只能靠 SSH 上去 grep 源码，主面板看不见。
#
# ⚠️ 改动 portal.py 的**能力**时记得同步 +1，否则主面板会按旧能力显示。
# 格式固定 `PORTAL_VERSION = 'x.y'`（capabilities 端点按行首匹配解析它）。
PORTAL_VERSION = '2.9'

# ---------------------------------------------------------------------------
# 流媒体 / AI 解锁检测（2.8，GET /api/v1/unlock-check）
#
# 判据参考社区通用的 RegionRestrictionCheck 思路，只用标准库 urllib，
# 不依赖 curl。每项返回 status：
#   yes      可用
#   partial  部分可用（如 Netflix 仅自制剧）
#   no       不可用 / 被识别为代理
#   unknown  检测失败（超时、网络错误）—— 与 no 区分，别把"没测成"说成"不解锁"
# ---------------------------------------------------------------------------
_UNLOCK_UA = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
              '(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36')


def _unlock_read(resp, limit):
    # 分块传输被对端提前断开时 read() 会抛 IncompleteRead —— 判据只看页面里
    # 的几个标记，拿到的部分内容已经够用，不能因此把整项判成「检测失败」。
    try:
        raw = resp.read(limit)
    except http.client.IncompleteRead as e:
        raw = e.partial
    return raw.decode('utf-8', 'replace')


def _unlock_fetch(url, timeout=8, limit=400000):
    """返回 (status_code, final_url, body_text)。HTTP 错误码也正常返回，网络错误抛异常。"""
    req = urllib.request.Request(url, headers={'User-Agent': _UNLOCK_UA, 'Accept-Language': 'en-US,en;q=0.9'})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.geturl(), _unlock_read(resp, limit)
    except urllib.error.HTTPError as e:
        try:
            body = _unlock_read(e, 200000)
        except Exception:
            body = ''
        return e.code, e.geturl() or url, body


def _unlock_netflix():
    code_full, _, _ = _unlock_fetch('https://www.netflix.com/title/81280792')
    code_orig, final, _ = _unlock_fetch('https://www.netflix.com/title/80018499')
    m = re.search(r'netflix\.com/([a-z]{2})(?:-[a-z]{2})?/title', final or '')
    region = m.group(1).upper() if m else ''
    if code_full == 200:
        return 'yes', region or 'US', '完整解锁'
    if code_orig == 200:
        return 'partial', region or 'US', '仅自制剧'
    return 'no', '', 'HTTP %s' % code_orig


def _unlock_disney():
    code, final, _ = _unlock_fetch('https://www.disneyplus.com/')
    if 'unavailable' in (final or '') or code == 403:
        return 'no', '', '地区不可用'
    m = re.search(r'disneyplus\.com/(?:[a-z]{2}-)?([a-z]{2})(?:/|$)', final or '')
    if code >= 400:
        return 'no', '', 'HTTP %s' % code
    return 'yes', (m.group(1).upper() if m else ''), ''


def _unlock_youtube():
    _, _, body = _unlock_fetch('https://www.youtube.com/premium')
    if 'Premium is not available in your country' in body:
        return 'no', '', 'Premium 地区不可用'
    m = re.search(r'"(?:countryCode|GL)":"([A-Z]{2})"', body)
    region = m.group(1) if m else ''
    if region == 'CN':
        return 'no', 'CN', '送中'
    return 'yes', region, ''


def _unlock_chatgpt():
    _, _, comp = _unlock_fetch('https://api.openai.com/compliance/cookie_requirements')
    _, _, ios = _unlock_fetch('https://ios.chat.openai.com/')
    _, _, trace = _unlock_fetch('https://chatgpt.com/cdn-cgi/trace')
    m = re.search(r'^loc=([A-Z]{2})', trace, re.M)
    region = m.group(1) if m else ''
    blocked_region = 'unsupported_country' in comp
    vpn = 'VPN' in ios
    if blocked_region:
        return 'no', region, '地区不支持'
    if vpn:
        return 'partial', region, '网页可用，App 识别为 VPN'
    return 'yes', region, ''


def _unlock_claude():
    code, final, _ = _unlock_fetch('https://claude.ai/')
    if 'app-unavailable-in-region' in (final or ''):
        return 'no', '', '地区不可用'
    # 403 是 Cloudflare 人机校验，说明请求到了 claude.ai 而不是被地区拦截。
    if code < 400 or code == 403:
        return 'yes', '', ''
    return 'no', '', 'HTTP %s' % code


def _unlock_gemini():
    # 页面约 800KB，开关标记在中段，读取上限要放宽。
    # 标记有新旧两种写法：`45631641,null,true` 与 `45631641\":true`。
    _, _, body = _unlock_fetch('https://gemini.google.com/', limit=2000000)
    if re.search(r'45631641(?:,null,|\\?":)true', body):
        return 'yes', '', ''
    return 'no', '', '地区不可用'


UNLOCK_CHECKS = (
    ('netflix', 'Netflix', _unlock_netflix),
    ('disney', 'Disney+', _unlock_disney),
    ('youtube', 'YouTube Premium', _unlock_youtube),
    ('chatgpt', 'ChatGPT', _unlock_chatgpt),
    ('claude', 'Claude', _unlock_claude),
    ('gemini', 'Gemini', _unlock_gemini),
)


def run_unlock_checks():
    results = [None] * len(UNLOCK_CHECKS)

    def work(i, key, name, fn):
        try:
            status, region, note = fn()
        except Exception as e:
            status, region, note = 'unknown', '', '检测失败：%s' % (type(e).__name__)
        results[i] = {'key': key, 'name': name, 'status': status, 'region': region, 'note': note}

    threads = [threading.Thread(target=work, args=(i, k, n, f), daemon=True)
               for i, (k, n, f) in enumerate(UNLOCK_CHECKS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    return [r or {'key': k, 'name': n, 'status': 'unknown', 'region': '', 'note': '检测超时'}
            for r, (k, n, _) in zip(results, UNLOCK_CHECKS)]

DEFAULT_WARP_DOMAINS = (
    'ipify.org', 'cloudflare.com',
    'openai.com', 'chatgpt.com', 'oaistatic.com', 'oaiusercontent.com', 'ai.com',
    'anthropic.com', 'claude.ai',
    'gemini.google.com', 'aistudio.google.com', 'generativelanguage.googleapis.com',
)


def strip_acl_block(text):
    """去掉 Hysteria config.yaml 里的 acl: 块，保留其余【所有】内容。

    🔴 为什么必须只删 acl 块、而不能"从 acl: 一路删到文件尾"：
    `install.sh` 是把 `obfs` 段**追加在配置末尾**的，也就是排在 `acl:` 之后。
    原实现一路删到底，会连混淆配置一起删掉 —— 服务端不再有 obfs，而客户端
    仍带着 salamander 混淆去连，QUIC 握手直接超时。现象是「能连上但没网」，
    而且**服务端一行日志都没有**，极难定位（真实事故：门户里点一下 WARP 开关
    就把线上节点的 Hysteria 打成了这样）。

    acl 块的范围：从顶格的 `acl:` 起，到下一个顶格（非空、非注释）行之前为止。
    """
    out, i = [], 0
    # config.yaml 读取失败或调用方传错时 text 可能不是字符串：
    # split 抛 AttributeError，而这条路径在「应用出站配置」上。
    if not isinstance(text, str):
        return ''
    lines = text.split('\n')
    n = len(lines)
    while i < n:
        line = lines[i]
        if line[:1] not in (' ', '\t') and line.strip().startswith('acl:'):
            i += 1
            while i < n:
                nxt = lines[i]
                if nxt.strip() and nxt[:1] not in (' ', '\t'):
                    break
                i += 1
            continue
        out.append(line)
        i += 1
    while out and not out[-1].strip():
        out.pop()
    return '\n'.join(out)


# ==============================================================================
# 自定义出站（Custom Outbounds）核心模块
# ==============================================================================
#
# 为什么需要它：原来面板只有 WARP 这一个固定出站，且只能"按域名分流"。
# 用户真正的需求是"把所有流量走某个代理"（全局出站）或
# "让特定域名走自定义 http/socks5 代理"，两者都无法表达。
#
# 三条硬约束（都是踩出来的，写错了Hysteria 直接起不来）：
#   1. 🔴 出站名不能含 `-`。ACL 里用 `名称(suffix:xxx)` 引用，
#      带横线的名字会被解析歧义，导致规则匹配不到（表现为"配了没生效"）。
#      所以下面统一用下划线命名。
#   2. 🔴 ACL 末尾必须有一条兜底规则（通常是 `direct(all)`），
#      否则未被任何规则覆盖的连接会走 outbounds 列表里的**第一个**出站，
#      而那不一定是用户想要的那个。
#   3. 🔴 ACL 引用了不存在的出站名 ⇒ Hysteria 启动失败
#      （`outbound xxx not found`）。所以写完必须真重启并校验 is-active，
#      失败立刻回滚 —— 一个开关不该把整台机器的 Hysteria 打挂。
#
# Hysteria 2 官方只支持三种出站类型：
#   direct / socks5(addr, username, password) / http(url, insecure)
# ⚠️ http 出站在协议层不支持 UDP，UDP 流量走它会被拒绝。

# 出站类型白名单：不在其中的类型一律拒绝，避免用户填错导致启动失败
OUTBOUND_TYPES = {
    'direct': ('直接连接（服务器本地网络）', None),
    'socks5': ('SOCKS5 代理', ('addr', 'username', 'password')),
    'http': ('HTTP / HTTPS 代理', ('url', 'insecure')),
}

# 出站名的合法字符：🔴 只允许字母数字与下划线，禁止横线（见文件头约束 1）
OUTBOUND_NAME_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]{0,31}$')


def sanitize_outbound_name(raw):
    """把用户输入的出站名规范化成合法标识符。

    🔴 不能只做正则校验然后拒绝——用户输入 "my-proxy" 时直接报错体验很差。
    这里做确定性转换：非字母数字一律换成下划线，再补上"out_" 前缀避免
    与 direct / warp_socks 这类内建名冲突。
    """
    s = re.sub(r'[^A-Za-z0-9_]', '_', str(raw or '').strip())
    s = re.sub(r'_+', '_', s).strip('_')
    if not s:
        return ''
    if not re.match(r'^[A-Za-z_]', s):
        s = 'out_' + s
    if s.lower() in ('direct', 'direct_ipv4', 'warp', 'warp_socks'):
        s = 'out_' + s
    return s[:32]


def validate_outbound(entry):
    """校验一条自定义出站配置，返回 (ok, cleaned, error)。

    校验失败必须给出**可执行**的提示，而不是"参数错误"这种废话——
    用户是自己填的，得告诉他哪一栏不对、正确格式是什么。
    """
    # 表单/JSON 里的字段可能是数字或列表：`.strip()` 直接抛 AttributeError，
    # 而调用点没有兜底 —— 一次手滑填成数字就让「保存出站」500，提示也没有。
    if not isinstance(entry, dict):
        return False, None, "出站配置必须是一个对象"
    raw_type = entry.get('type')
    otype = raw_type.strip().lower() if isinstance(raw_type, str) else ''
    if otype not in OUTBOUND_TYPES:
        return False, None, "类型只能是 direct / socks5 / http 之一"
    name = sanitize_outbound_name(entry.get('name'))
    if not name:
        return False, None, "名称不能为空"
    if not OUTBOUND_NAME_RE.match(name):
        return False, None, "名称只能含字母数字与下划线，且不能以数字开头"

    cleaned = {'name': name, 'type': otype}

    if otype == 'socks5':
        raw_addr = entry.get('addr')
        addr = raw_addr.strip() if isinstance(raw_addr, str) else ''
        # 必须带端口；只给域名或IP 是不够的
        if not re.match(r'^[^\s:]+:\d{1,5}$', addr):
            return False, None, "SOCKS5 地址格式应为 host:port，例如 1.2.3.4:1080"
        host, port = addr.rsplit(':', 1)
        if not (0 < int(port) < 65536):
            return False, None, "端口超出范围"
        cleaned['addr'] = addr
        # 账号密码会**逐字拼进 YAML**（render_outbound_yaml），
        # 含换行、# 或引号时会破坏配置结构（2026-10-24 补校验）。
        # 只放行代理凭据实际会用到的可见 ASCII，其余一律拒绝并说明。
        for field in ('username', 'password'):
            if entry.get(field):
                # 必须是字符串：列表/数字被 str() 成 "['x']" / "123" 之后同样
                # 满足可见 ASCII 校验，于是面板显示 password 已保存，客户端却
                # 拿着完全不同的凭据去握手 —— 只报鉴权失败，查不出原因。
                raw = entry[field]
                if not isinstance(raw, str):
                    return False, None, '%s 必须是字符串' % field
                value = raw.strip()
                if not re.fullmatch(r'[!-~]{1,128}', value):
                    return False, None, '%s 只能包含可见 ASCII 字符（不含空格与换行），长度 1-128' % field
                cleaned[field] = value

    elif otype == 'http':
        raw_url = entry.get('url')
        url = raw_url.strip() if isinstance(raw_url, str) else ''
        # 路径里也不允许空白：旧正则的 `.*` 允许空格，带空格的 URL
        # curl 会直接拒绝，而配置照样写进 YAML（2026-10-30 修）。
        if not re.match(r'^https?://[^\s/]+(?:/.*)?$', url, re.I) or re.search(r'\s', url):
            return False, None, "HTTP 代理地址格式应为 http://host:port 或 https://host:port（不能含空格）"
        cleaned['url'] = url
        # insecure 只接受明确的一串真值，其他一律当false（别把 "no" 当 true）
        cleaned['insecure'] = str(entry.get('insecure', '')).strip().lower() in ('1', 'true', 'yes', 'on')

    else:  # direct
        raw_mode = entry.get('mode')
        if raw_mode not in (None, '') and not isinstance(raw_mode, str):
            # 数字 5 被静默当成 auto，用户以为限定了 IPv4/IPv6 家族，
            # 实际按 auto 出去 —— 与「已保存」的提示矛盾。
            return False, None, "direct 模式必须是字符串"
        mode = raw_mode.strip() if isinstance(raw_mode, str) else ''
        if mode and mode not in ('auto', '64', '46', '6', '4'):
            return False, None, "direct 模式只能是 auto / 64 / 46 / 6 / 4 之一"
        if mode:
            cleaned['mode'] = mode

    return True, cleaned, ''


def _yaml_scalar(value):
    """把任意字符串安全地渲染成 YAML 单引号标量。

    校验层只要求「可见 ASCII」，但 `*`（别名）、`{`/`[`（流式集合）、
    `&`（锚点）、`%`（指令）开头的值直接拼进 YAML 会让整份配置解析失败 ——
    Hysteria 起不来，用户只看到「应用失败」却不知道是密码写法的问题。
    单引号标量里只需把 `'` 写成 `''`。
    """
    return "'" + str(value).replace("'", "''") + "'"



_OUTBOUND_NAME_LINE_RE = re.compile(r"^\s*-\s*name:\s*(.+?)\s*$")


def _yaml_name_value(raw):
    """把 `- name: xxx` 里的值还原成真正的名字。

    render_outbound_yaml 现在给值加单引号（防 YAML 注入），解析时必须把
    引号去掉，否则 ACL 里引用 'my_proxy' 与规则里的 my_proxy 对不上
    （2026-10-29 修）。
    """
    value = str(raw or '').strip()
    if len(value) >= 2 and value[0] == value[-1] == "'":
        return value[1:-1].replace("''", "'")
    if len(value) >= 2 and value[0] == value[-1] == '"':
        return value[1:-1].replace('\\"', '"')
    return value


def outbound_names_in(text):
    """按出现顺序返回配置里所有出站名（已去引号）。"""
    # 非字符串（快照被改坏）直接当空：findall 对 int/list 抛 TypeError。
    if not isinstance(text, str):
        return []
    # 必须带 re.M：否则 ^/$ 只匹配整串的开头结尾，一行都提取不到。
    return [_yaml_name_value(m)
            for m in re.findall(_OUTBOUND_NAME_LINE_RE.pattern, text or '', re.M)]

def clean_outbounds(outbounds):
    """只保留结构完整的出站条目；容器被改坏时返回空表。

    custom_outbounds 是用户可写的 JSON，旧版本还允许直接改 portal.json。
    渲染时 `entry['type']` 对 None / 字符串 / 缺字段会抛
    TypeError/KeyError，而调用点在 apply_egress_config 里 —— 一次坏数据就让
    WARP 与出站配置永久无法应用，界面只显示「应用失败」。
    """
    if not isinstance(outbounds, (list, tuple)):
        return []
    # 名称必须同时满足标识符规则：旧版本允许直接改 portal.json，历史数据里
    # 可能留着带换行的名字 —— 它会让 render_outbound_yaml 写出一段结构错乱
    # 的 YAML（后续每一行都被当成新内容），Hysteria 起不来。
    return [ob for ob in outbounds
            if isinstance(ob, dict) and ob.get('type') in OUTBOUND_TYPES
            and isinstance(ob.get('name'), str)
            and OUTBOUND_NAME_RE.match(ob['name'])]


def render_outbound_yaml(entry):
    """把一条出站配置渲染成 YAML 片段（缩进与 config.yaml 风格一致）。"""
    otype = entry['type']
    lines = ['  - name: %s' % _yaml_scalar(entry['name']),
             '    type: %s' % otype]
    if otype == 'socks5':
        lines.append('    socks5:')
        lines.append('      addr: %s' % _yaml_scalar(entry['addr']))
        if entry.get('username'):
            lines.append('      username: %s' % _yaml_scalar(entry['username']))
        if entry.get('password'):
            lines.append('      password: %s' % _yaml_scalar(entry['password']))
    elif otype == 'http':
        lines.append('    http:')
        lines.append('      url: %s' % _yaml_scalar(entry['url']))
        lines.append('      insecure: %s' % ('true' if entry.get('insecure') else 'false'))
    elif otype == 'direct':
        lines.append('    direct:')
        lines.append('      mode: %s' % (entry.get('mode') or 'auto'))
    return '\n'.join(lines)


def upsert_outbound_block(cfg_text, outbounds):
    """把自定义出站写进 config.yaml 的 outbounds 段，保留内建出站。

    内建出站（direct_ipv4 / warp_socks / warp）由 install.sh 写入，
    **必须保留**：ACL 里可能引用它们，且 direct_ipv4 承担"强制 IPv4"的意图。
    这里只做两件事：删掉上一次由本模块写入的出站（靠内建白名单排除），
    再追加新的。
    """
    text = strip_managed_outbounds(cfg_text)
    if not outbounds:
        return text

    block = '\n'.join(render_outbound_yaml(ob) for ob in clean_outbounds(outbounds))
    if 'outbounds:' in text:
        # 插到 outbounds 段的末尾（顶格行的下一行起）
        lines = text.split('\n')
        idx = next((i for i, l in enumerate(lines) if l.startswith('outbounds:')), None)
        if idx is None:
            text = text.rstrip('\n') + '\noutbounds:\n' + block + '\n'
        else:
            # 找 outbounds: 之后第一个顶格行，在它前面插入
            insert_at = len(lines)
            for j in range(idx + 1, len(lines)):
                s = lines[j]
                if s.strip() and s[:1] not in (' ', '\t'):
                    insert_at = j
                    break
            new_lines = lines[:insert_at] + block.split('\n') + lines[insert_at:]
            text = '\n'.join(new_lines)
    else:
        text = text.rstrip('\n') + '\n\noutbounds:\n' + block + '\n'
    return text.rstrip('\n') + '\n'


def strip_managed_outbounds(cfg_text):
    """移除上一次由本模块写入的自定义出站。

    🔴 判定方式不能靠"名字带 out_ 前缀" —— sanitize_outbound_name 只在
    名字与内建名冲突时才加前缀，用户输入 "my-proxy" 规范化后是 "my_proxy"
    （不带前缀）。按前缀过滤会漏掉它，导致每保存一次就重复追加一条，
    最终配置里出现多个同名出站，Hysteria 启动失败。

    正确做法：**用内建出站白名单排除**，其余带缩进的出站项一律视为
    自定义（自定义出站是本模块独占管理的，install.sh 不会写它们）。
    """
    builtin = {'direct', 'direct_ipv4', 'warp', 'warp_socks'}
    # 非字符串（拼接前的快照被改坏）直接当空配置：split 会抛 AttributeError，
    # 而调用点在「应用出站配置」路径上。
    if not isinstance(cfg_text, str):
        return ''
    lines = cfg_text.split('\n')
    out = []
    skipping = False
    for line in lines:
        m = _OUTBOUND_NAME_LINE_RE.match(line)
        if m:
            name = _yaml_name_value(m.group(1))
            # 内建出站：不跳过，继续保留
            skipping = name not in builtin
            if skipping:
                continue
            out.append(line)
            continue
        if skipping:
            # 出站项的字段都是缩进的；遇到顶格行说明这一项结束了
            if line.strip() and line[:1] not in (' ', '\t'):
                skipping = False
            else:
                continue
        out.append(line)
    return '\n'.join(out)


# 安全：代理用户不得访问节点本机/内网/云元数据（如 127.0.0.1 上的面板、
# Docker 网段、169.254.169.254）。所有生成的 ACL 都以这些 reject 开头。
PRIVATE_REJECT_RULES = ['127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16', '100.64.0.0/10', '0.0.0.0/8', '::1/128', 'fc00::/7', 'fe80::/10']



# Xray 侧的对应拦截（2026-10-24 补）。
#
# Hy2 走 config.yaml 的 ACL，一直有 reject 内网规则；但 Xray 承载的
# Reality / VMess / VLESS Encryption 三个入站此前是裸 freedom 出站 ——
# 代理用户可以借它们访问 127.0.0.1 上的门户端口、169.254.169.254 云元数据、
# Docker / 内网网段，等于绕开了 2026-10-18 针对 Hy2 的那次加固。
#
# 规则用 routing.rules 的 ip 匹配（不是 domain）：即使客户端不做 DNS 解析、
# 直接连 IP 也能挡住。block 出站排在 freedom 之前，且是 blackhole。
XRAY_PRIVATE_REJECT_IPS = [c for c in PRIVATE_REJECT_RULES]
XRAY_BLOCK_OUTBOUND_TAG = 'block-private'


def add_private_network_guard(config):
    """给 Xray 配置补「拒绝访问内网 / 云元数据」的路由与黑洞出站。

    幂等：重复调用不会重复追加规则或出站。
    """
    if not isinstance(config, dict):
        return config
    outbounds = config.setdefault('outbounds', [])
    if not isinstance(outbounds, list):
        outbounds = config['outbounds'] = []
    if not outbounds:
        outbounds.append({'protocol': 'freedom', 'tag': 'direct'})
    if not any(isinstance(o, dict) and o.get('tag') == XRAY_BLOCK_OUTBOUND_TAG
               for o in outbounds):
        # 黑洞必须排在 freedom 之后，否则会变成默认出站，把正常流量也吞掉。
        outbounds.append({'protocol': 'blackhole', 'tag': XRAY_BLOCK_OUTBOUND_TAG})
    routing = config.setdefault('routing', {})
    if not isinstance(routing, dict):
        routing = config['routing'] = {}
    rules = routing.setdefault('rules', [])
    if not isinstance(rules, list):
        rules = routing['rules'] = []
    guard = {'type': 'field', 'ip': list(XRAY_PRIVATE_REJECT_IPS),
             'outboundTag': XRAY_BLOCK_OUTBOUND_TAG}
    # 先拒内网，再走其它规则 —— 但计量 API 的回环规则例外，必须排在拦截之前
    # （2026-10-28 修）。原来拦截规则 insert(0) 压在 API 规则前面：发往 127.0.0.1:19997
    # 的统计调用全部命中 127.0.0.0/8 进黑洞，Reality 计量与设备上限静默失效。
    # API 规则只匹配本地 dokodemo 入站，排最前不放行任何用户流量。
    # api 段被改成数字/字符串时 `.get` 抛 AttributeError，而这条路径在
    # 「重生成 Reality / VMess / VLESS-Enc 入站」的锁内 —— 协议启停整轮失败。
    api_section = config.get('api')
    api_tag = api_section.get('tag') if isinstance(api_section, dict) else None
    api_rules = [r for r in rules if isinstance(r, dict) and api_tag and r.get('outboundTag') == api_tag]
    others = [r for r in rules if r != guard and r not in api_rules]
    routing['rules'] = api_rules + [guard] + others
    return config

def _acl_head():
    return ['acl:', '  inline:'] + ['    - reject(%s)' % c for c in PRIVATE_REJECT_RULES]


def build_acl_block(mode, rules, outbounds, tail_outbound='direct', existing_names=None):
    """生成 acl.inline 块。

    mode='global'：全部流量走选中的出站（真正的"全局出口"）
    mode='rules' ：名单内走对应出站，其余走 tail_outbound（传统分流）

    🔴 两种模式最后都补一条兜底，否则未匹配的连接会落到 outbounds
    列表第一个出站上——那通常是内建 direct_ipv4，行为不可控。
    """
    # 入参来自 render_egress_config 的快照，但也可能被直接调用（测试、旧路径）
    # 传进损坏值：数字会让 `for ... in 7` 抛 TypeError，条目是字符串时
    # `.get` 抛 AttributeError —— 都在「应用配置」路径上。
    outbounds = clean_outbounds(outbounds)
    names = [ob['name'] for ob in (outbounds or [])]
    existing = set(_existing_outbound_names() if existing_names is None else existing_names)
    available = set(names) | existing | {'direct', 'reject'}
    acl = _acl_head()

    if mode == 'global' and names:
        acl.append('    - %s(all)' % names[0])
        return '\n'.join(acl)

    if not isinstance(rules, (list, tuple)):
        rules = ()
    for r in rules:
        if not isinstance(r, dict):
            continue
        raw_dom = r.get('domain')
        dom = raw_dom.strip().lower() if isinstance(raw_dom, str) else ''
        if not dom:
            continue
        target = r.get('outbound') or ''
        # 出站可能已被用户删除 —— 引用不存在的名字会让 Hysteria 起不来
        if target not in available:
            target = 'warp_socks' if 'warp_socks' in existing else tail_outbound
        acl.append('    - %s(suffix:%s)' % (target, dom))

    acl.append('    - %s(all)' % tail_outbound)
    return '\n'.join(acl)


def _existing_outbound_names():
    """读当前 config.yaml 里已存在的出站名（供兜底判断用）。"""
    try:
        cfg = Path('/etc/hysteria/config.yaml').read_text(encoding='utf-8')
    except Exception:
        return []
    return outbound_names_in(cfg)


def outbound_target_exists(target, outbounds=None, existing_names=None):
    target = str(target or '').strip()
    if target in ('direct', 'reject'):
        return True
    # 容器被改成数字时 `for o in 7` 抛 TypeError，位置在 rule-add 的锁内，
    # 用户点「添加规则」会直接 500。
    rows = outbounds if isinstance(outbounds, (list, tuple)) else ()
    custom = {str(o.get('name') or '') for o in rows if isinstance(o, dict)}
    configured = set(_existing_outbound_names() if existing_names is None else existing_names)
    return bool(target) and target in custom | configured


def build_warp_acl_config(original, enabled, rules):
    """Render WARP domain ACL over the existing Hysteria config."""
    text = strip_acl_block(original)
    # rules 可能是数字（旧快照被改坏）：`for r in 7` 抛 TypeError，
    # 而这里是 WARP 开关/应用配置的必经路径。
    rows = rules if isinstance(rules, (list, tuple)) else ()
    custom_rules = [r for r in rows if isinstance(r, dict)
                    and r.get('outbound') not in ('', None, 'warp', 'warp_socks')]
    if not enabled and not custom_rules:
        tail0 = 'direct_ipv4' if re.search(r'^\s*-\s*name:\s*direct_ipv4\s*$', text, re.M) else 'direct'
        return text.rstrip('\n') + '\n\n' + '\n'.join(_acl_head() + ['    - %s(all)' % tail0]) + '\n'

    existing = outbound_names_in(text)
    warp_name = 'warp_socks' if 'warp_socks' in existing else 'warp'
    if warp_name not in existing:
        block = ("\n  - name: warp_socks\n    type: socks5\n"
                 "    socks5:\n      addr: 127.0.0.1:19898")
        if re.search(r'^outbounds:\s*$', text, re.M):
            text = re.sub(r'^outbounds:\s*$', 'outbounds:' + block, text, count=1, flags=re.M)
        else:
            text = text.rstrip('\n') + '\n\noutbounds:' + block + '\n'
        warp_name = 'warp_socks'
        existing.append(warp_name)

    if not re.search(r'^sniff:', text, re.M):
        text = text.rstrip('\n') + '\n\nsniff:\n  enable: true\n  timeout: 2s\n  rewriteDomain: false\n  tcpPorts: 80,443\n  udpPorts: 443\n'
    tail = 'direct_ipv4' if 'direct_ipv4' in existing else 'direct'
    lines = _acl_head()
    for rule in rows if enabled else custom_rules:
        domain = rule.get('domain', '') if isinstance(rule, dict) else rule
        target = rule.get('outbound') or warp_name if isinstance(rule, dict) else warp_name
        if target not in set(existing) | {'direct', 'reject'}:
            target = warp_name
        domain = str(domain).strip().lower().strip('.')
        if domain and re.fullmatch(r'[a-z0-9.-]+', domain):
            lines.append('    - %s(suffix:%s)' % (target, domain))
    lines.append('    - %s(all)' % tail)
    return text.rstrip('\n') + '\n\n' + '\n'.join(lines) + '\n'


def normalize_route_rules(rules):
    # 容器被改成数字/对象时旧写法 `for item in rules` 抛 TypeError，
    # 而它在 render_egress_config 里 —— WARP 分流保存永久失败。
    if not isinstance(rules, (list, tuple, set, frozenset)):
        return []
    result = []
    for item in rules:
        if isinstance(item, str):
            item = {'domain': item, 'outbound': 'warp_socks'}
        if not isinstance(item, dict):
            continue
        domain = str(item.get('domain') or '').strip().lower().strip('.')
        if domain and re.fullmatch(r'[a-z0-9.-]+', domain):
            result.append({'domain': domain, 'outbound': str(item.get('outbound') or 'warp_socks')})
    return result


def routing_state(data):
    """出站/分流状态快照；损坏的容器一律降级成空表。

    这个快照会直接进 render_egress_config 与 capabilities 响应：
    custom_outbounds 是数字时渲染抛异常（WARP 保存永久失败），
    warp_rules 是数字时 normalize_route_rules 之前就会在 deepcopy 后炸，
    面板拿不到能力清单。
    """
    rules = data.get('warp_rules')
    if not isinstance(rules, (list, tuple)):
        rules = DEFAULT_WARP_DOMAINS if data.get('warp_enabled') else []
    outbounds = data.get('custom_outbounds')
    if not isinstance(outbounds, (list, tuple)):
        outbounds = []
    mode = data.get('outbound_mode')
    return {'warp_enabled': bool(data.get('warp_enabled', False)),
            'warp_rules': copy.deepcopy(list(rules)),
            'custom_outbounds': copy.deepcopy(list(outbounds)),
            'outbound_mode': mode if isinstance(mode, str) else 'rules'}


def render_egress_config(original, state):
    enabled = bool(state.get('warp_enabled', False))
    # Ensure the WARP transport/sniffer, then render the one shared route table.
    base = strip_acl_block(build_warp_acl_config(original, enabled, []))
    outs = clean_outbounds(state.get('custom_outbounds', []))
    base = upsert_outbound_block(base, outs)
    existing = outbound_names_in(base)
    tail = 'direct_ipv4' if 'direct_ipv4' in existing else 'direct'
    rules = normalize_route_rules(state.get('warp_rules', []))
    if not enabled:
        rules = [r for r in rules if r['outbound'] not in ('warp', 'warp_socks')]
    elif 'warp_socks' not in existing and 'warp' in existing:
        rules = [dict(r, outbound='warp') if r['outbound'] == 'warp_socks' else r for r in rules]
    mode = state.get('outbound_mode', 'rules')
    if mode == 'global' and not outs:
        mode = 'rules'
    # 🔴 不能在这里提前返回「已剥离 ACL 的 base」（2026-10-29 修）：
    # 关闭 WARP 且没有自定义规则时 rules 恰好为空，旧代码直接返回 base ——
    # 连内网 / 云元数据的 reject 规则一起消失了，界面却显示重载成功。
    # 统一交给 build_acl_block：即使没有规则，它也会输出 reject 头 + 兜底。
    return base.rstrip('\n') + '\n\n' + build_acl_block(mode, rules, outs, tail, existing_names=existing) + '\n'


def _hy2_runtime_identity():
    """Return active state, PID and start timestamp for reload verification."""
    proc = subprocess.run(
        ['systemctl', 'show', 'hysteria-server', '--property=ActiveState',
         '--property=MainPID', '--property=ExecMainStartTimestamp'],
        capture_output=True, text=True, timeout=8)
    values = {}
    for line in proc.stdout.splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            values[key] = value
    return values.get('ActiveState', ''), values.get('MainPID', '0'), values.get('ExecMainStartTimestamp', '')


def _hy2_config_loaded(config_path, identity=None):
    try:
        state, pid, started = identity or _hy2_runtime_identity()
        fields = started.split()
        timestamp = time.mktime(time.strptime(' '.join(fields[1:3]), '%Y-%m-%d %H:%M:%S'))
        return state == 'active' and pid not in ('', '0') and Path(config_path).stat().st_mtime <= timestamp + 1
    except Exception:
        return False


def apply_egress_config(data, data_lock, config_path='/etc/hysteria/config.yaml'):
    """Apply WARP rules transactionally; success requires a new active process."""
    cfg = Path(config_path)
    try:
        original = cfg.read_text(encoding='utf-8')
    except Exception as exc:
        return False, '读取 Hysteria 配置失败: %s' % exc
    with data_lock:
        if data.get('outbound_mode') == 'global' and not data.get('custom_outbounds'):
            data['outbound_mode'] = 'rules'
        state = routing_state(data)
    rendered = render_egress_config(original, state)
    try:
        before = _hy2_runtime_identity()
        if rendered == original and _hy2_config_loaded(cfg, before):
            return True, ''
        fd, tmp = tempfile.mkstemp(prefix='.config.yaml.warp-', dir=str(cfg.parent))
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                stream.write(rendered)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(tmp, cfg.stat().st_mode & 0o777)
            os.replace(tmp, cfg)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
        # 整机流量超额停用期间不能启动服务，但配置应当落盘并视为成功 ——
        # 旧实现继续等 active，12 秒后必然「应用失败、已回滚」，
        # 于是停用期间任何 WARP/出站改动都保存不了（2026-10-30 修）。
        if _unit_suspended('hysteria-server'):
            return True, ''
        _restart_hy2()
        after = ('', '0', '')
        for _ in range(12):
            after = _hy2_runtime_identity()
            if after[0] == 'active' and after[1] not in ('', '0') and after != before:
                time.sleep(1)
                if _hy2_runtime_identity() == after and cfg.read_text(encoding='utf-8') == rendered:
                    return True, ''
            if after[0] in ('failed', 'inactive'):
                break
            time.sleep(1)
        detail = 'Hysteria 没有加载新配置（state=%s,pid=%s,start=%s）' % after
    except Exception as exc:
        detail = '应用 WARP 分流配置失败: %s' % exc

    rollback_state = _rollback_outbounds(cfg, original)
    if rollback_state != 'active':
        return False, '%s；并且恢复原配置后服务状态为 %s' % (detail, rollback_state)
    return False, '%s；已回滚原配置' % detail


def apply_warp_acl_config(data, data_lock, config_path='/etc/hysteria/config.yaml'):
    return apply_egress_config(data, data_lock, config_path)


def warp_acl_matches(config_text, enabled, rules):
    """Whether the saved config contains the exact ACL/outbound state requested."""
    return config_text == build_warp_acl_config(config_text, enabled, rules)


def detect_outbound_ip(kind='auto', addr='', timeout=6):
    """探测出站真实出口 IP —— 面板要显示"现在出去是哪个 IP"。

    🔴 这是用户判断"到底生效没有"的唯一依据。旧面板只显示 WARP 装没装，
    显示不了实际出口，用户只能靠访问 ipify 自己猜。
    """
    proxy_url = ''
    if kind == 'socks5' and addr:
        proxy_url = 'socks5h://' + addr
    elif kind == 'http' and addr:
        proxy_url = addr
    elif kind == 'warp':
        proxy_url = 'socks5h://127.0.0.1:19898'
    try:
        seconds = max(1, float(timeout))
        # urllib's ProxyHandler speaks HTTP CONNECT, not the SOCKS5 protocol.
        # Explicitly override no_proxy: '*' would silently bypass this proxy.
        args = ['curl', '--disable', '--silent', '--show-error', '--fail',
                '--connect-timeout', str(min(3, seconds)), '--max-time', str(seconds),
                '--proxy', proxy_url, '--noproxy', '' if proxy_url else '*',
                'https://api4.ipify.org?format=json']
        proc = subprocess.run(args, capture_output=True, text=True, timeout=seconds + 2)
        if proc.returncode != 0:
            return ''
        payload = proc.stdout.strip()
        try:
            result = json.loads(payload).get('ip', '')
        except (ValueError, AttributeError):
            result = payload
        return str(ipaddress.ip_address(result))
    except Exception:
        return ''


def apply_outbounds_config(data, data_lock, config_path='/etc/hysteria/config.yaml'):
    """Custom outbounds and WARP share the same compiler, transaction and readiness check."""
    return apply_egress_config(data, data_lock, config_path)


# serve() 启动后换成真实判断：该服务是否因整机流量超额停用中。
_unit_suspended = lambda unit: False  # noqa: E731


def _restart_hy2():
    """停 → 清失败计数 → 启动。**所有**改Hysteria 配置后都必须走这里。

    🔴 为什么不用 `systemctl restart`：
    systemd 有 start-limit（默认 5 次/10 秒）。面板上的连续操作会密集 restart，
    计数耗尽后进入 `start-limit-hit`，此后 start/restart 一律被直接拒绝，
    服务就永久锁死 —— 而配置完全合法、端口空闲，极难定位（第 4 轮回归真实踩到）。
    `reset-failed` 是官方解封手段，必须在**每次**启动前调用。

    流量超额停用期间不启动：配置已经落盘，控制台恢复节点时会带着新配置启动。
    """
    if _unit_suspended('hysteria-server'):
        return
    subprocess.run(['systemctl', 'stop', 'hysteria-server'],
                   capture_output=True, timeout=25)
    # 🔴 关键：每次启动前都要 reset，否则上一次的失败计数会累积
    subprocess.run(['systemctl', 'reset-failed', 'hysteria-server'],
                   capture_output=True, timeout=15)
    subprocess.run(['systemctl', 'start', 'hysteria-server'],
                   capture_output=True, timeout=30)


def _unreachable_outbounds(outs, timeout=2):
    """返回【连不上】的自定义出站名列表（纯本地 socket 探测，不发数据）。

    🔴 为什么要单独探测：Hysteria 启动后会立刻尝试连接全局出站，
    连不上就直接退出。而这时配置本身完全合法，
    旧提示却说"配置可能有误 / HTTP 不支持 UDP"——
    用户会去反复检查地址格式，永远查不到真因（代理根本没在跑）。
    第 4 轮回归就是踩这个：测试出站指向 127.0.0.1:19898，
    而 WARP 没装 → 报"配置可能有误"，实际是"代理没启动"。

    只对 socks5 / http 有意义（direct 不需要外部服务）。
    """
    dead = []
    for ob in outs or []:
        target = None
        if ob.get('type') == 'socks5':
            target = ob.get('addr') or ''
        elif ob.get('type') == 'http':
            m = re.match(r'^[a-zA-Z]+://([^/:]+)(?::(\d+))?', ob.get('url') or '')
            if m:
                target = '%s:%s' % (m.group(1), m.group(2) or '80')
        if not target or ':' not in target:
            continue
        host, port = target.rsplit(':', 1)
        try:
            port = int(port)
        except ValueError:
            continue
        sock = None
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
        except Exception:
            dead.append(ob.get('name'))
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass
    return dead


def _rollback_outbounds(cfg, original):
    """回滚配置并尽力把服务拉回可用状态。

    🔴 回滚是最后一道保险，它自己失败的话用户就彻底没救了。
    所以这里做了三件之前没做的事：
      1. `reset-failed`：否则上一轮失败留下的 start-limit-hit 会让
         restart 直接被拒（真实事故：回滚也跟着一起失败）。
      2. 写回配置后再 reset 再 restart，顺序不能乱。
      3. 校验最终状态：回滚后仍不 active 就明确记下来，
         让面板能告诉用户"需要手动干预"，而不是静默留一个坏服务。
    """
    state = 'unknown'
    try:
        cfg.write_text(original, encoding='utf-8')
        # 🔴 必须走 _restart_hy2（内含 reset-failed），
        #    这里原来直接 restart，会被 start-limit 挡住 ——
        #    后果是「回滚也失败」，用户彻底没救（真实事故）。
        _restart_hy2()
        for _i in range(10):
            state = subprocess.run(['systemctl', 'is-active', 'hysteria-server'],
                                   capture_output=True, text=True,
                                   timeout=8).stdout.strip()
            if state in ('active', 'failed', 'inactive'):
                break
            time.sleep(1)
    except Exception as exc:
        _log_ignored('wait_service', exc)
    return state


def core_version_key(value):
    match = re.search(r'(\d+)\.(\d+)\.(\d+)', str(value or ''))
    return tuple(map(int, match.groups())) if match else ()


def _log_ignored(where, exc):
    """尽力而为的步骤失败时不中断主流程，但至少留一行日志，便于事后排查。"""
    print(f'[portal] {where} ignored {type(exc).__name__}: {exc}', file=sys.stderr)


def atomic_write_private(path, payload):
    """原子、落盘、仅 root 可读地写文件。

    - 临时文件一创建就是 0600：先按 umask 建再 chmod，中间那段时间里
      密码与 api_key 对本机其他用户可读。
    - replace 前 fsync 文件、之后 fsync 目录：否则断电后可能留下空文件，
      portal.json 里是全部用户数据。
    """
    path = Path(path)
    temp = path.with_suffix('.tmp')
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        if hasattr(os, 'fchmod'):  # 临时文件若已存在，O_CREAT 不会改它原来的权限
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb') as fh:
            fd = None
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
    finally:
        if fd is not None:
            os.close(fd)
    os.replace(temp, path)
    if hasattr(os, 'O_DIRECTORY'):
        dfd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)


def portal_update_process_lock(base_dir):
    """与终端更新共用永久锁文件；调用者只能 close，不能 LOCK_UN。

    flock 绑定到 open file description，pass_fds 继承的子进程与父进程共享锁。
    父进程显式解锁会连带释放子进程的锁；只关闭自己的 fd 才能覆盖后台核验。
    """
    if fcntl is None:
        return None
    fd = os.open(Path(base_dir) / '.portal-update.lock', os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BaseException:
        os.close(fd)
        raise
    return fd


def portal_update_restart_prefix():
    """systemd 重启会清理原服务 cgroup，先把持锁脚本迁入独立 scope。"""
    if os.name == 'posix' and Path('/run/systemd/system').is_dir():
        runner = shutil.which('systemd-run')
        if not runner:
            raise RuntimeError('门户更新需要 systemd-run 独立 scope，未写入更新文件')
        # --scope 在启动 job 完成后 exec 目标程序，保留 pass_fds 的锁 fd。
        return [runner, '--scope', '--quiet',
                '--unit=hysteria-portal-update-' + uuid.uuid4().hex, 'bash', '-c']
    return ['bash', '-c']


def portal_start_update(restart_prefix, script, lock_fd, ready_timeout=10):
    """只有持锁子脚本就绪才交接；失败时关闭 go 管道，禁止稍后再执行重启。"""
    if lock_fd is None:  # Windows 开发环境没有 POSIX fd 继承。
        return subprocess.Popen(restart_prefix + [script], stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, start_new_session=True)
    ready_r, ready_w = os.pipe()
    go_r = go_w = None
    child = None
    try:
        go_r, go_w = os.pipe()
        # systemd-run --scope exec bash 后才发 ready；go EOF 时必须直接退出。
        guarded = ('printf R >&%d; exec %d>&-; '
                   'IFS= read -r portal_update_go <&%d || exit 1; exec %d<&-; '
                   '[ "$portal_update_go" = go ] || exit 1; %s'
                   % (ready_w, ready_w, go_r, go_r, script))
        child = subprocess.Popen(restart_prefix + [guarded], stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, start_new_session=True,
                                 pass_fds=(lock_fd, ready_w, go_r))
        os.close(ready_w)
        ready_w = None
        os.close(go_r)
        go_r = None
        readable, _, _ = select.select([ready_r], [], [], ready_timeout)
        if not readable or os.read(ready_r, 1) != b'R' or child.poll() is not None:
            raise RuntimeError('门户重启脚本未就绪，已放弃更新')
        os.write(go_w, b'go\n')
        return child
    except BaseException:
        if child is not None:
            try:
                child.terminate()
                child.wait(timeout=2)
            except Exception as exc:
                _log_ignored('portal_update.start_cleanup', exc)
        raise
    finally:
        for fd in (ready_r, ready_w, go_r, go_w):
            if fd is not None:
                os.close(fd)


def portal_update_restart_script(port, backups, created, wait_seconds=20):
    """面板自更新后的重启脚本：起不来就自动回滚到旧版本。

    门户同时是 Hy2 的鉴权后端和 Teyir 管理节点的唯一入口。新版本一旦启动即崩，
    全节点用户连不上，控制台也没法远程修 —— 所以重启后轮询 /api/health，
    限时内没有响应就把 .bak 换回去、删掉本次新增的文件，再重启一次。
    """
    probe = ("import urllib.request; "
             "urllib.request.urlopen('http://127.0.0.1:%d/api/health', timeout=2).read()"
             % int(port))
    restore = ' '.join('cp -f %s %s;' % (shlex.quote(str(bak)), shlex.quote(str(dest)))
                       for dest, bak in backups)
    remove = ' '.join('rm -f %s;' % shlex.quote(str(dest)) for dest in created)
    marker = shlex.quote('/etc/hysteria/portal-rollback-failed')
    # 回滚后再做一次健康检查：旧版本本身也可能起不来（更新前就处于 failed）。
    # 旧脚本只重启、不复查，最终状态是「服务挂着、界面打不开」，日志却说
    # 「已自动回滚」（2026-10-29 修）。复查仍失败就写一个明确的标记文件，
    # 下次启动 / 人工排查能直接看到。
    return ('sleep 1; systemctl restart hysteria-portal; '
            'for i in $(seq 1 %d); do sleep 1; python3 -c %s && exit 0; done; '
            'logger -t hysteria-portal "面板更新后未能启动，已自动回滚到旧版本"; '
            '%s %s systemctl restart hysteria-portal; '
            'for i in $(seq 1 10); do sleep 1; python3 -c %s && '
            '{ logger -t hysteria-portal "回滚后已恢复"; exit 0; }; done; '
            'logger -t hysteria-portal "回滚后仍未启动，需要人工介入"; '
            'echo "portal rollback failed at $(date -Is)" > %s'
            % (int(wait_seconds), shlex.quote(probe), restore, remove,
               shlex.quote(probe), marker))


PORTAL_BUNDLE_FILES = (
    'portal.py', 'portal_assets.py', 'usage-meter-core-20261007-v1.py',
    'usage-meter-readers-20261007-v1.py', 'usage-meter-runtime-20261007-v1.py',
    'usage-meter-xray-config-20261007-v1.py',
)


def portal_bundle_version(local_shas, remote_shas):
    """Compare every required file; partial observations cannot establish currency."""
    # 两个入参都可能不是 dict：local_shas 由本机文件算出（文件读失败时为 None），
    # remote_shas 来自 GitHub API（限流时是错误对象）。旧写法 `.get` 直接抛
    # AttributeError，/check-version 整条接口 500 —— 面板连「有没有更新」都看不到。
    local_shas = local_shas if isinstance(local_shas, dict) else {}
    remote_shas = remote_shas if isinstance(remote_shas, dict) else {}
    valid = lambda sha: isinstance(sha, str) and re.fullmatch(r'[0-9a-f]{40}', sha)
    changed = [name for name in PORTAL_BUNDLE_FILES
               if valid(remote_shas.get(name)) and local_shas.get(name) != remote_shas[name]]
    unknown = [name for name in PORTAL_BUNDLE_FILES if not valid(remote_shas.get(name))]
    status = 'update_available' if changed else ('unknown' if unknown else 'up_to_date')
    def fingerprint(shas):
        if not all(valid(shas.get(name)) for name in PORTAL_BUNDLE_FILES):
            return ''
        return hashlib.sha256(''.join(name + ':' + shas[name] + '\n'
                                     for name in PORTAL_BUNDLE_FILES).encode()).hexdigest()[:7]
    return {'status': status, 'has_update': bool(changed), 'changed_files': changed,
            'unknown_files': unknown, 'current': fingerprint(local_shas) or '不完整',
            'latest': fingerprint(remote_shas)}


def resolve_update_ref(ref):
    if re.fullmatch(r'[0-9a-f]{40}', ref):
        return ref
    if ref != 'main':
        raise ValueError('Invalid immutable ref')
    value = ''
    try:
        req = urllib.request.Request('https://api.github.com/repos/' + AWG_REPO + '/commits/main',
                                     headers={'User-Agent': 'hysteria2-installer'})
        with urllib.request.urlopen(req, timeout=8) as response:
            value = json.loads(response.read().decode('utf-8')).get('sha', '')
    except Exception as exc:
        _log_ignored('resolve_update_ref.github', exc)
    if not re.fullmatch(r'[0-9a-f]{40}', value):
        # GitHub API 匿名每 IP 60 次/小时，共享 IP 上被限流是常态。
        # 退回仓库的 commits Atom feed（2026-10-29 修）：由 github.com 直接提供、
        # 不计 API 额度，条目里带完整 commit，同样能锁定到具体提交。
        # （jsDelivr 的 resolved 接口对分支返回 null，不能用作回退。）
        try:
            req = urllib.request.Request(
                'https://github.com/' + AWG_REPO + '/commits/main.atom',
                headers={'User-Agent': 'hysteria2-installer'})
            with urllib.request.urlopen(req, timeout=8) as response:
                feed = response.read().decode('utf-8', 'replace')
            m = re.search(r'/commit/([0-9a-f]{40})', feed)
            value = m.group(1) if m else ''
        except Exception as exc:
            _log_ignored('resolve_update_ref.atom', exc)
    if not re.fullmatch(r'[0-9a-f]{40}', value):
        raise RuntimeError('无法固定面板更新版本（GitHub API 与 commits.atom 均不可用），'
                           '未修改现有文件')
    return value


# ==============================================================================
# 下载完整性校验（2026-10-27）
# ------------------------------------------------------------------------------
# 与 install.sh 里的同名逻辑保持一致：先解析确定版本，再从**官方**发布取校验
# 清单，按精确资产名解析出唯一 SHA256，下载到私有临时目录校验通过才替换。
#
# fail-closed 的情形：清单取不到 / 为空 / 没有该资产 / 同一资产多条匹配 /
# 摘要不是 64 位十六进制 / 内容与摘要不一致。
# 第三方镜像不能提供可信摘要：只有先从官方拿到预期摘要，才允许把镜像当传输
# 候选，且内容必须与官方摘要逐字节一致。
# 同源摘要只证明与官方发布一致，不构成独立签名。
# ==============================================================================

_SHA256_RE = re.compile(r'^[0-9a-f]{64}$')


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def parse_checksum_manifest(text, asset):
    """从 `<sha256>  <name>` 清单里取唯一匹配资产的摘要。

    无匹配 / 多条匹配 / 摘要畸形一律返回 None（调用方必须 fail-closed）。
    兼容 CRLF、`*name`、`./name`，并允许按 basename 匹配（hysteria 的清单里
    路径形如 `build/hysteria-linux-amd64`）。
    """
    if not isinstance(text, str) or not asset:
        return None
    found = None
    count = 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        digest = parts[0].lower()
        name = parts[-1].lstrip('*')
        while name.startswith('./'):
            name = name[2:]
        if name != asset and name.rsplit('/', 1)[-1] != asset:
            continue
        if not _SHA256_RE.match(digest):
            return None
        count += 1
        found = digest
    return found if count == 1 else None


def parse_xray_dgst(text):
    """从 Xray 的 `.dgst` 里取 SHA2-256（`SHA2-256= <hex>`）。

    只认 SHA2-256 —— 绝不把 MD5 / SHA1 当作校验依据。缺失或重复返回 None。
    """
    if not isinstance(text, str):
        return None
    found = None
    count = 0
    for raw in text.splitlines():
        line = raw.strip()
        if '=' not in line:
            continue
        key, value = line.split('=', 1)
        key = key.strip().upper().replace('_', '-')
        if key != 'SHA2-256':
            continue
        digest = value.strip().lower()
        if not _SHA256_RE.match(digest):
            return None
        count += 1
        found = digest
    return found if count == 1 else None


def fetch_text(url, timeout=30, headers=None):
    req = urllib.request.Request(url, headers=headers or {'User-Agent': 'hysteria2-installer'})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode('utf-8', errors='replace')


def fetch_expected_sha256(manifest_url, asset, parser=None):
    """取官方清单并解析唯一摘要；任何异常/缺失都返回 None（fail-closed）。"""
    try:
        text = fetch_text(manifest_url)
    except Exception:
        return None
    return parser(text) if parser is not None else parse_checksum_manifest(text, asset)


def verify_sha256(path, expected):
    """摘要格式非法或内容不匹配都返回 False。"""
    if not isinstance(expected, str) or not _SHA256_RE.match(expected):
        return False
    try:
        return sha256_file(path) == expected
    except OSError:
        return False


def git_blob_sha(data):
    """git blob 身份：sha1("blob <len>\\0" + content)。

    ⚠️ 它**不等于**文件的 sha1，少写 blob 头永远对不上 GitHub contents API 的 sha。
    """
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\x00' + data).hexdigest()


def safe_tar_members(names, wanted):
    """校验 tar 成员名，并返回与 wanted 同名的**包内实际成员名**。

    拒绝绝对路径与含 `..` 的成员（防以 root 写出临时目录），
    且只接受一个精确同名的常规文件（不做"第一个可执行文件"兜底）。
    """
    hits = []
    for name in names:
        clean = name[2:] if name.startswith('./') else name
        if name.startswith('/') or clean.startswith('/') or '..' in clean.split('/'):
            raise ValueError('tar 包内含不安全路径成员: %s' % name)
        if clean == wanted or clean.rsplit('/', 1)[-1] == wanted:
            hits.append(name)
    if len(hits) != 1:
        raise ValueError('tar 包内 %s 成员缺失或不唯一（%d 个）' % (wanted, len(hits)))
    return hits[0]


def safe_zip_members(names, wanted):
    """校验 zip 成员名并返回唯一精确匹配的成员名。"""
    hits = []
    for name in names:
        clean = name[2:] if name.startswith('./') else name
        if name.startswith('/') or clean.startswith('/') or '..' in clean.split('/'):
            raise ValueError('zip 包内含不安全路径成员: %s' % name)
        if clean == wanted or clean.rsplit('/', 1)[-1] == wanted:
            hits.append(name)
    if len(hits) != 1:
        raise ValueError('zip 包内 %s 成员缺失或不唯一（%d 个）' % (wanted, len(hits)))
    return hits[0]


# 上游 Hysteria 没有 hysteria-linux-armv7 资产（实测 404），armv7 机器要用
# hysteria-linux-arm。旧的 armv7 映射是已证实的缺陷。
HYSTERIA_ARCH_ASSET = {'amd64': 'amd64', 'arm64': 'arm64', 'armv7': 'arm'}


def hysteria_asset_arch(machine=None):
    machine = (machine or platform.machine()).lower()
    arch = {'x86_64': 'amd64', 'amd64': 'amd64', 'aarch64': 'arm64',
            'arm64': 'arm64', 'armv7l': 'armv7', 'armv7': 'armv7'}.get(machine)
    return HYSTERIA_ARCH_ASSET.get(arch) if arch else None



def _prune_core_backups(directory, keep=3):
    """只保留最近 keep 份核心备份。

    每次升级都会复制一份完整二进制（Hysteria ~30 MB / Xray ~36 MB），
    旧实现从不清理：小盘 VPS 上历经几次升级就可能写满根分区，
    而 portal.json 的原子写入失败会连带影响用户数据（2026-10-29 加）。
    """
    directory = Path(directory)
    try:
        items = sorted((p for p in directory.iterdir()
                        if p.is_file() and p.name.startswith(('hysteria-', 'xray-'))),
                       key=lambda p: p.stat().st_mtime, reverse=True)
    except OSError:
        return
    for old in items[keep:]:
        try:
            old.unlink()
        except OSError:
            continue


def _require_disk_space(path, need_bytes):
    """可用空间不足时抛错，避免把盘写满导致数据丢失。"""
    try:
        free = shutil.disk_usage(str(path)).free
    except OSError:
        return
    if free < need_bytes:
        raise RuntimeError('磁盘空间不足：需要约 %d MB，当前可用 %d MB'
                           % (need_bytes // (1024 * 1024), free // (1024 * 1024)))

def upgrade_core_binary(binary='/usr/local/bin/hysteria', backup_dir='/etc/hysteria/core-backups', allow_custom=False):
    binary = Path(binary)
    current = subprocess.run([str(binary), 'version'], capture_output=True, text=True, timeout=5).stdout
    current_line = next((line.split(':', 1)[1].strip() for line in current.splitlines() if line.strip().startswith('Version:')), '')
    if '+' in current_line and not allow_custom:
        raise RuntimeError('当前核心含定制补丁，升级官方核心需要明确确认覆盖补丁')
    machine = platform.machine().lower()
    arch = {'x86_64': 'amd64', 'amd64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64', 'armv7l': 'armv7'}.get(machine)
    if not arch:
        raise RuntimeError('Unsupported core architecture')
    asset_arch = HYSTERIA_ARCH_ASSET.get(arch)
    if not asset_arch:
        raise RuntimeError('Unsupported core architecture')
    asset = 'hysteria-linux-' + asset_arch
    # 下载 + 备份两份完整二进制，先确认放得下再开始（2026-10-29 加）。
    try:
        _require_disk_space(binary.parent, binary.stat().st_size * 2 + 64 * 1024 * 1024)
    except FileNotFoundError:
        pass
    fd, name = tempfile.mkstemp(prefix='.hysteria-update-', dir=str(binary.parent))
    os.close(fd)
    candidate = Path(name)
    backup = None
    replaced = False
    try:
        # 先解析确定版本，再取该版本的官方 hashes.txt。绝不用浮动 latest 的字节。
        tag = ''
        try:
            tag = str(json.loads(fetch_text(
                'https://api.github.com/repos/apernet/hysteria/releases/latest',
                timeout=10)).get('tag_name') or '')
        except Exception:
            tag = ''
        if not tag:
            # 官方下载站的 latest 会 302 到 /app/<version>/<asset>，据此解析版本。
            # 任何解析失败（网络、HTML 错误页、重定向缺失）都只意味着"版本无法确定"，
            # 必须继续走下面的 fail-closed 分支，而不是把底层异常类型抛给调用方。
            try:
                req = urllib.request.Request(
                    'https://download.hysteria.network/app/latest/' + asset,
                    headers={'User-Agent': 'hysteria2-installer'})
                with urllib.request.urlopen(req, timeout=20) as resp:
                    final = resp.geturl() or ''
                m = re.search(r'/app/(v[0-9][^/]*)/' + re.escape(asset) + r'$', final)
                # 下载站只给裸版本号，而 GitHub 的 release tag 是 `app/vX.Y.Z`；
                # 不补前缀拼出的 hashes.txt / 资产 URL 实测 404，回退路径会永远失败。
                tag = ('app/' + m.group(1)) if m else ''
            except Exception:
                tag = ''
        if not tag:
            raise RuntimeError('无法确定 Hysteria 版本，已放弃更新（不做无校验下载）')
        expected = fetch_expected_sha256(
            'https://github.com/apernet/hysteria/releases/download/' + tag + '/hashes.txt',
            asset)
        if not expected:
            raise RuntimeError(
                '取不到 Hysteria %s 的官方 hashes.txt（或其中没有 %s），已放弃更新' % (tag, asset))
        url = ('https://github.com/apernet/hysteria/releases/download/'
               + tag + '/' + asset)
        req = urllib.request.Request(url, headers={'User-Agent': 'hysteria2-installer'})
        with urllib.request.urlopen(req, timeout=90) as source, open(candidate, 'wb') as dest:
            shutil.copyfileobj(source, dest)
        if not verify_sha256(candidate, expected):
            raise RuntimeError('候选核心的 SHA256 与官方 hashes.txt 不一致，原核心未更改')
        with candidate.open('rb') as stream:
            if stream.read(4) != b'\x7fELF':
                raise RuntimeError('下载内容不是 Linux 核心二进制，原核心未更改')
        candidate.chmod(0o755)
        verified = subprocess.run([str(candidate), 'version'], capture_output=True, text=True, timeout=8)
        newer = next((line.split(':', 1)[1].strip() for line in verified.stdout.splitlines() if line.strip().startswith('Version:')), '')
        if verified.returncode != 0 or not core_version_key(newer):
            raise RuntimeError('候选核心版本校验失败，原核心未更改')
        if core_version_key(current_line) and core_version_key(newer) <= core_version_key(current_line):
            return {'changed': False, 'version': current_line, 'message': '当前核心版本不低于官方候选，未替换现有补丁'}
        directory = Path(backup_dir)
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        _prune_core_backups(directory)   # 先腾地方，再写本次备份
        backup = directory / ('hysteria-' + str(time.time_ns()))
        shutil.copy2(binary, backup)
        before = _hy2_runtime_identity()
        os.replace(candidate, binary)
        replaced = True
        _restart_hy2()
        time.sleep(1)
        after = _hy2_runtime_identity()
        if after[0] != 'active' or after == before:
            raise RuntimeError('新核心未成功加载')
        return {'changed': True, 'version': newer, 'backup': str(backup)}
    except Exception:
        if replaced and backup is not None:
            shutil.copy2(backup, binary)
            _restart_hy2()
        raise
    finally:
        candidate.unlink(missing_ok=True)


def gost_tls_paths(root):
    """Reuse the node's existing certificate/key instead of referencing nonexistent files."""
    root = Path(root)
    config = root / 'config.yaml'
    cert = _config_tls_cert_path(str(config)) or _config_acme_cert_path(str(config))
    key = ''
    in_tls = False
    if config.exists():
        for raw in config.read_text(encoding='utf-8').splitlines():
            if not raw.strip() or raw.lstrip().startswith('#'):
                continue
            if not raw.startswith((' ', '\t')):
                in_tls = raw.split(':', 1)[0] == 'tls'
            elif in_tls and raw.strip().startswith('key:'):
                values = shlex.split(raw.strip().split(':', 1)[1], comments=True)
                key = values[0] if values else ''
    if cert:
        cert = Path(os.path.expandvars(str(cert)))
        if not cert.is_absolute():
            cert = root / cert
        key = Path(os.path.expandvars(key)) if key else cert.with_suffix('.key')
        if not key.is_absolute():
            key = root / key
        if cert.is_file() and key.is_file() and cert.stat().st_size and key.stat().st_size:
            return str(cert), str(key)
    legacy = root / 'gost-cert'
    if (legacy / 'cert.pem').is_file() and (legacy / 'key.pem').is_file():
        return str(legacy / 'cert.pem'), str(legacy / 'key.pem')
    raise RuntimeError('HTTPS 代理缺少可用证书和私钥，请先配置节点证书')


def apply_xray_config_transaction(config, config_path='/etc/hysteria/xray.json',
                                  binary='/usr/local/bin/xray', restart=True):
    """Validate a candidate before replacing; restore prior config on start failure."""
    path = Path(config_path)
    original = path.read_bytes() if path.exists() else None
    mode = path.stat().st_mode & 0o777 if path.exists() else 0o600
    candidate = path.with_name(path.name + '.portal-candidate.json')
    was_active = subprocess.run(['systemctl', 'is-active', 'xray'], capture_output=True,
                                text=True, timeout=5).stdout.strip() == 'active'
    replaced = False
    try:
        candidate.write_text(json.dumps(config, indent=2), encoding='utf-8')
        candidate.chmod(mode)
        test = subprocess.run([binary, 'run', '-test', '-c', str(candidate)],
                              capture_output=True, text=True, timeout=10)
        if test.returncode != 0:
            raise RuntimeError('Xray 配置预检失败，原配置未更改')
        os.replace(candidate, path)
        replaced = True
        if restart:
            subprocess.run(['systemctl', 'reset-failed', 'xray'], capture_output=True, timeout=5)
            started = subprocess.run(['systemctl', 'restart', 'xray'], capture_output=True, timeout=15)
            active = subprocess.run(['systemctl', 'is-active', 'xray'], capture_output=True,
                                    text=True, timeout=5).stdout.strip()
            if started.returncode != 0 or active != 'active':
                raise RuntimeError('Xray 启动失败，已恢复原配置')
            # 核心管理页单独安装 Xray 时只写单元不 enable；第一次真正有配置跑起来
            # 才设开机自启（幂等）。
            subprocess.run(['systemctl', 'enable', 'xray'], capture_output=True, timeout=15)
    except Exception:
        if replaced:
            if original is None:
                path.unlink(missing_ok=True)
            else:
                candidate.write_bytes(original)
                candidate.chmod(mode)
                os.replace(candidate, path)
            if was_active and original is not None:
                subprocess.run(['systemctl', 'reset-failed', 'xray'], capture_output=True, timeout=5)
                subprocess.run(['systemctl', 'restart', 'xray'], capture_output=True, timeout=15)
        raise
    finally:
        candidate.unlink(missing_ok=True)


def set_outbound_apply_error(data, data_lock, save_data, msg):
    """记录/清除"上次应用失败"的痕迹（与 WARP 开关同样的处理思路）。

    🔴 同apply_outbounds_config：data / data_lock / save_data 都得由调用方传入。
    """
    try:
        with data_lock:
            if msg:
                data['outbound_apply_error'] = msg
            else:
                data.pop('outbound_apply_error', None)
        save_data()
    except Exception:
        # 记录失败本身绝不能影响主流程
        pass


# 🔴 必须是原始字符串（r"""），不能改成普通三引号。
# 这是内嵌的 JS 源码，里面写的 \n 需要【原样保留】成 JS 的转义序列。
# 若用普通字符串，Python 会在解析阶段把 \n 变成真实换行塞进 JS 的字符串字面量里，
# 造成 JS 语法错误；而 JS 语法错误会让【整段脚本】无法解析 ——
# 表现不是某个按钮失灵，而是页面上所有按钮、标签页、轮询全部失效
# （历史上真发生过：更新后 Web 面板的菜单整个点不动）。
# 同理见下面的 LOGIN_SCRIPT / USER_SCRIPT。




def user_view_key(secret, user_id, nonce=''):
    # nonce 是开户时随机生成的 view_nonce：同名用户删了重建会换新 nonce，
    # 旧分享链接随之失效，不会让上一个买家看到新买家的配置。
    # 老用户没有 nonce，保持原算法，已发出去的链接不受影响。
    msg = f'uv:{user_id}:{nonce}' if nonce else f'uv:{user_id}'
    return hmac.new(str(secret).encode(), msg.encode(), hashlib.sha256).hexdigest()[:16]


def rotate_user_view_key_on_change(previous, current):
    """Grandfather legacy links until an actual password/status transition.

    Same-value reconciliation retries preserve links. Disabling rotates even if
    subsequently re-enabled, so a previously disclosed link cannot revive.
    """
    if (previous.get('password') != current.get('password') or
            (previous.get('status', 'active') != 'disabled' and
             current.get('status', 'active') == 'disabled')):
        current['view_nonce'] = secrets.token_hex(16)


def user_share_available(user, now=None):
    """分享页是否可用 —— 判据必须与 user_access_allowed 完全同源。

    ⚠️ 2026-10-25 修：旧实现用 `not expires` 把 0 当「永久」，
    而 user_access_allowed 用 `expires_at is None` 才当永久。
    于是 expires_at=0 的用户出现「分享页能打开、节点却连不上」的矛盾状态，
    与 users/list 显示的 active 也不一致。现在两者共用同一个函数。
    """
    return user_access_allowed(user, now)



def _expiry_text(value):
    """把 expires_at 渲染成人能看懂的到期时间。

    ⚠️ 旧实现用 `expires_at < 2000000000`（2033 年）判断「是否永久」，
    于是给了十年有效期的用户会被显示成「永久有效」—— 到期那天会突然停服，
    而面板一直写着永久（2026-10-29 修）。只有**没设到期**才是永久。
    """
    if value is None:
        return '永久有效'
    if isinstance(value, bool):
        # True 会被 float() 变成 1.0 → 渲染成 1970 年的日期，而准入判据
        # 认为它已过期。这类值只可能是数据坏掉，统一按无效处理。
        return '到期时间无效'
    try:
        ts = float(value)
    except (TypeError, ValueError):
        # 无法解析 ≠ 永久。user_access_denial 对同样的值返回
        # 'Invalid user record' 并拒绝连接；面板却写「永久有效」，
        # 于是「显示永久、实际连不上」——最难排查的一类矛盾状态。
        return '到期时间无效'
    if ts <= 0:
        return '已过期'
    if ts > 253402300799:       # 9999-12-31，防御性上限
        return '永久有效'
    try:
        return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))
    except (OverflowError, OSError, ValueError):
        return '永久有效'

def user_note_text(value):
    """账户备注的展示文本；非字符串（手工编辑/旧格式）一律显示占位符。

    备注会进 html.escape()，它对非字符串调用 .replace() 直接抛
    AttributeError —— 单条坏备注会让整个总览页/客户页 500。
    """
    return value if isinstance(value, str) and value else '-'


def format_bytes(b):
    # 负数只可能来自计数器回退或手工改坏的数据；直接展示 "-1 B" 会让人
    # 以为用量是负的。归零并保留原语义（调用方另有 used_bytes 原始值）。
    if b < 0:
        b = 0
    if b < 1024:
        return f"{b} B"
    elif b < 1024**2:
        return f"{b/1024:.1f} KB"
    elif b < 1024**3:
        return f"{b/1024**2:.2f} MB"
    elif b < 1024**4:
        return f"{b/1024**3:.2f} GB"
    else:
        # 大流量套餐（几 TB）此前一律显示成「数千 GB」，读起来费劲。
        return f"{b/1024**4:.2f} TB"


def read_masquerade_port(config_path='/etc/hysteria/config.yaml'):
    """从 Hysteria 的 config.yaml 里读出 masquerade 的真实监听端口。

    这是订阅端口的**权威来源** —— 门户的公网入口就是这个 masquerade 端口
    （`listenHTTPS`），订阅链接必须用它。
    """
    try:
        text = Path(config_path).read_text(encoding='utf-8')
    except OSError:
        return None
    for line in text.split('\n'):
        stripped = line.strip()
        if stripped.startswith('listenHTTPS:'):
            raw = stripped.split(':', 1)[1].strip()
            # 形如 ":11690" / "0.0.0.0:11690" / "11690"
            # 去掉可能的引号（`: "8443"` 这种写法 YAML 完全合法）。
            raw = raw.rsplit(':', 1)[-1].strip().strip('"').strip("'")
            if raw.isdigit():
                port = int(raw)
                # 端口 0 或越界不能当作有效值返回：调用方会把它拼进订阅链接，
                # 生成一个永远连不上的地址（2026-10-25 修）。
                if 1 <= port <= 65535:
                    return port
    return None



def read_meta_file(meta_path):
    """读取 client_meta.json；文件损坏时返回空 dict 而不是抛异常。

    🔴 2026-10-25 修：此前有 14 处直接 `json.loads(meta_path.read_text())`，
    文件被截断或手工改坏时抛 JSONDecodeError。regenerate_page 几乎在每次
    用户变更后都会调用，于是「一个坏文件」会让开户/删除/启停全部失败，
    且报错是不可理解的解码异常。

    放在模块级而不是闭包里：do_POST 在部分测试里是被单独摘出来执行的，
    闭包里的名字不在作用域内。
    """
    try:
        meta = json.loads(Path(meta_path).read_text(encoding='utf-8'))
        if not isinstance(meta, dict):
            raise ValueError('client metadata must be a JSON object')
        return meta
    except (OSError, ValueError) as exc:
        print('[portal] client_meta.json unreadable: ' + type(exc).__name__, file=sys.stderr)
        return {}

def resolve_subscription_port(m, config_path='/etc/hysteria/config.yaml'):
    """解析订阅链接该用的端口。按优先级取值，**绝不返回伪造的 8443**。

    🔴 为什么需要这个函数（真实 bug）：
    原代码写 `m.get("subscription_port", 8443)` —— 一旦 `client_meta.json`
    里缺这个键（历史遗留 / 手工改过），就兜底成 **8443**。
    但 8443 在生成本机服务时是被**主动避开**的端口（见端口黑名单），
    机器上通常**根本没有 8443 在监听**。结果：面板生成的 Clash 订阅链接
    指向一个不存在的地址，客户端只报一句笼统的「订阅导入失败」，
    用户完全无从下手（2026-09-30 真实报障）。

    取值优先级：
      1. `m['subscription_port']`  —— 显式配置，最权威
      2. config.yaml 的 `masquerade.listenHTTPS` —— 公网入口的真实端口
      3. 传入的 fallback（仅用于两处都读不到时的极端兜底）

    返回 (port, source)，source 用于日志/排障时说明端口来自哪里。
    """
    explicit = m.get('subscription_port') if isinstance(m, dict) else None
    # 与 artifacts() 同一套校验：True 会变成端口 1、1.5 被截成 1、
    # inf 抛 OverflowError。这些值都会生成一条指向**没人监听**端口的订阅链接，
    # 客户端只报「订阅导入失败」，看不出是配置坏了（2026-10-30 修）。
    value = _valid_port(explicit)
    if value:
        return value, 'client_meta'

    detected = read_masquerade_port(config_path)
    if detected:
        return detected, 'config.yaml'

    # 两处都读不到：退回 Hysteria 的默认监听端口，而不是伪造的 8443。
    return 443, 'fallback'


def portal_access_payload(url, username, password, api_key):
    """portal-access.json 的**唯一**构造点。

    这里必须收敛成一个函数，因为同一个负载现在有两个消费者：

      1. prepare()  —— 原子写盘成 /etc/hysteria/portal-access.json
      2. page_html() —— 渲染成「接入 TEYIR 控制台」卡片上那个「复制整份凭据」按钮

    两者若各写各的，字段顺序或分隔符一旦漂移，操作者从面板复制出来的就不再是
    磁盘上那份文件的内容 —— 而它俩看起来一模一样，出问题时极难察觉。
    收成一个函数后，「面板上复制的 == 磁盘上的 == 控制台解析的」由构造保证，
    不再依赖谁记得同步。

    注意 dict 的插入顺序就是 json.dumps 的输出顺序，改成别的顺序会改变字节。
    """
    return dict(url=url, username=username, password=password, api_key=api_key)


def page_html(m, uri, subscription, clash, sing, users=None, api_key=None, token="", session_secret="",
              username="", password=""):
    def field(identifier, value, kind="link"):
        return f'<textarea id="{identifier}" class="{kind}" aria-label="{identifier}" readonly spellcheck="false">{html.escape(value)}</textarea>'
    def copy(identifier):
        return f'<button class="button primary" type="button" data-copy="{identifier}" data-orig="复制">复制</button>'
    
    is_insecure = m.get("is_insecure", False)
    server_name = m.get("server_name") or m.get("public_ip", "localhost")
    public_ip = m.get("public_ip", server_name)
    host = public_ip if is_insecure else server_name
    # 自签模式下 server_name 是**伪装 SNI**（如 www.bing.com），机主既不拥有它、
    # 它也不指向本机。此前 <h1> 直接显示 server_name，于是每个自签节点的门户
    # 标题都是 www.bing.com —— 全页最大字号的那一行偏偏是错的，新手第一眼以为
    # 这面板属于 Bing。标题改用真实 host，并把伪装 SNI 单独标出来说明。
    fake_sni_hint = (f' · <span style="opacity:.75">伪装 SNI: {html.escape(server_name)}'
                     f'（自签模式，非真实域名）</span>') if is_insecure else ""
    sub_port = resolve_subscription_port(m)[0]
    _raw_pin = (m.get("pin_sha256") or "").strip().lower()
    pin_sha256 = _raw_pin if (is_insecure and len(_raw_pin) == 64
                              and all(c in "0123456789abcdef" for c in _raw_pin)) else ""
    pin_block = (f'<div class="api-box"><div><div style="font-size:11px;color:var(--muted);font-weight:700">'
                 f'自签证书 SHA-256 指纹 (HEX · 已写入直链 pinSHA256 / Xray 的 pinnedPeerCertSha256)</div>'
                 f'<div class="api-key-code" id="api-pin-val">{html.escape(pin_sha256)}</div></div>'
                 f'<button class="button" type="button" data-copy="api-pin-val" data-orig="复制指纹">复制指纹</button></div>') if pin_sha256 else ''
    listen_port = m.get("listen_port", 19984)
    obfs_pw = m.get("obfs_password", "")
    # 非 dict 的 users（null / list / 截断写入）按空表渲染：下面多处用
    # len(users) 与 users.items()，任一抛异常都会让整页 500。
    users = users if isinstance(users, dict) else {}
    now_ts = int(time.time())
    
    user_rows = []
    active_count = 0
    total_used_bytes = 0

    # 排序键必须能比较：某条记录的 created_at 被改成字符串时，
    # 旧写法会让整张用户表 500（2026-10-30 修）。
    # 单条记录不是 dict（手工编辑 / 截断写入）时跳过该行；`users` 整体不是
    # dict 时按空表渲染 —— 页面是 /auth 与所有管理操作的必经路径，
    # 这里抛异常等于整个控制台白屏，而两个服务仍然 active。
    rows = [(uid, u) for uid, u in users.items() if isinstance(u, dict)]
    for uid, u in sorted(rows, key=lambda x: _safe_int(x[1].get("created_at") or 0),
                         reverse=True):
        used_bytes = _safe_int(u.get("used_bytes") or 0)
        limit_bytes = _safe_int(u.get("limit_bytes") or 0)
        total_used_bytes += used_bytes

        # 展示用的分支判断必须与准入判据 user_access_allowed 同源：
        # 缺 status 视为 active，expires_at 到点即过期。
        is_traffic_ok = limit_bytes <= 0 or used_bytes < limit_bytes
        try:
            is_time_ok = u.get("expires_at") is None or float(u.get("expires_at")) > now_ts
        except (TypeError, ValueError):
            is_time_ok = True
        is_active = user_access_allowed(u, now_ts)

        if is_active:
            active_count += 1

        if not is_traffic_ok:
            status_html = '<span class="status-pill expired">流量超额</span>'
        elif not is_time_ok:
            status_html = '<span class="status-pill expired">已到期</span>'
        elif u.get("status", "active") != "active":
            status_html = '<span class="status-pill expired">已停用</span>'
        else:
            status_html = '<span class="status-pill active">正常</span>'

        expires_str = _expiry_text(u.get("expires_at"))
        # 设备上限与在线数可能是 `"5"`、None 或旧格式（在线 IP 存成数字）。
        # 直接比较 `> 0` / `len(...)` 会让整页 500 —— 与 created_at 同一类问题。
        ip_limit = _safe_int(u.get("ip_limit") or 0)
        ip_limit_str = f"{ip_limit} IP" if ip_limit > 0 else "不限"
        online_raw = u.get("online_ips")
        online_ips = len(online_raw) if isinstance(online_raw, (dict, list)) else _safe_int(online_raw or 0)
        online_str = f'<span class="badge-count" style="font-size:11px;">{online_ips} 在线</span>' if online_ips > 0 else '<span style="color:var(--muted)">0</span>'
        
        # 流量展示与进度条
        if limit_bytes > 0:
            percent = min(round((used_bytes / limit_bytes) * 100), 100)
            bar_class = "danger" if percent >= 90 else ""
            traffic_display = f"""<div><span data-user-usage="{html.escape(uid)}">{format_bytes(used_bytes)}</span> / {format_bytes(limit_bytes)} <span style="font-size:11px;color:var(--muted)">({percent}%)</span></div>
            <div class="traffic-bar"><div class="traffic-fill {bar_class}" style="width:{percent}%"></div></div>"""
        else:
            traffic_display = f"""<div><span data-user-usage="{html.escape(uid)}">{format_bytes(used_bytes)}</span> <span style="font-size:11px;color:var(--muted)">(不限)</span></div>"""

        note = user_note_text(u.get("note"))
        user_key = user_view_key(session_secret, uid, u.get('view_nonce', '')) if session_secret else ""

        row_state = "active" if is_active else "inactive"
        row_search = html.escape((uid + " " + ("-" if note == "-" else note)).lower())
        user_rows.append(f"""<tr data-user-row data-state="{row_state}" data-search="{row_search}">
          <td class="uid-cell"><strong title="{html.escape(uid)}">{html.escape(uid)}</strong><div class="uid-note" title="{html.escape(note)}">{html.escape(note)}</div></td>
          <td>{status_html}</td>
          <td>{ip_limit_str} ({online_str})</td>
          <td>
            {traffic_display}
            <div style="margin-top:4px"><span class="speed-badge" data-user-speed="{html.escape(uid)}">↓ 0 B/s · ↑ 0 B/s</span></div>
          </td>
          <td>{expires_str}</td>
          <td><code style="font-size:11px">{html.escape(u.get("password","")[:4] + "****" + u.get("password","")[-4:])}</code></td>
          <td>
            {'' if uid == MASTER_USER_ID else f'''<button class="button primary btn-user-connect" style="padding:4px 10px;font-size:11px;margin-right:6px" type="button" data-uid="{html.escape(uid)}" data-token="{token}" data-key="{user_key}">专属连接</button>'''}
            {'' if uid == MASTER_USER_ID else f'''<form method="POST" action="/{token}/manage-user" style="display:inline" class="js-confirm-delete" data-confirm="确定注销此用户？此操作不可撤销。">
              <input type="hidden" name="action" value="delete">
              <input type="hidden" name="user_id" value="{html.escape(uid)}">
              <button class="button danger" style="padding:4px 10px;font-size:11px" type="submit">删除</button>
            </form>'''}
            {'<span style="font-size:11px;color:var(--muted)">机主账号不可注销，也不提供专属分享链接（其密码即节点主密码，链接不会轮换）</span>' if uid == MASTER_USER_ID else ''}
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

    # 接入 TEYIR 控制台（hy2-ops-console）用的四个字段。
    #
    # 设计要点：username/password 本来就已经以明文出现在本页的订阅链接里
    # （field_sub = clash-subscription 那条 https://user:password@host:port/…），
    # 而本页本身又必须通过 Basic 鉴权才打得开 —— 能看到这一页的人，手上必然
    # 已经有这对凭据。所以把四项单列出来**没有引入任何新的暴露面**，
    # 只是把「翻 SSH cat 文件」换成「点一下复制」。
    #
    # 反过来，绝不能把这份负载挂到 /api/v1/ 的 Bearer 链路上去：api_key 的权限
    # 明确低于 Basic（前者够不着门户网页端），用低权限凭据换高权限凭据就是提权。
    access_url = f"https://{host}:{sub_port}/{token}/"
    access_json = json.dumps(
        portal_access_payload(access_url, username, password, api_key or ""),
        ensure_ascii=False)
    field_access_json = (
        f'<textarea id="teyir-access-json" class="config" aria-label="teyir-access-json" '
        f'readonly spellcheck="false" style="height:92px">{html.escape(access_json)}</textarea>')
    copy_access_json = copy("teyir-access-json")

    def _access_row(identifier, label, value):
        """克隆既有 api-box 的结构，保持与「API 基础地址」一行完全一致的观感。"""
        return (f'<div class="api-box"><div><div style="font-size:11px;color:var(--muted);'
                f'font-weight:700">{label}</div>'
                f'<div class="api-key-code" id="{identifier}">{html.escape(value)}</div></div>'
                f'<button class="button" type="button" data-copy="{identifier}" '
                f'data-orig="复制">复制</button></div>')

    teyir_block = f"""
<section class="card" id="teyir-join-card" style="border-left:4px solid var(--accent)">
  <div class="card-head"><span class="step">面板</span><div>
    <h2>接入 TEYIR 控制台（一键复制）</h2>
    <p>把整份凭据粘到控制台的「添加节点」输入框，就不必再 SSH 上机器 cat 文件</p>
  </div></div>

  <div class="api-box" style="align-items:flex-start">
    <div style="flex:1;min-width:0">
      <div style="font-size:11px;color:var(--muted);font-weight:700">整份 portal-access.json（推荐：一次粘好全部字段）</div>
      {field_access_json}
    </div>
    {copy_access_json}
  </div>

  <details style="margin-top:6px">
    <summary class="hint" style="cursor:pointer">或按字段单独复制（控制台里手工填写时才需要）</summary>
    <div style="display:grid;gap:10px;margin-top:12px">
      {_access_row("teyir-url-val", "门户地址 url", access_url)}
      {_access_row("teyir-user-val", "门户用户名 username", username)}
      {_access_row("teyir-pass-val", "门户密码 password", password)}
      {_access_row("teyir-key-val", "api_key（Bearer 鉴权）", api_key or "")}
    </div>
  </details>

  <p class="hint" style="margin-top:12px">
    这四项与 <code>/etc/hysteria/portal-access.json</code> 完全一致。控制台侧：
    「节点」→「添加节点」→ 把上面整份 JSON 粘进<strong>整份 portal-access.json</strong> 输入框 →
    点「读取节点信息」→ 保存。登记后即可在面板里管理用户、代理服务、版本升级、BBR、Reality、WARP、
    AmneziaWG 与组件安装，<strong>无需 SSH 密钥或密码</strong>。
    <br>api_key 走 Bearer，权限较低（够不着门户网页端）；username + password 走 HTTP Basic，
    才是门户管理员凭据。两者请都按密码对待。
  </p>
</section>
"""

    return f"""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>HY2 · 节点与集群中心</title><style>{STYLE}</style></head><body><main>
<nav class="topbar" aria-label="页面标识"><div class="brand"><span class="logo">H₂</span> HYSTERIA <span> / 控制中心</span></div><span class="private">● 集群运行中</span></nav>
<header class="hero"><div class="eyebrow">HYSTERIA 2 NODE DASHBOARD</div><h1>{html.escape(host)}</h1><p>官方核心驱动 · 极速 QUIC 代理 · 多用户开户与流量/IP限制{fake_sni_hint}</p>
<form method="POST" action="/{token}/logout" style="margin-top:10px"><button class="button" type="submit" style="padding:6px 14px;font-size:12px">退出登录</button></form></header>

<!-- 顶部 Tab 导航栏 -->
<div class="tab-bar">
  <button class="tab-btn active" data-tab="connect" type="button">🚀 节点导入 (Connect)</button>
  <button class="tab-btn" data-tab="users" type="button">👥 多用户管理 ({active_count}/{len(users)})</button>
  <button class="tab-btn" data-tab="proxies" type="button">🧩 扩展服务</button>
  <button class="tab-btn" data-tab="reality" type="button">🛡️ 备用通道与网络</button>
  <button class="tab-btn" data-tab="cores" type="button">🧱 核心管理</button>
  <button class="tab-btn" data-tab="cluster" type="button">🔑 接入控制台 / REST API</button>
  <button class="tab-btn" data-tab="configs" type="button">⚙️ 系统与版本</button>
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
        <span class="badge-count" style="background:#f0f7f6">总已用流量: <span id="total-used-bytes">{format_bytes(total_used_bytes)}</span></span>
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
          <input id="f_days" name="duration_days" type="number" min="1" max="36500" value="30" placeholder="默认 30 天">
          <small>从创建时间起算的有效天数</small>
        </div>

        <div class="form-field">
          <label for="f_traffic">流量限额 (GB) <span>0 为不限</span></label>
          <input id="f_traffic" name="traffic_gb" type="number" step="0.5" min="0" value="0" placeholder="输入例如 100">
          <small>达到限额后系统将自动阻断连接</small>
        </div>

        <div class="form-field">
          <label for="f_iplimit">同时在线网络数 <span>按公网 IP 计，0 为不限</span></label>
          <input id="f_iplimit" name="ip_limit" type="number" min="0" max="1000" value="0" placeholder="例如填 1 或 2">
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

    <div class="user-toolbar">
      <input id="user-search" type="search" aria-label="搜索用户" placeholder="搜索用户标识 / 备注 / 订单号" autocomplete="off">
      <select id="user-filter" aria-label="按状态筛选">
        <option value="all">全部状态</option>
        <option value="active">仅正常</option>
        <option value="inactive">仅异常（到期/超额/停用）</option>
      </select>
      <span class="user-count" id="user-count"></span>
    </div>
    <div class="user-table-wrap user-table-scroll">
      <table class="user-table">
        <thead><tr><th>用户标识</th><th>状态</th><th>IP 限制 (实时)</th><th>已用流量 / 配额</th><th>到期时间</th><th>连接密码</th><th>操作</th></tr></thead>
        <tbody id="user-tbody">{users_table_html}</tbody>
      </table>
    </div>
    <div class="user-pager" id="user-pager"></div>
  </section>
</div>

<!-- Tab 3: 扩展服务视图 —— 入站代理 / WARP 分流 / 自定义出站 / AmneziaWG -->
<div class="tab-pane" id="pane-proxies">
  <!-- 这四块互相独立，原来全部纵向堆在一页里：最长的「自定义出站」把
       AmneziaWG 推到几屏之外，用户以为没有这个功能。改为组内子标签，
       每页只呈现一件事；按钮 id 与接口保持不变。 -->
  <div class="subtab-bar" role="tablist" aria-label="扩展服务分类">
    <button class="subtab-btn active" data-subtab="ingress" type="button">🌐 入站代理</button>
    <button class="subtab-btn" data-subtab="warp" type="button">⚡ WARP 分流</button>
    <button class="subtab-btn" data-subtab="outbound" type="button">🔀 自定义出站</button>
    <button class="subtab-btn" data-subtab="awg" type="button">🛡️ AmneziaWG</button>
  </div>
  <div class="subtab-pane active" id="sub-ingress">
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
            <input id="custom-proxy-port" type="number" aria-label="自定义端口" min="1" max="65535" placeholder="输入自定义端口(留空则随机)" style="width:200px;height:34px;padding:0 10px;border:1px solid var(--line);border-radius:6px;font-size:12px">
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
  </div>

  <div class="subtab-pane" id="sub-warp">
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
  </div>

  <div class="subtab-pane" id="sub-outbound">
  <!-- 区块 2.5: 自定义出站（全局出口 / 自定义 http·socks5 代理） -->
  <section class="card ob-card" style="margin-top:0">
    <div class="ob-head">
      <div class="ob-title-box">
        <h2 class="ob-title">🌐 自定义出站（全局出口 · 第三方代理）</h2>
        <p style="font-size:13px;margin:4px 0 0;color:var(--muted)">
          让流量走你自己指定的出口：可把<b>全部流量</b>交给一个代理，或让特定域名分别走不同代理。
        </p>
      </div>
      <span class="ob-mode-badge" id="ob-mode-badge">加载中...</span>
    </div>

    <!-- 出站模式：分流 / 全局 -->
    <div class="ob-mode-card">
      <div class="ob-mode-title">🎚️ 出站模式</div>
      <div class="ob-mode-switch">
        <button class="ob-mode-btn active" id="btn-ob-mode-rules" data-mode="rules" type="button">
          <b>按域名分流</b>
          <span>名单内走指定出站，其余走直连</span>
        </button>
        <button class="ob-mode-btn" id="btn-ob-mode-global" data-mode="global" type="button">
          <b>全局出口</b>
          <span>所有流量都走第一个出站</span>
        </button>
      </div>
      <p class="ob-mode-note" id="ob-mode-note">
        全局模式下，客户端访问任何网站都从你指定的出口出去（对解锁 AI、换 IP 场景最有效）。
      </p>
    </div>

    <!-- 真实出口 IP 探测 -->
    <div class="ob-probe-card">
      <div class="ob-probe-left">
        <div class="ob-probe-title">📍 当前真实出口 IP</div>
        <div class="ob-probe-ip" id="ob-outbound-ip">探测中...</div>
        <div class="ob-probe-sub" id="ob-outbound-ip-note">这是客户端流量出去时对方看到的地址</div>
      </div>
      <div class="ob-probe-actions">
        <select id="ob-probe-kind" class="ob-select" style="max-width:170px">
          <option value="direct">直连（服务器本机）</option>
          <option value="warp">WARP (127.0.0.1:19898)</option>
          <option value="socks5">自定义 SOCKS5</option>
          <option value="http">自定义 HTTP</option>
        </select>
        <input type="text" id="ob-probe-addr" class="ob-input" style="max-width:190px"
               placeholder="1.2.3.4:1080 或 http://1.2.3.4:8080" hidden>
        <button class="button" id="btn-ob-probe" type="button">探测出口</button>
      </div>
    </div>

    <!-- 自定义出站列表 -->
    <div class="ob-list-card">
      <div class="ob-list-head">
        <span class="ob-list-title">📦 已配置的出站</span>
        <span class="ob-count-badge" id="ob-count">0 个</span>
      </div>
      <div class="ob-list" id="ob-list">
        <span style="font-size:12px;color:var(--muted)">加载中...</span>
      </div>
    </div>

    <!-- 新增/编辑出站表单 -->
    <div class="ob-form-card">
      <div class="ob-form-title" id="ob-form-title">➕ 新增出站</div>
      <div class="ob-form-grid">
        <label class="ob-field">
          <span>名称</span>
          <input type="text" id="ob-name" class="ob-input" placeholder="例如：us_exit">
          <em>只能用字母数字与下划线；横线会自动转为下划线</em>
        </label>
        <label class="ob-field">
          <span>类型</span>
          <select id="ob-type" class="ob-select">
            <option value="socks5">SOCKS5 代理</option>
            <option value="http">HTTP / HTTPS 代理</option>
            <option value="direct">直连（服务器本地网络）</option>
          </select>
          <em id="ob-type-hint">需填 host:port</em>
        </label>
      </div>
      <!-- SOCKS5 专用字段 -->
      <div class="ob-form-block" id="ob-block-socks5">
        <label class="ob-field ob-field-wide">
          <span>SOCKS5 地址</span>
          <input type="text" id="ob-socks-addr" class="ob-input" placeholder="1.2.3.4:1080 或 1.2.3.4:1080">
        </label>
        <div class="ob-form-grid">
          <label class="ob-field">
            <span>用户名（可选）</span>
            <input type="text" id="ob-socks-user" class="ob-input" placeholder="留空表示无认证">
          </label>
          <label class="ob-field">
            <span>密码（可选）</span>
            <input type="text" id="ob-socks-pass" class="ob-input" placeholder="留空表示无认证">
          </label>
        </div>
      </div>
      <!-- HTTP 专用字段 -->
      <div class="ob-form-block" id="ob-block-http" hidden>
        <label class="ob-field ob-field-wide">
          <span>HTTP 代理地址</span>
          <input type="text" id="ob-http-url" class="ob-input" placeholder="http://1.2.3.4:8080">
          <em>HTTP 出站不支持 UDP，UDP 流量会被拒绝</em>
        </label>
        <label class="ob-inline-check">
          <input type="checkbox" id="ob-http-insecure">
          <span>跳过证书校验（代理是自签 https 证书时勾选）</span>
        </label>
      </div>
      <div class="ob-form-actions">
        <button class="button primary" id="btn-ob-save" type="button">保存并生效</button>
        <button class="button" id="btn-ob-cancel" type="button" hidden>取消编辑</button>
        <span class="ob-form-msg" id="ob-form-msg"></span>
      </div>
    </div>

    <!-- 分流规则（每条可指定走哪个出站）-->
    <div class="ob-rules-card">
      <div class="ob-list-head">
        <span class="ob-list-title">🎯 分流规则（仅在「按域名分流」模式下生效）</span>
        <span class="ob-count-badge" id="ob-rules-count">0 条</span>
      </div>
      <div class="ob-add-form">
        <input type="text" id="ob-rule-domain" class="ob-input" placeholder="域名，如 openai.com">
        <select id="ob-rule-outbound" class="ob-select" style="max-width:200px"></select>
        <button class="button" id="btn-ob-rule-add" type="button">添加规则</button>
      </div>
      <div class="ob-rules-list" id="ob-rules-list">
        <span style="font-size:12px;color:var(--muted)">加载中...</span>
      </div>
    </div>
  </section>
  </div>

  <div class="subtab-pane" id="sub-awg">
  <!-- 区块 3: AmneziaWG 抗 DPI 协议 (用户态 WireGuard 分支) -->
  <section class="card awg-card" style="margin-top:0">
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
</div>

<!-- Tab 4: 备用通道与网络加速（Reality / 证书 / BBR） -->
<div class="tab-pane" id="pane-reality">
  <div class="subtab-bar" role="tablist" aria-label="备用通道与网络分类">
    <button class="subtab-btn active" data-subtab="reality-node" type="button">🛡️ Reality 备用节点</button>
    <button class="subtab-btn" data-subtab="vmess" type="button">🧩 VMess 兼容通道</button>
    <button class="subtab-btn" data-subtab="vlessenc" type="button">🔐 VLESS Encryption</button>
    <button class="subtab-btn" data-subtab="anytls" type="button">🧬 AnyTLS</button>
    <button class="subtab-btn" data-subtab="cert" type="button">🔐 证书状态</button>
    <button class="subtab-btn" data-subtab="bbr" type="button">🚀 BBR 加速</button>
  </div>
  <div class="subtab-pane active" id="sub-reality-node">
  <section class="card" style="margin-bottom:22px">
    <div class="user-header">
      <div>
        <h2>🛡️ VLESS-Reality 应急抗封锁备用节点</h2>
        <p style="font-size:13px">采用 TCP + TLS 1.3 偷取大厂证书真实握手伪装（借尸还魂），彻底免疫 UDP 丢包限制与 QoS 扼杀</p>
      </div>
      <div style="display:flex;gap:10px;align-items:center">
        <span class="status-pill" id="reality-badge" style="background:#f1efe8;color:#5f5e5a">检测中...</span>
        <button class="button primary js-goto" data-goto="cores" id="btn-install-xray" type="button" style="padding:6px 14px;font-size:12px;display:none">🧱 前往核心管理安装</button>
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
          <div class="tags"><span class="tag">VLESS</span><span class="tag">Reality</span><span class="tag">Vision</span><span class="tag" id="reality-port-tag">TCP --</span></div>
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
  </div>

  <div class="subtab-pane" id="sub-vmess">
  <!-- VMess-WS-TLS 独立卡片（2026-10-24 加）。
       与 Reality 分开一张卡、各自一个开关：两者共用 Xray 进程，但启用条件
       完全不同（Reality 偷握手，VMess 必须出示自己的域名证书），
       混在一个开关里会出现「点了开启，其实只开了其中一个」。 -->
  <section class="card" style="margin-bottom:22px">
    <div class="user-header">
      <div>
        <h2>🧩 VMess-WS-TLS 兼容通道</h2>
        <p style="font-size:13px">WebSocket + TLS 标准协议，兼容仅支持 VMess 的老客户端；与 Reality 共用 Xray 核心，可同时开启</p>
      </div>
      <div style="display:flex;gap:10px;align-items:center">
        <span class="status-pill" id="vmess-badge" style="background:#f1efe8;color:#5f5e5a">检测中...</span>
        <button class="button primary js-goto" data-goto="cores" id="vmess-goto-cores" type="button" style="padding:6px 14px;font-size:12px;display:none">🧱 前往核心管理安装</button>
        <button class="toggle-btn off" id="btn-toggle-vmess" type="button" style="display:none">切换中...</button>
      </div>
    </div>
    <div class="warp-switch-card" style="background:#f7f9fc;border-color:#d7e2ee">
      <div class="warp-desc-title" style="color:#1a365d">🔐 与 Reality 的区别</div>
      <p class="warp-desc-text" style="color:#4a5568">
        Reality 借用大厂证书握手，无需自己的域名；VMess-WS 是真正的 TLS 服务端，
        <b>必须已绑定域名且持有可被客户端校验的证书</b>（自签证书会被拒绝启用）。
        端口自动挑选空闲 TCP 端口，WS 路径随机生成并保持稳定。
      </p>
    </div>
    <div id="vmess-content-box" style="display:none">
      <div class="layout" style="margin-top:10px">
        <section class="card qr-card" style="background:#fbfcfd;border-color:var(--line)">
          <div class="eyebrow" style="color:#7c3aed">VMESS CONNECT</div>
          <h2>VMess 节点扫码</h2>
          <p class="hint">适用于 v2rayN / NekoBox / Shadowrocket</p>
          <div class="qr-frame" style="max-width:220px;margin:16px auto;padding:10px"><div id="vmess-qr-box" style="width:100%;height:auto"></div></div>
          <div class="tags"><span class="tag">VMess</span><span class="tag">WebSocket</span><span class="tag">TLS</span><span class="tag" id="vmess-port-tag">TCP --</span></div>
        </section>
        <div class="stack">
          <section class="card" style="border-color:#d7e2ee">
            <div class="card-head"><span class="step" style="background:#f3e8ff;color:#7c3aed">01</span><div><h2>VMess 直链 (URI)</h2><p>Base64 标准格式，导入即用</p></div></div>
            <textarea class="link" id="vmess-uri-val" readonly style="height:86px;font-size:11.5px"></textarea>
            <div class="actions" style="margin-top:12px">
              <button class="button primary" id="btn-copy-vmess-uri" type="button">复制 VMess 直链</button>
            </div>
          </section>
          <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px">
            <div style="background:#fbfcfd;border:1px solid var(--line);border-radius:12px;padding:12px">
              <div style="font-size:11px;color:var(--muted);font-weight:700;margin-bottom:2px">域名 / SNI</div>
              <div style="font-size:13px;font-weight:750;color:var(--ink);font-family:monospace" id="vmess-domain-val">-</div>
            </div>
            <div style="background:#fbfcfd;border:1px solid var(--line);border-radius:12px;padding:12px">
              <div style="font-size:11px;color:var(--muted);font-weight:700;margin-bottom:2px">用户 UUID</div>
              <div style="font-size:12px;font-weight:750;color:var(--ink);font-family:monospace;word-break:break-all" id="vmess-uuid-val">-</div>
            </div>
            <div style="background:#fbfcfd;border:1px solid var(--line);border-radius:12px;padding:12px">
              <div style="font-size:11px;color:var(--muted);font-weight:700;margin-bottom:2px">WS 路径</div>
              <div style="font-size:12px;font-weight:750;color:var(--ink);font-family:monospace;word-break:break-all" id="vmess-path-val">-</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </section>
  </div>

  <div class="subtab-pane" id="sub-vlessenc">
  <!-- VLESS Encryption（2026-10-24 加）：VMess 的上游替代路线，
       与 VMess 一样需要域名 + 可信证书，但多一层后量子密钥交换。 -->
  <section class="card" style="margin-bottom:22px">
    <div class="user-header">
      <div>
        <h2>🔐 VLESS Encryption 通道</h2>
        <p style="font-size:13px">Xray 官方推荐的 VMess 替代方案：ML-KEM-768 后量子密钥交换 + 1-RTT 前向保密；与 Reality / VMess 共用 Xray 核心，可同时开启</p>
      </div>
      <div style="display:flex;gap:10px;align-items:center">
        <span class="status-pill" id="vlessenc-badge" style="background:#f1efe8;color:#5f5e5a">检测中...</span>
        <button class="button primary js-goto" data-goto="cores" id="vlessenc-goto-cores" type="button" style="padding:6px 14px;font-size:12px;display:none">🧱 前往核心管理安装</button>
        <button class="toggle-btn off" id="btn-toggle-vlessenc" type="button" style="display:none">切换中...</button>
      </div>
    </div>
    <div class="warp-switch-card" style="background:#f7f9fc;border-color:#d7e2ee">
      <div class="warp-desc-title" style="color:#1a365d">🔐 与 Reality / VMess 的区别</div>
      <p class="warp-desc-text" style="color:#4a5568">
        Reality 借用大厂证书握手，无需自己的域名；VLESS Encryption 与 VMess 一样是
        <b>真正的 TLS 服务端，必须已绑定域名且持有可被客户端校验的证书</b>。
        相比 VMess，它带后量子密钥交换与前向保密，是上游推荐的方向。
        <b>需要较新的客户端支持</b>，老客户端可能无法识别该加密参数。
      </p>
    </div>
    <div id="vlessenc-content-box" style="display:none">
      <div class="layout" style="margin-top:10px">
        <section class="card qr-card" style="background:#fbfcfd;border-color:var(--line)">
          <div class="eyebrow" style="color:#0f766e">VLESS ENCRYPTION</div>
          <h2>VLESS Encryption 扫码</h2>
          <p class="hint">需要支持 VLESS Encryption 的新版客户端</p>
          <div class="qr-frame" style="max-width:220px;margin:16px auto;padding:10px"><div id="vlessenc-qr-box" style="width:100%;height:auto"></div></div>
          <div class="tags"><span class="tag">VLESS</span><span class="tag">ML-KEM-768</span><span class="tag">TLS</span><span class="tag" id="vlessenc-port-tag">TCP --</span></div>
        </section>
        <div class="stack">
          <section class="card" style="border-color:#d7e2ee">
            <div class="card-head"><span class="step" style="background:#ccfbf1;color:#0f766e">01</span><div><h2>VLESS 直链 (URI)</h2><p>含 encryption 参数，导入即用</p></div></div>
            <textarea class="link" id="vlessenc-uri-val" readonly style="height:86px;font-size:11.5px"></textarea>
            <div class="actions" style="margin-top:12px">
              <button class="button primary" id="btn-copy-vlessenc-uri" type="button">复制 VLESS 直链</button>
            </div>
          </section>
          <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px">
            <div style="background:#fbfcfd;border:1px solid var(--line);border-radius:12px;padding:12px">
              <div style="font-size:11px;color:var(--muted);font-weight:700;margin-bottom:2px">域名 / SNI</div>
              <div style="font-size:13px;font-weight:750;color:var(--ink);font-family:monospace" id="vlessenc-domain-val">-</div>
            </div>
            <div style="background:#fbfcfd;border:1px solid var(--line);border-radius:12px;padding:12px">
              <div style="font-size:11px;color:var(--muted);font-weight:700;margin-bottom:2px">用户 UUID</div>
              <div style="font-size:12px;font-weight:750;color:var(--ink);font-family:monospace;word-break:break-all" id="vlessenc-uuid-val">-</div>
            </div>
            <div style="background:#fbfcfd;border:1px solid var(--line);border-radius:12px;padding:12px">
              <div style="font-size:11px;color:var(--muted);font-weight:700;margin-bottom:2px">监听端口</div>
              <div style="font-size:13px;font-weight:750;color:var(--ink);font-family:monospace" id="vlessenc-tcp-val">-</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </section>
  </div>

  <div class="subtab-pane" id="sub-anytls">
  <!-- AnyTLS（2026-10-28 加）：由独立的 sing-box 进程承载，不在 xray.json 里。 -->
  <section class="card" style="margin-bottom:22px">
    <div class="user-header">
      <div>
        <h2>🧬 AnyTLS 通道</h2>
        <p style="font-size:13px">基于 TLS 的多路复用代理，带填充以弱化 TLS-in-TLS 特征；底层走 TCP，UDP 由客户端封装转发。由 sing-box 承载，与 Xray 上的协议互不影响</p>
      </div>
      <div style="display:flex;gap:10px;align-items:center">
        <span class="status-pill" id="anytls-badge" style="background:#f1efe8;color:#5f5e5a">检测中...</span>
        <button class="button primary js-goto" data-goto="cores" id="anytls-goto-cores" type="button" style="padding:6px 14px;font-size:12px;display:none">🧱 前往核心管理安装</button>
        <button class="toggle-btn off" id="btn-toggle-anytls" type="button" style="display:none">切换中...</button>
      </div>
    </div>
    <div class="warp-switch-card" style="background:#f7f9fc;border-color:#d7e2ee">
      <div class="warp-desc-title" style="color:#1a365d">🧬 启用前须知</div>
      <p class="warp-desc-text" style="color:#4a5568">
        AnyTLS 是真正的 TLS 服务端，<b>必须已绑定域名且持有可被客户端校验的证书</b>（与 VMess / VLESS Encryption 相同）。
        首次开启会从 SagerNet/sing-box 官方 Release 下载并校验 sing-box（需 1.12+），可能需要一两分钟。
        客户端需支持 AnyTLS：Clash Verge / mihomo、sing-box 1.12+、Shadowrocket 等。
        每个用户有独立密码，停用 / 到期 / 超额会同步收回。<b>AnyTLS 的流量暂不计入用户已用流量。</b>
      </p>
    </div>
    <div id="anytls-content-box" style="display:none">
      <div class="layout" style="margin-top:10px">
        <section class="card qr-card" style="background:#fbfcfd;border-color:var(--line)">
          <div class="eyebrow" style="color:#0f766e">ANYTLS</div>
          <h2>AnyTLS 扫码</h2>
          <p class="hint">机主账号的连接；其他用户请用「专属连接」</p>
          <div class="qr-frame" style="max-width:220px;margin:16px auto;padding:10px"><div id="anytls-qr-box" style="width:100%;height:auto"></div></div>
          <div class="tags"><span class="tag">AnyTLS</span><span class="tag">TLS</span><span class="tag" id="anytls-port-tag">TCP --</span></div>
        </section>
        <div class="stack">
          <section class="card" style="border-color:#d7e2ee">
            <div class="card-head"><span class="step" style="background:#ccfbf1;color:#0f766e">01</span><div><h2>AnyTLS 直链 (URI)</h2><p>anytls:// 格式，导入即用</p></div></div>
            <textarea class="link" id="anytls-uri-val" readonly style="height:86px;font-size:11.5px"></textarea>
            <div class="actions" style="margin-top:12px">
              <button class="button primary" id="btn-copy-anytls-uri" type="button">复制 AnyTLS 直链</button>
            </div>
          </section>
          <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px">
            <div style="background:#fbfcfd;border:1px solid var(--line);border-radius:12px;padding:12px">
              <div style="font-size:11px;color:var(--muted);font-weight:700;margin-bottom:2px">域名 / SNI</div>
              <div style="font-size:13px;font-weight:750;color:var(--ink);font-family:monospace" id="anytls-domain-val">-</div>
            </div>
            <div style="background:#fbfcfd;border:1px solid var(--line);border-radius:12px;padding:12px">
              <div style="font-size:11px;color:var(--muted);font-weight:700;margin-bottom:2px">监听端口</div>
              <div style="font-size:13px;font-weight:750;color:var(--ink);font-family:monospace" id="anytls-tcp-val">-</div>
            </div>
            <div style="background:#fbfcfd;border:1px solid var(--line);border-radius:12px;padding:12px">
              <div style="font-size:11px;color:var(--muted);font-weight:700;margin-bottom:2px">sing-box 版本</div>
              <div style="font-size:13px;font-weight:750;color:var(--ink);font-family:monospace" id="anytls-ver-val">-</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </section>
  </div>
  <div class="subtab-pane" id="sub-cert">
  <!-- 区块: 证书状态与到期告警
       为什么放在最前面：证书过期/临期是「昨天还好好的、今天突然连不上」里最高频的真凶，
       而自动自愈只对齐信任模型、不会去续期证书 —— 不把剩余天数摆出来就只能在掉线后才发现。 -->
  <section class="card cert-section">
    <div class="user-header">
      <div>
        <h2>🔐 证书状态与到期提醒</h2>
        <p style="font-size:13px">节点对外服务所用的 TLS 证书。临期与过期会在此提前告警，避免突然掉线</p>
      </div>
      <div style="display:flex;gap:10px;align-items:center">
        <span class="status-pill" id="cert-badge" style="background:#eaf5ef;color:var(--accent)">检测中...</span>
      </div>
    </div>

    <div class="cert-bar">
      <div style="font-size:13px;font-weight:750;color:var(--ink)">
        剩余有效天数: <span class="bbr-stat-val" id="cert-daysleft">--</span>
      </div>
      <div class="bbr-sub-text">到期时刻 (notAfter): <span id="cert-notafter" style="font-family:monospace">--</span></div>
    </div>

    <div class="cert-fields">
      <div><div class="cert-field-label">证书主体 (CN)</div><div class="cert-field-val" id="cert-cn">--</div></div>
      <div><div class="cert-field-label">覆盖域名 (SAN)</div><div class="cert-field-val" id="cert-sans">--</div></div>
      <div><div class="cert-field-label">签发方</div><div class="cert-field-val" id="cert-issuer">--</div></div>
      <div><div class="cert-field-label">证书类型</div><div class="cert-field-val" id="cert-type">--</div></div>
      <div><div class="cert-field-label">订阅使用的 SNI</div><div class="cert-field-val" id="cert-servername">--</div></div>
      <div><div class="cert-field-label">指纹校验 (pinSHA256)</div><div class="cert-field-val" id="cert-pin">--</div></div>
    </div>

    <div class="cert-alert" id="cert-alert"></div>
    <div class="cert-heal-note" id="cert-heal-note" style="display:none"></div>
  </section>
  </div>

  <div class="subtab-pane" id="sub-bbr">
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
</div>

<!-- Tab 3: 集群与通用 REST API 对接视图 -->
<!-- 核心管理（2026-10-28）：所有核心集中在这里看装没装、版本与服务状态，
     Xray / sing-box 在这里单独安装；各协议页只负责启停，不再各自放安装按钮。 -->
<div class="tab-pane" id="pane-cores">
  <section class="card">
    <div class="user-header">
      <div>
        <h2>🧱 核心管理</h2>
        <p style="font-size:13px">各协议依赖的核心程序：安装状态、版本、服务运行情况。装好核心后，到对应协议页打开开关即可使用</p>
      </div>
      <button class="button" id="btn-refresh-cores" type="button" style="padding:6px 14px;font-size:12px">↻ 刷新</button>
    </div>
    <div class="core-grid" id="core-grid"><div class="core-empty">检测中...</div></div>
  </section>
</div>

<div class="tab-pane" id="pane-cluster">
{teyir_block}

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
    <div class="card-head"><span class="step">UP</span><div><h2>系统版本与一键更新</h2><p>在线比对并升级 Hysteria 2 官方内核、控制面板自身与 AmneziaWG 引擎</p></div></div>

    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:16px;margin-bottom:16px">
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
      <!-- AmneziaWG 引擎版本 -->
      <div class="api-box" style="margin-bottom:0">
        <div>
          <div style="font-size:11px;color:var(--muted);font-weight:700">AmneziaWG 引擎 (hy2-awgctl)</div>
          <div style="font-size:14px;font-weight:700;margin-top:4px" id="awg-ver-display">检测中...</div>
        </div>
        <button class="button primary" id="btn-update-awg-engine" type="button" style="display:none">一键更新 AWG</button>
      </div>
    </div>

    <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
      <button class="button" id="btn-recheck-update" type="button" style="padding:5px 13px;font-size:12px">🔄 重新检测</button>
      <div id="update-status-msg" style="font-size:12px;color:var(--muted)"></div>
    </div>

    <p style="font-size:11.5px;color:var(--muted);margin:10px 0 0;line-height:1.75">
      面板按<b>六个文件的整包内容指纹</b>与仓库 main 分支比对，任何文件不同或缺失都会提示更新；远端检测不完整时会明确提示。核心与 AWG 分别检测版本与文件内容。
      更新面板时会先留一份 <code>.bak</code> 备份再原子替换，并自动重启面板服务；更新 AWG 引擎不会影响已发放的客户端配置。
      远端结果在服务端缓存 5 分钟，避免触发 GitHub 的接口限流。
    </p>
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
<div class="modal-backdrop" id="custom-confirm-modal" role="dialog" aria-modal="true" aria-labelledby="confirm-title" aria-describedby="confirm-text">
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
    # token 来自 portal.json：被手工改成含引号/尖括号时，它会原样进 action
    # 属性 —— 既能破坏表单，也是一条自伤 XSS。error_msg 同理，且非字符串时
    # html.escape 直接抛 AttributeError，登录页变成 500（谁都进不来）。
    token = token if isinstance(token, str) else ''
    error_banner = ''
    if isinstance(error_msg, str) and error_msg:
        error_banner = ('<div class="error-tip" role="alert"><span>⚠</span><span>'
                        f'{html.escape(error_msg)}</span></div>')
    return f'''<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>验证访问 · Hysteria 2 节点中心</title><style>{STYLE}</style></head><body>
<div class="login-wrap"><div class="login-card">
<div class="login-brand"><div class="login-logo">H₂</div><div class="login-badge">HYSTERIA 2 GATEWAY</div><h1 class="login-title">私密身份认证</h1><p class="login-sub">请输入服务器生成的专属凭据以进入节点中心</p></div>
<form class="login-form" method="POST" action="/{html.escape(token)}/login">
{error_banner}
<div class="field-group"><label class="field-label" for="username">用户名 (Username)</label><input class="field-input" id="username" name="username" type="text" autocomplete="username" required autofocus placeholder="输入随机生成的用户名"></div>
<div class="field-group"><div class="field-label"><label for="password">密码 (Password)</label></div><div class="field-pwd"><input class="field-input" id="password" name="password" type="password" autocomplete="current-password" required placeholder="输入访问密钥"><button type="button" class="toggle-pwd">显示</button></div></div>
<div class="remember-row"><input type="checkbox" id="remember" name="remember" value="1" checked><label for="remember">在此浏览器保持登录（30天）</label></div>
<button class="btn-submit" type="submit">立即进入私密中心 →</button>
</form>
<div class="login-footer">如果遗忘凭据，随时在服务器终端执行<br><code>bash install.sh info</code> 找回账号密码</div>
</div></div>
<script>{LOGIN_SCRIPT}</script></body></html>'''



def share_unavailable_html(reason):
    """分享链接不可用时给一个可读的说明页，而不是一行裸 403。

    用户拿到的是一条 URL，看到英文 "Access denied" 只会以为链接坏了；
    实际原因通常是到期、超额或停用（2026-10-29 加）。
    """
    # reason 由调用方从用户记录里拼出来（停用/到期/超额），但外部也可能
    # 传进数字或列表：html.escape 会调 .replace() 直接抛 AttributeError，
    # 于是「账号不可用」这条本该给人看的说明变成 500。
    body = html.escape(reason if isinstance(reason, str) and reason else '该链接当前不可用')
    return f"""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>链接不可用</title>
<style>{STYLE}</style></head><body><main style="max-width:640px">
<header class="hero"><div class="eyebrow">HYSTERIA 2 CLIENT ACCESS</div>
<h1>链接当前不可用</h1><p>{body}</p></header>
<section class="card"><p class="hint">如需继续使用，请联系节点管理员续费或恢复账号。
本页不包含任何连接凭据。</p></section></main></body></html>"""


def _safe_int(value, default=0):
    """把任意输入转 int；失败返回 default。

    用于渲染循环里的用量/时间字段：单条坏数据不应该让整页 500。
    """
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return default

def user_page_html(server_name, host, listen_port, obfs_badge, uid, uinfo, uri, clash, sing, qr_svg, token, user_key, sub_port=None):
    # 数据被改坏时（字符串用量、非法到期时间）不能让客户页面 500：
    # 这几个值直接来自 portal.json（2026-10-30 修）。
    used_bytes = _safe_int(uinfo.get("used_bytes") or 0)
    limit_bytes = _safe_int(uinfo.get("limit_bytes") or 0)
    now_ts = int(time.time())
    # 与 user_access_allowed 同源：到点即过期、缺 status 视为 active。
    is_traffic_ok = limit_bytes <= 0 or used_bytes < limit_bytes
    _exp = uinfo.get("expires_at")
    try:
        is_time_ok = _exp is None or float(_exp) > now_ts
    except (TypeError, ValueError):
        is_time_ok = True

    if not is_traffic_ok:
        status_html = '<span class="status-pill expired">流量已超额</span>'
    elif not is_time_ok:
        status_html = '<span class="status-pill expired">服务已到期</span>'
    elif uinfo.get("status", "active") != "active":
        status_html = '<span class="status-pill expired">账号已停用</span>'
    else:
        status_html = '<span class="status-pill active">运行正常</span>'

    expires_str = _expiry_text(uinfo.get("expires_at"))
    # 与总览页同一处理：设备上限可能是 "5" / None（手工编辑或旧格式）。
    ip_limit = _safe_int(uinfo.get("ip_limit") or 0)
    # 按公网 IP 计：同一 Wi-Fi 下多台设备只占 1 个名额，文案不能写成「台设备」。
    ip_limit_str = f"{ip_limit} 个网络（同一网络下设备不限）" if ip_limit > 0 else "不限制"

    if limit_bytes > 0:
        percent = min(round((used_bytes / limit_bytes) * 100), 100)
        bar_class = "danger" if percent >= 90 else ""
        traffic_display = f"""<div>{format_bytes(used_bytes)} / {format_bytes(limit_bytes)} <span style="font-size:12px;color:var(--muted)">({percent}%)</span></div>
        <div class="traffic-bar" style="width:100%;height:8px"><div class="traffic-fill {bar_class}" style="width:{percent}%"></div></div>"""
    else:
        traffic_display = f"""<div>{format_bytes(used_bytes)} <span style="font-size:12px;color:var(--muted)">(不限制总流量)</span></div>"""

    # 备注来自请求体或手工编辑，可能是数字/列表；html.escape 会调 .replace()，
    # 非字符串直接让客户页 500。
    note = user_note_text(uinfo.get("note"))
    # 🔴 订阅端口来自**节点 meta**，不是用户对象 —— 用户对象里从来没有这个键。
    # 调用方应从 meta 传入真实端口；若未传，则按权威来源解析，
    # **绝不兜底成伪造的 8443**（8443 在本项目里是被主动避开的黑名单端口）。
    if sub_port is None:
        sub_port = resolve_subscription_port({})[0]
    clash_sub_url = f"https://{_host_for_url(host)}:{sub_port}/{token}/u/{quote(uid)}/clash.yaml?k={user_key}"

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
    # ⚠️ style-src 里的哈希只覆盖 <style> 块，**不覆盖 style="..." 属性** ——
    # CSP 里没有 style-src-attr 时，内联样式属性会被直接丢弃。本页面大量使用
    # 内联样式做颜色/间距/进度条宽度，实测（浏览器计算样式）颜色被还原成默认值，
    # 界面静默降级。这里单独放开属性级的 inline，<style> 块仍然受哈希保护。
    # （旧浏览器不认 style-src-attr，行为与现在一致，不会更差。）
    return ("default-src 'none'; connect-src 'self'; img-src 'self' data:; style-src 'sha256-" + digest(STYLE)
            + "'; style-src-attr 'unsafe-inline'; script-src " + " ".join(scripts)
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


def pin_sha256_of_file(cert_file):
    """SHA-256(DER) of an arbitrary PEM path, lowercase HEX64, or '' on failure."""
    cert_file = Path(cert_file)
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


def _config_tls_cert_path(config_path='/etc/hysteria/config.yaml'):
    """Return the leaf/fullchain cert path that Hysteria actually serves with.

    Reads `tls.cert:` from config.yaml. ACME caches are resolved separately
    by _config_acme_cert_path; they are not the self-signed server.crt.
    """
    try:
        text = Path(config_path).read_text(encoding='utf-8')
    except OSError:
        return ''
    in_tls = False
    for raw in text.split('\n'):
        if not raw.strip() or raw.lstrip().startswith('#'):
            continue
        if not raw.startswith((' ', '\t')):
            in_tls = raw.split(':', 1)[0].strip() == 'tls'
            continue
        if in_tls:
            stripped = raw.strip()
            if stripped.startswith('cert:'):
                value = stripped.split(':', 1)[1].strip().strip('"').strip("'")
                return value
            if stripped.startswith('key:'):
                in_tls = False
    return ''


def _parse_cert_subject(cert_file):
    """(common_name, [san...], self_signed_bool) for a PEM path.

    SAN is preferred over CN for the usable server_name: every browser/client
    built after 2017 ignores CN and matches only SAN, so a cert whose CN is
    right but whose SAN is empty/wrong will still fail `CRYPTO_ERROR 0x150`.
    """
    cert_file = Path(cert_file)
    if not cert_file.exists():
        return '', [], False
    try:
        # fullchain.pem holds the leaf first; openssl x509 reads the first block.
        # 分别取 CN / SAN / issuer：不要合并成一次调用再切字符串 ——
        # `-subject -ext subjectAltName -issuer` 的输出里 SAN 块夹在
        # subject 与 issuer 之间，按 issuer 切会把 SAN 块并进 CN。
        p_subj = subprocess.run(['openssl', 'x509', '-in', str(cert_file),
                                 '-noout', '-subject'], capture_output=True, timeout=5, text=True)
        p_iss = subprocess.run(['openssl', 'x509', '-in', str(cert_file),
                                '-noout', '-issuer'], capture_output=True, timeout=5, text=True)
        p_san = subprocess.run(['openssl', 'x509', '-in', str(cert_file),
                                '-noout', '-ext', 'subjectAltName'], timeout=5,
                               capture_output=True, text=True)
        if p_subj.returncode != 0:
            return '', [], False

        subject_line = p_subj.stdout.strip().split('subject=', 1)[-1].splitlines()[0].strip()
        issuer_line = p_iss.stdout.strip().split('issuer=', 1)[-1].splitlines()[0].strip() \
            if p_iss.returncode == 0 else ''
        cn = ''
        for part in subject_line.split(','):
            part = part.strip()
            if part.startswith('CN') and '=' in part:
                cn = part.split('=', 1)[1].strip()
                break

        sans = []
        for line in p_san.stdout.splitlines():
            line = line.strip()
            if line.startswith('DNS:'):
                sans = [d.strip() for d in line[len('DNS:'):].split(',') if d.strip()]
                break

        self_signed = bool(issuer_line) and issuer_line == subject_line
        return cn, sans, self_signed
    except Exception:
        return '', [], False


def _config_acme_cert_path(config_path):
    """读取内置 ACME 缓存；None 表示非 ACME，缺文件则返回预期路径。

    安装器的服务 WorkingDirectory 为配置目录，默认缓存为 ./acme。
    只匹配配置域名，不拿旧自签证书或别的域名掩盖申请失败。
    """
    try:
        text = Path(config_path).read_text(encoding='utf-8')
    except OSError:
        return None
    in_acme = False
    found_acme = False
    in_domains = False
    domains = []
    storage = ''
    ca = 'letsencrypt'
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith('#'):
            continue
        if not raw.startswith((' ', '\t')):
            in_acme = raw.split(':', 1)[0].strip() == 'acme'
            found_acme = found_acme or in_acme
            in_domains = False
            continue
        if not in_acme:
            continue
        line = raw.strip()
        if line.startswith('-') and in_domains:
            values = shlex.split(line[1:].strip(), comments=True)
            if values:
                domains.append(values[0].lower())
            continue
        key, sep, value = line.partition(':')
        if not sep:
            continue
        in_domains = key == 'domains'
        values = shlex.split(value.strip(), comments=True)
        scalar = ' '.join(values)
        if key == 'dir':
            storage = scalar
        elif key == 'ca':
            ca = scalar.lower()
        elif key == 'domains' and scalar.startswith('[') and scalar.endswith(']'):
            domains.extend(d.strip().lower() for d in scalar[1:-1].split(',') if d.strip())
    if not found_acme:
        return None
    base = Path(storage or os.environ.get('HYSTERIA_ACME_DIR') or 'acme')
    if not base.is_absolute():
        base = Path(config_path).parent / base
    # CertMagic 的存储键把通配符替换为 wildcard_。
    domains = [d.replace('*', 'wildcard_') for d in domains
               if d and '/' not in d and '\\' not in d and d not in ('.', '..')]
    issuer = ('acme.zerossl.com-v2-dv90' if ca == 'zerossl'
              else 'acme-v02.api.letsencrypt.org-directory')
    if ca.startswith(('http://', 'https://')):
        issuer = ca.split('://', 1)[1].strip('/').replace('/', '-')
    for domain in domains:
        candidate = base / 'certificates' / issuer / domain / (domain + '.crt')
        if candidate.is_file():
            return candidate
    domain = domains[0] if domains else 'unknown-domain'
    return base / 'certificates' / issuer / domain / (domain + '.crt')


def _resolve_live_cert(root, config_path='/etc/hysteria/config.yaml'):
    """返回 (cert_path, cn, sans, self_signed) —— 门户实际在用的那张证书。

    与 sync_cert_trust 共用同一套解析规则（读 config.yaml 的 tls.cert，
    相对路径按配置目录解析；ACME 读缓存，非 ACME 退回 cert/server.crt），保证
    「自愈用的证书」和「界面显示的证书」永远是同一张 —— 否则卡片显示
    A、自愈修 B，又是一轮新的不一致。
    """
    tls_cert = _config_tls_cert_path(config_path)
    cert_file = None
    if tls_cert:
        candidate = Path(tls_cert)
        if not candidate.is_absolute():
            candidate = Path(config_path).parent / candidate
        if candidate.exists():
            cert_file = candidate
    if cert_file is None:
        cert_file = _config_acme_cert_path(config_path)
    if cert_file is None:
        cert_file = Path(root) / 'cert' / 'server.crt'
    cn, sans, self_signed = _parse_cert_subject(cert_file)
    return cert_file, cn, sans, self_signed


def _cert_key_candidates(cert_file):
    """按部署布局列出私钥可能的位置。

    三种真实布局：
      * ACME（Hysteria 内置）：<domain>.crt 与 <domain>.key 同目录；
      * 安装器自签 / 指定证书：cert/server.crt 配 cert/server.key；
      * Caddy / certbot：fullchain.pem 配 privkey.pem，*.crt 配同名 *.key。
    只按文件名推断，不跨目录乱找 —— 找错私钥比找不到更危险。
    """
    cert_file = Path(cert_file)
    name = cert_file.name
    out = []
    if name.endswith('.crt'):
        out.append(cert_file.with_suffix('.key'))
    if name.endswith('.pem'):
        out.append(cert_file.with_name(name[:-4] + '.key'))
    out.append(cert_file.with_name('privkey.pem'))
    return out


def cert_key_matches(cert_file, key_file):
    """证书与私钥是否成对：比较二者的公钥指纹。"""
    try:
        pub = subprocess.run(['openssl', 'x509', '-in', str(cert_file), '-noout', '-pubkey'],
                             capture_output=True, timeout=5)
        if pub.returncode != 0:
            return False
        pub_digest = subprocess.run(['openssl', 'sha256'], input=pub.stdout,
                                    capture_output=True, timeout=5)
        prv = subprocess.run(['openssl', 'pkey', '-in', str(key_file), '-pubout'],
                             capture_output=True, timeout=5)
        if prv.returncode != 0:
            return False
        prv_digest = subprocess.run(['openssl', 'sha256'], input=prv.stdout,
                                    capture_output=True, timeout=5)
    except Exception:
        return False
    a = pub_digest.stdout.split()[-1] if pub_digest.stdout.split() else b''
    b = prv_digest.stdout.split()[-1] if prv_digest.stdout.split() else b''
    return bool(a) and a == b


def _find_cert_key(cert_file, cfg_dir):
    """为已选定的证书找出**配对**的私钥；找不到返回 None。

    先看 config.yaml 的 tls.key（显式配置优先），再按布局推断。
    """
    cfg_dir = Path(cfg_dir)
    candidates = []
    try:
        text = (cfg_dir / 'config.yaml').read_text(encoding='utf-8')
    except OSError:
        text = ''
    in_tls = False
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith('#'):
            continue
        if not raw.startswith((' ', '\t')):
            in_tls = raw.split(':', 1)[0].strip() == 'tls'
            continue
        if in_tls and raw.strip().startswith('key:'):
            value = raw.strip().split(':', 1)[1].strip().strip('"').strip("'")
            path = Path(value)
            candidates.append(path if path.is_absolute() else cfg_dir / path)
            break
    candidates.extend(_cert_key_candidates(cert_file))
    seen = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        if candidate.is_file() and cert_key_matches(cert_file, candidate):
            return candidate
    return None


# 到期告警阈值（天）。设成常量是为了让界面文案、API 返回、日志措辞一致 ——
# 三处各写一个数字必然会出现「界面说还剩 10 天、日志说还剩 30 天」。
CERT_EXPIRY_WARN_DAYS = 30
CERT_EXPIRY_CRITICAL_DAYS = 7


def cert_status(root, meta=None, config_path='/etc/hysteria/config.yaml',
                selfheal_state_path=None):
    """证书当前状态 + 到期告警，供门户卡片与 /cert-status 端点使用。

    🔴 为什么必须把「还有几天到期」摆到界面上：真实故障里最难查的一类是
    「昨天还好好的，今天突然连不上了」。绝大多数不是配置错，而是**证书过期** ——
    而过期这件事在自愈体系里是静默的（自愈只对齐信任模型，不会去续期证书）。
    卡片 + 倒计时 + 临期告警，是让这类故障在到期前就被看见的唯一办法。
    """
    root = Path(root)
    # meta 来自 client_meta.json：被截断成 list/str 时 `.get` 抛 AttributeError，
    # 证书卡片与 /cert-status 直接 500 —— 而证书到期正是最需要它的时候。
    meta = meta if isinstance(meta, dict) else {}
    cert_file, cn, sans, self_signed = _resolve_live_cert(root, config_path)

    info = {
        'ok': False,
        'cert_exists': cert_file.exists(),
        'cert_path': str(cert_file),
        'common_name': cn,
        'sans': sans,
        'self_signed': bool(self_signed),
        'issuer': '',
        'not_before': '',
        'not_after': '',
        'expires_in_days': None,
        'expires_at': None,
        'expired': False,
        'warn_level': 'unknown',      # unknown | ok | warn | critical | expired
        'server_name': meta.get('server_name', ''),
        'cert_type': meta.get('cert_type', ''),
        'is_insecure': bool(meta.get('is_insecure')),
        'pin_sha256': meta.get('pin_sha256', ''),
        'healed_at': 0,
        'heal_count': 0,
    }

    if not cert_file.exists():
        return info

    try:
        # issuer 单独取（subject 已由 _parse_cert_subject 拿过）
        p_iss = subprocess.run(['openssl', 'x509', '-in', str(cert_file), '-noout',
                                '-issuer', '-startdate', '-enddate'],
                               capture_output=True, text=True, timeout=8)
        raw = p_iss.stdout if p_iss.returncode == 0 else ''
        for line in raw.splitlines():
            line = line.strip()
            if line.startswith('issuer='):
                info['issuer'] = line.split('=', 1)[1].strip()
            elif line.startswith('notBefore='):
                info['not_before'] = line.split('=', 1)[1].strip()
            elif line.startswith('notAfter='):
                info['not_after'] = line.split('=', 1)[1].strip()
    except Exception as exc:
        _log_ignored('cert_info.openssl', exc)

    # notAfter 形如 'Oct  9 00:00:00 2027 GMT' —— 用 dateutil 之类会引入依赖，
    # 直接交给 openssl 换算成 epoch（-checkend 是相对秒数，但我们要绝对到期时刻，
    # 所以这里解析文本更稳）。解析失败就留 None，前端只显示「未知」。
    if info['not_after']:
        try:
            # ⚠️ LC_ALL=C 是必需的（2026-10-09 修）：not_after 来自 openssl，
            # 永远是英文月份（Oct  9 ...），但 GNU date 解析 'Oct' 要过 LC_TIME。
            # 在 zh_CN.UTF-8 下解析失败 -> int('') -> ValueError -> 静默留 None ->
            # warn_level 变 'unknown'，而卡片没有 unknown 分支，会显示成
            # 「● 正常 · null 天后到期」的**绿色安慰性假象**，恰好毁掉这张卡片的用途。
            ts = subprocess.run(['date', '-d', info['not_after'], '+%s'],
                                capture_output=True, text=True, timeout=5,
                                env={**os.environ, 'LC_ALL': 'C', 'LANG': 'C'})
            epoch = int(ts.stdout.strip())
            now = int(time.time())
            info['expires_in_days'] = int((epoch - now) // 86400)
            info['expires_at'] = epoch
            info['expired'] = epoch < now
        except Exception as exc:
            _log_ignored('cert_info.notAfter', exc)

    days = info['expires_in_days']
    if info['expired']:
        info['warn_level'] = 'expired'
    elif days is None:
        info['warn_level'] = 'unknown'
    elif days <= CERT_EXPIRY_CRITICAL_DAYS:
        info['warn_level'] = 'critical'
    elif days <= CERT_EXPIRY_WARN_DAYS:
        info['warn_level'] = 'warn'
    else:
        info['warn_level'] = 'ok'

    # 自愈痕迹：让「刚刚自动修过一次」在界面上可见，而不是悄无声息。
    if selfheal_state_path and Path(selfheal_state_path).exists():
        try:
            st = json.loads(Path(selfheal_state_path).read_text(encoding='utf-8'))
            info['healed_at'] = int(st.get('healed_at') or 0)
            info['heal_count'] = int(st.get('heal_count') or 0)
            if st.get('last_pin'):
                info['pin_sha256'] = st['last_pin']
        except Exception as exc:
            _log_ignored('cert_info.heal_state', exc)

    info['ok'] = True
    return info


def _cert_summary(root, meta, config_path='/etc/hysteria/config.yaml'):
    """给 capabilities / 面板用的证书摘要（比 cert_status 更窄，异常一律吞掉）。

    capabilities 是主面板拉全量节点状态的入口，任何一个字段抛异常都会让
    整份能力清单拿不到 —— 证书只是附加信息，宁可少给也不能拖累主流程。
    """
    try:
        info = cert_status(root, meta or {}, config_path)
        return {
            'ok': info['ok'],
            'server_name': info.get('server_name', ''),
            'self_signed': info.get('self_signed', False),
            'issuer': info.get('issuer', ''),
            'not_after': info.get('not_after', ''),
            'expires_in_days': info.get('expires_in_days'),
            'expired': info.get('expired', False),
            'warn_level': info.get('warn_level', 'unknown'),
        }
    except Exception:
        return {'ok': False}


def record_cert_heal(root, state, before, after):
    """把一次自愈写成痕迹文件，供界面显示「上次自动对齐时间」。"""
    try:
        state_path = Path(root) / 'cert-selfheal.json'
        prev_count = 0
        if state_path.exists():
            try:
                prev_count = int(json.loads(state_path.read_text(encoding='utf-8')).get('heal_count') or 0)
            except Exception:
                prev_count = 0
        # before/after 是 meta 快照；被改成数字/列表时 `.get` 抛 AttributeError，
        # 而 record_cert_heal 在自愈主流程里 —— 一次坏 meta 就让自愈痕迹写不下来
        # （或直接打断自愈）。
        before = before if isinstance(before, dict) else {}
        after = after if isinstance(after, dict) else {}
        last_pin = after.get('pin_sha256')
        payload = {
            'healed_at': int(time.time()),
            'heal_count': prev_count + 1,
            'last_pin': last_pin if isinstance(last_pin, str) else '',
            'fields': [k for k in ('cert_type', 'server_name', 'is_insecure', 'pin_sha256')
                       if before.get(k) != after.get(k)],
        }
        tmp = state_path.with_suffix('.tmp')
        tmp.write_text(json.dumps(payload, ensure_ascii=False), encoding='utf-8')
        tmp.chmod(0o600)
        tmp.replace(state_path)
    except Exception as e:
        print('[portal] 写入证书自愈痕迹失败: %s' % str(e)[:120], file=sys.stderr)


def _is_dns_name(value):
    value = (value or '').strip()
    if not value or len(value) > 253:
        return False
    if value.startswith('www.bing.com'):
        return True
    return bool(re.match(r'^[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?'
                         r'(\.[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)+$', value))


def sync_cert_trust(m, root, meta_path, config_path='/etc/hysteria/config.yaml'):
    """Idempotently reconcile client_meta.json's trust model with the live cert.

    🔴 为什么需要这个函数（真实 bug，2026-10-08）：
    `client_meta.json` 里的 `cert_type` / `server_name` / `is_insecure` /
    `pin_sha256` 四个字段是**安装那一刻**根据用户选择写死的。一旦证书文件
    在安装之后被**带外替换**（Caddy 抢证续期、手工 cp、menu-4 只换证书没重跑
    generate_server_config），四个字段就会同时与真实证书漂移：

        config.yaml 用的是 CN=se.zy3a.com 的真 Let's Encrypt 证书，
        meta 却还记着 cert_type=self_signed / server_name=www.bing.com /
        is_insecure=true / pin=旧自签指纹。

    后果：面板生成的订阅把 `sni=www.bing.com` 发给客户端，而服务端出示的是
    `se.zy3a.com` 的证书 → 客户端直接 `CRYPTO_ERROR 0x150`（SNI 不匹配）。
    用户只看到「连不上」，完全无从下手 —— 而 `sync_pin()` 只管 pin，从不碰
    另外三个字段，所以自愈永远不会发生。

    本函数以**证书文件本身**为唯一事实来源，幂等地把四个字段拉回一致：
      * 读 config.yaml 的 tls.cert（读不到就退回 cert/server.crt）；
      * 自签（issuer==subject）→ cert_type=self_signed, is_insecure=True,
        server_name=SAN 首选 / CN 次选，pin=该证书的 SHA-256(DER)；
      * 非自签 → cert_type 保留 acme/custom（有 acme 块即 acme），
        is_insecure=False, server_name=SAN 首选 / CN，pin 清空（可信链不需要 pin）。
    只有真正发生漂移时才写盘并返回 True。
    """
    if not isinstance(m, dict):
        return False

    config_has_acme = False
    try:
        config_has_acme = bool(re.search(r'^acme:', Path(config_path).read_text(encoding='utf-8'), re.M))
    except OSError:
        pass

    # 证书解析统一走 _resolve_live_cert —— 自愈与界面显示必须是同一张证书，
    # 否则会出现「卡片显示 A、自愈修 B」这种更隐蔽的不一致。
    cert_file, cn, sans, self_signed = _resolve_live_cert(root, config_path)
    if not cert_file.exists():
        # 证书都读不到，不做任何猜测 —— 交给原来的行为。
        return False

    # server_name 取值：SAN 首选（现代客户端只看 SAN），CN 兜底。
    # 过滤掉 wildcard / 纯 IP / 明显不是域名的 SAN，避免把 *.example.com 写进 sni。
    # ⚠️ 先看「当前配置里已有的 server_name 是否仍在这张证书里」（2026-10-29 修）。
    # 一张证书常覆盖多个域名，直接取第一个非通配 SAN 会在换证后把 SNI 悄悄
    # 换成另一个域名 —— 已发出的订阅全部连不上。install.sh 的 sync_cert_meta
    # 已经是这个优先级，两处必须一致。
    current_sn = str(m.get('server_name') or '').strip().lower()
    san_lower = [str(x).strip().lower() for x in (sans or [])]
    candidate = ''
    if current_sn and (current_sn in san_lower or current_sn == str(cn or '').strip().lower()):
        candidate = str(m.get('server_name')).strip()
    if not candidate:
        for san in sans or []:
            if san.startswith('*.'):
                continue
            if _is_dns_name(san):
                candidate = san
                break
    if not candidate and _is_dns_name(cn):
        candidate = cn

    if self_signed:
        new_type = 'self_signed'
        new_insecure = True
        new_pin = pin_sha256_of_file(cert_file)
    else:
        new_type = 'acme' if config_has_acme else 'custom'
        new_insecure = False
        new_pin = ''

    new_sn = candidate or m.get('server_name') or m.get('public_ip', 'localhost')

    changed = False
    if m.get('cert_type') != new_type:
        m['cert_type'] = new_type
        changed = True
    if bool(m.get('is_insecure')) != bool(new_insecure):
        m['is_insecure'] = new_insecure
        changed = True
    if m.get('server_name') != new_sn:
        m['server_name'] = new_sn
        changed = True
    if (m.get('pin_sha256') or '') != (new_pin or ''):
        m['pin_sha256'] = new_pin
        changed = True

    if changed:
        Path(meta_path).write_text(json.dumps(m, ensure_ascii=False), encoding='utf-8')
        print(f"[portal] 证书信任模型已自愈: cert_type={new_type} "
              f"is_insecure={new_insecure} server_name={new_sn} "
              f"pin={'<set>' if new_pin else '<empty>'} (证书={cert_file})",
              file=sys.stderr)
    return changed


def reality_uuid_for_user(user_id):
    """为某个 Hy2 用户派生**稳定**的 VLESS UUID。

    为什么用派生而不是随机（2026-10-03）：
    随机 UUID 的话，「开户 → 销户 → 再开户」每次都要改 xray.json，
    而且**同一用户每次拉订阅拿到的 Reality 链接都会变** ——
    客户端会当成新节点，旧的配置失效。

    派生（uuid5）让「同一个 user_id 永远得到同一个 UUID」，
    于是：
      * 订阅可以重复拉取，链接稳定；
      * 销户时只要从 clients 里删掉对应 id 即可；
      * 再开户同 user_id 时链接与之前一致（幂等）。

    命名空间固定为 URL —— 换 namespace 会让已发出去的链接全部失效。
    """
    return str(uuid.uuid5(uuid.NAMESPACE_URL, 'hy2-portal-reality:' + str(user_id)))


def drop_meter_totals(data, user_id):
    """删除用户时清掉它的累计用量；计量状态损坏时保留原件，不能连注销一起失败。

    计量容器可能是旧备份、截断写入或人工编辑留下的 None / list / str。
    旧写法 `(data.get('usage_meter') or {}).get('totals', {}).pop(...)` 在
    这些形态下抛 AttributeError/TypeError，位置又在 del users 之后、save_data
    之前 —— 用户已从内存删除、磁盘没保存、访问也没撤销，重启后「已删用户」
    原地复活并继续能连。注销必须优先完成，计量清理只是附带动作。
    """
    meter = data.get('usage_meter')
    if not isinstance(meter, dict):
        return False
    totals = meter.get('totals')
    if not isinstance(totals, dict):
        return False
    totals.pop(user_id, None)
    return True


def config_section(data, key):
    """取 data[key] 里的协议配置；值不是 dict 时返回空表。

    所有协议配置（reality / vmess / vlessenc / anytls）都走这里：
    旧代码 `dict(data.get(key) or {})` 在值被改成数字时抛 TypeError，
    而这些调用点分布在订阅生成、协议启停、能力清单与状态卡片上 ——
    一条坏配置会让整块功能 500。
    """
    value = data.get(key) if isinstance(data, dict) else None
    return value if isinstance(value, dict) else {}


def user_table(data):
    """取用户表；整表被改成 null/list/str 时当空表。

    /auth 是按密码遍历 users 的：`data['users']` 被手工改成 null 时
    `users.items()` 抛 AttributeError，而那段代码不在 try 里 —— 异常穿透
    do_POST，连接直接被掐断。Hysteria 只会看到鉴权连接中断并反复重试，
    面板日志里也没有「用户表坏了」这类可读线索。损坏时按空表处理，
    照常返回 ok:false，让客户端拿到明确的鉴权失败。
    """
    users = data.get('users') if isinstance(data, dict) else None
    return users if isinstance(users, dict) else {}


def legacy_used_bytes(data, uid):
    """计量模块缺失时的旧用量回退；记录损坏时给 0，不能让接口 500。"""
    user = user_table(data).get(uid)
    if not isinstance(user, dict):
        return 0
    value = user.get('used_bytes', 0)
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


TRAFFIC_SUSPEND_UNIT_RE = re.compile(r'^[a-z0-9][a-z0-9@._-]{0,127}$')


def suspend_state(data):
    """读取整机超额停用状态；损坏值按「未停用」处理，units 必须是合法服务名列表。

    旧写法 `dict(data.get('traffic_suspend') or {})` 在状态被写成 7 / "broken"
    时抛 TypeError/ValueError —— 主控制台判定超额后调用 node/suspend 直接 500，
    一台服务都没停，用户继续超量使用。units 是字符串时更糟：`u in units`
    变成子串匹配，逐字符 systemctl stop，既停不掉又留下错误停用记录。
    """
    state = data.get('traffic_suspend') if isinstance(data, dict) else None
    # 只有明确的 True 才算停用：1 / 'yes' / 非空列表都不能当作已停用，
    # 否则恢复流程会跳过真正的启动动作。
    if not isinstance(state, dict) or state.get('suspended') is not True:
        return {}
    clean = dict(state)
    units = clean.get('units')
    clean['units'] = ([u for u in units
                       if isinstance(u, str) and TRAFFIC_SUSPEND_UNIT_RE.match(u)]
                      if isinstance(units, list) else [])
    return clean


def pending_revocations(data):
    """待撤销用户集合；损坏值按空集处理，且只保留合法 user_id。

    旧写法 `set(data.get('_pending_revocations', []))` 在字段被写成数字时抛
    TypeError，在写成字符串时把 `"abc"` 拆成 a/b/c 三个假 user_id —— 撤销
    worker 每 5 秒重试一次，前一种让撤销永久失败，后一种会往 xray 里写
    不存在的账号。
    """
    raw = data.get('_pending_revocations') if isinstance(data, dict) else None
    if not isinstance(raw, (list, tuple, set, frozenset)):
        return set()
    return {uid for uid in raw if isinstance(uid, str) and USER_ID_RE.match(uid)}


def proxy_services(data):
    """代理服务列表；容器被改坏时返回空表，条目必须是 dict。

    gost 配置生成与端口核对都遍历它。容器是 null/str/int 时旧写法
    `for ... in data.get('proxy_services', [])` 抛 TypeError，reload_gost
    一律失败 —— 表现成「新增代理永远应用失败」，而日志只有一句
    「GOST 配置未成功应用」，看不出是数据坏了。
    """
    services = data.get('proxy_services') if isinstance(data, dict) else None
    if not isinstance(services, list):
        return []
    return [item for item in services if isinstance(item, dict)]


def users_list_rows(users):
    """遍历用户表；整表被改成 list/None/str 时按空表处理而不是抛异常。"""
    if not isinstance(users, dict):
        return []
    return list(users.items())


def active_online_ips(tracker, uid, now_ts, timeout):
    """某用户的在线 IP 列表；traker 条目损坏时返回空表而不是让整个列表接口 500。"""
    row = tracker.get(uid) if isinstance(tracker, dict) else None
    if not isinstance(row, dict):
        return []
    rows = []
    for ip, seen in row.items():
        if isinstance(seen, bool):
            continue
        try:
            seen = int(seen)
        except (TypeError, ValueError, OverflowError):
            continue
        if now_ts - seen < timeout:
            rows.append({'ip': str(ip), 'last_seen': seen})
    return sorted(rows, key=lambda row: row['ip'])


def users_list_entry(uid, info, tracker, now_ts, summary, ip_timeout):
    """users/list 的一行；损坏账户返回 None，不能拖垮整张对账列表。

    两侧（Web/API 的 GET 与 REST POST）共用这一个构造器。旧实现直接
    `info.get(...)`、`ip_tracker.get(uid, {}).items()`：只要有一份用户记录被
    手工改成字符串，或者 ip_tracker 里残留旧格式的列表，整个 users/list 就抛
    AttributeError → 500，控制台对账/同步/开户全部失败，而 /auth 仍然正常，
    表面看只像「控制台坏了」。
    """
    if not isinstance(info, dict):
        return None
    return {
        'user_id': uid,
        'expires_at': info.get('expires_at', 0),
        'active': user_access_allowed(info, now_ts),
        'status': info.get('status', 'active'),
        'traffic_limit_bytes': info.get('limit_bytes', 0),
        'traffic_used_bytes': info.get('used_bytes', 0),
        'limit_bytes': info.get('limit_bytes', 0),
        'used_bytes': info.get('used_bytes', 0),
        **summary,
        'online_ips': active_online_ips(tracker, uid, now_ts, ip_timeout),
        'ip_limit': info.get('ip_limit', 0),
        'created_at': info.get('created_at', now_ts),
    }


# 托管入站里 client.id 的合法形态（UUID v4/v5 文本）。
REALITY_UUID_RE = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-'
                             r'[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')


def reality_registry(data):
    """从 portal.json 的 data 里取出「user_id → UUID」的 Reality 账号表。

    存在 data['reality_users'] 里；首次调用时按现有 users 回填
    （保证升级后老用户也有 UUID，不需要重新开户）。
    """
    reg = data.get('reality_users')
    if not isinstance(reg, dict):
        reg = {}
    # data['users'] 被手工改成 null/list 时，`.keys()` 会抛 AttributeError；
    # 这条路径在同步 Xray clients 的锁内，异常会让停用/到期撤销半途中断。
    users = user_table(data)
    changed = False
    for uid in list(users.keys()):
        if uid not in reg:
            reg[uid] = reality_uuid_for_user(uid)
            changed = True
    # 清理已不存在用户的条目 —— 避免 xray clients 无限增长。
    # 值也必须是合法 UUID 字符串：被改成数字/None 时它会原样写进 xray
    # clients，Xray 启动即失败（`id` 必须是 UUID），而面板显示一切正常。
    for uid in list(reg.keys()):
        value = reg[uid]
        if uid not in users:
            del reg[uid]
            changed = True
        elif (user_access_allowed(users[uid])
              and (not isinstance(value, str) or not value
                   or not REALITY_UUID_RE.match(value))):
            # 用户还在且**会进 clients**、但 UUID 被改坏：重新派生（uuid5 是
            # 确定性的，重建后与其他协议是同一个身份）。停用用户的映射保持
            # 原样 —— 它不进 clients，且重新启用时要沿用原身份。
            reg[uid] = reality_uuid_for_user(uid)
            changed = True
    if changed:
        data['reality_users'] = reg
    return reg


# ---- 项目托管的 Xray 入站（2026-10-24 VMess 接入时统一）----
#
# 背景：此前 Reality 的生成/撤销/启停全都按「第一个 protocol=vless 且
# security=reality 的入站」来定位，一旦同一份 xray.json 里再放一个 VMess
# 入站，这些函数就会**看不见它** —— 停用/到期只收回 Reality，VMess 照样能连。
# 现在所有托管入站都带固定 tag，定位一律按 tag（旧的无 tag Reality 由
# legacy 匹配兜底，升级后第一次写入即补上 tag）。
REALITY_INBOUND_TAG = 'vless-reality-in'
VMESS_INBOUND_TAG = 'vmess-ws-in'
# VLESS Encryption（Xray v25.9.5+）：与 Reality 同为 VLESS，但**不需要偷别人的
# 证书握手** —— 它自己用 ML-KEM-768 做后量子密钥交换，走普通 TLS。
# 这是 VMess 被上游标记弃用后的官方替代路线（2026-10-24 加）。
VLESSENC_INBOUND_TAG = 'vless-enc-in'
MANAGED_INBOUND_TAGS = (REALITY_INBOUND_TAG, VMESS_INBOUND_TAG, VLESSENC_INBOUND_TAG)


def managed_inbound_index(config, tag):
    """返回 (下标, 入站)。先按 tag 找；找不到再按协议特征兜底旧配置。

    兜底只对 Reality 生效：旧版配置里的 Reality 入站没有 tag，
    但 VMess 是本版本才引入的，不存在无 tag 的历史配置。
    """
    # config 来自 xray.json：被截断/改坏时可能是 list 或字符串。
    # 旧写法 `.get` 抛 AttributeError，而这里在撤销、启停、能力清单三条路径上
    # —— 异常会让「停用/到期用户收回」整轮失败。
    if not isinstance(config, dict):
        return -1, None
    inbounds = config.get('inbounds') or []
    if not isinstance(inbounds, list):
        return -1, None
    for i, item in enumerate(inbounds):
        if isinstance(item, dict) and item.get('tag') == tag:
            return i, item
    # 兜底匹配只在「**该协议自己**还没有带 tag 的入站」时启用。
    #
    # ⚠️ 2026-10-25 修：上一版写的是「配置里存在任意带 tag 的托管入站就
    # 不兜底」。结果是节点上只要先启用了 VMess（带 tag），旧版留下的
    # 无 tag Reality 入站就再也认不领 —— Reality 卡片显示未启用、
    # 撤销也覆盖不到它。判据必须按协议各自独立。
    if tag == REALITY_INBOUND_TAG:
        for i, item in enumerate(inbounds):
            if (isinstance(item, dict) and item.get('protocol') == 'vless'
                    and (item.get('streamSettings') or {}).get('security') == 'reality'):
                return i, item
    return -1, None


def upsert_managed_inbound(config, tag, inbound):
    """把托管入站按 tag 写入/替换，**保留**其它入站、api、routing、outbounds。

    旧实现重生成 Reality 时是「整份 previous 覆盖 + 改第一个 Reality」，
    在只有一种协议时没问题；加入 VMess 后那样会**丢掉 VMess 入站**。
    这里只动自己那一个元素，别的原样保留。
    """
    # config 本身也可能是 list/str（xray.json 被截断或整份改坏）；
    # 旧写法 config.get 抛 AttributeError，启停/重生成整条路径失败。
    if not isinstance(config, dict):
        raise ValueError('invalid Xray configuration root; existing configuration preserved')
    # 缺失的 inbounds 可创建，但损坏的已有内容不能被清空覆盖。
    if 'inbounds' in config and not isinstance(config['inbounds'], list):
        raise ValueError('invalid Xray inbounds; existing configuration preserved')
    config.setdefault('inbounds', [])
    idx, current = managed_inbound_index(config, tag)
    inbound = copy.deepcopy(inbound)
    inbound['tag'] = tag
    if idx < 0:
        config['inbounds'].append(inbound)
        return config
    inbounds = config['inbounds']
    # 保留旧入站上可能存在的、本版本不认识的额外键（例如手工加的 sniffing 扩展），
    # 但 settings/streamSettings 必须整体以新值为准，否则 clients 会新旧混在一起。
    merged = copy.deepcopy(current)
    merged.update(inbound)
    inbounds[idx] = merged
    return config


def remove_managed_inbound(config, tag):
    """按 tag 移除托管入站，返回是否真的移除了。"""
    idx, _ = managed_inbound_index(config, tag)
    if idx < 0:
        return False
    del config['inbounds'][idx]
    return True


def has_managed_inbound(config, tag):
    return managed_inbound_index(config, tag)[0] >= 0


def vmess_uuid_for_user(user_id):
    """为某个用户派生**稳定**的 VMess UUID。

    命名空间与 Reality **不同**：同一 user_id 在两种协议下得到不同 UUID。
    这不是为了安全，而是为了排查时能一眼分辨「这条连接走的是哪个协议」；
    也避免用户误把 Reality 的 UUID 填进 VMess 客户端还能连上的混淆。
    命名空间固定，换掉会让已下发的 VMess 订阅全部失效。
    """
    return str(uuid.uuid5(uuid.NAMESPACE_URL, 'hy2-portal-vmess:' + str(user_id)))


def vmess_clients(data):
    """生成 VMess 入站的 clients —— 与 reality_clients 同一套准入判据。

    ⚠️ 两个必须遵守的差异：
      1. **不能带 flow**：flow 是 VLESS 专用字段，VMess 客户端见到会报配置错误。
      2. 空表同样要给占位 client —— 与 Reality 同理，Xray 的 VMess 入站
         clients 为空时同样不接受任何连接，而服务状态仍是 active。
    """
    users = user_table(data)
    clients = []
    for uid in sorted(users):
        if not user_access_allowed(users.get(uid) or {}):
            continue
        clients.append({'id': vmess_uuid_for_user(uid), 'email': uid})
    if not clients:
        clients = [{'id': str(uuid.uuid4()), 'email': 'placeholder'}]
    return clients


def vmess_uri_for_user(vcfg, user_id, public_ip, label=None):
    """拼一条标准 vmess:// 直链（Base64 JSON，v2rayN / NekoBox / Shadowrocket 通用）。

    与 vless:// 不同，vmess 没有查询串格式，主流客户端都认 Base64(JSON)。
    字段名必须用小写 `v`/`ps` 等老字段：v2rayN 与 Shadowrocket 都按这套解析，
    新版 `vmess://` URI 草案（带 path 查询串）支持面反而更窄。
    """
    # 配置来自 portal.json：被改成数字/列表时 `.get` 直接抛 AttributeError，
    # 而调用点在用户订阅生成路径上 —— 一条坏配置让整份订阅 500。
    if not isinstance(vcfg, dict):
        return ''
    host = vcfg.get('domain') or public_ip
    # 与 VLESS-Reality 同一套端口校验：`"abc"` / True / 70000 会生成一条
    # 客户端无法解析的链接（admin 面板仍显示成功）。
    port = _valid_port(vcfg.get('port'))
    path = vcfg.get('ws_path') or '/'
    if not (host and port and path):
        return ''
    tag = label or ('VMess-WS-' + str(user_id))
    payload = {
        'v': '2', 'ps': tag, 'add': str(host), 'port': str(port),
        'id': vmess_uuid_for_user(user_id), 'aid': '0', 'scy': 'auto',
        'net': 'ws', 'type': 'none', 'host': str(host), 'path': path,
        'tls': 'tls', 'sni': str(vcfg.get('sni') or host), 'alpn': '',
        'fp': 'chrome',
    }
    raw = json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    return 'vmess://' + base64.b64encode(raw).decode('ascii')


# ---- AnyTLS（2026-10-28 加，由 sing-box 承载）----
#
# Xray 没有 AnyTLS 服务端，所以它跑在**独立的 sing-box 进程**里
# （systemd 单元 hy2-anytls，配置 /etc/hysteria/anytls.json），不碰 xray.json。
# 与 VMess / VLESS Encryption 一样是真正的 TLS 服务端，需要域名 + 可信证书；
# 底层走 TCP，UDP 由客户端用 UDP-over-TCP 封装。
#
# 用户密码不能像 VMess 那样用 uuid5(user_id) 派生：user_id 出现在分享链接里，
# 谁都能算出来。这里用节点私有的 secret 做 HMAC，secret 只在首次启用时生成，
# 停用再启用也沿用它，否则已下发的订阅会全部失效。
ANYTLS_SERVICE = 'hy2-anytls'
ANYTLS_BINARY = '/usr/local/bin/sing-box'
ANYTLS_CONFIG_NAME = 'anytls.json'
ANYTLS_INBOUND_TAG = 'anytls-in'
# AnyTLS 入站从 sing-box 1.12.0 起才有。
ANYTLS_MIN_SINGBOX = (1, 12, 0)
ANYTLS_UNIT_CONTENT = '''[Unit]
Description=AnyTLS (sing-box) managed by hy2 portal
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/sing-box run -c /etc/hysteria/anytls.json
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
'''
# anytls.json 的读-改-写与启停都在这把锁内，规则同 reality_apply_lock。
anytls_apply_lock = threading.Lock()
# 核心安装/卸载串行化：两个并发 install-core 会同时写 xray.new / sing-box.new，
# 后完成者覆盖前者；与 uninstall 并发时还可能「刚装好就被删」（2026-10-29 加）。
core_operation_lock = threading.Lock()
# AWG 操作串行化：peer-add 是「读 peers.json → 算下一个地址 → 写回」的
# 读-改-写，两个并发请求会同时读到旧列表 —— 后写者覆盖前者（客户端丢失），
# 或两名客户端拿到同一个 address（2026-10-29 加）。
awg_operation_lock = threading.Lock()


def anytls_password_for_user(secret, user_id):
    """由节点 secret 派生某用户**稳定且不可猜**的 AnyTLS 密码。"""
    return hmac.new(str(secret).encode('utf-8'),
                    ('hy2-portal-anytls:' + str(user_id)).encode('utf-8'),
                    hashlib.sha256).hexdigest()[:32]


def anytls_config(data):
    """AnyTLS 配置字典；被改成数字/字符串时按未配置处理。

    这些值来自 portal.json（旧版本可直接编辑）。`anytls_users` 在同步
    sing-box 用户表的路径上，`.get` 抛 AttributeError 会让同步整轮失败，
    而界面只显示「启用失败」。
    """
    cfg = data.get('anytls_config') if isinstance(data, dict) else None
    return cfg if isinstance(cfg, dict) else {}


def anytls_users(data):
    """AnyTLS 入站的 users —— 与其它协议同一套准入判据 user_access_allowed。

    空表同样要给占位用户：sing-box 的 anytls 入站 users 为空会拒绝启动。
    占位密码也由 secret 派生（而不是随机），否则每轮收回都会算出不同的
    配置、触发一次无谓的重启。
    """
    secret = anytls_config(data).get('secret')
    secret = secret if isinstance(secret, str) else ''
    users = []
    if secret:
        all_users = user_table(data)
        for uid in sorted(all_users):
            if user_access_allowed(all_users.get(uid) or {}):
                users.append({'name': uid, 'password': anytls_password_for_user(secret, uid)})
    if not users:
        # 占位密码必须**稳定**：secret 缺失时旧实现每次用随机数，导致
        # sync_anytls_users 每轮都认为名单变了 → 反复重写配置并重启 sing-box
        # （2026-10-29 修）。secret 正常一定存在；这里用固定串兜底，
        # 保证最坏情况下也只是「没人能连」，而不是重启风暴。
        users = [{'name': 'placeholder',
                  'password': anytls_password_for_user(secret or 'anytls-placeholder', 'placeholder')}]
    return users


def build_anytls_config(acfg, users, cert_file, key_file):
    """生成 sing-box 的完整配置（只有一个 anytls 入站）。

    出站同样要拒绝内网 / 云元数据，与 Hy2 ACL、Xray 的 add_private_network_guard
    对齐。先 resolve 再按 IP 拒：客户端用域名访问内网地址时也能挡住。
    """
    return {
        'log': {'level': 'warn', 'timestamp': True},
        'inbounds': [{
            'type': 'anytls',
            'tag': ANYTLS_INBOUND_TAG,
            'listen': '::',
            'listen_port': int(acfg['port']),
            'users': users,
            'tls': {
                'enabled': True,
                'server_name': acfg.get('sni') or acfg.get('domain'),
                'certificate_path': cert_file,
                'key_path': key_file,
            },
        }],
        'outbounds': [{'type': 'direct', 'tag': 'direct'}],
        'route': {
            'rules': [
                {'action': 'resolve'},
                {'ip_cidr': list(PRIVATE_REJECT_RULES), 'action': 'reject'},
            ],
            'final': 'direct',
        },
    }


def anytls_uri_for_user(acfg, user_id, label=None):
    """anytls:// 直链（mihomo / sing-box 系 / Shadowrocket 通用格式）。"""
    # 配置可能是数字/字符串（旧版本可直编 portal.json），端口也可能是
    # "abc"/True —— 旧写法 int(port) 抛 ValueError，整份订阅生成失败。
    if not isinstance(acfg, dict):
        return ''
    secret = acfg.get('secret')
    if not isinstance(secret, str) or not secret:
        return ''
    host = acfg.get('domain')
    port = _valid_port(acfg.get('port'))
    if not (host and port):
        return ''
    pwd = anytls_password_for_user(secret, user_id)
    params = urlencode({'sni': acfg.get('sni') or host})
    return f"anytls://{pwd}@{_host_for_url(host)}:{int(port)}/?{params}#{quote(label or ('AnyTLS-' + str(user_id)))}"


def apply_anytls_config(config, config_path, restart=True, run=subprocess.run):
    """原子应用 sing-box 配置：预检 → 替换 → 重启 → 核对，任何一步失败就回滚。

    调用方必须持有 anytls_apply_lock。
    """
    config_path = Path(config_path)
    original = config_path.read_bytes() if config_path.exists() else None
    candidate = config_path.with_name('anytls.candidate.json')
    candidate.write_text(json.dumps(config, indent=2, ensure_ascii=False), encoding='utf-8')
    os.chmod(str(candidate), 0o600)
    replaced = False
    try:
        run([ANYTLS_BINARY, 'check', '-c', str(candidate)],
            capture_output=True, timeout=15, check=True)
        candidate.replace(config_path)
        replaced = True
        if restart:
            run(['systemctl', 'reset-failed', ANYTLS_SERVICE], capture_output=True, timeout=5)
            run(['systemctl', 'restart', ANYTLS_SERVICE], capture_output=True, timeout=15, check=True)
            run(['systemctl', 'is-active', '--quiet', ANYTLS_SERVICE],
                capture_output=True, timeout=5, check=True)
    except Exception:
        if replaced:
            if original is None:
                config_path.unlink(missing_ok=True)
            else:
                config_path.write_bytes(original)
            if restart and original is not None:
                run(['systemctl', 'restart', ANYTLS_SERVICE], capture_output=True, timeout=15)
        raise
    finally:
        candidate.unlink(missing_ok=True)


def sync_anytls_users(root, snapshot, apply=None, service_active=None):
    """把 anytls.json 的 users 对齐到当前准入名单（停用/到期/超额/删除即收回）。

    名单没变就什么也不做；变了就重写并重启 —— sing-box 只有重启才会
    断开已建立的会话，否则被收回的用户能一直用到自己断线。
    服务没在运行（例如整机流量超额停用中）时只写文件、不拉起服务。
    """
    path = Path(root) / ANYTLS_CONFIG_NAME
    # snapshot 是 apply_access 的深拷贝，正常一定是 dict；但 refresh/selfheal
    # 也会传进来，损坏时 `.get` 抛异常会让整轮撤销失败（用户撤不回来）。
    if not isinstance(snapshot, dict):
        return False
    section = snapshot.get('anytls_config')
    if not path.exists() or not (isinstance(section, dict) and section.get('enabled')):
        return False
    apply = apply or apply_anytls_config
    if service_active is None:
        service_active = lambda: _systemd_state(ANYTLS_SERVICE) == 'active'  # noqa: E731
    with anytls_apply_lock:
        # ⚠️ 2026-10-29 修：这里原来是裸 json.loads，anytls.json 被截断或手工
        # 改坏时抛 JSONDecodeError，而本函数在 enforce_node_access 顶部调用 ——
        # 一个坏文件就让开户/续费/停用/删除全部返回 503，报错还写成
        # "Reality sync failed"，完全指不到真正的文件。
        try:
            config = json.loads(path.read_text(encoding='utf-8'))
        except (OSError, ValueError) as exc:
            raise RuntimeError('AnyTLS configuration unreadable; cannot confirm user sync') from exc
        wanted = anytls_users(snapshot)
        inbounds = config.get('inbounds') if isinstance(config, dict) else None
        if not isinstance(inbounds, list) or any(not isinstance(item, dict) for item in inbounds):
            raise ValueError('invalid AnyTLS inbounds; cannot confirm user sync')
        matches = [item for item in inbounds if item.get('tag') == ANYTLS_INBOUND_TAG]
        if len(matches) != 1:
            raise ValueError('missing or duplicate AnyTLS inbound; cannot confirm user sync')
        inbound = matches[0]
        if inbound.get('users') == wanted:
            return False
        inbound['users'] = wanted
        apply(config, path, restart=service_active())
        return True


def _singbox_version(binary=ANYTLS_BINARY, run=subprocess.run):
    """返回 sing-box 版本元组；读不出来返回 None。"""
    try:
        out = run([binary, 'version'], capture_output=True, text=True, timeout=5).stdout
    except Exception:
        return None
    m = re.search(r'version\s+v?(\d+)\.(\d+)\.(\d+)', out or '')
    return tuple(int(x) for x in m.groups()) if m else None


XRAY_UNIT_CONTENT = '''[Unit]
Description=Xray Service (VLESS-Reality / VMess / VLESS Encryption)
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


def write_xray_unit():
    """写 xray.service 并 daemon-reload；不 enable —— 没有任何协议配置时
    开机自启只会让它每 3 秒失败重启一次。由首次成功应用配置时再 enable。"""
    unit = Path('/etc/systemd/system/xray.service')
    if not unit.exists() or unit.read_text(encoding='utf-8') != XRAY_UNIT_CONTENT:
        unit.write_text(XRAY_UNIT_CONTENT, encoding='utf-8')
        subprocess.run(['systemctl', 'daemon-reload'], capture_output=True, timeout=30)



XRAY_PINNED_VERSION = '26.3.27'


def _version_tuple(value):
    """把 '26.3.27' / 'v26.3.27' 转成可比较的整数元组；无法解析时返回 ()。

    ⚠️ 必须补齐到固定长度再比较：Python 的元组比较是逐位前缀式，
    `(1, 2, 0) > (1, 2)` 为真 —— 同一个版本写全/写短就会判成「当前版本更高」，
    「重新安装 / 修复」被静默拒绝（2026-10-30 修）。
    """
    parts = re.findall(r'\d+', str(value or ''))
    if not parts:
        return ()
    numbers = [int(p) for p in parts[:4]]
    return tuple(numbers + [0] * (3 - len(numbers))) if len(numbers) < 3 else tuple(numbers)


def _xray_version(binary='/usr/local/bin/xray', run=subprocess.run):
    """返回已安装 Xray 的版本字符串（如 '26.3.27'）；读不出来返回 ''。"""
    try:
        out = run([binary, 'version'], capture_output=True, text=True, timeout=5)
    except Exception:
        return ''
    m = re.search(r'Xray\s+v?(\d+(?:\.\d+)+)', (out.stdout or '') + (out.stderr or ''))
    return m.group(1) if m else ''

def install_xray_binary():
    """下载官方 Xray-core 并校验 SHA2-256 后装到 /usr/local/bin/xray，返回 (ok, message)。

    只装二进制，不写配置、不启用任何协议：核心管理页单独安装时用它，
    Reality 的一键安装在它之上再生成配置（2026-10-28 从 install-xray 拆出）。
    """
    machine = platform.machine().lower()
    # 架构映射必须覆盖 armv7：旧实现把除 aarch64 外的一切都当成 amd64，
    # 于是 armv7 机器会被静默装上 Xray-linux-64.zip 并当作 xray 运行。
    if 'aarch64' in machine or 'arm64' in machine:
        xarch = 'arm64-v8a'
    elif 'armv7' in machine or 'armhf' in machine:
        xarch = 'arm32-v7a'
    elif 'x86_64' in machine or 'amd64' in machine:
        xarch = '64'
    else:
        return False, '不支持的 CPU 架构，无法选择 Xray 资产: %s' % machine
    xasset = f"Xray-linux-{xarch}.zip"
    # 固定版本是有意的（配合 .dgst 校验），但「重新安装 / 修复」按钮不能
    # 静默把更高版本降回来（2026-10-29 修）。当前版本更高时明确拒绝，
    # 由用户决定是否降级（例如手工换二进制）。
    current = _xray_version()
    if current and _version_tuple(current) > _version_tuple(XRAY_PINNED_VERSION):
        return False, ('当前 Xray 版本 %s 高于本脚本内置的 %s。为避免静默降级，'
                       '已放弃安装；如确需降级请手动替换二进制'
                       % (current, XRAY_PINNED_VERSION))
    xbase = 'https://github.com/XTLS/Xray-core/releases/download/v%s/' % XRAY_PINNED_VERSION
    # 先取官方 `.dgst` 并只认 SHA2-256；取不到就不装。
    expected = fetch_expected_sha256(xbase + xasset + '.dgst', None,
                                     parser=parse_xray_dgst)
    if not expected:
        return False, ('取不到 %s 的官方 SHA2-256 摘要（.dgst 缺失、畸形或重复）—— '
                       '无法验证下载内容，已放弃安装' % xasset)
    dl_urls = [
        xbase + xasset,
        f"https://ghfast.top/{xbase}{xasset}",
        f"https://github.moeyy.xyz/{xbase}{xasset}",
    ]
    installed = False
    errors = []
    with tempfile.TemporaryDirectory() as tmpdir:
        zpath = Path(tmpdir) / 'xray.zip'
        for u in dl_urls:
            host = u.split('/')[2] if '//' in u else u
            try:
                req = urllib.request.Request(u, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=45) as resp, open(zpath, 'wb') as out_f:
                    shutil.copyfileobj(resp, out_f)
                if not verify_sha256(zpath, expected):
                    errors.append('%s: SHA256 与官方 .dgst 不一致' % host)
                    continue
                if not zipfile.is_zipfile(str(zpath)):
                    errors.append('%s: 内容不是有效 zip' % host)
                    continue
                with zipfile.ZipFile(zpath, 'r') as zf:
                    member = safe_zip_members(zf.namelist(), 'xray')
                    zf.extract(member, path=tmpdir)
                bin_path = Path(tmpdir) / 'xray'
                if bin_path.exists():
                    staged = Path('/usr/local/bin/xray.new')
                    shutil.copyfile(str(bin_path), str(staged))
                    os.chmod(str(staged), 0o755)
                    os.replace(str(staged), '/usr/local/bin/xray')
                    installed = True
                    break
                errors.append('%s: 包内没有 xray' % host)
            except Exception as exc:
                errors.append('%s: %s: %s' % (host, type(exc).__name__, exc))

    if not installed:
        return False, '下载或解压 Xray 核心失败 —— ' + ' ｜ '.join(errors)
    return True, 'Xray-core 安装完成'


def install_singbox():
    """从 SagerNet/sing-box 官方 Release 安装 sing-box，返回 (ok, message)。

    sing-box 的 Release 没有 checksums 文件，预期摘要取 GitHub API 给每个
    资产记录的 sha256 digest（只信 api.github.com，镜像只作传输候选）。
    """
    current = _singbox_version()
    if current and current >= ANYTLS_MIN_SINGBOX:
        return True, 'sing-box %s 已安装' % '.'.join(map(str, current))
    machine = platform.machine().lower()
    arch = {'x86_64': 'amd64', 'amd64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64',
            'armv7l': 'armv7', 'armv7': 'armv7'}.get(machine)
    if not arch:
        return False, '不支持的 CPU 架构: %s' % machine
    try:
        req = urllib.request.Request('https://api.github.com/repos/SagerNet/sing-box/releases/latest',
                                     headers={'User-Agent': 'hy2-portal'})
        with urllib.request.urlopen(req, timeout=15) as r:
            release = json.loads(r.read().decode('utf-8'))
    except Exception as exc:
        return False, '取不到 sing-box 最新版本信息: %s' % exc
    tag = str(release.get('tag_name') or '')
    ver = tag.lstrip('v')
    asset_name = f'sing-box-{ver}-linux-{arch}.tar.gz'
    asset = next((a for a in release.get('assets') or [] if a.get('name') == asset_name), None)
    digest = str((asset or {}).get('digest') or '')
    expected = digest[len('sha256:'):] if digest.startswith('sha256:') else ''
    if not re.fullmatch(r'[0-9a-f]{64}', expected):
        return False, '取不到 %s 的官方 SHA256，无法校验下载内容，已放弃安装' % asset_name
    official = f'https://github.com/SagerNet/sing-box/releases/download/{tag}/{asset_name}'
    errors = []
    with tempfile.TemporaryDirectory() as tmpdir:
        archive = Path(tmpdir) / 'sing-box.tar.gz'
        for url in (official, 'https://ghfast.top/' + official):
            host = url.split('/')[2]
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'hy2-portal'})
                with urllib.request.urlopen(req, timeout=180) as resp, open(archive, 'wb') as out:
                    shutil.copyfileobj(resp, out)
                if not verify_sha256(archive, expected):
                    errors.append('%s: SHA256 与官方不一致' % host)
                    continue
                with tarfile.open(str(archive), 'r:gz') as tar:
                    member_name = safe_tar_members([m.name for m in tar.getmembers() if m.isfile()],
                                                   'sing-box')
                    member = tar.getmember(member_name)
                    staged = Path(ANYTLS_BINARY + '.new')
                    with tar.extractfile(member) as src, open(staged, 'wb') as dst:
                        shutil.copyfileobj(src, dst)
                os.chmod(str(staged), 0o755)
                version = _singbox_version(str(staged))
                if not version or version < ANYTLS_MIN_SINGBOX:
                    staged.unlink(missing_ok=True)
                    return False, 'sing-box 版本 %s 不支持 AnyTLS（需要 1.12.0+）' % ver
                os.replace(str(staged), ANYTLS_BINARY)
                return True, 'sing-box %s 安装完成' % ver
            except Exception as exc:
                errors.append('%s: %s: %s' % (host, type(exc).__name__, exc))
    return False, '下载 sing-box 失败 —— ' + ' ｜ '.join(errors)


# ---- VLESS Encryption（2026-10-24 加，VMess 的上游替代路线）----
#
# 与 Reality 的区别：Reality 借用大厂站点的证书握手来伪装，**不需要自己的域名**；
# VLESS Encryption 是自己做真正的 TLS 服务端 + ML-KEM-768 后量子密钥交换，
# 因此和 VMess 一样需要域名与可信证书。
#
# 密钥由 `xray vlessenc` 生成一对：
#   decryption -> 服务端 inbound.settings.decryption
#   encryption -> 客户端 outbound.users[].encryption
# 两者必须来自**同一次**调用，混用会让握手直接失败（实测过）。

VLESSENC_DECRYPTION_RE = re.compile(
    r'^mlkem768x25519plus\.(native|xorpub|random)\.[0-9]+s?(-[0-9]+)?\.[A-Za-z0-9_\-]+$')


def generate_vless_encryption_pair(binary='/usr/local/bin/xray'):
    """调用 `xray vlessenc` 生成一对密钥，返回 (decryption, encryption)。

    只取输出里**第一组**（X25519 认证那组）：后一组 ML-KEM-768 认证的
    decryption 长度可达上千字符，塞进 config.yaml 会很难维护，
    而 Xray 自己的提示也写明「Ephemeral key exchange is Post-Quantum safe anyway」——
    临时密钥交换本身已是后量子安全，第一组足够。
    """
    out = subprocess.run([binary, 'vlessenc'], capture_output=True, text=True, timeout=10)
    if out.returncode != 0:
        raise RuntimeError('xray vlessenc 执行失败，无法生成 VLESS Encryption 密钥')
    dec = enc = ''
    for line in out.stdout.splitlines():
        line = line.strip()
        if not dec and line.startswith('"decryption":'):
            dec = line.split(':', 1)[1].strip().strip(',').strip('"')
        elif not enc and line.startswith('"encryption":'):
            enc = line.split(':', 1)[1].strip().strip(',').strip('"')
        if dec and enc:
            break
    if not (dec and enc):
        raise RuntimeError('xray vlessenc 输出里没有找到密钥对')
    if not VLESSENC_DECRYPTION_RE.match(dec):
        raise RuntimeError('生成的 decryption 格式不符合预期，已放弃写入')
    return dec, enc


def vlessenc_clients(data):
    """VLESS Encryption 入站的 clients。

    与 Reality 用**同一个** UUID 派生（同一用户同一身份），
    但**不带 flow**：xtls-rprx-vision 是 Reality 专用，VLESS Encryption 不能带。
    """
    users = user_table(data)
    clients = []
    for uid in sorted(users):
        if not user_access_allowed(users.get(uid) or {}):
            continue
        clients.append({'id': reality_uuid_for_user(uid), 'email': uid})
    if not clients:
        clients = [{'id': str(uuid.uuid4()), 'email': 'placeholder'}]
    return clients


def vlessenc_uri_for_user(vcfg, user_id, public_ip, label=None):
    """拼一条 vless:// 直链，带上 encryption 参数。

    ⚠️ encryption 必须逐字照抄客户端密钥（含 `.` 分隔的各段），
    任何字符被 URL 编码或截断都会导致握手失败。
    """
    if not isinstance(vcfg, dict):
        return ''
    host = vcfg.get('domain') or public_ip
    # 同 Reality / VMess：非整数端口会让客户端解析失败。
    port = _valid_port(vcfg.get('port'))
    enc = vcfg.get('encryption', '')
    if not (host and port and enc):
        return ''
    tag = label or ('VLESS-Enc-' + str(user_id))
    params = {'encryption': enc, 'security': 'tls', 'sni': str(vcfg.get('sni') or host),
              'type': 'tcp', 'headerType': 'none', 'fp': 'chrome'}
    return (f"vless://{reality_uuid_for_user(user_id)}@{_host_for_url(host)}:{port}"
            f"?{urlencode(params, safe='')}#{quote(tag)}")


# WARP 出口 IP 探测结果缓存：前端每 10 秒轮询，而每次探测都要走一次外网。
_warp_probe_cache = {}


_ACCESS_APPLIED = {}

def user_access_denial(info, now=None):
    """Hy2、托管协议和分享页共用准入判据，并保留鉴权错误说明。"""
    if not isinstance(info, dict):
        return 'Invalid user record'
    if info.get('status', 'active') != 'active':
        return 'User account inactive'
    now = time.time() if now is None else now
    # 只有缺失 / None 表示永久；0、小数、数字字符串走同一时钟判定。
    try:
        expires_at = info.get('expires_at')
        # bool 是 int 的子类：`limit_bytes: true` 会被当成「1 字节配额」，
        # 用户只要用了 1 字节就被判超额停用，而界面上配额显示成 1 B。
        # JSON 里把字段写成 true 是控制台/旧脚本的常见错误，必须显式拒绝。
        for field in ('limit_bytes', 'used_bytes'):
            if isinstance(info.get(field), bool):
                return 'Invalid user record'
        if expires_at is not None and not float(expires_at) > now:
            return 'User account expired'
        limit_bytes = int(info.get('limit_bytes', 0))
        used_bytes = int(info.get('used_bytes', 0))
    except (ValueError, TypeError, OverflowError):
        return 'Invalid user record'
    if limit_bytes > 0 and used_bytes >= limit_bytes:
        return 'Traffic quota exceeded'
    return None


def user_access_allowed(info, now=None):
    return user_access_denial(info, now) is None

REALITY_IPLIMIT_RELEASE_SECONDS = 180
REALITY_IPLIMIT_TAG_PREFIX = 'iplimit-'


def active_ip_limits(users):
    """逐账户读取设备上限，损坏记录不能撤销其他账户的拦截。"""
    # 调用方传的是 user_table(data)，但 ip_limit worker 也会直接传快照；
    # 容器被改坏时 `.items()` 抛异常，整轮设备上限失效（全部设备放行）。
    if not isinstance(users, dict):
        return {}
    limits = {}
    for uid, info in users.items():
        if not user_access_allowed(info):
            continue
        raw = info.get('ip_limit', 0)
        # bool 是 int 的子类：True 会被静默算成「1 个设备」，把一个本应
        # 不限设备的账号限成单设备（JSON 里写成 true 就会触发）。
        if isinstance(raw, bool):
            continue
        try:
            limit = int(raw)
        except (ValueError, TypeError, OverflowError):
            continue
        if limit > 0:
            limits[uid] = limit
    return limits


# ---- 跨节点统一设备上限（2026-10-30）----
# 节点自己的同时在线 IP 检查只看本机：同一订阅在每台节点上各能用满 ip_limit 个网络。
# 控制台把各节点在线 IP 合并后，把「超出总名额的 IP」通过 users/ip-deny 下发到每台节点：
# Hy2 在 /auth 拒绝、已在线的踢下线；Reality 并入 iplimit 黑洞规则。
# 每条拦截带有效期（控制台每轮续期），控制台停发或节点重启后自动失效 —— 宁可漏拦，不误拦到永远。
IP_DENY_MAX_IPS = 64
IP_DENY_TTL_RANGE = (30, 3600)


def parse_ip_deny(params, now):
    """校验 users/ip-deny 请求。返回 (user_id, {ip: 过期时间})；不合法抛 ValueError。"""
    user_id = str(params.get('user_id', '')).strip()
    if not USER_ID_RE.match(user_id):
        raise ValueError('Invalid user_id format')
    raw = params.get('ips', [])
    if not isinstance(raw, list) or len(raw) > IP_DENY_MAX_IPS:
        raise ValueError('ips must be a list of at most %d addresses' % IP_DENY_MAX_IPS)
    try:
        ttl = int(params.get('ttl', 600))
    except (TypeError, ValueError):
        raise ValueError('Invalid ttl')
    if not IP_DENY_TTL_RANGE[0] <= ttl <= IP_DENY_TTL_RANGE[1]:
        raise ValueError('ttl must be between %d and %d seconds' % IP_DENY_TTL_RANGE)
    entries = {}
    for item in raw:
        try:
            ip = str(ipaddress.ip_address(str(item).strip()))
        except ValueError:
            raise ValueError('Invalid IP address: %s' % str(item)[:64])
        entries[ip] = now + ttl
    return user_id, entries


def active_ip_deny(table, uid, now):
    """{ip} —— 某用户当前仍在有效期内的拦截 IP；顺手清掉过期的。

    ⚠️ 这个函数在 /auth 的 data_lock 内被每个新连接调用。表项被写成字符串、
    或过期时间被写成非数字时，旧写法 `.items()` / `until <= now` 直接抛异常，
    异常穿透 do_POST → 连接被掐断，客户端只会无限重试（表现为「突然全节点
    连不上」）。损坏项按「无拦截」处理并清掉，绝不能让鉴权路径抛异常。
    """
    if not isinstance(table, dict):
        return set()
    row = table.get(uid)
    if not isinstance(row, dict):
        if uid in table:
            table.pop(uid, None)
        return set()
    for ip in [ip for ip, until in row.items()
               if not isinstance(until, (int, float)) or isinstance(until, bool)
               or until <= now]:
        row.pop(ip)
    if not row:
        table.pop(uid, None)
        return set()
    return set(row)


def kick_hy2_users(root, uids):
    """让 Hy2 核心断开这些用户的全部会话（被拦 IP 断开后重连会在 /auth 被拒，放行的设备会自动重连）。"""
    cfg_path = Path(root) / 'usage-meter-config.json'
    try:
        cfg = json.loads(cfg_path.read_text(encoding='utf-8')) if cfg_path.exists() else {}
    except (OSError, ValueError):
        cfg = {}
    # 配置文件可能被截断/手工改坏：hysteria 段是字符串、缺 secret 时
    # `.get` / `hc['secret']` 抛异常。调用方只把异常当「踢人失败」吞掉，
    # 但被拦 IP 的旧会话会一直保持连接，直到自然断开。
    hc = cfg.get('hysteria') if isinstance(cfg, dict) else None
    hc = hc if isinstance(hc, dict) else {}
    secret = hc.get('secret')
    url = hc.get('url')
    url = url.rstrip('/') if isinstance(url, str) else ''
    if (not uids or not isinstance(secret, str) or not secret
            or not re.fullmatch(r'http://(?:127\.0\.0\.1|\[::1\]):[0-9]+', url)):
        return False
    req = urllib.request.Request(url + '/kick', data=json.dumps(sorted(uids)).encode(),
                                 headers={'Authorization': secret, 'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=4):
        pass
    return True


def plan_reality_iplimit(limits, reality_ips, hy2_ips, state, now,
                         release_after=REALITY_IPLIMIT_RELEASE_SECONDS):
    """决定 Reality 上哪些 IP 放行、哪些拦截（纯函数，便于测试）。

    Xray 没有按用户限 IP 的能力，所以由门户在外面做：每轮读一次 Reality 在线 IP，
    与 Hy2 正在用的 IP 合并计数，「先到先得」放行前 N 个，其余的交给
    apply_reality_iplimit 下发黑洞路由规则。

    limits      {uid: ip_limit}，只含 ip_limit > 0 的用户
    reality_ips {uid: set(ip)}，本轮 Xray 报告在线的 IP（被拦的 IP 也会出现：
                连接进得来、鉴权通过，只是被路由进黑洞）
    hy2_ips     {uid: set(ip)}，Hy2 正在用或 180 秒内鉴权过的 IP
    state       {uid: {'admitted': {...}, 'blocked': {...}}}，跨轮次保留，原地更新

    被拦的 IP **不计入**占用，否则会「拦了→掉线→名额空出→放行→又超限」来回跳。
    放行过的 IP 断开后保留 release_after 秒，与 Hy2 的 IP_TIMEOUT_SECONDS 同一口径；
    这也意味着满额用户切换网络后，旧 IP 要等这段时间才释放。
    返回 {uid: set(要拦截的 ip)}。
    """
    if not isinstance(state, dict):
        state = {}
    for uid in list(state):
        if uid not in limits:
            state.pop(uid)
    blocked_out = {}
    for uid, limit in limits.items():
        row = state.get(uid)
        # 跨轮次状态是内存字典，格式被旧版本/手工改坏时（字符串、缺 admitted 等）
        # 旧写法直接 row['admitted'] 抛 TypeError，iplimit worker 每轮都在这里
        # 失败 —— 设备上限形同虚设，且日志只有一句「本轮跳过」。
        if (not isinstance(row, dict) or not isinstance(row.get('admitted'), dict)
                or not isinstance(row.get('blocked'), dict)):
            row = {'admitted': {}, 'blocked': {}}
            state[uid] = row
        # admitted: {ip: last_seen}；blocked: {ip: [first_blocked, last_seen]}。
        # 被拦 IP 要单独记「开始等待的时间」，名额空出时按它排队。
        admitted, blocked = row['admitted'], row['blocked']
        seen = set(reality_ips.get(uid) or ())
        # 单个 IP 的时间戳/区间被改坏时只丢这一条：不能让它把整轮规划打断，
        # 否则该用户的所有设备都不再受上限约束。
        for ip in list(admitted):
            last = admitted[ip]
            if not isinstance(last, (int, float)) or isinstance(last, bool):
                admitted.pop(ip)
            elif ip in seen:
                admitted[ip] = now
            elif now - last >= release_after:
                admitted.pop(ip)
        for ip in list(blocked):
            span = blocked[ip]
            if (not isinstance(span, (list, tuple)) or len(span) != 2
                    or not all(isinstance(v, (int, float)) and not isinstance(v, bool)
                               for v in span)):
                blocked.pop(ip)
                continue
            if ip in seen:
                blocked[ip][1] = now
            elif now - blocked[ip][1] >= release_after:
                blocked.pop(ip)
        occupied = set(hy2_ips.get(uid) or ()) | set(admitted)
        # 先处理等待最久的被拦 IP，再处理新出现的；同一时间按 IP 排序保证结果确定。
        waiting = sorted((ip for ip in seen if ip not in admitted),
                         key=lambda ip: (ip not in blocked, blocked[ip][0] if ip in blocked else now, ip))
        for ip in waiting:
            if ip in occupied or len(occupied) < limit:
                blocked.pop(ip, None)
                admitted[ip] = now
                occupied.add(ip)
            elif ip not in blocked:
                blocked[ip] = [now, now]
        if blocked:
            blocked_out[uid] = set(blocked)
        if not admitted and not blocked:
            state.pop(uid)
    return blocked_out


def reality_iplimit_rules(blocked):
    """{uid: ips} -> {ruleTag: rule}。tag 由用户和 IP 集合派生：内容变了 tag 就变，
    同步时只比对 tag 即可，不需要依赖 lsrules 回显规则内容（它不回显）。"""
    rules = {}
    for uid, ips in blocked.items():
        if not ips:
            continue
        ips = sorted(ips)
        digest = hashlib.sha256((uid + '|' + ','.join(ips)).encode()).hexdigest()
        tag = '%s%s-%s' % (REALITY_IPLIMIT_TAG_PREFIX,
                           hashlib.sha256(uid.encode()).hexdigest()[:12], digest[:12])
        rules[tag] = {'ruleTag': tag, 'type': 'field', 'user': [uid], 'source': ips,
                      'outboundTag': 'iplimit-block'}
    return rules


def apply_reality_iplimit(binary, address, desired, run=subprocess.run):
    """把运行中 Xray 的 iplimit-* 规则同步成 desired。

    规则只存在于 Xray 内存：Xray 一重启就清空，所以每轮都用 lsrules 对一次账，
    而不是记住「上次下发过什么」。返回 (added, removed) 的 tag 数。
    """
    if not address.startswith('127.0.0.1:'):
        raise ValueError('xray api must be loopback')
    server = '--server=' + address
    listed = run([binary, 'api', 'lsrules', server], capture_output=True, text=True, timeout=5)
    if listed.returncode != 0:
        raise RuntimeError('xray lsrules failed')
    # lsrules 的输出来自外部进程：空串、非 JSON、rules 被写成字符串或含非 dict
    # 条目都可能出现。旧写法 `r.get(...)` 直接抛 AttributeError/JSONDecodeError，
    # 每轮都失败 —— 已下发的拦截规则既不会被补也不会被清。
    try:
        listing = json.loads(listed.stdout or '{}')
    except ValueError:
        listing = {}
    rows = listing.get('rules') if isinstance(listing, dict) else None
    current = {str(r.get('ruleTag')) for r in (rows if isinstance(rows, list) else [])
               if isinstance(r, dict)
               and str(r.get('ruleTag', '')).startswith(REALITY_IPLIMIT_TAG_PREFIX)}
    missing = [tag for tag in sorted(desired) if tag not in current]
    stale = sorted(current - set(desired))
    if missing:
        with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False, encoding='utf-8') as fh:
            json.dump({'routing': {'rules': [desired[tag] for tag in missing]}}, fh)
            rule_file = fh.name
        try:
            added = run([binary, 'api', 'adrules', server, '-append', rule_file],
                        capture_output=True, text=True, timeout=5)
        finally:
            os.unlink(rule_file)
        if added.returncode != 0:
            raise RuntimeError('xray adrules failed')
    # 先加新规则再删旧规则：同一用户换 IP 集合时不留「没有规则」的空窗。
    if stale:
        removed = run([binary, 'api', 'rmrules', server] + stale,
                      capture_output=True, text=True, timeout=5)
        if removed.returncode != 0:
            raise RuntimeError('xray rmrules failed')
    return len(missing), len(stale)


def read_reality_online_ips(binary, address, uids, run=subprocess.run):
    """{uid: set(ip)}：只查 uids 里当前在线的用户。读不到就抛异常，由调用方放行。"""
    server = '--server=' + address
    out = run([binary, 'api', 'statsgetallonlineusers', server], capture_output=True, text=True, timeout=5)
    if out.returncode != 0:
        raise RuntimeError('xray statsgetallonlineusers failed')
    try:
        listing = json.loads(out.stdout or '{}')
    except ValueError:
        listing = {}
    names = listing.get('users') if isinstance(listing, dict) else None
    # users 可能是字符串（旧版本回显）或含非字符串条目；按字符拆会把
    # "alice" 变成 a/l/i/c/e 五个假用户，然后逐个去查 IP。
    names = names if isinstance(names, list) else []
    online = set()
    for name in names:
        if not isinstance(name, str):
            continue
        parts = name.split('>>>')
        online.add(parts[1] if len(parts) == 3 and parts[0] == 'user' else name)
    result = {}
    # uids 由调用方从 limits 传入；容器被改坏时 set() 会抛 TypeError，
    # 而调用方只会把异常当成「读不到在线数据」并把全部拦截规则撤掉。
    uids = uids if isinstance(uids, (list, tuple, set, frozenset, dict)) else ()
    for uid in sorted(set(uids) & online):
        got = run([binary, 'api', 'statsonlineiplist', server, '--email=' + uid],
                  capture_output=True, text=True, timeout=5)
        if got.returncode != 0:
            raise RuntimeError('xray statsonlineiplist failed')
        try:
            payload = json.loads(got.stdout or '{}')
        except ValueError:
            payload = {}
        ips = payload.get('ips') if isinstance(payload, dict) else None
        if not isinstance(ips, dict):
            raise ValueError('invalid online ip list')
        clean = set()
        for ip in ips:
            try:
                clean.add(str(ipaddress.ip_address(ip)))
            except ValueError:
                # 单个畸形 IP 不能让整轮抛异常 —— 调用方会因此撤掉**全部**
                # 拦截规则，等于所有超额用户瞬间恢复不限设备。
                continue
        result[uid] = clean
    return result


def _systemd_state(unit):
    """systemctl is-active 的结果；拿不到（无 systemd、超时）时返回空串。"""
    try:
        return subprocess.run(['systemctl', 'is-active', unit], capture_output=True,
                              text=True, timeout=5).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ''



def _nft_input_chain():
    """找到 nftables 里 hook input 且 policy drop 的链，返回 (family, table, chain)。

    纯 nftables 主机（没有 ufw / firewalld）上，门户自己开的 Reality / VMess /
    AnyTLS / GOST 端口如果不在这里放行，外网就连不上 —— 而安装器只放行了
    Hy2 自己的端口（2026-10-29 修）。
    """
    try:
        out = subprocess.run(['nft', 'list', 'ruleset'], capture_output=True, text=True,
                             timeout=5).stdout
    except Exception:
        return None
    table = ''
    chain = ''
    for line in out.splitlines():
        if line.startswith('table '):
            parts = line.split()
            if len(parts) >= 3:
                table = parts[1] + ' ' + parts[2]
            chain = ''
        elif line.lstrip().startswith('chain ') and table:
            chain = line.split()[1].rstrip('{').rstrip(':')
        elif 'hook input' in line and 'policy drop' in line and chain:
            fam, _, name = table.partition(' ')
            return fam, name, chain
    return None


def _nft_port_rule(proto, port):
    """匹配本模块写入的 accept 规则（用于幂等判断与删除）。"""
    return re.compile(r'\b%s\s+dport\s+%d\s+accept\b' % (re.escape(proto), int(port)))

def firewall_port(port, proto='tcp', open_=True):
    """在本机防火墙（ufw / firewalld，仅当它们正在运行）上放行或收回一个端口。

    尽力而为：防火墙操作失败不影响调用方的结果，只记日志。
    Hy2 与 AWG 的端口由安装脚本放行；门户自己装的 Reality 和 GOST 代理端口要在这里处理，
    否则开着防火墙的系统上本机探测一切正常，外网却连不上。
    """
    try:
        port = int(port)
    except (TypeError, ValueError):
        return
    if not 1 <= port <= 65535 or proto not in ('tcp', 'udp'):
        return
    spec = '%d/%s' % (port, proto)
    try:
        handled = False
        if shutil.which('ufw'):
            status = subprocess.run(['ufw', 'status'], capture_output=True, text=True, timeout=10).stdout
            if status.startswith('Status: active'):
                cmd = ['ufw', 'allow', spec] if open_ else ['ufw', 'delete', 'allow', spec]
                subprocess.run(cmd, capture_output=True, timeout=15)
                handled = True
        if shutil.which('firewall-cmd') and _systemd_state('firewalld') == 'active':
            flag = '--add-port=' if open_ else '--remove-port='
            subprocess.run(['firewall-cmd', '--zone=public', flag + spec, '--permanent'],
                           capture_output=True, timeout=15)
            subprocess.run(['firewall-cmd', '--reload'], capture_output=True, timeout=15)
            handled = True
        if not handled and shutil.which('nft'):
            # 纯 nftables 主机：安装器只放行了 Hy2 的端口，门户新增的协议端口
            # 必须在这里补上，否则外网连不上而本机一切正常（2026-10-29 修）。
            target = _nft_input_chain()
            if target:
                fam, tbl, chain = target
                listed = subprocess.run(['nft', '-a', 'list', 'chain', fam, tbl, chain],
                                        capture_output=True, text=True, timeout=5).stdout
                matched = [ln for ln in listed.splitlines() if _nft_port_rule(proto, port).search(ln)]
                if open_:
                    if not matched:
                        subprocess.run(['nft', 'add', 'rule', fam, tbl, chain,
                                        proto, 'dport', str(port), 'accept'],
                                       capture_output=True, timeout=10)
                else:
                    for line in matched:
                        hm = re.search(r'# handle (\d+)', line)
                        if hm:
                            subprocess.run(['nft', 'delete', 'rule', fam, tbl, chain,
                                            'handle', hm.group(1)],
                                           capture_output=True, timeout=10)
    except Exception as exc:
        _log_ignored('firewall_port', exc)


def password_taken(users, pwd, owner_uid):
    """pwd 是否已被 owner_uid 以外的用户（含机主）占用。调用方须持有 data_lock。

    /auth 按密码找用户、命中第一个就停：两人同密码时，后者的流量、限额、
    到期都会算到前者头上；撞上机主密码则直接拿到不限量的永久账号。
    """
    if not isinstance(users, dict):
        return False
    return any(uid != owner_uid and isinstance(u, dict)
               and str(u.get('password', '')) == str(pwd)
               for uid, u in users.items())

def enforce_node_access(root, snapshot, force_ids=()):
    """分别尝试 AnyTLS 与 Xray；任一路无法确认时保留待撤销状态。"""
    anytls_error = None
    try:
        sync_anytls_users(root, snapshot)
    except Exception as exc:
        anytls_error = exc
    result = _enforce_node_access_xray_hy2(root, snapshot, force_ids)
    if anytls_error is not None:
        raise RuntimeError('AnyTLS user sync could not be confirmed') from anytls_error
    return result


def _enforce_node_access_xray_hy2(root, snapshot, force_ids=()):
    """确认旧会话和 Xray 核心都已收回；失败不伪造销户成功。"""
    root = Path(root)
    # 快照里的 users 可能是 null/list（手工编辑或截断写入）：直接 .items()
    # 抛 AttributeError，撤销流程每 5 秒重试失败，停用/到期用户保持在线。
    users = snapshot.get('users') if isinstance(snapshot, dict) else None
    users = users if isinstance(users, dict) else {}
    blocked = sorted({str(uid) for uid in force_ids}
                     | {uid for uid, info in users.items()
                        if not user_access_allowed(info)})
    cfg_path = root / 'usage-meter-config.json'
    try:
        cfg = json.loads(cfg_path.read_text(encoding='utf-8')) if cfg_path.exists() else {}
    except (OSError, ValueError):
        cfg = {}
    if blocked:
        # 配置被截断/改坏时旧写法 `.get` 抛 AttributeError，异常类型不是
        # 「无法确认撤销」那条明确的 RuntimeError，调用方日志里只会看到
        # AttributeError —— 排查方向被带偏到代码 bug 而不是坏配置。
        hc = cfg.get('hysteria') if isinstance(cfg, dict) else None
        hc = hc if isinstance(hc, dict) else {}
        url = hc.get('url')
        url = url.rstrip('/') if isinstance(url, str) else ''
        if not re.fullmatch(r'http://(?:127\.0\.0\.1|\[::1\]):[0-9]+', url):
            raise RuntimeError('cannot confirm Hy2 revocation: loopback stats unavailable')
        def request_stats(path, payload=None):
            req = urllib.request.Request(url + path, data=json.dumps(payload).encode() if payload is not None else None,
                                         headers={'Authorization': hc['secret'], 'Content-Type':'application/json'})
            with urllib.request.urlopen(req, timeout=4) as response:
                raw=response.read()
            return json.loads(raw) if raw.strip() else {}
        try:
            online=request_stats('/online')
        except OSError:
            # Hy2 已停（例如整机流量超额停用）时统计接口必然连不上，但此时也
            # 不可能有在线会话；新连接的鉴权照样会被拒。不跳过的话，停用期间
            # 控制台删除 / 停用用户会一直拿到 503。
            # 只认「流量超额停用」这一种已知停机：服务没装、单元不存在时 is-active
            # 同样返回 inactive，那种情况不能当作「无在线会话」放行（CI 上踩到）。
            if _unit_suspended('hysteria-server') and _systemd_state('hysteria-server') in ('inactive', 'failed'):
                online={}
            else:
                raise
        active=[uid for uid in blocked if int(online.get(uid, 0)) > 0]
        if active:
            request_stats('/kick', active)
            time.sleep(0.2)
            online=request_stats('/online')
            if any(int(online.get(uid, 0)) > 0 for uid in active):
                # 标准核心只在下一次传输消费 kick；闲置/多实例需确保全部会话关闭。
                subprocess.run(['systemctl','restart','hysteria-server'],capture_output=True,timeout=12,check=True)
                subprocess.run(['systemctl','is-active','--quiet','hysteria-server'],capture_output=True,timeout=4,check=True)
                online=request_stats('/online')
                if any(int(online.get(uid, 0)) > 0 for uid in active):
                    raise RuntimeError('Hy2 sessions still present after revocation')
    xj=root/'xray.json'
    if not xj.exists():
        return True
    original=xj.read_bytes()
    xcfg=json.loads(original)
    # 运行中的 Xray 可能仍加载旧配置；损坏的磁盘配置不能证明没有入站。
    if not isinstance(xcfg, dict) or ('inbounds' in xcfg and not isinstance(xcfg['inbounds'], list)):
        raise ValueError('invalid Xray configuration; cannot confirm revocation')
    if any(not isinstance(item, dict) for item in xcfg.get('inbounds', [])):
        raise ValueError('invalid Xray inbound entry; cannot confirm revocation')
    tags = [item.get('tag') for item in xcfg.get('inbounds', [])]
    if any(tags.count(tag) > 1 for tag in MANAGED_INBOUND_TAGS):
        raise ValueError('duplicate managed Xray inbound tag; cannot confirm revocation')
    # 收回必须覆盖**所有**托管入站：只看 Reality 的话，VMess-only 节点上
    # 停用/到期/超额的用户会继续用 VMess 连（2026-10-24 接入 VMess 时的关键缺口）。
    _client_builders={REALITY_INBOUND_TAG:reality_clients,
                      VMESS_INBOUND_TAG:vmess_clients,
                      VLESSENC_INBOUND_TAG:vlessenc_clients}
    wanted_by_tag={}
    for tag in MANAGED_INBOUND_TAGS:
        idx,_inbound=managed_inbound_index(xcfg,tag)
        if idx<0:
            continue
        wanted_by_tag[tag]=_client_builders[tag](snapshot)
    if not wanted_by_tag:
        return True
    signature=hashlib.sha256(json.dumps(wanted_by_tag,sort_keys=True).encode()).hexdigest()
    epoch=subprocess.run(['systemctl','show','xray','--property=InvocationID','--value'],capture_output=True,text=True,timeout=4,check=True).stdout.strip()
    current={tag:xcfg['inbounds'][managed_inbound_index(xcfg,tag)[0]].get('settings',{}).get('clients')
             for tag in wanted_by_tag}
    if current==wanted_by_tag and _ACCESS_APPLIED.get(str(root))==(signature,epoch):
        return True
    # 首次升级/删除请求也核验实际重载，不能仅比较磁盘配置。
    if not blocked and not force_ids and current==wanted_by_tag:
        return True
    for tag,wanted in wanted_by_tag.items():
        idx,_inbound=managed_inbound_index(xcfg,tag)
        xcfg['inbounds'][idx].setdefault('settings',{})['clients']=wanted
    candidate=xj.with_name('xray.expiry-candidate.json')
    candidate.write_text(json.dumps(xcfg,indent=2),encoding='utf-8')
    candidate.chmod(xj.stat().st_mode & 0o777)
    binary=cfg.get('reality',{}).get('binary','/usr/local/bin/xray')
    replaced=False
    try:
        subprocess.run([binary,'run','-test','-c',str(candidate)],capture_output=True,timeout=10,check=True)
        if xj.read_bytes()!=original:
            raise RuntimeError('Xray configuration changed concurrently; retry')
        shutil.copy2(xj,xj.with_name('xray.expiry-last-good.json'))
        candidate.replace(xj); replaced=True
        state=subprocess.run(['systemctl','is-active','xray'],capture_output=True,text=True,timeout=4).stdout.strip()
        if state in ('inactive','failed'):
            _ACCESS_APPLIED[str(root)]=(signature,epoch)
            return True
        subprocess.run(['systemctl','reset-failed','xray'],capture_output=True,timeout=4,check=True)
        subprocess.run(['systemctl','restart','xray'],capture_output=True,timeout=12,check=True)
        subprocess.run(['systemctl','is-active','--quiet','xray'],capture_output=True,timeout=4,check=True)
        epoch=subprocess.run(['systemctl','show','xray','--property=InvocationID','--value'],capture_output=True,text=True,timeout=4,check=True).stdout.strip()
        if not epoch:raise RuntimeError('missing Reality runtime epoch')
        _ACCESS_APPLIED[str(root)]=(signature,epoch)
        return True
    except Exception:
        if replaced:
            candidate.write_bytes(original);candidate.replace(xj)
            subprocess.run(['systemctl','restart','xray'],capture_output=True,timeout=12)
        raise
    finally:
        candidate.unlink(missing_ok=True)



def managed_reserved_ports(meta, data, config=None, exclude_key=None):
    """汇总「本机其它协议正在用 / 配置里已占」的端口，供 _pick_reality_port 避让。

    2026-10-24 修：三个启用流程各自只避开 hy2 与订阅端口，彼此之间不避让 ——
    实测 VMess 选中 2087 而 VLESS Encryption 正监听 2087，两个入站撞车。
    这里统一从 data 与现有 xray.json 的 inbounds 收集，避免每处各写一遍再漏。
    """
    # meta / data 都来自磁盘上的 JSON，可能被截断成 list/str；`.get` 抛异常
    # 会让端口选择整条失败 —— 协议启停直接报错，而界面只说「启用失败」。
    meta = meta if isinstance(meta, dict) else {}
    data = data if isinstance(data, dict) else {}
    ports = set()
    for value in (meta.get('listen_port'), meta.get('subscription_port')):
        try:
            ports.add(int(value))
        except (TypeError, ValueError):
            pass
    for key in ('reality_config', 'vmess_config', 'vlessenc_config', 'anytls_config'):
        # AnyTLS 停用后保留 secret 与端口记录（再启用要沿用），但那个端口已经空出来了。
        section = data.get(key)
        if key == 'anytls_config' and not (isinstance(section, dict) and section.get('enabled')):
            continue
        if key == exclude_key:
            # 协议**自己**的端口不是冲突：重新启用时应当沿用它。
            # 不排除的话，重新生成配置会把自己的端口也当成「被占用」，
            # 于是一次无关的启停就把 Reality 从 443 换到 2053
            # （2026-10-25 实测踩到）。
            continue
        try:
            ports.add(int((data or {}).get(key, {}).get('port')))
        except (TypeError, ValueError, AttributeError):
            pass
    own_tags = {REALITY_INBOUND_TAG: 'reality_config',
                VMESS_INBOUND_TAG: 'vmess_config',
                VLESSENC_INBOUND_TAG: 'vlessenc_config'}
    for inbound in ((config or {}).get('inbounds') or []):
        # 同理：自己那一条入站的端口不算冲突。
        if exclude_key and own_tags.get((inbound or {}).get('tag')) == exclude_key:
            continue
        try:
            ports.add(int(inbound.get('port')))
        except (TypeError, ValueError, AttributeError):
            pass
    ports.discard(0)
    return ports


def apply_xray_config_with_meter(config, config_path, meter_cfg_path, portal_dir):
    """把计量 StatsService、内网拦截补进配置后，原子应用并重启 Xray。

    2026-10-25 抽出：这段「读计量配置 → 加载模块 → add_stats → 加内网拦截 →
    事务应用」在三个协议的启用流程里各写了一遍。前两轮的并发锁与端口避让
    bug 正是「三处各写一遍、只修了一处」造成的，这里合并成单一入口。
    """
    config_path = Path(config_path)
    if meter_cfg_path.exists():
        meter = json.loads(meter_cfg_path.read_text(encoding='utf-8')).get('reality') or {}
        address = meter.get('address', '')
        if address:
            if not address.startswith('127.0.0.1:'):
                raise ValueError('统计接口必须为回环地址')
            stats_path = Path(portal_dir) / 'usage-meter-xray-config-20261007-v1.py'
            spec = importlib.util.spec_from_file_location('portal_stats_cfg', stats_path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            config = mod.add_stats(config, int(address.rsplit(':', 1)[1]))
    config = add_private_network_guard(config)
    # ⚠️ 必须用模块级 `_unit_suspended`，不能直接调 `unit_suspended`。
    #
    # 2026-10-26 生产实测：12 台节点升级后点「启用 VLESS Encryption」报
    #   name 'unit_suspended' is not defined
    #
    # 根因：`unit_suspended` 是 main() 内部的嵌套函数，只有 main() 的作用域
    # 看得见；本函数是模块级的，运行时找不到这个名字。
    # 模块级本来就有 `_unit_suspended = lambda unit: False` 兜底，且 main()
    # 会用 `global _unit_suspended` 把它替换成真实现 —— 模块级代码一律走它。
    #
    # 为什么以前没炸：这条路径只在「需要重新生成 Xray 配置」时才走到；
    # 存量节点升级前配置已生成，不会重新进入。启用新协议必然要写配置，
    # 于是必然触发。
    apply_xray_config_transaction(config, config_path=str(config_path),
                                  binary='/usr/local/bin/xray',
                                  restart=not _unit_suspended('xray'))
    return config

def reality_clients(data):
    """生成 xray inbound.settings.clients —— 每个**在用**的 Hy2 用户一个 VLESS 身份。

    ⚠️ 2026-10-04 修的关键缺口：**必须排除 status='disabled' 的用户**。

    为什么（这是在 us2 上真实连接测出来的）：
        Reality 走的是 **xray 自己的 UUID 白名单**，它**不经过 hy2 的
        handle_auth** —— 而 status 字段只在 handle_auth 里被检查。
        于是旧实现下：
            users/set_status(active=False)  -> Hy2 立刻被拒，但 **Reality 照样能连**
        实测：停用后拿原参数连 Reality 仍返回 204。
        这就是「停用了但货还在」—— 与 10-03 那批孤儿账号同源。

    为什么在**生成时过滤**而不是**从 registry 里删**：
        registry（data['reality_users']）是「user_id -> UUID」的**持久映射**，
        UUID 由 uuid5 派生、与 user_id 一一对应。
        停用是**可恢复**语义（买家不用重配），所以：
          - 停用：UUID 仍留在 registry（保住映射），但从 clients 里**消失** → 连不上
          - 启用：同一 uuid5 让它**自动回到** clients → 原样恢复，无需重发配置
        如果改成停用时删 registry 条目，启用后虽然能重新派生出一样的 UUID，
        但中间那段「注册表与真实用户不一致」的状态容易在别处被误读，不如只过滤干净。

    空表也要返回**一个**占位 client：xray 的 vless inbound 在
    clients 为空时会拒绝所有连接，且 `systemctl restart xray` 仍然成功 ——
    表现为「服务 active 但所有人都连不上」，极难排查（2026-10-03 实测踩过）。
    所以宁可给一个随机占位 UUID，也不要让 clients 空着。
    """
    reg = reality_registry(data)
    users = user_table(data)
    clients = []
    for uid, uid_uuid in sorted(reg.items()):
        info = users.get(uid) or {}
        # 只有 active 的用户才进白名单。
        # 缺 status 视为 active —— 与 handle_auth 的判据保持同源
        # （那边也是 `info.get('status', 'active') == 'active'`），
        # 两处判据必须一致，否则又会出现「一处放行、一处拒绝」的矛盾状态。
        if not user_access_allowed(info):
            continue
        clients.append({'id': uid_uuid, 'flow': 'xtls-rprx-vision', 'email': uid})
    if not clients:
        clients = [{'id': str(uuid.uuid4()), 'flow': 'xtls-rprx-vision',
                    'email': 'placeholder'}]
    return clients


def _reality_public_params(rcfg):
    """挑出 Reality 的**客户端公开参数**（白名单）。

    背景（2026-10-04）：主面板要把 Reality 接进合并订阅，就必须知道每台节点
    自己的 pbk / sid / sni / port。此前这些只在节点 Web 会话里可见，
    Bearer 通道拿不到 → 面板只能下发 Hy2，订阅里永远没有 Reality。

    为什么这些可以走 Bearer 通道：
        pbk（公钥）、sid（short_id）、sni 本来就会写进下发给客户端的订阅链接，
        客户端人手一份 —— 它们是**客户端配置必须携带的公开值**，不是机密。
        **private_key 才是服务端机密**，这里**绝不**包含它。

    为什么用白名单而不是整字典透传：
        reality_config 里同时存着 private_key。整字典透传等于把私钥
        送上 Bearer 通道；而白名单让「以后新增字段」默认**不**泄漏 ——
        加字段必须显式改这里，是一次有意识的决定。

    返回值恒为 dict（即使 rcfg 为空），方便调用方直接 ** 展开：
    缺少的参数会缺席，而不是变成 None —— 面板据此判断"这台没配 Reality"。
    """
    if not isinstance(rcfg, dict):
        return {}
    out = {}
    # 只挑明确要用的四个键。顺序固定，便于人读与测试对比。
    pub_key = rcfg.get('public_key')
    if isinstance(pub_key, str) and pub_key.strip():
        out['public_key'] = pub_key.strip()
    short_id = rcfg.get('short_id')
    if isinstance(short_id, str) and short_id.strip():
        out['short_id'] = short_id.strip()
    dest_sni = rcfg.get('dest_sni')
    if isinstance(dest_sni, str) and dest_sni.strip():
        out['dest_sni'] = dest_sni.strip()
    # 与 artifacts() 同一套端口校验：True 会变成 1、1.5 被截断成 1，
    # 主面板据此下发一个指向错误端口的 Reality 节点（客户端连不上）。
    port = _valid_port(rcfg.get('port') or 0)
    if port:
        out['port'] = port
    return out


def managed_inbound_active(config, tag):
    """托管入站必须有已安装核心和运行证据，磁盘残留配置不代表在线。"""
    if not Path('/usr/local/bin/xray').is_file():
        return False
    idx, inbound = managed_inbound_index(config, tag)
    if idx < 0:
        return False
    state = _systemd_state('xray')
    if state and state != 'active':
        return False
    # 已运行服务仍需对应端口监听；非 systemd 环境同样沿用只读探测。
    try:
        port = int(inbound.get('port', 0))
    except (TypeError, ValueError):
        return False
    listening = _listening_ports()
    # ss 完全不可用时无法证实端口，但服务是 active（或环境里没有 systemd，
    # state 为空）且配置里有该入站 —— 宁可继续下发节点，
    # 也不能把「探测不了」当成「没在运行」。
    if globals().get('_LISTEN_PROBE_OK', True) is False and state in ('active', ''):
        return True
    return port in listening


def _listening_ports():
    """读出「当前已被监听」的 TCP/UDP 端口集合。

    ⚠️ 为什么用 `ss` 而不是 `socket.bind()` 探测（2026-10-04 遵循既有教训）：
    本文件里 gost 那段代码明确记着一条血泪——
        「BUGFIX: 不再用 socket bind 做端口探测 (在某些环境会卡住)」
    所以这里沿用同一条路线：**只读地看内核里已有的监听表**，不主动 bind。
    好处是不卡、无副作用、也不需要 root 之外的任何能力。

    返回 set；`ss` 不可用或输出异常时返回**空集**——
    调用方据此退回到「只避开内置黑名单」，而不是直接失败。
    （宁可少避开一个端口，也不该让整个 Reality 配置生成不出来。）
    """
    ports, ok = _listening_ports_detail()
    # 记录本次探测是否真的成功：调用方据此区分「没有端口在监听」与
    # 「ss 不可用读不到」。用模块级变量而不是改返回值，保持既有调用方不变。
    global _LISTEN_PROBE_OK
    _LISTEN_PROBE_OK = ok
    return ports


def _listening_ports_detail():
    """返回 (端口集合, 是否至少有一个 ss 调用成功)。

    区分「真的没有端口在监听」与「ss 不可用读不到」很重要：
    前者应当如实反映，后者如果当成空集，会让订阅生成把**所有** Xray 协议
    判成未运行、静默只下发 Hy2（2026-10-29 修）。
    """
    ports = set()
    ok = False
    for flag in ('-lntH', '-lunH'):
        try:
            result = subprocess.run(['ss', flag], capture_output=True, text=True,
                                    timeout=5)
        except Exception:
            continue
        if result.returncode != 0:
            continue
        ok = True
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            # 第 4 列形如 0.0.0.0:8443 / [::]:22 / 127.0.0.1:43685 / *:54344
            addr = parts[3]
            if ':' not in addr:
                continue
            tail = addr.rsplit(':', 1)[1]
            if tail.isdigit():
                ports.add(int(tail))
    return ports, ok


# Reality 自动选端口时**永不使用**的端口。
#
# 分两类，理由不同：
#   1. 系统/常规服务端口：22(ssh) 80 443 —— 其中 443 要单独处理（见下），
#      80/22 绝不能被 Reality 抢走。
#   2. 本项目自用的固定端口：19898(hy2 备用) 40000(端口跳跃上限)
#      8443(默认订阅端口) 56195 —— 这些在别的节点上就是别人的位置。
#      ⚠️ 洛杉矶-NTT 实测：8443 是 **hysteria 的订阅端口**，
#      而别的节点 8443 是 xray —— 光看数字无法判断归属，
#      所以最终判据必须是「实际监听表」，这里只是兜底黑名单。
_REALITY_RESERVED_PORTS = {
    22, 80, 19898, 40000, 56195, 8443,
}

# 自动选端口的候选顺序。
#
# 443 放第一位：Reality 伪装成常规 HTTPS，443 最自然、最不容易被
# 中间设备针对；但**只有它真的空闲时才用**（不少节点 443 被 Caddy 占着）。
# 其余候选按「远离常见服务区间 + 好记」挑选，覆盖 443 冲突的常见情形。
_REALITY_PORT_CANDIDATES = [443, 8443, 2053, 2083, 2087, 2096, 9443, 5443, 8444]


def _pick_reality_port(preferred=None, extra_blocked=None):
    """挑一个**确实没被占用**的端口给 Reality 用。

    参数：
        preferred    —— 期望端口（来自已有配置或调用方指定）。可用就直接用它。
        extra_blocked—— 额外要避开的端口（如本机 hy2 的 listen_port）。

    返回 (port, reason)：
        port 为 0 表示**没找到可用端口**，调用方应当报错而不是硬塞一个。
        reason 是人可读的说明，会写进日志/响应，方便运维判断。

    判定顺序（从「最可信」到「最将就」）：
        1. preferred 空闲 → 用它（保持既有配置稳定，不随便改端口）
        2. 候选表里第一个空闲的 → 用它
        3. 全都不空闲 → 返回 0（**绝不硬塞**，宁可不生成也不配一个撞车的）
    """
    listening = _listening_ports()
    blocked = set(_REALITY_RESERVED_PORTS)
    if extra_blocked:
        for p in extra_blocked:
            try:
                iv = int(p)
            except (TypeError, ValueError, OverflowError):
                continue
            if 1 <= iv <= 65535:
                blocked.add(iv)

    def _as_port(v):
        """把任意输入安全地转成端口号，非法一律返回 0。

        ⚠️ 为什么必须容错（2026-10-04 单测抓到的真 bug）：
        旧写法直接拿 preferred 参与 `p < 1` 比较，一旦它是字符串（例如
        portal.json 被手工改坏、或旧版本写入了非数字），就抛
        TypeError: '<' not supported between instances of 'str' and 'int'，
        **把整个 Reality 配置生成打死** —— 而调用方只看到 500，
        根本猜不到是「配置里存了个坏端口值」。
        这里降级为「忽略这个偏好值」，继续正常选端口。
        """
        # bool 是 int 的子类（True == 1），配置里出现 true 会被当成端口 1；
        # 小数会被 int() 静默截断（65535.9 -> 65535）。两者都拒绝（2026-10-25）。
        if isinstance(v, bool):
            return 0
        if isinstance(v, float) and not v.is_integer():
            return 0
        try:
            iv = int(v)
        except (TypeError, ValueError):
            return 0
        return iv if 1 <= iv <= 65535 else 0

    # `pref` 必须在 free() 之前算出来 —— free() 要用它判断
    # 「这个端口是不是 Reality 自己已经在用的」。
    pref = _as_port(preferred)

    def free(p):
        # ⚠️⚠️ 顺序与例外（2026-10-04 实测抓到的严重风险，务必看懂再改）：
        #
        # 「已在用这个端口的，可能正是 Reality 自己」——这是最常见的情况：
        # 重新生成配置、点「重置密钥」时，xray 正监听在 8443 上。
        # 如果把黑名单放在最前面，8443 会被判成「被占用」，
        # 于是**给一个正在服务的节点换端口** —— tokyo 实测就会从
        # 8443 换到 2053，**21 个在跑的用户当场全部断线**。
        #
        # 所以判据必须是：
        #   * 该端口在**配置里已经属于 Reality**（preferred == p）
        #     ⇒ 无论监听表还是黑名单都不算冲突 —— 那就是「自己」。
        #   * 否则才看黑名单与监听表。
        # ⚠️ preferred 只有在「没被显式拉黑」时才算自己。
        # 2026-10-24 修：旧实现无条件 `p == pref: return True`，
        # 于是调用方即使把某个端口放进 extra_blocked（例如另一个托管协议
        # 正在用它），preferred 照样胜出 —— 实测 preferred=2087 且
        # extra_blocked={2087} 仍返回 2087，两个入站撞同一端口，
        # Xray 预检通过但 bind 失败，事务回滚，用户只看到 500。
        # 黑名单代表「调用方明确知道这端口不能给」，优先级必须高于偏好值。
        if p in blocked:
            return False
        if p == pref:
            return True
        # 以**实际监听表**为准。黑名单只是补充 ——
        # 因为「8443 归谁」在不同节点上完全不同，写死数字必然出错。
        return p not in listening

    # 1) 已有配置的端口优先（避免无谓地改动已有节点的端口）
    if pref and free(pref):
        return pref, '沿用已配置端口 %d（空闲）' % pref

    # 2) 按候选顺序找第一个空闲的
    for cand in _REALITY_PORT_CANDIDATES:
        if free(cand):
            if pref:
                return cand, ('原端口 %d 已被占用，自动改用 %d' % (pref, cand))
            return cand, '自动选择空闲端口 %d' % cand

    # 3) 失败：绝不硬塞
    return 0, ('未找到可用端口（候选 %s 全部被占用；'
               '当前监听 %s）' % (_REALITY_PORT_CANDIDATES, sorted(listening)[:12]))


def reality_uri_for_user(rcfg, user_id, public_ip, label=None):
    """给某个用户拼他自己的 VLESS-Reality 直链。

    rcfg 是 data['reality_config']（含 uuid/short_id/dest_sni/port/public_key）。
    单用户的 rcfg 里存的是**旧版单账号**的 uuid —— 这里忽略它，
    改用该 user_id 派生出的 UUID（reality_uuid_for_user）。
    """
    # 同 VMess / VLESS-Encryption：非 dict 配置在订阅路径上直接抛
    # AttributeError，用户拿不到任何节点。
    if not isinstance(rcfg, dict):
        return ''
    short_id = rcfg.get('short_id', '')
    dest_sni = rcfg.get('dest_sni', 'www.apple.com')
    pub_key = rcfg.get('public_key', '')
    # 端口必须是合法整数：被改成 "abc" / None / 70000 时链路会拼出
    # `vless://...#:abc` 这种所有客户端都拒绝的地址，而页面照样显示成功
    # （与 VMess 分支同一套 _valid_port 校验，2026-10-30 修）。
    port = _valid_port(rcfg.get('port', 443))
    if not (short_id and dest_sni and pub_key and port):
        return ''
    uid_uuid = reality_uuid_for_user(user_id)
    tag = label or ('VLESS-Reality-' + str(user_id))
    return (f"vless://{uid_uuid}@{_host_for_url(public_ip)}:{port}"
            f"?security=reality&encryption=none&pbk={pub_key}"
            f"&headerType=none&fp=chrome&type=tcp&flow=xtls-rprx-vision"
            f"&sni={dest_sni}&sid={short_id}#{quote(tag)}")



def _valid_port(value):
    """把配置里的端口值转成合法 int；非法返回 0。

    artifacts() 会用它决定是否下发某个协议节点：配置被改坏时
    宁可少下发一个节点，也不能让整个页面/订阅生成抛异常 ——
    该函数在每次页面渲染时都会调用。
    """
    if isinstance(value, bool):
        return 0
    if isinstance(value, float) and not value.is_integer():
        return 0
    try:
        port = int(value)
    except (TypeError, ValueError, OverflowError):
        return 0
    return port if 1 <= port <= 65535 else 0


def _host_for_url(host):
    """IPv6 字面量拼进 URL 时必须加方括号。

    `https://2001:db8::1:8443/...` 无法解析；正确写法是 `[2001:db8::1]`。
    安装器只取 IPv4，所以正常路径不会命中，但手工写入 server_name/public_ip
    或将来支持 IPv6 时会（2026-10-29 加）。
    """
    host = str(host or '')
    if ':' in host and not host.startswith('['):
        return '[' + host + ']'
    return host


def artifacts(m, auth_override=None, name_override=None, reality=None, user_id=None,
              vmess=None, vlessenc=None, anytls=None):
    """生成 hy2:// 直链 + Clash / Sing-box 配置。

    reality（可选）—— 传 rcfg 时会**额外产出一条 VLESS-Reality 节点**，
    并把 Clash 的 PROXY 组改成 url-test（Hy2 与 Reality 自动择优），
    这样「UDP 被 QoS 的网络」会自己切到 TCP 通道（2026-10-03）。

    vmess（可选）—— 传 data['vmess_config'] 时再追加一条 VMess-WS-TLS。
    ⚠️ 返回值仍是三元组 (uri, clash, sing)，不新增返回位：调用点有 7 处，
    改返回结构会让任何漏改的一处静默错位。VMess 的 vmess:// 直链由
    vmess_uri_for_user() 单独生成，在需要的端点里作为额外字段下发。
    """
    is_insecure = m.get('is_insecure', False)
    server_name = m.get('server_name') or m.get('public_ip', 'localhost')
    public_ip = m.get('public_ip', server_name)
    host = public_ip if is_insecure else server_name
    # 标签会进 quote() 与客户端配置；非字符串（调用方传错或数据被改坏）
    # 会抛 TypeError，把整页渲染和订阅下载一起打断。
    name = name_override if isinstance(name_override, str) and name_override else ('Hy2-' + str(host))
    # 🔴 只有「没有覆盖」才回落节点主密码（auth_override is None）。
    # 旧写法 `auth_override or ...` 把用户密码的空串/0/None 也当成「未指定」，
    # 于是密码被清空或改坏的用户，分享链接里会直接出现**机主密码**。
    password = m.get('auth_password', '') if auth_override is None else auth_override
    # 密码来自用户记录，可能是数字/列表（手工编辑、旧格式）。quote() 只接受
    # 字符串，非字符串会让整个订阅/分享页 500；退回空串等于「这条链接不可用」，
    # 但仍能渲染页面并提示检查账号。
    if not isinstance(password, str):
        password = ''
    # 端口必须落成合法整数（2026-10-25 修）：meta 被改坏时 listen_port 可能是
    # None / 字符串，旧代码会原样拼出 `hysteria2://...:None` 这种所有客户端
    # 都会拒绝的链接，而且没有任何报错提示。这里退回默认端口。
    listen_port = _valid_port(m.get('listen_port')) or 19984
    obfs_password = m.get('obfs_password', '')
    hop_port_range = m.get('hop_port_range', '')
    # 证书信任策略（已逐条对照 v2rayNG 源码 / Xray 内核行为对齐）：
    #   * 公网可信证书：直链不带任何 pin / insecure，全客户端开箱即用；
    #   * 自签证书：同时带 pinSHA256(<HEX64>) 与 insecure=1 ——
    #       v2rayNG/v2rayN 把 pinSHA256 直接塞进 Xray 的 pinnedPeerCertSha256，该字段必须是【纯 HEX】，
    #       写 base64 会触发 `encoding/hex: invalid byte` 导致配置构建失败（这正是上一版扫码连不上的根因）；
    #       v2rayNG 源码仅在 pin 为空时才输出 allowInsecure，故两者并存既不报错，又能让只认 insecure 的
    #       sing-box / NekoBox / Clash / 官方 hysteria 正常跳过校验。
    # meta 被手工改坏时这类字段可能是数字/列表：.strip() / 字符串拼接都会抛异常，
    # 而 artifacts() 在每次页面渲染和订阅下载都会调用。
    raw_pin = m.get('pin_sha256')
    raw_pin = raw_pin.strip().lower() if isinstance(raw_pin, str) else ''
    pin_sha256 = raw_pin if len(raw_pin) == 64 and all(c in '0123456789abcdef' for c in raw_pin) else ''
    if not isinstance(obfs_password, str):
        obfs_password = ''
    if not isinstance(hop_port_range, str):
        hop_port_range = ''
    params = {'sni': server_name}
    if is_insecure:
        params['insecure'] = '1'
        if pin_sha256:
            params['pinSHA256'] = pin_sha256
    if obfs_password:
        params.update({'obfs': 'salamander', 'obfs-password': obfs_password})
    if hop_port_range:
        params['mport'] = hop_port_range
    uri = f"hysteria2://{quote(password, safe='')}@{_host_for_url(host)}:{listen_port}?{urlencode(params)}#{quote(name)}"
    
    proxy = dict(name=name, type='hysteria2', server=host, port=listen_port,
                 password=password, sni=server_name, **{'skip-cert-verify': is_insecure})
    sing = dict(type='hysteria2', tag=name, server=host, server_port=listen_port,
                password=password, tls=dict(enabled=True, server_name=server_name, insecure=is_insecure))
    if hop_port_range:
        proxy['ports'] = str(listen_port) + ',' + hop_port_range
        # sing-box 的 server_ports 每一项都必须是「起:止」区间（sing-quic ParsePorts），
        # 单写 "443" 会报 bad port range、整份配置加载失败。
        sing['server_ports'] = [f'{listen_port}:{listen_port}', hop_port_range.replace('-', ':')]
        del sing['server_port']
    if obfs_password:
        proxy.update({'obfs': 'salamander', 'obfs-password': obfs_password})
        sing['obfs'] = dict(type='salamander', password=obfs_password)

    # ---- Reality 备用通道（可选）----
    #
    # 目标是「一条订阅里既有 UDP 的 Hy2、又有 TCP 的 Reality」，
    # 客户端用 url-test 自动择优：UDP 通走 Hy2，UDP 被 QoS/阻断时自动切 Reality。
    # ⚠️ 只有 reality + user_id 同时给出时才追加 —— 单机管理员视角（user_id=None）
    # 仍只出一条 Hy2，避免给自己输出一个用不上的节点。
    reality_proxy = None
    reality_sing = None
    if reality and user_id:
        ruri = reality_uri_for_user(reality, user_id, public_ip,
                                    label=(name + '-Reality'))
        r_uuid = reality_uuid_for_user(user_id)
        r_port = _valid_port(reality.get('port', 443))
        r_sni = reality.get('dest_sni', 'www.apple.com')
        r_pbk = reality.get('public_key', '')
        r_sid = reality.get('short_id', '')
        if ruri and r_pbk and r_sid and r_port:
            rname = name + '-Reality'
            reality_proxy = dict(name=rname, type='vless', server=public_ip,
                                 port=r_port, uuid=r_uuid, udp=True,
                                 tls=dict(servername=r_sni),
                                 flow='xtls-rprx-vision',
                                 servername=r_sni,
                                 reality_opts=dict(public_key=r_pbk,
                                                   short_id=r_sid),
                                 **{'client-fingerprint': 'chrome'})
            reality_sing = dict(type='vless', tag=rname, server=public_ip,
                               server_port=r_port, uuid=r_uuid,
                               flow='xtls-rprx-vision',
                               tls=dict(enabled=True, server_name=r_sni,
                                        reality=dict(enabled=True,
                                                     public_key=r_pbk,
                                                     short_id=r_sid),
                                        utls=dict(enabled=True,
                                                  fingerprint='chrome')))

    # ---- VMess-WS-TLS 备用通道（可选，2026-10-24 加）----
    #
    # 与 Reality 同样是 TCP 通道，但依赖**自己的域名证书**：Reality 偷别人的
    # 握手，VMess 必须真的出示证书。因此只在启用且拿到域名时才追加。
    vmess_proxy = None
    vmess_sing = None
    if vmess and user_id and vmess.get('domain') and _valid_port(vmess.get('port')):
        v_name = name + '-VMess'
        v_uuid = vmess_uuid_for_user(user_id)
        v_host = vmess['domain']
        v_sni = vmess.get('sni') or v_host
        v_path = vmess.get('ws_path') or '/'
        v_port = _valid_port(vmess.get('port'))
        vmess_proxy = dict(name=v_name, type='vmess', server=v_host,
                           port=v_port, uuid=v_uuid, alterId=0,
                           cipher='auto', udp=True, tls=True, servername=v_sni,
                           network='ws', **{'ws-opts': {'path': v_path,
                                                        'headers': {'Host': v_sni}}},
                           **{'client-fingerprint': 'chrome'})
        vmess_sing = dict(type='vmess', tag=v_name, server=v_host,
                          server_port=v_port, uuid=v_uuid,
                          security='auto', alter_id=0,
                          transport=dict(type='ws', path=v_path,
                                         headers={'Host': v_sni}),
                          tls=dict(enabled=True, server_name=v_sni,
                                   utls=dict(enabled=True, fingerprint='chrome')))

    # ---- VLESS Encryption（可选）----
    # 同样是 TCP + 自有证书，但比 VMess 多了后量子密钥交换。
    vlessenc_proxy = None
    vlessenc_sing = None
    if vlessenc and user_id and vlessenc.get('domain') \
            and _valid_port(vlessenc.get('port')) and vlessenc.get('encryption'):
        e_name = name + '-VLESS-Enc'
        e_uuid = reality_uuid_for_user(user_id)
        e_host = vlessenc['domain']
        e_sni = vlessenc.get('sni') or e_host
        e_enc = vlessenc['encryption']
        e_port = _valid_port(vlessenc.get('port'))
        vlessenc_proxy = dict(name=e_name, type='vless', server=e_host,
                              port=e_port, uuid=e_uuid, udp=True,
                              tls=True, servername=e_sni, network='tcp',
                              encryption=e_enc,
                              **{'client-fingerprint': 'chrome'})
        vlessenc_sing = dict(type='vless', tag=e_name, server=e_host,
                             server_port=e_port, uuid=e_uuid,
                             encryption=e_enc,
                             tls=dict(enabled=True, server_name=e_sni,
                                      utls=dict(enabled=True, fingerprint='chrome')))

    # ---- AnyTLS（可选，2026-10-28 加）----
    # TCP + 自有证书，由 sing-box 承载；UDP 走客户端的 UDP-over-TCP。
    anytls_proxy = None
    anytls_sing = None
    if anytls and user_id and anytls.get('domain') \
            and _valid_port(anytls.get('port')) and anytls.get('secret'):
        a_name = name + '-AnyTLS'
        a_host = anytls['domain']
        a_sni = anytls.get('sni') or a_host
        a_pwd = anytls_password_for_user(anytls['secret'], user_id)
        a_port = _valid_port(anytls.get('port'))
        anytls_proxy = dict(name=a_name, type='anytls', server=a_host,
                            port=a_port, password=a_pwd, udp=True,
                            sni=a_sni, **{'client-fingerprint': 'chrome'})
        anytls_sing = dict(type='anytls', tag=a_name, server=a_host,
                           server_port=a_port, password=a_pwd,
                           tls=dict(enabled=True, server_name=a_sni,
                                    utls=dict(enabled=True, fingerprint='chrome')))

    proxies = [proxy] + ([reality_proxy] if reality_proxy else []) + \
              ([vmess_proxy] if vmess_proxy else []) + \
              ([vlessenc_proxy] if vlessenc_proxy else []) + \
              ([anytls_proxy] if anytls_proxy else [])
    sing_outbounds = [sing] + ([reality_sing] if reality_sing else []) + \
                     ([vmess_sing] if vmess_sing else []) + \
                     ([vlessenc_sing] if vlessenc_sing else []) + \
                     ([anytls_sing] if anytls_sing else [])
    alternates = [p['name'] for p in (reality_proxy, vmess_proxy, vlessenc_proxy, anytls_proxy) if p]

    if alternates:
        # url-test：客户端定时探测多条链路，自动选延迟低的。
        # 比 select 好在「不需要用户手动切」——UDP 被 QoS 时会自己落到 TCP 通道。
        group_proxies = [name] + alternates
        group = {'name': 'PROXY', 'type': 'url-test', 'proxies': group_proxies,
                 'url': 'https://www.gstatic.com/generate_204',
                 'interval': 300, 'tolerance': 50}
    else:
        group = {'name': 'PROXY', 'type': 'select', 'proxies': [name, 'DIRECT']}

    clash = {'mixed-port': 7890, 'allow-lan': False, 'mode': 'rule',
             'proxies': proxies, 'proxy-groups': [group],
             'rules': ['MATCH,PROXY']}
    sing_doc = {'outbounds': sing_outbounds}
    if alternates:
        # sing-box 侧同样给一个 urltest outbound，让 SFA/SFI 自动择优。
        sing_doc['outbounds'].append({
            'type': 'urltest', 'tag': 'PROXY',
            'outbounds': [sing['tag']] + [o['tag'] for o in
                                          (reality_sing, vmess_sing, vlessenc_sing, anytls_sing) if o],
            'url': 'https://www.gstatic.com/generate_204',
            'interval': '5m', 'tolerance': 50,
        })
        sing_doc['route'] = {'final': 'PROXY'}
    return (uri, json.dumps(clash, ensure_ascii=False, indent=2),
            json.dumps(sing_doc, ensure_ascii=False, indent=2))


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
                Path(meta_path).write_text(json.dumps(m, ensure_ascii=False), encoding='utf-8')
    elif m.get('pin_sha256'):
        m['pin_sha256'] = ''
        Path(meta_path).write_text(json.dumps(m, ensure_ascii=False), encoding='utf-8')


def prepare(meta_path, port, node_api_key=None):
    root = Path(meta_path).parent
    m = json.loads(Path(meta_path).read_text(encoding='utf-8'))
    # 先修信任模型（cert_type/server_name/is_insecure/pin），再对齐 pin。
    # 顺序不能反：sync_pin 依赖 is_insecure 判断 pin 该不该留，而 is_insecure
    # 本身可能正漂移着（自签证书被换成正式证书后仍是 true）。
    sync_cert_trust(m, root, meta_path)
    sync_pin(m, root, meta_path)

    uri, clash, sing = artifacts(m)
    # ⚠️ 不能用 check=True（2026-10-09 修）：qrencode 缺失/失败会抛异常，
    # 而这里在 prepare() 的主流程上 —— 一个可选的二维码不该让**整个安装失败**。
    # 实测 qrencode 不在时会 FileNotFoundError，用户的安装跑到这一步直接崩。
    # 改成降级：二维码留空，页面会提示改用「节点直链 (URI)」导入。
    try:
        qr = subprocess.run(['qrencode', '-t', 'SVG', '-o', '-'], input=uri.encode(),
                            capture_output=True, timeout=20)
        qr_svg = qr.stdout if qr.returncode == 0 else b''
    except Exception:
        qr_svg = b''
    user, password, token = secrets.token_hex(8), secrets.token_urlsafe(32), secrets.token_hex(32)
    host = m['public_ip'] if m['is_insecure'] else m['server_name']
    # 初始化时把订阅端口**解析并写回** client_meta.json（自愈）：
    # 历史机器上这个键可能缺失或是错的，写回真实值后，
    # 后续所有读取路径（含用户专属页）都不会再落到伪造的 8443 上。
    sub_port, sub_port_src = resolve_subscription_port(m)
    if m.get('subscription_port') != sub_port:
        m['subscription_port'] = sub_port
        Path(meta_path).write_text(json.dumps(m, ensure_ascii=False, indent=2), encoding='utf-8')
        print(f'[portal] 订阅端口已自愈为 {sub_port}（来源: {sub_port_src}）', file=sys.stderr)
    base = f"https://{host}:{sub_port}/{token}/"
    subscription = f"https://{user}:{password}@{host}:{sub_port}/{token}/clash.yaml"
    session_secret = secrets.token_hex(32)
    api_key = node_api_key or secrets.token_hex(24)

    users = {
        MASTER_USER_ID: {
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
    page = page_html(m, uri, subscription, clash, sing, users=users, api_key=api_key, token=token, session_secret=session_secret,
                     username=user, password=password)
    auth = base64.b64encode(f'{user}:{password}'.encode())

    data = dict(port=int(port), token=token, auth_hash=hashlib.sha256(auth).hexdigest(),
                session_secret=session_secret, api_key=api_key, users=users,
                proxy_services=[], page=page, qr=qr_svg.decode('utf-8', 'replace'), clash=clash, sing=sing)
    for filename, value in [('portal.json', data), ('portal-access.json', portal_access_payload(base, user, password, api_key))]:
        path = root / filename
        # 用 atomic_write_private：write_text 先按 umask 创建再 chmod，
        # 中间有一段文件是 0644 的窗口，里面装着全部用户密码与 api_key；
        # chmod 失败时更是永久 0644（2026-10-29 修）。
        atomic_write_private(path, json.dumps(value, ensure_ascii=False).encode('utf-8'))


def qr_svg_for(uri):
    """生成二维码 SVG；失败返回 None（调用方据此保留旧图）。

    抽出来是为了能在**数据锁外**先算好：qrencode 是子进程，最长 20 秒，
    在锁内跑会阻塞 /auth（2026-10-29 修）。
    """
    try:
        qr = subprocess.run(['qrencode', '-t', 'SVG', '-o', '-'],
                            input=str(uri).encode(), capture_output=True, timeout=20)
        if qr.returncode == 0 and qr.stdout:
            return qr.stdout.decode('utf-8', 'replace')
    except Exception as exc:
        _log_ignored('qr_refresh', exc)  # 保留旧图，别把框清空
    return None


_QR_UNSET = object()


def sync_download_artifacts(data, uri, clash, sing, qr=_QR_UNSET):
    """把 data 里的 clash / sing / qr 与刚算出的 artifacts 对齐。

    🔴 为什么必须抽成函数（2026-10-09）：
    `clash` / `sing` / `qr` 三个键是**用户直接下载的东西** ——
    「下载配置」按钮、二维码都读它们。它们原先只在 prepare() 里被赋值，
    于是 refresh() / regenerate_page() 重新算出的 clash/sing 只喂给了 page_html
    就被丢掉：页面文本框里是新 sni，二维码和下载文件却还是换证**之前**的旧节点。
    用户扫了码立刻 CRYPTO_ERROR 0x150，而面板显示一切正常。

    qr 单独处理：qrencode 可能不存在，此时**保留旧二维码**而不是清空 ——
    空白框比旧图更难排查，失败原因另由调用方记录。
    """
    data['clash'] = clash
    data['sing'] = sing
    if qr is _QR_UNSET:
        qr = qr_svg_for(uri)   # 调用方没预先算，就在这里算（prepare 阶段）
    # qr 可能是调用方传进来的非字符串（旧调用点/测试）；下载端点会
    # `.encode()` 它，非字符串会让「下载配置」掐断连接。
    if isinstance(qr, str) and qr:
        data['qr'] = qr
    return data


def refresh(meta_path, config_path='/etc/hysteria/config.yaml'):
    root = Path(meta_path).parent
    m = json.loads(Path(meta_path).read_text(encoding='utf-8'))
    # 证书可能已被带外替换（Caddy 续期 / 手工换证），先修信任模型再对齐 pin。
    # 顺序有依赖：sync_pin 依赖 is_insecure 判断 pin 去留，而 is_insecure 本身
    # 可能正漂移着（自签被换成正式证书后仍是 true）。
    sync_cert_trust(m, root, meta_path, config_path=config_path)
    sync_pin(m, root, meta_path)

    path = root / 'portal.json'
    data = json.loads(path.read_text(encoding='utf-8'))
    # 凭据文件缺失/损坏时重建（保 token、API Key、用户），而不是让
    # 「刷新页面」「证书自愈」这类日常操作直接抛异常（2026-10-30 修）。
    access, _rebuilt = ensure_portal_access(root, m, data)
    uri, clash, sing = artifacts(m)
    host = m['public_ip'] if m['is_insecure'] else m['server_name']
    subscription = (f"https://{access['username']}:{access['password']}@"
                    f"{_host_for_url(host)}:{resolve_subscription_port(m)[0]}/{data['token']}/clash.yaml")
    
    # 空串 / null 也要重新生成：session_secret 是分享链接 k 的 HMAC 密钥，
    # 空串等于「任何人都能算出任意用户的 k」（`in` 判断只看键在不在）。
    if not isinstance(data.get('session_secret'), str) or not data['session_secret']:
        data['session_secret'] = secrets.token_hex(32)
    if 'api_key' not in data:
        data['api_key'] = access.get('api_key') or secrets.token_hex(24)
        access['api_key'] = data['api_key']
        # 与其他路径一致：portal-access.json 含用户名/密码/api_key，
        # write_text 会先按 umask 建出 0644 再补权限（2026-10-29 修）。
        atomic_write_private(root / 'portal-access.json',
                             json.dumps(access, ensure_ascii=False).encode('utf-8'))
    if 'users' not in data:
        data['users'] = {
            MASTER_USER_ID: {
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
    data['page'] = page_html(m, uri, subscription, clash, sing, users=data['users'], api_key=data['api_key'], token=data['token'], session_secret=data.get('session_secret', ''),
                             username=access.get('username', ''), password=access.get('password', ''))
    # 🔴 clash/sing/qr 必须一起更新（2026-10-09 修）：
    # 这三个键原先**只在 prepare() 里写过**，refresh() 重新算出的 clash/sing
    # 只喂给了 page_html 就被丢掉，于是「下载配置」按钮和二维码仍在发换证**之前**
    # 的旧节点。页面文本框显示的是新 sni、二维码却是旧的 —— 用户扫了码导入，
    # 立刻 CRYPTO_ERROR 0x150，而面板看起来一切正常。这正是 sync_cert_trust
    # 要消灭的失败模式，只是从下一层又冒了出来。
    sync_download_artifacts(data, uri, clash, sing)
    
    # 域名 / 订阅端口改过之后，交给控制台的门户地址也要跟上（token 与凭据不变）。
    access_url = f"https://{host}:{resolve_subscription_port(m)[0]}/{data['token']}/"
    if access.get('url') != access_url:
        access['url'] = access_url
        atomic_write_private(root / 'portal-access.json', json.dumps(access, ensure_ascii=False).encode('utf-8'))
    atomic_write_private(path, json.dumps(data, ensure_ascii=False).encode('utf-8'))



def ensure_portal_access(root, meta, data):
    """读取 portal-access.json；缺失时重建并返回 (access, rebuilt)。

    重建保留 token / API Key / 全部用户，只换一个新的控制台登录密码
    （旧密码明文无法从 auth_hash 还原）。adopt 与 refresh 共用，避免
    「凭据文件一丢，重装/刷新就崩或清空用户表」（2026-10-30 修）。
    """
    root = Path(root)
    path = root / 'portal-access.json'
    if path.exists():
        try:
            return json.loads(path.read_text(encoding='utf-8')), False
        except (OSError, ValueError):
            pass
    username = secrets.token_hex(8)
    password = secrets.token_urlsafe(18)
    auth = base64.b64encode(f'{username}:{password}'.encode())
    data['auth_hash'] = hashlib.sha256(auth).hexdigest()
    host = meta['public_ip'] if meta.get('is_insecure') else meta.get('server_name', 'localhost')
    sub_port, _src = resolve_subscription_port(meta)
    url = f"https://{_host_for_url(host)}:{sub_port}/{data.get('token', '')}/"
    access = portal_access_payload(url, username, password, data.get('api_key', ''))
    atomic_write_private(path, json.dumps(access, ensure_ascii=False).encode('utf-8'))
    print('[portal] portal-access.json 缺失或损坏，已重建访问凭据'
          '（token / API Key / 用户保留）', file=sys.stderr)
    return access, True

def adopt(meta_path, port, node_api_key=None):
    """「重新修改配置 / 重新安装」时沿用现有门户，而不是 prepare() 推倒重建。

    prepare() 会重新生成 token、门户账号密码、session_secret、API Key，并把用户表
    清成只剩机主 —— 对 Teyir 管理的节点，这等于控制台保存的凭据全部失效、
    控制台开的子账号与代理服务全部丢失。这里只更新本次确实变了的东西：
    门户本地端口、机主密码（= Hy2 认证密码）、以及调用方显式给出的新 API Key，
    其余数据原样保留，再交给 refresh() 按新的节点参数重建页面与订阅。
    """
    root = Path(meta_path).parent
    m = json.loads(Path(meta_path).read_text(encoding='utf-8'))
    path = root / 'portal.json'
    data = json.loads(path.read_text(encoding='utf-8'))
    access_path = root / 'portal-access.json'
    access, _rebuilt = ensure_portal_access(root, m, data)
    data['port'] = int(port)
    master = data.setdefault('users', {}).setdefault(MASTER_USER_ID, {
        'expires_at': 2085974400, 'ip_limit': 0, 'limit_bytes': 0, 'used_bytes': 0,
        'status': 'active', 'created_at': int(time.time()), 'note': 'Master Admin'})
    # auth_password 缺失时不要崩（旧备份 / 手写 meta 可能没有这个键）：
    # 保留旧的主密码，比让整个 adopt 失败要好。
    if isinstance(m.get('auth_password'), str) and m['auth_password']:
        master['password'] = m['auth_password']
    # 门户登录密码（= Hy2 主密码）变化后，必须让旧会话失效：
    # 会话 Cookie 只用 session_secret 签名，而它此前从不轮换，
    # 改完密码后旧浏览器还能继续用 30 天（2026-10-30 修）。
    # 用**访问凭据**算（门户登录校验的就是它），不能用 master 密码：
    # 两者如果漂移，用 master 密码算出来的 hash 会让真正的登录密码失效。
    _new_hash = hashlib.sha256(base64.b64encode(
        f"{access.get('username','')}:{access.get('password','')}".encode())).hexdigest()
    if data.get('auth_hash') != _new_hash:
        data['auth_hash'] = _new_hash
        data['session_secret'] = secrets.token_hex(32)
    if node_api_key:
        data['api_key'] = node_api_key
        access['api_key'] = node_api_key
        atomic_write_private(access_path, json.dumps(access, ensure_ascii=False).encode('utf-8'))
    atomic_write_private(path, json.dumps(data, ensure_ascii=False).encode('utf-8'))
    refresh(meta_path)


def selfheal(meta_path, config_path='/etc/hysteria/config.yaml'):
    """定时/事件触发的证书一致性自愈（供 systemd timer / path unit 调用）。

    为什么要独立成一个入口（而不是复用 refresh）：
      * refresh 会**无条件重写 portal.json**（重算 qr / page / token 派生），
        而续期自愈绝大多数时候无事发生 —— 每 30 分钟重写一次大 JSON 既浪费、
        也会让门户的 mtime 一直变（不利于排障时判断「谁改过门户」）。
      * 本入口只在**检测到漂移**时才动盘：先 sync_cert_trust 修 meta，
        若 meta 真变了，才顺带 refresh 一次让 portal.json 里的 page 跟上
        （page 里的 server_name / sni 是烘进 HTML 的，meta 变了必须重生成）。

    返回 True 表示发生了自愈（并已同步 portal.json），False 表示本来就一致。
    """
    root = Path(meta_path).parent
    meta_file = Path(meta_path)
    if not meta_file.exists():
        return False
    try:
        m = json.loads(meta_file.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return False

    before = dict(m)
    changed = sync_cert_trust(m, root, meta_path, config_path=config_path)
    # sync_cert_trust 只在漂移时写盘；pin 的修正也一并在此处理（保持与 refresh 一致）。
    pin_before = m.get('pin_sha256')
    sync_pin(m, root, meta_path)
    if m.get('pin_sha256') != pin_before:
        changed = True

    if changed:
        # 留痕：让「刚刚自动对齐过一次」在门户卡片上可见，而不是悄无声息。
        record_cert_heal(root, None, before, m)

    if changed:
        # meta 变了 → portal.json 里烘进去的 server_name/sni 已过期，重生成一次。
        try:
            refresh(meta_path, config_path=config_path)
            print('[portal] 证书自愈后已同步门户页面', file=sys.stderr)
        except Exception as e:
            print('[portal] 证书自愈已修 meta，但同步门户页面失败: %s' % str(e)[:160],
                  file=sys.stderr)
    return changed


def serve(path):
    portal_path = Path(path)
    data = json.loads(portal_path.read_text(encoding='utf-8'))
    # 必需字段缺失时给出明确中文错误再退出。旧行为是在后面的 data['port']
    # 处抛 KeyError，日志里只有一段 traceback —— 而门户是 Hysteria 的鉴权后端，
    # 它起不来等于全部用户连不上（2026-10-29 加）。
    _required = ('port', 'token', 'auth_hash', 'users')
    _missing = [k for k in _required if k not in data]
    if _missing:
        raise SystemExit('[portal] portal.json 缺少必需字段: %s。'
                         '请从备份恢复 portal.json 或重新执行安装。'
                         % ', '.join(_missing))
    # 与 prepare() 同一条规则：空串/None 不能当密钥用（.get 的默认值只在
    # 键缺失时生效，手工改坏或截断写入会留下空串）。
    # 🔴 两者都必须是字符串：hmac.new(...encode()) 在数字/None 上抛异常，
    # 而这一段在 serve() 顶部 —— 门户直接起不来（Hy2 鉴权后端随之全挂）。
    # auth_hash 损坏时不替机主编一个新密码（会静默改掉登录凭据），
    # 与缺失字段同样给明确错误并退出。
    if not isinstance(data.get('auth_hash'), str) or not data['auth_hash']:
        raise SystemExit('[portal] portal.json 的 auth_hash 已损坏。'
                         '请从备份恢复 portal.json 或重新执行安装。')
    session_secret = data.get('session_secret')
    if not isinstance(session_secret, str) or not session_secret:
        # 回落到 auth_hash 是旧行为；但**必须写回 data**，否则后续
        # regenerate_page() 仍从 data 读空值，用户分享链接的 k 变成空串，
        # 所有已发出去的链接都会失效。
        session_secret = data['auth_hash']
        data['session_secret'] = session_secret
    # api_key 与 session_secret 同理：空串会让 Bearer 校验退化成常量比较。
    # 重新生成后要**落盘**（portal.json 与 portal-access.json 两处），
    # 否则每次重启都换一个新 key，控制台永远对不上。
    if not isinstance(data.get('api_key'), str) or not data['api_key']:
        data['api_key'] = secrets.token_hex(24)
        try:
            atomic_write_private(portal_path,
                                 json.dumps(data, ensure_ascii=False).encode('utf-8'))
            _access_file = portal_path.parent / 'portal-access.json'
            if _access_file.exists():
                _access = json.loads(_access_file.read_text(encoding='utf-8'))
                _access['api_key'] = data['api_key']
                atomic_write_private(_access_file,
                                     json.dumps(_access, ensure_ascii=False).encode('utf-8'))
            print('[portal] api_key 缺失或无效，已重新生成并落盘', file=sys.stderr)
        except OSError as _e:
            print('[portal] api_key 重新生成后写盘失败: %s' % _e, file=sys.stderr)
    meta_path = portal_path.parent / 'client_meta.json'

    data_lock = threading.RLock()
    portal_upgrade_lock = threading.Lock()
    warp_apply_lock = threading.Lock()
    reality_apply_lock = threading.Lock()
    gost_operation_lock = threading.RLock()
    for key in ('warp_applying', 'egress_applying', '_egress_pending'):
        data.pop(key, None)  # pending worker threads cannot survive a process restart
    # core_upgrade 被手工改成 7 / "x" 时 `.get` 抛 AttributeError，门户直接起不来
    # —— 而门户同时是 Hy2 鉴权后端。非 dict 一律视为没有进行中的任务。
    _core_job = data.get('core_upgrade')
    if not isinstance(_core_job, dict):
        _core_job = None
    if _core_job is not None and _core_job.get('state') == 'running':
        data['core_upgrade'] = dict(_core_job, state='interrupted',
            error='门户重启打断更新任务，请核对当前核心版本后重试')
    elif _core_job is None and 'core_upgrade' in data:
        data.pop('core_upgrade', None)
    ip_tracker = {}
    IP_TIMEOUT_SECONDS = 180
    # 跨节点统一设备上限：控制台下发的 {uid: {ip: 过期时间}}，只在内存里（见 parse_ip_deny）。
    global_ip_deny = {}
    VALID_USER_ID_RE = USER_ID_RE
    # AmneziaWG 客户端名称：与 awgctl.sh 中的校验保持一致
    VALID_AWG_NAME_RE = re.compile(r'^[A-Za-z0-9_.\-]{1,32}$')
    # AmneziaWG 连接地址（endpoint）：域名或 IP 字面量，可带可选端口。
    # 🔴 必须禁掉换行/空白：endpoint 会被渲染进客户端 .conf 文件
    # （render_client_config 的 `Endpoint = ${endpoint}:${port}`），
    # 一个带换行的值能往配置里注入任意行（2026-10-28 修）。
    # 允许 IPv6 字面量（含冒号）与域名（含连字符/点/下划线）。
    VALID_AWG_ENDPOINT_RE = re.compile(
        r'^[A-Za-z0-9_.\-]+(?::[0-9]{1,5})?$|^\[[0-9A-Fa-f:.]+\](?::[0-9]{1,5})?$')

    # 实时速率计算滑动窗口数据结构: {uid: [(timestamp, total_bytes_tx, total_bytes_rx)]}
    speed_tracker = {}

    access_apply_lock = threading.RLock()
    # 上一次成功收回时的「被封禁用户集合」。过期用户不会从 data 里移走，
    # 不记这个的话 worker 每 5 秒都会重做一遍收回（查 /online、比对 xray）。
    last_enforced_blocked = None

    def blocked_user_ids():
        # users 容器损坏时按空表处理：这里每 5 秒被撤销 worker 调用一次，
        # 抛异常会让停用/到期用户永久保持在线。
        return frozenset(uid for uid, u in user_table(data).items()
                         if not user_access_allowed(u))

    def apply_access(force_ids=()):
        # access_apply_lock 串行化收回流程；data_lock 只在拍快照和写回结果时短暂持有。
        # 🔴 不能在持有 data_lock 时做 HTTP / systemctl：/auth 每个请求都要拿 data_lock，
        # 收回期间（最长 4s 查询 + 12s 重启）会卡住所有 Hy2 新连接的鉴权。
        # 快照过期也安全：账号变更后调用方会再调 apply_access，被 access_apply_lock
        # 排在本轮之后，用新快照重新生效。
        nonlocal last_enforced_blocked
        with access_apply_lock:
            with data_lock:
                pending=pending_revocations(data) | set(force_ids)
                snapshot=copy.deepcopy(data)
                blocked=blocked_user_ids()
            try:
                enforce_node_access(portal_path.parent,snapshot,pending)
            except Exception as exc:
                with data_lock:
                    data['_pending_revocations']=sorted(pending_revocations(data) | pending)
                    save_data()
                print('[expiry] access enforcement failed: '+type(exc).__name__,file=sys.stderr)
                return False
            with data_lock:
                # 收回期间新排进来的待撤销项要保留，只清掉本轮已确认的。
                remaining=pending_revocations(data) - pending
                if remaining:
                    data['_pending_revocations']=sorted(remaining)
                else:
                    data.pop('_pending_revocations',None)
                save_data()
            last_enforced_blocked=blocked
            return True
    def expiry_access_worker():
        while True:
            try:
                with data_lock:
                    needed=bool(pending_revocations(data)) or blocked_user_ids()!=(last_enforced_blocked or frozenset())
                if needed:apply_access()
            except Exception as exc:
                print('[expiry] worker retry: '+type(exc).__name__,file=sys.stderr)
            time.sleep(5)

    def save_data():
        with data_lock:
            # ⚠️ 必须显式 encoding='utf-8'（2026-10-03 实测）。
            # Path.write_text 不给 encoding 时跟随 locale：Linux 上是 UTF-8
            # 没事，但 Windows 上是 GBK —— 页面里含 `₂` 之类字符时
            # 直接 UnicodeEncodeError 把 HTTP handler 打死，客户端看到的是
            # "Remote end closed connection without response"，
            # 排查时完全看不出是编码问题。
            payload = json.dumps(data, ensure_ascii=False).encode('utf-8')
            atomic_write_private(portal_path, payload)

    # ---- 整机流量与超额停用（2026-10-14，供主控制台的节点流量限额使用）----
    #
    # 计量口径：只取**默认路由所在的网卡**（/proc/net/route 与 ipv6_route 中
    # 目的地全零的那张），因为 VPS 商家按物理出口网卡计费。把所有网卡加起来
    # 会把 WARP / AWG 等隧道接口上的流量再算一遍（它们最终也走物理网卡）。
    # 计数器是开机以来的累计值；控制台用 boot_id 识别重启造成的归零。
    _TUNNEL_IFACE_PREFIXES = ('lo', 'wg', 'warp', 'awg', 'tun', 'tap', 'docker', 'veth', 'br-', 'virbr')

    def node_default_ifaces():
        ifaces = set()
        try:
            with open('/proc/net/route', encoding='ascii') as fh:
                next(fh, None)
                for line in fh:
                    parts = line.split()
                    if len(parts) > 2 and parts[1] == '00000000':
                        ifaces.add(parts[0])
        except OSError:
            pass
        try:
            with open('/proc/net/ipv6_route', encoding='ascii') as fh:
                for line in fh:
                    parts = line.split()
                    if len(parts) >= 10 and parts[0] == '0' * 32 and parts[1] == '00':
                        ifaces.add(parts[9])
        except OSError:
            pass
        physical = {i for i in ifaces if not i.startswith(_TUNNEL_IFACE_PREFIXES)}
        return sorted(physical or ifaces)

    def node_traffic_counters():
        wanted = set(node_default_ifaces())
        rx = tx = 0
        seen = []
        with open('/proc/net/dev', encoding='ascii') as fh:
            for line in fh:
                if ':' not in line:
                    continue
                name, rest = line.split(':', 1)
                name = name.strip()
                if name not in wanted:
                    continue
                cols = rest.split()
                rx += int(cols[0])
                tx += int(cols[8])
                seen.append(name)
        try:
            boot_id = Path('/proc/sys/kernel/random/boot_id').read_text(encoding='ascii').strip()
        except OSError:
            boot_id = ''
        return {'rx_bytes': rx, 'tx_bytes': tx, 'interfaces': seen, 'boot_id': boot_id}

    # 超额停用只停**对外提供代理**的服务，portal 自己不停 —— 否则控制台
    # 下个周期就没法远程恢复。停之前记下哪些本来是开着的，恢复时只启动它们，
    # 不会把机主有意关掉的服务顺手拉起来。
    TRAFFIC_SUSPEND_UNITS = ('hysteria-server', 'xray', 'gost', 'amneziawg-server', ANYTLS_SERVICE)

    def _unit_active(unit):
        try:
            return subprocess.run(['systemctl', 'is-active', unit], capture_output=True,
                                  text=True, timeout=5).stdout.strip() == 'active'
        except Exception:
            return False

    traffic_suspend_lock = threading.Lock()

    def unit_suspended(unit):
        """该服务是否因整机流量超额被停用中 —— 停用期间任何流程都不能把它拉起来。

        状态损坏时按「未停用」处理：这里只读一次快照，抛异常会让
        「停用期间不得重启」这项保护变成 HTTP 500，反而更危险。
        """
        with data_lock:
            state = suspend_state(data)
        return state.get('suspended') is True and unit in state['units']

    global _unit_suspended
    _unit_suspended = unit_suspended

    def set_traffic_suspension(suspend):
        with traffic_suspend_lock:
            return _set_traffic_suspension(suspend)

    def _set_traffic_suspension(suspend):
        with data_lock:
            # 状态被写成 7 / 字符串时 `dict(...)` 抛异常，超额停用直接 500，
            # 一台服务都没停。这里统一走 suspend_state 的清洗规则。
            state = suspend_state(data)
        results = {}
        if suspend:
            units = state.get('units') if state.get('suspended') else None
            if units is None:
                units = [u for u in TRAFFIC_SUSPEND_UNITS if _unit_active(u)]
            else:
                # 已处于停用状态时也要复核一遍：停用期间有人手动
                # systemctl start 起来的服务，必须重新停掉，否则整机超额
                # 状态形同虚设（2026-10-29 修）。
                for _u in TRAFFIC_SUSPEND_UNITS:
                    if _u not in units and _unit_active(_u):
                        units.append(_u)
            for u in units:
                r = subprocess.run(['systemctl', 'stop', u], capture_output=True, timeout=20)
                results[u] = r.returncode == 0
            new_state = {'suspended': True, 'units': units,
                         'since': state.get('since') or int(time.time())}
        else:
            for u in state.get('units') or []:
                subprocess.run(['systemctl', 'reset-failed', u], capture_output=True, timeout=5)
                r = subprocess.run(['systemctl', 'start', u], capture_output=True, timeout=20)
                results[u] = r.returncode == 0
            # 没启动成功的服务必须留在停用记录里：原来一律清空，控制台下一轮重试
            # 时已无服务可启、直接回成功，该服务就一直停着而控制台以为已恢复。
            remaining = [u for u, ok in results.items() if not ok]
            if remaining:
                new_state = {'suspended': True, 'units': remaining,
                             'since': state.get('since') or int(time.time())}
            else:
                new_state = {'suspended': False}
        with data_lock:
            data['traffic_suspend'] = new_state
        save_data()
        return new_state, results

    # 计量每 5 秒对每个来源采样一次。若每次都整份落盘（portal.json 含整页 HTML，
    # 几百 KB 起步），一天要写好几 GB，且写盘期间一直占着 /auth 也要的 data_lock。
    # 这里限流到每 METER_SAVE_INTERVAL 秒一次；内存里的计数始终是最新的，
    # 其他任何 save_data() 也会顺带把它写下去。进程意外退出最多丢这一段间隔的
    # 基线，下次采样按单调计数器补算差值，不会少计。
    METER_SAVE_INTERVAL = 60
    _meter_last_save = [0.0]

    def save_meter_data():
        now = time.monotonic()
        if now - _meter_last_save[0] < METER_SAVE_INTERVAL:
            return
        save_data()
        _meter_last_save[0] = now

        # 每个来源使用实际采样间隔计算速率，不能把 5 秒增量除以固定 3 秒。
    SPEED_WINDOW_SECONDS = 15

    def _meter_speed_sample(uid, tx, rx, elapsed, source):
        if elapsed <= 0:
            return
        with data_lock:
            speed_tracker.setdefault(uid, {})[source] = (
                time.monotonic(), tx / elapsed, rx / elapsed)

    # 计量模块不改变 UUID/密码/状态；旧记账值另存，used_bytes 同步真实累计。
    usage_meter = None
    try:
        _usage_runtime_path = Path(__file__).parent / 'usage-meter-runtime-20261007-v1.py'
        _usage_spec = importlib.util.spec_from_file_location('portal_usage_runtime', _usage_runtime_path)
        _usage_runtime = importlib.util.module_from_spec(_usage_spec)
        _usage_spec.loader.exec_module(_usage_runtime)
        if getattr(_usage_runtime, 'ACCOUNTING_REVISION', None) != '2026-10-12-real-usage-v2':
            raise RuntimeError('usage_meter_runtime_revision_mismatch')
        usage_meter = _usage_runtime.from_file(data, data_lock, save_meter_data,
                                              portal_path.parent / 'usage-meter-config.json',
                                              on_speed=_meter_speed_sample)
    except Exception as _usage_exc:
        print('[portal] 真实计量未初始化: ' + type(_usage_exc).__name__, file=sys.stderr)

    def live_online_ips(uid):
        """计量模块采到的该用户**当前仍在连**的 IP（核心 /online/ips）；拿不到返回空集。

        /auth 只在建连时记 IP、180 秒后遗忘，而 Hy2 的 QUIC 连接会一直保持；
        只靠它的话，第一台设备连上 3 分钟后第二台就能绕过同时在线 IP 限制。
        """
        if usage_meter is None:
            return set()
        snapshot = getattr(usage_meter, 'live_snapshot', None)
        sampled_at = getattr(usage_meter, 'live_sampled_at', 0)
        if not snapshot or time.time() - sampled_at >= 45:
            return set()
        row = (snapshot.get('users') or {}).get(uid) or {}
        if not row.get('hysteria_ok'):
            return set()
        return {str(item.get('ip')) for item in row.get('ips') or [] if item.get('ip')}

    # ---- Reality 设备上限（2026-10-23）----
    # Hy2 的上限在 /auth 里拦；Reality 不经过 /auth，由这个循环每轮读 Xray 在线 IP、
    # 与 Hy2 合并计数，超出的 IP 下发黑洞路由规则。读不到在线数据时一律不拦人。
    reality_iplimit_state = {}
    reality_ip_snapshot = {'ips': {}, 'at': 0.0}

    def reality_live_ips(uid):
        """本循环最近一轮读到的该用户 Reality **放行中**的 IP，供 /auth 合并计数。"""
        with data_lock:
            if time.time() - reality_ip_snapshot['at'] >= 30:
                return set()
            row = reality_iplimit_state.get(uid) or {}
            return set(row.get('admitted') or ())

    def reality_iplimit_worker():
        cfg_path = portal_path.parent / 'usage-meter-config.json'
        xray_path = portal_path.parent / 'xray.json'
        stats_path = Path(__file__).parent / 'usage-meter-xray-config-20261007-v1.py'
        ready = False
        enable_retry_at = 0.0
        last_error = ''
        binary = address = ''
        while True:
            try:
                rcfg = (json.loads(cfg_path.read_text(encoding='utf-8')) if cfg_path.exists() else {}).get('reality') or {}
                binary, address = rcfg.get('binary', ''), rcfg.get('address', '')
                if not (binary and address and xray_path.exists() and Path(binary).is_file()):
                    time.sleep(30); continue
                # 模块级代码看不到 main() 内的嵌套函数，必须用 _unit_suspended。
                if _unit_suspended('xray') or _systemd_state('xray') != 'active':
                    time.sleep(10); continue
                if not ready:
                    # 开启路由接口要重启一次 Xray；失败后 10 分钟内不再尝试，免得反复重启。
                    if time.time() < enable_retry_at:
                        time.sleep(30); continue
                    enable_retry_at = time.time() + 600
                    spec = importlib.util.spec_from_file_location('portal_iplimit_cfg', stats_path)
                    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
                    # 与到期收回（access_apply_lock）、Reality 重生成（reality_apply_lock）串行，
                    # 否则两边同时改 xray.json，会有一方以「并发修改」失败一轮（jp 上线时踩过）。
                    with access_apply_lock, reality_apply_lock:
                        outcome = mod.enable_iplimit_routing(str(xray_path), binary, address)
                    if outcome.get('changed'):
                        print('[iplimit] 已为 Reality 开启设备上限路由接口，备份: %s' % outcome.get('backup'),
                              file=sys.stderr)
                    ready = True
                    enable_retry_at = 0.0
                with data_lock:
                    limits = active_ip_limits(user_table(data))
                    now_ts = time.time()
                    hy2 = {uid: {ip for ip, t in ip_tracker.get(uid, {}).items() if now_ts - t < IP_TIMEOUT_SECONDS}
                           for uid in limits}
                for uid in limits:
                    hy2[uid] |= live_online_ips(uid)
                reality = read_reality_online_ips(binary, address, limits)
                with data_lock:
                    blocked = plan_reality_iplimit(limits, reality, hy2, reality_iplimit_state, time.time())
                    # 控制台下发的跨节点超额 IP 一并拦截（与本机名额判断取并集）。
                    for _uid in list(global_ip_deny):
                        _ips = active_ip_deny(global_ip_deny, _uid, time.time())
                        if _ips:
                            blocked.setdefault(_uid, set()).update(_ips)
                    reality_ip_snapshot.update(ips=reality, at=time.time())
                added, removed = apply_reality_iplimit(binary, address, reality_iplimit_rules(blocked))
                if added or removed:
                    print('[iplimit] Reality 拦截规则更新: +%d -%d，当前拦截 %d 个用户'
                          % (added, removed, len(blocked)), file=sys.stderr)
                last_error = ''
            except Exception as exc:
                # 读不到在线数据就不知道谁超限：放行（撤掉全部拦截），下一轮重试。
                with data_lock:
                    reality_ip_snapshot.update(ips={}, at=0.0)
                    reality_iplimit_state.clear()
                msg = type(exc).__name__ + ': ' + str(exc)[:120]
                if msg != last_error:
                    print('[iplimit] Reality 设备上限本轮跳过（已放行）: ' + msg, file=sys.stderr)
                    last_error = msg
                if ready:
                    try:
                        apply_reality_iplimit(binary, address, {})
                    except Exception:
                        pass
                # 下一轮重新核对路由接口还在（xray.json 可能被别处重写）；已就绪时不会重启 Xray。
                ready = False
            time.sleep(5)

    def usage_summary(uid):
        if usage_meter is not None:
            return usage_meter.summary(uid)
        return {'measured_bytes': None, 'measurement_ok': False,
                'measurement_scope': 'unavailable', 'measurement_sources': {},
                'measurement_started_at': None, 'measurement_gaps': [],
                'legacy_auth_value': legacy_used_bytes(data, uid)}

    def usage_list_summary(uid):
        """users/list 用的 usage_summary：measurement_gaps 不再逐用户复制（2026-10-28 修）。

        gaps 是**整台节点**的计量缺口（最多 100 条），每个用户都一样。
        原来每个用户各带一份完整拷贝：53 个用户的日本-东京 users/list 实测 628 KB，
        超过控制台 256 KiB 读取上限被截断，对账/同步/开户全部失败。
        现在每个用户只带条数，完整列表由调用方在信封里放一次（键名不变，
        新版控制台读不到用户里的就用信封里的；单个用户的接口仍带完整列表）。
        返回 (不含 gaps/sources 的 summary, gaps, sources)。
        """
        summary = usage_summary(uid)
        gaps = summary.pop('measurement_gaps', None) or []
        # measurement_sources 同样是**节点级**的（每个来源的健康快照），
        # 每个用户带一份会让几百用户时响应再次逼近 256 KiB 上限
        # （2026-10-30 修，与 gaps 同源问题）。信封里放一次，用户级留空。
        sources = summary.pop('measurement_sources', None) or {}
        summary['measurement_gap_count'] = len(gaps)
        return summary, gaps, sources

    def usage_hot_summary(uid):
        """usage_summary 的热路径版（2026-10-28 修）。

        /traffic-speed 每 2 秒轮询 × 全部用户，前端只消费 5 个标量字段；
        走完整 summary() 会给每个用户 deepcopy gaps/sources/online，
        白耗 CPU 且长时间占住 data_lock（/auth 会被卡）。
        优先用计量模块的 hot_summary；拿不到（未初始化）退回最小值。
        """
        if usage_meter is not None:
            hot = getattr(usage_meter, 'hot_summary', None)
            if hot is not None:
                return hot(uid)
        return {'measured_bytes': None, 'measurement_ok': False,
                'measurement_started_at': None,
                'measurement_scope': 'unavailable'}

    def write_gost_config():
        """根据 proxy_services 动态生成 gost.yml 配置并触发热重载。"""
        gost_cfg_path = portal_path.parent / 'gost.yml'
        services = []
        with data_lock:
            # 单条代理记录被改坏（null / 字符串 / 端口非数字）时跳过它：
            # 旧写法在这里抛异常，reload_gost 一律返回 False，
            # 「新增代理」永久失败，而错误信息只说「配置未成功应用」。
            for idx, svc in enumerate(proxy_services(data)):
                if not isinstance(svc, dict):
                    continue
                ptype = svc.get('type') if isinstance(svc.get('type'), str) else 'socks5'
                raw_port = svc.get('port')
                if isinstance(raw_port, bool):
                    continue
                try:
                    port = int(raw_port or 0)
                except (TypeError, ValueError, OverflowError):
                    continue
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
                    cert_file, key_file = gost_tls_paths(portal_path.parent)
                    entry['listener'] = {'type': 'tls', 'tls': {
                        'certFile': cert_file, 'keyFile': key_file}}
                services.append(entry)

        cfg = {'services': services}
        # gost.yml 里有代理账号密码，与 portal.json 同样必须一创建就是 0600。
        atomic_write_private(gost_cfg_path, json.dumps(cfg, ensure_ascii=False, indent=2).encode('utf-8'))

    def gost_ports_ready():
        with data_lock:
            # 容错：数据里某条记录的 port 被改坏时，跳过它而不是让整个
            # reload 因 ValueError 失败（2026-10-29 修）。
            ports = []
            for item in proxy_services(data):
                try:
                    ports.append(int(item['port']))
                except (KeyError, TypeError, ValueError):
                    continue
        if not ports:
            return True
        # 读监听表而不是逐个 create_connection（2026-10-29 改）：
        # 每次重载都往 gost 发一次真实连接，会把它记成鉴权失败请求；
        # 端口恰好处于 TIME_WAIT 时还会误判「未生效」并触发回滚 + 二次 reload。
        listening, probed = _listening_ports_detail()
        if not probed:
            return True      # 探测不了就不阻断，交给服务状态判断
        return all(port in listening for port in ports)
        return True

    def reload_gost():
        """Return real application success, including expected listener readiness."""
        if not Path('/usr/local/bin/gost').exists():
            return False
        with gost_operation_lock:
            try:
                ensure_gost_unit()
                write_gost_config()
                # 模块级代码看不到 main() 内的嵌套函数，必须用 _unit_suspended。
                if _unit_suspended('gost'):
                    # 停用期间只更新配置；控制台恢复节点时 gost 会带着它启动。
                    # 但仍然要确认写出来的是合法 JSON：否则恢复整机时 gost 起不来，
                    # 而此前每次操作都报告成功（2026-10-29 修）。
                    try:
                        json.loads((portal_path.parent / 'gost.yml').read_text(encoding='utf-8'))
                    except (OSError, ValueError):
                        return False
                    return True
                if gost_status():
                    r = subprocess.run(['systemctl', 'reload', 'gost'], capture_output=True, timeout=5)
                    if r.returncode == 0:
                        for _ in range(10):
                            if gost_status() and gost_ports_ready():
                                return True
                            time.sleep(0.2)
                r = subprocess.run(['systemctl', 'restart', 'gost'], capture_output=True, timeout=12)
                if r.returncode != 0:
                    return False
                for _ in range(15):
                    if gost_status() and gost_ports_ready():
                        return True
                    time.sleep(0.2)
            except Exception:
                return False
        return False


    # 远端根目录文件 sha 的短缓存。
    # 必要性：版本检查会在每次页面加载时触发，而 GitHub 未认证 API 限 60 次/小时/IP。
    # 用「目录列表」接口一次拿回所有文件的 sha（而不是逐文件取），再叠 5 分钟缓存，
    # 把每次检查的 API 调用压到 1 次。
    _ver_cache = {'t': 0.0, 'data': None}
    _core_ver_cache = {'t': 0.0, 'tag': ''}

    def _remote_root_shas():
        now = time.time()
        if _ver_cache['data'] is not None and now - _ver_cache['t'] < 300:
            return _ver_cache['data']
        try:
            req = urllib.request.Request(
                'https://api.github.com/repos/' + AWG_REPO + '/contents/?ref=main',
                headers={'User-Agent': 'Mozilla/5.0',
                         'Accept': 'application/vnd.github+json'})
            with urllib.request.urlopen(req, timeout=8) as resp:
                items = json.loads(resp.read().decode('utf-8'))
            # GitHub 在限流/出错时返回的是对象（{"message": ...}），不是列表；
            # 旧写法 `for it in items` 直接抛 TypeError，虽然被下面 except 兜住，
            # 但每次都白跑一遍请求且永远拿不到缓存。
            shas = ({it['name']: it.get('sha', '') for it in items
                     if isinstance(it, dict) and it.get('name')}
                    if isinstance(items, list) else {})
            if shas:
                _ver_cache['t'] = now
                _ver_cache['data'] = shas
                return shas
        except Exception as exc:
            _log_ignored('version_check', exc)
        return None

    def _version_triple(local_path, remote_name):
        """返回 (本地短sha, 远端短sha, 是否有更新)。

        用 git blob sha 比对而不是「日期常量」或「提交 sha」：
          - 面板文件本身不带 git 元数据，拿不到本地提交 sha；
          - blob sha 只取决于文件内容，远端 sha 能从 API 的 JSON 直接取到。
        远端取不到时返回 has_update=False —— 宁可漏报也不误报"有新版本"。
        """
        loc = _local_blob_sha(local_path)
        if not loc:
            return ('未安装', '', False)
        shas = _remote_root_shas() or {}
        rem = shas.get(remote_name, '')
        if not rem:
            return (loc[:7], '', False)
        return (loc[:7], rem[:7], loc != rem)

    def gost_status():
        """检测 gost 服务运行状态。"""
        try:
            out = subprocess.run(['systemctl', 'is-active', 'gost'], capture_output=True, text=True, timeout=3).stdout.strip()
            return out == 'active'
        except Exception:
            return False

    def write_gost_selfcheck():
        """把启动自检脚本写到 GOST_SELFCHECK_PATH (unit 的 ExecStartPost 调用).

        install.sh 的 install_gost() 会写同一份内容; 这里再写一次是为了覆盖
        "服务器上已装过旧版 gost、unit 却没有自检" 的情况。
        """
        try:
            GOST_SELFCHECK_PATH.parent.mkdir(parents=True, exist_ok=True)
            GOST_SELFCHECK_PATH.write_text(GOST_SELFCHECK_SCRIPT, encoding='utf-8')
            os.chmod(str(GOST_SELFCHECK_PATH), 0o755)
        except OSError:
            pass

    def ensure_gost_unit():
        """幂等地把 gost.service 补齐成当前标准内容（缺 ExecReload / -R / 自检就重写）.

        为什么必须做：老机器上的 unit 是历史版本生成的（没有 ExecReload、
        没有 -R、没有自检）。只在"一键安装 gost"时覆写 unit 是不够的 ——
        老用户不重装就永远拿不到修复，而 reload_gost() 又依赖 unit 里的
        ExecReload 才能平滑重载。所以每次改配置前先自愈一次。

        判据用**逐项包含**而不是整体比较：comment 行的措辞变化不该触发重写，
        真正影响行为的三项（ExecReload / -R / ExecStartPost）才是关键。
        只在确实缺失时才写盘 + daemon-reload，避免无谓重启。
        """
        unit_path = Path('/etc/systemd/system/gost.service')
        try:
            current = unit_path.read_text(encoding='utf-8') if unit_path.exists() else ''
        except OSError:
            return
        needed = ('ExecReload=/bin/kill -HUP $MAINPID',
                  '-R 30s',
                  'ExecStartPost=' + GOST_SELFCHECK_PATH.as_posix())
        if all(s in current for s in needed):
            return                                   # 已是最新, 不做任何事
        try:
            write_gost_selfcheck()
            unit_path.write_text(GOST_UNIT_CONTENT, encoding='utf-8')
            subprocess.run(['systemctl', 'daemon-reload'], capture_output=True, timeout=5)
        except Exception as exc:
            _log_ignored('gost_unit_install', exc)

    # ------------------------------------------------------------------
    # AmneziaWG (AWG) 支持
    #
    # 设计取舍：门户不重新实现 AWG 的配置生成逻辑，而是调用 shell 侧的
    # /usr/local/bin/hy2-awgctl（由 install.sh 安装）。这样命令行菜单与 Web
    # 门户共用同一套实现，不会出现两份逻辑漂移 —— 考虑到 S1-S4/H1-H4 必须
    # 两端逐字节一致，重复实现的风险太高。
    # ------------------------------------------------------------------
    AWG_CTL = '/usr/local/bin/hy2-awgctl'
    AWG_DIR_PATH = Path('/etc/amnezia/amneziawg')
    AWG_META_PATH = AWG_DIR_PATH / 'awg_meta.json'
    AWG_PEERS_PATH = AWG_DIR_PATH / 'awg_peers.json'
    AWG_CONF_PATH = AWG_DIR_PATH / 'awg0.conf'
    AWG_GO_PATH = Path('/usr/local/bin/amneziawg-go')
    AWG_SVC_NAME = 'amneziawg-server'
    # 当前运行的面板文件本身（用于与远端比对版本）
    PORTAL_SELF = Path(__file__).resolve()

    # ------------------------------------------------------------------
    # gost 入站代理的 systemd 单元
    #
    # ⚠️ 这份内容必须与 install.sh 里 install_gost() 写出的**完全一致**。
    # 曾经两处不一致（install.sh 有 ExecReload、portal.py 没有），后果是:
    # 门户走 reload_gost() 调 `systemctl reload gost` 时, 因为 unit 缺 ExecReload
    # 而 CanReload=no, systemctl 返回码 3 且"什么都没做" —— 新代理端口永远不监听.
    # tests/test_portal_gost_reload.py 有断言钉死两处一致, 改一处必须同步另一处.
    #
    # 三个要点:
    #   1) `ExecReload=/bin/kill -HUP $MAINPID` —— gost v3 支持 SIGHUP 重载配置
    #      (已实测: 改 gost.yml 后 kill -HUP, 端口 42197->42198 成功切换).
    #   2) `-R 30s` —— gost 官方的周期自动重载. 这是**兜底**: 即使门户侧的
    #      reload/restart 因任何原因失败, 配置也会在 30 秒内自动生效.
    #      实测 v3.3.0 有效 (改配置后 2 秒内完成重载).
    #   3) `ExecStartPost` 轮询 ss 确认端口已监听 —— 把"active 但无监听"的
    #      静默故障变成**启动失败**, 从而触发 systemd 重试而不是假装健康.
    # ------------------------------------------------------------------
    # 启动自检脚本: 从 gost.yml 解析出所有监听端口, 逐个确认已监听.
    # 无代理配置 (services 为空) 时直接放行 —— 那是合法状态.
    # 目的: 把"systemd 说 active、实际没监听"的静默故障转成**启动失败**, 交给 systemd 重试.
    #
    # 写成独立脚本文件 (/usr/local/lib/hy2-gost-selfcheck) 而不是塞进 unit 的
    # ExecStartPost 一行里, 是因为后者要嵌套四层引号 (systemd -> sh -c -> python3 -c
    # -> JSON), 极难读也极易写错. 独立文件把复杂度降到一层.
    GOST_SELFCHECK_PATH = Path('/usr/local/lib/hy2-gost-selfcheck')
    GOST_SELFCHECK_SCRIPT = '''#!/usr/bin/env python3
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
'''

    GOST_UNIT_CONTENT = (
        '[Unit]\n'
        'Description=GOST Proxy Service (SOCKS5/HTTP/HTTPS inbound)\n'
        'After=network-online.target\n'
        'Wants=network-online.target\n'
        '\n'
        '[Service]\n'
        'Type=simple\n'
        'ExecStart=/usr/local/bin/gost -C /etc/hysteria/gost.yml -R 30s\n'
        '# 平滑重载: gost v3 收到 SIGHUP 会重新读取 -C 指定的配置文件\n'
        'ExecReload=/bin/kill -HUP $MAINPID\n'
        'Restart=always\n'
        'RestartSec=3\n'
        'LimitNOFILE=65535\n'
        '# 启动自检: 确认 gost.yml 里声明的端口都真的监听了, 否则视为启动失败\n'
        'ExecStartPost=' + GOST_SELFCHECK_PATH.as_posix() + '\n'
        '\n'
        '[Install]\n'
        'WantedBy=multi-user.target\n'
    )

    def awg_read_json(path, default):
        try:
            if path.exists():
                return json.loads(path.read_text(encoding='utf-8'))
        except Exception as exc:
            _log_ignored('read_json', exc)
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

    def _fetch_repo_file(filename, marker=None, min_size=1024, ref="main", expect_blob=None):
        """从多个源依次尝试获取仓库里的某个文件，返回内容字节；全失败返回 None。

        ⚠️ 不能只用 raw.githubusercontent.com：实测 push 后数分钟仍返回旧内容，
        而且【不把查询串算进缓存键】—— 加 ?cb=<时间戳> 也没用。
        实测同一时刻：api.github.com（Accept: vnd.github.raw）与 jsDelivr 都是最新，
        raw 滞后。顺序：API（权威）→ jsDelivr（无限速）→ raw（兜底）。
        与 install.sh 中 awg_fetch_ctl 的策略保持一致。

        expect_blob 不为 None 时，每个源取回的内容都必须与它（git blob sha）一致：
        jsDelivr / raw 可能返回与所 pin commit 不符的内容（缓存污染或 CDN 侧篡改），
        只比对 marker 挡不住 —— 只要内容里含 marker 且语法合法就会被写盘。
        """
        if ref != "main" and not re.fullmatch(r"[0-9a-f]{40}", ref):
            raise ValueError("invalid immutable ref")
        if expect_blob is not None and not re.fullmatch(r"[0-9a-f]{40}", expect_blob):
            raise ValueError("invalid expected blob sha")
        sources = [
            ('https://api.github.com/repos/' + AWG_REPO + '/contents/' + filename + '?ref=' + ref,
             {'User-Agent': 'Mozilla/5.0', 'Accept': 'application/vnd.github.raw'}),
            ('https://cdn.jsdelivr.net/gh/' + AWG_REPO + '@' + ref + '/' + filename,
             {'User-Agent': 'Mozilla/5.0'}),
            ('https://raw.githubusercontent.com/' + AWG_REPO + '/' + ref + '/' + filename,
             {'User-Agent': 'Mozilla/5.0'}),
        ]
        for url, headers in sources:
            try:
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=30) as resp:
                    content = resp.read()
                # 体积 + 关键字双重校验，挡住错误页
                if len(content) > min_size and (marker is None or marker in content):
                    if expect_blob is not None and _git_blob_sha(content) != expect_blob:
                        continue          # 与所 pin commit 的内容不符，换下一个源
                    return content
            except Exception:
                continue
        return None

    def _git_blob_sha(data):
        """按 git 的算法算 blob sha：sha1("blob <len>\\0" + content)。

        这样本地文件可以直接与 GitHub contents API 返回的 sha 比对，
        既权威又不需要下载远端内容（API 只回一个 JSON）。
        """
        return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\x00' + data).hexdigest()

    def _local_blob_sha(path):
        try:
            return _git_blob_sha(Path(path).read_bytes())
        except Exception:
            return None

    def _remote_blob_sha(filename, marker=None, ref="main"):
        """取远端文件的 git blob sha（**只**走 contents API 的 JSON）。

        🔴 2026-10-27：旧实现在 API 失败时会退回「下载内容后自己算 blob sha」——
        那样"预期身份"就来自待校验的内容本身，比对恒成立，等于没有身份校验。
        现在 API 拿不到就返回 None，调用方必须 fail-closed（放弃更新）。
        marker 参数仅为兼容既有调用点保留，此处不再用于下载内容。
        """
        try:
            url = ('https://api.github.com/repos/' + AWG_REPO + '/contents/'
                   + filename + '?ref=' + ref)
            req = urllib.request.Request(url, headers={
                'User-Agent': 'Mozilla/5.0',
                'Accept': 'application/vnd.github+json',
            })
            with urllib.request.urlopen(req, timeout=8) as resp:
                info = json.loads(resp.read().decode('utf-8'))
            sha = info.get('sha', '') if isinstance(info, dict) else ''
            if isinstance(sha, str) and re.fullmatch(r'[0-9a-f]{40}', sha):
                return sha
        except Exception as exc:
            _log_ignored('awg_remote_sha', exc)
        return None

    def ensure_awgctl(force=False):
        """确保 hy2-awgctl 可用；缺失时从主仓库拉取（与 install.sh 的策略一致）。

        force=True 时即使已存在也重新获取，且仅在内容变化时才替换 —— 否则已经装过
        AWG 的机器会把引擎永久冻结在首次安装的版本上。

        🔴 2026-10-27：先把 main 固定成 40 位 commit，再用该 commit 的 blob 身份
        比对取回内容。旧实现直接取 `?ref=main` 且只 grep 一个字符串标记，
        main 被推入恶意提交就会把 hy2-awgctl 刷成攻击者版本并以 root 执行。
        """
        if not force and Path(AWG_CTL).exists():
            return True
        try:
            ref = resolve_update_ref('main')
            expected = _remote_blob_sha('awgctl.sh', marker=b'hy2-awgctl', ref=ref)
            if not expected:
                return False
            content = _fetch_repo_file('awgctl.sh', marker=b'hy2-awgctl', min_size=2048,
                                       ref=ref, expect_blob=expected)
            if content is None:
                return False
            # 内容一致就直接返回，避免无谓改写
            if force and Path(AWG_CTL).exists():
                try:
                    if Path(AWG_CTL).read_bytes() == content:
                        return True
                except Exception:
                    pass
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
        """调用 hy2-awgctl。返回 (returncode, stdout, stderr)。

        所有调用都用同一把锁串行化：awgctl 的 peer 增删与协议线切换都是
        读-改-写配置，并发执行会丢客户端或撞地址。
        """
        with awg_operation_lock:
            proc = subprocess.run([AWG_CTL] + args, capture_output=True, text=True,
                                  timeout=timeout)
        return proc.returncode, proc.stdout, proc.stderr

    def awg_err_tail(rc, out, err, limit=700):
        text = (err or '').strip() or (out or '').strip()
        return text[-limit:] if text else '退出码 ' + str(rc)

    def awg_state():
        meta = awg_read_json(AWG_META_PATH, {})
        if not isinstance(meta, dict):
            meta = {}
        # peers 文件是 awgctl.sh 写的 JSON：被截断/手工改坏时 `peers` 可能是
        # 字符串或含非 dict 条目。旧写法 len() / p.get() 直接抛异常，
        # 整个 /awg-state 端点 500，面板的 AWG 卡片整块空白。
        peers_doc = awg_read_json(AWG_PEERS_PATH, {})
        peers_raw = peers_doc.get('peers') if isinstance(peers_doc, dict) else None
        peers_raw = [p for p in peers_raw if isinstance(p, dict)] if isinstance(peers_raw, list) else []
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

    def _active_reality_config():
        """Reality 的配置，**仅在托管入站真的存在时**返回，否则 None。

        为什么按入站判断而不是 data['reality_config']：后者是「上次生成成功」
        的残留。Reality 被停掉后它还在，照着它生成订阅会下发一个连不上的节点。
        """
        try:
            cfg = json.loads(Path('/etc/hysteria/xray.json').read_text(encoding='utf-8'))
        except Exception:
            return None
        if not managed_inbound_active(cfg, REALITY_INBOUND_TAG):
            return None
        with data_lock:
            # 值可能是数字/字符串：dict(7) 抛 TypeError，订阅生成与状态卡片
            # 都会 500（配置只应来自本模块写入，但旧版本可直接编辑）。
            _r = data.get('reality_config')
            rcfg = dict(_r) if isinstance(_r, dict) else {}
        return rcfg or None

    def _active_vmess_config():
        """VMess 的配置，同样以托管入站是否存在为准。"""
        try:
            cfg = json.loads(Path('/etc/hysteria/xray.json').read_text(encoding='utf-8'))
        except Exception:
            return None
        if not managed_inbound_active(cfg, VMESS_INBOUND_TAG):
            return None
        with data_lock:
            _v = data.get('vmess_config')
            vcfg = dict(_v) if isinstance(_v, dict) else {}
        return vcfg or None

    def _active_vlessenc_config():
        """VLESS Encryption 的配置，同样以托管入站是否存在为准。"""
        try:
            cfg = json.loads(Path('/etc/hysteria/xray.json').read_text(encoding='utf-8'))
        except Exception:
            return None
        if not managed_inbound_active(cfg, VLESSENC_INBOUND_TAG):
            return None
        with data_lock:
            _e = data.get('vlessenc_config')
            ecfg = dict(_e) if isinstance(_e, dict) else {}
        return ecfg or None

    def _active_anytls_config():
        """AnyTLS 的配置：已启用且 sing-box 配置文件在才算（停用后只保留 secret）。"""
        with data_lock:
            _a = data.get('anytls_config')
            acfg = dict(_a) if isinstance(_a, dict) else {}
        if not acfg.get('enabled') or not (portal_path.parent / ANYTLS_CONFIG_NAME).exists():
            return None
        return acfg

    def regenerate_page():
        m = read_meta_file(meta_path)
        uri, clash, sing = artifacts(m)
        root = portal_path.parent
        access_file = root / 'portal-access.json'
        access = json.loads(access_file.read_text(encoding='utf-8')) if access_file.exists() else {}
        host = m.get('public_ip', '127.0.0.1') if m.get('is_insecure') else m.get('server_name', 'localhost')
        subscription = f"https://{access.get('username','')}:{access.get('password','')}@{host}:{resolve_subscription_port(m)[0]}/{data['token']}/clash.yaml"
        
        now_ts = int(time.time())
        display_users = {}
        # 只把「拍快照」放在锁内，渲染与落盘放到锁外（2026-10-25 修）。
        # page_html 在 2000 用户时约 27 ms，/auth 每个连接都要拿 data_lock，
        # 持锁渲染会短暂阻塞新连接鉴权；而渲染本身不依赖锁。
        with data_lock:
            # 清理离线已久的 ip_tracker 键
            dead_uids = [u for u, tr in ip_tracker.items()
                         if not isinstance(tr, dict)
                         or not any(now_ts - t < IP_TIMEOUT_SECONDS for t in tr.values())]
            for du in dead_uids:
                ip_tracker.pop(du, None)

            for uid, uinfo in users_list_rows(user_table(data)):
                # 单条记录被手工改坏时跳过这一行，不能让整页渲染失败
                # （regenerate_page 在 /auth 常见路径上，抛异常等于面板白屏）。
                if not isinstance(uinfo, dict):
                    continue
                u_copy = dict(uinfo)
                tracked = ip_tracker.get(uid)
                u_copy['online_ips'] = ({ip: t for ip, t in tracked.items()
                                         if now_ts - t < IP_TIMEOUT_SECONDS}
                                        if isinstance(tracked, dict) else {})
                display_users[uid] = u_copy
            _api_key = data.get('api_key')
            _token = data['token']

        # 渲染与二维码都在锁外做（2026-10-29 修，注释此前与实现不符）：
        # page_html 在上千用户时约 27 ms，qrencode 最坏 20 秒，而 /auth
        # 每个新连接都要拿同一把 data_lock。
        page = page_html(m, uri, subscription, clash, sing, users=display_users,
                         api_key=_api_key, token=_token,
                         session_secret=session_secret,
                         username=access.get('username', ''), password=access.get('password', ''))
        qr_svg = qr_svg_for(uri)

        with data_lock:
            # 内容没变就不重写：页面在用户、端口、证书都没变化时是同一份，
            # 每次刷新都全量序列化 + fsync 是纯浪费（2000 用户约 8 ms/次）。
            changed = data.get('page') != page
            data['page'] = page
            # 与 refresh() 同理：二维码/下载配置必须跟着 uri 一起更新，
            # 否则自愈换了 sni 之后，页面文本框是对的、二维码仍是旧节点。
            # ⚠️ 2026-10-29 修：sync_download_artifacts 也会改 clash/sing/qr，
            # 而这些不在 page 里（二维码是单独生成的）。只看 page 是否变化
            # 会漏保存：例如 qrencode 从不可用变成可用时，新二维码只留在内存里，
            # 重启后下载按钮又回到旧图。
            before_downloads = (data.get('clash'), data.get('sing'), data.get('qr'))
            sync_download_artifacts(data, uri, clash, sing, qr=qr_svg)
            after_downloads = (data.get('clash'), data.get('sing'), data.get('qr'))
            changed = changed or before_downloads != after_downloads
        if changed:
            save_data()

    # 会话在服务端过期：签名里带签发时间。原来的签名只覆盖固定 token，
    # 每次登录得到同一个值、永不过期（Max-Age 只约束浏览器），泄露即永久可用。
    SESSION_MAX_AGE = 30 * 86400

    def sign_session(token, issued_at=None):
        issued_at = int(time.time()) if issued_at is None else int(issued_at)
        sig = hmac.new(session_secret.encode(), f'sess:{token}:{issued_at}'.encode(), hashlib.sha256).hexdigest()
        return f'{token}.{issued_at}.{sig}'

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
        parts = cookies['hy2_session'].value.split('.')
        if len(parts) != 3 or not parts[1].isdigit() or not parts[0].isascii() or not parts[2].isascii():
            return False
        t, issued_at, sig = parts
        if not 0 <= time.time() - int(issued_at) <= SESSION_MAX_AGE:
            return False
        expected = hmac.new(session_secret.encode(), f'sess:{t}:{issued_at}'.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(t, data['token']) and hmac.compare_digest(sig, expected)

    # SPEEDTEST_TARGETS 是 /api/v1/speedtest 的**唯一**靶点来源。
    #
    # ⚠️ 它是硬编码常量，**不接受任何来自调用方的输入**。这是安全要求，不是简化。
    # 本 portal 以 root 运行、subprocess 直接拼命令：一旦目标地址能由请求方
    # 指定，字符串逃出引号就是本机 RCE。所以「靶点可配」这件事只放在运维面板侧
    # （speedtest_targets 表，走 SSH 通道），这条无凭据通道保持最小权限。
    #
    # 为什么不接受域名作为靶点：ping 只吃 IP 字面量，不接受域名（防 DNS rebinding），
    # 且这里只测 ICMP，不提供任何 TCP / 带宽探测能力。
    #
    # 清单来源：逐个 `ping -c 3 -W 2` 实测的可用清单。骨干禁 ICMP 是常态
    # —— 实测 51 个候选里 31 个 100% 丢包，所以**只列实测丢包 0% 的**，
    # 不要凭印象增补。电信用 163 骨干、联通用 169 骨干。
    # 格式：(target_key, 展示名, IP, 运营商)
    SPEEDTEST_TARGETS = (
        # 电信 163 骨干
        ('telecom-bj-163',   '电信-北京(163)',   '202.96.128.86',  'telecom'),
        ('telecom-sh-163',   '电信-上海(163)',   '202.96.134.33',  'telecom'),
        ('telecom-gz-163',   '电信-广州(163)',   '202.96.209.5',   'telecom'),
        ('telecom-sd-163',   '电信-山东(163)',   '218.85.152.99',  'telecom'),
        ('telecom-hb-163',   '电信-湖北(163)',   '202.96.209.133', 'telecom'),
        # 联通 169 骨干 + 公共 DNS
        ('unicom-bj-169',    '联通-北京(169)',      '202.38.128.1',    'unicom'),
        ('unicom-gz-169',    '联通-广州(169)',      '219.158.16.53',   'unicom'),
        ('unicom-bj-106',    '联通-北京(DNS)',      '202.106.50.1',    'unicom'),
        ('unicom-dns-123',   '联通-北京(公共DNS)',  '123.123.123.123', 'unicom'),
        # 移动
        ('mobile-sh',        '移动-上海',     '211.136.112.200', 'mobile'),
        ('mobile-bj',        '移动-北京',     '211.136.25.153',  'mobile'),
        ('mobile-bj-2',      '移动-北京(2)',  '211.136.17.107',  'mobile'),
        ('mobile-gd',        '移动-广东',     '36.156.0.1',      'mobile'),
        ('mobile-ah',        '移动-安徽',     '120.196.165.24',  'mobile'),
        ('mobile-sd',        '移动-山东',     '39.128.28.66',    'mobile'),
        # 公共 DNS（三网都通，作跨网基准）
        ('dns-ali',          '阿里 DNS',     '223.5.5.5',       'other'),
        ('dns-tencent',      '腾讯 DNS',     '119.29.29.29',    'other'),
        ('dns-cnnic',        'CNNIC DNS',    '1.2.4.8',         'other'),
    )

    class Handler(BaseHTTPRequestHandler):
        def _sync_reality_clients(self):
            # 名字保留（调用点很多），实际语义已扩展为「同步所有托管入站」：
            # Reality 与 VMess 的 clients 都由 enforce_node_access 一并收回。
            return apply_access()

        def _extend_deadline(self, seconds):
            """为本连接延长死线（见 ThreadingHTTPServer.extend_deadline 的说明）。

            seconds 取该端点自己的最长预期耗时（subprocess 超时 + 余量）。
            连接不存在或已结束就是无操作，不影响别的请求。
            """
            try:
                self.server.extend_deadline(self.connection, seconds)
            except Exception:
                pass

        def _generate_and_apply_reality(self, restart=True, force=False):
            """生成（或刷新）Reality 的服务端配置。

            ⚠️ 2026-10-03 关键修正：**密钥对与 clients 都必须稳定**。
            旧实现每次调用都 `uuid.uuid4()` 重新生成 UUID 并把 clients 写死成
            1 个元素，于是：
              * 每刷新一次 Reality，**所有客户端的链接全部失效**；
              * 多用户共用同一个 UUID —— 任何一个人销户都会连累所有人。

            现在：密钥对只在「首次」生成（已有就复用），clients 由
            reality_clients(data) 从 data['users'] 派生，一个用户一个 UUID。

            force=True —— 只给「重置密钥对」按钮用：
            强制重新生成 private/public key 与 short_id。
            ⚠️ 仍然**不会**改任何用户的 UUID（那是 uuid5 派生的），
            所以重置密钥不会让已发出去的链接全挂 —— 只有私钥变了，
            客户端的 pbk（公钥）需要更新。
            """
            with data_lock:
                rcfg_old = dict(config_section(data, 'reality_config'))

            priv_key = '' if force else rcfg_old.get('private_key', '')
            pub_key = '' if force else rcfg_old.get('public_key', '')
            if not (priv_key and pub_key):
                # 生成失败就停止，不能让不同节点共用硬编码私钥。
                try:
                    p = subprocess.run(['/usr/local/bin/xray', 'x25519'],
                                       capture_output=True, text=True, timeout=5)
                    for line in p.stdout.splitlines():
                        if 'PrivateKey:' in line:
                            priv_key = line.split('PrivateKey:')[1].strip()
                        elif 'Password (PublicKey):' in line or 'PublicKey:' in line:
                            pub_key = line.split(':')[1].strip()
                except Exception:
                    priv_key = pub_key = ''
                if not priv_key or not pub_key or p.returncode != 0:
                    raise RuntimeError('X25519 密钥生成失败，原密钥和配置未修改')

            short_id = (secrets.token_hex(4) if force
                        else (rcfg_old.get('short_id') or secrets.token_hex(4)))
            dest_sni = rcfg_old.get('dest_sni') or 'www.apple.com'

            # ---- 端口：自动避让，绝不硬塞（2026-10-04 加）----
            #
            # 旧实现是 `rcfg_old.get('port') or 443` —— **首次安装无脑用 443**。
            # 后果（洛杉矶-NTT 实测）：该机 8443 是 hysteria 的订阅端口、
            # 443 也常被 Caddy 之类的服务占着，闭眼选必然撞车；
            # 而撞车的表现是「Reality 起不来或端口被抢」，排查成本很高。
            #
            # 现在改为：先问内核「哪些端口已在监听」，再从候选表里挑第一个空闲的。
            # 已有配置且仍空闲 ⇒ 保持原端口不变（不给老节点无谓改配置）。
            #
            # 注意：这里**只读**监听表，不做 bind 探测 ——
            # 本文件 gost 段记着血泪：「不再用 socket bind 做端口探测(在某些环境会卡住)」。
            m = read_meta_file(meta_path)
            _avoid = set()
            try:
                _avoid.add(int(m.get('listen_port') or 0))
            except Exception:
                pass
            try:
                _avoid.add(int(m.get('subscription_port') or 0))
            except Exception:
                pass

            # 避开所有托管协议已占用的端口，而不只是 hy2 / 订阅端口。
            try:
                _cfg_now = (json.loads(Path('/etc/hysteria/xray.json').read_text(encoding='utf-8'))
                            if Path('/etc/hysteria/xray.json').exists() else None)
            except (OSError, ValueError):
                _cfg_now = None
            with data_lock:
                _data_now = dict(data)
            _avoid |= managed_reserved_ports(m, _data_now, _cfg_now, exclude_key='reality_config')
            listen_port, port_reason = _pick_reality_port(
                preferred=rcfg_old.get('port'), extra_blocked=_avoid)
            if not listen_port:
                # 找不到空闲端口 ⇒ **明确失败**，不生成一份注定冲突的配置。
                #
                # ⚠️ 用抛异常而不是改返回值：本函数有 3 个调用点
                # （install-xray 之后、reality-toggle、reality-reset），
                # 改签名要同时改三处、且每处后续逻辑不同，很容易漏掉一处
                # 导致「看起来成功、实际没配置」。抛异常让**所有**调用点
                # 统一走各自的错误分支，不会有人悄悄拿到 None 当成功用。
                raise RuntimeError(port_reason)
            # 端口发生了变更才提示。旧端口可能是非法值（字符串/越界），
            # 这里同样要容错 —— 别让一个坏的历史值把日志行本身搞崩。
            try:
                _old_port = int(rcfg_old.get('port'))
            except (TypeError, ValueError):
                _old_port = 0
            if _old_port and _old_port != listen_port:
                print('[portal] Reality 端口变更: %s' % port_reason,
                      file=sys.stderr)

            public_ip = m.get('public_ip', '127.0.0.1')

            new_rcfg = {
                'private_key': priv_key, 'public_key': pub_key, 'short_id': short_id,
                'dest_sni': dest_sni, 'port': listen_port,
            }
            new_rcfg['uuid'] = reality_uuid_for_user(MASTER_USER_ID)
            new_rcfg['uri'] = reality_uri_for_user(new_rcfg, MASTER_USER_ID, public_ip,
                                                 label='Teyir-VLESS-Reality')
            with data_lock:
                clients = reality_clients(data)

            xray_json = {
                "log": {"loglevel": "warning"},
                "inbounds": [
                    {
                        "tag": "vless-reality-in",
                        "port": listen_port,
                        "protocol": "vless",
                        "settings": {
                            "clients": clients,
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
                "outbounds": [{"protocol": "freedom", "tag": "direct"}]
            }
            xray_path = Path('/etc/hysteria/xray.json')
            desired_inbound = xray_json['inbounds'][0]
            # 🔴 读-改-写必须整体在 reality_apply_lock 内（2026-10-24 修）。
            # 旧实现在锁外读 xray.json、锁内才写：两个协议同时启用时，
            # 后拿到锁的那次会用**较早读到的旧快照**覆盖磁盘，把先写入的
            # 另一个协议静默丢掉（两个请求都返回成功，用户下次重启才发现）。
            with reality_apply_lock:
                if xray_path.exists():
                    # 只按 tag 替换 Reality 自己那一条；VMess 入站、统计 api 入站、
                    # routing、outbounds 一律原样保留。旧版无 tag 的 Reality 由
                    # managed_inbound_index 的 legacy 匹配接住，写入时补上 tag。
                    previous = json.loads(xray_path.read_text(encoding='utf-8'))
                    xray_json = upsert_managed_inbound(previous, REALITY_INBOUND_TAG, desired_inbound)

                # 重生成 Reality 配置时保留计量能力；仅添加回环 StatsService。
                # add_stats 是幂等的，且**不改任何 clients**（有断言兜底），
                # 所以 VMess / VLESS Encryption 入站及其 clients 不会被它重置。
                _meter_config_path = portal_path.parent / 'usage-meter-config.json'
                if _meter_config_path.exists():
                    _meter_config = json.loads(_meter_config_path.read_text(encoding='utf-8'))
                    _meter_reality = _meter_config.get('reality')
                    if _meter_reality:
                        _address = _meter_reality['address']
                        if not _address.startswith('127.0.0.1:'):
                            raise ValueError('统计接口必须为回环地址')
                        _stats_path = Path(__file__).parent / 'usage-meter-xray-config-20261007-v1.py'
                        _stats_spec = importlib.util.spec_from_file_location('portal_stats_cfg', _stats_path)
                        _stats_mod = importlib.util.module_from_spec(_stats_spec)
                        _stats_spec.loader.exec_module(_stats_mod)
                        xray_json = _stats_mod.add_stats(xray_json, int(_address.rsplit(':', 1)[1]))
                # 统一补内网 / 云元数据拦截（Reality 入站同样适用）。
                xray_json = add_private_network_guard(xray_json)
                # 流量超额停用期间只落配置、不重启，否则等于替 Reality 解除了停用。
                apply_xray_config_transaction(xray_json, config_path=str(xray_path),
                                              binary=str(Path('/usr/local/bin/xray')),
                                              restart=restart and not unit_suspended('xray'))
                with data_lock:
                    data['reality_config'] = new_rcfg
                save_data()
            # Reality 走 TCP；开着 ufw / firewalld 时不放行，外网就连不上。
            firewall_port(new_rcfg.get('port'), 'tcp', open_=True)
            return clients

        server_version = 'Gateway'
        sys_version = ''
        def setup(self):
            super().setup()
            self.connection.settimeout(5)
        def log_message(self, *args):
            pass

        def verify_api_key(self):
            auth_header = self.headers.get('Authorization', '')
            # api_key 为空/非字符串时一律拒绝（2026-10-29 修）：
            # 旧实现拼出常量 "Bearer "，而 HTTP 头允许尾随空格，
            # 一个 `Authorization: Bearer ` 就能通过 —— 等于 API 全开。
            key = data.get('api_key')
            if not isinstance(key, str) or not key:
                return False
            expected = 'Bearer ' + key
            # ⚠️ 必须先挡非 ASCII（2026-10-09 修）：hmac.compare_digest 遇到
            # 含非 ASCII 字符的 str 会抛 TypeError（只支持 bytes 或纯 ASCII str）。
            # 一个 `Authorization: Bearer 中文` 的请求就会在处理函数里抛未捕获异常
            # → 连接被掐断、浏览器只看到通用错误，还分不清是「鉴权失败」还是「服务端坏了」。
            if not auth_header.isascii():
                return False
            return hmac.compare_digest(auth_header, expected)

        def is_authenticated(self):
            auth = self.headers.get('Authorization', '')
            # 头部没有体积上限，而这里要对它做 sha256。超长 Basic 头
            # （几 MB 的 base64）会让每个请求都白算一次哈希，属于廉价放大。
            # 正常凭据远小于 1 KiB，直接拒绝更长的（2026-10-25）。
            if len(auth) > 1024:
                return False
            if auth.startswith('Basic '):
                digest = hashlib.sha256(auth.removeprefix('Basic ').encode()).hexdigest()
                if hmac.compare_digest(digest, data['auth_hash']):
                    return True
            return verify_session(self.headers.get('Cookie', ''))

        def reply_json(self, code, payload):
            body = json.dumps(payload, ensure_ascii=False).encode('utf-8')
            self.send_response(code)
            self._responded = True
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            # 与 reply() 保持一致的安全头（2026-10-24 补）。
            # JSON 本身不渲染 HTML，但缺少 nosniff 时，某些浏览器/代理会把
            # 被错误标成 text/html 的响应当页面执行，属于低成本纵深防御。
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('X-Frame-Options', 'DENY')
            self.send_header('Referrer-Policy', 'no-referrer')
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
                elif bucket == 'auth':
                    # 🔴 /auth 专用桶（真实漏洞，2026-10-09 修）：
                    # 原来 /auth 完全不限流，理由写的是「来自 127.0.0.1 豁免」——
                    # 但 config.yaml 的 masquerade 把**公网 HTTPS 流量代理进本机
                    # 127.0.0.1:PORTAL**（type: proxy → http://127.0.0.1:PORT/），
                    # 于是公网攻击者打到的仍是这个 loopback 端口，那条假设不成立。
                    # 实测：经 masquerade 打 /auth 连发 20 次全部 200，
                    # 且四种可区分回复（User not found / inactive / expired /
                    # Traffic quota exceeded）构成完美的密码 oracle，可无限爆破。
                    # 桶要小得多：/auth 只有 hysteria 握手才会调，QPS 天然很低。
                    self.server.auth_requests[:] = [t for t in self.server.auth_requests if now - t < 1]
                    if len(self.server.auth_requests) >= 20:
                        return False
                    self.server.auth_requests.append(now)
                    return True
                else:
                    self.server.requests[:] = [t for t in self.server.requests if now - t < 1]
                    self.server.failures[:] = [t for t in self.server.failures if now - t < 60]
                    if len(self.server.requests) >= 50 or len(self.server.failures) >= 60:
                        return False
                    self.server.requests.append(now)
                    return True

        def login_rate_limited(self):
            """Web 登录的暴力破解防护。

            🔴 2026-10-25 修：原来登录失败记在通用的 `failures` 桶里，而该桶
            每次 check_rate_limit 都会把 60 秒以外的条目剪掉，并在 `>= 60`
            时拒绝 —— 60 秒内既要有 60 次请求、又要达到 60 次失败，
            实际上永远触发不了。攻击者每秒试一次密码可以无限进行。
            这里改成独立的 10 分钟滑窗失败桶：10 次失败后进入冷却。
            """
            now = time.monotonic()
            with data_lock:
                self.server.login_failures[:] = [
                    t for t in self.server.login_failures if now - t < 600]
                return len(self.server.login_failures) >= 10

        def record_login_failure(self):
            now = time.monotonic()
            with data_lock:
                self.server.login_failures.append(now)

        def record_failure(self):
            now = time.monotonic()
            with data_lock:
                self.server.failures.append(now)

        def auth_rate_limited(self):
            """/auth 专用限流 + 失败累计。

            为什么不用 check_rate_limit('auth') 就完事：那个桶只挡**速率**，
            挡不住低速爆破（每秒 1 次可以试 3 小时不停）。
            这里再叠一个 60 秒滑窗的**失败**计数，
            累计到阈值就短暂拒绝，逼迫爆破者付出时间成本。
            """
            now = time.monotonic()
            with data_lock:
                # 速率桶：1 秒内超过 20 次直接拒
                self.server.auth_requests[:] = [t for t in self.server.auth_requests if now - t < 1]
                too_fast = len(self.server.auth_requests) >= 20
                if not too_fast:
                    self.server.auth_requests.append(now)
                # 失败桶：60 秒内失败超过 30 次就拒（哪怕速率不超）
                self.server.auth_failures[:] = [
                    t for t in self.server.auth_failures if now - t < 60]
                too_many_failures = len(self.server.auth_failures) >= 30
            return too_fast or too_many_failures

        def record_auth_failure(self):
            now = time.monotonic()
            with data_lock:
                self.server.auth_failures.append(now)

        def handle_one_request(self):
            """兜住所有未捕获异常：转成 500 JSON 并记录，而不是掐断连接。

            处理器里有大量分支没有各自的 try（历史上多次出现「客户端只看到
            Remote end closed connection，日志里什么都没有」）。这里统一兜底，
            至少留下异常类型与路径，前端也能拿到一个可读的错误
            （2026-10-30 加）。
            """
            try:
                super().handle_one_request()
            except (BrokenPipeError, ConnectionResetError):
                self.close_connection = True
            except Exception as exc:
                print('[portal] unhandled error on %s %s: %s: %s'
                      % (getattr(self, 'command', '?'), getattr(self, 'path', '?'),
                         type(exc).__name__, str(exc)[:200]), file=sys.stderr)
                # 已经发过响应头就不能再发第二个（会把 HTTP 流写坏）。
                if getattr(self, '_responded', False):
                    self.close_connection = True
                    return
                try:
                    self.reply_json(500, {'ok': False,
                                          'error': 'Internal error: %s' % type(exc).__name__})
                except Exception:
                    self.close_connection = True

        def do_POST(self):
            try:
                body_length = int(self.headers.get('Content-Length', 0))
            except (ValueError, TypeError):
                return self.reply_json(400, {'ok': False, 'error': 'Invalid Content-Length'})
            if not 0 <= body_length <= 1024 * 1024:
                return self.reply_json(413, {'ok': False, 'error': 'Request body exceeds 1 MiB'})
            # 1. Hysteria 2 本地 HTTP 动态鉴权、实时流量统计与 IP 限额拦截端点
            #
            # 🔴 这里必须限流（2026-10-09 修）：原注释写「来自 127.0.0.1 豁免限流」，
            # 但 masquerade 会把**公网 HTTPS 流量代理进本机 127.0.0.1:PORTAL**，
            # 公网攻击者打到的同样是这个 loopback 端口，假设不成立。
            # 实测经 masquerade 连发 20 次 /auth 全部放行，且回复可区分用户是否存在，
            # 构成完美的密码 oracle。现在走 auth_rate_limited()，
            # 并且**失败也计数**（低速爆破同样被挡）。
            if self.path == '/auth':
                # Hy2 核心直连 /auth 从不带 X-Forwarded-For；带了说明是公网请求经
                # masquerade 代理进来的（config.yaml 里 xForwarded: true）。直接拒，
                # 且不计入全局失败桶 —— 否则外人刷 30 次错误密码就能让全节点无法登录。
                if (self.client_address[0] not in ('127.0.0.1', '::1') or
                        any(name in self.headers for name in
                            ('X-Forwarded-For', 'X-Forwarded-Host',
                             'X-Forwarded-Proto', 'Forwarded'))):
                    return self.reply_json(200, {'ok': False, 'msg': 'Forbidden'})
                if self.auth_rate_limited():
                    # 用与成功路径相同的 200 + JSON 形态回复：不给爆破者区分信号。
                    # （Hysteria 只会看 ok 字段；非 200 可能让它反复重试并刷日志。）
                    return self.reply_json(200, {'ok': False, 'msg': 'Auth service busy'})
                try:
                    length = int(self.headers.get('Content-Length', 0))
                    body = self.rfile.read(length).decode('utf-8', errors='replace')
                    req_data = json.loads(body)
                    client_auth = req_data.get('auth', '')
                    if not isinstance(client_auth, str):
                        raise ValueError('auth must be a string')
                    client_addr = req_data.get('addr', '')
                    # ⚠️ hysteria HTTP auth 的 tx/rx 是客户端**带宽声明**，
                    # 不是实际传输字节。把它累加进用量会让数字虚高且离谱。
                    # 真实用量由计量模块从 hysteria trafficStats / xray stats
                    # 的单调计数器累计（见 usage-meter-core）。
                    client_ip = client_addr.rsplit(':', 1)[0].strip('[]') if client_addr else ''
                    try:  # 与计量模块同一写法，避免 IPv6 表示不同导致同一设备被算两次
                        client_ip = str(ipaddress.ip_address(client_ip)) if client_ip else ''
                    except ValueError:
                        pass
                except Exception:
                    self.record_auth_failure()
                    return self.reply_json(200, {'ok': False, 'msg': 'Bad auth request'})

                now_ts = time.time()
                # 🔴 锁内只做判定与状态更新，**不要在锁内写响应**（2026-10-29 修）。
                # data_lock 是全局锁，/auth 又是每个新连接必走的路径；慢客户端
                # 或发送缓冲区满时，reply_json 里的 socket 写入会阻塞（最长到
                # 连接超时），期间所有请求都在排队，包括新的鉴权。
                deny = None
                with data_lock:
                    users = user_table(data)
                    matched_uid, matched_user = None, None
                    for uid, uinfo in users.items():
                        if not isinstance(uinfo, dict):
                            continue
                        password = uinfo.get('password')
                        if not isinstance(password, str) or not password:
                            continue
                        if hmac.compare_digest(password.encode(), client_auth.encode()):
                            matched_uid, matched_user = uid, uinfo
                            break

                    if not matched_user:
                        deny = 'User not found'
                    else:
                        deny = user_access_denial(matched_user, now_ts)
                        if deny is None and client_ip and client_ip in active_ip_deny(global_ip_deny, matched_uid, now_ts):
                            deny = 'Device limit exceeded across nodes'
                        try:
                            ip_limit = int(matched_user.get('ip_limit', 0))
                        except (ValueError, TypeError, OverflowError):
                            deny = deny or 'Invalid user record'
                        if deny is None:
                            # -------- 同时在线 IP 限制检查 -------- #
                            if ip_limit > 0 and client_ip:
                                tracker = ip_tracker.setdefault(matched_uid, {})
                                active_ips = {ip: t for ip, t in tracker.items()
                                              if now_ts - t < IP_TIMEOUT_SECONDS}
                                ip_tracker[matched_uid] = active_ips
                                # 已连着的设备即使超过 180 秒没重新鉴权也要算在内。
                                # Reality 放行中的 IP 也占名额：两个协议共用同一个设备上限。
                                occupied = (set(active_ips) | live_online_ips(matched_uid)
                                            | reality_live_ips(matched_uid))
                                if client_ip not in occupied and len(occupied) >= ip_limit:
                                    deny = f'Concurrent IP limit exceeded ({ip_limit} max)'
                                else:
                                    active_ips[client_ip] = now_ts
                            elif client_ip:
                                tracker = ip_tracker.setdefault(matched_uid, {})
                                tracker[client_ip] = now_ts

                if deny == 'User not found':
                    self.record_auth_failure()
                if deny:
                    return self.reply_json(200, {'ok': False, 'msg': deny})
                return self.reply_json(200, {'ok': True, 'id': matched_uid})

            # 2. REST API 接口通道 (独立 API 速率桶)
            if self.path.startswith('/api/v1/'):
                if not self.check_rate_limit(bucket='api'):
                    return self.reply(429, b'Too many requests')

                if not self.verify_api_key():
                    return self.reply_json(401, {'ok': False, 'error': 'Unauthorized API key'})

                try:
                    length = int(self.headers.get('Content-Length', 0))
                    body = self.rfile.read(length).decode('utf-8', errors='replace') if length > 0 else '{}'
                    params = json.loads(body)
                except Exception:
                    return self.reply_json(400, {'ok': False, 'error': 'Invalid JSON body'})

                if not isinstance(params, dict):
                    return self.reply_json(400, {'ok': False, 'error': 'JSON body must be an object'})
                sub = self.path[len('/api/v1/'):].split('?', 1)[0]
                if sub.startswith('users/'):
                    try:
                        for key in ('user_id', 'password'):
                            if params.get(key) is not None and not isinstance(params[key], str):
                                raise ValueError()
                        for key in ('duration_days', 'ip_limit', 'expires_at', 'limit_bytes', 'used_bytes'):
                            if key in params:
                                if isinstance(params[key], bool):
                                    raise ValueError()
                                params[key] = int(params[key])
                                if params[key] < (1 if key == 'duration_days' else 0):
                                    raise ValueError()
                        if 'traffic_gb' in params:
                            params['traffic_gb'] = float(params['traffic_gb'])
                            if not math.isfinite(params['traffic_gb']) or params['traffic_gb'] < 0:
                                raise ValueError()
                        if 'active' in params and not isinstance(params['active'], bool):
                            raise ValueError()
                    except (ValueError, TypeError, OverflowError):
                        return self.reply_json(400, {'ok': False, 'error': 'Invalid user parameter'})
                now_ts = int(time.time())

                # 动态开户 (支持 duration_days, ip_limit, traffic_gb)
                if sub == 'users/create':
                    user_id = (params.get('user_id') or ('hy2_' + secrets.token_hex(6))).strip()
                    if not VALID_USER_ID_RE.match(user_id):
                        return self.reply_json(400, {'ok': False, 'error': 'Invalid managed user_id'})
                    if user_id in RESERVED_USER_IDS:
                        # 分开提示：机主账号是节点主密码，placeholder 是计量占位名。
                        # 旧文案把它们混成「ID 格式错误」，排查时会被带偏。
                        return self.reply_json(400, {'ok': False, 'error':
                            'user_id 是保留名称（机主账号 / 计量占位），不能用于开户'})

                    pwd = params.get('password') or secrets.token_hex(16)
                    # 密码必须是字符串：数字/数组会原样落盘，/auth 与 Xray 同步各自
                    # str() 后的形态不一致，用户拿到的连接参数就对不上。
                    if not isinstance(pwd, str) or not pwd.strip():
                        return self.reply_json(400, {'ok': False, 'error': 'Invalid user parameter: password must be a non-empty string'})
                    # 🔴 2026-10-25 修：这些值直接来自请求体，`int('abc')` 会抛
                    # ValueError。该分支不在任何 try 里，异常会穿透 do_POST →
                    # 连接被掐断，客户端只看到 "Remote end closed connection"，
                    # 完全看不出是参数问题。这里统一解析并给出 400。
                    try:
                        days = int(params.get('duration_days', 30))
                        ip_limit = int(params.get('ip_limit', 0))
                        traffic_gb = float(params.get('traffic_gb', 0))
                        expires = int(params.get('expires_at', now_ts + days * 86400))
                    except (ValueError, TypeError, OverflowError):
                        return self.reply_json(400, {'ok': False, 'error':
                            'Invalid user parameter: duration_days / ip_limit / traffic_gb / expires_at must be numeric'})
                    if not math.isfinite(traffic_gb):
                        return self.reply_json(400, {'ok': False, 'error': 'Invalid user parameter: traffic_gb must be finite'})
                    if not 1 <= days <= 36500:
                        return self.reply_json(400, {'ok': False, 'error':
                            'Invalid user parameter: duration_days must be 1..36500'})
                    if not 0 <= ip_limit <= 1000:  # 与 users/update 的取值范围一致
                        return self.reply_json(400, {'ok': False, 'error': 'Invalid user parameter'})
                    # 上限与 users/renew 一致（1e6 GB）。没有上限时 1e308 能通过
                    # isfinite 检查，却在 int() 转换处抛 OverflowError 掐断连接。
                    if not 0 <= traffic_gb <= 1000000:
                        return self.reply_json(400, {'ok': False, 'error':
                            'Invalid user parameter: traffic_gb must be 0..1000000'})
                    # 与 users/renew 同一上界：无上界时能写入无意义的到期时间。
                    if not 0 <= expires <= 253402300799:
                        return self.reply_json(400, {'ok': False, 'error':
                            'Invalid user parameter: expires_at out of range'})
                    limit_bytes = int(traffic_gb * (1024**3)) if traffic_gb > 0 else 0
                    # limit_bytes / used_bytes 显式传入时以它为准（控制台对账时
                    # 会带上这两个字段）。旧实现只校验不使用，调用静默失效
                    # （2026-10-29 修）。
                    if 'limit_bytes' in params:
                        limit_bytes = int(params['limit_bytes'])
                    initial_used = int(params.get('used_bytes', 0))
                    # active 同理：旧实现校验了却始终写 status=active，
                    # 控制台传 {"active": false} 开户会拿到 200 但用户照样能连。
                    want_active = params.get('active', True)
                    note = str(params.get('note', '')).strip()[:200]

                    # 🔴 判定必须在锁内、回包必须在锁外：data_lock 是全局锁，
                    # /auth 每个新连接都要拿它；在锁内写 socket（慢客户端/缓冲区满
                    # 时会阻塞到连接超时）等于把全节点的鉴权一起卡住。
                    conflict = None
                    with data_lock:
                        existing = data.get('users', {}).get(user_id)
                        # 只认明确的真值：字符串 "0"/"false" 不该被当成 true。
                        _create_only = str(params.get('create_only', '')).strip().lower() in ('1', 'true', 'yes', 'on')
                        if _create_only and existing is not None:
                            conflict = (409, 'User already exists')
                        elif params.get('password') and password_taken(data.get('users', {}), pwd, user_id):
                            conflict = (409, 'Password already in use by another user')
                        if conflict is None:
                            record = {
                                'password': pwd,
                                'expires_at': expires,
                                'ip_limit': ip_limit,
                                'limit_bytes': limit_bytes,
                                'used_bytes': initial_used,
                                'status': 'active' if want_active else 'disabled',
                                'created_at': now_ts,
                                'note': note,
                                'view_nonce': secrets.token_hex(8),
                            }
                            if existing is not None:
                                # 更新已有用户不能换 nonce，否则发出去的分享链接会失效。
                                if 'view_nonce' in existing:
                                    record['view_nonce'] = existing['view_nonce']
                                else:
                                    record.pop('view_nonce')
                                # 显式传入的字段以本次请求为准；没传才保留旧值
                                # （2026-10-29 修：旧实现无条件保留旧 status/用量，
                                # 控制台对账时传 active=false 或 limit_bytes 会被静默忽略）。
                                if 'used_bytes' not in params:
                                    record['used_bytes'] = int(existing.get('used_bytes', 0))
                                record['created_at'] = existing.get('created_at', now_ts)
                                if 'active' not in params:
                                    record['status'] = existing.get('status', 'active')
                                for param, field in (('password', 'password'), ('ip_limit', 'ip_limit'),
                                                     ('traffic_gb', 'limit_bytes'), ('note', 'note')):
                                    if param not in params or (param == 'password' and not params.get(param)):
                                        record[field] = existing.get(field, record[field])
                                # traffic_gb 与 limit_bytes 都没传时才沿用旧配额。
                                if 'traffic_gb' not in params and 'limit_bytes' not in params:
                                    record['limit_bytes'] = existing.get('limit_bytes', record['limit_bytes'])
                                if 'duration_days' not in params and 'expires_at' not in params:
                                    record['expires_at'] = existing.get('expires_at', record['expires_at'])
                            if existing is not None:
                                rotate_user_view_key_on_change(existing, record)
                            data.setdefault('users', {})[user_id] = record
                            pwd, expires = record['password'], record['expires_at']
                            ip_limit, limit_bytes = record['ip_limit'], record['limit_bytes']
                            status_after = record.get('status', 'active')
                            # 同步 Reality 账号表（2026-10-03）：一个 Hy2 用户
                            # 对应一个 VLESS UUID，开户即生效。
                            reality_registry(data)
                            rcfg = dict(config_section(data, 'reality_config'))
                            vcfg_active = dict(config_section(data, 'vmess_config'))
                            ecfg_active = dict(config_section(data, 'vlessenc_config'))
                    if conflict is not None:
                        # 锁已释放，现在才写响应。
                        return self.reply_json(conflict[0], {'ok': False, 'error': conflict[1]})
                    regenerate_page()

                    # 受控对账开户必须确认Reality生效；失败可GET→update同值重试。
                    if _create_only and Path('/etc/hysteria/xray.json').exists():
                        if not self._sync_reality_clients():
                            return self.reply_json(503, {'ok': False, 'error': 'Reality sync failed; retry required'})
                    else:
                        if not self._sync_reality_clients():
                            return self.reply_json(503, {'ok': False, 'error': 'Reality sync failed; retry required'})

                    rcfg = _active_reality_config()
                    vcfg_active = _active_vmess_config()
                    ecfg_active = _active_vlessenc_config()
                    acfg_active = _active_anytls_config()
                    m = read_meta_file(meta_path)
                    # artifacts 传入 reality + user_id ⇒ 输出「Hy2 + Reality」双节点
                    # 且 Clash / Sing-box 的策略组变成 url-test（自动择优）。
                    uri, clash_yaml, sing_json = artifacts(
                        m, auth_override=pwd, name_override=f"Teyir-Hy2-{user_id}",
                        reality=rcfg, user_id=user_id, vmess=vcfg_active,
                        vlessenc=ecfg_active, anytls=acfg_active)
                    public_ip = m.get('public_ip', '127.0.0.1')
                    reality_uri = reality_uri_for_user(
                        rcfg, user_id, public_ip, label=f"Teyir-Reality-{user_id}")
                    vmess_uri = vmess_uri_for_user(
                        vcfg_active, user_id, public_ip,
                        label=f"Teyir-VMess-{user_id}") if vcfg_active else ''
                    vlessenc_uri = vlessenc_uri_for_user(
                        ecfg_active, user_id, public_ip,
                        label=f"Teyir-VLESS-Enc-{user_id}") if ecfg_active else ''
                    anytls_uri = anytls_uri_for_user(
                        acfg_active, user_id, label=f"Teyir-AnyTLS-{user_id}") if acfg_active else ''
                    return self.reply_json(200, {
                        'ok': True,
                        'user_id': user_id,
                        'password': pwd,
                        'ip_limit': ip_limit,
                        # 用落盘后的真实配额回报。旧实现回的是本次请求解析出的
                        # traffic_gb（未传时是 0），同名更新保留旧配额时会误导
                        # 控制台（2026-10-29 修）。
                        'traffic_gb': round(limit_bytes / (1024**3), 3),
                        'limit_bytes': limit_bytes,
                        'status': status_after,
                        'expires_at': expires,
                        'uri': uri,
                        'reality_uri': reality_uri,
                        'reality_uuid': reality_uuid_for_user(user_id),
                        'vmess_uri': vmess_uri,
                        'vmess_uuid': vmess_uuid_for_user(user_id) if vcfg_active else '',
                        'vlessenc_uri': vlessenc_uri,
                        'vlessenc_uuid': reality_uuid_for_user(user_id) if ecfg_active else '',
                        'anytls_uri': anytls_uri,
                        'clash': clash_yaml,
                        'sing_box': sing_json
                    })

                elif sub == 'users/update':
                    # 安全属性更新：不接收用量/创建时间/流量额度，不覆盖用户对象。
                    user_id = str(params.get('user_id', '')).strip()
                    if not VALID_USER_ID_RE.match(user_id):
                        return self.reply_json(400, {'ok': False, 'error': 'Invalid managed user_id'})
                    if user_id == MASTER_USER_ID:
                        return self.reply_json(400, {'ok': False, 'error':
                            '机主账号不通过本接口修改（主密码即节点鉴权密码）；'
                            '如需更换请使用终端菜单或在面板中操作'})
                    if user_id in RESERVED_USER_IDS:
                        return self.reply_json(400, {'ok': False, 'error':
                            'user_id 是保留名称，不能用于修改'})
                    allowed = {'user_id', 'password', 'expires_at', 'ip_limit', 'status'}
                    if set(params) - allowed:
                        return self.reply_json(400, {'ok': False, 'error': 'Unsupported attribute'})
                    try:
                        changes = {}
                        if 'password' in params:
                            if not isinstance(params['password'], str) or not params['password']:
                                raise ValueError()
                            changes['password'] = params['password']
                        if 'expires_at' in params:
                            changes['expires_at'] = int(params['expires_at'])
                            # 与 create / renew 使用同一上界（9999-12-31）。
                            if not 0 <= changes['expires_at'] <= 253402300799: raise ValueError()
                        if 'ip_limit' in params:
                            changes['ip_limit'] = int(params['ip_limit'])
                            if not 0 <= changes['ip_limit'] <= 1000: raise ValueError()
                        if 'status' in params:
                            if params['status'] not in ('active', 'disabled'): raise ValueError()
                            changes['status'] = params['status']
                    except (ValueError, TypeError):
                        return self.reply_json(400, {'ok': False, 'error': 'Invalid attribute'})
                    conflict = None
                    with data_lock:
                        u = data.get('users', {}).get(user_id)
                        if u is None:
                            conflict = (404, 'User not found')
                        elif 'password' in changes and password_taken(data.get('users', {}), changes['password'], user_id):
                            conflict = (409, 'Password already in use by another user')
                        else:
                            previous = dict(u)
                            u.update(changes)
                            rotate_user_view_key_on_change(previous, u)
                            result = {k: v for k, v in u.items() if k not in ('password', 'view_nonce')}
                            # 与 users/list 对齐：同时给 traffic_* 与原始名，任一套都能读到。
                            result.setdefault('traffic_limit_bytes', result.get('limit_bytes', 0))
                            result.setdefault('traffic_used_bytes', result.get('used_bytes', 0))
                    if conflict is not None:
                        # 锁内只判定；回包放在锁外，避免慢客户端阻塞 /auth。
                        return self.reply_json(conflict[0], {'ok': False, 'error': conflict[1]})
                    regenerate_page()
                    # 即使同值也重试权威同步；不得因上次写入已落盘而吞掉重载失败。
                    if not self._sync_reality_clients():
                        return self.reply_json(503, {'ok': False, 'error': 'Reality sync failed; retry required'})
                    return self.reply_json(200, {'ok': True, 'user_id': user_id, 'user': result})

                elif sub == 'users/renew':
                    user_id = str(params.get('user_id', '')).strip()
                    if not VALID_USER_ID_RE.match(user_id):
                        return self.reply_json(400, {'ok': False, 'error': 'Invalid user_id format'})
                    try:
                        raw_days = params.get('extend_days', 30)
                        if isinstance(raw_days, bool) or not str(raw_days).isascii() or not str(raw_days).isdigit():
                            raise ValueError()
                        days = int(raw_days)
                        raw_traffic = params.get('add_traffic_gb', 0)
                        if isinstance(raw_traffic, bool):
                            raise ValueError()
                        add_traffic_gb = float(raw_traffic)
                        if not 1 <= days <= 36500 or not math.isfinite(add_traffic_gb) or not 0 <= add_traffic_gb <= 1000000:
                            raise ValueError()
                        added_bytes = int(add_traffic_gb * (1024**3))
                    except (ValueError, TypeError, OverflowError):
                        return self.reply_json(400, {'ok': False, 'error': 'Invalid renewal: extend_days must be 1..36500; add_traffic_gb must be finite and 0..1000000'})
                    conflict = None
                    with data_lock:
                        u = data.get('users', {}).get(user_id)
                        if not u:
                            conflict = (404, 'User not found')
                        else:
                            # expires_at 可能是 None（「永久」的表示方式之一）：
                            # max(None, int) 会抛 TypeError，而这里在锁内、无兜底，
                            # 连接会被直接掐断（2026-10-29 修）。
                            try:
                                base_time = max(int(u.get('expires_at') or 0), now_ts)
                                new_expiry = int(base_time) + days * 86400
                                new_limit = int(u.get('limit_bytes', 0)) + added_bytes
                                if not 0 <= new_expiry <= 253402300799 or not 0 <= new_limit <= 2**63 - 1:
                                    raise ValueError()
                            except (ValueError, TypeError, OverflowError):
                                conflict = (400, 'Renewal exceeds supported limits')
                            else:
                                # 不能无条件写 status='active'：管理员因滥用手动停用的
                                # 用户，控制台一续费就会被静默恢复可用（2026-10-29 修）。
                                # 到期与否由 expires_at 判定，不依赖 status。
                                u.update(expires_at=new_expiry, limit_bytes=new_limit)
                                exp_at = u['expires_at']
                                lim_b = u.get('limit_bytes', 0)
                                status_now = u.get('status', 'active')
                    if conflict is not None:
                        # 锁内只判定；回包放在锁外，避免慢客户端阻塞 /auth。
                        return self.reply_json(conflict[0], {'ok': False, 'error': conflict[1]})
                    regenerate_page()
                    # 续费后立即同步协议客户端：过期用户续费后不必等 5 秒的
                    # 后台 worker 才恢复连接。
                    if not self._sync_reality_clients():
                        return self.reply_json(503, {'ok': False, 'error': 'Reality sync failed; retry required'})
                    return self.reply_json(200, {'ok': True, 'user_id': user_id,
                                                 'expires_at': exp_at, 'limit_bytes': lim_b,
                                                 'traffic_gb': round(lim_b / (1024**3), 3),
                                                 'status': status_now})

                elif sub == 'users/ip-deny':
                    # 跨节点统一设备上限（2026-10-30）：整份替换该用户的拦截 IP（空列表 = 解除）。
                    try:
                        user_id, entries = parse_ip_deny(params, time.time())
                    except ValueError as exc:
                        return self.reply_json(400, {'ok': False, 'error': str(exc)})
                    now_ts = time.time()
                    with data_lock:
                        before = active_ip_deny(global_ip_deny, user_id, now_ts)
                        if entries:
                            global_ip_deny[user_id] = dict(entries)
                        else:
                            global_ip_deny.pop(user_id, None)
                        recent = {ip for ip, t in ip_tracker.get(user_id, {}).items() if now_ts - t < IP_TIMEOUT_SECONDS}
                    # 只对「新加入拦截、且此刻在线」的 IP 踢一次：控制台每轮续期不会反复踢人。
                    fresh = set(entries) - before
                    online = recent | live_online_ips(user_id)
                    kicked = False
                    if fresh & online:
                        try:
                            kicked = kick_hy2_users(portal_path.parent, [user_id])
                        except Exception as exc:
                            _log_ignored('ip_deny_kick', exc)
                    return self.reply_json(200, {'ok': True, 'user_id': user_id,
                                                 'denied': sorted(entries), 'kicked': kicked})

                elif sub == 'users/delete':
                    user_id = str(params.get('user_id', '')).strip()
                    if not VALID_USER_ID_RE.match(user_id):
                        return self.reply_json(400, {'ok': False, 'error': 'Invalid user_id format'})
                    # 与 Web 表单同一条保护：机主账号注销 = 主密码在 /auth 里失效。
                    if user_id == MASTER_USER_ID:
                        return self.reply_json(400, {'ok': False, 'error': 'Cannot delete the master account'})
                    with data_lock:
                        data['_pending_revocations']=sorted(pending_revocations(data) | {user_id})
                        if user_id in data.get('users', {}):
                            del data['users'][user_id]
                            # 已删用户的累计用量不再有人读，留着只会让 portal.json 越写越大。
                            # 计数器游标不能删：服务没重启时同名用户再出现会被重复计数；
                            # 服务重启换 epoch 时 usage-meter-core 会自然丢弃它们。
                            drop_meter_totals(data, user_id)
                            if user_id in ip_tracker:
                                del ip_tracker[user_id]
                            # 速率样本同理：不删的话，同名用户重建后第一轮
                            # 速率会沿用旧样本算出尖峰（2026-10-25 修）。
                            speed_tracker.pop(user_id, None)
                            # 2026-10-03：同步删掉该用户的 Reality 身份。
                            # 不删的话 —— xray 里那个 UUID 还在，买家退了款
                            # 照样能用 Reality 连上，属于「钱退了货还在」。
                            reality_registry(data)
                            deleted = True
                        else:
                            deleted = False
                    regenerate_page()
                    if not apply_access([user_id]):
                        return self.reply_json(503, {'ok': False, 'error': 'Access revocation pending; retry required'})
                    return self.reply_json(200, {'ok': True, 'access_revoked': True, 'message': 'User deleted' if deleted else 'User already absent; revocation confirmed'})

                elif sub == 'users/set_status':
                    # 可恢复的停用/启用：只改 status，不动密码/到期/已用流量。
                    # 鉴权回调会检查 status（见 handle_auth），所以置为 disabled
                    # 后**已连接与再连接的客户端都会立刻被拒**。
                    # 重新置回 active 即原样恢复，买家不用重配 —— 这是与
                    # users/delete（不可恢复、且会清零 used_bytes）的关键区别。
                    user_id = str(params.get('user_id', '')).strip()
                    if not VALID_USER_ID_RE.match(user_id):
                        return self.reply_json(400, {'ok': False, 'error': 'Invalid user_id format'})
                    if 'active' not in params:
                        return self.reply_json(400, {'ok': False, 'error': 'Missing required field: active'})
                    want = 'active' if params.get('active') else 'disabled'
                    # 与 users/delete 同一条保护：机主账号不允许停用，
                    # 否则会出现"把面板自己锁在门外"的后果。
                    if user_id == MASTER_USER_ID and want != 'active':
                        return self.reply_json(400, {'ok': False, 'error': 'Cannot disable the master account'})
                    with data_lock:
                        u = data.get('users', {}).get(user_id)
                        missing = not u
                        if not missing:
                            before = u.get('status', 'active')
                            previous = dict(u)
                            u['status'] = want
                            rotate_user_view_key_on_change(previous, u)
                    if missing:
                        # 锁内只判定；回包放在锁外，避免慢客户端阻塞 /auth。
                        return self.reply_json(404, {'ok': False, 'error': 'User not found'})
                    regenerate_page()
                    # ⚠️ 2026-10-04 补：停用/启用必须同步到 xray。
                    #
                    # 原因：status 只在 hy2 的 handle_auth 里被检查，
                    # 而 Reality 走的是 xray 自己的 UUID 白名单 ——
                    # **不经过 handle_auth**。旧实现下停用后 Reality 仍可连
                    # （us2 实测停用后仍返回 204）。
                    #
                    # reality_clients() 现在会过滤掉 disabled 用户，
                    # 所以这里重写一次 xray.json 就能真正切断。
                    #
                    # 只在**状态真的变了**时才同步：重复调用同一状态
                    # （changed=False）不该触发 xray 重载 —— 面板可能轮询式调用，
                    # 每次都重启会撞 systemd 的 start-limit（10-03 踩过）。
                    if not self._sync_reality_clients():
                        return self.reply_json(503, {'ok': False, 'error': 'Reality sync failed; retry required'})
                    return self.reply_json(200, {
                        'ok': True,
                        'user_id': user_id,
                        'status': want,
                        # changed=false 表示本来就是该状态（幂等）。
                        # 调用方据此区分"真的改了"与"重复调用"。
                        'access_revoked': want != 'active',
                        'changed': before != want,
                    })

                elif sub == 'users/list':
                    # BUGFIX #10: 商城节点对账用, 列出所有动态用户 (脱敏不返回 password)
                    now_ts = int(time.time())
                    users_out = []
                    node_gaps = []
                    node_sources = {}
                    with data_lock:
                        for uid, info in users_list_rows(data.get('users')):
                            summary, node_gaps, node_sources = usage_list_summary(uid)
                            entry = users_list_entry(uid, info, ip_tracker, now_ts,
                                                     summary, IP_TIMEOUT_SECONDS)
                            if entry is not None:
                                users_out.append(entry)
                    return self.reply_json(200, {'ok': True, 'count': len(users_out), 'users': users_out,
                                                 'measurement_gaps': node_gaps,
                                                 'measurement_sources': node_sources})

                elif sub == 'proxy-services/add':
                    # API 通道此前没有异常保护：数据里某条代理的 port 被改坏时
                    # int() 抛 ValueError 会穿透 do_POST，连接被直接掐断
                    # （2026-10-29 修，与 users/create 同型）。
                    try:
                        status, payload = self._manage_proxy_operation('create', params)
                    except Exception as exc:
                        return self.reply_json(500, {'ok': False, 'error': 'proxy add failed: %s' % exc})
                    return self.reply_json(status, payload)

                elif sub == 'proxy-services/list':
                    with data_lock:
                        items = proxy_services(data)
                    m = read_meta_file(meta_path)
                    host = m.get('public_ip', '127.0.0.1') if m.get('is_insecure') else m.get('server_name', 'localhost')
                    # 不脱敏 password, 调用方是受信 API key
                    return self.reply_json(200, {
                        'ok': True,
                        'count': len(items),
                        'gost_installed': Path('/usr/local/bin/gost').exists(),
                        'gost_active': gost_status(),
                        'host': host,
                        'services': items,
                    })

                elif sub == 'proxy-services/delete':
                    try:
                        status, payload = self._manage_proxy_operation('delete', params)
                    except Exception as exc:
                        return self.reply_json(500, {'ok': False, 'error': 'proxy delete failed: %s' % exc})
                    return self.reply_json(status, payload)

                elif sub == 'node/suspend':
                    # 主控制台的节点流量限额：超额时停代理服务，新周期恢复。
                    if not isinstance(params.get('suspended'), bool):
                        return self.reply_json(400, {'ok': False, 'error': 'suspended must be a boolean'})
                    state, results = set_traffic_suspension(params['suspended'])
                    failed = [u for u, ok in results.items() if not ok]
                    return self.reply_json(200 if not failed else 500, {
                        'ok': not failed, 'suspended': state.get('suspended', False),
                        'units': results, 'failed': failed})

                return self.reply_json(404, {'ok': False, 'error': 'API endpoint not found'})

            # 普通 Web 请求限流
            if not self.check_rate_limit(bucket='web'):
                return self.reply(429, b'Too many requests')

            # 3. Web 网页版管理通道 (用户管理 / WARP 开关 / 触发升级)
            prefix = '/' + data['token'] + '/'
            if self.path == prefix + 'do-upgrade':
                return self._h_post_do_upgrade(prefix)

            if self.path == prefix + 'manage-proxy':
                return self._h_post_manage_proxy(prefix)

            if self.path == prefix + 'install-gost':
                return self._h_post_install_gost(prefix)

            # ---------------- AmneziaWG (AWG) ----------------
            if self.path == prefix + 'install-amneziawg':
                return self._h_post_install_amneziawg(prefix)

            if self.path == prefix + 'manage-amneziawg':
                return self._h_post_manage_amneziawg(prefix)

            if self.path == prefix + 'manage-warp':
                return self._h_post_manage_warp(prefix)

            if self.path == prefix + 'install-xray':
                return self._h_post_install_xray(prefix)

            if self.path == prefix + 'manage-reality':
                return self._h_post_manage_reality(prefix)

            if self.path == prefix + 'manage-vmess':
                return self._h_post_manage_vmess(prefix)

            if self.path == prefix + 'manage-vlessenc':
                return self._h_post_manage_vlessenc(prefix)

            if self.path == prefix + 'manage-anytls':
                return self._h_post_manage_anytls(prefix)

            if self.path == prefix + 'install-core':
                return self._h_post_install_core(prefix)

            if self.path == prefix + 'uninstall-core':
                return self._h_post_uninstall_core(prefix)

            if self.path == prefix + 'set-bbr':
                return self._h_post_set_bbr(prefix)

            if self.path == prefix + 'reboot-server':
                return self._h_post_reboot_server(prefix)

            if self.path == prefix + 'manage-user':
                return self._h_post_manage_user(prefix)

            # 4. Web 表单登录 / 退出
            if self.path == prefix + 'login':
                return self._h_post_login(prefix)

            # 退出登录（2026-10-29 加）：此前没有任何登出入口，勾了「记住我」
            # 的用户只能去浏览器里手删 Cookie，共用电脑时不安全。
            if self.path == prefix + 'logout':
                self.send_response(302)
                self._responded = True
                self.send_header('Location', prefix)
                self.send_header('Set-Cookie',
                                 'hy2_session=; Path=/%s/; HttpOnly; SameSite=Strict; Secure; Max-Age=0'
                                 % data['token'])
                self.send_header('Cache-Control', 'no-store')
                self.send_header('Connection', 'close')
                self.end_headers()
                return

            if self.path == prefix + 'install-warp':
                return self._h_post_install_warp(prefix)

            # ---------------- 自定义出站（写） ----------------
            if self.path == prefix + 'manage-outbounds':
                return self._ob_manage()


            return self.reply(404, b'Not found')

        # ==========================================================================
        # do_POST 各端点的处理逻辑
        # --------------------------------------------------------------------------
        # 原先 13 个端点全都内联在 do_POST 里（1245 行），靠 if 的先后顺序阅读，
        # 分支之间还会互相干扰 —— 改一处要通读全篇才能确认没踩到别人。
        # 现在每个端点一个方法，do_POST 只负责分发。
        # ⚠️ 这里是纯代码搬移，逻辑一行未改。data / data_lock / save_data 等
        # 是 serve() 的闭包变量，方法在 serve() 内的类里定义，照常可访问。
        # ==========================================================================

        def _h_post_do_upgrade(self, prefix):
            if not self.is_authenticated():
                return self.reply_json(401, {'ok': False, 'error': 'Unauthorized'})
            if not portal_upgrade_lock.acquire(blocking=False):
                return self.reply_json(409, {'ok': False, 'error': '已有门户更新在执行，请等待核验'})
            try:
                return self._h_post_do_upgrade_impl(prefix)
            finally:
                portal_upgrade_lock.release()

        def _h_post_do_upgrade_impl(self, prefix):
            """POST /do-upgrade 的处理逻辑（从 do_POST 机械搬移而来）。"""
            if not self.is_authenticated():
                return self.reply_json(401, {'ok': False, 'error': 'Unauthorized'})
            update_lock_fd = None
            try:
                length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(length).decode('utf-8', errors='replace')
                form = parse_qs(body)
                target = form.get('target', [''])[0]
                if target not in ('core', 'portal', 'awg', 'reality-online'):
                    return self.reply_json(400, {'ok': False, 'error': 'Invalid target'})

                if target == 'reality-online':
                    # 开启在线统计要重启 xray；流量超额停用期间重启等于替 Reality 解除停用。
                    if unit_suspended('xray'):
                        return self.reply_json(409, {'ok': False, 'error': '节点因流量超额停用中，请在控制台恢复节点后再开启'})
                    cfg_path = portal_path.parent / 'usage-meter-config.json'
                    cfg = json.loads(cfg_path.read_text(encoding='utf-8')).get('reality', {})
                    spec = importlib.util.spec_from_file_location('reality_online_config', Path(__file__).parent / 'usage-meter-xray-config-20261007-v1.py')
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    with reality_apply_lock:
                        outcome = module.enable_reality_online(str(portal_path.parent / 'xray.json'), cfg['binary'], cfg['address'])
                    return self.reply_json(200, {'ok': True, 'reality_online': outcome})

                if target == 'portal':
                    ref = form.get('ref', ['main'])[0]
                    if ref != 'main' and not re.fullmatch(r'[0-9a-f]{40}', ref):
                        return self.reply_json(400, {'ok': False, 'error': 'Invalid immutable ref'})
                    try:
                        update_lock_fd = portal_update_process_lock(PORTAL_SELF.parent)
                    except BlockingIOError:
                        return self.reply_json(409, {'ok': False, 'error': '已有门户更新在执行，请等待核验'})
                    restart_prefix = portal_update_restart_prefix()
                    # 六个文件 × 三个源 × 30 秒超时 + blob 校验，最坏远超
                    # 30 秒默认死线：不抬死线，更新结果永远送不回浏览器
                    # （副作用照常发生，面板却显示失败/无响应，2026-10-28 修）。
                    self._extend_deadline(600)
                    # 门户前后端与四个计量模块必须一起更新，避免新旧回调接口不兼容。
                    # 🔴 必须成对更新 —— 门户同时是 Hysteria 的鉴权后端，
                    # 只换其中一个会让它起不来、所有客户端连不上。
                    # 所以流程是：两个都取回 → 都做语法校验 → 再一起原子替换；
                    # 任一环节失败就整体放弃，磁盘上不留下任何改动。
                    #
                    # 自更新不走 do_upgrade.sh：那个脚本从 raw.githubusercontent.com
                    # 拉文件，会踩 raw 的 CDN 缓存（实测 push 后数分钟仍返回旧内容），
                    # 表现为"更新完还是旧版"。这里用多源回退直接取。
                    ref = resolve_update_ref(ref)
                    fetched = []
                    # 标记必须按文件各选各的 —— 踩过：给 portal_assets.py 用了
                    # b'hysteria2-installer'，但那个字符串只存在于 portal.py 里，
                    # 于是三个源全被判成"内容不对"，自更新永远失败。
                    # 现在 portal_assets.py 用 b'SCRIPT = r'：既确实存在，
                    # 又顺带校验了「JS 常量仍是原始字符串」这个关键属性。
                    #
                    # 🔴 除 marker + 语法外，每个文件还必须与**所 pin commit 的 git blob
                    #    身份**一致。jsDelivr / raw 可能与所 pin 的 commit 不符（缓存污染
                    #    或 CDN 侧篡改），只校验 marker 挡不住：内容含 marker 且语法合法
                    #    就会被写成 root 运行的面板代码。
                    for fname, marker, minsize in (('portal.py', b'hysteria2-installer', 20000),
                                                   ('portal_assets.py', b'SCRIPT = r', 10000),
                                                   ('usage-meter-core-20261007-v1.py', b'ACCOUNTING_REVISION = "2026-10-12-real-usage-v2"', 1024),
                                                   ('usage-meter-readers-20261007-v1.py', b'def read_hysteria', 1024),
                                                   ('usage-meter-runtime-20261007-v1.py', b'ACCOUNTING_REVISION = "2026-10-12-real-usage-v2"', 1024),
                                                   ('usage-meter-xray-config-20261007-v1.py', b'def add_stats', 1024)):
                        expected = _remote_blob_sha(fname, marker=marker, ref=ref)
                        if not expected:
                            return self.reply_json(500, {'ok': False, 'error':
                                '取不到 %s@%s 的预期 blob 身份 —— 已放弃更新，面板保持原样'
                                % (fname, ref[:7])})
                        content = _fetch_repo_file(fname, marker=marker, min_size=minsize,
                                                   ref=ref, expect_blob=expected)
                        if content is None:
                            return self.reply_json(500, {'ok': False, 'error':
                                '取不到 %s（三个源均失败或内容与 %s 不符）—— 已放弃更新，面板保持原样'
                                % (fname, ref[:7])})
                        try:
                            ast.parse(content.decode('utf-8'))
                        except Exception as e:
                            return self.reply_json(500, {'ok': False, 'error':
                                '%s 未通过 Python 语法校验（%s）—— 已放弃更新' % (fname, e)})
                        fetched.append((fname, content))

                    base_dir = PORTAL_SELF.parent
                    backups = []
                    created = []
                    changed = False
                    try:
                        for fname, content in fetched:
                            dest = base_dir / fname
                            try:
                                if dest.read_bytes() == content:
                                    continue          # 内容一致就不动它
                            except Exception:
                                pass
                            if dest.exists():
                                bak = Path(str(dest) + '.bak')
                                shutil.copy2(str(dest), str(bak))
                                backups.append((dest, bak))
                            else:
                                created.append(dest)
                            tmp = str(dest) + '.new'
                            with open(tmp, 'wb') as fh:
                                fh.write(content)
                            os.chmod(tmp, 0o644)
                            os.replace(tmp, str(dest))
                            changed = True
                        if changed:
                            # scope 内脚本 ready/go 握手完成才交接；失败也走整包回滚。
                            portal_start_update(
                                restart_prefix, portal_update_restart_script(data['port'], backups, created),
                                update_lock_fd)
                    except Exception as e:
                        # 出错就把已替换的恢复回去，绝不留下半新半旧的状态
                        for dest, bak in backups:
                            try:
                                shutil.copy2(str(bak), str(dest))
                            except Exception as exc:
                                _log_ignored('portal_update.rollback', exc)
                        for dest in created:
                            Path(dest).unlink(missing_ok=True)
                        return self.reply_json(500, {'ok': False, 'error':
                            '更新过程中出错，已回滚到原版本：%s' % e})

                    if not changed:
                        return self.reply_json(200, {'ok': True, 'target': target,
                                                     'message': '面板已是最新，无需更新'})
                    # 已就绪的独立 scope 子脚本持锁至重启、核验与回滚结束。
                    # 父 handler 的 finally 只关闭自己的 fd，绝不 LOCK_UN。
                    return self.reply_json(200, {'ok': True, 'target': target,
                                                 'message': '面板已更新（后端 + 前端资源），服务重启中'})

                if target == 'awg':
                    if not awg_installed():
                        return self.reply_json(400, {'ok': False,
                                                     'error': 'AmneziaWG 尚未安装'})
                    # 先刷新控制脚本自身，再更新二进制。不需要重启面板。
                    ensure_awgctl(force=True)
                    # awgctl update 要下载并核验二进制，超时 420 秒。
                    self._extend_deadline(480)
                    rc, out, err = awg_run(['update'], timeout=420)
                    if rc != 0:
                        return self.reply_json(500, {'ok': False,
                            'error': 'AWG 更新失败：' + awg_err_tail(rc, out, err)})
                    return self.reply_json(200, {'ok': True, 'target': target,
                                                 'message': 'AmneziaWG 引擎已更新，客户端无需重新导入'})

                # core 仍交给 do_upgrade.sh：下载的是 Hysteria 官方发布，
                # 与 raw 的 CDN 缓存无关。
                allow_custom = form.get('allow_custom', ['0'])[0] == '1'
                with data_lock:
                    _job_now = data.get('core_upgrade')
                    _busy = isinstance(_job_now, dict) and _job_now.get('state') == 'running'
                    if not _busy:
                        data['core_upgrade'] = {'state': 'running', 'started_at': int(time.time())}
                if _busy:
                    # 锁内只判定；回包放在锁外，避免慢客户端阻塞 /auth。
                    return self.reply_json(409, {'ok': False, 'error': '核心更新仍在运行，请等待完成'})
                save_data()
                def upgrade_worker():
                    try:
                        result = upgrade_core_binary(allow_custom=allow_custom)
                        job = dict(result, state='completed')
                    except Exception as exc:
                        job = {'state': 'failed', 'error': str(exc)}
                    with data_lock:
                        data['core_upgrade'] = dict(job, finished_at=int(time.time()))
                        _core_ver_cache['t'] = 0.0
                    save_data()
                try:
                    self.reply_json(200, {'ok': True, 'target': 'core', 'applying': True,
                        'message': '核心更新任务已接受，下载、应用和回滚结果将单独核验'})
                finally:
                    threading.Thread(target=upgrade_worker, daemon=True).start()
                return
            except Exception as e:
                return self.reply_json(500, {'ok': False, 'error': ('%s: %s' % (type(e).__name__, str(e)))[:160]})
            finally:
                if update_lock_fd is not None:
                    os.close(update_lock_fd)

        def _manage_proxy_operation(self, action, params):
            if action not in ('create', 'delete'):
                return 400, {'ok': False, 'error': 'Invalid action'}
            with gost_operation_lock:
                if not Path('/usr/local/bin/gost').exists():
                    return 409, {'ok': False, 'error': '请先安装 GOST，再创建代理服务'}
                with data_lock:
                    # 保留原始值用于回滚；工作副本只取合法条目，
                    # 否则容器被改坏后追加/筛选都会抛异常。
                    previous = copy.deepcopy(data.get('proxy_services', []))
                    working = proxy_services(data)
                if action == 'create':
                    ptype = str(params.get('protocol') or params.get('type') or 'socks5').lower()
                    if ptype not in ('socks5', 'http', 'https'):
                        return 400, {'ok': False, 'error': 'Invalid proxy type'}
                    raw_port = str(params.get('port') or '').strip()
                    try:
                        port = int(raw_port) if raw_port else 0
                    except (TypeError, ValueError):
                        return 400, {'ok': False, 'error': 'Invalid port'}
                    if raw_port and not 1 <= port <= 65535:
                        return 400, {'ok': False, 'error': 'Port must be in 1..65535'}
                    if ptype == 'https':
                        # 没有可用证书时给 400 + 可读原因，而不是 500 的
                        # 「proxy add failed: ...」（2026-10-30 修）。
                        try:
                            gost_tls_paths(portal_path.parent)
                        except RuntimeError as exc:
                            return 400, {'ok': False, 'error': str(exc)}
                    existing = set()
                    for item in previous:
                        try:
                            existing.add(int(item['port']))
                        except (KeyError, TypeError, ValueError):
                            continue
                    # 自动选端口时必须避开本机已知的端口：
                    # Hy2 主端口、订阅端口、各协议端口、已在监听的端口。
                    # 旧实现只在 12000-58000 里随机，撞上订阅端口就会
                    # 「保存成功但 gost 起不来」，然后回滚（2026-10-30 修）。
                    _meta_now = read_meta_file(meta_path)
                    try:
                        _cfg_now = json.loads(Path('/etc/hysteria/xray.json').read_text(encoding='utf-8'))
                    except (OSError, ValueError):
                        _cfg_now = None
                    with data_lock:
                        _data_now = dict(data)
                    _avoid = managed_reserved_ports(_meta_now, _data_now, _cfg_now)
                    _avoid |= _listening_ports()
                    if port and port in _avoid:
                        # 显式端口也要检查：否则 gost 起不来 → 回滚 →
                        # 用户只看到「应用失败」（2026-10-30 修）。
                        return 400, {'ok': False, 'error':
                            '端口 %d 已被本机占用（Hy2 / 订阅 / 其它服务），请换一个' % port}
                    candidates = [port] if port else [random.randint(12000, 58000) for _ in range(100)]
                    selected = 0
                    for candidate in candidates:
                        # 不再用 socket.bind 探测：本文件别处（gost 段）明确记着
                        # 「bind 探测在某些环境会卡住」。_avoid 已经包含 `ss`
                        # 读到的监听端口，判断它即可（2026-10-30 修）。
                        if candidate in existing or candidate in _avoid                                 or (not port and 20000 <= candidate <= 40000):
                            continue
                        selected = candidate
                        break
                    if not selected:
                        return 400, {'ok': False, 'error': '指定端口已占用，或无法找到空闲端口'}
                    port = selected
                    username = str(params.get('username') or '').strip()[:64] or ('user_' + secrets.token_hex(4))
                    password = str(params.get('password') or '').strip() or secrets.token_hex(12)
                    if ptype in ('http', 'https') and ':' in username:
                        return 400, {'ok': False, 'error': 'HTTP Basic 认证用户名不能包含冒号'}
                    if ptype == 'socks5' and (len(username.encode('utf-8')) > 255 or len(password.encode('utf-8')) > 255):
                        return 400, {'ok': False, 'error': 'SOCKS5 账号或密码不能超过 255 字节'}
                    entry = {'id': 'proxy_' + secrets.token_hex(6), 'type': ptype, 'port': port,
                             'username': username, 'password': password, 'created_at': int(time.time()),
                             'note': str(params.get('note') or '').strip()[:200]}
                    with data_lock:
                        data['proxy_services'] = working + [entry]
                else:
                    proxy_id = str(params.get('id') or '').strip()
                    if not proxy_id:
                        return 400, {'ok': False, 'error': 'Missing id'}
                    remaining = [item for item in working if item.get('id') != proxy_id]
                    if len(remaining) == len(working):
                        return 404, {'ok': False, 'error': 'Proxy service not found'}
                    with data_lock:
                        data['proxy_services'] = remaining
                save_data()
                if not reload_gost():
                    with data_lock:
                        data['proxy_services'] = previous
                    save_data()
                    reload_gost()
                    return 500, {'ok': False, 'applied': False,
                        'error': 'GOST 配置未成功应用或端口未监听，代理记录已恢复；请检查服务日志'}
                if action == 'delete':
                    for item in working:
                        if item.get('id') == proxy_id:
                            firewall_port(item.get('port'), 'tcp', open_=False)
                    return 200, {'ok': True, 'applied': True, 'message': 'Proxy service deleted'}
                # 开着 ufw / firewalld 的系统上不放行的话，本机探测一切正常、外网却连不上。
                firewall_port(port, 'tcp', open_=True)
                m = read_meta_file(meta_path)
                host = m.get('public_ip', '127.0.0.1') if m.get('is_insecure') else m.get('server_name', 'localhost')
                host_part = '[' + host + ']' if ':' in host and not host.startswith('[') else host
                uri = '%s://%s:%s@%s:%s' % (ptype, quote(username, safe=''), quote(password, safe=''), host_part, port)
                qr_svg = ''
                try:
                    qr = subprocess.run(['qrencode', '-t', 'SVG', '-o', '-'], input=uri.encode(),
                                        capture_output=True, timeout=3)
                    if qr.returncode == 0:
                        qr_svg = qr.stdout.decode('utf-8')
                except Exception as exc:
                    _log_ignored('qr_svg', exc)
                return 200, dict(entry, ok=True, applied=True, host=host, url=uri, qr=qr_svg,
                                 format='%s:%s:%s:%s' % (host, port, username, password), gost_active=True)

        def _h_post_manage_proxy(self, prefix):
            if not self.is_authenticated():
                return self.reply_json(401, {'ok': False, 'error': 'Unauthorized'})
            try:
                length = int(self.headers.get('Content-Length', 0))
                form = parse_qs(self.rfile.read(length).decode('utf-8', errors='replace'))
                params = {key: values[0] for key, values in form.items()}
                status, payload = self._manage_proxy_operation(params.pop('action', ''), params)
                return self.reply_json(status, payload)
            except Exception as exc:
                return self.reply_json(500, {'ok': False, 'error': str(exc)})

        def _h_post_install_gost(self, prefix):
            """POST /install-gost 的处理逻辑（从 do_POST 机械搬移而来）。"""
            if not self.is_authenticated():
                return self.reply_json(401, {'ok': False, 'error': 'Unauthorized'})
            try:
                # 下载走多源回退、单源 180 秒超时：默认 30 秒连接死线
                # 会先一步关掉连接（2026-10-28 修，见 _extend_deadline）。
                self._extend_deadline(600)
                if Path('/usr/local/bin/gost').exists():
                    version = subprocess.run(['/usr/local/bin/gost', '-V'], capture_output=True, timeout=5)
                    if version.returncode == 0:
                        if not reload_gost():
                            return self.reply_json(500, {'ok': False, 'error': 'GOST 修复失败或端口未就绪，请检查日志'})
                        return self.reply_json(200, {'ok': True, 'applied': True, 'message': 'GOST 已恢复运行，监听端口已核对'})
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

                # 先从该版本的**官方** checksums.txt 取预期摘要；取不到就不装。
                # 第三方镜像（ghfast / moeyy）只能作传输候选，不能提供可信摘要：
                # 它们必须与官方摘要逐字节一致才会被接受。
                expected = fetch_expected_sha256(
                    f"https://github.com/go-gost/gost/releases/download/{tag}/checksums.txt",
                    pkg_name)
                if not expected:
                    return self.reply_json(500, {'ok': False, 'error':
                        '取不到 gost %s 的官方校验清单（checksums.txt）或其中没有 %s —— '
                        '无法验证下载内容，已放弃安装' % (tag, pkg_name)})

                download_urls = [
                    f"https://github.com/go-gost/gost/releases/download/{tag}/{pkg_name}",
                    f"https://ghfast.top/https://github.com/go-gost/gost/releases/download/{tag}/{pkg_name}",
                    f"https://github.moeyy.xyz/https://github.com/go-gost/gost/releases/download/{tag}/{pkg_name}"
                ]

                installed = False
                errors = []
                with tempfile.TemporaryDirectory() as tmpdir:
                    archive_path = Path(tmpdir) / 'gost.tar.gz'
                    for u in download_urls:
                        host = u.split('/')[2] if '//' in u else u
                        try:
                            req = urllib.request.Request(u, headers={'User-Agent': 'Mozilla/5.0'})
                            # 超时给足：包有 ~17MB，30 秒在慢线路上不够
                            with urllib.request.urlopen(req, timeout=180) as resp, open(archive_path, 'wb') as out_f:
                                shutil.copyfileobj(resp, out_f)
                            if not verify_sha256(archive_path, expected):
                                errors.append('%s: SHA256 与官方 checksums.txt 不一致' % host)
                                continue
                            if not tarfile.is_tarfile(str(archive_path)):
                                errors.append('%s: 内容不是有效 tar.gz' % host)
                                continue
                            src_bin = Path(tmpdir) / 'gost'
                            with tarfile.open(str(archive_path), 'r:gz') as tar:
                                # 拒绝绝对路径 / `..`，且只接受唯一精确同名的常规成员
                                member_name = safe_tar_members(
                                    [m.name for m in tar.getmembers()], 'gost')
                                member = next(m for m in tar.getmembers()
                                              if m.name == member_name and m.isfile())
                                with tar.extractfile(member) as source, open(src_bin, 'wb') as dest:
                                    shutil.copyfileobj(source, dest)
                            if src_bin.exists():
                                staged = Path('/usr/local/bin/gost.new')
                                shutil.copyfile(str(src_bin), str(staged))
                                os.chmod(str(staged), 0o755)
                                os.replace(str(staged), '/usr/local/bin/gost')
                                installed = True
                                break
                            errors.append('%s: 包内没有 gost 可执行文件' % host)
                        except Exception as e:
                            errors.append('%s: %s: %s' % (host, type(e).__name__, e))

                if not installed:
                    # 把【每个源】的错误都报出来。
                    # 只显示最后一个源的错误会掩盖真正原因 —— 例如首个源超时、
                    # 末个源 DNS 失败时，用户只会看到 DNS 错误，完全被带偏。
                    return self.reply_json(500, {'ok': False,
                                                 'error': '下载或解压 GOST 失败 —— ' + ' ｜ '.join(errors)})

                # 确保 systemd 服务存在
                # 先落地启动自检脚本 (unit 的 ExecStartPost 会调用它), 再写 unit.
                write_gost_selfcheck()
                service_content = GOST_UNIT_CONTENT
                Path('/etc/systemd/system/gost.service').write_text(service_content, encoding='utf-8')
                subprocess.run(['systemctl', 'daemon-reload'], capture_output=True, timeout=30)
                subprocess.run(['systemctl', 'enable', 'gost'], capture_output=True, timeout=30)

                # 重新生成 gost.yml 并启动服务
                if not reload_gost():
                    return self.reply_json(500, {'ok': False, 'error': 'GOST 已安装，但服务或监听端口未就绪'})

                # 核实真的起来了 —— 不谎报成功 (见技能 §12).
                # `is-active` 为 active 但端口未绑定, 是本项目踩过的静默故障.
                if not gost_status():
                    return self.reply_json(500, {'ok': False,
                                                 'error': 'GOST 已安装但服务未启动成功，请查看 journalctl -u gost -n 20'})
                return self.reply_json(200, {'ok': True, 'message': f'GOST {tag} 官方核心安装成功，服务已自动配置并启动！'})
            except Exception as e:
                return self.reply_json(500, {'ok': False, 'error': f'执行异常: {str(e)}'})

        def _h_post_install_amneziawg(self, prefix):
            """POST /install-amneziawg 的处理逻辑（从 do_POST 机械搬移而来）。"""
            if not self.is_authenticated():
                return self.reply_json(401, {'ok': False, 'error': 'Unauthorized'})
            try:
                length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(length).decode('utf-8', errors='replace')
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
                # 连接地址必须是「域名或 IP:端口」形态：含换行/空白会让
                # render_client_config 把任意行注入客户端配置文件（2026-10-28 修）。
                if not VALID_AWG_ENDPOINT_RE.fullmatch(endpoint):
                    return self.reply_json(400, {'ok': False,
                        'error': '连接地址只能是域名或 IP（可带 :端口），不允许换行、空格或特殊字符'})
                # 端口若由用户指定，提前拦掉会与 Hysteria2 端口跳跃冲突的取值
                if port:
                    if not port.isdigit() or not (1 <= int(port) <= 65535):
                        return self.reply_json(400, {'ok': False, 'error': '端口必须是 1-65535 的数字'})
                    if 20000 <= int(port) <= 40000:
                        return self.reply_json(400, {'ok': False, 'error': '该端口落在 Hysteria2 的端口跳跃区间 20000-40000 内，会导致 AWG 收不到握手包，请改用 50000-59000'})
                if not ensure_awgctl():
                    return self.reply_json(500, {'ok': False, 'error': '无法获取 hy2-awgctl（服务器可能无法访问 github.com），请手动执行 install.sh 的 AmneziaWG 菜单'})
                # 安装要下载并核验两个二进制，awgctl 超时 420 秒。
                self._extend_deadline(480)

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

        def _h_post_manage_amneziawg(self, prefix):
            """POST /manage-amneziawg 的处理逻辑（从 do_POST 机械搬移而来）。"""
            if not self.is_authenticated():
                return self.reply_json(401, {'ok': False, 'error': 'Unauthorized'})
            try:
                length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(length).decode('utf-8', errors='replace')
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

                # update / set_line 的 awgctl 超时给到 420 秒（要下载并交叉
                # 验证二进制），必须先把连接死线抬到覆盖全程。
                if action in ('set_line', 'update'):
                    self._extend_deadline(480)

                if action == 'peer_add':
                    name = (form.get('name', [''])[0] or '').strip()
                    endpoint = (form.get('endpoint', [''])[0] or '').strip()
                    if not VALID_AWG_NAME_RE.match(name):
                        return self.reply_json(400, {'ok': False, 'error': '客户端名称只允许字母、数字、点、下划线、连字符，长度 1-32'})
                    if not endpoint:
                        return self.reply_json(400, {'ok': False, 'error': '必须提供连接地址'})
                    # 与安装通道同一校验：换行/空白能注入客户端配置行（2026-10-28 修）。
                    if not VALID_AWG_ENDPOINT_RE.fullmatch(endpoint):
                        return self.reply_json(400, {'ok': False,
                            'error': '连接地址只能是域名或 IP（可带 :端口），不允许换行、空格或特殊字符'})
                    # peer-add 会生成密钥并渲染服务端配置，90 秒超时。
                    self._extend_deadline(120)
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
                    # 先把控制工具自身刷新到最新，否则引擎会永久停在首装版本
                    ensure_awgctl(force=True)
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

        def _egress_pending_count(value):
            """待应用计数；被改坏成非数字时按 0 处理。

            旧写法 int(data.get('_egress_pending', 0)) 在值是 "abc"/列表/None 时
            抛异常，位置在**返回响应之前** —— 用户点了「应用」，请求直接 500，
            而配置其实一行都没写。
            """
            if isinstance(value, bool):
                return 0
            try:
                return max(0, int(value))
            except (TypeError, ValueError, OverflowError):
                return 0

        def _reply_with_egress_apply(self, payload, kind='outbound'):
            with data_lock:
                data['egress_applying'] = True
                data['_egress_pending'] = _egress_pending_count(data.get('_egress_pending')) + 1
            save_data()
            def worker():
                with warp_apply_lock:
                    try:
                        applied, error = apply_egress_config(data, data_lock)
                    except Exception as exc:
                        applied, error = False, '应用出站失败: %s' % type(exc).__name__
                    with data_lock:
                        pending = max(0, _egress_pending_count(data.get('_egress_pending')) - 1)
                        if pending:
                            data['_egress_pending'] = pending
                        else:
                            data.pop('_egress_pending', None)
                            data.pop('egress_applying', None)
                            data.pop('warp_applying', None)
                        key = 'warp_apply_error' if kind == 'warp' else 'outbound_apply_error'
                        if error:
                            data[key] = error
                            data['egress_apply_error'] = error
                        else:
                            data.pop(key, None)
                            data.pop('egress_apply_error', None)
                    save_data()
                    if not applied:
                        print('[portal] egress apply failed: %s' % error, file=sys.stderr, flush=True)
            try:
                self.reply_json(200, dict(payload, ok=True, applying=True, applied=False))
            finally:
                threading.Thread(target=worker, daemon=True).start()

        def _reply_with_warp_apply(self, payload):
            return self._reply_with_egress_apply(payload, kind='warp')

        def _h_post_manage_warp(self, prefix):
            """POST /manage-warp 的处理逻辑（从 do_POST 机械搬移而来）。"""
            if not self.is_authenticated():
                return self.reply_json(401, {'ok': False, 'error': 'Unauthorized'})
            try:
                length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(length).decode('utf-8', errors='replace') if length > 0 else ''
                form = parse_qs(body)
                action = form.get('action', ['toggle'])[0]
                if action not in ('toggle', 'enable', 'disable', 'apply',
                                  'add_rule', 'del_rule', 'reset_rules'):
                    return self.reply_json(400, {'ok': False, 'error': '未知 WARP 操作'})

                bad_domain = False
                with data_lock:
                    rules = normalize_route_rules(data.get('warp_rules', DEFAULT_WARP_DOMAINS))
                    if action == 'toggle':
                        data['warp_enabled'] = not bool(data.get('warp_enabled'))
                    elif action in ('enable', 'disable'):
                        data['warp_enabled'] = action == 'enable'
                    elif action == 'add_rule':
                        raw = form.get('domain', [''])[0].strip().lower()
                        domain = re.sub(r'^[a-zA-Z]+://', '', raw).split('/')[0].split(':')[0].strip('.')
                        if not domain or not re.fullmatch(r'[a-z0-9.-]+', domain):
                            bad_domain = True
                        else:
                            rules = [r for r in rules if r['domain'] != domain]
                            rules.append({'domain': domain, 'outbound': 'warp_socks'})
                    elif action == 'del_rule':
                        domain = form.get('domain', [''])[0].strip().lower()
                        rules = [r for r in rules if not (r['domain'] == domain and r['outbound'] in ('warp', 'warp_socks'))]
                    elif action == 'reset_rules':
                        rules = [r for r in rules if r['outbound'] not in ('warp', 'warp_socks')]
                        keep = {r['domain'] for r in rules}
                        rules.extend({'domain': d, 'outbound': 'warp_socks'} for d in DEFAULT_WARP_DOMAINS if d not in keep)
                    data['warp_rules'] = rules
                    new_state = bool(data.get('warp_enabled'))
                    current_rules = [r['domain'] for r in rules if r['outbound'] in ('warp', 'warp_socks')]

                if bad_domain:
                    # 锁内只判定；回包放在锁外，避免慢客户端阻塞 /auth。
                    return self.reply_json(400, {'ok': False, 'error': '域名格式不正确'})
                save_data()

                return self._reply_with_warp_apply({
                    'enabled': new_state,
                    'rules': current_rules,
                })
            except Exception as e:
                return self.reply_json(500, {'ok': False, 'error': ('%s: %s' % (type(e).__name__, str(e)))[:160]})

        def _h_post_install_xray(self, prefix):
            """POST /install-xray 的处理逻辑（从 do_POST 机械搬移而来）。"""
            if not self.is_authenticated():
                return self.reply_json(401, {'ok': False, 'error': 'Unauthorized'})
            try:
                # 三个下载源 × 45 秒 + 校验/解压，全程远超 30 秒默认死线。
                self._extend_deadline(300)
                ok, msg = install_xray_binary()
                if not ok:
                    return self.reply_json(500, {'ok': False, 'error': msg})

                write_xray_unit()
                subprocess.run(['systemctl', 'enable', 'xray'], capture_output=True, timeout=30)
                self._generate_and_apply_reality(True)

                # 不要谎报成功：xray 默认监听 TCP 443，若该端口已被别的服务
                # （Caddy / Nginx 等）占用就根本起不来。必须核实服务状态 ——
                # 否则用户只会看到"安装成功"却怎么都用不了，且不知道该查什么。
                time.sleep(2)
                xr_state = subprocess.run(['systemctl', 'is-active', 'xray'],
                                          capture_output=True, text=True, timeout=5).stdout.strip()
                if xr_state != 'active':
                    xr_log = subprocess.run(['journalctl', '-u', 'xray', '-n', '8', '--no-pager'],
                                            capture_output=True, text=True, timeout=5).stdout
                    return self.reply_json(500, {'ok': False, 'error':
                        'Xray 已安装但服务未能启动（当前状态 %s）。'
                            '最常见原因是 TCP 443 已被其他服务（如 Caddy / Nginx）占用。'
                            '日志尾部：%s' % (xr_state, xr_log.strip()[-400:])})

                return self.reply_json(200, {'ok': True, 'message': 'Xray-core 安装成功，VLESS-Reality 已在 TCP %s 端口就绪！' % data.get('reality_config', {}).get('port', '')})
            except Exception as e:
                return self.reply_json(500, {'ok': False, 'error': f'安装执行异常: {str(e)}'})

        def _h_post_manage_reality(self, prefix):
            """POST /manage-reality 的处理逻辑（从 do_POST 机械搬移而来）。"""
            if not self.is_authenticated():
                return self.reply_json(401, {'ok': False, 'error': 'Unauthorized'})
            try:
                length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(length).decode('utf-8', errors='replace') if length > 0 else ''
                form = parse_qs(body)
                action = form.get('action', ['toggle'])[0]

                if action == 'toggle':
                    # 🔴 只动 Reality 自己的入站（2026-10-24 修）。
                    # 旧实现用 `systemctl stop xray` 关闭 Reality —— 那会把
                    # 同一进程里的 VMess / VLESS Encryption 一起停掉；
                    # 而开启时又直接 restart，会把用户先前**主动关掉**的
                    # 其它协议一并复活。现在与另两个协议同一套语义：
                    # 移除/写回自己的入站，再重启一次（restart，不是 stop）。
                    xray_path = Path('/etc/hysteria/xray.json')
                    try:
                        cfg_now = (json.loads(xray_path.read_text(encoding='utf-8'))
                                   if xray_path.exists() else None)
                    except ValueError:
                        return self.reply_json(500, {'ok': False, 'error':
                            'xray.json 不是合法 JSON，未做任何修改'})
                    reality_on = bool(cfg_now) and has_managed_inbound(cfg_now, REALITY_INBOUND_TAG)
                    if reality_on:
                        with reality_apply_lock:
                            try:
                                current = json.loads(xray_path.read_text(encoding='utf-8'))
                            except (OSError, ValueError):
                                current = cfg_now
                            remove_managed_inbound(current, REALITY_INBOUND_TAG)
                            apply_xray_config_transaction(
                                current, config_path=str(xray_path),
                                binary='/usr/local/bin/xray',
                                restart=not unit_suspended('xray'))
                        new_active = False
                    else:
                        if unit_suspended('xray'):
                            return self.reply_json(409, {'ok': False, 'error': '节点因流量超额停用中，Reality 将在控制台恢复节点时自动启动'})
                        # _generate_and_apply_reality 内部已加锁并做事务重启。
                        self._generate_and_apply_reality(True)
                        if not Path('/usr/local/bin/xray').exists():
                            return self.reply_json(500, {'ok': False, 'error': 'Xray 未安装'})
                        actual = subprocess.run(['systemctl', 'is-active', 'xray'],
                                                capture_output=True, text=True, timeout=3).stdout.strip()
                        if actual != 'active':
                            return self.reply_json(500, {'ok': False, 'error': 'Reality 尚未运行，不能报告已开启'})
                        new_active = True
                    return self.reply_json(200, {'ok': True, 'active': new_active})

                elif action == 'reset':
                    # force=True：只有「重置密钥」按钮才真的换密钥对。
                    # 用户的 UUID 是 uuid5 派生的，不受密钥轮换影响。
                    self._generate_and_apply_reality(True, force=True)
                    return self.reply_json(200, {'ok': True, 'message': '已重置密钥并重启生效'})

                return self.reply_json(400, {'ok': False, 'error': 'Invalid action'})
            except Exception as e:
                return self.reply_json(500, {'ok': False, 'error': ('%s: %s' % (type(e).__name__, str(e)))[:160]})

        def _vmess_certificate(self, domain, protocol='VMess'):
            """挑一张**能对外出示**的证书给 TLS 协议用，返回 (cert, key, sni)。

            与 Reality 不同，VMess-WS 与 VLESS Encryption 都是真正的 TLS 服务端，
            必须出示一张客户端能验证通过的证书。这里只认「有 SAN 且覆盖域名」的证书：
              * 自签证书在多数客户端会直接报错，不静默降级成 insecure；
              * 证书与私钥必须配对，否则 Xray 预检会失败。
            做不到就抛异常，让调用方明确拒绝启用，而不是生成一份必然连不上的配置。

            protocol 只影响错误文案：两个协议共用同一套校验，但报错必须说清
            是哪个协议启用失败，否则用户会去查错地方。
            """
            cfg_dir = Path('/etc/hysteria')
            cert_file, cn, sans, self_signed = _resolve_live_cert(cfg_dir)
            if not cert_file or not Path(cert_file).is_file():
                raise RuntimeError('找不到可用 TLS 证书，%s 需要先配置证书' % protocol)
            if self_signed:
                raise RuntimeError('当前为自签证书，%s 客户端无法校验；请先配置域名证书' % protocol)
            names = set(sans or []) | ({cn} if cn else set())
            if domain not in names:
                raise RuntimeError('证书不包含域名 %s（现有: %s）' % (
                    domain, ', '.join(sorted(names)) or '无'))
            key_file = _find_cert_key(Path(cert_file), cfg_dir)
            if key_file is None:
                raise RuntimeError(
                    '找不到与证书 %s 配对的私钥；%s 需要证书与私钥成对可用'
                    % (cert_file, protocol))
            # 证书链必须完整（至少叶证书 + 中间证书）。Go 系客户端
            # （Xray / v2rayN / hysteria）不会通过 AIA 补齐中间证书，
            # 只给叶证书时握手会报 x509: certificate signed by unknown authority。
            # 安装器 _accept_cert_pair 有同样的判据，门户这边此前漏了。
            try:
                pem_text = Path(cert_file).read_text(encoding='utf-8', errors='ignore')
            except OSError:
                pem_text = ''
            if pem_text.count('BEGIN CERTIFICATE') < 2:
                raise RuntimeError(
                    '证书 %s 只有叶证书、缺少中间证书链；客户端会报 unknown authority。'
                    '请使用 fullchain 或包含完整链的证书文件' % cert_file)
            return str(cert_file), str(key_file), domain

        def _vmess_ws_path(self):
            """随机且**持久**的 WS 路径。路径本身不是机密，但随机值能挡掉
            按固定路径扫描的主动探测；它写在订阅里，所以必须稳定。"""
            with data_lock:
                existing = (data.get('vmess_config') or {}).get('ws_path')
            if isinstance(existing, str) and re.fullmatch(r'/[A-Za-z0-9_\-]{8,48}', existing):
                return existing
            return '/' + secrets.token_urlsafe(18).replace('=', '')

        def _apply_vmess_enable(self):
            """启用 VMess：写托管入站 → 事务替换 → 重启 xray → 落配置。

            顺序刻意如此：**配置先落地、数据后写入**。反过来一旦事务失败，
            data 里就留下一个「显示已启用、实际没有」的状态。
            """
            m = read_meta_file(meta_path)
            public_ip = m.get('public_ip', '127.0.0.1')
            domain = (m.get('server_name') or '').strip()
            if not domain or not _is_dns_name(domain):
                raise RuntimeError('VMess 需要先绑定域名（当前无可用 server_name）')
            cert_file, key_file, sni = self._vmess_certificate(domain)
            with data_lock:
                old = dict(config_section(data, 'vmess_config'))
                reality_port = config_section(data, 'reality_config').get('port')
            # 必须显式避开 Reality 的端口：它可能刚写进配置、尚未重启，
            # 监听表里还看不到，只靠 ss 探测会让两者撞同一个端口。
            try:
                _cfg_now = (json.loads(Path('/etc/hysteria/xray.json').read_text(encoding='utf-8'))
                            if Path('/etc/hysteria/xray.json').exists() else None)
            except (OSError, ValueError):
                _cfg_now = None
            with data_lock:
                _data_now = dict(data)
            blocked = managed_reserved_ports(m, _data_now, _cfg_now, exclude_key='vmess_config')
            blocked.add(reality_port)
            listen_port, reason = _pick_reality_port(
                preferred=old.get('port') or 2087,
                extra_blocked=blocked)
            if not listen_port:
                raise RuntimeError(reason)
            ws_path = self._vmess_ws_path()
            with data_lock:
                clients = vmess_clients(data)
            inbound = {
                'tag': VMESS_INBOUND_TAG,
                'port': listen_port,
                'protocol': 'vmess',
                'settings': {'clients': clients},
                'streamSettings': {
                    'network': 'ws',
                    'security': 'tls',
                    'tlsSettings': {
                        'serverName': sni,
                        'certificates': [{'certificateFile': cert_file,
                                          'keyFile': key_file}],
                    },
                    'wsSettings': {'path': ws_path},
                },
                'sniffing': {'enabled': True,
                             'destOverride': ['http', 'tls', 'quic']},
            }
            xray_path = Path('/etc/hysteria/xray.json')
            if not Path('/usr/local/bin/xray').exists():
                raise RuntimeError('Xray 核心未安装')
            # 读-改-写整体在锁内：否则并发启用另一个协议时，本次会用旧快照
            # 覆盖磁盘、把对方静默丢掉（2026-10-24 修，理由同 Reality）。
            with reality_apply_lock:
                config = (json.loads(xray_path.read_text(encoding='utf-8'))
                          if xray_path.exists() else {'log': {'loglevel': 'warning'},
                                                      'outbounds': [{'protocol': 'freedom',
                                                                     'tag': 'direct'}]})
                config = upsert_managed_inbound(config, VMESS_INBOUND_TAG, inbound)
                apply_xray_config_with_meter(
                    config, xray_path, portal_path.parent / 'usage-meter-config.json',
                    Path(__file__).parent)
            new_cfg = {'port': listen_port, 'domain': domain, 'sni': sni,
                       'ws_path': ws_path, 'uuid': vmess_uuid_for_user(MASTER_USER_ID)}
            new_cfg['uri'] = vmess_uri_for_user(new_cfg, MASTER_USER_ID, public_ip,
                                                label='VMess-WS-' + domain)
            with data_lock:
                data['vmess_config'] = new_cfg
            save_data()
            # 启用后重建页面：连接页的 Clash/sing-box 文本与二维码要立刻
            # 包含新协议，否则要手动刷新页面才看得到（2026-10-29 修）。
            regenerate_page()
            firewall_port(listen_port, 'tcp', open_=True)
            return new_cfg

        def _apply_vlessenc_enable(self):
            """启用 VLESS Encryption：生成/复用密钥对 → 写托管入站 → 事务重启。

            与 VMess 一样需要域名 + 可信证书（它是真正的 TLS 服务端）。
            密钥对只在**首次**生成：换掉 decryption 会让所有已下发的
            encryption 立刻失效，等于把在用的用户全部踢下线。
            """
            m = read_meta_file(meta_path)
            public_ip = m.get('public_ip', '127.0.0.1')
            domain = (m.get('server_name') or '').strip()
            if not domain or not _is_dns_name(domain):
                raise RuntimeError('VLESS Encryption 需要先绑定域名（当前无可用 server_name）')
            cert_file, key_file, sni = self._vmess_certificate(domain, 'VLESS Encryption')
            with data_lock:
                old = dict(config_section(data, 'vlessenc_config'))
                blocked_ports = {
                    m.get('listen_port'), m.get('subscription_port'),
                    (data.get('reality_config') or {}).get('port'),
                    (data.get('vmess_config') or {}).get('port'),
                }
            try:
                _cfg_now = (json.loads(Path('/etc/hysteria/xray.json').read_text(encoding='utf-8'))
                            if Path('/etc/hysteria/xray.json').exists() else None)
            except (OSError, ValueError):
                _cfg_now = None
            with data_lock:
                _data_now = dict(data)
            blocked_ports |= managed_reserved_ports(m, _data_now, _cfg_now, exclude_key='vlessenc_config')
            listen_port, reason = _pick_reality_port(
                preferred=old.get('port') or 2088, extra_blocked=blocked_ports)
            if not listen_port:
                raise RuntimeError(reason)
            decryption = old.get('decryption', '')
            encryption = old.get('encryption', '')
            if not (decryption and encryption):
                decryption, encryption = generate_vless_encryption_pair()
            with data_lock:
                clients = vlessenc_clients(data)
            inbound = {
                'tag': VLESSENC_INBOUND_TAG,
                'port': listen_port,
                'protocol': 'vless',
                'settings': {'clients': clients, 'decryption': decryption},
                'streamSettings': {
                    'network': 'tcp',
                    'security': 'tls',
                    'tlsSettings': {
                        'serverName': sni,
                        'certificates': [{'certificateFile': cert_file,
                                          'keyFile': key_file}],
                    },
                },
                'sniffing': {'enabled': True,
                             'destOverride': ['http', 'tls', 'quic']},
            }
            xray_path = Path('/etc/hysteria/xray.json')
            if not Path('/usr/local/bin/xray').exists():
                raise RuntimeError('Xray 核心未安装')
            # 读-改-写整体在锁内（2026-10-24 修，理由同 Reality / VMess）。
            with reality_apply_lock:
                config = (json.loads(xray_path.read_text(encoding='utf-8'))
                          if xray_path.exists() else {'log': {'loglevel': 'warning'},
                                                      'outbounds': [{'protocol': 'freedom',
                                                                     'tag': 'direct'}]})
                config = upsert_managed_inbound(config, VLESSENC_INBOUND_TAG, inbound)
                apply_xray_config_with_meter(
                    config, xray_path, portal_path.parent / 'usage-meter-config.json',
                    Path(__file__).parent)
            new_cfg = {'port': listen_port, 'domain': domain, 'sni': sni,
                       'decryption': decryption, 'encryption': encryption}
            new_cfg['uri'] = vlessenc_uri_for_user(new_cfg, MASTER_USER_ID, public_ip,
                                                   label='VLESS-Enc-' + domain)
            with data_lock:
                data['vlessenc_config'] = new_cfg
            save_data()
            # 启用后重建页面：连接页的 Clash/sing-box 文本与二维码要立刻
            # 包含新协议，否则要手动刷新页面才看得到（2026-10-29 修）。
            regenerate_page()
            firewall_port(listen_port, 'tcp', open_=True)
            return new_cfg

        def _h_post_manage_vmess(self, prefix):
            """POST /manage-vmess —— 独立启停 VMess，不影响 Reality。

            ⚠️ 关闭时**必须重载 Xray**：仅从 xray.json 删掉入站不会断开
            已经建立的连接，Xray 只在重载时才会重建监听。所以即便 Reality
            仍在运行，这里也要 restart 一次（不是 stop），
            这样 Reality 的用户只会短暂重连，不会被整体停掉。
            """
            if not self.is_authenticated():
                return self.reply_json(401, {'ok': False, 'error': 'Unauthorized'})
            try:
                length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(length).decode('utf-8', errors='replace') if length > 0 else ''
                form = parse_qs(body)
                action = form.get('action', ['toggle'])[0]
                xray_path = Path('/etc/hysteria/xray.json')
                config = (json.loads(xray_path.read_text(encoding='utf-8'))
                          if xray_path.exists() else None)
                enabled = bool(config) and has_managed_inbound(config, VMESS_INBOUND_TAG)
                if action == 'toggle':
                    action = 'disable' if enabled else 'enable'
                if action not in ('enable', 'disable'):
                    return self.reply_json(400, {'ok': False, 'error': 'Invalid action'})
                if action == 'enable':
                    if unit_suspended('xray'):
                        return self.reply_json(409, {'ok': False, 'error':
                            '节点因流量超额停用中，VMess 将在控制台恢复节点时一并恢复'})
                    cfg = self._apply_vmess_enable()
                    return self.reply_json(200, {'ok': True, 'active': True,
                                                 'port': cfg['port'], 'uri': cfg['uri']})
                if not enabled:
                    return self.reply_json(200, {'ok': True, 'active': False,
                                                 'message': 'VMess 本来就没有启用'})
                with data_lock:
                    closed_port = int((data.get('vmess_config') or {}).get('port') or 0)
                # 在锁内重新读取磁盘内容再删：handler 开头读到的 config 可能
                # 已被另一个协议的启用覆盖，用旧副本写回会把它静默丢掉。
                with reality_apply_lock:
                    try:
                        current = json.loads(xray_path.read_text(encoding='utf-8'))
                    except (OSError, ValueError):
                        current = config
                    remove_managed_inbound(current, VMESS_INBOUND_TAG)
                    apply_xray_config_transaction(
                        current, config_path=str(xray_path),
                        binary='/usr/local/bin/xray',
                        restart=not unit_suspended('xray'))
                with data_lock:
                    data.pop('vmess_config', None)
                save_data()
                # 停用后同样重建连接页：否则订阅里仍带着已关闭的节点。
                regenerate_page()
                if closed_port:
                    firewall_port(closed_port, 'tcp', open_=False)
                return self.reply_json(200, {'ok': True, 'active': False})
            except Exception as exc:
                return self.reply_json(500, {'ok': False, 'error': str(exc)})

        def _h_get_vmess_status(self, subpath):
            """GET /vmess-status —— 状态以**实际入站**为准，不看 data 里的残留配置。"""
            if not self.is_authenticated():
                return self.reply_json(401, {'ok': False, 'error': 'Unauthorized'})
            installed = Path('/usr/local/bin/xray').exists()
            xray_path = Path('/etc/hysteria/xray.json')
            active = False
            if xray_path.exists():
                try:
                    cfg = json.loads(xray_path.read_text(encoding='utf-8'))
                    active = managed_inbound_active(cfg, VMESS_INBOUND_TAG)
                except Exception:
                    active = False
            with data_lock:
                # 配置可能被改成数字/字符串：dict(7) 抛 TypeError，
                # 整个 /vmess-status 500，协议卡片整块空白。
                _v = data.get('vmess_config')
                vcfg = dict(_v) if isinstance(_v, dict) else {}
            qr_svg = ''
            _uri = vcfg.get('uri')
            if active and isinstance(_uri, str) and _uri:
                try:
                    qr = subprocess.run(['qrencode', '-t', 'SVG', '-o', '-'],
                                        input=_uri.encode('utf-8'),
                                        capture_output=True, timeout=3)
                    if qr.returncode == 0:
                        qr_svg = qr.stdout.decode('utf-8')
                except Exception as exc:
                    _log_ignored('vmess_qr', exc)
            return self.reply_json(200, {
                'ok': True, 'installed': installed, 'active': active,
                'config': {
                    'uri': vcfg.get('uri', '') if active else '',
                    'uuid': vcfg.get('uuid', '') if active else '',
                    'domain': vcfg.get('domain', ''),
                    'sni': vcfg.get('sni', ''),
                    'ws_path': vcfg.get('ws_path', ''),
                    'port': vcfg.get('port', 0) if active else 0,
                    'qr_svg': qr_svg,
                },
            })

        def _h_get_cores_status(self, subpath):
            """GET /cores-status —— 核心管理页：各核心装没装、版本、服务状态、被谁依赖。"""
            if not self.is_authenticated():
                return self.reply_json(401, {'ok': False, 'error': 'Unauthorized'})

            def version_of(binary, args, pattern):
                if not Path(binary).exists():
                    return ''
                try:
                    out = subprocess.run([binary] + args, capture_output=True, text=True, timeout=5)
                    m = re.search(pattern, (out.stdout or '') + (out.stderr or ''))
                    return m.group(1) if m else '已安装'
                except Exception:
                    return '已安装'

            def state_of(unit):
                if not Path('/etc/systemd/system/%s.service' % unit).exists() and \
                        not Path('/lib/systemd/system/%s.service' % unit).exists():
                    return 'none'
                return _systemd_state(unit) or 'unknown'

            singbox = _singbox_version()
            cores = [
                {'id': 'hysteria', 'name': 'Hysteria 2', 'used_by': ['Hysteria 2 主协议'],
                 'version': version_of('/usr/local/bin/hysteria', ['version'], r'Version:\s*v?([\w.\-]+)'),
                 'service': 'hysteria-server', 'installable': False,
                 'manage': 'configs', 'note': '主协议核心，升级请在「系统与版本」'},
                {'id': 'xray', 'name': 'Xray-core', 'used_by': ['VLESS-Reality', 'VMess', 'VLESS Encryption'],
                 'version': version_of('/usr/local/bin/xray', ['version'], r'Xray\s+v?([\w.\-]+)'),
                 'service': 'xray', 'installable': True, 'manage': 'reality/reality-node'},
                {'id': 'sing-box', 'name': 'sing-box', 'used_by': ['AnyTLS'],
                 'version': '.'.join(map(str, singbox)) if singbox else '',
                 'service': ANYTLS_SERVICE, 'installable': True, 'manage': 'reality/anytls'},
                {'id': 'gost', 'name': 'GOST', 'used_by': ['SOCKS5 / HTTP 入站代理'],
                 'version': version_of('/usr/local/bin/gost', ['-V'], r'gost\s+v?([\w.\-]+)'),
                 'service': 'gost', 'installable': False, 'manage': 'proxies/ingress',
                 'note': '安装时会同时生成代理配置，请在「扩展服务 → 入站代理」中安装'},
                {'id': 'warp', 'name': 'WARP (wgcf + wireproxy)', 'used_by': ['WARP 分流'],
                 'version': '已安装' if Path('/usr/local/bin/wireproxy').exists() else '',
                 'service': 'wireproxy', 'installable': False, 'manage': 'proxies/warp',
                 'note': '安装需要注册 WARP 账户，请在「扩展服务 → WARP 分流」中安装'},
                {'id': 'amneziawg', 'name': 'AmneziaWG', 'used_by': ['AmneziaWG VPN'],
                 'version': '已安装' if awg_installed() else '',
                 'service': AWG_SVC_NAME, 'installable': False, 'manage': 'proxies/awg',
                 'note': '安装需要选择协议版本与端点，请在「扩展服务 → AmneziaWG」中安装'},
            ]
            for core in cores:
                core['installed'] = bool(core['version'])
                core['state'] = state_of(core['service'])
            return self.reply_json(200, {'ok': True, 'cores': cores})

        def _h_post_install_core(self, prefix):
            """POST /install-core —— 只安装核心二进制，不启用任何协议。

            Xray / sing-box 是纯核心：装好后由各协议页的开关去生成配置并启动。
            GOST / WARP / AmneziaWG 的安装本身带配置，仍在各自页面完成。
            """
            if not self.is_authenticated():
                return self.reply_json(401, {'ok': False, 'error': 'Unauthorized'})
            try:
                self._extend_deadline(420)
                length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(length).decode('utf-8', errors='replace') if length > 0 else ''
                name = parse_qs(body).get('name', [''])[0]
                if name not in ('xray', 'sing-box'):
                    return self.reply_json(400, {'ok': False, 'error': '不支持在这里安装该核心'})
                with core_operation_lock:
                    if name == 'xray':
                        ok, msg = install_xray_binary()
                        if ok:
                            write_xray_unit()
                    else:
                        ok, msg = install_singbox()
                return self.reply_json(200 if ok else 500, {'ok': ok, ('message' if ok else 'error'): msg})
            except Exception as exc:
                return self.reply_json(500, {'ok': False, 'error': str(exc)})

        def _core_users(self, name):
            """返回仍在使用该核心的协议名列表；非空时拒绝卸载。"""
            if name == 'sing-box':
                return ['AnyTLS'] if _active_anytls_config() else []
            try:
                cfg = json.loads(Path('/etc/hysteria/xray.json').read_text(encoding='utf-8'))
            except FileNotFoundError:
                # 没有配置文件 = 确实没有任何 Xray 协议在用，可以卸载。
                return []
            except (OSError, ValueError):
                # 配置存在但读不出来时**不能**当成「没人用」：旧实现返回 []，
                # 于是卸载会直接停服务删二进制，所有 Reality/VMess/VLESS-Enc
                # 用户当场断线且无法自愈（2026-10-29 修，fail-closed）。
                return ['（xray.json 无法解析，请先修复）']
            labels = {REALITY_INBOUND_TAG: 'VLESS-Reality', VMESS_INBOUND_TAG: 'VMess',
                      VLESSENC_INBOUND_TAG: 'VLESS Encryption'}
            return [labels[tag] for tag in MANAGED_INBOUND_TAGS if has_managed_inbound(cfg, tag)]

        def _h_post_uninstall_core(self, prefix):
            """POST /uninstall-core —— 卸载 Xray / sing-box 核心。

            有协议还在用就拒绝：直接删核心会让这些协议的用户全部断线，
            而协议页仍显示「已启用」。先去协议页关掉，再回来卸载。
            协议的配置（密钥、端口、secret）保留，重装核心后再开启即可沿用。
            """
            if not self.is_authenticated():
                return self.reply_json(401, {'ok': False, 'error': 'Unauthorized'})
            try:
                length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(length).decode('utf-8', errors='replace') if length > 0 else ''
                name = parse_qs(body).get('name', [''])[0]
                units = {'xray': ('xray', '/usr/local/bin/xray'),
                         'sing-box': (ANYTLS_SERVICE, ANYTLS_BINARY)}
                if name not in units:
                    return self.reply_json(400, {'ok': False, 'error': '不支持在这里卸载该核心'})
                in_use = self._core_users(name)
                if in_use:
                    return self.reply_json(409, {'ok': False, 'error':
                        '以下协议仍在使用 %s：%s。请先到对应协议页关闭后再卸载' % (name, '、'.join(in_use))})
                unit, binary = units[name]
                with core_operation_lock:
                    subprocess.run(['systemctl', 'disable', '--now', unit], capture_output=True, timeout=30)
                    Path('/etc/systemd/system/%s.service' % unit).unlink(missing_ok=True)
                    subprocess.run(['systemctl', 'daemon-reload'], capture_output=True, timeout=30)
                    subprocess.run(['systemctl', 'reset-failed', unit], capture_output=True, timeout=5)
                    Path(binary).unlink(missing_ok=True)
                return self.reply_json(200, {'ok': True, 'message': '%s 已卸载' % name})
            except Exception as exc:
                return self.reply_json(500, {'ok': False, 'error': str(exc)})

        def _apply_anytls_enable(self):
            """启用 AnyTLS：装 sing-box → 选端口 → 写配置并重启 → 落 data。

            与 Xray 系协议一样「配置先落地、数据后写入」，事务失败时 data
            不会留下「显示已启用、实际没有」的状态。secret 只在首次生成。
            """
            m = read_meta_file(meta_path)
            domain = (m.get('server_name') or '').strip()
            if not domain or not _is_dns_name(domain):
                raise RuntimeError('AnyTLS 需要先绑定域名（当前无可用 server_name）')
            cert_file, key_file, sni = self._vmess_certificate(domain, 'AnyTLS')
            version = _singbox_version()
            if not version or version < ANYTLS_MIN_SINGBOX:
                raise RuntimeError('sing-box 核心未安装或版本低于 1.12，请先在「核心管理」中安装')
            with data_lock:
                old = dict(config_section(data, 'anytls_config'))
                _data_now = dict(data)
            try:
                _cfg_now = (json.loads(Path('/etc/hysteria/xray.json').read_text(encoding='utf-8'))
                            if Path('/etc/hysteria/xray.json').exists() else None)
            except (OSError, ValueError):
                _cfg_now = None
            blocked = managed_reserved_ports(m, _data_now, _cfg_now, exclude_key='anytls_config')
            listen_port, reason = _pick_reality_port(
                preferred=old.get('port') or 2096, extra_blocked=blocked)
            if not listen_port:
                raise RuntimeError(reason)
            new_cfg = {'enabled': True, 'port': listen_port, 'domain': domain, 'sni': sni,
                       'secret': old.get('secret') or secrets.token_hex(32)}
            with data_lock:
                preview = dict(data)
                preview['anytls_config'] = new_cfg
                users = anytls_users(preview)
            unit_path = Path('/etc/systemd/system/%s.service' % ANYTLS_SERVICE)
            if not unit_path.exists() or unit_path.read_text(encoding='utf-8') != ANYTLS_UNIT_CONTENT:
                unit_path.write_text(ANYTLS_UNIT_CONTENT, encoding='utf-8')
                subprocess.run(['systemctl', 'daemon-reload'], capture_output=True, timeout=30)
            with anytls_apply_lock:
                apply_anytls_config(build_anytls_config(new_cfg, users, cert_file, key_file),
                                    portal_path.parent / ANYTLS_CONFIG_NAME, restart=True)
                # 配置预检 + 启动成功之后再 enable（2026-10-29 修）。
                # 旧实现先 enable 再校验：证书缺失时单元已被设为开机自启，
                # 之后每次开机 sing-box 都会每 3 秒失败重启一次。
                subprocess.run(['systemctl', 'enable', ANYTLS_SERVICE],
                               capture_output=True, timeout=30)
            with data_lock:
                data['anytls_config'] = new_cfg
            save_data()
            # 启用后重建页面：连接页的 Clash/sing-box 文本与二维码要立刻
            # 包含新协议，否则要手动刷新页面才看得到（2026-10-29 修）。
            regenerate_page()
            firewall_port(listen_port, 'tcp', open_=True)
            return new_cfg

        def _h_post_manage_anytls(self, prefix):
            """POST /manage-anytls —— 独立启停 AnyTLS（sing-box），不影响 Xray 上的协议。"""
            if not self.is_authenticated():
                return self.reply_json(401, {'ok': False, 'error': 'Unauthorized'})
            try:
                length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(length).decode('utf-8', errors='replace') if length > 0 else ''
                action = parse_qs(body).get('action', ['toggle'])[0]
                enabled = _active_anytls_config() is not None
                if action == 'toggle':
                    action = 'disable' if enabled else 'enable'
                if action not in ('enable', 'disable'):
                    return self.reply_json(400, {'ok': False, 'error': 'Invalid action'})
                if action == 'enable':
                    with data_lock:
                        suspended = suspend_state(data).get('suspended') is True
                    if suspended:
                        return self.reply_json(409, {'ok': False, 'error':
                            '节点因流量超额停用中，请在控制台恢复节点后再启用 AnyTLS'})
                    cfg = self._apply_anytls_enable()
                    return self.reply_json(200, {'ok': True, 'active': True, 'port': cfg['port'],
                                                 'uri': anytls_uri_for_user(cfg, MASTER_USER_ID,
                                                                            label='AnyTLS-' + cfg['domain'])})
                if not enabled:
                    return self.reply_json(200, {'ok': True, 'active': False,
                                                 'message': 'AnyTLS 本来就没有启用'})
                with anytls_apply_lock:
                    subprocess.run(['systemctl', 'disable', '--now', ANYTLS_SERVICE],
                                   capture_output=True, timeout=30)
                    # 必须确认真的停了再删配置（2026-10-29 修）。
                    # stop 失败（进程卡住 / D-Bus 超时）时，sing-box 仍带着旧
                    # 用户表运行：被停用的用户照样能连，界面却显示「已关闭」。
                    state = _systemd_state(ANYTLS_SERVICE)
                    if state == 'active':
                        return self.reply_json(500, {'ok': False, 'error':
                            'AnyTLS 服务未能停止，配置已保留，请重试或查看 systemctl status %s'
                            % ANYTLS_SERVICE})
                    (portal_path.parent / ANYTLS_CONFIG_NAME).unlink(missing_ok=True)
                with data_lock:
                    acfg = dict(config_section(data, 'anytls_config'))
                    closed_port = int(acfg.get('port') or 0)
                    # secret 与端口保留：再次启用时沿用，已下发的订阅不失效。
                    acfg['enabled'] = False
                    data['anytls_config'] = acfg
                save_data()
                # 停用后同样重建连接页：否则订阅里仍带着已关闭的节点。
                regenerate_page()
                if closed_port:
                    firewall_port(closed_port, 'tcp', open_=False)
                return self.reply_json(200, {'ok': True, 'active': False})
            except Exception as exc:
                return self.reply_json(500, {'ok': False, 'error': str(exc)})

        def _h_get_anytls_status(self, subpath):
            """GET /anytls-status —— 以 sing-box 服务实际状态为准。"""
            if not self.is_authenticated():
                return self.reply_json(401, {'ok': False, 'error': 'Unauthorized'})
            acfg = _active_anytls_config() or {}
            running = bool(acfg) and _systemd_state(ANYTLS_SERVICE) == 'active'
            version = _singbox_version()
            uri = anytls_uri_for_user(acfg, MASTER_USER_ID,
                                      label='AnyTLS-' + str(acfg.get('domain', ''))) if acfg else ''
            qr_svg = ''
            if running and uri:
                try:
                    qr = subprocess.run(['qrencode', '-t', 'SVG', '-o', '-'], input=uri.encode('utf-8'),
                                        capture_output=True, timeout=3)
                    if qr.returncode == 0:
                        qr_svg = qr.stdout.decode('utf-8')
                except Exception as exc:
                    _log_ignored('anytls_qr', exc)
            return self.reply_json(200, {
                'ok': True,
                'installed': bool(version),
                'version': '.'.join(map(str, version)) if version else '',
                'enabled': bool(acfg),
                'active': running,
                'config': {
                    'uri': uri if running else '',
                    'domain': acfg.get('domain', ''),
                    'sni': acfg.get('sni', ''),
                    'port': acfg.get('port', 0) if running else 0,
                    'qr_svg': qr_svg,
                },
            })

        def _h_post_manage_vlessenc(self, prefix):
            """POST /manage-vlessenc —— 独立启停 VLESS Encryption。

            与 VMess 同样的关键约束：关闭时只移除自己的入站并**重启** Xray
            （restart 而非 stop），Reality / VMess 的用户只会短暂重连。
            """
            if not self.is_authenticated():
                return self.reply_json(401, {'ok': False, 'error': 'Unauthorized'})
            try:
                length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(length).decode('utf-8', errors='replace') if length > 0 else ''
                form = parse_qs(body)
                action = form.get('action', ['toggle'])[0]
                xray_path = Path('/etc/hysteria/xray.json')
                config = (json.loads(xray_path.read_text(encoding='utf-8'))
                          if xray_path.exists() else None)
                enabled = bool(config) and has_managed_inbound(config, VLESSENC_INBOUND_TAG)
                if action == 'toggle':
                    action = 'disable' if enabled else 'enable'
                if action not in ('enable', 'disable'):
                    return self.reply_json(400, {'ok': False, 'error': 'Invalid action'})
                if action == 'enable':
                    if unit_suspended('xray'):
                        return self.reply_json(409, {'ok': False, 'error':
                            '节点因流量超额停用中，VLESS Encryption 将在控制台恢复节点时一并恢复'})
                    cfg = self._apply_vlessenc_enable()
                    return self.reply_json(200, {'ok': True, 'active': True,
                                                 'port': cfg['port'], 'uri': cfg['uri']})
                if not enabled:
                    return self.reply_json(200, {'ok': True, 'active': False,
                                                 'message': 'VLESS Encryption 本来就没有启用'})
                with data_lock:
                    closed_port = int((data.get('vlessenc_config') or {}).get('port') or 0)
                # 在锁内重新读取磁盘内容再删：handler 开头读到的 config 可能
                # 已被另一个协议的启用覆盖，用旧副本写回会把它静默丢掉。
                with reality_apply_lock:
                    try:
                        current = json.loads(xray_path.read_text(encoding='utf-8'))
                    except (OSError, ValueError):
                        current = config
                    remove_managed_inbound(current, VLESSENC_INBOUND_TAG)
                    apply_xray_config_transaction(
                        current, config_path=str(xray_path),
                        binary='/usr/local/bin/xray',
                        restart=not unit_suspended('xray'))
                with data_lock:
                    data.pop('vlessenc_config', None)
                save_data()
                # 停用后同样重建连接页：否则订阅里仍带着已关闭的节点。
                regenerate_page()
                if closed_port:
                    firewall_port(closed_port, 'tcp', open_=False)
                return self.reply_json(200, {'ok': True, 'active': False})
            except Exception as exc:
                return self.reply_json(500, {'ok': False, 'error': str(exc)})

        def _h_get_vlessenc_status(self, subpath):
            """GET /vlessenc-status —— 与 VMess 一致，以实际入站为准。"""
            if not self.is_authenticated():
                return self.reply_json(401, {'ok': False, 'error': 'Unauthorized'})
            installed = Path('/usr/local/bin/xray').exists()
            xray_path = Path('/etc/hysteria/xray.json')
            active = False
            if xray_path.exists():
                try:
                    active = managed_inbound_active(
                        json.loads(xray_path.read_text(encoding='utf-8')),
                        VLESSENC_INBOUND_TAG)
                except Exception:
                    active = False
            with data_lock:
                # 同 /vmess-status：非 dict 配置会让 dict() 抛异常。
                _e = data.get('vlessenc_config')
                ecfg = dict(_e) if isinstance(_e, dict) else {}
            qr_svg = ''
            _euri = ecfg.get('uri')
            if active and isinstance(_euri, str) and _euri:
                try:
                    qr = subprocess.run(['qrencode', '-t', 'SVG', '-o', '-'],
                                        input=_euri.encode('utf-8'),
                                        capture_output=True, timeout=3)
                    if qr.returncode == 0:
                        qr_svg = qr.stdout.decode('utf-8')
                except Exception as exc:
                    _log_ignored('vlessenc_qr', exc)
            return self.reply_json(200, {
                'ok': True, 'installed': installed, 'active': active,
                'config': {
                    'uri': ecfg.get('uri', '') if active else '',
                    'uuid': reality_uuid_for_user(MASTER_USER_ID) if active else '',
                    'domain': ecfg.get('domain', ''),
                    'sni': ecfg.get('sni', ''),
                    'port': ecfg.get('port', 0) if active else 0,
                    'qr_svg': qr_svg,
                },
            })

        def _h_post_set_bbr(self, prefix):
            """Apply only an available kernel algorithm, verify it, and restore on failure."""
            if not self.is_authenticated():
                return self.reply_json(401, {'ok': False, 'error': 'Unauthorized'})
            try:
                length = int(self.headers.get('Content-Length', 0))
                form = parse_qs(self.rfile.read(length).decode('utf-8', errors='replace'))
                ver = form.get('version', ['v1'])[0].lower()
                if ver not in ('v1', 'v2', 'v3'):
                    return self.reply_json(400, {'ok': False, 'error': 'Invalid BBR version'})
                target = {'v1': 'bbr', 'v2': 'bbr2', 'v3': 'bbr3'}[ver]
                subprocess.run(['modprobe', 'tcp_' + target], capture_output=True, timeout=5)
                available = subprocess.run(['sysctl', '-n', 'net.ipv4.tcp_available_congestion_control'],
                                           capture_output=True, text=True, timeout=3)
                if available.returncode != 0:
                    return self.reply_json(500, {'ok': False, 'error': '无法读取内核可用拥塞算法'})
                if target not in available.stdout.split():
                    return self.reply_json(409, {'ok': False, 'error':
                        '当前内核未提供 %s，不能通过 sysctl 切换到 BBR %s；原配置保持不变' % (target, ver.upper())})
                settings = {'net.core.default_qdisc': 'fq',
                            'net.ipv4.tcp_congestion_control': target,
                            'net.ipv4.tcp_notsent_lowat': '16384',
                            'net.ipv4.tcp_slow_start_after_idle': '0'}
                runtime = {}
                for key in settings:
                    result = subprocess.run(['sysctl', '-n', key], capture_output=True, text=True, timeout=3)
                    if result.returncode != 0 or not result.stdout.strip():
                        return self.reply_json(500, {'ok': False, 'error': '读取 sysctl 失败，未修改配置'})
                    runtime[key] = result.stdout.strip()
                paths = [Path('/etc/modules-load.d/bbr.conf'), Path('/etc/sysctl.d/99-bbr.conf')]
                originals = {path: path.read_bytes() if path.exists() else None for path in paths}
                try:
                    paths[0].write_text('tcp_' + target + '\n', encoding='utf-8')
                    paths[1].write_text('\n'.join('%s = %s' % item for item in settings.items()) + '\n', encoding='utf-8')
                    applied = subprocess.run(['sysctl', '-p', str(paths[1])], capture_output=True, text=True, timeout=5)
                    if applied.returncode != 0:
                        raise RuntimeError('sysctl 应用失败')
                    for key in ('net.ipv4.tcp_congestion_control', 'net.core.default_qdisc'):
                        actual = subprocess.run(['sysctl', '-n', key], capture_output=True, text=True, timeout=3)
                        if actual.returncode != 0 or actual.stdout.strip() != settings[key]:
                            raise RuntimeError('sysctl 读回与目标不一致')
                except Exception:
                    for path, content in originals.items():
                        if content is None:
                            path.unlink(missing_ok=True)
                        else:
                            path.write_bytes(content)
                    for key, value in runtime.items():
                        subprocess.run(['sysctl', '-w', key + '=' + value], capture_output=True, timeout=3)
                    return self.reply_json(500, {'ok': False, 'error': 'BBR 应用失败，已恢复原文件并尝试恢复原运行参数'})
                with data_lock:
                    data['bbr_target_version'] = ver
                save_data()
                return self.reply_json(200, {'ok': True, 'applied': True, 'current': target,
                    'message': 'BBR %s 已应用并核对实际算法为 %s，无需重启整机' % (ver.upper(), target)})
            except Exception as exc:
                return self.reply_json(500, {'ok': False, 'error': 'BBR 操作失败: ' + type(exc).__name__})

        def _h_post_reboot_server(self, prefix):
            """POST /reboot-server 的处理逻辑（从 do_POST 机械搬移而来）。"""
            if not self.is_authenticated():
                return self.reply_json(401, {'ok': False, 'error': 'Unauthorized'})
            try:
                subprocess.Popen(['bash', '-c', 'sleep 1 && reboot'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return self.reply_json(200, {'ok': True, 'message': '服务器正在重启中'})
            except Exception as e:
                return self.reply_json(500, {'ok': False, 'error': ('%s: %s' % (type(e).__name__, str(e)))[:160]})

        def _h_post_manage_user(self, prefix):
            """POST /manage-user 的处理逻辑（从 do_POST 机械搬移而来）。"""
            if not self.is_authenticated():
                return self.reply(401, b'Unauthorized')
            try:
                length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(length).decode('utf-8', errors='replace')
                form = parse_qs(body)
                action = form.get('action', [''])[0]
                user_id = form.get('user_id', [''])[0].strip()
                now_ts = int(time.time())
                if action not in ('create', 'delete'):
                    return self.reply(400, b'Invalid action')
                with data_lock:
                    previous_user = copy.deepcopy(data.get('users', {}).get(user_id))


                if not VALID_USER_ID_RE.match(user_id):
                    return self.reply(400, b'Invalid user_id format')
                # 与 REST API 同一条规则：保留名不能作为真实用户（placeholder 会和
                # Xray 的占位 client 撞 email，admin_master 是机主账号）。
                if action == 'create' and user_id in RESERVED_USER_IDS:
                    return self.reply(400, b'Reserved user_id')

                if action == 'create' and user_id:
                    pwd = form.get('password', [''])[0].strip() or secrets.token_hex(16)
                    # 同 REST 通道：非数字输入必须回 400，而不是让异常掐断连接。
                    try:
                        days = int(form.get('duration_days', ['30'])[0] or 30)
                        ip_limit = int(form.get('ip_limit', ['0'])[0] or 0)
                        traffic_gb = float(form.get('traffic_gb', ['0'])[0] or 0)
                    except (ValueError, TypeError, OverflowError):
                        return self.reply(400, b'Invalid duration, IP limit or traffic quota')
                    # 上限 1e6 GB：没有上限时超大值会在 int() 处抛 OverflowError。
                    # 天数上限与 REST API 的 users/create 一致（1..36500）。
                    if (not 1 <= days <= 36500 or not 0 <= ip_limit <= 1000 or not math.isfinite(traffic_gb)
                            or not 0 <= traffic_gb <= 1000000):
                        return self.reply(400, b'Invalid duration, IP limit or traffic quota')
                    limit_bytes = int(traffic_gb * (1024**3)) if traffic_gb > 0 else 0
                    note = form.get('note', [''])[0].strip()[:200]
                    # 🔴 2026-10-09 修：原来是无条件赋值，同名 id 会被**静默覆盖** ——
                    # 密码被改、used_bytes 归零（已购/已用流量凭空消失）、有效期重算，
                    # 而用户拿到的是 200 成功响应。API 那条路径有 create_only 守卫，
                    # 网页表单这条没有。表单又不预填 id、不提示重名，重复提交很容易撞上。
                    # 现在显式 409，并回显密码尾号帮机主确认自己是不是认错了人。
                    conflict = None
                    with data_lock:
                        existing = data.get('users', {}).get(user_id)
                        if existing is not None:
                            tail = (existing.get('password') or '')[-4:]
                            # 数据被改坏时 int('x') 会抛 ValueError，这里只影响
                            # 一条提示文案，不值得让整个 409 变成 500（2026-10-30 修）。
                            try:
                                _used = int(existing.get('used_bytes') or 0)
                            except (TypeError, ValueError):
                                _used = 0
                            used_gb = round(_used / (1024 ** 3), 2)
                            conflict = ('exists', tail, used_gb)
                        elif password_taken(data.get('users', {}), pwd, user_id):
                            conflict = ('password',)
                        else:
                            data.setdefault('users', {})[user_id] = {
                                'password': pwd,
                                'expires_at': now_ts + days * 86400,
                                'ip_limit': ip_limit,
                                'limit_bytes': limit_bytes,
                                'used_bytes': 0,
                                'status': 'active',
                                'created_at': now_ts,
                                'note': note,
                                'view_nonce': secrets.token_hex(8),
                            }
                    if conflict is not None:
                        if conflict[0] == 'exists':
                            return self.reply(409, (
                                f'用户 {user_id} 已存在（当前密码尾号 {conflict[1]}，已用 {conflict[2]} GB）。'
                                # Web 端没有「修改」入口（只有 REST API 的 users/update），
                                # 旧文案会把管理员指向不存在的功能（2026-10-25 修）。
                                '如需改参数请调用 REST API 的 users/update，或先删除该用户再重建。'
                            ).encode('utf-8'))
                        return self.reply(409, '该密码已被其他用户使用，请换一个（留空则自动生成）。'.encode('utf-8'))
                elif action == 'delete' and user_id:
                    # 🔴 admin_master 不能被注销：它的 password 就是 Hysteria 的
                    # auth_password（机主本人的主密码）。/auth 是遍历 data['users']
                    # 按密码匹配的，一旦这条记录被删，主密码在 /auth 里立刻变成
                    # "User not found" —— 机主自己都被踢下线、再也连不上节点，
                    # 只能重装。所以这里必须拒绝，UI 那边也不渲染删除按钮。
                    if user_id == MASTER_USER_ID:
                        return self.reply(400, b'Cannot delete the master account')
                    delete_missing = False
                    with data_lock:
                        if user_id not in data.get('users', {}):
                            delete_missing = True
                        else:
                            data['_pending_revocations']=sorted(pending_revocations(data) | {user_id})
                            del data['users'][user_id]
                            # 已删用户的累计用量不再有人读，留着只会让 portal.json 越写越大。
                            # 计数器游标不能删：服务没重启时同名用户再出现会被重复计数；
                            # 服务重启换 epoch 时 usage-meter-core 会自然丢弃它们。
                            drop_meter_totals(data, user_id)
                            if user_id in ip_tracker:
                                del ip_tracker[user_id]
                            # 速率样本同理：不删的话，同名用户重建后第一轮
                            # 速率会沿用旧样本算出尖峰（2026-10-25 修）。
                            speed_tracker.pop(user_id, None)
                    if delete_missing:
                        # 锁内只判定；回包放在锁外，避免慢客户端阻塞 /auth。
                        return self.reply(404, b'User not found')

                regenerate_page()
                if not self._sync_reality_clients():
                    with data_lock:
                        if action == 'delete':
                            save_data()
                            revoked_pending = True
                        else:
                            revoked_pending = False
                            if previous_user is None:
                                data.get('users', {}).pop(user_id, None)
                            else:
                                data.setdefault('users', {})[user_id] = previous_user
                    save_data()
                    if revoked_pending:
                        # 锁内只判定；回包放在锁外，避免慢客户端阻塞 /auth。
                        return self.reply(503, b'Access revocation pending; retry required')
                    return self.reply(503, 'Reality 同步失败，用户操作已撤销，请检查服务后重试'.encode('utf-8'))

                regenerate_page()
                self.send_response(302)
                self._responded = True
                self.send_header('Location', prefix + '#users')
                self.end_headers()
                return
            except Exception:
                return self.reply(400, b'Bad request')

        def _h_post_login(self, prefix):
            """POST /login 的处理逻辑（从 do_POST 机械搬移而来）。"""
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

            if self.login_rate_limited():
                # 与密码错误用同一页面形态，不给爆破者「已被限流」的区分信号。
                page = login_html(data['token'],
                                  error_msg='尝试次数过多，请 10 分钟后再试')
                return self.reply(429, page.encode('utf-8'), 'text/html; charset=utf-8')

            submitted_auth = base64.b64encode(f'{user}:{pwd}'.encode())
            submitted_digest = hashlib.sha256(submitted_auth).hexdigest()

            if not hmac.compare_digest(submitted_digest, data['auth_hash']):
                self.record_login_failure()
                page = login_html(data['token'], error_msg='用户名或密码不正确，请重新输入')
                return self.reply(200, page.encode('utf-8'), 'text/html; charset=utf-8')

            sess_val = sign_session(data['token'])
            max_age = f'; Max-Age={SESSION_MAX_AGE}' if remember else ''
            cookie = f'hy2_session={sess_val}; Path=/{data["token"]}/; HttpOnly; SameSite=Strict; Secure{max_age}'
            self.send_response(302)
            self._responded = True
            self.send_header('Location', prefix)
            self.send_header('Set-Cookie', cookie)
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            return

        def _h_post_install_warp(self, prefix):
            """POST /install-warp 的处理逻辑（从 do_POST 机械搬移而来）。"""
            if not self.is_authenticated():
                return self.reply_json(401, {'ok': False, 'error': 'Unauthorized'})
            try:
                # 安装脚本 subprocess 超时 180 秒，必须同步抬连接死线。
                self._extend_deadline(240)
                install_warp_sh = r'''
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

# ---- 完整性校验辅助（与 install.sh / portal.py 主流程同一套规则）----
# 从 `<sha256>  <name>` 清单里取唯一匹配摘要；无匹配/多条/畸形 => 失败。
manifest_sha256() {
    awk -v f="$2" '{n=$2; sub(/^\.\//,"",n); sub(/^\*/,"",n); b=n; sub(/.*\//,"",b);
                    if (n==f || b==f) print $1}' "$1" | tr 'A-F' 'a-f' | sort -u |
    awk 'NR==1{d=$0} END{if (NR==1 && d ~ /^[0-9a-f]{64}$/) print d; else exit 1}'
}
verify_sha() {
    [[ "$2" =~ ^[0-9a-f]{64}$ ]] || return 1
    [[ "$(sha256sum "$1" | awk '{print $1}')" == "$2" ]]
}
tar_member() {
    local m n=0 hit=""
    while IFS= read -r m; do
        case "$m" in /*|..|../*|*/../*|*/..) return 2 ;; esac
        if [[ "${m#./}" == "$1" ]]; then n=$((n + 1)); hit="$m"; fi
    done < <(tar -tzf "$2" 2>/dev/null)
    [[ $n -eq 1 ]] || return 3
    echo "$hit"
}

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
    WG_DL="wgcf_${VER}_linux_${WG_A}"
    TD=$(mktemp -d)
    trap 'rm -rf "$TD"' EXIT
    # 先取该版本官方 checksums.txt，取不到就放弃（不做无校验下载）。
    if ! curl -fsSL --max-time 30 --retry 2 -o "${TD}/checksums.txt" \
            "https://github.com/ViRb3/wgcf/releases/download/v${VER}/checksums.txt" 2>/dev/null; then
        rm -rf "$TD"; echo "取不到 wgcf v${VER} 的官方 checksums.txt，已放弃安装" >&2; exit 1
    fi
    WANT=$(manifest_sha256 "${TD}/checksums.txt" "$WG_DL") || WANT=""
    if [ -z "$WANT" ]; then
        rm -rf "$TD"; echo "checksums.txt 中 ${WG_DL} 的摘要缺失或不唯一，已放弃安装" >&2; exit 1
    fi
    if ! curl -fsSL --max-time 90 -o "${TD}/${WG_DL}" "https://github.com/ViRb3/wgcf/releases/download/v${VER}/${WG_DL}"; then
        rm -rf "$TD"; echo "wgcf 下载失败 (v${VER}/${WG_A})" >&2; exit 1
    fi
    if ! verify_sha "${TD}/${WG_DL}" "$WANT"; then
        rm -rf "$TD"; echo "wgcf 校验失败：SHA256 与官方 checksums.txt 不一致" >&2; exit 1
    fi
    install -m 755 "${TD}/${WG_DL}" "${WGCF_BIN}.new" || { rm -rf "$TD"; exit 1; }
    rm -rf "$TD"; trap - EXIT
    mv -f "${WGCF_BIN}.new" "$WGCF_BIN"
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
    WP_DL="wireproxy_linux_${WP_A}.tar.gz"
    # 先清掉上一个临时目录：旧 trap 只认当前的 $TD，直接重新赋值会让
    # wgcf 那次 mktemp 的目录永远留在 /tmp（2026-10-30 修）。
    rm -rf "$TD"
    TD=$(mktemp -d)
    trap 'rm -rf "$TD"' EXIT
    if ! curl -fsSL --max-time 30 --retry 2 -o "${TD}/checksums.txt" \
            "https://github.com/whyvl/wireproxy/releases/download/${TAG}/checksums.txt" 2>/dev/null; then
        rm -rf "$TD"; echo "取不到 wireproxy ${TAG} 的官方 checksums.txt，已放弃安装" >&2; exit 1
    fi
    WANT=$(manifest_sha256 "${TD}/checksums.txt" "$WP_DL") || WANT=""
    if [ -z "$WANT" ]; then
        rm -rf "$TD"; echo "checksums.txt 中 ${WP_DL} 的摘要缺失或不唯一，已放弃安装" >&2; exit 1
    fi
    if ! curl -fsSL --max-time 90 -o "${TD}/${WP_DL}" "https://github.com/whyvl/wireproxy/releases/download/${TAG}/${WP_DL}"; then
        rm -rf "$TD"; echo "wireproxy 下载失败 (${TAG}/${WP_A})" >&2; exit 1
    fi
    if ! verify_sha "${TD}/${WP_DL}" "$WANT"; then
        rm -rf "$TD"; echo "wireproxy 校验失败：SHA256 与官方 checksums.txt 不一致" >&2; exit 1
    fi
    MEMBER=$(tar_member wireproxy "${TD}/${WP_DL}") || {
        rm -rf "$TD"; echo "wireproxy 包内含不安全路径或成员不唯一，已放弃安装" >&2; exit 1; }
    mkdir -p "${TD}/x"
    if ! tar -xzf "${TD}/${WP_DL}" -C "${TD}/x" "$MEMBER" 2>/dev/null; then
        rm -rf "$TD"; echo "wireproxy 解压失败" >&2; exit 1
    fi
    install -m 755 "${TD}/x/${MEMBER}" "${WP_BIN}.new" || { rm -rf "$TD"; exit 1; }
    rm -rf "$TD"; trap - EXIT
    mv -f "${WP_BIN}.new" "$WP_BIN"
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
# 两个探测点都不通才重启：只看 ipify 的话，ipify 自己故障会让 wireproxy 每 3 分钟被白白重启一次。
probe() { curl --proxy socks5h://127.0.0.1:19898 --silent --fail --max-time 6 "$1" >/dev/null 2>&1; }
if ! probe https://api4.ipify.org && ! probe https://www.cloudflare.com/cdn-cgi/trace; then
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
                    err_detail = (res.stderr or res.stdout or '').strip()
                    # 🔴 2026-10-28 修：裸 bash -c 脚本失败时 stderr 常为空
                    # （set -e 中断、无 trap），旧代码会回一句「安装失败: 安装失败」
                    # —— 与没说一样，且没有任何落盘日志可查。
                    # 现在：a) 兜底文案写明最常见根因与排查命令；
                    # b) 尾部输出写进 stderr 日志（journalctl -u hysteria-portal 可见）。
                    if not err_detail:
                        print('[portal] install-warp failed rc=%d stdout_tail=%r' % (
                            res.returncode, (res.stdout or '')[-500:]), file=sys.stderr, flush=True)
                        err_detail = ('脚本中断且无错误输出（rc=%d）。常见原因：apt 源不可达、'
                                      'wgcf 注册接口被限流。排查：journalctl -u hysteria-portal -n 50'
                                      % res.returncode)
                    return self.reply_json(500, {'ok': False, 'error': f'安装失败: {err_detail[-400:]}'})

                # Install success is not routing success: apply the domain ACL
                # directly, never call the legacy script with mismatched arguments.
                with data_lock:
                    data['warp_enabled'] = True
                    data.setdefault('warp_rules', list(DEFAULT_WARP_DOMAINS))
                save_data()
                return self._reply_with_warp_apply({
                    'message': 'WARP 通道安装完成，正在应用分流配置。',
                })
            except Exception as e:
                return self.reply_json(500, {'ok': False, 'error': f'执行异常: {str(e)}'})

        def do_GET(self):
            # 存活探针：面板自更新后据此判断新版本是否真的起来了（失败则回滚）。
            # 无需鉴权、不含任何数据，只回答「进程活着且能处理请求」。
            if self.path.split('?', 1)[0] == '/api/health':
                return self.reply_json(200, {'ok': True})
            if self.path.startswith('/api/v1/'):
                if not self.check_rate_limit(bucket='api'):
                    return self.reply(429, b'Too many requests')
                if not self.verify_api_key():
                    return self.reply_json(401, {'ok': False, 'error': 'Unauthorized API key'})
                sub = self.path[len('/api/v1/'):].split('?', 1)[0]
                # 下方比较前 sub 已在上游剥掉 query（见 8160 行 split('?', 1)[0]），
                # speedtest / unlock-check 处再剥一次是历史遗留的双保险 ——
                # 保留无害。🔴 2026-10-28 更正：旧注释声称「既有端点
                # (node/meta、users/list…) 会因 query 落空 → 404」已不成立，
                # 上游统一剥 query 后所有端点都扛得住 `/api/v1/node/meta?x=1`。
                # 该注释误导过排障方向（让人以为 404 是 query 引起的），删除。
                if sub.split('?', 1)[0] == 'speedtest':
                    return self._h_api_speedtest()
                if sub.split('?', 1)[0] == 'unlock-check':
                    return self._h_api_unlock_check()
                if sub == 'capabilities':
                    # 节点能力总览（2026-10-04 加）。
                    #
                    # 为什么需要：主面板要一眼知道「这台节点有什么、什么版本、
                    # 什么开着」。此前这些信息散在 /reality-status、/bbr-status、
                    # /warp-status、/awg-state 等多个端点上，而且**全部走网页会话
                    # 鉴权**（is_authenticated），Bearer api_key 够不到 ——
                    # 于是主面板只能显示"未知"。
                    #
                    # 设计边界（很重要）：
                    #   * 只暴露**能力、状态与客户端公开参数**。
                    #   * **服务端机密绝不出现**：private_key、api_key、任何用户的密码。
                    #   * 为什么公开参数（pbk/sid/sni）可以在这里给：
                    #     它们本来就会写进下发给客户端的订阅链接，属于「客户端
                    #     配置必须携带的公开值」，不是机密。主面板要生成合并
                    #     订阅就必须拿到它们。
                    #   * 收窄到**白名单**（见 _reality_public_params）：只挑
                    #     明确要用的几个键，不做整字典透传 —— 这样以后
                    #     reality_config 里新增任何字段都不会自动泄漏出去。
                    m = read_meta_file(meta_path)
                    with data_lock:
                        d_snap = {
                            'reality': dict(config_section(data, 'reality_config')),
                            'vmess': dict(config_section(data, 'vmess_config')),
                            'vlessenc': dict(config_section(data, 'vlessenc_config')),
                            'anytls': dict(config_section(data, 'anytls_config')),
                            'warp_enabled': bool(data.get('warp_enabled')),
                            'users_count': len(user_table(data)),
                            'proxy_services': proxy_services(data),
                        }
                    # 协议是否真的在服务，以 xray.json 里有没有托管入站为准 ——
                    # data 里的配置是「上次生成成功」的残留，停用后仍在。
                    try:
                        _xcfg = json.loads(Path('/etc/hysteria/xray.json')
                                           .read_text(encoding='utf-8'))
                        d_snap['vmess_inbound'] = managed_inbound_active(_xcfg, VMESS_INBOUND_TAG)
                        d_snap['reality_inbound'] = managed_inbound_active(_xcfg, REALITY_INBOUND_TAG)
                        d_snap['vlessenc_inbound'] = managed_inbound_active(_xcfg, VLESSENC_INBOUND_TAG)
                    except Exception:
                        d_snap['vmess_inbound'] = False
                        d_snap['reality_inbound'] = False
                        d_snap['vlessenc_inbound'] = False

                    def _svc_active(unit):
                        try:
                            out = subprocess.run(['systemctl', 'is-active', unit],
                                                 capture_output=True, text=True,
                                                 timeout=3).stdout.strip()
                            return out == 'active'
                        except Exception:
                            return False

                    def _bin(name):
                        return Path('/usr/local/bin/' + name).exists()

                    def _bbr_now():
                        """读当前内核拥塞控制算法。返回 (是否 BBR 系, 算法名)。

                        ⚠️ 每个请求跑一次 sysctl 是本意：BBR 是**内核运行态**，
                        缓存它会让面板显示与真实状态脱节（刚开完 BBR 却仍显示 cubic）。
                        sysctl -n 是纯内存读取，开销可忽略。
                        """
                        try:
                            cc = subprocess.run(
                                ['sysctl', '-n', 'net.ipv4.tcp_congestion_control'],
                                capture_output=True, text=True, timeout=3
                            ).stdout.strip()
                        except Exception:
                            cc = ''
                        return (cc.startswith('bbr'), cc)

                    # 节点门户自身版本：这个文件里写着版本号常量，
                    # 主面板据此判断"节点跑的是新 portal 还是老 portal"。
                    portal_version = ''
                    try:
                        for line in Path(__file__).read_text(encoding='utf-8').splitlines()[:80]:
                            if line.startswith('PORTAL_VERSION'):
                                portal_version = line.split('=', 1)[1].strip().strip('"\'')
                                break
                    except Exception:
                        portal_version = ''

                    return self.reply_json(200, {
                        'ok': True,
                        'portal_version': portal_version,
                        'generated_at': int(time.time()),
                        'protocols': {
                            # 主协议恒有；其余按实际安装情况报。
                            'hysteria2': {
                                'installed': True,
                                'active': _svc_active('hysteria-server'),
                                'port': int(m.get('listen_port', 0) or 0),
                            },
                            'vless_reality': dict(
                                {
                                    'installed': _bin('xray'),
                                    # 与 /reality-status 同一判据：看 Reality 入站是否存在。
                                    # 只看 Xray 进程会让「只开了 VMess」的节点报 Reality 运行中。
                                    'active': d_snap['reality_inbound'],
                                    'port': int(d_snap['reality'].get('port', 0) or 0),
                                    # 是否已配置。
                                    #
                                    # short_id 是配置过的可靠标志（每次生成配置都会写它）。
                                    'configured': bool(d_snap['reality'].get('short_id')),
                                },
                                # ---- 客户端公开参数（2026-10-04 加）----
                                #
                                # 为什么必须给：主面板要把 Reality 接进**合并订阅**，
                                # 就必须知道每台节点自己的 pbk / sid / sni。
                                # 此前只有节点 Web 会话能看到这些值，Bearer 通道
                                # 拿不到 —— 于是面板只能下发 Hy2，订阅里永远没有
                                # Reality（2026-10-04 实测确认的缺口）。
                                #
                                # 边界（很重要）：这里给的是**客户端配置必须携带的
                                # 公开值** —— pbk/sid/sni 本来就会写进订阅链接，
                                # 客户端人手一份，不是机密。
                                # **private_key 永远不在此输出**，它才是真正的服务端机密。
                                **_reality_public_params(d_snap['reality']),
                            ),
                            # VMess-WS-TLS（2026-10-24 加）。与 Reality 一样只给
                            # 客户端公开参数；ws_path 本来就是订阅里的公开路径，
                            # 证书私钥路径绝不在此输出。
                            'vmess': dict(
                                {
                                    'installed': _bin('xray'),
                                    'active': d_snap['vmess_inbound'],
                                    'configured': bool(d_snap['vmess'].get('domain')),
                                },
                                **({'port': int(d_snap['vmess'].get('port') or 0)}
                                   if d_snap['vmess'].get('port') else {}),
                                **({'domain': d_snap['vmess']['domain']}
                                   if d_snap['vmess'].get('domain') else {}),
                                **({'ws_path': d_snap['vmess']['ws_path']}
                                   if d_snap['vmess'].get('ws_path') else {}),
                                **({'sni': d_snap['vmess']['sni']}
                                   if d_snap['vmess'].get('sni') else {}),
                            ),
                            # VLESS Encryption：同样只暴露客户端需要的参数，
                            # decryption（服务端私钥）绝不出现在这里。
                            'vlessenc': dict(
                                {
                                    'installed': _bin('xray'),
                                    'active': d_snap['vlessenc_inbound'],
                                    'configured': bool(d_snap['vlessenc'].get('domain')),
                                },
                                **({'port': int(d_snap['vlessenc'].get('port') or 0)}
                                   if d_snap['vlessenc'].get('port') else {}),
                                **({'domain': d_snap['vlessenc']['domain']}
                                   if d_snap['vlessenc'].get('domain') else {}),
                                **({'sni': d_snap['vlessenc']['sni']}
                                   if d_snap['vlessenc'].get('sni') else {}),
                            ),
                            # AnyTLS（2026-10-29 补）：由独立的 sing-box 进程承载，
                            # 所以 installed 看 sing-box、active 看 hy2-anytls 服务。
                            # 同样只给客户端公开参数，secret（服务端派生密钥）不外泄。
                            'anytls': dict(
                                {
                                    'installed': bool(_singbox_version()),
                                    # 与 /anytls-status、_active_*_config 同一判据：
                                    # 「已启用且配置文件在」。只看服务状态会在
                                    # 配置被删/损坏但进程还在时误报能力可用。
                                    'active': _active_anytls_config() is not None
                                              and _svc_active(ANYTLS_SERVICE),
                                    'configured': bool(d_snap['anytls'].get('domain')),
                                },
                                **({'port': int(d_snap['anytls'].get('port') or 0)}
                                   if d_snap['anytls'].get('port') else {}),
                                **({'domain': d_snap['anytls']['domain']}
                                   if d_snap['anytls'].get('domain') else {}),
                                **({'sni': d_snap['anytls']['sni']}
                                   if d_snap['anytls'].get('sni') else {}),
                            ),
                        },
                        'extras': {
                            'gost': {'installed': _bin('gost'),
                                     'active': _svc_active('gost'),
                                     'services': len(d_snap['proxy_services'])},
                            'amneziawg': {'installed': _bin('amneziawg-go'),
                                          'active': _svc_active('amneziawg-go')},
                            'warp': {'installed': Path('/etc/hysteria/warp').exists()
                                     or _bin('wireproxy'),
                                     'enabled': d_snap['warp_enabled']},
                            'bbr': {'enabled': _bbr_now()[0], 'algo': _bbr_now()[1]},
                            # 证书到期一并带出（2026-10-09）：主面板的节点列表
                            # 需要在**到期前**就把临期节点标出来，而不是等用户
                            # 报障「昨天还好好的今天连不上」才回来查。只给面板
                            # 排障必需的最小字段，不泄露私钥之类的东西。
                            'cert': _cert_summary(meta_path.parent, m),
                        },
                        'node': {
                            'public_ip': m.get('public_ip', ''),
                            'server_name': m.get('server_name', ''),
                            'is_insecure': bool(m.get('is_insecure')),
                            'hop_port_range': m.get('hop_port_range', ''),
                            'users_count': d_snap['users_count'],
                        },
                    })
                if sub.startswith('users/get/'):
                    user_id = sub[len('users/get/'):]
                    if not VALID_USER_ID_RE.match(user_id):
                        return self.reply_json(400, {'ok': False, 'error': 'Invalid user_id format'})
                    with data_lock:
                        u = data.get('users', {}).get(user_id)
                        missing_user = u is None
                        result = None
                        if u is not None:
                            result = {k: v for k, v in u.items() if k not in ('password', 'view_nonce')}
                            # 与 users/list 对齐：同时给 traffic_* 与原始名，任一套都能读到。
                            result.setdefault('traffic_limit_bytes', result.get('limit_bytes', 0))
                            result.setdefault('traffic_used_bytes', result.get('used_bytes', 0))
                    if missing_user:
                        # 锁内只判定；回包放在锁外，避免慢客户端阻塞 /auth。
                        return self.reply_json(404, {'ok': False, 'error': 'User not found'})
                    return self.reply_json(200, {'ok': True, 'user_id': user_id, 'user': result})
                if sub == 'node/traffic':
                    try:
                        counters = node_traffic_counters()
                    except Exception as e:
                        return self.reply_json(500, {'ok': False, 'error': 'read counters failed: ' + str(e)[:120]})
                    with data_lock:
                        suspended = suspend_state(data).get('suspended') is True
                    counters.update({'ok': True, 'suspended': suspended, 'time': int(time.time())})
                    return self.reply_json(200, counters)
                if sub == 'node/meta':
                    m = read_meta_file(meta_path)
                    with data_lock:
                        users_count = len(user_table(data))
                    # 🔴 白名单，2026-10-09 修（真实泄漏）：
                    # 原来直接把整个 client_meta.json 原样返回，而 install.sh 往里写了
                    # auth_password 与 obfs_password。api_key 是**低权限**凭据
                    # （见 page_html 里那段说明：权限低于 Basic，够不着网页端），
                    # 把它按设计发到商城/自动化脚本手上，却顺带送了机主密码 ——
                    # 无限流量、不过期。用低权限凭据换高权限凭据就是提权。
                    # 实测已确认 auth_password / obfs_password 都被返回。
                    # capabilities 早就是白名单的，这里对齐同一套做法。
                    _secret_keys = {'auth_password', 'obfs_password', 'pin_sha256'}
                    public_meta = {k: v for k, v in m.items() if k not in _secret_keys}
                    return self.reply_json(200, {'ok': True, 'meta': public_meta, 'users_count': users_count, 'time': int(time.time())})
                if sub == 'users/list':
                    # BUGFIX #10: 商城节点对账用, 列出所有动态用户 (脱敏不返回 password)
                    now_ts = int(time.time())
                    users_out = []
                    node_gaps = []
                    node_sources = {}
                    with data_lock:
                        for uid, info in users_list_rows(data.get('users')):
                            summary, node_gaps, node_sources = usage_list_summary(uid)
                            entry = users_list_entry(uid, info, ip_tracker, now_ts,
                                                     summary, IP_TIMEOUT_SECONDS)
                            if entry is not None:
                                users_out.append(entry)
                    return self.reply_json(200, {'ok': True, 'count': len(users_out), 'users': users_out,
                                                 'measurement_gaps': node_gaps,
                                                 'measurement_sources': node_sources})
                if sub == 'proxy-services/list':
                    with data_lock:
                        items = proxy_services(data)
                    # 面板只看这条 API: 补齐 host 与 gost 运行状态,
                    # 否则列表显示不出主机名, 也无法区分"服务真的可用"和"条目存在".
                    m = read_meta_file(meta_path)
                    host = m.get('public_ip', '127.0.0.1') if m.get('is_insecure') else m.get('server_name', 'localhost')
                    return self.reply_json(200, {
                        'ok': True,
                        'count': len(items),
                        'gost_installed': Path('/usr/local/bin/gost').exists(),
                        'gost_active': gost_status(),
                        'host': host,
                        'services': items,
                    })
                return self.reply_json(404, {'ok': False, 'error': 'API endpoint not found'})

            if not self.check_rate_limit(bucket='web'):
                return self.reply(429, b'Too many requests')

            prefix = '/' + data['token'] + '/'
            if not self.path.startswith(prefix):
                return self.reply(404, b'Not found')

            subpath = self.path[len(prefix):].split('?', 1)[0]
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

                authed = self.is_authenticated()
                with data_lock:
                    u = data.get('users', {}).get(target_uid)
                    u_copy = dict(u) if u else None

                query = parse_qs(self.path.split('?', 1)[1]) if '?' in self.path else {}
                k_val = query.get('k', [''])[0]
                expected_k = (user_view_key(session_secret, target_uid, u_copy.get('view_nonce', ''))
                              if u_copy else '')

                if not authed:
                    # ⚠️ 顺序很重要（2026-10-29 修）：
                    #   1. 未鉴权时「用户不存在」必须与「key 错误」返回同一个响应，
                    #      否则知道门户 token 的人可以逐个试出哪些 user_id 存在；
                    #   2. hmac.compare_digest 遇到非 ASCII 的 str 会抛 TypeError
                    #      （do_GET 没有兜底，连接直接被重置），所以先挡非 ASCII。
                    ok_key = (bool(k_val) and k_val.isascii() and u_copy is not None
                              and hmac.compare_digest(k_val, expected_k))
                    if not ok_key:
                        return self.reply(403, b'Access denied: invalid key')
                elif u_copy is None:
                    return self.reply(404, b'User not found')
                # 管理员已通过登录鉴权时可以查看任意用户（包括已停用的）：
                # 核对配置、重发凭据都是正当操作，页面本身也会标明账号状态。
                # 只有走分享链接（未鉴权）的访问才需要拦。
                if not authed and not user_share_available(u_copy):
                    # 区分原因，给一条人能看懂的说明（旧实现只有一行英文 403）。
                    now_ts = int(time.time())
                    limit_b = int(u_copy.get('limit_bytes', 0) or 0)
                    used_b = int(u_copy.get('used_bytes', 0) or 0)
                    exp = u_copy.get('expires_at')
                    if u_copy.get('status', 'active') != 'active':
                        reason = '账号已被停用'
                    elif exp is not None and exp <= now_ts:
                        reason = '服务已到期'
                    elif limit_b > 0 and used_b >= limit_b:
                        reason = '流量已超额'
                    else:
                        reason = '当前不可用'
                    return self.reply(403, share_unavailable_html(reason).encode('utf-8'),
                                      'text/html; charset=utf-8')

                m = read_meta_file(meta_path)
                # meta 损坏时 artifacts 会退回 localhost/默认端口，生成一条
                # 永远连不上的链接却返回 200（2026-10-29 修）。
                if not (m.get('server_name') or m.get('public_ip')):
                    return self.reply(503, share_unavailable_html(
                        '节点元信息缺失或损坏，请联系管理员检查 client_meta.json').encode('utf-8'),
                        'text/html; charset=utf-8')
                # 密码缺失/被改坏时不能生成链接：空密码会拼出
                # `hysteria2://@host`，客户端导入即失败，页面却显示成功。
                pwd = u_copy.get('password')
                if not isinstance(pwd, str) or not pwd:
                    return self.reply(503, share_unavailable_html(
                        '该账号的密码为空或已损坏，请联系管理员重置密码').encode('utf-8'),
                        'text/html; charset=utf-8')
                uri, clash_yaml, sing_json = artifacts(
                    m, auth_override=pwd, name_override=f"Hy2-{target_uid}",
                    reality=_active_reality_config(), user_id=target_uid,
                    vmess=_active_vmess_config(),
                    vlessenc=_active_vlessenc_config(),
                    anytls=_active_anytls_config())

                if action_file == 'clash.yaml':
                    return self.reply(200, clash_yaml.encode('utf-8'), 'application/yaml')
                elif action_file == 'sing-box.json':
                    return self.reply(200, sing_json.encode('utf-8'), 'application/json')
                elif action_file == 'qr.svg':
                    try:
                        qr_bytes = subprocess.run(['qrencode', '-t', 'SVG', '-o', '-'], input=uri.encode(), capture_output=True, check=True, timeout=10).stdout
                        return self.reply(200, qr_bytes, 'image/svg+xml')
                    except Exception:
                        return self.reply(500, b'QR generation failed')
                elif action_file == '':
                    try:
                        qr_svg = subprocess.run(['qrencode', '-t', 'SVG', '-o', '-'], input=uri.encode(), capture_output=True, check=True, timeout=10).stdout.decode('utf-8')
                    except Exception:
                        qr_svg = ''
                    server_name = m.get('server_name') or m.get('public_ip', 'localhost')
                    host = m.get('public_ip', server_name) if m.get('is_insecure') else server_name
                    listen_port = m.get('listen_port', 19984)
                    obfs_badge = "Salamander" if m.get('obfs_password') else "QUIC"
                    page = user_page_html(server_name, host, listen_port, obfs_badge, target_uid, u_copy, uri, clash_yaml, sing_json, qr_svg, data['token'], expected_k, resolve_subscription_port(m)[0])
                    return self.reply(200, page.encode('utf-8'), 'text/html; charset=utf-8')
                else:
                    return self.reply(404, b'Not found')

            # 2. 版本检查与更新 API
            if subpath == 'traffic-speed':
                return self._h_get_traffic_speed(subpath)

            if subpath == 'proxy-services':
                return self._h_get_proxy_services(subpath)

            if subpath == 'check-version':
                return self._h_get_check_version(subpath)

            if subpath == 'reality-status':
                return self._h_get_reality_status(subpath)

            if subpath == 'vmess-status':
                return self._h_get_vmess_status(subpath)

            if subpath == 'vlessenc-status':
                return self._h_get_vlessenc_status(subpath)

            if subpath == 'anytls-status':
                return self._h_get_anytls_status(subpath)

            if subpath == 'cores-status':
                return self._h_get_cores_status(subpath)

            if subpath == 'bbr-status':
                return self._h_get_bbr_status(subpath)

            if subpath == 'upgrade-status':
                if not self.is_authenticated():
                    return self.reply_json(401, {'ok': False, 'error': 'Unauthorized'})
                with data_lock:
                    _job_now = data.get('core_upgrade')
                    job = dict(_job_now) if isinstance(_job_now, dict) else {}
                return self.reply_json(200, {'ok': True, 'job': job})

            if subpath == 'warp-status':
                return self._h_get_warp_status(subpath)

            # ---------------- 自定义出站（读） ----------------
            # 🔴 走 prefix（网页会话）而不是 /api/v1/（api_key）：
            #    出站含代理地址与凭据，属于管理操作，
            #    必须走管理员会话，不能仅凭 api_key 就能改流量出口。
            if subpath == 'outbounds/list':
                return self._ob_list()
            #🔴 self.path 是**含 query** 的原始路径：
            #   `outbounds/probe?kind=direct` 会让 subpath 变成
            #   `outbounds/probe?kind=direct`，等值比较直接落空 → 404。
            #   本项目多个既有端点都有这个毛病，这里新端点自己扛住：先剥 query。
            if subpath.split('?', 1)[0] == 'outbounds/probe':
                return self._ob_probe()

            if subpath == 'cert-status':
                return self._h_get_cert_status(subpath)

            if subpath == 'user-config' or subpath.startswith('user-config?'):
                if not self.is_authenticated():
                    return self.reply_json(401, {'ok': False, 'error': 'Unauthorized'})
                query = parse_qs(self.path.split('?', 1)[1]) if '?' in self.path else {}
                target_uid = query.get('user_id', [''])[0].strip()
                if not VALID_USER_ID_RE.match(target_uid):
                    return self.reply_json(400, {'ok': False, 'error': 'Invalid user_id format'})
                with data_lock:
                    u = data.get('users', {}).get(target_uid)
                    u_copy = dict(u) if u else None
                if not u_copy:
                    # 锁内只判定；回包放在锁外，避免慢客户端阻塞 /auth。
                    return self.reply_json(404, {'ok': False, 'error': 'User not found'})

                m = read_meta_file(meta_path)
                pwd = u_copy.get('password')
                if not isinstance(pwd, str) or not pwd:
                    return self.reply_json(503, {'ok': False,
                        'error': '该账号的密码为空或已损坏，请先重置密码再导出配置'})
                uri, clash_yaml, sing_json = artifacts(
                    m, auth_override=pwd, name_override=f"Hy2-{target_uid}",
                    reality=_active_reality_config(), user_id=target_uid,
                    vmess=_active_vmess_config(),
                    vlessenc=_active_vlessenc_config(),
                    anytls=_active_anytls_config())
                qr_svg = ""
                try:
                    qr_svg = subprocess.run(['qrencode', '-t', 'SVG', '-o', '-'], input=uri.encode(), capture_output=True, check=True, timeout=10).stdout.decode('utf-8')
                except Exception as exc:
                    _log_ignored('qr_svg', exc)

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
                return self._h_get_awg_state(subpath)

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

                # 客户端不存在时给 404，而不是让底层命令失败后统一报 500 ——
                # 前端需要能区分「查无此人」与「服务端出错」。
                peers_now = awg_read_json(AWG_PEERS_PATH, {}).get('peers', []) or []
                if not any(p.get('name') == name for p in peers_now):
                    return self.reply(404, b'Client not found')

                # 连接地址优先用查询参数，其次用安装时记录的 endpoint
                endpoint = (query.get('endpoint', [''])[0] or '').strip() or awg_state()['endpoint']
                if not endpoint:
                    return self.reply(400, b'Endpoint not configured; re-run install with an endpoint')
                # 与 POST 通道同一校验：换行/空白能注入客户端配置行。
                if not VALID_AWG_ENDPOINT_RE.fullmatch(endpoint):
                    return self.reply(400, b'Invalid endpoint format')

                try:
                    rc, out, err = awg_run(['client-conf', name, '--endpoint', endpoint], timeout=60)
                except Exception as exc:
                    return self.reply(500, ('error: ' + str(exc)).encode('utf-8'))
                if rc != 0 or not out.strip():
                    return self.reply(500, awg_err_tail(rc, out, err, 400).encode('utf-8'))

                if awg_route == 'awg-conf':
                    body = out.encode('utf-8')
                    self.send_response(200)
                    self._responded = True
                    self.send_header('Content-Type', 'text/plain; charset=utf-8')
                    # 名称虽已过 VALID_AWG_NAME_RE，仍是全文件唯一一处把变量
                    # 直接拼进响应头的位置。统一再白名单过滤一遍，杜绝 CRLF。
                    safe_name = re.sub(r'[^A-Za-z0-9_.\-]', '_', str(name))[:64] or 'client'
                    self.send_header('Content-Disposition',
                                     'attachment; filename="' + safe_name + '.conf"')
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
            # 🔴 2026-10-09 修（真机演练发现）：clash.yaml / sing-box.json / qr.svg
            # 必须**每次都重生成**，不能直接吐内存里的 data[key]。
            #
            # 原因：selfheal 是在**另一个短命进程**里跑的（systemd timer/path unit
            # 调 `portal.py selfheal`），它把修好的产物写进了 portal.json；而本门户
            # 进程持有的 data 是**启动时的内存快照**，对这些磁盘写入一无所知。
            # 于是磁盘上是新的、端点发出去的是旧的 —— 实测（容器内真机演练）：
            #   meta / portal.json / 页面直链  = round2.example.com  ✅
            #   clash.yaml 端点              = newnode.example.com  ❌
            # 用户扫二维码/导入订阅就是旧节点，直接 CRYPTO_ERROR 0x150。
            # 页面之所以是对的，只因为 subpath=='' 分支恰好会调 regenerate_page()。
            if key in ('clash', 'sing', 'qr'):
                regenerate_page()
            with data_lock:
                # 用 .get：qrencode 从未成功时 data 里可能根本没有 'qr'
                # （例如从旧备份恢复的 portal.json），旧实现会 KeyError 并
                # 直接掐断连接，而不是返回一个可读的错误（2026-10-29 修）。
                # 值也可能被改成数字/列表：`.encode()` 抛 AttributeError，
                # 连接照样被掐断 —— 这是用户点「下载配置」的路径。
                raw_content = data.get(key)
                content = raw_content.encode() if isinstance(raw_content, str) else b''
            self.reply(200, content, mime)

        # ==========================================================================
        # do_GET 各端点的处理逻辑（同样是纯代码搬移，逻辑未改）
        # 参数按每个分支实际用到的上下文变量自动生成 —— 用到才传，不用不传。
        # ==========================================================================

        def _h_get_traffic_speed(self, subpath):
            """GET /traffic-speed 的处理逻辑（从 do_GET 机械搬移而来）。"""
            if not self.is_authenticated():
                return self.reply_json(401, {'ok': False, 'error': 'Unauthorized'})
            cur_mono = time.monotonic()
            total_rx_speed = 0.0
            total_tx_speed = 0.0
            user_speeds = {}

            with data_lock:
                # 内存里的速率样本可能是旧格式（列表）或半截元组；采样循环
                # 内部也会写这个字典。任何一条坏样本都不能让 /traffic-speed
                # 每 2 秒 500（控制台首页实时流量整块空白）。
                # 整个字典被替换成非 dict 时只读本次的空视图，不回写。
                tracker = speed_tracker if isinstance(speed_tracker, dict) else {}
                for uid, sources in list(tracker.items()):
                    if not isinstance(user_table(data).get(uid), dict):
                        tracker.pop(uid, None)
                        continue
                    recent = {}
                    if isinstance(sources, dict):
                        for source, sample in sources.items():
                            if (isinstance(sample, (tuple, list)) and len(sample) >= 3
                                    and all(isinstance(v, (int, float))
                                            and not isinstance(v, bool) for v in sample[:3])
                                    and cur_mono - sample[0] <= SPEED_WINDOW_SECONDS):
                                recent[source] = sample
                    if recent:
                        speed_tracker[uid] = recent
                    else:
                        # 全部过期就整条删掉。旧实现只把值改成 {}，键永远留着：
                        # 已删除的用户、改名后的旧 id 会一直占着条目，
                        # 长期运行的节点上这个字典只增不减（2026-10-25 修）。
                        speed_tracker.pop(uid, None)
                    u_tx_speed = sum(sample[1] for sample in recent.values())
                    u_rx_speed = sum(sample[2] for sample in recent.values())
                    total_tx_speed += u_tx_speed
                    total_rx_speed += u_rx_speed
                    user_speeds[uid] = {'tx': u_tx_speed, 'rx': u_rx_speed}
                for uid, user in users_list_rows(user_table(data)):
                    if not isinstance(user, dict):
                        continue
                    entry = user_speeds.setdefault(uid, {'tx': 0, 'rx': 0})
                    # /traffic-speed 是每 2 秒一次的高频轮询，前端只用
                    # used_bytes / measured_bytes / measurement_ok 三个字段。
                    # usage_summary 里的 measurement_gaps（最多 100 条）与
                    # measurement_sources 每个用户都要 deepcopy 一次，
                    # 响应体会随用户数平方级膨胀（实测 500 用户 5.4 MiB/次）。
                    # 2026-10-28 再收紧：改用 usage_hot_summary，把 deepcopy
                    # 本身也省掉 —— 只读标量，锁持有时间从 O(N×gaps) 降到 O(N)。
                    _summary = usage_hot_summary(uid)
                    entry['measured_bytes'] = _summary.get('measured_bytes')
                    entry['measurement_ok'] = _summary.get('measurement_ok')
                    entry['measurement_started_at'] = _summary.get('measurement_started_at')
                    entry['measurement_scope'] = _summary.get('measurement_scope')
                    entry['used_bytes'] = user.get('used_bytes', 0)

            return self.reply_json(200, {
                'ok': True,
                'node_tx': total_tx_speed,
                'node_rx': total_rx_speed,
                'users': user_speeds,
                'total_used_bytes': sum(u['used_bytes'] for u in user_speeds.values())
            })

        def _h_get_proxy_services(self, subpath):
            """GET /proxy-services 的处理逻辑（从 do_GET 机械搬移而来）。"""
            if not self.is_authenticated():
                return self.reply_json(401, {'ok': False, 'error': 'Unauthorized'})
            with data_lock:
                services = proxy_services(data)
            m = read_meta_file(meta_path)
            host = m.get('public_ip', '127.0.0.1') if m.get('is_insecure') else m.get('server_name', 'localhost')
            return self.reply_json(200, {
                'ok': True,
                'gost_installed': Path('/usr/local/bin/gost').exists(),
                'gost_active': gost_status(),
                'host': host,
                'services': services
            })

        def _h_get_check_version(self, subpath):
            """GET /check-version 的处理逻辑（从 do_GET 机械搬移而来）。"""
            if not self.is_authenticated():
                return self.reply_json(401, {'ok': False, 'error': 'Unauthorized'})
            query = parse_qs(self.path.split('?', 1)[1]) if '?' in self.path else {}
            if query.get('force', ['0'])[0] == '1':
                _ver_cache['t'] = 0.0
                _core_ver_cache['t'] = 0.0
            core_curr, core_latest, core_has_update = '未知', '', False
            try:
                out = subprocess.run(['/usr/local/bin/hysteria', 'version'], capture_output=True, text=True, timeout=3).stdout
                for line in out.splitlines():
                    if line.strip().startswith('Version:'):
                        core_curr = line.split(':', 1)[1].strip().removeprefix('v')
                        break
            except Exception as exc:
                _log_ignored('core_version', exc)
            now = time.time()
            if now - _core_ver_cache['t'] >= (300 if _core_ver_cache['tag'] else 30):
                try:
                    req = urllib.request.Request('https://api.github.com/repos/apernet/hysteria/releases/latest',
                                                 headers={'User-Agent': 'hysteria2-installer'})
                    with urllib.request.urlopen(req, timeout=3) as response:
                        release = json.loads(response.read().decode('utf-8'))
                    _core_ver_cache['tag'] = str(release.get('tag_name') or '').removeprefix('app/').removeprefix('v')
                except Exception:
                    _core_ver_cache['tag'] = ''
                _core_ver_cache['t'] = now
            core_latest = _core_ver_cache['tag']
            if core_version_key(core_curr) and core_version_key(core_latest):
                core_has_update = core_version_key(core_latest) > core_version_key(core_curr)

            # 面板自身与 AWG 引擎：用 git blob sha 比对文件内容。
            # 原实现依赖 data['portal_sha']，但那个字段从来没被写入过，
            # 导致 portal_has_update 恒为 False、「更新面板」按钮永远不显示。
            local_bundle = {name: _local_blob_sha(PORTAL_SELF.parent / name)
                            for name in PORTAL_BUNDLE_FILES}
            bundle_version = portal_bundle_version(local_bundle, _remote_root_shas())
            portal_curr = bundle_version['current']
            portal_latest = bundle_version['latest']
            portal_has_update = bundle_version['has_update']
            awg_curr, awg_latest, awg_has_update = _version_triple(
                AWG_CTL, 'awgctl.sh')

            return self.reply_json(200, {
                'ok': True,
                'core_current': core_curr,
                'core_custom': '+' in core_curr,
                'core_latest': core_latest,
                'core_has_update': core_has_update,
                'portal_current': portal_curr,
                'portal_latest': portal_latest,
                'portal_has_update': portal_has_update,
                'portal_update_status': bundle_version['status'],
                'portal_bundle': {
                    'files': local_bundle,
                    'status': bundle_version['status'],
                    'changed_files': bundle_version['changed_files'],
                    'unknown_files': bundle_version['unknown_files'],
                    'runtime_revision': getattr(_usage_runtime, 'ACCOUNTING_REVISION', '')
                                        if usage_meter is not None else '',
                    'meter_initialized': usage_meter is not None,
                    'measurement': usage_summary(MASTER_USER_ID),
                },
                'awg_installed': Path(AWG_CTL).exists(),
                'awg_current': awg_curr,
                'awg_latest': awg_latest,
                'awg_has_update': awg_has_update,
            })

        def _h_get_reality_status(self, subpath):
            """GET /reality-status 的处理逻辑（从 do_GET 机械搬移而来）。"""
            if not self.is_authenticated():
                return self.reply_json(401, {'ok': False, 'error': 'Unauthorized'})
            is_installed = Path('/usr/local/bin/xray').exists()
            # 判据必须是「Reality 入站是否存在」，不能只看 Xray 进程：
            # VMess 上线后，只开 VMess 的节点上 Xray 同样是 active，
            # 按进程判断会让 Reality 卡片显示「运行中」，而用户拿到的
            # Reality 链接根本连不上（2026-10-24 接入 VMess 时暴露）。
            is_active = False
            if is_installed:
                try:
                    xray_path = Path('/etc/hysteria/xray.json')
                    if xray_path.exists():
                        is_active = managed_inbound_active(
                            json.loads(xray_path.read_text(encoding='utf-8')),
                            REALITY_INBOUND_TAG)
                except Exception:
                    is_active = False

            with data_lock:
                rcfg = dict(config_section(data, 'reality_config'))

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
                    # 停用后不再下发 URI（与 VMess / VLESS Encryption 对齐）：
                    # 前端虽已隐藏内容区，但接口仍返回可用链接会误导脚本调用方。
                    'uri': rcfg.get('uri', '') if is_active else '',
                    'uuid': rcfg.get('uuid', ''),
                    'pub_key': rcfg.get('public_key', ''),
                    'short_id': rcfg.get('short_id', ''),
                    'flow': 'xtls-rprx-vision',
                    'sni': rcfg.get('dest_sni', 'www.apple.com'),
                    'port': rcfg.get('port', 443) if is_active else 0,
                    'qr_svg': qr_svg if is_active else ''
                }
            })

        def _h_api_unlock_check(self):
            """GET /api/v1/unlock-check —— 在节点本机检测流媒体 / AI 服务解锁情况（2.8 加）。

            与 /api/v1/speedtest 同一安全边界：检测目标**完全硬编码**在
            UNLOCK_CHECKS 里，调用方传不进任何 URL —— 否则这就是一个
            以节点 IP 出口的任意 HTTP 代理。
            各项并发执行、单项 8 秒超时，整体约 10 秒内返回。
            """
            self._extend_deadline(60)
            results = run_unlock_checks()
            return self.reply_json(200, {'ok': True, 'results': results, 'time': int(time.time())})

        def _h_api_speedtest(self):
            """GET /api/v1/speedtest —— 在**节点本机**测到大陆三网的 ICMP 延迟。

            为什么需要这个端点
            ------------------
            运维面板原先只能 SSH 到节点跑探针脚本。没绑 SSH 凭据的节点压根测不了，
            页面上是四行「未测得」—— 而那不是线路问题，是没通道。
            节点本来就有 Bearer 鉴权的 /api/v1/ 通道，于是把测速放这里。

            与 SSH 通道的关系
            ----------------
            这是**补充**，不是取代：
              - SSH 通道：节点零改动即可用，靶点表在面板侧可配，
                但需要主机凭据，凭据失效就整台没数据。
              - 本通道：不需要任何主机凭据，但要求 portal ≥ 本版本。
            面板侧按「有 SSH 走 SSH，没有才走 portal」的顺序自动选择。

            安全边界（这是本端点最要紧的部分）
            ------------------------------------
            **靶点完全硬编码，调用方一个字节都传不进来。**
            最初的设想是让面板传一串目标过来，理由是"靶点可配"。
            那等于开了一个任意 ICMP 探测器 —— 而更糟的是：
            本 portal 跑在 root 下、subprocess 直接拼命令，
            一旦目标串逃逸出引号就是本机 RCE。
            代价是"改靶点要改 portal"，这个代价**故意要付**：
            靶点表在面板侧（speedtest_targets），走 SSH 通道调整即可，
            而这条无凭据通道保持最小权限。

            并发与耗时
            ----------
            串行 ping：并发会互相推高延迟、测出来的数不可复现。
            18 个靶点 × 3 包 × 2 秒 ≈ 最坏 108 秒。本 portal 是
            ThreadingMixIn，不阻塞其他请求，但自己这条连接会等那么久。
            超时给 10 秒（单个 ping），整体由调用方的 HTTP 超时兜底。

            返回字段与面板 node_speedtests 对齐：
            icmp_avg_ms / icmp_loss_pct 为 null 表示"没测到"，
            与 0 区分 —— 0ms 和测不到是完全不同的意思。
            """
            # 依赖自检：没装 ping 就明确报 NO_PING，让上层知道
            # "这台机器测不了"而不是"靶点全不通"（两者含义完全不同）。
            if not shutil.which('ping'):
                return self.reply_json(200, {
                    'ok': False, 'error': 'NO_PING',
                    'error_label': '节点未安装 ping，无法测速',
                    'results': [],
                })
            # 18 个靶点 × 3 包，单个 ping 最坏 10 秒：并行后耗时约等于
            # 最慢的单个靶点，但 30 秒死线仍可能不够（丢包重传多的线路）。
            self._extend_deadline(120)

            # 并行探测（2026-10-25 修）。旧实现串行 ping 18 个靶点，
            # 每个最坏 10 秒 → 单请求可达 180 秒；而门户只有 8 个并发槽、
            # 连接期限 30 秒，期限只关 socket 不终止线程，槽位仍被占住。
            # 8 个这样的请求就能让 /auth 也拿不到槽位，所有用户掉线重连失败。
            # 并行后整体耗时约等于最慢的单个靶点。
            results = []
            with ThreadPoolExecutor(max_workers=min(8, len(SPEEDTEST_TARGETS))) as pool:
                measured_pairs = list(pool.map(lambda t: self._ping_one(t[2]),
                                               SPEEDTEST_TARGETS))
            for (key, name, host, carrier), (avg, loss) in zip(SPEEDTEST_TARGETS, measured_pairs):
                results.append({
                    'target_key': key,
                    'target_name': name,
                    'target_host': host,
                    'carrier': carrier,
                    'icmp_avg_ms': avg,
                    'icmp_loss_pct': loss,
                })

            measured = sum(1 for r in results if r['icmp_avg_ms'] is not None)
            return self.reply_json(200, {
                'ok': True,
                'results': results,
                'measured_targets': measured,
                'total_targets': len(results),
                'time': int(time.time()),
            })

        def _ping_one(self, host):
            """ping 一个靶点，返回 (avg_ms, loss_pct)，测不到时都是 None。

            解析要同时认两种 ping 实现：
              iputils:  rtt min/avg/max/mdev = 1.2/3.4/5.6/0.7 ms
              BusyBox:  round-trip min/avg/max = 1.2/3.4/5.6 ms
            共同点是 `= a/b/c` 且 avg 是第二项 —— 只锚定这个形状，
            不锚定前缀名。只认一种会让精简镜像的节点永远"未测得"，
            而界面上看不出原因。
            """
            try:
                # ⚠️ LC_ALL=C 是必需的（2026-10-09 修）：下面两个正则只认英文输出
                # （'% packet loss' / 小数点分隔的 `= a/b/c`）。在本地化 locale 下
                # 解析会全面失效 —— 实测 zh_CN 下丢包率解析不到，
                # de_DE 下连 avg 都解析不到（逗号当小数点），测速永远显示「未测得」。
                # -n 则保证 host 不会被当成命令选项。
                proc = subprocess.run(
                    ['ping', '-n', '-c', '3', '-W', '2', host],
                    capture_output=True, text=True, timeout=10,
                    env={**os.environ, 'LC_ALL': 'C', 'LANG': 'C'})
            except Exception:
                return None, None
            out = proc.stdout or ''

            loss = None
            m = re.search(r'([0-9]+(?:\.[0-9]+)?)%\s*packet loss', out)
            if m:
                try:
                    loss = min(100.0, max(0.0, float(m.group(1))))
                except ValueError:
                    loss = None

            avg = None
            m = re.search(r'=\s*([0-9.]+)/([0-9.]+)/[0-9.]+', out)
            if m:
                try:
                    avg = min(60000.0, max(0.0, float(m.group(2))))
                except ValueError:
                    avg = None
            return avg, loss

        def _h_get_bbr_status(self, subpath):
            """GET /bbr-status 的处理逻辑（从 do_GET 机械搬移而来）。"""
            if not self.is_authenticated():
                return self.reply_json(401, {'ok': False, 'error': 'Unauthorized'})
            try:
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

                # tcp_available_congestion_control 只列出**已加载**的模块：新机器上
                # tcp_bbr 还没 modprobe，只会看到 "reno cubic"，前端据此把按钮全禁用。
                # 所以把「内核里装了、可被 modprobe 的模块」也算作可用。
                available = subprocess.run(['sysctl', '-n', 'net.ipv4.tcp_available_congestion_control'],
                                           capture_output=True, text=True, timeout=2).stdout.split()
                for algo in ('bbr', 'bbr2', 'bbr3'):
                    if algo not in available and subprocess.run(
                            ['modinfo', '-n', 'tcp_' + algo], capture_output=True, timeout=2).returncode == 0:
                        available.append(algo)

                return self.reply_json(200, {
                    'ok': True,
                    'current': cc_out or '未知',
                    'available': available,
                    'qdisc': qdisc_out or 'fq_codel',
                    'kernel': kernel_ver,
                    'configured': configured_bbr or target_ver or cc_out,
                    'need_reboot': need_reboot
                })
            except Exception as e:
                return self.reply_json(500, {'ok': False, 'error': ('%s: %s' % (type(e).__name__, str(e)))[:160]})

        def _ob_list(self):
            """GET <prefix>outbounds/list —— 出站列表 + 模式 + 内建出站。"""
            if not self.is_authenticated():
                return self.reply_json(401, {'ok': False, 'error': 'Unauthorized'})
            with data_lock:
                outs = list(data.get('custom_outbounds', []))
                mode = data.get('outbound_mode', 'rules')
                rules = list(data.get('warp_rules', []))
                state = routing_state(data)
                applying = bool(data.get('egress_applying'))
                error = data.get('egress_apply_error') or data.get('outbound_apply_error', '')
            try:
                text = Path('/etc/hysteria/config.yaml').read_text(encoding='utf-8')
                applied = text == render_egress_config(text, state) and _hy2_config_loaded('/etc/hysteria/config.yaml')
            except Exception:
                applied = False

            return self.reply_json(200, {
                'ok': True,
                'mode': mode,
                'applying': applying, 'applied': applied and not applying, 'apply_error': error,
                'outbounds': outs,
                # 规则里的旧格式是纯字符串（只有域名），前端需要渲染成对象
                'rules': [({'domain': r, 'outbound': 'warp_socks'} if isinstance(r, str)
                           else dict(r)) for r in rules],
                'builtin': _existing_outbound_names(),
                'types': [{'id': k, 'label': v[0]} for k, v in OUTBOUND_TYPES.items()],
            })

        def _ob_probe(self):
            """GET <prefix>outbounds/probe?kind=&addr= —— 探测真实出口 IP。

            🔴 只探测、不改任何配置，可以放心反复点。
            这是用户判断"到底生效没有"的唯一依据。
            """
            if not self.is_authenticated():
                return self.reply_json(401, {'ok': False, 'error': 'Unauthorized'})
            query = parse_qs(self.path.split('?', 1)[1]) if '?' in self.path else {}
            kind = (query.get('kind', ['direct'])[0] or 'direct').strip().lower()
            addr = (query.get('addr', [''])[0] or '').strip()
            if kind not in ('direct', 'auto', 'warp', 'socks5', 'http') or (kind in ('socks5', 'http') and not addr):
                return self.reply_json(400, {'ok': False, 'error': 'Invalid outbound probe type or missing address'})
            ip = detect_outbound_ip(kind, addr)
            return self.reply_json(200, {'ok': True, 'ip': ip, 'kind': kind})

        def _ob_manage(self):
            """POST <prefix>manage-outbounds —— 出站增删改 / 模式切换 / 规则增删。"""
            if not self.is_authenticated():
                return self.reply_json(401, {'ok': False, 'error': 'Unauthorized'})
            try:
                length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(length).decode('utf-8', errors='replace') if length > 0 else ''
                form = parse_qs(body)
            except Exception:
                return self.reply_json(400, {'ok': False, 'error': 'Bad request'})
            action = (form.get('action', [''])[0] or '').strip().lower()
            if not action:
                return self.reply_json(400, {'ok': False, 'error': '缺少 action 参数'})

            msg = ''
            # ---------- 出站增删改 ----------
            if action in ('save', 'delete'):
                if action == 'save':
                    entry = {
                        'name': (form.get('name', [''])[0] or '').strip(),
                        'type': (form.get('type', [''])[0] or '').strip().lower(),
                        'addr': (form.get('addr', [''])[0] or '').strip(),
                        'url': (form.get('url', [''])[0] or '').strip(),
                        'username': (form.get('username', [''])[0] or '').strip(),
                        'password': (form.get('password', [''])[0] or '').strip(),
                        'insecure': (form.get('insecure', [''])[0] or '').strip(),
                        # 🔴 键名必须与 validate_outbound / render_outbound_yaml 一致。
                        #   原来这里读 form 的 'ob_mode' 写进 'mode'，
                        #   而 validate 里只认 entry['mode']（表单里没有这个字段名），
                        #   导致 direct 的 mode **永远校验不到** —— 用户填任何值都被当作
                        #   "未填"而放行，错值直接进 config.yaml ⇒ hysteria 起不来。
                        #   表单侧按type 切换字段，两个键名现已统一为 mode。
                        'mode': (form.get('mode', [''])[0] or '').strip(),
                    }
                    ok, cleaned, err = validate_outbound(entry)
                    if not ok:
                        return self.reply_json(400, {'ok': False, 'error': err})
                    with data_lock:
                        outs = [o for o in data.get('custom_outbounds', [])
                                if o.get('name') != cleaned['name']]
                        outs.append(cleaned)
                        data['custom_outbounds'] = outs
                    msg = '出站「%s」已保存' % cleaned['name']
                else:
                    name = (form.get('name', [''])[0] or '').strip()
                    if not name:
                        return self.reply_json(400, {'ok': False, 'error': '缺少 name 参数'})
                    missing_outbound = False
                    with data_lock:
                        outs = list(data.get('custom_outbounds', []))
                        if not any(o.get('name') == name for o in outs):
                            missing_outbound = True
                        else:
                            data['custom_outbounds'] = [o for o in outs if o.get('name') != name]
                            # 🔴 必须同步清理引用它的分流规则，否则 ACL 里会留下
                            #    不存在的出站名 ⇒ Hysteria 启动失败（且用户毫无察觉）。
                            data['warp_rules'] = [r for r in data.get('warp_rules', [])
                                                  if (r.get('outbound') if isinstance(r, dict) else None) != name]
                    if missing_outbound:
                        # 锁内只判定；回包放在锁外，避免慢客户端阻塞 /auth。
                        return self.reply_json(404, {'ok': False, 'error': '出站不存在'})
                    msg = '出站「%s」已删除' % name

            # ---------- 模式切换 ----------
            elif action == 'mode':
                mode = (form.get('mode', [''])[0] or '').strip().lower()
                if mode not in ('rules', 'global'):
                    return self.reply_json(400, {
                        'ok': False,
                        'error': '模式只能是 rules（按域名分流）或 global（全局出口）'})
                if mode == 'global' and not data.get('custom_outbounds'):
                    return self.reply_json(400, {'ok': False, 'error': '请先新增一个出站，再切换全局出口'})
                with data_lock:
                    # 🔴 不在这里拦"全局模式但没有出站"：
                    #    apply_outbounds_config 会自动退回rules，
                    #    由那一层统一处理，避免两处规则不一致。
                    data['outbound_mode'] = mode
                msg = '已切换到' + ('全局出口' if mode == 'global' else '按域名分流')

            # ---------- 分流规则增删 ----------
            elif action in ('rule-add', 'rule-del'):
                dom = (form.get('domain', [''])[0] or '').strip().lower()
                if not dom:
                    return self.reply_json(400, {'ok': False, 'error': '缺少 domain 参数'})
                rule_error = None
                with data_lock:
                    rules = [({'domain': r, 'outbound': 'warp_socks'} if isinstance(r, str) else dict(r))
                             for r in data.get('warp_rules', [])]
                    if action == 'rule-add':
                        cleaned = re.sub(r'^[a-zA-Z]+://', '', dom).split('/')[0].split(':')[0].strip('.')
                        target = (form.get('outbound', ['warp_socks'])[0] or 'warp_socks').strip()
                        if not cleaned or not re.match(r'^[a-zA-Z0-9.\-]+$', cleaned):
                            rule_error = '域名格式不正确'
                        elif not outbound_target_exists(target, data.get('custom_outbounds', [])):
                            rule_error = 'Unknown outbound target; refresh and select a configured outbound'
                        else:
                            rules = [r for r in rules if r['domain'] != cleaned]
                            rules.append({'domain': cleaned, 'outbound': target})
                            msg = '规则「%s」→ %s 已添加' % (cleaned, target)
                    else:
                        rules = [r for r in rules if r['domain'] != dom]
                        msg = '规则「%s」已删除' % dom
                    if rule_error is None:
                        data['warp_rules'] = rules
                if rule_error is not None:
                    # 锁内只判定；回包放在锁外，避免慢客户端阻塞 /auth。
                    return self.reply_json(400, {'ok': False, 'error': rule_error})
            else:
                return self.reply_json(400, {'ok': False, 'error': '未知 action: ' + action})

            save_data()
            return self._reply_with_egress_apply({'message': msg}, kind='outbound')

        def _h_get_warp_status(self, subpath):
            """GET /warp-status 的处理逻辑（从 do_GET 机械搬移而来）。"""
            if not self.is_authenticated():
                return self.reply_json(401, {'ok': False, 'error': 'Unauthorized'})
            with data_lock:
                enabled = data.get('warp_enabled', False)
                state = routing_state(data)
                rules = [r['domain'] for r in normalize_route_rules(state['warp_rules']) if r['outbound'] in ('warp', 'warp_socks')]
                overridden = state['outbound_mode'] == 'global' and bool(state['custom_outbounds'])
            # 统一到 wgcf + wireproxy(127.0.0.1:19898)；同时兼容尚未升级、
            # 仍跑官方 cloudflare-warp(127.0.0.1:40000) 的旧节点，避免误报「未安装」
            is_installed = (shutil.which('wireproxy') is not None
                            or shutil.which('warp-cli') is not None
                            or Path('/etc/systemd/system/wireproxy.service').exists())
            connected = False
            outbound_ip = ''
            if is_installed and enabled:
                # 出口 IP 探测要真的走一次外网（实测 150-300 ms），而前端每 10 秒
                # 轮询一次状态。加 30 秒缓存：状态变化本来也不是秒级的，
                # 且每次探测都占一个并发槽，会拖慢真正需要响应的请求。
                cached = _warp_probe_cache.get('value')
                if cached and time.monotonic() - _warp_probe_cache.get('at', 0) < 30:
                    outbound_ip, connected = cached
                else:
                    for warp_addr in ('127.0.0.1:19898', '127.0.0.1:40000'):
                        outbound_ip = detect_outbound_ip('socks5', warp_addr, timeout=3)
                        if outbound_ip:
                            connected = True
                            break
                    _warp_probe_cache['value'] = (outbound_ip, connected)
                    _warp_probe_cache['at'] = time.monotonic()
            try:
                cfg_text = Path('/etc/hysteria/config.yaml').read_text(encoding='utf-8')
                applied = cfg_text == render_egress_config(cfg_text, state)
                applied = applied and _hy2_config_loaded('/etc/hysteria/config.yaml')
            except Exception:
                applied = False
            with data_lock:
                apply_error = data.get('egress_apply_error') or data.get('warp_apply_error', '')
                applying = bool(data.get('egress_applying') or data.get('warp_applying'))
            return self.reply_json(200, {
                'ok': True,
                'installed': is_installed,
                'enabled': enabled,
                'connected': connected,
                'applied': applied and not applying,
                'applying': applying,
                'apply_error': apply_error,
                'overridden': overridden,
                'ip': outbound_ip,
                'rules': rules
            })

        def _h_get_cert_status(self, subpath):
            """GET /cert-status —— 证书当前状态 + 到期倒计时 + 上次自愈痕迹。

            🔴 这个端点存在的理由：证书过期是「昨天还好好的、今天突然连不上」
            这类故障里最高频的真凶，而自愈体系**只对齐信任模型、不会去续期证书**。
            把剩余天数摆到界面上，是让这类故障在到期前而不是掉线后被看见的唯一办法。
            """
            if not self.is_authenticated():
                return self.reply_json(401, {'ok': False, 'error': 'Unauthorized'})
            try:
                meta = read_meta_file(meta_path)
            except Exception:
                meta = {}
            root = meta_path.parent
            try:
                info = cert_status(root, meta,
                                   selfheal_state_path=str(root / 'cert-selfheal.json'))
            except Exception as exc:
                return self.reply_json(500, {'ok': False, 'error': str(exc)})

            # 与门户实际下发给客户端的 sni 对照：不一致说明又发生了漂移
            # （自愈单元没装 / 装的是旧版 / 证书刚换还没跑到）。
            live_sn = ''
            for san in info.get('sans') or []:
                if not san.startswith('*.') and _is_dns_name(san):
                    live_sn = san
                    break
            if not live_sn and _is_dns_name(info.get('common_name') or ''):
                live_sn = info['common_name']
            info['live_server_name'] = live_sn
            info['meta_matches_cert'] = bool(live_sn) and live_sn == info.get('server_name')
            info['warn_days'] = CERT_EXPIRY_WARN_DAYS
            info['critical_days'] = CERT_EXPIRY_CRITICAL_DAYS
            return self.reply_json(200, info)

        def _h_get_awg_state(self, subpath):
            """GET /awg-state 的处理逻辑（从 do_GET 机械搬移而来）。"""
            if not self.is_authenticated():
                return self.reply_json(401, {'ok': False, 'error': 'Unauthorized'})
            return self.reply_json(200, awg_state())

        def reply(self, code, body, mime='text/plain', www_auth=False):
            self.send_response(code)
            self._responded = True
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

        def __init__(self, *args, **kwargs):
            self.slots = threading.BoundedSemaphore(8)
            self.deadlines = {}
            self.deadline_lock = threading.Lock()
            super().__init__(*args, **kwargs)
            threading.Thread(target=self.watch_deadlines, daemon=True).start()

        def extend_deadline(self, request, seconds):
            """长操作续期连接死线（2026-10-28 修）。

            🔴 30 秒死线曾无差别杀掉所有合法的慢端点：install-gost /
            install-xray / install-warp / do-upgrade / awg update 的
            subprocess 超时给到 180-420 秒，但连接在 30 秒整就被
            watch_deadlines 关闭 —— 用户在面板点「安装」永远收到
            "Empty reply from server"，日志里只有一条 BrokenPipeError。
            处理线程继续跑完全程、副作用全部发生，唯独响应送不出去。

            处理办法：慢端点在开始前调一次本方法，把该连接的死线抬到
            覆盖自己的最长操作时长。死线防的是「连接挂着不动」的
            slow-loris 行为，不是防「服务端正在干活」。
            """
            with self.deadline_lock:
                if request in self.deadlines:
                    self.deadlines[request] = max(self.deadlines[request],
                                                  time.monotonic() + seconds)

        def watch_deadlines(self):
            while True:
                time.sleep(0.25)
                with self.deadline_lock:
                    for connection, deadline in list(self.deadlines.items()):
                        if time.monotonic() >= deadline:
                            try:
                                connection.shutdown(socket.SHUT_RDWR)
                            except OSError:
                                pass
                            self.deadlines.pop(connection, None)

        def process_request(self, request, address):
            if not self.slots.acquire(blocking=False):
                self.shutdown_request(request)
                return
            with self.deadline_lock:
                self.deadlines[request] = time.monotonic() + 30
            try:
                super().process_request(request, address)
            except Exception:
                with self.deadline_lock:
                    self.deadlines.pop(request, None)
                self.slots.release()
                raise

        def process_request_thread(self, request, address):
            try:
                super().process_request_thread(request, address)
            finally:
                with self.deadline_lock:
                    self.deadlines.pop(request, None)
                self.slots.release()


    server = ThreadingHTTPServer(('127.0.0.1', data['port']), Handler)
    server.requests, server.failures, server.api_requests = [], [], []
    # /auth 专用限流桶（2026-10-09）：见 auth_rate_limited() 的说明 ——
    # /auth 经 masquerade 对公网可达，必须有独立的速率+失败计数。
    server.auth_requests, server.auth_failures = [], []
    # Web 登录专用失败桶（2026-10-25）：见 login_rate_limited() 的说明。
    server.login_failures = []

    # 启动兜底：如果上一次运行时有 clients 变更被「节流」跳过
    # （历史上的节流机制已移除），配置写进 xray.json 了但服务没重载。
    # 这里在 serve 之前无条件对一次 —— 幂等、便宜（约 100ms）。
    #
    # ⚠️ 顺带解封 start-limit：上一版因为频繁 restart 撞上
    # systemd 的 start-limit，xray 停在 failed 且无法自愈。
    # reset-failed 是标准的解封手段，不影响正常运行中的服务。
    try:
        if Path('/etc/hysteria/xray.json').exists():
            with data_lock:
                _want = {REALITY_INBOUND_TAG: reality_clients(data),
                         VMESS_INBOUND_TAG: vmess_clients(data),
                         VLESSENC_INBOUND_TAG: vlessenc_clients(data)}
            _got = {}
            try:
                _cfg = json.loads(Path('/etc/hysteria/xray.json').read_text(encoding='utf-8'))
                # 同样覆盖所有托管入站：只补 Reality 的话，VMess-only 节点重启后
                # 新增用户永远进不了白名单（要等到下次有人开户才可能碰巧修好）。
                for _tag in MANAGED_INBOUND_TAGS:
                    _idx, _inb = managed_inbound_index(_cfg, _tag)
                    if _idx >= 0:
                        _got[_tag] = _inb.get('settings', {}).get('clients') or []
            except Exception:
                _got = {}
            # 比较**完整 clients**（含 UUID / flow），而不是只比 email：
            # 注册表被重建或配置被手工改过时，email 相同但 UUID 已变，
            # 只比 email 会认为「已同步」而放过（2026-10-29 修）。
            # 只遍历 _got 里实际存在的入站 —— 解析失败时 _got 为空，
            # 此时不做判断，避免每次启动都盲目重启 Xray。
            if any(_want[t] != (_got.get(t) or []) for t in _got):
                subprocess.run(['systemctl', 'reset-failed', 'xray'],
                               capture_output=True, timeout=5)
                subprocess.run(['systemctl', 'restart', 'xray'],
                               capture_output=True, timeout=10)
                print('[portal] 启动时补同步了 xray clients',
                      file=sys.stderr)
    except Exception as e:
        print('[portal] 启动补同步跳过: %s' % str(e)[:120], file=sys.stderr)

    # 已启用但配置文件不在：说明配置被删或从未写成功。此时各协议的
    # _active_*_config() 会如实返回「未启用」，订阅里也不会带上它 ——
    # 但如果不提示，用户只会觉得「节点突然少了一个」（2026-10-29 加）。
    try:
        with data_lock:
            _enabled = {k: bool((data.get(k) or {}).get('enabled'))
                        for k in ('reality_config', 'vmess_config',
                                  'vlessenc_config', 'anytls_config')}
        _missing = []
        if _enabled['reality_config'] and not Path('/etc/hysteria/xray.json').exists():
            _missing.append('Reality')
        if _enabled['vmess_config'] or _enabled['vlessenc_config']:
            try:
                _cfg = json.loads(Path('/etc/hysteria/xray.json').read_text(encoding='utf-8'))
            except (OSError, ValueError):
                _cfg = {'inbounds': []}
            if _enabled['vmess_config'] and not has_managed_inbound(_cfg, VMESS_INBOUND_TAG):
                _missing.append('VMess')
            if _enabled['vlessenc_config'] and not has_managed_inbound(_cfg, VLESSENC_INBOUND_TAG):
                _missing.append('VLESS Encryption')
        if _enabled['anytls_config'] and not (portal_path.parent / ANYTLS_CONFIG_NAME).exists():
            _missing.append('AnyTLS')
        if _missing:
            print('[portal] 以下协议标记为已启用但配置文件缺失，当前不会生效：%s。'
                  '请在面板重新开关一次以重建配置。' % '、'.join(_missing),
                  file=sys.stderr)
    except Exception as _e:
        print('[portal] 协议状态自检跳过: %s' % str(_e)[:120], file=sys.stderr)

    # AnyTLS 跑在独立的 sing-box 进程里，不在上面那段 xray.json 的兜底范围内。
    # 只开 AnyTLS、从未启用过 Xray 协议的节点根本没有 xray.json，
    # 不单独对一次的话，重启后 anytls.json 的用户表会与 data 长期不一致
    # （2026-10-29 修）。
    try:
        with data_lock:
            _any_snapshot = copy.deepcopy(data)
        if sync_anytls_users(portal_path.parent, _any_snapshot):
            print('[portal] 启动时补同步了 AnyTLS users', file=sys.stderr)
    except Exception as e:
        print('[portal] AnyTLS 启动补同步跳过: %s' % str(e)[:120], file=sys.stderr)

    # 超额停用要扛住重启：开机后 systemd 会把服务重新拉起来，这里再停一次。
    try:
        with data_lock:
            _susp = suspend_state(data)
        if _susp.get('suspended'):
            for _u in _susp.get('units') or []:
                subprocess.run(['systemctl', 'stop', _u], capture_output=True, timeout=20)
            print('[portal] 流量超额停用中，已重新停止: %s' % ','.join(_susp.get('units') or []),
                  file=sys.stderr)
    except Exception as e:
        print('[portal] 重新应用超额停用失败: %s' % str(e)[:120], file=sys.stderr)

    if usage_meter is not None:
        usage_meter.start()
    threading.Thread(target=expiry_access_worker,name="portal-expiry-enforcer",daemon=True).start()
    threading.Thread(target=reality_iplimit_worker,name="portal-reality-iplimit",daemon=True).start()
    server.serve_forever()


if __name__ == '__main__':
    _cmd = sys.argv[1] if len(sys.argv) > 1 else ''
    if _cmd == 'prepare':
        api_key = sys.argv[4] if len(sys.argv) > 4 else None
        prepare(sys.argv[2], sys.argv[3], api_key)
    elif _cmd == 'refresh':
        refresh(sys.argv[2])
    elif _cmd == 'adopt':
        adopt(sys.argv[2], sys.argv[3], sys.argv[4] if len(sys.argv) > 4 else None)
    elif _cmd == 'selfheal':
        # 供 systemd timer / path unit 调用；退出码恒 0（自愈失败不应让 timer 报错刷屏，
        # 真实失败原因已打到 stderr 由 journal 记录）。
        try:
            _cfg = sys.argv[3] if len(sys.argv) > 3 else '/etc/hysteria/config.yaml'
            selfheal(sys.argv[2], config_path=_cfg)
        except Exception as e:
            print('[portal] selfheal 失败: %s' % str(e)[:200], file=sys.stderr)
    elif _cmd == 'serve':
        serve(sys.argv[2])
    else:
        # 🔴 绝不能把未知子命令当 serve 处理：旧版门户没有 selfheal，
        #    `python3 portal.py selfheal <meta>` 会落到 serve 分支，
        #    于是「自愈」实际**启动了第二个门户进程**（或因参数不对报
        #    无关的 KeyError），而调用方看到的是「命令成功」——
        #    又是一次静默降级。这里必须显式报错并以非 0 退出。
        print('[portal] 未知子命令: %r（可用: prepare / refresh / selfheal / serve）'
              % _cmd, file=sys.stderr)
        sys.exit(2)


