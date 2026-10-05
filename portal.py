"""仅监听回环地址；公网 TLS 由 Hysteria 的 masquerade proxy 提供。
采用现代轻奢 Tab 导航系统，解耦节点连接、多用户管理（支持 IP 限制与实时流量统计）与集群 API 凭据。
"""
import ast
import base64
import hashlib
import hmac
import html
import json
import os
import platform
import random
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.request
import uuid
import zipfile
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from socketserver import ThreadingMixIn
from urllib.parse import parse_qs, quote, urlencode

# 前端资源（CSS / 内嵌 JS）拆到了独立模块 portal_assets.py。
# 部署时两个文件必须成对存在 —— 见 install.sh 的 portal_ensure_py。
# 这里 import 进来后，portal.STYLE / portal.SCRIPT 等名字依然照常可用，
# 所以 content_policy()、page_html() 与既有测试都不需要改。
try:
    from portal_assets import STYLE, SCRIPT, LOGIN_SCRIPT, USER_SCRIPT
except ImportError as _e:      # pragma: no cover - 只在部署缺文件时触发
    raise SystemExit(
        '缺少 portal_assets.py —— 门户由 portal.py 与 portal_assets.py 两个文件组成，\n'
        '它们必须放在同一目录下（通常都是 /etc/hysteria/）。\n'
        '原始错误: %s\n'
        '修复：重新执行一次安装 / 更新（bash install.sh install 或门户里的「更新」）。' % _e
    )

# 机主账号。它的 password 就是 Hysteria 的 auth_password —— /auth 是遍历
# data['users'] 按密码匹配的，这条记录一旦被删，主密码立刻变成 "User not found"，
# 机主本人都会被踢下线且再也连不上（只能重装）。因此全站禁止注销它。
MASTER_USER_ID = 'admin_master'

# 节点门户的版本号（2026-10-04 加）。
#
# 用途：主控面板要靠它判断「这台节点跑的是新 portal 还是老 portal」——
# 老门户没有 capabilities 端点、没有多用户 Reality，功能表现完全不同。
# 之前只能靠 SSH 上去 grep 源码，主面板看不见。
#
# ⚠️ 改动 portal.py 的**能力**时记得同步 +1，否则主面板会按旧能力显示。
# 格式固定 `PORTAL_VERSION = 'x.y'`（capabilities 端点按行首匹配解析它）。
PORTAL_VERSION = '2.2'


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



# 🔴 必须是原始字符串（r"""），不能改成普通三引号。
# 这是内嵌的 JS 源码，里面写的 \n 需要【原样保留】成 JS 的转义序列。
# 若用普通字符串，Python 会在解析阶段把 \n 变成真实换行塞进 JS 的字符串字面量里，
# 造成 JS 语法错误；而 JS 语法错误会让【整段脚本】无法解析 ——
# 表现不是某个按钮失灵，而是页面上所有按钮、标签页、轮询全部失效
# （历史上真发生过：更新后 Web 面板的菜单整个点不动）。
# 同理见下面的 LOGIN_SCRIPT / USER_SCRIPT。




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
            raw = raw.rsplit(':', 1)[-1].strip()
            if raw.isdigit():
                return int(raw)
    return None


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
    if explicit:
        try:
            value = int(explicit)
            if 1 <= value <= 65535:
                return value, 'client_meta'
        except (TypeError, ValueError):
            pass

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
            {'' if uid == MASTER_USER_ID else f'''<form method="POST" action="/{token}/manage-user" style="display:inline" class="js-confirm-delete" data-confirm="确定注销此用户？此操作不可撤销。">
              <input type="hidden" name="action" value="delete">
              <input type="hidden" name="user_id" value="{html.escape(uid)}">
              <button class="button danger" style="padding:4px 10px;font-size:11px" type="submit">删除</button>
            </form>'''}
            {'<span style="font-size:11px;color:var(--muted)">机主账号不可注销</span>' if uid == MASTER_USER_ID else ''}
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
<header class="hero"><div class="eyebrow">HYSTERIA 2 NODE DASHBOARD</div><h1>{html.escape(server_name)}</h1><p>官方核心驱动 · 极速 QUIC 代理 · 多用户开户与流量/IP限制</p></header>

<!-- 顶部 Tab 导航栏 -->
<div class="tab-bar">
  <button class="tab-btn active" data-tab="connect">🚀 节点导入 (Connect)</button>
  <button class="tab-btn" data-tab="users">👥 多用户管理 ({active_count}/{len(users)})</button>
  <button class="tab-btn" data-tab="proxies">🧩 代理 · WARP · AWG</button>
  <button class="tab-btn" data-tab="reality">🛡️ VLESS-Reality (备用)</button>
  <button class="tab-btn" data-tab="cluster">🔑 接入控制台 / REST API</button>
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
  <!-- 本页三块：入站代理 / WARP 分流 / AmneziaWG。
       标签原来只写「入站代理 & WARP」，而 AmneziaWG 是 README 的重点功能，
       藏在第三张卡片里新手根本找不到 —— 所以标签和页内都补上说明。 -->
  <div style="margin-bottom:16px;padding:12px 14px;background:#f3f7f6;border-radius:10px;font-size:12.5px;color:#456972;line-height:1.75">
    本页是三块<b>互相独立</b>的功能，只想要其中某一项就找到对应卡片操作，互不影响：<br>
    <b>① 入站代理</b> —— 把服务器当普通 SOCKS5 / HTTP 代理用（客户端不用装 Hysteria）<br>
    <b>② Cloudflare WARP 分流</b> —— 让指定域名走干净的住宅出口，用于解锁 AI 服务<br>
    <b>③ AmneziaWG</b> —— 抗 DPI 的 WireGuard 分支，需要客户端额外装一个 WireGuard 类 App
  </div>
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
      版本按<b>文件内容哈希</b>（git blob sha）与仓库 main 分支当前内容比对，不是按日期或提交号 —— 面板文件本身不带 git 元数据。
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
<div class="field-group"><div class="field-label"><label for="password">密码 (Password)</label></div><div class="field-pwd"><input class="field-input" id="password" name="password" type="password" autocomplete="current-password" required placeholder="输入访问密钥"><button type="button" class="toggle-pwd">显示</button></div></div>
<div class="remember-row"><input type="checkbox" id="remember" name="remember" value="1" checked><label for="remember">在此浏览器保持登录（30天）</label></div>
<button class="btn-submit" type="submit">立即进入私密中心 →</button>
</form>
<div class="login-footer">如果遗忘凭据，随时在服务器终端执行<br><code>bash install.sh info</code> 找回账号密码</div>
</div></div>
<script>{LOGIN_SCRIPT}</script></body></html>'''


def user_page_html(server_name, host, listen_port, obfs_badge, uid, uinfo, uri, clash, sing, qr_svg, token, user_key, sub_port=None):
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
    # 🔴 订阅端口来自**节点 meta**，不是用户对象 —— 用户对象里从来没有这个键。
    # 调用方应从 meta 传入真实端口；若未传，则按权威来源解析，
    # **绝不兜底成伪造的 8443**（8443 在本项目里是被主动避开的黑名单端口）。
    if sub_port is None:
        sub_port = resolve_subscription_port({})[0]
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


# 当前运行实例的 portal.json 字典。仅在 serve() 启动时登记，
# 供省略 data 参数的旧调用形式使用（见 reality_uuid_for_user）。
_active_reality_data = None


REALITY_UUID_VERSION = 2

# 「已注销」的凭据保留时限（秒）。
#
# 为什么不立刻删：销户后如果马上清掉条目，同一个 user_id 再开户就会拿到
# **另一个** UUID —— 客户端手里的旧配置失效，且订阅重新拉取会多出一个节点。
# 旧实现靠 uuid5 派生天然幂等；改成随机 UUID 后必须显式保留一段时间才能等价。
#
# 保留窗口内该身份**已经不在 xray 的 clients 里**（reality_clients 只输出
# data['users'] 中现存且 active 的用户），所以「钱退了货还在」不成立 ——
# 这里留的只是凭据本身，不是访问权。
REALITY_RETIRED_TTL_SECONDS = 30 * 86400


def reality_uuid_for_user(user_id, data=None):
    """取某个用户的 VLESS-Reality 凭据（UUID）。

    凭据**只从持久化的注册表读取**，绝不从 user_id 派生 ——
    user_id 是公开的（出现在订阅链接、客服记录、订单号里），
    由它派生等于「知道 user_id 就能算出别人的凭据」。

    凭据不存在时**当场生成并写回 data**（而不是抛错）——
    调用方有 serve() 里带锁的、也有测试/工具里直接调函数的，
    让本函数自身自足，就不会再出现「忘了先初始化某个全局」的耦合。

    data 省略时回退到 _active_reality_data —— 那是 serve() 里登记的
    **当前运行实例**的 portal.json 字典，仅为兼容旧的调用形式；
    显式传 data 永远是首选。
    """
    owner = data if data is not None else _active_reality_data
    if owner is None:
        raise RuntimeError('Reality registry not initialized')
    reg = reality_registry(owner)
    key = str(user_id)
    value = reg.get(key)
    if not value:
        value = str(uuid.uuid4())
        reg[key] = value
        owner['reality_users'] = reg
        # ⚠️ 本函数**不负责落盘** —— save_data() 是 serve() 里的闭包，
        #    模块级函数够不到它。所有可能新增凭据的调用点
        #    （users/create、_generate_and_apply_reality、serve 启动）
        #    都必须自己调 save_data()，否则重启后随机凭据丢失、
        #    客户手里的 Reality 链接会失效。
    return value


def reality_registry(data):
    """维护 data['reality_users']：user_id → UUID 的凭据注册表。

    两条路径必须分清，混在一起就是 bug：

      * **升级迁移**（reality_uuid_version < 2，只跑一次）：
        老节点的用户从来没有注册表，凭据一直是 uuid5 派生的 ——
        必须**原样补回派生值**，否则所有已发出的链接在升级瞬间全部失效。
      * **新增用户**（版本已是 2）：发一个**随机** UUIDv4 并持久化，
        此后永远读注册表，不再派生。

    已注销用户的条目**保留** REALITY_RETIRED_TTL_SECONDS，
    这样销户→重开户能拿回同一个 UUID（幂等），超期才真正回收。
    """
    global _active_reality_data
    reg = data.get('reality_users')
    if not isinstance(reg, dict):
        reg = {}
    users = data.get('users', {}) or {}

    # —— 一次性的老数据迁移 ——
    # 判据是版本号，且迁移后立即升版本；因此这里最多执行一次。
    # ⚠️ 不能拿 legacy 去决定「新用户是否随机」—— 那样第二次调用
    #    legacy 已为假，销户重建就会误走随机分支（这正是要修的 bug）。
    migrating = data.get('reality_uuid_version') != REALITY_UUID_VERSION
    now = time.time()
    retired = data.get('reality_retired_users')
    if not isinstance(retired, dict):
        retired = {}

    for uid in users:
        if uid not in reg:
            if migrating:
                # 老用户：必须还原升级前的派生值，链接才不变。
                reg[uid] = _legacy_reality_uuid(uid)
            else:
                reg[uid] = str(uuid.uuid4())

    # —— 销户回收 ——
    # 刚注销的用户先进 retired 表（带时间戳），保留窗口内不真删。
    for uid in list(reg):
        if uid not in users:
            retired.setdefault(uid, now)
    for uid in list(retired):
        if uid in users:
            del retired[uid]                       # 又开回来了
        elif now - retired[uid] > REALITY_RETIRED_TTL_SECONDS:
            retired.pop(uid, None)
            reg.pop(uid, None)                     # 超期才回收凭据

    data['reality_users'] = reg
    data['reality_retired_users'] = retired
    data['reality_uuid_version'] = REALITY_UUID_VERSION
    _active_reality_data = data
    return reg


def _legacy_reality_uuid(user_id):
    """升级前的派生规则（uuid5 + 固定命名空间）。

    ⚠️ 命名空间与算法**不可更改** —— 它决定了老用户凭据的还原结果，
    换掉等于让所有已发出去的 Reality 链接失效。
    仅用于一次性迁移，新凭据一律 uuid4。
    """
    return str(uuid.uuid5(uuid.NAMESPACE_URL, 'hy2-portal-reality:' + str(user_id)))


def reality_clients(data):
    """生成 xray inbound.settings.clients —— 每个 Hy2 用户一个 VLESS 身份。

    空表也要返回**一个**占位 client：xray 的 vless inbound 在
    clients 为空时会拒绝所有连接，且 `systemctl restart xray` 仍然成功 ——
    表现为「服务 active 但所有人都连不上」，极难排查（2026-10-03 实测踩过）。
    所以宁可给一个随机占位 UUID，也不要让 clients 空着。
    """
    reg = reality_registry(data)
    users = data.get('users', {}) or {}
    clients = [{'id': uid_uuid, 'flow': 'xtls-rprx-vision', 'email': uid}
               for uid, uid_uuid in sorted(reg.items())
               # 只输出「现存的、且 active 的」用户。
               # 已注销但仍在保留窗口内的凭据**不进 clients** ——
               # 保留只是为了重开户时 UUID 不变，不是保留访问权。
               if uid in users
               and (users.get(uid) or {}).get('status', 'active') == 'active']
    if not clients:
        clients = [{'id': str(uuid.uuid4()), 'flow': 'xtls-rprx-vision',
                    'email': 'placeholder'}]
    return clients


def reality_uri_for_user(rcfg, user_id, public_ip, label=None, data=None):
    """给某个用户拼他自己的 VLESS-Reality 直链。

    rcfg 是 data['reality_config']（含 short_id/dest_sni/port/public_key）。
    单用户的 rcfg 里存的是**旧版单账号**的 uuid —— 这里忽略它，
    改从凭据注册表取该用户自己的 UUID（reality_uuid_for_user）。

    data 需要显式传入，凭据才有处可读写（缺失时会回退到当前运行实例，
    见 reality_uuid_for_user）。
    """
    if not rcfg:
        return ''
    short_id = rcfg.get('short_id', '')
    dest_sni = rcfg.get('dest_sni', 'www.apple.com')
    port = rcfg.get('port', 443)
    pub_key = rcfg.get('public_key', '')
    if not (short_id and dest_sni and pub_key):
        return ''
    uid_uuid = reality_uuid_for_user(user_id, data)
    tag = label or ('VLESS-Reality-' + str(user_id))
    return (f"vless://{uid_uuid}@{public_ip}:{port}"
            f"?security=reality&encryption=none&pbk={pub_key}"
            f"&headerType=none&fp=chrome&type=tcp&flow=xtls-rprx-vision"
            f"&sni={dest_sni}&sid={short_id}#{quote(tag)}")


def artifacts(m, auth_override=None, name_override=None, reality=None, user_id=None,
              data=None):
    """生成 hy2:// 直链 + Clash / Sing-box 配置。

    reality（可选）—— 传 rcfg 时会**额外产出一条 VLESS-Reality 节点**，
    并把 Clash 的 PROXY 组改成 url-test（Hy2 与 Reality 自动择优），
    这样「UDP 被 QoS 的网络」会自己切到 TCP 通道（2026-10-03）。

    data（可选）—— 凭据注册表所在的数据字典。带 reality + user_id 时
    必须给，否则取不到（也不该凭空生成）该用户的 Reality UUID。
    """
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
                                    label=(name + '-Reality'), data=data)
        r_uuid = reality_uuid_for_user(user_id, data)
        r_port = reality.get('port', 443)
        r_sni = reality.get('dest_sni', 'www.apple.com')
        r_pbk = reality.get('public_key', '')
        r_sid = reality.get('short_id', '')
        if ruri and r_pbk and r_sid:
            rname = name + '-Reality'
            reality_proxy = dict(name=rname, type='vless', server=public_ip,
                                 port=r_port, uuid=r_uuid, udp=True,
                                 tls=dict(servername=r_sni),
                                 flow='xtls-rprx-vision',
                                 servername=r_sni,
                                 reality_opts=dict(public_key=r_pbk,
                                                   short_id=r_sid),
                                 client_fingerprint='chrome')
            reality_sing = dict(type='vless', tag=rname, server=public_ip,
                               server_port=r_port, uuid=r_uuid,
                               flow='xtls-rprx-vision',
                               tls=dict(enabled=True, server_name=r_sni,
                                        reality=dict(enabled=True,
                                                     public_key=r_pbk,
                                                     short_id=r_sid),
                                        utls=dict(enabled=True,
                                                  fingerprint='chrome')))

    proxies = [proxy] + ([reality_proxy] if reality_proxy else [])
    sing_outbounds = [sing] + ([reality_sing] if reality_sing else [])

    if reality_proxy:
        # url-test：客户端定时探测两条链路，自动选延迟低的。
        # 比 select 好在「不需要用户手动切」——UDP 被 QoS 时会自己落到 Reality。
        group_proxies = [name, reality_proxy['name']]
        group = {'name': 'PROXY', 'type': 'url-test', 'proxies': group_proxies,
                 'url': 'https://www.gstatic.com/generate_204',
                 'interval': 300, 'tolerance': 50}
    else:
        group = {'name': 'PROXY', 'type': 'select', 'proxies': [name, 'DIRECT']}

    clash = {'mixed-port': 7890, 'allow-lan': False, 'mode': 'rule',
             'proxies': proxies, 'proxy-groups': [group],
             'rules': ['MATCH,PROXY']}
    sing_doc = {'outbounds': sing_outbounds}
    if reality_sing:
        # sing-box 侧同样给一个 urltest outbound，让 SFA/SFI 自动择优。
        sing_doc['outbounds'].append({
            'type': 'urltest', 'tag': 'PROXY',
            'outbounds': [sing['tag'], reality_sing['tag']],
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
    m = json.loads(Path(meta_path).read_text())
    sync_pin(m, root, meta_path)

    uri, clash, sing = artifacts(m)
    qr = subprocess.run(['qrencode', '-t', 'SVG', '-o', '-'], input=uri.encode(), capture_output=True, check=True).stdout
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
                proxy_services=[], page=page, qr=qr.decode(), clash=clash, sing=sing, reality_uuid_version=2)
    for filename, value in [('portal.json', data), ('portal-access.json', portal_access_payload(base, user, password, api_key))]:
        path = root / filename
        path.write_text(json.dumps(value, ensure_ascii=False), encoding='utf-8')
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
    subscription = f"https://{access['username']}:{access['password']}@{host}:{resolve_subscription_port(m)[0]}/{data['token']}/clash.yaml"
    
    if 'session_secret' not in data:
        data['session_secret'] = secrets.token_hex(32)
    if 'api_key' not in data:
        data['api_key'] = access.get('api_key') or secrets.token_hex(24)
        access['api_key'] = data['api_key']
        (root / 'portal-access.json').write_text(json.dumps(access, ensure_ascii=False), encoding='utf-8')
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
    
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(data, ensure_ascii=False), encoding='utf-8')
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
            # ⚠️ 必须显式 encoding='utf-8'（2026-10-03 实测）。
            # Path.write_text 不给 encoding 时跟随 locale：Linux 上是 UTF-8
            # 没事，但 Windows 上是 GBK —— 页面里含 `₂` 之类字符时
            # 直接 UnicodeEncodeError 把 HTTP handler 打死，客户端看到的是
            # "Remote end closed connection without response"，
            # 排查时完全看不出是编码问题。
            try:
                temp = portal_path.with_suffix('.tmp')
                temp.write_text(json.dumps(data, ensure_ascii=False),
                                encoding='utf-8')
                temp.chmod(0o600)
                temp.replace(portal_path)
            except OSError:
                disk_path = Path('/etc/hysteria/portal.json')
                if disk_path.exists():
                    disk_temp = disk_path.with_suffix('.tmp')
                    disk_temp.write_text(json.dumps(data, ensure_ascii=False),
                                         encoding='utf-8')
                    disk_temp.chmod(0o600)
                    disk_temp.replace(disk_path)

    # 启动时先把凭据注册表补齐并落盘，再开始服务：
    #   * 老库（version<2）在这里一次性迁移成派生值 —— 存量链接不变；
    #   * 新库只是把注册表与版本号写正（幂等，无副作用）。
    reality_registry(data)
    save_data()

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
            tmp.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding='utf-8')
            tmp.chmod(0o644)
            tmp.replace(gost_cfg_path)
        except OSError:
            pass

    def reload_gost():
        """让 gost 重新读取 gost.yml. 未安装 gost 时静默跳过.

        ⚠️ 这里踩过三个坑, 改动前务必读完:

        坑 0 —— 「未运行就不管」是错的. 2026-10-01 真实事故: 机器装了 gost 但
        服务处于 inactive（重启后 enabled 但被手工停过 / 首次创建代理时还没起过）,
        旧逻辑 `if not gost_status(): return` 直接静默返回 —— 配置没写、服务没起,
        控制台却提示"创建成功", 端口永远不监听. 正确行为: **已安装但未运行时,
        写好配置并 systemctl start**（安装了二进制就代表能力存在, 起不来再报错）.
        只有「二进制不存在」才静默跳过.

        坑 1 —— subprocess.run **不检查退出码**, 只在超时/找不到命令时抛异常.
        因此早期写成:

            try:
                subprocess.run(['systemctl', 'reload', 'gost'], timeout=2)
            except Exception:
                ... kill -HUP ...
                except Exception:
                    ... restart ...

        是**完全错的**: 当 unit 没有 ExecReload 时, systemctl 会打印
        "Job type reload is not applicable for unit gost.service." 并且
        **以退出码 3 正常返回** —— 不抛异常, 于是两个 fallback 成了永不执行的
        死代码. 结果是: 配置写进了 gost.yml, 但 gost 进程从未重载, 新代理的端口
        一直不监听. 现象极具误导性 —— `systemctl is-active gost` 是 active,
        页面提示"创建成功", 但代理就是连不上.

        坑 2 —— 判断"reload 是否可用"不能靠猜, 要实际执行后看返回码.
        `systemctl reload` 在以下两种情况下行为完全不同:
          - unit 有 ExecReload  -> CanReload=yes, 返回 0, 配置真正重载
          - unit 没有 ExecReload -> CanReload=no,  返回 3, **什么都没做**
        两种情况下 subprocess.run 都不抛异常, 所以**必须显式查 returncode**.

        现行策略: 二进制不存在 -> 静默跳过; 已安装但 inactive -> 写配置并 start;
        运行中 -> 先试 reload, 返回码非 0 就退化为 restart (restart 一定生效).
        另外 unit 里还配了 gost 官方的 `-R 30s` 周期自动重载作为第二重保险
        (实测 v3.3.0 的 -R 有效: 改配置后 2 秒内自动重载并换端口).

        保持异步执行 (daemon 线程 + 短 timeout), 避免 gost 卡住时把 portal 的
        do_POST 一起拖死.
        """
        if not Path('/usr/local/bin/gost').exists():
            return                                  # 未安装: 静默跳过 (唯一合法的跳过理由)
        # 先自愈 unit: 老机器的 unit 可能没有 ExecReload (那样 reload 会静默失败).
        ensure_gost_unit()
        write_gost_config()

        def _do_reload():
            active = gost_status()
            # 第一优先: 服务在运行则平滑 reload (不断开现有连接).
            # 必须查 returncode —— 见坑 1/2.
            if active:
                try:
                    r = subprocess.run(['systemctl', 'reload', 'gost'],
                                       capture_output=True, timeout=5)
                    if r.returncode == 0:
                        return
                except Exception:
                    pass
            # 退化路径: inactive 未被上面 start 兜住 / reload 不可用 / reload 失败.
            # restart 对三种状态都有效 (inactive 时等价于 start), 代价是断当前连接.
            try:
                subprocess.run(['systemctl', 'restart', 'gost'],
                               capture_output=True, timeout=10)
            except Exception:
                pass

        threading.Thread(target=_do_reload, daemon=True).start()

    # 远端根目录文件 sha 的短缓存。
    # 必要性：版本检查会在每次页面加载时触发，而 GitHub 未认证 API 限 60 次/小时/IP。
    # 用「目录列表」接口一次拿回所有文件的 sha（而不是逐文件取），再叠 5 分钟缓存，
    # 把每次检查的 API 调用压到 1 次。
    _ver_cache = {'t': 0.0, 'data': None}

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
            shas = {it['name']: it.get('sha', '')
                    for it in items if isinstance(it, dict) and it.get('name')}
            if shas:
                _ver_cache['t'] = now
                _ver_cache['data'] = shas
                return shas
        except Exception:
            pass
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
            current = unit_path.read_text() if unit_path.exists() else ''
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
        except Exception:
            pass

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

    def _fetch_repo_file(filename, marker=None, min_size=1024):
        """从多个源依次尝试获取仓库里的某个文件，返回内容字节；全失败返回 None。

        ⚠️ 不能只用 raw.githubusercontent.com：实测 push 后数分钟仍返回旧内容，
        而且【不把查询串算进缓存键】—— 加 ?cb=<时间戳> 也没用。
        实测同一时刻：api.github.com（Accept: vnd.github.raw）与 jsDelivr 都是最新，
        raw 滞后。顺序：API（权威）→ jsDelivr（无限速）→ raw（兜底）。
        与 install.sh 中 awg_fetch_ctl 的策略保持一致。
        """
        sources = [
            ('https://api.github.com/repos/' + AWG_REPO + '/contents/' + filename + '?ref=main',
             {'User-Agent': 'Mozilla/5.0', 'Accept': 'application/vnd.github.raw'}),
            ('https://cdn.jsdelivr.net/gh/' + AWG_REPO + '@main/' + filename,
             {'User-Agent': 'Mozilla/5.0'}),
            ('https://raw.githubusercontent.com/' + AWG_REPO + '/main/' + filename,
             {'User-Agent': 'Mozilla/5.0'}),
        ]
        for url, headers in sources:
            try:
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=30) as resp:
                    content = resp.read()
                # 体积 + 关键字双重校验，挡住错误页
                if len(content) > min_size and (marker is None or marker in content):
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

    def _remote_blob_sha(filename, marker=None):
        """取远端文件的 git blob sha。优先走 contents API 的 JSON（便宜），
        拿不到时退回「下载内容后自己算」。"""
        try:
            url = 'https://api.github.com/repos/' + AWG_REPO + '/contents/' + filename + '?ref=main'
            req = urllib.request.Request(url, headers={
                'User-Agent': 'Mozilla/5.0',
                'Accept': 'application/vnd.github+json',
            })
            with urllib.request.urlopen(req, timeout=8) as resp:
                info = json.loads(resp.read().decode('utf-8'))
            sha = info.get('sha', '')
            if len(sha) == 40:
                return sha
        except Exception:
            pass
        content = _fetch_repo_file(filename, marker)
        return _git_blob_sha(content) if content else None

    def ensure_awgctl(force=False):
        """确保 hy2-awgctl 可用；缺失时从主仓库拉取（与 install.sh 的策略一致）。

        force=True 时即使已存在也重新获取，且仅在内容变化时才替换 —— 否则已经装过
        AWG 的机器会把引擎永久冻结在首次安装的版本上。
        """
        if not force and Path(AWG_CTL).exists():
            return True
        try:
            content = _fetch_repo_file('awgctl.sh', marker=b'hy2-awgctl', min_size=2048)
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
        subscription = f"https://{access.get('username','')}:{access.get('password','')}@{host}:{resolve_subscription_port(m)[0]}/{data['token']}/clash.yaml"
        
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

            data['page'] = page_html(m, uri, subscription, clash, sing, users=display_users, api_key=data.get('api_key'), token=data['token'], session_secret=session_secret,
                                     username=access.get('username', ''), password=access.get('password', ''))
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
            """把 data['users'] 派生出的 UUID 列表写进 xray.json 并热重载。

            只在 **xray 已安装**（/etc/hysteria/xray.json 存在）时才动手 ——
            没装 Reality 的节点不该因为一次开户就被创建出 xray 配置。
            静默跳过是**正确**的：这不是错误，只是该节点没启用 Reality。
            """
            xj = Path('/etc/hysteria/xray.json')
            if not xj.exists():
                return False
            try:
                cfg = json.loads(xj.read_text())
            except Exception:
                return False
            inbounds = cfg.get('inbounds') or []
            vless = next((i for i in inbounds
                          if i.get('protocol') == 'vless'
                          and (i.get('streamSettings') or {}).get('security') == 'reality'),
                         None)
            if vless is None:
                return False
            with data_lock:
                clients = reality_clients(data)
            vless.setdefault('settings', {})['clients'] = clients
            vless['settings']['decryption'] = vless['settings'].get('decryption', 'none')
            try:
                xj.write_text(json.dumps(cfg, indent=2), encoding='utf-8')
            except Exception:
                return False
            # 重载 xray。
            #
            # ⚠️ 2026-10-03 实测踩坑（真机 jp 节点）：
            #   开户/销户每次都会走到这里，而 xray **不支持 systemctl reload**
            #   （它没有 ExecReload），于是每次都回退到 `systemctl restart`。
            #   连着几次（我的五轮验证一口气开了十几个探针账号）之后，
            #   systemd 的 start-limit 被打满 —— 服务进入 `failed`：
            #     xray.service: Start request repeated too quickly.
            #     xray.service: Failed with result 'start-limit-hit'.
            #   之后**即使配置完全正确也无法启动**，只能
            #   `systemctl reset-failed xray` 手工解封。
            #   症状极具误导性：portal 一切正常、xray.json 也对，
            #   但 Reality 通道全断、443 没人监听。
            #
            # 对策（三条一起，缺一不可）：
            #   1. restart 前先 reset-failed —— 绕开 start-limit 计数；
            #   2. 加 ExecReload 到 unit（由调用方保证），这样能走 reload 就不重启；
            #   3. 节流 —— 短时间内多次变更只重启一次（见 _reality_restart_gate）。
            if self._reality_restart_allowed():
                subprocess.run(['systemctl', 'reset-failed', 'xray'],
                               capture_output=True, timeout=5)
                r = subprocess.run(['systemctl', 'reload', 'xray'],
                                   capture_output=True, timeout=5)
                if r.returncode != 0:
                    subprocess.run(['systemctl', 'restart', 'xray'],
                                   capture_output=True, timeout=10)
            return True

        def _reality_restart_allowed(self, min_interval=3.0):
            """节流：min_interval 秒内只放行一次 xray 重启。

            为什么要节流：批量开户（商城一次性给 10 个用户开号）会产生
            连续十几次 clients 变更，每次都 restart 一遍既慢又容易撞
            systemd start-limit。这里做「时间闸门」——多出来的变更
            仍然会写进 xray.json，只是**不立刻重启**；由下一次调用
            或 portal 启动时的兜底逻辑补上。

            ⚠️ 被节流掉的那次不能算「成功」：返回 False 让调用方知道
            「配置已写、服务尚未重载」，与「配置没写」区分开。
            """
            # ⚠️ 用模块顶部已导入的 time，不在函数里 import ——
            #   tests/test_portal_assets.py 的 SourceHygieneTest
            #   明令禁止函数级 import（会让每个请求都走一次 import 查找，
            #   且 import 位置分散后很难审计）。
            now = time.monotonic()
            last = getattr(self, '_reality_last_restart', 0.0)
            if now - last < min_interval:
                return False
            self._reality_last_restart = now
            return True

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
                rcfg_old = dict(data.get('reality_config', {}) or {})

            priv_key = '' if force else rcfg_old.get('private_key', '')
            pub_key = '' if force else rcfg_old.get('public_key', '')
            if not (priv_key and pub_key):
                # 首次才生成。xray 不可用时回落到硬编码常量（沿用旧行为）。
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
                if not priv_key or not pub_key:
                    priv_key = 'SKHsyFDGviRODhpQJQLAxAU-qRBBWjKjntbVXp8KW10'
                    pub_key = '2uyjYiLgv9SAjn6eVC21EywA55xyiebI-wg03rgBH2g'

            short_id = (secrets.token_hex(4) if force
                        else (rcfg_old.get('short_id') or secrets.token_hex(4)))
            dest_sni = rcfg_old.get('dest_sni') or 'www.apple.com'
            listen_port = rcfg_old.get('port') or 443

            m = json.loads(meta_path.read_text()) if meta_path.exists() else {}
            public_ip = m.get('public_ip', '127.0.0.1')

            with data_lock:
                data['reality_config'] = {
                    'private_key': priv_key,
                    'public_key': pub_key,
                    'short_id': short_id,
                    'dest_sni': dest_sni,
                    'port': listen_port,
                }
                # 单用户视角的 uri 仍然给（Web 面板二维码要用），
                # 取机主自己的 UUID —— 保证刷新后链接不变。
                data['reality_config']['uuid'] = reality_uuid_for_user(
                    MASTER_USER_ID, data)
                data['reality_config']['uri'] = reality_uri_for_user(
                    data['reality_config'], MASTER_USER_ID, public_ip,
                    label='Teyir-VLESS-Reality', data=data)
                clients = reality_clients(data)
            save_data()

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
            Path('/etc/hysteria/xray.json').write_text(
                json.dumps(xray_json, indent=2), encoding='utf-8')
            if restart:
                subprocess.run(['systemctl', 'restart', 'xray'],
                               capture_output=True, timeout=5)
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
                        # 同步 Reality 账号表（2026-10-03）：一个 Hy2 用户
                        # 对应一个 VLESS UUID，开户即生效。
                        #
                        # ⚠️ 必须**当场落盘**（2026-10-05 修）：新凭据是随机的
                        # 并存在 data['reality_users'] 里，不写盘就只活在内存。
                        # 面板重启（部署/换版/崩溃）后会从盘上重新加载，
                        # 于是同一个 user_id 会**再生成一个不同的 UUID** ——
                        # 客户手里的 Reality 链接直接失效，且只有 Reality 通道
                        # 挂掉、Hy2 正常，极难定位。
                        reality_registry(data)
                        save_data()
                        rcfg = dict(data.get('reality_config', {}) or {})
                    regenerate_page()

                    # 销户/开户都要让 xray 的 clients 跟着变（多协议共用一套账号）
                    self._sync_reality_clients()

                    m = json.loads(meta_path.read_text()) if meta_path.exists() else {}
                    # artifacts 传入 reality + user_id ⇒ 输出「Hy2 + Reality」双节点
                    # 且 Clash / Sing-box 的策略组变成 url-test（自动择优）。
                    uri, clash_yaml, sing_json = artifacts(
                        m, auth_override=pwd, name_override=f"Teyir-Hy2-{user_id}",
                        reality=rcfg, user_id=user_id, data=data)
                    public_ip = m.get('public_ip', '127.0.0.1')
                    reality_uri = reality_uri_for_user(
                        rcfg, user_id, public_ip,
                        label=f"Teyir-Reality-{user_id}", data=data)
                    return self.reply_json(200, {
                        'ok': True,
                        'user_id': user_id,
                        'password': pwd,
                        'ip_limit': ip_limit,
                        'traffic_gb': traffic_gb,
                        'expires_at': expires,
                        'uri': uri,
                        'reality_uri': reality_uri,
                        'reality_uuid': reality_uuid_for_user(user_id, data),
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
                    # 与 Web 表单同一条保护：机主账号注销 = 主密码在 /auth 里失效。
                    if user_id == MASTER_USER_ID:
                        return self.reply_json(400, {'ok': False, 'error': 'Cannot delete the master account'})
                    with data_lock:
                        if user_id in data.get('users', {}):
                            del data['users'][user_id]
                            if user_id in ip_tracker:
                                del ip_tracker[user_id]
                            # 2026-10-03：同步删掉该用户的 Reality 身份。
                            # 不删的话 —— xray 里那个 UUID 还在，买家退了款
                            # 照样能用 Reality 连上，属于「钱退了货还在」。
                            #
                            # 2026-10-05：这里也会把凭据移进 retired（保留
                            # 窗口内不真删，重开户才能拿回同一个 UUID），
                            # 所以同样必须落盘 —— 否则重启后 retired 丢失，
                            # 重开户会拿到新 UUID。
                            reality_registry(data)
                            save_data()
                            deleted = True
                        else:
                            deleted = False
                    if deleted:
                        regenerate_page()
                        # 把 clients 变更热重载到 xray（不装 Reality 时静默跳过）
                        self._sync_reality_clients()
                        return self.reply_json(200, {'ok': True, 'message': 'User deleted'})
                    return self.reply_json(404, {'ok': False, 'error': 'User not found'})

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
                        if not u:
                            return self.reply_json(404, {'ok': False, 'error': 'User not found'})
                        before = u.get('status', 'active')
                        u['status'] = want
                        # 状态本身也要落盘 —— 否则重启后停用被「忘掉」，
                        # 已停用的账号会自己恢复成可用。
                        save_data()
                    regenerate_page()
                    # ⚠️ 必须把 status 变更同步进 xray —— 与开户/销户同等对待。
                    # reality_clients() 只输出 active 用户，但那份列表**只在
                    # 重载 xray 时才写进 xray.json**；不在这里调一次的话，
                    # 停用后那条 client 仍留在 xray 里，买家照旧能用 Reality
                    # 连上（Hy2 侧因为鉴权回调查 status 会立刻被拒，
                    # 于是一个人被停用后「UDP 断了、TCP 还通」，最难排查）。
                    self._sync_reality_clients()
                    return self.reply_json(200, {
                        'ok': True,
                        'user_id': user_id,
                        'status': want,
                        # changed=false 表示本来就是该状态（幂等）。
                        # 调用方据此区分"真的改了"与"重复调用"。
                        'changed': before != want,
                    })

                elif sub == 'users/list':
                    # BUGFIX #10: 商城节点对账用, 列出所有动态用户 (脱敏不返回 password)
                    now_ts = int(time.time())
                    users_out = []
                    with data_lock:
                        for uid, info in data.get('users', {}).items():
                            entry = {
                                'user_id': uid,
                                'expires_at': info.get('expires_at', 0),
                                # ⚠️ active 必须**同时**看 status 与到期：
                                # 鉴权回调判的是 status（见 handle_auth），
                                # 而这里原实现只看 expires_at —— 两者不一致的后果是
                                # "停用后列表仍报 active，但客户端连不上"，
                                # 那是最难排查的一类矛盾。两者必须同源。
                                'active': (info.get('status', 'active') == 'active'
                                           and info.get('expires_at', 0) > now_ts),
                                'status': info.get('status', 'active'),
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
                        'url': uri_link, 'format': f"{host}:{port}:{username}:{password}",
                        'gost_active': gost_status(),
                    })

                elif sub == 'proxy-services/list':
                    with data_lock:
                        items = list(data.get('proxy_services', []))
                    m = json.loads(meta_path.read_text()) if meta_path.exists() else {}
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

            if self.path == prefix + 'set-bbr':
                return self._h_post_set_bbr(prefix)

            if self.path == prefix + 'reboot-server':
                return self._h_post_reboot_server(prefix)

            if self.path == prefix + 'manage-user':
                return self._h_post_manage_user(prefix)

            # 4. Web 表单登录
            if self.path == prefix + 'login':
                return self._h_post_login(prefix)

            if self.path == prefix + 'install-warp':
                return self._h_post_install_warp(prefix)


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
            """POST /do-upgrade 的处理逻辑（从 do_POST 机械搬移而来）。"""
            if not self.is_authenticated():
                return self.reply_json(401, {'ok': False, 'error': 'Unauthorized'})
            try:
                length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(length).decode('utf-8')
                form = parse_qs(body)
                target = form.get('target', [''])[0]
                if target not in ('core', 'portal', 'awg'):
                    return self.reply_json(400, {'ok': False, 'error': 'Invalid target'})

                if target == 'portal':
                    # 面板由【两个文件】组成：portal.py（后端）+ portal_assets.py（前端资源）。
                    # 🔴 必须成对更新 —— 门户同时是 Hysteria 的鉴权后端，
                    # 只换其中一个会让它起不来、所有客户端连不上。
                    # 所以流程是：两个都取回 → 都做语法校验 → 再一起原子替换；
                    # 任一环节失败就整体放弃，磁盘上不留下任何改动。
                    #
                    # 自更新不走 do_upgrade.sh：那个脚本从 raw.githubusercontent.com
                    # 拉文件，会踩 raw 的 CDN 缓存（实测 push 后数分钟仍返回旧内容），
                    # 表现为"更新完还是旧版"。这里用多源回退直接取。
                    fetched = []
                    # 标记必须按文件各选各的 —— 踩过：给 portal_assets.py 用了
                    # b'hysteria2-installer'，但那个字符串只存在于 portal.py 里，
                    # 于是三个源全被判成"内容不对"，自更新永远失败。
                    # 现在 portal_assets.py 用 b'SCRIPT = r'：既确实存在，
                    # 又顺带校验了「JS 常量仍是原始字符串」这个关键属性。
                    for fname, marker, minsize in (('portal.py', b'hysteria2-installer', 20000),
                                                   ('portal_assets.py', b'SCRIPT = r', 10000)):
                        content = _fetch_repo_file(fname, marker=marker, min_size=minsize)
                        if content is None:
                            return self.reply_json(500, {'ok': False, 'error':
                                '取不到 %s（三个源均失败）—— 已放弃更新，面板保持原样' % fname})
                        try:
                            ast.parse(content.decode('utf-8'))
                        except Exception as e:
                            return self.reply_json(500, {'ok': False, 'error':
                                '%s 未通过 Python 语法校验（%s）—— 已放弃更新' % (fname, e)})
                        fetched.append((fname, content))

                    base_dir = PORTAL_SELF.parent
                    backups = []
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
                            tmp = str(dest) + '.new'
                            with open(tmp, 'wb') as fh:
                                fh.write(content)
                            os.chmod(tmp, 0o644)
                            os.replace(tmp, str(dest))
                            changed = True
                    except Exception as e:
                        # 出错就把已替换的恢复回去，绝不留下半新半旧的状态
                        for dest, bak in backups:
                            try:
                                shutil.copy2(str(bak), str(dest))
                            except Exception:
                                pass
                        return self.reply_json(500, {'ok': False, 'error':
                            '更新过程中出错，已回滚到原版本：%s' % e})

                    if not changed:
                        return self.reply_json(200, {'ok': True, 'target': target,
                                                     'message': '面板已是最新，无需更新'})
                    # 延迟重启，且必须脱离当前会话：本进程马上会被 systemctl 杀掉，
                    # 不脱离的话重启命令会跟着一起死（start_new_session=True）。
                    subprocess.Popen(
                        ['bash', '-c', 'sleep 1; systemctl restart hysteria-portal'],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        start_new_session=True)
                    return self.reply_json(200, {'ok': True, 'target': target,
                                                 'message': '面板已更新（后端 + 前端资源），服务重启中'})

                if target == 'awg':
                    if not awg_installed():
                        return self.reply_json(400, {'ok': False,
                                                     'error': 'AmneziaWG 尚未安装'})
                    # 先刷新控制脚本自身，再更新二进制。不需要重启面板。
                    ensure_awgctl(force=True)
                    rc, out, err = awg_run(['update'], timeout=420)
                    if rc != 0:
                        return self.reply_json(500, {'ok': False,
                            'error': 'AWG 更新失败：' + awg_err_tail(rc, out, err)})
                    return self.reply_json(200, {'ok': True, 'target': target,
                                                 'message': 'AmneziaWG 引擎已更新，客户端无需重新导入'})

                # core 仍交给 do_upgrade.sh：下载的是 Hysteria 官方发布，
                # 与 raw 的 CDN 缓存无关。
                subprocess.Popen(['bash', '/etc/hysteria/do_upgrade.sh', target],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return self.reply_json(200, {'ok': True, 'target': target})
            except Exception as e:
                return self.reply_json(500, {'ok': False, 'error': str(e)})

        def _h_post_manage_proxy(self, prefix):
            """POST /manage-proxy 的处理逻辑（从 do_POST 机械搬移而来）。"""
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

        def _h_post_install_gost(self, prefix):
            """POST /install-gost 的处理逻辑（从 do_POST 机械搬移而来）。"""
            if not self.is_authenticated():
                return self.reply_json(401, {'ok': False, 'error': 'Unauthorized'})
            try:
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
                            size = archive_path.stat().st_size
                            if size > 1024 * 1024 and tarfile.is_tarfile(str(archive_path)):
                                with tarfile.open(str(archive_path), 'r:gz') as tar:
                                    tar.extractall(path=tmpdir)
                                src_bin = Path(tmpdir) / 'gost'
                                if src_bin.exists():
                                    shutil.move(str(src_bin), '/usr/local/bin/gost')
                                    os.chmod('/usr/local/bin/gost', 0o755)
                                    installed = True
                                    break
                                errors.append('%s: 包内没有 gost 可执行文件' % host)
                            else:
                                errors.append('%s: 内容异常（%d 字节，非有效 tar.gz）' % (host, size))
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
                subprocess.run(['systemctl', 'daemon-reload'], capture_output=True)
                subprocess.run(['systemctl', 'enable', 'gost'], capture_output=True)

                # 重新生成 gost.yml 并启动服务
                write_gost_config()
                subprocess.run(['systemctl', 'restart', 'gost'], capture_output=True, timeout=10)

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

        def _h_post_manage_amneziawg(self, prefix):
            """POST /manage-amneziawg 的处理逻辑（从 do_POST 机械搬移而来）。"""
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

        def _h_post_manage_warp(self, prefix):
            """POST /manage-warp 的处理逻辑（从 do_POST 机械搬移而来）。"""
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
                    raw_text = cfg_path.read_text(encoding='utf-8')

                    # 只删掉 acl: 块，保留其余全部内容 —— 详见模块级
                    # strip_acl_block() 的注释（那里记录了踩过的坑：
                    # 原来的"删到文件尾"会把末尾的 obfs 段一起删掉，
                    # 导致"能连上但没网"）。
                    cfg_text = strip_acl_block(raw_text)

                    def has_outbound(name):
                        return re.search(r'^\s*-\s*name:\s*' + name + r'\s*$',
                                         cfg_text, re.M) is not None

                    if new_state:
                        # 出站名要探测实际存在的那个：config 模板用 warp_socks，
                        # 而某些版本的 toggle_warp.sh 会把它改写成 warp。
                        warp_name = 'warp_socks' if has_outbound('warp_socks') else 'warp'
                        if not has_outbound(warp_name):
                            warp_outbound = ("\n  - name: warp_socks\n    type: socks5\n"
                                                 "    socks5:\n      addr: 127.0.0.1:19898")
                            if 'outbounds:' in cfg_text:
                                cfg_text = cfg_text.replace('outbounds:', 'outbounds:' + warp_outbound, 1)
                            else:
                                cfg_text += '\noutbounds:' + warp_outbound
                            warp_name = 'warp_socks'

                        # 🔴 ACL 末尾引用的出站必须【真实存在】，否则 hysteria 直接
                        # 起不来，报错形如：
                        #   invalid config: acl.inline: error at line N:
                        #   outbound direct_ipv4 not found
                        # 历史教训：这里曾无条件写 direct_ipv4(all)。该出站由 config
                        # 模板定义，而 toggle_warp.sh 重写配置时可能把它连 outbounds
                        # 段一起删掉 —— 于是 Web 端点一下 WARP 开关就把 Hysteria
                        # 打成 failed，整台机器的 Hysteria 全挂。
                        # 现在先探测：存在才用 direct_ipv4（保留强制 IPv4 的意图），
                        # 否则退回 hysteria 内置的 direct。
                        tail_name = 'direct_ipv4' if has_outbound('direct_ipv4') else 'direct'

                        acl_block = '\nacl:\n  inline:\n'
                        for d in current_rules:
                            acl_block += '    - %s(suffix:%s)\n' % (warp_name, d)
                        acl_block += '    - %s(all)\n' % tail_name
                        cfg_text += acl_block

                    new_text = cfg_text.strip() + '\n'

                    # 改配置前留备份，重启后校验；起不来就自动回滚。
                    # 光靠"写对了"不够 —— 一个引用错出站的 ACL 就足以让服务起不来，
                    # 所以必须有一层兜底，不能让 Web 上的一个开关把服务打挂。
                    backup = cfg_path.read_text(encoding='utf-8')
                    cfg_path.write_text(new_text, encoding='utf-8')
                    subprocess.run(['systemctl', 'restart', 'hysteria-server'],
                                   capture_output=True, timeout=15)
                    time.sleep(2)
                    state = subprocess.run(['systemctl', 'is-active', 'hysteria-server'],
                                           capture_output=True, text=True, timeout=5).stdout.strip()
                    if state != 'active':
                        cfg_path.write_text(backup, encoding='utf-8')
                        subprocess.run(['systemctl', 'restart', 'hysteria-server'],
                                       capture_output=True, timeout=15)
                        with data_lock:
                            data['warp_apply_error'] = 'ACL 写入后 Hysteria 启动失败，已自动回滚配置'
                    else:
                        with data_lock:
                            data.pop('warp_apply_error', None)
                    # data_lock 是可重入锁，save_data 内部会再取一次，安全
                    save_data()

                threading.Thread(target=apply_hy2_acl, daemon=True).start()

                return self.reply_json(200, {
                    'ok': True,
                    'enabled': new_state,
                    'rules': current_rules
                })
            except Exception as e:
                return self.reply_json(500, {'ok': False, 'error': str(e)})

        def _h_post_install_xray(self, prefix):
            """POST /install-xray 的处理逻辑（从 do_POST 机械搬移而来）。"""
            if not self.is_authenticated():
                return self.reply_json(401, {'ok': False, 'error': 'Unauthorized'})
            try:
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
                Path('/etc/systemd/system/xray.service').write_text(service_content, encoding='utf-8')
                subprocess.run(['systemctl', 'daemon-reload'], capture_output=True)
                subprocess.run(['systemctl', 'enable', 'xray'], capture_output=True)
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

                return self.reply_json(200, {'ok': True, 'message': 'Xray-core 安装成功，VLESS-Reality 节点已在 TCP 443 端口就绪！'})
            except Exception as e:
                return self.reply_json(500, {'ok': False, 'error': f'安装执行异常: {str(e)}'})

        def _h_post_manage_reality(self, prefix):
            """POST /manage-reality 的处理逻辑（从 do_POST 机械搬移而来）。"""
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
                    # force=True：只有「重置密钥」按钮才真的换密钥对。
                    # 用户的 UUID 是 uuid5 派生的，不受密钥轮换影响。
                    self._generate_and_apply_reality(True, force=True)
                    return self.reply_json(200, {'ok': True, 'message': '已重置密钥并重启生效'})

                return self.reply_json(400, {'ok': False, 'error': 'Invalid action'})
            except Exception as e:
                return self.reply_json(500, {'ok': False, 'error': str(e)})

        def _h_post_set_bbr(self, prefix):
            """POST /set-bbr 的处理逻辑（从 do_POST 机械搬移而来）。"""
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

        def _h_post_reboot_server(self, prefix):
            """POST /reboot-server 的处理逻辑（从 do_POST 机械搬移而来）。"""
            if not self.is_authenticated():
                return self.reply_json(401, {'ok': False, 'error': 'Unauthorized'})
            try:
                subprocess.Popen(['bash', '-c', 'sleep 1 && reboot'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return self.reply_json(200, {'ok': True, 'message': '服务器正在重启中'})
            except Exception as e:
                return self.reply_json(500, {'ok': False, 'error': str(e)})

        def _h_post_manage_user(self, prefix):
            """POST /manage-user 的处理逻辑（从 do_POST 机械搬移而来）。"""
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
                    # 🔴 admin_master 不能被注销：它的 password 就是 Hysteria 的
                    # auth_password（机主本人的主密码）。/auth 是遍历 data['users']
                    # 按密码匹配的，一旦这条记录被删，主密码在 /auth 里立刻变成
                    # "User not found" —— 机主自己都被踢下线、再也连不上节点，
                    # 只能重装。所以这里必须拒绝，UI 那边也不渲染删除按钮。
                    if user_id == MASTER_USER_ID:
                        return self.reply(400, b'Cannot delete the master account')
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

        def _h_post_install_warp(self, prefix):
            """POST /install-warp 的处理逻辑（从 do_POST 机械搬移而来）。"""
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

        def do_GET(self):
            if self.path.startswith('/api/v1/'):
                if not self.check_rate_limit(bucket='api'):
                    return self.reply(429, b'Too many requests')
                if not self.verify_api_key():
                    return self.reply_json(401, {'ok': False, 'error': 'Unauthorized API key'})
                sub = self.path[len('/api/v1/'):]
                # 剥掉 query 再比较。
                #
                # ⚠️ self.path 是**含 query 的**原始路径，`/api/v1/speedtest?x=1`
                # 会让 sub 变成 'speedtest?x=1'，等值比较直接落空 → 404。
                # 既有端点（node/meta、users/list…）都有这个毛病，
                # 改成"全部剥 query"会改变它们的行为，超出本次改动范围。
                # 这里只让**新端点**自己扛住：切掉 '?' 再比，
                # 且 _h_api_speedtest 不读任何 query 参数
                # （靶点硬编码，见 SPEEDTEST_TARGETS 的安全说明）。
                if sub.split('?', 1)[0] == 'speedtest':
                    return self._h_api_speedtest()
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
                    #   * 只暴露**能力与状态**（装没装、开没开、什么版本），
                    #   **不暴露任何凭据**（私钥/公钥/UUID/api_key/密码）。
                    #   * 那些敏感值仍只在网页会话下可见，主面板拿不到也不需要。
                    #   * 因此这个端点可以安全地留在 Bearer 通道上。
                    m = json.loads(meta_path.read_text()) if meta_path.exists() else {}
                    with data_lock:
                        d_snap = {
                            'reality': dict(data.get('reality_config') or {}),
                            'warp_enabled': bool(data.get('warp_enabled')),
                            'users_count': len(data.get('users', {})),
                            'proxy_services': list(data.get('proxy_services') or []),
                        }

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
                            'vless_reality': {
                                'installed': _bin('xray'),
                                'active': _svc_active('xray'),
                                # 只报端口，不报 UUID/公钥/私钥。
                                'port': int(d_snap['reality'].get('port', 0) or 0),
                                # 是否已配置。
                                #
                                # ⚠️ 刻意**不引用** reality_config 里的密钥字段名。
                                # 本端点在 Bearer 通道上，虽然只输出 bool（不泄漏值），
                                # 但「响应体构造代码里出现密钥字段名」是个**坏信号**：
                                # ① 后来者照抄很容易顺手把值也带出去；
                                # ② 静态检查/人工审计无法一眼区分「读了」和「输出了」。
                                # short_id 是配置过的可靠标志（每次生成配置都会写它），
                                # 用它判断既准确又让这段代码零密钥字段引用。
                                'configured': bool(d_snap['reality'].get('short_id')),
                            },
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
                        },
                        'node': {
                            'public_ip': m.get('public_ip', ''),
                            'server_name': m.get('server_name', ''),
                            'is_insecure': bool(m.get('is_insecure')),
                            'hop_port_range': m.get('hop_port_range', ''),
                            'users_count': d_snap['users_count'],
                        },
                    })
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
                                # 与 API 通道同一判据（status + 到期），理由见那边注释。
                                'active': (info.get('status', 'active') == 'active'
                                           and info.get('expires_at', 0) > now_ts),
                                'status': info.get('status', 'active'),
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
                    # 面板只看这条 API: 补齐 host 与 gost 运行状态,
                    # 否则列表显示不出主机名, 也无法区分"服务真的可用"和"条目存在".
                    m = json.loads(meta_path.read_text()) if meta_path.exists() else {}
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

            if subpath == 'bbr-status':
                return self._h_get_bbr_status(subpath)

            if subpath == 'warp-status':
                return self._h_get_warp_status(subpath)

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

        def _h_get_proxy_services(self, subpath):
            """GET /proxy-services 的处理逻辑（从 do_GET 机械搬移而来）。"""
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

        def _h_get_check_version(self, subpath):
            """GET /check-version 的处理逻辑（从 do_GET 机械搬移而来）。"""
            if not self.is_authenticated():
                return self.reply_json(401, {'ok': False, 'error': 'Unauthorized'})
            core_curr = '未知'
            core_latest = '未知'
            core_has_update = False

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

            # 面板自身与 AWG 引擎：用 git blob sha 比对文件内容。
            # 原实现依赖 data['portal_sha']，但那个字段从来没被写入过，
            # 导致 portal_has_update 恒为 False、「更新面板」按钮永远不显示。
            portal_curr, portal_latest, portal_has_update = _version_triple(
                str(PORTAL_SELF), 'portal.py')
            awg_curr, awg_latest, awg_has_update = _version_triple(
                AWG_CTL, 'awgctl.sh')

            return self.reply_json(200, {
                'ok': True,
                'core_current': core_curr,
                'core_latest': core_latest,
                'core_has_update': core_has_update,
                'portal_current': portal_curr,
                'portal_latest': portal_latest,
                'portal_has_update': portal_has_update,
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

            results = []
            for key, name, host, carrier in SPEEDTEST_TARGETS:
                avg, loss = self._ping_one(host)
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
                proc = subprocess.run(
                    ['ping', '-c', '3', '-W', '2', host],
                    capture_output=True, text=True, timeout=10,
                )
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

        def _h_get_warp_status(self, subpath):
            """GET /warp-status 的处理逻辑（从 do_GET 机械搬移而来）。"""
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

        def _h_get_awg_state(self, subpath):
            """GET /awg-state 的处理逻辑（从 do_GET 机械搬移而来）。"""
            if not self.is_authenticated():
                return self.reply_json(401, {'ok': False, 'error': 'Unauthorized'})
            return self.reply_json(200, awg_state())

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

    # 启动兜底：如果上一次运行时有 clients 变更被「节流」跳过
    # （见 _reality_restart_allowed），配置写进 xray.json 了但服务没重载。
    # 这里在 serve 之前无条件对一次 —— 幂等、便宜（约 100ms）。
    #
    # ⚠️ 顺带解封 start-limit：上一版因为频繁 restart 撞上
    # systemd 的 start-limit，xray 停在 failed 且无法自愈。
    # reset-failed 是标准的解封手段，不影响正常运行中的服务。
    try:
        if Path('/etc/hysteria/xray.json').exists():
            with data_lock:
                _want = reality_clients(data)
            _got = []
            try:
                _cfg = json.loads(Path('/etc/hysteria/xray.json').read_text(encoding='utf-8'))
                for _i in (_cfg.get('inbounds') or []):
                    if _i.get('protocol') == 'vless' and \
                       (_i.get('streamSettings') or {}).get('security') == 'reality':
                        _got = _i.get('settings', {}).get('clients') or []
                        break
            except Exception:
                _got = []
            if [c.get('email') for c in _want] != [c.get('email') for c in _got]:
                subprocess.run(['systemctl', 'reset-failed', 'xray'],
                               capture_output=True, timeout=5)
                subprocess.run(['systemctl', 'restart', 'xray'],
                               capture_output=True, timeout=10)
                print('[portal] 启动时补同步了 xray clients（%d 个）' % len(_want),
                      file=sys.stderr)
    except Exception as e:
        print('[portal] 启动补同步跳过: %s' % str(e)[:120], file=sys.stderr)

    server.serve_forever()


if __name__ == '__main__':
    if sys.argv[1] == 'prepare':
        api_key = sys.argv[4] if len(sys.argv) > 4 else None
        prepare(sys.argv[2], sys.argv[3], api_key)
    elif sys.argv[1] == 'refresh':
        refresh(sys.argv[2])
    else:
        serve(sys.argv[2])


