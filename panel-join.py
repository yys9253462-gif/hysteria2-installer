#!/usr/bin/env python3
"""打印（或直接上报）本节点接入 hy2-ops-console 面板所需的全部信息。

## 为什么要有这个脚本

面板导入节点只需要两个字段：api_url 和 api_key。但这两个值在节点上
分散在两处，而且 api_url 不是「随便哪个端口」：

  * portal.py 只监听 127.0.0.1:<portal.json 里的 port>，面板从外部连不到
  * 真正对外可达的是 hysteria 的 masquerade 反代端口，即 config.yaml 里的
    `masquerade.listenHTTPS`
  * 这个端口**每台机器可能不一样** ——实测三台机器分别是 8443 / 8443 / 11690。
    照抄 8443 会在第三台上直接失败，且报错只是「连接不上」，很难联想到是端口抄错。

于是「把一台已经跑着的 hy2 节点接进面板」原本要手工做四步：
  1. ssh 上机器
  2. 从 portal.json 里找 api_key 和 portal 端口
  3. 从 config.yaml 里找域名和 listenHTTPS 端口
  4. 自己拼成 https://域名:端口 再粘到面板

这个脚本把 2~4 步合成为一条命令。

## 用法

    # 只打印（最常用）：把两行结果粘进面板导入框
    python3 panel-join.py

    # 输出可直接粘贴的 curl 命令 / JSON
    python3 panel-join.py --format json
    python3 panel-join.py --format curl --panel https://mb.teyir.com --admin-token <JWT>

    # 直接上报，连面板都不用开：脚本自己 POST /api/nodes
    python3 panel-join.py --register --panel https://mb.teyir.com --admin-token <JWT>

    # 令牌不想出现在 ps / shell 历史里，就改用环境变量：
    PANEL_ADMIN_TOKEN=<JWT> python3 panel-join.py --register --panel https://mb.teyir.com

## 退出码

    0  成功拿到 api_url + api_key
    2  缺少文件（portal.json / config.yaml）
    3  节点没有对外可达的 API 通道（没有 masquerade.listenHTTPS），需要人工处理
"""
import argparse
import json
import os
import re
import sys
import urllib.request
import urllib.error

CONFIG = "/etc/hysteria/config.yaml"
PORTAL = "/etc/hysteria/portal.json"
META = "/etc/hysteria/client_meta.json"


def meta_host(meta_text):
    """与门户同一条规则取对外地址：自签用 public_ip，可信证书用 server_name。

    只看 config.yaml 的 acme.domains 不够：证书来自 Caddy / 手工路径（tls 段）
    或自签时根本没有这一段，旧逻辑拼出 `https://13427` 这种没有主机的地址
    （2026-11-03 在瑞典节点实测）。
    """
    try:
        meta = json.loads(meta_text or "")
    except ValueError:
        return ""
    if not isinstance(meta, dict):
        return ""
    key = "public_ip" if meta.get("is_insecure") else "server_name"
    host = meta.get(key)
    return host.strip() if isinstance(host, str) else ""


def read(path):
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read()


def parse_simple_yaml(text):
    """只取需要的几个键，不引第三方依赖（节点上不一定装了 PyYAML）。

    hy2 的 config.yaml 结构很浅，缩进两级，按缩进扫一遍足够。
    """
    out = {}
    # 记录每个顶层键下面的子键值对
    top = None
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip() or line.strip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        body = line.strip()
        if indent == 0:
            if ":" in body:
                k, _, v = body.partition(":")
                top = k.strip()
                out[top] = {"__value__": v.strip()}
            continue
        if ":" not in body or top is None:
            continue
        k, _, v = body.partition(":")
        out[top][k.strip()] = v.strip().strip('"').strip("'")
    return out


def main():
    ap = argparse.ArgumentParser(description="生成本节点接入 hy2-ops-console 所需的信息")
    ap.add_argument("--config", default=CONFIG)
    ap.add_argument("--portal", dest="portal_file", default=PORTAL)
    ap.add_argument("--meta", dest="meta_file", default=META)
    ap.add_argument("--panel", help="面板地址，如 https://mb.teyir.com")
    # 也可用环境变量 PANEL_ADMIN_TOKEN 传：命令行参数会出现在 ps / shell 历史里。
    ap.add_argument("--admin-token", default=os.environ.get("PANEL_ADMIN_TOKEN"),
                    help="面板管理员 JWT（用于 --register 或 --format curl；也可设环境变量 PANEL_ADMIN_TOKEN）")
    ap.add_argument("--name", help="节点名，默认用 域名-端口")
    ap.add_argument("--format", choices=["text", "json", "curl"], default="text")
    ap.add_argument("--register", action="store_true", help="直接 POST 到面板完成登记")
    args = ap.parse_args()

    cfg_text, portal_text = read(args.config), read(args.portal_file)
    if cfg_text is None or portal_text is None:
        missing = [p for p, t in ((args.config, cfg_text), (args.portal_file, portal_text))
                   if t is None]
        print("找不到：" + "、".join(missing), file=sys.stderr)
        print("本脚本要在已经装好 hysteria2 的节点上跑。", file=sys.stderr)
        return 2

    try:
        meta = json.loads(portal_text)
    except Exception as e:
        print(f"portal.json 解析失败：{e}", file=sys.stderr)
        return 2

    api_key = meta.get("api_key") or ""
    portal_port = meta.get("port")
    if not api_key:
        print("portal.json 里没有 api_key —— 这台节点的 portal 版本太旧，"
              "请先升级 hysteria2-installer。", file=sys.stderr)
        return 2

    cfg = parse_simple_yaml(cfg_text)
    masq = cfg.get("masquerade", {})

    # 域名：优先 client_meta.json（门户发订阅用的同一个地址），
    # 再退回 acme.domains 的第一项（列表在 YAML 里是 "- xxx" 行，简单解析拿不到，
    # 所以退回到正则扫）
    domain = meta_host(read(args.meta_file))
    m = re.search(r"^\s*-\s*([A-Za-z0-9._-]+)\s*$", cfg_text, re.M)
    acme_block = re.search(r"^acme:(.*?)(?=^[a-z])", cfg_text, re.M | re.S)
    if not domain and acme_block:
        dm = re.search(r"domains:\s*\n((?:\s*-\s*[^\n]+\n)+)", acme_block.group(1))
        if dm:
            first = re.search(r"-\s*([A-Za-z0-9._-]+)", dm.group(1))
            if first:
                domain = first.group(1)
    if not domain and m:
        domain = m.group(1)

    # 对外可达端口 = masquerade.listenHTTPS
    # 可能写成 `:8443` 或 `0.0.0.0:8443`：只取最后一个冒号后的数字（2026-11-04 修），
    # 旧实现拼出 https://a.com:0.0.0.0:8443 还返回 0。
    https_port = (masq.get("listenHTTPS") or "").rpartition(":")[2].strip()
    if not https_port.isdigit():
        m2 = re.search(r"listenHTTPS:\s*\S*?:?(\d+)\s*$", cfg_text, re.M)
        https_port = m2.group(1) if m2 else ""

    if not https_port:
        print("=" * 60, file=sys.stderr)
        print("这台节点没有对外可达的 API 通道。", file=sys.stderr)
        print("portal.py 只监听 127.0.0.1:%s，面板在另一台机器上连不到它。" % portal_port,
              file=sys.stderr)
        print("需要在 config.yaml 的 masquerade 段加一行：", file=sys.stderr)
        print("    listenHTTPS: :8443      # 或别的未被占用的端口", file=sys.stderr)
        print("然后重启 hysteria-server，再跑一次本脚本。", file=sys.stderr)
        print("=" * 60, file=sys.stderr)
        return 3

    listen = (cfg.get("listen", {}).get("__value__") or "").lstrip(":")
    if not domain:
        # 没有主机名就拼不出能用的地址；旧实现输出 `https://<端口>` 并返回 0。
        print("取不到节点的对外地址：client_meta.json 没有 server_name / public_ip，"
              "config.yaml 里也没有 acme.domains。", file=sys.stderr)
        return 3
    host = f"[{domain}]" if ":" in domain and not domain.startswith("[") else domain
    api_url = f"https://{host}:{https_port}"

    result = {
        "api_url": api_url,
        "api_key": api_key,
        "domain": domain,
        "listen_port": int(listen) if listen.isdigit() else None,
        "portal_port": portal_port,
        "masquerade_https_port": int(https_port) if https_port.isdigit() else None,
        "suggested_name": (f"{domain}-{listen}" if domain and listen else domain),
    }

    if args.format == "json":
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    if args.format == "curl":
        if not args.panel:
            print("--format curl 需要 --panel", file=sys.stderr)
            return 2
        body = json.dumps({
            "name": args.name or result["suggested_name"],
            "api_url": result["api_url"],
            "api_key": result["api_key"],
        }, ensure_ascii=False)
        print(f"curl -X POST '{args.panel}/api/nodes' \\")
        if args.admin_token:
            print(f"  -H 'Authorization: Bearer {args.admin_token}' \\")
        else:
            print("  -H 'Authorization: Bearer <管理员JWT>' \\")
        print("  -H 'Content-Type: application/json' \\")
        print(f"  -d '{body}'")
        return 0

    if args.register:
        if not args.panel:
            print("--register 需要 --panel", file=sys.stderr)
            return 2
        if not args.admin_token:
            print("--register 需要 --admin-token", file=sys.stderr)
            return 2
        body = json.dumps({
            "name": args.name or result["suggested_name"],
            "api_url": result["api_url"],
            "api_key": result["api_key"],
        }, ensure_ascii=False).encode()
        req = urllib.request.Request(args.panel + "/api/nodes", data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Authorization", "Bearer " + args.admin_token)
        try:
            r = urllib.request.urlopen(req, timeout=30)
            print(f"登记成功 HTTP {r.status}")
            print(r.read().decode())
            return 0
        except urllib.error.HTTPError as e:
            detail = e.read().decode()[:300]
            print(f"登记失败 HTTP {e.code}: {detail}", file=sys.stderr)
            return 1
        except Exception as e:
            print(f"登记失败：{type(e).__name__}: {e}", file=sys.stderr)
            return 1

    # 默认：人类可读
    print("=" * 58)
    print("把下面两行粘进面板的「登记节点」对话框")
    print("=" * 58)
    print(f"  节点 API 地址 (api_url) : {result['api_url']}")
    print(f"  通信密钥      (api_key) : {result['api_key']}")
    print("-" * 58)
    print(f"  建议节点名              : {result['suggested_name']}")
    print(f"  hy2 监听端口 (UDP)      : {listen or '—'}")
    print(f"  portal 内网端口         : {portal_port}")
    print(f"  对外 API 端口           : {https_port}  ← 取自 masquerade.listenHTTPS")
    print("=" * 58)
    return 0


if __name__ == "__main__":
    sys.exit(main())
