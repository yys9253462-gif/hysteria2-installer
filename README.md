# Hysteria 2 全功能生产级一键部署与管理脚本

[![GitHub License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Debian%20%7C%20Ubuntu%20%7C%20CentOS%20%7C%20Alpine-success.svg)](#)
[![Hysteria Version](https://img.shields.io/badge/Hysteria-v2.x-orange.svg)](https://v2.hysteria.network/)

极速、轻量、高可用的 **Hysteria 2 (Hy2)** 官方服务端一键自动化部署脚本。针对恶劣网络环境、高丢包率场景与运营商 UDP QoS 做了深度优化。

---

## ✨ 核心特性

- ⚡ **官方核心保证**：自动检测 CPU 架构（amd64 / arm64 / armv7），直接拉取 Hysteria 官方最新发布版二进制。
- 🛡️ **自签 / 自定义 / 域名证书**：支持一键生成 ECC (prime256v1) 自签证书、指定已有 acme.sh / certbot 证书，或绑定域名并自动申请 Let's Encrypt 证书。
- 🔀 **端口跳跃 (Port Hopping) 默认启用**：内置自动化 `iptables` 多端口转发规则（默认 UDP 20000-40000），有效突破单一 UDP 端口被运营商 QoS 限速或丢包。
- 🎭 **Salamander 混淆 默认启用**：全自动生成高熵随机密码，将 QUIC 数据报文伪装为完全随机的杂波，彻底免疫 GFW 主动探测与深度包检测。
- 🛡️ **AmneziaWG 抗 DPI 协议 (可选安装)**：一键部署 WireGuard 的抗审查分支，密码学内核完全不变，只把数据包的头部、长度与时序特征随机化。采用**用户态 `amneziawg-go`** 部署 —— 不编译内核模块、不引入 Docker、不在服务器上装 Go 工具链：二进制由本仓库的 GitHub Actions 交叉编译成**全静态**产物（amd64 / arm64 / armv7）后发布到 Release 下载。支持 **AWG 2.x / 3.x 双协议线可切换**、多客户端管理、`.conf` 下载与二维码导入，并在 Web 控制台提供独立的客户端管理与状态面板。
- 🌐 **Cloudflare WARP 智能分流 (AI 加速)**：内置 `wgcf` + `wireproxy` 自建本地出口（socks5 `127.0.0.1:19898`，免 apt、无需官方 MASQUE 客户端，绕开 Debian 12 上 `cloudflare-warp` 因 apt keyring bug 装不上的问题），配合 3 分钟探活自愈 Watchdog，并在 Web 控制台独立扩展页面提供一键按需启闭开关，实现 OpenAI、Claude、Gemini 干净住宅出口与 VPS 原生极速直连。
- 🔄 **Web 端双重版本检测与一键升级**：在 Web 仪表盘在线比对 Hysteria 2 官方内核与控制面板自身版本，发现新版一键平滑无损热升级。
- 🕳️ **独立「入站代理 & WARP」扩展专区 (SOCKS5 / HTTP / HTTPS)**：集成 GOST 引擎，支持 Web 端一键安装/修复核心；解耦独立页面一键添加/删除三种入站代理服务（独立账号密码认证），客户端无需安装 Hysteria 也能直接把服务器当普通代理用，配置动态生成并平滑热重载。
- 📱 **多客户端格式全覆盖**：
  - 标准 **`hysteria2://`** 节点直链（支持 v2rayN、Nekobox、Shadowrocket、Sing-box 等一键导入）
  - **Clash.Meta / Mihomo** (Clash Verge Rev) 节点配置片段
  - **Sing-box** (SFA / SFI) Outbound 节点配置片段
  - 安装完成显示私密 HTTPS 信息页地址和随机登录凭据；二维码、订阅和配置统一在登录后的网页查看。
- 🏢 **多租户集群 Agent 节点模式（电商/多用户对接）**：
  - 支持作为分布式集群节点接入发卡商城或统一控制台（如 `pay.isoziyuan.com`）。
  - 内置高性能 REST API（`/api/v1/users/create`, `renew`, `delete`, `node/meta`）与 Hysteria 2 本地 HTTP 动态鉴权。
  - 用户开通、续费与注销实时生效，**零中断、无需重启 Hysteria 2 服务**。
- 🛠️ **全生命周期管理**：Systemd 服务自动守护、开机自启、内核 UDP 缓冲与参数调优、一键升级、实时日志监控与彻底卸载。

---

## 🚀 极速一键安装

在你的 Linux 服务器终端（以 `root` 用户）执行以下单行命令即可启动管理交互菜单：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/yys9253462-gif/hysteria2-installer/main/install.sh)
```

或使用 `wget`：

```bash
bash <(wget -qO- https://raw.githubusercontent.com/yys9253462-gif/hysteria2-installer/main/install.sh)
```

---

## 📋 控制台交互菜单

安装后，随时在终端直接执行脚本即可呼出管理菜单：

```
================================================================
       Hysteria 2 全功能生产级管理脚本 (x86_64)         
       GitHub: https://github.com/yys9253462-gif/hysteria2-installer    
================================================================
核心状态: 运行中 (Active) | 版本: v2.12.x
AWG 状态 : 运行中 | 协议线: AWG 3.x | UDP 53821
----------------------------------------------------------------
  1. 全新安装 Hysteria 2
  2. 更新 Hysteria 2 核心至最新版
  3. 查看私密信息页地址和登录凭据
  4. 重新修改配置 (端口/密码/证书/域名/混淆)
  5. 一键安装并配置 Cloudflare WARP 出口 (AI解锁)
  6. 一键安装 gost 入站代理引擎 (SOCKS5/HTTP/HTTPS)
----------------------------------------------------------------
  7. 一键安装 AmneziaWG (抗 DPI · 用户态 WireGuard)
  8. AmneziaWG 管理 (客户端 / 版本切换 / 更新 / 卸载)
----------------------------------------------------------------
  9. 启动服务
  10. 停止服务
  11. 重启服务
  12. 查看实时运行日志
  13. 彻底卸载 Hysteria 2
  0. 退出脚本
================================================================
```

> `AWG 状态` 那一行只在本机安装过 AmneziaWG 时才显示，未安装时菜单外观与旧版完全一致。

---

## 🛡️ AmneziaWG 抗 DPI 协议

**AmneziaWG 是 WireGuard 的抗审查分支**：加密内核（Curve25519 / ChaCha20-Poly1305 / BLAKE2s / Noise_IK）一字未改，只把数据包的**头部、长度与时序特征**随机化，让 DPI（深度包检测）无法按固定指纹识别。

标准 WireGuard 的问题是"太规整"：握手包恒定 148 字节、头部类型字段恒为 `0x01 00 00 00`，这些值**全世界每个部署都一样**，所以审查方写一条规则就能全网封杀。AmneziaWG 用四层机制拆掉这些常量：垃圾包（`Jc`/`Jmin`/`Jmax`）、随机长度前缀（`S1`-`S4`）、动态头部（`H1`-`H4`）、协议签名包（`I1`-`I5`）。

### 为什么走用户态而不是内核模块

内核模块性能更好，但在 Debian 12 上代价过高，因此本项目选择用户态：

| 方案 | 问题 |
| :--- | :--- |
| 官方 PPA (DKMS) | **只发布 Ubuntu 包**，Debian 上要强塞 Ubuntu 源，脏且易碎 |
| 手工编译模块 | 5.6+ 内核要求提供**完整内核源码树**（不是 `linux-headers`），官方原话 "pretty huge" |
| 运维成本 | 宿主内核升级后需 DKMS 重建，失败会影响系统启动 |

用户态方案的代价是吞吐上限低于内核态（单线程用户态转发），对个人使用完全够用。`awg-quick` 会自动检测内核模块：**如果宿主机自己装了 `amneziawg` 内核模块，会自动优先走内核态**，无需改配置。

### 端口为什么不能用 20000-40000

Hysteria 2 的端口跳跃会给本机装上这条规则：

```bash
iptables -t nat -A PREROUTING -p udp --dport 20000:40000 -j REDIRECT --to-ports <HY2端口>
```

**落在 20000-40000 区间的 UDP 会被全部劫持给 Hysteria**。AmneziaWG 的监听端口若落在这个区间，会**收不到任何握手包**。因此本脚本默认从 **50000-59000** 中选取空闲端口，并在你手工指定端口时直接拦截该区间。同时避开 `51820` —— WireGuard 的默认端口本身就是个弱指纹。

### 协议线怎么选

| 协议线 | 上游 tag | 特点 |
| :--- | :--- | :--- |
| **AWG 3.x** (默认) | `v3.1.20260828` | 头部保护、时序随机化、随机包尾，对抗**连接行为分析**。要求 `S1`-`S4` 全部 ≥ 12 |
| **AWG 2.x** | `v0.2.19` | 参数体系成熟、生态验证更充分，兼容性最好 |

⚠️ **两条协议线的参数体系不同，切换会重新生成全部混淆参数，所有已发放的客户端配置会立即失效，必须全部重新导出。** 菜单里的"切换协议线"会明确警告并要求二次确认。

### 三条必须记住的约束

1. **`S1`-`S4` / `H1`-`H4` / `HeaderProtectionKey` 必须两端逐字节一致** —— 任何一端改动都会导致完全连不上。这也是"握手成功但没流量"类问题的头号原因。
2. **`H1`-`H4` 之间不得重叠**（官方硬性要求）。本脚本用四分带取值，天然满足。
3. **`Jc` / `Jmin` / `Jmax` 可以两端不同**，其余参数必须一致。

### 客户端导入

客户端配置在 Web 控制台 "入站代理与 WARP 扩展服务" 页面的 AmneziaWG 卡片里，或终端菜单第 8 项：

- **下载配置** → 生成标准 `.conf`，可直接导入 [AmneziaWG 官方客户端](https://github.com/amnezia-vpn/amneziawg-windows-client/releases)、WG Tunnel、AmneziaVPN
- **二维码** → 手机端扫码导入

> 标准 WireGuard 客户端**连不上**开了混淆的服务器，反之亦然 —— 混淆参数是配置的必需部分，不是可选项。

---

## ⚡ 常用快捷命令

支持命令行无交互直达指令：

| 快捷命令 | 功能说明 |
| :--- | :--- |
| `bash install.sh info` | 再次显示私密信息页地址与登录凭据 |
| `bash install.sh refresh-page` | 只更新网页外观，保留节点参数、网页路径和账号密码 |
| `bash install.sh status` | 查看 Systemd 运行状态 |
| `bash install.sh restart` | 重启 Hysteria 2 服务端 |
| `bash install.sh update` | 一键检查并更新 Hysteria 官方二进制 |
| `bash install.sh uninstall`| 彻底卸载服务并清理配置文件 |
| `bash install.sh awg-install --line 3 --endpoint vpn.example.com --client phone` | 非交互安装 AmneziaWG（`--port` 可选，留空自动选取） |
| `bash install.sh awg-menu` | 进入 AmneziaWG 管理子菜单 |
| `bash install.sh awg-status` | 查看 AmneziaWG 运行状态 |
| `bash install.sh awg-update` | 更新 AmneziaWG 二进制（参数与客户端不受影响） |
| `bash install.sh awg-uninstall` | 卸载 AmneziaWG |
| `bash install.sh awg peer-list --json` | 透传任意底层命令给 `hy2-awgctl` |

底层引擎是独立脚本 `awgctl.sh`（安装为 `/usr/local/bin/hy2-awgctl`），命令行菜单与 Web 门户共用同一套实现，不存在两份配置生成逻辑：

```bash
hy2-awgctl status                              # 运行状态
hy2-awgctl peer-add phone --endpoint vpn.example.com   # 新增客户端并打印 .conf
hy2-awgctl client-conf phone --endpoint vpn.example.com # 只输出 .conf 文本
hy2-awgctl qr phone                            # 终端直接显示二维码
hy2-awgctl peer-del phone                      # 删除客户端（立即断线）
hy2-awgctl update --line 2                     # 切换协议线
hy2-awgctl resync                              # 依 meta 重新渲染配置并重启
```

---

## ⚙️ 目录结构与配置参考

- **服务端主配置文件**：`/etc/hysteria/config.yaml`
- **自签证书存放目录**：`/etc/hysteria/cert/`
- **连接元数据备份**：`/etc/hysteria/client_meta.json`
- **Systemd 服务单元**：`/etc/systemd/system/hysteria-server.service`

安装 AmneziaWG 后额外产生：

- **AWG 服务端配置**：`/etc/amnezia/amneziawg/awg0.conf`（由 `hy2-awgctl` 生成，勿手工编辑）
- **AWG 密钥与参数**：`/etc/amnezia/amneziawg/awg_meta.json`（服务端私钥、端口、协议线、混淆参数）
- **AWG 客户端列表**：`/etc/amnezia/amneziawg/awg_peers.json`
- **AWG Systemd 服务单元**：`/etc/systemd/system/amneziawg-server.service`（用户态，走 `awg-quick`）
- **AWG 控制工具**：`/usr/local/bin/hy2-awgctl`，二进位于 `/usr/local/bin/amneziawg-go`、`awg`、`awg-quick`

### 绑定域名并自动申请证书

安装或菜单中的“重新修改配置”时，在 TLS 证书方式中选择 `3`，输入域名和通知邮箱即可。脚本会让 Hysteria 使用 ACME HTTP-01 自动申请和续期证书。

开始前必须完成以下事项：

- 为域名创建指向服务器公网 IPv4 的 `A` 记录；若设置了 `AAAA` 记录，也必须确保 IPv6 可访问，否则请删除它。
- 在云厂商安全组中放行 **TCP 80**；若启用 Clash 订阅，还需放行脚本显示的订阅 TCP 端口（优先使用 8443，如被占用会自动选择空闲高位端口）。
- 脚本会自动放行本机 UFW/firewalld 的 TCP 80，但云安全组需要自行放行。

**脚本会先做 DNS 解析预校验**：自动查询 `${SERVER_NAME}` 的 A 记录并与本机公网 IPv4 比对，三种结果——

| 解析结果 | 脚本行为 |
|---|---|
| 命中本机公网 IP | 直接继续申请证书 |
| 解析到其他 IP | 输出明确告警，询问是否仍要继续（默认 **N** 中止） |
| 无 A 记录 | 输出可能原因清单，询问是否仍要继续（默认 **N** 中止） |

这样可避免 Let's Encrypt HTTP-01 必然失败导致 `hysteria-server` 反复重启、日志刷屏却没有任何中文提示的尴尬。

成功后客户端会使用该域名作为服务器地址和 SNI，且不再需要开启 `skip-cert-verify` / `insecure`。

### 服务端配置模板 (`config.yaml`)

```yaml
listen: :4433

tls:
  cert: /etc/hysteria/cert/server.crt
  key: /etc/hysteria/cert/server.key

auth:
  type: password
  password: your_secure_password

masquerade:
  type: proxy
  proxy:
    url: https://www.bing.com/
    rewriteHost: true

bandwidth:
  up: 1 gbps
  down: 1 gbps

# 默认使用 IPv4 直连，避免没有 IPv6 出站路由的 VPS 在访问
# YouTube 等同时返回 IPv4 / IPv6 地址的网站时连接失败。
outbounds:
  - name: direct_ipv4
    type: direct
    direct:
      mode: "4"
  - name: warp_socks
    type: socks5
    socks5:
      addr: 127.0.0.1:19898

# 默认开启 Salamander 混淆
obfs:
  type: salamander
  salamander:
    password: your_random_obfs_password

# 开启 WARP 时的 AI 分流 ACL 规则 (支持 Web 控制台一键启闭)
acl:
  inline:
    - warp_socks(openai.com)
    - warp_socks(chatgpt.com)
    - warp_socks(oaistatic.com)
    - warp_socks(oaiusercontent.com)
    - warp_socks(ai.com)
    - warp_socks(gemini.google.com)
    - warp_socks(aistudio.google.com)
    - warp_socks(generativelanguage.googleapis.com)
    - warp_socks(anthropic.com)
    - warp_socks(claude.ai)
```

> 脚本默认将 Hysteria 的 direct 出站固定为 IPv4。这可以避免部分仅有 IPv4
> 出站能力的 VPS 因 DNS 返回 IPv6 地址而出现 `network is unreachable`，进而无法播放
> YouTube 等双栈网站的视频。若服务器已配置并验证 IPv6 出站，也可将
> `outbounds[0].direct.mode` 改为 `auto`，恢复双栈 Happy Eyeballs 策略。开启 WARP 后，OpenAI / Claude / Gemini 自动引流至 Cloudflare 干净出口。

---

## 📲 客户端配置说明

### 1. v2rayN / Nekobox / Shadowrocket
打开终端显示的私密信息页，输入账号密码后，扫描二维码或复制 HY2 链接导入。

### 2. Clash.Meta / Mihomo
复制网页中的带认证订阅地址到客户端。订阅为完整配置，含代理组和路由；JSON 格式也是合法 YAML。若客户端不支持 URL 中的 Basic Auth 用户信息，请在浏览器登录后下载配置导入。

### 3. Sing-box
将生成的 JSON 片断添加进 `outbounds` 节点列表中。

## 私密信息页的安全与运行要求

需要 Python 3.9+、qrencode 和 systemd 247+（使用 LoadCredential）。一键脚本内嵌网页程序，不依赖外部二维码网站或第三方 JS。二维码仅在服务器本地生成。

Hysteria 在空闲 TCP 端口上提供 HTTPS，并将请求转发到只监听 127.0.0.1 的独立低权限网页服务。共用 Hysteria 当前证书与续期机制；不占用已有网站的 80/443。使用 ACME HTTP-01 申请证书本身仍需要 TCP 80 可用。自签证书会触发浏览器证书告警；推荐使用受信任的域名证书。

页面路径使用 256-bit 随机值，随机密码同样具有 256-bit 熵。页面、二维码、订阅与下载均验证 Basic Auth；没有免登录订阅后门。随机路径不代表端口不可扫描，认证才是访问控制。请保密 URL 与账号密码，订阅 URL 内含凭据。

只开放四个固定路由，禁止目录浏览；响应带 no-store、CSP、禁止嵌入、禁止索引及禁止 referrer 标头。后端不记录访问路径或密码，使用恒定时间摘要比较验证认证。全局每秒最多 20 个请求，60 秒内 30 次失败认证后临时限流；高频攻击仍可能导致暂时不可用。可在云安全组将网页端口限制为自己的 IP。

每次重新配置都会轮换网页路径和登录凭据，旧链接失效，客户端需更新订阅。菜单 3 仅显示已有访问凭据。卸载时停止并删除 hysteria-portal.service 及其配置。已有旧版安装需重新配置才启用网页；本次仓库更新不会自动部署到服务器。

开发检查：`bash -n install.sh` 和 `python3 -m unittest discover -s tests -v`。维护 portal.py 后须同步 install.sh 的 PYPORTAL 内嵌段；回归测试会验证一致性。

---

## 📄 开源许可证

本项目基于 [MIT License](LICENSE) 开源。
