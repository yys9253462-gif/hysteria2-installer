# Hysteria 2 全功能生产级一键部署与管理脚本

[![GitHub License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Debian%20%7C%20Ubuntu%20%7C%20CentOS-success.svg)](#)
[![Hysteria Version](https://img.shields.io/badge/Hysteria-v2.x-orange.svg)](https://v2.hysteria.network/)

极速、轻量、高可用的 **Hysteria 2 (Hy2)** 官方服务端一键自动化部署脚本。针对恶劣网络环境、高丢包率场景与运营商 UDP QoS 做了深度优化。

---

## ✨ 核心特性

- ⚡ **官方核心保证**：自动检测 CPU 架构（amd64 / arm64 / armv7），从 Hysteria 官方发布下载二进制。下载前先解析出**确定的版本**，取该版本的官方 `hashes.txt` 按精确资产名解析 SHA256，校验通过才替换；取不到清单或摘要不一致一律放弃安装，现有二进制不动。（armv7 机器实际使用上游的 `hysteria-linux-arm` 资产 —— 上游没有 `armv7` 命名的资产。）
- 🛡️ **自签 / 自定义 / 域名证书**：支持一键生成 ECC (prime256v1) 自签证书、指定已有 acme.sh / certbot 证书，或绑定域名并自动申请 Let's Encrypt 证书。
- 🔀 **端口跳跃 (Port Hopping) 默认启用**：内置自动化 `iptables` 多端口转发规则（默认 UDP 20000-40000），有效突破单一 UDP 端口被运营商 QoS 限速或丢包。
- 🎭 **Salamander 混淆 默认启用**：全自动生成高熵随机密码，将 QUIC 数据报文伪装为完全随机的杂波，彻底免疫 GFW 主动探测与深度包检测。
- 🛡️ **AmneziaWG 抗 DPI 协议 (可选安装)**：一键部署 WireGuard 的抗审查分支，密码学内核完全不变，只把数据包的头部、长度与时序特征随机化。采用**用户态 `amneziawg-go`** 部署 —— 不编译内核模块、不引入 Docker、不在服务器上装 Go 工具链：二进制由本仓库的 GitHub Actions 交叉编译成**全静态**产物（amd64 / arm64 / armv7）后发布到 Release 下载。支持 **AWG 2.x / 3.x 双协议线可切换**、多客户端管理、`.conf` 下载与二维码导入，并在 Web 控制台提供独立的客户端管理与状态面板。
- 🌐 **Cloudflare WARP 智能分流 (AI 加速)**：内置 `wgcf` + `wireproxy` 自建本地出口（socks5 `127.0.0.1:19898`，免 apt、无需官方 MASQUE 客户端，绕开 Debian 12 上 `cloudflare-warp` 因 apt keyring bug 装不上的问题），配合 3 分钟探活自愈 Watchdog，并在 Web 控制台独立扩展页面提供一键按需启闭开关，实现 OpenAI、Claude、Gemini 干净住宅出口与 VPS 原生极速直连。
- 🧭 **VLESS-Reality 备用通道 (可选)**：在 Web 控制台一键启用 Xray Reality（TCP）。订阅里同时下发 Hy2 与 Reality 两个节点，Clash 用 url-test 自动择优 —— UDP 被 QoS 或阻断时自动切到 TCP 通道；每个 Hy2 用户对应一个 Reality 身份，停用 / 删除用户时两边同步生效。
- 🧩 **VMess-WS-TLS 兼容通道 (可选)**：与 Reality 共用 Xray 核心，可在 Web 控制台独立启停，互不影响。使用独立 TCP 端口、随机且稳定的 WebSocket 路径，**需要已绑定域名并持有客户端可校验的证书**（自签证书会被拒绝启用）。每个 Hy2 用户对应一个 VMess 身份，订阅同时下发 `vmess://`、Clash 与 sing-box 配置，停用 / 到期 / 超额与 Reality 一并收回。⚠️ 上游 Xray 已把 VMess 标记为**非移除性弃用**（缺少前向保密），目前仍可正常使用，但新部署建议优先选下面的 VLESS Encryption。
- 🔐 **VLESS Encryption 通道 (可选)**：VMess 的官方替代路线，Xray v25.9.5+ 提供。使用 ML-KEM-768 后量子密钥交换与 1-RTT 前向保密，与 Reality / VMess 共用 Xray 核心、各自独立启停。同样需要已绑定域名与客户端可校验的证书；密钥对由 `xray vlessenc` 生成，只在首次启用时创建，**重置会让已下发的链接全部失效**。每个 Hy2 用户对应一个 VLESS 身份，订阅同时下发 `vless://`（含 `encryption` 参数）、Clash 与 sing-box 配置。⚠️ 需要较新的客户端支持，老客户端可能不识别该加密参数。
- 🔄 **Web 端双重版本检测与一键升级**：在 Web 仪表盘在线比对 Hysteria 2 官方内核与控制面板自身版本，发现新版一键升级。面板更新检测覆盖 `portal.py`、`portal_assets.py` 和四个计量模块，任一差异或缺失都会提示更新，检测不完整时显示无法确认。在线安装、终端门户升级、面板自更新与 `awgctl.sh` 获取均先把 `main` 锁定到具体 commit 再下载（完整本地文件快路径除外）；若 GitHub API 无法解析 commit 则中止，不回退到浮动 `main`，以免跨版本混装。锁定后仍支持 API / jsDelivr / raw 三源回退，每个文件除内容特征与 Python 语法校验外，还必须与**该 commit 的 git blob 身份**（`sha1("blob <len>\0"+content)`，注意不等于文件 sha1）一致，任一不过就整体放弃；换上新版后若 20 秒内健康检查（`/api/health`）不通过，自动换回旧版本。

> **下载完整性保证与边界（2026-10-27）**：Hysteria 核心、gost、Xray、wgcf、wireproxy 的安装/升级都会先解析确定版本与架构，从**官方**发布取校验清单（`hashes.txt` / `checksums.txt` / Xray 的 `.dgst`，后者只认 SHA2-256），按精确资产名解析**唯一** SHA256，下载到私有临时目录校验通过才解包/替换/执行。清单取不到、为空、资产缺失、同一资产匹配到多条、摘要畸形或内容不匹配，一律 fail-closed，错误不会覆盖现有产物。第三方镜像（`ghfast.top` / `github.moeyy.xyz`）只在**已从官方取得预期摘要之后**才作为传输候选，内容必须与官方摘要逐字节一致，它们本身不能提供可信摘要。AWG 的 `SHA256SUMS` 缺失已改为硬失败，且**没有任何跳过开关**（既无 CLI 选项也不读环境变量）。tar/zip 解包会拒绝绝对路径与 `..` 成员，并且只接受唯一精确同名的成员（不再"取包内第一个可执行文件"）。
>
> **这些校验挡不住什么**：所有摘要都与产物来自**同一上游发布**（同源），不构成独立签名 —— 若上游账号或 Release 资产本身被替换，摘要会一起被替换。真正的供应链保证需要上游签名（cosign / minisign）或把摘要固定在仓库 commit 里。
>
> **acme.sh（DNS API 兜底签发）的获取与版本策略（2026-10-27）**：不再执行 `get.acme.sh` 的管道安装脚本。流程改为：GitHub 官方 API 把 `acmesh-official/acme.sh` 的 `master` 解析成 **40 位 commit** → 取该 commit 的官方递归 tree → 只下载**本次会执行的 4 个文件**（`acme.sh`、`dnsapi/dns_cf.sh`、`dnsapi/dns_ali.sh`、`dnsapi/dns_dp.sh`）到私有临时目录，逐个比对 `sha1("blob <len>\0"+content)` 是否等于官方 tree 里的 blob（路径必须唯一、必须是普通文件，链接/子模块一律拒绝）→ 全部通过后才执行安装器 → 安装后再核一次（除上游会改写的 shebang 外逐字节一致）。任一环节失败（API 限流、tree 截断、路径异常、内容不符、安装失败）都硬退出并给出可读原因，且不覆盖现有安装、不删除原有证书/账号数据。安装后会把 `account.conf` 的 `AUTO_UPGRADE` 设为 `'0'`：acme.sh 的 `--cron` 在 `AUTO_UPGRADE=1` 时会先在线升级再续期，等于后台定期执行未校验的新代码；**cron 续期本身保留**，证书正常自动续期。已存在的 acme.sh 一律**不重装、不覆盖、不删除**：先用官方固定 commit 的 tree 逐文件核验 `acme.sh` 与三个 DNS 插件（只允许上游安装器改写的 shebang 差异，且 shebang 必须是安全形态：**绝对路径且位于标准系统目录**（`/bin`、`/usr/bin`、`/usr/local/bin`、`/sbin`、`/usr/sbin`、`/usr/local/sbin`）下的 `sh`/`bash`，或 `/usr/bin/env sh|bash`；`#!/tmp/x/bash` 这类同 basename 的任意路径一律不信任），**核验通过**才继续使用并关闭其自动升级；**核验不通过（内容不符、缺插件、API 限流/元数据取不到）则硬失败**——不执行该脚本、不调用它签发、不写它的 `account.conf`、不关闭它的自动升级，现有证书/账号/脚本原样保留。修复办法是**保留数据**：整体备份 `~/.acme.sh` 后把不一致的 `acme.sh` 与 `dnsapi/` 插件**移出**（`mv`，不是删），再重跑本脚本重新校验安装；证书目录与 `account.conf` 保持不动。**不要直接删掉整个 `~/.acme.sh`**（会连同证书与账号一起丢失）。版本策略是"跟随上游 master 的固定 commit"（每次安装时重新 pin，不在本仓库写死某个 commit）。**关闭自动升级后如何更新 acme.sh**：先把 `~/.acme.sh` 整体备份，再删除其中的 `acme.sh`（保留证书与账号目录），重新运行本脚本 —— 会重新 pin 到最新 commit 并逐文件校验后安装；本项目**不提供**任何"跳过校验的更新命令"。
>
> **acme.sh 方案的边界**：上游没有独立签名（无 cosign/minisign/发布附件摘要），预期身份来自 GitHub 官方 API 返回的 tree，因此信任根是 **GitHub 账号与传输 TLS** —— 若上游仓库/账号本身被攻破，本方案挡不住；它挡住的是"镜像/中间人/浮动分支在下载时被替换"这一类。GitHub Actions 的 `actions/*` 仍使用浮动 major tag。
- 🕳️ **独立「入站代理 & WARP」扩展专区 (SOCKS5 / HTTP / HTTPS)**：集成 GOST 引擎，支持 Web 端一键安装/修复核心；解耦独立页面一键添加/删除三种入站代理服务（独立账号密码认证），客户端无需安装 Hysteria 也能直接把服务器当普通代理用，配置动态生成并平滑热重载。
- 📱 **多客户端格式全覆盖**：
  - 标准 **`hysteria2://`** 节点直链（支持 v2rayN、Nekobox、Shadowrocket、Sing-box 等一键导入）
  - **Clash.Meta / Mihomo** (Clash Verge Rev) 节点配置片段
  - **Sing-box** (SFA / SFI) Outbound 节点配置片段
  - 安装完成显示私密 HTTPS 信息页地址和随机登录凭据；二维码、订阅和配置统一在登录后的网页查看。
- 🏢 **多租户集群 Agent 节点模式（Teyir 控制台 / 发卡商城对接）**：
  - 可作为集群节点接入 [Teyir 控制台](#-接入-teyir-控制台)或发卡商城（如 `pay.isoziyuan.com`）。
  - 内置 REST API（`Authorization: Bearer <API Key>`）与 Hysteria 2 本地 HTTP 动态鉴权，接口清单见[下文](#-接入-teyir-控制台)。
  - 用户开通、续费、停用与注销实时生效，**零中断、无需重启 Hysteria 2 服务**；注销 / 停用时会主动断开该用户已有的连接，并同步收回 Reality 身份。
- 📊 **按真实流量计量**：用量取自 Hysteria `trafficStats` 与 Xray stats 的单调计数器（不是客户端声明的带宽），服务重启、计数器回退都会单独处理，不会重复计数或漏记；用户到期 / 超额后自动停用。同时在线 IP 限制会把「仍然连着的设备」算在内，不会因为连接持续超过 3 分钟就被绕过（需要核心提供在线 IP 数据，取不到时按鉴权时间判断）。
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

> 上面两条命令走的是 `raw.githubusercontent.com`，它有 CDN 缓存，**刚推送更新后的几分钟内可能仍取到上一版**。
> 如果确认刚更新过却看不到新行为，等几分钟再执行一次即可。脚本内部拉取 `awgctl.sh` 时已改用
> **GitHub API → jsDelivr → raw** 三级回退来规避这个问题（raw 实测不把查询串算进缓存键，加时间戳参数无效）。

### 免交互部署（云 init / CI / 批量装机）

核心安装支持环境变量，配 `install` 子命令即可无人值守：

```bash
HY2_CERT_TYPE=3 HY2_DOMAIN=hy2.example.com HY2_EMAIL=me@example.com bash install.sh install
```

| 环境变量 | 取值说明 |
| :--- | :--- |
| `HY2_PORT` | 监听 UDP 端口，须为 1-65535 的整数。留空则自动选取 |
| `HY2_PASSWORD` | 机主账号的连接密码（门户鉴权按用户匹配）。留空则自动生成 |
| `HY2_NODE_MODE` | 仅支持 `2`（商城版 Agent，默认）。留空即商城版；传 `1` 会直接报错退出 |
| `HY2_CERT_TYPE` | `1` 自签名 / `2` 指定已有证书文件 / `3` 域名自动申请 Let's Encrypt / `4` 自动扫描本机已装证书 |
| `HY2_DOMAIN` | 绑定域名（SNI）。**`HY2_CERT_TYPE=3` 时必填** |
| `HY2_EMAIL` | Let's Encrypt 通知邮箱 |
| `HY2_PRESERVE_PORTAL` | 本机已装过时是否沿用现有门户：`1`（默认）保留门户登录凭据、API Key、订阅地址与全部用户；`0` 推倒重建 |

> ⚠️ `HY2_CERT_TYPE=2` **不适合纯无人值守**：它需要你再回答证书与私钥的文件路径。
> 要做完全免交互请选 `1`、`3`（配 `HY2_DOMAIN`）或 `4`。
>
> 这些变量在**动工之前**就会校验，非法值会立即报错退出，不会装到一半才失败。

---

## 📋 控制台交互菜单

安装后，随时在终端直接执行脚本即可呼出管理菜单：

```
================================================================
       Hysteria 2 全功能生产级管理脚本 (x86_64)         
       GitHub: https://github.com/yys9253462-gif/hysteria2-installer    
================================================================
核心状态: 运行中 | 版本: v2.13.0
门户状态: 运行中 | 运行模式: 商城版（Agent 模式）
扩展服务: Xray(Reality/VMess/VLESS-Enc): 运行中  GOST: 运行中  WARP: 运行中
AWG 状态 : 运行中 | 协议线: AWG 3.x | UDP 53821
----------------------------------------------------------------
  1. 重新安装 Hysteria 2 (会覆盖现有配置)
  2. 更新 Hysteria 2 核心至最新版
  3. 查看私密信息页地址和登录凭据
  4. 重新修改配置 (端口/密码/证书/域名/混淆/API Key)
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
----------------------------------------------------------------
  14. 刷新信息页与订阅 (不改任何配置)
  15. 重启门户 (信息页 / 鉴权后端 / 控制台 API)
  16. 显示接入 Teyir 控制台的信息
  0. 退出脚本
================================================================
```

> - `扩展服务` 只列本机装过的服务，`AWG 状态` 只在装过 AmneziaWG 时显示；节点被 Teyir 因流量超额停用时会多一行醒目提示，此时 9 / 11 不会手动拉起服务。
> - 已安装时，第 1 项（重新安装）和第 4 项（重新修改配置）默认**沿用现有门户**：门户登录凭据、API Key、订阅地址、全部用户与代理服务保持不变，已接入 Teyir 控制台的节点不受影响；节点通信 API Key 也默认保持当前设置。
> - 本项目只提供**商城版（Agent 模式）**节点，安装时不再询问单机 / 商城模式。从旧单机版升级的机器请用第 1 项重装一次，认证方式会自动切换为门户鉴权。
> - 任何一项操作失败都只会提示并回到菜单，不会把整个脚本退出；查看日志时按 Ctrl+C 只退出日志。

---

## 🔗 接入 Teyir 控制台

Teyir 控制台可以集中管理多台节点：开户、续费、停用、流量统计、整机流量限额、代理服务与测速。本项目安装出的节点固定以 **Agent 模式（商城版）**运行，无需再选择运行模式。

### 接入需要的四项信息

| 字段 | 用途 |
| :--- | :--- |
| 门户地址 `url` | `https://<域名或 IP>:<订阅端口>/<随机路径>/`，控制台从这里访问节点 |
| 门户用户名 / 密码 | HTTP Basic，网页通道（版本检查、用户配置、面板更新等） |
| API Key | `Authorization: Bearer <API Key>`，REST API 通道 |

三种取法，内容完全一致：

- 终端菜单 **第 16 项「显示接入 Teyir 控制台的信息」**；
- 网页登录后的「接入 TEYIR 控制台」卡片，可一键复制整份 JSON；
- 仓库里的 `panel-join.py`：在节点上运行，自动从 `config.yaml` / `portal.json` 拼出对外可达的地址，也可以直接登记到控制台：

  ```bash
  curl -fsSLO https://raw.githubusercontent.com/yys9253462-gif/hysteria2-installer/main/panel-join.py
  python3 panel-join.py                    # 只打印
  PANEL_ADMIN_TOKEN=<JWT> python3 panel-join.py --register --panel https://你的控制台地址
  ```

  管理员令牌建议用环境变量 `PANEL_ADMIN_TOKEN` 传，命令行参数 `--admin-token` 会出现在 `ps` 和 shell 历史里。

> 已接入控制台的节点，用菜单第 1 项（重新安装）或第 4 项（重新修改配置）时，「是否沿用现有门户」请保持默认的 **Y**：门户地址、凭据、API Key 与控制台开的全部用户都不会变，控制台无需任何改动。

### REST API

所有接口都要带 `Authorization: Bearer <API Key>`，请求体为 JSON，每秒最多 50 次请求。

| 方法 | 路径 | 说明 |
| :--- | :--- | :--- |
| POST | `/api/v1/users/create` | 开户；已存在的同名用户按传入字段更新。`password` 不能与其他用户重复（返回 409），不传则自动生成 |
| POST | `/api/v1/users/update` | 修改密码 / 到期时间 / IP 限制 / 状态 |
| POST | `/api/v1/users/renew` | 续期、加流量 |
| POST | `/api/v1/users/set_status` | 启用 / 停用（停用会断开现有连接） |
| POST | `/api/v1/users/delete` | 注销（断开现有连接并收回 Reality 身份） |
| GET / POST | `/api/v1/users/list` | 全部用户及用量、在线 IP |
| GET | `/api/v1/users/get/<user_id>` | 单个用户 |
| GET / POST | `/api/v1/proxy-services/list` | GOST 入站代理列表 |
| POST | `/api/v1/proxy-services/add` / `delete` | 增删 GOST 代理（自动在 ufw / firewalld 上放行或收回端口） |
| GET | `/api/v1/node/meta` | 节点参数（不含认证密码与混淆密码） |
| GET | `/api/v1/node/traffic` | 默认路由网卡的累计收发字节、boot_id、是否处于超额停用 |
| POST | `/api/v1/node/suspend` | `{"suspended": true/false}`：整机流量超额停用 / 恢复 |
| GET | `/api/v1/capabilities` | 节点支持的能力 |
| GET | `/api/v1/speedtest` | 到三网与公共 DNS 的延迟（靶点写死在代码里） |
| GET | `/api/health` | 存活探针，无需鉴权，只返回 `{"ok": true}` |

撤销类操作（注销、停用、到期）要确认旧连接真的断开、Reality 白名单真的生效才返回成功；做不到时返回 503，并在后台继续重试，调用方重试即可。

### 整机流量超额停用

控制台按「默认路由所在网卡」的流量统计整机用量（VPS 商家也是这么计费的）。超额时调用 `node/suspend` 停掉对外服务（Hysteria 2、Xray、GOST、AmneziaWG），门户自身保持运行，以便新周期远程恢复：

- 停用状态写在 `portal.json`，**重启机器后会自动再停一次**；
- 停用期间，改 Hy2 配置、增删代理、改 Reality 配置都只写配置文件、不会把服务拉起来；终端菜单的「启动 / 重启服务」也会拒绝执行并说明原因；
- 恢复时只启动停用前本来开着的服务；某个服务没能启动，会留在停用记录里，控制台下一轮重试会继续启动它。

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

> **Linux 客户端注意**：导出的配置带 `DNS = 1.1.1.1`，而 `awg-quick` 会调用 `resolvconf` 来应用它。
> 最小化的 Debian / Ubuntu 云镜像通常**没有安装 `resolvconf`**，此时 `awg-quick up` 会报
> `resolvconf: command not found` 并回滚掉刚建立的接口（真实 Debian 12 上实测过）。
> 两种处理方式：`apt install resolvconf`，或直接删掉配置里的 `DNS` 行改用系统 DNS。
> 手机端（AmneziaWG 官方客户端 / WG Tunnel）与桌面客户端不受影响。

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
- **连接元数据**：`/etc/hysteria/client_meta.json`（域名、端口、认证 / 混淆密码、证书信任方式）
- **Systemd 服务单元**：`/etc/systemd/system/hysteria-server.service`、`hysteria-portal.service`

门户（私密信息页 / 订阅 / 鉴权后端 / 控制台 API）相关：

- **门户程序**：`/etc/hysteria/portal.py`、`portal_assets.py` 与 4 个 `usage-meter-*.py` 计量模块（安装时下载，面板可一键自更新）
- **门户数据**：`/etc/hysteria/portal.json`（用户、代理服务、Reality 配置、计量数据、超额停用状态等，权限 0600）
- **门户凭据**：`/etc/hysteria/portal-access.json`（门户地址、登录用户名密码、API Key，即接入 Teyir 要的四项）
- **计量配置**：`/etc/hysteria/usage-meter-config.json`（Hysteria `trafficStats` 与 Xray stats 的地址和密钥）
- **Reality**：`/etc/hysteria/xray.json`，二进制 `/usr/local/bin/xray`，服务 `xray.service`（在网页里启用后才有）
- **GOST 代理**：`/etc/hysteria/gost.yml`（含代理账号密码，权限 0600），二进制 `/usr/local/bin/gost`
- **WARP 出口**：`/etc/wireguard/wgcf.conf`、`wgcf-account.toml`、`wp.conf`，服务 `wireproxy.service`
- **改配置前的快照**：`*.bak-<时间戳>`（菜单第 1 / 4 项改动前自动备份 meta、门户数据与 config.yaml）

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
- 在云厂商安全组中放行 **TCP 80**，以及安装结束时显示的**订阅 TCP 端口**（私密信息页、订阅和控制台 API 都走它；从 10000-60000 中随机挑一个空闲端口，刻意避开 8443 和端口跳跃区间）。
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

# 商城版（Agent 模式）：每个连接都交给本机门户鉴权
# 门户按用户、到期时间、流量额度与在线 IP 限制逐连接判定
auth:
  type: http
  http:
    url: http://127.0.0.1:<门户本地端口>/auth

# 订阅端口上的 HTTPS 转发到只监听 127.0.0.1 的门户（私密信息页 / 订阅 / 控制台 API）
masquerade:
  type: proxy
  proxy:
    url: http://127.0.0.1:<门户本地端口>/
    rewriteHost: false
    # 给公网请求打上 X-Forwarded-For，门户据此拒绝公网直打 /auth（v2.8.0+ 支持）
    xForwarded: true
  listenHTTPS: :<订阅端口>

# 真实流量计量的只读统计端点，只监听回环地址
trafficStats:
  listen: 127.0.0.1:19996
  secret: your_random_stats_secret

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

### 运行要求

需要 Python 3.9+、qrencode 和 systemd 247+。门户程序由安装脚本下载，不依赖外部二维码网站或第三方 JS，二维码只在服务器本地生成。

Hysteria 在订阅端口上提供 HTTPS，把请求转发给只监听 127.0.0.1 的门户服务（`hysteria-portal`，以 root 运行，因为它要管理 Hysteria、Xray、GOST、AmneziaWG 等系统服务）。门户共用 Hysteria 当前的证书与续期机制，不占用已有网站的 80/443；用 ACME HTTP-01 申请证书时仍需要 TCP 80 可用。自签证书会触发浏览器告警，推荐使用受信任的域名证书。

> Agent 模式下门户同时是 Hysteria 的鉴权后端：门户停了，所有用户都连不上。终端菜单的状态栏会显示门户状态，第 15 项可单独重启门户。

### 访问控制

- 页面路径是 256-bit 随机值，登录密码同样有 256-bit 熵；随机路径不代表端口扫不到，认证才是访问控制。请保密 URL 与账号密码，订阅 URL 内含凭据。
- 管理页面、订阅与下载都要求登录（HTTP Basic 或登录后的会话 cookie）。会话 cookie 带签发时间，服务端 30 天后拒绝；cookie 设置了 `HttpOnly`、`SameSite=Strict`、`Secure`。
- **用户专属分享链接**（`<门户地址>u/<用户>?k=...`）是唯一免登录的入口，只能看到该用户自己的配置。同名用户删掉重建后，旧链接自动失效。
- REST API 只认 `Authorization: Bearer <API Key>`，权限低于网页登录。

### 防护与限流

- 响应带 `no-store`、CSP、禁止嵌入、禁止索引、禁止 referrer 等标头；后端不记录访问路径或密码，凭据比较都是恒定时间。
- 网页：每秒最多 50 个请求，60 秒内失败 60 次后临时限流；API：每秒最多 50 个请求。
- Hysteria 鉴权（`/auth`）：每秒最多 20 次，60 秒内失败 30 次后临时限流。经伪装代理从公网打进来的 `/auth` 请求（带 `X-Forwarded-For`）直接拒绝且不计入失败次数，外人刷不满限流、也就没法让全节点无法登录。老节点要在下次「更新 Hysteria 2 核心」时才会自动补上 `xForwarded` 配置。
- 高频攻击仍可能让网页暂时不可用，可在云安全组把订阅端口限制为自己（和控制台）的 IP。

### 改配置与卸载

- 菜单第 1 / 4 项在已装机上默认**沿用现有门户**：网页路径、登录凭据、API Key、订阅地址与全部用户都不变，客户端订阅和控制台都不用改。选 `N` 才会重建门户（路径与凭据换新，旧链接失效）。
- 菜单第 3 项只显示已有凭据，第 14 项按当前参数刷新信息页与订阅，不改任何配置。
- 卸载时停止并删除 `hysteria-portal`、`xray`、`gost`、`wireproxy` 等服务及 `/etc/hysteria`；`/etc/wireguard` 里只删除 wgcf 自己的文件，系统里其它 WireGuard 配置不受影响。

### 开发

开发检查：`bash -n install.sh` 和 `python3 -m unittest discover -s tests -v`。
`portal.py` 现在由 `install.sh` **在运行时获取**（三级回退：GitHub API → jsDelivr → raw，
拿到后做 Python 语法校验），所以**不需要**再手动同步任何内嵌副本 —— 改完 `portal.py`
直接提交即可，机器上重新执行一次安装/更新就会拿到新版。若要本地调试，把 `portal.py`
放在 `install.sh` 同目录即可优先使用本地文件。

---

## 🧰 仓库里的辅助脚本

这些脚本**不会**被一键安装自动执行，按需单独下载运行：

| 脚本 | 用途 |
| :--- | :--- |
| `panel-join.py` | 在节点上打印（或直接登记）接入 Teyir 控制台所需的地址与 API Key，见[接入 Teyir 控制台](#-接入-teyir-控制台) |
| `fix_cert_chain.sh` | 修复「证书链不完整」：`tls.cert` 指向只有叶证书的文件时，客户端报 `x509: certificate signed by unknown authority`，脚本把它换成 fullchain |
| `alpine2debian.sh` | 机器落在 Alpine 救援 / 内存模式时，用 Debian 官方 debootstrap 在本地把系统刷成 Debian 12，不下载第三方安装脚本 |
| `reinstall-debian13.sh` | 从 Alpine 救援环境重装 Debian 13（借道 InstallNET，负责联网、DNS、GRUB 修复等前后保障）；下载走 HTTPS 证书校验，未指定 root 密码时随机生成并显示 |

> ⚠️ 两个重装脚本都会**清空整块系统盘**，只在你确定要重装时使用。
>
> 本安装脚本依赖 systemd，不支持以 OpenRC 运行的 Alpine；Alpine 机器请先用上面两个脚本之一换成 Debian 再安装。

---

## 📄 开源许可证

本项目基于 [MIT License](LICENSE) 开源。
