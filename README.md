# Hysteria 2 一键部署与管理脚本

[![GitHub License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Debian%20%7C%20Ubuntu%20%7C%20CentOS-success.svg)](#)
[![Hysteria Version](https://img.shields.io/badge/Hysteria-v2.x-orange.svg)](https://v2.hysteria.network/)

**Hysteria 2** 官方服务端一键部署脚本，自带 Web 控制台、多用户管理与集群接入，针对高丢包与 UDP QoS 环境做了优化。

## ✨ 功能

- **Hysteria 2 主协议**：官方二进制（amd64 / arm64 / armv7），默认开启端口跳跃（UDP 20000-40000）与 Salamander 混淆；证书支持自签、已有证书或域名自动申请 Let's Encrypt。
- **备用通道（可选，网页一键启停）**：
  - **VLESS-Reality**（TCP）：借用大厂证书握手，无需域名；
  - **VMess-WS-TLS**、**VLESS Encryption**（后量子密钥交换）、**AnyTLS**：需要域名与可信证书。
  - 订阅里与 Hy2 一起下发，Clash / sing-box 用 url-test 自动择优，UDP 被限时自动走 TCP。
- **核心管理页**：集中查看 Hysteria 2 / Xray / sing-box / GOST / WARP / AmneziaWG 的安装状态、版本与服务状态，Xray 与 sing-box 可在此安装 / 卸载。
- **扩展服务**：GOST 入站代理（SOCKS5 / HTTP / HTTPS）、Cloudflare WARP 分流（AI 站点走干净出口）、AmneziaWG 抗 DPI VPN。
- **多用户**：每个用户独立的到期时间、流量额度、同时在线 IP 限制，按真实流量计量；停用 / 到期 / 超额 / 删除即时在所有协议上收回并断开现有连接。
- **集群节点**：内置 REST API，可接入 Teyir 控制台或发卡商城，支持整机流量超额停用 / 恢复。
- **安全下载**：所有核心都从官方发布下载并校验 SHA256；面板与脚本更新先锁定到具体 commit 并逐文件核对，失败不会覆盖现有版本，更新后健康检查不过会自动回滚。

## 🚀 安装

以 `root` 运行：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/yys9253462-gif/hysteria2-installer/main/install.sh)
```

> `raw.githubusercontent.com` 有几分钟 CDN 缓存，刚更新过的话稍等再执行。

### 免交互安装

```bash
HY2_CERT_TYPE=3 HY2_DOMAIN=hy2.example.com HY2_EMAIL=me@example.com bash install.sh install
```

| 环境变量 | 说明 |
| :--- | :--- |
| `HY2_PORT` | UDP 监听端口，留空自动选取 |
| `HY2_PASSWORD` | 机主账号密码，留空自动生成 |
| `HY2_CERT_TYPE` | `1` 自签 / `2` 指定证书文件（需交互）/ `3` 域名申请 Let's Encrypt / `4` 扫描本机已有证书 |
| `HY2_DOMAIN` | 域名（SNI），`HY2_CERT_TYPE=3` 时必填 |
| `HY2_EMAIL` | Let's Encrypt 通知邮箱 |
| `HY2_PRESERVE_PORTAL` | 已装过时是否沿用门户（凭据、API Key、用户）：`1` 默认保留，`0` 重建 |

### 用域名申请证书

证书方式选 `3` 前，先把域名 A 记录指向本机，并在云安全组放行 **TCP 80** 和安装结束时显示的**订阅端口**。脚本会先校验 DNS 解析，不指向本机时默认中止。

## 📋 管理

再次执行脚本即可打开管理菜单：

```
  1. 重新安装 Hysteria 2          9. 启动服务
  2. 更新 Hysteria 2 核心         10. 停止服务
  3. 查看信息页地址和登录凭据      11. 重启服务
  4. 重新修改配置                 12. 查看实时日志
  5. 安装 WARP 出口               13. 彻底卸载
  6. 安装 GOST 入站代理            14. 刷新信息页与订阅
  7. 安装 AmneziaWG               15. 重启门户
  8. AmneziaWG 管理               16. 显示接入 Teyir 控制台的信息
  0. 退出
```

已安装时第 1 / 4 项默认**沿用现有门户**，用户与控制台接入不受影响。

常用命令：

| 命令 | 功能 |
| :--- | :--- |
| `bash install.sh info` | 显示信息页地址与登录凭据 |
| `bash install.sh refresh-page` | 刷新信息页与订阅，不改配置 |
| `bash install.sh status` / `restart` | 查看状态 / 重启 Hysteria 2 |
| `bash install.sh update` | 更新 Hysteria 2 核心 |
| `bash install.sh uninstall` | 彻底卸载 |
| `bash install.sh awg-install --line 3 --endpoint vpn.example.com --client phone` | 免交互安装 AmneziaWG |
| `bash install.sh awg-menu` / `awg-status` / `awg-update` / `awg-uninstall` | AmneziaWG 管理 |

AmneziaWG 的底层工具是 `hy2-awgctl`（`peer-add`、`peer-del`、`qr`、`client-conf`、`update --line 2` 等）。注意：AWG 端口不能落在 20000-40000（会被端口跳跃规则劫持），默认从 50000-59000 选取；切换 2.x / 3.x 协议线会让已发放的客户端配置全部失效。

## 📲 客户端

安装结束会显示私密信息页地址和登录凭据，登录后可以：

- 扫码或复制 `hysteria2://` 链接（v2rayN、NekoBox、Shadowrocket 等）；
- 复制 Clash.Meta / Mihomo 订阅地址，或下载 sing-box 配置；
- 在「多用户管理」里给每个用户生成专属分享链接（免登录，只能看自己的配置）。

## 🔗 接入 Teyir 控制台

接入需要门户地址、门户用户名 / 密码、API Key，可从以下任一处获取：菜单「显示接入 Teyir 控制台的信息」、网页里的接入卡片，或节点上运行 `panel-join.py`：

```bash
curl -fsSLO https://raw.githubusercontent.com/yys9253462-gif/hysteria2-installer/main/panel-join.py
python3 panel-join.py                    # 只打印
PANEL_ADMIN_TOKEN=<JWT> python3 panel-join.py --register --panel https://你的控制台地址
```

### REST API

请求头 `Authorization: Bearer <API Key>`，请求体 JSON，每秒最多 50 次。

| 方法 | 路径 | 说明 |
| :--- | :--- | :--- |
| POST | `/api/v1/users/create` | 开户（同名则更新） |
| POST | `/api/v1/users/update` | 改密码 / 到期 / IP 限制 / 状态 |
| POST | `/api/v1/users/renew` | 续期、加流量 |
| POST | `/api/v1/users/set_status` | 启用 / 停用 |
| POST | `/api/v1/users/delete` | 注销 |
| GET / POST | `/api/v1/users/list` | 全部用户及用量 |
| GET | `/api/v1/users/get/<user_id>` | 单个用户 |
| GET / POST | `/api/v1/proxy-services/list`、`add`、`delete` | GOST 入站代理 |
| GET | `/api/v1/node/meta`、`node/traffic` | 节点参数、网卡累计流量 |
| POST | `/api/v1/node/suspend` | 整机超额停用 / 恢复 |
| GET | `/api/v1/capabilities`、`speedtest` | 节点能力、三网延迟 |
| GET | `/api/v1/unlock-check` | 节点本机检测流媒体 / AI 服务解锁情况 |
| GET | `/api/health` | 存活探针（无需鉴权） |

> 各协议的启停（Reality / VMess / VLESS Encryption / AnyTLS）与核心安装都在**网页控制台**里，
> 走 Basic / 会话鉴权，不在上表的 Bearer 通道内。`capabilities` 会返回各协议是否安装、是否启用。

撤销类操作要确认旧连接已断开才返回成功，做不到时返回 503 并在后台重试。

## ⚙️ 文件位置

| 路径 | 内容 |
| :--- | :--- |
| `/etc/hysteria/config.yaml` | Hysteria 2 服务端配置 |
| `/etc/hysteria/client_meta.json` | 域名、端口、密码、证书信任方式 |
| `/etc/hysteria/portal*.py`、`usage-meter-*.py` | 门户程序（6 个文件，面板可自更新） |
| `/etc/hysteria/portal.json` | 用户、协议配置、计量数据（0600） |
| `/etc/hysteria/portal-access.json` | 门户地址、登录凭据、API Key |
| `/etc/hysteria/xray.json` | Reality / VMess / VLESS Encryption |
| `/etc/hysteria/anytls.json` | AnyTLS（sing-box） |
| `/etc/hysteria/gost.yml` | GOST 代理 |
| `/etc/wireguard/` | WARP（wgcf / wireproxy） |
| `/etc/amnezia/amneziawg/` | AmneziaWG |

## 🔒 安全说明

- 门户只监听 `127.0.0.1`，由 Hysteria 在订阅端口上做 HTTPS 转发；门户同时是 Hysteria 的鉴权后端，门户停了用户就连不上。
- 页面路径与登录密码都是 256-bit 随机值；会话 cookie 为 `HttpOnly`、`SameSite=Strict`、`Secure`。
- 网页、API、`/auth`、登录各自限流；代理用户无法访问节点本机、内网与云元数据地址。
- 下载校验的摘要与产物来自同一上游发布，挡得住镜像和中间人篡改，挡不住上游账号本身被攻破。
- GitHub 匿名 API 每 IP 每小时 60 次；同一台机器上其它程序也在调用时，面板的版本检测与更新会失败。可把一个**无任何权限的** GitHub token 写入 `/etc/hysteria/github-token`（权限 0600），面板与安装脚本只在访问 `api.github.com` 时带上它，额度提高到每小时 5000 次。

## 🧰 辅助脚本

| 脚本 | 用途 |
| :--- | :--- |
| `panel-join.py` | 打印或登记接入 Teyir 控制台的信息 |
| `fix_cert_chain.sh` | 修复只有叶证书导致的 `x509: certificate signed by unknown authority` |
| `alpine2debian.sh` | 把 Alpine 救援环境刷成 Debian 12 |
| `reinstall-debian13.sh` | 从 Alpine 救援环境重装 Debian 13 |

> ⚠️ 两个重装脚本会清空整块系统盘。本脚本依赖 systemd，不支持 OpenRC 的 Alpine。

## 🛠️ 开发

```bash
bash -n install.sh
python3 -m unittest discover -s tests -p 'test_*.py'
```

改代码前请先读 [AGENTS.md](AGENTS.md)。

## 📄 许可证

[MIT License](LICENSE)
