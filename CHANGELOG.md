# 变更记录

## 未发布

### 新增：AmneziaWG (AWG) 抗 DPI 协议支持
- **一键部署 WireGuard 的抗审查分支**。密钥与加密内核完全沿用 WireGuard（Curve25519 / ChaCha20-Poly1305 / BLAKE2s / Noise_IK），只把数据包的头部、长度与时序特征随机化，使 DPI 无法按固定签名识别。
- **走用户态部署，不碰内核、不引入 Docker、不在服务器上编译**：
  - 上游 `amneziawg-go` 官方**只发布 Docker 镜像**（无独立二进制），`amneziawg-tools` 官方只发布 `ubuntu-22.04` / `alpine-3.19` 两个包（无通用 Linux 包）；
  - 因此新增 `.github/workflows/build-awg.yml`，用 GitHub Actions 交叉编译 **amd64 / arm64 / armv7** 三个架构、并以 **`-static` 全静态链接**（消除 glibc 版本依赖，CI 跑在较新 Ubuntu 上、动态链接产物在 Debian 12 上会因 glibc 版本不足无法运行），产物发布到 Release 标签 `awg-binaries`；
  - `install.sh` 侧只做"下载静态二进制 + systemd"，与本项目既有扩展（WARP / gost）完全同构。
- **新增 `awgctl.sh`（安装为 `/usr/local/bin/hy2-awgctl`）**：把 AWG 的安装、配置生成、客户端管理全部收敛到一个文件，命令行菜单与 Web 门户都只做调用，**杜绝两份配置生成逻辑漂移**（考虑到 `S1`-`S4`/`H1`-`H4` 必须两端逐字节一致，重复实现的风险不可接受）。
- **双协议线可切换**：AWG 3.x（`amneziawg-go` `v3.1.20260828`，含 `HeaderProtectionKey` / 时序随机化 / 随机包尾）与 AWG 2.x（`v0.2.19`）。切换会重新生成混淆参数并明确提示"所有客户端配置将失效"。
- **端口安全**：Hysteria 2 的端口跳跃会装上 `udp --dport 20000:40000 -j REDIRECT`，落在该区间的 AWG 端口**收不到任何握手包**。因此默认从 **50000-59000** 选空闲端口，并在命令行与 Web 两处都硬拦截 20000-40000；同时避开 `51820`（WireGuard 默认端口本身是弱指纹）。
- **参数生成遵循上游全部硬约束**：`Jc` 4~12、`Jmin`/`Jmax` = 8/80、`S1`/`S2`/`S3` 15~150 且 `S1+56 ≠ S2`、`S4` 3.x 时 ≥12（头部保护要求）、`H1`~`H4` 用**四分带取值**天然满足"范围不得重叠"。
- **`MTU` 自动扣减 `S4`**（`1420 - S4`）：`S4` 是每个 Data 包的随机填充，不扣掉外层会分片。
- **Web 控制台接入**："入站代理与 WARP 扩展服务"页面新增 AmneziaWG 卡片 —— 状态徽章、协议线选择、一键安装、客户端增删、`.conf` 下载、二维码、切换协议线、更新二进制。
- **客户端私钥绝不下发前端**：`awg-state` 只回传 `name` / `address` / `created_at`。
- **卸载不牵连**：`uninstall_all()` 对 AmneziaWG 单独询问，避免"卸载 Hysteria 2"顺带删掉用户还想保留的客户端配置。

### 修复（由本次新增的测试发现）
- **门户 `awg-conf` / `awg-qr.svg` 路由完全失效**：门户里 `subpath` 是**含查询串**的（上游就是这样切分的），原先用 `subpath in ('awg-conf', 'awg-qr.svg')` 比对，带 `?name=` 的请求永远匹配不上、会静默落到 404。改为先剥掉 `?query` 再比对。
- **协议线空值误判**：原先写成 `(value or '3').strip()`，纯空格能通过 `or` 判定、再被 `strip()` 成空串，导致误报"协议线非法"。改为先去空白再取默认。
- **`manage-amneziawg` 未知动作报错误导**：原先先检查安装状态再校验动作名，未安装时会返回"尚未安装"而不是"未知操作"，排障容易被带偏。已调整为先校验动作名。

### 测试
- 新增 `.github/workflows/tests.yml`：在 push / PR 时校验三份 shell 脚本语法、**强制校验 `install.sh` 内嵌的 `portal.py` 副本与 `portal.py` 逐字节一致**（这条不变量极易悄悄退化，本次开发中就差一点把门户改动丢掉），并跑完整测试套件。
- 新增 `tests/test_awgctl.sh`（纯逻辑，无需 root，可跨平台运行）：覆盖混淆参数的**全部上游硬约束**、端口跳跃区间避让、**服务端与客户端配置的 11 个参数逐字节一致性**、peer 生命周期与地址回收、meta 读写、随机数边界、命令行参数解析。做了反向验证（故意注入 `H2=H1` 与"客户端 S1 不一致"两个缺陷，确认测试能抓到）。
- 新增 `tests/test_portal_awg.py`：页面渲染（含 **f-string 无残留占位符** 回归检查）、**CSP `sha256` 白名单跟随 `SCRIPT` 变化**、端点鉴权、路径穿越与非法名称拦截、端口区间拦截、**私钥不泄露**、`awg-conf` 路由可达性。
- 迭代轮数可用 `AWG_TEST_ROUNDS` 调整（CI/Linux 默认 1500；Windows 上每次 `awg_rand` 都要起 `od` 子进程，建议调低）。

### WARP 实现统一 (wgcf + wireproxy)
- **统一出口实现为 `wgcf` + `wireproxy`（socks5 `127.0.0.1:19898`）**，彻底废弃官方 `cloudflare-warp` / `warp-cli` / `warp-svc`（`127.0.0.1:40000`）那套 —— 原方案在 Debian 12 / bookworm 上因 apt keyring 解析缺陷永远装不上。此前「命令行主菜单装一套新版、Web 控制台却装另一套旧版」的分裂已全部对齐：
  - `install.sh`：config 模板默认 outbound、主菜单第 5 项 `install_warp_local_proxy()`、`toggle_warp.sh` 的出口探活；
  - `portal.py`（及 `install.sh` 内嵌副本，二者重新保持逐字节一致）：Web 控制台「一键安装 WARP」接口、`warp-status` 状态检测、出口探活、动态 ACL 注入、前端确认文案。
- **修复 32 位 ARM 资产名映射错误**：`wireproxy` 的 armv7 资产实际名为 `wireproxy_linux_arm.tar.gz`，原代码拼成 `armv7` 必然 404，已拆分为独立架构映射（`wgcf` 仍使用 `armv7`）。
- **版本探测不再强依赖 `jq`**：实测部分服务器未安装 `jq`，无 `jq` 时自动回退到 `grep` + `cut` 解析 `tag_name`，避免整段安装中断。
- **自动清理旧出口残留**：部署新版时若检测到 `warp-svc`，在 wireproxy 探活成功之后自动 `disable --now`，杜绝两套 WARP 并存互相打架。
- **WARP 开关不再无谓重启**：`toggle_warp.sh` 仅在 ACL 段实际发生变化时才 `systemctl restart hysteria-server`，避免「点一次开关就掐断全部在线用户」。
- **兼容过渡不误报**：`warp-status` 同时识别 `wireproxy` 与旧的 `warp-cli`，探活按 `19898` → `40000` 顺序回退，尚未升级的存量节点不会被误判为「未安装 WARP」。

### Security & Performance
- 引入 `ThreadingHTTPServer` 多线程并发模型与全局数据锁，彻底解决单线程 HTTP 服务下并发阻塞与数据竞争问题。
- 本地 `/auth` 动态鉴权通道豁免外部限流，同时将 REST API 与 Web 访问的限流桶解耦，杜绝误伤高频合法握手。
- 对所有用户标识 `user_id`（创建/续费/删除/用户专属直连）施加严格字符白名单正则校验（`^[a-zA-Z0-9_\-\.]{1,64}$`），防范路径遍历与标头注入风险。
- `ip_tracker` 增加过期键自动回收机制，防止长久运行下产生内存膨胀。

### Fixed & Hardened (全面排查与安全加固)
- 彻底修复 GOST 一键安装下载包格式失效问题：
  - 根除旧版硬编码过期的 `v3.0.0-nightly.20240128` 与失效反代源（404 导致报 `gzip: stdin: not in gzip format`）；
  - 全面升级为 Python 原生下载引擎，动态探测并锁定官方稳定正式版（`v3.3.0`），增加文件类型与 `tarfile` 完整性深度校验，多镜像源自动降级重试；
  - 同步更新 `portal.py` 及 `install.sh` 内嵌实现，杜绝代码分裂。
- 根除代码分裂与覆盖倒退 (P0)：将最新 `portal.py`（含独立代理与WARP扩展专区、一键安装GOST、秒级无表单生成、居中弹窗、SVG二维码）完整同步内嵌至 `install.sh`，杜绝终端重配时覆盖降级。
- 证书签发崩溃死循环熔断保护 (P1)：`hysteria-server.service` 增加 `Restart=on-failure`、`RestartSec=10`、`StartLimitIntervalSec=300`、`StartLimitBurst=5`，彻底避免因域名解析延迟打满 Let's Encrypt 配额被惩罚锁死 1 小时。
- 端口跳跃开机自愈守护 (P2)：新增 `hy2-iptables.service` 开机持久化守护服务，解决 Debian 12 / Ubuntu 默认缺少 `netfilter-persistent` 导致系统重启后端口跳跃全失效的隐患。
- 代理生成结果现代轻奢 UI 重构 + 动态 SVG 二维码：彻底消灭排版留白，顶部横幅大字体突出呈现「域名:端口」与彩色协议胶囊；中间对称布局用户名与密码卡片；左侧动态生成矢量 SVG 二维码支持 Shadowrocket/NekoBox 手机端扫码一键导入，右侧提供直链 URL 与通用格式的双模式快捷复制。
- 入站代理秒级一键生成模式：移除繁琐输入表单，支持直接点击「⚡ 一键生成 SOCKS5 / HTTP / HTTPS」，后端自动寻找高位空闲端口（智能避开跳跃段与系统服务）并生成高安全随机凭据。
- 代理生成成功高亮卡片：创建后立即在上方展开专属结果卡片，清晰呈现「代理协议、连接域名、端口号、用户名、密码」，并支持一键复制标准直连 URL（`protocol://user:pass@host:port`）与工具格式（`host:port:user:pass`）。
- 代理列表展示增强：表格中新增完整连接直链预览与「一键复制链接」快捷按钮，无需再手动拼装地址。
- Web 控制台支持一键安装/修复 GOST：新增 `/install-gost` 接口与前端一键安装交互，自动根据系统架构（x86_64 / aarch64）拉取官方二进制，自动化配置 `gost.service`、开机自启与配置热重载。
- 独立「入站代理 & WARP」扩展专区：将入站代理（GOST 驱动）与 Cloudflare WARP 智能分流从「多用户管理」页面彻底解耦，在顶部导航栏开设全新专属 Tab 页面（`#pane-proxies`），让用户管理页面回归纯粹。
- 入站代理服务管理：集成 gost 引擎，在 Web 控制台一键添加/删除 SOCKS5 / HTTP / HTTPS 三种入站代理服务（独立账号密码认证），客户端无需安装 Hysteria 也能直接把服务器当普通代理用；配置动态生成并平滑热重载。
- 节点实时吞吐与用户网速看板：利用 `/auth` 增量流量与 10 秒时间滑动窗口算法，在 Web 控制台实时渲染节点上行/下行并发带宽仪表盘与各个买家用户的瞬时网速（如 `↓ 12.4 MB/s · ↑ 1.2 MB/s`），每 2 秒无感轮询更新。
- Web 控制台双重版本检测与一键升级：在线比对 Hysteria 2 官方内核与控制面板自身版本，支持在 Web 端一键无损升级与平滑热重启。
- Web 控制台一键启闭 Cloudflare WARP 智能分流出口（AI 加速），秒级切换 OpenAI / Claude / Gemini 路由与 VPS 原生直连。
- 内置 Cloudflare WARP Local Proxy（端口 40000 · MASQUE）一键自动化配置与 3 分钟探活自愈 Watchdog（Systemd Timer 守护）。
- Hysteria 2 默认配置文件集成 `outbounds` 与 `acl` 私网回穿防御（`block(geoip:private)`）。
- 多租户集群 Agent 节点模式：支持外部电商/控制台（如 pay.isoziyuan.com）通过安全 REST API（`/api/v1/users/create`, `renew`, `delete`, `node/meta`）实时动态开户、延期续费与状态上报。
- Hysteria 2 HTTP 动态鉴权集成：基于本地高速 HTTP 认证通道（`/auth`），买家开通/续费/到期注销零中断，完全无需重启 Hysteria 2 核心服务。
- 私密 HTTPS 信息页，集中提供 HY2 链接、本地生成的二维码、Clash 完整订阅及 Sing-box 出站配置。
- 页面、二维码和下载均要求 Basic Auth，随机路径与密码、限流、禁缓存及安全响应头保护节点信息。
- 独立回环网页服务使用 systemd 动态用户和凭据隔离；卸载自动清理。

### Changed
- 一键安装流程极致精简：默认全自动开启端口跳跃（UDP 20000-40000 -> 监听端口）与 Salamander 混淆（自动生成高熵密钥），彻底取消冗余交互询问，实现真正的零打扰极速安装。
- 私密信息页将浏览器原生 Basic Auth 弹窗重构为高颜值 Web 登录界面，支持密码显隐切换、错误友好提示、30天安全免密 Session 保持；同时维持代理客户端（Clash/Sing-box）标准 Basic Auth 自动订阅兼容性。
- 信息页改为响应式卡片布局，提供复制按钮、二维码卡片和可折叠配置；使用 CSP 哈希白名单允许内置样式与脚本。refresh-page 可单独更新现有网页。
- 终端仅显示网页地址与登录凭据，重新配置会轮换访问凭据。
- TCP 端口通过真实 bind 检测选择；无 TERM 时菜单不会直接退出。
- 认证与混淆密码使用 OpenSSL 随机数生成，不再在输入提示中打印。

### Requirements
- Python 3.9+、systemd 247+ 和 qrencode。自签证书模式需要手动核对并信任证书；推荐使用有效域名证书。
