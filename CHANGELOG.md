## 2026-10-12 — 可核验批量更新与 Hy2 在线实例统计

- 门户更新支持固定到不可变提交 SHA；GitHub API、jsDelivr、raw 三条回退源使用同一提交，杜绝更新途中 main 漂移。
- 同节点门户更新加互斥锁，重复下发明确返回 409，不再并发替换鉴权程序。
- 真实计量同时读取 Hysteria `/online`，单独返回 Hy2 客户端实例数；读取失败保持未知，不伪装成 0，也不冒充 Reality/在线 IP。
- 用户状态在到期、停用之外同时考虑真实流量配额，避免列表显示“启用”但新连接已因超额被拒。
- 新增不可变来源、并发更新锁、在线实例与未知状态回归测试。

## 2026-10-12 — 防止新面板混装旧计量模块

- 实机确认旧运行时强制等待未安装的 Reality，并且没有同步用户累计，造成 Hy2 采样成功但页面仍显示“计量未就绪 / 0 B”。
- 安装、Web 更新和运行时检查计量核心/运行时修订号，拒绝语法正确但接口过时的缓存文件。
- 终端更新先下载并校验完整六文件，再备份落地；获取失败保持整包不变，写入失败恢复旧包。
- 未启用来源不再污染计量健康摘要；升级继续沿用旧计量累计与游标，不重复计费、不清零。
- 新增历史数据迁移、缺 Xray、模块版本一致性和终端更新失败不改文件的回归测试。

## 2026-10-12 — 修复 ACME 证书状态误报

- 面板读取内置 ACME 实际缓存，不再错误读取自签模式的 `cert/server.crt`。
- 支持默认目录、`acme.dir` 相对/绝对路径、同进程环境变量覆盖，以及 Let's Encrypt、ZeroSSL、自定义 CA；只选择配置域名与 CA。
- ACME 证书未生成时保持缺失状态，不使用旧自签证书掩盖失败；TLS、自签模式保持原行为。
- 原路径随自动续期继续生效，无需复制证书或重启 Hysteria。
- 新增 12 项路径、缺失、续期与兼容性回归测试。

## 2026-10-12 — 修复真实流量统计链路

- 真实累计同步至用户用量，统一页面、API 与鉴权配额检查；旧值保存到 legacy_auth_value，不混入新计量窗口。
- 实时速率按实际采样间隔计算，分来源合并，空闲归零；页面累计用量随轮询更新。
- 未安装 Xray 时不要求 Reality 统计可用；采集未就绪在页面明确提示。
- 持久化失败同时回滚用户用量与计量游标，失败采样不发布速率。
- 新增累计、配额、来源、速率、重启、回退及保存失败回归测试。

# 变更记录

## 未发布

### 增强：证书页明确显示自动续期方式
- 内置 Hysteria ACME 证书显示“到期前自动尝试续期”，并提醒续期依赖域名解析与验证条件正常。
- 自签证书明确提示不会自动续期；外部/手动证书提示由 Caddy、acme.sh 等外部任务负责。
- 增加内置 ACME / 自签续期状态分类回归测试。

### 修复：换证后 clash/sing/二维码端点仍发旧节点（真机容器演练才发现）
- **发现方式**：在**干净的 Debian 12 容器**里从头装一遍（systemd 252 / Debian 12，
  走菜单 1 + 一路回车，13.1 秒装完），然后模拟 Caddy 续期覆盖证书，观察四个出口。
- **症状**：换证后自愈确实把 `client_meta.json` 修对了，但四个出口**不一致**：
  ```
  meta / portal.json / 页面直链 / sing-box.json = round2.example.com   ✅
  clash.yaml 端点                = newnode.example.com  ❌
  ```
  用户「扫二维码导入」或「下载配置」拿到的仍是换证前的旧节点 → `CRYPTO_ERROR 0x150`，
  而面板看起来一切正常。
- **根因**：`selfheal` 跑在**另一个短命进程**里（systemd timer / path unit 调
  `portal.py selfheal`），把修好的产物写进 `portal.json`；而长期运行的门户进程持有的
  `data` 是**启动时的内存快照**，对这些磁盘写入一无所知。
  页面之所以正确，只因`subpath==''` 分支恰好会调 `regenerate_page()`；
  而 `clash.yaml` / `sing-box.json` / `qr.svg` 直接读 `data[key]`。
- **修法**：这三个下载类端点在吐数据**之前**先 `regenerate_page()`。
- **注意**：这不是上一条「`sync_download_artifacts` 只在 prepare 写过」的重复 ——
  那条修的是「refresh 不更新 clash/sing/qr」，这条修的是「即使 refresh 写了磁盘，
  运行中的进程也读不到」。两条都必须修，缺一个都会继续发旧节点。
- **实测**：修复后同一演练，四个出口全部 = `round2.example.com`。
- **回归**：新增 `test_download_routes_regenerate_before_serving`（纯静态检查，
  不依赖运行时，两平台都跑；变异测试确认能抓到回退）。

### 修复：小白安装链路全面排查（2 个严重安全漏洞 + 8 个装不上的坑）
本轮做法：静态审查 `install.sh` 与 `portal.py` 两条链，**逐条在测试机 `se` 上实测复现**
（不是纸面推断），确认后再修，每条都补了回归用例。

#### 🔴 严重：`/auth` 无限流 = 公网可无限爆破密码
- **实测证据**：原注释写「来自 127.0.0.1 豁免限流」，但 `config.yaml` 的 masquerade 把
  **公网 HTTPS 流量代理进本机 127.0.0.1:PORTAL**（`type: proxy → http://127.0.0.1:PORT/`），
  于是公网攻击者打到的仍是这个 loopback 端口，那条假设根本不成立。
  用正确 SNI 打 masquerade 端口：`/auth` 返回 **200**，连发 20 次**全部放行**，
  且四种可区分回复（`User not found` / `inactive` / `expired` / `Traffic quota exceeded`）
  构成完美的密码 oracle。
- **修法**：新增 `auth_rate_limited()`（1 秒 20 次的速率桶 **+** 60 秒 30 次的失败桶，
  叠成两层——只限速率挡不住每秒 1 次的低速爆破），失败也计数；拒绝时用与成功路径
  同形态的 200 + JSON，不给爆破者区分信号。已装机器**无需任何操作**即生效（升级 portal）。
- **实测**：修复后连发 30 次 → 前 20 次正常、后 10 次被拦；**正确密码 3 次仍全部
  `ok: true`**，确认不会误伤真实客户端。

#### 🔴 严重：`/api/v1/node/meta` 把机主密码送给了低权限 api_key
- **实测证据**：该端点原样返回整个 `client_meta.json`，其中含 `auth_password` 与
  `obfs_password`。而 `api_key` 是**低权限**凭据（页面文案自己写着「权限较低，够不着门户
  网页端」），文档还建议把它发给商城/自动化脚本 —— 等于用低权限凭据换到无限流量、
  永不过期的机主密码。已实测确认两个密码都被返回。
- **修法**：改成白名单（对齐 `capabilities` 既有做法）。
- **实测**：修复后返回的键只剩
  `cert_type / hop_port_range / is_insecure / listen_port / public_ip / server_name / subscription_port`，
  真实密码字符串不再出现在响应里；运维需要的非敏感字段全部保留。

#### 装不上的坑（按严重度）
1. **DNS 预校验把安装直接杀掉**：`verify_domain_resolves_to_this_host` 返回 1/2 时的
   **裸调用**在 `set -eo pipefail` 下当场终止 —— 下面那句「仍要继续申请 ACME 证书吗?」
   是**死代码**。实测 exit=2。域名刚买、A 记录还没生效（本该是最常见的场景）时，
   新手看到红色报错后脚本静默退出，只能重装。改为 `|| dns_rc=$?`。
2. **GitHub API 失败时回退分支不可达**：`install_binary` 的版本获取是命令替换里的 curl，
   失败即终止（实测 exit=6），专门为「api.github.com 被墙」写的直链回退形同虚设 ——
   而这恰是本工具用户最常见的处境。`install_gost` 同一处同样的坑，一并修。
3. **`get_public_ip` 兜底 `127.0.0.1`**：函数**永远返回 0**，所以所有 `|| exit 1` 都是死代码；
   更糟的是把 `127.0.0.1` 当公网 IP 写进 `client_meta.json`、印在信息页 URL 上。
   用户节点「看起来装好了」但订阅/二维码指向 `127.0.0.1`，永远连不上且毫无提示。
   改为取不到就**报错并中止**，并显式拒绝回环/私有地址。
4. **菜单 4「重新修改配置」静默换掉所有凭据**：`RANDOM_PASS` / `OBFS_PASSWORD` 原先
   无条件重新随机 —— 用户只想改个端口，所有已发放客户端立刻失效；`prepare()` 还会按
   只剩机主的 users 表重建 `portal.json`，**商城开的子账号直接消失**；
   全仓库**没有任何一处 .bak**。现在：默认**沿用旧密码**、改配前留带时间戳的快照、
   菜单里明确告知后果并要求确认。
5. **选证书方式 4 无退路**：`select_local_certificate` 失败即终止安装（机器上只有叶证书时
   必然发生），而自签本来是菜单里的合法选项。改为自动回退自签。
6. **`install_dependencies` 装完不校验**：缺 `jq` 这类致命问题要等到几百行后第一次调用才炸，
   用户看到的报错完全看不出所以然。改为逐个校验关键依赖并给出可直接复制的安装命令；
   `qrencode` 缺失只降级提示。
7. **订阅端口分配失败会写出 `listenHTTPS: :`**：python 缺失或 100 次都撞占用端口时，
   命令替换失败被 set -e 变成 traceback。改为判空 + 明确报错。
8. **acme 域名/邮箱未加引号**：`SERVER_NAME` 里出现空格或 `#` 会被 YAML 解析成另一个值、
   或把 `#` 之后整行当注释吃掉 → hysteria 语法错、服务反复重启，错误信息指不到输入框。

#### 装了但用不了
9. **换证后二维码与下载配置仍是旧节点**：`clash`/`sing`/`qr` 三个键**只在 `prepare()` 里写过**，
   `refresh()` / `regenerate_page()` 重算出的 clash/sing 只喂给 `page_html` 就丢弃 ——
   页面文本框显示新 sni、二维码和「下载配置」却是换证前的旧节点，扫了码立刻
   `CRYPTO_ERROR 0x150`。抽出 `sync_download_artifacts()` 三处统一调用（qr 失败时**保留旧图**
   而不是清空成白框）。
10. **`prepare()` 遇缺 `qrencode` 直接崩**：`check=True` 让一个可选二维码能弄崩整个安装。
    改为降级为空，并修掉随之暴露的过时断言。
11. **本地化 locale 让两处功能静默失效**：`ping` 与 `date -d` 的输出被正则/`date` 解析，
    但全文件**没有任何 `LC_ALL`**。实测 `zh_CN` 下测速丢包率解析不到、`de_DE` 下连 avg 都
    解析不到；`LC_TIME` 非 C 时 `date -d` 解析英文月份失败 → 证书倒计时退化，
    而前端**没有 `unknown` 分支**，会显示成「● 正常 · null 天后到期」的**绿色假象**。
    两处钉 `LC_ALL=C` + `ping -n`，前端补 `unknown` 分支与对应告警文案。
12. **自签模式门户标题显示伪装域名**：`<h1>` 用的是 `server_name`（自签时是 `www.bing.com`
    这个诱饵域名），全页最大字号那行偏偏是错的。改用真实 `host`，并把伪装 SNI 单独标注。
13. **网页「创建用户」静默覆盖同名用户**：无条件赋值导致密码被改、**`used_bytes` 归零**
    （已购流量凭空消失）、有效期重算，而用户拿到 200 成功响应。改为 409 拒绝并回显密码尾号。
14. **非 ASCII `Authorization` 头打崩请求处理**：`hmac.compare_digest` 对非 ASCII str 抛
    `TypeError` → 连接被掐断、浏览器只见通用错误，还分不清是鉴权失败还是服务端坏了。
    补 `isascii()` 前置判断。
15. **主监听端口从不查占用**：脚本明明有现成的 `port_owner()`（80/443 检测在用），主端口却
    从没查过；撞上占用时 hysteria bind 失败、服务反复重启，错误信息指不到「端口被占」。
    补检测 + 报出占用进程名。
16. **卸载先问 AWG 再问主确认**：用户对第一个破坏性问题答 `n` 之后，却已经对另一个组件
    做了表态；两个 `read` 也都没有 `|| true`。改为先问主确认。
17. **信息页在菜单 3 / `info` 下打印空的 `TCP`**（`HY2_SUB_PORT` 压根没被赋值），
    新手以为安装漏了东西。改为从 URL 提取端口。

#### 回归
- 新增 `tests/test_novice_install_audit.py`（27 例）：shell 侧**抽取 install.sh 里的真实函数
  真跑一遍**（验证 set -e 下的可达性、兜底、备份、密码复用），python 侧**真起一个 portal**
  验证限流 / 脱敏 / 下载产物同步 / 非 ASCII 头，另有仓库不变量防回退。
  测试机 se（Linux）全绿，本机（Windows）跳过缺 bash/jq 的 7 例。
- 顺带修好 `tests/test_meter_config.py` 的两处**平台假设**（`pwd -W`、`'/'→'\\'`），
  它此前在 Linux 上是「必失败」的；现在两平台 8/8 全绿。

#### 真机容器演练（`tests/rehearsal/`，可复现）
在干净 Debian 12 容器（systemd 252）里从头装一遍，**每步单独计时、逐份留日志**：
- **安装 13.1 秒**完成，`hysteria-server` / `hysteria-portal` 均 active，
  hysteria 自己的日志证实三个监听全部起来（主端口 / trafficStats / masquerade HTTPS）。
- **真实客户端自连成功**：用节点自身凭据起 hysteria 客户端，
  日志出现 `connected to server`，经其 SOCKS5 请求外网拿到出口 IP `13.63.71.232`，
  与节点公网 IP 一致 —— 证明 TLS + pin + salamander obfs + 鉴权整条链真的通。
- **真实计量在工作**：`/traffic` 返回 `{"user":{"tx":4271,"rx":12729}}`。
- **换证自愈 1 秒内完成**，四个出口最终一致（本条修复的直接来源，见上）。
- 日常操作（菜单 3 / `status` / `info` / restart / 菜单 11 / 卸载回答 n 取消）全部正常。
- 演练脚本：`tests/rehearsal/{harness,stage1-interactive,stage2-usability,
  stage3-daily-ops,stage4-certrotation}.sh`。

### 增强：证书状态卡片 + 到期前告警（把静默的「证书过期」变可见）
- **动机**：上一条把「证书被换掉」修成了自动对齐，但**证书过期**这件事仍然是静默的 ——
  自愈只对齐信任模型、不会去续期证书。而「昨天还好好的、今天突然连不上」这类报障里，
  最高频的真凶就是证书过期/续期失败，用户却只能在**掉线之后**才发现。
- **修法**：
  1. `portal.py::cert_status()` —— 以门户实际在用的那张证书为唯一事实来源，输出
     CN / SAN / 签发方 / notBefore / notAfter / 剩余天数 / 判级，并读出自愈痕迹。
     判级阈值提为常量 `CERT_EXPIRY_WARN_DAYS=30` / `CERT_EXPIRY_CRITICAL_DAYS=7` ——
     界面文案、API 返回、日志措辞共用同一组数字，避免「界面说 10 天、日志说 30 天」。
  2. 新端点 `GET /cert-status`（Basic 鉴权，与其它状态端点一致），额外返回
     `live_server_name` 与 `meta_matches_cert` —— 直接告诉用户「订阅用的 SNI 与证书
     实际覆盖的域名是否一致」，这是漂移是否复发的一眼判据。
  3. `capabilities.extras.cert` 同步带出摘要（Bearer 通道），主面板可在节点列表里
     把临期节点提前标出来，而不必等用户报障。该字段异常一律吞掉（退化成 `{'ok': False}`），
     绝不拖累主面板拉全量状态。
  4. 门户新增「🔐 证书状态与到期提醒」卡片：剩余天数 + 到期时刻 + CN/SAN/签发方/
     证书类型/订阅 SNI/pin，四档告警条（已过期 / 剩 ≤7 天 / 剩 ≤30 天 / 元数据不一致），
     并显示「最近一次自动对齐」时间与累计次数 —— 让静默发生过什么变可见。
  5. 自愈发生时写 `cert-selfheal.json` 痕迹（时间/次数/变更字段），由卡片展示。
- **顺带收敛一处隐患**：证书解析统一走 `_resolve_live_cert()` —— 自愈与界面显示
  必须读同一张证书，否则会出现「卡片显示 A、自愈修 B」这种更隐蔽的不一致。
- **实测证据（测试机 se，真实节点 + 真实 HTTP 鉴权）**：
  - 真实 LE 证书：`expires_in_days=89`、`warn_level=ok`、`meta_matches_cert=true`；
    `capabilities.extras.cert` 同步返回。
  - 注入 5 天到期证书：`warn_level=critical`、正确识别为自签 —— 告警链路生效。
  - 篡改 meta 触发自愈后：`fields=["server_name"]` 落盘、`healed_at` 显示为
    「2026-10-09 00:21」、`meta_matches_cert` 转回 true；再触发一次 `heal_count`
    不变（幂等）。
  - 真实页面（Basic 鉴权取回 136KB HTML）7 个卡片 id 全部存在，CSP 头正确放行新脚本。
- **回归**：`tests/test_cert_trust_heal.py` 扩到 26 例（新增 cert_status 4 例：
  正式证书字段、阈值判级用真证书+打补丁 time 走真实代码路径、证书缺失、摘要不抛异常；
  端点鉴权、卡片 11 个 id、JS 接线、CSP 仍覆盖新脚本等不变量）。
  `PORTAL_VERSION` 2.3 → 2.4。

### 增强：证书一致性自愈常驻化（定时 + 事件双保险，覆盖外部续期）
- **动机**：上一条修复只在**安装 / 手动刷新**时对齐信任模型。若证书由**外部**程序
  续期（Caddy 抢证、`acme.sh --cron` 等），换证当下没有任何本项目的代码被触发 ——
  用户不点「刷新」就一直带着旧 sni，表现为「都换正式证书了还 CRYPTO_ERROR 0x150」。
- **修法**：
  1. `portal.py::selfheal()` —— 独立的轻量入口。只在**检测到漂移**时才动盘：
     先修 meta，meta 真变了才顺带 `refresh()` 重生成 portal.json 里的页面
     （避免每 30 分钟无谓重写大 JSON、也让门户 mtime 不再无意义地变）。
  2. `portal.py` CLI 新增 `selfheal` 子命令；`refresh()` 也补上 `sync_cert_trust`
     （原先只有 `sync_pin`，等于手动刷新也修不全四个字段）。
  3. `install.sh::setup_cert_selfheal()` 装三个单元：
     - `hy2-cert-selfheal.timer`（`OnUnitActiveSec=30min`）—— 兜底扫，覆盖任何换证方式；
     - `hy2-cert-selfheal.path`（`PathChanged=<证书目录>`）—— 换证落盘即刻触发。
       盯**目录**而非单文件：Caddy/acme.sh 续期是「写新文件再 rename 覆盖」，
       单文件 `PathChanged` 在 rename 场景下可能因 inode 变化而漏触发。
     - `hy2-cert-selfheal.service`（oneshot，执行体只调 `portal.py selfheal`）。
  4. 老装机无需重装：`refresh_portal()` 与 `do_upgrade.sh portal` 都会幂等补齐单元。
  5. `uninstall_all()` 清理 timer / path / service 与执行脚本。
- **顺带修掉两个真坑**：
  * **未知子命令不再落进 `serve`**：旧版门户没有 `selfheal`，`python3 portal.py selfheal <meta>`
    会掉进 `else: serve(...)` 分支，于是「自愈」实际去**启动第二个门户进程**
    （实测还伴随无关的 `KeyError: 'auth_hash'`），而调用方只看到「命令跑过了」。
    现在未知子命令显式报错并 `exit 2`。
  * **自愈脚本不再吞掉 stderr**：原来 `>/dev/null 2>&1 || true`，失败完全无痕 ——
    「服务显示成功、其实啥也没修」又是本项目最忌的静默降级。现在输出进 journal，
    并在 portal.py 缺 `def selfheal(` 时明确记「版本过旧，请升级门户」。
- **实测证据（测试机 se，模拟 Caddy 续期）**：把证书换成 `CN=www.bing.com` 自签、
  meta 仍记 `se.zy3a.com/custom`（漂移），`touch` 证书目录后
  path unit **自动触发**并自愈为 `self_signed/www.bing.com/true`，
  `pin_sha256` 与证书真实 SHA-256 指纹逐字符一致，journal 留痕完整；
  再触发两次均零写入零日志（幂等）；换回真实 Let's Encrypt 证书后自愈**反向**修正为
  `custom/se.zy3a.com/false`。`hysteria-portal` / `hysteria-server` /
  `hy2-cert-selfheal.timer` / `hy2-cert-selfheal.path` 全部 active。
- **回归**：`tests/test_cert_trust_heal.py` 扩到 18 例（新增 selfheal 入口 3 例 +
  严格 CLI 1 例 + 版本守卫标记一致性 1 例 + 定时/事件单元不变量 1 例），
  测试机 se 上 18/18 绿。两个新坑都用变异测试验证过用例能抓到。

### 修复：真实计量从未启用（`install.sh` 从不写 `trafficStats`，portal 静默降级）
- **现象（真实故障）**：装完后仪表盘「真实计量」永远显示「未开始计量」，
  `/traffic-speed` 恒为 `0`，`users/list` 的 `measurement_ok` 恒为 `false`，
  而安装过程**看起来完全成功**——是本项目最忌的静默降级。
- **根因链**：`install.sh` 生成的 `config.yaml` **从来没有 `trafficStats:` 段** →
  portal 启动时 `usage-meter-config.json` 缺失 → `真实计量未初始化: FileNotFoundError`
  → `usage_meter=None` → `poll()` 从不运行 → speed_tracker 为空 → `/traffic-speed` 返回 0。
- **修法**：
  1. `generate_server_config()` 生成 `METER_SECRET`（`openssl rand -hex 16`）并把
     `trafficStats: {listen: 127.0.0.1:19996, secret: ...}` 写进配置模板。
  2. `portal_ensure_py()` 由「缺 secret 就 `log_warn` 后继续」改为**幂等补写 + 硬失败**：
     补不上就 `return 1`，拒绝以静默降级的方式继续安装。
  3. `do_upgrade.sh portal` 路径同样幂等补写 `trafficStats` 并重建
     `usage-meter-config.json`（老装机在线升级也能修好）。
- **实测证据（测试机 se）**：修复后 `/traffic` 返回 `{"user":{"tx":3297,"rx":92021}}`，
  `/traffic-speed` 返回 `rx=26310.67`，`measurement_scope` 变为
  `since_measurement_started`（此前为 `unavailable`）。
- **回归**：新增 `tests/test_meter_config.py`（8 例，含动态执行真实
  `do_upgrade.sh` 自愈片段的用例）。

### 修复：证书信任模型漂移导致 `CRYPTO_ERROR 0x150`（`sync_pin` 只管 pin）
- **现象（真实故障）**：证书文件在安装后被带外替换（Caddy 抢证续期、手工 `cp`、
  菜单 4 只换证书没重跑 `generate_server_config`）后，客户端连不上，
  只能看到笼统的握手失败；用错误 SNI（如 `www.bing.com`）连接时报
  `CRYPTO_ERROR 0x150`。
- **根因**：`client_meta.json` 的 `cert_type` / `server_name` / `is_insecure` /
  `pin_sha256` 是**安装那一刻**写死的。证书被替换后四个字段同时与真实证书漂移
  （实测：config 用 `CN=se.zy3a.com` 的真 Let's Encrypt 证书，meta 却仍是
  `cert_type=self_signed / server_name=www.bing.com / is_insecure=true /` 旧自签 pin），
  面板于是把 `sni=www.bing.com` 发给客户端。而既有的 `sync_pin()` **只修 pin，
  从不碰另外三个字段**，自愈永远不会发生。
- **修法**：以**证书文件本身**为唯一事实来源，新增幂等自愈：
  1. `portal.py::sync_cert_trust()`——读 `config.yaml` 的 `tls.cert`
     （相对路径显式相对配置目录解析；acme 模式退回 `cert/server.crt`），
     由 `CN`/`SAN`/`issuer==subject` 推断
     `cert_type` / `is_insecure` / `server_name`（SAN 优先）/ `pin_sha256`，
     仅在漂移时写盘。已在 `prepare()` 中**先于** `sync_pin()` 调用（顺序有依赖：
     `sync_pin` 需要正确的 `is_insecure` 才决定 pin 去留）。
  2. `install.sh::sync_cert_meta()` 做同样的事，挂到 `refresh_portal()`；
     `do_upgrade.sh portal` 内联同一段自愈。
- **踩坑记录**：
  * 证书路径必须**相对配置目录**解析，否则 `-f`/`.exists()` 拿进程 CWD 判、永远失败
    （`portal.py` 与 `install.sh` 两侧各踩到一次）。
  * jq 的 `//` 把布尔 `false` 当 `null`，`.is_insecure // empty` 会把 `false`
    变成空串 → 自愈每轮都判成漂移、反复写盘。改用
    `if has("is_insecure") then (.is_insecure|tostring) else "" end`。
  * 解析证书不能用一次 `openssl x509 -subject -ext subjectAltName -issuer` 再切字符串：
    SAN 块夹在 subject 与 issuer 之间，按 issuer 切会把 SAN 并进 CN。改为分别调用。
- **实测证据（测试机 se，真实漂移状态）**：自愈前
  `cert_type=self_signed, server_name=www.bing.com, is_insecure=true, pin=8037cef0…`；
  自愈后 `cert_type=custom, server_name=se.zy3a.com, is_insecure=false, pin=""`，
  门户输出的 URI 变为 `…@se.zy3a.com:19906?sni=se.zy3a.com…`（此前是
  `sni=www.bing.com`），且二次运行确认为 no-op（幂等）。
- **回归**：新增 `tests/test_cert_trust_heal.py`（10 例：`portal.py` 侧 4 例 +
  真实执行 `install.sh` 自愈片段的 shell 侧 4 例 + 仓库不变量 2 例；
  在测试机 se 上 10/10 绿）。已用变异测试验证新用例能真正抓到上述两个坑。

### 修复与增强：Reality 停用同步、端口冲突规避与能力参数白名单
- 停用用户时同步移除其 Reality 客户端身份；重新启用时恢复原映射，避免已停用账号仍可连接。
- Reality 自动选择端口时检查当前监听端口、保留端口和额外冲突端口；已有可用配置端口继续沿用。
- 能力接口仅通过白名单提供客户端必需的公开 Reality 参数，不透传服务端私钥或其他未知字段。
- 新增回归用例覆盖停用用户过滤、公开参数白名单与端口选择边界。

### 修复：门户新建 gost 入站代理后端口一直不监听（`reload_gost()` 静默失效）
- **现象（真实故障）**：在门户里新建 HTTP / SOCKS5 代理，页面提示「创建成功」、
  二维码和连接串都正常显示，但**代理就是连不上** —— 对应的端口从未被监听。
  `systemctl is-active gost` 是 `active`，`journalctl` 里也没有任何错误，极具误导性。
- **根因**：`reload_gost()` 依赖 `subprocess.run` 的**异常**来判断 reload 是否成功：

  ```python
  try:
      subprocess.run(['systemctl', 'reload', 'gost'], timeout=2)
  except Exception:            # ← 以为失败会抛异常
      ... kill -HUP ...
      except Exception:
          ... restart ...
  ```

  但 `subprocess.run` **不检查退出码**，只在超时或找不到命令时才抛异常。
  而 `portal.py` 生成的 unit **没有 `ExecReload`**（`CanReload=no`），
  此时 `systemctl reload` 会打印
  `Job type reload is not applicable for unit gost.service.`
  并且**以退出码 3 正常返回** —— 不抛异常。
  于是 `kill -HUP` 与 `restart` 两个 fallback **全是永不执行的死代码**。
  结果：`gost.yml` 写进了新服务，gost 进程却从未重载。
- **实测证据（服务器上复现）**：
  ```
  systemctl reload gost                    -> 退出码 3
  subprocess.run(...)                      -> 不抛异常, returncode=3
  写配置含 :42194 后等 3 秒                -> ss 里没有 42194   ← BUG
  ```
- **修法（四层防护，每一层都单独能救场）**：
  1. **`reload_gost()` 显式检查 `returncode`**：返回 0 才算成功，否则退化为
     `systemctl restart`（restart 一定生效）。不再依赖异常判断，也删掉了
     那套手工 `kill -HUP` 的死代码。
  2. **unit 加 `ExecReload=/bin/kill -HUP $MAINPID`** —— gost v3 支持 SIGHUP 重载
     配置（实测：改 `gost.yml` 后 `kill -HUP`，端口 42197 → 42198 成功切换）。
  3. **unit 的 `ExecStart` 加 `-R 30s`** —— gost 官方的周期自动重载，作为兜底。
     实测 v3.3.0 有效（改配置后 2 秒内完成重载）。即使门户侧 reload / restart
     全部失败，配置也会在 30 秒内自动生效。
  4. **unit 加 `ExecStartPost` 启动自检**（`/usr/local/lib/hy2-gost-selfcheck`）：
     解析 `gost.yml` 里声明的端口，逐个确认真的在监听；任一端口 5 秒内未监听
     就返回非 0 —— 把「`active` 但无监听」的**假健康**变成**启动失败**，
     交给 systemd 重试。无代理配置时放行（那是合法状态）。
- **顺带修掉的两处不一致 / 隐患**：
  - `install.sh` 与 `portal.py` 生成的 unit **此前不一致**（前者有 `ExecReload`、
    后者没有），这正是「命令行装的 gost 能被 reload、门户装的不能」的原因。
    现在统一为一处定义、两处逐字节一致，并加了断言钉死。
  - 新增 **`ensure_gost_unit()`**：每次改配置前幂等自愈 unit。
    否则**老机器不重装就永远拿不到修复** —— 它们的 unit 缺 `ExecReload`，
    reload 会一直静默失败。自愈判据用「逐项包含」而非整体比对，
    避免注释措辞变化触发无谓重写。
  - `Path.as_posix()` 替代 `str(Path)` 拼接 unit 内容：
    后者在 Windows 上会把路径渲染成反斜杠（`\usr\local\lib\...`）。
- 新增 `tests/test_portal_gost_reload.py`（**15 项**）：
  锁死「reload 必须看 `returncode`」「两处 unit 必须一致且含三项关键配置」
  「自检脚本在端口未监听时必须返回非 0」。
  做过两组反向验证：① 去掉 `returncode` 检查 → 2 项失败；
  ② 去掉 `-R 30s` → 2 项失败（含两处一致性断言）。
- **真机端到端验证（us 节点）**：走门户 API 新建代理 → 新端口 42188 在 4 秒内
  成功监听；经该代理 `curl https://api.ipify.org` 返回 `200` 与出口 IP；
  错误密码被拒（HTTP 000）；删除代理后端口正常关闭；
  `systemctl show -p CanReload gost` 由 `no` 变为 **`yes`**。

### 修复：订阅链接端口兜底成伪造的 8443，导致客户端导入失败
- **现象**：面板生成的 Clash 订阅链接指向 `:8443`，而机器上**根本没有 8443 在监听**，
  客户端只报一句笼统的「订阅导入失败」，用户完全无从下手。
- **根因**：多处用 `m.get("subscription_port", 8443)` 取订阅端口 —— 一旦
  `client_meta.json` 缺这个键（历史遗留 / 手工改过），就兜底成 **8443**。
  但 8443 在本项目的端口分配里是**被主动避开**的黑名单成员，
  这个兜底值在真实部署里**几乎总是错的**。
  其中**用户专属页**更严重：它从 `uinfo`（用户对象）取 `subscription_port`，
  而该键只存在于节点 meta 里 —— 所以**必然**落到 8443。
- **修法**：
  - 新增 `resolve_subscription_port(m)`，按优先级取值：
    `client_meta.subscription_port` → **config.yaml 的 `masquerade.listenHTTPS`**（权威来源）→ 兜底。
    并返回来源标记，便于排障时说明端口来自哪里。
  - 新增 `read_masquerade_port()` 解析 config.yaml 的 `listenHTTPS`
    （兼容 `:11690` / `0.0.0.0:11690` 两种写法）。
  - `prepare()` 初始化时**把解析结果写回 `client_meta.json`（自愈）**，幂等、不重复写，
    并打印一行来源日志。
  - 修掉用户专属页从 `uinfo` 取端口的错误（改为由调用方传入节点 meta 的解析结果）。
  - 顺带修掉 3 处 `m['subscription_port']` 的**硬取值**（缺键会 KeyError 崩溃）。
- **install.sh 同步**：`select_subscription_port()` 不再优先尝试 8443，
  直接从高位随机端口挑，并显式避开黑名单与 20000-40000 跳跃区间；
  `HY2_SUB_PORT` 初始值由 `"8443"` 改为空（表"尚未确定"）。
- 新增 `tests/test_portal_sub_port.py`（**11 项**），锁死「缺键时绝不返回伪造的 8443」这条不变量；
  做过反向验证（把兜底改回 8443，测试立即失败）。

### 修复：防火墙自动放行漏掉了 nftables，且从未放行过「UDP 主监听端口」
- **背景（真实故障复现）**：在一台只跑 nftables 的机器上装完后，`hysteria-server` 显示 `active`、配置与证书全对，但客户端**连不上**，面板节点测试恒为 **-1（超时）**。诡异之处在于 `hysteria client` 连 `127.0.0.1:<listen>` **成功**、连 `<公网IP>:<listen>` **超时**。
- **根因一（覆盖面缺口）**：`setup_system_firewall()` 只处理 `ufw` 与 `firewalld`。函数名与日志里写着 `iptables`，但函数体里**没有任何 iptables/nftables 的 INPUT 放行逻辑**。纯 nft 的机器因此完全不被覆盖（`iptables-nft` 兜底也不会去碰自定义的 nft 表）。
- **根因二（更隐蔽）**：所有分支都遗漏了**UDP 主监听端口**。客户端订阅里的 `port: <listen>` 是**直连主端口**的（`ports: "<listen>,20000-40000"` 里的跳跃段是可选项），而此前只放行了跳跃段 `20000-40000`。于是「跳跃段通、主端口不通」—— `hysteria client` 连跳跃端口测试会成功，让人误判为服务正常。
- **修复**：
  - 新增 **nftables 分支**：用 `nft list ruleset` 的层级结构解析出那条 `hook input` + `policy drop` 的 base chain（**只在确有条目会 DROP 时才动它**，默认放行的机器不受影响），幂等追加放行 `udp <listen>`、`udp <hop 起-止>`、`tcp <订阅端口>`，并在 ACME 模式下放行 `tcp 80`。
  - 新增**裸 iptables 兜底分支**：仅在既无 ufw/firewalld 也无 nft 时生效，且只在 `INPUT` 链 policy 为 `DROP` 时才插入规则。
  - **刻意不做「把端口并入已有 dport 集合」的优化**：那需要解析 `nft -a` 的 handle 再跑 `nft replace rule`，handle 的输出格式在不同 nft 版本间有差异，猜测成本高于收益；追加独立规则语义等价且天然幂等。
  - nft 规则默认不持久化，因此会打印明确警告，提示用户若有 `/etc/nftables.conf` 或自建加载服务需同步写入。
- **验证**：解析/拆分/幂等/数字边界（`14617` 不会误命中 `146170`）/不误伤 `policy accept` 机器 —— 共 9 项单元测试全通过。

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

### 修复（由真实 Debian 12 端到端验证发现）
- **卸载后残留空的 `/etc/amnezia` 目录**：`rm -rf /etc/amnezia/amneziawg` 只删子目录，父目录留成空壳，与"彻底卸载"不符。改为删完子目录后用 `rmdir` 收拾父目录 —— 用 `rmdir` 而非 `rm -rf` 是有意的：只在确实为空时删除，万一用户在该目录下还有别的东西（例如官方 Amnezia 包的其他组件）不会被误删。
- **`hy2-awgctl` 一旦存在就永不更新**：`awg_ensure_ctl` 原本看到文件存在就直接返回，导致已经装过 AWG 的机器会把引擎**永久冻结在首次安装的版本**上——后续所有引擎侧修复都下发不到。新增 `awg_ensure_ctl --refresh`（内容一致则不改写），并接入菜单「更新二进制」与 CLI `awg-update`；门户侧 `ensure_awgctl(force=True)` 同样接入 `manage-amneziawg` 的 `update` 动作。
- **改用多源回退获取 `awgctl.sh`，不再依赖 `raw.githubusercontent.com`**：实测 raw 在 push 之后数分钟仍返回旧内容，导致刚修好的问题在测试里复现不出来、用户也可能拿到旧引擎。**而且它不把查询串算进缓存键** —— 用三个不同的 `?cb=<时间戳>` 请求，返回的是同一份旧文件，所以"加缓存破坏参数"这条路是走不通的（一开始就是这么写的，实测后被推翻）。同一时刻实测：`api.github.com` + `Accept: application/vnd.github.raw` 与 `cdn.jsdelivr.net/gh/<repo>@main` 都返回最新，raw 滞后。现改为 **GitHub API（权威）→ jsDelivr（无限速）→ raw（兜底）** 三级回退，与项目里 gost 安装用多镜像的做法一致。
- **`hy2-awgctl uninstall` 不移除控制工具自身**：菜单路径会删，直接调用不会，两边行为不一致。已补上（延迟到进程退出后再删，避免删掉正在被 bash 读取的脚本；且仅当运行的确实是已安装的那份才删，不会误删用户仓库里的副本）。

### 端到端验证（真实 Debian 12）
- 新增 `tests/awg-e2e-smoke.sh`：在真实机器上走完整链路 —— 通过 `install.sh awg-install` 非交互安装、校验端口避让、拒绝落入劫持区间的端口、**用导出的客户端配置在本机起第二个实例并从隧道内 ping 服务端**、切换协议线后重验、最后卸载并核对无残留。
- 在 `se`（Debian 12 / 内核 6.1.0-50-cloud-amd64，**该机 20000-40000 的 UDP 确实已被 Hysteria2 的跳跃规则劫持**）上实测：**37 项断言全部通过**，其中关键结论：
  - 自动选中端口 52369 且在跳跃区间之外，`ss` 可见 `amneziawg-go` 真实监听；
  - 手动指定 25000 被拒绝并说明原因；
  - **AWG 3.x 与 AWG 2.x 两条协议线的隧道内 ping 均 3/3 通、0% 丢包、握手建立、有真实收发字节** —— 这才真正证明了「两端参数逐字节一致」成立；
  - 3.x 含 `HeaderProtectionKey`、2.x 不含，两端各自一致；
  - 卸载后 `/etc/amnezia`、服务单元、二进制、接口全部清理，AWG 自己的 `MASQUERADE` / `FORWARD` 规则归零，且 **Hysteria2 服务与其端口跳跃规则毫发无伤**。
- 踩到的两个"假故障"值得记录：判定 iptables 残留时**不能比对整张表** —— 本机跑着 Docker，它会在任意时刻动态增删自己的 `br-*` 规则，导致误报（本测试先后用行数比较和全表比对各误报过一次）；改为只比对 AWG 自己的规则。

### 新手体验与交互逻辑优化（五轮走查 + 真机实测）
- 🔴 **`curl … | bash` 会把脚本体当输入吃掉**（新手最容易踩的坑）。
  README 推荐的是 `bash <(curl …)`，但很多人习惯直接 `curl … | bash` ——
  此时 bash 把 stdin 当脚本来读，脚本里每条 `read` 都会去读**脚本体自身**，
  表现为「菜单一闪而过 / 装到一半卡住 / 选项乱跳」，且没有任何有意义的报错。
  现在检测 `BASH_SOURCE[0]` 为空（= 脚本来自 stdin）时把 stdin 接回 `/dev/tty`；
  确实没有终端时打印正确用法并退出。
  **同时区分了另一种情况**：`printf '1\n' | bash install.sh`（脚本是文件、答案来自 stdin）
  是正常自动化用法，**不能**被劫持 —— 靠 `BASH_SOURCE[0]` 是否为空精确判别。
- 🔴 **主监听端口完全没有合法性校验**。输错（`abc` / `99999` / `0`）会一路写进配置，
  装完表现为「显示安装成功但服务起不来」，新手根本想不到是自己打错了。
  新增 `is_valid_port()`，交互输入与环境变量两条路径走同一套校验；
  且**环境变量在动工之前就校验**（不再装到一半才报错）。
- **默认监听端口会落在 20000-40000 这个端口跳跃区间内**（随机区间是 10000-49999）。
  主监听端口落在跳跃区间里会和 REDIRECT 规则互相干扰。现在默认值主动避开该区间，
  用户手填落在区间内时会给出警告。
- **装完之后没有任何"下一步"引导**。原来只吐一串凭据就结束，新手完全不知道接着做什么。
  现在收尾输出改成清晰的三步走：打开信息页 → 扫码/复制直链导入客户端 → 确认云安全组放行
  （并明确列出该放行 UDP 跳跃区间与信息页 TCP 端口，注明"装好了却连不上十有八九是这里"）。
- **支持免交互部署**：新增 `HY2_PORT` / `HY2_PASSWORD` / `HY2_NODE_MODE` / `HY2_CERT_TYPE` /
  `HY2_DOMAIN` / `HY2_EMAIL` 环境变量，`bash install.sh install` 可完全无人值守
  （此前只有 AmneziaWG 支持 `--line/--endpoint/--client`，核心安装做不到，不对称）。
- **已安装时选择「1. 全新安装」没有任何确认**，会静默重生成配置、可能换掉端口/密码/证书
  并让已发放的客户端配置失效。现在会二次确认，并提示可改用第 4 项「重新修改配置」。
- **操作完成后直接把用户丢回 shell**。原来只有第 7 项会停留，其余全部直接退出，
  想接着做点别的就得重跑脚本。现在统一回到主菜单（输入 q 退出），
  同时把主菜单从递归调用改成循环（原来连续输错会不断叠加递归）。
- **stdin 到 EOF 时会静默以退出码 1 结束**（管道输入用尽或用户按 Ctrl+D）。
  现在给出明确提示后正常退出。
- **加了 Ctrl+C 中断保护**：中断时告知"已完成的步骤不会回滚，重新运行即可继续"，
  而不是让用户对着半成品不知所措。
- **证书选择提示自相矛盾**：第 3 项标着「推荐」，默认值却是第 1 项（自签名）。
  现在把权衡写清楚（有域名选 3、没域名选 1 且客户端要开 insecure），
  且选 1 后明确提示客户端需要跳过证书校验、直链已自动带 pinSHA256。
- **Web 面板里 AmneziaWG 找不到**：它是 README 的重点功能，却藏在标签「入站代理 & WARP」
  下的第三张卡片里。标签改为「🧩 代理 · WARP · AWG」，并在页首加一段说明讲清
  这一页是三块互相独立的功能。

### 测试
- `.github/workflows/tests.yml` 新增「交互逻辑行为测试」：**真的把脚本跑起来验行为**，
  而不只是 `bash -n`。覆盖：`curl|bash` 必须被拦截且非零退出、管道喂答案不能被误拦、
  端口校验的合法/非法用例、三个环境变量的非法值必须在动工前被拦。
  （真机 `se` 上已逐条验证通过。）
- 回归：按钮冒烟 63 项、门户配置编辑 7 项、门户资源 7 项、门户 AWG 20 项、AWG 逻辑 102 项全过。

### 修复（线上事故：门户点一下 WARP 开关会把 Hysteria 打成「连上没网」）
- **根因**：`apply_hy2_acl()` 重写 `config.yaml` 时用的是「**从 `acl:` 那行一路删到文件尾**」，
  而 `install.sh` 是把 `obfs` 段**追加在配置末尾**的（排在 `acl:` 之后）——
  于是混淆配置被一起删掉。服务端不再有 obfs，客户端却仍带着 salamander 混淆去连，
  **QUIC 握手直接超时**。
- **现象极具误导性**：客户端报 `connect error: timeout: no recent network activity`，
  而**服务端一行日志都没有**；`systemctl is-active` 是 active、端口在监听、
  REDIRECT 规则计数正常增长 —— 每个单点看起来都是好的，唯独连不上。
- **修法**：新增模块级 `strip_acl_block()`，**只删 `acl:` 块**（从顶格的 `acl:` 到下一个
  顶格非空行为止），保留文件里其它所有内容。
- **验证**：新增 `tests/test_portal_config_edit.py`（7 项）。核心回归是
  「acl 之后的 obfs 段必须原样保留」。做了反向验证：把实现换回旧逻辑后 7 项里
  **4 项立刻失败**（含核心那条），证明测试不是空转。
  端到端实测：通过门户点一次 WARP 开关 → `obfs` 段仍在、salamander 密码仍在、
  Hysteria 仍 active；外部客户端（Windows）连 `rd.hejige.com:21242` 成功，
  `www.baidu.com`/`www.google.com` 均 HTTP 200、`api4.ipify.org` 按 ACL 走 WARP 出口。

  > 这次是**在按钮冒烟测试里点 WARP 开关时触发的**，把测试机 `se` 的 Hysteria
  > 打成了上述状态。教训：**凡是"重写配置文件某一段"的代码，都必须按块替换、
  > 绝不能按"从这里删到结尾"处理** —— 因为追加在末尾的段落（本项目就是 `obfs`）
  > 会被无声吞掉，而且症状与原因隔得很远。

### 修复（用户报「AmneziaWG 连上了但没网」）
- 🔴 **服务端 PostUp 只放行了 FORWARD 的去程，回程被丢 —— 表现就是"握手成功但上不了网"**。
  原规则只有 `-i awg0 -j ACCEPT`（客户端→公网）。而**回程包是 `in=<出口网卡> out=awg0`**，
  不匹配 `-i`，于是落到链尾的 policy。多数发行版的 `FORWARD` 默认策略是 `DROP`，
  **装了 Docker 更是必然被设成 `DROP`** —— 结果就是隧道内一切正常（能 ping 通服务端、
  收发字节都在涨、去程的 FORWARD 计数也在正常增长），**唯独客户端上不了网**。
  这与"没连上"的现象很像，极易误判。WireGuard 官方文档同样是两个方向都放行。
  现补上回程方向，并用 `conntrack --ctstate RELATED,ESTABLISHED` 限定为已建立连接
  （比官方写法更严，避免任意来源的包都被转发进隧道，对"客户端上网"完全够用）。

  定位过程值得记录：先怀疑端口/参数/MTU，抓包后发现内层包**已经出现在服务端的 `awg0` 上**
  却从未从出口网卡发出；在 raw/nat/forward 三个钩子上挂计数器，看到包只到达最早的
  `raw PREROUTING`（-300）就消失了 —— 说明死在路由判定；最后确认是回程方向的 FORWARD 缺放行。

- 🔴 **`hy2-awgctl update` 在协议线未变时完全不重建配置**，导致上面这类"引擎侧的配置修复"
  永远下发不到老安装（用户点了更新也没用）。现改为无论协议线是否变化都重新渲染服务端配置；
  混淆参数来自 meta、未改动，所以已发放的客户端配置依然有效。
  **已实测**：把配置人为退回有 bug 的版本 → 上不了网；跑一次 `hy2-awgctl update` → 自动修复、上网恢复。

### 测试（新增「能不能真的上网」这一层）
- 新增 `tests/awg-internet-netns.sh`：把客户端放进 **network namespace**（独立网络栈，
  等价于真实设备），在 netns 内起完整隧道并 ping 公网。默认路由的改动只发生在 netns 内，
  绝不影响宿主机 SSH。
- 新增 `tests/awg-internet-capture.sh`：逐跳抓包（客户端 TUN / 加密 UDP / 服务端 TUN / 出口网卡），
  一眼看出包在哪一段消失，供后续排障复用。
- ⚠️ **踩到的测试方法坑**：一开始把客户端也跑在宿主机上，结果导出的客户端地址（10.66.66.2）
  成了**本机地址**，服务端在 `accept_local=0`（默认）下会按 martian source 丢弃 ——
  于是"复现"出一个假故障。实测把 `accept_local` 打开后 FORWARD 计数立刻从 0 涨到 189，
  证明转发链路本身没问题。**结论：验证"客户端能否上网"必须让客户端处于独立网络栈**
  （netns 或另一台机器），同机测法会得到假结果。
- `tests/awg-e2e-smoke.sh` 头部补上说明：它**只测到隧道内互通为止**，
  证明不了"能上网"，必须另跑 netns 脚本。

### 修复（真机按钮冒烟测试发现）
- 🔴 **Web 端点一下 WARP 开关会把 Hysteria 打成 failed，整台机器的 Hysteria 全挂**（严重）。
  门户的 `manage-warp` 无条件往 `config.yaml` 的 ACL 末尾写 `direct_ipv4(all)`，但**从不确保该出站存在**。而 `direct_ipv4` 出站是由 config 模板定义的，`toggle_warp.sh` 重写配置时可能把它连 `outbounds` 段一起删掉 —— 一旦两条路径混用，写出的 ACL 就引用了悬空出站，hysteria 启动即 FATAL：

  ```
  invalid config: acl.inline: error at line N: outbound direct_ipv4 not found
  ```

  且因为 `hysteria-server.service` 配了 `StartLimitBurst=5`，连续失败 5 次后 systemd 直接放弃（`Start request repeated too quickly`），**必须手工 `reset-failed` 才能恢复**。
  修复：写 ACL 前先探测实际存在的出站 —— `direct_ipv4` 存在才用它（保留强制 IPv4 的意图），否则退回 hysteria 内置的 `direct`；出站名同样探测（`warp_socks` / `warp`），不再假定模板布局。
- **给 WARP 配置写入加了「校验 + 自动回滚」兜底**：改配置前留备份，重启后确认 `systemctl is-active`；起不来就自动还原备份并重启，把失败信息记进 `portal_data['warp_apply_error']`。光靠"写对了"不够 —— 一个引用错出站的 ACL 就足以让服务起不来。
- **门户与 `toggle_warp.sh` 的出站命名不一致**：门户用旧名 `warp_socks`，而某些版本的 `toggle_warp.sh` 已迁移到 `warp`，导致配置里两个出站并存、ACL 引用哪一个全靠运气。现在按实际存在者取值。
- **`awg-conf` 查不存在的客户端返回 500**，语义上应是 404（前端需要区分「查无此人」与「服务端出错」）。

### 新增：Web 端更新面板
- **修好「更新面板」按钮不显示**：`portal_has_update` 依赖 `data['portal_sha']`，而该字段**只被读取、从未被写入**（全仓库 grep 只有两处读取、零处写入），导致它恒为 `False`、按钮永远 `display:none`。改用 **git blob sha 比对文件内容**（本地算 `sha1("blob <len>\0" + content)`，远端从 contents API 的 JSON 取 sha），并把写死的 `portal_current = '2026.09.21'` 一并换掉。
- **面板自更新不再走 `do_upgrade.sh`**：那个脚本从 `raw.githubusercontent.com` 拉 portal.py，会踩 raw 的 CDN 缓存（push 后数分钟仍是旧内容）。改为 portal.py 内部用三级回退取文件、留 `.bak` 备份后原子替换、`start_new_session=True` 延迟重启。
- 更新面板新增 **AmneziaWG 引擎** 一行（支持 `do-upgrade target=awg`）与「🔄 重新检测」按钮；版本文案区分「未安装 / 远端未取到 / 有新版本 / 最新」四种情况，避免拿不到远端时误报「最新」。
- 版本检查的远端结果**服务端缓存 5 分钟**，并改用「目录列表」接口一次取回所有文件 sha —— 版本检查每次页面加载都会触发，而 GitHub 未认证 API 限 60 次/小时/IP。

### 测试
- 新增 `.github/workflows/tests.yml`：在 push / PR 时校验 shell 脚本语法、**强制校验 `install.sh` 内嵌的 `portal.py` 副本与 `portal.py` 逐字节一致**（这条不变量极易悄悄退化，本次开发中就差一点把门户改动丢掉），并跑完整测试套件。
- 新增 `tests/test_awgctl.sh`（纯逻辑，无需 root，可跨平台运行）：覆盖混淆参数的**全部上游硬约束**、端口跳跃区间避让、**服务端与客户端配置的 11 个参数逐字节一致性**、peer 生命周期与地址回收、meta 读写、随机数边界、命令行参数解析。做了反向验证（故意注入 `H2=H1` 与"客户端 S1 不一致"两个缺陷，确认测试能抓到）。
- 新增 `tests/test_portal_awg.py`：页面渲染（含 **f-string 无残留占位符** 回归检查）、**CSP `sha256` 白名单跟随 `SCRIPT` 变化**、端点鉴权、路径穿越与非法名称拦截、端口区间拦截、**私钥不泄露**、`awg-conf` 路由可达性。
- 新增 `tests/portal-buttons-smoke.sh`：逐个调用每个按钮背后的端点，**走成功路径**而不只是验错误路径。在 se 上实测 **58 项断言全部通过**。其中专门为上面那个 WARP bug 加了回归断言：真的点一次 WARP 开关，并确认 Hysteria 仍然 active（两次切换各验一次）。
- 新增 `tests/portal-update-cycle.sh`：验证「推送后 Web 端能真的更新过去」的完整循环 —— 起点一致 → 扰动本地 → 检测到差异 → 点更新 → **内容逐字节收敛到 main**。在 se 上实测 15 项全过。
- 三个真机脚本（`awg-e2e-smoke.sh` / `portal-buttons-smoke.sh` / `portal-update-cycle.sh`）都需要 root + 已部署服务（会真的装/卸 AWG、创建删除用户、重启面板），因此 CI 里只做 `bash -n` 语法校验。
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
