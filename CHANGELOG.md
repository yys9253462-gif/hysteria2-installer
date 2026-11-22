## 2026-11-22 — 第五十九批十项修复，门户 2.69

- 门户备份清理守卫、重启脚本参数校验、受限流正整数守卫、校验清单双列解析、核心升级编码与锁 `O_NOFOLLOW`（`portal.py`）：`_prune_portal_backups()` 保底 `keep >= 1` 并跳过符号链接隔离单条 `OSError`；`portal_update_restart_script()` 拒绝小数、`NaN`、前导零与超长数字 `port`/`wait_seconds`；`_read_bounded_bytes()` 与 `_copy_stream_bounded()` 拒绝非正数或布尔上限及块大小；`parse_checksum_manifest()` 拒绝非字符串 `asset` 并要求严格双列防止注释尾词误匹配；`_upgrade_core_binary_locked()` 版本命令补齐 `encoding='utf-8', errors='replace'`，回滚写盘改用 `r+b` 模式 `fsync` 并保护清理异常；三处锁文件打开统一叠加 `O_NOFOLLOW`。
- Xray 内网黑洞首位防护与去重、出口 IP 拒整型假地址、不可达探测、回滚超时隔离、出站剥离段限定与死线封顶（`portal.py`）：`add_private_network_guard()` 过滤非字典脏出站、将 `block-private` 移离首位并去重旧版不完整黑洞规则；`detect_outbound_ip()` 拒绝非字符串 `addr`、补齐 `errors='replace'` 并校验字符串结果堵死整型假 IP 拼出 `'0.0.0.123'`；`_unreachable_outbounds()` 校验列表容器、有限正数 `timeout` 与纯 ASCII 无前导零 5 位端口；`_rollback_outbounds()` 拒绝非字符串 `original` 并隔离单轮 `is-active` 超时；`strip_managed_outbounds()` 限定仅在顶层 `outbounds:` 段内移除自定义出站；`ThreadingHTTPServer.extend_deadline()` 封顶 `3600.0` 秒，`process_request()` 捕获 `BaseException` 归还信号量。
- 证书自愈脏 SAN 与主机清洗、计量辅助函数守卫、`prepare`/`adopt` 严格 JSON 与凭据过滤及启动恢复读盘上限（`portal.py`）：`sync_cert_trust()` 限制 `config.yaml <= 4 MiB`、过滤非字符串 SAN、经 `_clean_host_scalar` 清洗主机名并与 `sync_pin()` 统一强制 `allow_nan=False`；`drop_meter_totals()`、`restore_meter_user()` 与 `reconcile_meter_usage()` 校验字典与非空字符串 `user_id`，`legacy_used_bytes()` 拒绝非法 `uid` 与负用量；`prepare()` 二维码拦截 `<script`/`<foreignObject` 并全量 `allow_nan=False`；`_adopt_locked()` 拒绝纯空白或含控制字符的 `auth_password` 与 `session_secret` 并强制 `allow_nan=False`；`recover_xray_service_on_start()` 限制 `xray.json <= 4 MiB` 并校验顶层字典，`repair_missing_api_key()` 补齐 `allow_nan=False`。
- 防火墙 `nftables` 区分 `drop` 与 `accept` 放行、ACME 签发对校验与自签失败透传及卸载目录防误删守卫（`install.sh`）：`setup_system_firewall()` 校验 `nft` 族/表/链合法标识符且 `_nft_has()` 必须匹配含 `accept` 的放行规则，修复已有 `drop` 规则被误判为已放行的漏洞；`setup_acme_certificate()` 校验 Nginx/DNS 返回的证书对含 `|` 且证书与私钥文件非空存在，退回自签失败改为透传返回 `1`；`uninstall_all()` 为 `$HY2_DIR` 与 `$AWG_DIR` 增加防误删系统根目录守卫，并跳过 `acme-*.crt` 符号链接且容错 `head -n 1`。
- 前端出站防重入与空编辑、BBR 与流量轮询 `401` 停轮询、AWG 命名正则对齐与弹窗容错及登录显隐判空（`portal_assets.py`）：`setOutboundMode()` 与出站删除在弹窗确认后补齐二次防重入，`obEls.btnSave` 入口判 `disabled`，出站编辑容错脏元素且 `!found` 早退；`checkBbrStatus()` 与 `pollTrafficSpeed()` 遇 `401` 均置位 `portalSessionExpired = true` 终结用户页 2 秒死循环请求（前者并隔离算法映射原型链键）；`renderAwgPeers()` 为 `decodeURIComponent` 包裹 `try/catch`；`btnAddAwgPeer` 命名正则收紧为 `/^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$/` 并校验 `!confTab.closed` 与 `json && json.ok`；`LOGIN_SCRIPT` 的 `toggleSecret()` 判空 `btn`。
- 混淆隧道服务端渲染防换行注入与溢出、`peer-add` 命名对齐、状态取首行及操作锁防符号链接截断（`awgctl.sh`）：`render_server_config()` 收紧 `port` 为 `^[1-9][0-9]{0,4}$`、`s4v` 为 `^[0-9]{1,5}$`、拒绝含空白或控制字符的 `server_private_key`/`HeaderProtectionKey`、清洗 `wan` 注释控制字符、校验混淆参数纯数字并在 `jq` 校验 peer `.address` 四段 `0..255` 无前导零；`cmd_peer_add()` 命名正则收紧为 `^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$` 并校验从 `meta` 回落的 `endpoint`；`cmd_status()` 版本解析加 `exit` 仅取首行；`acquire_lock()` 拒绝符号链接并改用 `umask 077; exec 9>>"$lock_file"` 避免截断目标文件。
- Xray 计量配置超长数字、脏出站与符号链接防护及计量核心空白 `epoch` 与控制字符拦截（`usage-meter-xray-config-20261007-v1.py`、`usage-meter-core-20261007-v1.py`）：Xray 计量配置新增 `_read_regular_config_bytes()`（`lstat()` 拒绝符号链接、目录、非常规文件与 `> 4 MiB`），`_validate_loopback_address()`、`_client_level_key()` 与 `_inbound_uses_port()` 限制数字长度防超过 4300 位触发整数转换崩溃，`add_iplimit_routing()` 先过滤非字典脏出站；`usage-meter-core` 的 `apply_sample()` 拒绝含空白 `epoch`、含控制字符 `sampled_at`/`uid` 及非字典 `adjustments`。
- 撤权入参过滤、流量数字上限、服务状态编码与防选项注入、时钟回拨免疫、GOST 端口去重与自检落盘 `fsync`（`portal.py`）：`apply_access()` 过滤 `force_ids` 中的非字符串/非法元素并拒绝标量字符串拆字符；`node_traffic_counters()` 限制 `/proc/net/dev` 字节列为纯 ASCII 且长度 `<= 24` 位防超长或全角数字异常；`_unit_active()` 拒绝非字符串、空白/控制字符及 `-` 开头参数，与 `gost_status()` 同步补齐 `encoding='utf-8', errors='replace'`；`save_meter_data()` 与 `_remote_root_shas()` 改用 `0 <= now - last < interval` 免疫时钟回拨（后者并校验 7~64 位十六进制 SHA 并规整小写）；`write_gost_config()` 限制端口串长度 `<= 16` 并对重复端口去重；`write_gost_selfcheck()` 补齐 `flush`/`fsync` 并隔离清理 `OSError`。
- SVG 二维码防 XSS 校验、登录登出 Cookie 路径防注入及 `capabilities`/`bbr-status`/`_ob_list` 读盘上限与编码守卫（`portal.py`）：新增 `_is_safe_svg_payload()` 统一覆盖用户 `qr.svg`、用户页内嵌 `qr_svg`、`awg-qr.svg` 与管理员 `qr.svg` 四处出口，拦截 `<script`、`<foreignObject`、`javascript:`、内联事件处理器及超大体积；新增 `_safe_cookie_path_token()` 加固登录与登出 `Set-Cookie` 路径并清洗 `Location` 控制字符；`/api/v1/capabilities`、`_h_get_bbr_status()` 与 `_ob_list()` 读取 `xray.json`/`99-bbr.conf`/`config.yaml` 时统一拒绝符号链接并施加体积上限与 `errors='replace'`，同时为 `systemctl`/`sysctl` 补齐 UTF-8 替换解码、`PORTAL_VERSION` 解析剥除行内注释及过滤非字符串 `bbr_target_version`。
- 面板接入防 3xx 重定向泄露令牌/符号链接/深层 YAML 同名键与路径穿越及证书链脚本安全备份与回读校验（`panel-join.py`、`fix_cert_chain.sh`）：`panel-join.py` 的 `read()` 改用 `os.lstat()` 拒绝符号链接与非常规文件，`parse_simple_yaml()` 限定顶层一级子缩进防止深层同名键覆盖 `masquerade.listenHTTPS`，`--panel` 校验主机合法性并拒绝 `..` 路径穿越段、`--name` 限长 256 字符，新增 `_NoRedirectHandler` 与 `_open_no_redirect()` 禁止自动跟随 3xx 重定向防泄露管理员 JWT 与节点 `api_key`；`fix_cert_chain.sh` 规范化前导 `-` 路径防选项注入、拒绝符号链接主配置、改用 `mktemp` 创建 0600 备份防符号链接覆写、写盘后新增回读一致校验不符即自动回滚并收紧 `Verify return code: 0` 边界正则。

## 2026-11-22 — 第五十八批十项修复，门户 2.68

- 伪装端口段限定与超长数字、AnyTLS/TUIC 重置超时隔离、出站去重与限流时钟回拨（`portal.py`）：`read_masquerade_port()` 施加 `4 MiB` 读盘上限、限定仅在顶层 `masquerade:` 段内解析且限制端口数字 `<= 16` 位；`apply_anytls_config()` 强制 `allow_nan=False` 并将正向与回滚 `systemctl reset-failed` 超时独立隔离避免跳过 `restart`；`normalize_route_rules()` 按 `(domain, outbound)` 保序去重，`render_egress_config()` 校验字符串入参；`check_rate_limit()`、`login_rate_limited()` 与 `record_login_failure()` 改用 `0 <= now - t < window` 免疫系统时钟回拨并限制失败记录内存上限，`_web_source_key()` 容错 `headers=None`；`_singbox_version()` 校验 `binary` 合法性与数字长度。
- 版本号解析防超长与全角数字、单元坏编码容错、四协议直链控制字符清洗与小数配额拦截（`portal.py`）：`core_version_key()` 与 `_version_tuple()` 拒绝非字符串、全角及超长数字，`_xray_version()` 校验 `binary` 与纯 ASCII 限长；`xray_unit_foreign()`、`gost_owned()` 与 `ensure_gost_unit()` 容错 `UnicodeDecodeError`（`ensure_gost_unit` 同步补 `fsync`）；`vmess`/`anytls`/`tuic`/`vlessenc` 四协议直链拒绝空/非字符串 `user_id`、剥离标签控制字符并拦截脏 `secret`；`user_access_denial()` 拒绝小数 `limit_bytes`/`used_bytes`（防止 `0.5` 被截断成 `0` 无限流量）与非有限/布尔 `now`。
- 混淆隧道 CIDR 地址冲突防护、损坏 `peers.json` 容错、安装参数预检、混淆参数位数与清理陷阱（`awgctl.sh`）：`peers_init()` 补 `RETURN` 清理陷阱；`peer_exists()` 容错损坏 `peers.json` 避免打断 `set -e`；`next_peer_address()` 在 `jq` 中用 `split("/")[0]` 剥离 CIDR 掩码彻底堵死 `.2/32` 冲突；`cmd_install()` 入口前置校验 `--client` 与 `--server-name`；`cmd_install()` 与 `cmd_update()` 限制混淆参数 S1~S4 为 1~5 位防 64 位整数溢出，`cmd_update()` 统一改用 `awg_transaction_on_exit`。
- 前端核心状态原型链键隔离、`probeOutbound`/`awgPost` 401 与非串 IP 及用户弹窗类型防护（`portal_assets.py`）：`renderCore()` 用 `Object.prototype.hasOwnProperty.call` 隔离 `CORE_STATE_TEXT` 原型链键（`constructor` 等）并过滤 `used_by` 空脏项；`probeOutbound()` 与 `awgPost()` 遇 `401` 置位 `portalSessionExpired` 给出中文登录过期提示（前者同步拦截非字符串 `ip`）；`loadCores()`/`installCore()`/`uninstallCore()` 补 `401` 置位与判空；用户连接弹窗拦截布尔 `traffic_limit`/`ip_limit` 与非法 `expires_at` 防止渲染异常文本。
- 安装脚本 acme 目标目录防误删、Nginx/DNS 签发拒裸 IP、邮箱防注入、IPv6 原子去行与凭据控制字符拦截（`install.sh`）：`hy2_acme_install_verified()` 入口增加 `$home` 防误删系统目录守卫；`setup_cert_via_nginx()` 与 `setup_cert_via_dns_api()` 排除纯数字末段裸 IPv4；`setup_cert_via_nginx()` 拒绝以 `-` 开头或含空白/控制字符的邮箱并用同目录临时文件原子去 IPv6 替代非原子 `sed -i`；`setup_cert_via_dns_api()` 拦截含控制字符的各家 DNS API 凭据防污染 `account.conf`。
- `sing-box` 压缩包多层穿越/特殊文件/`armhf`、VLESS 密钥生成校验、分流域名、`outbounds` 空数组与 ACL 去重（`portal.py`）：`install_singbox()` 循环剥离多层 `./` 堵死 `././/etc/passwd`、拒绝控制字符/冒号盘符与 FIFO/设备节点并补充 `'armhf': 'armv7'`，与 `install_xray_binary()` 同以 `O_CREAT|O_EXCL|O_NOFOLLOW` 安全写暂存文件并隔离 `finally` 清理异常；`generate_vless_encryption_pair()` 校验 `binary` 与 `VLESSENC_ENCRYPTION_RE` 并将子进程异常转为 `RuntimeError`；`_valid_route_domain()` 限长 253 并拒边缘连字符；`upsert_outbound_block()` 正确展开 `outbounds: []` 内联空数组；`build_acl_block()`/`build_warp_acl_config()` 去重重复规则并过滤脏 `existing_names`。
- 重装脚本整数防溢出、网络配置格式校验、镜像主机防注入与符号链接防护（`alpine2debian.sh`、`reinstall-debian13.sh`）：两份脚本均前置拦截前导零与超长位数 `SWAP_MB`（`reinstall-debian13.sh` 同步限 `PORT <= 5` 位、`RELEASE <= 2` 位），并新增纯 POSIX `sh` 的 `valid_iface()`/`valid_ipv4()`/`valid_cidr()` 在第 3 步抽取网络配置后即刻校验防脏配置致重装后失联；`alpine2debian.sh` 校验提取的 `DNS_HOST` 防选项注入并在写 chroot 临时脚本与密码文件前 `rm -f` 防符号链接覆盖；`reinstall-debian13.sh` 的 `init_log()`/`log_line()` 拒绝符号链接防覆写系统文件、二次体积复核补齐 `2 MiB` 上限与符号链接检查，随机密码生成补空/过短显式报错。
- Reality 直链清洗、端口限长、订阅脏凭据拦截、刷新与合并状态类型守卫及 SNI 清洗（`portal.py`）：`reality_uri_for_user()` 拒绝空/非串/纯空白/含控制字符 `user_id` 并剥离 `label` 控制字符；`_valid_port()` 限制数字串长度 `<= 16`；`artifacts()` 统一清洗 `user_id` 并拒绝纯空白或含控制字符的 AnyTLS/TUIC `secret`；`_refresh_portal_state()` 自愈缺失或非法 `token` 与纯空白/控制字符 `session_secret`，全部落盘序列化强制 `allow_nan=False`；`merge_cli_owned_state()` 守卫密钥与派生资源非空字符串及机主密码/到期类型；`_generate_and_apply_reality()` 经 `_clean_host_scalar` 清洗 `dest_sni`、用 `_valid_port` 收集避让端口并初始化子进程句柄安全解析公钥。
- 安装脚本邮箱防注入、公网 IP 多源回退与保留段过滤、域名解析防注入、端口本地列匹配与自愈防护（`install.sh`）：`is_valid_email()` 禁止本地部分以 `-` 开头防选项注入；`get_public_ip()` 将 0~255 段值与私有/回环/多播保留段（`>= 224`）校验移入多源循环，单一源返回非法或回环 IP 时自动回退尝试下一源；`resolve_domain_ips()` 拒绝空串、前导 `-` 与空白/控制字符并在 `getent`/`host` 加 `--`；`port_owner()` 内联端口校验并改用 `awk` 仅精确匹配 `ss -H` 第 4 列本地端口；`select_local_certificate()` 拒绝前导零编号防八进制报错并改用 `-nameopt multiline` 提取 CN；`setup_portal()` 补 `RETURN` 清理陷阱与 `umask 077`，`setup_cert_selfheal()` 拦截含控制字符证书路径。
- 计量运行时 `max_age` 与缺口缓存隔离、脏用户键与非法 `epoch` 早退、旧值清洗及配置防符号链接（`usage-meter-runtime-20261007-v1.py`）：`_source_fresh()` 校验 `max_age` 为有限正数；`_recent_gaps()` 容错非字典容器并对缓存命中返回元素级深拷贝防止外部篡改污染全局缓存；`PortalMeter.poll()` 在锁外拦截非法/含空白控制字符 `epoch`、跳过空串或非字符串脏 `uid` 防拖死整批采样事务、清洗写入 `legacy_auth_value` 的损坏 `used_bytes`、校验 `on_speed` 的 `interval`/`pair` 并在 `except` 兜底容错非字典 `self.data`；`configured_sources()` 与 `_measurement_total()` 补类型与空串守卫；`from_file()` 改用 `lstat()` 拒绝符号链接与非常规文件。

## 2026-11-22 — 第五十七批十项修复，门户 2.67

- 活跃拦截防永封、限流器时钟回拨、踢人脏值过滤、设备上限防崩与启动自愈（`portal.py`）：`active_ip_deny()` 拦截非字符串 `uid`/`ip` 与 `NaN`/`Infinity` 过期时间防止制造永久幽灵封禁；`AuthLimiter._prune()` 在检测到系统时钟回拨（`now < items[0]`）时主动清理未来时间戳并防护非有限 `now` 与不可哈希 `key`；`kick_hy2_users()` 过滤非字符串 `uid` 并拒绝裸字符串防止被拆成单字符逐个踢出；`plan_reality_iplimit()` 清理非有限时间戳并修复 `tuple` 型 `blocked[ip]` 原地赋值崩溃，`reality_iplimit_rules()` 过滤脏键值；`persist_interrupted_core_job()` 强制 `allow_nan=False` 自动清洗非有限浮点；`serve()` 启动拒绝前导零端口并自动重建含空白、控制字符或非 ASCII 的损坏 `api_key`。
- 压缩包多层穿越防护、备份清理跳符号链接、会话与请求体超长数字 DoS 及异常日志脱敏（`portal.py`）：`safe_tar_members()` 与 `safe_zip_members()` 循环剥离多层 `./` 堵死 `././/etc/passwd` 路径穿越，并拒绝控制字符、冒号盘符与空成员名；`_prune_core_backups()` 跳过符号链接、隔离单条 `OSError` 并保底 `keep >= 1`；`hysteria_asset_arch()` 补充 `'armhf': 'armv7'` 映射并容错非字符串；`verify_session()` 限制 `issued_at` 最长 12 位无前导零彻底堵死 Python 3.11+ 超 4300 位数字触发 `ValueError` 的拒绝服务漏洞并拦截损坏 `expected_token`；`handle_one_request()` 异常日志剥离查询串 `?k=...` 与控制字符防密钥泄露及日志注入；`do_POST()` 拦截超 10 位 `Content-Length` 数字直接返回 `413`。
- 安装脚本端口跳跃前导零、证书元数据空摘要与多字段 CN 及安装重配锁重挂（`install.sh`）：`setup_iptables_port_hopping()` 将端口正则收紧为 `^[1-9][0-9]{0,4}$` 并为 `_ipt_unit_tmp` 补齐 `RETURN` 清理陷阱；`generate_server_config()` 为 `_cfg_tmp` 补齐 `RETURN` 清理并在写 `toggle_warp.sh` 前防符号链接；`sync_cert_meta()` 改用 `-nameopt multiline` 精确提取 CN、排除空 DER 的 SHA256（`e3b0c442...`）、写盘前断言 JSON 对象并补齐 `RETURN` 清理；`flow_install()` 与 `flow_reconfigure()` 在 `setup_ports_and_obfs` 与 `generate_server_config` 后重挂 `_lock_trap` 防止全局单槽 `RETURN` 陷阱被覆盖。
- 前端代理链接解析/自动命名/表单校验、用户表单 401/错误截断及升级刷新锁（`portal_assets.py`）：`obParseLink()` 与 `obTestForm()` 拒绝前导零端口（后者同步判空 DOM 元素）；`obAutoName()` 修复 HTTP IPv6 代理名在首个冒号处截断的问题；`obSuggestName()` 确保追加数字后缀后总长永不超过 32 字符；`submitUserForm()` 遇到 `401` 给出中文登录过期提示并置位 `portalSessionExpired`，优先提取 JSON `error` 并对原始错误文本截断 200 字符防止 502 HTML 撑爆弹窗；`doUpgrade()` 用 `hasOwnProperty` 校验目标键并在安排页面刷新期间保持 `_busy` 锁不提前放开防止并发二次升级。
- 混淆隧道网卡校验、选口避跳跃段、事务恢复、下载校验与卸载防误删（`awgctl.sh`）：`detect_wan_iface()` 严格校验网卡名正则并拒绝 `.`/`..` 防 `/sys/class/net/..` 误判与规则注入；`pick_port()` 强制跳过 Hysteria 2 端口跳跃区间 `20000..40000`、限定合法端口范围并对超长 `hy2_port` 安全免疫；`awg_transaction_restore()` 校验 `service-state` 存在并对非法 `AWG_TRANSACTION_DIR_MODE` 安全回退 `700`；`download_binaries()` 解析 `SHA256SUMS` 忽略注释并循环剥离多层 `./`，同时循环剥离 `tar` 成员多层 `./` 拦截 `././/etc/passwd` 与控制字符；`cmd_uninstall()` 仅对合法端口收回防火墙并为 `rm -rf "$AWG_DIR"` 增加根目录与系统顶层目录防误删守卫（兼容 Windows 单测盘符路径）。
- 系统服务回滚隔离、端口与防火墙校验、流量停用补偿、凭据恢复与密码查重（`portal.py`）：`_restore_systemd_service_state()` 校验单元名与字典快照、独立隔离 `systemctl reset-failed` 超时不跳过 `restart`，且原状态非 `active` 时接受 `failed` 回滚结果；`protocol_port_in_use()` 与 `firewall_port()` 统一采用零外部依赖严格端口校验，拒绝 `0`、`Inf`/`NaN`、小数与前导零并消除 `OverflowError`；`suspend_state()` 去重保序并清洗非有限 `since`，`_set_traffic_suspension(True)` 在落盘失败补偿时仅拉起本次确实从运行态停掉的服务，绝不误拉已停用服务；`ensure_portal_access()` 拦截含冒号或控制字符的损坏凭据并规整非字符串 `token`/`api_key`；`password_taken()` 拒空/非字符串密码并改用常量时间比对。
- 面板接入脚本读盘上限/超长端口/非 ASCII 凭据/域名校验与证书链脚本加固（`panel-join.py`、`fix_cert_chain.sh`）：`panel-join.py` 的 `read()` 施加 `4 MiB` 读盘上限；端口数字串长度限制 `<= 16` 防止 Python 3.11+ 超长数字崩溃；`api_key` 与 `--admin-token` 拒绝非 ASCII 与空白字符防 HTTP 头编码异常；`_safe_host()` 与 `acme_first_domain()` 拒绝 `..`、前导连字符与超 253 字符脏域名并全量 `allow_nan=False`；`fix_cert_chain.sh` 的 `n_certs()` 排除注释行证书头、`restore_config_file()` 补 `RETURN` 清理陷阱、`masq_https_port()` 兼容 `mawk` 并在保留剥离前导零契约的同时限制数字长度防超长数字、`cert_sni()` 改用 `-nameopt multiline` 并消毒非法 SNI。
- 计量核心非法用户标识/空白时代与读取器密钥、超长数字、地址及布尔计数加固（`usage-meter-core-20261007-v1.py`、`usage-meter-readers-20261007-v1.py`）：`total_bytes()` 与 `adjusted_bytes()` 拒绝空串与不可哈希 `uid`，`apply_sample()` 拒绝空 `uid` 及空白或含控制字符的 `epoch`；`_validate_loopback_http_base()` 拒绝非 ASCII `secret` 与含空白/控制字符 URL；`parse_xray()` 拒非文本入参并限制数字串长度 `<= 30`；`_norm_ip()` 与 `_addr_ip()` 拒非字符串入参且限制端口数字 `<= 5` 位防超长整数 DoS；`parse_events()` 拒非序列入参并限时间戳长度 `<= 30`，`confirmed_ips()` 严格要求非布尔非负整数 `count` 走 fail-closed。
- 前端标签选择器防注入、`obApi` 401/空响应、重启刷新锁、复制清理与用户表容错（`portal_assets.py`）：`switchTab()` 前置白名单校验 `tabId`/`subId` 且先确认目标存在再移除旧激活状态，杜绝非法哈希抛选择器异常并清空页面；`obApi()` 遇 `401` 置位 `portalSessionExpired` 给中文过期提示并容错 JSON `null`；`waitPortalBack()` 校验超时与间隔边界并兼容无 `AbortController` 环境，`btnRebootServer` 触发页面刷新前保持禁用防止重复重启；`copyWithFeedback()` 与复制兜底将隐藏 `textarea` 移除放进 `finally`；`initUserTable()` 容错缺失 `data-search` 的行。
- 安装脚本下载回退防 `pipefail`、复用证书去引号注释、Caddy 域名清理、续期定时器原子写与 AWG 首客户端守卫（`install.sh`）：`install_binary()` 下载站回退分支补齐 `|| resolved=""`，修复 `set -eo pipefail` 下双源失败直接中途退出跳过报错的缺陷；`reuse_existing_cert_config()` 解析 `tls`/`acme` 段时正确剥离单/双引号与行尾注释并兼容 Tab 缩进；`setup_cert_via_existing_caddy()` 增加零外部依赖内联域名校验（拒绝前导连字符、纯数字末段 IP 与超 253 字符）、挂 `RETURN` 临时文件清理陷阱并为备份名加 `.$$`；`hy2_acme_ensure_renew_timer()` 拒含空白/控制字符/引号的 `home` 并经同目录 `mktemp` 原子写入 `.service`/`.timer`；`install_amneziawg()` 校验首个客户端名称合法性，并在未填连接地址时不再追加 `--client`。

## 2026-11-22 — 第五十六批十项修复，门户 2.66

- 证书指纹空路径误判、订阅产物控制字符剥离、用户列表脏值规整与初始化密码校验（`portal.py`）：修复 `sync_pin()` 在 `_resolve_live_cert` 返回空路径 `''` 时因 `Path('').exists()` 为真而误把当前目录当作证书文件跳过回落 `get_cert_pin_sha256` 的缺陷，改为显式判非空且为普通文件；`artifacts()` 剥除 `name_override`/`password`/`obfs_password` 中的控制字符并为 Clash/Sing-box 序列化强制 `allow_nan=False`；`users_list_entry()` 规整布尔、非有限浮点与非法字符串类型的到期时间/配额/用量/创建时间及状态；`prepare()` 拒绝 `client_meta.json` 中含控制字符的 `auth_password`。
- GOST 重载超时兜底、代理配置清洗、Xray 事务前置校验、证书自愈防非标准 JSON 与远端摘要清洗（`portal.py`）：`reload_gost()` 将 `systemctl reload` 与 `systemctl reset-failed` 各自包入独立异常隔离，防止偶发超时跳出外层导致 `restart` 兜底被跳过；`write_gost_config()` 拒绝前导零端口字符串、剥除代理账号密码控制字符并强制 `allow_nan=False`；`apply_xray_config_transaction()` 入口校验 `binary` 合法性（拒空/控制字符/连字符开头）、强制 `allow_nan=False` 并隔离 `finally` 临时文件清理异常防吞掉原始错误；`sync_cert_runtime()` 入口拦截 `None` 证书路径，与 `record_cert_heal()` 共同过滤旧状态中的 `NaN`/`Infinity` 写出严格 JSON；`_remote_root_shas()` 过滤非字符串 `name`/`sha` 并返回缓存副本。
- 升级引用解析回退、IP 拦截入参校验、API 鉴权长度/空白限制、状态落盘防非有限浮点与 `iplimit` 校验（`portal.py`）：`resolve_update_ref()` 拒绝非字符串 `ref` 并把 GitHub API 返回的 `{"sha": null}` 规整为空串以正常回落 `commits/main.atom`；`parse_ip_deny()` 严查字典请求体、字符串 `user_id`/IP 项及有限数值 `now`；`verify_api_key()` 增加 `1024` 字节请求头上限并拒绝含空白或控制字符的持久化 `api_key`，与 `is_authenticated()` 共同容错 `None` 请求头；`_prepare_save_payload()` 强制 `allow_nan=False` 并自动将脏非有限浮点清洗为 `null`；`reality_iplimit_worker()` 前置校验 `binary` 合法性并捕获 `Path.is_file()` 异常避免反复误清在线状态。
- 前端三大列表竞态序号防覆盖、弹窗确认后二次防重入与 SVG 二维码安全过滤（`portal_assets.py`）：为 `loadOutbounds()`、`loadProxyServices()` 与 `loadAwgState()` 补齐零外部依赖的函数自挂序号 `_seq`，丢弃早发慢回旧响应，并对 `loadOutbounds()` 强制数组类型清洗；为五大协议开关（Reality/VMess/VLESS Encryption/AnyTLS/TUIC）、重置 Reality 密钥以及 `installCore()`/`uninstallCore()` 全部补齐确认弹窗返回后的二次 `disabled` 校验，杜绝弹窗期连点双发；六处前端 `qr_svg` 渲染点统一叠加 `<svg` 前缀校验并拦截 `<foreignObject` 与 `on*=` 事件属性。
- 安装脚本精确证书链计数、校验清单解析对齐、占位页防注入与端口前导零拒绝（`install.sh`）：`pem_cert_count()` 改用 `tr -d '\r' | grep -cx -- '-----BEGIN CERTIFICATE-----'` 精确计数并前置文件可读校验，避免将证书签名请求或注释误计入证书链；`hy2_manifest_sha256()` 先剥前导空白再判注释行并循环剥除多层 `./` 与门户侧对齐；`hy2_fetch_manifest()` 补充 `--max-filesize 2097152` 上限；`caddy_decoy_directives()` 清洗 `$domain` 剔除反引号与 HTML 特殊字符防破坏 Caddyfile；`select_subscription_port()` 两段内嵌端口扫描拒绝前导零端口字符串。
- 计量运行时窗口/标识/配置体积防护与 Xray 计量配置严格 JSON 及清理隔离（`usage-meter-runtime-20261007-v1.py`、`usage-meter-xray-config-20261007-v1.py`）：`_parse_iso_utc_ts()` 补首尾去空白并兼容小写 `z`；`_recent_gaps()` 校验 `window_seconds` 为有限正数防止传入 `NaN` 令近期缺口被静默抹除；`configured_sources()` 与采集器对齐拒绝含控制字符或连字符开头的 `binary`；`summary()`/`hot_summary()`/`_measurement_total()` 安全处理不可哈希或非字符串 `uid`；`from_file()` 施加 `2 MiB` 体积上限；`enable_iplimit_routing()` 与 `enable_reality_online()` 强制 `allow_nan=False` 并隔离 `finally` 临时文件清理 `OSError`。
- 混淆隧道双端端点校验对齐与 `meta_set`/`peer_list`/`qr`/`awg_rand` 加固（`awgctl.sh`、`portal.py`）：`awgctl.sh` 的 `validate_endpoint()` 与 `portal.py` 的 `awg_endpoint_error()` 双端对齐拒绝超 253 字符域名并保持 5 位十进制端口兼容（`awg_endpoint_error` 同时拦截非字符串输入）；`cmd_peer_list()` 表格模式 `@tsv` 将非字符串字段规整为空串防 `jq` 崩溃；`meta_set()` 拒绝非对象顶层 JSON 并补 `mktemp` 失败检查与 `RETURN` 清理陷阱；`cmd_qr()` 先捕获配置渲染成功再交 `qrencode`；`awg_rand()` 前置校验非负整数上下界。
- 重装系统脚本整盘边界、挂载前缀精确匹配、镜像主机提取、密码控制符拦截与脚本上限（`alpine2debian.sh`、`reinstall-debian13.sh`）：两份脚本的 `is_whole_disk()` 显式拒绝空串、`.`、`..`、`/` 及含斜杠设备名；`disk_mounts()` 改用纯字符串前缀加数字后缀比对，消除设备名含 `.` 时拼入 `awk` 正则引发的通配误命中；`alpine2debian.sh` 提取 `DNS_HOST` 正确剥离端口与 IPv6 方括号，且在清盘前拦截含控制字符的 `ROOT_PWD` 防止 `chpasswd` 中断；`reinstall-debian13.sh` 的 `installnet_looks_valid()` 补充 `2 MiB` 上限校验与 `curl` 限流对齐。
- 管理页与用户分享页 HTML 属性转义、SVG 脚本拦截与非字符串入参容错（`portal.py`）：`user_page_html()` 严格校验 `qr_svg` 以 `<svg` 开头并拦截 `<script`、`<foreignObject` 与 `on*=` 事件属性，对下载文件名 `uid`、链接 `token`/`user_key` 与 `obfs_badge` 全面转义并容错非字符串 `uri`/`clash`/`sing`/`host`；`page_html()` 对全部 4 处表单/属性中的 `token`、`user_key` 及 API 凭据展示字段做安全转义并过滤非字符串 `uid` 与非字符串入参，彻底杜绝属性逃逸与脏参数引发的 500。
- 解锁读取截断、测速参数隔离、仓库拉取路径校验、`ensure_awgctl` 句柄回收与升级模块判空（`portal.py`）：`_unlock_read()` 对 `IncompleteRead.partial` 强制按 `limit` 截断并拦截非正上限；`_ping_one()` 前置拒绝以 `-` 开头或含控制字符的 `host` 并添加 `--` 参数分隔符；`_fetch_repo_file()` 与 `_remote_blob_sha()` 严格校验 `filename` 合法性防路径穿越与查询串注入（后者同步校验 `ref`）；`ensure_awgctl()` 在 `finally` 中安全关闭未移交的临时文件描述符；`_h_post_do_upgrade_impl()` 的 `reality-online` 分支判空 `spec`/`spec.loader` 并返回清晰中文 500 提示。

## 2026-11-22 — 第五十五批十项修复，门户 2.65

- 跨函数 `RETURN` 陷阱覆写治理与全仓清理陷阱自清（`install.sh`、`awgctl.sh`）：修复 Bash 全局单槽 `RETURN` 陷阱在调用同样注册 `RETURN` 陷阱的子函数后被静默清空的隐患；`portal_ensure_py` 在 `portal_fetch_py` 后重挂清理陷阱、`setup_cert_via_nginx` 将陷阱注册移至 `hy2_acme_ensure` 之后、`flow_install`/`flow_reconfigure`/`uninstall_all` 在跨子函数调用后重挂锁释放陷阱，并为 `install.sh` 与 `awgctl.sh` 全部局部 `RETURN` 陷阱统一补齐 `trap - RETURN;` 自清，防止泄漏核心锁句柄与临时目录。
- 五大协议状态接口二维码/端口/脏字段清洗、版本检查死线与代理快照隔离（`portal.py`）：`_h_get_vmess_status`、`_h_get_anytls_status`、`_h_get_tuic_status`、`_h_get_vlessenc_status` 与 `_h_get_reality_status` 统一拦截含 `<script` 的二维码 SVG、经 `_valid_port` 规整端口防非法 `Infinity`/`NaN`、清洗非字符串与含控制字符脏字段，并为 AnyTLS/TUIC 直链生成增加异常容错；`_h_get_check_version` 补齐 45 秒死线续期；`_h_get_proxy_services` 在锁内浅拷贝字典条目并过滤非字典脏项。
- 五大协议、WARP 安装与代理管理持久化异常统一返回 `503` 及代理删权/证书名加固（`portal.py`）：修复 `_h_post_manage_reality`、`_h_post_manage_vmess`、`_h_post_manage_anytls`、`_h_post_manage_tuic`、`_h_post_manage_vlessenc` 与 `_h_post_install_warp` 外层异常将 `AtomicWriteDurabilityError` 吞为 `500` 的缺陷，统一返回 `503`；`_manage_proxy_operation` 删除遇持久化不确定时仍尝试 `reload_gost()` 撤权并返 `503`、新增代理拦截含 `<script` 二维码并剥除备注控制字符；`_h_post_manage_reality` 的 `reset` 捕获读盘 `OSError` 并隔离 `systemctl is-active` 超时，`_vmess_certificate` 过滤非字符串 SAN/CN 防排序抛 `TypeError`。
- 前端 WARP 规则脏项过滤与防双击、BBR/证书/版本竞态序号与非有限天数防护（`portal_assets.py`）：`renderWarpRules` 先判 `Array.isArray(rules)` 并过滤缺失非空字符串域名的脏项防表格崩溃；`addWarpRule`/`delWarpRule` 增加并发防双击锁并兼容反代非 JSON 错误页；`checkBbrStatus`、`checkCertStatus` 与 `checkVersions` 均以零外部依赖自挂序号丢弃晚到旧响应；`checkCertStatus` 严格校验 `expires_in_days` 有限数值与 `healed_at` 有效时间戳并过滤非字符串 SAN，杜绝渲染绿色假正常与 `NaN` 日期。
- 计量采集器端口地址/`binary` 路径与输出上限校验及核心 `active_users` 拦截（`usage-meter-readers-20261007-v1.py`、`usage-meter-core-20261007-v1.py`）：`_validate_loopback_xray_addr` 与 `_addr_ip` 严格校验无前导零合法 `1..65535` 端口；`read_xray` 与 `read_live_connections` 统一拒绝空值、控制字符及以 `-` 开头的非法 `binary` 路径并捕获 `Path.is_file()` 异常防止炸毁整机 Hy2 在线 IP 快照，同时为 Xray 在线查询响应施加 `8 MiB` 上限并校验 `uid`；`apply_sample` 拦截 `active_users` 中不可哈希或非字符串元素并转为 `ValueError`，拒绝延续非有限 `baseline_at`。
- 混淆隧道服务端/客户端配置防换行注入、缺服务端公钥拦截与 `update` 密钥校验（`awgctl.sh`）：`render_server_config` 补齐 `RETURN` 清理陷阱并在 `jq` 中过滤含换行/控制字符的密钥/地址及清洗 `.name` 防注入 `awg0.conf`；`render_client_config` 拦截空 `server_public_key` 与含换行密钥并跳过空 `PresharedKey`；`cmd_update` 跨协议线生成 3.x `HeaderProtectionKey` 补齐非空校验；`awg_atomic_install_bin` 施加 `umask 077`。
- 迁移证书空 SHA256 假匹配修复、系统防火墙前导零拦截及 WARP/GOST 下载限流（`install.sh`）：`setup_certificates` 迁移复用分支先校验非空普通文件并验证提取出的原始公钥非空且排除空输入 SHA256；`setup_system_firewall` 将端口正则收紧为 `^[1-9][0-9]{0,4}$` 拦截前导零端口；`install_warp_local_proxy` 与 `install_gost` 全部下载 `curl` 补齐 `--max-filesize` 上限且临时目录施加 `umask 077`。
- 门户 `reply_json` 禁 `NaN`/`Infinity`、`reply` 防 CRLF 注入、`awg_state` 清洗与状态接口死线（`portal.py`）：`reply_json` 强制 `allow_nan=False` 并在遇到非有限浮点时自动递归清洗为 `null` 输出合法 RFC 8259 JSON；`reply()` 过滤非法 `extra_headers` 头名并剥离头值中的 CR/LF/NUL；`awg_state()` 经 `_valid_port` 清洗端口并过滤损坏 `endpoint` 与脏 peer 条目；`_h_get_warp_status` 与 `_h_get_cert_status` 补齐 30 秒死线续期并清洗非字符串错误/域名字段。
- 面板接入脚本主机/段限定与参数校验及证书链修复脚本精确 PEM 计数（`panel-join.py`、`fix_cert_chain.sh`）：`panel-join.py` 的 `_safe_host` 拦截非 IPv6 含冒号脏主机并规范化 IPv6，回退解析 `listenHTTPS` 严格限定在顶层 `masquerade:` 段内不跨段误抓，同时拒绝含空白 `api_key` 与含控制字符 `--name`；`fix_cert_chain.sh` 的 `n_certs` 精确匹配 `-----BEGIN CERTIFICATE-----` 防把 CSR 误算为证书，`leaf_pub` 排除空 SHA256，`set_tls_cert` 补齐 `RETURN` 清理陷阱与空路径拦截。
- REST 用户停用立即踢断 Hy2 在线会话、更新深拷贝快照、代理列表快照与损坏门户令牌拦截（`portal.py`）：修复 `POST /api/v1/users/set_status`（`active=false`）与 `POST /api/v1/users/update`（`status='disabled'`）停用用户后仅同步 Xray 却漏踢 Hysteria 2 活跃会话的问题，立即调用 `_kick_old_password_sessions` 断开在线连接；`users/update` 仅在无冲突时构造深拷贝响应快照；`GET /api/v1/proxy-services/list` 在锁内浅拷贝字典条目并过滤脏项；`do_GET` 与 `do_POST` 入口拒绝含控制字符或斜杠的损坏门户 `token` 并返回 `503`。

## 2026-11-22 — 第五十四批十项修复，门户 2.64

- 门户 REST 用户删除持久化异常保撤权、开户脏旧额容错与续费全角流量拦截（`portal.py`）：修复 `POST /api/v1/users/delete` 遭遇 `AtomicWriteDurabilityError` 时直接抛出 `500` 并跳过 `apply_access([user_id])` 踢人撤权的高危缺陷，改为保留已替换磁盘状态、跳过 `regenerate_page()`、继续执行撤权并返回统一 `503`；`users/create` 容错历史记录中非有限/布尔 `used_bytes`（防 `OverflowError`）与损坏 `limit_bytes`（防响应前除法 `TypeError`），并将 `{"note": null}` 规范化为空串而非 `'None'`；`users/renew` 拒绝全角数字 `add_traffic_gb`；`/api/v1/*` 入口拒绝重复与全角 `Content-Length`。
- 网页用户管理与 BBR 落盘持久化异常返回 `503`、全角配额拦截与 `O_NOFOLLOW` 写入（`portal.py`）：修复 `_h_post_manage_user` 遇 `AtomicWriteDurabilityError` 跳过 `_sync_reality_clients()` 撤权的问题，改为仍同步协议状态并返回 `503`；开户拒绝全角 `duration_days`/`ip_limit`/`traffic_gb`、剥除 `note` 控制字符并容错重名记录的非有限 `used_bytes`；`_set_bbr_locked` 拒绝重复与全角 `Content-Length`，`_write_bbr_file` 叠加 `O_NOFOLLOW` 防符号链接替换并刷盘父目录，落盘持久化不确定时返回 `503`。
- 安装脚本前导零端口回收防崩溃、卸载域名与符号链接防穿越及核心升级清理陷阱（`install.sh`）：修复 `close_replaced_ports` 与 `close_installer_ports` 中 `jq` 遇前导零端口字符串（如 `"08443"`）时 `tonumber` 报错致 `in_use` 为空进而误删在用防火墙端口的问题，改为正则 `^[1-9][0-9]{0,4}$` 与 `1..65535` 校验并将 `grep -qx` 改为 `grep -qxF`；`uninstall_all` 对 `nginx_domain` 增加零依赖内联域名校验并在删除 `99-hysteria2.conf` 与 `bbr.conf`/`99-bbr.conf` 前拒绝符号链接；`flow_update_core` 注册 `RETURN` 清理陷阱统一释放锁文件描述符与回滚暂存目录。
- 分享页与 `user-config` 脏节点身份拦截、有限到期过滤与二维码防脚本注入（`portal.py`）：修复 `GET /<tok>/u/<uid>` 与 `GET /<tok>/user-config` 因 `clean_node_identity` 自动回落 `'www.bing.com'` 导致空/含控制字符 `server_name`/`public_ip` 逃逸返回 `200` 并输出假链接的问题，改为直接经 `_clean_host_scalar` 校验原始字段非空；前置非法子路径返回 `404` 避免浪费生成 `artifacts()`；`user-config` 过滤非有限 `expires_at` 防输出非法 JSON 并净化非字符串 `note`；分享页、弹窗与附加链接卡片统一拦截含 `<script` 的二维码并容错非字符串 `label` 与非字典用户信息。
- 前端代理服务列表脏项与原型键隔离、用户弹窗二维码净化及 AWG 防双击（`portal_assets.py`）：`loadProxyServices` 过滤 `null`/非对象脏项防表格渲染崩溃，并用 `safeTypeClass ? typeLabel[safeTypeClass] : ...` 隔离 `type='constructor'` 原型链键碰撞；`showProxyResult` 白名单清洗 `proxy-type` 类名并拦截含 `<script` 的二维码；用户连接弹窗拦截含 `<script` 的 `qr_svg` 并容错脏 `extra_links`；`renderAwgPeers` 过滤缺失字符串 `name` 的脏条目防渲染幽灵删除按钮；为代理删除与 AWG 客户端删除按钮补齐防双击禁用保护。
- Xray 计量配置非字典入口拦截、重复规则/黑洞去重、`binary` 路径校验与客户端不变式（`usage-meter-xray-config-20261007-v1.py`）：`add_iplimit_routing` 与 `api_rule_first` 在非字典入参时显式抛出 `ValueError` 而非 `AttributeError`；`api_rule_first` 去重所有重复 `API_RULE` 保持首条唯一，`add_iplimit_routing` 去重重复 `iplimit-block` 出站保持唯一非首位 `blackhole`；新增 `_validate_binary` 在 `enable_iplimit_routing` 与 `enable_reality_online` 入口拒绝空值、控制字符及以 `-` 开头的非法路径；`enable_reality_online` 补齐入站客户端列表不变式校验。
- 出站全局模式与 WARP 覆盖可渲染口径统一、持久化不确定返 `503` 及请求体长度加固（`portal.py`）：彻底统一 `apply_egress_config`、`_ob_manage`（切换全局出站、删除出站降级、新增分流规则校验）与 `_h_get_warp_status`（`overridden` 标记）的可渲染出站口径；`_ob_manage` 与 `_h_post_manage_warp` 遇 `AtomicWriteDurabilityError` 返回明确 `503`；`_ob_manage`、`_ob_probe` 与 `_h_post_manage_warp` 拒绝重复与全角 `Content-Length`；`apply_egress_config` 隔离父目录刷盘 `OSError` 避免虚拟文件系统误触发回滚。
- 混淆隧道裸 IPv6 端点自动补方括号、脏 `peers.json` 防删不掉客户端与密钥非空校验（`awgctl.sh`）：`render_client_config` 为不含端口的裸 IPv6 `endpoint` 自动补全方括号输出 `[addr]:port`；`cmd_peer_del` 与 `cmd_peer_add` 归一化 `.peers` 数组并过滤非对象脏元素，修复单个脏条目导致 `jq` 报错删不掉合法客户端的问题；`cmd_client_conf` 与 `cmd_qr` 统一补齐 `first(...) // empty` 防止同名多条拼接出换行；`cmd_peer_add` 与 `cmd_install` 校验新生成的私钥与公钥非空。
- 证书配对空 SHA256 假匹配阻断、Web 证书扫描防词分割及门户整包安全落盘（`install.sh`）：修复 `_cert_key_usable` 在证书与私钥提取公钥均失败返回空串时因空输入 SHA256 相等而假匹配通过的隐患；`find_cert_in_webserver` 前置域名正则防穿越并改用 `while IFS= read -r` 逐行读取候选路径消除空格与通配符词分割；`portal_ensure_py` 为暂存目录施加 `umask 077`、挂 `RETURN` 清理陷阱并在整包替换后刷盘父目录；`backup_state_before_reconfigure` 淘汰旧快照时跳过符号链接。
- 全仓剩余 POST 处理函数请求体长度解析统一加固（`portal.py`）：将 `/auth`、`_h_post_do_upgrade_impl`、`_h_post_manage_proxy`、`_h_post_install_amneziawg`、`_h_post_manage_amneziawg`、`_h_post_manage_reality`、`_h_post_manage_vmess`、`_h_post_install_core`、`_h_post_uninstall_core`、`_h_post_manage_anytls`、`_h_post_manage_tuic`、`_h_post_manage_vlessenc` 与 `_h_post_login` 共 13 处剩余裸 `int(self.headers.get('Content-Length', 0))` 全部替换为零外部依赖的严格长度解析，统一拒绝重复头、全角数字、带符号数字与越界长度并在拒绝时不读取请求体，全仓裸 `Content-Length` 整型强转彻底清零。

## 2026-11-22 — 第五十三批十项修复，门户 2.63

- 计量缺口缓存浅拷贝、数值时间戳容错与脏用户列表隔离（`usage-meter-core-20261007-v1.py`、`usage-meter-runtime-20261007-v1.py`、`usage-meter-readers-20261007-v1.py`）：`_recent_gaps` 与 `_source_fresh` 兼容有限数值时间戳、拦截 `NaN`/`Inf` 并返回缓存浅拷贝防外部就地篡改；`summary()` 清洗非字典 `health` 与异常 `online_devices`；`apply_sample` 仅跳过 `sampled_users` 中的单个脏元素而保留全部合法用户；`service_epoch` 补充 `errors='replace'`，`parse_events` 捕获 `OverflowError` 转为 `ValueError`。
- 节点标识与备用协议订阅控制字符清洗及二维码/初始化校验（`portal.py`）：新增 `_clean_host_scalar` 拦截非字符串、控制字符与内部空白并应用于 `clean_node_identity`、`reality_uri_for_user` 及 `artifacts()` 四大备用协议（`vmess`/`vlessenc`/`anytls`/`tuic`）；`clean_hop_range` 拒绝前导零端口；`reality_uri_for_user` 容错非字符串 `label`；`prepare()` 校验非空 `auth_password` 且 `prepare()`/`qr_svg_for()` 统一校验 `b'<svg'`。
- 沿用端口校验、门户凭据损坏自愈、CLI 状态合并守卫与测速解析加固（`portal.py`）：`_adopt_locked` 复用 `_valid_port` 拒绝小数与全角数字；`ensure_portal_access` 在 `username`/`password` 缺失或非字符串时重建凭据防写坏 `auth_hash`；`merge_cli_owned_state` 容错非字典入参并守卫核心关键键不被坏值覆盖；`restore_egress_into_config` 改用 `_renderable_outbounds`；`_ping_one` 补充 `encoding='utf-8', errors='replace'`、收紧往返时延正则并校验 `math.isfinite`。
- 前端出站与核心列表脏项过滤、网速原型键隔离与防双击保护（`portal_assets.py`）：`obMetaOf`、`renderOutboundList` 与 `renderOutboundRules` 过滤 `null`/非对象/非数组脏输入防止渲染崩溃与写出 `'null'` 幽灵规则；`renderCore` 与 `loadCores` 兼容非数组 `used_by` 与非对象条目；`pollTrafficSpeed` 使用 `Object.prototype.hasOwnProperty.call` 隔离原型链键（如 `constructor`/`toString`）并校验 `Number.isFinite`；`btnRebootServer` 与 `btnRecheckUpdate` 补齐防双击，`LOGIN_SCRIPT` 对 `btn.parentElement` 判空。
- 混淆隧道脏 `peers.json` 过滤防 IP 碰撞与空私钥渲染及防火墙前导零拦截（`awgctl.sh`）：`render_client_config`、`peer_exists` 与 `next_peer_address` 过滤 `peers.json` 中的非对象脏条目，避免单个坏元素导致 `next_peer_address` 崩溃回退重复分配已占用 `.2` 地址碰撞或生成 `PrivateKey = null`，同时校验配置端口合法性；`allow_firewall`/`revoke_firewall` 拒绝前导零端口；`write_service` 补充 `umask 077` 与 `RETURN` 清理；`pick_port`/`validate_endpoint` 补充 `python3 -I` 隔离与纯 ASCII 端口范围校验。
- 托管协议直链字段与标签容错、端口挑选防溢出及布尔到期拦截（`portal.py`）：`protocol_host_sni` 复用 `_clean_host_scalar` 拦截控制字符与空白；`vmess_uri_for_user`、`vlessenc_uri_for_user`、`anytls_uri_for_user` 与 `tuic_uri_for_user` 清洗损坏的 `ws_path`/`encryption` 并容错非字符串 `label`；`pick_tuic_port` 与 `_pick_reality_port` 复用 `_valid_port` 防止 `float('inf')` 抛出 `OverflowError` 并拒绝小数/全角数字；`user_access_denial` 拦截布尔型 `expires_at` 并返回 `'Invalid user record'`。
- Nginx 与 DNS 签发域名校验、证书非空回滚、自愈脚本原子落盘与端口范围校验（`install.sh`）：`setup_cert_via_nginx` 与 `setup_cert_via_dns_api` 前置内联域名正则校验防路径穿越与 Nginx 配置注入，补全证书与私钥非空落地校验、失败回滚、`umask 077` 及 `RETURN` 清理；`setup_cert_selfheal` 改用同目录原子临时文件替换 `/usr/local/bin/hy2-cert-selfheal.sh` 并挂 `RETURN` 清理；`setup_systemd` 拒绝符号链接 `99-hysteria2.conf` 并挂 `RETURN` 清理；`enabled_protocol_ports` 校验 `1..65535` 端口范围。
- 门户本地与订阅端口避让计量/托管端口及消除 CI 端口偶发冲突（`install.sh`、`tests/test_sub_port_avoids_managed.py`）：`select_subscription_port` 订阅端口保留集补充 `19996/19997` 并改用 `with open()`；`PORTAL_LOCAL_PORT` 分配同步避开保留/计量/WARP 端口、`20000-40000` 跳跃区间与 `portal.json` 已登记托管端口；`setup_ports_and_obfs` 前置拦截含控制字符的 `AUTH_PASSWORD` 与非法 `NODE_API_KEY`；修复 `test_sub_port_avoids_managed.py` 硬编码 `45002` 与系统临时端口撞车导致的持续集成偶发失败。
- POST 请求体长度严格解析、`/auth` 方括号 IPv6 后缀校验、限流键防日志注入与能力接口清洗（`portal.py`）：`Handler.do_POST` 拒绝重复 `Content-Length` 头及全角/带符号/非纯 ASCII 长度并返回 `400`；`/auth` 校验方括号 IPv6 后尾缀必为空或合法无前导零 `:1..65535` 端口，拒绝 `[2001:db8::1]garbage` 畸形后缀；`auth_rate_key` 兜底剥除控制字符防止日志伪造注入；`GET /api/v1/capabilities` 续期连接死线（45 秒）并清洗 `node` 与四大备用协议中的非字符串或含控制字符脏字段。
- 分流 ACL 防注入、不可哈希目标容错、出站严格渲染与悬空全局出站防护（`portal.py`）：`_renderable_outbounds` 经 `validate_outbound` 严格过滤不可安全写入 YAML 的损坏出站；`build_acl_block` 与 `build_warp_acl_config` 复用 `_valid_route_domain` 阻断换行/括号/双点域名注入、容错不可哈希 `outbound` 并清洗非法 `tail_outbound`；`normalize_route_rules` 仅接受合法字符串域名并净化异常 `outbound`；`routing_state` 与 `render_egress_config` 容错非字典输入，并在全局模式下所有自定义出站均损坏不可渲染时自动降级为 `rules` 模式，彻底杜绝生成指向不存在出站的悬空 `global` ACL 导致服务重启失败。

## 2026-11-22 — 第五十二批十项修复，门户 2.62

- 重装系统脚本默认路由关键字解析、扇区数值清洗与私密受限下载（`reinstall-debian13.sh`、`alpine2debian.sh`）：提取默认路由改为按 `dev`/`via` 关键字定位，修复带 `proto static` 等字段时错抽网卡或网关导致重装失联；清洗 `/sys/block/*/size` 扇区值防空值或非数字触发算术崩溃；`alpine2debian.sh` 增 `/dev/nvme0n1` 磁盘探测、跳过无匹配 `*` 网卡并通过位置参数 `$1` 安全传入 `dd` 镜像路径；`reinstall-debian13.sh` 下载脚本施加 `umask 077` 与 `curl --max-filesize 2097152`。
- 门户更新死线顺序、核心更新线程失败回滚与版本/Reality 接口防御（`portal.py`）：`_h_post_do_upgrade_impl` 的 `target=='awg'` 将 `self._extend_deadline(480, heavy=True)` 移到 `ensure_awgctl(force=True)` 之前避免下载期被 30 秒死线截断；`target=='core'` 捕获工作线程 `start()` 异常并立即落盘恢复状态，防止 `core_upgrade` 永久卡死在 `running`；`_h_get_check_version` 忽略非字符串 `tag_name`，`_h_get_reality_status` 校验 `<svg` 与 `_valid_port`。
- 核心卸载多单元停服超时回滚与四大域名协议非字符串域名清洗（`portal.py`）：`_h_get_cores_status` 补 `self._extend_deadline(45)`；`_h_post_uninstall_core` 捕获初始 `is-enabled` / `disable --now` 超时以触发完整多单元回滚，并隔离回滚与收尾阶段 `daemon-reload`/`reset-failed` 超时不阻断二进制清理；VMess、VLESS Encryption、AnyTLS 与 TUIC 启用路径安全清洗非字符串 `server_name`。
- 出站写锁回滚快照缩窄、探测死线、缺失 `sysctl` 降级与登录口令校验（`portal.py`）：`_ob_manage` 将 `previous_egress` 回滚快照下沉至各分支实际写锁内，杜绝校验或落盘失败回滚冲掉并发修改；`_ob_probe` 补 `self._extend_deadline(45)`；`_h_get_bbr_status` 统一经 `_sysctl_read` 隔离缺失 `sysctl` 或超时降级返回 `200`；`_h_post_login` 拦截空或含控制字符的异常 `portal_token` 并返回 `503`。
- 核心二进制升级标签校验与受限流下载、GOST 证书自动回退与解锁协议白名单（`portal.py`）：`_upgrade_core_binary_locked` 校验远端 `tag` 格式防路径穿越、改用 `_copy_stream_bounded` 限流下载并补齐 `armhf`/`armv7` 架构映射；`gost_tls_paths` 容忍损坏 UTF-8 的 `config.yaml` 并支持 `fullchain.pem` 自动回退匹配 `privkey.pem`；`_write_private_bytes` 叠加 `O_NOFOLLOW`；`_unlock_fetch` 拦截非 `http`/`https` 方案防止误触发 `file://` 读取。
- 门户启动顶层对象与端口校验、超额停用逐单元隔离、死线参数防护与退出信号防重入（`portal.py`）：`serve()` 启动前校验 `portal.json` 顶层必为对象且经 `_valid_port` 校验规整监听端口；启动重放超额停用逐单元隔离 `systemctl stop` 超时并过滤非法或以 `-` 开头的脏单元名，杜绝首单元超时导致其余协议漏停；`ThreadingHTTPServer.extend_deadline` 拦截布尔、非正与 `NaN`/`Inf` 秒数防逃逸看门狗；`_h_get_cert_status` 过滤非字符串 `sans`/`common_name`；`_flush_and_exit` 增加重入保护并同时注册 `SIGTERM` 与 `SIGINT`。
- 节点流量读盘容错、速率采样有限性、在线 IP 快照安全与 GOST 凭据净化（`portal.py`）：`node_traffic_counters` 捕获 `/proc/net/dev` 读盘 `OSError` 优雅降级；`_meter_speed_sample` 拒绝 `NaN`/`Inf`/布尔/负数采样防止污染实时速率快照；`live_online_ips` 校验快照结构与有限数值 `sampled_at` 并过滤非字典条目，避免热加载计量异常拖垮 `/auth`；`reality_iplimit_worker` 原地容错损坏 `usage-meter-config.json` 并校验模块 `spec` 非空；`write_gost_config` 复用 `_valid_port` 拦截小数端口并将非字符串账号密码净化为空串。
- 前端出站 IPv6/端口校验、探测竞态序号、协议二维码 SVG 净化与防双击加固（`portal_assets.py`）：`obParseLink` 与 `obTestForm` 完整支持 `[IPv6]:port` 并严格校验端口 `1..65535`；`probeOutbound` 引入请求序号丢弃晚到旧响应；`submitUserForm`、`obTestForm` 及出站删除/规则增删按钮补齐防重入与防双击禁用保护；五大协议状态卡片二维码渲染统一校验合法 SVG 并拦截 `<script>`；`waitForEgressApply` 遇 `portalSessionExpired` 立即中止，`waitForCoreUpgrade` 容错非对象响应。
- 安装脚本下载体积上限、私有原子替换与缺失密钥 `trafficStats` 段自愈（`install.sh`）：`install_binary`、`portal_fetch_files`、`portal_remote_blob_shas`、`portal_fetch_py` 与 `awg_fetch_ctl` 统一为 `curl` 补齐 `--max-filesize` 上限，私有临时文件与目录统一使用 `umask 077` 并挂 `RETURN` 清理；`awg_fetch_ctl` 改用同目录暂存 `mv -f` 原子替换并校验 API 返回必为 JSON 对象；`portal_write_meter_config` 内联 Python 补齐 `-I` 隔离、拒绝符号链接配置，并在已有 `trafficStats:` 段但缺失/损坏 `secret` 时自动就地补齐。
- 出站 YAML 换行注入阻断、坏条目空段防护与 AnyTLS/TUIC 配置校验（`portal.py`）：`_yaml_scalar` 剔除控制与换行字符，`render_outbound_yaml` 严格按白名单校验 `direct.mode` 阻断 YAML 注入；新增 `_renderable_outbounds` 在 `upsert_outbound_block` 渲染前过滤缺少 `addr`/`url` 或含控制字符的损坏条目，全部被过滤时不再写出孤立空 `outbounds:` 段；`validate_outbound` 拒绝 SOCKS5 端口前导零与含 `/@?#` 脏主机；`build_anytls_config` 与 `build_tuic_config` 校验端口并清洗非字符串 `server_name`。

## 2026-11-22 — 第五十一批十项修复，门户 2.61

- 证书多域名 SAN 解析与损坏证书信任自愈防护（`portal.py`）：`_parse_cert_subject` 按逗号逐段剥离每一项 `DNS:` 前缀并忽略混排的 `IP Address:` 条目，修复多域名证书第二项起残留 `DNS:` 导致 `certificate_covers_domain` 匹配失败与 SNI 误漂移；`_config_tls_cert_path`、`_config_acme_cert_path`、`_find_cert_key` 与 `sync_cert_trust` 捕获 `UnicodeDecodeError` 与未闭合引号 `ValueError`，`_find_cert_key` 剥离 YAML 行尾注释并跳过空值；`_is_dns_name` 拒绝非字符串与宽松 `www.bing.com` 前缀伪造；`sync_cert_trust` 在证书文件损坏或解析结果全空时跳过自愈避免破坏现有信任配置，并清洗非字符串 `server_name`/`public_ip`。
- 首页直渲染订阅凭据编码、在线 IP 同步与 GET 路由加固（`portal.py`）：`_render_index_page` 对首页订阅链接中的账号密码执行 `quote(..., safe='')` URL 编码（与 `regenerate_page` 一致），并同步填充 `online_ips` 过滤无效非有限时间窗口，修复首页用户表在线 IP 数恒为 0 及与摘要不一致的问题；`subscription_userinfo` 兼容非字典输入，`subscription_profile_headers` 净化扩展名防响应头注入；`/api/v1/users/get/<uid>` 锁内深拷贝快照防并发序列化异常；分享页与 `user-config` 校验二维码含 `<svg`，`awg-conf`/`awg-qr.svg` 过滤非字符串脏 `endpoint`。
- 核心二进制受限流安装与 GOST 代理参数及异常回滚加固（`portal.py`）：新增 `_copy_stream_bounded` 受限流复制（归档上限 `160 MiB`、解压上限 `256 MiB`），覆盖 `install_xray_binary`、`install_singbox` 与 `_h_post_install_gost` 的下载与解压防异常流或压缩炸弹写爆磁盘；`install_xray_binary` 拒绝 zip 符号链接成员并改为流式直写暂存文件；`_h_post_install_gost` 拒绝不支持的 CPU 架构并隔离旧二进制探针、配置坏编码与 `is-enabled` 异常；`_manage_proxy_operation` 拦截全角/布尔端口及非字符串账号密码，并在 `reload_gost()` 抛异常时完整回滚。
- 前端升级、入站代理与 AWG 交互非 JSON 容错及 IPv6/SVG 防护（`portal_assets.py`）：`doUpgrade` 增并发锁防双击、兼容反代 502 非 JSON 页并同步更新状态文案；`showProxyResult` 为 IPv6 回退链接补方括号并拦截非 SVG 字符串写入二维码容器；`.btn-quick-proxy`、`btnInstallGost`、`[data-proxy-del]`、`.btn-user-connect` 与 `awgPost` 统一兼容非 JSON 错误页并展示 HTTP 状态码；`renderAwgPeers` 过滤空/非对象元素，AWG 表单操作按钮补齐防双击保护。
- 混淆隧道受限下载清理、前置 `jq` 依赖校验与损坏 `peers.json` 过滤（`awgctl.sh`）：`download_binaries` 在 `umask 077` 下建临时目录、注册 `RETURN` 清理陷阱并为 `curl` 增 `--max-filesize` 限制；`cmd_update` 在下载前前置调用 `require_jq`；`render_server_config` 校验 `meta.json` 端口范围 `1..65535`，并与 `cmd_peer_list`、`cmd_status`、`cmd_client_conf`、`cmd_qr` 统一过滤 `peers.json` 中的 `null`/非对象脏条目，防止写出非法 `awg0.conf`。
- ACME 账号配置原子替换、受限下载与防火墙端口回收加固（`install.sh`）：`hy2_acme_disable_auto_upgrade` 改为同目录 `umask 077 && mktemp` 原子 `mv -f` 替换，杜绝 `cat` 截断覆写损毁 DNS API 密钥；`hy2_acme_pin_commit`/`hy2_acme_tree_json`/`hy2_acme_fetch_verified` 补齐 `--max-filesize`，`hy2_acme_install_verified`/`hy2_acme_verify_existing` 设 `umask 077` 并挂 `RETURN` 清理；`hy2_acme_same_except_shebang` 拒绝符号链接目标；`close_replaced_ports` 与 `close_installer_ports` 兼容字符串端口、去重并拒绝倒置跳跃区间。
- Xray 计量配置异常客户端等级清洗、字符串/区间端口冲突检测与超时重试（`usage-meter-xray-config-20261007-v1.py`）：`add_stats` 与 `enable_reality_online` 规整 `client.level`，过滤 `null`/布尔/非法值避免污染 `policy.levels`；`add_stats` 识别字符串单端口及 `lo-hi` 端口区间冲突；`_restart_xray` 隔离 `systemctl reset-failed` 超时异常；`enable_iplimit_routing` 在 `lsrules` 探测超时时重试而非误回滚，两处事务暂存文件改用随机后缀并在替换后刷盘父目录。
- 节点面板接入脚本行内 ACME 域名解析与主机/畸形参数校验（`panel-join.py`）：`acme_first_domain` 支持 YAML 行内列表 `domains: [...]` 且严格匹配顶层 `acme:` 段避免前缀误认；`meta_host` 拦截含空白、控制字符及 `/\\@?#` 的非法主机名，`read` 遇目录或 `OSError` 优雅返回 `None`；收紧 `listenHTTPS` 回退正则防止 `:abc8443` 误抽端口；捕获畸形 IPv6 `--panel` 解析异常并拒绝纯空白 `--admin-token`。
- 证书链修复脚本 `masquerade` 段限定、空证书拦截与备份权限加固（`fix_cert_chain.sh`）：`masq_https_port` 限定仅在顶层 `masquerade:` 段内读取 `listenHTTPS` 防跨段误抓；证书不含有效 PEM 块（`COUNT < 1`）时直接报错退出不再误报「仅 1 张证书」；配置备份强制 `chmod 600`；`cert_sni` 与验证链路兼容无 `timeout` 命令环境并防 `pipefail` 异常中断。
- AWG 离线启停与重型死线续期顺序及空证书运行态防误重启（`portal.py`）：`_h_post_install_amneziawg` 严格校验纯 ASCII 端口、去前导零、拦截与已启用 TUIC UDP 端口冲突，并将 `self._extend_deadline(480, heavy=True)` 提到 `ensure_awgctl()` 之前；`_h_post_manage_amneziawg` 使 `start`/`stop`/`restart` 脱离 `ensure_awgctl()` 支持断网环境启停，其余重型动作先申请死线槽再拉取控制脚本；`selfheal` 校验普通文件且 `sync_cert_runtime` 拒绝为 0 字节截断证书触发全线服务重启。

## 2026-11-22 — 第五十批十项修复，门户 2.60

- `/auth` 与 `/api/v1/*` 请求体长度边界、裸 IPv6 完整解析与全角数字拦截（`portal.py`）：`/auth` 限制请求体长度 `0..65536` 并校验对象形态，优先直解析裸 IPv4/IPv6 地址避免无端口 IPv6 被 `rsplit(':')` 截断绕过跨节点设备黑名单，同时为 `ip_tracker` 过滤补齐 `math.isfinite`；`POST /api/v1/*` 限制请求体长度 `0..1048576` 防负长度绕过与大包内存耗尽，用户参数解析拒绝全角数字字符串。
- REST 用户删除并发回滚保护、退役用户还原与 API 密码控制字符拦截（`portal.py`）：`POST /api/v1/users/delete` 与 `_h_post_manage_user` 在落盘失败回滚时仅撤回当前用户的待撤销标记与单用户 `usage_meter.totals`/`adjustments`/`retired_users`，保留并发新增的其它待撤销用户与最新累计计量；`users/create` 与 `users/update` 统一拒绝含控制字符的密码并返回 `400`，`users/create` 补齐 `reconcile_meter_usage`/`restore_meter_user` 失败回滚，`users/ip-deny` 过滤补齐 `math.isfinite`。
- 端口跳跃参数校验与单元原子落盘、YAML 字段安全转义及纯 ASCII 端口解析（`install.sh`）：`setup_iptables_port_hopping` 内联校验监听与起止端口位于 `1..65535` 且起点不大于终点，防注入 `ExecStart`，并将 `hy2-iptables.service` 改为同目录 `mktemp` 原子落盘；`generate_server_config` 对 `SERVER_NAME`/`ACME_EMAIL`/`CERT_FILE`/`KEY_FILE` 经 `jq -Rn` 安全转义输出 YAML；`select_subscription_port` 校验端口字符串纯 ASCII 数字。
- 整机停用恢复 `reset-failed` 超时隔离、自更新脚本参数界限与出站纯 ASCII 端口校验（`portal.py`）：`_set_traffic_suspension` 在恢复启动与落盘失败补偿拉起中将 `systemctl reset-failed` 独立隔离，超时不再跳过 `systemctl start`；`portal_update_restart_script` 校验 `port`（`1..65535`）与 `wait_seconds`（`1..600`）并拒绝布尔值；`validate_outbound` 将 SOCKS5 端口正则收紧为 `[0-9]{1,5}` 拦截全角数字。
- 防火墙端口前置校验、无管道策略解析与门户文件身份映射过滤加固（`install.sh`）：`setup_system_firewall` 校验主监听、订阅端口与跳跃区间合法性，为 `ufw status` 补 `2>/dev/null`，并将裸 `iptables`/`ip6tables` 策略解析改为单次 `awk` 提取避免大输出 SIGPIPE；`portal_remote_blob_shas` 与 `portal_ensure_py` 在 `umask 077` 下创建临时文件与目录，并过滤非字符串 `sha` 与含空白/换行的异常 `name`。
- 计量核心退役用户坏累计清理与参数校验及运行时坏二进制路径容错（`usage-meter-core-20261007-v1.py`、`usage-meter-runtime-20261007-v1.py`）：`apply_sample` 拒绝误传字符串/字节串或非可迭代的 `active_users`，并先剔除清理已退役用户的残留脏 `totals` 再校验活跃用户，防止已删用户坏条目卡死全机计量；运行时 `configured_sources()` 捕获 `binary` 路径 `OSError`/`ValueError` 并拦截空字节，`summary()` 为采样时间补齐 `math.isfinite`。
- 混淆隧道控制脚本防火墙端口校验、peer 随机私密备份清理与自删参数安全传递（`awgctl.sh`）：`allow_firewall` 与 `revoke_firewall` 校验端口处于 `1..65535`；`cmd_peer_add` 与 `cmd_peer_del` 改为 `umask 077 && mktemp` 随机备份文件并注册 `RETURN` 清理陷阱杜绝明文私钥备份残留；`cmd_uninstall` 自删通过位置参数 `$1` 安全传递路径。
- 端口与跳跃区间纯 ASCII 校验、`artifacts`/`page_html`/`sync_pin` 非字典容错与 `prepare` 密钥校验（`portal.py`）：`_valid_port` 与 `clean_hop_range` 拒绝全角数字、正负号及非有限浮点；`artifacts`、`page_html` 与 `sync_pin` 入口容忍非字典 `client_meta` 避免 `AttributeError`；`prepare` 复用 `_valid_port` 并拒绝含空白、控制字符或非 ASCII 的 `node_api_key`。
- 前端 BBR、服务器重启、证书与核心管理非 JSON 错误页及坏字段容错（`portal_assets.py`）：`checkCertStatus`、`loadCores`、`btnRebootServer` 与 `.btn-apply-bbr` 兼容反代 502 等非 JSON HTML 响应并输出含 HTTP 状态码的清晰提示；`certShortIssuer` 与 `pin_sha256` 安全转字符串防非字符串字段崩溃；`.btn-apply-bbr`、`installCore` 与 `uninstallCore` 补齐防双击保护。
- 实时网速非有限与负速率过滤、伪装端口坏编码容错及出站替换前失败防误回滚（`portal.py`）：`_h_get_traffic_speed` 过滤 `NaN`/`Inf` 与负速率样本，确保响应始终为严格合法 JSON；`read_masquerade_port` 捕获 `UnicodeDecodeError` 并校验纯 ASCII 数字端口；`apply_egress_config` 仅在已 `os.replace` 替换配置后才触发 `_rollback_outbounds`，替换前写盘失败不再惊扰正在运行的服务，并在替换后刷盘父目录。

## 2026-11-22 — 第四十九批十项修复，门户 2.59

- 协议启停死线续期与 AnyTLS/TUIC 停用核心锁序及停服超时回滚（`portal.py`）：五大协议启停接口（Reality / VMess / VLESS Encryption / AnyTLS / TUIC）在持锁前补齐 `self._extend_deadline(120)` 防触发 30 秒连接死线；AnyTLS 与 TUIC 停用及回滚统一纳入 `core_operation_lock` 与跨进程文件锁 `core_operation_file_lock()`；`systemctl disable --now` 捕获超时与 `OSError` 并经 `_restore_systemd_service_state` 完整回滚。
- 沿用配置校验、页面重建凭据编码与 WARP 锁外探测（`portal.py`）：`_adopt_locked` 拦截布尔/越界端口及含空白、控制字符或非 ASCII 的 `node_api_key`；`regenerate_page` 安全读取 `token`、对订阅凭据做 `quote(..., safe='')` 编码并补充 `math.isfinite(t)` 过滤非有限时间；`restore_egress_into_config` 依据清洗后有效配置决定是否写回；`_h_post_manage_warp` 将 `warp_backend_installed()` 移出 `data_lock` 避免子进程阻塞鉴权。
- 门户与安装脚本双端 WARP 安装加固（`portal.py` 与 `install.sh`）：`atomic_write_mode` 叠加 `umask 077`；`tar_member` 增 `tar -tvzf` 校验拦截符号/硬链接、设备节点与反斜杠；`wgcf`/`wireproxy` 增加版本格式正则校验与随机 `mktemp` 暂存；`install.sh` 校验提取出的 `WG_PRIV`/`WG_PUB`/`WG_EP` 非空并将 `hy2-warp-watchdog.sh` 改为原子落盘。
- 归档安全扫描加固与借 Caddy 签发证书先验后原子替换（`portal.py` 与 `install.sh`）：`hy2_tar_listing_safe` 全面拦截符号/硬链接、设备节点、反斜杠与空归档；`setup_cert_via_existing_caddy` 增加合法域名格式校验，先在同目录候选文件上运行 `caddy validate --config "$cand" --adapter caddyfile` 校验通过再原子 `mv -f` 替换正式 `Caddyfile`，回滚同步改为原子替换。
- Xray 配置事务初始探针与 `reset-failed` 异常隔离及 `O_NOFOLLOW` 私有写盘（`portal.py`）：`apply_xray_config_transaction` 隔离初始 `is-active`/`is-enabled` 探测超时及启用/回滚阶段 `systemctl reset-failed` 超时异常，避免辅助清理失败触发误回滚或打断恢复；`_write_priv` 叠加 `O_NOFOLLOW` 防止临时路径符号链接覆写。
- 会话签验锁保护、Cookie 放大边界防护与重启接口命令探针（`portal.py`）：`sign_session` 在 `data_lock` 内原子读取 `session_epoch()`；`verify_session` 限制 `Cookie` 头总长不超过 `16384` 字节、最多验签前 `16` 个同名 `hy2_session` 候选防 HMAC CPU 放大，并对时间戳补充 `.isascii()` 拒绝全角数字；`_h_post_reboot_server` 先探测 `systemctl`/`reboot`/`/sbin/reboot` 可用性，缺失直接回 `500` 而不谎报 `200`，执行时通过 `exec "$@"` 安全传参。
- Xray 准入快照损坏容错、回滚异常保留与计量/保留端口防护（`portal.py`）：`_apply_xray_access_snapshot_locked` 容忍托管入站 `settings: null` 与非字符串 `binary`（回退 `/usr/local/bin/xray`），回滚写盘包裹独立 `OSError` 捕获避免磁盘满掩盖原始重启异常；`apply_xray_config_with_meter` 兼容非对象计量配置并严格校验回环纯 ASCII 端口 `1..65535`；`managed_reserved_ports` 拦截布尔端口及损坏 `config`/`inbounds` 元素防崩溃。
- 网页用户管理删除回滚并发保护与密码控制字符拦截（`portal.py`）：`_h_post_manage_user` 将回滚快照推迟至实际写锁内拍摄；删除落盘失败回滚时仅移除当前用户的待撤销标记并按单用户恢复 `usage_meter.totals`/`adjustments`，避免覆盖并发新增的其它待撤销用户与最新计量；新建用户拦截含换行/空字节等控制字符的密码并返回 `400`。
- 计量读取器纯 ASCII 端口与计数、方括号地址尾缀及在线时间戳边界加固（`usage-meter-readers-20261007-v1.py`）：`_validate_loopback_xray_addr` 与 `parse_xray` 补充 `.isascii()` 拦截全角数字绕过；`read_xray` 校验 `binary` 非空无空字节并限制标准输出上限 `8 MiB`；`_addr_ip` 校验方括号 IPv6 后尾缀必为空或合法 `:port`；`cmd` 使用 `errors='replace'` 防非 UTF-8 中断采集；Reality 在线 `seen` 时间戳拒绝负数、`NaN`/`Inf`、浮点与全角数字串。
- 前端五大协议开关失败恢复文案、空配置渲染防护与非 JSON 错误页提示（`portal_assets.py`）：Reality / VMess / VLESS Encryption / AnyTLS / TUIC 开关记录切换前文案，网络异常或状态刷新失败时自动还原不再永久卡在「切换中…」；`btnToggleReality` 补齐双击防护，与 `btnResetRealityKeys`、`obTestForm` 统一兼容反代 502 等非 JSON HTML 响应并输出含 HTTP 状态码的清晰错误；`checkVmessStatus` 与 `checkVlessencStatus` 提前判空 `json.config` 消除 `config: null` 引发的渲染异常。

## 2026-11-22 — 第四十八批十项修复，门户 2.58

- 出站探测协议与超时校验、WARP 旧端口回退及出站模式清洗口径统一（`portal.py`）：`detect_outbound_ip` 先于空白裁剪拦截控制字符、去重 `socks5://`/`socks5h://` 前缀并按白名单拦截非 HTTP(S)/SOCKS5 协议方案，拒绝布尔与非有限 `timeout`；`_ob_probe` 探测 WARP 19898 不可达时自动回退探测旧官方 `127.0.0.1:40000`；`routing_state`、`_ob_list`、`_ob_manage`、`_h_get_warp_status` 与 `apply_egress_config` 统一按 `clean_outbounds` 与合法 `rules`/`global` 模式判定，消除坏出站条目导致的模式与覆盖状态漂移。
- 证书运行态自愈损坏容错、缺失显式证书防护与启动恢复 Xray 异常隔离（`portal.py`）：`sync_cert_runtime` 拆分证书读取与 `cert-selfheal.json` 解析，状态文件损坏时降级重建而不阻断证书运行态重载；`record_cert_heal` 拒绝布尔与负 `heal_count`；`selfheal` 在 `config.yaml` 显式指向缺失证书时跳过 `sync_cert_runtime` 避免拿旧自签证书误重载；`recover_xray_service_on_start` 容忍入站 `settings: null` 并隔离 `systemctl` 超时与缺失异常，不打断门户启动。
- 代理删除防火墙误判、布尔端口/非对象配置防护与撤销队列并发合并（`portal.py`）：`_manage_proxy_operation` 删除代理回收防火墙时去除 `exclude_key='proxy_services'`，避免误关仍在运行的其余同端口代理；创建代理跳过历史布尔端口并将非对象 `xray.json` 置空；`apply_access` 落盘失败回滚 `_pending_revocations` 时合并锁外并发新增的待撤销项，杜绝待撤销用户丢失。
- 计量配置安全序列化与 `install_gost` 安全性与原子落盘加固（`install.sh`）：`portal_write_meter_config` 补写 `config.yaml` 后执行 `flush()` + `os.fsync()`，写出 `usage-meter-config.json` 改为经标准输入传密由 `python3` `json.dumps` 序列化并刷盘，修复含引号/反斜杠密钥写出非法 JSON 的问题；`install_gost` 增加 `GOST_LATEST` 版本格式校验、改用随机 `mktemp` 暂存并在替换前探针验证 `-V`，同时将 `gost.service` 改为原子落盘。
- 混淆隧道归档链接与反斜杠拦截、首次半写回滚清理及 `umask 077` 私有创建（`awgctl.sh`）：`download_binaries` 通过 `tar -tvzf` 拦截符号链接、硬链接、设备节点与反斜杠路径，解压后拒绝符号链接组件与 `VERSION`，备份目录与首次半写回滚清理孤儿二进制；`meta_set` 与 `awg_transaction_snapshot` 在 `umask 077` 下创建私有临时文件与快照目录。
- Xray 计量配置损坏段容错、ASCII 回环端口校验与 `O_NOFOLLOW` 落盘（`usage-meter-xray-config-20261007-v1.py`）：`_validate_loopback_address` 校验纯 ASCII 数字端口并拒绝前导零；`add_stats`、`add_iplimit_routing`、`api_rule_first`、`iplimit_routing_ready`、`enable_iplimit_routing` 与 `enable_reality_online` 全面容忍 `settings: null`/`policy: null`/`routing: null` 及非对象条目并返回清晰 `ValueError`；`_write_private_bytes` 叠加 `O_NOFOLLOW` 防临时路径符号链接覆写。
- 证书链修复脚本相对路径解析与面板接入脚本端口/凭据校验（`fix_cert_chain.sh` 与 `panel-join.py`）：`fix_cert_chain.sh` 按 `config.yaml` 所在目录解析相对 `tls.cert` 路径，在 `set_tls_cert`/`restore_config_file` 的 `mv` 失败时清理临时文件并拒绝含引号/反斜杠/换行的路径，回滚后复核服务是否真正拉起；`panel-join.py` 为全部端口校验补充 `.isascii()` 拦截全角数字，拒绝含控制字符的 `api_key` 及带内嵌账号密码的 `--panel` 地址。
- 鉴权限流防全局配额耗尽放大与 API 密钥/基础认证加锁容错（`portal.py`）：`AuthLimiter.limited` 优先校验单来源失败封禁上限，已封禁来源不再消耗 `global_requests` 配额防止拖死全节点合法用户；`verify_api_key` 与 `is_authenticated` 统一在 `data_lock` 内安全读取存储凭据，容忍缺失、非字符串及非 ASCII 脏值而不抛 `KeyError`/`TypeError`。
- Hysteria2 撤销统计接口回环端口、密钥与 `/online` 响应边界加固（`portal.py`）：`kick_hy2_users` 与 `_enforce_node_access_xray_hy2` 统一校验回环统计地址端口范围 `1..65535` 与无控制字符的非空 `secret`；`_enforce_node_access_xray_hy2` 经 `_read_bounded_bytes` 限长读取响应并严格校验 `/online` 为字典且在线计数为非布尔整数，避免 `KeyError`/`AttributeError` 与异常响应放大。
- 前端升级按钮超时恢复、安装按钮文案防覆写与代理样式类白名单（`portal_assets.py`）：`doUpgrade` 在面板重启等待超时后恢复按钮可点并切换为重试；`btnInstallWarp` 与 `btnInstallGost` 等待状态刷新且仅在未成功时恢复旧文案，避免 `finally` 覆写刷新后的状态文案；`loadProxyServices` 对 `proxy-type` 类名采用白名单过滤。

## 2026-11-22 — 第四十七批十项修复，门户 2.57

- 端口占用排除键与布尔端口防护及 BBR 状态缺失工具容错（`portal.py` 的 `protocol_port_in_use`、`firewall_port` 与 `_h_get_bbr_status`）：`protocol_port_in_use` 遵循 `exclude_key='proxy_services'` / `'anytls_config'` / `'tuic_config'` 避免自排冲突，拦截 `xray_config.inbounds` 非列表损坏，并与 `firewall_port` 统一拒绝布尔型 `port`（防 `int(True)` 误认端口 1）；`_h_get_bbr_status` 容忍 `99-bbr.conf` 非 UTF-8 损坏编码及精简系统缺失 `modinfo` 导致的 `FileNotFoundError`。
- Xray 一键安装停用护栏与门户初始化校验（`portal.py` 的 `_h_post_install_xray` 与 `prepare`）：`_h_post_install_xray` 在申领重型槽前拦截整机流量超额停用状态返回 409，并在 `data_lock` 内读取 `reality_config.port`；`prepare` 校验 `client_meta.json` 顶层必为 JSON 对象并拦截布尔与越界门户端口。
- Reality 启停状态持久化与保存失败回滚（`portal.py` 的 `_generate_and_apply_reality` 与 `_h_post_manage_reality`）：启用写入 `'enabled': True`，停用分支与 VMess / VLESS Encryption 对齐持久化 `data['reality_config']['enabled'] = False`，修复停用 Reality 后旧端口仍被 `protocol_port_in_use` 永久占用的缺陷，并在 `save_data()` 失败时完整回滚 Xray 配置与内存状态。
- AmneziaWG 启停死线续期与 BBR 应用落盘刷盘（`portal.py` 的 `_h_post_manage_amneziawg` 与 `_set_bbr_locked`）：AWG `start`/`stop`/`restart` 在等待 `awg_operation_lock` 前补齐 `self._extend_deadline(120)` 防撞 30 秒连接死线，且 `systemctl reset-failed` 隔离超时异常不阻断主操作；`_set_bbr_locked` 容忍 `modprobe` 缺失不阻断内核已内建 `tcp_bbr`，`_write_bbr_file` 自动建父目录并在替换前执行 `flush()` + `os.fsync()`。
- 流量计量运行时 UTC 时区修正、新建用户在线占位与坏源配置校验（`usage-meter-runtime-20261007-v1.py`）：`_source_fresh` 与 `_recent_gaps` 解析不带时区的 naive ISO 时间戳时默认按 UTC 处理，消除非 UTC 时区主机 8 小时偏移误判；`summary()` 对未出现在上轮 `live_snapshot` 中的新建用户返回完整标准不可用结构而非缺字段空字典 `{}`；`_read()` 拦截非字典源配置统一抛出 `ValueError`。
- REST 接口用户更新布尔/溢出校验、续费布尔存量防护与停用死线续期（`portal.py`）：`POST /api/v1/users/update` 拦截 `expires_at`/`ip_limit` 传入 JSON 布尔、浮点或非纯数字串并捕获 `OverflowError`；`users/renew` 拦截存量用户损坏的布尔 `expires_at`/`limit_bytes`；`node/suspend` 补齐 `self._extend_deadline(120)` 覆盖多单元启停耗时。
- 节点能力接口子进程去重与门户路由令牌加锁读取（`portal.py`）：`GET /api/v1/capabilities` 单次调用 `_singbox_version()` 与 `_bbr_now()` 消除重复子进程开销，并在端口非法时省略 `port` 键避免输出 `port: null`；`do_GET` 与 `do_POST` 统一在 `data_lock` 内读取门户令牌并在缺失或损坏时回 503。
- 专属分享路由防爆破、二维码降级图与端口清洗（`portal.py` 的 `u/<uid>`）：未鉴权密钥错误记入 `record_failure()` 限流桶并校验 `expected_k.isascii()`；`u/<uid>/qr.svg` 在 `qrencode` 缺失或输出异常时回退可读提示图 `QR_UNAVAILABLE_SVG`；渲染分享页复用锁内已读 `_portal_tok` 并经 `_valid_port` 清洗 `listen_port`。
- 主安装脚本重配置快照权限加固与订阅端口避让补全（`install.sh`）：`backup_state_before_reconfigure` 在 `umask 077` 下创建副本并收紧 `chmod 600`，旧快照淘汰改用内存数组彻底移除 `.snapshot-list-$$` 磁盘临时文件；`select_subscription_port` 将 `tuic_config` 与 `proxy_services` 全部端口纳入 `RESERVED` 避让集合。
- 重装脚本明文密码防泄漏与登录脚本判空（`reinstall-debian13.sh`、`alpine2debian.sh` 与 `portal_assets.py`）：`reinstall-debian13.sh` 自动生成随机 root 密码仅输出到终端不再经 `warn()` 写入持久化日志；`alpine2debian.sh` 写明文 `_rootpw` 前注册 `EXIT INT TERM` 清理陷阱防止中断残留；`LOGIN_SCRIPT` 的 `toggleSecret` 增加缺失元素判空。

## 2026-11-22 — 第四十六批十项修复，门户 2.56

- 核心升级候选刷盘、回滚异常隔离与核心锁描述符防泄漏（`portal.py` 的 `_upgrade_core_binary_locked` 与 `acquire_core_operation_lock`）：候选核心落盘后执行 `flush()` 与 `os.fsync()` 刷盘再替换；回滚阶段的 `tempfile.mkstemp` 与文件写入移入独立 `try` 块，避免磁盘写满掩盖原升级失败并跳过 `_restart_hy2()` 恢复；`acquire_core_operation_lock` 遇非 `BlockingIOError` 异常同样关闭 `lock_fd` 消除文件描述符泄漏。
- AnyTLS 配置应用回滚异常隔离（`portal.py` 的 `apply_anytls_config`）：将启动失败回滚阶段的旧配置删除（`unlink`）与恢复（`_restore_config_atomically`）包裹在独立异常捕获中，确保磁盘异常不掩盖原始启动失败且继续尝试重启恢复旧服务。
- sing-box 与 Xray 核心安装版本号校验、归档成员链接拦截与落盘刷盘（`portal.py` 的 `install_singbox` 与 `install_xray_binary`）：`install_singbox` 前置校验远端 `tag_name` 符合安全版本格式且不含 `..`，解压前遍历全部 tar 成员拦截路径穿越、反斜杠、空字节及符号/硬链接；两处核心二进制写入暂存文件后均执行 `flush()` 与 `os.fsync()` 刷盘再校验替换。
- 网页端 GOST 安装版本号校验、归档链接拦截、单元原子落盘与回滚完整度加固（`portal.py` 的 `_h_post_install_gost`）：远端 `tag_name` 经安全正则校验不合法即回退固定安全版；解压前全量拦截符号/硬链接与非法路径成员；暂存二进制与回滚文件写入均执行 `os.fsync()` 刷盘；`gost.service` 改用 `_atomic_write_text` 原子落盘；`restore_gost_assets` 单资产失败不早退，尽力恢复其余资产、内存数据与服务状态后再抛出异常。
- 引擎拉取同目录原子刷盘落盘、证书自愈状态容错与 Xray 单元编码自愈（`portal.py` 的 `ensure_awgctl`、`cert_status` 与 `write_xray_unit`）：`ensure_awgctl` 改在目标同目录创建临时文件并用 `os.fdopen` 写入、`os.fsync()` 刷盘、`os.replace` 原子替换且失败必清理临时文件（消除 `/tmp` 跨分区非原子覆写与残留）；`cert_status` 对 `healed_at`/`heal_count` 逐项校验并拒绝布尔值避免丢失 `last_pin`；`write_xray_unit` 捕获坏编码 `UnicodeDecodeError` 自动触发自愈覆写。
- 混淆隧道控制脚本渲染清理、MTU 下限钳位与原子落盘（`awgctl.sh`）：`render_server_config` 与 `render_client_config` 对损坏 `S4` 实施 `MTU >= 1280` 下限钳位；`render_server_config` 在 `umask 077` 下创建临时文件且渲染/落盘失败即刻删除含明文私钥的临时文件；`write_service` 与 `peers_init` 改为同目录 `mktemp` 原子替换；`peer_apply_live_add` 为预共享密钥临时文件增加 `umask 077` 与 `RETURN` 清理陷阱。
- 主安装脚本核心下载版本号校验与证书私钥原子落盘（`install.sh`）：`install_binary` 前置校验 `LATEST_TAG` 安全格式并用同目录随机 `mktemp` 替代固定 `${HY2_BIN}.new`；`setup_cert_via_dns_api` 在 `umask 077` 子壳内安装证书消除私钥 `0644` 暴露窗口；`generate_self_signed_cert` 改用 `umask 077` 同目录临时文件生成密钥与证书并双步校验后原子替换；`setup_acme_certificate` 修正未定义变量 `$acct` 为 `${HOME}/.acme.sh/acme.sh`。
- 归档成员反斜杠/空字节拦截、服务器死线看门狗锁外关闭与启动校验类型安全（`portal.py`）：`safe_tar_members` 与 `safe_zip_members` 拦截非字符串、反斜杠与 `\x00`；`ThreadingHTTPServer.claim_heavy` 二次加锁判重归还多余信号量防重型槽泄漏；`watch_deadlines` 改为锁内摘出超时连接、锁外执行 `shutdown` 并兜底异常防后台线程死亡；`serve()` 启动一致性检查改用 `config_section(data, k)` 容忍非字典配置。
- 前端纯 IPv6 代理链接修复、核心卸载按钮恢复与 BBR 空字段容错（`portal_assets.py`）：`loadProxyServices` 对纯 IPv6 主机补全方括号 `[host]` 并校验 `json.services` 为数组，修复纯 IPv6 节点列表展示与一键复制链接无法解析的缺陷；`uninstallCore` 在 `finally` 恢复按钮状态与原文字防永久灰显锁死；`checkBbrStatus` 对缺失的 `configured`/`current` 转字符串再调用 `.toUpperCase()` 避免空值报错覆盖整张卡片。
- 流量计量读取器回环地址与日志时间戳严格校验（`usage-meter-readers-20261007-v1.py`）：`read_hysteria`、`read_hysteria_online` 与 `read_live_connections` 统一经 `_validate_loopback_http_base` 拦截查询串、片段、userinfo、非法端口及含换行/空字节的 `secret`；`read_xray` 与在线统计经 `_validate_loopback_xray_addr` 严格校验 `127.0.0.1:1..65535` 防止参数注入；`parse_events` 在 `__MONOTONIC_TIMESTAMP` 为 `None` 时正确回退 `__REALTIME_TIMESTAMP` 并拦截布尔时间戳；`read_live_connections` 校验 `raw_ips` 仅含字符串。

## 2026-11-22 — 第四十五批十项修复，门户 2.55

- AnyTLS 与 TUIC 启用路径加锁与回滚键清理（`portal.py` 的 `_apply_anytls_enable` 与 `_apply_tuic_enable`）：将 `_apply_anytls_enable` 对 `data['anytls_config']` 的深拷贝移入 `data_lock`（数据锁）内部消除并发迭代隐患；`_apply_tuic_enable` 启用失败回滚时，若原无 `tuic_config` 则执行 `data.pop('tuic_config', None)` 而非残留空字典。
- 核心安装与卸载处理器参数前置校验与回滚隔离（`portal.py` 的 `_h_post_install_core` 与 `_h_post_uninstall_core`）：前置校验 `0 <= Content-Length <= 65536` 与合法核心名后再申领 `heavy=True` 重型槽，防止非法请求空占重型槽；卸载停服失败回滚循环逐单元隔离超时与子进程异常，避免首个单元恢复超时中断其余单元恢复，并统一兜底 500 错误格式。
- 流量计量核心非对象状态与非法采样时间拦截（`usage-meter-core-20261007-v1.py`）：`apply_sample`、`total_bytes` 与 `adjusted_bytes` 统一拦截非字典 `state` 抛出 `ValueError`；`apply_sample` 前置校验 `sampled_at` 为非空字符串或非布尔有限数字，拒绝 `None`、布尔值、空串及非有限数且不污染原状态。
- 全门户剩余五处表单长度校验清零与鉴权布尔时间戳过滤（`portal.py`）：`_h_post_manage_proxy`、`_h_post_install_amneziawg`、`_h_post_manage_amneziawg`、`_set_bbr_locked` 与 `_h_post_manage_user` 补齐 `0 <= Content-Length <= 65536` 拦截；`/auth` 两处 `ip_tracker` 过滤补齐 `not isinstance(t, bool)` 排除损坏布尔时间戳。
- 网页端安装 AmneziaWG 停用护栏与动态端口冲突校验（`portal.py` 的 `_h_post_install_amneziawg`）：整机流量超额停用期间返回 409 拒绝绕过停用启动服务；用户指定端口时额外读取 `client_meta.json`，提前拦截与 Hysteria2 主监听端口或自定义端口跳跃区间冲突的端口。
- 借 Nginx 签发证书原子落盘与核心操作锁/回滚备份加固（`install.sh`）：`setup_cert_via_nginx` 改为同目录 `mktemp` 原子写入 Nginx 验证站点配置，并将私钥安装与归属标记纳入 `umask 077`；`uninstall_all` 持锁后补充 `RETURN` 释放陷阱防中途退出漏锁；`flow_update_core` 在 `umask 077` 下创建核心回滚副本。
- 入站代理安装脚本原子落盘与 HTTPS 私钥权限保护（`install.sh` 的 `install_gost`）：自签 HTTPS 代理证书与私钥生成纳入 `umask 077` 并显式 `chmod 600`（消除此前 0644 暴露私钥窗口）；初始配置 `gost.yml` 与启动自检脚本 `hy2-gost-selfcheck` 改为同目录 `mktemp` 原子替换；归属标记在 `umask 077` 下创建。
- 四协议状态接口补齐死线续期（`portal.py` 的 `_h_get_vmess_status`、`_h_get_anytls_status`、`_h_get_tuic_status` 与 `_h_get_vlessenc_status`）：四个调用 `qrencode` 子进程的状态查询接口均补齐 `self._extend_deadline(30)`，与 Reality 状态接口对齐，避免低配机多并发下撞上默认 30 秒连接死线断连。
- 入站代理证书路径解析容错与 Reality 设备上限线程布尔时间戳过滤（`portal.py` 的 `gost_tls_paths` 与 `reality_iplimit_worker`）：`gost_tls_paths` 捕获 `shlex.split` 的未闭合引号 `ValueError` 并校验备用自签证书/私钥非空字节；`reality_iplimit_worker` 过滤 `ip_tracker` 排除布尔时间戳并复用单次时钟扫描黑名单。
- Xray 配置事务回滚三步独立隔离（`portal.py` 的 `apply_xray_config_transaction`）：将配置恢复、开机自启恢复与服务启停恢复拆分为三段独立异常处理，确保写盘失败不掩盖原始启动错误，且 `systemctl enable/disable` 超时不跳过后续服务恢复。

## 2026-11-22 — 第四十四批十项修复，门户 2.54

- 在线更新处理器四重加固（`portal.py` 的 `_h_post_do_upgrade_impl`）：校验 `Content-Length` 处于 `0..65536` 拦截负值或超大正文防止读取阻塞；`reality-online` 分支前置 `self._extend_deadline(60)` 并校验 `usage-meter-config.json` 顶层与 `reality` 字段（`binary`/`address`）有效后再执行；`awg` 分支检查 `ensure_awgctl(force=True)` 返回值，刷新失败立即报错中止；门户更新生成重启脚本时加锁读取门户端口。
- 七处协议与出站表单长度校验与 WARP 锁窗口消除（`portal.py`）：`manage-warp`、`manage-reality`、`manage-vmess`、`manage-anytls`、`manage-tuic`、`manage-vlessenc` 与 `_ob_manage` 全部校验 `0 <= Content-Length <= 65536`，杜绝负长度静默回落成 `action='toggle'` 意外翻转协议开关；`_h_post_manage_warp` 将未装 WARP 判定并入首次锁内写入条件，消除先写脏规则再二次加锁回滚的竞态窗口。
- 网页端安装 WARP 原子落盘、私钥保护与并发互斥（`portal.py` 的 `_h_post_install_warp`）：新增模块级 `_warp_install_lock` 串行保护安装避免并发覆写；内嵌脚本中 `wgcf-account.toml` 与 `wgcf.conf` 在 `umask 077` 下生成并设 `chmod 600`、改用私有临时日志取代固定 `/tmp/wgcf-*.log`；`wireproxy.service` 与看门狗脚本及单元全部改为同目录 `mktemp` 原子落盘；`save_data()` 失败时完整回滚内存 `warp_enabled` 与 `warp_rules`。
- 门户刷新与沿用流程非对象容错与损坏字段自愈（`portal.py` 的 `_refresh_portal_state` 与 `_adopt_locked`）：显式拦截非 JSON 对象的 `client_meta.json` 与 `portal.json` 并抛出清晰 `ValueError`；`_refresh_portal_state` 对空串或非字符串 `api_key`、非字典 `users` 与非列表 `proxy_services` 执行自愈修复。
- 版本检查缓存与升级线程并发加锁（`portal.py`）：新增模块级 `_ver_cache_lock` 保护 `_remote_root_shas`、`_h_get_check_version` 与 `upgrade_worker` 对 `_ver_cache`、`_core_ver_cache` 的原子读写与失效重置，同时保持网络请求在锁外执行不阻塞。
- 跨节点设备黑名单损坏追踪容错与过期清理（`portal.py` 的 `users/ip-deny`）：校验 `ip_tracker` 条目必为字典且时间戳为合法非布尔数字（过滤时钟回拨），防止损坏条目引发 500；`global_ip_deny` 超过 4096 条时自动回收全部已过期条目防内存无限增长。
- Xray 计量配置助手校验前置、超时重试与回滚隔离（`usage-meter-xray-config-20261007-v1.py`）：`add_stats`、`enable_iplimit_routing` 与 `enable_reality_online` 统一校验配置为对象且回环地址端口合法（`127.0.0.1:1..65535`）；`enable_reality_online` 重启后 gRPC 探活循环兼容 `TimeoutExpired` 重试；回滚写回原配置隔离 `OSError` 不掩盖原始异常。
- 面板接入脚本参数安全校验（`panel-join.py`）：校验 `--panel` 禁止空白与控制字符且显式端口处于 `1..65535`，拦截无效端口输出坏命令；`--admin-token` 拒绝换行与控制字符防止请求头注入；对 `portal.json` 异常 `port` 字段做安全类型校验。
- 安装脚本本地 WARP 部署私钥保护与原子落盘（`install.sh` 的 `install_warp_local_proxy`）：`wgcf` 账号与配置纳入 `umask 077` 并执行 `chmod 600` 保护私钥，日志改用私有 `mktemp` 并在退出前清理；归属标记在 `umask 077` 下创建；`wireproxy.service`、`hy2-warp-watchdog.service` 与 `hy2-warp-watchdog.timer` 改用同目录临时文件原子替换，二进制替换失败立即清理 `.new` 残片。
- 门户前端后台轮询节能、防连点与异常提示补齐（`portal_assets.py`）：网速 2 秒轮询补充 `!document.hidden && !portalSessionExpired` 护栏，切后台或会话过期立即停止；WARP 重置规则按钮增加请求中禁用防连点；AmneziaWG 安装、新增客户端、切协议线与升级四处操作全部补齐网络异常捕获弹窗提示，消除未处理 Promise 拒绝。

## 2026-11-22 — 第四十三批十项修复，门户 2.53

- 节点启动时间解析消除夏令时偏移（`portal.py` 的 `_hy2_config_loaded`）：解析 systemd 服务启动时间中的 `UTC`/`GMT` 时间戳时，改为纯整数格里高利历转纪元秒公式，彻底消除欧美夏令时下因 `time.mktime` 与 `time.timezone` 差 3600 秒导致的配置重载误判。
- 流量超额停用补偿恢复加固（`portal.py` 的 `_set_traffic_suspension`）：保存失败补偿恢复服务时统一捕获 `Exception`（覆盖子进程超时避免中止后续服务恢复），拉起服务前先执行 `systemctl reset-failed` 清除失败计数；恢复失败补偿停服时跳过已退役（`_retired`）协议服务。
- 网页端用户管理落盘回滚与安全响应头修复（`portal.py` 的 `_h_post_manage_user`）：`save_data()` 抛出磁盘异常时完整回滚内存中的 `users`、`_pending_revocations`、`usage_meter`、`ip_tracker`、`speed_tracker` 与 `global_ip_deny`，彻底消除磁盘满创建用户残留幽灵账号；回滚保存隔离异常；成功 302 跳转补齐 `Connection: close`、`Cache-Control: no-store`、`X-Content-Type-Options: nosniff`、`X-Frame-Options: DENY` 与 `Referrer-Policy: no-referrer`。
- 登录接口损坏哈希容错与安全响应头补齐（`portal.py` 的 `_h_post_login`）：拒绝负的 `Content-Length` 请求头；在 `data_lock`（数据锁）内读取 `token` 与 `auth_hash` 并校验 `auth_hash` 为纯 ASCII 字符串后再调用 `hmac.compare_digest`，避免损坏配置触发 `TypeError`；成功 302 跳转补齐断连与全套安全响应头。
- 删除最后一个自定义出站同步清理全局模式（`portal.py` 的 `_ob_manage`）：在同一次 `data_lock` 内删除最后一个自定义出站时，将残留的 `outbound_mode == 'global'` 一并重置为 `'rules'` 并随本次 `save_data()` 原子持久化，避免界面与实际出站模式脱节。
- 全门户用户表损坏容错清零与登出接口加固（`portal.py`）：清零全文件剩余 11 处裸用 `data.get('users', {})`，统一改为 `user_table(data)` 防御非对象损坏结构（写入前确保为字典）；登出处理改为在 `data_lock` 内读取 `token` 并补齐安全响应头。
- 流量计量运行时非对象配置与损坏时间戳容错（`usage-meter-runtime-20261007-v1.py`）：`PortalMeter.__init__` 与 `from_file` 对非字典配置立即抛出 `ValueError('invalid usage meter config')` 避免延迟崩溃；`summary()` 校验 `live_sampled_at` 与 `online_sampled_at` 为非布尔数字，防止损坏缓存触发 `TypeError`。
- 门户服务、证书自愈单元与旧出站迁移原子落盘（`install.sh` 的 `setup_portal`、`setup_cert_selfheal` 与 `warp_migrate_legacy_outbound`）：`hysteria-portal.service` 及 `hy2-cert-selfheal.{service,timer,path}` 改为同目录 `mktemp` 加 `chmod 644` 与 `mv -f` 原子替换；`warp_migrate_legacy_outbound` 移除非原子 `sed -i`，改为 `umask 077` 下同目录临时文件配合 `awk` 字面量替换、`chmod 600` 与 `mv -f` 原子落盘。
- 自定义出站校验支持 IPv6 代理并拦截控制字符与非法端口（`portal.py` 的 `validate_outbound`）：`socks5` 出站地址支持 `[IPv6]:port` 并经 `ipaddress.ip_address` 校验合法性；拦截 `socks5` 与 `http` 代理配置中的换行及控制字符；`http` 代理经 `urlsplit` 严格校验主机名非空与端口位于 `1..65535`。
- WARP 探测缓存并发加锁与多处接口细节加固（`portal.py`）：新增 `_warp_probe_lock` 保护 `_h_get_warp_status` 原子读写缓存，消除并发撕裂；`user-config` 接口调 `qrencode` 前补充 `self._extend_deadline(30)` 续期并校验节点元信息非空（缺失返回 503 JSON）；`awg-conf` 下载响应补齐 `X-Frame-Options: DENY` 与 `Referrer-Policy: no-referrer`；未认证登录页改为在 `data_lock` 内读取门户令牌。

## 2026-11-22 — 第四十二批十项修复，门户 2.52

- 节点能力接口门户版本截断修复（`portal.py` 的 `/api/v1/capabilities`）：此前按前 80 行扫描 `PORTAL_VERSION`，但常量定义已位于第 215 行，导致运维面板读取的 `portal_version` 恒为空串；改为流式逐行扫描命中即停并回落模块常量，同时省去每次请求将整份门户源码读入内存的开销。
- Reality 停用订阅清理与配置结构校验（`portal.py` 的 `_h_post_manage_reality`）：停用 Reality 后同步调用 `regenerate_page()` 刷新连接页与下载订阅缓存，消除停用后订阅仍残留旧节点的缺陷；增加对非对象 `xray.json`（如数组）的拦截并给出清晰中文 500 提示。
- 混淆隧道升 3.x 参数全量校验与列表输出加固（`awgctl.sh` 的 `cmd_install`、`cmd_update`、`cmd_peer_list` 与配置渲染）：升级或安装 AWG 3.x 时逐项检查 `S1`~`S4` 全部为纯数字且不小于 12（修复此前只检 `S4` 遗漏 `S1`~`S3` 的协议违规缺陷）；`cmd_peer_list` 改用环境变量 `ENVIRON["AWG_TR"]` 传递多行流量表消除 `mawk` 遇换行报错；渲染服务端与客户端配置计算 MTU 前校验 `S4` 为纯数字并按十进制解析。
- 会话验签多同名 Cookie 兼容与 GitHub 令牌缓存失效修复（`portal.py` 的 `verify_session` 与 `github_token`）：`verify_session` 收集全部同名 `hy2_session` 候选逐个验签并在数据锁内校验字符串类型，避免排在后面的旧路径失效 Cookie 覆盖有效会话或损坏 `token` 触发 `TypeError`；`github_token` 将文件权限位、`ctime`、索引节点与体积纳入缓存键并加锁，修复 `chmod` 放宽权限后缓存不失效仍沿用不安全令牌的问题。
- 页面重建与用户分享路由损坏数据容错（`portal.py` 的 `regenerate_page`、`/u/<uid>` 与 `/user-config`）：`regenerate_page` 过滤非数字或时钟回拨产生的异常 `ip_tracker` 时间戳，避免渲染时抛出 `TypeError` 白屏，并改在数据锁内读取门户令牌；`/u/<uid>` 与 `/user-config` 统一经 `user_table(data)` 访问用户表，且 `/u/<uid>` 校验清洗后的非空字符串节点身份防止非字符串绕过退回 `localhost`。
- 多协议停用路径配置校验与回滚容错加固（`portal.py` 的 `_h_post_manage_vmess`、`_h_post_manage_vlessenc`、`_h_post_manage_anytls` 与 `_h_post_manage_tuic`）：VMess 与 VLESS-Enc 停用增加 `xray.json` 非法与非对象校验，且 `save_data()` 失败回滚时若原无配置则清除脏键；AnyTLS 与 TUIC 停用回滚时隔离配置文件恢复异常，确保必定继续恢复原服务状态（AnyTLS 同步补齐原无配置时的清理）。
- 安装脚本主配置、元数据与系统服务单元原子落盘（`install.sh` 的 `generate_server_config` 与 `setup_systemd`）：`config.yaml`（连同末尾 `obfs:` 段）与 `client_meta.json` 改在 `umask 077` 下写入同目录临时文件、设 `0600` 后原子替换，消除写盘中断截断现役配置与私钥权限窗口；`99-hysteria2.conf`、`hysteria-server.service` 与日志级别 drop-in 同步改为同目录临时文件原子替换。
- 门户整包回滚异常隔离、常规令牌校验与证书链脚本私有备份（`install.sh` 与 `fix_cert_chain.sh`）：`portal_ensure_py` 发布事务失败回滚时逐个隔离文件 `OSError` 并使用 `unlink(missing_ok=True)`，避免单次恢复失败打断其余文件回滚；`install.sh` 的 `curl()` 包装器读取令牌前增加 `-f` 常规文件校验；`fix_cert_chain.sh` 备份配置增加进程号防同秒撞名并在 `umask 077` 下创建、失败即清理残片。
- 防火墙兜底补齐 IPv6 与末尾拦截规则识别（`install.sh` 的 `setup_system_firewall`）：裸 `iptables` 兜底块同步支持 `ip6tables` 避免双栈主机 IPv6 端口漏放行，并同时识别 `policy DROP/REJECT` 及云镜像常见的 `policy ACCEPT` 加末尾 `DROP`/`REJECT` 拦截规则；移除 `ufw` 与 `firewalld` 分支中重复放行订阅端口的冗余调用。
- Reality 状态页子进程按需调用与混淆隧道管理参数前置校验（`portal.py` 的 `_h_get_reality_status` 与 `_h_post_manage_amneziawg`）：Reality 未启用时跳过无意义的 `qrencode` 子进程调用；将 `peer_del` 客户端名与 `set_line` 协议线校验前置到安装检查与重型槽申领之前；`update` 分支检查 `ensure_awgctl(force=True)` 返回值，刷新失败立即报错中止。

## 2026-11-22 — 第四十一批十项修复，门户 2.51

- 辅助协议服务单元原子落盘与回滚隔离（`portal.py` 的 AnyTLS / TUIC 启用路径）：写入服务单元文件改用 `_restore_systemd_unit_file` 同目录临时文件原子替换；启用失败回滚时逐项隔离配置恢复、单元恢复与 `systemctl daemon-reload` 异常，防止重载超时或非零退出跳过原有服务状态恢复。
- 门户在线自更新与代理服务单元原子写入（`portal.py` 的 `do-upgrade`、`write_xray_unit` 与 `ensure_gost_unit`）：门户自更新的备份与失败回滚改用同目录临时文件落盘、刷盘并原子替换，新建文件清理逐个隔离文件系统异常；Xray 与 GOST 系统服务单元写入统一改为原子替换，消除半写入残片窗口。
- 订阅产物畸形配置容错与单节点分流去冗余（`portal.py` 的 `artifacts`）：校验 `vmess`、`vlessenc`、`anytls`、`tuic` 子段必为对象且核心字符串字段合法，防止手工损坏配置引发全站订阅 500；`sing-box` 订阅仅在存在真实 `sing-box` 可用备用节点（`sing_alternates`）时才生成 `urltest` 自动测速组，修复仅启用 Hy2 加 VLESS-Enc 时生成单节点空转测速组的问题。
- 网页端用户管理锁粒度与页面一致性修复（`portal.py` 的 `_h_post_manage_user`）：移除持有 `data_lock` 期间调用 `save_data()` 的阻塞路径；调整为先落盘再同步 Reality 客户端，消除成功路径重复两次重建订阅页；修复创建用户同步失败回滚后 `data['page']` 残留幽灵用户的问题，删除同步失败回滚时同样重建页面保持一致。
- 集群接口落盘锁释放与损坏用量限额容错（`portal.py` 的 `apply_access`、`users/set_status`、`users/create` 与 `users/renew`）：`apply_access` 失败持久化待撤销队列时移出 `data_lock` 并捕获落盘异常防阻塞鉴权与抛穿；`users/set_status` 补齐落盘持久性不确定时的跳过护栏防穿透 `AtomicWriteDurabilityError`；创建与续期接口安全容忍已有用量或限额为空值及损坏值。
- 门户前端安全属性、数值格式化与异常恢复修复（`portal_assets.py`）：所有新标签页链接与窗口补齐 `rel="noopener noreferrer"` / `noopener,noreferrer` 与 `opener = null` 防反控；速率格式化函数 `fmtUnits` 对非有限数与负数归零，避免界面显示 `NaN B/s`；出站规则域名去重改用 `Set` 消除对象原型属性污染；重启等待轮询 `waitPortalBack` 与混淆隧道删除接口补齐异步异常捕获恢复按钮状态。
- 安装脚本入站代理二进制原子回滚与残留清理（`install.sh` 的 `install_gost`）：新增私有掩码备份辅助函数 `_backup_gost_asset`（中途失败立即清理临时备份）与同目录临时文件原子回滚函数 `_restore_gost_asset`，免疫回滚覆写运行中 `gost` 二进制触发 `ETXTBSY`（文本文件忙）；替换失败时立即删除 `gost.new` 暂存文件。
- 证书域名接口退出码兼容与混淆隧道控制脚本原子部署（`install.sh` 的 `setup_cert_via_dns_api` 与 `awg_ensure_ctl`）：准确捕获 `acme.sh` 真实退出码并将退出码 `2`（有效证书未到期跳过）按成功处理；配置 `HY2_CF_KEY` 但缺少 `HY2_CF_EMAIL` 时返回非零并明确报错；部署 `awgctl.sh` 改用同目录临时文件原子替换目标脚本。
- 流量计量读取器结构校验与句柄释放加固（`usage-meter-readers-20261007-v1.py`）：`parse_xray` 对非对象根节点、行项或名称统一抛出 `ValueError`；`parse_events` 校验每行必为对象且时间戳合法，并以容错 `utf-8` 解码日志防止非 UTF-8 字节崩溃；`read_live_connections` 在 404 回退分支于 `finally` 中关闭 `HTTPError` 句柄，显式按 `utf-8` 读取配置并校验嵌套结构。
- 入站代理管理控制字符校验、回滚容错与端口快照加锁（`portal.py` 的 `_manage_proxy_operation` 与 `write_gost_config`）：拒绝代理账号或密码中包含换行及控制字符（返回 400）；`reload_gost` 失败与防火墙放行失败回滚均独立隔离 `save_data()` 和二次 `reload_gost()` 异常，确保落盘失败也能还原运行中的 `gost.yml`；`write_gost_config` 在 `data_lock` 内更新 `gost_written_ports`，删除回收防火墙前持锁拍取数据快照。

## 2026-11-22 — 第四十批十项修复，门户 2.50

- 混淆隧道控制脚本（`awgctl.sh`）三项稳定性与权限修复：`cmd_uninstall` 卸载前检查服务单元是否存在，跳过从未安装过的服务单元避免半装残留卡死卸载；`cmd_install` 与 `cmd_update` 在比较 `S4 < 12` 前先校验纯数字格式，防止畸形参数触发算术表达式报错；`cmd_peer_add` 与 `cmd_peer_del` 生成空备份占位文件时纳入 `umask 077` 私有掩码。
- 安装脚本归档查找与元数据自愈加固（`install.sh`）：`hy2_tar_find_member` 改为先捕获 `tar -tzf -` 成员清单并严格校验退出码与目标成员唯一性，拒绝截断压缩包及重复同名成员；`sync_cert_meta` 与内嵌 `do_upgrade.sh` 重写 `client_meta.json` 统一改为 `umask 077` 加同目录 `mktemp` 及 `chmod 600` 原子替换，消除可预测临时文件名与权限暴露窗口。
- 安装脚本核心操作锁与升级锁释放修复（`install.sh`）：新增 `release_installer_core_lock` 并在 `acquire_installer_core_lock` 中记录锁描述符 `_INSTALLER_CORE_LOCK_FD`、拿锁失败立即关闭描述符；`flow_update_core` 在所有退出与错误路径自包含关闭 `update_lock_fd`；`flow_install`、`flow_reconfigure`、`uninstall_all` 及直通安装分支在退出或完成核心变更后主动释放 `.core-operation.lock`，消除描述符泄漏与持续占锁阻塞门户问题。
- 入站代理面板安装与回滚加固（`portal.py` 的 `_h_post_install_gost` 与 `write_gost_selfcheck`）：安装暂存二进制改用随机后缀 `gost.new.<随机串>` 并在 `finally` 中保证未替换即清理；`write_gost_selfcheck` 改用同目录私有临时文件加 `os.replace` 原子落地；`restore_gost_assets` 改用同目录私有临时文件原子替换避免覆写运行中二进制触发 `ETXTBSY`（文本文件忙）及敏感配置权限窗口，并逐条隔离 `systemctl` 超时异常防回滚中途断裂。
- 救援环境重装脚本前置护栏与清理加固（`alpine2debian.sh`）：在清空磁盘前校验 `SWAP_MB`、`DEBIAN_SUITE`、`HOSTNAME`、`TIMEZONE`、`MIRROR` 与 `SECURITY_MIRROR`，拦截非法数值、路径穿越与命令注入字符；`chroot` 内部校验根分区 `ROOT_UUID` 非空并补齐 `PermitRootLogin yes` / `PasswordAuthentication yes` 追加兜底；无论 `chroot` 成功或失败均立即清除临时脚本与明文密码文件 `/tmp/_rootpw`。
- 流媒体解锁并发超时上限与证书自愈状态容错（`portal.py` 的 `run_unlock_checks`、`_unlock_fetch`、`_unlock_read` 与 `cert_status`）：`run_unlock_checks` 改为共享单轮 30 秒总截止时间，修复六线程串行等待最坏阻塞 180 秒拖死接口死线；`_unlock_fetch` 在捕获 `HTTPError` 后 `finally` 关闭连接句柄防止描述符泄漏；`_unlock_read` 兼容 `IncompleteRead.partial` 为空值；`cert_status` 校验自愈状态文件顶层为对象再读取字段。
- 拥塞控制状态解析与登录限流器内存边界修复（`portal.py` 的 `_h_get_bbr_status`、`login_rate_limited` 与 `record_login_failure`）：读取 `/etc/sysctl.d/99-bbr.conf` 时跳过 `#` / `;` 注释行并剥离行尾注释、精确匹配键名，修复注释旧值覆盖有效配置导致虚假「需要重启」提示；登录限流器及时淘汰 600 秒以外过期失败记录、清理空来源桶，并为 `_login_lock_logged_at` 去重表增加 4096 上限封顶防内存持续增长。
- 出口探测代理凭据脱敏与输入校验（`portal.py` 的 `detect_outbound_ip`）：含账号密码（`@`）的代理地址改由标准输入传入 `curl --config -`，彻底避免明文代理凭据暴露在系统进程表（`ps` / `/proc/<pid>/cmdline`）；拦截含空白或控制字符的畸形代理地址；直连模式省略空的 `--proxy` 参数仅传 `--noproxy '*'`。
- 重装脚本参数校验、下载超时与最小权限加固（`reinstall-debian13.sh`）：前置校验 `MIRROR` 仅允许安全 `http://` / `https://` 地址，拒绝前导零端口与 0 号版本；`download_installnet` 为 `wget` 增加 `-T 120` 超时防远端卡死无限挂起；`init_log` 使用 `umask 077` 与 `chmod 600` 保护重装日志，下载后的 `InstallNET.sh` 收紧为 `chmod 700`。
- 安装脚本计量配置锚点与证书借签回滚修复（`install.sh` 的 `portal_write_meter_config` 与 `setup_cert_via_existing_caddy`）：补写 `trafficStats:` 时改为按行首正则匹配真实顶层 `masquerade:` 段，避免命中注释行内的 `masquerade:` 写坏 `config.yaml`，并将 `config.yaml` 与 `usage-meter-config.json` 均改为同目录私有临时文件原子替换；借本机 Caddy 签发证书等待 60 秒超时失败时，若本次自动追加了占位域名块则自动从备份回滚并重载 Caddy，避免生产 `Caddyfile` 残留无效站点。

## 2026-11-21 — 第三十九批十项修复，门户 2.49

- 计量配置更新助手（`usage-meter-xray-config-20261007-v1.py`）新增 `_write_private_bytes` 直接以目标权限创建并落盘候选与备份配置，消除 `enable_iplimit_routing` 与 `enable_reality_online` 默认掩码暴露私钥窗口及非原子 `shutil.copy2` 备份问题；将候选文件写入移入 `try` 块确保失败必清理，并隔离回滚重启超时异常避免覆盖原始失败原因。
- 计量核心与运行时边界加固（`usage-meter-core-20261007-v1.py` 与 `usage-meter-runtime-20261007-v1.py`）：`apply_sample` 在空采样周期同样校验 `totals` 容器类型并显式报 `ValueError('invalid totals')`；`poll` 遇到损坏的非对象 `usage_meter` 容器时将对应来源记入 `failed_sources`；`summary` 对 `live_snapshot`、`online_counts` 增加结构校验与时钟回拨下界检查，防止异常快照报错或未来时间戳缓存永久判鲜。
- 门户敏感候选配置私有化与回滚加固（`portal.py` 新增 `_write_private_bytes`）：覆盖 `apply_xray_config_transaction`、`apply_anytls_config`、`_apply_xray_access_snapshot_locked` 与 `record_cert_heal`，消除明文候选文件默认掩码创建窗口与 `chmod` 失败残留，原子替换 `xray.expiry-last-good.json` 备份，并在回滚服务重启时隔离 `OSError` / 超时异常不掩盖原错。
- 入站代理重载与凭据修复加固（`portal.py` 的 `reload_gost` 与 `repair_missing_api_key`）：`reload_gost` 走 `systemctl restart gost` 兜底前先执行 `systemctl reset-failed gost`，防止触发重启频率上限后永久拉不起来；移除 `gost_ports_ready` 末尾不可达死代码；`repair_missing_api_key` 校验 `portal-access.json` 顶层必为对象。
- 门户前端脚本健壮性与安全修复（`portal_assets.py`）：`Response.prototype.json` 拦截器将合法但非对象的 JSON 负载（如 `null`、数字、字符串、布尔）统一包装成可读中文错误对象，防止调用点读取 `.ok` 抛出 `TypeError`；入站代理列表移除对 `fullUrl` 的双重 HTML 转义避免破坏复制链接；用户专属弹窗到期时间、流量与 IP 限制字段补齐 `obEsc` 转义。
- 证书链修复脚本加固（`fix_cert_chain.sh`）：`set_tls_cert` 在未实际匹配到 `tls.cert` 行时返回非零退出码而非静默成功并重启服务，临时文件在 `umask 077` 下创建；`masq_https_port` 去除端口前导零；新增 `restore_config_file` 通过同目录临时文件原子回滚原配置。
- 混淆隧道控制脚本原子替换改造（`awgctl.sh`）：新增 `awg_atomic_copy_file` 与 `awg_atomic_install_bin`，使 `awg_transaction_restore`、`download_binaries` 与 `restore_peer_files` 均通过同目录临时文件原子替换目标文件，避免覆写运行中 `amneziawg-go` 触发 `ETXTBSY` 导致回滚或更新失败；`download_binaries` 改为先在临时目录对新 `awg` 做冒烟校验再替换现役二进制。
- 设备上限守护线程容错与单调时钟改造（`portal.py` 的 `reality_iplimit_worker`）：安全校验 `usage-meter-config.json` 顶层与 `reality` 子段类型；`enable_retry_at` 10 分钟退避改用单调时钟 `time.monotonic()` 防系统时间回拨拉长退避；遍历 `ip_tracker` 时校验容器类型、数值时间戳与时钟回拨下界，避免单条坏记录触发全节点拦截规则清空放行。
- 拥塞控制切换原子写入与回滚隔离（`portal.py` 的 `_set_bbr_locked`）：`/etc/modules-load.d/bbr.conf` 与 `/etc/sysctl.d/99-bbr.conf` 的写入与回滚均改用同目录临时文件原子替换；`save_data()` 失败时优先恢复内存 `bbr_target_version` 并逐项隔离文件与 `sysctl -w` 回滚异常，防止某次内核参数恢复超时导致内存版本永久脏留。
- 整机网卡流量采集与鉴权追踪边界防护（`portal.py` 的 `node_default_ifaces`、`node_traffic_counters` 与 `/auth`）：读取 `/proc/net/route`、`/proc/net/ipv6_route`、`/proc/net/dev` 与 `boot_id` 统一采用 `utf-8` 容错解码并跳过列数不足或非法计数行，避免容器非 ASCII 网卡名引发 500；`/auth` 清洗非对象 `ip_tracker` 条目并过滤时钟回拨产生的未来时间戳，防止合法用户被异常阻断。

## 2026-11-21 — 第三十八批十项修复，门户 2.48

- 独立生成的升级与自愈脚本（`install.sh` 产出的 `do_upgrade.sh` 与 `repair-config.sh`）内联 `config_tls_cert()` 证书路径解析函数定义：此前两处调用了仅存在于 `install.sh` 运行时的未定义函数，导致自定义证书或反向代理证书节点在门户在线升级或自愈时回退为自签模式，且证书监控路径单元盯错目录。
- 核心在线升级失败回滚（`portal.py` 的 `_upgrade_core_binary_locked`）改为先写入同目录临时文件、赋权 `0o755` 再通过 `os.replace` 原子替换回目标路径，并隔离回滚重启异常避免掩盖原始失败原因：此前 `shutil.copy2` 直接覆写正在运行的二进制在 Linux 上可能触发 `ETXTBSY`（文本文件忙）导致回滚失败。
- 门户超文本服务（`portal.py` 的 `do_HEAD`）在入口与 `finally` 块中重置 `self._head_body_started = False`：修复超文本长连接（`HTTP/1.1` 复用）连续发送两次 `HEAD` 请求时，第二次响应头被 `_HeadersOnly.write` 全部吞掉导致客户端报空响应或协议错误的缺陷。
- 核心卸载接口（`portal.py` 的 `_h_post_uninstall_core`）补齐三项安全护栏：入口申领重型任务槽位（防止并发核心操作）；持有跨进程核心锁后拒绝卸载非本脚本托管的宿主机 `xray` 服务与二进制；采集伴随服务单元状态时识别从未安装过的单元（如未启用过的 `hy2-tuic`）并在停服与回滚中跳过，且回滚恢复活跃服务前先执行 `systemctl reset-failed`（同时统一核心锁冲突中文文案）。
- 节点身份与展示主机清洗统一收口（`portal.py` 共十处）：将 `cert_status`、`sync_cert_trust`、`ensure_portal_access`、`regenerate_page`、`_render_admin_page`、`_h_get_proxy_services`、`_manage_proxy_operation` 以及 `/api/v1/capabilities` 与 `proxy-services/list` 接口全部改用 `clean_node_identity` / `meta_display_host`，消除手工或旧版写入 `"is_insecure": "false"` 字符串假值导致的错拼公网地址与缺键报错。
- 出口分流脚本全面加固（`portal.py` 内嵌安装脚本与 `install.sh` 内嵌 `toggle_warp.sh`、`install_warp_local_proxy` 及看门狗脚本）：`tar_member()` 改为先从标准输入捕获归档清单并校验退出码，杜绝进程替换丢弃错误码放行截断压缩包；写入含私钥的 `wp.conf` 与重写 `config.yaml` 全部改用 `umask 077` 加同目录 `mktemp` 原子替换；五处重启或拉起 `wireproxy` 前均先执行 `systemctl reset-failed wireproxy`，防止撞上启动频率上限后看门狗永久自愈失败。
- 核心二进制安装流程加固（`portal.py` 的 `install_xray_binary` 与 `install_singbox`）：暂存文件改用同目录随机后缀并在 `finally` 中保证未替换即清理，消除异常中断后 `/usr/local/bin/*.new` 长期残留；`install_xray_binary` 解压路径改为严格对齐校验成员；`install_singbox` 为发布元数据拉取增加 2 MiB 体积上限及非对象、非列表条目容错，避免异常接口返回触发未捕获异常。
- 外部元数据与门户更新包拉取统一限流与容错（`portal.py` 新增 `_read_bounded_bytes`）：覆盖 `resolve_update_ref`（接口与提交订阅源）、`fetch_text`、`_remote_root_shas`、`fetch_portal_file`（4 MiB 上限）、`_remote_blob_sha`、`_h_post_install_gost` 与 `_h_get_check_version`，防止异常超大响应耗尽门户进程内存并拦截非对象数据结构。
- 分流规则域名增删逻辑统一（`portal.py` 的 `_h_post_manage_warp` 与 `_ob_manage` 抽出 `_clean_route_domain` 与 `_valid_route_domain`）：删除域名规则时采用与添加完全一致的协议头、路径、查询串、锚点、端口与首尾点清洗，修复粘贴完整地址能添加却删不掉的问题；同时拒绝包含连续点（`..`）的非法域名。
- 节点接入辅助脚本加固（`panel-join.py`）：`meta_host` 改用严格布尔解析并支持双字段回落，修复 `"is_insecure": "false"` 错选公网地址；`listenHTTPS` 与 `listen` 端口去除前导零并做端口范围校验；`--panel` 拒绝含 `?` 或 `#` 的地址避免拼坏登记路径；`--register` 改用上下文管理器关闭连接、加读取上限并用 `errors="replace"` 解码避免非 UTF-8 网关报错页引发解码崩溃。

## 2026-11-21 — 第三十七批十项修复，门户 2.47

- 实时在线地址采集（`usage-meter-readers-20261007-v1.py` 的 `read_live_connections` 与 `parse_events`）兼容空切片或空映射序列化产生的空值（`{"users": null}`、`{"ips": null}`、核心条目 `ips: null`），避免单次空在线状态把全机采集标成异常；同步补齐 `/online/ips` 与回退 `/online` 的 4 MiB 体积上限、日志非对象负载拦截与同协议双栈地址去重。
- 自定义出站可达性预检（`portal.py` 的 `_unreachable_outbounds`）改用标准库地址拆分器解析超文本与加密超文本出站，并剥离加密隧道协议地址的方括号：修复带认证信息代理（如 `http://user:pass@host:port`）被截成用户名、加密代理默认端口误用 80 以及双栈字面量地址被误判为无法连通的问题。
- 门户自更新重启脚本（`portal.py` 的 `portal_update_restart_script`）在升级后重启与失败自动回滚重启前均先执行 `systemctl reset-failed hysteria-portal`：避免新版本启动崩溃触发服务重启频率上限后，连自动回滚重启也被系统管理器拒绝而导致整机鉴权后端离线。
- 系统服务回滚恢复函数（`portal.py` 的 `_restore_systemd_service_state`）在还原原运行中服务时改为先执行 `systemctl reset-failed` 再执行 `systemctl restart`（而非 `systemctl start`）：既避免回滚撞上启动频率上限被拒，又解决服务仍以新配置运行时 `start` 静默空操作而未重载旧配置的缺陷。
- 备选传输协议（`AnyTLS` 与 `TUIC`）启停失败回滚的配置文件恢复全部改用原子私有落盘（`_restore_config_atomically`）替代裸 `cfg_path.write_bytes`，消除停用删除后再写回导致权限退化为全局可读并暴露用户密码及半写风险；两处停用回滚同时加回协议互斥锁防止与并发撤销线程竞态覆盖。
- 出站配置回滚（`_rollback_outbounds` 写回 `config.yaml`）与门户元数据自愈（`sync_cert_trust`、`sync_pin`、`prepare` 写回 `client_meta.json`）统一改用 `atomic_write_private` 原子落盘并保持仅机主可读权限，避免写入中断或并发读取产生半截配置并泄露机主密码。
- 入站代理安装失败回滚（`_h_post_install_gost` 的 `restore_gost_assets`）在重启旧服务前先清理失败计数，并按安装前快照独立还原开机自启与启停状态：修复原有禁用但运行中的服务被误设自启、以及原有已启用但停运的服务回滚时未被停止的问题。
- 证书链修复脚本（`fix_cert_chain.sh`）修复 `leaf_pub` 在损坏证书上对空输出求摘要导致两张损坏证书假匹配的缺陷（先确认公钥非空再算摘要），并让 `cert_of` 与 `set_tls_cert` 兼容带行尾注释的 `tls:` 顶格配置段。
- 系统重装脚本（`alpine2debian.sh` 与 `reinstall-debian13.sh`）统一采用精确整盘与分区枚举助手（`disk_mounts` 与 `disk_devices`），彻底清除卸载遍历、残留挂载检查与子分区签名探测中的前缀通配模糊匹配，避免多盘环境下 `/dev/sda` 误伤 `/dev/sdaa1` 或 `/dev/nvme0n1` 误伤 `/dev/nvme0n10p1`。
- 混淆隧道控制脚本（`awgctl.sh`）的 `render_client_config` 在渲染客户端连接地址时将带前导零的十进制显式端口规范化（如 `:08080` → `:8080`），避免非规范前导零端口直接落入客户端配置；同时 `cmd_uninstall` 延迟自删后台子进程关闭继承的锁文件描述符（`9>&-`），避免卸载退出后短时占锁阻塞后续命令。

## 2026-11-19 — 第三十六批十项修复，门户 2.46

- 计量核心（`usage-meter-core-20261007-v1.py`）在清理已删除用户累计流量（`totals`）时同步清除平级流量偏移（`adjustments[uid]`），同时保留暂未删除的停用用户偏移：此前仅遍历废弃的嵌套结构，导致带负偏移的已删用户被同名重建后 `adjusted_bytes` 算得负值并触发整机计量循环持续失败。
- Xray 计量配置助手（`usage-meter-xray-config-20261007-v1.py`）在 `enable_iplimit_routing` 与 `enable_reality_online` 失败回滚时恢复原 `xray.json` 文件权限（避免 `0600` 退化为默认掩码泄露私钥与用户列表）；同时 `enable_reality_online` 重启后轮询等待统计接口就绪（最多 10 次 × 0.5 秒），不再因单次立即探测连接被拒而误触回滚。
- 门户核心准入同步（`portal.py` 的 `_apply_xray_access_snapshot_locked`）失败回滚时同样恢复原 `xray.json` 权限，并在回滚重启 `xray` 前先执行 `systemctl reset-failed xray`：此前若重启刚撞上启动频率上限，回滚重启也会被 systemd 拒绝导致服务持续停机。
- 实时在线 IP 采集（`usage-meter-readers-20261007-v1.py` 的 `read_live_connections`）在 Xray 已安装但服务未运行时按空闲处理，不再每 15 秒报「Reality在线IP读取失败」；同时 `service_running` 捕获 `systemctl` 缺失或超时异常按约定返回在跑，不再在受限环境抛出未捕获异常。
- 门户选新端口避让（`managed_reserved_ports` 在 `keep_disabled=True` 时）同步避开已停用 AnyTLS 保留的端口：此前对 `anytls_config` 的提前跳过位于 `keep_disabled` 判断之前，停用 AnyTLS 后启用其它 TCP 协议或入站代理会抢走其保留端口，导致 AnyTLS 重新启用时被迫换端口、旧订阅失效。
- `install.sh` 内嵌的 `toggle_warp.sh` 改为按顶格缩进仅提取 `acl:` 块本身对比变更：此前用 `sed -n '/^acl:/,$p'` 连带读入排在后面的 `obfs:` 段，删旧 `acl:` 并追加新 `acl:` 到末尾后两者必然不等，导致规则无实质变化也误重启 `hysteria-server` 掐断全部在线连接。
- GOST 入站代理创建成功弹窗（`portal_assets.py` 的 `showProxyResult`）在服务器未安装 `qrencode` 或生成失败时，覆盖掉初始「生成中...」或上一次创建的旧二维码，并展示中文复制指引：此前保留旧二维码会导致扫码连错代理。
- `reinstall-debian13.sh` 为七个带值选项补齐参数个数校验（缺值直接中文报错退出，不再在 bash 下死循环或 sh 下裸崩），并将 `/proc/mounts` 匹配收敛为精确整盘或分区（`disk_mounts`），避免 `/dev/nvme0n1` 误命中 `/dev/nvme0n10p1` 或 `/dev/sda` 误命中 `/dev/sdaa1`。
- `install.sh` 重启核心服务（主服务 `hysteria-server`、门户 `hysteria-portal`、入站代理 `gost` 及其失败回滚）前统一先执行 `systemctl reset-failed`：此前服务刚撞上 `StartLimitBurst` 时，即便重装已写入完好配置仍会被 systemd 拒绝启动。
- 网页管理接口残余英文参数报错与代理删除提示统一中文化，覆盖 `do-upgrade`（更新目标、版本标识）、五个协议管理接口（Reality / VMess / AnyTLS / TUIC / VLESS Encryption）、BBR 版本切换及入站代理删除响应（`/api/v1/*` 外部接口契约与状态码保持不变）。

## 2026-11-18 — 第三十五批十项修复，门户 2.45

- 新建用户表单在浏览器里即按服务端规则校验：用户标识限制 1–64 位合法字符，连接密码首尾禁止空白，流量限额步长改为任意小数并设上限 1000000 GB，备注限长 200 字符。此前填了含空格的标识要提交后才被拒，填 0.3 GB 反被原步长 0.5 拦下，超长备注则被无声截断。
- 网页增删 GOST 入站代理（`manage-proxy`）的报错全部改为中文并说明怎么处理，包括请求无效、代理类型限定、端口范围、缺少编号、代理服务已被删除。此前原样弹出「Invalid port」「Proxy service not found」等英文。
- 出站连通性探测（`outbounds/probe`）：选了 SOCKS5 或 HTTP 代理却未填地址时前端直接提示并把焦点放到地址框，不再发出空请求；服务端探测接口的参数错误也改为中文说明。此前空地址照样发请求，结果区显示一行英文报错。
- 「安全重启服务器」确认框按危险操作处理（焦点默认停在「取消」，回车不会误触重启），并写明重启期间所有用户的连接都会中断。此前用普通警告样式，焦点停在「确定」。
- 网络中断或服务器正在重启时，浏览器的底层请求失败在统一入口转为中文「无法连接服务器（网络中断，或服务器正在重启）」，主动中止的请求（`AbortError`）原样放行。此前二十多个按钮弹出「请求异常: Failed to fetch / Load failed」。
- 用户表的分页按钮补齐中文无障碍名称（「上一页」「下一页」「第 N 页」），当前页标上 `aria-current="page"`。此前读屏对翻页箭头只念符号名，也听不出当前在哪一页。
- 计量模块采集 Reality（Xray `statsonlineiplist`）在线 IP 时与 Hy2 一致还原双栈监听下的 IPv4 映射地址（`::ffff:a.b.c.d` → `a.b.c.d`）：此前保留 `::ffff:` 前缀，同一台双协议测速设备在 Hy2 与 Reality 上被算成两个不同在线 IP，且与纯 IPv4 的跨节点设备拦截名单对不上。
- `awgctl.sh` 的 `validate_port` 与 `install.sh` 的 AmneziaWG 交互安装统一拒收带前导零的端口：此前 bash 算术把 `020000` 按八进制算成 `8192`，绕过了 `20000-40000` 端口跳跃区间拦截并原样写进 `awg0.conf`（`amneziawg-go` 按十进制监听 `20000`，握手包全被劫持）；填 `08080` / `09000` 则直接触发 bash 进制报错中断。
- `panel-join.py` 在缺少 `client_meta.json` 时只从 `config.yaml` 的 `acme.domains` 段提取域名（兼容 `acme:` 排在文件末尾或无尾部换行），同时 `portal.json` 顶层不是 JSON 对象时以退出码 2 友好报错：此前 `tls:` 模式无 `client_meta.json` 时会把 `acl` 等段落里的首个列表项（如 `direct`）当成节点域名拼进 `api_url` 并返回成功。
- 用户「专属连接」弹窗先解析响应内容再报错，并把 `user-config` 与出站管理（`_ob_manage`）的错误提示改为中文，同时在锁内清洗 `custom_outbounds` 后再判断是否允许切到全局出口（并对弹窗 Clash 订阅属性补齐 HTML 转义）：此前弹窗一遇非 200 就报「网络请求异常 (HTTP 404 / 503)」，吞掉了密码损坏、用户已删除、请求过频等真实原因；`custom_outbounds` 含损坏条目时还会放行切到无有效出站的全局模式。

## 2026-11-13 — 第三十四批十项修复，门户 2.44

- 测试 `test_portal` 在没装 qrencode 的机器上不再失败：上一批起二维码生成不出来时回一张说明图，这条测试还断言回空内容。现在不管装没装 qrencode 都要求回 SVG。
- 网页上所有二次确认都改用页内确认框，包括删除 AWG 客户端、出站、代理、WARP 分流域名，切换 AWG 协议线，重新生成 Reality 密钥，升级核心，安装 WARP / GOST / AmneziaWG 等。破坏性操作用危险样式，焦点默认停在「取消」。此前用浏览器原生确认框，默认按钮是「确定」，回车即执行。核心带定制补丁时，升级确认里还显示出字面的「\n」，现已修正。
- AmneziaWG「下载配置」「二维码」出错时说中文并说明怎么办，例如客户端名称不合法、客户端已被删除、没有可用的连接地址、服务器没装 qrencode 时改用「下载配置」。这两个地址是在新标签页里直接打开的，此前管理员看到的是「Client not found」这类英文。状态码不变。
- 管理页 API 文档里 `GET /api/v1/node/meta` 的说明与接口一致：列出实际返回的字段，并写明 `users_count` 包括机主账号与已停用、已过期的账号。此前写着返回「混淆模式以及当前有效用户数与总流量统计」，接口既不给混淆模式也不给流量。
- 网页切换 AmneziaWG 协议线直接切到另一条线（与终端菜单一致），确认框写明从哪条切到哪条。此前先弹原生输入框让人手打 2 / 3，打成当前线还要再弹一次「无需切换」。
- `manage-reality` 也接受明确的 `enable` / `disable`，与 VMess 等协议一致；状态已经符合时什么都不动。`toggle` 照常可用。
- Reality / VMess / VLESS-Enc / AnyTLS / TUIC 的开关按卡片显示的状态发送明确的开启 / 关闭，关闭前先确认，提示正在使用该协议的用户会立即断开。此前一律发 `toggle` 由服务端翻转：页面停留久了或在别处改过时，卡片写着「已关闭（点击开启）」，点下去却把协议关掉；关闭也没有任何确认。
- WARP 开关等状态查到才显示，并按状态发送明确的开启 / 关闭。此前页面一加载就显示「切换中...」且可点，状态查询失败时一直停在那里，点下去全凭运气。
- 出站「全局 / 按域名分流」切换：切到全局前先确认，提示全局模式下所有网站都走列表里的第一个出站，它不通时所有人断网。切换期间两个按钮禁用，点当前模式不再发请求。此前连点两下要重启两次服务，点当前模式也会重启一次。
- 登录过期后，各按钮的报错显示「登录已过期，请刷新页面重新登录」。多数端点的 401 回的是 JSON，此前弹出的是英文单词「Unauthorized」。

## 2026-11-13 — 第三十三批十项修复，门户 2.43

- 入站代理（gost）的启动自检脚本丢失时自动补回：单元的 `ExecStartPost` 指向这个脚本，脚本不在时 systemd 把每次启动都判为失败并停掉 gost，入站代理全部不可用。此前单元内容齐全就不再看脚本在不在，写脚本失败也悄悄吞掉、照样换上引用它的新单元；现在写不进去时保留旧单元并记日志，网页「安装入站代理服务」直接报错说明原因。
- 确认弹窗打开时焦点移到按钮上（删除这类危险操作停在「取消」，回车不会误删），Tab 只在「确定 / 取消」之间切换，关闭后焦点回到原来的按钮：此前焦点留在弹窗背后，键盘用户要按好几下 Tab 才摸到按钮，Tab 还会跑到弹窗背后的页面。
- 「入站代理创建成功」和用户「专属连接」两个弹窗同样处理：打开时焦点放到关闭按钮，关闭后还回去；两个弹窗标注为对话框并关联标题，关闭按钮读作「关闭」而不是「乘号」；页内提示条改为读屏会自动播报的状态区。
- 用户「专属连接」弹窗里的流量与用户表、后端同一写法：此前同一个用量在表格里是「1.5 KB」，在弹窗里是「1.50 KB」。
- 管理页、客户分享页和弹窗里的链接框、输入框、下拉框都有了中文无障碍名称（如「Hy2 节点直链」「Clash 订阅链接」「要走 WARP 的域名」）：此前读屏念的是元素 id（`hy2-link`、`teyir-access-json`），各协议的直链框、出站选择下拉框干脆没有名称。
- 门户凭据文件丢失后自动重建的登录密码与首次安装一样是 256 位随机值，此前只有 144 位。README 的安全说明同步写清：`Secure` cookie 只在经 HTTPS 访问时带，运维用 `ssh -L` 以 HTTP 直连门户时不带。
- `alpine2debian.sh` 的提示跟着 `--suite` 走：此前写死 Debian 12，换成 trixie 时清盘确认说「安装 Debian 12（trixie）」，装完的核验说明还让人去对 bookworm，像是装错了。
- 客户分享页的备用协议直链（Reality / VMess / VLESS-Enc / AnyTLS / TUIC）各带一个可展开的二维码，手机扫码即可导入：此前只给文字，而客户在电脑上打开分享页、UDP 不通时要的恰恰是这些节点。每张二维码最多等 5 秒，协议全开时页面也不会卡上一分多钟。
- 服务器生成不出二维码时（`qrencode` 是可选依赖）如实说明：管理页的二维码图片显示「二维码生成失败，请复制节点直链导入」，不再是一张裂开的图；客户分享页不再留一个空框、下面还写着「扫描即可直接接入」；弹窗不再一直显示「二维码生成中...」。
- 菜单「启动 / 重启 Hysteria」（以及 `bash install.sh restart`）成功后，如果门户没在运行就提醒用菜单 15 重启门户：门户是 Hy2 的鉴权后端，它停着用户照样连不上，此前只报「已启动 / 已重启」。

## 2026-11-13 — 第三十二批十项修复，门户 2.42

- `/api/v1/node/meta` 改为真正按白名单返回节点参数（公网 IP、域名、端口、跳跃区间、证书类型、是否跳过校验、订阅端口）：注释写的是白名单，实现却只剔除三个已知密钥，`client_meta.json` 以后新增的任何字段（包括新的密钥）都会自动发给只持有低权限 API Key 的一方。控制台用到的字段不变。
- 核心管理页的状态不再夹英文：systemd 查询失败、正在停止、正在重载时分别显示「状态未知」「停止中」「重载中」，此前显示「已安装 · ● unknown」。
- 客户分享页的 Sing-box 区块给出订阅链接（SFA / SFI 用「远程配置」即可自动更新），原始配置收进「查看/复制」；此前只有整段配置和下载按钮。
- 主菜单状态栏按实际状态显示：服务失败显示「运行失败（菜单 12 查看日志）」，崩溃自动重启中显示「启动中 / 自动重启中」，AWG 那一行同样处理；此前一律显示「已停止」或「已安装但未运行」，像是有人把服务停了。
- 核心管理页「重新安装 / 修复」后，如果该核心的服务正在运行，提示里说明它仍在用旧核心、重启该服务后才换成新版本；此前只说「安装完成」，卡片上的版本号却已经是新的。
- Web 登录锁定按来源留日志并写明来源：此前全局只记一条、有人登录成功才重置，之后别的来源被锁、同一来源 10 分钟后再被锁都没有日志，那唯一一条里也没有来源。
- 用户「专属连接」弹窗与客户分享页一样列出其它已启用协议的直链（Reality / VMess / VLESS-Enc / AnyTLS / TUIC，UDP 不通时用）；此前只有 Hy2 一条。
- `bash install.sh awg-status`（`hy2-awgctl status`）在已安装但服务没运行时退出码为 3，可直接用于监控；此前一律返回 0。未安装照旧返回 0。
- 用户表每 2 秒刷新的已用流量与网速和服务端渲染同一写法：此前首屏的「1.00 MB」两秒后被改写成「1024.00 KB」、「1.5 KB」变成「1.50 KB」，网速会显示「1024 B/s」，接口缺字段时甚至是「NaN MB/s」。
- 网页新建 / 删除用户的报错改成中文并说明怎么改（用户标识格式、保留名、数值范围、用户已不存在、旧连接尚未确认断开、登录失效等）：页内提交后这些文字原样弹给管理员，此前一半是英文。

## 2026-11-13 — 第三十一批十项修复，门户 2.41

- 门户启动时恢复 Xray 的结果如实记日志：重启后等它真的起来才写「启动时恢复了 xray 服务」，起不来时写明失败和最近日志。clients 与 portal.json 不一致时，按 portal.json 重写成功后会把停着的 Xray 拉起来；重写没成功就不拉起，旧配置里可能还有该收回的用户。这段逻辑改由可测的函数实现，测试不再测一个早已没人调用的旧版本。
- 网页里 AmneziaWG 的「启动 / 重启」先清失败计数：连续加客户端（热加入失败会兜底重启）再点几次重启就会撞上启动频率上限，此前 5 分钟内点「启动」只会报失败。
- `bash install.sh status` 同时显示门户（Hy2 鉴权后端）的状态；核心或门户不在运行时退出码非零，可直接用于监控。此前服务停着或已失败也返回 0，而且不看门户。
- README 的常用命令表补上 `bash install.sh install` 与 `bash install.sh awg <子命令>`；新增测试，以后脚本新增子命令而文档漏写会直接失败。
- AmneziaWG 客户端列表的「创建时间」按浏览器本地时间显示（原始 UTC 时间放在悬停提示里）：此前原样显示 UTC，国内看到的钟点差 8 小时。
- 菜单安装 WARP 时，只在配置里确实有旧版 `127.0.0.1:40000` 出站时才改写并重启 Hysteria：此前无条件重启，装一次 WARP 就把所有在线用户断开一次。
- `reinstall-debian13.sh` 把体检、确认过的磁盘通过 `-setdisk` 交给 InstallNET：此前不传，InstallNET 自己挑盘，用 `--disk /dev/vdb` 避开救援盘时实际被清空的可能是 vda，多块盘又有 LVM 时甚至是所有磁盘。`--disk` 给 `/dev/disk/by-id/...` 链接时先解析成真实设备，「正被挂载」这条救援盘特征不再漏判。
- `alpine2debian.sh` 的 `--disk` 给符号链接时先解析成真实设备：此前分区名按链接名推导，分区表写完、到格式化这步才失败，盘上数据没了、系统也没装上。
- 用户「专属连接」弹窗与客户分享页一样给出 sing-box 订阅链接（复制、下载、查看配置文本）：接口一直回着 sing-box 配置，弹窗此前只用了 Clash 那份。
- 菜单「查看实时运行日志」同时跟踪核心与门户的日志：用户连不上时原因常在门户这边（鉴权失败、收回失败、计量异常），此前只看核心。

## 2026-11-13 — 第三十批十项修复，门户 2.40

- 计量模块给 Xray 打开 IP 限制路由或在线统计时，重启前先清失败计数：Xray 刚连续重启过、撞上启动频率上限时，重启会被直接拒绝，回滚那次同样起不来，Xray 一直停着。
- 终端菜单「启动 / 重启 Hysteria」「重启门户」，以及 AmneziaWG 的安装、更新、切协议线、resync 和热加入 / 移除失败后的兜底重启，都先清失败计数：配置写坏时崩溃重启约 50 秒就撞上限，此前修好配置后启动会被拒绝长达 5 分钟。
- 版本检测失败时三栏显示「检测失败（可点「重新检测」重试）」，BBR 卡片的「当前内核拥塞控制」显示「读取失败」，不再永远停在「检测中…」/「读取中…」；已经显示过的结果不会被之后某次失败覆盖。
- 一键安装 WARP 失败时只提示原因，不再把整段 JSON 原文（会话过期或反代出错时是整页 HTML）拼进提示。
- 流量超额停用期间，终端菜单与命令行（`awg-install`、`awg install / update / resync`、菜单里的 resync、切协议线、更新）不再拉起 AmneziaWG：此前点一下停用就形同虚设。`awg peer-list` 这类只读命令照常可用。
- 核心管理页的 sing-box 卡片同时看 AnyTLS 与 TUIC 两个服务：只开 TUIC 时不再显示「无服务」；任一服务失败即显示失败。
- 网页「更新面板」后等门户真正恢复再刷新（最长 5 分钟）：此前固定 5 秒后刷新，重启稍慢或新版本起不来走了回滚，页面就落到浏览器的「无法访问此网站」。
- 菜单「刷新信息页」（`bash install.sh refresh-page`）重启门户后等 3 秒再确认：刚换上的门户文件起不来时不再报「网页已更新」，改为报错并打印最近日志；重启前同样先清失败计数。
- 证书自愈单元启用失败时如实报告：「刷新信息页」给出「证书自愈单元未能补齐」提示，全新安装给出警告但不判安装失败；此前一律报「已启用」。
- 登录页：凭据首尾带空白（从聊天软件或终端复制时常见）也能登录；两个输入框关闭手机输入法的自动大写与纠错（用户名是小写随机串，被改一个字母就登不进去）；输错后保留已填的用户名，焦点直接放到密码框。

## 2026-11-12 — 第二十九批十项修复，门户 2.39

- README 的环境变量表补齐 `install.sh` 实际读取的全部 `HY2_*`（指定证书文件、DNS API 各家凭据、`HY2_REGEN_SELF_SIGNED`、`HY2_LOG_LEVEL` 等），证书类型 `2` 不再写成「需交互」；新增测试，以后脚本新增变量而文档漏写会直接失败。
- WARP 未安装或状态查询失败时，分流名单的数量与列表照常显示（或说明读取失败），不再永远停在「加载中…」/「正在拉取规则…」。
- 门户开着时改地址栏的 `#` 或打开同页书签（如 `#cores`、`#proxies/awg`）会切到对应页面并刷新状态：此前没有任何反应，地址栏与显示的页面对不上；直达 `#reality` 时控制台也不再报 5 个「Cannot access … before initialization」错误。
- 账号收回确认不了时（统计接口不通、计量未配置等）不再每 5 秒整份重写一次 `portal.json`；日志写明具体原因，同一原因只在首次和此后每小时提醒一次，恢复时打一行「已恢复」。
- WARP 分流名单增删的起点与页面显示一致：WARP 关着、没保存过名单时页面是空表，点「+ Netflix」只加这一个，不再冒出整套默认域名；关着时点「停用」不再写入默认名单；域名不合法时内存里的名单也不会被改动。
- 装了 Xray 但没在运行时，计量不再把所有用户标成「计量异常」：此前每 5 秒去读 Xray 必然失败，Xray 从没启动过时 `measured_bytes` 还是 null（页面「计量未就绪」）。Xray 再启动后照常采样，按换 epoch 衔接。
- 网页「新建用户 / 删除用户」在页内提交：重名、密码已被占用、收回未完成、用户已不存在等错误就地提示并保留填好的表单，不再跳到一张只有一行纯文本的错误页；成功后自动刷新回到用户列表。
- 用户「专属连接」弹窗对停用 / 到期 / 超额 / 资料异常的账号顶部给出警示：此前照样展示「可直接发给客户」的链接，发出去客户也连不上。
- 后台轮询只在对应页面可见时进行：网速（每 2 秒）只在用户页、WARP 状态（每 10 秒）只在 WARP 子页轮询，切进页面时立即刷新。此前停在任何一页都在轮询，`/traffic-speed` 在全局锁内给每个用户算用量、`/warp-status` 每次起 `systemctl` 并定期经 WARP 探测出口。
- 复制按钮在文字恢复前再点一下不再卡住：用户分享页与管理弹窗此前会把「已复制 ✓」/「已选中，请按 Ctrl+C」当成原文，按钮永远停在那句话上。

## 2026-11-12 — 第二十八批十项修复，门户 2.38

- 卸载时收回本工具放行过的 ufw / firewalld 端口（UDP 主端口、跳跃区间、TCP 订阅端口、各协议与代理端口）：此前只有「改端口」会收回旧端口，卸载后这些端口一直开着。TCP 80 / 443 保留，机主自己的 gost 的代理端口也保留。
- 用户订阅带 `subscription-userinfo` 头：Clash Verge / Stash / Shadowrocket / sing-box 在订阅列表里直接显示已用、总量与到期，不限量与永久账号写 0。
- 安装收尾与 `bash install.sh info` 的安全组提示列出门户里已启用的 Reality / VMess / VLESS-Enc / AnyTLS / TUIC、入站代理与 AmneziaWG 端口：此前只列 Hy2 自己的端口，照着放行仍连不上这些协议。
- 出站分流面板与入站代理表格加载失败时显示原因，不再永远停在「加载中…」；已经显示过的数据不会因之后某次刷新失败被清空。
- 用户订阅带配置文件名（`节点-用户.yaml / .json`）与 24 小时自动更新间隔：客户端不再把订阅命名成网址或「Remote File」，节点改端口 / 换协议后自己跟上。
- 证书到期时间改用标准库解析（`ssl.cert_time_to_seconds`），不再起 `date -d` 子进程：与 locale 无关，没有 GNU date 的系统上证书卡片也不再退化成「未知」。
- DNS API 签发：Cloudflare 只给 API Token（官方推荐）即可，不再强制邮箱；Global API Key 改用 `HY2_CF_KEY + HY2_CF_EMAIL` 走 `CF_Key`（此前只能塞进 Token，被当成 Bearer 认证失败）；阿里云缺 `HY2_ALICLOUD_SECRET` 时直接说明，不去签发。
- 安装依赖时等 dpkg 锁（最多 5 分钟，门户在线装 WARP 时 60 秒）：新开的云主机开机后 unattended-upgrades 常占着锁，此前立刻失败，以「关键依赖缺失：jq」中止，看不出真正原因。
- `alpine2debian.sh` / `reinstall-debian13.sh` 拒绝把分区当成目标磁盘：`/dev/vda1` 也是块设备，此前照收，随后在分区里再建分区表或只擦掉这个分区，装不成系统。
- `users/renew` 给永久账号（未设到期）续费只加流量：此前把它当成早已过期，写成「今天 + N 天」（`extend_days` 缺省 30），只想加流量的永久用户 30 天后被停。

## 2026-11-12 — 第二十七批十项修复，门户 2.37

- iptables 在、nat 表却不可用（OpenVZ / 部分 LXC 容器），或加端口跳跃规则失败时，跳过端口跳跃继续安装：此前在 `set -e` 下直接退出，停在「二进制与证书已就位、配置与门户还没写」，重跑每次都卡在同一步。
- 清理死代码：门户未使用的 `SimpleCookie` 导入与变量、`selfheal` 每 30 分钟白算两遍的证书哈希；`install.sh` 里不会传给 awgctl 的 `AWG_RELEASE_TAG`（改它不起作用）与未使用的变量；`awgctl.sh` 未使用的局部变量。
- `reinstall-debian13.sh` 拒收会被 InstallNET 改写的 root 密码（空格、`* ? [`、`-` 开头等）：InstallNET 生成哈希时不给密码加引号，磁盘清空后新系统的 root 密码就不是输入的那个，SSH 登不上。
- `reinstall-debian13.sh --help` 只打印开头说明：此前按写死的行号把后面的常量与默认值代码一起打出来。
- 测试卫生：假 trafficStats 服务的 `shutdown()` 一并关闭监听 socket，两处子进程输出从「没人读的管道」改为文件，全量测试的 ResourceWarning 从 18 条降为 0；也消除了管道写满让门户卡在写日志上的偶发超时。
- `portal.py` 命令行缺参数时报用法并以 2 退出，不再抛 `IndexError` 堆栈；未知子命令的提示补上漏掉的 `adopt`。
- 门户读取 `config.yaml` 的 `tls.cert` 按 YAML 处理引号与行尾注释，cert / key 顺序任意：此前 `cert: /a.crt  # 注释` 读成带注释的路径，`key` 写在 `cert` 前面时取不到，证书状态、pin 与自愈都拿错证书。
- `install.sh` 四处各抄一份的 `tls.cert` 解析合并为 `config_tls_cert`，与门户同一规则：此前带行尾注释时 `sync_cert_meta` 找不到证书、证书自愈的 path 单元盯错目录。
- `fix_cert_chain.sh` 重启 hysteria-server 前先清失败计数：服务已撞上 StartLimitBurst 时 restart 会被直接拒绝，修好的证书链被当成「起不来」回滚。
- AmneziaWG 连接地址拒收末段全是数字却不是 IPv4 的值（`999.1.1.1`、`1.2.3`、`12345`），门户与 awgctl 同一规则：此前写进客户端配置后被当成域名解析，永远握不上手。

## 2026-11-12 — 第二十六批十项修复，门户 2.36

- `reinstall-debian13.sh` 下载 InstallNET 时 raw.githubusercontent.com 不通会退回 jsDelivr 镜像，并拒收错误页：此前「镜像」与主源是同一个地址且从未被使用，主源一断就只能失败。
- `fix_cert_chain.sh` 修复后的自检按门户同一规则读 `listenHTTPS`：`0.0.0.0:8443`、带引号、带行尾注释的写法与被注释掉的行，不再让自检连错端口、把修好的链报成「验证未通过」。
- 同一自检的 SNI 先取证书 SAN 里的域名（通配符换成 www.），没有再退回 CN 且只取 CN 本身：此前 CN 后面还有字段时截成 `a.com,O=X`，不带 CN 的证书退回 localhost 握手。
- 门户读取 masquerade 端口时忽略 YAML 行尾注释：此前 `listenHTTPS: :8443  # 订阅端口` 读不出端口，缺 `subscription_port` 的老 meta 订阅链接被拼成 443。
- `panel-join.py` 认安装脚本自己写的带引号 `acme.domains`：此前 `my-node.example.com` 被截成 `node.example.com` 登记到面板，不带连字符的域名则取不到。
- `panel-join.py` 去掉配置值的行尾注释与引号，`listen` 带主机时只取端口，对外端口必须在 1–65535，被注释掉的 `listenHTTPS` 不再当成端口：此前带注释的配置误报「没有对外可达的 API 通道」，`:0` 拼出永远连不上的地址还返回成功。
- `alpine2debian.sh` 的安全更新源跟随 `--mirror` / `MIRROR`（`…/debian` → `…/debian-security`，否则用 security.debian.org）：此前固定阿里云，拉取失败时 chroot 里的 `apt-get update` 中止，磁盘已清空却没装上内核与引导；`--help` 不再按写死的行号截掉末尾的警告。
- 管理页各状态卡片（WARP、Reality、VMess、VLESS-Enc、AnyTLS、TUIC、BBR、GOST、AmneziaWG）查询失败时显示「状态未知（请求失败）」，服务端错误放进悬停提示：此前接口报错、回 ok:false 或网络中断时徽章永远停在「检测中...」。
- 「重置 WARP 规则」失败时提示原因，成功后刷新状态：此前失败毫无反应，WARP 生效中仍显示「N 个已配置」。
- 「重启服务器」倒计时结束后等门户真正响应再刷新，5 分钟仍未恢复则提示去服务商控制台查看：此前 25 秒到点无条件刷新，多半落在浏览器的错误页。

## 2026-11-06 — 第二十五批十项修复，门户 2.35

- `portal.json` 的 `users` 不是对象时门户启动即报明确错误：此前照常启动，随后开户、改密、续费、分享页十几处 500。
- 单个用户条目被改成数字 / 字符串 / 列表时，`users/update`、用户详情、分享页按「不存在」处理，不再 500。
- 同一类损坏条目在 `users/renew` 与用户启用 / 停用接口上同样按「不存在」处理（此前停用接口崩溃，滥用用户停不掉）。
- 同一类损坏条目在 `users/create`（API 与 Web 表单）上按「不存在」处理，可以直接重建修好。
- `users/get/<id>` 遇到损坏条目回 404 而不是 500。
- 协议配置段（`reality_config` / `vmess_config`）被改成非对象时，VLESS Encryption 启用、VMess ws_path 读取、Reality 安装回执不再抛异常。
- `is_valid_port` 拒收前导零：`020000` 被 bash 当八进制（8192）导致跳跃区间检查漏判，`08` / `09` 直接报错，`0443` 让端口占用检测找不到占用者。
- 证书域名匹配只看 SAN / CN：此前在 `-subject` 整行里 grep，`O=` 里出现目标域名也会被当成匹配，复用到一张不覆盖该域名的证书。
- 安装结束的安全组提示列出 Hysteria 主监听 UDP 端口（直连走它）。
- nftables 放行覆盖所有会拦截的 input 链，包括 `policy accept` + 末尾 `drop` 的写法与 IPv6 链。

## 2026-11-06 — 第二十四批十项修复，门户 2.34

- nftables 放行覆盖所有会拦截的 input 链：此前只处理第一条 policy drop 链，双栈主机的 IPv6 链没放行；「policy accept + 末尾 drop」写法的链被完全跳过。
- 安装结束的安全组提示列出 Hysteria 2 主监听 UDP 端口：直连走它，不走跳跃区间，此前照着提示放行的用户直连全部超时。
- 订阅生成先清洗 client_meta.json：server_name / public_ip 为数字或 null、is_insecure 写成字符串、hop_port_range 为乱码或倒序时，不再输出 `server: 123`、`skip-cert-verify: 'false'`、`server_ports: ["garbage"]` 这种客户端拒收的配置。
- Reality 的 sni / 公钥 / short_id 被改坏时不再写进订阅（此前会出现 `servername: 123`、丢掉前导零的 short-id、被 & 截断的直链）。
- VMess / VLESS Encryption / AnyTLS / TUIC 的 domain / sni 被改坏时，直链退回公网 IP 或不生成，不再拼出 `@['d']:41000` 这类假地址。
- 分享页与 sync_pin 使用同一套 meta 清洗：server_name 为数字时分享页不再 500；is_insecure 为 "false" 时不再给可信证书节点写 pin。
- 管理页：server_name / public_ip / is_insecure 被改坏时不再 500 或显示错误的标题与提示。
- 管理页：pin_sha256 为非字符串时不再 500。
- 管理页的 API 基础地址给 IPv6 加方括号并转义主机名。
- 选新协议端口时避开停用协议保留的端口：再启用时不必换端口，已发的订阅继续可用。

## 2026-11-06 — 第二十三批十项修复，门户 2.33

- 机主手工加的、带自己 tag 的 Reality 入站不再被门户认领：此前一次开关就会被删掉或改写，门户用户还会被写进它的 clients。
- 计量模块上报的在线 IP 把 `::ffff:a.b.c.d` 还原成 IPv4，与拦截名单、/auth 同一写法。
- `do_upgrade.sh` 重启 Hysteria 前清失败计数：新核心起不来时回滚再启动旧核心，不再因撞上 StartLimitBurst 而回滚失败。
- 卸载 AmneziaWG 时收回其 UDP 监听端口的 ufw / firewalld 放行。
- 「重新修改配置」收回被换掉的端口时，若该端口仍被 gost 代理使用则保留放行。
- `bash install.sh <拼错的命令>` 报错并以 2 退出，不再进菜单、无终端时以 0 退出。
- 菜单 9（启动）在核心启动后立即退出时报失败并给出日志，不再显示「已启动」。
- 菜单 10（停止）停不掉时报失败，不再显示「已停止」。
- `bash install.sh status` 未安装时以非 0 退出。
- 菜单 16 遇到损坏的 `portal-access.json` 时提示用 `refresh-page` 重建。

## 2026-11-06 — 第二十二批十项修复，门户 2.32

- `toggle_warp.sh` 开启 WARP 时所有分流规则都排在兜底规则之前：此前有 9 条写在 `direct_ipv4(all)` 之后，永远不生效；切换时改为清失败计数再启动，流量超额停用期间不拉起服务。
- 内置 ACME 节点上，证书元数据自愈（刷新门户 / 在线升级）不再拿残留的旧自签证书，把 meta 改回 self_signed / www.bing.com / insecure。
- `HY2_CUSTOM_INSECURE` 归一成 true / false 再写入：此前 `yes` 让 jq 失败、client_meta.json 被截空，`1` 则让自愈每次都判漂移。
- /auth 把双栈监听报来的 `::ffff:a.b.c.d` 还原成 IPv4：拦截名单与设备上限此前对这类客户端永远对不上。
- AWG 客户端配置 / 二维码下载会延长连接死线：AWG 更新持锁期间不再 30 秒就被掐断。
- GitHub 版本检查失败缓存 60 秒：此前限流后每次打开页面都再请求两次 GitHub，GitHub 不通时页面多等 16 秒。
- BBR 设置串行化：两个请求同时改时不再互相把对方的结果当成「原状」回滚。
- 复制按钮在 http 下（没有 navigator.clipboard）走 execCommand 兜底：管理页不再对 API Key / pin 这类字段提示「已选中」却什么都没选；用户页不再静默失败。
- 核心更新进度显示任务自己的结果（如「未替换现有补丁」「停用中已就位」），会话过期时立即提示而不是空等 5 分钟。
- Esc 可关闭专属连接与代理详情弹窗。

## 2026-11-04 — 第二十一批十项修复，门户 2.31

- 「重新修改配置」沿用现有自签证书：此前每次重新生成，pin 跟着变，已发放的自签链接全部握手失败（强制换新：`HY2_REGEN_SELF_SIGNED=1`）。
- 只缺 `portal-access.json` 时「重新修改配置」照样询问并默认沿用门户：此前直接重建门户，token / API Key 全换、子账号清空。
- 没有 cron 的机器上 acme.sh 以 `--nocron` 安装，并由 `hy2-acme-renew.timer` 每日续期：此前安装器直接拒绝，Nginx / DNS API 签发都失败，装上也不会续期。
- 收回用户时的 Hy2 兜底重启改走清失败计数的重启，并等统计接口就绪：此前一阵连续收回就撞上启动次数上限，服务锁死、全员掉线。
- 同名旧账号收回未完成时拒绝重建（Web 与 API），新账号不再每 5 秒被踢。
- 新增 / 删除代理不再改写、重启不归本工具管理的 gost.service。
- AnyTLS 启用在协议锁内读取用户表，与撤销流程不再互相覆盖。
- `bash install.sh info` 遇到损坏或不完整的 `portal-access.json` 时提示用 `refresh-page` 重建，不再报 jq 错误或打印 `null`。
- 门户文件包下载失败时报出具体是哪个文件。
- 完整卸载一并移除本工具装的 acme.sh 续期定时器。

## 2026-11-04 — 第二十批十项修复，门户 2.30

- DNS API 签发把凭据以环境变量交给 acme.sh：此前传 `--dns_cf_token` 等 acme.sh 不认识的参数，Cloudflare / 阿里云 / DuckDNS 签发从未成功过；DuckDNS 改用正确的 `dns_duckdns` 插件。
- 内置 ACME 只要 TCP 80 空闲即可签发：此前 443 被占（本项目 Reality 默认就在 443）也判成端口冲突，被推去 Caddy / DNS API / 自签。
- 「重新修改配置」沿用门户时，把网页上保存的 WARP 分流与自定义出站写回新生成的 config.yaml，不再静默消失。
- WARP 安装中途失败（wgcf 注册被限流等）后，完整卸载也会清掉本工具下载的 wgcf / wireproxy。
- 分享页给出所有已启用协议的直链（Reality / VMess / VLESS-Enc / AnyTLS / TUIC），UDP 不通时用 v2rayNG / Shadowrocket 也能导入备用节点。
- 到期时间带上服务器的 UTC 偏移，用户弹窗与用户表 / 分享页显示同一段文本。
- 流量显示先取整再定单位，不再出现「1024.0 KB」（后端与弹窗同一规则）。
- 用量进度条只有真正用满才显示 100%。
- 门户保存状态时写盘与 fsync 不再占着数据锁，慢盘上 /auth 不再跟着卡。
- 设备上限 worker 先拿核心锁再改 xray.json，核心安装 / 升级 / 卸载途中不再重启 Xray。

## 2026-11-04 — 第十九批十项修复，门户 2.29

- `fix_cert_chain.sh` 只改 `tls:` 段里的 `cert:` 行并按字面替换：此前全文 sed，同前缀的 `key:` 路径一起被改坏，hysteria 起不来；新配置下起不来时自动恢复原配置。
- `fix_cert_chain.sh` 只接受叶证书与当前证书一致的 fullchain，多域名机器上不再换成别的域名的证书链。
- `fix_cert_chain.sh` 非 root 时拒绝实际修改（`--dry-run` 照常）。
- `fix_cert_chain.sh` `--config` 缺少取值时退出，不再死循环。
- `panel-join.py --format curl` 输出的每个值都按 shell 规则引用，节点名里的引号不能再拼出额外命令；不再原样打印管理员 JWT，改用 `$PANEL_ADMIN_TOKEN`。`--panel` 必须是 https。
- `panel-join.py` `listenHTTPS: 0.0.0.0:8443` 这类带主机的写法拼出正确的 api_url。
- `users/ip-deny` 拒收保留账号与带 zone 的 IPv6，IPv4 映射地址还原成 IPv4。
- adopt / refresh 不在门户状态锁内运行 qrencode：此前重装沿用门户时 /auth 最长卡 20 秒。
- 出口应用 worker 保存结果失败时不再整份回滚 data（此前会把同期删掉的用户救活、界面卡在「应用中」）。
- 核心更新 worker 结果落盘失败时不再让线程带着异常退出，结果照常显示。

## 2026-11-04 — 第十八批十二项修复，门户 2.28

- `reinstall-debian13.sh` 在用户输入 yes 确认之后才清盘：此前确认前就 wipefs，回答 no 时分区表已经没了。
- `reinstall-debian13.sh` 屏显与日志里遮掉新系统 root 密码。
- `alpine2debian.sh` 救援系统里手工配的静态 IPv4 写成静态地址，不再一律写 DHCP 导致重启后失联。
- `alpine2debian.sh` 判断默认路由改看输出（`ip route` 无默认路由时也返回 0），DHCP 会继续尝试后面的网卡。
- `alpine2debian.sh` 提示输入遇到 EOF 时给出明确错误，不再在 `set -eu` 下无声退出（含装完后的重启提问）。
- `alpine2debian.sh` `--disk` / `--mirror` / `--suite` / `--pwd` 缺少取值时报明确错误。
- `alpine2debian.sh` 分区未就绪的报错提示不再顺手执行 `partx`（反引号被当成命令替换）。
- 流量超额停用期间，1 号菜单「安装」与命令行 `install` 拒绝执行，不再重启服务绕过限额。
- 主监听端口被占时答 y 就地重选端口，而不是照样中止安装。
- AWG 菜单的各个提示在 EOF 时正常返回，不再被 `set -e` 静默杀掉或空转。
- AWG 混淆参数保证四类报文填充后的长度互不相同（此前约 0.9% 的参数组撞车）。
- CI 补上两个重装脚本及其测试的 `sh -n` / `bash -n` 语法校验。

## 2026-11-04 — 第十七批十项修复，门户 2.27

- 依赖安装：关键依赖先单独装、可选依赖逐个装。RHEL / Alma / Rocky 未开 EPEL 时，dnf 因找不到 qrencode 整批不装、jq 跟着缺而中止安装的问题不再出现。
- WARP 分流规则按域名层级排序：更具体的 `mail.google.com` 不再被先加的 `google.com` 吞掉。
- 出口列表在 `custom_outbounds` / `warp_rules` 损坏时照常返回，出口编辑器不再整块空白。
- 托管协议选端口时避开 gost 代理服务的端口：gost 停着时不再被新启用的协议占用。
- 用户专属连接弹窗只显示最后一次点击的结果：A 的晚到回包不再覆盖 B 的链接与二维码。
- 用户专属连接弹窗的设备上限与流量按用户表同一规则显示（不再出现「true IP」「NaN B」）。
- WARP 与 Reality 卡片丢弃晚到的旧状态回包，开关后不再被刷回旧状态。
- 「立即重启服务器」网络出错后按钮恢复可点。
- AWG 切换协议线 / 更新 / 删除客户端在请求期间禁用按钮，防止重复提交。
- Reality 重置密钥在请求期间禁用按钮，防止连续重置两次。

## 2026-11-04 — 第十六批十项修复，门户 2.26

- 证书自愈在 Caddy / 手工换证后会重载 Hysteria、Xray、AnyTLS、TUIC、gost：此前第二轮起永远看不到证书变化，服务一直握着旧证书直到过期。
- 流量超额停用期间，「重新修改配置」「WARP」「gost」菜单拒绝执行，不再重启服务绕过限额。
- 停用期间被关掉的 AnyTLS / TUIC 不再阻塞恢复：此前恢复每轮都失败、节点一直停着，Web 端也无法重新启用。
- 重新配置换了 Hysteria / 订阅端口后，收回旧端口的 ufw / firewalld 放行。
- 重选订阅端口时避开托管协议记下的端口，协议重新启用时不再撞车。
- AWG 换端口重装后收回旧端口的放行。
- AWG 客户端列表损坏时 peer-add / peer-del 拒绝执行，不再用空内容覆盖、删光全部客户端。
- 同域其它不合规范的 cookie 不再让管理员登录后立刻掉线。
- Web 与 API 建户使用同一密码规则：首尾带空白的密码直接拒绝，不再被静默截掉。
- 安装 Xray 时不覆盖不归本工具管理的 xray.service（如官方脚本装的 Xray）。

## 2026-11-04 — 第十五批十项修复，门户 2.25

- 端口跳跃的 OUTPUT 规则只重定向发往本机的 UDP：此前代理替用户访问远端 20000-40000 端口的 UDP（游戏、WebRTC、语音）全被截到本机监听口而断流。
- 导入证书（选项 2）拒绝过期 / 一天内过期的证书和不配对的私钥，回退自签而不是标成可信。
- 扫描本机证书（选项 4）跳过过期或私钥不配对的候选；SNI 必须合法且在证书上。
- 复用 Nginx / Caddy 已有证书时跳过过期证书。
- 通配符证书 `*.example.com` 可用于 `hy2.example.com`。
- `users/update` 不接受纯空白密码（与 create 一致）。
- `users/create` 的 `limit_bytes` / `used_bytes` 不能超过 int64，否则之后永远续不了期。
- `users/renew` 给不限流量的用户加流量时保持不限量，不再变成只剩本次加的量。
- 分享页的拒绝说明与准入判据同源，到期那一秒显示「服务已到期」。
- Xray 补 iplimit 路由时，首个出站就是托管黑洞也不会把黑洞复制成默认出站。

## 2026-11-04 — 第十四批十项修复，门户 2.24

- 重装沿用门户、刷新门户后重启服务时，旧进程退出前的保存不再把 adopt / refresh 刚写入的 API Key、登录凭据、机主密码盖回去（此前控制台重绑后立即 401）。
- 刷新门户时二维码在状态锁外生成，运行中门户的保存不再因此卡住 /auth 最长 20 秒。
- 缺少 `users` / `proxy_services` 的老 portal.json 刷新后补全的字段会真正落盘，门户不再因缺 users 拒绝启动。
- adopt 遇到 `users` 为 null / 列表、机主条目损坏时不再崩溃。
- client_meta.json 缺 `is_insecure` / `server_name` 时 prepare / refresh 不再 KeyError。
- 代理服务列表里的 IPv6 节点地址加上方括号，复制的 socks5:// / http:// 链接可用。
- AWG：首个客户端创建失败不再让已完成的安装报「安装失败」。
- AWG：首次安装失败回滚时执行 daemon-reload，不再总报「原状态恢复不完整」并留下事务目录。
- AWG：在 2.x 安装上 `install --line 3` 会重新生成不满足 3.x 的混淆参数，换协议线不再必然回滚。
- 完整卸载删除本工具创建的 ACME webroot（仍被其他 Nginx 配置引用时保留）。

## 2026-11-04 — 第十三批十项修复，门户 2.23

- AmneziaWG 客户端配置把 IPv6 也导进隧道（`AllowedIPs = 0.0.0.0/0, ::/0`），双栈网络上不再从本地出口泄露真实 IPv6。
- AnyTLS / TUIC 服务崩溃时不再写进订阅（整机超额停用期间照旧保留）。
- client_meta.json 的 `listen_port` 被改坏时，管理页、用户页和所有账号操作的页面重建不再 500。
- 手动导入证书时绑定域名必须合法：此前回车会退回公网 IP 并标成可信证书，链接 `sni=<IP>` 必然校验失败。DNS 不一致等提示在无人值守时读到 EOF 也不再让脚本静默退出。
- BBR 被 `/etc/sysctl.conf` 覆盖时指出冲突的那一行，不再一直提示「重启后生效」。
- AWG 连接地址必须真是主机：「...」「[:]」「[1.2.3.4]」等不再被接受（门户与 awgctl 两侧）。
- `hy2-awgctl qr` 先确认客户端存在，并校验存下的连接地址，与 client-conf 一致。
- `users/ip-deny` 的 ttl 为 Infinity / 小数 / true 时回 400，不再 500 或被静默截断。
- 代理服务 API 的错误回复不再带出内部异常里的文件路径（主动给出的说明照常返回）。
- `custom_outbounds` 为 null 或被改坏时，新增出站照常成功，不再 500。

## 2026-11-04 — 第十二批十项修复，门户 2.22

- 老版本 systemd（< 247）在申请证书之前就被拦下，不再先签完 ACME 证书（占 Let's Encrypt 配额）才中止。
- AmneziaWG 热添加客户端失败时按新配置重启接口，不再报「已创建」而客户端永远握不上手。
- 通过门户删除 AWG 客户端时延长连接死线，不再在等锁时被 30 秒死线掐断、重试又报「不存在」。
- AWG 的启动 / 停止 / 重启与客户端增删、更新串行执行。
- 内核缺少 `tcp_notsent_lowat` 等可选调优项时仍能开启 BBR，只是不写这一项。
- 证书文件存在但读不出有效期时，卡片显示「证书不可读」，不再显示温和的「到期时间未知」。
- 证书状态取不到时卡片说明原因，不再一直停在「检测中…」。
- 会话过期后后台轮询停止并提示刷新，不再每 2 秒发未认证请求、显示冻结的网速。
- users/list 缺 created_at 时报 0（未知），不再每次轮询都给一个新时间戳；`ip_limit: true` 报 0，与鉴权一致。
- 用户断开后网速立即归零，不再在 15 秒内继续显示断开前的速度。

## 2026-11-04 — 第十一批十项修复，门户 2.21

- `HY2_PRESERVE_PORTAL` 只接受 0 / 1：写成 `true` / `yes` / 带空格时，此前会静默重建门户（凭据、API Key、订阅地址全部重生成，除机主外的用户全部清空）。
- 门户收到 SIGTERM（重启、关机、自更新）时先把内存状态落盘：计量每 60 秒才写一次，此前最多丢一分钟流量，关机时还补算不回来。
- AmneziaWG 的 NAT 按隧道网段匹配，不再写死安装时的出口网卡：网卡改名或默认路由换网卡后，客户端不再出现「握手成功但上不了网」。SE 上在独立网络命名空间里验证了规则。
- 菜单 15 重启门户后确认它仍在运行，不再门户起不来也报「已重启」。
- 网页的「重启服务器」按钮在服务器拒绝时（有重型任务 / 会话过期）报错并恢复按钮，不再倒计时刷新、机器其实没重启。
- HEAD 请求按 GET 处理、不带正文，不再回 501（订阅管理器用 HEAD 探测时不再误报失效）。
- 网页安装 WARP 时，旧版 40000 端口的出站改在出站应用锁内迁移并原子落盘，不再由安装脚本在锁外 `sed -i`。
- 重置 Reality 密钥后没有新二维码时清掉旧的，不再让用户扫到旧 pbk。
- 核心版本读不出来时显示「读取失败」，不再显示「（最新）」并隐藏更新按钮。
- 计量的在线设备计数与采样时间在锁内一起更新，用户页不再偶发 500。

## 2026-11-04 — 第十批十项修复，门户 2.20

- `trafficStats.secret` 按原值读取：此前 `gsub(/[^0-9a-f]/,"")` 把手工改过的 secret（如 `AbCd-Efgh_123456`）截成 `bdf123456`，计量每次 401。install.sh 与 do_upgrade.sh 两处都已修改。
- 没装 WARP（wireproxy）时开启 WARP 返回 409，不再把默认分流域名导向没人监听的端口。
- 网页安装 WARP 在写入第一个 wireproxy 资产时才落归属标记，下载失败不再留下标记、导致之后误覆盖 / 误删机主自己的 wireproxy。
- 只由点组成的 user_id（`.` / `..`）不能再开户：分享链接会被浏览器折叠成机主订阅地址。已存在的这类用户仍可删除。
- 证书自愈在 config.yaml 指向的证书不存在时不改任何字段，不再退回旧自签证书、把订阅改成跳过校验。
- 自签证书缺 pin 时按实际在用的证书计算，不再固定读 `cert/server.crt`。
- 菜单 3 / `install.sh info` 在 ACME 节点上提示放行 TCP 80。
- 网页用户表单的中文错误回复声明 UTF-8，不再显示乱码。
- 网页用户表单在保存 / 同步阶段失败时回 500 并说明原因，不再一律回 400「Bad request」。
- 面板自更新成功后清掉上一次留下的「回滚失败」标记。

## 2026-11-04 — 第九批十项修复，门户 2.19

- 重建 Reality（开启、重置密钥）时在锁内重新取用户名单：此前锁外拍的快照可能包含等锁期间刚被撤销的用户，写回后他又能连 Reality，且不会再被撤销。
- 重新开启 Reality 时，保留的端口若已被 Caddy / Nginx 等占用会换一个，不再绑定失败报 500。
- Reality 已关闭时「重置密钥」返回 409，不再顺手把 Reality 重新打开、重新放行端口。
- 借 Nginx + certbot 已有证书：certbot 的 `live/` 目录是符号链接、私钥叫 `privkey.pem`，此前两者都没认出来，永远复用不上（SE 上实测）。
- 证书第一个 SAN 是通配符时，不再把 `*.example.com` 当成节点 SNI。
- 获取公网 IP 时，第一个源返回错误页会继续试下一个，不再直接报「无法获取公网 IP」。
- 网页安装 GOST 时先确认新二进制能在本机运行，跑不起来不会覆盖正在用的版本。
- 测速与解锁检测同一时刻只跑一轮，并发请求回 429，不再占满请求槽导致 /auth 拿不到槽。
- 控制台 API 里 `traffic_gb: true` 被拒绝，不再当成 1 GB 配额。

## 2026-11-03 — 第八批十项修复，门户 2.18

- 门户启动时发现 xray.json 的 clients 与 portal.json 不一致，会按 portal.json 重写并重启 Xray；此前只重启，Xray 重读的仍是旧文件，崩溃前刚开户 / 续费的用户一直连不上 Reality / VMess。
- GOST 生效判定只等实际写进 gost.yml 的端口：一条端口被改坏的代理不再让所有代理的增删都判失败并回滚。
- 一条 HTTPS 代理拿不到证书时只跳过它，不再让所有代理变更失败（包括删掉它本身）。
- `proxy_services` 为 null 或被改坏时，新增代理不再 500。
- 用户页与管理表里 `ip_limit: true` 显示为不限，与鉴权实际行为一致。
- 到期时间为 inf / NaN 时显示「到期时间无效」，与鉴权拒绝一致，不再显示「永久有效」。
- `hy2-awgctl peer-del` 遇到缺公钥的记录时重启接口把它断开，不再静默留着连接。
- 卸载会撤掉安装器登记的 acme.sh 续期（SE 上用 acme.sh 3.1.1 确认 `--remove` 行为）。
- 门户写的 BBR 文件带归属标记，卸载时删除；没有标记的文件保留。
- 代理详情的 URL / 格式 / 链接复制在剪贴板不可用时退回兼容方式。

## 2026-11-03 — 第七批十项修复，门户 2.17

- 核心升级（菜单与 `do_upgrade.sh core`）在重启后再确认 Hysteria 仍在运行：单元是 Type=simple，新核心不认配置或绑不上端口时 restart 照样返回成功，旧实现随即删掉回滚副本、报升级成功，节点崩溃循环且无法回滚。现在会回滚到本次旧核心。
- 重新启用已停用的协议时，保留的端口若已被别的服务占用会换一个，不再沿用后绑定失败、在对方让出端口前永远启用不了。
- 重新配置 / 重装时换成被 TUIC / AWG 等占用的新端口会被拦下；只有沿用 Hysteria 正在用的端口时跳过检查。
- 协议换端口后收回旧端口的防火墙放行规则（VMess / VLESS Encryption / AnyTLS / TUIC，与 Reality 一致）。
- 控制台读到的 AmneziaWG 运行状态改查真正的 systemd 单元 `amneziawg-server`，此前每台节点都显示停止。
- capabilities 遇到被改坏的协议端口时不再整体 500。
- 删除出站时，列表里有坏条目也能删掉，引用它的分流规则一并清除。
- 出站列表的「测出口」会带上 SOCKS5 账号密码，需要认证的出站不再总是探测失败。
- 重置 Reality 密钥后显示服务端的说明，不再写死「UUID 已重新生成并生效」。
- 代理详情里的单字段复制在剪贴板不可用时退回兼容方式，不再点了没反应。

## 2026-11-03 — 第六批十项修复，门户 2.16

- 用户超额或到期后仍在跑的流量照常记账：此前撤销延迟期间的流量从不进 used_bytes，续费后的第一次采样又被当作新基线，这段流量永久丢失。只有停用的用户不记账。
- WARP（wireproxy）同时走 IPv4 与 IPv6：使用 wgcf 下发的双栈地址和 `::/0`。此前只走 IPv4，解析到 IPv6 的分流域名连不上（SE 上用真 wgcf + wireproxy 实测）。install.sh 与网页安装都已修改。
- 调低用户的设备上限后，已在 Reality 上放行的多余设备会被拦下，不再一直在线。
- 端口跳跃的 IPv6 规则在开机时同样恢复。
- firewalld 规则写进默认区，不再写死 public：默认区是 drop / external 的机器上之前端口照样不通。
- 不限设备用户的 IP 记录会剪掉过期项，不再无界增长。
- 已删用户的计量记录在不再需要时清掉，不再随开号删号无界增长。
- 管理面板遇到限流（429）或会话过期（401）时给出可读原因，不再显示 JSON 解析错误。
- AmneziaWG 自动选端口改读 `ss` 监听表，不再用 socket bind 探测。
- 连接日志里出现不带端口的 IPv6 地址时，在线 IP 快照不再整体失败。

## 2026-11-03 — 第五批十项修复，门户 2.15

- Clash / mihomo 订阅里的 Reality 节点改用 mihomo 的字段写法（`tls: true`、`reality-opts`）：此前 mihomo v1.19.15 整份配置加载失败（SE 上用真 mihomo 校验）。
- 启用 VLESS Encryption 后 sing-box 订阅重新可用：sing-box 不支持这个协议，带 `encryption` 字段时整份 sing-box.json 加载失败，连 Hy2 节点一起不可用（SE 上 sing-box 1.14.4 校验）。sing-box 订阅里不再下发这一条，Clash 订阅照旧。
- 不带有效 key 的 API 请求单独限流，打满也不影响控制台的停用 / 删除。
- Web 失败请求按来源计数：拿到分享链接的人不再能让管理页和所有人的订阅更新都 429。
- 登录失败按来源计数（每来源 10 次 / 10 分钟，全局 200 次兜底），别人刷错误密码不再把机主锁在门外。来源取 Hysteria masquerade 写入的 X-Forwarded-For（v2.13.0 实测会覆盖客户端自带的值）。
- 门户访问凭据重建后，用旧密码登录的会话失效；分享链接不受影响。
- AnyTLS 端口被改坏时停用不再报错，面板状态与实际一致。
- 卸载时 AmneziaWG 移除失败会如实报错，并保留 `hy2-awgctl`。
- `hy2-awgctl resync` 新配置起不来时回滚到原配置。
- `hy2-awgctl peer-add` 失败（例如地址池满）不再留下含全部客户端私钥的备份文件。

## 2026-11-03 — 第四批十项修复，门户 2.14

- GOST 代理拒绝访问内网、云元数据与本机地址：此前买家拿到的 SOCKS5 / HTTP 代理能读 169.254.169.254，也能连本机的门户与 Xray API（SE 节点用真 gost 3.2.6 实测）。GOST 只按请求里的目标地址匹配，解析到内网的域名仍能穿过。
- AmneziaWG 客户端经隧道访问内网与云元数据的流量被丢弃，客户端之间互访不受影响。
- 手动导入证书时，不含任何证书的文件不再被当成完整证书链直接使用。
- `ip_limit` 写成 `true` 时 Hy2 与 Reality 都视为不限设备；此前 Hy2 限 1 台、Reality 不限。
- 开启 Reality 在线统计只保留一份备份，不再随每次改动累积；回滚重启失败时报告真正的失败原因。
- 出站、分流规则与 WARP 的变更重新能下发：此前每次保存都在写盘后报 500（NameError），配置写进 portal.json 却从未应用。
- 一条缺 domain 的分流规则不再让所有规则增删报 500。
- 机主账号的到期时间改为 9999-12-31；老节点上 2036-02-07 的旧值在 adopt 时一并改掉。
- 改用户密码（users/update，或 users/create 覆盖已有用户）后，用旧密码连着的 Hy2 会话会被断开。
- 退出登录在服务端作废会话：此前只清浏览器 Cookie，被复制走的 Cookie 在 30 天内照样能用。不带有效会话的登出请求不影响别人的登录。

## 2026-11-03 — 第三批十项修复，门户 2.13

- Xray 内网保护对域名目标也生效（`routing.domainStrategy` 设为 `IPIfNonMatch`）：此前用 `localhost.localdomain`、`localtest.me` 等解析到回环的域名能绕过拦截，访问本机门户、计量端口与云元数据（SE 节点用真 Xray 实测）。
- 网页安装 WARP 与 install.sh 用同一套归属规则：不再覆盖机器上别人的 wireproxy；写入归属标记，install.sh 卸载能把它清干净。
- `do_upgrade.sh portal` 自愈重写 client_meta.json 时保持 0600，主密码不再对本地用户可读。
- `do_upgrade.sh` 自愈按门户同一规则选 SNI：多域名证书不再把 SNI 换成另一个域名，第一个 SAN 是通配符时也能自愈。
- client_meta.json 是合法 JSON 但不是对象时，证书自愈安静跳过，不再每 30 分钟报错一次。
- Reality「重新生成密钥对」的提示改正（用户 UUID 不变，只需更新 pbk）；节点停用期间重置时如实说明新密钥在恢复后生效。
- portal-access.json 被截断或写坏时，管理页仍能打开。
- 门户地址与订阅地址里的 IPv6 主机加上方括号，控制台存下的门户地址可以正常解析。
- 借 Nginx 签发证书时，签发成功但复制证书失败，会撤掉新增的验证配置，不再留下无归属的站点。
- 安装 Xray 核心前先确认新二进制能运行，跑不起来不会覆盖正在用的旧核心。

## 2026-11-03 — 第二批十项修复，门户 2.12

- 撤销用户时若某个协议刚被停用，clients 不再被写进计量 API 入站（之后启用任何协议都会失败）。
- 停用 VMess / VLESS Encryption 保留 ws_path、密钥对与端口（只标 `enabled: false`）；再启用不再换参数，已发订阅继续有效。
- 已在 8443 等内置黑名单端口上服务的协议，重置密钥 / 重启开关时不再被挪到别的端口。
- 首次启用 VMess / VLESS Encryption / AnyTLS 时，默认端口（2087 / 2088 / 2096）也要查监听表，被占用就换一个，不再撞车回滚。
- `hy2-awgctl` 拿到操作锁后不再吞掉 stderr；AWG 出错时门户能看到真实原因。
- `hy2-awgctl` 下载有总时长上限，且 curl 不再继承锁；下载卡住不会永久占锁。
- Hysteria 服务端日志级别默认改回 `info`：官方核心没有 `/online/ips`，在线 IP 要靠 journal 的 INFO 行重建，`error` 级下设备上限会退化（SE 节点实测）。
- 安装 / 重装时先取门户整包再写 config.yaml；取不到时现有配置保持原样，不会让鉴权指向没人监听的端口。
- 菜单 2 更新核心时不再静默覆盖带 `+` 的定制核心；确需替换请 `export HY2_ALLOW_CUSTOM_CORE_REPLACE=1`。
- ACME 域名与通知邮箱按主机名 / 邮箱格式校验（含 `HY2_DOMAIN` / `HY2_EMAIL`），不再能把引号、分号、换行写进 config.yaml / nginx / Caddy 配置。

## 2026-11-03 — 十项修复，门户 2.11

- 网页自更新清理旧备份时只认门户六个文件的 `.bak-*`；此前第 4 次自更新会删掉 install.sh 改配置前留的 portal.json / client_meta.json / config.yaml / 证书快照。
- `anytls.json` 不在但 sing-box 仍在运行时，不再把撤销当作已完成（与 TUIC 一致），停用 / 到期 / 删除的用户不会继续用 AnyTLS 连。
- 用户详情弹窗里永久用户不再显示成 1970-01-01 到期。
- `panel-join.py` 按门户同一规则取主机名（自签用 public_ip，可信证书用 server_name），不再输出 `https://<端口>`；取不到主机名时退出码 3。
- 整机流量超额停用期间，AWG 的启动 / 重启 / 更新 / 切换协议线返回 409，不再把停用的 AWG 拉起来。
- 一条密码不是字符串的旧用户记录不再让管理页渲染失败。
- `fix_cert_chain.sh` 能读带引号的 `tls.cert`（install.sh 就是这样写的）。
- peers.json 里有坏条目时，AWG 客户端配置与二维码仍能下载。
- 停用期间在网页更新 Hysteria 核心：新核心保留，恢复节点时生效，不再被回滚并报「新核心未成功加载」（与 install.sh 一致）。
- 管理页与客户页的状态徽标取自同一准入判据；`/auth` 拒绝的坏记录不再显示「正常」。
- 启用 VMess / VLESS Encryption 不再自锁挂起；此前请求永远不返回，核心锁一直被占，之后每轮撤销都失败，停用 / 到期用户一直能连，直到门户重启。
- 用户记录被写成 null / 0 / 空串 / 空列表时，Reality / VMess / VLESS Encryption / AnyTLS / TUIC 不再给它可用身份（`/auth` 本来就拒绝）。
- REST API 收到含孤立代理项的 JSON 字符串时返回 400；此前它会让之后所有的落盘都失败，直到门户重启。
- AnyTLS / TUIC 配置文件丢失而服务仍在运行时：只有确有人要收回才报「无法确认」，不再让开户 / 续费全部 503；停用操作在这种状态下也能真正停掉服务。

## 2026-11-02 — /auth 按来源限流，门户 2.10

- `/auth` 的失败桶与速率桶改为按 Hysteria 鉴权体里的 `addr` 分桶（IPv4 单地址、IPv6 按 /64），旧实现是进程全局桶：任何人 60 秒内用错误密码连 30 次，全节点合法用户都被回 `Auth service busy`。全局只保留每秒 500 次的兜底，桶数上限 4096、淘汰最久未活动者。返回格式不变。
- 门户监听 backlog 从默认 5 调到 128（实测开机以来溢出 208 次）。
- Hysteria 服务端日志级别默认 `error`，写在 `hysteria-server.service.d/loglevel.conf`（`HYSTERIA_LOG_LEVEL`）；安装前 `export HY2_LOG_LEVEL=info` 可覆盖，重装时保留已有 drop-in。（2026-11-03 已改回默认 `info`，见上方条目。）
- 新增按来源限流、IPv6 归并、全局兜底、桶上限、backlog 与日志 drop-in 回归测试。

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

### 新增：TUIC v5 通道（2026-10-31）
- 由独立的 sing-box 进程 `hy2-tuic` 承载（配置 `/etc/hysteria/tuic.json`），与 AnyTLS / Xray 互不影响启停。
- 需要域名与可信证书；UDP 端口自动从 41000-49999 选取，避开 Hy2 端口跳跃区间，云安全组需放行。
- 每个用户的 UUID / 密码由节点 secret 派生；停用、到期、超额、删除同步收回，整机超额停用一并停服。
- 订阅（Clash / sing-box url-test）、`tuic://` 直链、REST API 的 `tuic_uri`、核心管理页与卸载流程同步支持。

### 新增：AnyTLS 通道与核心管理页（2026-10-28）
- AnyTLS 由 sing-box（`hy2-anytls`）承载，需要域名与可信证书。
- 新增「核心管理」页：集中查看各核心的版本与服务状态，Xray / sing-box 可在此安装、卸载（仍有协议在用时拒绝卸载）。

### 新增：跨节点统一设备上限（2026-10-30）
- `POST /api/v1/users/ip-deny`：控制台把各节点合并后超出总名额的 IP 下发到每台节点，整份替换、带 30-3600 秒有效期。
- Hy2 在 `/auth` 拒绝被拦 IP，新加入且在线的 IP 踢下线一次；Reality 并入 iplimit 黑洞规则。只存内存，过期或重启即失效。

### 增强：80 端口被 Nginx 占用时自动借 Nginx 签发证书（2026-10-29）
- 域名已有站点时用 acme.sh `--nginx` 模式，原站点配置不改动；没有时新增独立验证配置并走 webroot。
- 现有 Nginx 配置本身有错时直接放弃，不碰；签发失败撤掉新增的验证配置。续期后自动重启 Hy2 / Xray / AnyTLS / TUIC。

### 增强：可选 GitHub token（2026-10-28）
- 把无权限 token 写入 `/etc/hysteria/github-token`（0600），面板与安装脚本只在访问 `api.github.com` 时带上，避免匿名 60 次/小时额度被同机程序耗尽导致版本检测失败。

### 增强：自定义出站页改版（2026-10-31）
- 模式切换并入标题栏，出口探测与出站列表并排，分流规则在全局模式下变灰。
- 新增出站支持粘贴 `socks5://`、`http(s)://`、`user:pass@host:port`、`host:port:user:pass` 自动填写，类型按钮选择，名称自动生成，保存前可「测试连通」；编辑时锁定名称。

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
