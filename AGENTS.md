# 项目约定（改代码前必读）

这份文件记录**用真实故障换来的不变量**。改动前请先确认不会破坏它们。

## 门户组成

门户是**六个文件**，必须整组存在、整组更新：

```
portal.py
portal_assets.py
usage-meter-core-20261007-v1.py
usage-meter-readers-20261007-v1.py
usage-meter-runtime-20261007-v1.py
usage-meter-xray-config-20261007-v1.py
```

清单以 `PORTAL_BUNDLE_FILES` 为准。只更新其中一部分会让门户起不来，
而门户同时是 Hysteria 的鉴权后端 —— 它挂了所有用户都连不上。

## Xray 托管入站

三种协议共用一个 Xray 进程，各自一个带固定 tag 的入站：

| 协议 | tag | 需要域名证书 |
|---|---|---|
| VLESS-Reality | `vless-reality-in` | 否（借用大厂握手） |
| VMess-WS-TLS | `vmess-ws-in` | 是 |
| VLESS Encryption | `vless-enc-in` | 是 |

规则：

- **定位一律按 tag**（`managed_inbound_index`）。不要按协议特征去找入站。
- **读-改-写必须整体在 `reality_apply_lock` 内**。在锁外读 `xray.json`、
  锁内才写，会在两个协议同时启用时用旧快照覆盖磁盘，静默丢掉一个协议。
- **停用一种协议只删自己的入站并 restart**，绝不能 `systemctl stop xray`，
  那会把另外两个协议一起停掉。
- **撤销必须覆盖所有托管入站**（`MANAGED_INBOUND_TAGS`）。只看 Reality 的话，
  停用/到期/超额的用户在 VMess 上照样能连。
- clients 为空时要写**占位 client**，否则 Xray 起得来但没人能连。
- VMess / VLESS Encryption 的 clients **不能带 `flow`**（那是 Reality 专用）。

## 端口

- 端口选择走 `_pick_reality_port`，避让清单用 `managed_reserved_ports`。
- 显式拉黑的端口优先于「沿用原端口」，否则会撞车。
- 不要用 socket bind 探测端口（某些环境会卡住），只读 `ss` 的监听表。

## 用户生命周期

- 准入判据只有一份：`user_access_allowed`。`user_share_available` 必须与它同源。
- `expires_at` 缺失视为永久；`expires_at=0` 视为**已过期**。
- `admin_master` 与 `placeholder` 是保留名，不能作为真实 user_id。
- 删除用户要同时清 `ip_tracker`、`speed_tracker` 与 `usage_meter.totals`。

## 安全边界

- Xray 三种协议都要 `add_private_network_guard`：拒绝访问内网与云元数据。
- 所有 `subprocess.run` 传列表参数，不拼 shell 字符串，并带 `timeout`。
- 用户可控值进入命令前必须过 `VALID_USER_ID_RE` / `VALID_AWG_NAME_RE`。
- `/auth` 与 Web 登录各有独立的失败计数桶；不要合并进通用速率桶，
  那个桶 60 秒就剪裁，达不到阈值。

## 测试

- 新增行为要有回归测试，且**锁住行为而不是匹配源码字符串**。
- 测试里单独摘出执行的代码片段（`ast` 提取），需要把用到的名字补进环境。
- 完整回归：`python -m unittest discover -s tests -p 'test_*.py'`。
- CI 还会跑 shell 语法、安装交互、证书矩阵、下载冒烟，见 `.github/workflows/tests.yml`。

## 发布

- 门户自更新与安装都会先锁定 `main` 的具体 commit 再下载，避免跨版本混装。
- 改完后本地、GitHub `main`、节点三方要一致；节点升级前先备份 `/etc/hysteria/portal*.py`。
