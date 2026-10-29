"""门户计量运行时：真实累计同步到 used_bytes；旧值另存 legacy_auth_value，不混入新窗口。"""
import copy
import importlib.util
import json
import pathlib
import sys
import threading
import time
from datetime import datetime, timezone

ACCOUNTING_REVISION = "2026-10-12-real-usage-v2"
ROOT = pathlib.Path(__file__).parent

def load(name, filename):
    spec=importlib.util.spec_from_file_location(name, ROOT / filename)
    mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod); return mod

core=load('usage_meter_core', 'usage-meter-core-20261007-v1.py')
readers=load('usage_meter_readers', 'usage-meter-readers-20261007-v1.py')
if getattr(core, 'ACCOUNTING_REVISION', None) != ACCOUNTING_REVISION:
    raise RuntimeError('usage_meter_core_revision_mismatch')

def _source_fresh(health, source, max_age=30):
    """某来源的健康条目是否新鲜且可用。

    health 里的 sampled_at 可能缺失、为空或不是合法 ISO（恢复旧备份、
    手工编辑）。旧实现直接 health[s]['sampled_at'] + fromisoformat，
    会让 /traffic-speed 与 users/list 在 data_lock 内抛异常 → 整个列表接口
    500（2026-10-29 修）。解析失败一律视为「不新鲜」。
    """
    entry = (health or {}).get(source)
    if not isinstance(entry, dict) or not entry.get('ok'):
        return False
    raw = entry.get('sampled_at')
    if not isinstance(raw, str) or not raw:
        return False
    try:
        when = datetime.fromisoformat(raw.replace('Z', '+00:00')).timestamp()
    except (TypeError, ValueError):
        return False
    return 0 <= time.time() - when < max_age


_recent_gaps_cache = {'key': None, 'value': []}


def _recent_gaps(m, window_seconds=86400):
    """最近 window_seconds 内是否发生过计量缺口。

    `gaps` 是**历史事实**，只在超过 100 条时截断，从不按时间失效。
    旧实现用 `not m.get('gaps')` 判断健康度，于是节点第一次重启之后
    measurement_ok 永久为 false —— 控制台再也分不清「刚重启过一次」
    与「计量真的坏了」（2026-10-29 修）。
    没有时间戳的条目按「最近」处理（保守，宁可报异常）。
    """
    gaps = m.get('gaps') or []
    if not gaps:
        return []
    # 结果只取决于全局 gaps，而 summary()/hot_summary() 会**按用户**各调一次，
    # /traffic-speed 每 2 秒 × 全部用户 × 最多 100 条 gap，实测 2000 用户
    # 单次 0.12 秒全花在重复计算上（2026-10-29 修）。
    # 缺口列表可能整体替换，也可能在时间戳相同时发生改变；不能只看长度
    # 和最后一条时间，否则会把旧列表的健康结果复用到新的状态。
    cache_key = (json.dumps(gaps, sort_keys=True, ensure_ascii=False),
                 int(time.time() // 30), window_seconds)
    if _recent_gaps_cache.get('key') == cache_key:
        return _recent_gaps_cache['value']
    cutoff = time.time() - window_seconds
    recent = []
    for gap in gaps:
        at = (gap or {}).get('at') if isinstance(gap, dict) else None
        if not at:
            recent.append(gap)
            continue
        try:
            when = datetime.fromisoformat(str(at).replace('Z', '+00:00')).timestamp()
        except (TypeError, ValueError):
            recent.append(gap)
            continue
        if when >= cutoff:
            recent.append(gap)
    _recent_gaps_cache.update(key=cache_key, value=recent)
    return recent

class PortalMeter:
    def __init__(self, data, lock, save, config, read=None, epoch=None, on_speed=None):
        self.data, self.lock, self.save, self.config=data,lock,save,config
        self.read=read or self._read
        self.epoch=epoch or readers.service_epoch
        self.stop=threading.Event()
        # 速率采样回调（2026-10-08）：on_speed(uid, tx, rx, elapsed, source)
        # 由 portal.py 注入，把本轮真实字节增量写进 speed_tracker。
        # 之前 speed_tracker 没有写入侧，/traffic-speed 长期返回 0。
        # 参数是单用户增量、实际区间及来源；不是整个 deltas 字典。
        # 每个来源每个用户各调一次。
        self.on_speed=on_speed
        self.sample_times={}
        self.online_counts=None
        self.online_sampled_at=0
        self.live_snapshot=None
        self.live_sampled_at=0
        self.live_next_at=0

    def enabled_sources(self):
        sources=[s for s in ("hysteria", "reality") if self.config.get(s)]
        # 默认安装会写 Reality 配置，但未安装 xray 时不应阻塞 Hy2 计量。
        cfg=self.config.get("reality", {})
        if self.read == self._read and "reality" in sources and not pathlib.Path(cfg.get("binary", "")).is_file():
            sources.remove("reality")
        return sources

    def _read(self, source, cfg):
        if source=='hysteria':
            counters=readers.read_hysteria(cfg['url'],cfg['secret'])
            try:
                self.online_counts=readers.read_hysteria_online(cfg['url'],cfg['secret'])
                self.online_sampled_at=time.time()
            except Exception:
                self.online_counts=None
                self.online_sampled_at=0
            return counters
        return readers.read_xray(cfg['binary'],cfg['address'])

    def poll(self):
        if self.read == self._read and time.monotonic() >= self.live_next_at:
            self.live_next_at=time.monotonic()+15
            try:
                snapshot=readers.read_live_connections()
                with self.lock:
                    self.live_snapshot=snapshot
                    self.live_sampled_at=time.time()
            except Exception:
                with self.lock:
                    self.live_snapshot=None
                    self.live_sampled_at=0
        for source in self.enabled_sources():
            cfg=self.config.get(source)
            now=datetime.now(timezone.utc).isoformat()
            try:
                if not cfg: raise RuntimeError('source_not_configured')
                service='hysteria-server' if source=='hysteria' else 'xray'
                before=self.epoch(service)
                counters=self.read(source,cfg)
                if self.epoch(service)!=before: raise RuntimeError('service_changed_during_read')
                # 🔴 锁顺序（2026-10-29 修）：
                # 请求线程是「data_lock → meter.lock」（users/list、traffic-speed
                # 在持有 data_lock 时调用 summary()），所以这里**绝不能**在
                # 持有 meter.lock 时去调 save()（它内部拿 data_lock）或
                # on_speed（同样拿 data_lock）—— 那是典型的 ABBA 死锁，一旦
                # 交错门户就永久卡死，/auth 不可用、所有客户端掉线。
                # 现在：锁内只算与写字典，锁外落盘与回调。
                with self.lock:
                    meter=copy.deepcopy(self.data.get('usage_meter',{}))
                    # 每个账户首次基线：不将已存在、未归属新窗口的进程计数混入。
                    # 注意：registered_users 只用于诊断（首次接入时记录当时的账户集合），
                    # 计量准入完全由 totals/sources 决定，没有任何代码读取它。
                    meter.setdefault('registered_users', list(self.data.get('users',{})))
                    # 已存在客户在后续才第一次出现在计数器中时，core 从零累加是有效的：
                    # 当前服务为所有用户保持单调累计，且初始窗口无计数表示0。
                    outcome = core.apply_sample(meter,source,before,counters,now)
                    meter.setdefault('health',{})[source]={'ok':True,'sampled_at':now,'error':''}
                    meter.setdefault('started_at',now)
                    old=self.data.get('usage_meter')
                    user_changes=[]
                    for uid, user in self.data.get('users', {}).items():
                        if not isinstance(user, dict):
                            continue
                        user_before={k: user[k] for k in ('used_bytes', 'legacy_auth_value') if k in user}
                        user.setdefault('legacy_auth_value', user.get('used_bytes', 0))
                        user['used_bytes']=core.total_bytes(meter, uid)
                        user_after={k: user[k] for k in ('used_bytes', 'legacy_auth_value')}
                        user_changes.append((uid, user, user_before, user_after))
                    self.data['usage_meter']=meter
                    sampled=time.monotonic()
                    previous=self.sample_times.get(source)
                    deltas=dict(outcome.get('deltas') or {})
                    interval=sampled-previous if previous is not None else 0
                try:
                    self.save()
                except Exception:
                    with self.lock:
                        # 锁外写盘期间用户可能已被删除、停用或重新创建。只撤销
                        # 本次仍未被改动的计量字段，不能用旧快照替换整张用户表。
                        for uid, user, before, after in user_changes:
                            if self.data.get('users', {}).get(uid) is not user:
                                continue
                            for key, value in after.items():
                                if key not in user or user[key] != value:
                                    continue
                                if key in before: user[key]=before[key]
                                else: user.pop(key, None)
                        if self.data.get('usage_meter') is meter:
                            if old is None: self.data.pop('usage_meter',None)
                            else: self.data['usage_meter']=old
                    raise
                self.sample_times[source]=sampled
                if self.on_speed is not None and interval > 0:
                    for uid, pair in deltas.items():
                        try:
                            self.on_speed(uid, pair[0], pair[1], interval, source)
                        except Exception as exc:
                            print(f'[meter] on_speed failed: {type(exc).__name__}', file=sys.stderr)
            except Exception as exc:
                with self.lock:
                    old=copy.deepcopy(self.data.get('usage_meter'))
                    self.data.setdefault('usage_meter',{}).setdefault('health',{})[source]={
                        'ok':False,'sampled_at':now,'error':type(exc).__name__}
                try:
                    self.save()
                except Exception:
                    with self.lock:
                        if old is None: self.data.pop('usage_meter',None)
                        else: self.data['usage_meter']=old

    def summary(self, uid):
        with self.lock:
            m=self.data.get('usage_meter',{})
            health=m.get('health',{})
            enabled=self.enabled_sources()
            fresh=bool(enabled) and all(_source_fresh(health, s) for s in enabled)
            initialized=bool(enabled) and all(s in m.get('sources',{}) for s in enabled)
            return {'measured_bytes':core.total_bytes(m,uid) if initialized else None,
                'measurement_started_at':m.get('started_at'),
                'measurement_ok':initialized and fresh and not _recent_gaps(m),
                'measurement_current_ok': initialized and fresh,
                'measurement_complete': initialized and not m.get('gaps'),
                'current_online': copy.deepcopy(self.live_snapshot.get('users',{}).get(uid,{})) if self.live_snapshot is not None and time.time()-self.live_sampled_at < 45 else {'ips': [], 'ok': False, 'hysteria_ok': False, 'reality_ok': False, 'error':'current online IP unavailable'},
                'online_ip_scope': 'recent_authentication',
                'online_devices': self.online_counts.get(uid, 0) if self.online_counts is not None and time.time()-self.online_sampled_at < 30 else None,
                'online_devices_scope': 'hysteria_core_instances_only',
                'measurement_scope':'since_measurement_started',
                'measurement_sources':{s:copy.deepcopy(health.get(s, {})) for s in enabled},
                'measurement_gaps':copy.deepcopy(m.get('gaps',[])),
                'legacy_auth_value':self.data.get('users',{}).get(uid,{}).get('legacy_auth_value', self.data.get('users',{}).get(uid,{}).get('used_bytes',0))}

    def hot_summary(self, uid):
        """summary() 的轻量版：只算 /traffic-speed 高频轮询需要的标量字段。

        🔴 2026-10-28 修（性能）：summary() 对每个用户 deepcopy
        measurement_gaps（最多 100 条）、measurement_sources、
        current_online —— 而 /traffic-speed 每 2 秒一次 × 全部用户，
        前端只消费 measured_bytes / measurement_ok / used_bytes 等
        5 个标量。200 用户实测每次 56ms 全花在没人读的深拷贝上，
        且全程持有 meter lock 与 portal 的 data_lock（usage_summary
        在 data_lock 内被调用），用户量大时会卡 /auth 鉴权。
        热路径改用本方法：不做任何 deepcopy，只读标量。
        """
        with self.lock:
            m=self.data.get('usage_meter',{})
            health=m.get('health',{})
            enabled=self.enabled_sources()
            fresh=bool(enabled) and all(_source_fresh(health, s) for s in enabled)
            initialized=bool(enabled) and all(s in m.get('sources',{}) for s in enabled)
            return {'measured_bytes':core.total_bytes(m,uid) if initialized else None,
                'measurement_ok':initialized and fresh and not _recent_gaps(m),
                'measurement_started_at':m.get('started_at'),
                'measurement_scope':'since_measurement_started'}

    def run(self):
        while not self.stop.is_set():
            self.poll(); self.stop.wait(5)

    def start(self):
        thread=threading.Thread(target=self.run,name='portal-real-usage-meter',daemon=True)
        thread.start(); return thread


def from_file(data,lock,save,path,on_speed=None):
    config=json.loads(pathlib.Path(path).read_text(encoding='utf-8'))
    return PortalMeter(data,lock,save,config,on_speed=on_speed)
