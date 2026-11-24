"""幂等添加仅回环 StatsService；不修改任何 clients 或 Reality 参数。"""
import copy
import errno
import pathlib
import json
import os
import secrets
import shutil
import stat
import subprocess
import time

_MAX_XRAY_CONFIG_BYTES = 4 * 1024 * 1024


def _read_regular_config_bytes(path):
    """安全读取常规 Xray 配置文件：先 lstat 校验再 POSIX 下 O_NOFOLLOW+fstat 有界读盘，拒绝符号链接与超 4 MiB 文件。"""
    st0 = path.lstat()
    if stat.S_ISLNK(st0.st_mode) or not stat.S_ISREG(st0.st_mode):
        raise ValueError('xray config must be a regular file')
    if st0.st_size > _MAX_XRAY_CONFIG_BYTES:
        raise ValueError('xray config too large')
    nofollow = getattr(os, 'O_NOFOLLOW', 0)
    if nofollow:
        fd = None
        try:
            try:
                fd = os.open(str(path), os.O_RDONLY | nofollow)
            except OSError as exc:
                if exc.errno == errno.ELOOP:
                    raise ValueError('xray config must be a regular file') from None
                raise
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise ValueError('xray config must be a regular file')
            if st.st_size > _MAX_XRAY_CONFIG_BYTES:
                raise ValueError('xray config too large')
            with os.fdopen(fd, 'rb') as fh:
                fd = None
                raw = fh.read(_MAX_XRAY_CONFIG_BYTES + 1)
            if len(raw) > _MAX_XRAY_CONFIG_BYTES:
                raise ValueError('xray config too large')
            return raw, (st.st_mode & 0o777) or 0o600
        finally:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
    with open(path, 'rb') as fh:
        raw = fh.read(_MAX_XRAY_CONFIG_BYTES + 1)
    if len(raw) > _MAX_XRAY_CONFIG_BYTES:
        raise ValueError('xray config too large')
    return raw, (st0.st_mode & 0o777) or 0o600


def _validate_loopback_address(address):
    if not isinstance(address, str) or not address.startswith('127.0.0.1:'):
        raise ValueError('stats endpoint must be loopback')
    port_text = address[len('127.0.0.1:'):]
    if (not port_text.isascii() or not port_text.isdigit() or len(port_text) > 5
            or port_text.startswith('0') or not (1 <= int(port_text) <= 65535)):
        raise ValueError('stats endpoint must be loopback')


def _validate_binary(binary):
    if (not isinstance(binary, str) or not binary.strip()
            or binary.strip().startswith('-')
            or any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in binary)):
        raise ValueError('invalid xray binary')


def _client_level_key(raw_level):
    """将客户端 level 规整为非负整数字符串，忽略 null/布尔/非法值，避免污染 policy.levels。"""
    if isinstance(raw_level, bool) or raw_level is None:
        return None
    if isinstance(raw_level, int):
        return str(raw_level) if raw_level >= 0 else None
    if isinstance(raw_level, str):
        cleaned = raw_level.strip()
        if cleaned and len(cleaned) <= 6 and cleaned.isascii() and cleaned.isdigit():
            return str(int(cleaned))
    return None


def _inbound_uses_port(raw_port, target_port):
    """判断 Xray 入站 port（支持整数、数字字符串、逗号分隔列表或 lo-hi 区间）是否覆盖 target_port。"""
    if isinstance(raw_port, bool) or raw_port is None:
        return False
    if isinstance(raw_port, int):
        return raw_port == target_port
    if isinstance(raw_port, str):
        for seg in raw_port.split(','):
            seg = seg.strip()
            if not seg:
                continue
            if '-' in seg:
                lo_s, _, hi_s = seg.partition('-')
                lo_s, hi_s = lo_s.strip(), hi_s.strip()
                if (lo_s.isascii() and lo_s.isdigit() and len(lo_s) <= 5
                        and hi_s.isascii() and hi_s.isdigit() and len(hi_s) <= 5):
                    lo, hi = int(lo_s), int(hi_s)
                    if lo <= target_port <= hi:
                        return True
            elif seg.isascii() and seg.isdigit() and len(seg) <= 5 and int(seg) == target_port:
                return True
    return False


def _fsync_parent_dir(target):
    """在支持目录 fsync 的系统上刷盘父目录项，确保 os.replace 落盘持久。"""
    parent = pathlib.Path(target).parent
    try:
        dir_fd = os.open(str(parent), os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
    except OSError:
        return
    try:
        os.fsync(dir_fd)
    except OSError:
        pass
    finally:
        try:
            os.close(dir_fd)
        except OSError:
            pass


def _inbound_clients(inbound):
    if not isinstance(inbound, dict):
        return None
    settings = inbound.get('settings')
    if not isinstance(settings, dict):
        return None
    return settings.get('clients')


def _ensure_dict(parent, key):
    value = parent.get(key)
    if value is None:
        value = {}
        parent[key] = value
    elif not isinstance(value, dict):
        raise ValueError('invalid xray %s section' % key)
    return value


def _ensure_list(parent, key):
    value = parent.get(key)
    if value is None:
        value = []
        parent[key] = value
    elif not isinstance(value, list):
        raise ValueError('invalid xray %s section' % key)
    return value


def add_stats(config, port):
    if not isinstance(config, dict):raise ValueError('invalid xray config')
    if type(port) is not int or not 1024<=port<=65535:raise ValueError('invalid port')
    cfg=copy.deepcopy(config)
    inbounds=_ensure_list(cfg,'inbounds')
    original_clients=[copy.deepcopy(_inbound_clients(i)) for i in inbounds]
    raw_api=cfg.get('api')
    if raw_api is not None and not isinstance(raw_api, dict):
        raise ValueError('invalid xray api section')
    if raw_api and raw_api.get('tag')!='usage-meter-api':
        raise ValueError('existing api requires explicit compatibility review')
    if cfg.get('stats') is None:
        cfg['stats']={}
    elif not isinstance(cfg.get('stats'), dict):
        raise ValueError('invalid xray stats section')
    policy=_ensure_dict(cfg,'policy')
    levels=_ensure_dict(policy,'levels')
    used={'0'}
    for inbound in inbounds:
        clients=_inbound_clients(inbound)
        if isinstance(clients, list):
            for client in clients:
                if isinstance(client, dict):
                    lvl=_client_level_key(client.get('level',0))
                    if lvl is not None:
                        used.add(lvl)
    for level in used:
        lv=levels.get(level)
        if lv is None:
            lv={}
            levels[level]=lv
        elif not isinstance(lv, dict):
            raise ValueError('invalid xray policy level')
        lv['statsUserUplink']=True
        lv['statsUserDownlink']=True
        lv['statsUserOnline']=True
    api=raw_api or {'tag':'usage-meter-api'}
    cfg['api']=api
    raw_services=api.get('services')
    if raw_services is not None and not isinstance(raw_services, list):
        raise ValueError('invalid xray api services')
    services=list(raw_services or [])
    if 'StatsService' not in services:services.append('StatsService')
    api['services']=services
    add_iplimit_routing(cfg)
    entries=[i for i in inbounds if isinstance(i, dict) and i.get('tag')=='usage-meter-api-in']
    desired={'tag':'usage-meter-api-in','listen':'127.0.0.1','port':port,'protocol':'dokodemo-door','settings':{'address':'127.0.0.1'}}
    if entries:
        if len(entries)!=1 or entries[0]!=desired:raise ValueError('api inbound conflict')
    else:
        if any(isinstance(i, dict) and _inbound_uses_port(i.get('port'), port) for i in inbounds):
            raise ValueError('port conflict')
        inbounds.append(desired)
    routing=_ensure_dict(cfg,'routing')
    rules=_ensure_list(routing,'rules')
    if API_RULE not in rules:rules.insert(0,copy.deepcopy(API_RULE))
    api_rule_first(cfg)
    # 用显式 raise 而不是 assert：`python -O` 会把 assert 整段剥掉，
    # 这条「绝不改 clients」的安全检查就静默消失了（2026-10-30 修）。
    if original_clients!=[_inbound_clients(i) for i in inbounds[:len(original_clients)]]:
        raise ValueError('add_stats must not modify inbound clients')
    return cfg


IPLIMIT_OUTBOUND_TAG='iplimit-block'


def add_iplimit_routing(cfg):
    """为 Reality 设备上限补齐运行时路由能力：回环 API 加 RoutingService，加一个黑洞出站。

    规则本身由 portal 在运行时用 `xray api adrules -append` 下发，不落盘；
    这里只保证接口和出站存在。黑洞必须排在已有出站之后，否则会变成默认出站。
    """
    if not isinstance(cfg, dict):
        raise ValueError('invalid xray config')
    api=cfg.get('api')
    if not isinstance(api, dict) or api.get('tag')!='usage-meter-api':
        raise ValueError('iplimit routing requires usage-meter api')
    raw_services=api.get('services')
    if raw_services is not None and not isinstance(raw_services, list):
        raise ValueError('invalid xray api services')
    services=list(raw_services or [])
    if 'RoutingService' not in services:services.append('RoutingService')
    api['services']=services
    outbounds=_ensure_list(cfg,'outbounds')
    # 清理非 dict 脏元素，防止首位被脏对象占据导致 Xray 配置加载失败。
    outbounds[:] = [o for o in outbounds if isinstance(o, dict)]
    if not outbounds:outbounds.append({'protocol':'freedom','tag':'direct'})
    if isinstance(outbounds[0], dict) and outbounds[0].get('tag')==IPLIMIT_OUTBOUND_TAG:
        # 保留原默认出口的行为，托管 tag 留给后面的黑洞。首个出站本身就是托管黑洞时
        # 不能照抄：无 tag 的黑洞成了默认出站，全部流量被丢弃（2026-11-04 修）。
        if outbounds[0].get('protocol')=='blackhole':
            default={'protocol':'freedom','tag':'direct'}
        else:
            default=copy.deepcopy(outbounds[0])
            default.pop('tag')
        outbounds.insert(0,default)
    # 去重所有重复的托管黑洞 tag，保证 outbounds[1:] 中只保留一条干净的 blackhole 出站。
    deduped = []
    seen_block = False
    for outbound in outbounds:
        if isinstance(outbound, dict) and outbound.get('tag') == IPLIMIT_OUTBOUND_TAG:
            if not seen_block:
                deduped.append({'protocol': 'blackhole', 'tag': IPLIMIT_OUTBOUND_TAG})
                seen_block = True
            continue
        deduped.append(outbound)
    if not seen_block:
        deduped.append({'protocol': 'blackhole', 'tag': IPLIMIT_OUTBOUND_TAG})
    outbounds[:] = deduped
    return cfg


API_RULE={'type':'field','inboundTag':['usage-meter-api-in'],'outboundTag':'usage-meter-api'}


def api_rule_first(cfg):
    """回环统计 API 的路由规则必须排在所有规则最前（2026-10-28 修）。

    portal 的内网拦截规则（ip 含 127.0.0.0/8 → block-private）也用 insert(0)，
    谁后插谁在前；它一旦排到 API 规则前面，发往 127.0.0.1 的统计调用全被黑洞：
    Reality 计量与设备上限静默失效（斯德哥尔摩/香港/洛杉矶实测）。
    API 规则只匹配本地 dokodemo 入站，放最前不影响任何用户流量。返回是否改动。
    """
    if not isinstance(cfg, dict):
        raise ValueError('invalid xray config')
    routing=_ensure_dict(cfg,'routing')
    rules=_ensure_list(routing,'rules')
    others = [r for r in rules if r != API_RULE]
    desired = [copy.deepcopy(API_RULE)] + others
    if rules == desired:
        return False
    rules[:] = desired
    return True


def iplimit_routing_ready(cfg):
    if not isinstance(cfg, dict):
        return False
    routing=cfg.get('routing')
    rules=routing.get('rules') if isinstance(routing, dict) else None
    api=cfg.get('api')
    services=api.get('services') if isinstance(api, dict) else None
    outbounds=cfg.get('outbounds')
    if not isinstance(rules, list) or not isinstance(services, list) or not isinstance(outbounds, list):
        return False
    return ('RoutingService' in services and
            any(isinstance(o, dict) and o.get('tag')==IPLIMIT_OUTBOUND_TAG and o.get('protocol')=='blackhole'
                for o in outbounds[1:]) and
            bool(rules) and rules[0]==API_RULE)


def _write_private_bytes(target, payload, mode):
    """以指定权限创建并落盘文件，避免先默认掩码创建再改权产生私钥暴露窗口。"""
    target = pathlib.Path(target)
    mode = (mode & 0o777) or 0o600
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, 'O_NOFOLLOW'):
        flags |= os.O_NOFOLLOW
    fd = os.open(str(target), flags, mode)
    try:
        with os.fdopen(fd, 'wb') as handle:
            fd = None
            handle.write(payload)
            handle.flush()
            if hasattr(os, 'fchmod'):
                os.fchmod(handle.fileno(), mode)
            os.fsync(handle.fileno())
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
    os.chmod(target, mode)


def _restart_xray(check=True):
    # 先清失败计数，与门户其它重启 Xray 的地方一致：刚连续重启过、撞上 StartLimitBurst 时
    # restart 会被直接拒绝，回滚那次同样起不来，Xray 一直停着（2026-11-12 修）。
    # reset-failed 自身超时/失败不得打断真正的 restart。
    try:
        subprocess.run(['systemctl','reset-failed','xray'],capture_output=True,timeout=5)
    except (OSError, subprocess.SubprocessError):
        pass
    return subprocess.run(['systemctl','restart','xray'],capture_output=True,timeout=15,check=check)


def _rollback_restart_xray():
    try:
        _restart_xray(check=False)
    except (OSError, subprocess.SubprocessError):
        pass


def enable_iplimit_routing(config_path, binary, address):
    """幂等开启设备上限所需的路由接口；预检后替换，重启失败恢复原配置。不触碰 clients。"""
    _validate_binary(binary)
    _validate_loopback_address(address)
    path=pathlib.Path(config_path)
    original, orig_mode = _read_regular_config_bytes(path)
    config=json.loads(original.decode('utf-8', errors='replace'))
    if not isinstance(config, dict):raise ValueError('invalid xray config')
    if iplimit_routing_ready(config):
        return {'enabled':True,'changed':False,'backup':None}
    inbounds=_ensure_list(config,'inbounds')
    clients=[copy.deepcopy(_inbound_clients(i)) for i in inbounds]
    add_iplimit_routing(config)
    api_rule_first(config)
    if clients!=[_inbound_clients(i) for i in inbounds]:
        raise ValueError('add_iplimit_routing must not modify inbound clients')
    nonce=secrets.token_hex(6)
    candidate=path.with_name(path.name+f'.iplimit-candidate.{nonce}.json')
    # 只保留最近一份备份（2026-10-24 修）：旧实现每次都用纳秒时间戳新建
    # `xray.json.before-iplimit-<ns>`，而这个函数在每次 Xray 重启后都会被调用，
    # /etc/hysteria 下会无界累积备份文件（实测已出现）。
    # 固定文件名既保留回滚能力，又不会随重启增长。
    backup=path.with_name(path.name+'.before-iplimit')
    backup_tmp=path.with_name(path.name+f'.before-iplimit.{nonce}.tmp')
    replaced=False
    try:
        _write_private_bytes(candidate, json.dumps(config,indent=2,allow_nan=False).encode('utf-8'), orig_mode)
        subprocess.run([binary,'run','-test','-c',str(candidate)],capture_output=True,timeout=10,check=True)
        if _read_regular_config_bytes(path)[0] != original:raise RuntimeError('xray config changed concurrently')
        if backup.is_symlink():raise ValueError('xray backup path must not be symlink')
        _write_private_bytes(backup_tmp, original, orig_mode)
        os.replace(backup_tmp, backup)
        os.replace(candidate,path);replaced=True
        _fsync_parent_dir(path)
        _restart_xray()
        subprocess.run(['systemctl','is-active','--quiet','xray'],capture_output=True,timeout=5,check=True)
        for _ in range(10):
            try:
                probe=subprocess.run([binary,'api','lsrules','--server='+address],capture_output=True,timeout=5)
                if probe.returncode==0:break
            except (OSError, subprocess.TimeoutExpired):
                pass
            time.sleep(0.5)
        else:raise RuntimeError('routing api unavailable after restart')
    except Exception:
        if replaced:
            try:
                _write_private_bytes(candidate, original, orig_mode)
                os.replace(candidate,path)
                _fsync_parent_dir(path)
            except OSError:
                pass
            _rollback_restart_xray()
        raise
    finally:
        for _tmp in (candidate, backup_tmp):
            try:
                _tmp.unlink(missing_ok=True)
            except OSError:
                pass
    return {'enabled':True,'changed':True,'backup':str(backup)}


def enable_reality_online(config_path, binary, address):
    """只开启在线统计；校验后替换，失败恢复原配置，不触碰用户或 Reality 参数。"""
    _validate_binary(binary)
    _validate_loopback_address(address)
    path=pathlib.Path(config_path)
    original, orig_mode = _read_regular_config_bytes(path)
    config=json.loads(original.decode('utf-8', errors='replace'))
    if not isinstance(config, dict):raise ValueError('invalid xray config')
    policy=_ensure_dict(config,'policy')
    levels=_ensure_dict(policy,'levels')
    inbounds=_ensure_list(config,'inbounds')
    original_clients=[copy.deepcopy(_inbound_clients(i)) for i in inbounds]
    used={'0'}
    for inbound in inbounds:
        clients=_inbound_clients(inbound)
        if isinstance(clients, list):
            for client in clients:
                if isinstance(client, dict):
                    lvl=_client_level_key(client.get('level',0))
                    if lvl is not None:
                        used.add(lvl)
    changed=any(not (isinstance(levels.get(level), dict) and levels[level].get('statsUserOnline',False)) for level in used)
    for level in used:
        lv=levels.get(level)
        if lv is None:
            lv={}
            levels[level]=lv
        elif not isinstance(lv, dict):
            raise ValueError('invalid xray policy level')
        lv['statsUserOnline']=True
    if original_clients!=[_inbound_clients(i) for i in inbounds]:
        raise ValueError('enable_reality_online must not modify inbound clients')
    nonce=secrets.token_hex(6)
    candidate=path.with_name(path.name+f'.online-candidate.{nonce}.json')
    # 固定备份名，与 before-iplimit 同理（2026-11-03 修）：时间戳文件名每次改动
    # 新建一份，/etc/hysteria 下无界累积。
    backup=path.with_name(path.name+'.before-reality-online')
    backup_tmp=path.with_name(path.name+f'.before-reality-online.{nonce}.tmp')
    if changed:
        replaced=False
        try:
            _write_private_bytes(candidate, json.dumps(config,indent=2,allow_nan=False).encode('utf-8'), orig_mode)
            subprocess.run([binary,'run','-test','-c',str(candidate)],capture_output=True,timeout=10,check=True)
            if _read_regular_config_bytes(path)[0] != original:raise RuntimeError('xray config changed concurrently')
            if backup.is_symlink():raise ValueError('xray backup path must not be symlink')
            _write_private_bytes(backup_tmp, original, orig_mode)
            os.replace(backup_tmp, backup)
            os.replace(candidate,path);replaced=True
            _fsync_parent_dir(path)
            _restart_xray()
            subprocess.run(['systemctl','is-active','--quiet','xray'],capture_output=True,timeout=5,check=True)
            # 重启后等待 gRPC 统计接口就绪再判失败，与 enable_iplimit_routing 一致；
            # 单次立刻探测在负载较高机器上会误触回滚。
            for attempt in range(10):
                try:
                    subprocess.run([binary,'api','statsgetallonlineusers','--server='+address],capture_output=True,timeout=5,check=True)
                    break
                except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                    if attempt == 9:
                        raise
                    time.sleep(0.5)
        except Exception:
            if replaced:
                try:
                    _write_private_bytes(candidate, original, orig_mode)
                    os.replace(candidate,path)
                    _fsync_parent_dir(path)
                except OSError:
                    pass
                # 回滚后的重启不带 check 且隔离超时异常，避免顶掉真正的失败原因。
                _rollback_restart_xray()
            raise
        finally:
            for _tmp in (candidate, backup_tmp):
                try:
                    _tmp.unlink(missing_ok=True)
                except OSError:
                    pass
    else:
        subprocess.run(['systemctl','is-active','--quiet','xray'],capture_output=True,timeout=5,check=True)
        subprocess.run([binary,'api','statsgetallonlineusers','--server='+address],capture_output=True,timeout=5,check=True)
    return {'enabled':True,'changed':changed,'backup':str(backup) if changed else None}
