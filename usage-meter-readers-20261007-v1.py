"""节点计数器只读适配器；不 reset，不输出 secret。"""
import errno
import json
import os
import pathlib
import stat
import subprocess
import urllib.error
import urllib.request
from urllib.parse import urlparse

_ORIG_URLOPEN = urllib.request.urlopen
_ORIG_PATH_CLS = pathlib.Path
_ORIG_PATH_READ_TEXT = pathlib.Path.read_text


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """禁止本地统计接口跟随 3xx 重定向，防止把 Authorization 密钥发往跳转目标。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(
            req.full_url,
            code,
            f'redirect blocked ({msg})',
            headers,
            fp,
        )


def _open_no_redirect(req, timeout=4):
    if urllib.request.urlopen is not _ORIG_URLOPEN:
        return urllib.request.urlopen(req, timeout=timeout)
    opener = urllib.request.build_opener(_NoRedirectHandler())
    return opener.open(req, timeout=timeout)


def _read_bounded_json(path, max_bytes=8 * 1024 * 1024):
    """受限读取常规 JSON 配置文件：拒绝符号链接、非常规文件及超限体积，并兼容单测 Path/read_text 桩。"""
    p = pathlib.Path(path)
    if (not isinstance(p, _ORIG_PATH_CLS)
            or getattr(type(p), 'read_text', None) is not _ORIG_PATH_READ_TEXT):
        try:
            text = p.read_text(encoding='utf-8', errors='replace')
        except TypeError:
            text = p.read_text(encoding='utf-8')
        if len(text.encode('utf-8')) > max_bytes:
            raise ValueError('config file too large')
        return json.loads(text)
    st0 = p.lstat()
    if not stat.S_ISREG(st0.st_mode):
        raise ValueError('config path must be regular file')
    if st0.st_size > max_bytes:
        raise ValueError('config file too large')
    nofollow = getattr(os, 'O_NOFOLLOW', 0)
    if nofollow:
        fd = None
        try:
            try:
                fd = os.open(str(p), os.O_RDONLY | nofollow)
            except OSError as exc:
                if exc.errno == errno.ELOOP:
                    raise ValueError('config path must be regular file') from None
                raise
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise ValueError('config path must be regular file')
            if st.st_size > max_bytes:
                raise ValueError('config file too large')
            with os.fdopen(fd, 'rb') as fh:
                fd = None
                raw = fh.read(max_bytes + 1)
        finally:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
    else:
        with open(p, 'rb') as fh:
            raw = fh.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise ValueError('config file too large')
    return json.loads(raw.decode('utf-8', errors='replace'))


def service_epoch(service):
    if service not in ('hysteria-server', 'xray'):
        raise ValueError('unsupported service')
    r = subprocess.run(['systemctl','show',service,'--property=InvocationID','--value'],
                       capture_output=True, timeout=5, check=True)
    value = r.stdout.decode('utf-8', errors='replace').strip()
    if not value:
        raise RuntimeError('missing InvocationID')
    return value


def service_running(service):
    """inactive / failed 视为没在跑；systemd 不可用等读不出状态时按在跑处理，交给后续读取报错。"""
    if service not in ('hysteria-server', 'xray'):
        raise ValueError('unsupported service')
    try:
        r = subprocess.run(['systemctl', 'is-active', service], capture_output=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return True
    return r.stdout.decode(errors='replace').strip() not in ('inactive', 'failed')


def _validate_loopback_http_base(url, secret):
    if (not isinstance(url, str) or not url
            or any(ord(ch) < 32 or ord(ch) == 127 or ch.isspace() for ch in url)):
        raise ValueError('stats endpoint must be loopback HTTP base URL')
    if (not isinstance(secret, str) or not secret.isascii()
            or any(ord(ch) < 32 or ord(ch) == 127 for ch in secret)):
        raise ValueError('invalid stats secret')
    p = urlparse(url)
    try:
        port = p.port
    except ValueError:
        raise ValueError('stats endpoint must be loopback HTTP base URL') from None
    if (p.scheme != 'http' or p.hostname not in ('127.0.0.1', '::1')
            or p.path not in ('', '/') or p.params or p.query or p.fragment
            or p.username is not None or p.password is not None
            or (port is not None and not (1 <= port <= 65535))):
        raise ValueError('stats endpoint must be loopback HTTP base URL')
    return url.rstrip('/')


def _validate_loopback_xray_addr(address):
    if not isinstance(address, str) or not address.startswith('127.0.0.1:'):
        raise ValueError('xray endpoint must be loopback')
    port_text = address[len('127.0.0.1:'):]
    if (not (port_text.isascii() and port_text.isdigit())
            or len(port_text) > 5
            or port_text.startswith('0')
            or not (1 <= int(port_text) <= 65535)):
        raise ValueError('xray endpoint must be loopback')
    return address


def _valid_binary_path(binary):
    if not isinstance(binary, str):
        return False
    s = binary.strip()
    if not s or s.startswith('-') or any(ord(c) < 32 or ord(c) == 127 for c in binary):
        return False
    return True


def read_hysteria(url, secret):
    base = _validate_loopback_http_base(url, secret)
    req = urllib.request.Request(base + '/traffic', headers={'Authorization': secret})
    with _open_no_redirect(req, timeout=4) as response:
        if 300 <= getattr(response, 'status', 200) < 400:
            raise ValueError('unexpected redirect')
        raw=response.read(4*1024*1024+1)
    if len(raw)>4*1024*1024:
        raise ValueError('traffic response too large')
    result=json.loads(raw.decode('utf-8', errors='replace'))
    if not isinstance(result,dict): raise ValueError('invalid traffic response')
    for uid, counters in result.items():
        if (not isinstance(uid, str) or not uid
                or any(ord(ch) < 32 or ord(ch) == 127 for ch in uid)
                or not isinstance(counters, dict)):
            raise ValueError('invalid traffic response')
        for field in ('tx', 'rx'):
            if field in counters:
                val = counters[field]
                if type(val) is not int or val < 0:
                    raise ValueError('invalid traffic response')
    return result


def parse_xray(raw):
    if not isinstance(raw, (str, bytes, bytearray)):
        raise ValueError('invalid xray response')
    obj=json.loads(raw)
    if not isinstance(obj,dict): raise ValueError('invalid xray response')
    rows=obj.get('stat', obj.get('stats'))
    if rows is None:
        # statsquery 对空统计返回 {}；只允许空对象作为合法空响应。
        if obj == {}: return {}
        raise ValueError('missing stat array')
    if not isinstance(rows,list): raise ValueError('invalid stat array')
    out={}
    seen=set()
    for row in rows:
        if not isinstance(row,dict): raise ValueError('invalid xray stat row')
        name=row.get('name','')
        if not isinstance(name,str): raise ValueError('invalid xray stat name')
        parts=name.split('>>>')
        if len(parts)!=4 or parts[0]!='user' or parts[2]!='traffic': continue
        if parts[3] not in ('uplink','downlink'): continue
        if not parts[1] or any(ord(c) < 32 or ord(c) == 127 for c in parts[1]):
            raise ValueError('invalid xray user')
        value=row.get('value')
        if isinstance(value,str) and value.isascii() and value.isdigit() and len(value)<=30: value=int(value)
        if type(value) is not int or value<0: raise ValueError('invalid xray counter')
        pair=out.setdefault(parts[1],{'tx':0,'rx':0})
        # 方向必须与 Hy2 的语义对齐（2026-10-29 修）：
        #   * Hysteria 的 LogTraffic 在上行时记 tx、下行时记 rx
        #     （core/server/server.go：ReceiveDatagram→tx，SendMessage→rx）；
        #   * 界面把 rx 标成「下行 Download」、tx 标成「上行 Upload」。
        # Xray 的 uplink = 客户端→服务端 = 上行 = tx，downlink = 下行 = rx。
        # 旧实现把两者写反了：Reality/VMess/VLESS-Enc 的上下行显示互换。
        key='rx' if parts[3]=='downlink' else 'tx'
        # 用显式 seen 集合判重：旧写法 `key in pair` 恒真、再叠加 `!=0`，
        # 两条同为 0 的重复记录会被静默接受（2026-10-30 修）。
        if (parts[1], key) in seen: raise ValueError('duplicate traffic stat')
        seen.add((parts[1], key))
        pair[key]=value
    return out


def read_xray(binary, address):
    if not _valid_binary_path(binary):
        raise ValueError('invalid xray binary')
    address = _validate_loopback_xray_addr(address)
    r=subprocess.run([binary,'api','statsquery','--server='+address,'-pattern','user>>>','-reset=false'],
                     capture_output=True,timeout=5,check=True)
    if len(r.stdout)>8*1024*1024:
        raise ValueError('xray stats response too large')
    return parse_xray(r.stdout.decode('utf-8', errors='replace'))


def read_hysteria_online(url, secret):
    base = _validate_loopback_http_base(url, secret)
    req = urllib.request.Request(base + '/online', headers={'Authorization': secret})
    with _open_no_redirect(req, timeout=4) as response:
        if 300 <= getattr(response, 'status', 200) < 400:
            raise ValueError('unexpected redirect')
        raw = response.read(4 * 1024 * 1024 + 1)
    if len(raw) > 4 * 1024 * 1024:
        raise ValueError('online response too large')
    result = json.loads(raw.decode('utf-8', errors='replace'))
    if not isinstance(result, dict) or any(
            not isinstance(uid, str) or not uid
            or any(ord(ch) < 32 or ord(ch) == 127 for ch in uid)
            or type(count) is not int or count < 0
            for uid, count in result.items()):
        raise ValueError('invalid online counters')
    return result


"""只读采集：连接事件 + Hy2核心在线计数校验；不使用鉴权超时作在线判据。"""
import re,ipaddress,time,pathlib,urllib.error

def _norm_ip(value):
    """规范化单个 IP：IPv4 映射地址还原成 IPv4（与 /auth、拦截名单同一写法）。"""
    if not isinstance(value, str):
        raise ValueError('invalid_ip')
    ip=ipaddress.ip_address(value.strip())
    if ip.version==6 and ip.ipv4_mapped:
        ip=ip.ipv4_mapped
    return str(ip)

def _addr_ip(addr):
    """从 hysteria 日志的 addr 取 IP：[v6]:port、v4:port、裸 v4、裸 v6 都要认（2026-11-03 修）。

    旧写法 `rsplit(':',1)[0]` 把不带端口的 IPv6 截成 '2001:db8:'，ip_address 抛错，
    一条这样的日志让整台节点的在线 IP 快照失败。
    """
    if not isinstance(addr, str):
        raise ValueError('invalid_addr')
    text=addr.strip()
    if text.startswith('['):
        if ']' not in text:
            raise ValueError('invalid_bracketed_addr')
        end=text.index(']')
        rest=text[end+1:]
        if rest:
            if not rest.startswith(':'):
                raise ValueError('invalid_bracketed_addr')
            port_text=rest[1:]
            if (not (port_text.isascii() and port_text.isdigit())
                    or len(port_text) > 5
                    or port_text.startswith('0')
                    or not (1<=int(port_text)<=65535)):
                raise ValueError('invalid_bracketed_port')
        ip=ipaddress.ip_address(text[1:end])
    else:
        try:
            ip=ipaddress.ip_address(text)
        except ValueError:
            if ':' not in text:
                raise ValueError('invalid_addr') from None
            host_part, port_text = text.rsplit(':', 1)
            if (not (port_text.isascii() and port_text.isdigit())
                    or len(port_text) > 5
                    or port_text.startswith('0')
                    or not (1 <= int(port_text) <= 65535)):
                raise ValueError('invalid_addr_port')
            ip=ipaddress.ip_address(host_part)
    # 双栈监听时 IPv4 客户端报成 ::ffff:a.b.c.d：还原成 IPv4（2026-11-06 修），否则控制台的
    # 跨节点在线 IP 与拦截名单（纯 IPv4）对不上，同一设备在不同节点上像是两个。
    if ip.version==6 and ip.ipv4_mapped:
        ip=ip.ipv4_mapped
    return str(ip)

def parse_events(rows):
    """按「用户 + 客户端 IP」重放连接事件，返回 {(uid, ip): 仍在线的连接数}。

    🔴 2026-11-02 修：旧实现按 (uid, addr) 配对，addr 带源端口。客户端开了端口跳跃
    或 QUIC 迁移后，断开事件记的源端口和连上时不同（实测 153.37.136.218 连 :7206、
    断 :7215），旧连接永远配不上 ⇒ 日志连接数 > 核心计数 ⇒ 整台节点判「暂不一致」，
    控制台在线 IP 覆盖缺一块，跨节点设备上限整条订阅跳过。
    同一 IP 上哪条连接先断不影响「有哪些 IP 在线」；总数仍要和核心计数对上才采信。
    """
    active={}
    unmatched=set()
    if not isinstance(rows, (list, tuple)) or any(not isinstance(row,dict) for row in rows):
        raise ValueError('invalid_connection_event')
    def _event_sort_ts(row):
        raw_ts = row.get('__MONOTONIC_TIMESTAMP')
        if raw_ts is None:
            raw_ts = row.get('__REALTIME_TIMESTAMP')
        if raw_ts is None:
            return 0
        if isinstance(raw_ts, bool):
            raise ValueError('invalid_connection_event')
        if isinstance(raw_ts, str):
            s = raw_ts.strip()
            if (not s or len(s) > 30 or not s.isascii()
                    or not (s.isdigit() or (s.startswith('-') and s[1:].isdigit()))):
                raise ValueError('invalid_connection_event')
            return int(s)
        if type(raw_ts) is not int:
            raise ValueError('invalid_connection_event')
        return raw_ts
    try:
        rows=sorted(rows,key=_event_sort_ts)
    except (TypeError,ValueError,OverflowError):
        raise ValueError('invalid_connection_event') from None
    for row in rows:
        message=row.get('MESSAGE','')
        if isinstance(message,list):
            if any(type(x)!=int or not 0<=x<=255 for x in message):raise ValueError('invalid_journal_message')
            message=bytes(message).decode('utf-8',errors='replace')
        if not isinstance(message,str):raise ValueError('missing_journal_message')
        clean=re.sub(r'\x1b\[[0-9;]*m','',message)
        event=None
        try:
            if clean.startswith('{'):
                fields=json.loads(clean)
                if not isinstance(fields,dict):raise ValueError('invalid_connection_event')
                event=fields.get('msg') or fields.get('message')
            else:
                match=re.search(r'(?:^|\t)(client connected|client disconnected)\t',clean)
                if not match:continue
                event=match.group(1);fields=json.loads(clean[match.end():])
                if not isinstance(fields,dict):raise ValueError('invalid_connection_event')
        except (ValueError,TypeError):raise ValueError('invalid_connection_event') from None
        if event not in ('client connected','client disconnected'):continue
        uid,addr=fields.get('id'),fields.get('addr')
        if (not isinstance(uid,str) or not uid
                or any(ord(c) < 32 or ord(c) == 127 for c in uid)
                or not isinstance(addr,str)):
            raise ValueError('missing_connection_identity')
        ip=_addr_ip(addr)
        key=(uid,ip)
        if event=='client connected':
            active[key]=active.get(key,0)+1
        elif active.get(key,0)>0:
            active[key]-=1
            if not active[key]:del active[key]
        else:
            # 断开了一条日志里没见过的连接（连上那条已被轮转/丢失）：该用户剩余连接
            # 无法按 IP 对账，交给 confirmed_ips 判为未知，不猜。
            unmatched.add(uid)
    for uid in unmatched:
        active.setdefault((uid,None),0)
    return active

def confirmed_ips(connections,uid,count):
    if not isinstance(connections, dict) or not isinstance(uid, str) or not uid:
        return None
    if type(count) is not int or count < 0:
        return None
    if count==0:return []
    if (uid,None) in connections:return None
    known={ip:n for (user,ip),n in connections.items() if user==uid and ip is not None}
    if sum(known.values())!=count:return None
    return sorted(known)

def cmd(args):
    return subprocess.run(args,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=8,check=True).stdout

def read_live_connections():
    cfg=_read_bounded_json('/etc/hysteria/usage-meter-config.json', max_bytes=4*1024*1024)
    if not isinstance(cfg,dict):raise ValueError('invalid_meter_config')
    portal=_read_bounded_json('/etc/hysteria/portal.json', max_bytes=16*1024*1024)
    users=portal.get('users') if isinstance(portal,dict) and isinstance(portal.get('users'),dict) else {}
    output={'users':{},'sampled_at':int(time.time())}
    for uid in users:
        if not isinstance(uid, str) or not uid or any(ord(c) < 32 or ord(c) == 127 for c in uid):
            continue
        output['users'][uid]={'ips':[],'ok':False,'error':'Hy2 online IP unavailable','hysteria_ok':False,'reality_ok':False}
    core_counts=None
    try:
        h=cfg.get('hysteria')
        if not isinstance(h,dict):raise ValueError('invalid_hysteria_config')
        base=_validate_loopback_http_base(h.get('url'),h.get('secret'))
        live_req=urllib.request.Request(base+'/online/ips',headers={'Authorization':h['secret']})
        try:
            with _open_no_redirect(live_req,timeout=4) as response:
                if 300 <= getattr(response, 'status', 200) < 400:
                    raise ValueError('unexpected_redirect')
                raw=response.read(4*1024*1024+1)
            if len(raw)>4*1024*1024:raise ValueError('live_ips_response_too_large')
            live=json.loads(raw)
        except urllib.error.HTTPError as exc:
            try:
                if exc.code!=404:raise
                live=None
            finally:
                try:
                    exc.close()
                except Exception:
                    pass
        if live is not None:
            if not isinstance(live,dict) or live.get('revision')!='teyir-live-ips-v1' or not isinstance(live.get('users'),dict):raise ValueError('invalid_core_live_response')
            for uid,out in output['users'].items():
                row=live['users'].get(uid,{'connections':0,'ips':[]})
                if not isinstance(row,dict):raise ValueError('invalid_core_live_user')
                # Go 序列化空切片可能产出 null，按空列表处理，避免误判全机采集失败。
                raw_ips=[] if row.get('ips') is None else row.get('ips')
                if (type(row.get('connections'))!=int or row['connections']<0
                        or not isinstance(raw_ips,list)
                        or any(not isinstance(ip,str) for ip in raw_ips)):
                    raise ValueError('invalid_core_live_user')
                dedup_ips=list(dict.fromkeys(_norm_ip(ip) for ip in raw_ips))
                ips=[{'ip':ip,'protocol':'Hy2','last_seen':output['sampled_at']} for ip in dedup_ips]
                out.update(ok=True,hysteria_ok=True,error='',hysteria_count=row['connections'],ips=ips)
        else:
            online=read_hysteria_online(h['url'],h['secret'])
            core_counts=online
            if all(online.get(uid,0)==0 for uid in output['users']):
                for out in output['users'].values():out.update(ok=True,hysteria_ok=True,error='',hysteria_count=0)
            else:
                epoch=cmd(['systemctl','show','hysteria-server','--property=InvocationID','--value']).strip()
                if not re.fullmatch('[a-f0-9]{32}',epoch):raise ValueError('missing_service_epoch')
                journal=cmd(['journalctl','--no-pager','-o','json','--grep=client (connected|disconnected)', '_SYSTEMD_INVOCATION_ID='+epoch,'-n','20001'])
                if len(journal)>8*1024*1024:raise ValueError('journal_response_too_large')
                rows=[json.loads(line) for line in journal.splitlines() if line]
                if len(rows)>20000:raise ValueError('journal_history_truncated')
                connections=parse_events(rows)
                h=cfg['hysteria']
                online=read_hysteria_online(h['url'],h['secret'])
                after=cmd(['systemctl','show','hysteria-server','--property=InvocationID','--value']).strip()
                if after!=epoch:raise ValueError('service_changed_during_sample')
                for uid,out in output['users'].items():
                    count=online.get(uid,0)
                    known=confirmed_ips(connections,uid,count)
                    out['hysteria_count']=count
                    if known is None:
                        out['error']='Hy2连接日志与核心计数暂不一致，无法完整确定IP'
                        continue
                    out['hysteria_ok']=True;out['ok']=True;out['error']=''
                    out['ips']=[{'ip':ip,'protocol':'Hy2','last_seen':output['sampled_at']} for ip in sorted(set(known))]
    except Exception as exc:
        for uid,out in output['users'].items():
            if core_counts is not None and core_counts.get(uid,0)==0:
                out.update(ok=True,hysteria_ok=True,error='',hysteria_count=0)
            else:
                out.update(ok=False,hysteria_ok=False,error='Hy2在线IP采集失败：'+type(exc).__name__)
                out['ips']=[ip for ip in out['ips'] if ip['protocol']!='Hy2']
    # Reality 若已启用核心在线统计且服务正在运行则读取；装了 Xray 但未运行时按空闲处理，
    # 避免每 15 秒报「Reality在线IP读取失败」。未启用时明确说明，不用历史 access 日志猜。
    rcfg=cfg.get('reality') if isinstance(cfg.get('reality'),dict) else {}
    binary=rcfg.get('binary','') if isinstance(rcfg.get('binary'),str) else ''
    _bin_ok = False
    if _valid_binary_path(binary):
        try:
            _bin_ok = pathlib.Path(binary).is_file()
        except (OSError, ValueError):
            _bin_ok = False
    if _bin_ok and service_running('xray'):
        try:
            xcfg=_read_bounded_json('/etc/hysteria/xray.json', max_bytes=4*1024*1024)
            policy=xcfg.get('policy') if isinstance(xcfg,dict) else None
            levels=policy.get('levels') if isinstance(policy,dict) else None
            level0=levels.get('0') if isinstance(levels,dict) else None
            enabled=level0.get('statsUserOnline',False) if isinstance(level0,dict) else False
            if not enabled:raise ValueError('online_statistics_not_enabled')
            address=_validate_loopback_xray_addr(rcfg.get('address'))
            raw_allusers=cmd([binary,'api','statsgetallonlineusers','--server='+address])
            if len(raw_allusers)>8*1024*1024:raise ValueError('online_users_response_too_large')
            allusers=json.loads(raw_allusers)
            # Go 序列化空切片或空映射时常返回 null，仅把 None 视为缺省空集合，其它非法类型仍拒绝。
            names=([] if allusers.get('users') is None else allusers.get('users')) if isinstance(allusers,dict) else allusers
            if not isinstance(names,list):raise ValueError('invalid_online_users')
            if any(not isinstance(name,str) for name in names):raise ValueError('invalid_online_user_name')
            names_set={name.split('>>>')[1] if name.startswith('user>>>') and name.endswith('>>>online') and len(name.split('>>>'))==3 else name for name in names}
            for uid,out in output['users'].items():
                out['reality_ok']=True
                if uid not in names_set:continue
                if not isinstance(uid,str) or any(ord(c)<32 or ord(c)==127 for c in uid):
                    raise ValueError('invalid_online_user_name')
                raw_iplist=cmd([binary,'api','statsonlineiplist','--server='+address,'--email='+uid])
                if len(raw_iplist)>8*1024*1024:raise ValueError('online_ips_response_too_large')
                result=json.loads(raw_iplist)
                if not isinstance(result,dict):raise ValueError('invalid_online_ips')
                ips={} if result.get('ips') is None else result.get('ips')
                if not isinstance(ips,dict):raise ValueError('invalid_online_ips')
                # 双栈监听时 Xray 同样可能报 ::ffff:a.b.c.d，必须与 Hy2 一致还原成纯 IPv4 并去重，
                # 否则同一设备同时测速 Hy2 与 Reality 时会被当成两个在线 IP，也对不上跨节点拦截名单。
                merged={}
                for ip,seen in ips.items():
                    if isinstance(seen,str) and seen.isascii() and seen.isdigit() and len(seen)<=20:
                        ts=int(seen)
                    elif type(seen) is int and seen>=0:
                        ts=seen
                    else:
                        raise ValueError('invalid_online_seen')
                    norm=_norm_ip(ip)
                    if norm not in merged or ts>merged[norm]:
                        merged[norm]=ts
                for norm,ts in merged.items():
                    out['ips'].append({'ip':norm,'protocol':'Reality','last_seen':ts})
        except Exception as exc:
            for out in output['users'].values():
                out['reality_ok']=False
                out['ips']=[ip for ip in out['ips'] if ip['protocol']!='Reality']
                out['reality_error']='Reality在线IP未启用或不可读取：'+str(exc) if isinstance(exc,ValueError) else 'Reality在线IP读取失败：'+type(exc).__name__
    else:
        for out in output['users'].values():out['reality_ok']=True
    return output

