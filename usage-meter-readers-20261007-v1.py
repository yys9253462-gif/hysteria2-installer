"""节点计数器只读适配器；不 reset，不输出 secret。"""
import json
import subprocess
import urllib.request
from urllib.parse import urlparse


def service_epoch(service):
    if service not in ('hysteria-server', 'xray'):
        raise ValueError('unsupported service')
    r = subprocess.run(['systemctl','show',service,'--property=InvocationID','--value'],
                       capture_output=True, timeout=5, check=True)
    value = r.stdout.decode().strip()
    if not value:
        raise RuntimeError('missing InvocationID')
    return value


def read_hysteria(url, secret):
    p=urlparse(url)
    if p.scheme != 'http' or p.hostname not in ('127.0.0.1','::1') or p.path not in ('','/'):
        raise ValueError('stats endpoint must be loopback HTTP base URL')
    req=urllib.request.Request(url.rstrip('/')+'/traffic',headers={'Authorization':secret})
    with urllib.request.urlopen(req, timeout=4) as response:
        raw=response.read(4*1024*1024+1)
    if len(raw)>4*1024*1024:
        raise ValueError('traffic response too large')
    result=json.loads(raw)
    if not isinstance(result,dict): raise ValueError('invalid traffic response')
    return result


def parse_xray(raw):
    obj=json.loads(raw)
    rows=obj.get('stat', obj.get('stats'))
    if rows is None:
        # statsquery 对空统计返回 {}；只允许空对象作为合法空响应。
        if obj == {}: return {}
        raise ValueError('missing stat array')
    if not isinstance(rows,list): raise ValueError('invalid stat array')
    out={}
    seen=set()
    for row in rows:
        name=row.get('name','')
        parts=name.split('>>>')
        if len(parts)!=4 or parts[0]!='user' or parts[2]!='traffic': continue
        if parts[3] not in ('uplink','downlink'): continue
        value=row.get('value')
        if isinstance(value,str) and value.isdigit(): value=int(value)
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
    if not address.startswith('127.0.0.1:'): raise ValueError('xray endpoint must be loopback')
    r=subprocess.run([binary,'api','statsquery','--server='+address,'-pattern','user>>>','-reset=false'],
                     capture_output=True,timeout=5,check=True)
    return parse_xray(r.stdout.decode())


def read_hysteria_online(url, secret):
    p = urlparse(url)
    if p.scheme != 'http' or p.hostname not in ('127.0.0.1', '::1') or p.path not in ('', '/'):
        raise ValueError('stats endpoint must be loopback HTTP base URL')
    req = urllib.request.Request(url.rstrip('/') + '/online', headers={'Authorization': secret})
    with urllib.request.urlopen(req, timeout=4) as response:
        raw = response.read(4 * 1024 * 1024 + 1)
    if len(raw) > 4 * 1024 * 1024:
        raise ValueError('online response too large')
    result = json.loads(raw)
    if not isinstance(result, dict) or any(not isinstance(uid, str) or type(count) is not int or count < 0 for uid, count in result.items()):
        raise ValueError('invalid online counters')
    return result


"""只读采集：连接事件 + Hy2核心在线计数校验；不使用鉴权超时作在线判据。"""
import re,ipaddress,time,pathlib,urllib.error

def parse_events(rows):
    active={}
    rows=sorted(rows,key=lambda row:int(row.get('__MONOTONIC_TIMESTAMP',row.get('__REALTIME_TIMESTAMP',0))))
    for row in rows:
        message=row.get('MESSAGE','')
        if isinstance(message,list):
            if any(type(x)!=int or not 0<=x<=255 for x in message):raise ValueError('invalid_journal_message')
            message=bytes(message).decode('utf-8')
        if not isinstance(message,str):raise ValueError('missing_journal_message')
        clean=re.sub(r'\x1b\[[0-9;]*m','',message)
        event=None
        try:
            if clean.startswith('{'):
                fields=json.loads(clean);event=fields.get('msg') or fields.get('message')
            else:
                match=re.search(r'(?:^|\t)(client connected|client disconnected)\t',clean)
                if not match:continue
                event=match.group(1);fields=json.loads(clean[match.end():])
        except (ValueError,TypeError):raise ValueError('invalid_connection_event') from None
        if event not in ('client connected','client disconnected'):continue
        uid,addr=fields.get('id'),fields.get('addr')
        if not isinstance(uid,str) or not isinstance(addr,str):raise ValueError('missing_connection_identity')
        ip=addr.rsplit(':',1)[0].strip('[]')
        ip=str(ipaddress.ip_address(ip))
        key=(uid,addr)
        if event=='client connected':active[key]=ip
        else:active.pop(key,None)
    return active

def confirmed_ips(connections,uid,count):
    if count==0:return []
    known=[ip for (user,addr),ip in connections.items() if user==uid]
    if len(known)!=count:return None
    return sorted(set(known))

def cmd(args):
    return subprocess.run(args,capture_output=True,text=True,timeout=8,check=True).stdout

def read_live_connections():
    cfg=json.loads(pathlib.Path('/etc/hysteria/usage-meter-config.json').read_text())
    portal=json.loads(pathlib.Path('/etc/hysteria/portal.json').read_text())
    users=portal.get('users',{})
    output={'users':{},'sampled_at':int(time.time())}
    for uid in users:output['users'][uid]={'ips':[],'ok':False,'error':'Hy2 online IP unavailable','hysteria_ok':False,'reality_ok':False}
    core_counts=None
    try:
        h=cfg['hysteria']
        parsed=urlparse(h['url'])
        if parsed.scheme!='http' or parsed.hostname not in ('127.0.0.1','::1') or parsed.path not in ('','/'):raise ValueError('stats_not_loopback')
        live_req=urllib.request.Request(h['url'].rstrip('/')+'/online/ips',headers={'Authorization':h['secret']})
        try:
            with urllib.request.urlopen(live_req,timeout=4) as response:live=json.load(response)
        except urllib.error.HTTPError as exc:
            if exc.code!=404:raise
            live=None
        if live is not None:
            if live.get('revision')!='teyir-live-ips-v1' or not isinstance(live.get('users'),dict):raise ValueError('invalid_core_live_response')
            for uid,out in output['users'].items():
                row=live['users'].get(uid,{'connections':0,'ips':[]})
                if type(row.get('connections'))!=int or row['connections']<0 or not isinstance(row.get('ips'),list):raise ValueError('invalid_core_live_user')
                ips=[{'ip':str(ipaddress.ip_address(ip)),'protocol':'Hy2','last_seen':output['sampled_at']} for ip in row['ips']]
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
                parsed=urlparse(h['url'])
                if parsed.scheme!='http' or parsed.hostname not in ('127.0.0.1','::1') or parsed.path not in ('','/'):raise ValueError('stats_not_loopback')
                req=urllib.request.Request(h['url'].rstrip('/')+'/online',headers={'Authorization':h['secret']})
                with urllib.request.urlopen(req,timeout=4) as r:online=json.load(r)
                if not isinstance(online,dict) or any(type(x)!=int or x<0 for x in online.values()):raise ValueError('invalid_online_counts')
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
    # Reality 若已启用核心在线统计则读取；未启用时明确说明，不用历史access日志猜。
    rcfg=cfg.get('reality',{})
    binary=rcfg.get('binary','')
    if binary and pathlib.Path(binary).is_file():
        try:
            xcfg=json.loads(pathlib.Path('/etc/hysteria/xray.json').read_text())
            enabled=xcfg.get('policy',{}).get('levels',{}).get('0',{}).get('statsUserOnline',False)
            if not enabled:raise ValueError('online_statistics_not_enabled')
            address=rcfg['address']
            if not address.startswith('127.0.0.1:'):raise ValueError('stats_not_loopback')
            allusers=json.loads(cmd([binary,'api','statsgetallonlineusers','--server='+address]))
            names=allusers.get('users',[]) if isinstance(allusers,dict) else allusers
            if not isinstance(names,list):raise ValueError('invalid_online_users')
            if any(not isinstance(name,str) for name in names):raise ValueError('invalid_online_user_name')
            names=[name.split('>>>')[1] if name.startswith('user>>>') and name.endswith('>>>online') and len(name.split('>>>'))==3 else name for name in names]
            for uid,out in output['users'].items():
                out['reality_ok']=True
                if uid not in names:continue
                result=json.loads(cmd([binary,'api','statsonlineiplist','--server='+address,'--email='+uid]))
                ips=result.get('ips',{})
                if not isinstance(ips,dict):raise ValueError('invalid_online_ips')
                for ip,seen in ips.items():out['ips'].append({'ip':str(ipaddress.ip_address(ip)),'protocol':'Reality','last_seen':int(seen)})
        except Exception as exc:
            for out in output['users'].values():
                out['reality_ok']=False
                out['ips']=[ip for ip in out['ips'] if ip['protocol']!='Reality']
                out['reality_error']='Reality在线IP未启用或不可读取：'+str(exc) if isinstance(exc,ValueError) else 'Reality在线IP读取失败：'+type(exc).__name__
    else:
        for out in output['users'].values():out['reality_ok']=True
    return output

