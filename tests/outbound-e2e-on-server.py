#!/usr/bin/env python3
"""在真实部署的门户上，端到端验证自定义出站功能。

为什么必须真打真实服务：本次开发里先后踩了三个只有真跑才暴露的坑——
   1. 端点注册在 /api/v1/（api_key）但前端按 prefix 调 ⇒ 404
   2. subpath 含 query 导致等值比较落空 ⇒ 404
   3. portal.json的 page 字段是缓存，改代码后不 refresh 不生效
这三个都不是"读代码能看出来"的，必须真打。
"""
import hashlib
import hmac
import time
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

D = json.load(open('/etc/hysteria/portal.json'))
TOK = D['token']
B = 'http://127.0.0.1:33947/' + TOK + '/'
IAT = str(int(time.time()))
SIG = hmac.new(D['session_secret'].encode(), ('sess:' + TOK + ':' + IAT).encode(),
               hashlib.sha256).hexdigest()
CK = 'hy2_session=' + TOK + '.' + IAT + '.' + SIG
OP = urllib.request.build_opener()

PASS = 0
FAIL = 0


def case(name, ok, extra=''):
    global PASS, FAIL
    if ok:
        PASS += 1
        print('  PASS  ' + name)
    else:
        FAIL += 1
        print('  FAIL  ' + name)
        if extra:
            print('        | ' + str(extra)[:300])


def req(path, data=None):
    r = urllib.request.Request(B + path, data=data)
    r.add_header('Cookie', CK)
    return OP.open(r, timeout=60).read().decode('utf-8', 'ignore')


def post_probe(**kw):
    body = urllib.parse.urlencode(kw).encode()
    r = urllib.request.Request(B + 'outbounds/probe', data=body)
    r.add_header('Cookie', CK)
    r.add_header('Content-Type', 'application/x-www-form-urlencoded')
    return OP.open(r, timeout=60).read().decode('utf-8', 'ignore')


def post(action, **kw):
    """POST 包装。🔴 校验失败时端点会返回 400 —— 那是**正确行为**，
    必须把响应体取出来（里面有给用户看的拒绝原因），不能当异常丢掉。"""
    body = urllib.parse.urlencode(dict(action=action, **kw)).encode()
    r = urllib.request.Request(B + 'manage-outbounds', data=body)
    r.add_header('Cookie', CK)
    try:
        return json.loads(OP.open(r, timeout=60).read().decode('utf-8', 'ignore'))
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read().decode('utf-8', 'ignore'))
        except Exception:
            return {'ok': False, 'error': 'HTTP %d' % e.code}


print('=== 1) 页面渲染 ===')
h = req('')
case('页面含自定义出站区块', 'ob-outbound-ip' in h and 'btn-ob-mode-global' in h)
case('页面含 SOCKS5 地址框', 'ob-socks-addr' in h)
case('页面含 HTTP 地址框', 'ob-http-url' in h)
case('页面含全局模式按钮', 'ob-ob-mode-global' not in h and 'btn-ob-mode-global' in h)
case('页面含分流规则下拉', 'ob-rule-outbound' in h)

print('\n=== 2) 出站列表 ===')
j = json.loads(req('outbounds/list'))
case('list 返回 ok', j.get('ok') is True, j)
case('含三种类型', sorted(t['id'] for t in j.get('types', [])) == ['direct', 'http', 'socks5'], j.get('types'))
case('含内建出站', 'direct_ipv4' in (j.get('builtin') or []), j.get('builtin'))

print('\n=== 3) 出口 IP 探测 ===')
p = json.loads(post_probe(kind='direct'))
case('直连探测返回 ok', p.get('ok') is True, p)
case('直连出口 IP 非空（%s）' % p.get('ip'), bool(p.get('ip')))

print('\n=== 4) 参数校验（必须拒绝并给可读原因）===')
r = post('save', name='bad1', type='socks5', addr='1.2.3.4')
case('socks5 缺端口被拒', r.get('ok') is False and 'host:port' in r.get('error', ''), r)
r = post('save', name='bad2', type='http', url='socks5://x')
case('http 协议头错误被拒', r.get('ok') is False and 'http://' in r.get('error', ''), r)
r = post('save', name='bad3', type='ss', addr='1.2.3.4:1')
case('不支持的类型被拒', r.get('ok') is False and 'direct / socks5 / http' in r.get('error', ''), r)
r = post('save', name='bad4', type='socks5', addr='1.2.3.4:99999')
case('端口越界被拒', r.get('ok') is False, r)

print('\n=== 5) 新增真实出站（指向本机一个真实 socks5）===')
# 用 WARP 的端口做实测对象（若装了）；否则用一个必然不存在的端口，
# 只验"保存流程+回滚逻辑"，不验连通性。
r = post('save', name='probe_exit', type='socks5', addr='127.0.0.1:19898')
case('保存出站返回成功或明确的应用失败', r.get('ok') is True or 'applied' in r, r)
if r.get('ok'):
    j = json.loads(req('outbounds/list'))
    names = [o['name'] for o in (j.get('outbounds') or [])]
    case('出站已出现在列表（%s）' % names, 'probe_exit' in names)

    print('\n=== 6) 全局模式切换 ===')
    r = post('mode', mode='global')
    case('切到全局模式', r.get('ok') is True, r)
    cfg = open('/etc/hysteria/config.yaml').read()
    case('config.yaml 里出现全局 ACL', '(all)' in cfg.split('acl:')[-1] if 'acl:' in cfg else False)
    j = json.loads(req('outbounds/list'))
    case('列表回显 mode=global', j.get('mode') == 'global', j.get('mode'))

    print('\n=== 7) 分流规则增删 ===')
    r = post('rule-add', domain='openai.com', outbound='probe_exit')
    case('添加规则', r.get('ok') is True, r)
    j = json.loads(req('outbounds/list'))
    rules = j.get('rules') or []
    hit = [x for x in rules if x.get('domain') == 'openai.com']
    case('规则已存在且指向 probe_exit', hit and hit[0].get('outbound') == 'probe_exit', rules)

    print('\n=== 8) 删除出站须连带清理引用它的规则 ===')
    r = post('delete', name='probe_exit')
    case('删除出站', r.get('ok') is True, r)
    j = json.loads(req('outbounds/list'))
    rules = j.get('rules') or []
    case('引用它的规则已被清理',
         not any(x.get('outbound') == 'probe_exit' for x in rules), rules)
    #🔴 关键：删完之后配置必须仍然能被 hysteria 接受（没有悬空引用）
    case('删除后 hysteria 仍 active',
         __import__('subprocess').run(['systemctl', 'is-active', 'hysteria-server'],
                                      capture_output=True, text=True).stdout.strip() == 'active')
    r = post('mode', mode='rules')
    case('切回分流模式', r.get('ok') is True, r)

print('\n=== 9) 未登录不得访问 ===')
OP2 = urllib.request.build_opener()
try:
    OP2.open(urllib.request.Request(B + 'outbounds/list'), timeout=10)
    case('未登录访问被拒', False, '竟然成功了')
except urllib.error.HTTPError as e:
    case('未登录访问被拒（HTTP %d）' % e.code, e.code in (401, 403))

print('\n================ 结果 ================')
print('  通过: %d   失败: %d' % (PASS, FAIL))
sys.exit(0 if FAIL == 0 else 1)