"""地址栏哈希路由（2026-11-12 修）。

旧实现两处问题：
1. 首屏直达 #reality 时在脚本前部调用 check*Status，它们引用的 const 还没初始化，
   每次都抛 5 个「Cannot access … before initialization」未处理拒绝；
2. 没有监听 hashchange：门户开着时改地址栏哈希或打开同页书签，页面不切换，
   地址栏写着 #cores，显示的还是原来的标签。
按真实页面的元素构造假 DOM，在 node 里执行整份 portal.SCRIPT，锁住这两点。
run_portal_page / page_model 也供其它需要「整页脚本」的测试复用。
"""
import html
import json
import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal  # noqa: E402

NODE = shutil.which('node')

HARNESS = r"""
const vm = require('vm');
const errors = [];
process.on('unhandledRejection', e => errors.push('unhandledRejection: ' + ((e && e.message) || e)));
process.on('uncaughtException', e => errors.push('uncaught: ' + ((e && e.message) || e)));
const fetched = [];
const requests = [];
const alerts = [];
const nativeSubmits = [];
const windowListeners = {};
const intervals = [];
let reloads = 0;
let respond = null;

function makeEl(id, tag, cls) {
  const classes = new Set(cls || []);
  const listeners = {};
  const el = {
    id, tagName: tag || 'DIV', style: {}, dataset: {}, value: '', checked: false, disabled: false,
    textContent: '', innerHTML: '', className: '', hidden: false, children: [], options: [],
    classList: {
      add: c => classes.add(c), remove: c => classes.delete(c), contains: c => classes.has(c),
      toggle(c, force) {
        const on = force === undefined ? !classes.has(c) : !!force;
        if (on) classes.add(c); else classes.delete(c);
        return on;
      },
    },
    addEventListener(type, fn) { (listeners[type] = listeners[type] || []).push(fn); },
    removeEventListener(type, fn) { listeners[type] = (listeners[type] || []).filter(f => f !== fn); },
    dispatch(type, ev) { for (const fn of (listeners[type] || []).slice()) fn(ev || {type, target: el}); },
    click() { el.dispatch('click', {type: 'click', target: el}); },
    appendChild(c) { return c; }, append() {},
    prepend() {}, replaceChildren() {}, remove() {}, insertBefore(c) { return c; },
    querySelector() { return null; }, querySelectorAll() { return []; }, closest() { return null; },
    setAttribute() {}, getAttribute() { return null; }, removeAttribute() {}, hasAttribute() { return false; },
    focus() {}, blur() {}, select() {}, insertAdjacentHTML() {}, scrollIntoView() {},
    getBoundingClientRect() { return {top: 0, left: 0, width: 0, height: 0}; },
  };
  return el;
}

const els = {};
for (const id of M.ids) els[id] = makeEl(id);
const tabBtns = [];
const panes = [];
const subPanes = [];
const allSubBtns = [];
for (const tab of M.tabs) {
  const btn = makeEl(null, 'BUTTON', tab === M.active ? ['tab-btn', 'active'] : ['tab-btn']);
  btn.dataset.tab = tab;
  tabBtns.push(btn);
  const pane = els['pane-' + tab];
  pane.classList.add('tab-pane');
  if (tab === M.active) pane.classList.add('active');
  panes.push(pane);
  const btns = [];
  const subs = [];
  M.subtabs[tab].forEach((sub, i) => {
    const b = makeEl(null, 'BUTTON', i === 0 ? ['subtab-btn', 'active'] : ['subtab-btn']);
    b.dataset.subtab = sub;
    b.closest = sel => (sel === '.tab-pane' ? pane : null);
    btns.push(b);
    const p = els['sub-' + sub];
    p.classList.add('subtab-pane');
    if (i === 0) p.classList.add('active');
    subs.push(p);
  });
  allSubBtns.push(...btns);
  subPanes.push(...subs);
  pane.querySelectorAll = sel => (sel === '.subtab-btn' ? btns.slice() : sel === '.subtab-pane' ? subs.slice() : []);
  pane.querySelector = sel => {
    const m = /^\[data-subtab="([^"]+)"\]$/.exec(sel);
    return m ? (btns.find(b => b.dataset.subtab === m[1]) || null) : null;
  };
}

// 页面里的真实表单：类名、action、字段都取自渲染出的 HTML。
const forms = M.forms.map(f => {
  const listeners = {};
  const btn = {disabled: false};
  return {
    classes: f.classes, fields: f.fields, btn, listeners, dataset: f.dataset,
    getAttribute: name => (name === 'action' ? f.action : null),
    querySelector: sel => (sel === '[type="submit"]' ? btn : null),
    addEventListener(type, fn) { (listeners[type] = listeners[type] || []).push(fn); },
    submit() { nativeSubmits.push(f.action); },
  };
});

class FormData {
  constructor(form) { this.pairs = form.fields.map(pair => pair.slice()); }
  [Symbol.iterator]() { return this.pairs[Symbol.iterator](); }
}

const location = {pathname: '/t/', search: '', origin: 'http://127.0.0.1', host: '127.0.0.1', hash: M.start,
                  reload() { reloads += 1; }};
Object.defineProperty(location, 'href', {get() { return location.origin + location.pathname + location.hash; }});
const sandbox = {
  console, setTimeout, clearTimeout, clearInterval() {},
  setInterval(fn, ms) { intervals.push({fn, ms}); return intervals.length; },
  Response, Headers, Request, URL, URLSearchParams, TextEncoder, TextDecoder, AbortController, FormData,
  crypto: globalThis.crypto, btoa, atob, Blob: globalThis.Blob,
  location,
  history: {replaceState(_s, _t, url) { if (typeof url === 'string' && url.startsWith('#')) location.hash = url; }},
  navigator: {clipboard: {writeText: async () => {}}, userAgent: 'node'},
  localStorage: {getItem() { return null; }, setItem() {}, removeItem() {}},
  alert(msg) { alerts.push(String(msg)); }, confirm() { return false; }, prompt() { return null; },
  fetch: async (url, init) => {
    fetched.push(String(url));
    init = init || {};
    requests.push({url: String(url), method: init.method || 'GET', body: init.body || '', redirect: init.redirect || ''});
    if (respond) return respond(String(url), init);
    return new Response(JSON.stringify({ok: false, error: 'stub'}));
  },
  addEventListener(type, fn) { (windowListeners[type] = windowListeners[type] || []).push(fn); },
  removeEventListener() {}, scrollTo() {}, matchMedia() { return {matches: false, addEventListener() {}}; },
  innerWidth: 1280, innerHeight: 800,
  document: {
    hidden: false, visibilityState: 'visible', cookie: '',
    getElementById: id => els[id] || null,
    querySelectorAll(sel) {
      if (sel === '.tab-btn' || sel === '[data-tab]') return tabBtns.slice();
      if (sel === '.tab-pane') return panes.slice();
      if (sel === '.subtab-btn') return allSubBtns.slice();
      const m = /^form\.([\w-]+)$/.exec(sel);
      if (m) return forms.filter(f => f.classes.includes(m[1]));
      return [];
    },
    querySelector(sel) {
      const m = /^\[data-tab="([^"]+)"\]$/.exec(sel);
      return m ? (tabBtns.find(b => b.dataset.tab === m[1]) || null) : null;
    },
    createElement: tag => makeEl(null, String(tag).toUpperCase()),
    createTextNode: t => ({textContent: String(t)}),
    addEventListener() {}, removeEventListener() {},
    body: makeEl('body', 'BODY'), documentElement: makeEl('html', 'HTML'),
  },
};
sandbox.window = sandbox;
vm.createContext(sandbox);
try {
  vm.runInContext(SCRIPT, sandbox, {filename: 'portal-script.js'});
} catch (e) {
  errors.push('top-level: ' + ((e && e.message) || e));
}
const state = () => ({
  tab: panes.filter(p => p.classList.contains('active')).map(p => p.id),
  sub: subPanes.filter(p => p.classList.contains('active')).map(p => p.id),
  hash: location.hash,
});
const tick = () => new Promise(r => setTimeout(r, 30));
const go = async hash => {
  location.hash = hash;
  for (const fn of windowListeners.hashchange || []) fn({type: 'hashchange'});
  await tick();
};
(async () => {
  await tick();
  const report = {initial: state(), initialFetched: fetched.splice(0), steps: []};
  for (const hash of M.steps) {
    await go(hash);
    report.steps.push(Object.assign({fetched: fetched.splice(0)}, state()));
  }
  if (AFTER) {
    report.after = await AFTER({forms, els, requests, alerts, nativeSubmits, location, tick, go, intervals,
                                state, tabBtns, subBtns: allSubBtns,
                                setRespond: fn => { respond = fn; }, reloads: () => reloads});
  }
  report.errors = errors;
  console.log(JSON.stringify(report));
  process.exit(0);
})();
"""


def render(users=None):
    meta = {
        'public_ip': '1.2.3.4', 'server_name': 'h.example.com',
        'subscription_port': 8443, 'listen_port': 443, 'hop_port_range': '20000-40000',
        'auth_password': 'p', 'obfs_password': '', 'cert_type': 'acme',
        'is_insecure': False, 'pin_sha256': '',
    }
    return portal.page_html(
        meta, 'hysteria2://x@h:1/', '#s', 'c', '{}',
        users=users or {}, api_key=None, token='t', session_secret='s')


def _attr(attrs, name):
    m = re.search(r'\b%s="([^"]*)"' % name, attrs)
    return html.unescape(m.group(1)) if m else None


def page_model(users=None):
    page = render(users)
    tabs = re.findall(r'class="tab-btn[^"]*" data-tab="([a-z]+)"', page)
    subtabs = {}
    for tab in tabs:
        start = page.index('id="pane-%s"' % tab)
        nxt = page.find('id="pane-', start + 1)
        subtabs[tab] = re.findall(r'data-subtab="([a-z-]+)"', page[start:nxt if nxt != -1 else len(page)])
    forms = []
    for attrs, inner in re.findall(r'<form\b([^>]*)>(.*?)</form>', page, re.S):
        fields = []
        for tag in re.findall(r'<input\b[^>]*>', inner):
            name = _attr(tag, 'name')
            if name:
                fields.append([name, _attr(tag, 'value') or ''])
        forms.append({'classes': (_attr(attrs, 'class') or '').split(), 'action': _attr(attrs, 'action') or '',
                      'fields': fields, 'dataset': {'confirm': _attr(attrs, 'data-confirm') or ''}})
    return {
        'ids': sorted(set(re.findall(r'\bid="([^"]+)"', page))),
        'tabs': tabs,
        'active': re.search(r'class="tab-btn active" data-tab="([a-z]+)"', page).group(1),
        'subtabs': subtabs,
        'forms': forms,
    }


def run_portal_page(model, start='', steps=(), after=None):
    """按 model 搭假 DOM 执行整份 SCRIPT；after 是可选的 `async ctx => {...}` JS 源码。"""
    model = dict(model, start=start, steps=list(steps))
    source = 'const M = %s;\nconst SCRIPT = %s;\nconst AFTER = %s;\n%s' % (
        json.dumps(model), json.dumps(portal.SCRIPT), after or 'null', HARNESS)
    r = subprocess.run([NODE, '-'], input=source, capture_output=True, text=True, encoding='utf-8',
                       timeout=60)
    if r.returncode != 0:
        raise AssertionError(r.stderr)
    return json.loads(r.stdout.strip().splitlines()[-1])


@unittest.skipUnless(NODE, 'requires node')
class HashRoutingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.model = page_model()

    def run_page(self, start, steps=()):
        return run_portal_page(self.model, start, steps)

    def test_deep_links_open_the_tab_without_script_errors(self):
        cases = (('', 'pane-connect', None),
                 ('#reality', 'pane-reality', 'sub-reality-node'),
                 ('#reality/vmess', 'pane-reality', 'sub-vmess'),
                 ('#proxies/awg', 'pane-proxies', 'sub-awg'),
                 ('#users', 'pane-users', None),
                 ('#cores', 'pane-cores', None))
        for start, pane, sub in cases:
            with self.subTest(start=start):
                report = self.run_page(start)
                self.assertEqual(report['errors'], [])
                self.assertEqual(report['initial']['tab'], [pane])
                if sub:
                    self.assertIn(sub, report['initial']['sub'])
                if start == '#cores':
                    self.assertIn('/t/cores-status', report['initialFetched'])

    def test_hash_change_switches_the_tab_and_refreshes_it(self):
        report = self.run_page('', ['#cores', '#reality/vmess', '#nope'])
        self.assertEqual(report['errors'], [])
        cores, reality, unknown = report['steps']
        self.assertEqual(cores['tab'], ['pane-cores'], 'address bar says #cores but the page did not switch')
        self.assertIn('/t/cores-status', cores['fetched'])
        self.assertEqual(reality['tab'], ['pane-reality'])
        self.assertIn('sub-vmess', reality['sub'])
        for name in ('reality', 'vmess', 'vlessenc', 'anytls', 'tuic'):
            self.assertIn('/t/%s-status' % name, reality['fetched'])
        self.assertEqual(unknown['tab'], ['pane-reality'], 'an unknown hash must leave the page alone')
        self.assertFalse([u for u in unknown['fetched'] if u.endswith('-status')], unknown['fetched'])


if __name__ == '__main__':
    unittest.main()
