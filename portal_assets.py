"""门户前端资源（CSS / 内嵌 JS）。

🔴 这个文件里的 JS 常量必须是**原始字符串**（三引号前加 r）。
写成普通三引号字符串的话，源码里为 JS 字符串准备的 `\n` 会被 Python
在解析阶段转成真实换行、塞进 JS 单引号字符串里 —— JS 语法错误会让整段脚本
失效：页面能打开，但标签页切不动、所有按钮失灵。真实事故过一次。

由 portal.py 引入使用；部署时必须与 portal.py 成对存在（见 install.sh 的
portal_ensure_py —— 两个文件一起拉，要么都成功要么都不落地）。
"""


# ============================================================================
# STYLE
# ============================================================================
STYLE = """
:root{color-scheme:light;--ink:#122b31;--muted:#667c81;--line:#dce7e6;--accent:#087f74;--accent-hover:#066960;--danger:#cf3c3c;--danger-bg:#fdf2f2;--brand-bg:#eaf5ef;--card-bg:#ffffff}
*{box-sizing:border-box}body{margin:0;background:#f3f7f6;color:var(--ink);font:15px/1.6 system-ui,-apple-system,"Segoe UI","Microsoft YaHei",sans-serif}
main{max-width:1160px;margin:auto;padding:32px 28px 48px}.topbar{display:flex;justify-content:space-between;align-items:center;padding-bottom:24px}
.brand{font-weight:800;letter-spacing:.04em;display:flex;gap:10px;align-items:center}.logo{background:var(--ink);color:white;border-radius:12px;padding:7px 12px;font-size:17px}.private{font-size:12px;color:var(--accent);border:1px solid #c3ddd5;border-radius:30px;padding:5px 12px;background:#eaf5ef}
.eyebrow{font-size:11px;letter-spacing:.16em;font-weight:750;color:var(--accent)}h1{font-size:32px;letter-spacing:-.04em;margin:6px 0}h2{font-size:18px;margin:0 0 4px}p{margin:0;color:var(--muted)}.hero{margin-bottom:24px}.hero p{font-size:14px}

/* Tab 导航容器 */
/* 顶部主菜单（2026-10-28 美化）：整块圆角导航条 + 主题色填充的当前项，
   与下方白底子标签区分层级；宽屏铺满一行，窄屏横滑且不显示滚动条。 */
.tab-bar{display:flex;flex-wrap:wrap;gap:4px;padding:5px;margin-bottom:26px;background:rgba(255,255,255,.92);border:1px solid var(--line);border-radius:16px;box-shadow:0 6px 20px rgba(18,43,49,.06);overflow-x:auto;scrollbar-width:none;position:sticky;top:10px;z-index:30;backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px)}
.tab-bar::-webkit-scrollbar{display:none}
.tab-btn{flex:1 1 auto;display:inline-flex;align-items:center;justify-content:center;gap:7px;padding:10px 14px;border:none;background:none;color:var(--muted);font-size:13.5px;font-weight:700;cursor:pointer;border-radius:11px;transition:background .18s ease,color .18s ease,box-shadow .18s ease;white-space:nowrap}
.tab-btn:hover{color:var(--ink);background:#eef6f4}
.tab-btn.active{color:#fff;background:var(--accent);box-shadow:0 4px 12px rgba(8,127,116,.28)}
.tab-btn:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
@media(max-width:1180px) and (min-width:761px){.tab-btn{padding:9px 9px;font-size:12.5px;gap:5px}}
.tab-pane{display:none}
.tab-pane.active{display:block;animation:fadeIn .2s ease-out}
@keyframes fadeIn{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:translateY(0)}}

/* 组内子标签：一页里放多块独立服务时，避免纵向堆成几屏 */
.subtab-bar{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:18px;padding:6px;background:#e9f1ef;border-radius:14px}
.subtab-btn{border:1px solid transparent;background:transparent;color:#4c6b70;font:700 13px/1.4 inherit;padding:9px 16px;border-radius:10px;cursor:pointer;transition:all .15s ease;white-space:nowrap}
.subtab-btn:hover{background:#f5faf8;color:var(--ink)}
.subtab-btn.active{background:#fff;color:var(--accent);border-color:#cfe3dd;box-shadow:0 2px 8px #183f350d}
.subtab-pane{display:none}
/* 切换中的按钮必须有可见反馈，否则用户会以为没点上而反复点击 */
.toggle-btn:disabled,.button:disabled{opacity:.55;cursor:not-allowed;filter:saturate(.6)}
.subtab-pane.active{display:block;animation:fadeIn .18s ease-out}

/* 卡片与网格 */
.layout{display:grid;grid-template-columns:320px minmax(0,1fr);gap:22px;align-items:start}
.card{background:#fff;border:1px solid var(--line);border-radius:20px;padding:24px;box-shadow:0 5px 22px #183f3505}
.qr-card{text-align:center}.qr-frame{background:#fff;border:1px solid var(--line);border-radius:16px;padding:14px;margin:20px 0}.qr-frame img{display:block;width:100%;height:auto}
.hint{font-size:12px}.tags{display:flex;gap:6px;justify-content:center;flex-wrap:wrap;margin-top:18px}.tag{background:#f0f5f4;color:#526a70;border-radius:6px;padding:3px 8px;font-size:11px}
.stack{display:grid;gap:18px}.card-head{display:flex;gap:14px;align-items:center;margin-bottom:16px}.step{display:grid;place-items:center;flex:0 0 38px;height:38px;border-radius:11px;background:#e8f4f0;color:var(--accent);font-weight:750}.card-head p{font-size:12px}
textarea{display:block;width:100%;min-width:0;border:1px solid var(--line);background:#f7faf9;border-radius:12px;padding:14px;color:#35545c;font:12px/1.7 ui-monospace,SFMono-Regular,Consolas,monospace;resize:vertical;overflow-wrap:anywhere}
textarea.link{height:92px}textarea.config{height:290px;margin-top:18px}textarea:focus{outline:2px solid #65b3a5;outline-offset:2px}
.actions{display:flex;gap:10px;align-items:center;margin-top:14px;flex-wrap:wrap}
.button{display:inline-flex;align-items:center;justify-content:center;gap:6px;border:1px solid var(--line);background:white;border-radius:9px;padding:9px 15px;color:var(--ink);text-decoration:none;font:600 12px/1.5 inherit;cursor:pointer}
.button.primary{background:var(--accent);color:white;border-color:var(--accent)}.button.danger{background:var(--danger);color:white;border-color:var(--danger)}.button:hover{filter:brightness(.94)}
.note{font-size:12px;margin-top:12px}.advanced{margin-top:24px}.advanced-title{display:flex;align-items:center;justify-content:space-between;margin-bottom:12px}.advanced-title p{font-size:12px}.config-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}
summary{cursor:pointer;font-weight:650;list-style-position:inside}summary span{font-size:11px;font-weight:400;color:var(--muted);margin-left:10px}
.security{margin-top:24px;padding:15px 18px;border:1px solid #d8e6df;border-radius:12px;background:#eaf2ed;color:#4f6a60;font-size:12px}
footer{display:flex;justify-content:space-between;margin-top:32px;color:#879996;font-size:11px}.status{font-size:12px;color:var(--accent)}

/* 多用户与集群专属卡片样式 */
.user-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:18px;flex-wrap:wrap;gap:12px}
.badge-count{background:var(--brand-bg);color:var(--accent);border:1px solid #c3ddd5;border-radius:20px;padding:4px 12px;font-size:12px;font-weight:700}
.switch-box{display:flex;align-items:center;gap:12px;background:#f8fbfb;border:1px solid var(--line);border-radius:14px;padding:16px 20px;margin-bottom:20px;justify-content:space-between;flex-wrap:wrap}
.switch-info{display:flex;flex-direction:column;gap:4px}
.switch-title{font-size:14px;font-weight:700;color:var(--ink);display:flex;align-items:center;gap:8px}
.switch-desc{font-size:12px;color:var(--muted)}
.toggle-btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;padding:8px 18px;border-radius:10px;font-size:13px;font-weight:700;cursor:pointer;border:1px solid transparent;transition:all .15s ease}
.toggle-btn.on{background:var(--accent);color:#fff;border-color:var(--accent)}
.toggle-btn.off{background:#fff;color:var(--muted);border-color:var(--line)}
.toggle-btn:hover{filter:brightness(.92)}
.user-table-wrap{width:100%;overflow-x:auto;border:1px solid var(--line);border-radius:14px;background:#fff}
.user-table{width:100%;border-collapse:collapse;text-align:left;font-size:13px}
.user-table th{background:#f8fbfb;padding:12px 14px;color:var(--muted);font-weight:700;border-bottom:1px solid var(--line);white-space:nowrap}
.user-table td{padding:12px 14px;border-bottom:1px solid var(--line);vertical-align:middle;white-space:nowrap}
.user-table tr:last-child td{border-bottom:none}
.user-toolbar{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-bottom:12px}
.user-toolbar input,.user-toolbar select{height:36px;border:1px solid var(--line);border-radius:10px;padding:0 12px;font-size:13px;background:#fff;color:var(--ink)}
.user-toolbar input{flex:1 1 260px;min-width:0}
.user-count{font-size:12px;color:var(--muted);margin-left:auto}
.user-table-scroll{max-height:640px;overflow:auto}
.user-table-scroll thead th{position:sticky;top:0;z-index:2}
.user-table td{padding:8px 12px}
.user-table th{padding:10px 12px}
.user-table .uid-cell{max-width:300px}
.user-table .uid-cell strong,.user-table .uid-note{display:block;overflow:hidden;text-overflow:ellipsis}
.user-table .uid-note{font-size:11px;color:var(--muted)}
.user-table th:last-child,.user-table td:last-child{position:sticky;right:0;background:#fff;box-shadow:-6px 0 8px -6px rgba(18,43,49,.18)}
.user-table th:last-child{background:#f8fbfb;z-index:3}
.user-pager{display:flex;flex-wrap:wrap;gap:6px;align-items:center;justify-content:center;margin-top:12px}
.user-pager button{min-width:34px;height:32px;border:1px solid var(--line);border-radius:8px;background:#fff;cursor:pointer;font-size:12px;color:var(--ink)}
.user-pager button.active{background:var(--accent);border-color:var(--accent);color:#fff}
.user-pager button:disabled{opacity:.4;cursor:not-allowed}
.user-pager .pager-info{font-size:12px;color:var(--muted);margin:0 6px}
.status-pill{display:inline-block;padding:2px 8px;border-radius:20px;font-size:11px;font-weight:700}
.status-pill.active{background:#eafaf3;color:#0b8650}
.status-pill.expired{background:#fff1f0;color:#cf3c3c}
.traffic-bar{height:6px;width:90px;background:#e6edec;border-radius:4px;overflow:hidden;margin-top:5px}
.traffic-fill{height:100%;background:var(--accent);border-radius:4px}
.traffic-fill.danger{background:var(--danger)}
.speed-badge{display:inline-flex;align-items:center;gap:4px;background:#eef6f5;color:var(--accent);border-radius:6px;padding:2px 6px;font-size:11px;font-weight:700;font-family:ui-monospace,SFMono-Regular,Consolas,monospace}
.speed-badge.active{background:#e1f5ee;color:#085041}
.speed-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:18px}
.speed-card{background:#fff;border:1px solid var(--line);border-radius:12px;padding:14px 16px;display:flex;align-items:center;justify-content:space-between}
.speed-card .val{font-size:20px;font-weight:800;letter-spacing:-.02em;color:var(--ink);font-family:ui-monospace,SFMono-Regular,Consolas,monospace}
.speed-card .lbl{font-size:11px;color:var(--muted);font-weight:700;text-transform:uppercase}
.proxy-card{border-left:4px solid #534AB7}
.proxy-table{width:100%;border-collapse:collapse;text-align:left;font-size:13px}
.proxy-table th{background:#f8fbfb;padding:10px 12px;color:var(--muted);font-weight:700;border-bottom:1px solid var(--line);white-space:nowrap}
.proxy-table td{padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:middle}
.proxy-table tr:last-child td{border-bottom:none}
.proxy-type{display:inline-block;padding:2px 8px;border-radius:6px;font-size:11px;font-weight:700;font-family:ui-monospace,SFMono-Regular,Consolas,monospace}
.proxy-type.socks5{background:#EEEDFE;color:#3C3489}
.proxy-type.http{background:#E6F1FB;color:#0C447C}
.proxy-type.https{background:#E1F5EE;color:#085041}
.api-box{background:#f7faf9;border:1px solid var(--line);border-radius:12px;padding:16px;margin-bottom:16px;display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}
.api-key-code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:13px;color:#284d56;word-break:break-all;margin-top:4px}
.modal-form{display:grid;grid-template-columns:1fr 1fr;gap:16px 20px;background:#f8fbfb;border:1px solid var(--line);border-radius:14px;padding:22px;margin-bottom:20px}
.form-field{display:flex;flex-direction:column;gap:6px}
.form-field-full{grid-column:1/-1}
.form-field label{font-size:13px;font-weight:700;color:var(--ink);display:flex;justify-content:space-between;align-items:center}
.form-field label span{font-weight:400;color:var(--muted);font-size:12px}
.form-field input{height:42px;padding:0 12px;border:1px solid var(--line);border-radius:9px;font-size:13px;background:#fff;outline:none;transition:border-color .15s}
.form-field input:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(8,127,116,0.12)}
.form-field small{font-size:11px;color:var(--muted);line-height:1.4;margin-top:2px}
.input-with-action{display:flex;gap:8px}
.input-with-action input{flex:1;min-width:0}
.btn-mini{padding:0 12px;height:42px;background:#eaf5ef;border:1px solid #c3ddd5;color:var(--accent);border-radius:9px;font-size:12px;font-weight:700;cursor:pointer;white-space:nowrap;display:inline-flex;align-items:center;justify-content:center;transition:background .15s}
.btn-mini:hover{background:#dbeef7}

@media(max-width:760px){
  main{padding:20px 16px 32px}.topbar{padding-bottom:20px}.layout,.config-grid{grid-template-columns:1fr}.qr-frame{max-width:248px;margin:18px auto}.card{padding:20px}h1{font-size:26px}.advanced-title{display:block}footer{gap:15px;flex-direction:column}.private{font-size:10px}.brand{font-size:13px}
  .login-card{padding:28px 20px;border-radius:20px}
  .tab-bar{flex-wrap:nowrap;top:6px;border-radius:14px;scroll-snap-type:x proximity}
  .tab-btn{flex:0 0 auto;padding:9px 12px;font-size:13px;scroll-snap-align:center}
  .subtab-btn{padding:8px 12px;font-size:12.5px}
  .modal-form{grid-template-columns:1fr;gap:14px;padding:16px}
}

/* 登录样式 */
.login-wrap{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px 16px;background:radial-gradient(ellipse at top,#eef5f3 0%,#f3f7f6 100%)}
.login-card{width:100%;max-width:420px;background:#fff;border:1px solid var(--line);border-radius:24px;padding:36px 30px;box-shadow:0 12px 36px rgba(18,43,49,0.06)}
.login-brand{text-align:center;margin-bottom:28px}
.login-logo{display:inline-flex;align-items:center;justify-content:center;width:60px;height:60px;background:var(--accent);color:#fff;border-radius:18px;font-size:26px;font-weight:800;box-shadow:0 6px 16px rgba(8,127,116,0.22);margin-bottom:14px}
.login-badge{display:inline-block;font-size:11px;letter-spacing:.14em;font-weight:750;color:var(--accent);text-transform:uppercase;margin-bottom:6px}
.login-title{font-size:24px;letter-spacing:-.03em;color:var(--ink);margin:0 0 6px;font-weight:700}
.login-sub{font-size:13px;color:var(--muted);margin:0}
.login-form{display:grid;gap:18px}
.field-group{display:grid;gap:7px}
.field-label{font-size:13px;font-weight:650;color:var(--ink);display:flex;justify-content:space-between;align-items:center}
.field-input{width:100%;height:44px;padding:0 14px;border:1px solid var(--line);border-radius:11px;background:#f7faf9;color:var(--ink);font-size:14px;transition:all .15s ease}
.field-input:focus{outline:none;border-color:var(--accent);background:#fff;box-shadow:0 0 0 3px rgba(8,127,116,0.12)}
.field-pwd{position:relative}
.field-pwd input{padding-right:68px}
.toggle-pwd{position:absolute;right:8px;top:50%;transform:translateY(-50%);background:none;border:none;color:var(--muted);font-size:12px;font-weight:600;padding:6px 8px;cursor:pointer;border-radius:6px}
.toggle-pwd:hover{color:var(--accent);background:#eef5f3}
.remember-row{display:flex;align-items:center;gap:8px;margin-top:2px}
.remember-row input{accent-color:var(--accent);cursor:pointer;width:15px;height:15px}
.remember-row label{font-size:13px;color:var(--muted);cursor:pointer;user-select:none}
.btn-submit{width:100%;height:46px;background:var(--accent);color:#fff;border:none;border-radius:12px;font-size:14px;font-weight:700;cursor:pointer;transition:all .15s;margin-top:6px;display:flex;align-items:center;justify-content:center}
.btn-submit:hover{background:var(--accent-hover);box-shadow:0 4px 12px rgba(8,127,116,0.2)}
.btn-submit:active{transform:scale(0.99)}
.error-tip{padding:10px 14px;border-radius:10px;background:var(--danger-bg);color:var(--danger);font-size:13px;font-weight:550;display:flex;align-items:center;gap:8px;border:1px solid #f6cfcf}
.login-footer{margin-top:24px;padding-top:18px;border-top:1px solid #edf2f1;font-size:12px;color:var(--muted);line-height:1.6;text-align:center}
.login-footer code{background:#eef4f2;color:#33565f;padding:2px 6px;border-radius:4px;font-family:ui-monospace,SFMono-Regular,Consolas,monospace}

@media(max-width:760px){
  main{padding:20px 16px 32px}.topbar{padding-bottom:20px}.layout,.config-grid{grid-template-columns:1fr}.qr-frame{max-width:248px;margin:18px auto}.card{padding:20px}h1{font-size:26px}.advanced-title{display:block}footer{gap:15px;flex-direction:column}.private{font-size:10px}.brand{font-size:13px}
  .login-card{padding:28px 20px;border-radius:20px}
  .tab-bar{flex-wrap:nowrap;top:6px;border-radius:14px;scroll-snap-type:x proximity}
  .tab-btn{flex:0 0 auto;padding:9px 12px;font-size:13px;scroll-snap-align:center}
}

/* 专属连接弹窗与独立页面样式 */
.modal-backdrop{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(18,43,49,0.48);backdrop-filter:blur(5px);display:none;align-items:center;justify-content:center;z-index:9999;padding:16px}
.modal-backdrop.show{display:flex;animation:fadeIn .15s ease-out}
.modal-card{width:100%;max-width:700px;background:#fff;border:1px solid var(--line);border-radius:22px;padding:26px;box-shadow:0 20px 48px rgba(18,43,49,0.18);max-height:90vh;overflow-y:auto;display:flex;flex-direction:column;gap:16px}
.modal-head{display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid var(--line);padding-bottom:14px}
.modal-close{background:none;border:none;font-size:24px;color:var(--muted);cursor:pointer;padding:4px 8px;border-radius:6px;line-height:1}
.modal-close:hover{background:#f0f5f4;color:var(--ink)}
.user-connect-grid{display:grid;grid-template-columns:250px minmax(0,1fr);gap:18px;align-items:start}
@media(max-width:660px){.user-connect-grid{grid-template-columns:1fr}}
.user-meta-bar{display:flex;gap:12px;align-items:center;flex-wrap:wrap;background:#f7faf9;padding:10px 14px;border-radius:10px;border:1px solid var(--line);font-size:12px}

/* 代理成功专属弹窗高颜值设计 */
.pm-card{width:100%;max-width:650px;background:#fff;border:1px solid var(--line);border-radius:24px;padding:26px;box-shadow:0 24px 60px rgba(18,43,49,0.2);max-height:92vh;overflow-y:auto;display:flex;flex-direction:column;gap:16px}
.pm-banner{background:linear-gradient(135deg,#f0f8f6 0%,#f6faf9 100%);border:1.5px solid #cce8e1;border-radius:16px;padding:14px 18px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px}
.pm-host-box{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.pm-host-val{font-size:17px;font-weight:800;color:var(--ink);font-family:ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:-.02em}
.pm-port-val{color:var(--accent);font-weight:850}
.pm-status-tag{display:inline-flex;align-items:center;gap:4px;background:#e1f5ee;color:#085041;font-size:11px;font-weight:700;border-radius:20px;padding:3px 10px;border:1px solid #b7ebd8}
.pm-cred-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.pm-cred-card{background:#f8fbfb;border:1px solid var(--line);border-radius:12px;padding:12px 14px;display:flex;justify-content:space-between;align-items:center}
.pm-cred-lbl{font-size:11px;color:var(--muted);font-weight:700;margin-bottom:3px}
.pm-cred-val{font-size:13px;font-weight:750;color:var(--ink);font-family:ui-monospace,SFMono-Regular,Consolas,monospace;word-break:break-all}
.pm-main-grid{display:grid;grid-template-columns:140px minmax(0,1fr);gap:16px;align-items:center;background:#fafcfb;border:1px solid var(--line);border-radius:14px;padding:14px}
@media(max-width:560px){.pm-main-grid{grid-template-columns:1fr;justify-items:center}.pm-cred-grid{grid-template-columns:1fr}}
.pm-qr-frame{background:#fff;border:1px solid var(--line);border-radius:10px;padding:6px;display:flex;justify-content:center;align-items:center;width:130px;height:130px;box-shadow:0 3px 10px rgba(0,0,0,0.03)}
.pm-qr-frame svg{display:block;width:100%;height:100%}
.pm-links-stack{display:flex;flex-direction:column;gap:10px;min-width:0;width:100%}
.pm-code-box{display:flex;gap:6px;align-items:center;background:#fff;border:1px solid var(--line);border-radius:8px;padding:4px 6px 4px 10px;transition:border-color .15s}
.pm-code-box:focus-within{border-color:var(--accent);box-shadow:0 0 0 2px rgba(8,127,116,0.1)}
.pm-code-input{flex:1;min-width:0;border:none;background:transparent;font:11px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace;color:#284d56;outline:none}

/* WARP 与自定义分流模块高阶专业排版 */
.warp-section { margin-top: 10px; }
.warp-switch-card { background: #f6faf9; border: 1px solid #d3e7e2; border-radius: 14px; padding: 16px 20px; margin-bottom: 20px; }
.warp-desc-title { font-size: 13.5px; font-weight: 750; color: #11342d; display: flex; align-items: center; gap: 8px; margin-bottom: 4px; }
.warp-desc-text { font-size: 12.5px; color: #496861; line-height: 1.6; margin: 0; }

.warp-rules-card { background: #ffffff; border: 1px solid var(--line); border-radius: 16px; padding: 22px; box-shadow: 0 4px 16px rgba(18, 43, 49, 0.03); }
.warp-rules-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; flex-wrap: wrap; gap: 10px; }
.warp-rules-title-box { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.warp-rules-title { font-size: 14px; font-weight: 800; color: var(--ink); margin: 0; }
.warp-count-badge { background: #eaf5ef; color: var(--accent); border: 1px solid #c0ded4; border-radius: 20px; padding: 3px 10px; font-size: 11.5px; font-weight: 700; }
.warp-reset-btn { background: #fff; border: 1px solid var(--line); color: var(--muted); border-radius: 8px; padding: 5px 12px; font-size: 12px; font-weight: 600; cursor: pointer; transition: all .15s ease; }
.warp-reset-btn:hover { background: #f0f5f4; color: var(--ink); border-color: #b0d0c8; }

.warp-add-form { display: flex; gap: 10px; margin-bottom: 14px; }
@media(max-width: 600px) { .warp-add-form { flex-direction: column; } }

/* ===== 自定义出站（Custom Outbounds）区块 =====
   与 WARP 区块同风格但独立命名，避免选择器互相污染。 */
.ob-card { margin-top: 22px; }
.ob-head { display: flex; justify-content: space-between; align-items: center; gap: 14px; flex-wrap: wrap; }
.ob-title-box { min-width: 0; flex: 1 1 320px; }
.ob-title { font-size: 17px; font-weight: 800; color: var(--ink); margin: 0; }
.ob-subtitle { font-size: 13px; margin: 4px 0 0; color: var(--muted); }
/* 模式切换：标题栏右侧的分段按钮 */
.ob-mode-switch { display: inline-flex; padding: 4px; gap: 4px; border-radius: 12px; background: #eef3f2; border: 1px solid var(--line); }
.ob-mode-btn { border: 0; background: transparent; padding: 8px 16px; border-radius: 9px; cursor: pointer; transition: background .15s, box-shadow .15s; }
.ob-mode-btn b { font-size: 13px; font-weight: 750; color: var(--muted); white-space: nowrap; }
.ob-mode-btn:hover b { color: var(--ink); }
.ob-mode-btn.active { background: #fff; box-shadow: 0 1px 3px rgba(16,42,38,.14); }
.ob-mode-btn.active b { color: var(--accent); }
.ob-mode-btn.active[data-mode="global"] b { color: #8a5200; }
.ob-mode-note { font-size: 12.5px; color: #496861; margin: 12px 0 16px; line-height: 1.6; padding: 9px 13px; border-radius: 10px; background: #f3f8f7; border-left: 3px solid var(--accent); }
.ob-mode-note.global { background: #fff8ec; border-left-color: #e0a040; color: #6e4a12; }

.ob-grid { display: grid; grid-template-columns: minmax(260px, 2fr) 3fr; gap: 14px; margin-bottom: 14px; }
@media(max-width: 860px) { .ob-grid { grid-template-columns: 1fr; } }
.ob-probe-card, .ob-list-card, .ob-form-card, .ob-rules-card {
  border: 1px solid var(--line); border-radius: 14px; padding: 16px 18px; background: #fff; min-width: 0; }
.ob-form-card, .ob-rules-card { margin-bottom: 14px; }
.ob-rules-card { margin-bottom: 0; transition: opacity .2s; }
.ob-rules-card.inactive { opacity: .55; }
.ob-probe-card { background: #f8fbff; border-color: #d6e5f5; display: flex; flex-direction: column; }
.ob-probe-title { font-size: 12.5px; font-weight: 700; color: #2c5a86; margin-bottom: 6px; }
.ob-probe-ip { font-size: 22px; font-weight: 800; color: #1b3f61; font-family: ui-monospace, SFMono-Regular, Consolas, monospace; letter-spacing: -.02em; word-break: break-all; }
.ob-probe-sub { font-size: 11.5px; color: var(--muted); margin-top: 3px; }
.ob-probe-actions { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin-top: auto; padding-top: 14px; }
.ob-probe-actions .ob-select, .ob-probe-actions .ob-input { flex: 1 1 150px; min-width: 0; }

.ob-list-title { font-size: 14px; font-weight: 800; color: var(--ink); display: inline-flex; align-items: center; gap: 8px; }
.ob-list-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; gap: 10px; flex-wrap: wrap; }
.ob-new-btn { height: 32px; padding: 0 14px; font-size: 12.5px; }
.ob-count-badge { font-size: 11px; font-weight: 700; padding: 2px 9px; border-radius: 20px; background: #eaf5ef; color: var(--accent); border: 1px solid #c0ded4; }
.ob-empty { font-size: 12.5px; color: var(--muted); line-height: 1.6; }
.ob-list { display: flex; flex-direction: column; gap: 8px; }
.ob-item { display: flex; justify-content: space-between; align-items: center; gap: 12px;
  padding: 10px 13px; border: 1px solid var(--line); border-radius: 11px; background: #fbfcfd; flex-wrap: wrap; }
.ob-item-main { min-width: 0; flex: 1 1 200px; }
.ob-item-name { font-size: 13.5px; font-weight: 750; color: var(--ink); font-family: ui-monospace, SFMono-Regular, Consolas, monospace; }
.ob-item-meta { font-size: 12px; color: var(--muted); margin-top: 3px; word-break: break-all; }
.ob-item-type { font-size: 11px; font-weight: 700; padding: 2px 9px; border-radius: 6px; margin-left: 8px; vertical-align: middle; }
.ob-item-first { font-size: 10.5px; font-weight: 700; padding: 2px 8px; border-radius: 6px; margin-left: 6px; background: #fff4e5; color: #8a5200; vertical-align: middle; }
.ob-type-socks5 { background: #e8f0fd; color: #1d4e89; }
.ob-type-http { background: #fdeee8; color: #9a4a1e; }
.ob-type-direct { background: #eaf5ef; color: #2c6b52; }
.ob-item-actions { display: flex; gap: 6px; flex-shrink: 0; }
.ob-mini-btn { height: 28px; padding: 0 11px; font-size: 12px; font-weight: 650; border-radius: 8px;
  border: 1px solid var(--line); background: #fff; color: var(--ink); cursor: pointer; }
.ob-mini-btn:hover { border-color: var(--accent); color: var(--accent); }
.ob-mini-btn.danger:hover { border-color: #d64545; color: #d64545; background: #fef5f5; }

.ob-form-card { background: #fbfcfd; border-color: #c0ded4; box-shadow: 0 0 0 3px rgba(8,127,116,.06); }
.ob-form-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
.ob-form-title { font-size: 14px; font-weight: 800; color: var(--ink); }
.ob-form-close { border: 0; background: transparent; font-size: 20px; line-height: 1; color: var(--muted); cursor: pointer; padding: 2px 6px; border-radius: 6px; }
.ob-form-close:hover { color: var(--ink); background: #eef3f2; }
.ob-quick .ob-input { border-style: dashed; background: #f6faf9; font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 12.5px; }
.ob-quick.ok .ob-input { border-color: #6fbf9a; border-style: solid; }
.ob-quick.ok > em { color: #2c8a4e; }
.ob-quick.err > em { color: #d64545; }
.ob-type-switch { display: inline-flex; flex-wrap: wrap; gap: 6px; }
.ob-type-btn { height: 34px; padding: 0 16px; border-radius: 9px; border: 1.5px solid var(--line); background: #fff;
  font-size: 12.5px; font-weight: 700; color: var(--muted); cursor: pointer; }
.ob-type-btn:hover { border-color: var(--accent); color: var(--ink); }
.ob-type-btn.active { border-color: var(--accent); background: #eef7f5; color: var(--accent); }
.ob-pass-wrap { position: relative; display: block; }
.ob-pass-wrap .ob-input { padding-right: 52px; }
.ob-pass-eye { position: absolute; right: 6px; top: 50%; transform: translateY(-50%); height: 26px; padding: 0 8px;
  border: 0; border-radius: 6px; background: #eef3f2; color: #496861; font-size: 11.5px; font-weight: 700; cursor: pointer; }
.ob-name-field { max-width: 420px; }
.ob-name-field .ob-input[readonly] { background: #f3f5f5; color: var(--muted); }
.ob-form-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.ob-form-grid-3 { grid-template-columns: 2fr 1fr 1fr; }
@media(max-width: 640px) { .ob-form-grid, .ob-form-grid-3 { grid-template-columns: 1fr; } .ob-mode-switch { width: 100%; } .ob-mode-btn { flex: 1; } }
.ob-field { display: flex; flex-direction: column; gap: 5px; margin-bottom: 12px; min-width: 0; }
.ob-field[hidden] { display: none !important; }
.ob-field-wide { width: 100%; }
.ob-field > span { font-size: 12px; font-weight: 700; color: #496861; }
.ob-field > em { font-size: 11px; color: var(--muted); font-style: normal; line-height: 1.5; }
.ob-input, .ob-select { height: 38px; padding: 0 12px; border: 1.5px solid var(--line); border-radius: 10px;
  font-size: 13px; background: #fff; color: var(--ink); outline: none; width: 100%; box-sizing: border-box; min-width: 0; }
.ob-input:focus, .ob-select:focus { border-color: var(--accent); box-shadow: 0 0 0 3px rgba(8,127,116,.12); }
.ob-inline-check { display: flex; align-items: center; gap: 8px; font-size: 12.5px; color: #496861; margin-bottom: 12px; cursor: pointer; }
.ob-form-actions { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; margin-top: 4px; }
.ob-form-msg { font-size: 12px; font-weight: 650; }
.ob-form-msg.ok { color: #2c8a4e; }
.ob-form-msg.err { color: #d64545; }
.ob-status { display: block; margin: -6px 0 12px; }
.ob-status:empty { display: none; }

.ob-rules-hint { font-size: 11.5px; color: var(--muted); }
.ob-add-form { display: grid; grid-template-columns: 1fr minmax(140px, 220px) auto; gap: 10px; margin-bottom: 14px; }
@media(max-width: 640px) { .ob-add-form { grid-template-columns: 1fr; } }
.ob-rules-list { display: flex; flex-wrap: wrap; gap: 8px; }
.ob-rule-item { display: inline-flex; align-items: center; gap: 8px; padding: 6px 13px; background: #fff;
  border: 1px solid var(--line); border-radius: 20px; font-size: 12.5px; color: var(--ink); }
.ob-rule-domain { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; }
.ob-rule-target { font-size: 11px; color: var(--muted); font-weight: 600; }
.ob-rule-target::before { content: '→ '; }
.ob-rule-del { color: #d64545; text-decoration: none; font-size: 15px; line-height: 1; font-weight: 800; cursor: pointer; border-radius: 50%; }
.ob-rule-del:hover { color: #a82020; transform: scale(1.15); }
.warp-domain-input { flex: 1; height: 42px; padding: 0 14px; border: 1.5px solid var(--line); border-radius: 10px; font-size: 13px; color: var(--ink); background: #fdfefe; outline: none; transition: all .15s ease; }
.warp-domain-input:focus { border-color: var(--accent); background: #fff; box-shadow: 0 0 0 3px rgba(8, 127, 116, 0.12); }
.warp-add-btn { height: 42px; padding: 0 20px; font-size: 13px; font-weight: 700; border-radius: 10px; background: var(--accent); color: #fff; border: none; cursor: pointer; white-space: nowrap; transition: all .15s ease; }
.warp-add-btn:hover { filter: brightness(0.92); }

.warp-presets-bar { display: flex; align-items: center; gap: 8px; margin-bottom: 18px; flex-wrap: wrap; font-size: 12px; color: var(--muted); }
.warp-preset-chip { display: inline-flex; align-items: center; gap: 4px; background: #f3f7f6; color: #2e554d; border: 1px solid #d4e5e1; border-radius: 14px; padding: 3px 10px; text-decoration: none; font-size: 11.5px; font-weight: 600; transition: all .15s ease; }
.warp-preset-chip:hover { background: #e6f3ef; border-color: var(--accent); color: var(--accent); transform: translateY(-1px); }

.warp-tags-wrap { display: flex; flex-wrap: wrap; gap: 8px; padding: 14px; background: #fafcfb; border: 1px solid var(--line); border-radius: 12px; min-height: 48px; align-items: center; }
.warp-tag-item { display: inline-flex; align-items: center; gap: 6px; background: #ffffff; border: 1.5px solid #cfe0dc; color: #184239; border-radius: 20px; padding: 5px 12px; font-size: 12.5px; font-weight: 650; box-shadow: 0 2px 6px rgba(18, 43, 49, 0.03); transition: all .15s ease; }
.warp-tag-item:hover { border-color: #a8cfc6; box-shadow: 0 3px 8px rgba(18, 43, 49, 0.06); }
.warp-tag-text { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; letter-spacing: -0.01em; }
.warp-tag-del { color: #d64545; text-decoration: none; font-size: 15px; line-height: 1; padding: 0 2px; font-weight: 800; cursor: pointer; border-radius: 50%; }
.warp-tag-del:hover { color: #a82020; transform: scale(1.2); }

/* BBR 拥塞控制模块全局专属高质感样式 */
.bbr-section { margin-top: 24px; border-left: 4px solid var(--accent); }
.bbr-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin-top: 14px; }
@media(max-width: 860px) { .bbr-grid { grid-template-columns: 1fr; } }
.bbr-card { background: #ffffff; border: 1.5px solid var(--line); border-radius: 16px; padding: 20px; display: flex; flex-direction: column; justify-content: space-between; gap: 14px; box-shadow: 0 4px 14px rgba(18, 43, 49, 0.03); transition: all .18s ease; }
.bbr-card:hover { border-color: #a8cfc6; transform: translateY(-2px); box-shadow: 0 6px 20px rgba(18, 43, 49, 0.06); }
.bbr-card-head { display: flex; align-items: center; justify-content: space-between; margin-bottom: 6px; }
.bbr-card-title { font-size: 14.5px; font-weight: 800; color: var(--ink); }
.bbr-card-desc { font-size: 12px; color: var(--muted); margin: 0; line-height: 1.6; }
.bbr-btn { width: 100%; height: 42px; font-size: 13px; font-weight: 750; border-radius: 10px; cursor: pointer; display: inline-flex; align-items: center; justify-content: center; transition: all .15s ease; border: 1px solid transparent; }
.bbr-btn.v1 { background: var(--accent); color: #fff; }
.bbr-btn.v1:hover { filter: brightness(0.92); }
.bbr-btn.v2 { background: #f6ffed; border-color: #b7eb8f; color: #237804; }
.bbr-btn.v2:hover { background: #d9f7be; }
.bbr-btn.v3 { background: #fff0f6; border-color: #ffd6e7; color: #c41d7f; }
.bbr-btn.v3:hover { background: #ffadd2; }
.bbr-btn:disabled { opacity: .45; cursor: not-allowed; filter: grayscale(.6); }

.bbr-info-bar { background: #f8fbfb; border: 1px solid var(--line); border-radius: 14px; padding: 16px 20px; margin-bottom: 18px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; }
.bbr-stat-val { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; color: var(--accent); font-weight: 800; font-size: 14px; }
.bbr-sub-text { font-size: 12px; color: var(--muted); margin-top: 3px; }

/* 证书状态模块（2026-10-09）
   核心目的是让「证书快过期 / 已过期 / 与元数据不一致」在掉线**之前**可见。 */
.cert-section { margin-top: 24px; border-left: 4px solid var(--accent); }
.cert-bar { background: #f8fbfb; border: 1px solid var(--line); border-radius: 14px; padding: 16px 20px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; }
.cert-fields { display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 10px 20px; margin-top: 14px; }
.cert-field-label { font-size: 11.5px; color: var(--muted); margin-bottom: 2px; }
.cert-field-val { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 13px; font-weight: 750; color: var(--ink); word-break: break-all; }
/* 告警条：三档配色与 portal 既有告警一致（黄=注意，橙红=紧急） */
.cert-alert { display: none; margin-top: 14px; border-radius: 12px; padding: 12px 16px; font-size: 12.5px; font-weight: 700; line-height: 1.6; }
.cert-alert.warn { display: block; background: #fffbe6; border: 1px solid #ffe58f; color: #ad6800; }
.cert-alert.critical { display: block; background: #fff1f0; border: 1px solid #ffccc7; color: #a8071a; }
.cert-alert.info { display: block; background: #e6f4ff; border: 1px solid #91caff; color: #0958d9; }
.cert-heal-note { font-size: 11.5px; color: var(--muted); margin-top: 8px; }

/* 全局自定义高颜值确认弹窗与 Toast 样式 */
.confirm-card { width: 100%; max-width: 440px; background: #ffffff; border: 1.5px solid var(--line); border-radius: 20px; padding: 24px; box-shadow: 0 20px 50px rgba(18, 43, 49, 0.22); animation: scaleUp .18s cubic-bezier(0.16, 1, 0.3, 1); }
@keyframes scaleUp { from { opacity: 0; transform: scale(0.94); } to { opacity: 1; transform: scale(1); } }
.confirm-icon-box { width: 48px; height: 48px; border-radius: 14px; background: #eaf5ef; color: var(--accent); display: flex; align-items: center; justify-content: center; font-size: 24px; margin-bottom: 14px; }
.confirm-icon-box.danger { background: #fdf2f2; color: var(--danger); }
.confirm-icon-box.warn { background: #fff8e6; color: #d46b08; }
.confirm-title { font-size: 17px; font-weight: 800; color: var(--ink); margin-bottom: 8px; }
.confirm-text { font-size: 13px; color: var(--muted); line-height: 1.6; margin-bottom: 22px; }
.confirm-actions { display: flex; gap: 10px; justify-content: flex-end; }
.confirm-btn { height: 40px; padding: 0 18px; border-radius: 10px; font-size: 13px; font-weight: 700; cursor: pointer; transition: all .15s ease; border: 1px solid transparent; }
.confirm-btn.cancel { background: #f3f7f6; color: var(--ink); border-color: #d8e5e2; }
.confirm-btn.cancel:hover { background: #e5eeec; }
.confirm-btn.primary { background: var(--accent); color: #fff; }
.confirm-btn.primary:hover { filter: brightness(0.92); }
.confirm-btn.danger { background: var(--danger); color: #fff; }
.confirm-btn.danger:hover { filter: brightness(0.92); }

/* 全局 Toast 通知栏 */
.toast-container { position: fixed; top: 24px; right: 24px; z-index: 99999; display: flex; flex-direction: column; gap: 10px; pointer-events: none; }
.toast-item { background: #122b31; color: #ffffff; border-radius: 12px; padding: 12px 20px; font-size: 13px; font-weight: 650; box-shadow: 0 10px 30px rgba(0,0,0,0.18); display: flex; align-items: center; gap: 10px; pointer-events: auto; animation: toastIn .2s cubic-bezier(0.16, 1, 0.3, 1); }
.toast-item.success { background: #087f74; }
.toast-item.error { background: #cf3c3c; }
@keyframes toastIn { from { opacity: 0; transform: translateY(-10px); } to { opacity: 1; transform: translateY(0); } }

/* ===== AmneziaWG 抗 DPI 协议卡片 ===== */
.awg-card { background: #ffffff; border: 1px solid var(--line); border-radius: 16px; padding: 22px; box-shadow: 0 4px 16px rgba(18, 43, 49, 0.03); }
.awg-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; flex-wrap: wrap; gap: 10px; }
.awg-title-box { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.awg-title { font-size: 15px; font-weight: 800; color: var(--ink); margin: 0; }
.awg-desc { font-size: 12.5px; color: var(--muted); line-height: 1.7; margin: 0 0 14px; }
.awg-meta { display: flex; gap: 10px; flex-wrap: wrap; font-size: 12px; color: var(--muted); margin-bottom: 16px; }
.awg-meta span { background: #f3f7f6; border: 1px solid #d4e5e1; border-radius: 12px; padding: 4px 11px; font-weight: 650; }
/* 核心管理页（2026-10-28） */
.core-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 14px; margin-top: 16px; }
.core-card { border: 1px solid var(--line); border-radius: 14px; padding: 16px 18px; background: #fff; display: flex; flex-direction: column; gap: 10px; }
.core-head { display: flex; justify-content: space-between; align-items: center; gap: 10px; }
.core-name { font-size: 15px; font-weight: 800; color: var(--ink); }
.core-meta { font-size: 12px; color: var(--muted); line-height: 1.7; }
.core-meta b { color: var(--ink); font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-weight: 700; }
.core-note { font-size: 11.5px; color: var(--muted); background: #f8fbfb; border-radius: 8px; padding: 6px 10px; }
.core-actions { display: flex; gap: 8px; flex-wrap: wrap; margin-top: auto; }
.core-actions .button { padding: 6px 14px; font-size: 12px; }
.core-empty { color: var(--muted); font-size: 13px; padding: 12px 0; }
.awg-install-box { background: #f8fbfa; border: 1px solid #d9ebe6; border-radius: 14px; padding: 16px 18px; margin-bottom: 18px; }
.awg-label { display: block; font-size: 12px; font-weight: 700; color: var(--muted); margin: 12px 0 5px; }
.awg-label:first-child { margin-top: 0; }
.awg-input, .awg-select { width: 100%; height: 40px; padding: 0 12px; border: 1.5px solid var(--line); border-radius: 10px; font-size: 13px; color: var(--ink); background: #fdfefe; outline: none; box-sizing: border-box; }
.awg-input:focus, .awg-select:focus { border-color: var(--accent); background: #fff; box-shadow: 0 0 0 3px rgba(8, 127, 116, 0.12); }
.awg-warn { font-size: 11.5px; color: #993c1d; background: #faece7; border: 1px solid #f5c4b3; border-radius: 10px; padding: 9px 12px; line-height: 1.6; margin: 12px 0 0; }
.awg-add-form { display: flex; gap: 10px; margin-bottom: 16px; flex-wrap: wrap; }
.awg-add-form .awg-input { flex: 1; min-width: 150px; width: auto; }
.awg-table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
.awg-table th { text-align: left; font-size: 11.5px; color: var(--muted); font-weight: 700; padding: 8px 10px; border-bottom: 1px solid var(--line); white-space: nowrap; }
.awg-table td { padding: 10px; border-bottom: 1px solid #f0f4f3; color: var(--ink); vertical-align: middle; }
.awg-foot { display: flex; gap: 10px; margin-top: 16px; flex-wrap: wrap; }
.awg-hint { font-size: 11.5px; color: var(--muted); margin: 10px 0 0; line-height: 1.6; }
@media(max-width: 600px) { .awg-add-form { flex-direction: column; } .awg-add-form .awg-input { width: 100%; } }



"""

# ============================================================================
# SCRIPT
# ============================================================================
SCRIPT = r"""

// 全局高颜值 Promise 确认框与 Toast 机制
function showToast(msg, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) { alert(msg); return; }
  const toast = document.createElement('div');
  toast.className = 'toast-item ' + type;
  const icon = type === 'success' ? '✓ ' : (type === 'error' ? '✕ ' : 'ℹ ');
  toast.textContent = icon + msg;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.transition = 'all .25s ease';
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(-8px)';
    setTimeout(() => toast.remove(), 250);
  }, 2800);
}

let confirmOpen = false;
function showConfirm(options = {}) {
  // 弹窗已经打开时忽略新的请求（返回 false）。
  // 旧实现每次调用都往同一组按钮上再加一对监听：连续两次提交会让
  // 一次「确定」同时 resolve 两个 Promise，同一个操作被执行两遍
  // （2026-10-29 修）。
  if (confirmOpen) return Promise.resolve(false);

  const modal = document.getElementById('custom-confirm-modal');
  const titleEl = document.getElementById('confirm-title');
  const textEl = document.getElementById('confirm-text');
  const iconEl = document.getElementById('confirm-icon');
  const okBtn = document.getElementById('confirm-btn-ok');
  const cancelBtn = document.getElementById('confirm-btn-cancel');

  if (!modal || !titleEl || !textEl || !okBtn || !cancelBtn) {
    return Promise.resolve(confirm(options.text || '确定执行吗？'));
  }

  titleEl.textContent = options.title || '操作确认';
  textEl.textContent = options.text || '确定要继续执行吗？';
  if (iconEl) {
    iconEl.textContent = options.icon || '💡';
    iconEl.className = 'confirm-icon-box ' + (options.isDanger ? 'danger' : (options.isWarn ? 'warn' : ''));
  }
  okBtn.textContent = options.confirmText || '确定执行';
  okBtn.className = 'confirm-btn ' + (options.isDanger ? 'danger' : 'primary');
  modal.classList.add('show');
  confirmOpen = true;

  return new Promise((resolve) => {
    function cleanup(result) {
      modal.classList.remove('show');
      okBtn.removeEventListener('click', onOk);
      cancelBtn.removeEventListener('click', onCancel);
      document.removeEventListener('keydown', onKey);
      modal.removeEventListener('click', onBackdrop);
      confirmOpen = false;
      resolve(result);
    }
    function onOk() { cleanup(true); }
    function onCancel() { cleanup(false); }
    // Esc 关闭：纯键盘用户此前只能用 Tab 逐个跳到按钮。
    function onKey(e) { if (e.key === 'Escape') cleanup(false); }
    // 点背板关闭：与用户弹窗行为一致（此前确认弹窗只能点按钮）。
    function onBackdrop(e) { if (e.target === modal) cleanup(false); }
    okBtn.addEventListener('click', onOk);
    cancelBtn.addEventListener('click', onCancel);
    modal.addEventListener('click', onBackdrop);
    document.addEventListener('keydown', onKey);
  });
}

// 🔴 删除用户的二次确认不能写成内联的 onsubmit="return confirm(...)"：
// CSP 的 script-src 只允许带哈希的脚本、没有 'unsafe-inline'，内联事件处理器
// 会被浏览器直接拒绝 —— 表现为点了「删除」毫无提示、用户被静默删掉。
// 必须在这里用 addEventListener 绑定。
document.querySelectorAll('form.js-confirm-delete').forEach(form => {
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    showConfirm({
      title: '注销用户',
      text: form.dataset.confirm || '确定注销此用户？此操作不可撤销。',
      icon: '⚠️',
      isDanger: true,
      confirmText: '确定注销'
    }).then(ok => { if (ok) form.submit(); });
  });
});

function switchSubtab(paneId, subId) {
  const pane = document.getElementById('pane-' + paneId);
  if (!pane) return;
  pane.querySelectorAll('.subtab-btn').forEach(b => b.classList.remove('active'));
  pane.querySelectorAll('.subtab-pane').forEach(p => p.classList.remove('active'));
  const btn = pane.querySelector('[data-subtab="' + subId + '"]');
  const sub = document.getElementById('sub-' + subId);
  if (btn && sub) {
    btn.classList.add('active');
    sub.classList.add('active');
  }
}

// 顶层标签：默认打开组内第一个子页；也支持 #proxies/awg 这种直达写法。
function switchTab(tabId, subId) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
  const btn = document.querySelector('[data-tab="' + tabId + '"]');
  const pane = document.getElementById('pane-' + tabId);
  if (!btn || !pane) return;
  btn.classList.add('active');
  pane.classList.add('active');
  // 窄屏菜单横滑时，把当前项滚进可见区域（只滚菜单本身，不动页面）。
  const bar = btn.parentElement;
  if (bar && bar.scrollWidth > bar.clientWidth) {
    bar.scrollLeft = btn.offsetLeft - (bar.clientWidth - btn.offsetWidth) / 2;
  }
  const subs = pane.querySelectorAll('.subtab-btn');
  if (subs.length) {
    const wanted = subId && pane.querySelector('[data-subtab="' + subId + '"]');
    // 用实际生效的子页写哈希：传入的 subId 不存在时 switchSubtab 会回退到
    // 第一个子页，旧实现却把不存在的 id 写进 URL，刷新后显示与地址不一致。
    const effective = wanted ? subId : subs[0].dataset.subtab;
    switchSubtab(tabId, effective);
    history.replaceState(null, null, '#' + tabId + '/' + effective);
  } else {
    history.replaceState(null, null, '#' + tabId);
  }
}

document.querySelectorAll('[data-tab]').forEach(btn => {
  btn.addEventListener('click', () => {
    switchTab(btn.dataset.tab);
    // 备用通道页的状态可能在别处（终端、REST API、整机停用）被改过，
    // 每次切回来都重新拉一次，避免显示上次加载时的旧状态。
    if (btn.dataset.tab === 'reality') {
      checkRealityStatus();
      checkVmessStatus();
      checkVlessencStatus();
      checkAnytlsStatus();
      checkTuicStatus();
    }
    if (btn.dataset.tab === 'cores') loadCores();
  });
});

document.querySelectorAll('.subtab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const pane = btn.closest('.tab-pane');
    if (!pane) return;
    const paneId = pane.id.replace(/^pane-/, '');
    switchSubtab(paneId, btn.dataset.subtab);
    // 子页状态同样可能被终端 / REST API / 整机停用改过，切进来时重新拉一次。
    if (btn.dataset.subtab === 'vmess') checkVmessStatus();
    if (btn.dataset.subtab === 'vlessenc') checkVlessencStatus();
    if (btn.dataset.subtab === 'anytls') checkAnytlsStatus();
    if (btn.dataset.subtab === 'tuic') checkTuicStatus();
    if (btn.dataset.subtab === 'reality-node') checkRealityStatus();
    history.replaceState(null, null, '#' + paneId + '/' + btn.dataset.subtab);
  });
});

if (location.hash) {
  const hash = location.hash.substring(1);
  const [tabId, subId] = hash.split('/');
  if (document.getElementById('pane-' + tabId)) {
    switchTab(tabId, subId);
    // 直达链接同样要刷新：否则从书签/外部链接进来时看到的是页面加载瞬间的旧状态。
    if (tabId === 'reality') {
      checkRealityStatus();
      checkVmessStatus();
      checkVlessencStatus();
      // 深链接路径此前漏了 AnyTLS：书签进入时卡片会停在首屏旧状态。
      checkAnytlsStatus();
      checkTuicStatus();
    }
  }
}

function genRandom(targetId, prefix='') {
  const el = document.getElementById(targetId);
  if (!el) return;
  const rand = Array.from(crypto.getRandomValues(new Uint8Array(8))).map(b => b.toString(16).padStart(2, '0')).join('');
  el.value = prefix ? (prefix + '_' + rand.substring(0, 8)) : rand;
}

document.querySelectorAll('[data-gen]').forEach(btn => {
  btn.addEventListener('click', () => {
    genRandom(btn.dataset.gen, btn.dataset.prefix || '');
  });
});

document.querySelectorAll('[data-copy]').forEach(button => {
  button.addEventListener('click', async () => {
    const field = document.getElementById(button.dataset.copy);
    const status = document.getElementById('copy-status');
    try {
      const val = field.value || field.textContent || '';
      await navigator.clipboard.writeText(val);
      if (status) status.textContent = '已复制到剪贴板 ✓';
      button.textContent = '已复制 ✓';
      setTimeout(() => { button.textContent = button.dataset.orig || '复制'; }, 1800);
    } catch (_) {
      if (field.select) { field.focus(); field.select(); }
      if (status) status.textContent = '已选中，请按 Ctrl+C 复制';
    }
  });
});

// 专属连接弹窗逻辑
const uModal = document.getElementById('user-modal');
const uModalTitle = document.getElementById('um-title');
const uModalSub = document.getElementById('um-sub');
const uModalBody = document.getElementById('um-body');
const uModalClose = document.getElementById('um-close');

// WARP 状态与一键安装与自定义分流交互
const warpBadge = document.getElementById('warp-badge');
const btnToggleWarp = document.getElementById('btn-toggle-warp');
const btnInstallWarp = document.getElementById('btn-install-warp');
const warpTagsCloud = document.getElementById('warp-tags-cloud');
const warpRulesCount = document.getElementById('warp-rules-count');
const formAddWarpRule = document.getElementById('form-add-warp-rule');
const inputWarpDomain = document.getElementById('input-warp-domain');
const btnResetWarpRules = document.getElementById('btn-reset-warp-rules');

function renderWarpRules(rules, active = false) {
  if (!warpTagsCloud) return;
  const domains = (rules || []).map(r => typeof r === 'string'
    ? {domain:r, outbound:'warp_socks'} : r).filter(r => r && ['warp','warp_socks'].includes(r.outbound)).map(r => r.domain);
  if (warpRulesCount) warpRulesCount.textContent = domains.length + (active ? ' 个生效中' : ' 个已配置');
  if (!domains.length) {
    warpTagsCloud.innerHTML = '<span style="font-size:12px;color:var(--muted)">暂无 WARP 分流域名</span>';
    return;
  }
  warpTagsCloud.innerHTML = domains.map(d => '<span class="warp-tag-item"><span class="warp-tag-text">'
    + obEsc(d) + '</span><a href="javascript:void(0)" class="warp-tag-del" data-domain="'
    + obEsc(d) + '" title="移除此域名">×</a></span>').join('');
}

// WARP 分流标签的删除按钮：容器级事件委托（标签是动态重渲染的，不能逐个绑定）
if (warpTagsCloud) {
  warpTagsCloud.addEventListener('click', (e) => {
    const del = e.target.closest('.warp-tag-del');
    if (!del) return;
    e.preventDefault();
    const dom = del.getAttribute('data-domain');
    if (dom) delWarpRule(dom);
  });
}

async function addWarpRule(domain) {
  if (!domain) return;
  try {
    const res = await fetch(location.pathname + 'manage-warp', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'action=add_rule&domain=' + encodeURIComponent(domain)
    });
    const json = await res.json();
    if (json.ok) {
      if (inputWarpDomain) inputWarpDomain.value = '';
      if (Array.isArray(json.rules)) renderWarpRules(json.rules);
      // 与删除路径一致：新增后也要刷新状态，「N 个生效中」与徽章才会更新。
      await checkWarpStatus();
    } else {
      alert(json.error || '添加失败');
    }
  } catch (e) {
    alert('请求异常: ' + e.message);
  }
}

async function delWarpRule(domain) {
  if (!confirm('确定将 ' + domain + ' 从 WARP 分流列表中移除吗？')) return;
  try {
    const res = await fetch(location.pathname + 'manage-warp', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'action=del_rule&domain=' + encodeURIComponent(domain)
    });
    const json = await res.json();
    if (!res.ok || !json.ok) throw new Error(json.error || '分流规则应用失败');
    if (Array.isArray(json.rules)) renderWarpRules(json.rules);
    await checkWarpStatus();
  } catch (e) {
    alert('请求异常: ' + e.message);
  }
}

async function checkWarpStatus() {
  if (!warpBadge) return;
  try {
    const res = await fetch(location.pathname + 'warp-status', { credentials: 'same-origin' });
    if (!res.ok) return;
    const json = await res.json();
    if (!json.ok) return;

    if (btnInstallWarp) {
      if (!json.installed) {
        btnInstallWarp.style.display = 'inline-flex';
      } else {
        btnInstallWarp.style.display = 'none';
      }
    }

    if (!json.installed) {
      warpBadge.textContent = '● 未安装 WARP 客户端';
      warpBadge.style.background = '#fff1f0';
      warpBadge.style.color = '#cf3c3c';
      if (btnToggleWarp) btnToggleWarp.style.display = 'none';
      return;
    } else {
      if (btnToggleWarp) btnToggleWarp.style.display = 'inline-flex';
    }

    if (json.enabled) {
      const effective = json.connected && json.applied && !json.overridden;
      warpBadge.textContent = effective
        ? ('● 运行中 (' + (json.ip || '已连通') + ')')
        : (json.overridden ? '● 全局出口优先，WARP 名单分流待命'
           : json.applying ? '● 正在应用分流配置...'
           : (json.connected ? '● WARP通道可用，分流未应用' : '● 正在连接 / 异常'));
      warpBadge.title = json.apply_error || '';
      warpBadge.style.background = effective ? '#eaf3de' : '#fff1f0';
      warpBadge.style.color = effective ? '#27500a' : '#cf3c3c';
      if (btnToggleWarp) {
        btnToggleWarp.textContent = '已开启 (点击关闭)';
        btnToggleWarp.className = 'toggle-btn on';
      }
    } else {
      warpBadge.textContent = '○ 已停用 (直连模式)';
      warpBadge.style.background = '#f1efe8';
      warpBadge.style.color = '#5f5e5a';
      if (btnToggleWarp) {
        btnToggleWarp.textContent = '已关闭 (点击开启)';
        btnToggleWarp.className = 'toggle-btn off';
      }
    }

    if (Array.isArray(json.rules)) {
      renderWarpRules(json.rules, json.enabled && json.applied && !json.overridden);
    }
  } catch (_) {}
}

if (btnToggleWarp) {
  btnToggleWarp.addEventListener('click', async () => {
    btnToggleWarp.disabled = true;
    btnToggleWarp.textContent = '切换中...';
    try {
      const res = await fetch(location.pathname + 'manage-warp', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'action=toggle'
      });
      const json = await res.json();
      if (!json.ok) alert(json.error || '切换失败');
    } catch (e) {
      alert('操作失败: ' + e.message);
    } finally {
      btnToggleWarp.disabled = false;
      await checkWarpStatus();
    }
  });
}

if (btnInstallWarp) {
  btnInstallWarp.addEventListener('click', async () => {
    if (!confirm("确定要在服务器上一键部署 Cloudflare WARP 本地出口吗？将自动安装 wgcf + wireproxy，并启用 127.0.0.1:19898 的 socks5 出口。")) return;
    btnInstallWarp.disabled = true;
    const origText = btnInstallWarp.textContent;
    btnInstallWarp.textContent = '⏳ 正在安装 WARP (耗时约 30 秒)...';
    try {
      const res = await fetch(location.pathname + 'install-warp', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
      });
      if (!res.ok) {
        const errText = await res.text();
        showToast('安装失败 (HTTP ' + res.status + '): ' + errText, 'error');
        return;
      }
      const json = await res.json();
      if (json.ok) {
        showToast(json.message || 'Cloudflare WARP 安装成功！服务已自动就绪。', 'success');
        await checkWarpStatus();
      } else {
        showToast(json.error || '安装失败，请检查网络', 'error');
      }
    } catch (e) {
      showToast('安装请求异常: ' + e.message, 'error');
    } finally {
      btnInstallWarp.disabled = false;
      btnInstallWarp.textContent = origText;
    }
  });
}

if (formAddWarpRule) {
  formAddWarpRule.addEventListener('submit', (e) => {
    e.preventDefault();
    if (inputWarpDomain) addWarpRule(inputWarpDomain.value.trim());
  });
}

document.querySelectorAll('.preset-rule').forEach(el => {
  el.addEventListener('click', () => {
    const dom = el.getAttribute('data-domain');
    if (dom) addWarpRule(dom);
  });
});

if (btnResetWarpRules) {
  btnResetWarpRules.addEventListener('click', async () => {
    if (!confirm('确定重置为系统默认推荐的 AI 域名规则列表吗？')) return;
    try {
      const res = await fetch(location.pathname + 'manage-warp', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'action=reset_rules'
      });
      const json = await res.json();
      if (json.ok && Array.isArray(json.rules)) {
        renderWarpRules(json.rules);
      }
    } catch (e) {
      alert('请求异常: ' + e.message);
    }
  });
}

checkWarpStatus();
setInterval(() => { if (!document.hidden) checkWarpStatus(); }, 10000);

// ============================================================================
// 自定义出站（Custom Outbounds）
// ============================================================================
// 🔴 CSP 的 script-src 只有哈希白名单、没有 'unsafe-inline'，
//    所以任何 onclick="..." 内联事件都会被浏览器丢弃（表现为"按钮点了没反应"）。
//    全部交互统一用 data-* 属性 + 事件委托。
const obEls = {
  formCard: document.getElementById('ob-form-card'),
  quick: document.getElementById('ob-quick'),
  quickBox: document.getElementById('ob-quick-box'),
  quickHint: document.getElementById('ob-quick-hint'),
  nameHint: document.getElementById('ob-name-hint'),
  btnTest: document.getElementById('btn-ob-test'),
  btnClose: document.getElementById('btn-ob-close'),
  btnEye: document.getElementById('btn-ob-pass-eye'),
  status: document.getElementById('ob-status'),
  btnNew: document.getElementById('btn-ob-new'),
  rulesCard: document.getElementById('ob-rules-card'),
  modeNote: document.getElementById('ob-mode-note'),
  btnRules: document.getElementById('btn-ob-mode-rules'),
  btnGlobal: document.getElementById('btn-ob-mode-global'),
  ip: document.getElementById('ob-outbound-ip'),
  ipNote: document.getElementById('ob-outbound-ip-note'),
  probeKind: document.getElementById('ob-probe-kind'),
  probeAddr: document.getElementById('ob-probe-addr'),
  btnProbe: document.getElementById('btn-ob-probe'),
  list: document.getElementById('ob-list'),
  count: document.getElementById('ob-count'),
  formTitle: document.getElementById('ob-form-title'),
  name: document.getElementById('ob-name'),
  type: document.getElementById('ob-type'),
  typeHint: document.getElementById('ob-type-hint'),
  blockSocks: document.getElementById('ob-block-socks5'),
  blockHttp: document.getElementById('ob-block-http'),
  socksAddr: document.getElementById('ob-socks-addr'),
  socksUser: document.getElementById('ob-socks-user'),
  socksPass: document.getElementById('ob-socks-pass'),
  httpUrl: document.getElementById('ob-http-url'),
  httpInsecure: document.getElementById('ob-http-insecure'),
  directMode: document.getElementById('ob-direct-mode'),
  blockDirect: document.getElementById('ob-block-direct'),
  quickBox: document.getElementById('ob-quick-box'),
  btnSave: document.getElementById('btn-ob-save'),
  btnCancel: document.getElementById('btn-ob-cancel'),
  msg: document.getElementById('ob-form-msg'),
  ruleDomain: document.getElementById('ob-rule-domain'),
  ruleOutbound: document.getElementById('ob-rule-outbound'),
  btnRuleAdd: document.getElementById('btn-ob-rule-add'),
  rulesList: document.getElementById('ob-rules-list'),
  rulesCount: document.getElementById('ob-rules-count'),
};

const OB_TYPE_LABEL = {
  socks5: { label: 'SOCKS5', cls: 'ob-type-socks5', hint: '填 host:port，如 1.2.3.4:1080（暂不支持 IPv6 地址）' },
  http: { label: 'HTTP/HTTPS', cls: 'ob-type-http', hint: '填完整地址，如 http://1.2.3.4:8080' },
  direct: { label: '直连', cls: 'ob-type-direct', hint: '走服务器本机网络，可设置 IPv4/IPv6 地址族（一般用于分流规则里的例外）' },
};

// 🔴 密码绝不显示在列表里（门户有被截图的风险），只显示"已设置"
function obMetaOf(o) {
  if (o.type === 'socks5') {
    let s = o.addr || '';
    if (o.username) s += ' · 认证 ' + o.username + ':******';
    else if (o.password) s += ' · 密码已设置';
    return s;
  }
  if (o.type === 'http') return (o.url || '') + (o.insecure ? ' · 跳过证书校验' : '');
  return '服务器本地网络直连' + (o.mode && o.mode !== 'auto' ? ' (mode:' + o.mode + ')' : '');
}

function obEsc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}

function renderOutboundList(outs) {
  if (!obEls.list) return;
  if (obEls.count) obEls.count.textContent = outs.length + ' 个';
  if (!outs.length) {
    obEls.list.innerHTML = '<span class="ob-empty">还没有自定义出站。'
      + '点右上角「＋ 新增出站」添加一个 SOCKS5 / HTTP 代理，再切到「全局出口」即可让所有流量走它。</span>';
    return;
  }
  obEls.list.innerHTML = outs.map((o, idx) => {
    const t = OB_TYPE_LABEL[o.type] || { label: o.type, cls: '' };
    const testAddr = (o.type === 'socks5') ? (o.addr || '') : (o.url || '');
    return '<div class="ob-item">'
      + '<div class="ob-item-main">'
      + '<div class="ob-item-name">' + obEsc(o.name)
      + '<span class="ob-item-type ' + t.cls + '">' + obEsc(t.label) + '</span>'
      + (idx === 0 ? '<span class="ob-item-first" title="全局出口模式下所有流量走这个出站">全局出口</span>' : '')
      + '</div>'
      + '<div class="ob-item-meta">' + obEsc(obMetaOf(o)) + '</div></div>'
      + '<div class="ob-item-actions">'
      + '<button class="ob-mini-btn" data-ob-test="' + obEsc(o.name) + '" data-ob-kind="' + obEsc(o.type)
      + '" data-ob-addr="' + obEsc(testAddr) + '" data-ob-insecure="' + (o.insecure ? 'true' : 'false')
      + '">测出口</button>'
      + '<button class="ob-mini-btn" data-ob-edit="' + obEsc(o.name) + '">编辑</button>'
      + '<button class="ob-mini-btn danger" data-ob-del="' + obEsc(o.name) + '">删除</button>'
      + '</div></div>';
  }).join('');
}

function renderOutboundRules(rules, outs, builtin) {
  if (!obEls.rulesList) return;
  const norm = [];
  (rules || []).forEach(r => {
    norm.push((r && typeof r === 'object')
      ? { domain: r.domain, outbound: r.outbound || 'warp_socks' }
      : { domain: String(r), outbound: 'warp_socks' });
  });
  if (obEls.rulesCount) obEls.rulesCount.textContent = norm.length + ' 条';

  const customNames = new Set((outs || []).map(o => o && o.name).filter(Boolean));
  const builtinTypes = { warp_socks: 'socks5', direct_ipv4: 'direct', warp: 'socks5' };
  const configured = (builtin || []).filter(name => name && !customNames.has(name))
    .map(name => ({ name: name, type: builtinTypes[name] || '' }));
  const all = configured.concat([{ name: 'direct', type: 'direct' }, { name: 'reject', type: '' }], outs || []);
  const seen = {}; const uniq = [];
  all.forEach(o => { if (o && o.name && !seen[o.name]) { seen[o.name] = 1; uniq.push(o); } });

  if (obEls.ruleOutbound) {
    const cur = obEls.ruleOutbound.value;
    obEls.ruleOutbound.innerHTML = uniq.map(o => {
      const t = OB_TYPE_LABEL[o.type];
      return '<option value="' + obEsc(o.name) + '">' + obEsc(o.name)
        + (t ? ' (' + obEsc(t.label) + ')' : '') + '</option>';
    }).join('');
    if (cur) obEls.ruleOutbound.value = cur;
  }

  if (!norm.length) {
    obEls.rulesList.innerHTML = '<span class="ob-empty">暂无分流规则。'
      + '添加后该域名走指定出站，其余流量不受影响。</span>';
    return;
  }
  obEls.rulesList.innerHTML = norm.map(r => {
    return '<span class="ob-rule-item">'
      + '<span class="ob-rule-domain">' + obEsc(r.domain) + '</span>'
      + '<span class="ob-rule-target">' + obEsc(r.outbound) + '</span>'
      + '<a href="javascript:void(0)" class="ob-rule-del" data-rule-del="'
      + obEsc(r.domain) + '" title="移除">×</a></span>';
  }).join('');
}

function obSetModeUI(mode) {
  const isGlobal = mode === 'global';
  if (obEls.rulesCard) obEls.rulesCard.classList.toggle('inactive', isGlobal);
  if (obEls.btnGlobal) obEls.btnGlobal.classList.toggle('active', isGlobal);
  if (obEls.btnRules) obEls.btnRules.classList.toggle('active', !isGlobal);
  if (obEls.modeNote) {
    obEls.modeNote.classList.toggle('global', isGlobal);
    obEls.modeNote.textContent = isGlobal
      ? '全局模式：客户端访问任何网站都从列表里第一个出站出去。列表顺序即优先级。'
      : '按域名分流：名单内域名走指定出站，其余走直连（影响面可控，建议先用这个）。';
  }
}

function obTypeSwitch() {
  const t = obEls.type ? obEls.type.value : 'socks5';
  if (obEls.blockSocks) obEls.blockSocks.hidden = (t !== 'socks5');
  if (obEls.blockHttp) obEls.blockHttp.hidden = (t !== 'http');
  if (obEls.blockDirect) obEls.blockDirect.hidden = (t !== 'direct');
  document.querySelectorAll('[data-ob-type]').forEach(b => {
    const on = b.dataset.obType === t;
    b.classList.toggle('active', on);
    b.setAttribute('aria-checked', on ? 'true' : 'false');
  });
  if (obEls.typeHint) {
    const meta = OB_TYPE_LABEL[t];
    if (meta) obEls.typeHint.textContent = meta.hint;
  }
}

// 表单展开时消息写在表单里（贴着出错的字段）；收起时写在标题栏下的状态行，
// 否则「保存成功」「模式切换中」会写进看不见的表单。
function obMsg(text, kind) {
  const formOpen = obEls.formCard && !obEls.formCard.hidden;
  [obEls.msg, obEls.status].forEach(el => {
    if (!el) return;
    const target = (el === obEls.msg) === !!formOpen;
    el.textContent = target ? (text || '') : '';
    el.className = (el === obEls.msg ? 'ob-form-msg ' : 'ob-form-msg ob-status ') + (target ? (kind || '') : '');
  });
}

// 🔴 端点走<prefix>manage-outbounds（网页会话认证），不是 /api/v1/。
//    出站配置能改流量出口，属管理操作，不能仅凭 api_key 就能动。
async function waitForEgressApply() {
  const deadline = Date.now() + 45000;
  while (Date.now() < deadline) {
    await new Promise(resolve => setTimeout(resolve, 500));
    let json;
    try {
      const res = await fetch(location.pathname + 'outbounds/list', {credentials:'same-origin'});
      if (res.status === 401) throw new Error('登录已失效，请重新登录');
      if (!res.ok) continue;
      json = await res.json();
    } catch (err) {
      if (String(err.message).includes('登录已失效')) throw err;
      continue;
    }
    if (!json.applying) {
      if (!json.applied) throw new Error(json.apply_error || '配置尚未成功加载');
      return json;
    }
  }
  throw new Error('配置状态暂未确认，请刷新查看；不要重复提交同一操作');
}

async function obApi(action, params) {
  const p = Object.assign({ action: action }, params || {});
  const body = new URLSearchParams(p).toString();
  const res = await fetch(location.pathname + 'manage-outbounds', {
    method: 'POST', credentials: 'same-origin',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body,
  });
  let json = {};
  try { json = await res.json(); } catch (_) {}
  if (!res.ok || !json.ok) throw new Error(json.error || ('请求失败 HTTP ' + res.status));
  if (json.applying) json = Object.assign(json, await waitForEgressApply());
  return json;
}

let OB_STATE = { mode: 'rules', outbounds: [], rules: [], builtin: [] };

async function loadOutbounds() {
  if (!obEls.list) return;
  try {
    const res = await fetch(location.pathname + 'outbounds/list',
      { credentials: 'same-origin' });
    if (!res.ok) return;
    const json = await res.json();
    if (!json.ok) return;
    OB_STATE = { mode: json.mode || 'rules', outbounds: json.outbounds || [], rules: json.rules || [], builtin: json.builtin || [] };
    obSetModeUI(OB_STATE.mode);
    renderOutboundList(OB_STATE.outbounds);
    renderOutboundRules(OB_STATE.rules, OB_STATE.outbounds, OB_STATE.builtin);
    if (json.apply_error && !json.applying && !json.applied) obMsg(json.apply_error, 'err');
  } catch (_) {}
}

async function probeOutbound(kind, addr, insecure = false) {
  if (!obEls.ip) return;
  obEls.ip.textContent = '探测中...';
  if (obEls.ipNote) obEls.ipNote.textContent = '只检测所选出站端点的可达性，不代表已配置分流规则的实际出口';
  try {
    const body = new URLSearchParams({ kind: kind || 'direct', addr: addr || '',
      insecure: insecure ? 'true' : '' });
    const res = await fetch(location.pathname + 'outbounds/probe', {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });
    const json = await res.json();
    if (!json.ok) throw new Error(json.error || '探测失败');
    if (json.ip) {
      obEls.ip.textContent = json.ip;
      if (obEls.ipNote) obEls.ipNote.textContent = '探测地址：' + json.ip + '；客户端实际出口仍取决于当前模式与分流规则';
    } else {
      obEls.ip.textContent = '探测失败';
      if (obEls.ipNote) {
        obEls.ipNote.textContent = (kind === 'direct' || kind === 'warp')
          ? '本机无法访问 ipify —— 请检查出站网络连通性'
          : '该出站无法连通 —— 请检查地址、端口与认证信息';
      }
    }
  } catch (e) {
    obEls.ip.textContent = '探测失败';
    if (obEls.ipNote) obEls.ipNote.textContent = String(e.message || e);
  }
}

function obResetForm() {
  if (obEls.name) obEls.name.value = '';
  if (obEls.socksAddr) obEls.socksAddr.value = '';
  if (obEls.socksUser) obEls.socksUser.value = '';
  if (obEls.socksPass) obEls.socksPass.value = '';
  if (obEls.httpUrl) obEls.httpUrl.value = '';
  if (obEls.httpInsecure) obEls.httpInsecure.checked = false;
  if (obEls.directMode) obEls.directMode.value = 'auto';
  if (obEls.formTitle) obEls.formTitle.textContent = '➕ 新增出站';
  if (obEls.formCard) obEls.formCard.hidden = true;
  if (obEls.type) obEls.type.value = 'socks5';
  if (obEls.quick) obEls.quick.value = '';
  if (obEls.quickBox) { obEls.quickBox.hidden = false; obEls.quickBox.className = 'ob-field ob-quick'; }
  if (obEls.quickHint) obEls.quickHint.textContent = OB_QUICK_HINT;
  obNameLock(false);
  obNameAuto = true;
  obShowPass(false);
  obMsg('');
  obTypeSwitch();
}

// ---- 新增出站：快速填写 / 自动命名 / 测连通（2026-10-31）----
const OB_QUICK_HINT = '支持 socks5:// · socks:// · http(s):// 链接，以及代理商常见的 host:port:user:pass 格式';
let obNameAuto = true;   // 用户没手动改过名称时，随地址自动生成

function obNameLock(locked) {
  if (!obEls.name) return;
  obEls.name.readOnly = !!locked;
  if (obEls.nameHint) {
    obEls.nameHint.textContent = locked
      ? '编辑时不能改名；要换名称请删除后重新添加'
      : '字母、数字与下划线，不能以数字开头；分流规则里用它来指定出站';
  }
}

function obShowPass(show) {
  if (!obEls.socksPass || !obEls.btnEye) return;
  obEls.socksPass.type = show ? 'text' : 'password';
  obEls.btnEye.textContent = show ? '隐藏' : '显示';
  obEls.btnEye.setAttribute('aria-label', show ? '隐藏密码' : '显示密码');
}

function obDecode(s) {
  try { return decodeURIComponent(s || ''); } catch (e) { return s || ''; }
}

// 识别常见代理写法；认不出返回 null。只解析、不发请求。
function obParseLink(raw) {
  const s = String(raw || '').trim();
  if (!s) return null;
  let m = s.match(/^(?:socks5h?|socks):\/\/(?:([^:@\/\s]*)(?::([^@\/\s]*))?@)?([^\/:@\s]+):(\d{1,5})\/?(?:[?#].*)?$/i);
  if (m) return { type: 'socks5', host: m[3], addr: m[3] + ':' + m[4], user: obDecode(m[1]), pass: obDecode(m[2]) };
  m = s.match(/^https?:\/\/(?:[^@\/\s]*@)?([^\/:@\s]+)(?::\d{1,5})?\/?$/i);
  if (m) return { type: 'http', host: m[1], url: s.replace(/\/$/, '') };
  m = s.match(/^([^\s:@\/]+):(\d{1,5}):([^\s:]+):(\S+)$/);           // host:port:user:pass
  if (m) return { type: 'socks5', host: m[1], addr: m[1] + ':' + m[2], user: m[3], pass: m[4] };
  m = s.match(/^([^\s:@\/]+):([^\s:@]+)@([^\s:@\/]+):(\d{1,5})$/);   // user:pass@host:port
  if (m) return { type: 'socks5', host: m[3], addr: m[3] + ':' + m[4], user: m[1], pass: m[2] };
  m = s.match(/^([^\s:@\/]+):(\d{1,5})$/);                           // host:port
  if (m) return { type: 'socks5', host: m[1], addr: s, user: '', pass: '' };
  return null;
}

function obSuggestName(type, host) {
  let base = (type === 'http' ? 'http_' : 'socks_') + String(host || '').toLowerCase().replace(/[^a-z0-9]+/g, '_');
  base = base.replace(/_+$/, '').slice(0, 32);
  const taken = new Set(Array.from(document.querySelectorAll('[data-ob-edit]')).map(b => b.dataset.obEdit));
  let name = base, n = 2;
  while (taken.has(name)) name = base.slice(0, 29) + '_' + (n++);
  return name;
}

function obAutoName() {
  if (!obNameAuto || !obEls.name || obEls.name.readOnly) return;
  const t = obEls.type ? obEls.type.value : 'socks5';
  let host = '';
  if (t === 'socks5' && obEls.socksAddr) host = obEls.socksAddr.value.trim().replace(/:\d+$/, '');
  else if (t === 'http' && obEls.httpUrl) {
    const m = obEls.httpUrl.value.trim().match(/^https?:\/\/(?:[^@\/\s]*@)?([^\/:@\s]+)/i);
    host = m ? m[1] : '';
  }
  obEls.name.value = t === 'direct' ? 'direct_local' : (host ? obSuggestName(t, host) : '');
}

function obApplyQuick() {
  if (!obEls.quick) return;
  const raw = obEls.quick.value;
  const r = obParseLink(raw);
  if (!raw.trim()) {
    if (!obEls.quickBox.hidden) {
      obEls.quickBox.className = 'ob-field ob-quick';
      obEls.quickHint.textContent = OB_QUICK_HINT;
    }
    return;
  }
  if (!r) {
    // 清掉上一次识别出的凭据，防止用户换成无效链接后误保存旧代理。
    if (obEls.type) obEls.type.value = 'socks5';
    if (obEls.socksAddr) obEls.socksAddr.value = '';
    if (obEls.socksUser) obEls.socksUser.value = '';
    if (obEls.socksPass) obEls.socksPass.value = '';
    if (obEls.httpUrl) obEls.httpUrl.value = '';
    if (obEls.httpInsecure) obEls.httpInsecure.checked = false;
    obTypeSwitch();
    obAutoName();
    obEls.quickBox.className = 'ob-field ob-quick err';
    obEls.quickHint.textContent = '没认出这个格式，请直接在下方逐项填写';
    return;
  }
  if (obEls.type) obEls.type.value = r.type;
  if (r.type === 'socks5') {
    obEls.socksAddr.value = r.addr;
    obEls.socksUser.value = r.user || '';
    obEls.socksPass.value = r.pass || '';
  } else {
    obEls.httpUrl.value = r.url;
  }
  obTypeSwitch();
  obAutoName();
  obEls.quickBox.className = 'ob-field ob-quick ok';
  obEls.quickHint.textContent = '✓ 已识别为 ' + (r.type === 'http' ? 'HTTP 代理' : 'SOCKS5 代理')
    + (r.user ? '（带认证）' : '') + '，可点「测试连通」确认后再保存';
}

// 用表单当前填写的参数探测出口 IP —— 不保存、不改配置。
async function obTestForm() {
  const t = obEls.type ? obEls.type.value : 'socks5';
  let kind = t, addr = '';
  if (t === 'socks5') {
    const a = obEls.socksAddr.value.trim();
    if (!/^[^\s:]+:\d{1,5}$/.test(a)) { obMsg('SOCKS5 地址格式应为 host:port', 'err'); return; }
    const u = obEls.socksUser.value.trim(), pw = obEls.socksPass.value.trim();
    addr = (u || pw) ? encodeURIComponent(u) + ':' + encodeURIComponent(pw) + '@' + a : a;
  } else if (t === 'http') {
    addr = obEls.httpUrl.value.trim();
    if (!/^https?:\/\/\S+$/i.test(addr)) { obMsg('HTTP 代理地址应以 http:// 或 https:// 开头', 'err'); return; }
  } else {
    kind = 'direct';
  }
  obEls.btnTest.disabled = true;
  obMsg('测试中...', '');
  try {
    const body = new URLSearchParams({ kind: kind, addr: addr,
      insecure: (kind === 'http' && obEls.httpInsecure && obEls.httpInsecure.checked) ? 'true' : '' });
    const res = await fetch(location.pathname + 'outbounds/probe', {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });
    const json = await res.json();
    if (!json.ok) throw new Error(json.error || '测试失败');
    if (json.ip) obMsg('✓ 连通，出口 IP：' + json.ip, 'ok');
    else obMsg('✗ 连不通：请检查地址、端口与认证信息', 'err');
  } catch (e) {
    obMsg('测试失败：' + (e.message || e), 'err');
  } finally {
    obEls.btnTest.disabled = false;
  }
}

document.querySelectorAll('[data-ob-type]').forEach(b => {
  b.addEventListener('click', () => {
    if (obEls.type) obEls.type.value = b.dataset.obType;
    obTypeSwitch();
    obAutoName();
  });
});
if (obEls.quick) {
  obEls.quick.addEventListener('input', obApplyQuick);
  obEls.quick.addEventListener('paste', () => setTimeout(obApplyQuick, 0));
}
[obEls.socksAddr, obEls.httpUrl].forEach(el => { if (el) el.addEventListener('input', obAutoName); });
if (obEls.name) obEls.name.addEventListener('input', () => { obNameAuto = !obEls.name.value.trim(); });
if (obEls.btnEye) obEls.btnEye.addEventListener('click', () => obShowPass(obEls.socksPass.type === 'password'));
if (obEls.btnTest) obEls.btnTest.addEventListener('click', obTestForm);
if (obEls.btnClose) obEls.btnClose.addEventListener('click', () => obResetForm());
if (obEls.formCard) {
  // 表单里按回车 = 保存（快速填写框除外：回车只是确认识别）。
  obEls.formCard.addEventListener('keydown', e => {
    if (e.key !== 'Enter' || e.isComposing || e.target === obEls.quick || e.target.tagName !== 'INPUT') return;
    e.preventDefault();
    if (obEls.btnSave && !obEls.btnSave.disabled) obEls.btnSave.click();
  });
}

// 表单默认收起：点「新增」或「编辑」才展开，并滚到可见处。
function obOpenForm() {
  if (!obEls.formCard) return;
  obEls.formCard.hidden = false;
  obEls.formCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  const first = (obEls.quickBox && !obEls.quickBox.hidden) ? obEls.quick : obEls.socksAddr;
  if (first) first.focus({ preventScroll: true });
}

if (obEls.btnNew) {
  obEls.btnNew.addEventListener('click', () => { obResetForm(); obOpenForm(); });
}

function obFillForm(o) {
  if (!o) return;
  if (obEls.name) obEls.name.value = o.name;
  if (obEls.type) obEls.type.value = o.type;
  if (obEls.socksAddr) obEls.socksAddr.value = o.addr || '';
  if (obEls.socksUser) obEls.socksUser.value = o.username || '';
  if (obEls.socksPass) obEls.socksPass.value = o.password || '';
  if (obEls.httpUrl) obEls.httpUrl.value = o.url || '';
  if (obEls.httpInsecure) obEls.httpInsecure.checked = !!o.insecure;
  if (obEls.directMode) obEls.directMode.value = o.mode || 'auto';
  if (obEls.formTitle) obEls.formTitle.textContent = '✏️ 编辑出站：' + o.name;
  // 编辑时名称锁定：保存按名称覆盖，改名会变成「新增一条 + 旧的还在」。
  obNameLock(true);
  obNameAuto = false;
  if (obEls.quickBox) obEls.quickBox.hidden = true;
  obTypeSwitch();
  obOpenForm();
}

async function setOutboundMode(mode) {
  try {
    obMsg('切换中，正在重启服务...', '');
    const result = await obApi('mode', { mode: mode });
    mode = result.mode || mode;
    obSetModeUI(mode);
    obMsg('已切换到' + (mode === 'global' ? '全局出口' : '按域名分流') + ' ✓', 'ok');
    await loadOutbounds();
  } catch (e) {
    obMsg('切换失败：' + (e.message || e), 'err');
  }
}

// --- 事件绑定（全部 data-* + 委托，无内联 onclick）---
if (obEls.type) obEls.type.addEventListener('change', obTypeSwitch);
if (obEls.btnCancel) obEls.btnCancel.addEventListener('click', () => obResetForm());

if (obEls.btnSave) {
  obEls.btnSave.addEventListener('click', async () => {
    obMsg('保存中，正在重启服务生效...', '');
    obEls.btnSave.disabled = true;
    try {
      const t = obEls.type ? obEls.type.value : 'socks5';
      await obApi('save', {
        name: obEls.name ? obEls.name.value.trim() : '',
        type: t,
        addr: obEls.socksAddr ? obEls.socksAddr.value.trim() : '',
        url: obEls.httpUrl ? obEls.httpUrl.value.trim() : '',
        username: obEls.socksUser ? obEls.socksUser.value : '',
        password: obEls.socksPass ? obEls.socksPass.value : '',
        insecure: (obEls.httpInsecure && obEls.httpInsecure.checked) ? 'true' : '',
        mode: t === 'direct' && obEls.directMode ? obEls.directMode.value : '',
      });
      obResetForm();
      obMsg('已保存并生效 ✓', 'ok');
      await loadOutbounds();
    } catch (e) {
      // 🔴 失败必须原样显示原因 —— 服务可能已被回滚，用户需要知道
      obMsg('保存失败：' + (e.message || e), 'err');
    } finally {
      obEls.btnSave.disabled = false;
    }
  });
}

if (obEls.list) {
  obEls.list.addEventListener('click', async (e) => {
    const del = e.target.closest('[data-ob-del]');
    const edit = e.target.closest('[data-ob-edit]');
    const test = e.target.closest('[data-ob-test]');
    if (del) {
      e.preventDefault();
      const name = del.getAttribute('data-ob-del');
      if (!window.confirm('确认删除出站「' + name + '」？\n引用它的分流规则也会一并移除。')) return;
      try {
        await obApi('delete', { name: name });
        await loadOutbounds();
        obMsg('已删除「' + name + '」', 'ok');
      } catch (err) {
        obMsg('删除失败：' + (err.message || err), 'err');
      }
    } else if (edit) {
      e.preventDefault();
      const name = edit.getAttribute('data-ob-edit');
      const found = OB_STATE.outbounds.find(x => x.name === name);
      obFillForm(found);
      window.scrollTo({ top: obEls.list.offsetTop - 120, behavior: 'smooth' });
    } else if (test) {
      e.preventDefault();
      const kind = test.getAttribute('data-ob-kind');
      const addr = test.getAttribute('data-ob-addr') || '';
      const insecure = test.getAttribute('data-ob-insecure') === 'true';
      if (obEls.probeKind) obEls.probeKind.value = kind;
      if (obEls.probeAddr) {
        obEls.probeAddr.value = addr;
        obEls.probeAddr.hidden = (kind !== 'socks5' && kind !== 'http');
      }
      await probeOutbound(kind, addr, insecure);
      window.scrollTo({ top: obEls.ip.offsetTop - 200, behavior: 'smooth' });
    }
  });
}

if (obEls.rulesList) {
  obEls.rulesList.addEventListener('click', async (e) => {
    const del = e.target.closest('[data-rule-del]');
    if (!del) return;
    e.preventDefault();
    const dom = del.getAttribute('data-rule-del');
    try {
      await obApi('rule-del', { domain: dom });
      await loadOutbounds();
    } catch (err) {
      obMsg('删除规则失败：' + (err.message || err), 'err');
    }
  });
}

if (obEls.btnRuleAdd) {
  obEls.btnRuleAdd.addEventListener('click', async () => {
    const dom = obEls.ruleDomain ? obEls.ruleDomain.value.trim() : '';
    const tgt = obEls.ruleOutbound ? obEls.ruleOutbound.value : 'warp_socks';
    if (!dom) { obMsg('请填写域名', 'err'); return; }
    try {
      await obApi('rule-add', { domain: dom, outbound: tgt });
      if (obEls.ruleDomain) obEls.ruleDomain.value = '';
      await loadOutbounds();
      obMsg('规则已添加 ✓', 'ok');
    } catch (e) {
      obMsg('添加规则失败：' + (e.message || e), 'err');
    }
  });
}

if (obEls.btnRules) obEls.btnRules.addEventListener('click', () => setOutboundMode('rules'));
if (obEls.btnGlobal) obEls.btnGlobal.addEventListener('click', () => setOutboundMode('global'));

if (obEls.btnProbe) {
  obEls.btnProbe.addEventListener('click', () => {
    probeOutbound(obEls.probeKind ? obEls.probeKind.value : 'direct',
      obEls.probeAddr ? obEls.probeAddr.value.trim() : '', false);
  });
}
if (obEls.probeKind) {
  obEls.probeKind.addEventListener('change', () => {
    if (!obEls.probeAddr) return;
    const k = obEls.probeKind.value;
    obEls.probeAddr.hidden = (k !== 'socks5' && k !== 'http');
    obEls.probeAddr.placeholder = (k === 'http') ? 'http://1.2.3.4:8080' : '1.2.3.4:1080';
  });
}

loadOutbounds();
probeOutbound('direct', '');
obTypeSwitch();

// VLESS-Reality 客户端与状态交互
const realityBadge = document.getElementById('reality-badge');
const btnInstallXray = document.getElementById('btn-install-xray');
const btnToggleReality = document.getElementById('btn-toggle-reality');
const realityContentBox = document.getElementById('reality-content-box');
const realityUriVal = document.getElementById('reality-uri-val');
const realityQrBox = document.getElementById('reality-qr-box');
const realitySniVal = document.getElementById('reality-sni-val');
const realityUuidVal = document.getElementById('reality-uuid-val');
const realityPubkeyVal = document.getElementById('reality-pubkey-val');
const realityFlowVal = document.getElementById('reality-flow-val');
const btnCopyRealityUri = document.getElementById('btn-copy-reality-uri');
const btnResetRealityKeys = document.getElementById('btn-reset-reality-keys');

async function checkRealityStatus() {
  if (!realityBadge) return;
  try {
    const res = await fetch(location.pathname + 'reality-status', { credentials: 'same-origin' });
    if (!res.ok) return;
    const json = await res.json();
    if (!json.ok) return;
    const portTag = document.getElementById('reality-port-tag');
    if (portTag) portTag.textContent = 'TCP ' + (json.config?.port || '--');

    if (!json.installed) {
      realityBadge.textContent = '● 未安装 Xray 核心';
      realityBadge.style.background = '#fff1f0';
      realityBadge.style.color = '#cf3c3c';
      if (btnInstallXray) btnInstallXray.style.display = 'inline-flex';
      if (btnToggleReality) btnToggleReality.style.display = 'none';
      if (realityContentBox) realityContentBox.style.display = 'none';
      return;
    }

    if (btnInstallXray) btnInstallXray.style.display = 'none';
    if (btnToggleReality) btnToggleReality.style.display = 'inline-flex';

    if (json.active) {
      // 端口来自实际配置，不能写死 443：Reality 会自动避让到 8443 等空闲端口。
      realityBadge.textContent = '● 运行中 (TCP ' + (json.config?.port || '--') + ' 端口)';
      realityBadge.style.background = '#eaf3de';
      realityBadge.style.color = '#27500a';
      btnToggleReality.textContent = '已开启 (点击关闭)';
      btnToggleReality.className = 'toggle-btn on';
      if (realityContentBox) realityContentBox.style.display = 'block';
    } else {
      realityBadge.textContent = '○ 已停止';
      realityBadge.style.background = '#f1efe8';
      realityBadge.style.color = '#5f5e5a';
      btnToggleReality.textContent = '已关闭 (点击开启)';
      btnToggleReality.className = 'toggle-btn off';
      if (realityContentBox) realityContentBox.style.display = 'none';
    }

    if (json.config) {
      const cfg = json.config;
      if (realityUriVal) realityUriVal.value = cfg.uri || '';
      if (realityQrBox && cfg.qr_svg) realityQrBox.innerHTML = cfg.qr_svg;
      if (realitySniVal) realitySniVal.textContent = (cfg.sni || 'www.apple.com') + ':' + (cfg.port || 443);
      if (realityUuidVal) realityUuidVal.textContent = cfg.uuid || '-';
      if (realityPubkeyVal) realityPubkeyVal.textContent = cfg.pub_key || '-';
      if (realityFlowVal) realityFlowVal.textContent = (cfg.short_id || '') + ' · ' + (cfg.flow || 'xtls-rprx-vision');
    }
  } catch (_) {}
}

if (btnToggleReality) {
  btnToggleReality.addEventListener('click', async () => {
    btnToggleReality.disabled = true;
    btnToggleReality.textContent = '切换中...';
    try {
      const res = await fetch(location.pathname + 'manage-reality', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'action=toggle'
      });
      const json = await res.json();
      if (!json.ok) alert(json.error || '切换失败');
      await checkRealityStatus();
    } catch (e) {
      alert('请求异常: ' + e.message);
    } finally {
      btnToggleReality.disabled = false;
    }
  });
}

if (btnResetRealityKeys) {
  btnResetRealityKeys.addEventListener('click', async () => {
    if (!confirm("确定要重新生成 UUID 与 Reality 密钥对吗？旧客户端连接凭据将失效。")) return;
    try {
      const res = await fetch(location.pathname + 'manage-reality', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'action=reset'
      });
      const json = await res.json();
      if (json.ok) {
        alert('密钥与 UUID 已重新生成并生效！');
        await checkRealityStatus();
      } else {
        alert(json.error || '重置失败');
      }
    } catch (e) {
      alert('请求异常: ' + e.message);
    }
  });
}


// 复制到剪贴板：统一处理失败。
// navigator.clipboard 在非 HTTPS、权限被拒、旧浏览器下会 reject；
// 旧实现只有 .then 没有 .catch，失败时按钮毫无反应，看起来像点坏了。
// 失败时退回「选中文本」并提示手动复制（与页面通用 [data-copy] 处理器一致）。
function copyWithFeedback(text, button, doneText) {
  const orig = button.textContent;
  const ok = () => {
    button.textContent = doneText;
    setTimeout(() => { button.textContent = orig; }, 1500);
  };
  const fallback = () => {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    let copied = false;
    try { copied = document.execCommand('copy'); } catch (_) { copied = false; }
    ta.remove();
    if (copied) ok();
    else alert('复制失败，请手动选中后复制');
  };
  if (!navigator.clipboard || !navigator.clipboard.writeText) { fallback(); return; }
  navigator.clipboard.writeText(text).then(ok).catch(fallback);
}

if (btnCopyRealityUri) {
  btnCopyRealityUri.addEventListener('click', () => {
    if (realityUriVal && realityUriVal.value) {
      copyWithFeedback(realityUriVal.value, btnCopyRealityUri, '✓ 已复制直链');
    }
  });
}

checkRealityStatus();

// VMess-WS-TLS 卡片：与 Reality 分开显示，状态以「入站是否真的存在」为准。
const vmessBadge = document.getElementById('vmess-badge');
const btnToggleVmess = document.getElementById('btn-toggle-vmess');
const vmessContentBox = document.getElementById('vmess-content-box');
const vmessUriVal = document.getElementById('vmess-uri-val');
const vmessQrBox = document.getElementById('vmess-qr-box');
const vmessDomainVal = document.getElementById('vmess-domain-val');
const vmessUuidVal = document.getElementById('vmess-uuid-val');
const vmessPathVal = document.getElementById('vmess-path-val');
const btnCopyVmessUri = document.getElementById('btn-copy-vmess-uri');

// 请求序号：切换标签/子页会并发触发多次状态查询，旧响应晚到时
// 会把新状态覆盖回旧值（实测会出现徽章闪回「已关闭」）。
let vmessStatusSeq = 0;
async function checkVmessStatus() {
  if (!vmessBadge) return;
  const seq = ++vmessStatusSeq;
  try {
    const res = await fetch(location.pathname + 'vmess-status', { credentials: 'same-origin' });
    if (!res.ok) { if (seq === vmessStatusSeq) vmessBadge.textContent = '● 状态未知（请求失败）'; return; }
    const json = await res.json();
    if (seq !== vmessStatusSeq) return;   // 已有更新的请求，丢弃本次结果
    if (!json.ok) return;
    if (!json.installed) {
      // 没有 Xray 核心时不能显示「已关闭」—— 那会让人以为点一下就能开。
      vmessBadge.textContent = '● 未安装 Xray 核心';
      const gotoVmess = document.getElementById('vmess-goto-cores');
      if (gotoVmess) gotoVmess.style.display = 'inline-flex';
      vmessBadge.style.background = '#fff1f0';
      vmessBadge.style.color = '#cf3c3c';
      if (btnToggleVmess) btnToggleVmess.style.display = 'none';
      if (vmessContentBox) vmessContentBox.style.display = 'none';
      return;
    }
    if (btnToggleVmess) btnToggleVmess.style.display = 'inline-flex';
    const gotoVmessOk = document.getElementById('vmess-goto-cores');
    if (gotoVmessOk) gotoVmessOk.style.display = 'none';
    if (json.active) {
      vmessBadge.textContent = '● 运行中 (TCP ' + (json.config.port || '--') + ')';
      vmessBadge.style.background = '#eaf3de';
      vmessBadge.style.color = '#27500a';
      btnToggleVmess.textContent = '已开启 (点击关闭)';
      btnToggleVmess.className = 'toggle-btn on';
      if (vmessContentBox) vmessContentBox.style.display = 'block';
      const cfg = json.config || {};
      if (vmessUriVal) vmessUriVal.value = cfg.uri || '';
      if (vmessQrBox) vmessQrBox.innerHTML = cfg.qr_svg || '';
      if (vmessDomainVal) vmessDomainVal.textContent = (cfg.domain || '-') + (cfg.sni && cfg.sni !== cfg.domain ? ' / ' + cfg.sni : '');
      if (vmessUuidVal) vmessUuidVal.textContent = cfg.uuid || '-';
      if (vmessPathVal) vmessPathVal.textContent = cfg.ws_path || '-';
      const portTag = document.getElementById('vmess-port-tag');
      if (portTag) portTag.textContent = 'TCP ' + (cfg.port || '--');
    } else {
      vmessBadge.textContent = '○ 已关闭';
      vmessBadge.style.background = '#f1efe8';
      vmessBadge.style.color = '#5f5e5a';
      btnToggleVmess.textContent = '已关闭 (点击开启)';
      btnToggleVmess.className = 'toggle-btn off';
      if (vmessContentBox) vmessContentBox.style.display = 'none';
    }
  } catch (_) {}
}

if (btnToggleVmess) {
  btnToggleVmess.addEventListener('click', async () => {
    // 双击防护：请求未返回前直接忽略后续点击。
    // 否则两次 toggle 会一开一关，最终状态与用户预期相反。
    if (btnToggleVmess.disabled) return;
    btnToggleVmess.disabled = true;
    btnToggleVmess.textContent = '切换中...';
    try {
      const res = await fetch(location.pathname + 'manage-vmess', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'action=toggle'
      });
      // 先看 HTTP 状态：反向代理出错时返回的是 HTML 错误页，
      // 直接 res.json() 会抛「Unexpected token <」，把真实原因盖掉。
      let json = null;
      try { json = await res.json(); } catch (_) { json = null; }
      if (!res.ok || !json || !json.ok) {
        alert((json && json.error) || ('切换失败（HTTP ' + res.status + '）'));
      }
      // 只有成功时才刷新；失败保留原状态，避免把错误状态画到界面上。
      await checkVmessStatus();
    } catch (e) {
      alert('请求异常: ' + e.message);
    } finally {
      // 只恢复 disabled —— 文案由 checkVmessStatus() 按真实状态决定。
      // 旧实现在这里写回 orig，会把「已开启 (点击关闭)」又改回「已关闭」。
      btnToggleVmess.disabled = false;
    }
  });
}

if (btnCopyVmessUri) {
  btnCopyVmessUri.addEventListener('click', () => {
    if (vmessUriVal && vmessUriVal.value) {
      copyWithFeedback(vmessUriVal.value, btnCopyVmessUri, '✓ 已复制直链');
    }
  });
}

checkVmessStatus();

// VLESS Encryption 卡片：与 VMess / Reality 各自独立一个开关。
const vlessencBadge = document.getElementById('vlessenc-badge');
const btnToggleVlessenc = document.getElementById('btn-toggle-vlessenc');
const vlessencContentBox = document.getElementById('vlessenc-content-box');
const vlessencUriVal = document.getElementById('vlessenc-uri-val');
const vlessencQrBox = document.getElementById('vlessenc-qr-box');
const vlessencDomainVal = document.getElementById('vlessenc-domain-val');
const vlessencUuidVal = document.getElementById('vlessenc-uuid-val');
const vlessencTcpVal = document.getElementById('vlessenc-tcp-val');
const btnCopyVlessencUri = document.getElementById('btn-copy-vlessenc-uri');

let vlessencStatusSeq = 0;
async function checkVlessencStatus() {
  if (!vlessencBadge) return;
  const seq = ++vlessencStatusSeq;
  try {
    const res = await fetch(location.pathname + 'vlessenc-status', { credentials: 'same-origin' });
    if (!res.ok) { if (seq === vlessencStatusSeq) vlessencBadge.textContent = '● 状态未知（请求失败）'; return; }
    const json = await res.json();
    if (seq !== vlessencStatusSeq) return;
    if (!json.ok) return;
    if (!json.installed) {
      vlessencBadge.textContent = '● 未安装 Xray 核心';
      const gotoVlessenc = document.getElementById('vlessenc-goto-cores');
      if (gotoVlessenc) gotoVlessenc.style.display = 'inline-flex';
      vlessencBadge.style.background = '#fff1f0';
      vlessencBadge.style.color = '#cf3c3c';
      if (btnToggleVlessenc) btnToggleVlessenc.style.display = 'none';
      if (vlessencContentBox) vlessencContentBox.style.display = 'none';
      return;
    }
    if (btnToggleVlessenc) btnToggleVlessenc.style.display = 'inline-flex';
    const gotoVlessencOk = document.getElementById('vlessenc-goto-cores');
    if (gotoVlessencOk) gotoVlessencOk.style.display = 'none';
    if (json.active) {
      vlessencBadge.textContent = '● 运行中 (TCP ' + (json.config.port || '--') + ')';
      vlessencBadge.style.background = '#eaf3de';
      vlessencBadge.style.color = '#27500a';
      btnToggleVlessenc.textContent = '已开启 (点击关闭)';
      btnToggleVlessenc.className = 'toggle-btn on';
      if (vlessencContentBox) vlessencContentBox.style.display = 'block';
      const cfg = json.config || {};
      if (vlessencUriVal) vlessencUriVal.value = cfg.uri || '';
      if (vlessencQrBox) vlessencQrBox.innerHTML = cfg.qr_svg || '';
      if (vlessencDomainVal) vlessencDomainVal.textContent = (cfg.domain || '-') + (cfg.sni && cfg.sni !== cfg.domain ? ' / ' + cfg.sni : '');
      if (vlessencUuidVal) vlessencUuidVal.textContent = cfg.uuid || '-';
      if (vlessencTcpVal) vlessencTcpVal.textContent = 'TCP ' + (cfg.port || '--');
      const portTag = document.getElementById('vlessenc-port-tag');
      if (portTag) portTag.textContent = 'TCP ' + (cfg.port || '--');
    } else {
      vlessencBadge.textContent = '○ 已关闭';
      vlessencBadge.style.background = '#f1efe8';
      vlessencBadge.style.color = '#5f5e5a';
      btnToggleVlessenc.textContent = '已关闭 (点击开启)';
      btnToggleVlessenc.className = 'toggle-btn off';
      if (vlessencContentBox) vlessencContentBox.style.display = 'none';
    }
  } catch (_) {}
}

if (btnToggleVlessenc) {
  btnToggleVlessenc.addEventListener('click', async () => {
    if (btnToggleVlessenc.disabled) return;
    btnToggleVlessenc.disabled = true;
    btnToggleVlessenc.textContent = '切换中...';
    try {
      const res = await fetch(location.pathname + 'manage-vlessenc', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'action=toggle'
      });
      let json = null;
      try { json = await res.json(); } catch (_) { json = null; }
      if (!res.ok || !json || !json.ok) {
        alert((json && json.error) || ('切换失败（HTTP ' + res.status + '）'));
      }
      await checkVlessencStatus();
    } catch (e) {
      alert('请求异常: ' + e.message);
    } finally {
      btnToggleVlessenc.disabled = false;
    }
  });
}

if (btnCopyVlessencUri) {
  btnCopyVlessencUri.addEventListener('click', () => {
    if (vlessencUriVal && vlessencUriVal.value) {
      copyWithFeedback(vlessencUriVal.value, btnCopyVlessencUri, '✓ 已复制直链');
    }
  });
}

checkVlessencStatus();

// AnyTLS 卡片：由独立的 sing-box 承载，开关与 Xray 系协议互不影响。
const anytlsBadge = document.getElementById('anytls-badge');
const btnToggleAnytls = document.getElementById('btn-toggle-anytls');
const anytlsContentBox = document.getElementById('anytls-content-box');
const anytlsUriVal = document.getElementById('anytls-uri-val');
const btnCopyAnytlsUri = document.getElementById('btn-copy-anytls-uri');

function setAnytlsBadge(text, bg, color) {
  anytlsBadge.textContent = text;
  anytlsBadge.style.background = bg;
  anytlsBadge.style.color = color;
}

let anytlsStatusSeq = 0;
async function checkAnytlsStatus() {
  if (!anytlsBadge) return;
  const seq = ++anytlsStatusSeq;
  try {
    const res = await fetch(location.pathname + 'anytls-status', { credentials: 'same-origin' });
    if (!res.ok) { if (seq === anytlsStatusSeq) anytlsBadge.textContent = '● 状态未知（请求失败）'; return; }
    const json = await res.json();
    if (seq !== anytlsStatusSeq || !json.ok) return;
    const gotoAnytls = document.getElementById('anytls-goto-cores');
    if (!json.installed) {
      setAnytlsBadge('● 未安装 sing-box 核心', '#fff1f0', '#cf3c3c');
      if (btnToggleAnytls) btnToggleAnytls.style.display = 'none';
      if (gotoAnytls) gotoAnytls.style.display = 'inline-flex';
      if (anytlsContentBox) anytlsContentBox.style.display = 'none';
      return;
    }
    if (gotoAnytls) gotoAnytls.style.display = 'none';
    if (btnToggleAnytls) btnToggleAnytls.style.display = 'inline-flex';
    const verEl = document.getElementById('anytls-ver-val');
    if (verEl) verEl.textContent = json.version || '未安装';
    const cfg = json.config || {};
    if (json.active) {
      setAnytlsBadge('● 运行中 (TCP ' + (cfg.port || '--') + ')', '#eaf3de', '#27500a');
      btnToggleAnytls.textContent = '已开启 (点击关闭)';
      btnToggleAnytls.className = 'toggle-btn on';
      if (anytlsContentBox) anytlsContentBox.style.display = 'block';
      if (anytlsUriVal) anytlsUriVal.value = cfg.uri || '';
      const qrBox = document.getElementById('anytls-qr-box');
      if (qrBox) qrBox.innerHTML = cfg.qr_svg || '';
      const domainEl = document.getElementById('anytls-domain-val');
      if (domainEl) domainEl.textContent = (cfg.domain || '-') + (cfg.sni && cfg.sni !== cfg.domain ? ' / ' + cfg.sni : '');
      const tcpEl = document.getElementById('anytls-tcp-val');
      if (tcpEl) tcpEl.textContent = 'TCP ' + (cfg.port || '--');
      const portTag = document.getElementById('anytls-port-tag');
      if (portTag) portTag.textContent = 'TCP ' + (cfg.port || '--');
    } else {
      if (json.enabled) setAnytlsBadge('● 已启用但服务未运行', '#fff1f0', '#cf3c3c');
      else setAnytlsBadge('○ 已关闭', '#f1efe8', '#5f5e5a');
      btnToggleAnytls.textContent = json.enabled ? '已启用 (点击关闭)' : '已关闭 (点击开启)';
      btnToggleAnytls.className = json.enabled ? 'toggle-btn on' : 'toggle-btn off';
      if (anytlsContentBox) anytlsContentBox.style.display = 'none';
    }
  } catch (_) {}
}

if (btnToggleAnytls) {
  btnToggleAnytls.addEventListener('click', async () => {
    if (btnToggleAnytls.disabled) return;
    btnToggleAnytls.disabled = true;
    btnToggleAnytls.textContent = '切换中...';
    try {
      const res = await fetch(location.pathname + 'manage-anytls', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'action=toggle'
      });
      let json = null;
      try { json = await res.json(); } catch (_) { json = null; }
      if (!res.ok || !json || !json.ok) {
        alert((json && json.error) || ('切换失败（HTTP ' + res.status + '）'));
      }
      await checkAnytlsStatus();
    } catch (e) {
      alert('请求异常: ' + e.message);
    } finally {
      btnToggleAnytls.disabled = false;
    }
  });
}

if (btnCopyAnytlsUri) {
  btnCopyAnytlsUri.addEventListener('click', () => {
    if (anytlsUriVal && anytlsUriVal.value) {
      copyWithFeedback(anytlsUriVal.value, btnCopyAnytlsUri, '✓ 已复制直链');
    }
  });
}

checkAnytlsStatus();

// TUIC 卡片：由独立的 sing-box（hy2-tuic）承载，开关与 AnyTLS / Xray 系协议互不影响。
const tuicBadge = document.getElementById('tuic-badge');
const btnToggleTuic = document.getElementById('btn-toggle-tuic');
const tuicContentBox = document.getElementById('tuic-content-box');
const tuicUriVal = document.getElementById('tuic-uri-val');
const btnCopyTuicUri = document.getElementById('btn-copy-tuic-uri');

function setTuicBadge(text, bg, color) {
  tuicBadge.textContent = text;
  tuicBadge.style.background = bg;
  tuicBadge.style.color = color;
}

let tuicStatusSeq = 0;
async function checkTuicStatus() {
  if (!tuicBadge) return;
  const seq = ++tuicStatusSeq;
  try {
    const res = await fetch(location.pathname + 'tuic-status', { credentials: 'same-origin' });
    if (!res.ok) { if (seq === tuicStatusSeq) tuicBadge.textContent = '● 状态未知（请求失败）'; return; }
    const json = await res.json();
    if (seq !== tuicStatusSeq || !json.ok) return;
    const gotoTuic = document.getElementById('tuic-goto-cores');
    if (!json.installed) {
      setTuicBadge('● 未安装 sing-box 核心', '#fff1f0', '#cf3c3c');
      if (btnToggleTuic) btnToggleTuic.style.display = 'none';
      if (gotoTuic) gotoTuic.style.display = 'inline-flex';
      if (tuicContentBox) tuicContentBox.style.display = 'none';
      return;
    }
    if (gotoTuic) gotoTuic.style.display = 'none';
    if (btnToggleTuic) btnToggleTuic.style.display = 'inline-flex';
    const verEl = document.getElementById('tuic-ver-val');
    if (verEl) verEl.textContent = json.version || '未安装';
    const cfg = json.config || {};
    if (json.active) {
      setTuicBadge('● 运行中 (UDP ' + (cfg.port || '--') + ')', '#eaf3de', '#27500a');
      btnToggleTuic.textContent = '已开启 (点击关闭)';
      btnToggleTuic.className = 'toggle-btn on';
      if (tuicContentBox) tuicContentBox.style.display = 'block';
      if (tuicUriVal) tuicUriVal.value = cfg.uri || '';
      const qrBox = document.getElementById('tuic-qr-box');
      if (qrBox) qrBox.innerHTML = cfg.qr_svg || '';
      const domainEl = document.getElementById('tuic-domain-val');
      if (domainEl) domainEl.textContent = (cfg.domain || '-') + (cfg.sni && cfg.sni !== cfg.domain ? ' / ' + cfg.sni : '');
      const tcpEl = document.getElementById('tuic-tcp-val');
      if (tcpEl) tcpEl.textContent = 'UDP ' + (cfg.port || '--');
      const portTag = document.getElementById('tuic-port-tag');
      if (portTag) portTag.textContent = 'UDP ' + (cfg.port || '--');
    } else {
      if (json.enabled) setTuicBadge('● 已启用但服务未运行', '#fff1f0', '#cf3c3c');
      else setTuicBadge('○ 已关闭', '#f1efe8', '#5f5e5a');
      btnToggleTuic.textContent = json.enabled ? '已启用 (点击关闭)' : '已关闭 (点击开启)';
      btnToggleTuic.className = json.enabled ? 'toggle-btn on' : 'toggle-btn off';
      if (tuicContentBox) tuicContentBox.style.display = 'none';
    }
  } catch (_) {}
}

if (btnToggleTuic) {
  btnToggleTuic.addEventListener('click', async () => {
    if (btnToggleTuic.disabled) return;
    btnToggleTuic.disabled = true;
    btnToggleTuic.textContent = '切换中...';
    try {
      const res = await fetch(location.pathname + 'manage-tuic', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'action=toggle'
      });
      let json = null;
      try { json = await res.json(); } catch (_) { json = null; }
      if (!res.ok || !json || !json.ok) {
        alert((json && json.error) || ('切换失败（HTTP ' + res.status + '）'));
      }
      await checkTuicStatus();
    } catch (e) {
      alert('请求异常: ' + e.message);
    } finally {
      btnToggleTuic.disabled = false;
    }
  });
}

if (btnCopyTuicUri) {
  btnCopyTuicUri.addEventListener('click', () => {
    if (tuicUriVal && tuicUriVal.value) {
      copyWithFeedback(tuicUriVal.value, btnCopyTuicUri, '✓ 已复制直链');
    }
  });
}

checkTuicStatus();

// BBR 状态获取与一键切换交互
const bbrBadge = document.getElementById('bbr-badge');
const bbrCurrentText = document.getElementById('bbr-current-text');
const bbrQdiscText = document.getElementById('bbr-qdisc-text');
const bbrKernelText = document.getElementById('bbr-kernel-text');
const bbrRebootTip = document.getElementById('bbr-reboot-tip');
const btnRebootServer = document.getElementById('btn-reboot-server');

async function checkBbrStatus() {
  if (!bbrBadge) return;
  try {
    const res = await fetch(location.pathname + 'bbr-status', { credentials: 'same-origin' });
    if (!res.ok) return;
    const json = await res.json();
    if (!json.ok) return;

    if (Array.isArray(json.available)) document.querySelectorAll('.btn-apply-bbr').forEach(btn => {
      const algo = {v1:'bbr',v2:'bbr2',v3:'bbr3'}[btn.dataset.version];
      btn.disabled = !json.available.includes(algo);
      btn.title = btn.disabled ? '当前内核未提供该算法，需要先使用支持它的内核' : '';
    });
    if (bbrCurrentText) bbrCurrentText.textContent = json.current || 'cubic';
    if (bbrQdiscText) bbrQdiscText.textContent = json.qdisc || 'fq_codel';
    if (bbrKernelText) bbrKernelText.textContent = json.kernel || '--';

    const isBbrActive = (json.current && json.current.includes('bbr'));
    if (bbrBadge) {
      if (isBbrActive) {
        bbrBadge.textContent = '● 已开启 ' + json.current.toUpperCase();
        bbrBadge.style.background = '#eaf3de';
        bbrBadge.style.color = '#27500a';
      } else {
        bbrBadge.textContent = '○ 未开启 BBR (' + json.current + ')';
        bbrBadge.style.background = '#f1efe8';
        bbrBadge.style.color = '#5f5e5a';
      }
    }

    if (bbrRebootTip && btnRebootServer) {
      if (json.need_reboot) {
        bbrRebootTip.style.display = 'block';
        bbrRebootTip.textContent = '⚠️ 已成功配置 ' + json.configured.toUpperCase() + '，需要重启服务器后生效！';
        btnRebootServer.style.display = 'inline-flex';
      } else {
        bbrRebootTip.style.display = 'none';
        btnRebootServer.style.display = 'none';
      }
    }
  } catch (_) {}
}

// ---------------------------------------------------------------------------
// 证书状态 + 到期告警（2026-10-09）
//
// 为什么要把「还剩几天到期」摆到界面上：证书过期是「昨天还好好的、今天突然
// 连不上」这类故障里最高频的真凶，而自动自愈只对齐信任模型、**不会去续期证书**。
// 不显示剩余天数，过期就永远只能在掉线之后才发现。
// ---------------------------------------------------------------------------
const certBadge = document.getElementById('cert-badge');
const certAlert = document.getElementById('cert-alert');
const certRenewalNote = document.getElementById('cert-renewal-note');

function certSetField(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = (value === undefined || value === null || value === '') ? '--' : String(value);
}

function certShortIssuer(issuer) {
  if (!issuer) return '--';
  // "CN=Fake Root CA, O=..., C=US" -> 只留 CN，界面上更清爽
  const m = issuer.match(/CN=([^,]+)/);
  return m ? m[1] : issuer;
}

async function checkCertStatus() {
  if (!certBadge) return;
  let json;
  try {
    const res = await fetch(location.pathname + 'cert-status', { credentials: 'same-origin' });
    if (!res.ok) return;
    json = await res.json();
  } catch (_) { return; }

  certSetField('cert-cn', json.common_name);
  // 后端正常返回数组，但数据被改坏/版本不一致时可能是字符串或 null。
  // 直接 .join 会抛 TypeError，把整张证书卡片（含到期告警）一起废掉，
  // 而这张卡片恰恰是排查「证书过期」的唯一入口（2026-10-30 修）。
  const sansList = Array.isArray(json.sans) ? json.sans
                 : (typeof json.sans === 'string' && json.sans ? [json.sans] : []);
  certSetField('cert-sans', sansList.length ? sansList.join(', ') : '--');
  certSetField('cert-issuer', certShortIssuer(json.issuer));
  certSetField('cert-type', json.self_signed ? '自签名证书' : (json.cert_type === 'acme' ? "Let's Encrypt (ACME)" : '正式证书'));
  certSetField('cert-notafter', json.not_after || '--');
  if (certRenewalNote) {
    if (!json.ok) {
      certRenewalNote.textContent = '续期状态暂时无法确认：当前证书不可读取，请先修复证书文件。';
    } else if (json.self_signed || json.is_insecure) {
      certRenewalNote.textContent = '当前为自签名证书：不会自动续期；到期前请重新生成并更新客户端配置。';
    } else if (json.cert_type === 'acme' && json.renewal_managed) {
      certRenewalNote.textContent = '当前由 Hysteria 内置 ACME 管理：系统会在到期前自动尝试续期。请留意下方有效期与告警，确保域名解析和证书验证条件正常。';
    } else {
      certRenewalNote.textContent = '当前使用外部或手动配置的正式证书：是否自动续期取决于签发工具（如 Caddy / acme.sh）的续期任务，请确认任务正常运行。';
    }
  }
  certSetField('cert-servername', json.server_name || '--');
  certSetField('cert-pin', json.is_insecure ? (json.pin_sha256 ? json.pin_sha256.slice(0, 16) + '…' : '未设置') : '不需要（可信链）');

  const days = json.expires_in_days;
  certSetField('cert-daysleft', (days === null || days === undefined) ? '--' : days);

  // 到期倒计时徽章
  if (!json.ok) {
    certBadge.textContent = '⚠️ 证书不可读';
    certBadge.style.background = '#fff1f0';
    certBadge.style.color = '#a8071a';
  } else if (json.expired) {
    certBadge.textContent = '🔴 已过期 ' + Math.abs(days) + ' 天';
    certBadge.style.background = '#fff1f0';
    certBadge.style.color = '#a8071a';
  } else if (json.warn_level === 'critical') {
    certBadge.textContent = '🔴 仅剩 ' + days + ' 天到期';
    certBadge.style.background = '#fff1f0';
    certBadge.style.color = '#a8071a';
  } else if (json.warn_level === 'warn') {
    certBadge.textContent = '🟡 ' + days + ' 天后到期';
    certBadge.style.background = '#fffbe6';
    certBadge.style.color = '#ad6800';
  } else if (json.warn_level === 'unknown' || days === null || days === undefined) {
    // ⚠️ 必须单列一支：判级 unknown = 到期时间**读不出来**。
    // 若让它落进下面的 else，会显示成「● 正常 · null 天后到期」——
    // 一块绿色的安慰性假象，恰好毁掉这张卡片唯一的存在理由。
    certBadge.textContent = '⚠️ 到期时间未知';
    certBadge.style.background = '#fffbe6';
    certBadge.style.color = '#ad6800';
  } else {
    certBadge.textContent = '● 正常 · ' + days + ' 天后到期';
    certBadge.style.background = '#eaf5ef';
    certBadge.style.color = 'var(--accent)';
  }

  // 告警条：过期 / 临期 / 元数据不一致，三种情况分开说清楚该做什么
  if (certAlert) {
    certAlert.className = 'cert-alert';
    let msg = '';
    if (!json.ok) {
      certAlert.classList.add('critical');
      msg = '🔴 无法读取证书（' + (json.cert_path || '未知路径') + '）。请检查证书文件是否被误删或权限异常。';
    } else if (json.expired) {
      certAlert.classList.add('critical');
      msg = '🔴 证书已于 ' + json.not_after + ' 过期，客户端会直接握手失败。请立即续期（ACME 会自动续；自签名需重跑安装生成）。';
    } else if (json.warn_level === 'critical') {
      certAlert.classList.add('critical');
      msg = '🔴 证书只剩 ' + days + ' 天到期（' + json.not_after + '）。请立刻确认续期链路是否正常，避免随时掉线。';
    } else if (json.warn_level === 'warn') {
      certAlert.classList.add('warn');
      msg = '🟡 证书将在 ' + days + ' 天后到期（' + json.not_after + '）。若使用的是外部签发工具（Caddy / acme.sh），请确认其续期定时任务正常。';
    } else if (json.warn_level === 'unknown' || days === null || days === undefined) {
      certAlert.classList.add('warn');
      msg = '⚠️ 证书到期时间读不出来（解析失败），无法判断临期风险。请手动执行：openssl x509 -enddate -noout -in ' + (json.cert_path || '/etc/hysteria/cert/fullchain.pem') + ' 核对到期时刻。';
    } else if (json.meta_matches_cert === false) {
      certAlert.classList.add('info');
      msg = 'ℹ️ 证书与节点记录存在偏差：订阅使用的 SNI 是「' + (json.server_name || '空') +
            '」，而证书实际覆盖「' + (json.live_server_name || '空') + '」。自动自愈会在换证后自动对齐；若持续出现请检查自愈单元。';
    }
    if (msg) { certAlert.textContent = msg; certAlert.style.display = 'block'; }
    else { certAlert.style.display = 'none'; }
  }

  // 上次自动对齐时间：让「静默发生过什么」变可见
  const healNote = document.getElementById('cert-heal-note');
  if (healNote) {
    if (json.healed_at) {
      const t = new Date((json.healed_at || 0) * 1000);
      const p = n => String(n).padStart(2, '0');
      healNote.textContent = '最近一次自动对齐：' + t.getFullYear() + '-' + p(t.getMonth() + 1) + '-' + p(t.getDate()) +
        ' ' + p(t.getHours()) + ':' + p(t.getMinutes()) + '（累计 ' + (json.heal_count || 0) + ' 次）';
      healNote.style.display = 'block';
    } else {
      healNote.textContent = '尚未发生过自动对齐（证书与节点记录始终一致）';
      healNote.style.display = 'block';
    }
  }
}

document.querySelectorAll('.btn-apply-bbr').forEach(btn => {
  btn.addEventListener('click', async () => {
    const ver = btn.getAttribute('data-version') || 'v1';
    const label = { v1: 'BBR V1 (经典官方)', v2: 'BBR V2 (低丢包)', v3: 'BBR V3 (极限吞吐)' }[ver];
    const confirmed = await showConfirm({
      title: '开启 ' + label + ' 加速引擎',
      text: '系统将自动将拥塞控制与排队规则写入 Linux 内核持久化配置（/etc/sysctl.d/99-bbr.conf）。配置后可能需要安全重启服务器以完成生效。',
      icon: '🚀',
      confirmText: '立即开启 ' + ver.toUpperCase()
    });
    if (!confirmed) return;

    btn.disabled = true;
    const orig = btn.textContent;
    btn.textContent = '正在配置...';
    try {
      const res = await fetch(location.pathname + 'set-bbr', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'version=' + encodeURIComponent(ver)
      });
      const json = await res.json();
      if (json.ok) {
        showToast(json.message || '配置成功！', 'success');
        await checkBbrStatus();
      } else {
        showToast(json.error || '配置失败', 'error');
      }
    } catch (e) {
      alert('请求异常: ' + e.message);
    } finally {
      btn.disabled = false;
      btn.textContent = orig;
    }
  });
});

if (btnRebootServer) {
  btnRebootServer.addEventListener('click', async () => {
    const confirmed = await showConfirm({
      title: '安全重启服务器',
      text: '确定要立即重启服务器以完成新 BBR 内核网络参数生效吗？服务器将在 10 秒内安全完成重启，页面将自动发起 25 秒倒计时并在就绪后重连。',
      icon: '🔄',
      confirmText: '确定立即重启',
      isWarn: true
    });
    if (!confirmed) return;
    btnRebootServer.disabled = true;
    btnRebootServer.textContent = '⏳ 重启指令已发送...';
    try {
      const res = await fetch(location.pathname + 'reboot-server', {
        method: 'POST',
        credentials: 'same-origin'
      });
      alert("服务器正在重启中，系统将在 25 秒后自动刷新页面！");
      let countdown = 25;
      const timer = setInterval(() => {
        countdown--;
        btnRebootServer.textContent = '正在重启中 (' + countdown + 's)...';
        if (countdown <= 0) {
          clearInterval(timer);
          location.reload();
        }
      }, 1000);
    } catch (e) {
      alert("重启请求已发出: " + e.message);
    }
  });
}

// 多用户表：搜索 / 状态筛选 / 分页。用户上百时整表直出会把页面拉得极长，
// 「操作」列也被挤出视口；这里只在客户端切显隐，不改动行内的按钮与表单。
(function initUserTable() {
  const tbody = document.getElementById('user-tbody');
  if (!tbody) return;
  const rows = Array.from(tbody.querySelectorAll('tr[data-user-row]'));
  const search = document.getElementById('user-search');
  const filter = document.getElementById('user-filter');
  const countEl = document.getElementById('user-count');
  const pager = document.getElementById('user-pager');
  const PAGE_SIZE = 20;
  let page = 1;

  function render() {
    const q = (search && search.value || '').trim().toLowerCase();
    const st = filter ? filter.value : 'all';
    const matched = rows.filter(r => (st === 'all' || r.dataset.state === st) && (!q || r.dataset.search.includes(q)));
    const pages = Math.max(1, Math.ceil(matched.length / PAGE_SIZE));
    if (page > pages) page = pages;
    const start = (page - 1) * PAGE_SIZE;
    const visible = new Set(matched.slice(start, start + PAGE_SIZE));
    rows.forEach(r => { r.style.display = visible.has(r) ? '' : 'none'; });
    if (countEl) countEl.textContent = '共 ' + rows.length + ' 个用户 · 匹配 ' + matched.length + ' 个';
    if (!pager) return;
    pager.textContent = '';
    if (pages <= 1) return;
    const btn = (label, target, opts = {}) => {
      const b = document.createElement('button');
      b.type = 'button';
      b.textContent = label;
      if (opts.active) b.className = 'active';
      b.disabled = !!opts.disabled;
      b.addEventListener('click', () => { page = target; render(); });
      pager.appendChild(b);
    };
    btn('‹', page - 1, { disabled: page === 1 });
    for (let i = 1; i <= pages; i++) {
      if (i === 1 || i === pages || Math.abs(i - page) <= 2) btn(String(i), i, { active: i === page });
      else if (Math.abs(i - page) === 3) {
        const s = document.createElement('span'); s.className = 'pager-info'; s.textContent = '…'; pager.appendChild(s);
      }
    }
    btn('›', page + 1, { disabled: page === pages });
  }

  if (search) search.addEventListener('input', () => { page = 1; render(); });
  if (filter) filter.addEventListener('change', () => { page = 1; render(); });
  render();
})();

checkBbrStatus();
checkCertStatus();

// ---------------------------------------------------------------------------
// 核心管理页（2026-10-28）：核心集中安装与查看，协议页只做启停。
// ---------------------------------------------------------------------------
const coreGrid = document.getElementById('core-grid');
const CORE_STATE_TEXT = {
  active: ['● 运行中', '#eaf3de', '#27500a'],
  inactive: ['○ 未运行', '#f1efe8', '#5f5e5a'],
  failed: ['● 运行失败', '#fff1f0', '#cf3c3c'],
  activating: ['● 启动中', '#fffbe6', '#ad6800'],
  none: ['○ 无服务', '#f1efe8', '#5f5e5a'],
};

function coreEl(tag, cls, text) {
  const el = document.createElement(tag);
  if (cls) el.className = cls;
  if (text !== undefined) el.textContent = text;
  return el;
}

function renderCore(core) {
  const card = coreEl('div', 'core-card');
  const head = coreEl('div', 'core-head');
  head.appendChild(coreEl('div', 'core-name', core.name));
  const pill = coreEl('span', 'status-pill');
  if (core.installed) {
    const st = CORE_STATE_TEXT[core.state] || ['● ' + core.state, '#f1efe8', '#5f5e5a'];
    pill.textContent = '已安装 · ' + st[0];
    pill.style.background = st[1];
    pill.style.color = st[2];
  } else {
    pill.textContent = '未安装';
    pill.style.background = '#fff1f0';
    pill.style.color = '#cf3c3c';
  }
  head.appendChild(pill);
  card.appendChild(head);

  const meta = coreEl('div', 'core-meta');
  const line = (label, value) => {
    const row = coreEl('div');
    row.appendChild(document.createTextNode(label + '：'));
    row.appendChild(coreEl('b', '', value));
    meta.appendChild(row);
  };
  line('版本', core.installed ? core.version : '—');
  line('服务', core.service);
  line('用于', (core.used_by || []).join('、'));
  card.appendChild(meta);
  if (core.note) card.appendChild(coreEl('div', 'core-note', core.note));

  const actions = coreEl('div', 'core-actions');
  if (core.installable) {
    const btn = coreEl('button', 'button primary', core.installed ? '重新安装 / 修复' : '⚡ 安装');
    btn.type = 'button';
    btn.addEventListener('click', () => installCore(core, btn));
    actions.appendChild(btn);
    if (core.installed) {
      const del = coreEl('button', 'button danger', '卸载');
      del.type = 'button';
      del.addEventListener('click', () => uninstallCore(core, del));
      actions.appendChild(del);
    }
  }
  if (core.manage) {
    const go = coreEl('button', 'button', core.installable ? '前往使用' : (core.installed ? '前往管理' : '前往安装'));
    go.type = 'button';
    go.addEventListener('click', () => gotoTarget(core.manage));
    actions.appendChild(go);
  }
  card.appendChild(actions);
  return card;
}

let coresSeq = 0;
async function loadCores() {
  if (!coreGrid) return;
  const seq = ++coresSeq;
  try {
    const res = await fetch(location.pathname + 'cores-status', { credentials: 'same-origin' });
    const json = await res.json();
    if (seq !== coresSeq) return;
    if (!res.ok || !json.ok) throw new Error(json.error || ('HTTP ' + res.status));
    coreGrid.textContent = '';
    // 后端异常时 cores 可能不是数组（错误对象/undefined），直接 forEach 会
    // 抛出未处理的 rejection，核心卡片停在「读取中」且没有提示。
    const cores = Array.isArray(json.cores) ? json.cores : [];
    if (!cores.length) throw new Error('节点没有返回任何核心信息');
    cores.forEach(core => coreGrid.appendChild(renderCore(core)));
  } catch (e) {
    if (seq === coresSeq) coreGrid.replaceChildren(coreEl('div', 'core-empty', '读取核心状态失败：' + e.message));
  }
}

async function installCore(core, btn) {
  const confirmed = await showConfirm({
    title: (core.installed ? '重新安装 ' : '安装 ') + core.name,
    text: '将从官方 Release 下载并校验 SHA256 后安装，只安装核心程序，不会自动开启任何协议。可能需要一两分钟。',
    icon: '🧱',
    confirmText: '开始安装'
  });
  if (!confirmed) return;
  btn.disabled = true;
  const orig = btn.textContent;
  btn.textContent = '⏳ 正在下载并校验...';
  try {
    const res = await fetch(location.pathname + 'install-core', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'name=' + encodeURIComponent(core.id)
    });
    let json = null;
    try { json = await res.json(); } catch (_) { json = null; }
    if (json && json.ok) showToast(json.message || '安装完成', 'success');
    else alert((json && json.error) || ('安装失败（HTTP ' + res.status + '）'));
  } catch (e) {
    alert('请求异常: ' + e.message);
  } finally {
    btn.disabled = false;
    btn.textContent = orig;
    await loadCores();
  }
}

async function uninstallCore(core, btn) {
  const confirmed = await showConfirm({
    title: '卸载 ' + core.name,
    text: '将停止并删除 ' + core.name + ' 程序与 systemd 服务。若还有协议在使用它会被拒绝，请先到协议页关闭。协议的配置会保留，重新安装后再开启即可沿用。',
    icon: '🗑️',
    confirmText: '确定卸载',
    isDanger: true
  });
  if (!confirmed) return;
  btn.disabled = true;
  btn.textContent = '⏳ 正在卸载...';
  try {
    const res = await fetch(location.pathname + 'uninstall-core', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'name=' + encodeURIComponent(core.id)
    });
    let json = null;
    try { json = await res.json(); } catch (_) { json = null; }
    if (json && json.ok) showToast(json.message || '已卸载', 'success');
    else alert((json && json.error) || ('卸载失败（HTTP ' + res.status + '）'));
  } catch (e) {
    alert('请求异常: ' + e.message);
  } finally {
    await loadCores();
  }
}

function gotoTarget(target) {
  const [tabId, subId] = String(target).split('/');
  switchTab(tabId, subId);
  if (tabId === 'cores') loadCores();
  if (tabId === 'reality') {
    checkRealityStatus();
    checkVmessStatus();
    checkVlessencStatus();
    checkAnytlsStatus();
    checkTuicStatus();
  }
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

document.querySelectorAll('.js-goto').forEach(btn => {
  btn.addEventListener('click', () => gotoTarget(btn.dataset.goto));
});
const btnRefreshCores = document.getElementById('btn-refresh-cores');
if (btnRefreshCores) btnRefreshCores.addEventListener('click', loadCores);
if (location.hash.startsWith('#cores')) loadCores();


// 版本检测与一键更新交互
const coreVerDisplay = document.getElementById('core-ver-display');
const portalVerDisplay = document.getElementById('portal-ver-display');
const awgVerDisplay = document.getElementById('awg-ver-display');
const btnUpdateCore = document.getElementById('btn-update-core');
const btnUpdatePortal = document.getElementById('btn-update-portal');
const btnUpdateAwgEngine = document.getElementById('btn-update-awg-engine');
const updateStatusMsg = document.getElementById('update-status-msg');
const btnRecheckUpdate = document.getElementById('btn-recheck-update');

// 版本展示：区分「未安装 / 拿不到远端 / 有新版本 / 最新」四种情况，
// 避免拿不到远端时误报「最新」。
function fmtVer(current, latest, hasUpdate, installed) {
  if (installed === false) return '未安装';
  if (!current || current === '未安装') return '未安装';
  if (hasUpdate) return current + ' → ' + (latest || '新版本（部分文件尚未完成比对）') + ' 有新版本';
  if (!latest) return current + '（远端未取到，无法比对）';
  return current + '（最新）';
}

async function checkVersions(force = false) {
  if (!coreVerDisplay || !portalVerDisplay) return;
  try {
    const res = await fetch(location.pathname + 'check-version' + (force ? '?force=1' : ''), { credentials: 'same-origin' });
    if (!res.ok) return false;
    const json = await res.json();
    if (!json.ok) return false;

    // 核心展示
    coreVerDisplay.textContent = fmtVer(json.core_current, json.core_latest, json.core_has_update, true);
    if (btnUpdateCore) {
      btnUpdateCore.style.display = json.core_has_update ? 'inline-flex' : 'none';
      btnUpdateCore.onclick = () => doUpgrade('core');
    }

    // 面板展示
    portalVerDisplay.textContent = json.portal_update_status === 'unknown'
      ? json.portal_current + '（整包检测不完整，无法确认是否最新）'
      : fmtVer(json.portal_current, json.portal_latest, json.portal_has_update, true);
    if (btnUpdatePortal) {
      btnUpdatePortal.style.display = json.portal_has_update ? 'inline-flex' : 'none';
      btnUpdatePortal.onclick = () => doUpgrade('portal');
    }

    // AmneziaWG 引擎展示
    if (awgVerDisplay) {
      awgVerDisplay.textContent = fmtVer(json.awg_current, json.awg_latest, json.awg_has_update, json.awg_installed);
      if (btnUpdateAwgEngine) {
        btnUpdateAwgEngine.style.display = json.awg_has_update ? 'inline-flex' : 'none';
        btnUpdateAwgEngine.onclick = () => doUpgrade('awg');
      }
    }
    return true;
  } catch (_) { return false; }
}

async function waitForCoreUpgrade() {
  const deadline = Date.now() + 300000;
  while (Date.now() < deadline) {
    await new Promise(resolve => setTimeout(resolve, 2000));
    let state;
    try {
      const res = await fetch(location.pathname + 'upgrade-status', {credentials:'same-origin'});
      if (!res.ok) continue;
      state = (await res.json()).job || {};
    } catch (_) { continue; }
    if (state.state === 'completed') return;
    if (state.state === 'failed' || state.state === 'interrupted') throw new Error(state.error || '核心更新失败');
  }
  throw new Error('更新任务尚未确认完成，请刷新查看版本状态');
}

async function doUpgrade(target) {
  const names = { core: 'Hysteria 2 官方核心', portal: '控制面板自身', awg: 'AmneziaWG 引擎' };
  const btns = { core: btnUpdateCore, portal: btnUpdatePortal, awg: btnUpdateAwgEngine };
  const btn = btns[target];
  const custom = target === 'core' && coreVerDisplay?.textContent.includes('+');
  if (!confirm('确定要升级 ' + (names[target] || target) + ' 吗？' + (custom ? '\\n当前含定制补丁，升级官方核心会替换补丁。' : ''))) return;
  if (btn) { btn.disabled = true; btn.textContent = '升级中...'; }
  if (updateStatusMsg) updateStatusMsg.textContent = '正在下载并应用更新，请稍候...';
  try {
    const res = await fetch(location.pathname + 'do-upgrade', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'target=' + encodeURIComponent(target) + (custom ? '&allow_custom=1' : '')
    });
    const json = await res.json();
    if (json.ok) {
      if (target === 'core' && json.applying) {
        if (updateStatusMsg) updateStatusMsg.textContent = '更新任务运行中，正在等待验证实际结果...';
        await waitForCoreUpgrade();
      }
      const msg = json.message || '升级已触发';
      if (updateStatusMsg) updateStatusMsg.textContent = msg + '，5 秒后自动刷新页面...';
      setTimeout(() => location.reload(), 5000);
    } else {
      alert(json.error || '升级失败');
      if (updateStatusMsg) updateStatusMsg.textContent = json.error || '升级失败';
      if (btn) { btn.disabled = false; btn.textContent = '重试升级'; }
    }
  } catch (e) {
    alert('升级请求异常: ' + e.message);
    if (btn) { btn.disabled = false; btn.textContent = '重试升级'; }
  }
}

if (btnRecheckUpdate) {
  btnRecheckUpdate.addEventListener('click', async () => {
    btnRecheckUpdate.disabled = true;
    if (updateStatusMsg) updateStatusMsg.textContent = '正在重新检测...';
    try {
      const ok = await checkVersions(true);
      if (updateStatusMsg) updateStatusMsg.textContent = ok ? '检测完成（已主动刷新缓存）' : '检测失败，请检查网络；未把未知结果当成最新';
    } finally { btnRecheckUpdate.disabled = false; }
  });
}

checkVersions();

// 实时吞吐量与网速轮询 (每 2 秒更新一次)
const speedRxEl = document.getElementById('node-speed-rx');
const speedTxEl = document.getElementById('node-speed-tx');
const rxTagEl = document.getElementById('rx-active-tag');
const txTagEl = document.getElementById('tx-active-tag');

function fmtSpeed(bytesPerSec) {
  if (bytesPerSec < 1024) return bytesPerSec.toFixed(0) + ' B/s';
  if (bytesPerSec < 1024 * 1024) return (bytesPerSec / 1024).toFixed(1) + ' KB/s';
  return (bytesPerSec / (1024 * 1024)).toFixed(2) + ' MB/s';
}

let trafficPollPending = false;
async function pollTrafficSpeed() {
  if (document.hidden || trafficPollPending) return;
  trafficPollPending = true;
  try {
    const res = await fetch(location.pathname + 'traffic-speed', { credentials: 'same-origin' });
    if (!res.ok) return;
    const json = await res.json();
    if (!json.ok) return;

    if (speedRxEl) speedRxEl.textContent = fmtSpeed(json.node_rx || 0);
    if (speedTxEl) speedTxEl.textContent = fmtSpeed(json.node_tx || 0);

    if (rxTagEl) rxTagEl.className = (json.node_rx > 1024) ? 'speed-badge active' : 'speed-badge';
    if (txTagEl) txTagEl.className = (json.node_tx > 1024) ? 'speed-badge active' : 'speed-badge';

    // 累计用量同样实时更新，避免只能刷新页面后看到新值。
    const fmtUsage = value => {
      let n = Number(value || 0), i = 0;
      const units = ['B', 'KB', 'MB', 'GB', 'TB'];
      while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
      return (i ? n.toFixed(2) : n.toFixed(0)) + ' ' + units[i];
    };
    const totalUsage = document.getElementById('total-used-bytes');
    if (totalUsage) totalUsage.textContent = fmtUsage(json.total_used_bytes);
    document.querySelectorAll('[data-user-usage]').forEach(el => {
      const u = (json.users || {})[el.dataset.userUsage];
      if (!u) return;
      // 首屏由服务端渲染的是 used_bytes，这里保持一致：
      // 计量未就绪时旧实现会把它换成「计量未就绪」，数字凭空消失。
      el.textContent = fmtUsage(u.used_bytes);
      el.title = u.measured_bytes === null
        ? '计量未就绪，显示的是已记录用量'
        : (u.measurement_ok ? '真实累计用量（自计量开始）' : '计量异常或存在统计缺口；保留最近累计值');
    });

    // 更新各个用户的实时速率标签
    if (json.users) {
      document.querySelectorAll('[data-user-speed]').forEach(badge => {
        const uid = badge.dataset.userSpeed;
        const u = json.users[uid];
        if (u && (u.rx > 0 || u.tx > 0)) {
          badge.textContent = '↓ ' + fmtSpeed(u.rx) + ' · ↑ ' + fmtSpeed(u.tx);
          badge.className = 'speed-badge active';
        } else {
          badge.textContent = '↓ 0 B/s · ↑ 0 B/s';
          badge.className = 'speed-badge';
        }
      });
    }
  } catch (_) {} finally { trafficPollPending = false; }
}

setInterval(pollTrafficSpeed, 2000);
pollTrafficSpeed();

// 入站代理服务管理 (gost 驱动)
const gostBadge = document.getElementById('gost-badge');
const proxyTbody = document.getElementById('proxy-tbody');
const btnInstallGost = document.getElementById('btn-install-gost');
const proxyModal = document.getElementById('proxy-modal');
const pmClose = document.getElementById('pm-close');
const resPHost = document.getElementById('res-phost');
const resPPort = document.getElementById('res-pport');
const resPUser = document.getElementById('res-puser');
const resPPass = document.getElementById('res-ppass');
const resPUrl = document.getElementById('res-purl');
const resPFmt = document.getElementById('res-pfmt');
const btnCopyPUrl = document.getElementById('btn-copy-purl');
const btnCopyPFmt = document.getElementById('btn-copy-pfmt');

let curProxyServerHost = location.hostname;

function closeProxyModal() {
  if (proxyModal) proxyModal.classList.remove('show');
}
if (pmClose) pmClose.addEventListener('click', closeProxyModal);
if (proxyModal) {
  proxyModal.addEventListener('click', (e) => {
    if (e.target === proxyModal) closeProxyModal();
  });
}

const resPTypeBadge = document.getElementById('res-ptype-badge');
const resPQr = document.getElementById('res-pqr');

function showProxyResult(data) {
  if (!proxyModal) return;
  const host = data.host || curProxyServerHost;
  const ptype = data.type || 'socks5';
  const url = data.url || (ptype + '://' + encodeURIComponent(data.username) + ':' + encodeURIComponent(data.password) + '@' + host + ':' + data.port);
  const fmt = data.format || (host + ':' + data.port + ':' + data.username + ':' + data.password);

  if (resPTypeBadge) {
    resPTypeBadge.textContent = ptype.toUpperCase();
    resPTypeBadge.className = 'proxy-type ' + ptype;
  }
  if (resPHost) resPHost.textContent = host;
  if (resPPort) resPPort.textContent = data.port;
  if (resPUser) resPUser.textContent = data.username;
  if (resPPass) resPPass.textContent = data.password;
  if (resPUrl) resPUrl.value = url;
  if (resPFmt) resPFmt.value = fmt;

  if (resPQr && data.qr) {
    resPQr.innerHTML = data.qr;
  }

  if (btnCopyPUrl) {
    btnCopyPUrl.onclick = async () => {
      try {
        await navigator.clipboard.writeText(url);
        btnCopyPUrl.textContent = '已复制 ✓';
        setTimeout(() => { btnCopyPUrl.textContent = '复制 URL'; }, 1800);
      } catch (_) { alert('复制失败，请手动选择复制'); }
    };
  }

  if (btnCopyPFmt) {
    btnCopyPFmt.onclick = async () => {
      try {
        await navigator.clipboard.writeText(fmt);
        btnCopyPFmt.textContent = '已复制 ✓';
        setTimeout(() => { btnCopyPFmt.textContent = '复制格式'; }, 1800);
      } catch (_) { alert('复制失败，请手动选择复制'); }
    };
  }

  document.querySelectorAll('[data-copy-field]').forEach(b => {
    b.onclick = async () => {
      const el = document.getElementById(b.dataset.copyField);
      if (el) {
        try {
          await navigator.clipboard.writeText(el.textContent);
          const orig = b.textContent;
          b.textContent = '✓';
          setTimeout(() => { b.textContent = orig; }, 1500);
        } catch (_) {}
      }
    };
  });

  proxyModal.classList.add('show');
}

// 绑定秒级一键生成按钮
document.querySelectorAll('.btn-quick-proxy').forEach(btn => {
  btn.addEventListener('click', async () => {
    const ptype = btn.dataset.ptype;
    const cPortEl = document.getElementById('custom-proxy-port');
    const customPort = cPortEl ? cPortEl.value.trim() : '';
    btn.disabled = true;
    const origText = btn.textContent;
    btn.textContent = '⚡ 正在生成...';
    try {
      let body = 'action=create&type=' + encodeURIComponent(ptype);
      if (customPort) body += '&port=' + encodeURIComponent(customPort);

      const res = await fetch(location.pathname + 'manage-proxy', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: body
      });
      const json = await res.json();
      if (json.ok) {
        if (cPortEl) cPortEl.value = '';
        showProxyResult(json);
        loadProxyServices();
      } else {
        alert(json.error || '生成失败');
      }
    } catch (e) {
      alert('生成异常: ' + e.message);
    } finally {
      btn.disabled = false;
      btn.textContent = origText;
    }
  });
});

if (btnInstallGost) {
  btnInstallGost.addEventListener('click', async () => {
    if (!confirm("确定要一键安装或更新 GOST 代理服务吗？系统将自动匹配架构并配置自启。")) return;
    btnInstallGost.disabled = true;
    const origText = btnInstallGost.textContent;
    btnInstallGost.textContent = '⏳ 正在安装 GOST...';
    try {
      const res = await fetch(location.pathname + 'install-gost', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
      });
      const json = await res.json();
      if (json.ok) {
        alert(json.message || 'GOST 安装成功！服务已就绪。');
        loadProxyServices();
      } else {
        alert(json.error || '安装失败，请检查服务器网络或日志');
      }
    } catch (e) {
      alert('安装请求异常: ' + e.message);
    } finally {
      btnInstallGost.disabled = false;
      btnInstallGost.textContent = origText;
    }
  });
}

async function loadProxyServices() {
  if (!proxyTbody) return;
  try {
    const res = await fetch(location.pathname + 'proxy-services', { credentials: 'same-origin' });
    if (!res.ok) return;
    const json = await res.json();
    if (!json.ok) return;

    if (gostBadge) {
      if (!json.gost_installed) {
        gostBadge.textContent = '● 未安装 gost';
        gostBadge.style.background = '#fff1f0';
        gostBadge.style.color = '#cf3c3c';
        if (btnInstallGost) {
          btnInstallGost.style.display = 'inline-flex';
          btnInstallGost.textContent = '⚡ 一键安装 GOST';
        }
      } else if (json.gost_active) {
        gostBadge.textContent = '● gost 运行中';
        gostBadge.style.background = '#eaf3de';
        gostBadge.style.color = '#27500a';
        if (btnInstallGost) {
          btnInstallGost.style.display = 'none';
        }
      } else {
        gostBadge.textContent = '● gost 未启动';
        gostBadge.style.background = '#f1efe8';
        gostBadge.style.color = '#5f5e5a';
        if (btnInstallGost) {
          btnInstallGost.style.display = 'inline-flex';
          btnInstallGost.textContent = '🔄 重启/修复 GOST';
        }
      }
    }

    const services = json.services || [];
    if (services.length === 0) {
      proxyTbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--muted);padding:24px">暂无代理服务，点击上方「添加代理服务」创建</td></tr>';
      return;
    }
    if (json.host) curProxyServerHost = json.host;
    const typeLabel = { socks5: 'SOCKS5', http: 'HTTP', https: 'HTTPS' };
    proxyTbody.innerHTML = services.map(s => {
      const fullUrl = `${obEsc(s.type)}://${encodeURIComponent(s.username)}:${encodeURIComponent(s.password)}@${obEsc(curProxyServerHost)}:${obEsc(s.port)}`;
      return `
      <tr>
        <td><span class="proxy-type ${obEsc(s.type)}">${obEsc(typeLabel[s.type] || s.type)}</span></td>
        <td><code style="font-size:12px;font-weight:700;color:var(--accent)">:${obEsc(s.port)}</code></td>
        <td><code style="font-size:12px">${obEsc(s.username)}</code></td>
        <td><code style="font-size:12px">${obEsc(s.password)}</code></td>
        <td>
          <div style="display:flex;align-items:center;gap:6px">
            <code style="font-size:11px;background:#f5f8f7;padding:2px 6px;border-radius:4px;word-break:break-all">${obEsc(s.type)}://${obEsc(s.username)}:****@${obEsc(curProxyServerHost)}:${obEsc(s.port)}</code>
            <button class="button" style="padding:2px 8px;font-size:11px;white-space:nowrap" type="button" data-copy-link="${obEsc(fullUrl)}">复制链接</button>
          </div>
        </td>
        <td><button class="button danger" style="padding:4px 10px;font-size:11px" type="button" data-proxy-del="${obEsc(s.id)}">删除</button></td>
      </tr>`;
    }).join('');

    proxyTbody.querySelectorAll('[data-copy-link]').forEach(btn => {
      btn.addEventListener('click', async () => {
        try {
          await navigator.clipboard.writeText(btn.dataset.copyLink);
          const orig = btn.textContent;
          btn.textContent = '已复制 ✓';
          setTimeout(() => { btn.textContent = orig; }, 1800);
        } catch (_) { alert('复制失败'); }
      });
    });
    proxyTbody.querySelectorAll('[data-proxy-del]').forEach(btn => {
      btn.addEventListener('click', async () => {
        if (!confirm('确定删除该代理服务？')) return;
        btn.disabled = true;
        try {
          const res = await fetch(location.pathname + 'manage-proxy', {
            method: 'POST', credentials: 'same-origin',
            headers: {'Content-Type':'application/x-www-form-urlencoded'},
            body: 'action=delete&id=' + encodeURIComponent(btn.dataset.proxyDel)
          });
          const json = await res.json();
          if (!res.ok || !json.ok) throw new Error(json.error || '删除代理失败');
          await loadProxyServices();
        } catch (err) {
          alert(err.message || '删除代理请求失败');
        } finally { btn.disabled = false; }
      });
    });
  } catch (_) {}
}

// proxyForm replaced with instant buttons

loadProxyServices();

function closeUserModal() {
  if (uModal) uModal.classList.remove('show');
}
if (uModalClose) uModalClose.addEventListener('click', closeUserModal);
if (uModal) {
  uModal.addEventListener('click', (e) => {
    if (e.target === uModal) closeUserModal();
  });
}

document.querySelectorAll('.btn-user-connect').forEach(btn => {
  btn.addEventListener('click', async () => {
    const uid = btn.dataset.uid;
    const token = btn.dataset.token;
    const userKey = btn.dataset.key;
    if (!uModal || !uModalBody) return;
    
    uModalTitle.textContent = '用户专属连接: ' + uid;
    uModalSub.textContent = '正在获取专属配置与独立连接页...';
    uModalBody.innerHTML = '<div style="text-align:center;padding:36px;color:var(--muted)">加载专属数据中...</div>';
    uModal.classList.add('show');
    
    try {
      const res = await fetch('/' + token + '/user-config?user_id=' + encodeURIComponent(uid), { credentials: 'same-origin' });
      if (res.status === 401) {
        throw new Error('登录状态已失效，请刷新页面重新登录');
      }
      if (!res.ok) {
        throw new Error('网络请求异常 (HTTP ' + res.status + ')');
      }
      const json = await res.json();
      if (!json.ok) throw new Error(json.error || '加载失败');
      
      uModalSub.textContent = json.note ? ('备注: ' + json.note) : '专属独立配置与下载链接';
      
      const shareUrl = location.origin + '/' + token + '/u/' + encodeURIComponent(uid) + '?k=' + userKey;
      
      // 统一用 fmtBytes：旧写法把已用强制成 MB、配额强制成 GB，
      // 小配额（如 500 MB）会显示成「0.5 GB」，大用量则是「1536.0 MB」。
      const fmtBytes = v => {
        let n = Number(v || 0), i = 0;
        const units = ['B', 'KB', 'MB', 'GB', 'TB'];
        while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
        return (i ? n.toFixed(2) : n.toFixed(0)) + ' ' + units[i];
      };
      let trafficText = (json.traffic_limit > 0)
        ? (fmtBytes(json.traffic_used) + ' / ' + fmtBytes(json.traffic_limit))
        : (fmtBytes(json.traffic_used) + ' (不限)');
      // 与后端 _expiry_text 同一条规则：只有「没有到期时间」才是永久。
      // 旧阈值 2e9（2033 年）会把十年有效的用户显示成永久有效（2026-10-30 修）。
      let expireText = (json.expires_at === null || json.expires_at === undefined)
        ? '永久有效'
        : new Date(json.expires_at * 1000).toLocaleString();
      let ipText = (json.ip_limit > 0) ? (json.ip_limit + ' IP') : '不限';
      
      uModalBody.innerHTML = `
        <div class="user-meta-bar">
          <span>📅 到期: <b>${expireText}</b></span>
          <span>📊 流量: <b>${trafficText}</b></span>
          <span>📱 IP限制: <b>${ipText}</b></span>
        </div>
        
        <div style="background:#eaf5ef;border:1px solid #c3ddd5;border-radius:12px;padding:12px 14px">
          <div style="font-size:12px;font-weight:700;color:var(--accent);margin-bottom:6px">🌐 专属独立连接页面 (可直接发给客户):</div>
          <div class="input-with-action">
            <input type="text" id="um-share-url" value="${obEsc(shareUrl)}" readonly style="font-size:12px;height:38px">
            <button class="button primary" style="padding:0 12px;height:38px;font-size:12px" type="button" data-modal-copy="um-share-url">复制页面链接</button>
            <a class="button" style="padding:0 12px;height:38px;font-size:12px" href="${obEsc(shareUrl)}" target="_blank">打开页面 ↗</a>
          </div>
        </div>

        <div class="user-connect-grid">
          <div style="text-align:center;background:#fff;border:1px solid var(--line);border-radius:14px;padding:14px">
            <div style="font-size:12px;font-weight:700;color:var(--ink);margin-bottom:8px">专属二维码扫码导入</div>
            <div class="qr-frame" style="margin:0 auto;max-width:210px;padding:8px">${json.qr_svg || '<p style="color:var(--muted)">二维码生成中...</p>'}</div>
            <div style="font-size:11px;color:var(--muted);margin-top:8px">Shadowrocket / v2rayNG / Nekobox</div>
          </div>
          <div style="display:flex;flex-direction:column;gap:12px">
            <div>
              <div style="font-size:12px;font-weight:700;color:var(--ink);margin-bottom:4px">专属节点直链 (URI):</div>
              <textarea id="um-uri" class="link" style="height:65px;font-size:11px" readonly>${obEsc(json.uri)}</textarea>
              <div style="margin-top:6px;display:flex;gap:8px">
                <button class="button primary" style="padding:6px 14px;font-size:11px" type="button" data-modal-copy="um-uri">复制直链</button>
              </div>
            </div>
            <div>
              <div style="font-size:12px;font-weight:700;color:var(--ink);margin-bottom:4px">Clash / Mihomo 专属订阅链接:</div>
              <div class="input-with-action">
                <input type="text" id="um-clash-sub" value="${location.origin}/${token}/u/${encodeURIComponent(uid)}/clash.yaml?k=${userKey}" readonly style="font-size:11px;height:36px">
                <button class="button primary" style="padding:0 12px;height:36px;font-size:11px" type="button" data-modal-copy="um-clash-sub">复制订阅</button>
                <a class="button" style="padding:0 10px;height:36px;font-size:11px" href="/${token}/u/${encodeURIComponent(uid)}/clash.yaml?k=${userKey}" download="clash-${uid}.yaml">下载 ↓</a>
              </div>
              <details style="margin-top:6px">
                <summary style="font-size:11px;color:var(--muted)">查看/复制配置文本</summary>
                <textarea id="um-clash" class="link" style="height:65px;font-size:10px;margin-top:4px" readonly>${obEsc(json.clash)}</textarea>
                <div style="margin-top:4px"><button class="button" style="padding:2px 8px;font-size:10px" type="button" data-modal-copy="um-clash">复制文本</button></div>
              </details>
            </div>
          </div>
        </div>
      `;
      
      uModalBody.querySelectorAll('[data-modal-copy]').forEach(b => {
        b.addEventListener('click', async () => {
          const target = document.getElementById(b.dataset.modalCopy);
          if (!target) return;
          const text = target.value || target.textContent || '';
          // 用户弹窗里同样要处理失败：非 HTTPS 或权限被拒时会 reject，
          // 旧实现没有 catch，按钮静默无反应且控制台报未处理 rejection。
          copyWithFeedback(text, b, '已复制 ✓');
        });
      });
      
    } catch (err) {
      uModalBody.innerHTML = `<div style="text-align:center;padding:24px;color:var(--danger)">加载失败: ${obEsc(err.message)}</div>`;
    }
  });
});

/* ==================== AmneziaWG 抗 DPI 协议管理 ==================== */
const awgBadge = document.getElementById('awg-badge');
const awgInstallBox = document.getElementById('awg-install-box');
const btnInstallAwg = document.getElementById('btn-install-awg');
const btnDoInstallAwg = document.getElementById('btn-do-install-awg');
const awgLineSelect = document.getElementById('awg-line-select');
const awgEndpointInput = document.getElementById('awg-endpoint-input');
const awgMetaBox = document.getElementById('awg-meta');
const awgMetaLine = document.getElementById('awg-meta-line');
const awgMetaPort = document.getElementById('awg-meta-port');
const awgMetaPeers = document.getElementById('awg-meta-peers');
const awgMetaChip = document.getElementById('awg-meta-chip');
const awgPanel = document.getElementById('awg-panel');
const awgPeerTbody = document.getElementById('awg-peer-tbody');
const awgPeerName = document.getElementById('awg-peer-name');
const awgPeerEndpoint = document.getElementById('awg-peer-endpoint');
const btnAddAwgPeer = document.getElementById('btn-add-awg-peer');
const btnSwitchAwgLine = document.getElementById('btn-switch-awg-line');
const btnUpdateAwg = document.getElementById('btn-update-awg');
let awgCurrentEndpoint = '';
let awgCurrentLine = '3';

function awgPost(endpoint, params) {
  return fetch(location.pathname + endpoint, {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(params).toString()
  }).then(r => r.json()).catch(e => ({ ok: false, error: '请求异常: ' + e.message }));
}

function setAwgBadge(text, bg, color) {
  if (!awgBadge) return;
  awgBadge.textContent = text;
  awgBadge.style.background = bg;
  awgBadge.style.color = color;
}

async function loadAwgState() {
  if (!awgBadge) return;
  try {
    const res = await fetch(location.pathname + 'awg-state', { credentials: 'same-origin' });
    if (!res.ok) return;
    const json = await res.json();
    if (!json.ok) return;

    awgCurrentEndpoint = json.endpoint || '';
    awgCurrentLine = json.line || '3';
    if (awgEndpointInput && !awgEndpointInput.value) awgEndpointInput.value = awgCurrentEndpoint;
    if (awgPeerEndpoint && !awgPeerEndpoint.value) awgPeerEndpoint.value = awgCurrentEndpoint;
    if (awgMetaChip) awgMetaChip.textContent = json.installed ? ('AWG ' + awgCurrentLine + '.x') : '未安装';

    if (!json.installed) {
      setAwgBadge('● 未安装 AmneziaWG', '#fff1f0', '#cf3c3c');
      if (awgMetaBox) awgMetaBox.style.display = 'none';
      if (awgPanel) awgPanel.style.display = 'none';
      if (awgInstallBox) awgInstallBox.style.display = 'none';
      if (btnInstallAwg) { btnInstallAwg.style.display = 'inline-flex'; btnInstallAwg.textContent = '⚡ 一键安装 AmneziaWG'; }
      return;
    }

    if (awgLineSelect && awgCurrentLine) awgLineSelect.value = awgCurrentLine;

    if (json.active) {
      setAwgBadge('● AmneziaWG 运行中', '#eaf3de', '#27500a');
    } else {
      setAwgBadge('● AmneziaWG 已安装未运行', '#f1efe8', '#5f5e5a');
    }
    if (btnInstallAwg) btnInstallAwg.style.display = 'none';
    if (awgInstallBox) awgInstallBox.style.display = 'none';
    if (awgMetaBox) awgMetaBox.style.display = 'flex';
    if (awgMetaLine) awgMetaLine.textContent = '协议线 AWG ' + awgCurrentLine + '.x';
    if (awgMetaPort) awgMetaPort.textContent = 'UDP ' + (json.port || '未知');
    if (awgMetaPeers) awgMetaPeers.textContent = '客户端 ' + (json.peer_count || 0) + ' 个';
    if (awgPanel) awgPanel.style.display = 'block';

    renderAwgPeers(json.peers || []);
  } catch (e) { /* 静默失败，不打扰主界面 */ }
}

function renderAwgPeers(peers) {
  if (!awgPeerTbody) return;
  if (!peers.length) {
    awgPeerTbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:var(--muted);padding:20px">暂无客户端，用上方表单新增</td></tr>';
    return;
  }
  awgPeerTbody.innerHTML = peers.map(p => {
    const enc = encodeURIComponent(p.name);
    const bs = 'padding:3px 10px;font-size:11px';
    return '<tr data-awg-endpoint="' + obEsc(p.endpoint || '') + '">'
      // 名称/地址虽受后端正则限制，仍统一走 obEsc —— 与其他表格保持同一套转义习惯。
      + '<td><strong>' + obEsc(p.name) + '</strong></td>'
      + '<td>' + obEsc(p.address) + '</td>'
      + '<td style="color:var(--muted);font-size:11.5px">' + obEsc(p.created_at || '-') + '</td>'
      + '<td style="white-space:nowrap">'
      + '<button class="button" type="button" data-awg-conf="' + enc + '" style="' + bs + '">下载配置</button> '
      + '<button class="button" type="button" data-awg-qr="' + enc + '" style="' + bs + '">二维码</button> '
      + '<button class="button" type="button" data-awg-del="' + enc + '" style="' + bs + ';color:#cf3c3c">删除</button>'
      + '</td></tr>';
  }).join('');

  awgPeerTbody.querySelectorAll('[data-awg-conf]').forEach(b => {
    b.addEventListener('click', () => {
      const row = b.closest('tr');
      const endpoint = row && row.dataset.awgEndpoint ? '&endpoint=' + encodeURIComponent(row.dataset.awgEndpoint) : '';
      window.open(location.pathname + 'awg-conf?name=' + b.getAttribute('data-awg-conf') + endpoint, '_blank');
    });
  });
  awgPeerTbody.querySelectorAll('[data-awg-qr]').forEach(b => {
    b.addEventListener('click', () => {
      const row = b.closest('tr');
      const endpoint = row && row.dataset.awgEndpoint ? '&endpoint=' + encodeURIComponent(row.dataset.awgEndpoint) : '';
      window.open(location.pathname + 'awg-qr.svg?name=' + b.getAttribute('data-awg-qr') + endpoint, '_blank');
    });
  });
  awgPeerTbody.querySelectorAll('[data-awg-del]').forEach(b => {
    b.addEventListener('click', async () => {
      const n = decodeURIComponent(b.getAttribute('data-awg-del'));
      if (!confirm('确认删除客户端「' + n + '」？该客户端会立即断开连接。')) return;
      const json = await awgPost('manage-amneziawg', { action: 'peer_del', name: n });
      if (json.ok) { showToast('已删除客户端 ' + n, 'success'); loadAwgState(); }
      else { alert(json.error || '删除失败'); }
    });
  });
}

if (btnInstallAwg) {
  btnInstallAwg.addEventListener('click', () => {
    if (!awgInstallBox) return;
    awgInstallBox.style.display = (awgInstallBox.style.display === 'none') ? 'block' : 'none';
  });
}

if (btnDoInstallAwg) {
  btnDoInstallAwg.addEventListener('click', async () => {
    const line = awgLineSelect ? awgLineSelect.value : '3';
    const endpoint = awgEndpointInput ? awgEndpointInput.value.trim() : '';
    if (!endpoint) { alert('请填写客户端连接地址（域名或公网 IP）'); return; }
    if (!confirm('确认安装 AmneziaWG（协议线 AWG ' + line + '.x）？\n\n会下载自建静态二进制并启动独立服务，不影响现有的 Hysteria 2。')) return;
    btnDoInstallAwg.disabled = true;
    const orig = btnDoInstallAwg.textContent;
    btnDoInstallAwg.textContent = '⏳ 安装中，请稍候...';
    try {
      const json = await awgPost('install-amneziawg', { line: line, endpoint: endpoint });
      if (json.ok) { showToast(json.message || '安装完成', 'success'); loadAwgState(); }
      else { alert(json.error || '安装失败'); }
    } finally {
      btnDoInstallAwg.disabled = false;
      btnDoInstallAwg.textContent = orig;
    }
  });
}

if (btnAddAwgPeer) {
  btnAddAwgPeer.addEventListener('click', async () => {
    const name = awgPeerName ? awgPeerName.value.trim() : '';
    const endpoint = (awgPeerEndpoint && awgPeerEndpoint.value.trim()) || awgCurrentEndpoint;
    if (!name) { alert('请填写客户端名称'); return; }
    if (!/^[A-Za-z0-9_.-]{1,32}$/.test(name)) { alert('名称只允许字母、数字、点、下划线、连字符，且不超过 32 字符'); return; }
    if (!endpoint) { alert('请填写连接地址'); return; }
    // Open the tab synchronously in the click gesture; browsers block window.open
    // after an await because it no longer has transient user activation.
    const confTab = window.open('about:blank', '_blank');
    btnAddAwgPeer.disabled = true;
    try {
      const json = await awgPost('manage-amneziawg', { action: 'peer_add', name: name, endpoint: endpoint });
      if (json.ok) {
        if (awgPeerName) awgPeerName.value = '';
        const confUrl = location.pathname + 'awg-conf?name=' + encodeURIComponent(name)
          + '&endpoint=' + encodeURIComponent(endpoint);
        if (confTab) confTab.location = confUrl;
        else showToast('客户端已新增，请用列表中的“配置”按钮打开配置', 'success');
        if (confTab) showToast('已新增客户端 ' + name + '，正在打开配置', 'success');
        loadAwgState();
      } else {
        if (confTab) confTab.close();
        alert(json.error || '新增失败');
      }
    } catch (e) {
      if (confTab) confTab.close();
      throw e;
    } finally {
      btnAddAwgPeer.disabled = false;
    }
  });
}

if (btnSwitchAwgLine) {
  btnSwitchAwgLine.addEventListener('click', async () => {
    const target = prompt('切换 AmneziaWG 协议线\n\n2 = AWG 2.x（参数体系稳定）\n3 = AWG 3.x（含头部保护与抗行为分析）\n\n⚠️ 切换会重新生成全部混淆参数，已发放的客户端配置会立即失效，必须重新导出。\n\n请输入目标协议线：', awgCurrentLine === '3' ? '2' : '3');
    if (target !== '2' && target !== '3') return;
    if (target === awgCurrentLine) { alert('已经是 AWG ' + awgCurrentLine + '.x，无需切换。'); return; }
    if (!confirm('确认切换到 AWG ' + target + '.x？所有已发放的客户端配置都会失效。')) return;
    const json = await awgPost('manage-amneziawg', { action: 'set_line', line: target });
    if (json.ok) { showToast(json.message || '已切换协议线', 'success'); loadAwgState(); }
    else { alert(json.error || '切换失败'); }
  });
}

if (btnUpdateAwg) {
  btnUpdateAwg.addEventListener('click', async () => {
    if (!confirm('确认更新 AmneziaWG 二进制？协议线与混淆参数保持不变，客户端无需重新导入。')) return;
    const json = await awgPost('manage-amneziawg', { action: 'update' });
    if (json.ok) { showToast(json.message || '更新完成', 'success'); loadAwgState(); }
    else { alert(json.error || '更新失败'); }
  });
}

loadAwgState();
"""

# ============================================================================
# LOGIN_SCRIPT
# ============================================================================
LOGIN_SCRIPT = r"""
function toggleSecret(id, btn) {
  const el = document.getElementById(id);
  if (el.type === 'password') {
    el.type = 'text';
    btn.textContent = '隐藏';
  } else {
    el.type = 'password';
    btn.textContent = '显示';
  }
}

// 🔴 不能写成 <button onclick="toggleSecret(...)"> —— CSP 的 script-src 只有
// 哈希白名单、没有 'unsafe-inline'，内联事件处理器会被浏览器直接拒绝执行，
// 按钮点了毫无反应。必须在这里用 addEventListener 绑定（整段脚本有 CSP 哈希，
// 因此被允许）。
document.querySelectorAll('.toggle-pwd').forEach(btn => {
  btn.addEventListener('click', () => {
    const input = btn.parentElement.querySelector('input');
    if (input) toggleSecret(input.id, btn);
  });
});
"""

# ============================================================================
# USER_SCRIPT
# ============================================================================
USER_SCRIPT = r"""
document.querySelectorAll('[data-copy]').forEach(button => {
  button.addEventListener('click', async () => {
    const field = document.getElementById(button.dataset.copy);
    try {
      const val = field.value || field.textContent || '';
      await navigator.clipboard.writeText(val);
      const orig = button.textContent;
      button.textContent = '已复制 ✓';
      setTimeout(() => { button.textContent = orig; }, 1800);
    } catch (_) {
      if (field.select) { field.focus(); field.select(); }
    }
  });
});
"""
