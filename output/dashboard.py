"""
M.A.R.K. Sentinel — Dashboard Generator
Produces a self-contained single-file HTML dashboard from one or more JSON scan reports.
Open the output HTML in any browser — no server required.
"""
import json
from pathlib import Path


_CATS = ['AI-DEPLOY', 'AI-INP', 'AI-OUT', 'AI-AGENT', 'AI-SUPPLY', 'AI-GOV']
_CAT_LABELS = {
    'AI-DEPLOY': 'Deployment Security',
    'AI-INP':    'Input Safety',
    'AI-OUT':    'Output Safety',
    'AI-AGENT':  'Agentic Safety',
    'AI-SUPPLY': 'Supply Chain',
    'AI-GOV':    'Governance',
}

_CSS = r"""
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0d1117;color:#c9d1d9;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;font-size:14px;height:100vh;overflow:hidden}
#app{display:flex;height:100vh}
#sidebar{width:220px;min-width:220px;background:#010409;border-right:1px solid #21262d;display:flex;flex-direction:column}
.brand{padding:20px 16px 14px;border-bottom:1px solid #21262d}
.brand-mark{font-size:10px;letter-spacing:3px;color:#58a6ff;font-weight:700;text-transform:uppercase}
.brand-name{font-size:20px;font-weight:800;color:#e6edf3;letter-spacing:1px;margin-top:2px}
.brand-sub{font-size:10px;color:#484f58;margin-top:3px;letter-spacing:.5px}
#nav{padding:10px 0;flex:1}
.nav-item{display:flex;align-items:center;gap:10px;padding:10px 16px;color:#8b949e;cursor:pointer;font-size:13px;font-weight:500;border-left:2px solid transparent;transition:all .1s;user-select:none}
.nav-item:hover{background:#161b22;color:#c9d1d9}
.nav-item.active{background:#161b22;color:#58a6ff;border-left-color:#58a6ff}
.nav-icon{font-size:14px;width:18px;text-align:center}
.sidebar-footer{padding:10px 16px;border-top:1px solid #21262d;font-size:10px;color:#484f58;line-height:1.6}
#main{flex:1;display:flex;flex-direction:column;overflow:hidden;min-width:0}
#header{background:#161b22;border-bottom:1px solid #21262d;padding:11px 24px;display:flex;align-items:center;justify-content:space-between;flex-shrink:0}
.header-title{font-size:15px;font-weight:700;color:#e6edf3;display:flex;align-items:center;gap:8px}
.header-title span{font-size:11px;background:#21262d;color:#6e7681;padding:2px 8px;border-radius:10px;font-weight:400}
.header-meta{font-size:11px;color:#6e7681;display:flex;gap:16px}
#content{flex:1;overflow-y:auto;padding:24px}
.view{display:none}
.view.active{display:block}
.provider-bar{display:flex;gap:8px;margin-bottom:20px;flex-wrap:wrap;align-items:center}
.pbar-label{font-size:11px;color:#6e7681;margin-right:2px}
.pbtn{background:#21262d;border:1px solid #30363d;color:#8b949e;padding:5px 14px;border-radius:6px;cursor:pointer;font-size:12px;font-weight:500;transition:all .1s}
.pbtn:hover{border-color:#58a6ff;color:#c9d1d9}
.pbtn.active{background:#1f3358;border-color:#58a6ff;color:#58a6ff}
.stat-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:24px}
.stat-card{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:16px 18px}
.stat-card.t-red{border-top:3px solid #f85149}
.stat-card.t-yellow{border-top:3px solid #d29922}
.stat-card.t-green{border-top:3px solid #3fb950}
.stat-card.t-gray{border-top:3px solid #484f58}
.stat-num{font-size:34px;font-weight:800;line-height:1}
.c-red{color:#f85149}.c-orange{color:#f0883e}.c-yellow{color:#d29922}.c-green{color:#3fb950}.c-blue{color:#58a6ff}.c-gray{color:#6e7681}
.stat-label{font-size:11px;color:#8b949e;margin-top:5px;text-transform:uppercase;letter-spacing:.5px}
.stat-sub{font-size:11px;margin-top:5px}
.risk-row{display:flex;gap:12px;margin-bottom:24px}
.risk-card{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:18px 22px;flex:1;display:flex;align-items:center;gap:20px}
.risk-score{font-size:52px;font-weight:800;line-height:1}
.risk-info{flex:1}
.risk-label{font-size:18px;font-weight:700;color:#e6edf3}
.risk-desc{font-size:12px;color:#8b949e;margin-top:5px;line-height:1.5}
.probe-card{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:18px 22px;min-width:190px}
.probe-title{font-size:11px;color:#6e7681;text-transform:uppercase;letter-spacing:.5px;margin-bottom:10px}
.probe-stats{display:flex;gap:18px}
.probe-stat{text-align:center}
.probe-num{font-size:28px;font-weight:700}
.probe-lbl{font-size:10px;color:#6e7681;text-transform:uppercase;margin-top:2px}
.sec-hdr{font-size:12px;font-weight:600;color:#6e7681;text-transform:uppercase;letter-spacing:1px;margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid #21262d;display:flex;align-items:center;gap:8px}
.cat-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:24px}
.cat-card{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:14px 16px}
.cat-head{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px}
.cat-name{font-size:13px;font-weight:600;color:#e6edf3}
.cat-counts{font-size:11px;color:#6e7681}
.bar-track{background:#21262d;border-radius:4px;height:7px;overflow:hidden;display:flex}
.bar-seg{height:100%}
.bar-seg.fail{background:#f85149}.bar-seg.warn{background:#d29922}.bar-seg.pass{background:#3fb950}.bar-seg.skip{background:#363d47}
.cat-legend{display:flex;gap:10px;margin-top:7px}
.leg-item{display:flex;align-items:center;gap:4px;font-size:10px;color:#6e7681}
.leg-dot{width:6px;height:6px;border-radius:50%}
.leg-dot.fail{background:#f85149}.leg-dot.warn{background:#d29922}.leg-dot.pass{background:#3fb950}.leg-dot.skip{background:#363d47}
.filter-bar{display:flex;gap:6px;margin-bottom:10px;flex-wrap:wrap;align-items:center}
.fbtn{background:#21262d;border:1px solid #30363d;color:#8b949e;padding:4px 12px;border-radius:20px;cursor:pointer;font-size:11px;font-weight:500;transition:all .1s}
.fbtn:hover{border-color:#58a6ff;color:#c9d1d9}
.fbtn.on{color:#fff;border-color:transparent}
.fbtn.on.f-all{background:#388bfd}
.fbtn.on.f-critical,.fbtn.on.f-fail{background:#b91c1c}
.fbtn.on.f-warn{background:#92400e}
.fbtn.on.f-pass{background:#166534}
.fbtn.on.f-skip{background:#374151}
.findings-list{display:flex;flex-direction:column;gap:5px}
.finding{background:#161b22;border:1px solid #21262d;border-radius:6px;overflow:hidden}
.fhdr{display:flex;align-items:center;gap:10px;padding:11px 14px;cursor:pointer;transition:background .1s}
.fhdr:hover{background:#1c2128}
.find-ind{width:3px;height:30px;border-radius:2px;flex-shrink:0}
.find-ind.critical,.find-ind.fail{background:#f85149}
.find-ind.high{background:#f0883e}
.find-ind.medium{background:#d29922}
.find-ind.warn{background:#d29922}
.find-ind.pass{background:#3fb950}
.find-ind.skip{background:#363d47}
.sev-badge{font-size:10px;font-weight:700;padding:2px 7px;border-radius:3px;text-transform:uppercase;letter-spacing:.3px;flex-shrink:0}
.sev-badge.critical{background:#3d1212;color:#f85149;border:1px solid #f85149}
.sev-badge.high{background:#3d1f00;color:#f0883e;border:1px solid #f0883e}
.sev-badge.medium{background:#2d2000;color:#d29922;border:1px solid #d29922}
.sev-badge.low{background:#0d1f3d;color:#388bfd;border:1px solid #388bfd}
.sev-badge.warn{background:#2d2000;color:#d29922;border:1px solid #d29922}
.sev-badge.pass{background:#0d2d1a;color:#3fb950;border:1px solid #3fb950}
.sev-badge.skip{background:#1a1f27;color:#6e7681;border:1px solid #363d47}
.stat-badge{font-size:10px;font-weight:600;padding:2px 7px;border-radius:3px;text-transform:uppercase;flex-shrink:0}
.stat-badge.fail{background:#3d1212;color:#f85149}
.stat-badge.warn{background:#2d2000;color:#d29922}
.stat-badge.pass{background:#0d2d1a;color:#3fb950}
.stat-badge.skip{background:#1a1f27;color:#6e7681}
.find-id{font-size:11px;color:#6e7681;font-family:monospace;flex-shrink:0}
.find-title{font-size:13px;font-weight:500;color:#c9d1d9;flex:1;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.find-cat{font-size:10px;color:#363d47;flex-shrink:0;margin-left:4px}
.find-chev{color:#363d47;font-size:11px;transition:transform .2s;flex-shrink:0}
.finding.open .find-chev{transform:rotate(90deg)}
.fbody{display:none;padding:4px 14px 16px;border-top:1px solid #21262d}
.finding.open .fbody{display:block}
.find-details{color:#8b949e;font-size:13px;line-height:1.7;margin:12px 0}
.sub-lbl{font-size:10px;text-transform:uppercase;letter-spacing:.5px;color:#363d47;margin-top:14px;margin-bottom:6px;font-weight:600}
.ev-list{list-style:none;display:flex;flex-direction:column;gap:4px}
.ev-item{font-family:'SFMono-Regular','Consolas',monospace;font-size:12px;color:#8b949e;background:#0d1117;padding:6px 10px;border-radius:4px;border-left:2px solid #30363d}
.rem-steps{display:flex;flex-direction:column;gap:4px}
.rem-step{font-size:13px;color:#8b949e;line-height:1.7;padding:5px 0;border-bottom:1px solid #161b22}
.rem-step:last-child{border-bottom:none}
.fw-tags{display:flex;gap:5px;flex-wrap:wrap;margin-top:8px}
.fw-tag{background:#1f3358;color:#58a6ff;border:1px solid #1f4480;font-size:10px;padding:2px 8px;border-radius:4px;font-weight:500}
.ctrl-tags{display:flex;gap:5px;flex-wrap:wrap;margin-top:6px}
.ctrl-tag{background:#052e16;color:#4ade80;border:1px solid #166534;font-size:10px;padding:2px 7px;border-radius:3px;font-family:monospace;font-weight:600}
.heat-wrap{overflow-x:auto;margin-top:16px}
.heat-table{border-collapse:collapse;width:100%}
.heat-table thead th{background:#21262d;color:#8b949e;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;padding:10px 8px;text-align:center;border:1px solid #30363d;white-space:nowrap}
.heat-table thead th:first-child{text-align:left;min-width:90px}
.heat-sev-lbl{background:#0d1117;color:#c9d1d9;font-family:monospace;font-size:11px;font-weight:700;padding:14px 10px;text-align:left;border:1px solid #30363d;white-space:nowrap}
.heat-cell{padding:18px 8px;text-align:center;cursor:pointer;transition:opacity .12s;border:1px solid #0d1117;min-width:90px}
.heat-cell:hover{opacity:.75;outline:2px solid #58a6ff;outline-offset:-2px}
.heat-count{font-size:22px;font-weight:700;line-height:1}
.heat-lbl{font-size:10px;margin-top:3px;opacity:.8}
.heat-empty{background:#161b22;color:#484f58;border:1px solid #0d1117;padding:18px 8px;text-align:center;min-width:90px}
.heat-foot td{text-align:center;padding:8px;font-size:12px;font-weight:700;border-top:2px solid #30363d}
.heat-legend{display:flex;gap:20px;margin-top:14px;font-size:11px;color:#8b949e;flex-wrap:wrap}
.heat-legend span{display:flex;align-items:center;gap:6px}
.heat-swatch{width:14px;height:14px;border-radius:3px;flex-shrink:0}
.cov-summary{display:flex;gap:24px;flex-wrap:wrap;background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px 20px;margin-bottom:16px}
.cov-stat{text-align:center;min-width:80px}
.cov-stat-n{font-size:32px;font-weight:700;color:#c9d1d9;line-height:1}
.cov-stat-l{font-size:11px;color:#8b949e;margin-top:4px}
.cov-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:10px;margin-top:4px}
.cov-card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px 14px}
.cov-hdr{display:flex;justify-content:space-between;align-items:baseline;margin-bottom:8px}
.cov-family{font-family:monospace;font-size:13px;font-weight:700;color:#c9d1d9}
.cov-sub{font-size:11px;color:#8b949e}
.cov-pct{font-size:13px;font-weight:700}
.cov-bar-bg{height:5px;background:#30363d;border-radius:3px;margin-bottom:8px}
.cov-bar{height:5px;border-radius:3px;transition:width .4s}
.cov-chips{display:flex;flex-wrap:wrap;gap:3px}
.cov-yes{background:#052e16;color:#4ade80;border:1px solid #166534;font-size:10px;padding:1px 6px;border-radius:3px;font-family:monospace}
.cov-no{background:#1c1c1c;color:#484f58;border:1px solid #21262d;font-size:10px;padding:1px 6px;border-radius:3px;font-family:monospace}
.cov-uncovered{background:#1c1117;border:1px solid #5b2333;border-radius:8px;padding:12px 14px;margin-top:14px}
.sim-panels{display:grid;grid-template-columns:1fr auto 1fr;gap:12px;align-items:center;margin-bottom:20px}
.sim-panel{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;text-align:center}
.sim-panel-lbl{font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:#8b949e;margin-bottom:8px}
.sim-panel-score{font-size:30px;font-weight:700;line-height:1}
.sim-panel-sub{font-size:12px;color:#8b949e;margin-top:6px}
.sim-arrow{font-size:24px;color:#58a6ff;text-align:center}
.sim-gain{background:#0d2818;border:1px solid #166534;border-radius:6px;padding:10px 14px;margin-bottom:16px;font-size:13px;color:#4ade80}
.sim-table{width:100%;border-collapse:collapse}
.sim-table th{background:#21262d;color:#8b949e;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;padding:10px 12px;text-align:left;border-bottom:1px solid #30363d}
.sim-table td{padding:9px 12px;border-bottom:1px solid #21262d;font-size:13px;color:#c9d1d9;vertical-align:middle}
.sim-table tr.sim-done td{opacity:.35}
.sim-table tr.sim-done td:nth-child(5){text-decoration:line-through}
.sim-cb{width:15px;height:15px;cursor:pointer;accent-color:#3fb950}
.sim-delta{font-size:11px;font-family:monospace;color:#f85149;white-space:nowrap}
.probe-table{width:100%;border-collapse:collapse}
.probe-table th{background:#21262d;color:#8b949e;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;padding:10px 12px;text-align:left;border-bottom:1px solid #30363d}
.probe-table td{padding:10px 12px;border-bottom:1px solid #21262d;font-size:13px;color:#c9d1d9;vertical-align:top}
.probe-table tr:last-child td{border-bottom:none}
.probe-table tr:hover td{background:#1c2128}
.p-pass{color:#3fb950;font-weight:600}
.p-fail{color:#f85149;font-weight:600}
.p-skip{color:#6e7681}
.p-ev{font-family:monospace;font-size:11px;color:#6e7681;max-width:380px;word-break:break-word}
.cmp-wrap{overflow-x:auto}
.cmp-table{width:100%;border-collapse:collapse;font-size:12px}
.cmp-table th{background:#21262d;color:#8b949e;font-size:11px;font-weight:600;padding:10px;text-align:center;border:1px solid #30363d;white-space:nowrap}
.cmp-table th:first-child{text-align:left;min-width:230px}
.cmp-table td{padding:8px 10px;border:1px solid #21262d;text-align:center}
.cmp-table tr:hover td{background:#1c2128}
.cmp-id{font-family:monospace;font-size:11px;color:#6e7681;text-align:left}
.cmp-name{color:#6e7681;font-size:10px;text-align:left}
.cmp-cell{display:inline-block;padding:2px 8px;border-radius:3px;font-size:10px;font-weight:700;letter-spacing:.3px}
.cmp-cell.fail{background:#3d1212;color:#f85149}
.cmp-cell.warn{background:#2d2000;color:#d29922}
.cmp-cell.pass{background:#0d2d1a;color:#3fb950}
.cmp-cell.skip{background:#1a1f27;color:#6e7681}
.cmp-table .cat-row td{background:#1c2128;font-weight:700;font-size:11px;color:#58a6ff;letter-spacing:.5px;text-transform:uppercase;text-align:left;padding:8px 10px}
.rem-queue{display:flex;flex-direction:column;gap:7px}
.rem-item{background:#161b22;border:1px solid #21262d;border-radius:6px;padding:14px 16px;display:flex;gap:12px;align-items:flex-start}
.rem-item.critical{border-left:3px solid #f85149}
.rem-item.high{border-left:3px solid #f0883e}
.rem-item.medium{border-left:3px solid #d29922}
.rem-item.low{border-left:3px solid #388bfd}
.rem-id{font-family:monospace;font-size:11px;font-weight:700;padding:2px 8px;border-radius:4px;flex-shrink:0;margin-top:1px}
.rem-id.critical{background:#3d1212;color:#f85149}
.rem-id.high{background:#3d1f00;color:#f0883e}
.rem-id.medium{background:#2d2000;color:#d29922}
.rem-id.low{background:#0d1f3d;color:#388bfd}
.rem-body{flex:1}
.rem-title{font-size:13px;font-weight:600;color:#c9d1d9}
.rem-text{font-size:12px;color:#6e7681;margin-top:6px;line-height:1.8;white-space:pre-wrap}
.sec-div{margin:20px 0 10px;display:flex;align-items:center;gap:8px}
.sec-div-label{font-size:12px;font-weight:700}
.sec-div-line{flex:1;height:1px;background:#21262d}
.empty{text-align:center;padding:56px 24px;color:#6e7681}
.empty-icon{font-size:32px;margin-bottom:12px}
.empty-text{font-size:14px}
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:#0d1117}
::-webkit-scrollbar-thumb{background:#30363d;border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:#484f58}
.rep-cards{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:20px}
.rep-card{background:#161b22;border:1px solid #21262d;border-radius:10px;padding:24px;text-align:center;transition:all .2s}
.rep-card:hover{border-color:#58a6ff;background:#1c2128;transform:translateY(-2px);box-shadow:0 4px 20px rgba(88,166,255,.1)}
.rep-icon{font-size:34px;margin-bottom:12px}
.rep-title{font-size:15px;font-weight:700;color:#e6edf3;margin-bottom:8px}
.rep-desc{font-size:13px;color:#8b949e;line-height:1.6;margin-bottom:14px}
.rep-audience{font-size:10px;color:#58a6ff;font-weight:600;text-transform:uppercase;letter-spacing:.5px;padding:3px 10px;background:#1f3358;border-radius:10px;display:inline-block}
.rep-btn{background:#1f3358;border:1px solid #1f4480;color:#58a6ff;padding:9px 0;border-radius:6px;cursor:pointer;font-size:13px;font-weight:600;margin-top:14px;width:100%;transition:all .1s;display:block}
.rep-btn:hover{background:#58a6ff;border-color:#58a6ff;color:#fff}
.rep-note{font-size:12px;color:#484f58;text-align:center;margin-top:16px}
.search-input{width:100%;padding:8px 12px;background:#161b22;border:1px solid #30363d;border-radius:6px;color:#c9d1d9;font-size:13px;margin-bottom:10px;outline:none;transition:border-color .1s}
.search-input:focus{border-color:#58a6ff}
.search-input::placeholder{color:#484f58}
.stat-card[onclick]{cursor:pointer;transition:background .12s}
.stat-card[onclick]:hover{background:#1c2128}
.scan-form{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:22px;margin-bottom:16px}
.form-row{display:flex;align-items:center;gap:12px;margin-bottom:14px}
.form-label{font-size:12px;color:#6e7681;width:80px;flex-shrink:0;text-align:right;font-weight:500}
.form-input,.form-select{background:#0d1117;border:1px solid #30363d;color:#c9d1d9;padding:7px 10px;border-radius:5px;font-size:13px;flex:1;outline:none;transition:border-color .1s}
.form-input:focus,.form-select:focus{border-color:#58a6ff}
.run-btn{background:#1f3358;border:1px solid #1f4480;color:#58a6ff;padding:9px 22px;border-radius:6px;cursor:pointer;font-size:13px;font-weight:700;transition:all .12s}
.run-btn:hover{background:#58a6ff;border-color:#58a6ff;color:#fff}
.run-btn:disabled{background:#21262d;border-color:#30363d;color:#484f58;cursor:not-allowed}
.scan-term{background:#010409;border:1px solid #21262d;border-radius:8px;padding:16px;min-height:180px;max-height:420px;overflow-y:auto;font-family:'SFMono-Regular','Consolas',monospace;font-size:12px;line-height:1.7;color:#8b949e;margin-bottom:12px;white-space:pre-wrap}
.t-ok{color:#3fb950}.t-err{color:#f85149}.t-warn{color:#d29922}
.scan-done{display:flex;align-items:center;gap:12px;padding:12px 16px;background:#0d2d1a;border:1px solid #3fb950;border-radius:6px;margin-top:8px}
.scan-err-banner{padding:12px 16px;background:#3d1212;border:1px solid #f85149;border-radius:6px;margin-top:8px;color:#f85149;font-size:13px}
.reload-btn{background:#3fb950;border:none;color:#000;padding:6px 16px;border-radius:5px;cursor:pointer;font-size:12px;font-weight:700;margin-left:auto}
.server-notice{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:48px;text-align:center}
.radio-group{display:flex;gap:18px;align-items:center}
.radio-opt{display:flex;align-items:center;gap:6px;cursor:pointer;font-size:13px;color:#c9d1d9}
.radio-opt input{accent-color:#58a6ff;cursor:pointer}
"""

_JS = r"""
const CATS=['AI-DEPLOY','AI-INP','AI-OUT','AI-AGENT','AI-SUPPLY','AI-GOV'];
const CAT_LBL={'AI-DEPLOY':'Deployment Security','AI-INP':'Input Safety','AI-OUT':'Output Safety','AI-AGENT':'Agentic Safety','AI-SUPPLY':'Supply Chain','AI-GOV':'Governance'};
const SEV_ORD={CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3};
const STAT_ORD={FAIL:0,WARN:1,PASS:2,SKIP:3};
let curProv=0,curFilter='all',curCat='all',curSearch='',curSev='all',showDisagreementsOnly=false;
let _simFixed=new Set();

function esc(s){if(!s)return'';return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

function init(){
  const m=DATA.meta||{};
  document.getElementById('hdr-target').textContent=m.target||'';
  document.getElementById('hdr-date').textContent=m.scan_date||'';
  const _fwLabels={fedramp:'NIST 800-53',cmmc:'CMMC Level 2'};
  const _fwLabel=_fwLabels[m.profile_framework]||'';
  document.getElementById('hdr-profile').textContent=(m.profile||'')+(_fwLabel?' · '+_fwLabel:'');
  document.querySelectorAll('.nav-item').forEach(el=>{
    el.addEventListener('click',()=>{
      document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));
      el.classList.add('active');
      const v=el.dataset.view;
      document.querySelectorAll('.view').forEach(x=>x.classList.remove('active'));
      document.getElementById('view-'+v).classList.add('active');
      renderView(v);
    });
  });
  renderView('overview');
}

function renderView(v){
  switch(v){
    case'overview':renderOverview();break;
    case'findings':renderFindings();break;
    case'probes':renderProbes();break;
    case'compare':renderCompare();break;
    case'remediation':renderRemediation();break;
    case'reports':renderReports();break;
    case'scan':renderScan();break;
    case'heatmap':renderHeatMap();break;
    case'coverage':renderCoverage();break;
    case'simulator':renderSimulator();break;
  }
}

function provBar(view){
  if(DATA.providers.length<=1)return'';
  const btns=DATA.providers.map((p,i)=>
    `<button class="pbtn${i===curProv?' active':''}" onclick="selProv(${i},'${view}')">${esc(p.label)}</button>`
  ).join('');
  return`<div class="provider-bar"><span class="pbar-label">Provider:</span>${btns}</div>`;
}

function selProv(i,view){curProv=i;renderView(view);}

function goFindings(flt){curFilter=flt;curCat='all';curSearch='';document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));document.querySelector('.nav-item[data-view="findings"]').classList.add('active');document.querySelectorAll('.view').forEach(x=>x.classList.remove('active'));document.getElementById('view-findings').classList.add('active');renderFindings();}

function isDisagreement(id){const statuses=DATA.providers.map(p=>{const f=p.findings.find(x=>x.check_id===id);return f?f.status:'—';});return new Set(statuses).size>1;}
function toggleDisagreements(){showDisagreementsOnly=!showDisagreementsOnly;renderCompare();}

function riskInfo(s){
  const ratio=s.total_evaluated>0?s.fail/s.total_evaluated:0;
  const score=Math.round(ratio*100);
  if(s.has_critical_fail)return{cls:'c-red',label:'Critical Risk',score:Math.max(score,65)};
  if(s.fail>5)return{cls:'c-orange',label:'High Risk',score:Math.max(score,40)};
  if(s.fail>0)return{cls:'c-yellow',label:'Medium Risk',score:Math.max(score,20)};
  if(s.warn>0)return{cls:'c-yellow',label:'Low Risk',score:15};
  return{cls:'c-green',label:'Minimal Risk',score:5};
}

function renderOverview(){
  const p=DATA.providers[curProv];
  const s=p.summary;
  const risk=riskInfo(s);
  const probes=p.findings.filter(f=>f.evidence&&f.evidence.some(e=>e.includes&&e.includes("Probe '")));
  const pPass=probes.filter(f=>f.status==='PASS').length;
  const pFail=probes.filter(f=>f.status==='FAIL'&&f.evidence.some(e=>e.includes("canary")||e.includes("succeeded"))).length;
  const pSkip=p.findings.filter(f=>f.status==='SKIP').length;

  const catData={};
  CATS.forEach(c=>{catData[c]={fail:0,warn:0,pass:0,skip:0,total:0};});
  p.findings.forEach(f=>{const c=f.category;if(catData[c]){catData[c][f.status.toLowerCase()]++;catData[c].total++;}});

  const catCards=CATS.map(c=>{
    const d=catData[c];if(!d||d.total===0)return'';
    const t=d.total;
    const fw=(d.fail/t*100).toFixed(1),ww=(d.warn/t*100).toFixed(1),pw=(d.pass/t*100).toFixed(1),sw=(d.skip/t*100).toFixed(1);
    const parts=[];
    if(d.fail)parts.push(`<span class="c-red">${d.fail} fail</span>`);
    if(d.warn)parts.push(`<span class="c-yellow">${d.warn} warn</span>`);
    if(d.pass)parts.push(`<span class="c-green">${d.pass} pass</span>`);
    if(d.skip)parts.push(`<span class="c-gray">${d.skip} skip</span>`);
    return`<div class="cat-card">
      <div class="cat-head"><div class="cat-name">${CAT_LBL[c]||c}</div><div class="cat-counts">${parts.join(' · ')}</div></div>
      <div class="bar-track">
        <div class="bar-seg fail" style="width:${fw}%"></div>
        <div class="bar-seg warn" style="width:${ww}%"></div>
        <div class="bar-seg pass" style="width:${pw}%"></div>
        <div class="bar-seg skip" style="width:${sw}%"></div>
      </div>
      <div class="cat-legend">
        <div class="leg-item"><div class="leg-dot fail"></div>${d.fail} fail</div>
        <div class="leg-item"><div class="leg-dot warn"></div>${d.warn} warn</div>
        <div class="leg-item"><div class="leg-dot pass"></div>${d.pass} pass</div>
        <div class="leg-item"><div class="leg-dot skip"></div>${d.skip} skip</div>
      </div>
    </div>`;
  }).join('');

  const critCount=p.findings.filter(f=>f.status==='FAIL'&&f.severity==='CRITICAL').length;
  const highCount=p.findings.filter(f=>f.status==='FAIL'&&f.severity==='HIGH').length;
  const medCount=p.findings.filter(f=>f.status==='FAIL'&&f.severity==='MEDIUM').length;
  const sevBrk=[critCount?`<span class="c-red">${critCount} crit</span>`:'',highCount?`<span class="c-orange">${highCount} high</span>`:'',medCount?`<span class="c-yellow">${medCount} med</span>`:''].filter(Boolean).join(' · ');
  document.getElementById('view-overview').innerHTML=`
    ${provBar('overview')}
    <div class="risk-row">
      <div class="risk-card">
        <div class="risk-score ${risk.cls}">${risk.score}</div>
        <div class="risk-info">
          <div class="risk-label">${risk.label}</div>
          <div class="risk-desc">${s.fail} failing check${s.fail!==1?'s':''} · ${s.warn} warning${s.warn!==1?'s':''} · ${s.total_evaluated} controls evaluated</div>
        </div>
      </div>
      <div class="probe-card">
        <div class="probe-title">Live Probe Results</div>
        <div class="probe-stats">
          <div class="probe-stat"><div class="probe-num c-green">${pPass}</div><div class="probe-lbl">Passed</div></div>
          <div class="probe-stat"><div class="probe-num c-red">${pFail}</div><div class="probe-lbl">Failed</div></div>
          <div class="probe-stat"><div class="probe-num c-gray">${pSkip}</div><div class="probe-lbl">Skipped</div></div>
        </div>
      </div>
    </div>
    <div class="stat-grid">
      <div class="stat-card t-red" onclick="goFindings('fail')"><div class="stat-num c-red">${s.fail}</div><div class="stat-label">Failing</div>${sevBrk?`<div class="stat-sub" style="font-size:10px">${sevBrk}</div>`:''}</div>
      <div class="stat-card t-yellow" onclick="goFindings('warn')"><div class="stat-num c-yellow">${s.warn}</div><div class="stat-label">Warnings</div></div>
      <div class="stat-card t-green" onclick="goFindings('pass')"><div class="stat-num c-green">${s.pass}</div><div class="stat-label">Passing</div></div>
      <div class="stat-card t-gray"><div class="stat-num c-gray">${s.skip}</div><div class="stat-label">Not Evaluated</div><div class="stat-sub c-gray" style="font-size:10px">requires agent env</div></div>
    </div>
    <div class="sec-hdr">Security Posture by Category</div>
    <div class="cat-grid">${catCards}</div>`;
}

function renderFindings(){
  const p=DATA.providers[curProv];
  const fbtns=['all','critical','fail','warn','pass','skip'].map(s=>{
    const lbl=s==='all'?'All':s.toUpperCase();
    return`<button class="fbtn f-${s}${curFilter===s?' on':''}" onclick="setFlt('${s}')">${lbl}</button>`;
  }).join('');
  const cbtns=['all',...CATS].map(c=>{
    const lbl=c==='all'?'All Categories':(CAT_LBL[c]||c);
    return`<button class="fbtn${curCat===c?' on f-all':''}" onclick="setCat('${c}')">${lbl}</button>`;
  }).join('');

  let findings=[...p.findings].sort((a,b)=>{
    const sd=(STAT_ORD[a.status]??3)-(STAT_ORD[b.status]??3);
    if(sd!==0)return sd;
    return(SEV_ORD[a.severity]??3)-(SEV_ORD[b.severity]??3);
  });
  if(curFilter==='critical')findings=findings.filter(f=>f.severity==='CRITICAL'&&f.status==='FAIL');
  else if(curFilter!=='all')findings=findings.filter(f=>f.status.toLowerCase()===curFilter);
  if(curCat!=='all')findings=findings.filter(f=>f.category===curCat);
  if(curSev!=='all')findings=findings.filter(f=>f.severity===curSev);
  if(curSearch){const q=curSearch.toLowerCase();findings=findings.filter(f=>(f.title||'').toLowerCase().includes(q)||(f.check_id||'').toLowerCase().includes(q)||(f.category||'').toLowerCase().includes(q)||(f.details||'').toLowerCase().includes(q));}

  const rows=findings.map((f,i)=>{
    const sl=f.severity.toLowerCase(),stl=f.status.toLowerCase();
    const evHtml=(f.evidence||[]).map(e=>`<li class="ev-item">${esc(e)}</li>`).join('');
    const remHtml=(f.remediation||'').split('\n').filter(Boolean).map(s=>`<div class="rem-step">${esc(s)}</div>`).join('');
    const fwHtml=Object.entries(f.frameworks||{}).map(([k,v])=>`<span class="fw-tag">${esc(k)}: ${esc(v)}</span>`).join('');
    const ctrlHtml=(f.emphasis_controls||[]).map(c=>`<span class="ctrl-tag">${esc(c)}</span>`).join('');
    const ctrlLabel={fedramp:'NIST 800-53',cmmc:'CMMC Practices'}[(DATA.meta||{}).profile_framework]||'Controls';
    return`<div class="finding" id="f${i}">
      <div class="fhdr" onclick="togF(${i})">
        <div class="find-ind ${sl}"></div>
        <span class="sev-badge ${sl}">${esc(f.severity)}</span>
        <span class="stat-badge ${stl}">${esc(f.status)}</span>
        <span class="find-id">${esc(f.check_id)}</span>
        <span class="find-title">${esc(f.title)}</span>
        <span class="find-cat">${esc(f.category)}</span>
        <span class="find-chev">▶</span>
      </div>
      <div class="fbody">
        <div class="find-details">${esc(f.details)}</div>
        ${evHtml?`<div class="sub-lbl">Evidence</div><ul class="ev-list">${evHtml}</ul>`:''}
        ${remHtml?`<div class="sub-lbl">How to Fix</div><div class="rem-steps">${remHtml}</div>`:''}
        ${fwHtml?`<div class="sub-lbl">Framework Mappings</div><div class="fw-tags">${fwHtml}</div>`:''}
        ${ctrlHtml?`<div class="sub-lbl">${esc(ctrlLabel)}</div><div class="ctrl-tags">${ctrlHtml}</div>`:''}
      </div>
    </div>`;
  }).join('');

  document.getElementById('view-findings').innerHTML=`
    ${provBar('findings')}
    <input id="findings-search" class="search-input" type="text" placeholder="Search by title, ID, category, or details…" value="${esc(curSearch)}" oninput="setSearch(this.value)">
    <div class="filter-bar">${fbtns}</div>
    <div class="filter-bar">${cbtns}</div>
    <div class="findings-list">${rows||'<div class="empty"><div class="empty-icon">✓</div><div class="empty-text">No findings match this filter.</div></div>'}</div>`;
  const si=document.getElementById('findings-search');
  if(si&&curSearch){si.focus();si.setSelectionRange(curSearch.length,curSearch.length);}
}

function setFlt(f){curFilter=f;curSev='all';renderFindings();}
function setCat(c){curCat=c;renderFindings();}
function setSearch(v){curSearch=v;renderFindings();}
function togF(i){document.getElementById('f'+i).classList.toggle('open');}

function renderProbes(){
  const p=DATA.providers[curProv];
  const probeFindings=p.findings.filter(f=>f.evidence&&f.evidence.some(e=>typeof e==='string'&&e.includes("Probe '")));
  if(!probeFindings.length){
    document.getElementById('view-probes').innerHTML=`
      ${provBar('probes')}
      <div class="empty"><div class="empty-icon">⏭</div><div class="empty-text">No live probe data — scanned in config-only mode.</div></div>`;
    return;
  }
  const rows=[];
  probeFindings.forEach(f=>{
    const probeEvs=(f.evidence||[]).filter(e=>typeof e==='string'&&e.includes("Probe '"));
    if(probeEvs.length){
      probeEvs.forEach(ev=>{
        const passed=f.status==='PASS'||(ev.includes('rejected')||ev.includes('no canary')||ev.includes('refused'));
        const failed=f.status==='FAIL'&&(ev.includes('canary')||ev.includes('succeeded')||ev.includes('SENTINEL_'));
        rows.push({id:f.check_id,title:f.title,ev,passed,failed,status:f.status});
      });
    } else {
      rows.push({id:f.check_id,title:f.title,ev:(f.evidence||[]).join(' | '),passed:f.status==='PASS',failed:f.status==='FAIL',status:f.status});
    }
  });
  const trs=rows.map(r=>{
    const cls=r.passed?'p-pass':r.failed?'p-fail':'p-skip';
    const txt=r.passed?'✅ PASS':r.failed?'❌ FAIL':r.status;
    return`<tr><td><code>${esc(r.id)}</code></td><td>${esc(r.title)}</td><td class="${cls}">${txt}</td><td class="p-ev">${esc(r.ev)}</td></tr>`;
  }).join('');
  document.getElementById('view-probes').innerHTML=`
    ${provBar('probes')}
    <div class="sec-hdr">Live Adversarial Probe Results</div>
    <table class="probe-table">
      <thead><tr><th>Check</th><th>Description</th><th>Result</th><th>Evidence</th></tr></thead>
      <tbody>${trs}</tbody>
    </table>`;
}

function renderCompare(){
  if(DATA.providers.length<=1){
    document.getElementById('view-compare').innerHTML=`
      <div class="empty"><div class="empty-icon">⊞</div><div class="empty-text">Compare view requires multiple providers.<br>Run with the demo script to scan multiple providers at once.</div></div>`;
    return;
  }
  const checkMeta={};
  DATA.providers.forEach(p=>p.findings.forEach(f=>{
    if(!checkMeta[f.check_id])checkMeta[f.check_id]={title:f.title,cat:f.category};
  }));
  const allIds=Object.keys(checkMeta).sort();
  const disagreementCount=allIds.filter(id=>isDisagreement(id)).length;
  const hdrCols=DATA.providers.map(p=>`<th>${esc(p.label)}</th>`).join('');
  let html='';
  CATS.forEach(cat=>{
    const ids=allIds.filter(id=>checkMeta[id]&&checkMeta[id].cat===cat);
    const visIds=showDisagreementsOnly?ids.filter(id=>isDisagreement(id)):ids;
    if(!visIds.length)return;
    html+=`<tr class="cat-row"><td colspan="${DATA.providers.length+1}">${CAT_LBL[cat]||cat}</td></tr>`;
    visIds.forEach(id=>{
      const m=checkMeta[id];
      const cells=DATA.providers.map(p=>{
        const f=p.findings.find(x=>x.check_id===id);
        if(!f)return'<td>—</td>';
        const s=f.status.toLowerCase();
        return`<td><span class="cmp-cell ${s}">${f.status}</span></td>`;
      }).join('');
      html+=`<tr><td><div class="cmp-id">${esc(id)}</div><div class="cmp-name">${esc(m.title)}</div></td>${cells}</tr>`;
    });
  });
  document.getElementById('view-compare').innerHTML=`
    <div class="sec-hdr" style="justify-content:space-between">
      <span>Provider × Control Matrix</span>
      <div style="display:flex;align-items:center;gap:10px">
        <span style="font-size:11px;color:#6e7681">${disagreementCount} disagreement${disagreementCount!==1?'s':''}</span>
        <button class="pbtn${showDisagreementsOnly?' active':''}" onclick="toggleDisagreements()">Disagreements only</button>
      </div>
    </div>
    <div class="cmp-wrap"><table class="cmp-table">
      <thead><tr><th>Check</th>${hdrCols}</tr></thead>
      <tbody>${html||'<tr><td colspan="'+(DATA.providers.length+1)+'" style="text-align:center;padding:24px;color:#6e7681">No disagreements found — all providers agree on every check.</td></tr>'}</tbody>
    </table></div>`;
}

function renderRemediation(){
  const p=DATA.providers[curProv];
  const fails=p.findings.filter(f=>f.status==='FAIL'&&f.remediation)
    .sort((a,b)=>(SEV_ORD[a.severity]??3)-(SEV_ORD[b.severity]??3));
  if(!fails.length){
    document.getElementById('view-remediation').innerHTML=`
      ${provBar('remediation')}
      <div class="empty"><div class="empty-icon">✓</div><div class="empty-text">No failing checks — nothing to remediate.</div></div>`;
    return;
  }
  const groups={CRITICAL:[],HIGH:[],MEDIUM:[],LOW:[]};
  fails.forEach(f=>{(groups[f.severity]||groups.LOW).push(f);});
  const sevColors={CRITICAL:'#f85149',HIGH:'#f0883e',MEDIUM:'#d29922',LOW:'#388bfd'};
  let html='';
  Object.entries(groups).forEach(([sev,items])=>{
    if(!items.length)return;
    const sl=sev.toLowerCase();
    html+=`<div class="sec-div"><span class="sec-div-label" style="color:${sevColors[sev]}">${sev} (${items.length})</span><div class="sec-div-line"></div></div>`;
    items.forEach(f=>{
      html+=`<div class="rem-item ${sl}">
        <div class="rem-id ${sl}">${esc(f.check_id)}</div>
        <div class="rem-body">
          <div class="rem-title">${esc(f.title)}</div>
          <div class="rem-text">${esc(f.remediation)}</div>
        </div>
      </div>`;
    });
  });
  document.getElementById('view-remediation').innerHTML=`
    ${provBar('remediation')}
    <div class="sec-hdr">Prioritized Remediation Queue — ${fails.length} Actions</div>
    <div class="rem-queue">${html}</div>`;
}

function renderReports(){
  document.getElementById('view-reports').innerHTML=`
    ${provBar('reports')}
    <div class="sec-hdr">Generate Report</div>
    <div class="rep-cards">
      <div class="rep-card">
        <div class="rep-icon">📋</div>
        <div class="rep-title">Executive Report</div>
        <div class="rep-desc">Plain-language risk summary, business impact, and recommended actions. Zero technical jargon — written for decision makers.</div>
        <div class="rep-audience">CEO · Board · Business Owner</div>
        <button class="rep-btn" onclick="openReport('exec')">Generate Report →</button>
      </div>
      <div class="rep-card">
        <div class="rep-icon">🛡️</div>
        <div class="rep-title">CISO Report</div>
        <div class="rep-desc">Risk posture by category, framework alignment, provider comparison, governance gaps, and a phased remediation roadmap.</div>
        <div class="rep-audience">CISO · VP Security · Compliance</div>
        <button class="rep-btn" onclick="openReport('ciso')">Generate Report →</button>
      </div>
      <div class="rep-card">
        <div class="rep-icon">🔍</div>
        <div class="rep-title">Analyst Report</div>
        <div class="rep-desc">Full technical findings with file-level evidence, step-by-step remediation commands, probe results, and control mappings.</div>
        <div class="rep-audience">Security Engineer · DevSecOps · Auditor</div>
        <button class="rep-btn" onclick="openReport('analyst')">Generate Report →</button>
      </div>
    </div>
    <div class="rep-note">Each report opens in a new tab — use Ctrl+P / Cmd+P to save as PDF</div>`;
}

function openReport(type){
  const p=DATA.providers[curProv];
  const html=type==='exec'?buildExecReport(p):type==='ciso'?buildCISOReport(p):buildAnalystReport(p);
  const w=window.open('','_blank');
  w.document.write(html);
  w.document.close();
}

const BIZ_RISK={
  'AI-DEPLOY-001':'Your AI credentials are exposed in code — anyone who finds them can use your AI services at your expense and access your data.',
  'AI-DEPLOY-002':'Database passwords are stored in plain text — an attacker who reads your config files can take over your database.',
  'AI-DEPLOY-003':'There is no record of what your AI is doing — if something goes wrong you have nothing to investigate with.',
  'AI-DEPLOY-004':'Your AI service has no access controls — anyone who can reach your server can use it without a password.',
  'AI-DEPLOY-005':'AI traffic is not encrypted — sensitive conversations and business data could be intercepted in transit.',
  'AI-DEPLOY-006':'There are no usage limits on your AI — a script error or bad actor could exhaust your entire budget in minutes.',
  'AI-INP-001':'Your AI can be tricked into ignoring its rules — a crafted message can make it behave as if it has no restrictions.',
  'AI-INP-002':'Your AI accepted malicious instructions hidden in user input — an attacker can hijack its behavior.',
  'AI-INP-004':'A jailbreak attempt succeeded — a crafted prompt convinced your AI to operate without its safety restrictions.',
  'AI-GOV-001':'You have no documented AI usage policy — there is no basis for enforcement or compliance evidence.',
  'AI-GOV-002':'No data retention policy covers AI interactions — you may be in violation of GDPR, HIPAA, or CCPA.',
  'AI-GOV-003':'You have no AI incident response plan — if something goes wrong there is no documented path forward.',
  'AI-GOV-005':'Your AI system is not in any asset inventory — it cannot be managed, monitored, or secured if it is not tracked.',
  'AI-SUPPLY-005':'Your AI model version is not pinned — the model could change behavior overnight without your knowledge.',
};

function rptCSS(){return `<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;color:#1a1a1a;background:#fff;font-size:14px;line-height:1.6}
.page{max-width:820px;margin:0 auto;padding:48px 48px 80px}
.rpt-hdr{display:flex;justify-content:space-between;align-items:flex-start;padding-bottom:20px;border-bottom:3px solid #1a1a2e;margin-bottom:32px}
.rpt-brand{font-size:10px;letter-spacing:3px;color:#1a1a2e;font-weight:800;text-transform:uppercase}
.rpt-brand-name{font-size:22px;font-weight:900;color:#1a1a2e;margin-top:2px}
.rpt-type{font-size:13px;color:#6b7280;margin-top:4px}
.rpt-meta{text-align:right;font-size:12px;color:#6b7280;line-height:1.9}
h1{font-size:26px;font-weight:800;color:#1a1a2e;margin-bottom:8px}
h2{font-size:16px;font-weight:700;color:#1a1a2e;margin:28px 0 10px;padding-bottom:6px;border-bottom:1px solid #e5e7eb}
h3{font-size:13px;font-weight:700;color:#374151;margin:14px 0 6px}
p{color:#374151;margin-bottom:10px}
.risk-banner{padding:18px 22px;border-radius:8px;margin:20px 0;display:flex;align-items:center;gap:20px}
.risk-banner.red{background:#fef2f2;border:2px solid #dc2626}
.risk-banner.orange{background:#fff7ed;border:2px solid #ea580c}
.risk-banner.yellow{background:#fefce8;border:2px solid #ca8a04}
.risk-banner.green{background:#f0fdf4;border:2px solid #16a34a}
.rscore{font-size:44px;font-weight:900;line-height:1}
.rscore.red{color:#dc2626}.rscore.orange{color:#ea580c}.rscore.yellow{color:#ca8a04}.rscore.green{color:#16a34a}
.rlabel{font-size:19px;font-weight:800}
.rdesc{font-size:13px;color:#6b7280;margin-top:3px}
table{width:100%;border-collapse:collapse;margin:10px 0 16px;font-size:13px}
th{background:#1a1a2e;color:#fff;padding:9px 12px;text-align:left;font-size:11px;font-weight:700;letter-spacing:.4px;text-transform:uppercase}
td{padding:9px 12px;border-bottom:1px solid #e5e7eb;vertical-align:top}
tr:nth-child(even) td{background:#f9fafb}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.3px}
.badge.critical{background:#fee2e2;color:#dc2626}
.badge.high{background:#ffedd5;color:#ea580c}
.badge.medium{background:#fef9c3;color:#ca8a04}
.badge.low{background:#dbeafe;color:#2563eb}
.badge.pass{background:#dcfce7;color:#16a34a}
.badge.warn{background:#fef9c3;color:#ca8a04}
.badge.fail{background:#fee2e2;color:#dc2626}
.badge.skip{background:#f3f4f6;color:#6b7280}
ul,ol{padding-left:20px;margin:8px 0 12px}
li{margin-bottom:6px;color:#374151}
.stat-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:16px 0}
.sbox{background:#f9fafb;border:1px solid #e5e7eb;border-radius:8px;padding:12px;text-align:center}
.sbox-num{font-size:28px;font-weight:800}
.sbox-lbl{font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:.5px;margin-top:3px}
.frow{border:1px solid #e5e7eb;border-radius:6px;margin-bottom:10px;overflow:hidden;page-break-inside:avoid}
.frow-hdr{padding:10px 14px;display:flex;align-items:center;gap:8px;background:#f9fafb;border-bottom:1px solid #e5e7eb;flex-wrap:wrap}
.frow-body{padding:12px 14px}
.ev-box{background:#f3f4f6;border-left:3px solid #d1d5db;padding:7px 10px;font-family:monospace;font-size:12px;color:#374151;margin:5px 0;border-radius:0 4px 4px 0;word-break:break-all}
.rem-box{background:#f0fdf4;border-left:3px solid #16a34a;padding:10px 14px;border-radius:0 4px 4px 0;margin:8px 0}
.rem-box p{color:#166534;font-size:13px;margin-bottom:3px}
.section-intro{color:#6b7280;font-size:13px;margin-bottom:12px}
.rpt-footer{margin-top:48px;padding-top:14px;border-top:1px solid #e5e7eb;font-size:11px;color:#9ca3af;display:flex;justify-content:space-between}
code{background:#f3f4f6;padding:1px 5px;border-radius:3px;font-size:12px}
@media print{.page{padding:24px}body{font-size:12px}.frow{page-break-inside:avoid}}
</style>`;}

function _riskBannerClass(riskCls){
  return riskCls==='c-red'?'red':riskCls==='c-orange'?'orange':riskCls==='c-yellow'?'yellow':'green';
}
function _riskColor(riskCls){
  return riskCls==='c-red'?'#dc2626':riskCls==='c-orange'?'#ea580c':riskCls==='c-yellow'?'#ca8a04':'#16a34a';
}

function buildExecReport(p){
  const s=p.summary,d=DATA.meta||{},risk=riskInfo(s);
  const bc=_riskBannerClass(risk.cls),rc=_riskColor(risk.cls);
  const crits=p.findings.filter(f=>f.status==='FAIL'&&f.severity==='CRITICAL');
  const highs=p.findings.filter(f=>f.status==='FAIL'&&f.severity==='HIGH');
  const fails=p.findings.filter(f=>f.status==='FAIL');
  const rows=fails.slice(0,7).map(f=>{
    const biz=BIZ_RISK[f.check_id]||f.details;
    const step=(f.remediation||'').split('\n').filter(Boolean)[0]||'See detailed report';
    return`<tr><td><strong>${esc(f.title)}</strong><br><span style="color:#6b7280;font-size:12px">${esc(biz)}</span></td><td style="text-align:center"><span class="badge ${f.severity.toLowerCase()}">${esc(f.severity)}</span></td><td style="font-size:12px">${esc(step)}</td></tr>`;
  }).join('');
  const passing=p.findings.filter(f=>f.status==='PASS').map(f=>`<li>${esc(f.title)}</li>`).join('');
  return`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Executive Report — M.A.R.K. Sentinel</title>${rptCSS()}</head><body>
<div class="page">
  <div class="rpt-hdr">
    <div><div class="rpt-brand">M.A.R.K. Sentinel</div><div class="rpt-brand-name">SENTINEL</div><div class="rpt-type">Executive Security Report</div></div>
    <div class="rpt-meta"><strong>Target:</strong> ${esc((d.target||'').split('/').pop()||d.target||'')}<br><strong>Provider:</strong> ${esc(p.label)}<br><strong>Date:</strong> ${esc(d.scan_date||new Date().toLocaleDateString())}<br><strong>Profile:</strong> ${esc(d.profile||'')}${d.profile_framework?` · ${esc({fedramp:'NIST 800-53',cmmc:'CMMC Level 2'}[d.profile_framework]||d.profile_framework)}`:''}</div>
  </div>
  <h1>AI Security Assessment</h1>
  <p>We audited your AI deployment and evaluated ${s.total_evaluated} security controls. Here is what we found and what needs to happen next.</p>
  <div class="risk-banner ${bc}"><div class="rscore ${bc}">${risk.score}</div>
    <div><div class="rlabel" style="color:${rc}">${risk.label}</div>
    <div class="rdesc">${s.fail} issue${s.fail!==1?'s':''} require attention${crits.length?' — including '+crits.length+' critical risk'+(crits.length!==1?'s':'')+' requiring immediate action':' — none are critical'}</div></div>
  </div>
  <div class="stat-grid">
    <div class="sbox"><div class="sbox-num" style="color:#dc2626">${s.fail}</div><div class="sbox-lbl">Issues</div></div>
    <div class="sbox"><div class="sbox-num" style="color:#ca8a04">${s.warn}</div><div class="sbox-lbl">Warnings</div></div>
    <div class="sbox"><div class="sbox-num" style="color:#16a34a">${s.pass}</div><div class="sbox-lbl">Passing</div></div>
    <div class="sbox"><div class="sbox-num" style="color:#6b7280">${s.skip}</div><div class="sbox-lbl">Not Tested</div></div>
  </div>
  ${rows?`<h2>Issues Found</h2><p class="section-intro">Listed from most to least severe. Each item includes the immediate action required.</p>
  <table><thead><tr><th>Issue</th><th>Severity</th><th>First Action</th></tr></thead><tbody>${rows}</tbody></table>`:'<h2>No Issues Found</h2><p>All evaluated controls passed.</p>'}
  ${passing?`<h2>What Is Working</h2><ul>${passing}</ul>`:''}
  <h2>Recommended Next Steps</h2>
  <ol>
    ${crits.length?`<li><strong>Fix ${crits.length} critical issue${crits.length!==1?'s':''} now</strong> — active risks that could result in data exposure or unauthorized access today.</li>`:''}
    ${highs.length?`<li><strong>Address ${highs.length} high-severity issue${highs.length!==1?'s':''} within 7 days</strong> — significant risks that should not remain unresolved.</li>`:''}
    <li><strong>Run a follow-up scan</strong> after fixing issues to confirm they are resolved.</li>
    <li><strong>Ensure AI governance policies are documented</strong> — usage policy, data retention, and an incident response plan.</li>
  </ol>
  <div class="rpt-footer"><span>M.A.R.K. Sentinel — Powered by Hash</span><span>Generated ${new Date().toLocaleDateString()} · Confidential</span></div>
</div></body></html>`;
}

function buildCISOReport(p){
  const s=p.summary,d=DATA.meta||{},risk=riskInfo(s);
  const bc=_riskBannerClass(risk.cls),rc=_riskColor(risk.cls);
  const CATS_L=['AI-DEPLOY','AI-INP','AI-OUT','AI-AGENT','AI-SUPPLY','AI-GOV'];
  const CAT_L={'AI-DEPLOY':'Deployment Security','AI-INP':'Input Safety','AI-OUT':'Output Safety','AI-AGENT':'Agentic Safety','AI-SUPPLY':'Supply Chain','AI-GOV':'Governance'};
  const catRows=CATS_L.map(c=>{
    const ff=p.findings.filter(f=>f.category===c);
    if(!ff.length)return'';
    const fa=ff.filter(f=>f.status==='FAIL').length,wa=ff.filter(f=>f.status==='WARN').length,pa=ff.filter(f=>f.status==='PASS').length,sk=ff.filter(f=>f.status==='SKIP').length;
    const hasCrit=ff.some(f=>f.status==='FAIL'&&f.severity==='CRITICAL');
    const st=fa>0?(hasCrit?'<span class="badge critical">CRITICAL</span>':'<span class="badge fail">FAIL</span>'):wa>0?'<span class="badge warn">WARN</span>':'<span class="badge pass">PASS</span>';
    return`<tr><td><strong>${CAT_L[c]||c}</strong></td><td>${st}</td><td style="color:#dc2626;text-align:center">${fa}</td><td style="color:#ca8a04;text-align:center">${wa}</td><td style="color:#16a34a;text-align:center">${pa}</td><td style="color:#6b7280;text-align:center">${sk}</td></tr>`;
  }).join('');
  const fwMap={};
  p.findings.forEach(f=>Object.entries(f.frameworks||{}).forEach(([k,v])=>{if(!fwMap[k])fwMap[k]=new Set();v.split(',').forEach(x=>fwMap[k].add(x.trim()));}));
  const _emph=(DATA.meta||{}).profile_framework;
  if(_emph){const _el={fedramp:'NIST 800-53',cmmc:'CMMC Level 2'}[_emph];if(_el){if(!fwMap[_el])fwMap[_el]=new Set();p.findings.forEach(f=>(f.emphasis_controls||[]).forEach(c=>fwMap[_el].add(c)));}}
  const fwRows=Object.entries(fwMap).map(([k,v])=>`<tr><td><strong>${esc(k)}</strong></td><td style="font-family:monospace;font-size:12px">${[...v].sort().join(', ')}</td></tr>`).join('');
  const critHigh=p.findings.filter(f=>f.status==='FAIL'&&(f.severity==='CRITICAL'||f.severity==='HIGH'));
  const chRows=critHigh.map(f=>`<tr><td style="font-family:monospace;font-size:12px">${esc(f.check_id)}</td><td><span class="badge ${f.severity.toLowerCase()}">${f.severity}</span></td><td>${esc(f.title)}</td><td style="font-size:12px;color:#6b7280">${esc((f.evidence||[])[0]||'')}</td></tr>`).join('');
  const govGaps=p.findings.filter(f=>f.category==='AI-GOV'&&(f.status==='FAIL'||f.status==='WARN'));
  const govRows=govGaps.map(f=>`<tr><td style="font-family:monospace;font-size:12px">${esc(f.check_id)}</td><td>${esc(f.title)}</td><td><span class="badge ${f.status.toLowerCase()}">${f.status}</span></td><td style="font-size:12px">${esc((f.remediation||'').split('\n')[0]||'')}</td></tr>`).join('');
  let cmpSection='';
  if(DATA.providers.length>1){
    const probeIds=['AI-INP-001','AI-INP-002','AI-INP-004','AI-OUT-001','AI-OUT-002','AI-OUT-003','AI-OUT-004'];
    const pHdrs=DATA.providers.map(pp=>`<th style="text-align:center">${esc(pp.label)}</th>`).join('');
    const pRows=probeIds.map(id=>{
      const cells=DATA.providers.map(pp=>{const f=pp.findings.find(x=>x.check_id===id);if(!f)return'<td style="text-align:center;color:#9ca3af">—</td>';return`<td style="text-align:center"><span class="badge ${f.status.toLowerCase()}">${f.status}</span></td>`;}).join('');
      return`<tr><td style="font-family:monospace;font-size:12px">${id}</td>${cells}</tr>`;
    }).join('');
    cmpSection=`<h2>Provider Comparison — Adversarial Probes</h2><p class="section-intro">Live probes run against each AI model to test real-world behavior. Different models fail different checks.</p>
    <table><thead><tr><th>Check</th>${pHdrs}</tr></thead><tbody>${pRows}</tbody></table>`;
  }
  const imm=p.findings.filter(f=>f.status==='FAIL'&&f.severity==='CRITICAL').map(f=>esc(f.title)).join('<br>')||'None';
  const sterm=p.findings.filter(f=>f.status==='FAIL'&&f.severity==='HIGH').map(f=>esc(f.title)).join('<br>')||'None';
  const mterm=p.findings.filter(f=>f.status==='FAIL'&&(f.severity==='MEDIUM'||f.severity==='LOW')).map(f=>esc(f.title)).join('<br>')||'None';
  return`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>CISO Report — M.A.R.K. Sentinel</title>${rptCSS()}</head><body>
<div class="page">
  <div class="rpt-hdr">
    <div><div class="rpt-brand">M.A.R.K. Sentinel</div><div class="rpt-brand-name">SENTINEL</div><div class="rpt-type">CISO Security Report</div></div>
    <div class="rpt-meta"><strong>Target:</strong> ${esc((d.target||'').split('/').pop()||d.target||'')}<br><strong>Provider:</strong> ${esc(p.label)}<br><strong>Date:</strong> ${esc(d.scan_date||new Date().toLocaleDateString())}<br><strong>Profile:</strong> ${esc(d.profile||'')}${d.profile_framework?` · ${esc({fedramp:'NIST 800-53',cmmc:'CMMC Level 2'}[d.profile_framework]||d.profile_framework)}`:''}</div>
  </div>
  <h1>AI Security Posture Report</h1>
  <div class="risk-banner ${bc}"><div class="rscore ${bc}">${risk.score}</div>
    <div><div class="rlabel" style="color:${rc}">${risk.label}</div>
    <div class="rdesc">${s.fail} failing · ${s.warn} warnings · ${s.pass} passing · ${s.skip} not evaluated — ${s.total_evaluated} total controls</div></div>
  </div>
  <div class="stat-grid">
    <div class="sbox"><div class="sbox-num" style="color:#dc2626">${s.fail}</div><div class="sbox-lbl">FAIL</div></div>
    <div class="sbox"><div class="sbox-num" style="color:#ca8a04">${s.warn}</div><div class="sbox-lbl">WARN</div></div>
    <div class="sbox"><div class="sbox-num" style="color:#16a34a">${s.pass}</div><div class="sbox-lbl">PASS</div></div>
    <div class="sbox"><div class="sbox-num" style="color:#6b7280">${s.skip}</div><div class="sbox-lbl">SKIP</div></div>
  </div>
  <h2>Risk Posture by Category</h2>
  <table><thead><tr><th>Category</th><th>Status</th><th style="text-align:center">FAIL</th><th style="text-align:center">WARN</th><th style="text-align:center">PASS</th><th style="text-align:center">SKIP</th></tr></thead><tbody>${catRows}</tbody></table>
  ${critHigh.length?`<h2>Critical &amp; High Findings</h2><table><thead><tr><th>Control ID</th><th>Severity</th><th>Finding</th><th>Key Evidence</th></tr></thead><tbody>${chRows}</tbody></table>`:''}
  ${govRows?`<h2>Governance &amp; Compliance Gaps</h2><table><thead><tr><th>Control</th><th>Gap</th><th>Status</th><th>First Action</th></tr></thead><tbody>${govRows}</tbody></table>`:''}
  ${cmpSection}
  <h2>Framework Alignment</h2>
  <p class="section-intro">Controls referenced across all findings mapped to applicable frameworks.</p>
  <table><thead><tr><th>Framework</th><th>Controls Referenced</th></tr></thead><tbody>${fwRows}</tbody></table>
  <h2>Remediation Roadmap</h2>
  <table><thead><tr><th>Phase</th><th>Timeframe</th><th>Actions</th></tr></thead><tbody>
    <tr><td><strong style="color:#dc2626">Immediate</strong></td><td>0–48 hours</td><td>${imm}</td></tr>
    <tr><td><strong style="color:#ea580c">Short-term</strong></td><td>7–30 days</td><td>${sterm}</td></tr>
    <tr><td><strong style="color:#ca8a04">Medium-term</strong></td><td>30–90 days</td><td>${mterm}</td></tr>
    <tr><td><strong style="color:#16a34a">Ongoing</strong></td><td>Continuous</td><td>Scheduled re-scans · Governance policy reviews · Model version monitoring</td></tr>
  </tbody></table>
  <div class="rpt-footer"><span>M.A.R.K. Sentinel — Powered by Hash</span><span>Generated ${new Date().toLocaleDateString()} · Confidential</span></div>
</div></body></html>`;
}

function buildAnalystReport(p){
  const s=p.summary,d=DATA.meta||{};
  const sorted=[...p.findings].sort((a,b)=>(STAT_ORD[a.status]??3)-(STAT_ORD[b.status]??3)||(SEV_ORD[a.severity]??3)-(SEV_ORD[b.severity]??3));
  const blocks=sorted.filter(f=>f.status!=='SKIP').map(f=>{
    const sl=f.severity.toLowerCase(),st=f.status.toLowerCase();
    const evHtml=(f.evidence||[]).map(e=>`<div class="ev-box">${esc(e)}</div>`).join('');
    const remHtml=(f.remediation||'').split('\n').filter(Boolean).map(r=>`<p>→ ${esc(r)}</p>`).join('');
    const fwHtml=Object.entries(f.frameworks||{}).map(([k,v])=>`<span class="badge" style="background:#dbeafe;color:#1e40af;margin-right:4px;margin-bottom:3px">${esc(k)}: ${esc(v)}</span>`).join('');
    const aCtrlHtml=(f.emphasis_controls||[]).map(c=>`<span class="ctrl-tag">${esc(c)}</span>`).join('');
    const aCtrlLabel={fedramp:'NIST 800-53',cmmc:'CMMC Practices'}[(DATA.meta||{}).profile_framework]||'';
    return`<div class="frow">
      <div class="frow-hdr"><span class="badge ${sl}">${esc(f.severity)}</span><span class="badge ${st}">${esc(f.status)}</span><strong style="font-family:monospace;font-size:13px">${esc(f.check_id)}</strong><span style="flex:1">${esc(f.title)}</span><span style="font-size:11px;color:#9ca3af">${esc(f.category)}</span></div>
      <div class="frow-body"><p>${esc(f.details)}</p>
        ${evHtml?`<h3>Evidence</h3>${evHtml}`:''}
        ${remHtml?`<h3>Remediation Steps</h3><div class="rem-box">${remHtml}</div>`:''}
        ${fwHtml?`<div style="margin-top:8px">${fwHtml}</div>`:''}
        ${aCtrlHtml?`<div style="margin-top:6px"><strong style="font-size:11px;color:#6b7280">${esc(aCtrlLabel)}: </strong>${aCtrlHtml}</div>`:''}
      </div>
    </div>`;
  }).join('');
  const probeFinds=p.findings.filter(f=>f.evidence&&f.evidence.some(e=>typeof e==='string'&&e.includes("Probe '")));
  const probeRows=probeFinds.flatMap(f=>{
    const pe=(f.evidence||[]).filter(e=>typeof e==='string'&&e.includes("Probe '"));
    return pe.map(ev=>{
      const passed=f.status==='PASS'||(ev.includes('rejected')||ev.includes('no canary'));
      const failed=f.status==='FAIL'&&(ev.includes('canary')||ev.includes('succeeded'));
      return`<tr><td style="font-family:monospace;font-size:12px">${esc(f.check_id)}</td><td>${esc(f.title)}</td><td style="text-align:center"><span class="badge ${passed?'pass':failed?'fail':'skip'}">${passed?'PASS':failed?'FAIL':f.status}</span></td><td style="font-family:monospace;font-size:11px;word-break:break-all;color:#6b7280">${esc(ev)}</td></tr>`;
    });
  }).join('');
  const skipRows=sorted.filter(f=>f.status==='SKIP').map(f=>`<tr><td style="font-family:monospace;font-size:12px">${esc(f.check_id)}</td><td>${esc(f.title)}</td><td style="font-size:12px;color:#6b7280">${esc(f.details||'Requires agent environment')}</td></tr>`).join('');
  return`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Analyst Report — M.A.R.K. Sentinel</title>${rptCSS()}</head><body>
<div class="page">
  <div class="rpt-hdr">
    <div><div class="rpt-brand">M.A.R.K. Sentinel</div><div class="rpt-brand-name">SENTINEL</div><div class="rpt-type">Technical Analyst Report</div></div>
    <div class="rpt-meta"><strong>Target:</strong> ${esc(d.target||'')}<br><strong>Provider:</strong> ${esc(p.label)}<br><strong>Mode:</strong> ${esc(p.mode||'')}<br><strong>Date:</strong> ${esc(d.scan_date||new Date().toLocaleDateString())}</div>
  </div>
  <h1>AI Security Audit — Technical Findings</h1>
  <p>Target: <code>${esc(d.target||'')}</code> &nbsp;|&nbsp; Mode: <code>${esc(p.mode||'')}</code> &nbsp;|&nbsp; Profile: <code>${esc(d.profile||'')}</code></p>
  <div class="stat-grid">
    <div class="sbox"><div class="sbox-num" style="color:#dc2626">${s.fail}</div><div class="sbox-lbl">FAIL</div></div>
    <div class="sbox"><div class="sbox-num" style="color:#ca8a04">${s.warn}</div><div class="sbox-lbl">WARN</div></div>
    <div class="sbox"><div class="sbox-num" style="color:#16a34a">${s.pass}</div><div class="sbox-lbl">PASS</div></div>
    <div class="sbox"><div class="sbox-num" style="color:#6b7280">${s.skip}</div><div class="sbox-lbl">SKIP</div></div>
  </div>
  <h2>Detailed Findings</h2>
  ${blocks}
  ${probeRows?`<h2>Live Probe Results</h2><table><thead><tr><th>Check</th><th>Description</th><th style="text-align:center">Result</th><th>Evidence</th></tr></thead><tbody>${probeRows}</tbody></table>`:''}
  ${skipRows?`<h2>Not Evaluated — Requires Agent Environment</h2><p class="section-intro">These checks require a deployed AI agent with active tool access and cannot be evaluated against a raw API or config scan.</p><table><thead><tr><th>Control</th><th>Check</th><th>Reason</th></tr></thead><tbody>${skipRows}</tbody></table>`:''}
  <div class="rpt-footer"><span>M.A.R.K. Sentinel — Powered by Hash</span><span>Generated ${new Date().toLocaleDateString()} · Confidential</span></div>
</div></body></html>`;
}

let scanMode='demo',_scanRunning=false,_pollTimer=null;

function _pollForServer(){
  clearTimeout(_pollTimer);
  fetch('http://localhost:7331/api/status')
    .then(r=>r.ok?window.location.replace('http://localhost:7331'):null)
    .catch(()=>{_pollTimer=setTimeout(_pollForServer,1500);});
}

function renderScan(){
  const live=window.location.protocol!=='file:';
  if(!live){
    document.getElementById('view-scan').innerHTML=`
      <div class="server-notice">
        <div style="font-size:42px;margin-bottom:16px">🚀</div>
        <div style="font-size:17px;font-weight:700;color:#e6edf3;margin-bottom:10px">Launch Sentinel</div>
        <p style="color:#8b949e;margin-bottom:22px;max-width:420px;margin-left:auto;margin-right:auto">Double-click the launcher in the project folder.<br>It starts the server and opens this dashboard automatically — no terminal needed.</p>
        <div style="background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:16px 20px;display:inline-block;margin-bottom:18px;text-align:left">
          <div style="font-size:10px;color:#484f58;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">Launcher files</div>
          <div style="margin-bottom:6px"><span style="color:#6e7681;font-size:11px;width:60px;display:inline-block">macOS</span><code style="font-size:12px;color:#58a6ff">Sentinel.app</code></div>
          <div><span style="color:#6e7681;font-size:11px;width:60px;display:inline-block">Windows</span><code style="font-size:12px;color:#58a6ff">launch_sentinel.bat</code></div>
        </div>
        <p style="color:#484f58;font-size:11px">Already running the server? <a href="http://localhost:7331" style="color:#58a6ff">Open at localhost:7331 →</a></p>
      </div>`;
    _pollForServer();
    return;
  }
  const provRow=scanMode==='single'?`
    <div class="form-row">
      <span class="form-label">Provider</span>
      <select id="scan-provider" class="form-select">
        <option value="config">Config Scan (no API key)</option>
        <option value="openai">OpenAI / gpt-4o</option>
        <option value="claude">Anthropic / claude-opus-4-7</option>
        <option value="ollama">Ollama (local)</option>
        <option value="hash-ai">Hash-AI / openclaw</option>
      </select>
    </div>`:'';
  document.getElementById('view-scan').innerHTML=`
    <div class="scan-form">
      <div class="sec-hdr" style="margin-bottom:18px">Run New Scan</div>
      <div class="form-row">
        <span class="form-label">Mode</span>
        <div class="radio-group">
          <label class="radio-opt"><input type="radio" name="smode" value="demo" ${scanMode==='demo'?'checked':''} onchange="scanMode='demo';renderScan()"> All Providers (Demo)</label>
          <label class="radio-opt"><input type="radio" name="smode" value="single" ${scanMode==='single'?'checked':''} onchange="scanMode='single';renderScan()"> Single Provider</label>
        </div>
      </div>
      <div class="form-row">
        <span class="form-label">Target</span>
        <input id="scan-target" class="form-input" type="text" value="." placeholder="Path to project (default: current directory)">
      </div>
      ${provRow}
      <div class="form-row">
        <span class="form-label">Profile</span>
        <select id="scan-profile" class="form-select">
          <option value="default">Default</option>
          <option value="fedramp">FedRAMP / NIST 800-53</option>
          <option value="cmmc">CMMC</option>
          <option value="smb">SMB</option>
        </select>
      </div>
      <div class="form-row" style="justify-content:flex-end;margin-bottom:0">
        <button class="run-btn" id="run-btn" onclick="runScan()" ${_scanRunning?'disabled':''}>
          ${_scanRunning?'⏳ Scanning…':'▶ Run Scan'}
        </button>
      </div>
    </div>
    <div id="scan-term" class="scan-term" style="${_scanRunning?'':'display:none'}"></div>
    <div id="scan-result"></div>`;
  if(_scanRunning)_attachEventStream();
}

function runScan(){
  if(_scanRunning)return;
  _scanRunning=true;
  const target=document.getElementById('scan-target')?.value?.trim()||'.';
  const profile=document.getElementById('scan-profile')?.value||'default';
  const provider=document.getElementById('scan-provider')?.value||'config';
  const term=document.getElementById('scan-term');
  if(term){term.innerHTML='';term.style.display='block';}
  document.getElementById('scan-result').innerHTML='';
  document.getElementById('run-btn').disabled=true;
  document.getElementById('run-btn').textContent='⏳ Scanning…';
  const body={mode:scanMode,target,profile,providers:scanMode==='single'?[provider]:[]};
  fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})
    .then(r=>r.json())
    .then(d=>{if(d.error){_scanFinish('error',d.error);}else{_attachEventStream();}})
    .catch(e=>{_scanFinish('error',String(e));});
}

function _attachEventStream(){
  const term=document.getElementById('scan-term');
  const es=new EventSource('/api/events');
  es.onmessage=e=>{
    const d=JSON.parse(e.data);
    if(d.t==='log'){
      if(term){
        const line=d.line;
        const cls=line.includes('[✓]')||line.includes(' PASS')?'t-ok':line.includes('[✗]')||line.includes(' FAIL')||line.toLowerCase().includes('error')?'t-err':'';
        const div=document.createElement('div');
        if(cls)div.className=cls;
        div.textContent=line;
        term.appendChild(div);
        term.scrollTop=term.scrollHeight;
      }
    } else if(d.t==='done'){
      es.close();
      _scanFinish(d.status);
    }
  };
  es.onerror=()=>{es.close();_scanFinish('error','Connection to server lost.');};
}

function _scanFinish(status,msg){
  _scanRunning=false;
  const res=document.getElementById('scan-result');
  const btn=document.getElementById('run-btn');
  if(btn){btn.disabled=false;btn.textContent='▶ Run Scan';}
  if(!res)return;
  if(status==='done'){
    res.innerHTML=`<div class="scan-done"><span class="t-ok" style="font-size:18px">✓</span><span class="t-ok" style="font-weight:700">Scan complete — results updated</span><button class="reload-btn" onclick="location.reload()">Reload Dashboard</button></div>`;
  } else {
    res.innerHTML=`<div class="scan-err-banner">⚠ Scan failed${msg?' — '+esc(msg):''}.  Check the terminal output above for details.</div>`;
  }
}

// ── Heat Map ──────────────────────────────────────────────────────────────────
function renderHeatMap(){
  const p=DATA.providers[curProv];
  const sevs=['CRITICAL','HIGH','MEDIUM','LOW'];
  const cats=['AI-DEPLOY','AI-INP','AI-OUT','AI-AGENT','AI-SUPPLY','AI-GOV'];
  const catL={'AI-DEPLOY':'Deploy','AI-INP':'Input','AI-OUT':'Output','AI-AGENT':'Agentic','AI-SUPPLY':'Supply','AI-GOV':'Govern'};
  const sevBg={CRITICAL:'#7f1d1d',HIGH:'#431407',MEDIUM:'#422006',LOW:'#1e3a5f'};
  const sevTc={CRITICAL:'#fca5a5',HIGH:'#fb923c',MEDIUM:'#fbbf24',LOW:'#93c5fd'};
  const warnBg='#2d2006',warnTc='#fbbf24';
  const passBg='#052e16',passTc='#4ade80';

  const grid={};
  for(const sev of sevs){grid[sev]={};for(const cat of cats){
    const ff=p.findings.filter(f=>f.severity===sev&&f.category===cat);
    grid[sev][cat]={fail:ff.filter(f=>f.status==='FAIL').length,warn:ff.filter(f=>f.status==='WARN').length,total:ff.length};
  }}

  const header=`<tr><th></th>${cats.map(c=>`<th>${esc(catL[c])}</th>`).join('')}</tr>`;
  const rows=sevs.map(sev=>
    `<tr><td class="heat-sev-lbl">${sev}</td>${cats.map(cat=>{
      const d=grid[sev][cat];
      if(!d.total)return`<td class="heat-empty">—</td>`;
      const hasFail=d.fail>0,hasWarn=d.warn>0;
      const bg=hasFail?sevBg[sev]:hasWarn?warnBg:passBg;
      const tc=hasFail?sevTc[sev]:hasWarn?warnTc:passTc;
      const n=hasFail?d.fail:hasWarn?d.warn:'✓';
      const lbl=hasFail?'FAIL':hasWarn?'WARN':'PASS';
      return`<td class="heat-cell" style="background:${bg}" onclick="goFindingsFiltered('${sev}','${cat}')" title="${d.fail} FAIL · ${d.warn} WARN · ${d.total} total">
        <div class="heat-count" style="color:${tc}">${n}</div>
        <div class="heat-lbl" style="color:${tc}">${lbl}</div></td>`;
    }).join('')}</tr>`
  ).join('');
  const totRow=cats.map(cat=>{
    const tot=sevs.reduce((s,sev)=>s+grid[sev][cat].fail,0);
    return`<td style="color:${tot>0?'#f85149':'#3fb950'};font-weight:700">${tot}</td>`;
  }).join('');

  document.getElementById('view-heatmap').innerHTML=`
    ${provBar('heatmap')}
    <p style="color:#8b949e;font-size:13px;margin-bottom:4px">Cell = FAIL count for that severity × category combination. Click a cell to drill into those findings.</p>
    <div class="heat-wrap"><table class="heat-table">
      <thead>${header}</thead>
      <tbody>${rows}</tbody>
      <tfoot><tr><td class="heat-sev-lbl" style="font-size:10px;color:#8b949e">FAIL Total</td>${totRow}</tr></tfoot>
    </table></div>
    <div class="heat-legend">
      <span><div class="heat-swatch" style="background:#7f1d1d"></div>CRITICAL FAIL</span>
      <span><div class="heat-swatch" style="background:#431407"></div>HIGH FAIL</span>
      <span><div class="heat-swatch" style="background:#422006"></div>MEDIUM FAIL / WARN</span>
      <span><div class="heat-swatch" style="background:#052e16"></div>PASS</span>
      <span><div class="heat-swatch" style="background:#161b22;border:1px solid #30363d"></div>Not tested</span>
    </div>`;
}

function goFindingsFiltered(sev,cat){
  curFilter='fail';curCat=cat;curSev=sev;curSearch='';
  document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));
  document.querySelector('.nav-item[data-view="findings"]').classList.add('active');
  document.querySelectorAll('.view').forEach(x=>x.classList.remove('active'));
  document.getElementById('view-findings').classList.add('active');
  renderFindings();
}

// ── Control Coverage ──────────────────────────────────────────────────────────
function renderCoverage(){
  const cov=((DATA.meta)||{}).coverage||{};
  const type=cov.type||'none';
  const covered=new Set(cov.covered||[]);
  const expected=cov.expected||[];
  const pct=cov.pct||0;
  const labels=cov.labels||{};
  const notCovered=cov.not_covered||[];

  if(type==='none'){
    document.getElementById('view-coverage').innerHTML=`
      ${provBar('coverage')}
      <div style="padding:32px;text-align:center;color:#8b949e">
        <div style="font-size:32px;margin-bottom:12px">📋</div>
        <div style="font-size:14px">Control coverage analysis is available for <strong style="color:#c9d1d9">FedRAMP</strong> and <strong style="color:#c9d1d9">CMMC</strong> profiles.</div>
        <div style="font-size:12px;margin-top:8px">Re-run the scan with a FedRAMP or CMMC profile to see coverage.</div>
      </div>`;
    return;
  }

  const isFedRAMP=type==='fedramp';
  const title=isFedRAMP?'NIST 800-53 Control Coverage':'CMMC Domain Coverage';
  const pctColor=pct>=80?'#3fb950':pct>=50?'#eab308':'#f85149';

  // Group by family
  const families={};
  for(const id of expected){
    const fam=isFedRAMP?id.split('-')[0]:id;
    const lbl=labels[fam]||fam;
    if(!families[fam])families[fam]={label:lbl,expected:[],covered:[],notCovered:[]};
    families[fam].expected.push(id);
    if(covered.has(id))families[fam].covered.push(id);
    else families[fam].notCovered.push(id);
  }

  const cards=Object.entries(families).sort(([a],[b])=>a.localeCompare(b)).map(([fam,d])=>{
    const fp=Math.round(d.covered.length/d.expected.length*100);
    const fc=fp>=80?'#3fb950':fp>=50?'#eab308':'#f85149';
    const chips=d.expected.map(id=>`<span class="${covered.has(id)?'cov-yes':'cov-no'}">${esc(id)}</span>`).join('');
    return`<div class="cov-card">
      <div class="cov-hdr"><span class="cov-family">${esc(fam)}</span><span class="cov-sub">${esc(d.label)}</span><span class="cov-pct" style="color:${fc}">${fp}%</span></div>
      <div class="cov-bar-bg"><div class="cov-bar" style="width:${fp}%;background:${fc}"></div></div>
      <div class="cov-chips">${chips}</div>
    </div>`;
  }).join('');

  const gapList=notCovered.length?`
    <div class="cov-uncovered">
      <div style="font-size:12px;font-weight:600;color:#f87171;margin-bottom:8px">⚠ ${notCovered.length} control${notCovered.length!==1?'s':''} not tested by any current check</div>
      <div style="display:flex;flex-wrap:wrap;gap:4px">${notCovered.map(id=>`<span class="cov-no">${esc(id)}</span>`).join('')}</div>
      <div style="font-size:11px;color:#8b949e;margin-top:8px">These controls may require manual assessment or additional checks.</div>
    </div>`:'<div style="background:#0d2818;border:1px solid #166534;border-radius:6px;padding:12px;font-size:13px;color:#4ade80">✓ All expected controls are covered by at least one check.</div>';

  document.getElementById('view-coverage').innerHTML=`
    ${provBar('coverage')}
    <h3 style="margin:0 0 14px;font-size:15px;color:#c9d1d9">${esc(title)}</h3>
    <div class="cov-summary">
      <div class="cov-stat"><div class="cov-stat-n" style="color:${pctColor}">${pct}%</div><div class="cov-stat-l">Coverage</div></div>
      <div class="cov-stat"><div class="cov-stat-n" style="color:#3fb950">${covered.size}</div><div class="cov-stat-l">Controls Tested</div></div>
      <div class="cov-stat"><div class="cov-stat-n" style="color:${notCovered.length?'#f85149':'#3fb950'}">${notCovered.length}</div><div class="cov-stat-l">Gaps</div></div>
      <div class="cov-stat"><div class="cov-stat-n">${expected.length}</div><div class="cov-stat-l">In Scope</div></div>
    </div>
    <div class="cov-grid">${cards}</div>
    ${gapList}`;
}

// ── What-If Simulator ─────────────────────────────────────────────────────────
function _riskLevel(fails,warns,findings){
  const hasCrit=findings.some(f=>f.status==='FAIL'&&f.severity==='CRITICAL'&&!_simFixed.has(f.check_id));
  if(hasCrit)return{label:'CRITICAL',color:'#f85149'};
  const tot=findings.filter(f=>f.status!=='SKIP').length||1;
  if(fails/tot>0.4)return{label:'HIGH',color:'#f97316'};
  if(fails>0||warns/tot>0.3)return{label:'MEDIUM',color:'#eab308'};
  if(warns>0)return{label:'LOW',color:'#3b82f6'};
  return{label:'CLEAR',color:'#3fb950'};
}

function renderSimulator(){
  const p=DATA.providers[curProv];
  const active=p.findings.filter(f=>f.status!=='SKIP');
  const actionable=p.findings.filter(f=>f.status==='FAIL'||f.status==='WARN')
    .sort((a,b)=>(SEV_ORD[a.severity]??4)-(SEV_ORD[b.severity]??4));
  const tot=active.length||1;

  const curFail=active.filter(f=>f.status==='FAIL').length;
  const curWarn=active.filter(f=>f.status==='WARN').length;
  const curPass=active.filter(f=>f.status==='PASS').length;
  const curScore=Math.round(curPass/tot*100);
  const curRisk=_riskLevel(curFail,curWarn,p.findings);

  const fixedInSet=actionable.filter(f=>_simFixed.has(f.check_id));
  const projFail=active.filter(f=>f.status==='FAIL'&&!_simFixed.has(f.check_id)).length;
  const projWarn=active.filter(f=>f.status==='WARN'&&!_simFixed.has(f.check_id)).length;
  const projPass=curPass+fixedInSet.length;
  const projScore=Math.round(projPass/tot*100);
  const projRisk=_riskLevel(projFail,projWarn,p.findings);
  const delta=projScore-curScore;

  const rows=actionable.map(f=>{
    const done=_simFixed.has(f.check_id);
    const sl=f.severity.toLowerCase(),stl=f.status.toLowerCase();
    return`<tr class="${done?'sim-done':''}">
      <td style="text-align:center"><input type="checkbox" class="sim-cb" ${done?'checked':''} onchange="toggleSimFix('${f.check_id}',this.checked)"></td>
      <td><span class="badge ${sl}">${esc(f.severity)}</span></td>
      <td><span class="badge ${stl}">${esc(f.status)}</span></td>
      <td style="font-family:monospace;font-size:12px">${esc(f.check_id)}</td>
      <td>${esc(f.title)}</td>
      <td class="sim-delta">${done?'<span style="color:#3fb950">+1 PASS</span>':(f.status==='FAIL'?'−1 FAIL':'−1 WARN')}</td>
    </tr>`;
  }).join('');

  const gainBanner=fixedInSet.length?`<div class="sim-gain">
    Fixing <strong>${fixedInSet.length}</strong> finding${fixedInSet.length!==1?'s':''} moves risk from
    <strong style="color:${curRisk.color}">${curRisk.label}</strong> →
    <strong style="color:${projRisk.color}">${projRisk.label}</strong>
    and raises compliance score from <strong>${curScore}%</strong> → <strong style="color:#4ade80">${projScore}%</strong>
    ${delta>0?`(+${delta}%)`:''}</div>`:'';

  document.getElementById('view-simulator').innerHTML=`
    ${provBar('simulator')}
    <p style="color:#8b949e;font-size:13px;margin-bottom:16px">Check findings you plan to remediate. See projected risk posture update instantly.</p>
    <div class="sim-panels">
      <div class="sim-panel">
        <div class="sim-panel-lbl">Current posture</div>
        <div class="sim-panel-score" style="color:${curRisk.color}">${curRisk.label}</div>
        <div class="sim-panel-sub">${curFail} FAIL · ${curWarn} WARN · ${curScore}% compliant</div>
      </div>
      <div class="sim-arrow">→</div>
      <div class="sim-panel">
        <div class="sim-panel-lbl">Projected (${fixedInSet.length} fixed)</div>
        <div class="sim-panel-score" style="color:${projRisk.color}">${projRisk.label}</div>
        <div class="sim-panel-sub">${projFail} FAIL · ${projWarn} WARN · ${projScore}% compliant${delta>0?' <span style="color:#3fb950">+'+delta+'%</span>':''}</div>
      </div>
    </div>
    ${gainBanner}
    <div style="display:flex;gap:10px;margin-bottom:12px;align-items:center">
      <button class="pbtn" onclick="simAll(true)">Select All</button>
      <button class="pbtn" onclick="simAll(false)">Clear All</button>
      <span style="font-size:12px;color:#8b949e;margin-left:6px">${actionable.length} actionable finding${actionable.length!==1?'s':''}</span>
    </div>
    <table class="sim-table">
      <thead><tr><th style="width:36px">Fix?</th><th>Sev</th><th>Status</th><th>ID</th><th>Finding</th><th>Impact</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
}

function toggleSimFix(id,checked){if(checked)_simFixed.add(id);else _simFixed.delete(id);renderSimulator();}
function simAll(val){
  const p=DATA.providers[curProv];
  if(val)p.findings.filter(f=>f.status==='FAIL'||f.status==='WARN').forEach(f=>_simFixed.add(f.check_id));
  else _simFixed.clear();
  renderSimulator();
}

window.addEventListener('DOMContentLoaded',init);
"""


def _build_html(data: dict) -> str:
    data_json = json.dumps(data, ensure_ascii=False).replace('</script>', r'<\/script>')
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>M.A.R.K. Sentinel — Security Dashboard</title>
<style>{_CSS}</style>
</head>
<body>
<div id="app">
  <aside id="sidebar">
    <div class="brand">
      <div class="brand-mark">M.A.R.K.</div>
      <div class="brand-name">SENTINEL</div>
      <div class="brand-sub">AI Security Audit</div>
    </div>
    <nav id="nav">
      <div class="nav-item active" data-view="overview"><span class="nav-icon">◈</span> Overview</div>
      <div class="nav-item" data-view="findings"><span class="nav-icon">⚑</span> Findings</div>
      <div class="nav-item" data-view="probes"><span class="nav-icon">⚡</span> Live Probes</div>
      <div class="nav-item" data-view="compare"><span class="nav-icon">⊞</span> Compare</div>
      <div class="nav-item" data-view="remediation"><span class="nav-icon">✓</span> Remediation</div>
      <div class="nav-item" data-view="reports"><span class="nav-icon">📄</span> Reports</div>
      <div class="nav-item" data-view="scan"><span class="nav-icon">▶</span> Run Scan</div>
      <div class="nav-item" data-view="heatmap"><span class="nav-icon">⬛</span> Risk Heat Map</div>
      <div class="nav-item" data-view="coverage"><span class="nav-icon">◎</span> Control Coverage</div>
      <div class="nav-item" data-view="simulator"><span class="nav-icon">⚗</span> What-If Simulator</div>
    </nav>
    <div class="sidebar-footer">Powered by Hash<br>M.A.R.K. Sentinel v1.0</div>
  </aside>
  <div id="main">
    <div id="header">
      <div class="header-title">AI Security Dashboard <span id="hdr-profile"></span></div>
      <div class="header-meta">
        <span>🎯 <span id="hdr-target"></span></span>
        <span>📅 <span id="hdr-date"></span></span>
      </div>
    </div>
    <div id="content">
      <div id="view-overview" class="view active"></div>
      <div id="view-findings" class="view"></div>
      <div id="view-probes" class="view"></div>
      <div id="view-compare" class="view"></div>
      <div id="view-remediation" class="view"></div>
      <div id="view-reports" class="view"></div>
      <div id="view-scan" class="view"></div>
      <div id="view-heatmap" class="view"></div>
      <div id="view-coverage" class="view"></div>
      <div id="view-simulator" class="view"></div>
    </div>
  </div>
</div>
<script>const DATA={data_json};</script>
<script>{_JS}</script>
</body>
</html>"""


_FEDRAMP_EXPECTED = [
    'AC-2','AC-3','AC-4','AC-6','AC-7','AC-17','AC-20',
    'AU-2','AU-3','AU-6','AU-9','AU-11',
    'CA-2','CA-7',
    'CM-2','CM-3','CM-6','CM-7','CM-8','CM-10',
    'CP-9','CP-10',
    'IA-2','IA-3','IA-5','IA-8',
    'IR-4','IR-5','IR-6','IR-8',
    'MA-3','MA-4',
    'MP-6','MP-7',
    'PE-3','PE-6',
    'PL-2','PL-8',
    'PS-3','PS-6',
    'RA-2','RA-3','RA-5',
    'SA-9','SA-12','SA-15',
    'SC-5','SC-7','SC-8','SC-12','SC-13','SC-28',
    'SI-2','SI-3','SI-4','SI-7','SI-10','SI-12',
]

_CMMC_EXPECTED = ['AC','AT','AU','CA','CM','IA','IR','MA','MP','PE','PS','RA','SA','SC','SI']

_CMMC_LABELS = {
    'AC':'Access Control','AT':'Awareness & Training','AU':'Audit & Accountability',
    'CA':'Security Assessment','CM':'Config Management','IA':'Identification & Auth',
    'IR':'Incident Response','MA':'Maintenance','MP':'Media Protection',
    'PE':'Physical Protection','PS':'Personnel Security','RA':'Risk Assessment',
    'SA':'Sys & Services Acq','SC':'Comms Protection','SI':'System Integrity',
}


def generate(reports: list[dict], output_path: str | Path, *,
             meta: dict | None = None) -> Path:
    """
    Generate a self-contained dashboard HTML file from one or more JSON scan reports.
    Each report dict should be a parsed JSON report from format_json().
    Reports may include '_provider_label' and '_model' keys for display labeling.
    Returns the path to the written file.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    providers = []
    for r in reports:
        label = r.get('_provider_label') or r.get('mode', 'Unknown')
        model = r.get('_model') or r.get('model', '')
        if model and model not in label:
            label = f"{label.strip()} ({model})"
        providers.append({
            'label':    label.strip(),
            'mode':     r.get('mode', ''),
            'model':    model,
            'summary':  r.get('summary', {}),
            'findings': r.get('findings', []),
        })

    resolved_meta = meta or {}
    if reports:
        first = reports[0]
        resolved_meta.setdefault('scan_date',           first.get('scan_date', ''))
        resolved_meta.setdefault('target',              first.get('target', ''))
        resolved_meta.setdefault('profile',             first.get('profile', ''))
        resolved_meta.setdefault('profile_framework',   first.get('profile_framework'))
        resolved_meta.setdefault('profile_description', first.get('profile_description', ''))

    framework = resolved_meta.get('profile_framework')
    covered: set[str] = set()
    for r in reports:
        for f in r.get('findings', []):
            covered.update(f.get('emphasis_controls') or [])
    if framework == 'fedramp':
        expected = _FEDRAMP_EXPECTED
        covered_in = sorted(covered & set(expected))
        not_covered = sorted(set(expected) - covered)
        resolved_meta['coverage'] = {
            'type': 'fedramp', 'covered': covered_in, 'not_covered': not_covered,
            'expected': expected, 'pct': round(len(covered_in) / len(expected) * 100),
        }
    elif framework == 'cmmc':
        expected = _CMMC_EXPECTED
        covered_in = sorted(covered & set(expected))
        not_covered = sorted(set(expected) - covered)
        resolved_meta['coverage'] = {
            'type': 'cmmc', 'covered': covered_in, 'not_covered': not_covered,
            'expected': expected, 'pct': round(len(covered_in) / len(expected) * 100),
            'labels': _CMMC_LABELS,
        }
    else:
        resolved_meta['coverage'] = {'type': 'none', 'covered': [], 'not_covered': [], 'expected': [], 'pct': 0}

    html = _build_html({'meta': resolved_meta, 'providers': providers})
    output_path.write_text(html, encoding='utf-8')
    return output_path
