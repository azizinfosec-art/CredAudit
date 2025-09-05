import json
import os
from datetime import datetime
from jinja2 import Environment
from markupsafe import Markup
from .. import __version__ as _VERSION


TEMPLATE = """<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>CredAudit Report</title>
  <style>
    :root{
      --bg:#ffffff; --fg:#101418; --muted:#4b5563; --card:#f8fafc; --border:#e5e7eb;
      --sev-high:#ffe5e5; --sev-med:#fff4e5; --sev-low:#eef7ff; --code:#f6f8fa;
      --accent:#0ea5e9;
    }
    /* Hacker-style dark theme: neon green on black, with high-contrast severity */
    .dark{
      --bg:#000000; --fg:#b7f5c0; --muted:#7bbf89; --card:#0a140a; --border:#113311; --code:#0a1f0a; --accent:#00ff66;
      --sev-high: rgba(255, 77, 77, 0.12); --sev-med: rgba(255, 209, 102, 0.12); --sev-low: rgba(110, 231, 255, 0.12);
    }
    *{box-sizing:border-box}
    body{font-family:Segoe UI,Arial,sans-serif;background:var(--bg);color:var(--fg);margin:24px}
    header{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}
    h1{margin:0 0 4px 0;font-size:20px}
    .meta{color:var(--muted);font-size:12px}
    .controls{display:flex;gap:8px;flex-wrap:wrap;margin:12px 0}
    input[type="text"]{padding:8px;border:1px solid var(--border);border-radius:6px;min-width:260px;background:var(--bg);color:var(--fg)}
    .chip{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--border);padding:6px 8px;border-radius:999px;font-size:12px;background:var(--card)}
    .chip input{margin:0}
    button{padding:6px 10px;border:1px solid var(--border);background:var(--card);color:var(--fg);border-radius:6px;cursor:pointer}
    button:hover{border-color:var(--accent); box-shadow:0 0 0 2px rgba(0,255,102,0.15)}
    table{border-collapse:separate;border-spacing:0;width:100%;table-layout:fixed;margin-top:8px}
    th,td{border-bottom:1px solid var(--border);padding:10px 8px;font-size:13px;vertical-align:top}
    thead th{position:sticky;top:0;background:var(--card);text-align:left}
    th.sortable{cursor:pointer}
    .sev-High{background:var(--sev-high)}
    .sev-Medium{background:var(--sev-med)}
    .sev-Low{background:var(--sev-low)}
    code{background:var(--code);padding:2px 4px;border-radius:4px}
    .path{font-family:Consolas,monospace;word-break:break-all}
    .badge{display:inline-block;padding:2px 6px;border-radius:999px;font-size:12px;border:1px solid var(--border)}
    .badge.High{background:#fee2e2}
    .badge.Medium{background:#ffedd5}
    .badge.Low{background:#dbeafe}
    .dark .badge.High{background:#330000;border-color:#ff4d4d;color:#ff8a8a}
    .dark .badge.Medium{background:#332600;border-color:#ffd166;color:#ffe599}
    .dark .badge.Low{background:#002733;border-color:#6ee7ff;color:#a5f3ff}
    .nowrap{white-space:nowrap}
    .summary{display:flex;gap:12px;flex-wrap:wrap;margin-top:6px}
    .summary .card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:8px 10px;font-size:12px}
    .actions{display:flex;gap:8px;flex-wrap:wrap}
    .hidden{display:none}
  </style>
</head>
<body>
  <header>
    <h1>CredAudit Report</h1>
    <span class="meta">v{{ version }} &middot; {{ generated_at }} &middot; Findings: {{ total_count }} &middot; Files: {{ file_count }}</span>
  </header>
  <div class="summary">
    <div class="card">High: <b>{{ counts.High }}</b></div>
    <div class="card">Medium: <b>{{ counts.Medium }}</b></div>
    <div class="card">Low: <b>{{ counts.Low }}</b></div>
  </div>
  {% if truncated %}
  <div class="summary">
    <div class="card">Showing first <b>{{ shown_count }}</b> of <b>{{ total_count }}</b> findings (HTML limited). Full data is in JSON/CSV.</div>
  </div>
  {% endif %}
  <div class="controls">
    <input id="q" type="text" placeholder="Filter by file, rule, context..." />
    <label class="chip"><input type="checkbox" id="sevHigh" checked /> High</label>
    <label class="chip"><input type="checkbox" id="sevMed" checked /> Medium</label>
    <label class="chip"><input type="checkbox" id="sevLow" checked /> Low</label>
    <div class="actions">
      <button id="toggleTheme">Toggle Theme</button>
      <button id="toggleRaw">Show Raw Secrets</button>
      <button id="clear">Clear Filters</button>
    </div>
  </div>
  <table id="tbl">
    <thead>
      <tr>
        <th class="sortable" data-k="severity">Severity</th>
        <th class="sortable" data-k="file">File</th>
        <th class="sortable" data-k="rule">Rule</th>
        <th>Value</th>
        <th class="sortable nowrap" data-k="line">Line</th>
        <th>Context</th>
      </tr>
    </thead>
    <tbody></tbody>
  </table>
  <div class="actions" style="margin-top:10px">
    <button id="loadMore" class="hidden">Load More</button>
  </div>
  <script id="data" type="application/json">{{ data_json }}</script>
  <script>
  (function(){
    const qs=(s,el=document)=>el.querySelector(s);
    const qsa=(s,el=document)=>Array.from(el.querySelectorAll(s));
    const tbl=qs('#tbl');
    const q=qs('#q');
    const cbH=qs('#sevHigh'), cbM=qs('#sevMed'), cbL=qs('#sevLow');
    const btnClear=qs('#clear');
    const btnTheme=qs('#toggleTheme');
    const btnRaw=qs('#toggleRaw');
    const btnMore=qs('#loadMore');
    const tbody=qs('tbody', tbl);
    let showRaw=false;
    const RAW = document.getElementById('data').textContent;
    let DATA = [];
    try { DATA = JSON.parse(RAW); } catch(e) { DATA = []; }
    let filtered = DATA.slice();
    let page = 0;
    const PAGE_SIZE = 500;
    const sevRank={High:3,Medium:2,Low:1};

    function escapeHtml(s){
      return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;','\'':'&#39;'}[c]));
    }
    function renderRows(reset=false){
      if(reset){ tbody.innerHTML=''; page=0; }
      const start = page*PAGE_SIZE;
      const end = Math.min(filtered.length, start+PAGE_SIZE);
      const frag = document.createDocumentFragment();
      for(let i=start;i<end;i++){
        const f = filtered[i]||{};
        const tr = document.createElement('tr');
        tr.setAttribute('data-sev', f.severity||'');
        tr.setAttribute('data-file', (f.file||'').toLowerCase());
        tr.setAttribute('data-rule', (f.rule||'').toLowerCase());
        tr.className = 'sev-' + (f.severity||'');
        tr.innerHTML = `
          <td><span class=\"badge ${f.severity}\">${f.severity}</span></td>
          <td class=\"path\">${escapeHtml(f.file||'')}</td>
          <td>${escapeHtml(f.rule||'')}</td>
          <td><code class=\"val\" data-redacted=\"${escapeHtml(f.redacted||'')}\" data-raw=\"${escapeHtml(f.match||'')}\">${escapeHtml(showRaw ? (f.match||'') : (f.redacted||''))}</code></td>
          <td class=\"nowrap\">${f.line||''}</td>
          <td><code>${escapeHtml(f.context||'')}</code></td>`;
        frag.appendChild(tr);
      }
      tbody.appendChild(frag);
      page++;
      btnMore.classList.toggle('hidden', page*PAGE_SIZE >= filtered.length);
    }
    function applyFilters(){
      const term=(q.value||'').trim().toLowerCase();
      const allow={High:cbH.checked, Medium:cbM.checked, Low:cbL.checked};
      filtered = DATA.filter(f=>{
        const sev=f.severity||'Low'; if(!allow[sev]) return false;
        if(!term) return true;
        const file=(f.file||'').toLowerCase();
        const rule=(f.rule||'').toLowerCase();
        const ctx=(f.context||'').toLowerCase();
        return file.includes(term)||rule.includes(term)||ctx.includes(term);
      });
      renderRows(true);
    }
    function clearFilters(){ q.value=''; cbH.checked=cbM.checked=cbL.checked=true; applyFilters(); }
    function toggleTheme(){ document.body.classList.toggle('dark'); }
    function toggleRaw(){ showRaw=!showRaw; btnRaw.textContent = showRaw ? 'Hide Raw Secrets' : 'Show Raw Secrets'; qsa('code.val').forEach(el=>{ el.textContent = showRaw ? el.dataset.raw : el.dataset.redacted; }); }
    q.addEventListener('input', applyFilters); cbH.addEventListener('change', applyFilters); cbM.addEventListener('change', applyFilters); cbL.addEventListener('change', applyFilters);
    btnClear.addEventListener('click', clearFilters); btnTheme.addEventListener('click', toggleTheme); btnRaw.addEventListener('click', toggleRaw); btnMore.addEventListener('click', ()=>renderRows(false));
    // Sorting (on filtered array)
    qsa('th.sortable', tbl).forEach(th=>{ th.addEventListener('click', ()=>{ const k=th.dataset.k; const dir= th.dataset.dir==='asc' ? 'desc' : 'asc'; th.dataset.dir=dir; const cmp=(a,b)=>{ let va,vb; if(k==='severity'){ va=sevRank[a.severity]||0; vb=sevRank[b.severity]||0; } else if(k==='file'){ va=(a.file||'').toLowerCase(); vb=(b.file||'').toLowerCase(); } else if(k==='rule'){ va=(a.rule||'').toLowerCase(); vb=(b.rule||'').toLowerCase(); } else if(k==='line'){ va=parseInt(a.line||0)||0; vb=parseInt(b.line||0)||0; } else { va=''; vb=''; } return (va>vb?1:va<vb?-1:0) * (dir==='asc'?1:-1); }; filtered.sort(cmp); renderRows(true); }); });
    // Persist theme preference
    if(localStorage.getItem('credtheme')==='dark') document.body.classList.add('dark'); btnTheme.addEventListener('click', ()=>{ const d=document.body.classList.contains('dark'); localStorage.setItem('credtheme', d?'dark':'light'); });
    // Initial render
    applyFilters();
  })();
  </script>
</body>
</html>
"""


def export_html(findings, p):
    counts = {"High": 0, "Medium": 0, "Low": 0}
    files = set()
    for f in findings:
        sev = f.get("severity", "Low")
        if sev in counts:
            counts[sev] += 1
        fp = f.get("file")
        if fp:
            files.add(fp)
    env = Environment(autoescape=True)
    tmpl = env.from_string(TEMPLATE)
    # Limit rows for lighter HTML (override via env CREDAUDIT_HTML_MAX_ROWS)
    try:
        max_rows = int(os.environ.get('CREDAUDIT_HTML_MAX_ROWS', '2000'))
    except Exception:
        max_rows = 2000
    total_count = len(findings)
    display = findings if total_count <= max_rows else findings[:max_rows]
    data_json = Markup(json.dumps(display, ensure_ascii=False))
    html = tmpl.render(
        counts=counts,
        file_count=len(files),
        version=_VERSION,
        generated_at=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        data_json=data_json,
        truncated=(total_count > max_rows),
        shown_count=len(display),
        total_count=total_count,
    )
    with open(p, 'w', encoding='utf-8') as h:
        h.write(html)

