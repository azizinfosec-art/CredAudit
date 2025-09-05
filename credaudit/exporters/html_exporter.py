from jinja2 import Environment
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
      --bg:#000000;
      --fg:#b7f5c0;
      --muted:#7bbf89;
      --card:#0a140a;
      --border:#113311;
      --code:#0a1f0a;
      --accent:#00ff66;
      --sev-high: rgba(255, 77, 77, 0.12);
      --sev-med: rgba(255, 209, 102, 0.12);
      --sev-low: rgba(110, 231, 255, 0.12);
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
    /* High-contrast badges in dark theme */
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
    <span class="meta">v{{ version }} â€¢ {{ generated_at }} â€¢ Findings: {{ findings|length }} â€¢ Files: {{ file_count }}</span>
  </header>
  <div class="summary">
    <div class="card">High: <b>{{ counts.High }}</b></div>
    <div class="card">Medium: <b>{{ counts.Medium }}</b></div>
    <div class="card">Low: <b>{{ counts.Low }}</b></div>
  </div>
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
    <tbody>
      {% for f in findings %}
      <tr data-sev="{{ f.severity }}" data-file="{{ f.file | lower }}" data-rule="{{ f.rule | lower }}">
        <td><span class="badge {{ f.severity }}">{{ f.severity }}</span></td>
        <td class="path">{{ f.file }}</td>
        <td>{{ f.rule }}</td>
        <td>
          <code class="val" data-redacted="{{ f.redacted }}" data-raw="{{ f.match }}">{{ f.redacted }}</code>
        </td>
        <td class="nowrap">{{ f.line }}</td>
        <td><code>{{ f.context }}</code></td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
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
    let showRaw=false;
    function applyFilters(){
      const term=(q.value||'').trim().toLowerCase();
      const show={High:cbH.checked, Medium:cbM.checked, Low:cbL.checked};
      qsa('tbody tr', tbl).forEach(tr=>{
        const sev=tr.getAttribute('data-sev');
        const file=tr.getAttribute('data-file');
        const rule=tr.getAttribute('data-rule');
        const ctx=(tr.querySelector('td:last-child')?.innerText||'').toLowerCase();
        let ok=!!show[sev];
        if(ok && term){
          ok = file.includes(term) || rule.includes(term) || ctx.includes(term);
        }
        tr.style.display= ok ? '' : 'none';
      });
    }
    function clearFilters(){ q.value=''; cbH.checked=cbM.checked=cbL.checked=true; applyFilters(); }
    function toggleTheme(){ document.body.classList.toggle('dark'); }
    function toggleRaw(){
      showRaw=!showRaw; btnRaw.textContent = showRaw ? 'Hide Raw Secrets' : 'Show Raw Secrets';
      qsa('code.val').forEach(el=>{ el.textContent = showRaw ? el.dataset.raw : el.dataset.redacted; });
    }
    q.addEventListener('input', applyFilters);
    cbH.addEventListener('change', applyFilters);
    cbM.addEventListener('change', applyFilters);
    cbL.addEventListener('change', applyFilters);
    btnClear.addEventListener('click', clearFilters);
    btnTheme.addEventListener('click', toggleTheme);
    btnRaw.addEventListener('click', toggleRaw);
    // Sorting
    const sevRank={High:3,Medium:2,Low:1};
    qsa('th.sortable', tbl).forEach(th=>{
      th.addEventListener('click', ()=>{
        const k=th.dataset.k;
        const rows=qsa('tbody tr', tbl).filter(r=>r.style.display!=='none');
        const getVal=(tr)=>{
          if(k==='severity') return sevRank[tr.getAttribute('data-sev')]||0;
          if(k==='file') return tr.getAttribute('data-file');
          if(k==='rule') return tr.getAttribute('data-rule');
          if(k==='line') return parseInt(tr.children[4].innerText)||0;
          return '';
        };
        const dir= th.dataset.dir==='asc' ? 'desc' : 'asc';
        th.dataset.dir=dir;
        rows.sort((a,b)=>{ const va=getVal(a), vb=getVal(b); return (va>vb?1:va<vb?-1:0)*(dir==='asc'?1:-1); });
        const tb=qs('tbody', tbl);
        rows.forEach(r=>tb.appendChild(r));
      });
    });
    // Persist theme preference
    if(localStorage.getItem('credtheme')==='dark') document.body.classList.add('dark');
    btnTheme.addEventListener('click', ()=>{
      const d=document.body.classList.contains('dark');
      localStorage.setItem('credtheme', d?'dark':'light');
    });
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
    from datetime import datetime
    env = Environment(autoescape=True)
    tmpl = env.from_string(TEMPLATE)
    html = tmpl.render(
        findings=findings,
        counts=counts,
        file_count=len(files),
        version=_VERSION,
        generated_at=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    )
    with open(p, 'w', encoding='utf-8') as h:
        h.write(html)

