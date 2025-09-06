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
    .sev-filter{cursor:pointer; user-select:none}
    .toast{position:fixed;left:50%;bottom:16px;transform:translateX(-50%);background:var(--card);color:var(--fg);border:1px solid var(--border);padding:8px 12px;border-radius:6px;font-size:12px;box-shadow:0 2px 10px rgba(0,0,0,0.12);transition:opacity .25s}
  </style>
</head>
<body>
  <header>
    <h1>CredAudit Report</h1>
    <span class="meta">v{{ version }} &middot; {{ generated_at }} &middot; Findings: {{ total_count }} &middot; Files: {{ file_count }}</span>
  </header>
  <div class="summary">
    <div class="card sev-filter" data-sev="High">High: <b>{{ counts.High }}</b></div>
    <div class="card sev-filter" data-sev="Medium">Medium: <b>{{ counts.Medium }}</b></div>
    <div class="card sev-filter" data-sev="Low">Low: <b>{{ counts.Low }}</b></div>
  </div>
  {% if truncated %}
  <div class="summary">
    <div class="card">Showing first <b>{{ shown_count }}</b> of <b>{{ total_count }}</b> findings (HTML limited). Full data is in JSON/CSV.</div>
  </div>
  {% endif %}
  <div class="summary">
    <div class="card">
      Downloads: <a href="{{ csv_name }}" download>Full CSV</a> &middot; <a href="{{ json_name }}" download>Full JSON</a>
    </div>
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
      <button id="downloadCsv">Download CSV (page)</button>
      <button id="downloadCsvAll">Download CSV (all filtered)</button>
    </div>
    <div class="actions">
      <label class="chip">Rows per page
        <select id="pageSize">
          <option value="100">100</option>
          <option value="250">250</option>
          <option value="500" selected>500</option>
          <option value="1000">1000</option>
        </select>
      </label>
    </div>
  </div>
  <div class="summary"><div class="card" id="stats"></div></div>
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
      {% for f in display %}
      <tr class="sev-{{ f.severity }}" data-sev="{{ f.severity }}" data-file="{{ f.file|lower }}" data-rule="{{ f.rule|lower }}">
        <td><span class="badge {{ f.severity }}">{{ f.severity }}</span></td>
        <td class="path">{{ f.file }}</td>
        <td>{{ f.rule }}</td>
        <td><code class="val" data-redacted="{{ f.redacted }}" data-raw="{{ f.match }}">{{ f.redacted }}</code></td>
        <td class="nowrap">{{ f.line }}</td>
        <td><code>{{ f.context }}</code></td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  <div id="pager" class="actions" style="margin-top:10px"></div>
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
    const btnDownload=qs('#downloadCsv');
    const btnDownloadAll=qs('#downloadCsvAll');
    const selPageSize=qs('#pageSize');
    const pager=qs('#pager');
    const tbody=qs('tbody', tbl);
    let showRaw=false;
    const RAW = document.getElementById('data').textContent;
    let DATA = [];
    try { DATA = JSON.parse(RAW); } catch(e) { DATA = []; }
    let filtered = DATA.slice();
    let page = 1;
    let PAGE_SIZE = parseInt(selPageSize.value,10) || 500;
    const sevRank={High:3,Medium:2,Low:1};
    const BASE_NAME = {{ base_name_js }};

    function escapeHtml(s){
      return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;','\'':'&#39;'}[c]));
    }
    // Override to avoid single-quote escape issues in some encodings
    function escapeHtml(s){
      return String(s).replace(/[&<>\"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;'}[c]));
    }
    function renderRows(){
      const total = filtered.length;
      const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
      if(page < 1) page = 1; if(page > totalPages) page = totalPages;
      const start = (page - 1) * PAGE_SIZE;
      const end = Math.min(total, start + PAGE_SIZE);
      const frag = document.createDocumentFragment();
      tbody.innerHTML='';
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
      // Update stats summary
      (function(){
        var statsEl = document.getElementById('stats');
        if(statsEl){
          var totalFiltered = filtered.length;
          var startIdx = totalFiltered ? (start + 1) : 0;
          var endIdx = totalFiltered ? end : 0;
          var msg = 'Showing ' + startIdx + '-' + endIdx + ' of ' + totalFiltered;
          if(totalFiltered !== DATA.length){ msg += ' (filtered from ' + DATA.length + ')'; }
          statsEl.textContent = msg;
        }
      })();
      renderPager(totalPages);
    }
    function downloadCsvPage(){
      const start = (page-1)*PAGE_SIZE;
      const end = Math.min(filtered.length, start+PAGE_SIZE);
      const esc = (v)=> '"' + String(v==null?'':v).replace(/"/g,'""') + '"';
      const header = ['severity','file','rule','value','line','context'];
      const lines = [header.map(esc).join(',')];
      for(let i=start;i<end;i++){
        const f = filtered[i]||{};
        const row = [
          f.severity||'',
          f.file||'',
          f.rule||'',
          showRaw ? (f.match||'') : (f.redacted||''),
          f.line||'',
          f.context||''
        ];
        lines.push(row.map(esc).join(','));
      }
      const csv = lines.join('\r\n');
      const blob = new Blob([csv], {type:'text/csv;charset=utf-8'});
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = `${BASE_NAME}_page_${page}.csv`;
      document.body.appendChild(a); a.click(); document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }
    function downloadCsvAll(){
      const esc = (v)=> '"' + String(v==null?'':v).replace(/"/g,'""') + '"';
      const header = ['severity','file','rule','value','line','context'];
      const lines = [header.map(esc).join(',')];
      for(let i=0;i<filtered.length;i++){
        const f = filtered[i]||{};
        const row = [
          f.severity||'',
          f.file||'',
          f.rule||'',
          showRaw ? (f.match||'') : (f.redacted||''),
          f.line||'',
          f.context||''
        ];
        lines.push(row.map(esc).join(','));
      }
      const csv = lines.join('\r\n');
      const blob = new Blob([csv], {type:'text/csv;charset=utf-8'});
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = `${BASE_NAME}_filtered.csv`;
      document.body.appendChild(a); a.click(); document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }
    function renderPager(totalPages){
      function pageButton(lbl, target, disabled=false, active=false){
        const b = document.createElement('button'); b.textContent = lbl;
        if(disabled) b.disabled = true;
        if(active) b.style.fontWeight = 'bold';
        b.addEventListener('click', ()=>{ page = target; renderRows(); });
        return b;
      }
      pager.innerHTML='';
      const total = totalPages;
      pager.appendChild(pageButton('Â« First', 1, page===1));
      pager.appendChild(pageButton('â€¹ Prev', Math.max(1, page-1), page===1));
      const window = 3; let start = Math.max(1, page - window); let end = Math.min(total, page + window);
      if(start>1){ pager.appendChild(pageButton('1',1,false,page===1)); if(start>2){ const dots=document.createElement('span'); dots.textContent='â€¦'; dots.style.padding='6px'; pager.appendChild(dots);} }
      for(let p=start;p<=end;p++){ pager.appendChild(pageButton(String(p), p, false, p===page)); }
      if(end<total){ if(end<total-1){ const dots=document.createElement('span'); dots.textContent='â€¦'; dots.style.padding='6px'; pager.appendChild(dots);} pager.appendChild(pageButton(String(total), total, false, page===total)); }
      pager.appendChild(pageButton('Next â€º', Math.min(total, page+1), page===total));
      pager.appendChild(pageButton('Last Â»', total, page===total));
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
      page = 1;
      renderRows();
    }
    function clearFilters(){ q.value=''; cbH.checked=cbM.checked=cbL.checked=true; applyFilters(); }
    function toggleTheme(){ document.body.classList.toggle('dark'); }
    function toggleRaw(){ showRaw=!showRaw; btnRaw.textContent = showRaw ? 'Hide Raw Secrets' : 'Show Raw Secrets'; qsa('code.val').forEach(el=>{ el.textContent = showRaw ? el.dataset.raw : el.dataset.redacted; }); }
    q.addEventListener('input', applyFilters); cbH.addEventListener('change', applyFilters); cbM.addEventListener('change', applyFilters); cbL.addEventListener('change', applyFilters);
    selPageSize.addEventListener('change', ()=>{ PAGE_SIZE = parseInt(selPageSize.value,10)||500; page=1; renderRows(); });
    btnClear.addEventListener('click', clearFilters); btnTheme.addEventListener('click', toggleTheme); btnRaw.addEventListener('click', toggleRaw); btnDownload.addEventListener('click', downloadCsvPage); btnDownloadAll.addEventListener('click', downloadCsvAll);
    // Clickable severity summary cards (toggle filters)
    qsa('.sev-filter').forEach(el=>{ const sev=el.dataset.sev; const map={High:cbH, Medium:cbM, Low:cbL}; const sync=()=>{ el.style.opacity= map[sev].checked ? '1' : '0.5'; }; el.addEventListener('click', ()=>{ const c=map[sev]; c.checked=!c.checked; applyFilters(); sync(); }); sync(); });
    // Copy value on click with toast
    function showToast(msg){ const t=document.getElementById('toast'); if(!t) return; t.textContent=msg; t.classList.remove('hidden'); t.style.opacity='1'; setTimeout(()=>{ t.style.opacity='0'; }, 1200); setTimeout(()=>{ t.classList.add('hidden'); }, 1600); }
    tbody.addEventListener('click', (e)=>{ const el = e.target.closest && e.target.closest('code.val'); if(!el) return; const text = showRaw ? (el.dataset.raw||'') : (el.dataset.redacted||''); if(navigator.clipboard && typeof navigator.clipboard.writeText==='function'){ navigator.clipboard.writeText(text).then(()=>showToast('Copied')); } else { const ta=document.createElement('textarea'); ta.value=text; document.body.appendChild(ta); ta.select(); try{ document.execCommand('copy'); showToast('Copied'); }catch(ex){} document.body.removeChild(ta); } });
    // Keyboard shortcuts: f or / focus search, t theme, r raw, Esc clear
    document.addEventListener('keydown', (e)=>{ const tag=(e.target&&e.target.tagName)||''; if(tag==='INPUT'||tag==='SELECT'||(e.target&&e.target.isContentEditable)) return; const k=(e.key||'').toLowerCase(); if(k==='/'||k==='f'){ e.preventDefault(); q.focus(); } else if(k==='t'){ e.preventDefault(); toggleTheme(); } else if(k==='r'){ e.preventDefault(); toggleRaw(); } else if(k==='escape'){ clearFilters(); } });
    // Normalize pager labels to ASCII (in case of encoding issues)
    (function(){
      const pagerEl = document.getElementById('pager');
      if(!pagerEl) return;
      const fix = ()=>{
        pagerEl.querySelectorAll('button').forEach(b=>{
          const t=b.textContent||'';
          if(t.includes('First')) b.textContent='<< First';
          else if(t.includes('Prev')) b.textContent='< Prev';
          else if(t.includes('Next')) b.textContent='Next >';
          else if(t.includes('Last')) b.textContent='Last >>';
        });
        pagerEl.querySelectorAll('span').forEach(s=>{ if((s.textContent||'').trim().length===1) s.textContent='...'; });
      };
      const mo = new MutationObserver(fix);
      mo.observe(pagerEl, {childList:true, subtree:true});
      fix();
    })();
    // Sorting (on filtered array)
    qsa('th.sortable', tbl).forEach(th=>{ th.addEventListener('click', ()=>{ const k=th.dataset.k; const dir= th.dataset.dir==='asc' ? 'desc' : 'asc'; th.dataset.dir=dir; const cmp=(a,b)=>{ let va,vb; if(k==='severity'){ va=sevRank[a.severity]||0; vb=sevRank[b.severity]||0; } else if(k==='file'){ va=(a.file||'').toLowerCase(); vb=(b.file||'').toLowerCase(); } else if(k==='rule'){ va=(a.rule||'').toLowerCase(); vb=(b.rule||'').toLowerCase(); } else if(k==='line'){ va=parseInt(a.line||0)||0; vb=parseInt(b.line||0)||0; } else { va=''; vb=''; } return (va>vb?1:va<vb?-1:0) * (dir==='asc'?1:-1); }; filtered.sort(cmp); page=1; renderRows(); }); });
    // Intentionally do not auto-fetch full JSON to keep the page lightweight.
    // Persist theme preference
    if(localStorage.getItem('credtheme')==='dark') document.body.classList.add('dark'); btnTheme.addEventListener('click', ()=>{ const d=document.body.classList.contains('dark'); localStorage.setItem('credtheme', d?'dark':'light'); });
    // Initial render
    applyFilters();
    // Auto-download disabled to avoid unwanted downloads; use the buttons or static links instead.
  })();
  </script>
  <noscript>
    <div class="summary"><div class="card">JavaScript is disabled. Showing a static table. For filtering, sorting, and downloads, open this report in a browser with JavaScript enabled.</div></div>
  </noscript>
  <div id="toast" class="toast hidden" role="status" aria-live="polite"></div>
</body>
</html>
"""


def export_html(findings, p):
    counts = {"High": 0, "Medium": 0, "Low": 0}
    files = set()
    # Normalize incoming findings to expected schema/casing
    normalized = []
    for f in findings:
        f = dict(f) if isinstance(f, dict) else {}
        sev_raw = f.get("severity", "Low")
        sev = str(sev_raw).strip().title()
        if sev not in ("High", "Medium", "Low"):
            # Map common variants
            m = {"Sev-High": "High", "Sev-Medium": "Medium", "Sev-Low": "Low", "Critical": "High"}
            sev = m.get(sev, "Low")
        f["severity"] = sev
        # Ensure keys exist to avoid JS undefineds
        f.setdefault("file", f.get("path", ""))
        f.setdefault("rule", f.get("id", ""))
        f.setdefault("redacted", f.get("masked", f.get("value", f.get("match", ""))))
        f.setdefault("match", f.get("value", ""))
        f.setdefault("line", f.get("line", ""))
        f.setdefault("context", f.get("context", ""))
        normalized.append(f)
        if sev in counts:
            counts[sev] += 1
        fp = f.get("file")
        if fp:
            files.add(fp)
    env = Environment(autoescape=True)
    tmpl = env.from_string(TEMPLATE)
    # Limit rows for lighter HTML (override via env CREDAUDIT_HTML_MAX_ROWS)
    try:
        max_rows = int(os.environ.get('CREDAUDIT_HTML_MAX_ROWS', '500'))
    except Exception:
        max_rows = 500
    total_count = len(normalized)
    display = normalized if total_count <= max_rows else normalized[:max_rows]
    data_json = Markup(json.dumps(display, ensure_ascii=False))
    base_name = os.path.splitext(os.path.basename(p))[0]
    json_name = base_name + '.json'
    csv_name = base_name + '.csv'
    json_name_js = Markup(json.dumps(json_name))
    base_name_js = Markup(json.dumps(base_name))
    html = tmpl.render(
        counts=counts,
        file_count=len(files),
        version=_VERSION,
        generated_at=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        data_json=data_json,
        truncated=(total_count > max_rows),
        shown_count=len(display),
        total_count=total_count,
        csv_name=csv_name,
        json_name=json_name,
        json_name_js=json_name_js,
        base_name_js=base_name_js,
        display=display,
    )
    with open(p, 'w', encoding='utf-8') as h:
        h.write(html)

