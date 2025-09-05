from jinja2 import Template
T=Template("""<!DOCTYPE html>
<html><head><meta charset='utf-8'><title>CredAudit Report</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:24px}
h1{margin:0 0 8px 0}
.summary{margin:8px 0 16px 0}
table{border-collapse:collapse;width:100%}
th,td{border:1px solid #ddd;padding:8px;font-size:14px}
th{background:#f5f5f5;text-align:left}
.sev-High{background:#ffe5e5}
.sev-Medium{background:#fff4e5}
.sev-Low{background:#eef7ff}
code{background:#f6f8fa;padding:2px 4px;border-radius:4px}
.path{font-family:Consolas,monospace}
</style></head><body>
<h1>CredAudit Report</h1>
<div class="summary">
  <b>Total findings:</b> {{ findings|length }} &nbsp; | &nbsp;
  High: {{ counts.High }} &nbsp; Medium: {{ counts.Medium }} &nbsp; Low: {{ counts.Low }}
</div>
<table>
<thead><tr><th>Severity</th><th>File</th><th>Rule</th><th>Redacted</th><th>Line</th><th>Context</th></tr></thead>
<tbody>
{% for f in findings %}
<tr class="sev-{{f.severity}}"><td>{{f.severity}}</td><td class="path">{{f.file}}</td><td>{{f.rule}}</td><td><code>{{f.redacted}}</code></td><td>{{f.line}}</td><td><code>{{f.context}}</code></td></tr>
{% endfor %}
</tbody></table>
</body></html>""")
def export_html(findings,p):
    counts={"High":0,"Medium":0,"Low":0}
    for f in findings:
        sev=f.get("severity","Low")
        if sev in counts: counts[sev]+=1
    with open(p,'w',encoding='utf-8') as h:
        h.write(T.render(findings=findings, counts=counts))
