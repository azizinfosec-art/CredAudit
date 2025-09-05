import json, os
LEVEL_MAP={"High":"error","Medium":"warning","Low":"note"}
def export_sarif(findings, p):
    runs=[{"tool":{"driver":{"name":"CredAudit","version":"0.3.4"}},"results":[]}]
    for f in findings:
        runs[0]["results"].append({
            "ruleId": f.get("rule","Secret"),
            "level": LEVEL_MAP.get(f.get("severity","Low"),"note"),
            "message": {"text": f.get("redacted","[redacted]")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": os.path.abspath(f.get("file","")).replace("\\","/")},
                    "region": {"startLine": int(f.get("line",1))}
                }
            }]
        })
    with open(p,'w',encoding='utf-8') as h:
        json.dump({"version":"2.1.0","runs":runs}, h, ensure_ascii=False, indent=2)
