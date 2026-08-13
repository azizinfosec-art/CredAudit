import csv
from ..utils.common import redact_finding_record
FIELDS=['file','rule','redacted','severity','confidence','finding_class','validity','evidence','line','context']

def export_csv(f,p):
 with open(p,'w',encoding='utf-8',newline='') as h:
  w=csv.DictWriter(h,fieldnames=FIELDS); w.writeheader()
  for r in f:
   safe = redact_finding_record(r)
   if isinstance(safe.get('evidence'), list):
    safe['evidence'] = '; '.join(str(x) for x in safe.get('evidence') or [])
   w.writerow({k:safe.get(k,'') for k in FIELDS})
