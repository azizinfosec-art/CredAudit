import csv
from ..utils.common import redact_finding_record
FIELDS=['file','rule','redacted','severity','line','context']

def export_csv(f,p):
 with open(p,'w',encoding='utf-8',newline='') as h:
  w=csv.DictWriter(h,fieldnames=FIELDS); w.writeheader()
  for r in f:
   safe = redact_finding_record(r)
   w.writerow({k:safe.get(k,'') for k in FIELDS})
