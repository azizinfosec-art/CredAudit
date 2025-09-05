import csv
FIELDS=['file','rule','redacted','severity','line','context']

def export_csv(f,p):
 with open(p,'w',encoding='utf-8',newline='') as h:
  w=csv.DictWriter(h,fieldnames=FIELDS); w.writeheader()
  for r in f: w.writerow({k:r.get(k,'') for k in FIELDS})
