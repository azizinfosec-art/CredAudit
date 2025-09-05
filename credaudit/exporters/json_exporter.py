import json

def export_json(f,p):
 with open(p,'w',encoding='utf-8') as h: json.dump(f,h,ensure_ascii=False,indent=2)
