import math
def shannon_entropy(s: str) -> float:
    if not s: return 0.0
    d={}
    for b in s.encode('utf-8',errors='ignore'):
        d[b]=d.get(b,0)+1
    n=sum(d.values())
    e=0.0
    for v in d.values():
        p=v/n; e-=p*math.log2(p)
    return e
