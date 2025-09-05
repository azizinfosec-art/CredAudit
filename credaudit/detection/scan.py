import re, json, base64
from dataclasses import dataclass, asdict
from typing import List, Dict, Any
from .rules import build_rules
from ..utils.entropy import shannon_entropy
from ..utils.common import redact_secret
@dataclass
class Finding:
    file: str; rule: str; match: str; redacted: str; context: str; severity: str; line: int
def severity_for_rule(rule_name: str) -> str:
    base={
        "PrivateKey":"High",
        "AWSAccessKeyID":"High",
        "AWSSecretAccessKey":"High",
        "GitHubToken":"High",
        "StripeKey":"High",
        "AzureSAS":"High",
        "DBConnectionString":"Medium",
        "JWT":"Medium",
        "PasswordAssignment":"Medium",
        "PasswordAssignmentLoose":"Medium",
        "SlackWebhook":"Medium",
        "APIKeyGeneric":"Medium",
        "HighEntropyString":"Low",
    }
    return base.get(rule_name,"Low")
SUPPRESS_PHRASES = ["password policy","password manager","password length","min password","hashed password"]
def _looks_like_jwt(token: str)->bool:
    try:
        parts=token.split('.')
        if len(parts)!=3: return False
        header,payload,signature=parts
        def b64d(s):
            s+='='*((4-len(s)%4)%4)
            return base64.urlsafe_b64decode(s.encode('utf-8',errors='ignore'))
        h=json.loads(b64d(header) or b"{}")
        p=json.loads(b64d(payload) or b"{}")
        return isinstance(h,dict) and isinstance(p,dict)
    except Exception:
        return False
def scan_text(path, text, entropy_min_len=20, entropy_thresh=4.0)->List[Finding]:
    out=[]; lines=text.splitlines(); joined=text
    for r in build_rules():
        for m in r.pattern.finditer(joined):
            s=m.group(0); start=m.start(); line=joined.count('\n',0,start)+1; ctx=lines[line-1][:200] if 0<line<=len(lines) else s[:200]
            low=s.lower()
            for bad in ['username=','user=','name=','email=']:
                if bad in low: break
            else:
                if any(ph in low for ph in SUPPRESS_PHRASES): 
                    continue
                sev = severity_for_rule(r.name)
                if r.name=='JWT' and not _looks_like_jwt(s): 
                    continue
                out.append(Finding(path,r.name,s,redact_secret(s),ctx,sev,line))
    for t in re.findall(r"[A-Za-z0-9+/=_-]{20,}", joined):
        if len(t)>=entropy_min_len and shannon_entropy(t)>=entropy_thresh:
            pos=joined.find(t); line=joined.count('\n',0,pos)+1; ctx=lines[line-1][:200] if 0<line<=len(lines) else t[:200]
            out.append(Finding(path,'HighEntropyString',t,redact_secret(t),ctx,'Low',line))
    return out
def serialize_findings(l: List[Finding])->List[Dict[str,Any]]: return [asdict(x) for x in l]
