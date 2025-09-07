import re, json, base64
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional, Iterable
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
        # Provider-specific tokens
        "GoogleAPIKey":"Medium",
        "SlackToken":"High",
        "SendGridKey":"High",
        "GitLabPAT":"Medium",
        "NpmToken":"Medium",
        "OpenAIKey":"High",
        "TelegramBotToken":"Medium",
        "TwilioAccountSID":"Medium",
        "TwilioAuthToken":"High",
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
def scan_text(path, text, entropy_min_len=20, entropy_thresh=4.0, rule_level: Optional[int] = None, only_rules: Optional[Iterable[str]] = None)->List[Finding]:
    out=[]; lines=text.splitlines(); joined=text
    # Select rule set by sensitivity level (None implies default 2)
    only_set = set([x.strip() for x in (only_rules or []) if str(x).strip()]) if only_rules else None
    for r in build_rules(rule_level):
        if only_set is not None and r.name not in only_set:
            continue
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
    # Entropy-based detection is disabled at level 1 to reduce noise
    if (rule_level or 2) >= 2 and (only_set is None or 'HighEntropyString' in only_set):
        pat = re.compile(r"[A-Za-z0-9+/=_-]{20,}")
        for m in pat.finditer(joined):
            t = m.group(0)
            if len(t) >= entropy_min_len and shannon_entropy(t) >= entropy_thresh:
                pos = m.start()
                line = joined.count('\n', 0, pos) + 1
                ctx = lines[line-1][:200] if 0 < line <= len(lines) else t[:200]
                out.append(Finding(path, 'HighEntropyString', t, redact_secret(t), ctx, 'Low', line))
    return out
def serialize_findings(l: List[Finding])->List[Dict[str,Any]]: return [asdict(x) for x in l]
