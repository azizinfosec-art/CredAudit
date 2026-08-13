import re, json, base64
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional, Iterable
from .rules import build_rules
from ..utils.entropy import shannon_entropy
from ..utils.common import redact_secret
@dataclass
class Finding:
    file: str; rule: str; match: str; redacted: str; context: str; severity: str; line: int

SECRET_CAPTURE_GROUPS = {
    "PasswordAssignment": 3,
    "PasswordAssignmentLoose": 2,
    "AWSSecretAccessKey": 3,
    "DBConnectionString": 2,
    "TwilioAuthToken": 1,
    "UsernameAssignment": 3,
}

RULE_PRIORITY = {
    "PrivateKey": 100,
    "AWSSecretAccessKey": 95,
    "AWSAccessKeyID": 90,
    "OpenAIKey": 90,
    "StripeKey": 90,
    "SlackToken": 90,
    "SlackWebhook": 85,
    "SendGridKey": 85,
    "GitHubToken": 85,
    "GitLabPAT": 80,
    "NpmToken": 80,
    "GoogleAPIKey": 80,
    "AzureSAS": 80,
    "TelegramBotToken": 80,
    "TwilioAuthToken": 80,
    "TwilioAccountSID": 75,
    "APIKeyGeneric": 70,
    "DBConnectionString": 65,
    "JWT": 60,
    "PasswordAssignment": 50,
    "PasswordAssignmentLoose": 40,
    "UsernameNearPassword": 55,
    "UsernameAssignment": 25,
    "PasswordKeyword": 20,
    "PasswordCandidate": 15,
    "HighEntropyString": 10,
}

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
        "UsernameAssignment":"Low",
        "UsernameNearPassword":"High",
        "PasswordKeyword":"Low",
        "PasswordCandidate":"Low",
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
SUPPRESS_PHRASES = ["password policy","password manager","password length","min password","hashed password","secret scanner"]
def _clean_secret_value(value: str) -> str:
    cleaned = str(value or "").strip().strip("\"'`")
    while cleaned and cleaned[-1] in ",;)]}":
        cleaned = cleaned[:-1].rstrip()
    while cleaned and cleaned[0] in "([{":
        cleaned = cleaned[1:].lstrip()
    return cleaned

def _finding_match(rule_name: str, match: re.Match) -> str:
    group_index = SECRET_CAPTURE_GROUPS.get(rule_name)
    if group_index:
        try:
            value = match.group(group_index)
            if value:
                return _clean_secret_value(value)
        except Exception:
            pass
    return _clean_secret_value(match.group(0))

def _entropy_match_value(token: str) -> str:
    value = token.strip()
    if "=" in value.rstrip("="):
        left, right = value.split("=", 1)
        if any(k in left.lower() for k in ("password", "pass", "pwd", "secret", "api", "key", "token")):
            value = right.strip()
    return _clean_secret_value(value)

def _looks_like_password_candidate(value: str) -> bool:
    token = _clean_secret_value(value)
    if not (6 <= len(token) <= 64):
        return False
    low = token.lower()
    if any(ph in low for ph in SUPPRESS_PHRASES):
        return False
    if low.startswith(("http://", "https://", "www.")):
        return False
    if "/" in token or "\\" in token or "=" in token or ":" in token:
        return False
    if re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", token):
        return False
    if token.lower() in {"password", "username", "admin", "secret", "token"}:
        return False
    has_lower = any(c.islower() for c in token)
    has_upper = any(c.isupper() for c in token)
    has_letter = has_lower or has_upper
    has_digit = any(c.isdigit() for c in token)
    has_symbol = any(not c.isalnum() for c in token)
    if not has_letter or not has_digit:
        return False
    if has_symbol:
        return True
    if has_lower and has_upper:
        return True
    return False

def _username_neighbor_value(line_text: str) -> Optional[str]:
    text = str(line_text or "").strip()
    if not text:
        return None
    assignment = re.fullmatch(
        r"(?i)\b(username|user_id|userid|login|user|email)\b\s*[\"']?(=|:|=>|:=|->)\s*[\"']?([^\s\"']{1,})[\"']?",
        text,
    )
    if assignment:
        text = assignment.group(3)
    elif re.search(r"\s", text):
        return None
    token = _clean_secret_value(text)
    if not (2 <= len(token) <= 128):
        return None
    low = token.lower()
    if low in {"user", "username", "login", "email", "password", "pass", "pwd", "secret", "token"}:
        return None
    if any(ph in low for ph in SUPPRESS_PHRASES):
        return None
    if low.startswith(("http://", "https://", "www.")):
        return None
    if "/" in token or "=" in token or ":" in token:
        return None
    if not any(c.isalnum() for c in token):
        return None
    return token

def _finding_rank(finding: Finding) -> tuple[int, int]:
    sev_rank = {"Low": 1, "Medium": 2, "High": 3}.get(finding.severity, 1)
    return sev_rank, RULE_PRIORITY.get(finding.rule, 30)

def dedupe_findings(findings: List[Finding]) -> List[Finding]:
    best_by_value: Dict[tuple[str, int, str], Finding] = {}
    order: List[tuple[str, int, str]] = []
    for finding in findings:
        value = (finding.match or "").strip()
        if not value:
            continue
        key = (finding.file, int(finding.line or 0), value)
        current = best_by_value.get(key)
        if current is None:
            best_by_value[key] = finding
            order.append(key)
            continue
        if _finding_rank(finding) > _finding_rank(current):
            best_by_value[key] = finding
    return [best_by_value[key] for key in order]

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
            raw=m.group(0); s=_finding_match(r.name, m); start=m.start(); line=joined.count('\n',0,start)+1; ctx=lines[line-1][:200] if 0<line<=len(lines) else raw[:200]
            low=raw.lower()
            for bad in ['email=']:
                if bad in low: break
            else:
                if any(ph in low for ph in SUPPRESS_PHRASES): 
                    continue
                sev = severity_for_rule(r.name)
                if r.name=='JWT' and not _looks_like_jwt(s): 
                    continue
                out.append(Finding(path,r.name,s,redact_secret(s),ctx,sev,line))
    if (rule_level or 2) >= 2 and (only_set is None or 'PasswordCandidate' in only_set):
        token_pat = re.compile(r"[^\s]{6,64}")
        for idx, line_text in enumerate(lines, start=1):
            ctx = line_text[:200]
            for m in token_pat.finditer(line_text):
                token = _clean_secret_value(m.group(0))
                if _looks_like_password_candidate(token):
                    out.append(Finding(path, 'PasswordCandidate', token, redact_secret(token), ctx, 'Low', idx))
    # Entropy-based detection is disabled at level 1 to reduce noise
    if (rule_level or 2) >= 2 and (only_set is None or 'HighEntropyString' in only_set):
        pat = re.compile(r"[A-Za-z0-9+/=_-]{20,}")
        for m in pat.finditer(joined):
            t = _entropy_match_value(m.group(0))
            if len(t) >= entropy_min_len and shannon_entropy(t) >= entropy_thresh:
                pos = m.start()
                line = joined.count('\n', 0, pos) + 1
                ctx = lines[line-1][:200] if 0 < line <= len(lines) else t[:200]
                out.append(Finding(path, 'HighEntropyString', t, redact_secret(t), ctx, 'Low', line))
    deduped = dedupe_findings(out)
    password_like_lines = {
        int(f.line or 0)
        for f in deduped
        if f.rule in {"PasswordAssignment", "PasswordAssignmentLoose", "PasswordCandidate"}
    }
    if only_set is None or "UsernameNearPassword" in only_set:
        for line_no in sorted(password_like_lines):
            prev_line = line_no - 1
            if prev_line < 1 or prev_line in password_like_lines:
                continue
            username = _username_neighbor_value(lines[prev_line - 1])
            if username:
                ctx = lines[prev_line - 1][:200]
                deduped.append(Finding(path, 'UsernameNearPassword', username, redact_secret(username), ctx, 'High', prev_line))
        deduped = dedupe_findings(deduped)
    stronger_password_lines = {
        int(f.line or 0)
        for f in deduped
        if f.rule in {"PasswordAssignment", "PasswordAssignmentLoose"}
    }
    return [
        f for f in deduped
        if not (f.rule == "PasswordKeyword" and int(f.line or 0) in stronger_password_lines)
    ]
def serialize_findings(l: List[Finding])->List[Dict[str,Any]]: return [asdict(x) for x in l]
