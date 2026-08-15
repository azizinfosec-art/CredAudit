import os, re, json, base64
from bisect import bisect_right
from dataclasses import dataclass, asdict, field
from typing import List, Dict, Any, Optional, Iterable
from .rules import build_rules
from ..utils.entropy import shannon_entropy
from ..utils.common import redact_secret
@dataclass
class Finding:
    file: str; rule: str; match: str; redacted: str; context: str; severity: str; line: int
    confidence: int = 0
    finding_class: str = "possible"
    validity: str = "not_applicable"
    evidence: List[str] = field(default_factory=list)

SECRET_CAPTURE_GROUPS = {
    "PasswordAssignment": 3,
    "PasswordAssignmentLoose": 2,
    "PasswordValueAssignment": 3,
    "PasswordValueAssignmentLoose": 2,
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
    "PasswordValueAssignment": 64,
    "PasswordValueAssignmentLoose": 54,
    "PasswordAssignment": 50,
    "PasswordAssignmentLoose": 40,
    "UsernameNearPassword": 55,
    "CredentialPair": 58,
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
        "PasswordValueAssignment":"Medium",
        "PasswordValueAssignmentLoose":"Medium",
        "UsernameAssignment":"Low",
        "UsernameNearPassword":"High",
        "CredentialPair":"High",
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

CREDENTIAL_PAIR_USER_RE = re.compile(r"^[A-Za-z0-9._%+\-@\\]{1,128}$")
CREDENTIAL_PAIR_USER_DENYLIST = {
    "accept",
    "authorization",
    "content-length",
    "content-type",
    "date",
    "description",
    "file",
    "host",
    "line",
    "name",
    "path",
    "port",
    "referer",
    "referrer",
    "server",
    "status",
    "time",
    "title",
    "url",
    "uri",
    "user-agent",
    "version",
}
CREDENTIAL_PAIR_SECRET_DENYLIST = {
    "false",
    "localhost",
    "none",
    "null",
    "true",
}
CREDENTIAL_PAIR_METADATA_LABELS = {
    "accept-encoding",
    "accept-language",
    "cache-control",
    "content-description",
    "content-disposition",
    "content-encoding",
    "content-id",
    "content-language",
    "content-location",
    "content-transfer-encoding",
    "etag",
    "expires",
    "last-modified",
    "mime-version",
    "pragma",
    "transfer-encoding",
}
CREDENTIAL_PAIR_METADATA_PREFIXES = (
    "content-",
    "proxy-",
    "sec-",
)
COMMON_WEAK_PASSWORDS = {
    "123456",
    "12345678",
    "admin",
    "admin123",
    "changeme",
    "iloveyou",
    "letmein",
    "p@ss",
    "pass",
    "pass123",
    "passw0rd",
    "password",
    "password1",
    "qwerty",
    "root",
    "toor",
    "welcome",
}
FILENAME_CREDENTIAL_HINTS = (
    "account",
    "combo",
    "cred",
    "login",
    "pass",
    "password",
    "secret",
    "user",
)
PROVIDER_VALIDITY_RULES = {
    "AWSAccessKeyID",
    "AWSSecretAccessKey",
    "GitHubToken",
    "GitLabPAT",
    "GoogleAPIKey",
    "NpmToken",
    "OpenAIKey",
    "SendGridKey",
    "SlackToken",
    "StripeKey",
    "TelegramBotToken",
    "TwilioAuthToken",
}
BASE_CONFIDENCE = {
    "PrivateKey": 98,
    "AWSSecretAccessKey": 94,
    "AWSAccessKeyID": 90,
    "GitHubToken": 92,
    "StripeKey": 92,
    "OpenAIKey": 92,
    "SlackToken": 90,
    "SendGridKey": 90,
    "NpmToken": 88,
    "GoogleAPIKey": 88,
    "AzureSAS": 88,
    "TelegramBotToken": 86,
    "TwilioAuthToken": 90,
    "TwilioAccountSID": 80,
    "SlackWebhook": 90,
    "DBConnectionString": 88,
    "JWT": 78,
    "APIKeyGeneric": 70,
    "PasswordAssignment": 70,
    "PasswordAssignmentLoose": 62,
    "PasswordValueAssignment": 82,
    "PasswordValueAssignmentLoose": 74,
    "CredentialPair": 74,
    "UsernameNearPassword": 68,
    "PasswordCandidate": 45,
    "HighEntropyString": 42,
    "UsernameAssignment": 25,
    "PasswordKeyword": 18,
}
RULE_EVIDENCE = {
    "PrivateKey": "PEM private-key block with begin/end markers",
    "AWSAccessKeyID": "AWS access key identifier format",
    "AWSSecretAccessKey": "AWS secret access key assignment format",
    "GitHubToken": "GitHub token prefix and length format",
    "StripeKey": "Stripe secret key prefix and length format",
    "OpenAIKey": "OpenAI-style secret key format",
    "SlackToken": "Slack token prefix format",
    "SendGridKey": "SendGrid key format",
    "GitLabPAT": "GitLab personal access token format",
    "NpmToken": "npm token format",
    "GoogleAPIKey": "Google API key format",
    "AzureSAS": "Azure SAS URL contains signature",
    "TelegramBotToken": "Telegram bot token format",
    "TwilioAccountSID": "Twilio account SID format",
    "TwilioAuthToken": "Twilio auth token assignment format",
    "SlackWebhook": "Slack webhook URL format",
    "DBConnectionString": "database URI contains embedded password",
    "JWT": "valid JWT header and payload structure",
    "APIKeyGeneric": "generic API key prefix pattern",
    "PasswordAssignment": "password-like keyword with explicit assignment",
    "PasswordAssignmentLoose": "password-like keyword near guarded value",
    "PasswordValueAssignment": "password keyword with explicit assignment",
    "PasswordValueAssignmentLoose": "password keyword near guarded value",
    "CredentialPair": "compact same-line username:password format",
    "UsernameNearPassword": "username-like line immediately before password finding",
    "PasswordCandidate": "standalone token has password-like shape",
    "HighEntropyString": "long high-entropy token",
    "UsernameAssignment": "username/login assignment indicator",
    "PasswordKeyword": "password keyword indicator",
}

def _looks_like_domain(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}", value or ""))

PASSWORD_VALUE_KEYWORD_RE = re.compile(r"(?i)\b(password|passwd|passphrase|passcode|pass|pwd)\b")

def _looks_like_metadata_label(value: str) -> bool:
    low = str(value or "").strip().lower()
    if low in CREDENTIAL_PAIR_METADATA_LABELS:
        return True
    return any(low.startswith(prefix) for prefix in CREDENTIAL_PAIR_METADATA_PREFIXES)

def _looks_like_credential_pair_secret(value: str) -> bool:
    token = _clean_secret_value(value)
    if not (1 <= len(token) <= 256):
        return False
    low = token.lower()
    if low in CREDENTIAL_PAIR_SECRET_DENYLIST:
        return False
    if low.startswith(("http://", "https://", "www.")):
        return False
    if re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", token):
        return False
    if _looks_like_domain(token):
        return False
    if low in COMMON_WEAK_PASSWORDS:
        return True
    if _looks_like_password_candidate(token):
        return True
    has_letter = any(c.isalpha() for c in token)
    has_digit = any(c.isdigit() for c in token)
    has_symbol = any(not c.isalnum() for c in token)
    return len(token) >= 4 and has_letter and (has_digit or has_symbol)

def _credential_pair_parts(line_text: str) -> Optional[tuple[str, str]]:
    text = str(line_text or "").strip()
    if not text or ":" not in text or "://" in text:
        return None
    user, secret = text.split(":", 1)
    user = _clean_secret_value(user)
    secret = _clean_secret_value(secret)
    if not user or not secret:
        return None
    if re.search(r"\s", user) or re.search(r"\s", secret):
        return None
    low_user = user.lower()
    if low_user in CREDENTIAL_PAIR_USER_DENYLIST:
        return None
    if low_user in {"password", "passwd", "passphrase", "passcode", "pass", "pwd", "secret", "token", "api_key", "apikey", "key"}:
        return None
    if not CREDENTIAL_PAIR_USER_RE.fullmatch(user):
        return None
    if not any(c.isalpha() for c in user):
        return None
    if not _looks_like_credential_pair_secret(secret):
        return None
    return user, secret

def _credential_pair_password(line_text: str) -> Optional[str]:
    pair = _credential_pair_parts(line_text)
    return pair[1] if pair else None

def _file_size(path: str) -> Optional[int]:
    try:
        return os.path.getsize(path)
    except Exception:
        return None

def _filename_has_credential_hint(path: str) -> bool:
    name = os.path.basename(str(path or "")).lower()
    return any(hint in name for hint in FILENAME_CREDENTIAL_HINTS)

def _finding_class(rule_name: str, confidence: int) -> str:
    if rule_name == "PrivateKey" and confidence >= 95:
        return "confirmed_format"
    if confidence >= 80:
        return "likely"
    if confidence >= 50:
        return "possible"
    return "indicator"

def _severity_from_confidence(confidence: int) -> str:
    score = int(confidence or 0)
    if score >= 95:
        return "Critical"
    if score >= 80:
        return "High"
    if score >= 50:
        return "Medium"
    return "Low"

def _score_finding(finding: Finding, lines: List[str], credential_pair_count: int) -> tuple[int, List[str], str]:
    score = BASE_CONFIDENCE.get(finding.rule, 50)
    score_cap = 99
    evidence = [RULE_EVIDENCE.get(finding.rule, "rule pattern matched")]
    path = finding.file or ""
    ext = os.path.splitext(path)[1].lower()
    size = _file_size(path)
    ctx = str(finding.context or "")
    raw = str(finding.match or "")
    low_ctx = ctx.lower()

    if finding.rule == "CredentialPair":
        score_cap = 89
        pair = _credential_pair_parts(ctx)
        if pair:
            user, secret = pair
            score += 6
            evidence.append("line has no whitespace around the credential separator")
            metadata_label = _looks_like_metadata_label(user)
            if metadata_label:
                score_cap = 69
                evidence.append("left side looks like an HTTP/MIME metadata label, not a username")
            elif "@" in user or "\\" in user or "." in user:
                score += 5
                evidence.append("left side looks like an account name or email")
            else:
                score += 3
                evidence.append("left side is username-like")
            if secret.lower() in COMMON_WEAK_PASSWORDS:
                score += 8
                evidence.append("right side is a common weak password value")
            elif _looks_like_password_candidate(secret):
                score += 10
                evidence.append("right side has password-like complexity")
        if ext == ".txt":
            score += 5
            evidence.append("source file is plain text")
        if size is not None and size <= 5 * 1024 * 1024:
            score += 4
            evidence.append("source file is 5 MB or smaller")
        if _filename_has_credential_hint(path):
            score += 5
            evidence.append("filename suggests credential material")
        if credential_pair_count >= 2:
            score += 6
            evidence.append("file contains multiple credential-pair lines")
    elif finding.rule in {"PasswordAssignment", "PasswordAssignmentLoose", "PasswordValueAssignment", "PasswordValueAssignmentLoose"}:
        if finding.rule in {"PasswordValueAssignment", "PasswordValueAssignmentLoose"} and PASSWORD_VALUE_KEYWORD_RE.search(ctx):
            score += 10
            evidence.append("value appears after a password/pass/pwd keyword")
        elif re.search(r"(?i)\b(password|pass|pwd|secret|api[-_]?key|token)\b", ctx):
            score += 6
            evidence.append("context contains a secret-related keyword")
        if re.search(r"(=|:|=>|:=|->)", ctx):
            score += 5
            evidence.append("context uses an assignment separator")
        if raw.lower() in COMMON_WEAK_PASSWORDS:
            score += 5
            evidence.append("value is a common weak password")
        elif _looks_like_password_candidate(raw):
            score += 8
            evidence.append("value has password-like complexity")
        if ext in {".env", ".json", ".yaml", ".yml", ".ini", ".cfg", ".toml", ".txt"}:
            score += 3
            evidence.append("source file type commonly stores configuration or credentials")
    elif finding.rule == "UsernameNearPassword":
        score += 8
        evidence.append("nearby line contains a detected password value")
        if ext == ".txt":
            score += 4
            evidence.append("source file is plain text")
    elif finding.rule == "PasswordCandidate":
        if _looks_like_password_candidate(raw):
            score += 10
            evidence.append("token contains letters, digits, and complexity markers")
        if ext == ".txt":
            score += 3
            evidence.append("source file is plain text")
    elif finding.rule == "HighEntropyString":
        try:
            ent = shannon_entropy(raw)
            if ent >= 4.5:
                score += 8
                evidence.append("entropy is very high")
            elif ent >= 4.0:
                score += 4
                evidence.append("entropy is above threshold")
        except Exception:
            pass
    elif finding.rule in PROVIDER_VALIDITY_RULES:
        evidence.append("provider-specific format can be verified with a future validator")

    if any(ph in low_ctx for ph in SUPPRESS_PHRASES):
        score -= 20
        evidence.append("context contains documentation or policy wording")
    return max(0, min(score_cap, int(score))), evidence, ("unknown" if finding.rule in PROVIDER_VALIDITY_RULES else "not_applicable")

def _annotate_findings(findings: List[Finding], lines: List[str]) -> List[Finding]:
    credential_pair_count = sum(1 for line in lines if _credential_pair_parts(line))
    for finding in findings:
        score, evidence, validity = _score_finding(finding, lines, credential_pair_count)
        finding.confidence = score
        finding.evidence = evidence
        finding.validity = validity
        finding.finding_class = _finding_class(finding.rule, score)
        finding.severity = _severity_from_confidence(score)
    return findings

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
    sev_rank = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}.get(finding.severity, 1)
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

def _line_starts(text: str) -> List[int]:
    starts = [0]
    for m in re.finditer("\n", text or ""):
        starts.append(m.end())
    return starts

def _line_number_for_pos(line_starts: List[int], pos: int) -> int:
    try:
        return max(1, bisect_right(line_starts, max(0, int(pos))))
    except Exception:
        return 1

def _line_context(lines: List[str], line: int, fallback: str) -> str:
    return lines[line - 1][:200] if 0 < line <= len(lines) else str(fallback or "")[:200]

def scan_text(path, text, entropy_min_len=20, entropy_thresh=4.0, rule_level: Optional[int] = None, only_rules: Optional[Iterable[str]] = None)->List[Finding]:
    out=[]; lines=text.splitlines(); joined=text
    line_starts = _line_starts(joined)
    # Select rule set by sensitivity level (None implies default 2)
    only_set = set([x.strip() for x in (only_rules or []) if str(x).strip()]) if only_rules is not None else None
    for r in build_rules(rule_level):
        if only_set is not None and r.name not in only_set:
            continue
        for m in r.pattern.finditer(joined):
            raw=m.group(0); s=_finding_match(r.name, m); start=m.start(); line=_line_number_for_pos(line_starts,start); ctx=_line_context(lines,line,raw)
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
    if (rule_level or 2) >= 2 and (only_set is None or 'CredentialPair' in only_set):
        for idx, line_text in enumerate(lines, start=1):
            secret = _credential_pair_password(line_text)
            if secret:
                out.append(Finding(path, 'CredentialPair', secret, redact_secret(secret), line_text[:200], 'High', idx))
    # Entropy-based detection is disabled at level 1 to reduce noise
    if (rule_level or 2) >= 2 and (only_set is None or 'HighEntropyString' in only_set):
        pat = re.compile(r"[A-Za-z0-9+/=_-]{20,}")
        for m in pat.finditer(joined):
            t = _entropy_match_value(m.group(0))
            if len(t) >= entropy_min_len and shannon_entropy(t) >= entropy_thresh:
                pos = m.start()
                line = _line_number_for_pos(line_starts, pos)
                ctx = _line_context(lines, line, t)
                out.append(Finding(path, 'HighEntropyString', t, redact_secret(t), ctx, 'Low', line))
    deduped = dedupe_findings(out)
    password_like_lines = {
        int(f.line or 0)
        for f in deduped
        if f.rule in {"PasswordAssignment", "PasswordAssignmentLoose", "PasswordValueAssignment", "PasswordValueAssignmentLoose", "PasswordCandidate"}
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
        if f.rule in {"PasswordAssignment", "PasswordAssignmentLoose", "PasswordValueAssignment", "PasswordValueAssignmentLoose"}
    }
    final = [
        f for f in deduped
        if not (f.rule == "PasswordKeyword" and int(f.line or 0) in stronger_password_lines)
    ]
    return _annotate_findings(final, lines)
def serialize_findings(l: List[Finding])->List[Dict[str,Any]]: return [asdict(x) for x in l]
