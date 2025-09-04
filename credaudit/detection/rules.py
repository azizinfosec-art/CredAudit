import re

def get_builtin_rules():
    return [
        {
            "name": "AWS Key",
            "type": "AWS Key",
            "pattern": r"AKIA[0-9A-Z]{16,}|ASIA[0-9A-Z]{16,}",
        },
        {
            "name": "AWS Secret",
            "type": "AWS Secret",
            "pattern": r"(?i)aws(_|-)?secret(_|-)?access(_|-)?key[=:：]\s*[A-Za-z0-9/+=]{40}",
        },
        {
            "name": "GitHub Token",
            "type": "GitHub Token",
            "pattern": r"gh[pousr]_[A-Za-z0-9]{36,}",
        },
        {
            "name": "GCP Key",
            "type": "GCP Key",
            "pattern": r"AIza[0-9A-Za-z-_]{35,}",
        },
        {
            "name": "Slack Token",
            "type": "Slack Token",
            "pattern": r"xox[baprs]-[A-Za-z0-9-]{10,48}",
        },
        {
            "name": "JWT",
            "type": "JWT",
            "pattern": r"eyJ[A-Za-z0-9._-]{20,}\.[A-Za-z0-9._-]{20,}\.[A-Za-z0-9._-]{20,}",
        },
        {
            "name": "Azure Key",
            "type": "Azure Key",
            "pattern": r"(?i)azure[_-]?key[=:：]\s*[\w-]{20,}",
        },
        {
            "name": "Private Key",
            "type": "Private Key",
            "pattern": r"-----BEGIN( RSA| DSA| EC| OPENSSH)? PRIVATE KEY-----",
        },
        {
            "name": "SSH Key",
            "type": "SSH Key",
            "pattern": r"ssh-rsa\s+[A-Za-z0-9+/=]+",
        },
        {
            "name": "Stripe Live Secret",
            "type": "Stripe Secret",
            "pattern": r"sk_live_[0-9a-zA-Z]{24}",
        },
        {
            "name": "Stripe Test Secret",
            "type": "Stripe Secret",
            "pattern": r"sk_test_[0-9a-zA-Z]{24}",
        },
        {
            "name": "Twilio API Key",
            "type": "Twilio Key",
            "pattern": r"SK[0-9a-fA-F]{32}",
        },
        {
            "name": "Google OAuth Client ID",
            "type": "Google OAuth",
            "pattern": r"[0-9]+-([a-z0-9]+)\.apps\.googleusercontent\.com",
        },
        {
            "name": "Facebook Access Token",
            "type": "Facebook Token",
            "pattern": r"EAACEdEose0cBA[0-9A-Za-z]+",
        },
        {
            "name": "Heroku API Key",
            "type": "Heroku Key",
            "pattern": r"heroku[a-z0-9]{32}",
        },
        {
            "name": "Password",
            "type": "Password",
            "pattern": r"(?i)(pass(word)?|pwd|secret|apikey|api_key|token|auth)[\s]*[=:：][\s]*[^\s]+",
        },
        {
            "name": "API Key",
            "type": "API Key",
            "pattern": r"(?i)api[_-]?key[=:：]\s*[\w-]{20,}",
        },
        {
            "name": "Database Connection String",
            "type": "DB Conn String",
            "pattern": r"(postgres|mysql|mongodb|mssql|oracle|redis|sqlite)://[^\s]+",
        },
        {
            "name": "Generic Token",
            "type": "Generic Token",
            "pattern": r"(?i)(token|access[_-]?token)[\s]*[=:：][\s]*[A-Za-z0-9\-_.]{16,}",
        },
        {
            "name": "Generic Secret",
            "type": "Generic Secret",
            "pattern": r"(?i)(secret|client[_-]?secret)[\s]*[=:：][\s]*[A-Za-z0-9\-_.]{16,}",
        },
        {
            "name": "Generic Client ID",
            "type": "Generic Client ID",
            "pattern": r"(?i)client[_-]?id[=:：][\s]*[A-Za-z0-9\-_.]{10,}",
        },
        {
            "name": "Generic Bearer",
            "type": "Bearer Token",
            "pattern": r"Bearer\s+[A-Za-z0-9\-_.]{20,}",
        },
    ]

def match_rules(info, rules):
    text = info.get("text", "")
    matches = []
    for rule in rules:
        for m in re.finditer(rule["pattern"], text):
            matches.append({
                "path": info["path"],
                "type": rule["type"],
                "match": m.group(0),
                "position": m.start(),
            })
    return matches
