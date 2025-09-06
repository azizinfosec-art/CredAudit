import re
from dataclasses import dataclass
from typing import List, Pattern, Optional


@dataclass
class Rule:
    name: str
    pattern: Pattern
    description: str
    example: str


def build_rules(level: Optional[int] = None) -> List['Rule']:
    """Return rule set for the given sensitivity level.

    Levels:
      1 (cautious): high-confidence provider-specific rules only
      2 (balanced): level 1 + generic password/API key assignments
      3 (aggressive): same as level 2 (entropy handled in scanner)
    """
    lvl = int(level or 2)
    rules: List[Rule] = []
    rules.append(Rule(
        "PrivateKey",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", re.MULTILINE),
        "PEM-encoded private key material",
        "-----BEGIN PRIVATE KEY----- ...",
    ))
    rules.append(Rule(
        "AWSAccessKeyID",
        re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
        "AWS Access Key ID",
        "AKIA...",
    ))
    rules.append(Rule(
        "GitHubToken",
        re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b"),
        "GitHub token",
        "ghp_...",
    ))
    rules.append(Rule(
        "JWT",
        re.compile(r"\beyJ[0-9A-Za-z_-]+?\.[0-9A-Za-z_-]+?\.[0-9A-Za-z_-]{8,}\b"),
        "JWT",
        "eyJ...",
    ))
    if lvl >= 2:
        # Explicit separators near a password-like keyword
        rules.append(Rule(
            "PasswordAssignment",
            re.compile(r"\b(password|pass|pwd|secret|apikey|api_key|token)\b\s*(=|:|=>|:=|->)\s*[\"']?([^\s\"']{4,})[\"']?", re.IGNORECASE),
            "Password/secret assignment (explicit separators)",
            "password: secret123",
        ))
        # Whitespace-separated or with common separators, with basic strength guards
        rules.append(Rule(
            "PasswordAssignmentLoose",
            re.compile(r"(?ix)\b(password|pass|pwd|secret|api[-_]?key|token)\b(?:\s*(?:=|:|=>|:=|->)\s*|\s{1,3})[\"']?(?=[^\s\"']{6,})(?=[^\s\"']*(?:\d|[^A-Za-z]))([^\s\"']+)[\"']?"),
            "Password/secret assignment with whitespace or separators (guarded)",
            "password secret123",
        ))
        rules.append(Rule(
            "APIKeyGeneric",
            re.compile(r"\b(sk|pk)-[A-Za-z0-9]{10,}\b"),
            "Generic API key",
            "sk-abc123...",
        ))
    rules.append(Rule(
        "SlackWebhook",
        re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]{20,}"),
        "Slack Incoming Webhook URL",
        "https://hooks.slack.com/services/...",
    ))
    # New high-value rules
    rules.append(Rule(
        "AWSSecretAccessKey",
        re.compile(r"(?ix)\b(aws[_-]?secret[_-]?access[_-]?key)\b\s*(=|:)\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
        "AWS Secret Access Key (contextual assignment)",
        "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    ))
    rules.append(Rule(
        "AzureSAS",
        re.compile(r"(?i)https?://[a-z0-9.-]+\.core\.windows\.net/[^?\s]+\?[^\s]*sig=[A-Za-z0-9%+/=]{20,}"),
        "Azure Storage SAS URL containing signature",
        "https://acct.blob.core.windows.net/container/blob.txt?sv=...&sig=...",
    ))
    rules.append(Rule(
        "StripeKey",
        re.compile(r"\bsk_(live|test)_[A-Za-z0-9]{24,}\b"),
        "Stripe secret key",
        "sk_live_51H...",
    ))
    rules.append(Rule(
        "DBConnectionString",
        re.compile(r"(?ix)\b(postgres(?:ql)?|mysql|mongodb|rediss?)://[^\s:@/]+:([^\s@/]+)@[^\s]+"),
        "Database connection URI with embedded password",
        "postgres://user:pass@host:5432/db",
    ))
    if lvl >= 2:
        # Provider-specific high-signal tokens (balanced/aggressive levels)
        rules.append(Rule(
            "GoogleAPIKey",
            re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
            "Google API key",
            "AIza...",
        ))
        rules.append(Rule(
            "SlackToken",
            re.compile(r"\bxox[abprs]-[0-9A-Za-z-]{10,48}\b"),
            "Slack token",
            "xoxb-...",
        ))
        rules.append(Rule(
            "SendGridKey",
            re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b"),
            "SendGrid API key",
            "SG.xxxxx.yyyyy",
        ))
        rules.append(Rule(
            "GitLabPAT",
            re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"),
            "GitLab personal access token",
            "glpat-...",
        ))
        rules.append(Rule(
            "NpmToken",
            re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),
            "npm token",
            "npm_...",
        ))
        rules.append(Rule(
            "OpenAIKey",
            re.compile(r"\bsk-[A-Za-z0-9]{40,55}\b"),
            "OpenAI API key",
            "sk-...",
        ))
        rules.append(Rule(
            "TelegramBotToken",
            re.compile(r"\b[0-9]{9,10}:[A-Za-z0-9_-]{35}\b"),
            "Telegram bot token",
            "123456789:abcdef...",
        ))
        rules.append(Rule(
            "TwilioAccountSID",
            re.compile(r"\bAC[0-9a-fA-F]{32}\b"),
            "Twilio Account SID",
            "ACXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
        ))
        rules.append(Rule(
            "TwilioAuthToken",
            re.compile(r"(?i)\btwilio[^\n]{0,30}\b([0-9a-f]{32})\b"),
            "Twilio auth token (contextual)",
            "twilio auth token: 0123abcd...",
        ))
    return rules
