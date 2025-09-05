import re
from dataclasses import dataclass
from typing import List, Pattern


@dataclass
class Rule:
    name: str
    pattern: Pattern
    description: str
    example: str


def build_rules() -> List['Rule']:
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
    return rules

