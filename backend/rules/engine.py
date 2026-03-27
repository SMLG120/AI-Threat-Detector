"""
Rule-Based Detection Engine
ModSecurity CRS-inspired rule system for detecting OWASP Top 10 attacks.
Each rule has a severity, category, and pattern.
"""
import re
from dataclasses import dataclass, field
from typing import List, Tuple
from urllib.parse import unquote


@dataclass
class Rule:
    id: str
    name: str
    category: str
    severity: float  # 0.0 - 1.0
    pattern: re.Pattern
    fields: List[str] = field(default_factory=lambda: ["url", "body", "query"])


@dataclass
class RuleMatch:
    rule_id: str
    rule_name: str
    category: str
    severity: float
    matched_field: str
    matched_text: str


RULES: List[Rule] = [
    # ─── SQL Injection ───────────────────────────────────────────────────────
    Rule(
        id="SQLi-001",
        name="UNION SELECT Statement",
        category="SQL_INJECTION",
        severity=0.95,
        pattern=re.compile(r"union\s+(?:all\s+)?select", re.I),
    ),
    Rule(
        id="SQLi-002",
        name="Tautology Injection",
        category="SQL_INJECTION",
        severity=0.90,
        pattern=re.compile(r"'\s*(?:or|and)\s+['\d]+=\s*['\d]+", re.I),
    ),
    Rule(
        id="SQLi-003",
        name="SQL Comment Evasion",
        category="SQL_INJECTION",
        severity=0.80,
        pattern=re.compile(r"(?:--|#)\s*$|/\*.*?\*/", re.I),
    ),
    Rule(
        id="SQLi-004",
        name="Time-Based Blind SQLi",
        category="SQL_INJECTION",
        severity=0.92,
        pattern=re.compile(r"\b(?:sleep|waitfor\s+delay|benchmark)\s*\(", re.I),
    ),
    Rule(
        id="SQLi-005",
        name="Stacked Queries",
        category="SQL_INJECTION",
        severity=0.88,
        pattern=re.compile(r";\s*(?:drop|insert|update|delete|create)\s+", re.I),
    ),

    # ─── XSS ─────────────────────────────────────────────────────────────────
    Rule(
        id="XSS-001",
        name="Script Tag Injection",
        category="XSS",
        severity=0.90,
        pattern=re.compile(r"<script[\s>]", re.I),
    ),
    Rule(
        id="XSS-002",
        name="JavaScript Protocol Handler",
        category="XSS",
        severity=0.85,
        pattern=re.compile(r"javascript\s*:", re.I),
    ),
    Rule(
        id="XSS-003",
        name="Inline Event Handler",
        category="XSS",
        severity=0.80,
        pattern=re.compile(r"\bon\w+\s*=\s*['\"]?\s*(?:alert|eval|document)", re.I),
    ),
    Rule(
        id="XSS-004",
        name="DOM-based XSS",
        category="XSS",
        severity=0.85,
        pattern=re.compile(r"document\.(?:cookie|write|location)|window\.location", re.I),
    ),
    Rule(
        id="XSS-005",
        name="HTML Entity Encoded XSS",
        category="XSS",
        severity=0.75,
        pattern=re.compile(r"&#x[0-9a-f]+;|&lt;script", re.I),
    ),

    # ─── Path Traversal ───────────────────────────────────────────────────────
    Rule(
        id="PATH-001",
        name="Directory Traversal Sequence",
        category="PATH_TRAVERSAL",
        severity=0.85,
        pattern=re.compile(r"(?:\.\./|\.\.\\){2,}"),
    ),
    Rule(
        id="PATH-002",
        name="Encoded Path Traversal",
        category="PATH_TRAVERSAL",
        severity=0.88,
        pattern=re.compile(r"%2e%2e[%2f%5c]|%252e%252e", re.I),
    ),
    Rule(
        id="PATH-003",
        name="Sensitive File Access",
        category="PATH_TRAVERSAL",
        severity=0.95,
        pattern=re.compile(
            r"(?:/etc/(?:passwd|shadow|hosts)|windows/system32|boot\.ini|web\.config)",
            re.I,
        ),
    ),

    # ─── Command Injection ────────────────────────────────────────────────────
    Rule(
        id="CMD-001",
        name="Shell Command Chaining",
        category="CMD_INJECTION",
        severity=0.92,
        pattern=re.compile(r"(?:&&|\|\||;)\s*(?:ls|cat|id|whoami|uname|wget|curl)", re.I),
    ),
    Rule(
        id="CMD-002",
        name="Backtick Command Execution",
        category="CMD_INJECTION",
        severity=0.90,
        pattern=re.compile(r"`[^`]+`|\$\([^)]+\)"),
    ),
    Rule(
        id="CMD-003",
        name="Shell Interpreter Access",
        category="CMD_INJECTION",
        severity=0.95,
        pattern=re.compile(r"/bin/(?:sh|bash|dash|zsh)|cmd\.exe|powershell\.exe", re.I),
    ),
    Rule(
        id="CMD-004",
        name="Reverse Shell Pattern",
        category="CMD_INJECTION",
        severity=0.99,
        pattern=re.compile(
            r"(?:nc|ncat|netcat)\s+[-\w\s]*\d{2,5}|bash\s+-i\s+>&", re.I
        ),
    ),

    # ─── SSRF ─────────────────────────────────────────────────────────────────
    Rule(
        id="SSRF-001",
        name="Internal Network Access",
        category="SSRF",
        severity=0.88,
        pattern=re.compile(
            r"(?:localhost|127\.0\.0\.1|0\.0\.0\.0|::1|169\.254\.\d+\.\d+)", re.I
        ),
    ),
    Rule(
        id="SSRF-002",
        name="RFC1918 Private Address",
        category="SSRF",
        severity=0.80,
        pattern=re.compile(
            r"(?:192\.168\.|10\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.)", re.I
        ),
    ),
    Rule(
        id="SSRF-003",
        name="Dangerous Protocol Scheme",
        category="SSRF",
        severity=0.85,
        pattern=re.compile(r"(?:file|gopher|dict|ldap|ftp)://", re.I),
    ),
]

CATEGORY_WEIGHT = {
    "SQL_INJECTION": 1.0,
    "XSS": 0.9,
    "CMD_INJECTION": 1.0,
    "PATH_TRAVERSAL": 0.85,
    "SSRF": 0.85,
}


def run_rules(
    url: str,
    body: str = "",
    query: str = "",
) -> Tuple[float, List[RuleMatch]]:
    """
    Run all rules against the provided request fields.
    Returns (aggregated_score, list_of_matches).
    """
    decoded_url = unquote(unquote(url))
    decoded_body = unquote(body)
    decoded_query = unquote(query)

    field_map = {
        "url": decoded_url,
        "body": decoded_body,
        "query": decoded_query,
    }

    matches: List[RuleMatch] = []
    category_scores: dict[str, float] = {}

    for rule in RULES:
        for field_name in rule.fields:
            text = field_map.get(field_name, "")
            if not text:
                continue
            if rule.pattern.search(text):
                match_obj = rule.pattern.search(text)
                matches.append(
                    RuleMatch(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        category=rule.category,
                        severity=rule.severity,
                        matched_field=field_name,
                        matched_text=match_obj.group(0)[:100],
                    )
                )
                # Keep highest severity per category
                if rule.category not in category_scores or \
                        rule.severity > category_scores[rule.category]:
                    category_scores[rule.category] = rule.severity
                break  # one match per rule is enough

    if not category_scores:
        return 0.0, []

    # Aggregate: weighted average of top category scores
    weighted_sum = sum(
        score * CATEGORY_WEIGHT.get(cat, 1.0)
        for cat, score in category_scores.items()
    )
    total_weight = sum(
        CATEGORY_WEIGHT.get(cat, 1.0) for cat in category_scores
    )
    rule_score = min(weighted_sum / total_weight, 1.0)

    # Boost if multiple attack categories found
    if len(category_scores) > 1:
        rule_score = min(rule_score * 1.15, 1.0)

    return rule_score, matches
