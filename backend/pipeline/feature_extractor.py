"""
Feature Engineering Pipeline
Converts raw HTTP log entries into numerical feature vectors for ML models.
"""
import re
import math
from urllib.parse import urlparse, parse_qs, unquote
from typing import Optional
import numpy as np
from pydantic import BaseModel


class RawRequest(BaseModel):
    ip_address: str
    method: str
    url: str
    user_agent: Optional[str] = ""
    referer: Optional[str] = ""
    request_body: Optional[str] = ""
    status_code: Optional[int] = 200
    response_size: Optional[int] = 0
    headers: Optional[dict] = {}


class FeatureVector(BaseModel):
    # URL features
    url_length: float
    path_depth: float
    query_param_count: float
    query_string_length: float
    has_double_encoding: float
    has_unicode_escape: float
    has_hex_encoding: float

    # Entropy features (detect obfuscation)
    url_entropy: float
    query_entropy: float
    body_entropy: float

    # Attack pattern signals
    sql_pattern_score: float
    xss_pattern_score: float
    path_traversal_score: float
    cmd_injection_score: float
    ssrf_pattern_score: float

    # Request metadata
    method_is_post: float
    method_is_put: float
    method_is_delete: float
    has_body: float
    body_length: float

    # Suspicious signals
    has_script_tag: float
    has_null_byte: float
    has_long_param: float
    special_char_ratio: float
    digit_ratio: float
    uppercase_ratio: float

    # User agent features
    is_known_bot: float
    ua_length: float
    ua_is_empty: float

    def to_numpy(self) -> np.ndarray:
        return np.array(list(self.model_dump().values()), dtype=np.float32)


KNOWN_BOT_PATTERNS = re.compile(
    r"(googlebot|bingbot|slurp|duckduckbot|baiduspider|yandexbot|"
    r"sogou|exabot|facebot|ia_archiver|python-requests|curl|wget|"
    r"sqlmap|nikto|nmap|masscan|scrapy|libwww)",
    re.IGNORECASE,
)

SQL_PATTERNS = re.compile(
    r"(union\s+select|select\s+.+from|insert\s+into|drop\s+table|"
    r"exec\s*\(|xp_cmdshell|or\s+1=1|and\s+1=1|'\s*or\s*'|"
    r"--\s*$|;\s*--|\bwaitfor\b|\bsleep\b\s*\()",
    re.IGNORECASE,
)

XSS_PATTERNS = re.compile(
    r"(<script|javascript:|on\w+\s*=|eval\s*\(|document\.cookie|"
    r"<iframe|<object|<embed|alert\s*\(|confirm\s*\(|prompt\s*\(|"
    r"&#x|&lt;script)",
    re.IGNORECASE,
)

PATH_TRAVERSAL_PATTERNS = re.compile(
    r"(\.\./|\.\.\\|%2e%2e%2f|%252e%252e|/etc/passwd|/etc/shadow|"
    r"windows/system32|boot\.ini)",
    re.IGNORECASE,
)

CMD_INJECTION_PATTERNS = re.compile(
    r"(;\s*\w+|&&|\|\||`[^`]+`|\$\([^)]+\)|/bin/sh|/bin/bash|"
    r"cmd\.exe|powershell|nc\s+-|wget\s+http|curl\s+http)",
    re.IGNORECASE,
)

SSRF_PATTERNS = re.compile(
    r"(localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.|192\.168\.|10\.|"
    r"172\.(1[6-9]|2\d|3[01])\.|file://|gopher://|dict://|ftp://)",
    re.IGNORECASE,
)


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    n = len(text)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def pattern_score(text: str, pattern: re.Pattern) -> float:
    if not text:
        return 0.0
    matches = pattern.findall(text)
    return min(len(matches) / 3.0, 1.0)


def extract_features(req: RawRequest) -> FeatureVector:
    decoded_url = unquote(unquote(req.url))  # double decode
    parsed = urlparse(decoded_url)
    query_string = parsed.query or ""
    path = parsed.path or ""
    body = req.request_body or ""
    ua = req.user_agent or ""

    params = parse_qs(query_string)
    all_values = " ".join([v for vals in params.values() for v in vals])
    full_text = f"{decoded_url} {body} {all_values}"

    has_long_param = float(
        any(len(v) > 500 for vals in params.values() for v in vals)
    )

    special_chars = sum(1 for c in decoded_url if c in "!@#$%^&*()[]{}|\\<>?")
    special_char_ratio = special_chars / max(len(decoded_url), 1)

    digits = sum(1 for c in decoded_url if c.isdigit())
    digit_ratio = digits / max(len(decoded_url), 1)

    upper = sum(1 for c in decoded_url if c.isupper())
    uppercase_ratio = upper / max(len(decoded_url), 1)

    return FeatureVector(
        url_length=min(len(decoded_url) / 2000.0, 1.0),
        path_depth=min(path.count("/") / 10.0, 1.0),
        query_param_count=min(len(params) / 20.0, 1.0),
        query_string_length=min(len(query_string) / 1000.0, 1.0),
        has_double_encoding=float("%25" in req.url or req.url != decoded_url),
        has_unicode_escape=float("\\u" in full_text or "%u" in full_text),
        has_hex_encoding=float(bool(re.search(r"%[0-9a-fA-F]{2}", req.url))),
        url_entropy=shannon_entropy(decoded_url) / 8.0,
        query_entropy=shannon_entropy(query_string) / 8.0,
        body_entropy=shannon_entropy(body) / 8.0,
        sql_pattern_score=pattern_score(full_text, SQL_PATTERNS),
        xss_pattern_score=pattern_score(full_text, XSS_PATTERNS),
        path_traversal_score=pattern_score(full_text, PATH_TRAVERSAL_PATTERNS),
        cmd_injection_score=pattern_score(full_text, CMD_INJECTION_PATTERNS),
        ssrf_pattern_score=pattern_score(full_text, SSRF_PATTERNS),
        method_is_post=float(req.method.upper() == "POST"),
        method_is_put=float(req.method.upper() == "PUT"),
        method_is_delete=float(req.method.upper() == "DELETE"),
        has_body=float(len(body) > 0),
        body_length=min(len(body) / 10000.0, 1.0),
        has_script_tag=float("<script" in full_text.lower()),
        has_null_byte=float("\x00" in full_text or "%00" in req.url),
        has_long_param=has_long_param,
        special_char_ratio=min(special_char_ratio, 1.0),
        digit_ratio=digit_ratio,
        uppercase_ratio=uppercase_ratio,
        is_known_bot=float(bool(KNOWN_BOT_PATTERNS.search(ua))),
        ua_length=min(len(ua) / 500.0, 1.0),
        ua_is_empty=float(len(ua) == 0),
    )
