import pytest

from rules.engine import run_rules

ATTACKS = [
    ("https://x.com/p?id=1 UNION SELECT username,password FROM users", "SQL_INJECTION"),
    ("https://x.com/p?id=1' OR '1'='1", "SQL_INJECTION"),
    ("https://x.com/s?q=<script>alert(document.cookie)</script>", "XSS"),
    ("https://x.com/s?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", "XSS"),
    ("https://x.com/f?file=../../../../etc/passwd", "PATH_TRAVERSAL"),
    ("https://x.com/ping?host=8.8.8.8;cat /etc/shadow", "CMD_INJECTION"),
    ("https://x.com/fetch?url=http://169.254.169.254/latest/meta-data", "SSRF"),
]


@pytest.mark.parametrize("url,category", ATTACKS)
def test_detects_attack(url, category):
    score, matches = run_rules(url=url, query=url.split("?", 1)[1])
    assert score > 0.5
    assert category in {m.category for m in matches}


@pytest.mark.parametrize("url", [
    "https://shop.example.com/products?page=2&sort=price",
    "https://example.com/blog/2026/11/hello-world",
    "https://example.com/api/users/42",
])
def test_benign_traffic_scores_zero(url):
    query = url.split("?", 1)[1] if "?" in url else ""
    score, matches = run_rules(url=url, query=query)
    assert score == 0.0
    assert matches == []
