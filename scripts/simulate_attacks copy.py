# filepath: /Users/smlgmac/Desktop/Projects/Cybersecurity Projects/AI-Threat/ai-waf/scripts/simulate_attacks.py
import asyncio
import random
import time
from httpx import AsyncClient

# ...existing imports...

async def generate_random_request():
    # Sample benign/malicious patterns
    benign_urls = ["https://shop.example.com/products", "https://shop.example.com/about"]
    malicious_urls = ["https://shop.example.com/api/users?id=1' OR '1'='1", "https://shop.example.com/search?q=<script>alert(1)</script>"]
    is_malicious = random.choice([True, False])
    url = random.choice(malicious_urls if is_malicious else benign_urls)
    return {
        "ip_address": f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}",
        "method": random.choice(["GET", "POST"]),
        "url": url,
        "path": url.split("?")[0].replace("https://shop.example.com", ""),
        "query_string": url.split("?")[1] if "?" in url else "",
        "user_agent": random.choice(["Mozilla/5.0 (Windows)", "curl/8.2.1"]),
        "status_code": 200 if not is_malicious else random.choice([403, 500]),
        "response_size": random.randint(100, 10000),
        "request_body": "" if random.random() > 0.5 else '{"test": "data"}',
        "headers": {},
        "features": {}  # Will be extracted by backend
    }

async def continuous_simulation(count_per_batch=10, interval=5):
    async with AsyncClient() as client:
        while True:
            for _ in range(count_per_batch):
                data = await generate_random_request()
                try:
                    response = await client.post("http://localhost:8000/api/logs/ingest", json=data)
                    print(f"Sent: {response.status_code}")
                except Exception as e:
                    print(f"Error: {e}")
            await asyncio.sleep(interval)  # Wait before next batch

if __name__ == "__main__":
    asyncio.run(continuous_simulation())