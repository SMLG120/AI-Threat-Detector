# 🛡️ AI-WAF — AI-Powered Web Application Firewall

> **Real-time threat detection engine** for HTTP web traffic, combining machine learning ensemble models with a ModSecurity-inspired rule engine to emulate a next-generation WAF.

[![Python](https://img.shields.io/badge/Python-3.11-blue?style=flat-square&logo=python)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-async-009688?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18-61dafb?style=flat-square&logo=react)](https://react.dev)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ed?style=flat-square&logo=docker)](https://docker.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)

---

## ✨ Overview

AI-WAF is a full-stack, production-grade threat detection system that analyzes HTTP request logs in real time, assigns a **threat score (0–1)**, and classifies each request as **LOW / MEDIUM / HIGH** risk. It combines two detection strategies:

| Layer | Method | Weight |
|-------|--------|--------|
| **Rule Engine** | Regex patterns (ModSecurity CRS-inspired) | 45% |
| **Isolation Forest** | Anomaly detection (unsupervised) | 20% |
| **Random Forest** | Binary classification (supervised) | 25% |
| **Autoencoder** | Reconstruction error (deep learning) | 10% |

All scores are aggregated into a single weighted ensemble score.

---

## 🏗️ Architecture

```
HTTP Logs / nginx
      │
      ▼
┌─────────────────────────────────────────────────────┐
│                   FastAPI Backend                    │
│                                                     │
│  ┌──────────────┐    ┌──────────────────────────┐  │
│  │ Log Ingestion│───▶│  Feature Extraction      │  │
│  │  REST API    │    │  (30 numerical features) │  │
│  └──────────────┘    └──────────┬───────────────┘  │
│                                 │                   │
│              ┌──────────────────┼──────────────┐   │
│              ▼                  ▼              ▼    │
│       ┌──────────┐    ┌───────────────┐  ┌──────┐  │
│       │  Rule    │    │  ML Ensemble  │  │  DB  │  │
│       │  Engine  │    │  IF + RF + AE │  │  PG  │  │
│       └────┬─────┘    └──────┬────────┘  └──────┘  │
│            └────────┬────────┘                      │
│                     ▼                               │
│            ┌─────────────────┐                      │
│            │ Score Aggregator│                      │
│            │ Weighted Ensemble│                     │
│            └────────┬────────┘                      │
│                     │                               │
│         ┌───────────┴───────────┐                   │
│         ▼                       ▼                   │
│   PostgreSQL              WebSocket Broadcast        │
│   (persist logs)         (real-time dashboard)       │
└─────────────────────────────────────────────────────┘
                              │
                              ▼
                   ┌──────────────────┐
                   │  React Dashboard │
                   │  Live Charts     │
                   │  Alert Feed      │
                   └──────────────────┘
```

---

## 🚀 Quick Start (local)

### Prerequisites

- Docker & Docker Compose v2+
- (Optional) Python 3.11+ for the attack simulator

### 1. Configure

```bash
cp .env.example .env
# Fill in secrets — generate each with: openssl rand -hex 32
# For local use set DOMAIN=localhost
```

### 2. Launch

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build -d
```

| Service | URL |
|---------|-----|
| **Dashboard** | https://localhost (self-signed cert locally) — sign in with `DASHBOARD_API_KEY` |
| **API docs** (dev only) | http://localhost:8000/docs |

On first boot the `init` job runs database migrations and trains the bootstrap models.

### 3. Simulate Traffic

```bash
pip install httpx
export AIWAF_INGEST_KEY=<INGEST_API_KEY from .env>
python scripts/simulate_attacks.py --count 200 --ratio 0.35 --delay 0.05
```

---

## 🏭 Production Deployment

The default `docker-compose.yml` is the production stack:

| Service | Role |
|---------|------|
| `caddy` | Only public entrypoint (80/443). Automatic Let's Encrypt TLS, security headers, 1 MB body limit, blocks `/metrics` and `/docs` |
| `init` | One-off: `alembic upgrade head` + initial model bundle |
| `backend` | Gunicorn + Uvicorn workers, non-root, model volume mounted **read-only** |
| `worker` / `beat` | Celery: scheduled retraining + daily data retention |
| `postgres` / `redis` | Internal network only, password-protected |
| `backup` | Nightly `pg_dump` into `./backups` |

**Steps on a fresh VPS:**

1. Point a DNS `A` record (e.g. `waf.example.com`) at the server; open ports 80 and 443 only.
2. Install Docker, clone the repo, `cp .env.example .env`, and fill in `DOMAIN` and all secrets.
3. `docker compose up -d --build`
4. Visit `https://waf.example.com` and sign in with `DASHBOARD_API_KEY`.
5. Point your log shipper at `POST https://waf.example.com/api/logs/ingest` with header `X-API-Key: <INGEST_API_KEY>`.

**Upgrading an existing installation** created by an older version (which used `create_all`, ran as root, and had the hardcoded password `aiwaf_secret`):

```bash
# 0. Back up first
docker compose up -d postgres
docker exec aiwaf_postgres pg_dump -U aiwaf -d aiwaf | gzip > backups/pre-migration.sql.gz

# 1. Postgres only reads POSTGRES_PASSWORD when the volume is first created,
#    so rotate the existing user to the new password from .env
set -a; . ./.env; set +a
docker exec aiwaf_postgres psql -U aiwaf -d aiwaf -c "ALTER USER aiwaf WITH PASSWORD '$POSTGRES_PASSWORD';"

# 2. The API now runs as uid 10001; hand it the old root-owned model volume
docker run --rm -v ai-waf_model_data:/m alpine chown -R 10001:10001 /m

# 3. Mark the original schema as applied, then start (init applies 0002+)
docker compose run --rm --no-deps init alembic stamp 0001
docker compose up -d --build --remove-orphans
```

**Auth model**

| Key | Grants |
|-----|--------|
| `INGEST_API_KEY` | `POST /api/logs/ingest` only |
| `DASHBOARD_API_KEY` | All read endpoints, labeling, retraining, WebSocket (`/ws/stream?token=…`) |

**Observability:** JSON logs on stdout; `/health` (liveness) and `/ready` (DB + Redis + models) for probes; Prometheus metrics at `/metrics` on the internal network (`aiwaf_requests_analyzed_total`, `aiwaf_detection_seconds`, HTTP metrics).

---

## 📁 Project Structure

```
ai-waf/
├── backend/
│   ├── main.py                    # FastAPI app entry point
│   ├── core/
│   │   ├── config.py              # Settings (env vars, thresholds)
│   │   ├── database.py            # Async SQLAlchemy + PostgreSQL
│   │   ├── redis_client.py        # Async Redis wrapper
│   │   └── websocket_manager.py   # WS connection manager
│   ├── pipeline/
│   │   ├── feature_extractor.py   # 30-feature extraction engine
│   │   └── detector.py            # Orchestration pipeline
│   ├── rules/
│   │   └── engine.py              # ModSecurity CRS-inspired rules
│   ├── ml/
│   │   └── model_manager.py       # Ensemble model loader + inference
│   ├── api/routes/
│   │   ├── logs.py                # POST /api/logs/ingest, PATCH label
│   │   ├── threats.py             # GET /api/threats/alerts
│   │   ├── dashboard.py           # GET /api/dashboard/stats
│   │   ├── models.py              # POST /api/models/retrain
│   │   └── websocket.py           # WS /ws/stream
│   └── db/
│       └── models.py              # SQLAlchemy ORM models
├── frontend/
│   └── src/
│       ├── pages/Dashboard.tsx    # Main dashboard UI
│       ├── hooks/useWebSocket.ts  # WS hook with auto-reconnect
│       ├── api/client.ts          # API client
│       ├── types/index.ts         # TypeScript types
│       └── styles.css             # Dark cybersecurity theme
├── scripts/
│   └── simulate_attacks.py        # Attack traffic generator
├── caddy/
│   └── Caddyfile                  # TLS edge proxy + security headers
├── docker-compose.yml             # Production stack
└── docker-compose.dev.yml         # Local overrides (ports, /docs)
```

---

## 🔍 Detection Capabilities

### Rule Engine

Detects **OWASP Top 10** attack patterns using 20+ regex rules:

| Category | Rules | Examples |
|----------|-------|---------|
| SQL Injection | SQLi-001 to SQLi-005 | UNION SELECT, time-based blind, stacked queries |
| XSS | XSS-001 to XSS-005 | `<script>`, JS protocol, event handlers, DOM XSS |
| Path Traversal | PATH-001 to PATH-003 | `../../etc/passwd`, encoded traversal |
| Command Injection | CMD-001 to CMD-004 | shell chaining, backticks, reverse shells |
| SSRF | SSRF-001 to SSRF-003 | internal IPs, private ranges, file:// protocol |

### ML Feature Engineering

30 numerical features extracted per request:

- **URL features**: length, depth, param count, encoding detection
- **Entropy signals**: Shannon entropy on URL, query string, body (detects obfuscation)
- **Pattern scores**: regex density for each attack category
- **Request metadata**: HTTP method, body presence, size
- **Suspicious signals**: null bytes, long params, special char ratios
- **User agent analysis**: known bot detection, UA anomalies

---

## 📡 API Reference

### Ingest a Log

```http
POST /api/logs/ingest
Content-Type: application/json
X-API-Key: <INGEST_API_KEY>

{
  "ip_address": "45.33.32.156",
  "method": "GET",
  "url": "https://example.com/api/users?id=1' OR 1=1--",
  "user_agent": "curl/8.2.1",
  "request_body": ""
}
```

**Response:**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "threat_score": 0.8742,
  "threat_level": "HIGH",
  "is_malicious": true,
  "attack_types": ["SQL_INJECTION"]
}
```

### WebSocket Stream

```javascript
const ws = new WebSocket(`wss://${location.host}/ws/stream?token=${DASHBOARD_API_KEY}`);
ws.onmessage = (e) => {
  const { type, data } = JSON.parse(e.data);
  // type: "new_request" | "alert"
};
```

### Other Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/logs/` | Paginated log history (`limit` ≤ 200) |
| PATCH | `/api/logs/{id}/label` | Human-verified label `{"is_malicious": bool}` — the retraining ground truth |
| GET | `/api/threats/alerts` | Active threat alerts |
| GET | `/api/dashboard/stats` | Aggregated statistics |
| POST | `/api/models/retrain` | Queue model retraining (Celery) |
| GET | `/api/models/status` | Loaded model version + latest training metrics |
| GET | `/health` | Liveness (public) |
| GET | `/ready` | Readiness: DB, Redis, models (internal) |

All `/api/*` endpoints require `X-API-Key`. Interactive docs are available at http://localhost:8000/docs when running with `docker-compose.dev.yml`.

---

## ⚙️ Configuration

All configuration is via environment variables — see [`.env.example`](.env.example). Required: `DOMAIN`, `POSTGRES_PASSWORD`, `REDIS_PASSWORD`, `INGEST_API_KEY`, `DASHBOARD_API_KEY` (keys ≥ 32 chars, and different from each other). The app refuses to start without them, and validates that ensemble weights sum to 1.0.

The autoencoder is not implemented yet, so `AUTOENCODER_WEIGHT` defaults to `0` and its former 10% goes to the Random Forest.

---

## 🔄 Model Retraining

Retraining uses **only human-verified labels** — click **Attack** / **Benign** on rows in the dashboard (or call `PATCH /api/logs/{id}/label`). Training on the model's own predictions would create a feedback loop and let attackers poison the model.

- Runs every `RETRAIN_INTERVAL_HOURS` (default 6) via Celery beat, or on demand with the **Retrain** button.
- Needs `RETRAIN_MIN_VERIFIED_SAMPLES` (default 200) labels covering both classes.
- A candidate is evaluated on a held-out split of real verified traffic and promoted only if F1 ≥ `RETRAIN_MIN_F1` and not worse than the current model. Results are recorded in `model_metadata`.
- Promoted models are written atomically and every API worker hot-reloads them via Redis pub/sub.

Request logs older than `RETENTION_DAYS` (default 30) are purged daily; verified samples are kept.

---

## 🧪 Running Tests

```bash
cd backend
pip install -r requirements-dev.txt
pytest -v
```

---

## 🗺️ Roadmap

- [ ] GeoIP blocking with MaxMind GeoLite2
- [ ] Active learning — label new samples from UI
- [ ] Graph Neural Network for IP relationship analysis
- [ ] Kubernetes Helm chart
- [ ] ONNX export for all models
- [x] Prometheus metrics endpoint
- [ ] IP reputation scoring

---

## 📄 License

MIT © 2024 — See [LICENSE](LICENSE) for details.

---

<div align="center">
  <sub>Built as a portfolio project demonstrating full-stack engineering + ML + cybersecurity knowledge.</sub>
</div>
