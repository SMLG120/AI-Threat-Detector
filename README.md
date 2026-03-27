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

## 🚀 Quick Start

### Prerequisites

- Docker & Docker Compose v2+
- (Optional) Python 3.11+ for the attack simulator

### 1. Clone & Launch

```bash
git clone https://github.com/YOUR_USERNAME/ai-waf.git
cd ai-waf

# Start all services
docker compose up --build -d
```

Services will be available at:

| Service | URL |
|---------|-----|
| **Dashboard** | http://localhost:3000 |
| **API docs** | http://localhost:8000/docs |
| **API (direct)** | http://localhost:8000 |

> **Note:** On first boot, the backend will auto-train ML models using synthetic data. This takes ~30–60 seconds.

### 2. Simulate Traffic

```bash
cd scripts

# Install dependencies (one time)
pip install httpx

# Run the simulator — 200 requests, 35% malicious
python simulate_attacks.py --count 200 --ratio 0.35 --delay 0.05

# Heavy attack scenario
python simulate_attacks.py --count 500 --ratio 0.7 --delay 0
```

### 3. Watch the Dashboard

Open http://localhost:3000 and watch threats appear in real time via WebSocket.

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
│   │   ├── logs.py                # POST /api/logs/ingest
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
├── nginx/
│   └── nginx.conf                 # Reverse proxy + WS config
└── docker-compose.yml
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
const ws = new WebSocket("ws://localhost:8000/ws/stream");
ws.onmessage = (e) => {
  const { type, data } = JSON.parse(e.data);
  // type: "new_request" | "alert"
};
```

### Other Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/logs/` | Paginated log history |
| GET | `/api/threats/alerts` | Active threat alerts |
| GET | `/api/dashboard/stats` | Aggregated statistics |
| POST | `/api/models/retrain` | Trigger model retraining |
| GET | `/api/models/status` | Model health check |
| GET | `/health` | Service health |

Full interactive docs at **http://localhost:8000/docs**

---

## ⚙️ Configuration

All configuration via environment variables or `.env`:

```env
# Database
DATABASE_URL=postgresql+asyncpg://aiwaf:aiwaf_secret@postgres:5432/aiwaf
REDIS_URL=redis://redis:6379/0

# Detection thresholds
THREAT_SCORE_LOW=0.30
THREAT_SCORE_MEDIUM=0.60
THREAT_SCORE_HIGH=0.85

# Ensemble weights (must sum to 1.0)
RULE_WEIGHT=0.45
ISOLATION_FOREST_WEIGHT=0.20
RANDOM_FOREST_WEIGHT=0.25
AUTOENCODER_WEIGHT=0.10
```

---

## 🔄 Model Retraining

Once enough real traffic accumulates in the database, trigger retraining via the dashboard or API:

```bash
curl -X POST http://localhost:8000/api/models/retrain
```

The system will pull labeled request logs from PostgreSQL and retrain the Isolation Forest and Random Forest models, then save them to disk.

---

## 🧪 Running Tests

```bash
cd backend
pip install pytest pytest-asyncio httpx
pytest tests/ -v
```

---

## 🗺️ Roadmap

- [ ] GeoIP blocking with MaxMind GeoLite2
- [ ] Active learning — label new samples from UI
- [ ] Graph Neural Network for IP relationship analysis
- [ ] Kubernetes Helm chart
- [ ] ONNX export for all models
- [ ] Prometheus metrics endpoint
- [ ] IP reputation scoring

---

## 📄 License

MIT © 2024 — See [LICENSE](LICENSE) for details.

---

<div align="center">
  <sub>Built as a portfolio project demonstrating full-stack engineering + ML + cybersecurity knowledge.</sub>
</div>
