# AI-WAF: AI-Powered Web Application Firewall & Security Monitoring Platform

[![Python](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111%2B-009688.svg)](https://fastapi.tiangolo.com)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED.svg)](https://www.docker.com/)
[![React](https://img.shields.io/badge/React-18-61DAFB.svg)](https://react.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

AI-WAF is a high-performance, production-style Web Application Firewall (WAF) and real-time security monitoring platform designed to operate as a reverse proxy between internet clients and arbitrary protected web applications.

It fuses deterministic **rule-based detection** with **supervised machine-learning classification** and a dynamic **risk scoring engine** to detect and mitigate application-layer cyber attacks before they reach backend workloads.

---

## 1. High-Level Architecture

```
Internet Clients
       │
       ▼
[ Reverse Proxy / Load Balancer (Nginx) ]
       │
       ▼
[ AI-WAF Gateway (FastAPI:8000) ]
  ├── Request Parser & Size Enforcer
  ├── Rate Limiter (Redis)
  ├── Request Normalizer (Multi-pass URL/Entity/Unicode)
  │
  ├── Multi-Layer Threat Analysis
  │     ├── Rule Detection Engine (SQLi, XSS, RCE, Path Traversal)
  │     └── ML Classifier (TF-IDF + Character n-grams + Logistic Regression)
  │
  └── Risk Engine (Score: 0 - 100)
        ├── ALLOW (0-29)   ──► Transparent Forward to Upstream Protected App
        ├── FLAG  (30-69)  ──► Log Security Event & Forward
        └── BLOCK (70-100) ──► HTTP 403 Forbidden + Log Security Event (PostgreSQL)

Protected Application (Upstream:3000)
       ▲
       │ (Legitimate traffic only)
```

---

## 2. Threat Classification Taxonomy

AI-WAF classifies incoming HTTP traffic into one of six categories:
1. **NORMAL** — Legitimate user and API traffic
2. **SQL INJECTION (SQLi)** — Structural syntax manipulation, stacked queries, boolean/time-based SQL payloads
3. **CROSS-SITE SCRIPTING (XSS)** — Dangerous markup, event handlers, javascript pseudoprotocols, script injections
4. **COMMAND INJECTION (RCE)** — Shell operators, pipeline chaining, OS environment manipulation
5. **PATH TRAVERSAL** — Directory escape attempts (`../`, mixed slashes, encoded traversals)
6. **SUSPICIOUS / UNKNOWN** — Anomalous payloads matching rate-limit or heuristic anomaly triggers

---

## 3. Directory Layout

```
ai-waf/
├── backend/                  # FastAPI Reverse Proxy Gateway & Security Engine
│   ├── app/
│   │   ├── api/              # Versioned API routes & health diagnostics
│   │   ├── proxy/            # Transparent HTTP reverse proxy & upstream handlers
│   │   ├── detection/        # Rule engine, ML classifier, and Risk Engine
│   │   │   ├── rules/        # Modular detection rules (SQLi, XSS, RCE, Path Traversal)
│   │   │   └── ml/           # Local model inference & vectorization
│   │   ├── rate_limit/       # Redis-backed sliding window rate limiter
│   │   ├── database/         # SQLAlchemy models, migrations, and event repositories
│   │   ├── logging/          # Redacted structured JSON security logger
│   │   └── schemas/          # Pydantic request & response models
│   ├── tests/                # Automated pytest suite
│   └── requirements.txt
│
├── demo-app/                 # Upstream demonstration target application
│   ├── main.py
│   └── requirements.txt
│
├── ml/                       # ML research, dataset processing, and training pipeline
│   ├── data/                 # Raw and processed datasets
│   ├── notebooks/            # Exploration notebooks
│   ├── preprocessing/        # Dataset cleaning, normalization & splitting
│   ├── training/             # Scikit-learn training & evaluation scripts
│   └── models/               # Serialized model artifacts (.joblib, metadata.json)
│
├── frontend/                 # React 18 + TypeScript + Tailwind CSS Admin Dashboard
│   ├── src/
│   │   ├── components/       # UI Cards, Topology Map, Event Tables, Badges
│   │   ├── pages/            # Overview, Events, Rules, Models, App Management
│   │   └── services/         # API clients
│   └── package.json
│
├── nginx/                    # Edge load balancer & reverse proxy configuration
├── docker/                   # Multi-stage Dockerfiles
├── docs/                     # Technical specifications & threat models
├── docker-compose.yml        # Multi-container orchestration
└── .env.example              # Environment configuration template
```

---

## 4. Quick Start with Docker Compose

To launch the complete platform (WAF Gateway, Protected Demo App, PostgreSQL, Redis, React Dashboard, and Nginx):

```bash
# 1. Clone repository and navigate into project directory
cd ai-waf

# 2. Setup environment file
cp .env.example .env

# 3. Build and launch all services in detached mode
docker compose up --build -d

# 4. View active service logs
docker compose logs -f waf-backend
```

### Accessing Endpoints:
- **WAF Security Dashboard**: [http://localhost:5173](http://localhost:5173) (or [http://localhost](http://localhost))
- **WAF Gateway API**: [http://localhost:8000](http://localhost:8000)
- **WAF Health Diagnostics**: [http://localhost:8000/api/health](http://localhost:8000/api/health)
- **Protected Upstream Demo App**: [http://localhost:3000](http://localhost:3000) (Internal upstream target)

---

## 5. Local Development (Without Docker)

### Backend & WAF Gateway:
```bash
cd backend
python -m venv .venv
# On Windows: .venv\Scripts\activate | On Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### Protected Demo App:
```bash
cd demo-app
python -m venv .venv
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 3000 --reload
```

### Frontend Dashboard:
```bash
cd frontend
npm install
npm run dev
```

---

## 6. Development Phases Roadmap

- [x] **Phase 1**: Project Scaffolding, Infrastructure, FastAPI Gateway Foundation, Demo App, React Dashboard Scaffolding, Health Check Diagnostics.
- [x] **Phase 2**: HTTP Request Inspection Pipeline & Normalization.
- [x] **Phase 3**: Rule Detection Engine (SQLi, XSS, RCE, Path Traversal).
- [x] **Phase 4**: Supervised ML Pipeline (TF-IDF + Character n-grams + Logistic Regression).
- [x] **Phase 5**: Risk Scoring & Decision Engine.
- [x] **Phase 6**: High-performance Async Reverse Proxy Gateway.
- [x] **Phase 7**: PostgreSQL Persistence & Security Event Storage.
- [x] **Phase 8**: Redis Sliding-Window Rate Limiting.
- [x] **Phase 9**: Interactive Real-Time Cyber Monitoring Dashboard.
- [x] **Phase 10**: Security Hardening, SSRF Protection, and Credential Redaction.
- [ ] **Phase 11**: End-to-End Automated Testing & Security Verification.
- [ ] **Phase 12**: Production Deployment, Nginx SSL/TLS, and Metrics.
