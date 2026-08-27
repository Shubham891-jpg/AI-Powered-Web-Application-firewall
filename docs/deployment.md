# AI-WAF Deployment & Operations Guide

## 1. Deployment Modes

### 1.1 Local Development (Docker Compose)
The primary development and demonstration topology uses Docker Compose:
- **`waf-backend`**: Reverse proxy gateway & detection engine (Port 8000)
- **`protected-demo-app`**: Upstream mock e-commerce web application (Port 3000)
- **`postgres`**: Security event and policy persistence (Port 5432)
- **`redis`**: Rate limiting and state cache (Port 6379)
- **`waf-frontend`**: React security analytics dashboard (Port 5173 / 80)
- **`nginx`**: Edge gateway routing traffic across services (Port 80)

To start:
```bash
docker compose up --build -d
```

### 1.2 Standalone Python & Node Execution
For direct debugging and development without containers:
```bash
# 1. Start demo upstream
cd demo-app && uvicorn main:app --port 3000

# 2. Start WAF Gateway
cd backend && uvicorn app.main:app --port 8000

# 3. Start Frontend Dashboard
cd frontend && npm run dev
```

---

## 2. Health Monitoring & Observability
- **Liveness probe**: `GET /health` -> returns 200 `{"status": "ok"}`
- **Readiness probe**: `GET /api/health` -> verifies DB pool, Redis ping, and upstream connectivity.
