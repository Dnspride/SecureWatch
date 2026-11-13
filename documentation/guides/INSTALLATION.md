# SecureWatch Platform Installation Guide

## 1. Overview
SecureWatch is an enterprise cybersecurity platform uniting IAM, Endpoint Security Monitoring, EDR, and SIEM into a single pane of glass.

---

## 2. Prerequisites
- Docker Engine 24.0+ & Docker Compose v2.20+
- Python 3.11+
- Node.js 18+ (for local frontend development)
- PostgreSQL 15+ & Redis 7+ (or run via provided Docker Compose)

---

## 3. Quickstart with Docker Compose

1. **Clone and Navigate to Workspace:**
   ```bash
   cd d:\DHANUZ\Apps\Antigravity
   ```

2. **Configure Environment:**
   ```bash
   cp .env.example .env
   # Edit .env and customize secrets/passwords
   ```

3. **Start All Services:**
   ```bash
   docker compose up -d
   ```
   This initializes:
   - PostgreSQL 15 on port 5432
   - Redis 7 on port 6379
   - OpenSearch 2.11 on port 9200
   - Backend API on port 8000
   - Frontend SOC Console on port 3000
   - Celery background workers and scheduler

4. **Verify Container Health:**
   ```bash
   docker compose ps
   ```

5. **Access the Console:**
   - Web SOC Dashboard: `http://localhost:3000`
   - Interactive Swagger API Docs: `http://localhost:8000/docs`
   - Default Administrator Credentials:
     - Username: `admin`
     - Password: `SecureWatch@2026!`
