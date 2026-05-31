# Ghost Security Platform v3.0 — Architecture & Feature Map

## Stack at a Glance

```
FastAPI (78 endpoints)
  └── Multi-LLM Router (Claude / OpenAI / Gemini / Ollama + consensus)
  └── Orchestration (DAG TaskGraph · RuntimeSupervisor · Tracing)
  └── Security Engines
        ├── Python OWASP (35) · Secrets (45) · Taint · AST Call Graph
        ├── TON / FunC / Tact (87 rules) · Contract Graph
        ├── JS/TS (25) · Solidity (20)
        ├── Dependency (73 CVE + Reachability)
        └── Kubernetes (18, CIS Benchmark + OWASP K8s)
  └── Post-Processing
        ├── ConfidenceEngine (FP filter · P1-P5 priority)
        ├── CVE/CWE Enricher (30 CWE · OWASP Top10 · osv.dev)
        ├── ReachabilityAnalyzer (-67% dep CVE noise)
        ├── MessageNormalizer (no empty messages)
        └── RemediationEngine (pattern · LLM · diff · PR · rollback)
  └── Persistence
        ├── SQLite (scan history · diff · trend)
        └── Vector Memory (Qdrant → ChromaDB → in-memory)
  └── Integrations
        ├── GitHub App (inline PR comments · Check Runs)
        ├── SARIF 2.1.0 + GitHub Actions YAML
        ├── VS Code Extension (TypeScript, scan-on-save)
        ├── Prometheus /metrics + Grafana dashboard
        └── Helm Chart (Kubernetes deployment)
```

## Rule Count

| Scanner | Rules |
|---------|-------|
| OWASP Python | 35 |
| TON (FunC/Tact) | **87** |
| Secret Detection | 45 |
| JS/TS | 25 |
| Solidity | 20 |
| K8s (CIS) | **18** |
| Dependency CVEs | 73 |
| Semgrep (optional) | 5000+ |

## Tests: 155/155 ✅

| Suite | Tests |
|-------|-------|
| test_all_scanners | 88 |
| test_runtime | 35 |
| test_ton_extended | 19 |
| test_five_features | 48 |

## New in This Session (5 major features)

### 1. Multi-LLM Router
`runtime/providers/multi_llm_router.py`
Claude + OpenAI + Gemini + Ollama. Task routing table (security/coding/ton/fast/remediation).
Fallback chains — при падении провайдера → следующий автоматически.
Consensus engine: 3 провайдера + vote/longest/fastest/cheapest стратегии.
Cost tracker с учётом стоимости по провайдерам.

### 2. Vector Memory
`memory/vector/ghost_memory.py`
Qdrant → ChromaDB → in-memory fallback.
OpenAI embeddings → Ollama nomic-embed-text → TF-IDF fallback.
3 коллекции: ghost_findings, ghost_remediations, ghost_scans.
Семантический поиск похожих уязвимостей из истории всех сканов.
Self-improving: чем больше сканов — тем точнее recall.

### 3. Telemetry Stack
`telemetry/metrics.py`
11 Prometheus метрик: scans, findings, LLM calls, API latency, memory entries.
OpenTelemetry трейсы с JSONL fallback.
Grafana dashboard JSON (8 панелей) — авто-провижн через docker compose.
`GET /metrics` — подключается к Prometheus за 30 секунд.

### 4. Kubernetes Security Scanner
`scanners/k8s_scanner/k8s_scanner.py`
18 правил, CIS Kubernetes Benchmark + OWASP K8s Top 10.
Статический анализ YAML манифестов без живого кластера.
Live mode через kubectl (если доступен).
RBAC audit: wildcard permissions, cluster-admin bindings, default SA.
Pod Security: privileged, root, hostNetwork, allowPrivilegeEscalation.
Secrets в env vars, resource limits, image tag pinning.
Helm chart для деплоя Ghost в Kubernetes (`infra/helm/`).

### 5. Autonomous Remediation Engine
`remediation/remediation_engine.py`
Pattern fixer (детерминированный, confidence=0.90): MD5→SHA256, shell=True→False, debug=True→False, K8s privileged→false и др.
LLM fixer (через Multi-LLM Router, confidence=0.70): генерирует полный фикс с контекстом.
Patch validator: синтаксис Python (ast.parse) + YAML.
FileApplier с backup/rollback — применяет только с явного подтверждения.
PRCreator — создаёт draft GitHub PR с diff.
`POST /api/remediate/generate` — diff показывается пользователю, применение опционально.

## Docker Compose Profiles

```bash
docker compose up                    # ghost + redis
docker compose --profile ai up      # + Ollama + model bootstrap
docker compose --profile memory up  # + Qdrant
docker compose --profile telemetry up  # + Prometheus + Grafana
docker compose --profile full up    # всё вместе
```

## Quick Commands

```bash
# TON bug bounty scan
curl -X POST :8000/api/ton/bounty-scan \
  -d '{"path":"/contracts/wallet.fc","generate_reports":true}'

# K8s manifest audit
curl -X POST :8000/api/scan/k8s/manifest \
  -d '{"path":"/k8s/manifests/"}'

# Multi-LLM consensus
curl -X POST :8000/api/llm/consensus \
  -d '{"task":"security","prompt":"...","strategy":"vote"}'

# Auto-fix generation
curl -X POST :8000/api/remediate/generate \
  -d '{"finding":{...},"code_context":"hashlib.md5(x)"}'

# Prometheus scrape
curl :8000/metrics

# Semantic memory search
curl -X POST :8000/api/memory/search \
  -d '{"finding":{"type":"sql_injection","cwe":"CWE-89"}}'
```
