# Ghost Security Platform — Roadmap: Next Stage

**Current:** v3.0 Enterprise Hardening  
**Next:** v3.1 → v4.0 Production Scale

---

## Priority 1 — Short-term (1–4 weeks)

### P1-A: Distributed Task Queue (Redis)
- Replace in-process `asyncio.Queue` in `RuntimeSupervisor` with Redis-backed queue
- Enables horizontal scaling (multiple API workers)
- Module: `core/distributed/task_queue.py` already stubbed — implement `RedisTaskQueue`
- Config: `REDIS_URL` env var already in `.env.example`

### P1-B: Real Embeddings for Memory (without OpenAI dependency)
- `MemoryManager` currently requires OpenAI for embeddings
- Add `sentence-transformers` local embedding backend as default
- Fallback: OpenAI embeddings when `OPENAI_API_KEY` set
- Removes the hard OpenAI dependency for offline deployments

### P1-C: Persistent Scan History (SQLite/Postgres)
- Currently scan results live only in memory + ChromaDB
- Add lightweight SQLite-first scan history store
- Expose via `/api/scans/history` endpoint
- Module: `core/storage/scan_store.py` (new)

### P1-D: Extended Test Coverage
- Target: ≥ 80% line coverage on `runtime/`, `core/`, `verifier/`
- Add scanner-level integration tests (require Bandit/Semgrep in CI)
- Add API endpoint tests using FastAPI `TestClient` (httpx)
- Add property-based tests for `ConfidenceEngine` (hypothesis library)

---

## Priority 2 — Medium-term (1–3 months)

### P2-A: WebSocket-Native Dashboard
- Upgrade SSE → WebSocket for bidirectional control (pause scan, cancel task)
- Real-time graph visualization of TaskGraph execution
- Agent activity feed with per-agent metrics

### P2-B: Semgrep Pro / Custom Rulesets
- Load custom YAML rulesets from `scanners/semgrep_scanner/rules/`
- Rule editor in dashboard
- Automated rule generation from past findings via LLM

### P2-C: GitHub App Integration
- OAuth GitHub App (vs personal token)
- Automatic PR annotation with inline security comments
- Repository onboarding wizard

### P2-D: Grafana Dashboard Template
- Ship a `infra/grafana-dashboard.json` with pre-built panels:
  - Scan duration histogram
  - Findings by severity (time series)
  - Agent success/error rates
  - LLM latency p50/p95/p99
  - Queue depth

### P2-E: SBOM Generation
- Generate Software Bill of Materials (CycloneDX/SPDX) alongside scan
- Integrate with `scanners/dependency_scanner.py`
- Export: JSON, XML, CSV

---

## Priority 3 — Long-term (3–6 months)

### P3-A: Multi-Tenancy
- Organization/project isolation
- Per-org API keys and rate limits
- Audit log per organization
- ChromaDB collection namespacing

### P3-B: Kubernetes Deployment
- Helm chart in `infra/helm/`
- `RuntimeSupervisor` → Celery workers on separate pods
- Horizontal Pod Autoscaler on queue depth metric

### P3-C: Compliance Reporting
- SOC 2 / ISO 27001 control mapping
- NIST CSF alignment
- Automated compliance evidence packaging

### P3-D: IDE Integrations
- VS Code extension — inline findings as diagnostics
- JetBrains plugin
- Language Server Protocol (LSP) findings provider

### P3-E: Advanced TON Features
- Live mainnet/testnet transaction monitoring
- Contract upgrade impact analysis
- Cross-contract dependency graph with risk propagation
- Integration with TON Explorer API

---

## Technical Debt to Address

| Item | Priority | Effort |
|------|----------|--------|
| `MemoryManager` hard-depends on ChromaDB + OpenAI | High | Medium |
| `api/server.py` (838 lines) — split into routers | Medium | Small |
| `orchestrator/multi_agent_runtime.py` — add unit tests | High | Small |
| `core/compliance/` — currently empty | Low | Medium |
| `core/validation/` — currently empty | Low | Medium |
| `agents/research/`, `agents/reviewer/` — empty `__init__` files | Low | Small |
| Docker CI step requires Dockerfile (not yet present) | Medium | Small |
| `runtime/self_healing_loop.py` — review for dead code | Low | Small |

---

## Performance Targets (v4.0)

| Metric | Current | Target |
|--------|---------|--------|
| API response (health check) | <50ms | <10ms |
| Small repo scan (< 1000 files) | ~30s | <15s |
| LLM remediation generation | ~5s (Ollama) | <3s |
| Concurrent scans | 8 (single node) | 50+ (distributed) |
| Finding deduplication accuracy | ~85% | >95% |
| False positive rate | ~15% | <5% |

---

## Dependency Upgrades (tracked)

| Package | Current | Watch For |
|---------|---------|-----------|
| FastAPI | 0.110+ | v1.0 stable |
| ChromaDB | 0.4.x | 0.6.x API changes |
| Pydantic | 2.x | Minor breaking changes |
| semgrep | external | Rule format changes |
| bandit | 1.7.x | 1.8.x |
