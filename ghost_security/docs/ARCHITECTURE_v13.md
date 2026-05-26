# Ghost Security Platform v13 — Architecture Document

**Version:** 13.0.0
**Date:** 2026-05-26
**Branch:** claude/v13-development

---

## 1. System Overview

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                        Ghost Security Platform v13                               │
│                                                                                  │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────────┐  │
│  │  CLI / IDE  │    │  REST API   │    │  SaaS Cloud │    │   CI/CD Hooks   │  │
│  │ ghost_cli   │    │  FastAPI    │    │  (Multi-    │    │  GitHub Actions │  │
│  │ VS Code ext │    │  :8080      │    │   tenant)   │    │  pre-commit     │  │
│  └──────┬──────┘    └──────┬──────┘    └──────┬──────┘    └────────┬────────┘  │
│         └─────────────────┴──────────────────┴──────────────────┘            │
│                                       │                                          │
│                              ┌────────▼────────┐                                │
│                              │  Security        │                                │
│                              │  Pipeline        │                                │
│                              │ (Orchestrator)   │                                │
│                              └────────┬─────────┘                               │
│                                       │                                          │
│          ┌─────────────────────────────┼──────────────────────────────┐         │
│          │                             │                              │         │
│   ┌──────▼──────┐            ┌─────────▼──────┐            ┌─────────▼──────┐  │
│   │ Multi-chain │            │  AST + Dataflow │            │  Secret +      │  │
│   │  Scanners   │            │  Engine         │            │  Supply Chain  │  │
│   │  (6 chains) │            │  (taint + CFG)  │            │  Scanners      │  │
│   └──────┬──────┘            └─────────┬──────┘            └─────────┬──────┘  │
│          │                             │                              │         │
│          └─────────────────────────────┼──────────────────────────────┘         │
│                                        │                                         │
│                              ┌─────────▼──────────┐                             │
│                              │  Verifier / FP      │                             │
│                              │  Reduction Engine   │                             │
│                              │  (confidence score) │                             │
│                              └─────────┬───────────┘                             │
│                                        │                                         │
│          ┌─────────────────────────────┼──────────────────────────────┐         │
│          │                             │                              │         │
│   ┌──────▼──────┐            ┌─────────▼──────┐            ┌─────────▼──────┐  │
│   │  Local AI   │            │  Reporting      │            │  Observability  │  │
│   │  (Ollama)   │            │  (SARIF/HTML/   │            │  (Prometheus +  │  │
│   │  + OpenAI   │            │   Markdown)     │            │   Grafana +     │  │
│   └─────────────┘            └─────────────────┘            │   OTel traces)  │  │
│                                                              └─────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Component Descriptions

### 2.1 Entry Points

| Component | Path | Description |
|-----------|------|-------------|
| CLI | `ghost_cli.py`, `ghost_cli_main.py` | Primary command-line interface for scans, reports, and config |
| REST API | `api/server.py` | FastAPI server with SSE streaming, scan queue, and health endpoints |
| VS Code Extension | `vscode_extension_compiled/` | IDE integration with real-time scan feedback |
| JetBrains Plugin | `jetbrains_plugin/` | IntelliJ IDEA / PyCharm integration |
| Web Dashboard | `web/templates/index.html` | Browser-based scan dashboard |

### 2.2 Security Pipeline (Orchestrator)

The central orchestration lives in `scanners/security_pipeline.py` and `orchestrator/`:

- **`orchestrator/task_graph.py`** — DAG-based task execution with topological sort for parallel analysis
- **`orchestrator/multi_agent_runtime.py`** — Multi-agent debate cycle: Plan → Execute → Debate → Verify → Report
- **`agents/orchestrator.py`** — Top-level agent coordinator
- **`agents/planner_agent.py`** — Decomposes scan requests into sub-tasks
- **`agents/security_agent.py`** — Executes security analysis tasks
- **`agents/critic_agent.py`** — Reviews and challenges findings

### 2.3 Multi-Chain Scanners

| Chain | Scanner Module | Rules Directory |
|-------|---------------|-----------------|
| EVM / Solidity | `scanners/evm_scanner/evm_analyzer.py` | `rules/evm/` |
| Solana / Anchor | `scanners/solana_scanner/solana_analyzer.py` | `rules/solana/` |
| CosmWasm / Cosmos | `scanners/cosmos_scanner/cosmwasm_analyzer.py` | `rules/cosmos/` |
| ink! / Polkadot | `scanners/polkadot_scanner/ink_analyzer.py` | `rules/polkadot/` |
| Move / Sui / Aptos | `scanners/move_scanner/move_analyzer.py` | `rules/move/` |
| TON / FunC / Tact | `scanners/ton_scanner/ton_analyzer.py` | `rules/ton/` |

### 2.4 AST + Dataflow Engine

- **`scanners/ast_scanner/ast_analyzer.py`** — Language-agnostic AST parsing for Python, Solidity, JavaScript
- **`core/analysis/taint_tracker.py`** — Inter-procedural taint analysis tracking user-controlled data to sensitive sinks
- **`core/analysis/call_graph.py`** — Call graph construction for control flow analysis
- **`scanners/js_analyzer.py`** — JavaScript-specific AST analysis

### 2.5 Verifier / FP Reduction

- **`verifier/confidence_engine.py`** — Multi-source consensus scoring (0.0–1.0)
- **`verifier/fp_reducer_v2.py`** — 60+ false-positive suppression patterns
- **`verifier/duplicate_detector.py`** — Fingerprint-based deduplication
- **`verifier/exploitability_scorer.py`** — CVSS-like exploitability scoring

### 2.6 Local AI Stack

- **`runtime/ollama_runtime.py`** — Ollama integration with fallback chain
- **`runtime/supervisor.py`** — Task supervision with retries, timeouts, and cancellation
- **`runtime/watchdog.py`** — Runtime health monitoring with heartbeat
- **`runtime/trace.py`** — Execution span tracking

### 2.7 Observability

- **`telemetry/prometheus_metrics.py`** — Prometheus metric registry
- **`telemetry/otel_setup.py`** — OpenTelemetry SDK initialization
- **`telemetry/trace_context.py`** — Distributed trace context propagation
- **`api/metrics.py`** — `/metrics` Prometheus scrape endpoint
- **`infra/grafana/dashboard.json`** — Grafana operational dashboard

---

## 3. Data Flow: Scan Request → Output

```
1. Scan Request
   │
   ├── ghost_cli.py scan --path ./contracts
   ├── POST /api/v1/scans
   └── VS Code: "Ghost: Scan Workspace"
   │
   ▼
2. Security Pipeline (security_pipeline.py)
   │  - Enumerate files by extension
   │  - Route to appropriate scanners
   │  - Initialize progress tracking
   │
   ▼
3. Scanner Pipeline (parallel execution)
   │
   ├── EVM Scanner ──────────────────────────────┐
   ├── Solana Scanner ────────────────────────────┤
   ├── CosmWasm Scanner ──────────────────────────┤──► Raw Findings []
   ├── TON Scanner ───────────────────────────────┤
   ├── Secret Scanner ────────────────────────────┤
   └── AST/Dataflow Engine ───────────────────────┘
   │
   ▼
4. AST Engine (ast_scanner/ast_analyzer.py)
   │  - Parse source into AST
   │  - Build call graph
   │  - Run taint tracking
   │  - Apply pattern rules
   │
   ▼
5. FP Reduction (verifier/)
   │  - fp_reducer_v2: suppress known FP patterns
   │  - duplicate_detector: fingerprint + deduplicate
   │  - confidence_engine: score 0.0–1.0
   │  - exploitability_scorer: CVSS-like score
   │
   ▼
6. Scoring & Enrichment
   │  - EPSS score lookup (scanners/epss_enricher.py)
   │  - OSV database check (scanners/osv_scanner.py)
   │  - Severity normalization (CRITICAL/HIGH/MEDIUM/LOW/INFO)
   │
   ▼
7. AI Analysis (optional, runtime/ollama_runtime.py)
   │  - Chain-of-thought reasoning per finding
   │  - Remediation generation
   │  - Threat model (STRIDE)
   │  - Executive summary
   │
   ▼
8. Output
   ├── SARIF (reports/sarif_exporter.py)
   ├── Enriched SARIF (reports/sarif_enriched.py)
   ├── HTML Report (reports/report_generator.py)
   ├── Markdown Summary
   ├── JSON (machine-readable)
   └── GitHub PR annotations (via SARIF upload)
```

---

## 4. Multi-Chain Scanner Architecture

Each chain scanner follows a common interface pattern:

```python
class ChainScanner:
    def scan(self, source: str, filename: str) -> list[Finding]:
        ...

    def get_rules(self) -> list[Rule]:
        ...

    def supports_file(self, path: str) -> bool:
        ...
```

Rule files are YAML-based under `rules/<chain>/`:

```yaml
# Example: rules/evm/reentrancy.yaml
rules:
  - id: evm-reentrancy-001
    name: Reentrancy via external call before state update
    severity: CRITICAL
    chain: evm
    pattern:
      type: ast
      node: ExternalCall
      before_state_update: true
    message: "External call made before state variable update — potential reentrancy"
    cwe: CWE-841
    references:
      - https://swcregistry.io/docs/SWC-107
```

---

## 5. Cloud SaaS Architecture (Multi-Tenant)

```
┌─────────────────────────────────────────────────────────────┐
│                    Cloud SaaS Layer                          │
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │ API Gateway  │  │  Auth Layer  │  │  Billing Layer   │  │
│  │ (FastAPI +   │  │  API Keys +  │  │  Plan Enforcer + │  │
│  │  rate limit) │  │  JWT Sessions│  │  Usage Tracker   │  │
│  └──────┬───────┘  └──────┬───────┘  └────────┬─────────┘  │
│         └─────────────────┴──────────────────┘             │
│                            │                                 │
│                   ┌────────▼─────────┐                      │
│                   │ Tenant Manager   │                      │
│                   │ (Data isolation) │                      │
│                   └────────┬─────────┘                      │
│                            │                                 │
│         ┌──────────────────┼──────────────────┐            │
│         │                  │                  │            │
│  ┌──────▼───────┐  ┌───────▼──────┐  ┌───────▼──────┐     │
│  │  Scan Worker │  │  PostgreSQL  │  │    Redis     │     │
│  │  (async)     │  │  (findings,  │  │  (queue +    │     │
│  │  cloud/      │  │   tenants)   │  │   cache)     │     │
│  │  workers/    │  │              │  │              │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
└─────────────────────────────────────────────────────────────┘
```

**Key modules:**

| Module | Path | Purpose |
|--------|------|---------|
| API Key Manager | `cloud/auth/api_key_manager.py` | Key generation, validation, revocation |
| Session Manager | `cloud/auth/session_manager.py` | JWT session lifecycle |
| Plan Enforcer | `cloud/billing/plan_enforcer.py` | Free/Pro/Enterprise feature gating |
| Usage Tracker | `cloud/billing/usage_tracker.py` | Per-tenant scan and API usage metering |
| Tenant Manager | `cloud/tenant/tenant_manager.py` | Data isolation between tenants |
| Scan Worker | `cloud/workers/scan_worker.py` | Async background scan execution |

---

## 6. Observability Stack

```
Ghost Security App
       │
       ├── Prometheus metrics (/metrics endpoint)
       │         │
       │         ▼
       │   Prometheus Server (infra/prometheus.yml)
       │         │
       │         ▼
       │   Grafana (infra/grafana/dashboard.json)
       │     - ghost_scans_total
       │     - ghost_scan_duration_seconds
       │     - ghost_findings_total{severity=...}
       │     - ghost_queue_depth
       │     - ghost_errors_total
       │     - ghost_llm_calls_total
       │
       └── OpenTelemetry traces
                 │
                 ▼
         OTel Collector (OTLP)
                 │
                 ▼
         Jaeger / Tempo (distributed tracing)
```

**Metric definitions** (`telemetry/prometheus_metrics.py`):
- `ghost_scans_total` — Counter: total scans by chain and status
- `ghost_scan_duration_seconds` — Histogram: scan duration distribution
- `ghost_findings_total` — Counter: findings by severity and chain
- `ghost_queue_depth` — Gauge: current scan queue depth
- `ghost_errors_total` — Counter: errors by error type
- `ghost_llm_calls_total` — Counter: LLM API calls by model and task

---

## 7. Local AI Stack (Ollama)

```
ghost_cli / API request
       │
       ▼
OllamaRuntime (runtime/ollama_runtime.py)
       │
       ├── ModelHealth check (is Ollama running?)
       │         │
       │    ┌────▼──────────────────────────────┐
       │    │  Ollama local server (:11434)      │
       │    │  Models: qwen2.5-coder:7b          │
       │    │          codellama                 │
       │    │          llama3                    │
       │    └────────────────────────────────────┘
       │
       ├── [fallback] OpenAI API
       │         └── gpt-4o / gpt-4-turbo
       │
       └── [offline fallback] Deterministic responses
                 └── Template-based remediation hints

Tasks executed via LLM:
  - Chain-of-thought vulnerability analysis
  - Remediation suggestion generation
  - STRIDE threat model
  - Executive summary generation
  - Finding classification / severity justification
```

---

## 8. Security Guarantees

### 8.1 No Live Network Calls During Scan

The core scanning engine makes **zero outbound network calls** during analysis:

1. All rule files are local YAML (`rules/`)
2. AST parsing is done in-process (Python `ast` module, custom Solidity parser)
3. Pattern matching uses local compiled patterns
4. FP reduction uses local rule tables

### 8.2 Source Code Never Leaves the Machine

- Scanner receives file contents as strings
- No content is sent to external APIs unless the user explicitly enables LLM analysis
- In offline mode (`--offline`), all LLM tasks use deterministic fallbacks

### 8.3 Secrets Never Logged

- `runtime/structured_logger.py` sanitizes sensitive fields
- API keys are masked in all log output
- The `detect-private-key` pre-commit hook prevents accidental commits

### 8.4 Multi-Tenant Data Isolation

- Each tenant has a separate database schema (PostgreSQL row-level security)
- `cloud/tenant/tenant_manager.py` enforces tenant context on every query
- Redis keys are namespaced by tenant ID

---

## 9. Technology Stack Summary

| Layer | Technology |
|-------|-----------|
| Language | Python 3.11+ |
| Web framework | FastAPI + uvicorn |
| Data validation | Pydantic v2 |
| Vector memory | ChromaDB |
| Relational DB | PostgreSQL 15 |
| Cache / Queue | Redis 7 |
| Local LLM | Ollama (qwen2.5-coder, codellama, llama3) |
| Cloud LLM | OpenAI gpt-4o |
| Metrics | Prometheus + Grafana |
| Tracing | OpenTelemetry |
| Containers | Docker + Docker Compose |
| Orchestration | Kubernetes + Helm |
| CI/CD | GitHub Actions |
| Code quality | ruff + pre-commit |
| Testing | pytest + pytest-asyncio |
