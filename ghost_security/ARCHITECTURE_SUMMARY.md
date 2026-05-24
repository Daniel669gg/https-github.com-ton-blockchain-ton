# Ghost Security Platform — Architecture Summary

**Version:** v3.0 Enterprise  
**Stack:** Python 3.11+, FastAPI, Ollama, ChromaDB, TON Sandbox

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Ghost Security Platform                       │
├───────────────┬──────────────────────┬──────────────────────────────┤
│   API Layer   │   Orchestration      │   Runtime Infra              │
│  (FastAPI)    │   (Multi-Agent)      │                              │
│               │                      │  ┌────────────────────────┐  │
│  /api/scan    │  Plan → Execute →    │  │  RuntimeSupervisor     │  │
│  /api/find    │  Debate → Verify →   │  │  • Retries + backoff   │  │
│  /api/health  │  Report             │  │  • Timeout management  │  │
│  /metrics     │                      │  │  • Graceful shutdown   │  │
│  /ws/stream   │  TaskGraph (DAG)     │  └────────────────────────┘  │
│               │  • Parallel exec     │  ┌────────────────────────┐  │
│  Dashboard    │  • Dep resolution    │  │  RuntimeWatchdog  NEW  │  │
│  (HTML/WS)    │  • Audit trail       │  │  • Heartbeat monitor   │  │
│               │                      │  │  • Auto-recovery       │  │
└───────────────┴──────────────────────┴──┴────────────────────────┘──┘
                                                     │
┌───────────────────────────── Scanner Layer ─────────────────────────┐
│  ASTScanner  │  SemgrepScanner  │  SecretDetector  │  TONAnalyzer   │
│  TaintTracker│  CallGraph       │  OWASPScanner    │  ContractGraph │
│  DepsScanner │  JSAnalyzer      │  LLMAnalyzer     │  TraceAnalyzer │
└─────────────────────────────────────────────────────────────────────┘
                                                     │
┌───────────────────────────── AI Layer ──────────────────────────────┐
│  OllamaRouter (local)                CloudFallback (OpenAI)         │
│  • deepseek-r1  (reasoning)          • gpt-4o-mini                  │
│  • deepseek-coder-v2  (TON/code)     • Any OpenAI-compatible API    │
│  • qwen3  (summarise/critique)                                       │
│  • llama3.2  (report/remediation)    Offline fallbacks always active │
│  • phi4-mini  (triage, fast)                                         │
└─────────────────────────────────────────────────────────────────────┘
                                                     │
┌───────────────────────────── Core Services ─────────────────────────┐
│  ConfidenceEngine  │  HealthMonitor  │  SecurityEventBus            │
│  MemoryManager     │  MetricsRegistry│  StructuredLogger            │
│  TraceLogger  UPGRADED  │  RepoIndexer  │  CVEEnricher              │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Module Map

### `runtime/`
| Module | Responsibility |
|--------|---------------|
| `supervisor.py` | Async task pool with retries, timeouts, graceful shutdown |
| `watchdog.py` ⭐NEW | Heartbeat monitoring and auto-recovery daemon |
| `trace.py` ⭐UPGRADED | Execution spans, trace IDs, async context managers |
| `structured_logger.py` | JSON-structured logging with ContextVar trace propagation |
| `ollama_runtime.py` | Multi-model routing, Ollama/OpenAI fallback chain |
| `model_router.py` | Model selection and health-check cache |
| `autonomous_loop.py` | Observe→Plan→Execute→Verify cycle |

### `orchestrator/`
| Module | Responsibility |
|--------|---------------|
| `task_graph.py` | DAG-based task execution with parallel scheduling |
| `multi_agent_runtime.py` | Plan→Execute→Debate→Verify→Report pipeline |

### `core/`
| Package | Responsibility |
|---------|---------------|
| `metrics/` ⭐NEW | Prometheus-compatible metrics: Counters, Gauges, Histograms |
| `runtime/` | Health monitor with background probe loop |
| `telemetry/` | In-process event bus (pub/sub, audit trail) |
| `analysis/` | Taint tracker, call graph builder |
| `knowledge/` | CVE enricher, security memory (ChromaDB) |
| `security/` | API middleware, findings triage |
| `memory/` | Vector memory manager (ChromaDB + embeddings) |
| `indexing/` | Repository semantic indexer |
| `remediation/` | Patch generator |
| `verifier/` | Confidence scoring, FP reduction |

### `scanners/`
| Scanner | Detects |
|---------|---------|
| `ast_scanner/` | Python AST vulnerabilities, dangerous APIs |
| `secret_scanner/` | 60+ secret patterns (API keys, certs, URIs) |
| `semgrep_scanner/` | OWASP Top 10, TON rules, custom rulesets |
| `ton_scanner/` | TON smart contract vulnerabilities |
| `github_watcher/` | PR/commit security analysis |
| `dependency_scanner.py` | Known-vulnerable dependencies |
| `owasp_scanner.py` | OWASP Top 10 patterns |
| `js_analyzer.py` | JavaScript/TypeScript security |

### `api/`
| Module | Responsibility |
|--------|---------------|
| `server.py` | FastAPI app: scan, findings, health, SSE streaming |
| `metrics.py` ⭐NEW | `/metrics` (Prometheus text format) + `/api/metrics/snapshot` |
| `routes_ext.py` | Extended agent and orchestration routes |

### `reports/`
| Module | Output |
|--------|--------|
| `report_generator.py` | HTML, JSON, Markdown reports |
| `sarif_exporter.py` | SARIF 2.1.0 |
| `sarif_enriched.py` | SARIF with CWE/OWASP enrichment |

### `verifier/`
| Module | Responsibility |
|--------|---------------|
| `confidence_engine.py` | Statistical confidence scoring, FP heuristics, deduplication |
| `test_verifier.py` | Verifier unit tests |

---

## Data Flow — Security Scan

```
User Request (API / CLI / GitHub PR)
         │
         ▼
    api/server.py  ─── emits ──→  SecurityEventBus
         │
         ▼
  MultiAgentOrchestrator
    ├── PlannerAgent   → scan plan (DAG)
    ├── TaskGraph      → parallel scanner execution
    │     ├── ASTScanner
    │     ├── SemgrepScanner
    │     ├── SecretDetector
    │     └── TONAnalyzer
    ├── CriticAgent    → challenge findings
    ├── DebateRound    → contested findings resolved
    ├── SecurityAgent  → cross-scanner risk assessment
    └── ConfidenceEngine → score, deduplicate, prioritise
         │
         ▼
  ReportGenerator → HTML / SARIF / JSON / Markdown
         │
         ▼
  MemoryManager   → store in ChromaDB for future correlation
```

---

## Observability Flow

```
Any subsystem
    │
    ├── StructuredLogger.info("event", key=val)
    │       → JSON line: {ts, level, trace_id, component, msg, ...}
    │
    ├── TRACER.async_span("operation")
    │       → Span {trace_id, span_id, name, duration_ms, status}
    │       → Written to ghost_trace.jsonl
    │
    ├── METRICS.scans_completed.inc(scanner="ast")
    │       → Prometheus counter increment
    │       → Exposed at GET /metrics
    │
    └── BUS.publish("scan.completed", payload={...})
            → SecurityEventBus subscribers notified
            → Audit trail (last 1000 events)
```

---

## Deployment Architecture

```
                        ┌─────────────────────┐
                        │   Reverse Proxy      │
                        │   (nginx / Caddy)    │
                        └──────────┬──────────┘
                                   │
                        ┌──────────▼──────────┐
                        │   Ghost API Server   │
                        │   (FastAPI/uvicorn)  │
                        │   :8000              │
                        └──────┬───────┬──────┘
                               │       │
              ┌────────────────┘       └─────────────────┐
              │                                          │
   ┌──────────▼──────────┐                   ┌──────────▼──────────┐
   │   Ollama             │                   │   ChromaDB           │
   │   (local LLM)        │                   │   (vector memory)    │
   │   :11434             │                   │   (filesystem)       │
   └─────────────────────┘                   └─────────────────────┘
              │
   ┌──────────▼──────────┐
   │   Prometheus         │   (optional)
   │   scrapes /metrics   │
   └──────────┬──────────┘
              │
   ┌──────────▼──────────┐
   │   Grafana            │   (optional)
   └─────────────────────┘
```

---

## Security Posture

- **No offensive tooling** — zero exploit automation, zero attack payloads
- **No fake AI** — all AI calls go to real Ollama/OpenAI endpoints with offline fallbacks
- **No mock orchestration** — TaskGraph executes real coroutines
- **API key auth** via `X-API-Key` header (optional, env-controlled)
- **Rate limiting** — 120 req/min per IP
- **CORS** — configurable via `ALLOWED_ORIGINS` env var
- **Secrets** — read from env vars only, never hardcoded
