# Ghost Security v12 → v13: Baseline Metrics

**Date:** 2026-05-25
**Branch:** claude/v13-development (from claude/elegant-euler-SROPU)

## Baseline (v12)

| Metric | Value |
|--------|-------|
| Python modules | 208 |
| Lines of code | 52,826 |
| CLI commands | 35 |
| REST API endpoints | 149 |
| Tests passing | 757 / 757 (3 skipped) |
| YAML rule files | 44 |
| Total rules | 3,077 |
| LLM providers | 4 |
| Scanner categories | 22 |
| Cold start | 0.05s |
| VS Code extension | v2.0.0 (10 commands) |
| Compliance frameworks | 6 |
| Export formats | 6 |

## v13 Targets

| Metric | Target |
|--------|--------|
| Python modules | ~350 |
| Lines of code | ~95,000 |
| CLI commands | 50+ |
| Tests | 1,500+ |
| Rules | 4,500+ |
| Blockchain coverage | 8 chains |
| AST engine | ✅ Python/JS/TS/Solidity/Rust/Go |
| FP rate | <5% |
| Cloud SaaS | ✅ |
| VS Code Marketplace | ✅ |
| Observability | OpenTelemetry + Prometheus + Grafana |
