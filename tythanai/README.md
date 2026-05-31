# Ghost Security Platform — FINAL v2.2

Automated white-hat security auditing platform for bug bounty research.
Static analysis only — reads code, never touches production systems.

---

## Quick Start

```bash
tar -xzf ghost_security_FINAL_v3.tar.gz && cd ghost_final
./install.sh && source .venv/bin/activate
python3 doctor.py          # verify all 59 checks pass
python3 ghost_cli.py server  # dashboard → http://localhost:8000
```

## All CLI Commands

```bash
# Full pipeline (all scanners at once)
python3 ghost_cli.py scan       ./target -o report.html

# Per-scanner
python3 ghost_cli.py owasp      ./target -o owasp.json    # OWASP Top 10 (35 rules)
python3 ghost_cli.py scan       ./target --mode secrets    # 40+ secret patterns
python3 ghost_cli.py deps       ./target -o deps.json      # 80+ CVEs
python3 ghost_cli.py taint      ./target -o taint.json     # dataflow analysis
python3 ghost_cli.py ton        ./contracts/ -o ton.md     # TON FunC/Tact (28 rules)
python3 ghost_cli.py solidity   ./contracts/ -o sol.json   # Solidity (15 rules)
python3 ghost_cli.py profile    ./target -o heatmap.json   # risk heatmap

# Bug Bounty workflow
python3 ghost_cli.py bounty triage  -i findings.json       # eligibility + payout
python3 ghost_cli.py bounty writeup -i finding.json -o disclosure.md

# Export & reporting
python3 ghost_cli.py sarif      report.json  # → GitHub Security tab
python3 ghost_cli.py memory     summary      # historical trends

# LLM / AI
python3 ghost_cli.py llm-status              # check Ollama / OpenAI
python3 ghost_cli.py server                  # Copilot at /api/copilot/ask
```

## Scanners Included

| Scanner | Coverage | Rules |
|---|---|---|
| **OWASP Top 10** | A01–A10, Python + JS/TS | 35 rules |
| **JS/TS Analyzer** | XSS, injection, SSRF, JWT, proto pollution | 24 rules |
| **Solidity Analyzer** | Reentrancy, tx.origin, overflow, DoS | 15 rules |
| **TON Analyzer** | FunC/Tact: access control, replay, gas, Jetton | 28 rules |
| **Secret Detector** | OpenAI, AWS, GCP, GitHub, Stripe, JWT, PEM… | 40+ patterns |
| **Dependency Scanner** | Python + Node CVEs 2019–2024 | 80+ CVEs |
| **Taint Tracker** | Python AST dataflow source→sink | 10 sinks |
| **AST Scanner** | Python SAST, unsafe calls | via bandit |

## REST API Endpoints

```
POST /api/scan/all          # full pipeline
POST /api/scan/owasp        # OWASP A01-A10
POST /api/scan/js           # JS/TS analysis
POST /api/scan/solidity     # Solidity analysis
POST /api/scan/deps         # dependency CVEs
POST /api/scan/taint        # dataflow analysis
POST /api/scan/secrets      # secret detection
POST /api/audit/ton         # TON contracts
POST /api/ton/analyze-snippet
GET  /api/ton/rules

POST /api/enrich            # LLM enrichment
POST /api/triage            # dedup + scoring
POST /api/remediate         # auto-patches
POST /api/threat-model      # STRIDE analysis
POST /api/bounty/triage     # bug bounty eligibility
POST /api/bounty/writeup    # disclosure write-up
POST /api/repo/profile      # risk heatmap

POST /api/copilot/ask       # AI security assistant
POST /api/copilot/explain   # explain finding
POST /api/copilot/fix       # suggest code fix
POST /api/copilot/review    # review code snippet

POST /api/export/sarif      # SARIF 2.1.0
POST /api/reports/generate-html

GET  /api/memory/summary    # historical data
GET  /api/memory/recurring  # repeat vulnerabilities
GET  /api/memory/trend      # risk trend 30 days
GET  /api/health/llm        # model router status
GET  /api/queue/status      # task queue

GET  /                      # Dashboard UI
GET  /docs                  # Swagger API docs
```

## Docker

```bash
# Standard (needs OPENAI_API_KEY for AI features)
docker compose up

# With local Ollama (no API key needed)
docker compose --profile local-llm up
```

## CI/CD — GitHub Actions

Copy `integrations/github/github_actions.yml` to `.github/workflows/` in your repo.
- Auto-scans on every push/PR
- Uploads SARIF to GitHub Security tab
- Posts findings summary as PR comment
- Fails build on CRITICAL findings

## Bug Bounty Workflow

```
1. Find target with public source code (HackerOne / Immunefi / Bugcrowd)
2. git clone <target-repo>
3. python3 ghost_cli.py scan ./target -o report.html
4. python3 ghost_cli.py deps ./target
5. python3 ghost_cli.py owasp ./target
6. Manually verify HIGH/CRITICAL findings (remove false positives)
7. python3 ghost_cli.py bounty triage -i findings.json
8. python3 ghost_cli.py bounty writeup -i finding.json -o disclosure.md
9. Submit via the bug bounty platform
```

## Environment Variables

```bash
OPENAI_API_KEY=sk-...          # for LLM features (optional)
OPENAI_BASE_URL=http://localhost:11434/v1  # Ollama
LLM_MODEL=gpt-4o-mini
GITHUB_TOKEN=ghp_...           # for GitHub scanning
```
