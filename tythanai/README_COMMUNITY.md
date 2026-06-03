# TythanAI — Community Edition

[![License: BSL 1.1](https://img.shields.io/badge/License-BSL_1.1-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://python.org)
[![SARIF](https://img.shields.io/badge/output-SARIF_2.1.0-orange.svg)](https://sarifweb.azurewebsites.net/)
[![Web3](https://img.shields.io/badge/Web3-TON_%C2%B7_Solana_%C2%B7_CosmWasm_%C2%B7_Solidity-purple.svg)](#)

**One scanner that combines conventional and Web3-native security analysis.**
TON · Solana · CosmWasm · Solidity · Python · JS · Go · Java · Rust.
No account. Runs locally. Source-available.

---

## What it does

| Module | Coverage |
|--------|----------|
| **SAST** | Semgrep (optional) + bundled custom rules |
| **SCA** | Dependency CVEs from OSV.dev (online) + offline known-CVE DB |
| **Secrets** | API keys, tokens, private keys, high-entropy strings |
| **IaC** | Terraform, Kubernetes, Docker misconfigurations |
| **Web3** | TON FunC/Tolk · Solana Anchor · CosmWasm · Solidity contract audit |
| **Output** | Terminal · SARIF 2.1.0 · HTML report · JSON |

---

## Quick start

```bash
# 1. Clone
git clone https://github.com/tythanai/tythanai.git
cd tythanai

# 2. (optional) install deps for the full pipeline
pip install -r requirements.txt

# 3. Scan
python tythanai_community_cli.py scan ./your-project
```

**Expected output:**

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  SCAN SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Target    : ./your-project
  Risk      : CRITICAL (100/100)
  Findings  : 12

  CRITICAL      1
  HIGH          8
  MEDIUM        3

  SAST     : 0 findings
  SCA/CVE  : 7 findings
  Secrets  : 1 findings
  IaC      : 1 findings
  Web3     : 3 findings
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## Options

```bash
python tythanai_community_cli.py scan <target> [options]

  --no-sast / --no-sca / --no-secrets / --no-iac / --no-web3
  --sarif <file>     Write SARIF 2.1.0 (→ GitHub Code Scanning)
  --html  <file>     Write an HTML report
  --json  <file>     Write JSON findings
  --quiet            Suppress the banner
```

**Exit codes:** `0` clean · `1` low · `2` medium · `3` high/critical — wire into CI directly.

### GitHub Code Scanning in 5 lines

```yaml
- run: python tythanai_community_cli.py scan . --sarif results.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

---

## Community vs Pro

The Community Edition is fully functional for everyday scanning. These advanced
modules are reserved for **TythanAI Pro / Enterprise**:

| 🔒 Pro feature | What it adds |
|----------------|--------------|
| AutoPR | Auto-generated fix Pull Requests |
| DAST | Active web scanning |
| CPG taint analysis | Full data-flow taint tracking (Go / Java / Rust) |
| AI fix suggestions | LLM-powered remediation |
| Rules marketplace | Semantic rule search + 3 462-rule library |
| Economic risk scorer | On-chain loss modelling (TON / EVM) |
| SaaS dashboard | Usage analytics, billing, webhooks |
| Multi-agent orchestrator | Parallel scanner fleet |

→ **Upgrade:** https://tythanai.io/upgrade

---

## Accuracy

Benchmarked on the Juliet corpus (98 test cases):
**Precision 90.0% · Recall 83.1% · F1 86.4%.** See `BENCHMARK_REPORT.md`.

---

## License

Business Source License 1.1 — free for individuals, teams under 3 developers,
and non-production use. Converts to **Apache 2.0 on 2029-06-01**. See `LICENSE`.

© 2026 TythanAI Labs
