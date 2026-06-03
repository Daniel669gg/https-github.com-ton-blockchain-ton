# TythanAI — GitHub Launch Plan

**Date prepared:** 2026-06-03  
**Target:** public launch of `tythanai` on GitHub

---

## Step 1 — Create the GitHub Repository

1. Go to **github.com → New repository**
2. Set:
   - **Owner:** `tythanai` (create org first at github.com/organizations/new)
   - **Repository name:** `tythanai`
   - **Visibility:** Public
   - **Description:** *(paste the one-liner below)*
   - **Initialize:** No (you'll push local code)
   - **License:** None (you already have BSL 1.1 in the repo)
3. Click **Create repository**

**Repository description (GitHub "About" field — 350-char max):**
```
Web3-native security scanner for TON, Solana, CosmWasm & Solidity — plus SAST, SCA, secrets, IaC and SARIF output. One CLI, no account required. Community edition is free and source-available.
```

**Topics to add** (Settings → General → Topics):
```
security  sast  sca  web3  ton  solana  cosmwasm  solidity  smart-contracts  defi  sarif  cli  devsecops  static-analysis  vulnerability-scanner
```

---

## Step 2 — Prepare the Local Repo for Push

```bash
# From your ghost_security directory:
cd /path/to/ghost_security

# Verify git identity (first time only)
git config user.name  "TythanAI Team"
git config user.email "security@tythanai.io"

# Set the remote to your new repo
git remote add origin https://github.com/tythanai/tythanai.git
# or if remote already exists:
git remote set-url origin https://github.com/tythanai/tythanai.git
```

---

## Step 3 — Final Pre-push Checklist

Run these checks before pushing:

```bash
# 1. All tests green
python -m pytest tests/ -q --tb=short
# Expected: 3600+ passed, 0 failed

# 2. Community CLI works
python tythanai_community_cli.py version
python tythanai_community_cli.py scan . --no-sast --no-sca --no-secrets --no-iac --no-web3 --quiet

# 3. Files present
ls LICENSE NOTICE README.md SECURITY.md CODE_OF_CONDUCT.md GOVERNANCE.md ROADMAP.md CONTRIBUTING.md

# 4. No .env or secrets committed
git diff --cached --name-only | grep -E '\.env|secrets|credentials'
```

---

## Step 4 — Push to GitHub

```bash
git checkout -b main
git add .
git commit -m "feat: TythanAI v1.0 — Web3-native security scanner (community edition)"
git push -u origin main
```

If the branch name must stay `master`:
```bash
git push -u origin master
```

---

## Step 5 — Configure GitHub Repository Settings

After push, in **Settings**:

| Setting | Value |
|---------|-------|
| Default branch | `main` |
| Issues | Enabled |
| Discussions | Enabled (great for community) |
| Wiki | Disabled (docs in repo) |
| Sponsorships | Enable if you want GitHub Sponsors |
| Branch protection → `main` | Require PR + 1 review |
| Security → Advisories | Enabled |
| Security → Dependabot | Enabled |
| Security → Secret scanning | Enabled |

---

## Step 6 — Create the v1.0.0 Release

1. **Releases → Draft a new release**
2. **Tag:** `v1.0.0`
3. **Title:** `TythanAI v1.0.0 — Community Edition`
4. **Body:** *(paste the release notes below)*
5. Upload: `tythanai_community_cli.py` as a release asset (zero-install single-file launcher)
6. Mark as **Latest release**

**Release notes body:**
```markdown
## TythanAI v1.0.0 — Community Edition

### What's new
- SAST (Semgrep + 500 custom rules across Python, JS, Go, Java, Rust, Ruby, PHP, C/C++)
- SCA with real CVE data from OSV.dev (Python, JS/Node, Go, Java, Rust)
- Secrets detection (API keys, tokens, private keys)
- IaC scanning (Terraform, Kubernetes, Docker)
- **Web3 audit: TON FunC/Tolk · Solana Anchor · CosmWasm · Solidity**
- SARIF 2.1.0 output → GitHub Code Scanning
- HTML + JSON report
- No account, no signup, runs locally

### Install
```bash
git clone https://github.com/tythanai/tythanai.git
cd tythanai
pip install -e ".[full]"
tythanai scan .
```

Or community CLI (no install):
```bash
python tythanai_community_cli.py scan .
```

### Accuracy (Juliet corpus, 98 test cases)
Precision 90.0% · Recall 83.1% · F1 86.4%

### Upgrade to Pro
Unlock AutoPR, DAST, full taint analysis, rules marketplace → https://tythanai.io/upgrade
```

---

## Step 7 — Add GitHub Actions CI

Create `.github/workflows/ci.yml`:

```yaml
name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.11" }
      - run: pip install -e ".[full]"
      - run: python -m pytest tests/ -q --tb=short
```

And a self-scan badge workflow `.github/workflows/scan.yml`:

```yaml
name: TythanAI Scan
on: [push]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.11" }
      - run: pip install -e ".[full]"
      - run: tythanai scan . --sarif results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

---

## Step 8 — README Badges

Add these to the top of README.md after the title:

```markdown
[![License: BSL 1.1](https://img.shields.io/badge/License-BSL_1.1-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://python.org)
[![Tests](https://github.com/tythanai/tythanai/actions/workflows/ci.yml/badge.svg)](https://github.com/tythanai/tythanai/actions)
[![SARIF](https://img.shields.io/badge/output-SARIF_2.1.0-orange.svg)](https://sarifweb.azurewebsites.net/)
[![Web3](https://img.shields.io/badge/Web3-TON_%C2%B7_Solana_%C2%B7_CosmWasm_%C2%B7_Solidity-purple.svg)](README.md)
```

---

## Step 9 — Announcement Copy

### Hacker News (Show HN)

**Title:**
```
Show HN: TythanAI – open-source security scanner with native TON/Solana/CosmWasm support
```

**Body:**
```
I built TythanAI because mainstream scanners (Semgrep, Snyk, CodeQL) have zero
coverage for Web3 smart contracts — no TON FunC/Tolk rules, no Solana Anchor
patterns, no CosmWasm checks.

TythanAI is a source-available CLI that audits both:
- Your Web3 contracts: TON (FunC + Tolk), Solana (Anchor), CosmWasm, Solidity
- Your backend code: SAST (500+ custom rules), SCA with EPSS/OSV, secrets, IaC

One command, no account:
  pip install -e ".[full]"
  tythanai scan .

SARIF output works natively with GitHub Code Scanning. Honest benchmark:
Precision 90%, Recall 83%, F1 86.4% on the Juliet corpus.

Community edition is free and source-available (BSL 1.1 → Apache 2.0 in 2029).
GitHub: https://github.com/tythanai/tythanai
```

---

### Product Hunt

**Tagline (60 chars max):**
```
Security scanner for Web3 + Web2 code. One CLI, no account.
```

**Description:**
```
TythanAI is the first security scanner with native support for TON FunC/Tolk,
Solana Anchor, CosmWasm, and Solidity smart contracts — packaged alongside
conventional SAST, SCA (with EPSS exploit-probability ranking), secrets
detection, and IaC scanning.

Run it locally in 4 steps. Get SARIF output straight into GitHub Code Scanning.
No account, no paid plan required for the community edition.

→ Community edition: free, source-available (BSL 1.1)
→ Pro: AutoPR fix PRs, DAST, full taint analysis, rules marketplace
```

---

### Twitter/X thread (3 posts)

**Post 1:**
```
Shipping TythanAI — security scanning for teams building Web3 + Web2.

TON · Solana · CosmWasm · Solidity · Python · JS · Go · Java · Rust

One CLI, no account.

github.com/tythanai/tythanai
```

**Post 2:**
```
What makes it different:

→ Mainstream scanners (Semgrep, Snyk, CodeQL) have zero TON/Solana/CosmWasm rules
→ TythanAI bundles Web3 audit + SAST + SCA + secrets + IaC in one run
→ SARIF output → GitHub Code Scanning natively
→ Honest benchmark: P:90% R:83% F1:86% on Juliet corpus
```

**Post 3:**
```
Community edition is free and source-available.
Pro adds: AutoPR fix PRs, DAST, full taint analysis.

4-step install:
git clone github.com/tythanai/tythanai
cd tythanai && pip install -e ".[full]"
tythanai scan .
```

---

## Step 10 — TON Ecosystem Outreach

These communities are your primary early adopters — reach them directly:

| Channel | Where | What to post |
|---------|-------|--------------|
| TON Dev Chat | t.me/tondev | "Built a scanner with native FunC/Tolk rules — 5 reentrancy patterns, weak PRNG, gas limits" |
| TON Grants | ton.org/grants | Apply — Web3 security tooling is a stated priority |
| Solana Discord | #developer-tools | "First multi-chain scanner that does Anchor patterns natively" |
| CosmWasm Telegram | t.me/CosmWasm | Share the CosmWasm rule examples |
| ETH Security | discord.gg/eth-r&d | Solidity coverage + SARIF GitHub integration |

---

## Summary Timeline

| Day | Action |
|-----|--------|
| D+0 | Create org + repo, push code, create release v1.0.0 |
| D+0 | Post Show HN + Twitter thread |
| D+1 | Submit to Product Hunt |
| D+1 | Post in TON Dev Chat + Solana Discord |
| D+3 | Apply to TON Grants program |
| D+7 | Review Issues/feedback, cut v1.0.1 patch if needed |
