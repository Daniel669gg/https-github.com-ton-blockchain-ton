# AUDIT — Repository Truth Report
**TythanAI / Ghost Security Platform**
Independent technical due-diligence — Phase 1 of 10
Audit date: 2026-06-02 · Auditor model: Claude Opus 4.8 · Method: direct measurement (no estimates)

> This document reports **measured reality**, not documentation claims. Every number
> below was produced by a reproducible command against the canonical source tree
> (`ghost_security/`). Where documentation contradicts reality, the correction is given.

---

## 1. Measured repository metrics (ground truth)

| Metric | Measured value | Method |
|---|---:|---|
| Python files (canonical `ghost_security/`) | **403** | `find … -name '*.py'` excl. `__pycache__` |
| Total Python LOC (canonical) | **126,731** | `cat \| wc -l` |
| Test files | **66** | `find -name 'test_*.py'` |
| Tests collected by pytest | **1,865** | `pytest --collect-only` |
| Test files failing to import | **13** | collection errors (see §4) |
| Scanner classes (`class *Scanner`) | **27** | grep across `scanners/`, `backend/scanners/` |
| Rule files (YAML) | **71** | `find rules -name '*.yaml'` |
| API route decorators | **179** | `@app/@router/@api .(get/post/…)` |
| Markdown docs | **22** | `find -name '*.md'` |
| Plugins (`plugins/*.py`) | **0** | directory is effectively empty |
| Committed `.tar.gz` archives in git | **22** (≈118 MB) | `git ls-files` |
| Committed `.pyc` on disk | **617** | `find -name '*.pyc'` |
| `.git` directory size | **145 MB** | `du -sh .git` |
| LICENSE file | **absent** | — |
| Source files with copyright header | **1 / 403** | grep `Copyright` |

---

## 2. Structural truth — the repository contains MULTIPLE project trees

The repository root is **not** a clean single-project layout. It contains:

| Path | Python files | Status | Verdict |
|---|---:|---|---|
| `ghost_security/` | 403 | Newest mtimes (2026-06-02), all Phase 6–9 work | ✅ **CANONICAL** |
| `tythanai/` | 445 | Frozen 2026-05-31 (v3 era), no recent commits | ⚠️ **STALE FULL DUPLICATE** |
| `backend/` (root) | 7 | Fragment | ⚠️ Stale fragment |
| `scanners/` (root) | 1 | Fragment | ⚠️ Stale fragment |
| `tests/` (root) | 8 | Fragment | ⚠️ Stale fragment |
| `sentinelops_cli.py` (root) | 1 file, **200 KB** | Monolith | ⚠️ Legacy monolith |

**Finding R-1 (CRITICAL for presentation):** Two near-complete parallel project trees
(`tythanai/` 445 files and `ghost_security/` 403 files) coexist. A reviewer cloning the
repo cannot tell which is real. This alone fails a "clean repository" smell test.

**Finding R-2 (HIGH):** 118 MB of build artifacts (22 release tarballs) are committed to
git, inflating `.git` to 145 MB. Source repositories must never contain their own release
archives. Reclaiming this requires history rewrite (see remediation).

**Finding R-3 (MEDIUM):** `.pytest_cache/` and 617 `.pyc` files are present on disk;
`.gitignore` is inadequate.

---

## 3. Documentation vs. reality — contradictions

| Claim (location) | Documented | Measured | Status |
|---|---|---|---|
| Test coverage (`README_AI_PLATFORM.md`) | "883+ tests across 25 suites" | 1,865 collected / **13 import-broken** | ⚠️ Number stale *and* 13 suites don't run |
| Benchmark (`BENCHMARK_REPORT.md`) | 100% P / 100% R / 100% F1 / 0% FPR | Derived from **~25 curated samples** | ❌ **NOT CREDIBLE** (see §5) |
| OWASP rules (`README.md`) | "35 rules" | YAML rule files exist; count not yet reconciled per-engine | ⚠️ Verify |
| TON rules (`README.md`) | "28 rules" | TON scanner present (Phase 8 real) | ⚠️ Verify per-engine |
| Root `README.md` | n/a | **47 bytes: "Ton repo"** | ❌ Placeholder |

---

## 4. The test suite does not import cleanly (13 files)

`pytest --collect-only` reports **13 collection errors** from **5 distinct root causes**
— classic refactor drift (symbols renamed or modules moved, tests not updated):

| Root cause | Missing symbol/module | Test files affected |
|---|---|---:|
| 1 | `SSAConverter` not in `backend.core.cpg.ssa` (`SSAForm` exists) | 1 |
| 2 | `_parse_requirements_txt` not in `backend.scanners.supply_chain` | 4 |
| 3 | `backend.core.confidence` module removed (`Finding` moved to `engine.finding_normalizer`) | 1 |
| 4 | `backend.core.cpg.builder` module removed | 2 |
| 5 | `backend/core/knowledge/__init__.py` imports non-existent `.models`, `.store`, `.research_pipeline` | 5 |

**Finding R-4 (CRITICAL for presentation):** Running `pytest` on a fresh clone produces 13
import explosions before any test executes. Root cause 5 is the worst — a package
`__init__.py` that imports three modules that no longer exist, breaking *every* import of
`backend.core.knowledge.*`. **These are being repaired in this audit pass** (real aliases
for renames, corrected `__init__` to match reality — no fabricated implementations).

---

## 5. Benchmark credibility — the headline number is not defensible

`BENCHMARK_REPORT.md` headline:

> Precision **100.0%** · Recall **100.0%** · F1 **100.0%** · FPR **0.0%** · Accuracy **100.0%**

Measured basis: **~25 curated samples** (python 7, js 3, func 2, go 2, php 2, ruby 2 …),
all authored alongside the rules that detect them.

**Why this fails due diligence:**
1. **Self-confirming corpus.** Samples were written to match the rules. 100% on your own
   happy-path fixtures measures nothing about real-world performance.
2. **No external benchmark.** No OWASP Benchmark, Juice Shop, DVWA, or real-CVE corpus.
3. **Sample size.** 25 cases cannot support a 0.0% false-positive-rate claim; the
   confidence interval is enormous.
4. **A perfect score is a red flag**, not a selling point. Sophisticated buyers read
   100%/0% as "untested," not "flawless."

**Remediation (Phase 5 deliverable):** Replace the headline with honest, externally-derived
metrics, or explicitly relabel the current numbers as **"internal regression fixtures
(25 cases) — not a generalization benchmark."** A `BENCHMARK_CREDIBILITY_REPORT.md` will
define the proper evaluation harness (OWASP Benchmark + Juice Shop + real CVEs) and report
true P/R/F1/FPR/FNR — even if the honest numbers are lower. **Honest 78% beats fabricated
100% in every acquisition conversation.**

---

## 6. What is genuinely strong (verified, not inflated)

A truthful audit reports strengths with the same rigor as weaknesses:

- ✅ **Platform internals are clean of the vulnerabilities it detects.** The alarming raw
  grep counts (75 `eval(`, 39 `shell=True`, 26 `pickle.load`, 20 `yaml.load`) are — on
  inspection — **detection patterns inside the scanner's own rule databases, source-sink
  DBs, and test fixtures**, not live platform calls. The real-usage `eval(` check returns
  empty; `runtime/tool_executor.py` is explicitly "Safe subprocess execution. Never uses
  `shell=True`." The product practises what it preaches.
- ✅ **Low debt markers:** only 4 `TODO`, 3 `FIXME`, 1 `NotImplementedError` across 403
  files — unusually disciplined.
- ✅ **Phase 8 (TON) and Phase 9 (Cloud) are real:** 78 + 79 = **157 tests pass** and were
  re-verified during this audit; no stubs.
- ✅ **27 scanner classes, 71 YAML rule packs, 179 API routes** — substantial real surface.

---

## 7. Required corrections (apply to bring docs to 100% truth)

1. `README.md` (root): replace "Ton repo" placeholder with a real project README.
2. `README_AI_PLATFORM.md`: change "883+ tests" → exact current count after import repair.
3. `BENCHMARK_REPORT.md`: relabel/replace the 100% headline per §5.
4. Remove the stale `tythanai/` tree and root fragments OR clearly mark canonical (decision
   pending — irreversible, see master roadmap).
5. Purge 22 tarballs from the tree and from history; add a real `.gitignore`.
6. Add `LICENSE` + copyright headers (legal ownership — see ACQUISITION doc).

---

*Phase 1 complete. Numbers herein are reproducible. Subsequent phases (security, SAST
validation, benchmark harness, dead code, architecture, testing gaps, commercial &
acquisition readiness) build on this verified baseline.*
