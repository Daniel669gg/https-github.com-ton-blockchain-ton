"""
Ghost Security — Findings Triage AI
Duplicate detection, false-positive scoring, exploitability confidence,
severity normalization, and deduplication across scanners.
"""
import re, hashlib, time
from typing import Dict, List, Tuple

SEV_ORDER = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}

# Heuristics that reduce confidence a finding is real
FP_SIGNALS = [
    (r"test",           -15, "test file"),
    (r"spec",           -10, "spec file"),
    (r"mock",           -10, "mock file"),
    (r"example",        -10, "example file"),
    (r"demo",            -8, "demo file"),
    (r"vendor",          -8, "vendor/third-party"),
    (r"node_modules",   -20, "node_modules"),
    (r"\.pyc$",         -25, "compiled file"),
]

# Heuristics that increase exploitability confidence
EXPLOIT_SIGNALS = [
    ("evidence",         +15, "has evidence"),
    ("exploit_scenario", +10, "has scenario"),
    ("CWE-78",           +20, "command injection"),
    ("CWE-89",           +20, "SQL injection"),
    ("CWE-798",          +25, "hardcoded credential"),
    ("CWE-95",           +20, "code injection"),
    ("CWE-287",          +15, "auth bypass"),
    ("CWE-284",          +10, "access control"),
    ("CRITICAL",         +15, "critical severity"),
    ("HIGH",             +10, "high severity"),
]


class FindingsTriage:
    """
    Post-processing pipeline for raw scanner output.
    1. Deduplicate across scanners (same file+line+CWE = same finding)
    2. Score false-positive risk per finding
    3. Score exploitability confidence
    4. Normalize severity names across scanners
    5. Sort by risk priority
    """

    # ── Public API ────────────────────────────────────────────────────────────

    def triage(self, findings: List[Dict]) -> Dict:
        """Full triage pipeline. Returns enriched, deduplicated, sorted findings."""
        t0 = time.time()

        # Step 1: normalize severity naming
        findings = [self._normalize_severity(f) for f in findings]

        # Step 2: deduplicate
        findings, dupes = self._deduplicate(findings)

        # Step 3: score each finding
        for f in findings:
            f["fp_score"]           = self._fp_score(f)
            f["exploitability"]     = self._exploit_score(f)
            f["triage_priority"]    = self._priority(f)

        # Step 4: sort (priority asc = most important first)
        findings.sort(key=lambda f: (f["triage_priority"],
                                     SEV_ORDER.get(f.get("severity","INFO"),4)))

        # Step 5: split confirmed vs review
        confirmed = [f for f in findings if f["fp_score"] < 40]
        for_review= [f for f in findings if f["fp_score"] >= 40]

        return {
            "total":        len(findings),
            "confirmed":    len(confirmed),
            "for_review":   len(for_review),
            "duplicates_removed": dupes,
            "findings":     findings,
            "duration_ms":  round((time.time()-t0)*1000, 1),
        }

    def deduplicate_only(self, findings: List[Dict]) -> Tuple[List[Dict], int]:
        return self._deduplicate(findings)

    # ── Internal ──────────────────────────────────────────────────────────────

    def _deduplicate(self, findings: List[Dict]) -> Tuple[List[Dict], int]:
        """Merge findings with the same semantic identity."""
        seen: Dict[str, Dict] = {}
        for f in findings:
            key = self._identity_key(f)
            if key not in seen:
                seen[key] = dict(f)
                seen[key]["_sources"] = [f.get("source","?")]
            else:
                # Merge: keep highest severity, union sources
                existing = seen[key]
                if SEV_ORDER.get(f.get("severity","INFO"),4) < SEV_ORDER.get(existing.get("severity","INFO"),4):
                    existing["severity"] = f["severity"]
                src = f.get("source","?")
                if src not in existing.get("_sources",[]):
                    existing.setdefault("_sources",[]).append(src)
                existing["confirmed_by_multiple"] = True

        deduped = list(seen.values())
        return deduped, len(findings) - len(deduped)

    def _identity_key(self, f: Dict) -> str:
        """Canonical identity: cwe + file + ~line (±3) + type."""
        line  = int(f.get("line",0) or 0)
        line  = (line // 3) * 3   # bucket to nearest 3 lines
        parts = [
            f.get("cwe",""),
            str(Path(f.get("file","")).name if f.get("file") else ""),
            str(line),
            f.get("id","")[:6],
        ]
        return hashlib.md5("|".join(parts).encode()).hexdigest()[:12]

    def _normalize_severity(self, f: Dict) -> Dict:
        """Normalize inconsistent severity names from different scanners."""
        raw = str(f.get("severity","")).upper().strip()
        mapping = {
            "CRITICAL":"CRITICAL","ERROR":"HIGH","HIGH":"HIGH",
            "WARNING":"MEDIUM","MEDIUM":"MEDIUM","WARN":"MEDIUM",
            "NOTE":"LOW","LOW":"LOW","INFO":"INFO","INFORMATION":"INFO",
            "NONE":"INFO","UNKNOWN":"INFO",
        }
        f["severity"] = mapping.get(raw, "INFO")
        return f

    def _fp_score(self, f: Dict) -> int:
        """0-100. Higher = more likely false positive."""
        score = 30   # base
        path  = str(f.get("file","")).lower()
        for pattern, delta, _ in FP_SIGNALS:
            if re.search(pattern, path):
                score += delta
        # Low confidence = higher FP risk
        conf = f.get("confidence", 70)
        if conf < 50:  score += 20
        elif conf < 65: score += 10
        # No evidence = higher FP risk
        if not f.get("evidence"): score += 15
        return max(0, min(100, score))

    def _exploit_score(self, f: Dict) -> int:
        """0-100. Higher = more likely exploitable."""
        score = 40  # base
        raw   = str(f)
        for key, delta, _ in EXPLOIT_SIGNALS:
            if key in raw:
                score += delta
        return max(0, min(100, score))

    def _priority(self, f: Dict) -> int:
        """1-5 sort priority. 1 = fix immediately."""
        sev   = f.get("severity","INFO")
        fp    = f.get("fp_score", 30)
        exp   = f.get("exploitability", 40)
        if sev == "CRITICAL" and fp < 30:  return 1
        if sev in ("CRITICAL","HIGH") and fp < 50: return 2
        if sev == "HIGH" and exp > 60:     return 2
        if sev == "MEDIUM" and fp < 40:    return 3
        if sev in ("LOW","INFO"):          return 5
        return 4

from pathlib import Path as Path
