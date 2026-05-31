"""
TythanAI — TON Message Flow Analyzer (Static)
Static analysis of FunC/Tact contracts for message flow issues:
state transitions, ownership paths, upgrade vectors.
"""
import re
from pathlib import Path
from typing import Dict, List, Set, Tuple

OP_PATTERNS = {
    r"op\s*==\s*0x([0-9a-fA-F]+)": "op_check",
    r"op\s*==\s*(\d+)":             "op_check_dec",
    r"~load_uint\s*\(32\)":         "op_load",
    r"send_raw_message\s*\(":       "send",
    r"set_data\s*\(":               "state_write",
    r"get_data\s*\(\s*\)":          "state_read",
    r"equal_slices\s*\(":           "ownership_check",
    r"accept_message\s*\(\s*\)":    "gas_accept",
    r"throw_unless\s*\(":           "guard",
    r"throw_if\s*\(":               "guard",
    r"set_code\s*\(":               "upgrade",
}

class MessageFlowAnalyzer:
    """
    Statically traces message handling paths in FunC/Tact contracts.
    Identifies: unguarded state writes, missing op validation,
    upgrade paths, and ownership check coverage.
    """

    def analyze(self, file_path: str) -> Dict:
        p = Path(file_path)
        if not p.exists() or p.suffix.lower() not in (".fc",".func",".tact"):
            return {"error": "unsupported file"}
        content = p.read_text(errors="replace")
        lines   = content.splitlines()

        ops_found:    List[str] = []
        sends:        List[int] = []
        state_writes: List[int] = []
        guards:       List[int] = []
        upgrades:     List[int] = []
        gas_accepts:  List[int] = []
        ownership_checks: List[int] = []

        for lineno, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith(";;") or stripped.startswith("//"):
                continue
            for pattern, tag in OP_PATTERNS.items():
                if re.search(pattern, line):
                    if tag == "op_check" or tag == "op_check_dec":
                        m = re.search(pattern, line)
                        ops_found.append(m.group(1) if m else "?")
                    elif tag == "send":          sends.append(lineno)
                    elif tag == "state_write":   state_writes.append(lineno)
                    elif tag == "guard":         guards.append(lineno)
                    elif tag == "upgrade":       upgrades.append(lineno)
                    elif tag == "gas_accept":    gas_accepts.append(lineno)
                    elif tag == "ownership_check": ownership_checks.append(lineno)

        # Heuristic: state writes without preceding guard in same function block
        unguarded_writes = []
        for sw in state_writes:
            # Look for a guard within 20 lines before this write
            window_start = max(0, sw - 20)
            window = "\n".join(lines[window_start:sw])
            if not re.search(r"throw_unless|throw_if|equal_slices", window):
                unguarded_writes.append(sw)

        findings = []
        if upgrades and not ownership_checks:
            findings.append({"severity":"CRITICAL","rule":"MF001",
                "description":"Upgrade path (set_code) found with no ownership check detected",
                "line": upgrades[0]})
        if gas_accepts and not guards:
            findings.append({"severity":"CRITICAL","rule":"MF002",
                "description":"accept_message() found with no guard (throw_unless/throw_if) in file",
                "line": gas_accepts[0]})
        if unguarded_writes:
            findings.append({"severity":"HIGH","rule":"MF003",
                "description":f"State write (set_data) at line {unguarded_writes[0]} may lack preceding guard",
                "line": unguarded_writes[0]})
        if sends and not state_writes:
            findings.append({"severity":"INFO","rule":"MF004",
                "description":"send_raw_message without set_data — verify state is persisted before send",
                "line": sends[0]})

        return {
            "file":       str(p),
            "ops_found":  ops_found,
            "send_count": len(sends),
            "state_writes": state_writes,
            "guards":     guards,
            "upgrades":   upgrades,
            "ownership_checks": ownership_checks,
            "unguarded_writes": unguarded_writes,
            "findings":   findings,
            "risk_level": ("CRITICAL" if any(f["severity"]=="CRITICAL" for f in findings) else
                           "HIGH"     if any(f["severity"]=="HIGH"     for f in findings) else
                           "LOW"),
        }
