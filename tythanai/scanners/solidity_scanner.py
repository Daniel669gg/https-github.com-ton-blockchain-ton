"""
TythanAI — Solidity Smart Contract Analyzer
Static analysis for EVM-based contracts (.sol).
Covers: reentrancy, integer overflow, access control,
tx.origin, unchecked calls, and more.
"""
import re
from pathlib import Path
from typing import Dict, List

SOL_RULES: List[Dict] = [
    {"id":"SOL001","severity":"CRITICAL","cwe":"CWE-362",
     "pattern":r'\.(transfer|send|call)\s*\{?[^}]*\}?\s*\(',
     "desc":"External call before state update — potential reentrancy",
     "fix":"Follow checks-effects-interactions: update state BEFORE external calls; use ReentrancyGuard",
     "category":"Reentrancy"},
    {"id":"SOL002","severity":"HIGH","cwe":"CWE-284",
     "pattern":r'tx\.origin\s*==',
     "desc":"tx.origin for authentication — bypassed by phishing contracts",
     "fix":"Use msg.sender instead of tx.origin for access control",
     "category":"Access Control"},
    {"id":"SOL003","severity":"HIGH","cwe":"CWE-190",
     "pattern":r'uint\d*\s+\w+\s*=\s*\w+\s*[+\-\*]',
     "desc":"Arithmetic without SafeMath or unchecked block — overflow/underflow risk",
     "fix":"Use Solidity 0.8+ (built-in overflow checks) or OpenZeppelin SafeMath",
     "category":"Integer Overflow"},
    {"id":"SOL004","severity":"CRITICAL","cwe":"CWE-284",
     "pattern":r'selfdestruct\s*\(',
     "desc":"selfdestruct — irreversible contract destruction; verify access control",
     "fix":"Guard with onlyOwner; consider removing selfdestruct in new contracts",
     "category":"Access Control"},
    {"id":"SOL005","severity":"HIGH","cwe":"CWE-703",
     "pattern":r'\.call\s*\{[^}]*\}\s*\([^)]*\)(?!\s*;?\s*require)',
     "desc":"Low-level .call() return value not checked — silent failure",
     "fix":"Always check return value: (bool ok,) = addr.call{...}(...); require(ok)",
     "category":"Unchecked Return"},
    {"id":"SOL006","severity":"HIGH","cwe":"CWE-338",
     "pattern":r'block\.(timestamp|number|difficulty|prevrandao)',
     "desc":"Block variable used as entropy — manipulable by validators/miners",
     "fix":"Use Chainlink VRF or Commit-Reveal scheme for randomness",
     "category":"Randomness"},
    {"id":"SOL007","severity":"HIGH","cwe":"CWE-284",
     "pattern":r'function\s+\w+\s*\([^)]*\)\s*(?:public|external)(?!\s+(?:view|pure|returns))',
     "desc":"State-changing public/external function — verify access control exists",
     "fix":"Add onlyOwner, onlyRole, or custom modifier to sensitive functions",
     "category":"Access Control"},
    {"id":"SOL008","severity":"MEDIUM","cwe":"CWE-400",
     "pattern":r'for\s*\([^;]+;\s*\w+\s*<\s*\w+\.length',
     "desc":"Unbounded loop over dynamic array — DoS via gas exhaustion",
     "fix":"Cap array size; use pull-payment pattern; paginate large iterations",
     "category":"Gas / DoS"},
    {"id":"SOL009","severity":"HIGH","cwe":"CWE-284",
     "pattern":r'(owner|admin)\s*=\s*(?!msg\.sender)',
     "desc":"Owner/admin set to non-msg.sender value — verify intent",
     "fix":"Set owner = msg.sender in constructor; use two-step ownership transfer",
     "category":"Access Control"},
    {"id":"SOL010","severity":"MEDIUM","cwe":"CWE-682",
     "pattern":r'delegatecall\s*\(',
     "desc":"delegatecall executes code in caller's context — storage collision risk",
     "fix":"Ensure storage layouts match exactly; use EIP-1967 proxy pattern",
     "category":"Delegatecall"},
    {"id":"SOL011","severity":"HIGH","cwe":"CWE-362",
     "pattern":r'(mapping|uint|address)\s+\w+\s*;\s*\n.*function.*\n.*\.call',
     "desc":"State variable near external call — check for reentrancy path",
     "fix":"Use nonReentrant modifier from OpenZeppelin ReentrancyGuard",
     "category":"Reentrancy"},
    {"id":"SOL012","severity":"MEDIUM","cwe":"CWE-20",
     "pattern":r'abi\.encodePacked\s*\([^)]*,',
     "desc":"abi.encodePacked with multiple dynamic types — hash collision risk",
     "fix":"Use abi.encode() instead of abi.encodePacked() for multiple dynamic types",
     "category":"Hash Collision"},
    {"id":"SOL013","severity":"HIGH","cwe":"CWE-284",
     "pattern":r'(initialize|init)\s*\([^)]*\)\s*(?:public|external)',
     "desc":"Public initializer — verify it can only be called once (proxy pattern risk)",
     "fix":"Use OpenZeppelin Initializable with initializer modifier",
     "category":"Initializer"},
    {"id":"SOL014","severity":"LOW","cwe":"CWE-703",
     "pattern":r'revert\s*\(\s*\)',
     "desc":"Empty revert — no error message makes debugging and monitoring harder",
     "fix":"Use revert CustomError() or revert('reason') for traceability",
     "category":"Error Handling"},
    {"id":"SOL015","severity":"MEDIUM","cwe":"CWE-284",
     "pattern":r'ecrecover\s*\(',
     "desc":"ecrecover — returns address(0) on invalid signature; check for zero address",
     "fix":"require(signer != address(0), 'Invalid signature') after ecrecover",
     "category":"Signature Validation"},
]

class SolidityScanner:
    """Static analyzer for Solidity smart contracts (.sol)."""

    def analyze_file(self, file_path: str) -> List[Dict]:
        p = Path(file_path)
        if p.suffix.lower() != ".sol":
            return []
        try:
            content = p.read_text(errors="replace")
        except OSError:
            return []
        findings, lines = [], content.splitlines()
        for rule in SOL_RULES:
            pat = re.compile(rule["pattern"])
            for lineno, line in enumerate(lines, 1):
                stripped = line.strip()
                if stripped.startswith(("//","/*","*")):
                    continue
                if pat.search(line):
                    findings.append({
                        "type":"SOLIDITY_VULNERABILITY","id":rule["id"],
                        "severity":rule["severity"],"cwe":rule["cwe"],
                        "file":str(p),"line":lineno,
                        "description":rule["desc"],"evidence":stripped[:120],
                        "recommendation":rule["fix"],"category":rule["category"],
                        "source":"solidity_scanner","confidence":75,
                    })
        seen, result = set(), []
        for f in findings:
            k = (f["id"],f["file"],f["line"])
            if k not in seen: seen.add(k); result.append(f)
        return result

    def scan_directory(self, directory: str) -> Dict:
        all_findings, count = [], 0
        for f in Path(directory).rglob("*.sol"):
            if ".git" not in f.parts:
                all_findings.extend(self.analyze_file(str(f))); count += 1
        sev_c: Dict = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
        for f in all_findings:
            sev_c[f.get("severity","MEDIUM")] = sev_c.get(f.get("severity","MEDIUM"),0)+1
        return {"files_scanned":count,"total_findings":len(all_findings),
                "severity_counts":sev_c,"findings":all_findings}
