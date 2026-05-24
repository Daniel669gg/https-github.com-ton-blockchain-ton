"""
Ghost Security Platform — Security Agent
Delegates to real scanners (AST, secrets, TON) and returns structured results.
"""
from pathlib import Path
from typing import Dict


class SecurityAgent:
    def __init__(self):
        import sys; sys.path.insert(0, str(Path(__file__).parent.parent))
        from scanners.ast_scanner.ast_analyzer import ASTScanner
        from scanners.secret_scanner.secret_detector import SecretDetector
        from scanners.ton_scanner.ton_analyzer import TONAnalyzer
        self._ast = ASTScanner()
        self._secrets = SecretDetector()
        self._ton = TONAnalyzer()

    async def scan(self, output: Dict) -> Dict:
        target = output.get("path") or output.get("file") or output.get("target")
        if not target or not Path(target).exists():
            return {"status": "no_target", "findings": [], "risk_score": "unknown"}

        all_findings = []
        p = Path(target)
        if p.suffix.lower() in (".fc", ".func", ".tact", ".fift", ".fif"):
            all_findings.extend(self._ton.analyze_file(str(p)))
        elif p.is_dir():
            all_findings.extend(self._ast.scan_directory(str(p)).get("findings", []))
            all_findings.extend(self._secrets.scan_directory(str(p)).get("findings", []))
            all_findings.extend(self._ton.scan_directory(str(p)).get("findings", []))
        else:
            all_findings.extend(self._ast.scan_file(str(p)))
            all_findings.extend(self._secrets.scan_file(str(p)))

        crits = sum(1 for f in all_findings if f.get("severity") == "CRITICAL")
        highs = sum(1 for f in all_findings if f.get("severity") == "HIGH")
        risk = "critical" if crits else "high" if highs else "medium" if all_findings else "low"
        return {"status": "completed", "findings": all_findings,
                "total_findings": len(all_findings), "risk_score": risk,
                "critical": crits, "high": highs}
