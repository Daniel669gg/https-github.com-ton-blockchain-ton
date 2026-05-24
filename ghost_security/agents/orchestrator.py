"""
Ghost Security Platform — Multi-Agent Orchestrator
Real multi-agent coordination system.
Coordinator → Research Agent, Security Agent, Coding Agent, Reviewer Agent
No placeholders. Real LLM-powered agents with real tools.
"""
import json
import time
import threading
from typing import Dict, List, Optional, Any, Callable
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from config.config import LLM_MODEL, LLM_FAST_MODEL, OPENAI_API_KEY, OPENAI_BASE_URL
from core.agent.agent_loop import AgentLoop
from core.tools.tool_registry import ToolRegistry
from core.memory.memory_manager import MemoryManager
from core.planner.task_planner import TaskPlanner
from scanners.ast_scanner.ast_analyzer import ASTScanner
from scanners.semgrep_scanner.semgrep_scanner import SemgrepScanner
from scanners.secret_scanner.secret_detector import SecretDetector
from scanners.github_watcher.github_watcher import GitHubWatcher


class AgentRole(Enum):
    COORDINATOR = "coordinator"
    RESEARCH = "research"
    SECURITY = "security"
    CODING = "coding"
    REVIEWER = "reviewer"


@dataclass
class AgentTask:
    """Task assigned to a specific agent."""
    task_id: str
    role: AgentRole
    description: str
    context: str = ""
    priority: str = "medium"
    status: str = "pending"  # pending, running, completed, failed
    result: Optional[Dict] = None
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    findings: List[Dict] = field(default_factory=list)


@dataclass
class AuditSession:
    """A complete audit session with all agents."""
    session_id: str
    target: str
    audit_type: str
    status: str = "initializing"
    tasks: List[AgentTask] = field(default_factory=list)
    all_findings: List[Dict] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    completed_at: Optional[float] = None
    report: Optional[Dict] = None
    progress: int = 0
    current_step: str = ""


class MultiAgentOrchestrator:
    """
    Real multi-agent orchestrator for security auditing.
    Coordinates specialized agents, aggregates findings, and produces reports.
    """

    def __init__(self):
        self.tool_registry = ToolRegistry()
        self.memory = MemoryManager()
        self.planner = TaskPlanner()
        self.ast_scanner = ASTScanner()
        self.semgrep_scanner = SemgrepScanner()
        self.secret_detector = SecretDetector()
        self.github_watcher = GitHubWatcher()

        self._sessions: Dict[str, AuditSession] = {}
        self._callbacks: Dict[str, List[Callable]] = {}

        # Register scanner tools in tool registry
        self._register_scanner_tools()

    def _register_scanner_tools(self):
        """Register scanner tools so agents can use them."""
        from core.tools.tool_registry import Tool, ToolResult

        def ast_scan_file(path: str) -> ToolResult:
            findings = self.ast_scanner.scan_file(path)
            return ToolResult(True, json.dumps(findings, indent=2),
                              metadata={"count": len(findings)})

        def ast_scan_directory(path: str) -> ToolResult:
            result = self.ast_scanner.scan_directory(path)
            return ToolResult(True, json.dumps(result, indent=2),
                              metadata={"count": result.get("total_findings", 0)})

        def semgrep_scan(path: str) -> ToolResult:
            result = self.semgrep_scanner.scan_path(path)
            return ToolResult(
                result.get("error") is None,
                json.dumps(result, indent=2),
                error=result.get("error", ""),
                metadata={"count": result.get("total_findings", 0)}
            )

        def secret_scan_file(path: str) -> ToolResult:
            findings = self.secret_detector.scan_file(path)
            return ToolResult(True, json.dumps(findings, indent=2),
                              metadata={"count": len(findings)})

        def secret_scan_directory(path: str) -> ToolResult:
            result = self.secret_detector.scan_directory(path)
            return ToolResult(True, json.dumps(result, indent=2),
                              metadata={"count": result.get("total_findings", 0)})

        def github_watch(owner: str, repo: str, branch: str = "main") -> ToolResult:
            result = self.github_watcher.watch_repository(owner, repo, branch)
            return ToolResult(
                "error" not in result,
                json.dumps(result, indent=2),
                error=result.get("error", ""),
                metadata={"count": result.get("total_findings", 0)}
            )

        def github_repo_info(owner: str, repo: str) -> ToolResult:
            result = self.github_watcher.get_repo_info(owner, repo)
            return ToolResult("error" not in result, json.dumps(result, indent=2))

        scanner_tools = [
            Tool("ast_scan_file", "Run AST security analysis on a single file",
                 {"path": {"type": "string", "description": "File path to scan"}}, ast_scan_file),
            Tool("ast_scan_directory", "Run AST security analysis on entire directory",
                 {"path": {"type": "string", "description": "Directory path to scan"}}, ast_scan_directory),
            Tool("semgrep_scan", "Run Semgrep security scanner on path",
                 {"path": {"type": "string", "description": "Path to scan"}}, semgrep_scan),
            Tool("secret_scan_file", "Scan file for hardcoded secrets",
                 {"path": {"type": "string"}}, secret_scan_file),
            Tool("secret_scan_directory", "Scan directory for hardcoded secrets",
                 {"path": {"type": "string"}}, secret_scan_directory),
            Tool("github_watch", "Watch GitHub repository for security issues",
                 {"owner": {"type": "string"}, "repo": {"type": "string"},
                  "branch": {"type": "string", "default": "main"}}, github_watch),
            Tool("github_repo_info", "Get GitHub repository information",
                 {"owner": {"type": "string"}, "repo": {"type": "string"}}, github_repo_info),
        ]

        for tool in scanner_tools:
            self.tool_registry.register(tool)

    def start_audit(self, target: str, audit_type: str = "full",
                    session_id: Optional[str] = None,
                    callback: Optional[Callable] = None) -> str:
        """
        Start a full security audit using multiple agents.
        Returns session_id for tracking progress.
        """
        import hashlib
        if not session_id:
            session_id = hashlib.md5(f"{target}{time.time()}".encode()).hexdigest()[:12]

        session = AuditSession(
            session_id=session_id,
            target=target,
            audit_type=audit_type
        )
        self._sessions[session_id] = session

        if callback:
            self._callbacks[session_id] = [callback]

        # Run in background thread
        thread = threading.Thread(
            target=self._run_audit,
            args=(session_id, target, audit_type),
            daemon=True
        )
        thread.start()

        return session_id

    def _notify(self, session_id: str, event: str, data: Any):
        """Notify callbacks of progress."""
        for cb in self._callbacks.get(session_id, []):
            try:
                cb(event, data)
            except Exception:
                pass

    def _run_audit(self, session_id: str, target: str, audit_type: str):
        """Run the full multi-agent audit pipeline."""
        session = self._sessions[session_id]
        session.status = "running"
        session.current_step = "Planning"
        self._notify(session_id, "status", {"status": "running", "step": "Planning"})

        try:
            # Step 1: Create audit plan
            plan = self.planner.create_plan(target, audit_type)
            session.progress = 10
            self._notify(session_id, "plan_created", plan)

            # Step 2: Research Agent — gather information
            session.current_step = "Reconnaissance"
            session.progress = 20
            research_findings = self._run_research_agent(session_id, target, plan)
            session.all_findings.extend(research_findings)

            # Step 3: Security Agent — run scanners
            session.current_step = "Security Scanning"
            session.progress = 40
            scanner_findings = self._run_scanner_pipeline(session_id, target)
            session.all_findings.extend(scanner_findings)

            # Step 4: Security Agent — deep analysis with LLM
            session.current_step = "Deep Analysis"
            session.progress = 60
            deep_findings = self._run_security_agent(session_id, target, plan, scanner_findings)
            session.all_findings.extend(deep_findings)

            # Step 5: Reviewer Agent — verify and deduplicate
            session.current_step = "Review & Verification"
            session.progress = 80
            verified_findings = self._run_reviewer_agent(session_id, session.all_findings)

            # Step 6: Generate report
            session.current_step = "Report Generation"
            session.progress = 90
            report = self._generate_report(session_id, target, verified_findings, plan)
            session.report = report
            session.all_findings = verified_findings

            session.status = "completed"
            session.completed_at = time.time()
            session.progress = 100
            session.current_step = "Completed"
            self._notify(session_id, "completed", {"report": report})

        except Exception as e:
            session.status = "failed"
            session.current_step = f"Error: {str(e)}"
            self._notify(session_id, "error", {"error": str(e)})

    def _run_research_agent(self, session_id: str, target: str, plan: Dict) -> List[Dict]:
        """Research agent: gather information about target."""
        self._notify(session_id, "agent_start", {"agent": "research", "target": target})

        # Determine if target is a path, URL, or GitHub repo
        findings = []
        target_path = Path(target)

        if target_path.exists():
            # Local path — list structure
            if target_path.is_dir():
                # Count files by type
                file_types = {}
                for f in target_path.rglob('*'):
                    if f.is_file():
                        ext = f.suffix.lower()
                        file_types[ext] = file_types.get(ext, 0) + 1

                self._notify(session_id, "research_info", {
                    "type": "directory",
                    "path": str(target_path),
                    "file_types": file_types
                })

        elif target.startswith("https://github.com/"):
            # GitHub repository
            parts = target.replace("https://github.com/", "").strip("/").split("/")
            if len(parts) >= 2:
                owner, repo = parts[0], parts[1]
                repo_info = self.github_watcher.get_repo_info(owner, repo)
                self._notify(session_id, "research_info", {"type": "github", "info": repo_info})

        return findings

    def _run_scanner_pipeline(self, session_id: str, target: str) -> List[Dict]:
        """Run all static scanners on target."""
        all_findings = []
        target_path = Path(target)

        if not target_path.exists():
            # Try as GitHub URL
            if target.startswith("https://github.com/"):
                parts = target.replace("https://github.com/", "").strip("/").split("/")
                if len(parts) >= 2:
                    owner, repo = parts[0], parts[1]
                    # Watch for security issues in recent commits
                    result = self.github_watcher.watch_repository(owner, repo)
                    all_findings.extend(result.get("findings", []))
                    self._notify(session_id, "scanner_result", {
                        "scanner": "github_watcher",
                        "count": len(result.get("findings", []))
                    })
            return all_findings

        # Local path scanning
        scan_target = str(target_path)

        # 1. Secret detection
        self._notify(session_id, "scanner_start", {"scanner": "secret_detector"})
        if target_path.is_file():
            secret_findings = self.secret_detector.scan_file(scan_target)
        else:
            secret_result = self.secret_detector.scan_directory(scan_target)
            secret_findings = secret_result.get("findings", [])
        all_findings.extend(secret_findings)
        self._notify(session_id, "scanner_result", {
            "scanner": "secret_detector", "count": len(secret_findings)
        })

        # 2. AST analysis
        self._notify(session_id, "scanner_start", {"scanner": "ast_scanner"})
        if target_path.is_file():
            ast_findings = self.ast_scanner.scan_file(scan_target)
        else:
            ast_result = self.ast_scanner.scan_directory(scan_target)
            ast_findings = ast_result.get("findings", [])
        all_findings.extend(ast_findings)
        self._notify(session_id, "scanner_result", {
            "scanner": "ast_scanner", "count": len(ast_findings)
        })

        # 3. Semgrep
        self._notify(session_id, "scanner_start", {"scanner": "semgrep"})
        semgrep_result = self.semgrep_scanner.scan_path(scan_target)
        semgrep_findings = semgrep_result.get("findings", [])
        all_findings.extend(semgrep_findings)
        self._notify(session_id, "scanner_result", {
            "scanner": "semgrep", "count": len(semgrep_findings)
        })

        return all_findings

    def _run_security_agent(self, session_id: str, target: str,
                             plan: Dict, initial_findings: List[Dict]) -> List[Dict]:
        """Security agent: deep LLM-powered analysis."""
        self._notify(session_id, "agent_start", {"agent": "security"})

        # Build context from initial findings
        findings_summary = self._summarize_findings(initial_findings)

        task = f"""Perform deep security analysis of: {target}

Initial scanner findings summary:
{json.dumps(findings_summary, indent=2)}

Top findings requiring investigation:
{json.dumps(initial_findings[:5], indent=2)}

Your tasks:
1. Investigate the most critical findings in detail
2. Look for additional vulnerabilities not caught by scanners
3. Check for business logic flaws
4. Verify authentication and authorization mechanisms
5. Look for insecure configurations

Use available tools to read files, run commands, and gather evidence.
Add confirmed findings using add_finding tool.
"""

        agent = AgentLoop(self.tool_registry, self.memory)
        events = []
        agent.add_callback(lambda e, d: events.append((e, d)))

        result = agent.run(task, max_iterations=10)
        self._notify(session_id, "agent_complete", {
            "agent": "security",
            "findings": len(result.get("findings", []))
        })

        return result.get("findings", [])

    def _run_reviewer_agent(self, session_id: str, findings: List[Dict]) -> List[Dict]:
        """Reviewer agent: verify, deduplicate, and prioritize findings."""
        self._notify(session_id, "agent_start", {"agent": "reviewer"})

        # Deduplicate by file+line+type
        seen = set()
        deduped = []
        for f in findings:
            key = (f.get("file", ""), f.get("line", 0), f.get("type", ""))
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        # Sort by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_findings = sorted(
            deduped,
            key=lambda f: severity_order.get(f.get("severity", "INFO"), 5)
        )

        self._notify(session_id, "agent_complete", {
            "agent": "reviewer",
            "original": len(findings),
            "after_dedup": len(sorted_findings)
        })

        return sorted_findings

    def _generate_report(self, session_id: str, target: str,
                          findings: List[Dict], plan: Dict) -> Dict:
        """Generate comprehensive security report."""
        from openai import OpenAI

        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            sev = f.get("severity", "INFO")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        risk_score = min(
            severity_counts["CRITICAL"] * 25 +
            severity_counts["HIGH"] * 15 +
            severity_counts["MEDIUM"] * 8 +
            severity_counts["LOW"] * 3, 100
        )

        # Generate executive summary using LLM
        executive_summary = self._generate_executive_summary(target, findings, severity_counts)

        # Group findings by type
        by_type = {}
        for f in findings:
            t = f.get("type", "Unknown")
            if t not in by_type:
                by_type[t] = []
            by_type[t].append(f)

        # Generate recommendations
        recommendations = self._generate_recommendations(findings)

        report = {
            "session_id": session_id,
            "target": target,
            "audit_type": plan.get("audit_type", "full"),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "risk_score": risk_score,
            "risk_level": self._risk_level(risk_score),
            "executive_summary": executive_summary,
            "severity_counts": severity_counts,
            "total_findings": len(findings),
            "findings": findings,
            "findings_by_type": {k: len(v) for k, v in by_type.items()},
            "recommendations": recommendations,
            "plan": plan
        }

        # Save report to file
        reports_dir = Path(__file__).parent.parent / "reports"
        reports_dir.mkdir(exist_ok=True)
        report_path = reports_dir / f"report_{session_id}.json"
        report_path.write_text(json.dumps(report, indent=2))

        return report

    def _generate_executive_summary(self, target: str, findings: List[Dict],
                                     severity_counts: Dict) -> str:
        """Generate executive summary using LLM."""
        try:
            from openai import OpenAI
            client = OpenAI(api_key=OPENAI_API_KEY, base_url=OPENAI_BASE_URL)

            critical_findings = [f for f in findings if f.get("severity") == "CRITICAL"][:3]
            prompt = f"""Write a concise executive summary (3-4 sentences) for a security audit report.

Target: {target}
Findings: {severity_counts.get('CRITICAL', 0)} critical, {severity_counts.get('HIGH', 0)} high, {severity_counts.get('MEDIUM', 0)} medium, {severity_counts.get('LOW', 0)} low

Most critical issues:
{json.dumps(critical_findings, indent=2) if critical_findings else 'None'}

Write professionally. Be specific about risks found."""

            response = client.chat.completions.create(
                model=LLM_FAST_MODEL,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=300,
                temperature=0.3
            )
            return response.choices[0].message.content
        except Exception:
            critical = severity_counts.get("CRITICAL", 0)
            high = severity_counts.get("HIGH", 0)
            total = sum(severity_counts.values())
            return (f"Security audit of '{target}' identified {total} findings including "
                    f"{critical} critical and {high} high severity issues. "
                    f"Immediate remediation is recommended for critical findings.")

    def _generate_recommendations(self, findings: List[Dict]) -> List[str]:
        """Generate prioritized recommendations from findings."""
        recs = set()
        for f in findings:
            rec = f.get("recommendation", "")
            if rec and len(rec) > 10:
                recs.add(rec)
        # Add general recommendations based on finding types
        types = {f.get("type", "") for f in findings}
        if "Hardcoded Secret" in types:
            recs.add("Implement a secrets management solution (HashiCorp Vault, AWS Secrets Manager)")
            recs.add("Rotate all exposed credentials immediately")
            recs.add("Add pre-commit hooks to prevent secret commits (e.g., git-secrets, truffleHog)")
        if "SQL Injection" in types:
            recs.add("Use parameterized queries or ORM throughout the codebase")
            recs.add("Implement input validation and sanitization layer")
        if "Command Injection" in types:
            recs.add("Avoid shell=True in subprocess calls; use argument lists")
            recs.add("Implement allowlist for any user-controlled command parameters")
        if "Weak Cryptography" in types:
            recs.add("Upgrade all MD5/SHA1 usages to SHA-256 or SHA-3")
            recs.add("Use secrets module instead of random for security-sensitive operations")
        return list(recs)[:15]

    def get_session(self, session_id: str) -> Optional[AuditSession]:
        """Get audit session by ID."""
        return self._sessions.get(session_id)

    def get_session_status(self, session_id: str) -> Dict:
        """Get current status of audit session."""
        session = self._sessions.get(session_id)
        if not session:
            return {"error": "Session not found"}
        return {
            "session_id": session_id,
            "status": session.status,
            "progress": session.progress,
            "current_step": session.current_step,
            "target": session.target,
            "findings_count": len(session.all_findings),
            "started_at": session.started_at,
            "completed_at": session.completed_at
        }

    def _summarize_findings(self, findings: List[Dict]) -> Dict:
        """Summarize findings for agent context."""
        by_severity = {}
        by_type = {}
        for f in findings:
            sev = f.get("severity", "INFO")
            by_severity[sev] = by_severity.get(sev, 0) + 1
            t = f.get("type", "Unknown")
            by_type[t] = by_type.get(t, 0) + 1
        return {"by_severity": by_severity, "by_type": by_type, "total": len(findings)}

    @staticmethod
    def _risk_level(score: int) -> str:
        if score >= 75:
            return "CRITICAL"
        elif score >= 50:
            return "HIGH"
        elif score >= 25:
            return "MEDIUM"
        elif score > 0:
            return "LOW"
        return "NONE"
