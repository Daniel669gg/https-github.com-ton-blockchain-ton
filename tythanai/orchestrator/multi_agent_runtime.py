"""
TythanAI — Multi-Agent Runtime v2.2
Implements a Plan → Execute → Debate → Verify → Report cycle.
Agents debate findings before finalising: reduces false positives,
improves severity calibration, and produces higher-quality reports.
"""
import asyncio
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))
from runtime.trace import TraceLogger


class RuntimeState(Enum):
    PLANNING   = "planning"
    EXECUTING  = "executing"
    DEBATING   = "debating"
    VERIFYING  = "verifying"
    REPORTING  = "reporting"
    COMPLETE   = "complete"
    FAILED     = "failed"


@dataclass
class DebateRound:
    """One round of inter-agent debate on a contested finding."""
    finding_id:   str
    proposer:     str          # agent that raised the finding
    challenger:   str          # agent challenging it
    challenge:    str          # challenge argument
    response:     str          # proposer's rebuttal
    verdict:      str          # "keep" | "downgrade" | "remove"
    new_severity: Optional[str] = None


@dataclass
class AgentTask:
    role:      str
    objective: str
    result:    Optional[Dict] = None
    error:     Optional[str]  = None
    duration:  float = 0.0


class MultiAgentRuntime:
    """
    Orchestrates multi-agent security audit with built-in debate.

    Pipeline:
      1. Planner  → produces ordered step list
      2. Executor → runs each step (scanners, tools)
      3. Critic   → challenges findings individually
      4. Debate   → contested findings go to 3-way debate
      5. Security → final cross-scanner risk assessment
      6. Report   → produces structured output
    """

    MAX_DEBATE_FINDINGS = 10   # limit LLM calls
    DEBATE_SEVERITY_THRESHOLD = ("CRITICAL", "HIGH")

    def __init__(self, planner, executor, critic, security):
        self.planner  = planner
        self.executor = executor
        self.critic   = critic
        self.security = security
        self.state    = RuntimeState.PLANNING
        self.trace    = TraceLogger()
        self._llm     = self._init_llm()

    # ── Public API ────────────────────────────────────────────────────────────

    async def run(self, task: str, audit_type: str = "full") -> Dict:
        session_id = f"session_{int(time.time())}"
        started_at = time.time()
        all_findings: List[Dict] = []
        step_results: List[Dict] = []
        debate_log:   List[Dict] = []

        self.trace.log("start", "runtime", "begin", {"task": task, "session": session_id})

        # ── 1. Plan ───────────────────────────────────────────────────────────
        self.state = RuntimeState.PLANNING
        self.trace.log("plan", "planner", "start", {"task": task})
        try:
            plan = await self.planner.plan(task, audit_type)
        except Exception as e:
            plan = [f"Scan target: {task}"]
        self.trace.log("plan", "planner", "done", {"steps": len(plan)})

        # ── 2. Execute ────────────────────────────────────────────────────────
        self.state = RuntimeState.EXECUTING
        for i, step in enumerate(plan, 1):
            self.trace.log(f"step_{i}", "executor", "start", {"step": step})
            t0 = time.time()
            try:
                result = await self._execute_step(step, task)
            except Exception as e:
                result = {"status": "error", "error": str(e), "findings": []}
            duration = round(time.time() - t0, 2)

            findings = result.get("findings", [])
            all_findings.extend(findings)
            step_results.append({"step": step, "findings": len(findings),
                                  "duration": duration, "status": result.get("status","ok")})
            self.trace.log(f"step_{i}", "executor", "done",
                           {"findings": len(findings), "duration": duration})

        # ── 3. Critic review ──────────────────────────────────────────────────
        self.state = RuntimeState.DEBATING
        self.trace.log("critique", "critic", "start", {"findings": len(all_findings)})
        critique = await self.critic.review({"findings": all_findings})
        self.trace.log("critique", "critic", "done", {"score": critique.get("quality_score")})

        # ── 4. Debate contested findings ──────────────────────────────────────
        if self._llm and all_findings:
            candidates = [
                f for f in all_findings
                if f.get("severity") in self.DEBATE_SEVERITY_THRESHOLD
            ][:self.MAX_DEBATE_FINDINGS]

            for finding in candidates:
                round_ = await self._debate_finding(finding)
                if round_:
                    debate_log.append(round_.__dict__)
                    if round_.verdict == "remove":
                        all_findings = [f for f in all_findings if f is not finding]
                    elif round_.verdict == "downgrade" and round_.new_severity:
                        finding["severity"] = round_.new_severity
                        finding["debate_note"] = round_.challenge[:120]

        self.trace.log("debate", "runtime", "done",
                       {"rounds": len(debate_log), "removed": sum(1 for d in debate_log if d["verdict"]=="remove")})

        # ── 5. Final security scan ────────────────────────────────────────────
        self.state = RuntimeState.VERIFYING
        sec_result = await self.security.scan({"findings": all_findings, "target": task})
        self.trace.log("security", "security_agent", "done")

        # ── 6. Build report ───────────────────────────────────────────────────
        self.state = RuntimeState.REPORTING
        severity_counts: Dict[str, int] = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"INFO":0}
        for f in all_findings:
            sev = f.get("severity","INFO")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        risk_score = min(
            severity_counts["CRITICAL"]*25 + severity_counts["HIGH"]*15 +
            severity_counts["MEDIUM"]*8 + severity_counts["LOW"]*3, 100
        )
        risk_level = (
            "CRITICAL" if risk_score>=75 else
            "HIGH"     if risk_score>=50 else
            "MEDIUM"   if risk_score>=25 else "LOW"
        )

        report = {
            "session_id":       session_id,
            "target":           task,
            "audit_type":       audit_type,
            "timestamp":        time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "duration_s":       round(time.time()-started_at, 1),
            "status":           "completed",
            "risk_score":       risk_score,
            "risk_level":       risk_level,
            "executive_summary": self._executive_summary(
                task, all_findings, severity_counts, debate_log),
            "severity_counts":  severity_counts,
            "total_findings":   len(all_findings),
            "findings":         all_findings,
            "debate_log":       debate_log,
            "step_results":     step_results,
            "critique":         critique,
            "recommendations":  self._recommendations(all_findings, severity_counts),
        }

        self.state = RuntimeState.COMPLETE
        self.trace.log("complete", "runtime", "done",
                       {"findings": len(all_findings), "risk": risk_level})
        return report

    # ── Internal helpers ──────────────────────────────────────────────────────

    async def _execute_step(self, step: str, task: str) -> Dict:
        """Delegate step execution to the executor or directly to scanners."""
        if hasattr(self.executor, "execute"):
            return await self.executor.execute(step)
        # Lightweight fallback: pass step as a scan path hint
        return {"status": "skipped", "findings": []}

    async def _debate_finding(self, finding: Dict) -> Optional[DebateRound]:
        """Run a two-turn debate: challenger challenges, proposer responds, verdict issued."""
        if not self._llm:
            return None
        try:
            # Turn 1: challenger argues it might be FP or lower severity
            challenge_prompt = (
                "You are a skeptical security auditor. Challenge this finding — "
                "argue why it could be a false positive or lower severity. Be specific.\n\n"
                f"Finding: {json.dumps(finding, indent=2)[:1500]}\n\n"
                "Reply in 2-3 sentences only."
            )
            c_resp = self._llm.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role":"user","content":challenge_prompt}],
                max_tokens=200, temperature=0.4,
            )
            challenge = c_resp.choices[0].message.content.strip()

            # Turn 2: proposer defends
            defend_prompt = (
                "You are the original security analyst. Defend this finding against this challenge.\n\n"
                f"Finding: {json.dumps(finding, indent=2)[:1000]}\n"
                f"Challenge: {challenge}\n\n"
                "Reply in 2-3 sentences and end with VERDICT: keep / downgrade / remove"
            )
            d_resp = self._llm.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role":"user","content":defend_prompt}],
                max_tokens=200, temperature=0.2,
            )
            defense = d_resp.choices[0].message.content.strip()

            # Parse verdict
            import re
            vm = re.search(r"VERDICT:\s*(keep|downgrade|remove)", defense, re.IGNORECASE)
            verdict = vm.group(1).lower() if vm else "keep"
            new_sev = None
            if verdict == "downgrade":
                sev_down = {"CRITICAL":"HIGH","HIGH":"MEDIUM","MEDIUM":"LOW","LOW":"INFO"}
                new_sev = sev_down.get(finding.get("severity","INFO"), "INFO")

            return DebateRound(
                finding_id=finding.get("id","?"),
                proposer="security_agent", challenger="critic_agent",
                challenge=challenge, response=defense,
                verdict=verdict, new_severity=new_sev,
            )
        except Exception:
            return None

    def _init_llm(self):
        try:
            from config.config import OPENAI_API_KEY, OPENAI_BASE_URL
            if OPENAI_API_KEY:
                from openai import OpenAI
                return OpenAI(api_key=OPENAI_API_KEY, base_url=OPENAI_BASE_URL)
        except Exception:
            pass
        return None

    def _executive_summary(self, target, findings, counts, debate_log) -> str:
        total   = len(findings)
        removed = sum(1 for d in debate_log if d.get("verdict") == "remove")
        dg      = sum(1 for d in debate_log if d.get("verdict") == "downgrade")
        s = (f"Audit of {target} identified {total} finding(s): "
             f"{counts['CRITICAL']} critical, {counts['HIGH']} high, "
             f"{counts['MEDIUM']} medium, {counts['LOW']} low.")
        if debate_log:
            s += (f" Multi-agent debate reviewed {len(debate_log)} contested finding(s), "
                  f"removing {removed} likely false positive(s) and downgrading {dg}.")
        return s

    def _recommendations(self, findings: List[Dict], counts: Dict) -> List[str]:
        recs = []
        if counts["CRITICAL"]:
            recs.append(f"Immediately remediate {counts['CRITICAL']} critical finding(s) before deployment.")
        if counts["HIGH"]:
            recs.append(f"Address {counts['HIGH']} high-severity finding(s) within one sprint.")
        seen_cwes = {f.get("cwe","") for f in findings if f.get("cwe")}
        if "CWE-798" in seen_cwes:
            recs.append("Rotate all exposed credentials immediately and audit secret storage practices.")
        if "CWE-78" in seen_cwes or "CWE-95" in seen_cwes:
            recs.append("Implement strict input validation and consider sandboxing untrusted code execution.")
        if "CWE-284" in seen_cwes or "CWE-287" in seen_cwes:
            recs.append("Review access control logic and enforce principle of least privilege.")
        if not recs:
            recs.append("Continue regular security scanning as part of the CI/CD pipeline.")
        return recs
