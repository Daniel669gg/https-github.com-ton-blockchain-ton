"""
Ghost Security Platform — Agent Loop
Real implementation of observe → reason → act → verify → retry cycle.
No placeholders. No fake AI. Real LLM calls with real tool execution.
"""
import json
import time
import traceback
from typing import Any, Dict, List, Optional
from pathlib import Path
from openai import OpenAI

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from config.config import (
    OPENAI_API_KEY, OPENAI_BASE_URL, LLM_MODEL,
    MAX_ITERATIONS, MAX_RETRIES, TOOL_TIMEOUT
)
from core.tools.tool_registry import ToolRegistry, ToolResult
from core.memory.memory_manager import MemoryManager
from core.verifier.verifier import AgentVerifier


SYSTEM_PROMPT = """You are Ghost Security — an autonomous AI security auditor for white-hat research and bug bounty programs.
Your mission: perform thorough, evidence-based security audits to help developers find and responsibly disclose vulnerabilities.

METHODOLOGY: Observe → Reason → Act → Verify → Report

CAPABILITIES:
- Analyze source code for security vulnerabilities: injection flaws, logic errors, weak cryptography, access-control issues.
- Review smart contracts (TON / FunC / Tact) for common vulnerability patterns.
- Use available tools to gather evidence before reporting any finding.

TOOLS:
- AST scanner, Semgrep, secret detector, sandbox, Git analyzer, file reader.
- NEVER report a finding without a concrete code reference or tool output.
- Use `run_in_sandbox` to safely verify logic issues.
- Use `git_deep_analyze` to review commit history for security-relevant changes.

OUTPUT RULES:
- Use `add_finding` for each confirmed, evidence-backed finding.
- Use `finish_task` when the audit is fully complete.
- Each finding must include: file, line, CWE, severity, evidence, and remediation advice.

Be thorough, precise, and professional. Confirm before reporting.
"""


class AgentLoop:
    """
    Real autonomous agent loop.
    Connects LLM reasoning with real tool execution.
    """

    def __init__(self, tool_registry: ToolRegistry, memory: MemoryManager):
        self.tools = tool_registry
        self.memory = memory
        self.verifier = AgentVerifier()
        self.llm = OpenAI(api_key=OPENAI_API_KEY, base_url=OPENAI_BASE_URL)
        self.iteration = 0
        self.findings: List[Dict] = []
        self.task_complete = False
        self.final_summary: Optional[Dict] = None
        self._callbacks: List = []

    def add_callback(self, cb):
        """Add progress callback (for streaming to UI)."""
        self._callbacks.append(cb)

    def _notify(self, event_type: str, data: Any):
        """Notify all callbacks of an event."""
        for cb in self._callbacks:
            try:
                cb(event_type, data)
            except Exception:
                pass

    def _build_tool_schemas(self) -> List[Dict]:
        """Build OpenAI function calling schemas from tool registry."""
        schemas = []
        for tool_info in self.tools.list_tools():
            properties = {}
            required = []
            for param_name, param_info in tool_info["parameters"].items():
                prop = {"type": param_info.get("type", "string")}
                if "description" in param_info:
                    prop["description"] = param_info["description"]
                if "default" in param_info:
                    prop["default"] = param_info["default"]
                properties[param_name] = prop
                if not param_info.get("optional", False) and "default" not in param_info:
                    required.append(param_name)

            schemas.append({
                "type": "function",
                "function": {
                    "name": tool_info["name"],
                    "description": tool_info["description"],
                    "parameters": {
                        "type": "object",
                        "properties": properties,
                        "required": required
                    }
                }
            })

        # Add finish_task tool
        schemas.append({
            "type": "function",
            "function": {
                "name": "finish_task",
                "description": "Call this when the security audit is complete to submit final findings",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "summary": {"type": "string", "description": "Executive summary of findings"},
                        "findings": {
                            "type": "array",
                            "description": "List of confirmed security findings",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "type": {"type": "string"},
                                    "severity": {"type": "string"},
                                    "file": {"type": "string"},
                                    "line": {"type": "integer"},
                                    "description": {"type": "string"},
                                    "evidence": {"type": "string"},
                                    "recommendation": {"type": "string"}
                                }
                            }
                        },
                        "risk_score": {"type": "integer", "description": "Overall risk score 0-100"},
                        "recommendations": {"type": "array", "items": {"type": "string"}}
                    },
                    "required": ["summary", "findings", "risk_score"]
                }
            }
        })

        # Add add_finding tool
        schemas.append({
            "type": "function",
            "function": {
                "name": "add_finding",
                "description": "Add a confirmed security finding during analysis",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "type": {"type": "string", "description": "Vulnerability type"},
                        "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]},
                        "file": {"type": "string"},
                        "line": {"type": "integer"},
                        "description": {"type": "string"},
                        "evidence": {"type": "string", "description": "Actual code/data proving the issue"},
                        "recommendation": {"type": "string"}
                    },
                    "required": ["type", "severity", "description", "evidence"]
                }
            }
        })

        return schemas

    def run(self, task: str, context: Optional[str] = None, max_iterations: int = MAX_ITERATIONS) -> Dict:
        """
        Run the agent loop for a given security task.
        Returns structured results with real findings.
        """
        self.iteration = 0
        self.findings = []
        self.task_complete = False
        self.final_summary = None

        # Build initial messages
        messages = [{"role": "system", "content": SYSTEM_PROMPT}]

        # Add relevant memory context
        similar = self.memory.search_similar(task, n_results=3)
        if similar:
            context_from_memory = "\n".join([s["document"] for s in similar])
            messages.append({
                "role": "system",
                "content": f"Relevant past findings for context:\n{context_from_memory}"
            })

        # Add session context
        session_ctx = self.memory.get_session_context(max_messages=5)
        messages.extend(session_ctx)

        # Add the task
        task_message = task
        if context:
            task_message = f"{task}\n\nAdditional context:\n{context}"
        messages.append({"role": "user", "content": task_message})

        self.memory.add_to_session("user", task_message)
        self._notify("task_start", {"task": task, "max_iterations": max_iterations})

        tool_schemas = self._build_tool_schemas()

        # Main agent loop
        while self.iteration < max_iterations and not self.task_complete:
            self.iteration += 1
            self._notify("iteration", {"iteration": self.iteration, "max": max_iterations})

            retry_count = 0
            llm_response = None

            # LLM call with retries
            while retry_count < MAX_RETRIES:
                try:
                    response = self.llm.chat.completions.create(
                        model=LLM_MODEL,
                        messages=messages,
                        tools=tool_schemas,
                        tool_choice="auto",
                        temperature=0.1,
                        max_tokens=4000
                    )
                    llm_response = response
                    break
                except Exception as e:
                    retry_count += 1
                    self._notify("llm_error", {"error": str(e), "retry": retry_count})
                    if retry_count >= MAX_RETRIES:
                        return self._build_error_result(f"LLM failed after {MAX_RETRIES} retries: {e}")
                    time.sleep(2 ** retry_count)

            choice = llm_response.choices[0]
            msg = choice.message

            # Add assistant message to history
            messages.append(msg.model_dump(exclude_none=True))

            # Process text response
            if msg.content:
                self._notify("reasoning", {"text": msg.content})
                self.memory.add_to_session("assistant", msg.content)

            # No tool calls — agent is done thinking
            if not msg.tool_calls:
                if choice.finish_reason == "stop":
                    # Agent finished without calling finish_task
                    self._notify("agent_done", {"reason": "natural_stop"})
                    break
                continue

            # Execute tool calls
            for tool_call in msg.tool_calls:
                tool_name = tool_call.function.name
                try:
                    tool_args = json.loads(tool_call.function.arguments)
                except json.JSONDecodeError:
                    tool_args = {}

                self._notify("tool_call", {"tool": tool_name, "args": tool_args})

                # Handle special internal tools
                if tool_name == "finish_task":
                    self.task_complete = True
                    self.final_summary = tool_args
                    # Merge any findings added via add_finding
                    if "findings" in tool_args:
                        for f in tool_args["findings"]:
                            if f not in self.findings:
                                self.findings.append(f)
                    tool_result_content = json.dumps({"status": "task_completed"})
                    self._notify("task_complete", tool_args)

                elif tool_name == "add_finding":
                    self.findings.append(tool_args)
                    self.memory.add_finding(tool_args)
                    tool_result_content = json.dumps({"status": "finding_added", "id": len(self.findings)})
                    self._notify("finding_added", tool_args)

                else:
                    # Execute real tool
                    result = self.tools.execute(tool_name, **tool_args)
                    tool_result_content = json.dumps(result.to_dict())
                    self._notify("tool_result", {
                        "tool": tool_name,
                        "success": result.success,
                        "duration": result.duration
                    })

                # Add tool result to messages
                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": tool_result_content
                })

            if self.task_complete:
                break

        return self._build_result()

    def _build_result(self) -> Dict:
        """Build final structured result."""
        # Self-Verification step (Absolute Edition)
        if self.findings:
            self._notify("verifying", {"count": len(self.findings)})
            # Verify findings list to reduce false positives
            self.findings = self.verifier.verify_findings("Verify security audit findings", self.findings)

        if self.final_summary:
            return {
                "status": "completed",
                "iterations": self.iteration,
                "findings": self.findings,
                "summary": self.final_summary.get("summary", ""),
                "risk_score": self.final_summary.get("risk_score", 0),
                "recommendations": self.final_summary.get("recommendations", []),
                "finding_count": len(self.findings),
                "critical_count": sum(1 for f in self.findings if f.get("severity") == "CRITICAL"),
                "high_count": sum(1 for f in self.findings if f.get("severity") == "HIGH"),
                "medium_count": sum(1 for f in self.findings if f.get("severity") == "MEDIUM"),
                "low_count": sum(1 for f in self.findings if f.get("severity") == "LOW"),
            }
        return {
            "status": "completed_no_summary",
            "iterations": self.iteration,
            "findings": self.findings,
            "summary": "Analysis completed. No critical findings summary provided.",
            "risk_score": self._estimate_risk_score(),
            "finding_count": len(self.findings)
        }

    def _build_error_result(self, error: str) -> Dict:
        return {
            "status": "error",
            "error": error,
            "iterations": self.iteration,
            "findings": self.findings,
            "finding_count": len(self.findings)
        }

    def _estimate_risk_score(self) -> int:
        """Estimate risk score from findings."""
        score = 0
        weights = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3, "INFO": 1}
        for f in self.findings:
            score += weights.get(f.get("severity", "INFO"), 1)
        return min(score, 100)
