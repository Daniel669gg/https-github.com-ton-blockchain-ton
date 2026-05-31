"""ReAct agent — iterative finding re-evaluation and attack chain construction."""
from __future__ import annotations

import asyncio
import json
import logging
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

from backend.core.confidence import Finding

logger = logging.getLogger("tythanai.react_agent")

# ── Optional dependency: Anthropic SDK ────────────────────────────────────────
try:
    import anthropic as _anthropic_sdk

    _ANTHROPIC_AVAILABLE = True
except ImportError:  # pragma: no cover
    _anthropic_sdk = None  # type: ignore[assignment]
    _ANTHROPIC_AVAILABLE = False
    logger.info("anthropic SDK not installed — falling back to rule-based mode")

# ── Optional dependency: ChromaDB ─────────────────────────────────────────────
try:
    import chromadb as _chromadb

    _CHROMADB_AVAILABLE = True
except ImportError:  # pragma: no cover
    _chromadb = None  # type: ignore[assignment]
    _CHROMADB_AVAILABLE = False
    logger.info("chromadb not installed — agent step embeddings disabled")

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

_MAX_ITERATIONS = 50
_MODEL = "claude-sonnet-4-6"

_SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

# Uncertain confidence range: findings in this band are re-evaluated
_UNCERTAIN_LOW = 0.70
_UNCERTAIN_HIGH = 0.85

# ─────────────────────────────────────────────────────────────────────────────
# Data models
# ─────────────────────────────────────────────────────────────────────────────


class AttackChain(BaseModel):
    """A correlated sequence of findings forming an attack vector."""

    chain_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    finding_ids: List[str] = Field(default_factory=list)
    severity: str = "HIGH"
    narrative: str = ""
    confidence: float = 0.8


class ReactAgentResult(BaseModel):
    """Final result returned by the ReactAgent after its analysis loop."""

    updated_findings: List[Finding] = Field(default_factory=list)
    removed_findings: List[Finding] = Field(default_factory=list)
    attack_chains: List[AttackChain] = Field(default_factory=list)
    narrative: str = ""
    iterations_used: int = 0
    session_id: str = Field(default_factory=lambda: str(uuid.uuid4()))


# ─────────────────────────────────────────────────────────────────────────────
# SQLite persistence helpers
# ─────────────────────────────────────────────────────────────────────────────


def _ensure_db(conn: sqlite3.Connection) -> None:
    """Create required tables if they don't exist."""
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS agent_runs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id  TEXT    NOT NULL,
            timestamp   TEXT    NOT NULL,
            step_number INTEGER NOT NULL,
            reasoning   TEXT    NOT NULL,
            action      TEXT    NOT NULL,
            observation TEXT    NOT NULL
        );

        CREATE TABLE IF NOT EXISTS attack_chains (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id  TEXT    NOT NULL,
            chain_id    TEXT    NOT NULL,
            finding_ids TEXT    NOT NULL,  -- JSON array
            severity    TEXT    NOT NULL,
            narrative   TEXT    NOT NULL
        );
        """
    )
    conn.commit()


def _persist_step(
    conn: sqlite3.Connection,
    session_id: str,
    step: int,
    reasoning: str,
    action: str,
    observation: str,
) -> None:
    conn.execute(
        "INSERT INTO agent_runs (session_id, timestamp, step_number, reasoning, action, observation) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (session_id, datetime.now(tz=timezone.utc).isoformat(), step, reasoning, action, observation),
    )
    conn.commit()


def _persist_chain(conn: sqlite3.Connection, session_id: str, chain: AttackChain) -> None:
    conn.execute(
        "INSERT INTO attack_chains (session_id, chain_id, finding_ids, severity, narrative) "
        "VALUES (?, ?, ?, ?, ?)",
        (
            session_id,
            chain.chain_id,
            json.dumps(chain.finding_ids),
            chain.severity,
            chain.narrative,
        ),
    )
    conn.commit()


# ─────────────────────────────────────────────────────────────────────────────
# Rule-based fallback (no LLM needed)
# ─────────────────────────────────────────────────────────────────────────────


class _RuleBasedFallback:
    """
    Deterministic attack-chain detector and finding re-evaluator.
    Used when no Anthropic API key is available.

    Rules:
    - SQLi finding + no-authentication finding → CRITICAL chain
    - eval/exec finding + no-input-validation finding → CRITICAL chain
    - Any CRITICAL + any HIGH → escalate connected HIGH to CRITICAL
    - Uncertain findings (0.70–0.85) with supporting evidence → keep/raise
    - Uncertain findings with no corroborating context → remove (FP reduction)
    """

    # Pairs of rule-id substrings whose co-occurrence triggers escalation
    _CHAIN_RULES: List[Tuple[str, str, str, str]] = [
        ("SQLI", "NO-AUTH",     "CRITICAL", "SQL injection with missing authentication creates unauthenticated RCE path"),
        ("SQLI", "AUTH-BYPASS", "CRITICAL", "SQL injection combined with authentication bypass enables full data exfiltration"),
        ("EXEC", "NO-VALID",    "CRITICAL", "Dynamic code execution without input validation allows arbitrary code execution"),
        ("EVAL", "NO-VALID",    "CRITICAL", "eval() without input sanitization is exploitable for RCE"),
        ("B64",  "EXEC",        "CRITICAL", "Base64-encoded payload with exec() — classic obfuscated backdoor pattern"),
        ("PATH-TRAV", "WRITE",  "CRITICAL", "Path traversal combined with write access enables arbitrary file overwrite"),
        ("SSRF", "INTERNAL",    "HIGH",     "SSRF with access to internal resources enables lateral movement"),
        ("XSS",  "NO-CSP",      "HIGH",     "XSS without Content Security Policy allows persistent cross-site attacks"),
    ]

    def evaluate(
        self,
        findings: List[Finding],
        source_context: str,
    ) -> Tuple[List[Finding], List[Finding], List[AttackChain], str]:
        """
        Returns: (updated_findings, removed_findings, chains, narrative)
        """
        updated: List[Finding] = []
        removed: List[Finding] = []

        # ── Step 1: Re-evaluate uncertain findings ──────────────────────────
        for f in findings:
            if _UNCERTAIN_LOW <= f.confidence <= _UNCERTAIN_HIGH:
                decision = self._scrutinize(f, findings, source_context)
                if decision == "remove":
                    removed.append(f)
                    logger.debug("FP removed: %s@%s:%d (confidence=%.2f)", f.rule_id, f.file, f.line, f.confidence)
                    continue
                elif decision == "elevate":
                    elevated = f.model_copy(update={"confidence": min(1.0, f.confidence + 0.1)})
                    updated.append(elevated)
                    continue
            updated.append(f)

        # ── Step 2: Detect attack chains ────────────────────────────────────
        chains: List[AttackChain] = []
        rule_ids_upper = {f.fingerprint(): f.rule_id.upper() for f in updated}
        all_rule_ids = " ".join(rule_ids_upper.values())

        for kw_a, kw_b, severity, narrative_template in self._CHAIN_RULES:
            # Check if both keywords appear anywhere in the rule-id set
            if kw_a in all_rule_ids and kw_b in all_rule_ids:
                # Find matching findings
                matching_a = [f for f in updated if kw_a in f.rule_id.upper()]
                matching_b = [f for f in updated if kw_b in f.rule_id.upper()]
                if matching_a and matching_b:
                    chain_finding_ids = (
                        [f.fingerprint() for f in matching_a]
                        + [f.fingerprint() for f in matching_b]
                    )
                    chains.append(AttackChain(
                        finding_ids=chain_finding_ids,
                        severity=severity,
                        narrative=narrative_template,
                        confidence=0.9,
                    ))
                    logger.info("Attack chain detected: %s + %s → %s", kw_a, kw_b, severity)

                    # ── Step 3: Elevate severity in chain ─────────────────
                    if severity == "CRITICAL":
                        updated = self._elevate_in_chain(updated, chain_finding_ids)

        # ── Step 4: Build attack narrative ──────────────────────────────────
        narrative = self._build_narrative(updated, chains)

        return updated, removed, chains, narrative

    def _scrutinize(
        self,
        finding: Finding,
        all_findings: List[Finding],
        context: str,
    ) -> str:
        """Decide whether to keep, elevate, or remove an uncertain finding."""
        rule_upper = finding.rule_id.upper()

        # Check for corroborating evidence from other findings
        related = [
            f for f in all_findings
            if f is not finding and f.file == finding.file
        ]

        # If there are CRITICAL/HIGH findings in the same file, keep this one
        has_supporting = any(
            _SEV_ORDER.get(f.severity, 0) >= _SEV_ORDER.get("HIGH", 0)
            for f in related
        )

        # If context contains test patterns → this may be a FP in test code
        context_lower = context.lower()
        is_test_context = any(
            tok in context_lower
            for tok in ("def test_", "unittest", "pytest", "mock.", "fixture")
        )

        if is_test_context and "TEST" not in rule_upper:
            return "remove"

        if has_supporting:
            return "elevate"

        # No corroborating evidence + confidence near lower bound → remove
        if finding.confidence <= 0.72:
            return "remove"

        return "keep"

    @staticmethod
    def _elevate_in_chain(
        findings: List[Finding],
        chain_fp_ids: List[str],
    ) -> List[Finding]:
        """Elevate severity of findings that are part of a critical attack chain."""
        elevated: List[Finding] = []
        for f in findings:
            if f.fingerprint() in chain_fp_ids and f.severity in ("HIGH", "MEDIUM"):
                new_sev = "CRITICAL" if f.severity == "HIGH" else "HIGH"
                elevated.append(f.model_copy(update={"severity": new_sev}))
                logger.debug("Elevated %s %s→%s via chain", f.rule_id, f.severity, new_sev)
            else:
                elevated.append(f)
        return elevated

    @staticmethod
    def _build_narrative(findings: List[Finding], chains: List[AttackChain]) -> str:
        """Compose a human-readable attack narrative."""
        if not findings:
            return "No significant security findings detected."

        critical = [f for f in findings if f.severity == "CRITICAL"]
        high = [f for f in findings if f.severity == "HIGH"]

        parts: List[str] = ["Most critical attack scenario: "]

        if chains:
            # Pick the chain with highest severity
            top_chain = max(chains, key=lambda c: _SEV_ORDER.get(c.severity, 0))
            parts.append(top_chain.narrative + ".")
        elif critical:
            top = critical[0]
            parts.append(f"{top.description} ({top.rule_id} in {top.file}:{top.line}).")
        elif high:
            top = high[0]
            parts.append(f"{top.description} ({top.rule_id} in {top.file}:{top.line}).")
        else:
            parts.append("Low-severity findings only — no immediate exploitation path identified.")

        if len(chains) > 1:
            parts.append(
                f" Additionally, {len(chains) - 1} other attack chain(s) detected "
                f"across {len(findings)} total findings."
            )
        elif findings:
            parts.append(
                f" Total: {len(findings)} finding(s) across "
                f"{len({f.file for f in findings})} file(s)."
            )

        return "".join(parts)


# ─────────────────────────────────────────────────────────────────────────────
# LLM-backed ReAct loop
# ─────────────────────────────────────────────────────────────────────────────


class _LLMReActLoop:
    """
    Runs the Reason-Act-Observe loop using the Anthropic API.

    Iteration structure:
    1. Reason  — ask Claude to analyze findings and identify attack chains
    2. Act     — choose which findings to re-verify / correlate
    3. Observe — update internal state based on Claude's observations
    """

    _SYSTEM_PROMPT = (
        "You are a security analysis agent performing iterative re-evaluation of "
        "security findings. Your goals:\n"
        "1. Re-evaluate findings with confidence 0.70–0.85 — remove false positives, "
        "   elevate true positives.\n"
        "2. Identify attack chains where multiple findings combine into a more severe risk.\n"
        "3. Build a concise attack narrative.\n\n"
        "You do NOT create new findings — only re-evaluate existing ones.\n\n"
        "Respond ONLY with valid JSON matching this schema:\n"
        "{\n"
        '  "reasoning": "string",\n'
        '  "action": "re_evaluate | form_chain | conclude",\n'
        '  "findings_to_remove": ["fingerprint1", ...],\n'
        '  "findings_to_elevate": [{"fingerprint": "...", "new_severity": "...", "new_confidence": 0.95}],\n'
        '  "attack_chains": [{"finding_fingerprints": [...], "severity": "CRITICAL", "narrative": "..."}],\n'
        '  "narrative": "Most critical attack scenario: ...",\n'
        '  "done": false\n'
        "}"
    )

    def __init__(self, client: Any, max_iterations: int = _MAX_ITERATIONS) -> None:
        self._client = client
        self._max_iterations = max_iterations

    async def run(
        self,
        findings: List[Finding],
        source_context: str,
        session_id: str,
        db_conn: sqlite3.Connection,
    ) -> Tuple[List[Finding], List[Finding], List[AttackChain], str, int]:
        """
        Run the ReAct loop.
        Returns (updated_findings, removed_findings, chains, narrative, iterations_used).
        """
        working_set = {f.fingerprint(): f for f in findings}
        removed: Dict[str, Finding] = {}
        chains: List[AttackChain] = []
        narrative = ""

        # Prepare initial context for the LLM
        findings_json = json.dumps(
            [
                {
                    "fingerprint": fp,
                    "rule_id": f.rule_id,
                    "file": f.file,
                    "line": f.line,
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "description": f.description,
                    "cwe_id": f.cwe_id,
                }
                for fp, f in working_set.items()
            ],
            indent=2,
        )
        user_message = (
            f"Analyze these security findings and re-evaluate them:\n\n"
            f"```json\n{findings_json}\n```\n\n"
            f"Source context:\n```\n{source_context[:2000]}\n```"
        )

        messages: List[Dict[str, Any]] = [{"role": "user", "content": user_message}]

        iterations_used = 0
        for step in range(self._max_iterations):
            iterations_used = step + 1

            try:
                response = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda m=messages: self._client.messages.create(
                        model=_MODEL,
                        max_tokens=2048,
                        system=self._SYSTEM_PROMPT,
                        messages=m,
                    ),
                )
                raw_text = response.content[0].text.strip()
            except Exception as exc:
                logger.error("LLM call failed at step %d: %s", step, exc)
                break

            # Parse JSON response
            try:
                parsed = self._extract_json(raw_text)
            except (json.JSONDecodeError, ValueError) as exc:
                logger.warning("JSON parse error at step %d: %s", step, exc)
                parsed = {"done": True}

            reasoning = parsed.get("reasoning", "")
            action = parsed.get("action", "conclude")
            observation = f"Step {step}: action={action}"

            # Persist to SQLite
            _persist_step(db_conn, session_id, step, reasoning, action, observation)

            # Apply removals
            for fp in parsed.get("findings_to_remove", []):
                if fp in working_set:
                    removed[fp] = working_set.pop(fp)

            # Apply elevations
            for elevation in parsed.get("findings_to_elevate", []):
                fp = elevation.get("fingerprint")
                if fp and fp in working_set:
                    f = working_set[fp]
                    updates: Dict[str, Any] = {}
                    if "new_severity" in elevation:
                        updates["severity"] = elevation["new_severity"]
                    if "new_confidence" in elevation:
                        updates["confidence"] = float(elevation["new_confidence"])
                    if updates:
                        working_set[fp] = f.model_copy(update=updates)

            # Collect chains
            for chain_data in parsed.get("attack_chains", []):
                chain = AttackChain(
                    finding_ids=chain_data.get("finding_fingerprints", []),
                    severity=chain_data.get("severity", "HIGH"),
                    narrative=chain_data.get("narrative", ""),
                    confidence=0.9,
                )
                chains.append(chain)
                _persist_chain(db_conn, session_id, chain)

            if parsed.get("narrative"):
                narrative = parsed["narrative"]

            # Continue loop with assistant turn
            messages.append({"role": "assistant", "content": raw_text})

            if parsed.get("done", False) or action == "conclude":
                break

            # Ask for next step
            messages.append({
                "role": "user",
                "content": (
                    f"Continue analysis. {len(working_set)} findings remain. "
                    "If analysis is complete, set done=true."
                ),
            })

        return (
            list(working_set.values()),
            list(removed.values()),
            chains,
            narrative or "Analysis complete.",
            iterations_used,
        )

    @staticmethod
    def _extract_json(text: str) -> Dict[str, Any]:
        """Extract JSON object from LLM response text (handles markdown fences)."""
        # Strip markdown code fences if present
        if "```json" in text:
            start = text.index("```json") + 7
            end = text.index("```", start)
            text = text[start:end].strip()
        elif "```" in text:
            start = text.index("```") + 3
            end = text.index("```", start)
            text = text[start:end].strip()

        # Find first { ... } block
        brace_start = text.find("{")
        brace_end = text.rfind("}")
        if brace_start != -1 and brace_end != -1:
            text = text[brace_start : brace_end + 1]

        return json.loads(text)


# ─────────────────────────────────────────────────────────────────────────────
# ChromaDB integration
# ─────────────────────────────────────────────────────────────────────────────


class _ChromaStore:
    """Stores agent step embeddings in ChromaDB for cross-session knowledge reuse."""

    def __init__(self) -> None:
        self._collection: Optional[Any] = None
        if _CHROMADB_AVAILABLE:
            try:
                client = _chromadb.Client()
                self._collection = client.get_or_create_collection("agent_steps")
                logger.info("ChromaDB collection 'agent_steps' initialized")
            except Exception as exc:
                logger.warning("ChromaDB init failed: %s", exc)

    def store_step(self, session_id: str, step: int, text: str) -> None:
        if self._collection is None:
            return
        try:
            self._collection.add(
                documents=[text],
                metadatas=[{"session_id": session_id, "step": step}],
                ids=[f"{session_id}_{step}"],
            )
        except Exception as exc:
            logger.debug("ChromaDB store failed: %s", exc)

    def query_similar(self, text: str, n_results: int = 3) -> List[str]:
        if self._collection is None:
            return []
        try:
            results = self._collection.query(query_texts=[text], n_results=n_results)
            return results.get("documents", [[]])[0]
        except Exception as exc:
            logger.debug("ChromaDB query failed: %s", exc)
            return []


# ─────────────────────────────────────────────────────────────────────────────
# Main agent class
# ─────────────────────────────────────────────────────────────────────────────


class ReactAgent:
    """
    ReAct (Reason-Act-Observe) security analysis agent.

    Iteratively re-evaluates findings to:
    - Remove false positives (confidence 0.70–0.85 scrutiny)
    - Detect attack chains (severity escalation for correlated findings)
    - Build an attack narrative

    Modes:
    - LLM mode (api_key provided): uses claude-sonnet-4-6 via Anthropic SDK
    - Fallback mode (no api_key):  deterministic rule-based analysis

    SQLite persistence:
    - agent_runs table: per-step reasoning/action/observation log
    - attack_chains table: detected chains with finding references
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        db_path: str = "data/agent.db",
    ) -> None:
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self._db_path = db_path
        self._chroma = _ChromaStore()

        # Initialize LLM client if possible
        self._llm_client: Optional[Any] = None
        if self._api_key and _ANTHROPIC_AVAILABLE:
            try:
                self._llm_client = _anthropic_sdk.Anthropic(api_key=self._api_key)
                logger.info("ReactAgent initialized in LLM mode (model=%s)", _MODEL)
            except Exception as exc:
                logger.warning("Failed to init Anthropic client: %s — using fallback", exc)
        else:
            mode = "fallback (no API key)" if not self._api_key else "fallback (anthropic SDK unavailable)"
            logger.info("ReactAgent initialized in %s mode", mode)

        self._fallback = _RuleBasedFallback()

    def _get_db_conn(self) -> sqlite3.Connection:
        """Open (and initialize) the SQLite database."""
        db_dir = os.path.dirname(self._db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)
        conn = sqlite3.connect(self._db_path)
        _ensure_db(conn)
        return conn

    async def run(
        self,
        findings: List[Finding],
        source_context: str = "",
    ) -> ReactAgentResult:
        """
        Run the ReAct loop on *findings*.

        Returns ReactAgentResult with:
        - updated_findings: refined set of findings
        - removed_findings: findings determined to be false positives
        - attack_chains: correlated finding chains
        - narrative: human-readable attack description
        - iterations_used: number of ReAct iterations consumed
        - session_id: unique ID for this analysis run
        """
        session_id = str(uuid.uuid4())
        conn = self._get_db_conn()

        try:
            if self._llm_client is not None:
                loop = _LLMReActLoop(self._llm_client, max_iterations=_MAX_ITERATIONS)
                updated, removed, chains, narrative, iterations = await loop.run(
                    findings=findings,
                    source_context=source_context,
                    session_id=session_id,
                    db_conn=conn,
                )
            else:
                updated, removed, chains, narrative = self._fallback.evaluate(
                    findings, source_context
                )
                iterations = 1

                # Persist the single fallback step
                _persist_step(
                    conn,
                    session_id,
                    step=0,
                    reasoning="Rule-based fallback analysis",
                    action="evaluate_all",
                    observation=(
                        f"removed={len(removed)} findings, "
                        f"chains={len(chains)}, "
                        f"narrative={narrative[:80]}"
                    ),
                )
                for chain in chains:
                    _persist_chain(conn, session_id, chain)

            # Store step summary in ChromaDB
            step_text = (
                f"session={session_id} findings={len(updated)} "
                f"removed={len(removed)} chains={len(chains)} "
                f"narrative={narrative[:200]}"
            )
            self._chroma.store_step(session_id, 0, step_text)

        finally:
            conn.close()

        return ReactAgentResult(
            updated_findings=updated,
            removed_findings=removed,
            attack_chains=chains,
            narrative=narrative,
            iterations_used=iterations,
            session_id=session_id,
        )
