"""
backend/agents/base.py — Shared agent protocol, context/result types, and registry.

Design principles:
- Protocol-based (structural typing): existing agents don't need to subclass anything.
- Non-breaking: all three existing agent generations keep working as-is.
- AgentRegistry is a lightweight dispatch table; agents are registered lazily.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Shared data classes
# ---------------------------------------------------------------------------

@dataclass
class AgentContext:
    """Input context passed to every agent."""
    target: str
    findings: List[Dict[str, Any]] = field(default_factory=list)
    options: Dict[str, Any] = field(default_factory=dict)
    session_id: Optional[str] = None


@dataclass
class AgentResult:
    """Normalized output returned by every agent."""
    agent_name: str
    success: bool
    output: Any
    errors: List[str] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Protocol (structural interface — no forced subclassing)
# ---------------------------------------------------------------------------

@runtime_checkable
class BaseAgent(Protocol):
    """
    Structural protocol satisfied by any agent that exposes an async ``run``
    method accepting an :class:`AgentContext` and returning an
    :class:`AgentResult`.

    Existing agents (SecurityAgent, PlannerAgent, …) do NOT need to change —
    the registry wraps them via :class:`AgentAdapter` if their signature
    differs from the protocol.
    """

    async def run(self, context: AgentContext) -> AgentResult:
        ...


# ---------------------------------------------------------------------------
# Adapter — wraps legacy agents that don't follow the new protocol
# ---------------------------------------------------------------------------

class AgentAdapter:
    """Wraps a legacy agent so it can be stored in :class:`AgentRegistry`."""

    def __init__(self, name: str, agent: Any) -> None:
        self._name = name
        self._agent = agent

    async def run(self, context: AgentContext) -> AgentResult:
        """Dispatch to the legacy agent's native method."""
        agent = self._agent
        errors: List[str] = []
        output: Any = None
        findings: List[Dict[str, Any]] = []

        try:
            # Generation 3 — ReactAgent: async run(findings, source_context)
            if hasattr(agent, "run") and callable(agent.run):
                import inspect
                sig = inspect.signature(agent.run)
                params = list(sig.parameters.keys())

                if "findings" in params:
                    # ReactAgent / reasoning agents
                    result = await agent.run(
                        findings=context.findings,
                        source_context=context.options.get("source_context", ""),
                    )
                    output = result
                    if hasattr(result, "findings"):
                        findings = result.findings or []
                elif "context" in params:
                    result = await agent.run(context)
                    output = result
                else:
                    result = await agent.run(context.target)
                    output = result

            # Generation 1 — SecurityAgent: async scan(output_dict)
            elif hasattr(agent, "scan") and callable(agent.scan):
                result = await agent.scan({
                    "target": context.target,
                    "path": context.target,
                    **context.options,
                })
                output = result
                findings = result.get("findings", []) if isinstance(result, dict) else []

            # Generation 1 — PlannerAgent / others with sync methods
            elif hasattr(agent, "plan") and callable(agent.plan):
                result = agent.plan(context.target, context.options.get("audit_type", "full"))
                output = result
            else:
                errors.append(f"Agent {self._name!r} has no compatible run/scan/plan method")

        except Exception as exc:
            logger.warning("Agent %r raised: %s", self._name, exc)
            errors.append(str(exc))

        return AgentResult(
            agent_name=self._name,
            success=not errors,
            output=output,
            errors=errors,
            findings=findings,
        )


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

class AgentRegistry:
    """
    Lightweight agent registry.

    Agents are registered by name.  Any object with a compatible ``run``
    method (matching :class:`BaseAgent` protocol) is stored directly; others
    are wrapped in :class:`AgentAdapter`.
    """

    def __init__(self) -> None:
        self._agents: Dict[str, Any] = {}

    def register(self, name: str, agent: Any) -> None:
        """Register *agent* under *name*.  Wraps non-protocol agents automatically."""
        if isinstance(agent, BaseAgent):
            self._agents[name] = agent
        else:
            self._agents[name] = AgentAdapter(name, agent)
        logger.debug("AgentRegistry: registered %r", name)

    def get(self, name: str) -> Optional[Any]:
        """Return the registered agent (or None if not found)."""
        return self._agents.get(name)

    def list_agents(self) -> List[str]:
        """Return sorted list of registered agent names."""
        return sorted(self._agents.keys())

    def __contains__(self, name: str) -> bool:
        return name in self._agents


# ---------------------------------------------------------------------------
# Default registry instance — shared across the application
# ---------------------------------------------------------------------------

AGENT_REGISTRY = AgentRegistry()


def _bootstrap_registry() -> None:
    """Lazily register all known agents into AGENT_REGISTRY."""
    import sys
    from pathlib import Path
    _root = Path(__file__).parent.parent.parent
    if str(_root) not in sys.path:
        sys.path.insert(0, str(_root))

    _candidates = [
        ("security_agent",  "agents.security_agent",   "SecurityAgent"),
        ("planner_agent",   "agents.planner_agent",    "PlannerAgent"),
        ("critic_agent",    "agents.critic_agent",     "CriticAgent"),
        ("orchestrator",    "agents.orchestrator",     "MultiAgentOrchestrator"),
        ("rule_generator",  "backend.agents.rule_generator", "RuleGenerator"),
    ]
    for reg_name, module_path, class_name in _candidates:
        try:
            mod = __import__(module_path, fromlist=[class_name])
            cls = getattr(mod, class_name)
            AGENT_REGISTRY.register(reg_name, cls())
        except Exception as exc:
            logger.debug("AgentRegistry: could not load %r: %s", reg_name, exc)


def get_registry() -> AgentRegistry:
    """Return the bootstrapped default registry."""
    if not AGENT_REGISTRY.list_agents():
        _bootstrap_registry()
    return AGENT_REGISTRY
