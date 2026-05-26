"""
Ghost Security Platform — Policy-as-Code Engine

Provides YAML-based security policy evaluation to gate deployments
based on scan findings.

Quick start:
    from core.policy import PolicyEngine, PolicyResult

    engine = PolicyEngine()
    engine.load_policies("policies/")
    result = engine.evaluate(findings)
    print(engine.generate_gate_report(result))
"""
from core.policy.policy_engine import (
    Policy,
    PolicyCondition,
    PolicyEngine,
    PolicyResult,
    PolicyRule,
    ViolationDetail,
)

__all__ = [
    "PolicyEngine",
    "PolicyResult",
    "PolicyRule",
    "PolicyCondition",
    "Policy",
    "ViolationDetail",
]
