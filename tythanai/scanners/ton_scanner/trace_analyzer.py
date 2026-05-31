class TraceAnalyzer:
    """Extracts and analyzes TON transaction traces for invariant violations"""
    
    def __init__(self):
        self.invariants = [
            {"name": "non_negative_balance", "check": lambda state: state.get("balance", 0) >= 0},
            {"name": "valid_plugin_map", "check": lambda state: "plugins" in state}
        ]

    def process_trace(self, trace_data):
        """Process a raw trace from the sandbox and check for violations"""
        violations = []
        for step in trace_data:
            state_after = step.get("state_after", {})
            for inv in self.invariants:
                if not inv["check"](state_after):
                    violations.append({
                        "invariant": inv["name"],
                        "step": step.get("id"),
                        "severity": "CRITICAL"
                    })
        return violations

    def visualize_trace(self, trace_data):
        """Generate a simplified text-based visualization of the transaction chain"""
        viz = []
        for step in trace_data:
            viz.append(f"[{step['id']}] {step['from']} -> {step['to']} ({step['value']} nanoTON) | Status: {step['status']}")
        return "\n".join(viz)
