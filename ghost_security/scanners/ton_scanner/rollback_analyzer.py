class RollbackAnalyzer:
    """Analyzes TON transaction rollback semantics and send mode edge cases"""
    
    def check_send_mode_risk(self, mode):
        """Analyze risks associated with different send modes in TON"""
        risks = []
        if mode & 64:
            risks.append({
                "severity": "MEDIUM",
                "description": "Mode 64 (carry remaining value) can lead to unexpected balance drain if not carefully managed."
            })
        if mode & 128:
            risks.append({
                "severity": "HIGH",
                "description": "Mode 128 (carry all balance) is highly dangerous. It empties the contract balance completely."
            })
        return risks

    def analyze_rollback_failure(self, trace):
        """Check if storage mutation happened despite action phase failure"""
        # Logic to compare state before and after a failed transaction in the trace
        # In TON, storage is committed BEFORE actions. If actions fail, storage is NOT rolled back automatically.
        for tx in trace:
            if tx.get("status") == "failed" and tx.get("storage_changed"):
                return {
                    "type": "ROLLBACK_INCONSISTENCY",
                    "severity": "CRITICAL",
                    "description": "Storage was modified but outbound actions failed. This creates a 'phantom' state."
                }
        return None
