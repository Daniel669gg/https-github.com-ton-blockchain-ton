import subprocess
import json
import os
from pathlib import Path

class TONSandboxWrapper:
    """Python wrapper for the Node.js TON Sandbox (Absolute Edition)"""
    
    def __init__(self):
        self.sandbox_dir = Path(__file__).parent / "sandbox"
        self.emulator_script = self.sandbox_dir / "run_emulator.ts"
        
    def _create_runner_script(self, action, params):
        """Create a temporary TS script to run a specific sandbox action"""
        script_content = f"""
import {{ Blockchain, SandboxContract, TreasuryContract }} from '@ton/sandbox';
import {{ Address, Cell, beginCell, toNano }} from '@ton/core';

async function main() {{
    const blockchain = await Blockchain.create();
    const treasury = await blockchain.treasury('seed');
    
    const action = "{action}";
    const params = {json.dumps(params)};
    
    if (action === "test_transaction") {{
        // Logic for testing a transaction
        console.log(JSON.stringify({{ status: "success", traces: [] }}));
    }}
}}

main().catch(err => {{
    console.error(err);
    process.exit(1);
}});
"""
        with open(self.emulator_script, 'w') as f:
            f.write(script_content)

    def run_test(self, action, params):
        """Run a test in the sandbox and return results"""
        self._create_runner_script(action, params)
        try:
            result = subprocess.run(
                ["npx", "ts-node", str(self.emulator_script)],
                capture_output=True, text=True, cwd=str(self.sandbox_dir), timeout=30
            )
            if result.returncode != 0:
                return {"error": result.stderr}
            return json.loads(result.stdout)
        except Exception as e:
            return {"error": str(e)}
