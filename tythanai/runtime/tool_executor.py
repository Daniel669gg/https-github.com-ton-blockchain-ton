"""
TythanAI Platform — Tool Executor
Safe subprocess execution. Never uses shell=True.
"""
import subprocess
import shlex
from typing import Dict, List, Union


class ToolExecutor:
    """
    Sandboxed tool execution layer.
    Uses shlex.split() + shell=False to prevent command injection.
    """
    DEFAULT_TIMEOUT = 30

    def run(self, command: Union[str, List[str]], timeout: int = DEFAULT_TIMEOUT) -> Dict:
        args = shlex.split(command) if isinstance(command, str) else list(command)
        try:
            result = subprocess.run(
                args, shell=False,
                capture_output=True, text=True, timeout=timeout,
            )
            return {"stdout": result.stdout, "stderr": result.stderr,
                    "returncode": result.returncode, "success": result.returncode == 0}
        except FileNotFoundError:
            return {"stdout": "", "stderr": f"Command not found: {args[0]}", "returncode": 127, "success": False}
        except subprocess.TimeoutExpired:
            return {"stdout": "", "stderr": f"Timed out after {timeout}s", "returncode": -1, "success": False}
        except Exception as e:
            return {"stdout": "", "stderr": str(e), "returncode": -1, "success": False}
