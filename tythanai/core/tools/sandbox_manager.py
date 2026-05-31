import subprocess
import os

class SandboxManager:
    """Manages Docker containers for safe code execution during audits"""
    
    def __init__(self, image="python:3.10-slim"):
        self.image = image
        
    def run_code(self, code, filename="test.py"):
        """Execute code in a temporary Docker container"""
        # Create temp dir
        tmp_dir = "/tmp/ghost_sandbox"
        os.makedirs(tmp_dir, exist_ok=True)
        file_path = os.path.join(tmp_dir, filename)
        
        with open(file_path, 'w') as f:
            f.write(code)
            
        try:
            # Run docker with limits
            cmd = [
                "docker", "run", "--rm",
                "-v", f"{tmp_dir}:/app",
                "-w", "/app",
                "--network", "none",
                "--memory", "128m",
                "--cpus", "0.5",
                self.image,
                "python", filename
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return {
                "stdout": result.stdout,
                "stderr": result.stderr,
                "exit_code": result.returncode
            }
        except subprocess.TimeoutExpired:
            return {"error": "Execution timed out (potential infinite loop or heavy task)"}
        except Exception as e:
            return {"error": f"Sandbox execution failed: {e}"}
        finally:
            if os.path.exists(file_path):
                os.unlink(file_path)
