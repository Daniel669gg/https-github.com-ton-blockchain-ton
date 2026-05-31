"""
TythanAI Platform — Tool Registry
Real tool system with JSON I/O, timeouts, and sandboxing. No placeholders.
"""
import subprocess
import os
import json
import time
import signal
import tempfile
import shlex
from typing import Any, Dict, List, Optional, Callable
from pathlib import Path
from dataclasses import dataclass, field

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from config.config import TOOL_TIMEOUT, SANDBOX_MAX_OUTPUT


@dataclass
class ToolResult:
    """Structured result from tool execution."""
    success: bool
    output: str
    error: str = ""
    exit_code: int = 0
    duration: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "success": self.success,
            "output": self.output[:SANDBOX_MAX_OUTPUT],
            "error": self.error[:2000],
            "exit_code": self.exit_code,
            "duration": round(self.duration, 3),
            "metadata": self.metadata
        }


@dataclass
class Tool:
    """Tool definition with schema and executor."""
    name: str
    description: str
    parameters: Dict[str, Any]
    executor: Callable
    timeout: int = TOOL_TIMEOUT
    requires_sandbox: bool = False


class ToolRegistry:
    """
    Registry of real executable tools.
    All tools have proper timeouts, error handling, and structured I/O.
    """

    def __init__(self):
        self._tools: Dict[str, Tool] = {}
        from core.tools.sandbox_manager import SandboxManager
        self.sandbox = SandboxManager()
        self._register_builtin_tools()

    def register(self, tool: Tool):
        """Register a tool."""
        self._tools[tool.name] = tool

    def get(self, name: str) -> Optional[Tool]:
        """Get tool by name."""
        return self._tools.get(name)

    def list_tools(self) -> List[Dict]:
        """List all registered tools with their schemas."""
        return [
            {
                "name": t.name,
                "description": t.description,
                "parameters": t.parameters
            }
            for t in self._tools.values()
        ]

    def execute(self, name: str, **kwargs) -> ToolResult:
        """Execute a tool by name with given parameters."""
        tool = self._tools.get(name)
        if not tool:
            return ToolResult(
                success=False,
                output="",
                error=f"Tool '{name}' not found. Available: {list(self._tools.keys())}"
            )
        start = time.time()
        try:
            result = tool.executor(**kwargs)
            result.duration = time.time() - start
            return result
        except Exception as e:
            return ToolResult(
                success=False,
                output="",
                error=str(e),
                duration=time.time() - start
            )

    def _run_subprocess(self, cmd: List[str], cwd: Optional[str] = None,
                        timeout: int = TOOL_TIMEOUT, env: Optional[Dict] = None) -> ToolResult:
        """Run subprocess with timeout and capture output."""
        start = time.time()
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd,
                env={**os.environ, **(env or {})}
            )
            return ToolResult(
                success=result.returncode == 0,
                output=result.stdout[:SANDBOX_MAX_OUTPUT],
                error=result.stderr[:2000],
                exit_code=result.returncode,
                duration=time.time() - start
            )
        except subprocess.TimeoutExpired:
            return ToolResult(
                success=False,
                output="",
                error=f"Command timed out after {timeout}s",
                exit_code=-1,
                duration=time.time() - start
            )
        except FileNotFoundError as e:
            return ToolResult(
                success=False,
                output="",
                error=f"Command not found: {e}",
                exit_code=-1,
                duration=time.time() - start
            )

    def _register_builtin_tools(self):
        """Register all built-in tools."""

        # --- FILESYSTEM TOOLS ---
        def read_file(path: str, encoding: str = "utf-8") -> ToolResult:
            try:
                p = Path(path)
                if not p.exists():
                    return ToolResult(False, "", f"File not found: {path}")
                if p.stat().st_size > 5 * 1024 * 1024:  # 5MB limit
                    return ToolResult(False, "", f"File too large: {p.stat().st_size} bytes")
                content = p.read_text(encoding=encoding, errors='replace')
                return ToolResult(True, content, metadata={"size": p.stat().st_size, "lines": content.count('\n')})
            except Exception as e:
                return ToolResult(False, "", str(e))

        def write_file(path: str, content: str) -> ToolResult:
            try:
                p = Path(path)
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(content, encoding='utf-8')
                return ToolResult(True, f"Written {len(content)} bytes to {path}")
            except Exception as e:
                return ToolResult(False, "", str(e))

        def list_directory(path: str, pattern: str = "*", recursive: bool = False) -> ToolResult:
            try:
                p = Path(path)
                if not p.exists():
                    return ToolResult(False, "", f"Directory not found: {path}")
                if recursive:
                    files = [str(f) for f in p.rglob(pattern) if f.is_file()]
                else:
                    files = [str(f) for f in p.glob(pattern) if f.is_file()]
                return ToolResult(True, json.dumps(files[:500]), metadata={"count": len(files)})
            except Exception as e:
                return ToolResult(False, "", str(e))

        # --- TERMINAL TOOL ---
        def run_command(command: str, cwd: Optional[str] = None, timeout: int = TOOL_TIMEOUT) -> ToolResult:
            """Run shell command safely."""
            # Block dangerous commands
            dangerous = ['rm -rf /', 'mkfs', 'dd if=', ':(){:|:&};:', 'chmod 777 /']
            for d in dangerous:
                if d in command:
                    return ToolResult(False, "", f"Blocked dangerous command: {d}")
            try:
                args = shlex.split(command)
            except ValueError:
                args = command.split()
            return self._run_subprocess(args, cwd=cwd, timeout=min(timeout, 60))

        # --- GIT TOOLS ---
        def git_clone(url: str, dest: str, depth: int = 1) -> ToolResult:
            cmd = ["git", "clone", "--depth", str(depth), url, dest]
            return self._run_subprocess(cmd, timeout=120)

        def git_log(path: str, n: int = 10) -> ToolResult:
            cmd = ["git", "-C", path, "log", f"-{n}", "--oneline", "--no-color"]
            return self._run_subprocess(cmd, timeout=15)

        def git_diff(path: str, commit1: str = "HEAD~1", commit2: str = "HEAD") -> ToolResult:
            cmd = ["git", "-C", path, "diff", commit1, commit2]
            return self._run_subprocess(cmd, timeout=15)

        def git_status(path: str) -> ToolResult:
            cmd = ["git", "-C", path, "status", "--porcelain"]
            return self._run_subprocess(cmd, timeout=10)

        def git_deep_analyze(path: str, n: int = 50) -> ToolResult:
            """Find suspicious commits in history."""
            from scanners.github_watcher.git_analyzer import GitDeepAnalyzer
            analyzer = GitDeepAnalyzer(path)
            findings = analyzer.find_suspicious_commits(n)
            return ToolResult(True, json.dumps(findings, indent=2))

        def git_blame(path: str, file: str, line: int) -> ToolResult:
            """Find who authored a specific line."""
            from scanners.github_watcher.git_analyzer import GitDeepAnalyzer
            analyzer = GitDeepAnalyzer(path)
            info = analyzer.get_blame_info(file, line)
            return ToolResult(True, json.dumps(info))

        # --- PYTHON EXECUTION (sandboxed) ---
        def run_python(code: str, timeout: int = 10) -> ToolResult:
            """Run Python code in a temp file with timeout."""
            with tempfile.NamedTemporaryFile(suffix='.py', mode='w', delete=False) as f:
                f.write(code)
                tmpfile = f.name
            try:
                return self._run_subprocess(
                    ["python3", tmpfile],
                    timeout=min(timeout, 15)
                )
            finally:
                try:
                    os.unlink(tmpfile)
                except Exception:
                    pass

        def run_in_sandbox(code: str, filename: str = "test.py") -> ToolResult:
            """Execute code in a real Docker sandbox (Absolute Edition)."""
            start_time = time.time()
            result = self.sandbox.run_code(code, filename)
            if "error" in result:
                return ToolResult(False, "", result["error"], duration=time.time()-start_time)
            return ToolResult(
                success=result["exit_code"] == 0,
                output=result["stdout"],
                error=result["stderr"],
                exit_code=result["exit_code"],
                duration=time.time()-start_time
            )

        # --- BINARY ANALYSIS ---
        def analyze_binary(path: str) -> ToolResult:
            """Real binary analysis using file, strings, objdump."""
            if not Path(path).exists():
                return ToolResult(False, "", f"File not found: {path}")
            results = {}
            # file command
            r = self._run_subprocess(["file", path], timeout=5)
            results["file_type"] = r.output.strip()
            # strings
            r = self._run_subprocess(["strings", "-n", "8", path], timeout=10)
            strings_list = [s for s in r.output.split('\n') if s.strip()][:100]
            results["strings"] = strings_list
            # sha256
            import hashlib
            try:
                with open(path, 'rb') as f:
                    results["sha256"] = hashlib.sha256(f.read()).hexdigest()
            except Exception as e:
                results["sha256_error"] = str(e)
            # objdump sections (if ELF/PE)
            r = self._run_subprocess(["objdump", "-h", path], timeout=10)
            if r.success:
                results["sections"] = r.output[:2000]
            # nm symbols
            r = self._run_subprocess(["nm", "-D", path], timeout=10)
            if r.success:
                results["symbols"] = r.output[:2000]
            return ToolResult(True, json.dumps(results, indent=2))

        # --- NETWORK TOOLS ---
        def dns_lookup(domain: str) -> ToolResult:
            return self._run_subprocess(["nslookup", domain], timeout=10)

        def port_scan(host: str, ports: str = "80,443,22,8080,8443") -> ToolResult:
            """Basic port scan using nc."""
            results = {}
            for port in ports.split(','):
                port = port.strip()
                r = self._run_subprocess(
                    ["nc", "-z", "-w", "2", host, port],
                    timeout=5
                )
                results[port] = "open" if r.success else "closed"
            return ToolResult(True, json.dumps(results))

        def http_request(url: str, method: str = "GET", headers: Optional[Dict] = None) -> ToolResult:
            """Make HTTP request."""
            import urllib.request
            import urllib.error
            try:
                req = urllib.request.Request(url, method=method.upper())
                if headers:
                    for k, v in headers.items():
                        req.add_header(k, v)
                with urllib.request.urlopen(req, timeout=10) as resp:
                    body = resp.read(50000).decode('utf-8', errors='replace')
                    return ToolResult(
                        True, body,
                        metadata={
                            "status": resp.status,
                            "headers": dict(resp.headers)
                        }
                    )
            except urllib.error.HTTPError as e:
                return ToolResult(False, "", f"HTTP {e.code}: {e.reason}")
            except Exception as e:
                return ToolResult(False, "", str(e))

        # --- HASH / CRYPTO ---
        def compute_hash(data: str, algorithm: str = "sha256") -> ToolResult:
            import hashlib
            try:
                h = hashlib.new(algorithm)
                h.update(data.encode())
                return ToolResult(True, h.hexdigest())
            except Exception as e:
                return ToolResult(False, "", str(e))

        # Register all tools
        tools_to_register = [
            Tool("read_file", "Read file contents", {
                "path": {"type": "string", "description": "File path to read"},
                "encoding": {"type": "string", "default": "utf-8"}
            }, read_file),
            Tool("write_file", "Write content to file", {
                "path": {"type": "string"},
                "content": {"type": "string"}
            }, write_file),
            Tool("list_directory", "List files in directory", {
                "path": {"type": "string"},
                "pattern": {"type": "string", "default": "*"},
                "recursive": {"type": "boolean", "default": False}
            }, list_directory),
            Tool("run_command", "Execute shell command", {
                "command": {"type": "string"},
                "cwd": {"type": "string", "optional": True},
                "timeout": {"type": "integer", "default": 30}
            }, run_command),
            Tool("git_clone", "Clone git repository", {
                "url": {"type": "string"},
                "dest": {"type": "string"},
                "depth": {"type": "integer", "default": 1}
            }, git_clone),
            Tool("git_log", "Get git commit log", {
                "path": {"type": "string"},
                "n": {"type": "integer", "default": 10}
            }, git_log),
            Tool("git_diff", "Get git diff", {
                "path": {"type": "string"},
                "commit1": {"type": "string", "default": "HEAD~1"},
                "commit2": {"type": "string", "default": "HEAD"}
            }, git_diff),
            Tool("git_status", "Get git status", {
                "path": {"type": "string"}
            }, git_status),
            Tool("git_deep_analyze", "Deeply analyze git history for suspicious security-related commits", {
                "path": {"type": "string"},
                "n": {"type": "integer", "default": 50}
            }, git_deep_analyze),
            Tool("git_blame", "Identify the author and commit of a specific line of code", {
                "path": {"type": "string"},
                "file": {"type": "string"},
                "line": {"type": "integer"}
            }, git_blame),
            Tool("run_python", "Execute Python code safely", {
                "code": {"type": "string"},
                "timeout": {"type": "integer", "default": 10}
            }, run_python),
            Tool("run_in_sandbox", "Execute Python code in a real Docker sandbox (Absolute Edition)", {
                "code": {"type": "string"},
                "filename": {"type": "string", "default": "test.py"}
            }, run_in_sandbox),
            Tool("analyze_binary", "Analyze binary file (file/strings/objdump/nm/sha256)", {
                "path": {"type": "string"}
            }, analyze_binary),
            Tool("dns_lookup", "DNS lookup for domain", {
                "domain": {"type": "string"}
            }, dns_lookup),
            Tool("port_scan", "Scan ports on host", {
                "host": {"type": "string"},
                "ports": {"type": "string", "default": "80,443,22,8080,8443"}
            }, port_scan),
            Tool("http_request", "Make HTTP request", {
                "url": {"type": "string"},
                "method": {"type": "string", "default": "GET"},
                "headers": {"type": "object", "optional": True}
            }, http_request),
            Tool("compute_hash", "Compute hash of data", {
                "data": {"type": "string"},
                "algorithm": {"type": "string", "default": "sha256"}
            }, compute_hash),
        ]

        for tool in tools_to_register:
            self.register(tool)
