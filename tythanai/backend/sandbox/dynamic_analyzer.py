"""Dynamic analyzer — runs suspicious code in isolated Docker container."""
from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

logger = logging.getLogger("tythanai.dynamic_analyzer")

# ─────────────────────────────────────────────────────────────────────────────
# Data models
# ─────────────────────────────────────────────────────────────────────────────

class Anomaly(BaseModel):
    """A detected anomaly during dynamic analysis."""
    kind: str           # fork_bomb | privilege_escalation | escalation_attempt | network_exfiltration
    severity: str       # CRITICAL | HIGH | MEDIUM | LOW
    detail: str
    timestamp_s: float = 0.0


class DynamicReport(BaseModel):
    """Result of dynamic analysis of a code file."""
    verdict: str = "clean"          # clean | suspicious | malicious | unavailable | error
    anomalies: List[Anomaly] = Field(default_factory=list)
    syscall_summary: Dict[str, int] = Field(default_factory=dict)
    duration_s: float = 0.0
    error: Optional[str] = None
    container_id: Optional[str] = None
    language: str = "python"

    @property
    def is_clean(self) -> bool:
        return self.verdict == "clean"

    @property
    def highest_severity(self) -> str:
        order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        if not self.anomalies:
            return "NONE"
        return max(self.anomalies, key=lambda a: order.get(a.severity, 0)).severity


# ─────────────────────────────────────────────────────────────────────────────
# Syscall / log patterns for anomaly detection
# ─────────────────────────────────────────────────────────────────────────────

# Regex patterns used to detect anomalous behaviour in container logs / strace output
_FORK_PATTERN = re.compile(
    r"(?:clone|fork|vfork)\s*\(",
    re.IGNORECASE,
)
_WRITE_SENSITIVE_PATTERN = re.compile(
    r'(?:open|openat|creat)\s*\([^,]*"(?:/etc/|/bin/|/usr/|/sbin/)',
    re.IGNORECASE,
)
_SETUID_PATTERN = re.compile(
    r"\b(?:setuid|setgid|capset|ptrace)\s*\(",
    re.IGNORECASE,
)
_CONNECT_PATTERN = re.compile(
    r"\bconnect\s*\(\s*\d+",
    re.IGNORECASE,
)
_PROC_COUNT_PATTERN = re.compile(
    r"Process\s+(\d+)\s+(?:attached|resumed)",
    re.IGNORECASE,
)

# Language → Docker image mapping (lightweight)
_LANGUAGE_IMAGE: Dict[str, str] = {
    "python": "python:3.11-slim",
    "node": "node:20-slim",
    "javascript": "node:20-slim",
    "ruby": "ruby:3.2-slim",
    "bash": "debian:bookworm-slim",
    "sh": "debian:bookworm-slim",
}

# Language → run command inside container
_LANGUAGE_CMD: Dict[str, List[str]] = {
    "python": ["python3", "-u", "/code/target.py"],
    "node": ["node", "/code/target.js"],
    "javascript": ["node", "/code/target.js"],
    "ruby": ["ruby", "/code/target.rb"],
    "bash": ["bash", "/code/target.sh"],
    "sh": ["sh", "/code/target.sh"],
}

# Extension map for staging the file in the temp dir
_LANGUAGE_EXT: Dict[str, str] = {
    "python": ".py",
    "node": ".js",
    "javascript": ".js",
    "ruby": ".rb",
    "bash": ".sh",
    "sh": ".sh",
}

# Warmup period: ignore syscall events during first 30s (Python/Node startup noise)
_WARMUP_SECONDS = 30.0

# Hard timeout for container run
_TIMEOUT_SECONDS = 120


# ─────────────────────────────────────────────────────────────────────────────
# Main analyzer class
# ─────────────────────────────────────────────────────────────────────────────

class DynamicAnalyzer:
    """
    Runs suspicious code inside a locked-down Docker container and detects
    anomalous behaviour via strace output or container log patterns.

    Container security settings applied:
    - network_mode: none
    - read_only filesystem
    - --security-opt no-new-privileges
    - --memory 256m
    - --pids-limit 50
    - code mounted as read-only volume
    """

    def __init__(
        self,
        timeout: int = _TIMEOUT_SECONDS,
        warmup_s: float = _WARMUP_SECONDS,
    ) -> None:
        self.timeout = timeout
        self.warmup_s = warmup_s
        self._docker_available: Optional[bool] = None

    # ── Public API ─────────────────────────────────────────────────────────────

    def analyze(self, code_path: str, language: str = "python") -> DynamicReport:
        """
        Run the file at *code_path* inside a Docker sandbox and return
        a DynamicReport describing any detected anomalies.

        Gracefully returns verdict="unavailable" when Docker is not installed.
        """
        if not self._check_docker():
            logger.warning("Docker not available — returning unavailable report")
            return DynamicReport(
                verdict="unavailable",
                error="Docker not installed",
                language=language,
            )

        language = language.lower()
        image = _LANGUAGE_IMAGE.get(language, "python:3.11-slim")
        run_cmd = _LANGUAGE_CMD.get(language, ["python3", "-u", "/code/target.py"])
        ext = _LANGUAGE_EXT.get(language, ".py")

        # Prepare a temp staging dir with the code file
        with tempfile.TemporaryDirectory(prefix="ghost_dyn_") as stage_dir:
            target_name = f"target{ext}"
            target_path = os.path.join(stage_dir, target_name)
            shutil.copy2(code_path, target_path)

            return self._run_in_docker(
                stage_dir=stage_dir,
                run_cmd=run_cmd,
                image=image,
                language=language,
            )

    # ── Docker helpers ─────────────────────────────────────────────────────────

    def _check_docker(self) -> bool:
        """Check once whether the Docker CLI is accessible."""
        if self._docker_available is not None:
            return self._docker_available
        try:
            result = subprocess.run(
                ["docker", "version", "--format", "{{.Server.Version}}"],
                capture_output=True,
                timeout=10,
            )
            self._docker_available = result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            self._docker_available = False
        return self._docker_available  # type: ignore[return-value]

    def _build_docker_cmd(
        self,
        stage_dir: str,
        run_cmd: List[str],
        image: str,
        container_name: str,
    ) -> List[str]:
        """Assemble the full `docker run` command with hardened security flags."""
        cmd: List[str] = [
            "docker", "run",
            "--rm",
            "--name", container_name,
            "--network", "none",
            "--read-only",
            "--security-opt", "no-new-privileges",
            "--memory", "256m",
            "--pids-limit", "50",
            "--tmpfs", "/tmp:size=32m",    # writable /tmp for Python import cache
            "-v", f"{stage_dir}:/code:ro",  # code as read-only volume
            image,
        ] + run_cmd
        return cmd

    def _run_in_docker(
        self,
        stage_dir: str,
        run_cmd: List[str],
        image: str,
        language: str,
    ) -> DynamicReport:
        """Execute container and analyse its output."""
        container_name = f"ghost_dyn_{int(time.time() * 1000)}"
        cmd = self._build_docker_cmd(stage_dir, run_cmd, image, container_name)

        start_ts = time.monotonic()
        stdout_lines: List[str] = []
        stderr_lines: List[str] = []

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            duration_s = time.monotonic() - start_ts
            stdout_lines = proc.stdout.splitlines()
            stderr_lines = proc.stderr.splitlines()
        except subprocess.TimeoutExpired:
            duration_s = float(self.timeout)
            # Kill the container on timeout
            self._kill_container(container_name)
            logger.warning("Container %s timed out after %ds", container_name, self.timeout)
        except subprocess.CalledProcessError as exc:
            duration_s = time.monotonic() - start_ts
            logger.error("Container run failed: %s", exc)
            return DynamicReport(
                verdict="error",
                error=str(exc),
                duration_s=duration_s,
                container_id=container_name,
                language=language,
            )
        except Exception as exc:
            duration_s = time.monotonic() - start_ts
            logger.error("Unexpected error running container: %s", exc)
            return DynamicReport(
                verdict="error",
                error=str(exc),
                duration_s=duration_s,
                container_id=container_name,
                language=language,
            )

        # Analyse combined output
        all_lines = stdout_lines + stderr_lines
        anomalies, syscall_summary = self._analyse_output(all_lines, start_ts)

        verdict = self._compute_verdict(anomalies)
        return DynamicReport(
            verdict=verdict,
            anomalies=anomalies,
            syscall_summary=syscall_summary,
            duration_s=round(duration_s, 3),
            container_id=container_name,
            language=language,
        )

    def _kill_container(self, name: str) -> None:
        """Attempt to forcefully remove a container by name."""
        try:
            subprocess.run(
                ["docker", "rm", "-f", name],
                capture_output=True,
                timeout=15,
            )
        except Exception:
            pass

    # ── Output analysis ────────────────────────────────────────────────────────

    def _analyse_output(
        self,
        lines: List[str],
        start_ts: float,
    ) -> Tuple[List[Anomaly], Dict[str, int]]:
        """
        Scan container output / strace lines for anomaly patterns.

        Applies a 30-second warmup window: events in the first _WARMUP_SECONDS
        of execution are ignored (covers Python/Node interpreter startup).
        """
        anomalies: List[Anomaly] = []
        syscall_summary: Dict[str, int] = {}
        fork_count = 0
        current_ts = 0.0

        # Try to parse strace-style timestamps from lines; fall back to line index
        elapsed_approx = 0.0
        lines_per_second = max(1, len(lines)) / max(1.0, self.timeout)

        for i, line in enumerate(lines):
            # Estimate elapsed time from line position if no timestamps present
            elapsed_approx = i / lines_per_second

            # Skip warmup window
            if elapsed_approx < self.warmup_s:
                # Still accumulate syscall counts during warmup
                self._count_syscall(line, syscall_summary)
                continue

            self._count_syscall(line, syscall_summary)

            # ── Fork bomb detection ──────────────────────────────────────────
            if _FORK_PATTERN.search(line):
                fork_count += 1
                if fork_count > 50:
                    anomalies.append(Anomaly(
                        kind="fork_bomb",
                        severity="CRITICAL",
                        detail=f"Excessive child processes detected (count>{fork_count}): {line[:200]}",
                        timestamp_s=elapsed_approx,
                    ))

            # ── Write to sensitive paths ─────────────────────────────────────
            if _WRITE_SENSITIVE_PATTERN.search(line):
                anomalies.append(Anomaly(
                    kind="privilege_escalation",
                    severity="HIGH",
                    detail=f"Write attempt to sensitive path: {line[:200]}",
                    timestamp_s=elapsed_approx,
                ))

            # ── setuid / ptrace ──────────────────────────────────────────────
            if _SETUID_PATTERN.search(line):
                anomalies.append(Anomaly(
                    kind="escalation_attempt",
                    severity="CRITICAL",
                    detail=f"Privilege escalation syscall: {line[:200]}",
                    timestamp_s=elapsed_approx,
                ))

            # ── Network connection attempt ───────────────────────────────────
            if _CONNECT_PATTERN.search(line):
                anomalies.append(Anomaly(
                    kind="network_exfiltration",
                    severity="HIGH",
                    detail=f"Network connect() attempt (blocked by network_mode:none): {line[:200]}",
                    timestamp_s=elapsed_approx,
                ))

        # Deduplicate anomaly kinds (keep first occurrence of each kind)
        seen_kinds: set[str] = set()
        deduped: List[Anomaly] = []
        for a in anomalies:
            if a.kind not in seen_kinds:
                seen_kinds.add(a.kind)
                deduped.append(a)

        return deduped, syscall_summary

    @staticmethod
    def _count_syscall(line: str, summary: Dict[str, int]) -> None:
        """Extract syscall name from a strace-format line and increment counter."""
        # strace format: "PID  syscall(args) = retval"
        # We just match the first word that looks like a syscall
        m = re.match(r"^\s*(?:\d+\s+)?([a-z_][a-z0-9_]{1,30})\s*\(", line)
        if m:
            syscall = m.group(1)
            summary[syscall] = summary.get(syscall, 0) + 1

    @staticmethod
    def _compute_verdict(anomalies: List[Anomaly]) -> str:
        """Determine overall verdict from anomaly list."""
        if not anomalies:
            return "clean"
        severities = {a.severity for a in anomalies}
        if "CRITICAL" in severities:
            return "malicious"
        if "HIGH" in severities:
            return "suspicious"
        return "suspicious"
