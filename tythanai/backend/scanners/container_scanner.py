"""Container Security Scanner: Dockerfile analysis + image layer checks."""
from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

logger = logging.getLogger("tythanai.container")

try:
    import yaml as _yaml  # type: ignore

    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False
    logger.info("PyYAML not installed; docker-compose checks will use regex fallback")


# ─────────────────────────────────────────────────────────────────────────────
# Result model
# ─────────────────────────────────────────────────────────────────────────────


class ContainerFinding(BaseModel):
    rule_id: str
    file: str
    line: int
    severity: str
    description: str
    recommendation: str
    layer: str = ""  # dockerfile instruction
    category: str = ""  # BASE_IMAGE/PRIVILEGE/SECRETS/NETWORK/BUILD


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

_SKIP_DIRS = {"node_modules", ".git", "vendor"}

_SECRET_ENV_RE = re.compile(
    r'(?:^|_)(?:password|passwd|secret|token|api_?key|private_?key|auth|credential)(?:_|$)',
    re.IGNORECASE,
)


def _res(
    rule_id: str,
    file: str,
    line: int,
    severity: str,
    description: str,
    recommendation: str,
    layer: str = "",
    category: str = "",
) -> ContainerFinding:
    return ContainerFinding(
        rule_id=rule_id,
        file=file,
        line=line,
        severity=severity,
        description=description,
        recommendation=recommendation,
        layer=layer,
        category=category,
    )


def _yaml_load(content: str) -> Optional[Any]:
    if not _YAML_AVAILABLE:
        return None
    try:
        return _yaml.safe_load(content)
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Dockerfile parser
# ─────────────────────────────────────────────────────────────────────────────


class _DockerfileInstruction:
    """Represents a parsed Dockerfile instruction with its line number."""

    __slots__ = ("line_no", "instruction", "arguments", "raw")

    def __init__(self, line_no: int, instruction: str, arguments: str, raw: str) -> None:
        self.line_no = line_no
        self.instruction = instruction.upper()
        self.arguments = arguments.strip()
        self.raw = raw


def _parse_dockerfile(content: str) -> List[_DockerfileInstruction]:
    """
    Parse a Dockerfile into a list of instructions.

    Handles line continuations (backslash at end of line) and comment lines.
    """
    instructions: List[_DockerfileInstruction] = []
    lines = content.splitlines()
    i = 0
    while i < len(lines):
        raw_line = lines[i]
        line_no = i + 1
        stripped = raw_line.strip()

        # Skip blank lines and comments
        if not stripped or stripped.startswith("#"):
            i += 1
            continue

        # Handle line continuation
        combined = stripped
        while combined.endswith("\\"):
            combined = combined[:-1]
            i += 1
            if i < len(lines):
                combined += lines[i].strip()

        # Parse instruction
        parts = combined.split(None, 1)
        if parts:
            instruction = parts[0].upper()
            arguments = parts[1] if len(parts) > 1 else ""
            instructions.append(
                _DockerfileInstruction(line_no, instruction, arguments, combined)
            )

        i += 1

    return instructions


# ─────────────────────────────────────────────────────────────────────────────
# Main scanner
# ─────────────────────────────────────────────────────────────────────────────


class ContainerScanner:
    """
    Scans Dockerfiles and docker-compose files for security misconfigurations.
    """

    # ── Dockerfile ────────────────────────────────────────────────────────────

    def scan_dockerfile(self, path: str) -> List[ContainerFinding]:
        """Scan a single Dockerfile for security issues."""
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except OSError as exc:
            logger.warning("Cannot read %s: %s", path, exc)
            return []

        try:
            return self._check_dockerfile(path, content)
        except Exception as exc:
            logger.warning("Error scanning Dockerfile %s: %s", path, exc)
            return []

    def _check_dockerfile(self, path: str, content: str) -> List[ContainerFinding]:
        results: List[ContainerFinding] = []
        instructions = _parse_dockerfile(content)

        # Pre-pass statistics
        run_count = sum(1 for i in instructions if i.instruction == "RUN")
        has_user = any(
            i.instruction == "USER" and i.arguments.strip().lower() not in ("root", "0")
            for i in instructions
        )
        has_healthcheck = any(
            i.instruction == "HEALTHCHECK" and i.arguments.strip().upper() != "NONE"
            for i in instructions
        )
        user_instructions = [i for i in instructions if i.instruction == "USER"]
        # The effective USER at the end of the build — if last USER is root/0/missing → warn
        last_user_is_root = True
        if user_instructions:
            last_user = user_instructions[-1].arguments.strip().lower()
            last_user_is_root = last_user in ("root", "0", "")

        # ── CONT-001: FROM with :latest ───────────────────────────────────────
        for inst in instructions:
            if inst.instruction == "FROM":
                # FROM <image>[:<tag>] [AS <name>]
                image_part = inst.arguments.split()[0] if inst.arguments.split() else ""
                # Scratch is acceptable
                if image_part.lower() == "scratch":
                    continue
                # latest tag or no tag at all (implicit latest)
                if ":" not in image_part or image_part.endswith(":latest"):
                    results.append(
                        _res(
                            "CONT-001", path, inst.line_no, "MEDIUM",
                            f"Unpinned base image: '{image_part}' uses :latest or no tag",
                            "Pin the base image to a specific digest or version tag.",
                            layer="FROM",
                            category="BASE_IMAGE",
                        )
                    )

        # ── CONT-002: USER root or no USER directive ───────────────────────────
        if not user_instructions or last_user_is_root:
            # Find a representative line
            line_no = user_instructions[-1].line_no if user_instructions else len(content.splitlines())
            reason = "Container runs as root" if user_instructions else "No USER directive; container defaults to root"
            results.append(
                _res(
                    "CONT-002", path, line_no, "HIGH",
                    reason,
                    "Add a USER instruction with a non-root UID (e.g., USER 1000).",
                    layer="USER",
                    category="PRIVILEGE",
                )
            )

        # ── CONT-003: RUN with pipe-to-shell ──────────────────────────────────
        pipe_shell_re = re.compile(
            r'(?:curl|wget)\b.*\|\s*(?:sh|bash|dash|zsh|ash|python|perl|ruby)\b',
            re.IGNORECASE,
        )
        for inst in instructions:
            if inst.instruction == "RUN":
                if pipe_shell_re.search(inst.arguments):
                    results.append(
                        _res(
                            "CONT-003", path, inst.line_no, "CRITICAL",
                            "RUN instruction pipes remote content directly to a shell",
                            "Download and verify the script checksum before executing.",
                            layer="RUN",
                            category="BUILD",
                        )
                    )

        # ── CONT-004: ADD with URL ────────────────────────────────────────────
        url_re = re.compile(r'^https?://', re.IGNORECASE)
        for inst in instructions:
            if inst.instruction == "ADD":
                src = inst.arguments.split()[0] if inst.arguments.split() else ""
                if url_re.match(src):
                    results.append(
                        _res(
                            "CONT-004", path, inst.line_no, "MEDIUM",
                            f"ADD with URL '{src}' bypasses Docker build cache and checksum verification",
                            "Use RUN curl/wget with explicit checksum verification, or COPY.",
                            layer="ADD",
                            category="BUILD",
                        )
                    )

        # ── CONT-005: ENV with secret name and non-empty value ────────────────
        for inst in instructions:
            if inst.instruction == "ENV":
                # ENV can be: KEY=VALUE or KEY VALUE or multiple KEY=VALUE pairs
                pairs = _parse_env_instruction(inst.arguments)
                for key, value in pairs:
                    if _SECRET_ENV_RE.search(key) and value and value.strip():
                        results.append(
                            _res(
                                "CONT-005", path, inst.line_no, "CRITICAL",
                                f"ENV instruction sets secret-named variable '{key}' with a plaintext value",
                                "Use Docker secrets, BuildKit secrets, or runtime environment injection.",
                                layer="ENV",
                                category="SECRETS",
                            )
                        )

        # ── CONT-006: apt-get install without --no-install-recommends ─────────
        apt_re = re.compile(r'apt(?:-get)?\s+install\b', re.IGNORECASE)
        no_rec_re = re.compile(r'--no-install-recommends', re.IGNORECASE)
        for inst in instructions:
            if inst.instruction == "RUN":
                if apt_re.search(inst.arguments) and not no_rec_re.search(inst.arguments):
                    results.append(
                        _res(
                            "CONT-006", path, inst.line_no, "LOW",
                            "apt-get/apt install without --no-install-recommends installs unnecessary packages",
                            "Add --no-install-recommends to reduce image size and attack surface.",
                            layer="RUN",
                            category="BUILD",
                        )
                    )

        # ── CONT-007: EXPOSE 22 ───────────────────────────────────────────────
        for inst in instructions:
            if inst.instruction == "EXPOSE":
                exposed_ports = inst.arguments.split()
                for port_spec in exposed_ports:
                    port_num = port_spec.split("/")[0]
                    try:
                        if int(port_num) == 22:
                            results.append(
                                _res(
                                    "CONT-007", path, inst.line_no, "HIGH",
                                    "SSH port 22 is exposed in the container image",
                                    "Remove EXPOSE 22; use exec/attach for container access.",
                                    layer="EXPOSE",
                                    category="NETWORK",
                                )
                            )
                    except ValueError:
                        continue

        # ── CONT-008: chmod 777 ───────────────────────────────────────────────
        chmod_re = re.compile(r'chmod\s+(?:-[Rr]\s+)?777\b', re.IGNORECASE)
        for inst in instructions:
            if inst.instruction == "RUN":
                if chmod_re.search(inst.arguments):
                    results.append(
                        _res(
                            "CONT-008", path, inst.line_no, "HIGH",
                            "RUN instruction sets world-writable permissions (chmod 777)",
                            "Use least-privilege permissions; avoid 777.",
                            layer="RUN",
                            category="PRIVILEGE",
                        )
                    )

        # ── CONT-009: COPY . . or ADD . . ────────────────────────────────────
        broad_copy_re = re.compile(r'^\.\s+\.', re.MULTILINE)
        for inst in instructions:
            if inst.instruction in ("COPY", "ADD"):
                args_stripped = inst.arguments.strip()
                # Handle --from=... flags
                args_no_flags = re.sub(r'--\S+\s*', '', args_stripped).strip()
                if re.match(r'^\.\s+\.', args_no_flags):
                    results.append(
                        _res(
                            "CONT-009", path, inst.line_no, "MEDIUM",
                            f"{inst.instruction} copies the entire build context (. .)",
                            "Use a .dockerignore file and copy only required files.",
                            layer=inst.instruction,
                            category="BUILD",
                        )
                    )

        # ── CONT-010: Too many RUN layers ─────────────────────────────────────
        if run_count > 5:
            # Report at first RUN statement
            first_run = next((i for i in instructions if i.instruction == "RUN"), None)
            results.append(
                _res(
                    "CONT-010", path, first_run.line_no if first_run else 1, "LOW",
                    f"Dockerfile has {run_count} separate RUN statements; consider consolidating",
                    "Combine RUN commands with && to reduce layer count and image size.",
                    layer="RUN",
                    category="BUILD",
                )
            )

        # ── CONT-011: No HEALTHCHECK ──────────────────────────────────────────
        if not has_healthcheck:
            results.append(
                _res(
                    "CONT-011", path, len(content.splitlines()), "LOW",
                    "No HEALTHCHECK instruction defined in Dockerfile",
                    "Add a HEALTHCHECK instruction to enable container health monitoring.",
                    layer="HEALTHCHECK",
                    category="BUILD",
                )
            )

        # ── CONT-012: --privileged flag ───────────────────────────────────────
        privileged_re = re.compile(r'--privileged\b', re.IGNORECASE)
        for inst in instructions:
            if inst.instruction in ("RUN", "CMD", "ENTRYPOINT"):
                if privileged_re.search(inst.arguments):
                    results.append(
                        _res(
                            "CONT-012", path, inst.line_no, "CRITICAL",
                            f"--privileged flag found in {inst.instruction} instruction",
                            "Remove --privileged; it grants the container full host access.",
                            layer=inst.instruction,
                            category="PRIVILEGE",
                        )
                    )

        return results

    # ── Docker Compose ────────────────────────────────────────────────────────

    def scan_compose(self, path: str) -> List[ContainerFinding]:
        """Scan a docker-compose file for security issues."""
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except OSError as exc:
            logger.warning("Cannot read %s: %s", path, exc)
            return []

        try:
            return self._check_compose(path, content)
        except Exception as exc:
            logger.warning("Error scanning compose file %s: %s", path, exc)
            return []

    def _check_compose(self, path: str, content: str) -> List[ContainerFinding]:
        results: List[ContainerFinding] = []
        lines = content.splitlines()

        compose: Optional[Any] = _yaml_load(content)
        if not isinstance(compose, dict):
            # Regex fallback
            return self._check_compose_regex(path, content)

        # docker-compose v2/v3 format
        services: Dict = compose.get("services", {}) or {}
        if not services:
            return results

        def line_for(keyword: str, service: str) -> int:
            """Find line number for a keyword within a service block."""
            in_service = False
            for i, ln in enumerate(lines, 1):
                if re.match(rf'\s*{re.escape(service)}\s*:', ln):
                    in_service = True
                if in_service and keyword in ln:
                    return i
            return 1

        _SENSITIVE_MOUNTS = {"/etc", "/var/run/docker.sock", "/proc", "/sys", "/dev", "/root"}

        for svc_name, svc_body in services.items():
            if not isinstance(svc_body, dict):
                continue

            # ── CONT-C-001: privileged: true ─────────────────────────────────
            if svc_body.get("privileged") is True:
                results.append(
                    _res(
                        "CONT-C-001", path, line_for("privileged", svc_name), "CRITICAL",
                        f"Service '{svc_name}' runs in privileged mode",
                        "Remove privileged: true; use specific capabilities instead.",
                        category="PRIVILEGE",
                    )
                )

            # ── CONT-C-002: network_mode: host ────────────────────────────────
            network_mode = svc_body.get("network_mode", "")
            if network_mode == "host":
                results.append(
                    _res(
                        "CONT-C-002", path, line_for("network_mode", svc_name), "HIGH",
                        f"Service '{svc_name}' uses host network mode",
                        "Use bridge networking and expose only required ports.",
                        category="NETWORK",
                    )
                )

            # ── CONT-C-003: No memory limit ───────────────────────────────────
            has_mem_limit = bool(
                svc_body.get("mem_limit")
                or _nested_get(svc_body, "deploy", "resources", "limits", "memory")
            )
            if not has_mem_limit:
                results.append(
                    _res(
                        "CONT-C-003", path, line_for(svc_name, svc_name), "MEDIUM",
                        f"Service '{svc_name}' has no memory limit configured",
                        "Set mem_limit or deploy.resources.limits.memory.",
                        category="COMPUTE",
                    )
                )

            # ── CONT-C-004: Sensitive host path mounts ─────────────────────────
            volumes: List = svc_body.get("volumes", []) or []
            for vol in volumes:
                host_path = ""
                if isinstance(vol, str):
                    # format: host_path:container_path[:options]
                    parts = vol.split(":")
                    if len(parts) >= 2:
                        host_path = parts[0]
                elif isinstance(vol, dict):
                    # long-form volume syntax
                    source = vol.get("source", "")
                    if vol.get("type") == "bind":
                        host_path = source

                if host_path:
                    for sensitive in _SENSITIVE_MOUNTS:
                        if host_path == sensitive or host_path.startswith(sensitive + "/") or host_path == sensitive.rstrip("/"):
                            ln = line_for(host_path, svc_name)
                            results.append(
                                _res(
                                    "CONT-C-004", path, ln, "CRITICAL",
                                    f"Service '{svc_name}' mounts sensitive host path '{host_path}'",
                                    "Avoid mounting sensitive host paths; use named volumes instead.",
                                    category="PRIVILEGE",
                                )
                            )
                            break

            # ── CONT-C-005: pid_mode: host ────────────────────────────────────
            pid_mode = svc_body.get("pid", "") or svc_body.get("pid_mode", "")
            if pid_mode == "host":
                results.append(
                    _res(
                        "CONT-C-005", path, line_for("pid", svc_name), "HIGH",
                        f"Service '{svc_name}' shares the host PID namespace",
                        "Remove pid: host to isolate process namespaces.",
                        category="PRIVILEGE",
                    )
                )

            # ── CONT-C-006: Plaintext secrets in environment variables ─────────
            env_section = svc_body.get("environment", {}) or {}
            env_pairs: List[Tuple[str, str]] = []

            if isinstance(env_section, dict):
                env_pairs = list(env_section.items())
            elif isinstance(env_section, list):
                for item in env_section:
                    if isinstance(item, str) and "=" in item:
                        k, _, v = item.partition("=")
                        env_pairs.append((k.strip(), v.strip()))

            for env_key, env_val in env_pairs:
                if _SECRET_ENV_RE.search(env_key) and env_val and str(env_val).strip():
                    results.append(
                        _res(
                            "CONT-C-006", path, line_for(env_key, svc_name), "HIGH",
                            f"Service '{svc_name}' has plaintext secret in environment variable '{env_key}'",
                            "Use Docker secrets or environment variable files with proper permissions.",
                            category="SECRETS",
                        )
                    )

        return results

    def _check_compose_regex(self, path: str, content: str) -> List[ContainerFinding]:
        """Regex-only fallback for docker-compose parsing when YAML is unavailable."""
        results: List[ContainerFinding] = []
        lines = content.splitlines()

        def find_line(s: str) -> int:
            for i, ln in enumerate(lines, 1):
                if s in ln:
                    return i
            return 1

        if re.search(r'^\s*privileged\s*:\s*true', content, re.MULTILINE):
            results.append(
                _res("CONT-C-001", path, find_line("privileged: true"), "CRITICAL",
                     "Service runs in privileged mode",
                     "Remove privileged: true.", category="PRIVILEGE")
            )
        if re.search(r'^\s*network_mode\s*:\s*host', content, re.MULTILINE):
            results.append(
                _res("CONT-C-002", path, find_line("network_mode"), "HIGH",
                     "Service uses host network mode",
                     "Use bridge networking.", category="NETWORK")
            )
        for sensitive in ("/var/run/docker.sock", "/proc", "/etc", "/sys"):
            if sensitive in content:
                results.append(
                    _res("CONT-C-004", path, find_line(sensitive), "CRITICAL",
                         f"Sensitive host path '{sensitive}' is mounted",
                         "Avoid mounting sensitive host paths.", category="PRIVILEGE")
                )
                break

        return results

    # ── Directory scanner ─────────────────────────────────────────────────────

    def scan_directory(self, directory: str) -> List[ContainerFinding]:
        """Recursively find and scan Dockerfiles and docker-compose files."""
        results: List[ContainerFinding] = []
        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
            for filename in files:
                full_path = os.path.join(root, filename)
                lower = filename.lower()

                if _is_dockerfile(lower):
                    results.extend(self.scan_dockerfile(full_path))
                elif _is_compose_file(lower):
                    results.extend(self.scan_compose(full_path))

        return results


# ─────────────────────────────────────────────────────────────────────────────
# Filename matchers
# ─────────────────────────────────────────────────────────────────────────────


def _is_dockerfile(name: str) -> bool:
    """Return True if the filename looks like a Dockerfile."""
    if name == "dockerfile":
        return True
    if name.startswith("dockerfile.") or name.endswith(".dockerfile"):
        return True
    # e.g. Dockerfile.prod, Dockerfile-alpine
    if re.match(r'^dockerfile[-.]', name):
        return True
    return False


def _is_compose_file(name: str) -> bool:
    """Return True if the filename looks like a docker-compose file."""
    return bool(re.match(r'^docker-compose[.\-].*\.(ya?ml)$', name) or name in ("docker-compose.yml", "docker-compose.yaml"))


# ─────────────────────────────────────────────────────────────────────────────
# ENV instruction parser
# ─────────────────────────────────────────────────────────────────────────────


def _parse_env_instruction(args: str) -> List[Tuple[str, str]]:
    """
    Parse Docker ENV instruction arguments into (key, value) pairs.

    Handles both forms:
    - KEY=VALUE [KEY2=VALUE2 ...]
    - KEY VALUE  (legacy single-pair form)
    """
    pairs: List[Tuple[str, str]] = []

    # Check if it uses the KEY=VALUE form
    if "=" in args:
        # Split on whitespace but respect quoted values
        token_re = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'|\S*)')
        for m in token_re.finditer(args):
            key = m.group(1)
            value = m.group(2).strip('"\'')
            pairs.append((key, value))
    else:
        # Legacy form: ENV KEY value with spaces
        parts = args.split(None, 1)
        if len(parts) == 2:
            pairs.append((parts[0], parts[1]))
        elif parts:
            pairs.append((parts[0], ""))

    return pairs


# ─────────────────────────────────────────────────────────────────────────────
# Nested dict accessor
# ─────────────────────────────────────────────────────────────────────────────


def _nested_get(obj: Any, *keys: str) -> Optional[Any]:
    """Safely traverse nested dicts."""
    for k in keys:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(k)
        if obj is None:
            return None
    return obj


# ─────────────────────────────────────────────────────────────────────────────
# Module-level convenience function
# ─────────────────────────────────────────────────────────────────────────────


def scan_containers(directory: str) -> List[ContainerFinding]:
    """Scan an entire directory for container security issues."""
    return ContainerScanner().scan_directory(directory)
