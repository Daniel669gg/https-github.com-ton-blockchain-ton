"""
TythanAI Platform — Setup
"""
from pathlib import Path

# Create all __init__.py files
packages = [
    "config",
    "core",
    "core/agent",
    "core/memory",
    "core/planner",
    "core/tools",
    "core/verifier",
    "scanners",
    "scanners/ast_scanner",
    "scanners/semgrep_scanner",
    "scanners/binary_scanner",
    "scanners/github_watcher",
    "scanners/secret_scanner",
    "agents",
    "agents/research",
    "agents/coding",
    "agents/security",
    "agents/reviewer",
    "api",
    "reports",
    "tests",
]

base = Path(__file__).parent
for pkg in packages:
    init_file = base / pkg / "__init__.py"
    if not init_file.exists():
        init_file.write_text(f'"""TythanAI Platform — {pkg}"""\n')

print("All __init__.py files created")
