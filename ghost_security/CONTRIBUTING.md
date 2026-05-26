# Contributing to Ghost Security Platform

Thank you for your interest in contributing to Ghost Security! This guide covers how to set up your
development environment, run tests, add new rules, and submit pull requests.

---

## Table of Contents

1. [Development Setup](#development-setup)
2. [Running Tests](#running-tests)
3. [Adding New Rules](#adding-new-rules)
4. [Adding New Scanners](#adding-new-scanners)
5. [Code Style](#code-style)
6. [Pre-commit Hooks Setup](#pre-commit-hooks-setup)
7. [PR Requirements](#pr-requirements)

---

## Development Setup

### Prerequisites

- Python 3.11 or later
- Git
- (Optional) Docker for running the full stack
- (Optional) Ollama for local AI features

### Clone and Install

```bash
git clone https://github.com/ton-blockchain/ghost_security.git
cd ghost_security

# Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate   # macOS/Linux
# .venv\Scripts\activate    # Windows

# Install dependencies
pip install -r requirements.txt

# Install development tools
pip install pre-commit ruff pytest pytest-asyncio
```

### Environment Configuration

Copy the example environment file:

```bash
cp .env.example .env
```

Edit `.env` and set any API keys you want to use. For fully offline development, no API keys
are needed.

### Verify Installation

```bash
python ghost_cli.py --help
python ghost_cli.py doctor
```

---

## Running Tests

### Run all tests

```bash
pytest tests/ -v
```

### Run a specific test suite

```bash
pytest tests/test_v13_ast_engine.py -v
pytest tests/test_multichain_scanners.py -v
```

### Run with coverage

```bash
pytest tests/ --cov=. --cov-report=html
open htmlcov/index.html
```

### Async tests

All async tests use `pytest-asyncio`. Mark async tests with:

```python
import pytest

@pytest.mark.asyncio
async def test_my_async_feature():
    ...
```

### Run the scanner on a test file

```bash
python ghost_cli.py scan --path tests/ --severity LOW
```

---

## Adding New Rules

Rules are YAML files under `rules/<chain>/`. Each file contains a list of detection rules.

### Rule YAML format

```yaml
# rules/evm/my_new_rule.yaml
rules:
  - id: evm-my-rule-001
    name: Short descriptive name
    severity: HIGH          # CRITICAL | HIGH | MEDIUM | LOW | INFO
    chain: evm              # evm | solana | cosmos | polkadot | move | ton
    description: |
      A longer description of what this rule detects and why it matters.
    pattern:
      type: ast             # ast | regex | semgrep
      # For ast type:
      node: ExternalCall    # AST node type to match
      conditions:
        - field: before_state_update
          value: true
      # For regex type:
      # regex: "pattern_here"
      # For semgrep type:
      # semgrep_rule: "pattern: ..."
    message: "Human-readable finding message shown to the user"
    remediation: |
      How to fix this issue. Include code examples where possible.
    references:
      - https://swcregistry.io/docs/SWC-107
      - https://docs.soliditylang.org/...
    cwe: CWE-841
    tags:
      - reentrancy
      - defi
```

### Testing your rule

1. Create a test smart contract with the vulnerability:

```bash
mkdir tests/fixtures/evm
cat > tests/fixtures/evm/my_vulnerability.sol << 'EOF'
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableExample {
    mapping(address => uint256) public balances;

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] = 0;  // state update AFTER external call
    }
}
EOF
```

2. Write a test:

```python
# tests/test_my_new_rule.py
from scanners.evm_scanner.evm_analyzer import EVMScanner

def test_my_rule_detects_vulnerability():
    scanner = EVMScanner()
    source = open("tests/fixtures/evm/my_vulnerability.sol").read()
    findings = scanner.scan(source, "my_vulnerability.sol")
    assert any(f.rule_id == "evm-my-rule-001" for f in findings)
    assert any(f.severity == "HIGH" for f in findings)
```

3. Run your test: `pytest tests/test_my_new_rule.py -v`

---

## Adding New Scanners

To add a scanner for a new language or blockchain:

### 1. Create the scanner module

```
scanners/
  my_chain_scanner/
    __init__.py
    my_chain_analyzer.py
```

### 2. Implement the scanner interface

```python
# scanners/my_chain_scanner/my_chain_analyzer.py
from dataclasses import dataclass
from typing import List


@dataclass
class Finding:
    rule_id: str
    name: str
    severity: str
    message: str
    file: str
    line: int
    confidence: float = 0.8


class MyChainScanner:
    """Scanner for MyChain smart contracts."""

    SUPPORTED_EXTENSIONS = {".myc", ".mychain"}

    def supports_file(self, path: str) -> bool:
        return any(path.endswith(ext) for ext in self.SUPPORTED_EXTENSIONS)

    def scan(self, source: str, filename: str) -> List[Finding]:
        findings = []
        # Implement detection logic here
        return findings
```

### 3. Register the scanner

Add it to `scanners/security_pipeline.py`:

```python
from scanners.my_chain_scanner.my_chain_analyzer import MyChainScanner

SCANNERS = [
    ...
    MyChainScanner(),
]
```

### 4. Add rules

Create `rules/my_chain/security.yaml` with your initial ruleset.

### 5. Write tests

Create `tests/test_my_chain_scanner.py` covering:
- Detection of known vulnerabilities
- No false positives on clean code
- Edge cases (empty files, syntax errors)

---

## Code Style

Ghost Security uses **ruff** for linting and formatting.

### Format code

```bash
ruff format .
```

### Lint code

```bash
ruff check . --fix
```

### Configuration

Ruff is configured in `pyproject.toml`. Key settings:
- Line length: 100
- Target Python version: 3.11+
- Enabled rule sets: E, F, W, I (isort), N, UP, B, C4, SIM

### Type hints

All new code should use Python type hints:

```python
def scan_file(path: str, options: dict[str, str]) -> list[Finding]:
    ...
```

---

## Pre-commit Hooks Setup

Install the pre-commit hooks to run checks automatically before every commit:

```bash
pip install pre-commit
pre-commit install
```

The hooks configured in `.pre-commit-config.yaml` will run:
1. **ruff** — lint and format
2. **ruff-format** — code formatting
3. **trailing-whitespace** — remove trailing whitespace
4. **end-of-file-fixer** — ensure files end with newline
5. **check-yaml** — validate YAML syntax
6. **check-json** — validate JSON syntax
7. **check-merge-conflict** — detect merge conflict markers
8. **detect-private-key** — prevent committing secrets
9. **ghost-security-check** — run Ghost Security self-scan on staged files

### Run hooks manually

```bash
pre-commit run --all-files
```

### Skip hooks (emergency only)

```bash
git commit --no-verify -m "emergency fix"
```

Note: skipping hooks is discouraged. Fix the issue instead.

---

## PR Requirements

All pull requests must meet these requirements before merging:

### Required

- [ ] All existing tests pass: `pytest tests/ -v`
- [ ] No new lint errors: `ruff check .`
- [ ] New features have tests (minimum: happy path + one edge case)
- [ ] New rules have at least one positive and one negative test case
- [ ] PR description explains **what** and **why** (not just what)

### Recommended

- [ ] New scanners include performance benchmarks
- [ ] Complex algorithms are commented with references to papers/specs
- [ ] Breaking changes are documented in the PR description

### PR Title Format

Use the conventional commits format:

```
feat(evm): add flash loan detection rule
fix(ton): correct replay attack detection false positive
docs: update architecture for v13
test(solana): add account validation test coverage
refactor(verifier): extract confidence scoring to separate class
```

### Review Process

1. Open a draft PR early to get early feedback
2. At least one maintainer approval required before merge
3. All CI checks must be green
4. Squash merge preferred for clean history

---

## Getting Help

- Open a GitHub Issue for bugs or feature requests
- Check existing issues before opening a new one
- For security vulnerabilities, see `GHOST-2025-001-public-disclosure.md` for our disclosure policy
