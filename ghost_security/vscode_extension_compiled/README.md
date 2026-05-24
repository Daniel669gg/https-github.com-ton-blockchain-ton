# Ghost Security — VS Code Extension

Real-time AI security scanning for TON/Web3 and all major languages.

## Features
- 🔍 Scan on save — instant security feedback
- 🔴 Inline diagnostics for CRITICAL/HIGH findings  
- 💰 TON Bug Bounty self-check
- 📊 Findings panel with severity grouping
- 🌍 Python, JS/TS, Go, Java, PHP, Ruby, Rust, Solidity, FunC/Tact

## Setup
1. Install extension
2. Open Settings → Ghost Security
3. Set `ghost.serverUrl` to your Ghost Security Platform instance
4. Enable `ghost.scanOnSave` (default: on)

## Commands
- `Ghost: Scan Current File`
- `Ghost: Scan Workspace` 
- `Ghost: TON Bug Bounty Self-Check`

## Requirements
Ghost Security Platform running locally or remotely.
Quick start: `pip install ghost-security && ghost serve`

## Links
- [Ghost Security Platform](https://ghost-security.io)
- [Documentation](https://docs.ghost-security.io)
- [Bug Bounty Guide](https://github.com/ghost-security/platform)
