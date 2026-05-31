# Ghost Security VS Code Extension — Changelog

## [2.0.0] - 2026-05-25
### Added
- 3,077 security rules across 17 languages
- Built-in fallback scanner (works without Ghost CLI)
- SARIF 2.1.0 export
- CDN rules update (`ghost.updateRules`)
- Findings tree view in activity bar
- Status bar with live finding count
- `ghost.exportSarif` and `ghost.exportJson` commands
- `ghost.showRuleInfo` command
- Keyboard shortcuts: Ctrl+Shift+G S/W/F

### Changed
- Upgraded from v1 to v2 architecture
- `activationEvents` updated to `onStartupFinished`
- Package renamed from `ghost-security` v1 to v2.0.0

## [1.0.0] - 2025-01-01
### Added
- Initial release
- Basic scan on save
- Diagnostic integration
