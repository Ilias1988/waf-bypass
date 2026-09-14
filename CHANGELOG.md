# Changelog

All notable changes to this project are documented here.

## [1.1.0] - 2026-09-14

### Added

- Target-aware command injection support for Linux shells, Windows `cmd.exe`, and PowerShell.
- Exact byte downloads for UTF-16LE/BE XML variants.
- Deterministic adversarial regression coverage across all configured category, target, and layer combinations.
- Output validity labels and prerequisite notes for conditional or legacy transformations.
- SEO-aligned introductory and FAQ content plus WebSite/WebApplication structured data.
- Cloudflare Web Analytics for page-view and performance statistics.
- Windows CI and a repeatable release checklist.

### Changed

- Reworked SQL and JavaScript transformations around protected lexical regions instead of broad whole-payload replacements.
- Preserved raw URL authority/suffix data and existing transport-encoded literals.
- Clarified that generated variants are test candidates, not guaranteed WAF bypasses.
- Hardened the local GitHub Pages deploy helper with explicit confirmation, isolated temporary staging, argument-array Git execution, and cleanup in `finally`.

### Fixed

- SQL quoted strings, PostgreSQL dollar quotes, Oracle q-quotes, comments, and identifiers being corrupted by transformations.
- JavaScript strings, comments, object methods, and injection-context variants being altered incorrectly.
- PowerShell commands and transport-encoded CMDi inputs producing broken shell syntax.
- Encoding depth, Unicode, XML byte order, URL normalization, duplicate output, and selected-layer coverage regressions.
