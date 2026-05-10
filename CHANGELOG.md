# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project follows semantic versioning.

## [Unreleased]

## [0.2.0] - 2026-05-10

### Added

- `mcp-guard scan --all` discovery mode for known Cursor, VS Code, Claude Code, and Claude Desktop MCP config locations.
- `--client`, `--scope`, and `--list-targets` discovery options.
- Aggregate JSON output with `schemaVersion: "2"` and target metadata for every finding.
- Aggregate text output grouped by target and server.

### Changed

- Server normalization now preserves `headers`, `envFile`, and `type` fields from common MCP client configs.
- `MCPG001` now scans secret-like header keys in addition to environment variables.

## [0.1.0] - 2026-05-10

### Added

- Initial TypeScript CLI package scaffold using npm, Vitest, tsup, commander, jsonc-parser, zod, and picocolors.
- `mcp-guard scan <path>` command with text and JSON output.
- `--fail-on <level>`, `--quiet`, `--json`, and `--no-color` CLI options.
- Static MCP configuration loading with JSON and JSONC support.
- Server normalization for `mcpServers` and `servers` maps.
- Rule registry and scanner orchestration with summary risk calculation.
- JSON and text reporters with home-path redaction.
- GitHub Actions CI for Node.js 20 and 22 using npm.
- User-facing README with usage, rules, exit codes, limitations, and development commands.

### Rules

- `MCPG001`: secret-like environment variables.
- `MCPG002`: shell interpreters used as commands.
- `MCPG003`: dynamic package runners.
- `MCPG004`: plain HTTP transport.
- `MCPG005`: broad filesystem access.
- `MCPG006`: privileged container runtime arguments and socket/root mounts.
- `MCPG007`: suspicious shell pipelines and destructive shell patterns.
- `MCPG008`: public HTTPS remote endpoints.
- `MCPG009`: server entries missing both `command` and `url`.

### Security

- Environment variable values are not printed in findings.
- HTTP URL findings avoid leaking userinfo, query strings, and paths.
- CLI load errors redact the user's home path.
