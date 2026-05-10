# mcp-guard

Security scanner for MCP servers and configurations.

mcp-guard helps developers inspect MCP servers and MCP client configuration files before connecting them to AI coding tools, agents, or local development environments. It highlights risky permissions, shell commands, remote endpoints, container settings, and secret-like environment variables.

Part of Nestarc Labs experimental open-source tools for safer backend and AI-assisted development workflows.

## Status

v0.2.0 pre-release. This project is not yet published to npm.

## Why

MCP servers can expose local files, environment variables, shell commands, network endpoints, containers, and external services. mcp-guard performs static checks to highlight potentially risky configuration before use.

It is a static scanner. It does not execute the server and does not make network calls.

## Install

After the package is published:

```bash
npm install -g @nestarc/mcp-guard
```

Or run directly:

```bash
npx @nestarc/mcp-guard scan ./mcp.json
```

## Usage

```bash
mcp-guard scan ./mcp.json
mcp-guard scan ./mcp.json --json
mcp-guard scan ./mcp.json --fail-on high
mcp-guard scan ./mcp.json --quiet --no-color
mcp-guard scan --all
mcp-guard scan --all --client cursor
mcp-guard scan --all --scope project
mcp-guard scan --all --list-targets
```

## Discovery Mode

`mcp-guard scan --all` scans known common MCP configuration locations for the current project and user profile. Discovery is conservative: missing files are ignored, files are never executed, and only readable local config files are scanned.

| Client | Scope | Location |
| --- | --- | --- |
| Cursor | Project | `.cursor/mcp.json` |
| Cursor | User | `~/.cursor/mcp.json` |
| VS Code | Project | `.vscode/mcp.json` |
| VS Code | User | Platform-specific VS Code user profile MCP config |
| Claude Code | Project | `.mcp.json` |
| Claude Code | User | `~/.claude.json` |
| Claude Desktop | User | Platform-specific Claude app config directory |

Discovery covers known common locations, not every possible client-specific storage path.

### Options

| Option | Description |
| --- | --- |
| `--json` | Output machine-readable JSON. |
| `--fail-on <level>` | Exit with code 1 when any finding reaches the given severity: `info`, `low`, `medium`, `high`, or `critical`. |
| `--no-color` | Disable colored terminal output. mcp-guard also respects `NO_COLOR`. |
| `--quiet` | Print only the summary in text mode. |
| `--all` | Discover and scan known MCP configuration files instead of scanning one explicit path. |
| `--client <name>` | Limit discovery to one client: `cursor`, `vscode`, `claude-code`, or `claude-desktop`. Requires `--all`. |
| `--scope <scope>` | Limit discovery to `project`, `user`, or `all`. Defaults to `all`. Requires `--all`. |
| `--list-targets` | Print discovered targets and exit without scanning. Requires `--all`. |

### Exit Codes

| Code | Meaning |
| --- | --- |
| 0 | Scan completed, and no finding reached the `--fail-on` threshold. |
| 1 | Scan completed, and at least one finding reached the `--fail-on` threshold. |
| 2 | Invalid input, parse error, missing file, CLI usage error, or unexpected scanner error. |

Without `--fail-on`, findings are reported but do not make the command fail.

## Rules

| Rule | Severity | What it checks |
| --- | --- | --- |
| `MCPG001` | High, or medium for placeholder, empty, or short values | Secret-like environment variables and headers such as `TOKEN`, `SECRET`, `PASSWORD`, `PASSWD`, `API_KEY`, `APIKEY`, `PRIVATE_KEY`, `CREDENTIAL`, `ACCESS_KEY`, `AUTHORIZATION`, `COOKIE`, `X-API-KEY`, `AWS_*`, `GCP_*`, `GOOGLE_*`, `AZURE_*`, `OPENAI_*`, `ANTHROPIC_*`, `GITHUB_TOKEN`, and `GITLAB_TOKEN`. Values are never printed. |
| `MCPG002` | High | Shell interpreters used as commands, including `bash`, `sh`, `zsh`, `fish`, `dash`, `ksh`, `cmd`, `powershell`, and `pwsh`. |
| `MCPG003` | Medium | Dynamic package runners such as `npx`, `pnpx`, `bunx`, `uvx`, and package-manager `dlx` commands. |
| `MCPG004` | Medium | Plain HTTP transport. |
| `MCPG005` | High | Broad filesystem access such as `/`, `~`, `/Users`, `/home`, drive roots, home directories, and parent traversal. |
| `MCPG006` | High | Container runtime arguments that grant elevated host access, including `--privileged`, Docker socket mounts, and host root mounts. |
| `MCPG007` | Critical | Suspicious shell patterns such as `curl | sh`, `wget | bash`, `rm -rf`, and `chmod +x`. |
| `MCPG008` | Low | Public HTTPS remote endpoints. |
| `MCPG009` | Info | Server entries missing both `command` and `url`. |

## Limitations

mcp-guard is a static scanner. It does not certify an MCP server as safe, execute the server during scans, inspect fetched packages, or verify remote services. False positives and false negatives are possible. Always review findings in context before deciding whether to trust a server.

## CI

Use an explicit file path when your repository stores MCP config in a known location:

```bash
npx @nestarc/mcp-guard scan ./.cursor/mcp.json --fail-on high
```

Use discovery mode when the CI workspace may contain one of several known project-level MCP config files:

```bash
npx @nestarc/mcp-guard scan --all --scope project --fail-on high
```

Single-file JSON output uses `schemaVersion: "1"`. Discovery JSON output uses `schemaVersion: "2"` and includes target metadata on every finding.

## Development

Requires Node.js 20+.

```bash
npm install
npm test
npm run build
npm run dev -- scan test/fixtures/risky.json
```

For clean installs in CI or a fresh checkout with an existing lockfile, use:

```bash
npm ci
```

## Release

Releases are published to npm from GitHub Actions when a GitHub Release is published.

Before the first release, configure npm Trusted Publishing for `@nestarc/mcp-guard` with:

| Field | Value |
| --- | --- |
| Repository | `nestarc/mcp-guard` |
| Workflow filename | `release.yml` |

To publish a release:

```bash
npm version patch
git push --follow-tags
```

Then create and publish a GitHub Release for the version tag, such as `v0.1.0`.

The release workflow runs `npm ci`, `npm run typecheck`, `npm test`, `npm run build`, and `npm pack --dry-run`, then publishes with provenance using `npm publish --access public --provenance`.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for notable changes.

## License

Apache-2.0
