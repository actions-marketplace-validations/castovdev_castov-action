<p align="center">
  <a href="https://www.castov.com">
    <img src="./assets/castov-logo-horizontal.png" alt="Castov" width="260" />
  </a>
</p>

# Castov AI & MCP Security Audit

Deterministic, zero-network security audit (`CAS-001`–`CAS-016`) for Model Context Protocol (MCP) servers, AI agent configurations (`.mcp.json`, Claude Desktop, Cursor, Windsurf, Cline, `.claude/settings.json`), and leaked secrets in GitHub Actions (`runs.using: node24`).

Powered by [`@castovcom/core`](https://www.npmjs.com/package/@castovcom/core) — identical rule engine and secret masking to the `castov` CLI.

---

## Quick Start (`push` & `pull_request`)

```yaml
name: Castov Security Audit

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  castov:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Castov AI & MCP Security Audit
        id: castov
        uses: castovdev/castov-action@v2
        with:
          path: "."
          format: "sarif"
          report-file: "castov-results.sarif"
          fail-on: "high"

      - name: Upload SARIF to GitHub Code Scanning
        if: always() && github.event.pull_request.head.repo.fork != true
        continue-on-error: true
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ steps.castov.outputs.sarif-file || steps.castov.outputs.report-file }}
          category: "castov-mcp-audit"
```

---

## Least-Privilege Permissions Matrix

| Feature | Required `permissions` | Notes |
| :--- | :--- | :--- |
| Audit + Annotations + Step Summary | `contents: read` | Default minimum permission |
| SARIF Upload to Code Scanning | `security-events: write` | Guard with `github.event.pull_request.head.repo.fork != true` on public fork PRs |
| PR Summary Comment (`comment-on-pr: "true"`) | `pull-requests: write` | Opt-in (`false` by default); degrades gracefully with a warning on `403`/`404`/`429` |

---

## Inputs

| Input | Default | Description |
| :--- | :--- | :--- |
| `path` | `"."` | Target directory to audit relative to `GITHUB_WORKSPACE` |
| `format` | `"sarif"` | Primary report format written to `report-file` (`sarif` \| `json` \| `md` \| `text`) |
| `fail-on` | `"high"` | Minimum severity to fail the workflow (`critical` \| `high` \| `medium` \| `low` \| `none`) |
| `fail-on-incomplete` | `"true"` | Fail if discovery caps or filesystem skips make the scan incomplete (`true` \| `false`) |
| `baseline` | `""` | Optional workspace-relative path to a Castov baseline JSON file |
| `ignore-rules` | `""` | Comma-separated list of rule IDs to ignore (e.g. `CAS-002,CAS-014`) |
| `report-file` | `"castov-results.sarif"` | Output path for the generated report relative to `GITHUB_WORKSPACE` |
| `sarif-file` | `""` | Optional path to always emit a SARIF 2.1.0 report alongside `format` |
| `annotations` | `"true"` | Emit GitHub workflow annotations (`::error` / `::warning` / `::notice`) |
| `summary` | `"true"` | Write Markdown audit summary to `GITHUB_STEP_SUMMARY` |
| `comment-on-pr` | `"false"` | Post or update a data-minimized PR summary comment when `pull-requests: write` is granted |
| `github-token` | `${{ github.token }}` | GitHub token used only when `comment-on-pr` is enabled |

---

## Outputs

| Output | Description |
| :--- | :--- |
| `audit-status` | Audit completion status (`complete` \| `incomplete` \| `failed`) |
| `exit-code` | Audit exit code (`0` = passed, `1` = failed) |
| `findings-count` | Total findings count |
| `critical-count` | Critical findings count |
| `high-count` | High findings count |
| `skipped-files-count` | Number of files or directories skipped during discovery |
| `report-file` | Workspace-relative path to the generated report file |
| `sarif-file` | Workspace-relative path to the SARIF file if generated |

---

## Advanced Usage

### Baseline Suppression & Ignored Rules

```yaml
- uses: castovdev/castov-action@v2
  with:
    baseline: ".castov-baseline.json"
    ignore-rules: "CAS-002,CAS-014"
    fail-on: "high"
```

### Dual Report Output + PR Comment

```yaml
permissions:
  contents: read
  pull-requests: write
  security-events: write

steps:
  - uses: actions/checkout@v4
  - uses: castovdev/castov-action@v2
    with:
      format: "md"
      report-file: "reports/castov.md"
      sarif-file: "reports/castov.sarif"
      comment-on-pr: "true"
```

---

## Audit Status & Exit-Code Precedence

- `audit-status`: `"complete" | "incomplete" | "failed"`
- Incomplete scans (caused by depth, file-count, or byte-size limits, permission errors, or skipped symlinks) are **never** reported as clean and fail closed (`exit-code = 1`) unless `fail-on-incomplete: "false"` is explicitly set.
- `fail-on-incomplete: "false"` **never** overrides genuine findings that meet the `fail-on` severity threshold.

---

## Security & Privacy Guarantees

- **Zero-network audit engine**: All scanning runs statically and locally inside `GITHUB_WORKSPACE`; audited MCP server commands are never executed.
- **Strict secret masking**: Raw secret values never appear in workflow annotations, `GITHUB_STEP_SUMMARY`, SARIF/JSON/Markdown reports, or PR comments.
- **Symlink & path-traversal protection**: Symbolic links are never followed or overwritten; all report writes use atomic sibling staging and roll back newly created outputs on failure.
- **Data-minimized PR comments**: `comment-on-pr` emits only severity counts, rule IDs, sanitized relative paths, and static rule descriptions.

---

## Migrating from `v1` (`v1.0.0`) to `v2` (`v2.0.0`)

`v2.0.0` is a major, breaking upgrade from `v1.0.0` (`castovdev/castov-action@v1` remains available and unchanged for existing workflows).

### Breaking Changes in `v2`

1. **Runtime (`composite` -> native `node24`)**: `v1` used a composite shell step with Node 20 and `npx castov@1.3.3`. `v2` runs natively on `node24` via a self-contained `dist/index.cjs` bundle powered by `@castovcom/core` with zero network calls.
2. **Removed inputs (`command`, `args`)**: `v2` is dedicated to deterministic security auditing (`CAS-001`–`CAS-016`) and no longer accepts `command` or `args`. Workflows running CLI utilities like `cidr` or `rules` should stay on `castovdev/castov-action@v1` or invoke `npx castov@1.7.1` directly.
3. **New 12 inputs & 8 outputs**: Replace `args` with `path` (default `"."`), and configure `format`, `fail-on`, `fail-on-incomplete`, `baseline`, `ignore-rules`, `report-file`, `sarif-file`, `annotations`, `summary`, `comment-on-pr`, and `github-token`. `v2` also exposes 8 structured outputs (`audit-status`, `exit-code`, `findings-count`, `critical-count`, `high-count`, `skipped-files-count`, `report-file`, `sarif-file`).
4. **Reports, annotations & fail-closed exit codes**: `v2` writes `castov-results.sarif` (`sarif` 2.1.0) by default, emits workflow annotations and `GITHUB_STEP_SUMMARY`, and fails closed (`exit-code = 1`) when `fail-on` (default `"high"`) is met or when a scan is `incomplete` (unless `fail-on-incomplete: "false"`).

### Example Upgrade

```yaml
# Before (v1)
- uses: castovdev/castov-action@v1
  with:
    command: "scan"
    args: "."

# After (v2)
- uses: castovdev/castov-action@v2
  with:
    path: "."
    format: "sarif"
    fail-on: "high"
```

---

## License

[MIT](./LICENSE) — Copyright (c) 2026 Castov (https://www.castov.com)
