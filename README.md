# strange_security

Centralized GitHub Actions security definitions for the
[`strangebasisdevs`](https://github.com/strangebasisdevs) organization.

This repository provides reusable workflows for consistent static analysis,
dependency vulnerability scanning, and secret detection across organization
repositories. Results are uploaded to GitHub code scanning as SARIF.

## Security checks

| Workflow | Checks | Behavior |
| --- | --- | --- |
| `semgrep.yml` | Static analysis using Semgrep's `p/default` ruleset | Generates and uploads SARIF results |
| `trivy.yml` | Filesystem vulnerabilities and secrets | Reports `HIGH` and `CRITICAL` findings, ignores unfixed vulnerabilities, and fails the job when findings are detected |

Both workflows run on `ubuntu-latest`, check out the caller repository, and
upload results even when a scan reports findings.

## Usage

Call the reusable workflows from jobs in a repository under
`strangebasisdevs`:

```yaml
name: Security gate

on:
  pull_request:
  push:
    branches:
      - main

permissions:
  contents: read
  security-events: write

jobs:
  semgrep:
    name: Semgrep
    uses: strangebasisdevs/strange_security/.github/workflows/semgrep.yml@main

  trivy:
    name: Trivy
    uses: strangebasisdevs/strange_security/.github/workflows/trivy.yml@main
```

The caller must grant `contents: read` so scans can check out its source and
`security-events: write` so results can be uploaded to GitHub code scanning.
The repository's [security gate](.github/workflows/security_gate.yml) uses this
same configuration to validate changes to the shared definitions.

## Workflow behavior

### Semgrep

Semgrep scans the caller's source with its default ruleset and writes findings
to the `semgrep` category in GitHub code scanning.

### Trivy

Trivy scans the caller's checked-out filesystem for:

- known dependency vulnerabilities
- secrets committed to the repository

Only `HIGH` and `CRITICAL` findings are reported. Unfixed vulnerabilities are
ignored. A reported finding fails the Trivy job, making it suitable as a pull
request security gate, while `if: always()` ensures the SARIF report is still
uploaded for review.

## Maintenance

Third-party actions are pinned to full commit SHAs to reduce supply-chain risk.
Dependabot checks GitHub Actions dependencies every Monday at 09:00 UTC and
opens updates with the `dependencies` and `github-actions` labels.

Changes to these workflows affect every repository that references `@main`.
Review and test updates in this repository before merging them to `main`.