# strange_security

Centralized GitHub Actions security definitions for the
[`strangebasisdevs`](https://github.com/strangebasisdevs) organization.

This repository provides a consistent security baseline that organization
repositories can consume instead of maintaining separate scanner
configurations. Results are uploaded to GitHub code scanning as SARIF.

## Security checks

| Workflow | Coverage | Enforcement |
| --- | --- | --- |
| [Semgrep](workflows/semgrep.yml) | Static analysis using Semgrep's `p/default` ruleset | Findings are uploaded to code scanning |
| [Trivy](workflows/trivy.yml) | Filesystem scan for vulnerabilities and secrets | Fails on `HIGH` or `CRITICAL` findings; ignores unfixed vulnerabilities |

Both workflows run on `ubuntu-latest`, check out the calling repository, and
upload SARIF even when a scan reports findings. Third-party actions are pinned
to full commit SHAs.

## Usage

Add a workflow such as `.github/workflows/security_gate.yml` to a consuming
repository:

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

The repository includes [`.github/security_gate.yml`](.github/security_gate.yml)
as the current combined gate definition. It runs both scans for pull requests
and pushes to `main`.

> [!IMPORTANT]
> GitHub requires reusable workflows to be stored in `.github/workflows`.
> The reusable definitions currently live in `workflows/`, so they must be
> moved to `.github/workflows` before the example above can be consumed by
> other repositories. The combined gate must likewise be placed under
> `.github/workflows` in any repository where it should run.

For stronger supply-chain guarantees, consumers can replace `@main` with a
release tag or commit SHA after versions are published.

## Permissions and repository settings

The workflows request only:

- `contents: read` to check out source code
- `security-events: write` to upload SARIF results

GitHub code scanning must be available and enabled in the consuming repository
for results to appear under **Security > Code scanning**. Pull requests from
forks may not receive `security-events: write` because GitHub restricts token
permissions for untrusted contributions.

## Maintenance

[Dependabot](.github/dependabot.yml) checks GitHub Actions dependencies every
Monday at 09:00 UTC. It opens up to 10 pull requests at a time and applies the
`dependencies` and `github-actions` labels.

When updating pinned actions, preserve full commit SHAs and update the adjacent
version comments so the reviewed release remains visible.
