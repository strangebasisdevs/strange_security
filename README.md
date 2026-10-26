# strange_security

Centralized GitHub Actions security definitions for the
[`strangebasisdevs`](https://github.com/strangebasisdevs) organization.

This repository provides reusable workflows for consistent static analysis,
dependency vulnerability scanning, and secret detection across organization
repositories. Results are uploaded to GitHub code scanning as SARIF.

## Security checks

| Workflow | Checks | Fails the job on |
| --- | --- | --- |
| `semgrep.yml` | Static analysis using Semgrep's `p/default` ruleset | Any finding |
| `trivy.yml` | Secrets in the working tree, and filesystem dependency vulnerabilities | Any secret, at any severity; `HIGH` or `CRITICAL` vulnerabilities that have a fix |
| `gitleaks.yml` | Secrets anywhere in the git history | Any finding |
| `trivy-image.yml` | Secrets and OS/package vulnerabilities in one container image, by digest | Any secret, at any severity; `HIGH` or `CRITICAL` vulnerabilities that have a fix |

All of them run on `ubuntu-24.04`, check out the caller repository, and upload
their SARIF reports even when a scan fails the job.

Semgrep and Trivy also check out this repository into `.strange-security`, at
the exact commit the called workflow file came from, so they can build the
Dependabot-pinned scanner images in `scanner-images/`. The checkout is
excluded from the scans. The commit comes from `job.workflow_repository` and
`job.workflow_sha`, not from the `github` context, which in a called workflow
describes the caller.

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
  actions: read
  contents: read
  security-events: write

jobs:
  semgrep:
    name: Semgrep
    uses: strangebasisdevs/strange_security/.github/workflows/semgrep.yml@main

  trivy:
    name: Trivy
    uses: strangebasisdevs/strange_security/.github/workflows/trivy.yml@main

  gitleaks:
    name: Gitleaks
    uses: strangebasisdevs/strange_security/.github/workflows/gitleaks.yml@main
```

The caller must grant `contents: read` so scans can check out its source and
`security-events: write` so results can be uploaded to GitHub code scanning.
Releases and tags (`v1.0.0` and later) are cut from this repository. Consumers
pin the reusable workflows by full commit SHA with the release in a comment,
for example `.../semgrep.yml@<40-hex-sha> # v1.0.0`, and Dependabot moves the
pin. The `@main` in the examples above is shorthand for that; do not reference
a branch or tag in a real workflow.

### Scanning a container image

`trivy-image.yml` scans one published image, addressed by digest. It is meant
for release workflows: push the image untagged, scan it, and tag it only when
the scan passes. Pass the image reference without a tag, and the digest that
the push returned:

```yaml
jobs:
  publish:
    # ... builds and pushes the image untagged, then exposes its digest
    outputs:
      digest: ${{ steps.push.outputs.digest }}

  scan:
    name: Trivy image
    needs: publish
    permissions:
      actions: read
      contents: read
      packages: read
      security-events: write
    uses: strangebasisdevs/strange_security/.github/workflows/trivy-image.yml@main
    with:
      image: ghcr.io/strangebasisdevs/strange_ringtone
      digest: ${{ needs.publish.outputs.digest }}
      registry-login: true # only for a private image

  tag:
    needs: [publish, scan]
    # ... tags the digest only after the scan job succeeded
```

The job is named `Trivy image scan`. The workflow scans exactly
`image@digest` and rejects an `image` that carries a tag or digest, or a
`digest` that is not `sha256:` plus 64 hex characters. Public images
need no login. For a private image pass `registry-login: true`: the workflow
then runs `docker login ghcr.io` as `github.actor` with the caller's
`GITHUB_TOKEN` (through stdin, not a third-party action), so the caller must
also grant `packages: read`; no secrets are passed. That covers private images
in the same organisation, provided the calling repository has read access to
the package.

Pull requests from forks get a read-only `GITHUB_TOKEN`, so the SARIF upload
steps fail there even when the scans pass. Do not work around this with
`pull_request_target` or `workflow_run`: both run with write access next to
untrusted code.

## Workflow behavior

### Semgrep

Semgrep scans the caller's source with its default ruleset and writes findings
to the `semgrep` category in GitHub code scanning. It runs with `--error`, so
any finding fails the job.

### Trivy

Trivy runs two scans over the caller's checked-out filesystem:

- **Secrets**, at every severity, uploaded to the `trivy-secret` category.
  Severity is not filtered because some built-in secret rules rate below
  `HIGH`, and any committed secret should fail the gate.
- **Dependency vulnerabilities**, `HIGH` and `CRITICAL` only, ignoring those
  without a fix, uploaded to the `trivy` category.

Either scan fails the job. The vulnerability scan still runs when the secret
scan fails, so both reports are uploaded.

### Trivy image

Trivy image runs the same two scans as Trivy, against the image instead of
the working tree:

- **Secrets** in the image layers, at every severity, uploaded to the
  `trivy-image-secret/<image>` category.
- **Vulnerabilities** in OS packages and language dependencies, `HIGH` and
  `CRITICAL` only, ignoring those without a fix, uploaded to the
  `trivy-image/<image>` category.

Either scan fails the job, and both reports are uploaded either way. The
categories include the image name, so a caller that scans several images
keeps a separate code scanning result for each. The runner's Docker daemon
pulls the image (after logging in, if asked to), and Trivy reads it through the Docker
socket, so the registry credentials never enter the Trivy container. The
caller's `.trivyignore` and `trivy.yaml` apply, as for the filesystem scan.

### Gitleaks

Gitleaks checks out the caller with full history (`fetch-depth: 0`) and scans
every commit, so a secret that was committed and later deleted still fails the
job. Merge commits are diffed against each parent (`git log -m`), so a secret
added while resolving a conflict is caught too, though a secret merged in from
a branch can be reported twice. Findings are redacted in the log and uploaded to the `gitleaks` category.
A finding means the credential is already public: rotate it first.

It uses the gitleaks release binary, checked against its published sha256,
rather than the gitleaks GitHub Action.

### Suppressions

The policy is in [docs/SUPPRESSIONS.md](docs/SUPPRESSIONS.md): inline
`nosemgrep: <rule-id>` with a reason line above, never for Trivy or gitleaks.
Semgrep fails on a bare suppression or one without a reason (the
`Check Semgrep suppressions` step runs `scripts/check_suppressions.py` on the
caller's code). Repositories point their `CLAUDE.md` at that file rather than
restating it.

The scanners read suppressions from the caller's repository: `.semgrepignore`
and `nosemgrep` comments, `.trivyignore` and `trivy.yaml`, and `.gitleaks.toml`
and `.gitleaksignore`. A pull request that adds or changes one of these can
silence a finding, so review those files as security-relevant.

## Tests

`python3 -m unittest discover --start-directory tests` runs the standard-library
unit tests, and the `Unit tests` job in the security gate runs them on every
pull request. They cover:

- the image and digest validation in `trivy-image.yml`, by extracting the real
  step and running it under bash, including multiline inputs;
- the suppression check in `scripts/check_suppressions.py`.

## Maintenance

Third-party actions are pinned to full commit SHAs, and scanner container
images are pinned to immutable digests, to reduce supply-chain risk. Dependabot
checks the GitHub Actions pins in `.github/workflows` and the image pins in
`scanner-images` every Monday at 09:00 UTC, with a seven-day cooldown on new
releases. Dependabot does not track the gitleaks binary in `gitleaks.yml`;
update its version and sha256 together by hand.

Changes to these workflows affect every repository that references `@main`.
Review and test updates in this repository before merging them to `main`.

The repository's [security gate](.github/workflows/security_gate.yml) calls the
workflows locally (`./.github/workflows/...`), where the caller and the called
workflow share one repository. That hides any mix-up between the two, so its
`contract` job also fails if a reusable workflow reads the caller's
`github.workflow_*` context or checks out `.strange-security` without
`job.workflow_repository` and `job.workflow_sha`.

The gate also calls `trivy-image.yml` on the public Trivy scanner image pinned
in `scanner-images/trivy.Dockerfile`, so every reusable workflow runs on every
pull request. Update that image and digest in `security_gate.yml` together with
the Dockerfile.
