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

Each reusable workflow declares a fixed `permissions` cap: `contents: read`,
`actions: read` and `security-events: write`. A called workflow can only keep
or reduce the token its caller grants, and it cannot make a permission depend
on an input, so every caller must grant all three to the calling job (or at the
top level of its workflow), also with `upload-sarif: false`. `packages` is not in
the cap: the scan job never holds `packages: read`, whatever the caller grants.

Releases and tags (`v1.0.0` and later) are cut from this repository. Consumers
pin the reusable workflows by full commit SHA with the release in a comment,
for example `.../semgrep.yml@<40-hex-sha> # v1.0.0`, and Dependabot moves the
pin. The `@main` in the examples above is shorthand for that; do not reference
a branch or tag in a real workflow.

### Inputs

Every reusable workflow takes these two optional inputs:

| Input | Type | Default | Effect |
| --- | --- | --- | --- |
| `upload-sarif` | boolean | `true` | Upload the SARIF reports to code scanning. `false` skips every upload step; the caller still grants `security-events: write`, because the workflow's permissions cap requires it. Use it in private user repositories without code scanning. |
| `timeout-minutes` | number | `30` | Timeout of the scan job. The first step rejects anything but a whole number from 1 to 360 before any scan runs. |

`trivy-image.yml` adds `image`, `digest` (both required) and `registry-login`
(boolean, default `false`), described below.

A private repository without code scanning, with a longer timeout. The caller
still grants the full cap:

```yaml
permissions:
  actions: read
  contents: read
  security-events: write

jobs:
  semgrep:
    uses: strangebasisdevs/strange_security/.github/workflows/semgrep.yml@main
    with:
      upload-sarif: false
      timeout-minutes: 45
```

The scan still fails the job on findings; only the upload is skipped.

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
      security-events: write
    uses: strangebasisdevs/strange_security/.github/workflows/trivy-image.yml@main
    with:
      image: ghcr.io/strangebasisdevs/strange_ringtone
      digest: ${{ needs.publish.outputs.digest }}

  tag:
    needs: [publish, scan]
    # ... tags the digest only after the scan job succeeded
```

The job is named `Trivy image scan`. The workflow scans exactly
`image@digest` and rejects an `image` that carries a tag or digest, or a
`digest` that is not `sha256:` plus 64 hex characters.

Public images need no login. For a private image, `registry-login: true` makes
the workflow run `docker login ghcr.io` as `github.actor` with the caller's
`GITHUB_TOKEN` (through stdin, not a third-party action; no secrets are
passed). Limitation: the workflow's permissions cap has no `packages: read`, so
that token cannot read private GHCR packages and the pull of a private image
fails, even if the caller grants `packages: read`. The login step is kept and
gated on the input, but it only helps where the token can already pull the
image, for example a package that is public or linked to a repository the
token can read. Until the owner decides on another credential, scan private
images by a route that does not need this workflow to authenticate.

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
scan fails, so both reports are uploaded (unless `upload-sarif` is `false`).

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
- the suppression check in `scripts/check_suppressions.py`, including which
  comment markers count for which file extensions;
- the `timeout-minutes` validation step of every reusable workflow, extracted
  and run under bash, and the `upload-sarif`, `timeout-minutes` and
  `registry-login` wiring in `tests/test_inputs.py` (inputs and defaults, every
  upload step conditional, the exact permissions cap in every workflow without
  `packages`, the gate exercising the opt-outs on the `trivy-image` job only);
- the structure of the workflow files in `tests/test_workflows.py` (checker
  step ordering, SARIF written to a dedicated directory outside the workspace
  with the source mounted read-only, conditional registry login,
  reusable-workflow detection checked per line and against a real `grep -E`
  when one is installed, digest-pinned gate image).

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
`github.workflow_*` context, checks out `.strange-security` without
`job.workflow_repository` and `job.workflow_sha`, lacks the permissions cap
(exactly `actions: read` and `contents: read`, plus `security-events: write`
where it uploads SARIF), declares `packages` or any other permission, or has a
second, job-level `permissions` block.

The gate also calls `trivy-image.yml` on the digest-pinned public image
`gcr.io/distroless/static-debian12`, so every reusable workflow runs on every
pull request, with `upload-sarif: false` and a non-default `timeout-minutes`
so those inputs run too, and with the full cap granted (no `packages`). That
image is not tied to `scanner-images/trivy.Dockerfile`;
refresh its digest in `security_gate.yml` by hand.
