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
| `trivy-images.yml` | The same checks on a list of images (`repo:tag`, `repo@sha256:...`), each in its own job | The same, decided by a fail-closed gate script; a non-empty exceptions file |

All of them run on `ubuntu-24.04`, check out the caller repository, and upload
their SARIF reports even when a scan fails the job.

Semgrep and the Trivy workflows also check out this repository into
`.strange-security`, at the exact commit the called workflow file came from, so
they can build the Dependabot-pinned scanner images in `scanner-images/` (and
`trivy-images.yml` can run its script from `scripts/`). The checkout is
excluded from the scans. The commit comes from `job.workflow_repository` and
`job.workflow_sha`, not from the `github` context, which in a called workflow
describes the caller.

## Usage

Call the reusable workflows from jobs in a repository under
`strangebasisdevs`. Releases and tags (`v1.0.0` and later) are cut from this
repository. Consumers pin the reusable workflows by full commit SHA with the
release in a comment, and Dependabot moves the pin. The examples below write
that as `@<40-hex-sha> # vX.Y.Z`: put the real commit SHA and release there.
Do not reference a branch or a tag in a real workflow.

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
    uses: strangebasisdevs/strange_security/.github/workflows/semgrep.yml@<40-hex-sha> # vX.Y.Z

  trivy:
    name: Trivy
    uses: strangebasisdevs/strange_security/.github/workflows/trivy.yml@<40-hex-sha> # vX.Y.Z

  gitleaks:
    name: Gitleaks
    uses: strangebasisdevs/strange_security/.github/workflows/gitleaks.yml@<40-hex-sha> # vX.Y.Z
```

Each reusable workflow declares a fixed `permissions` cap: `contents: read`,
`actions: read` and `security-events: write`. A called workflow can only keep
or reduce the token its caller grants, and it cannot make a permission depend
on an input, so every caller must grant all three to the calling job (or at the
top level of its workflow), also with `upload-sarif: false`. `packages` is not in
the cap: the scan job never holds `packages: read`, whatever the caller grants.

### Inputs

Every reusable workflow takes these two optional inputs:

| Input | Type | Default | Effect |
| --- | --- | --- | --- |
| `upload-sarif` | boolean | `true` | Upload the SARIF reports to code scanning. `false` skips every upload step; the caller still grants `security-events: write`, because the workflow's permissions cap requires it. Use it in private user repositories without code scanning. |
| `timeout-minutes` | number | `30` | Timeout of the scan job. The first step rejects anything but a whole number from 1 to 360 before any scan runs. |

`trivy-image.yml` adds `image`, `digest` (both required), `registry-login`
(boolean, default `false`) and the optional `registry-token` secret.
`trivy-images.yml` adds `images` (required), `exceptions-file`,
`registry-login` and the same secret. Both are described below.

A private repository without code scanning, with a longer timeout. The caller
still grants the full cap:

```yaml
permissions:
  actions: read
  contents: read
  security-events: write

jobs:
  semgrep:
    uses: strangebasisdevs/strange_security/.github/workflows/semgrep.yml@<40-hex-sha> # vX.Y.Z
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
    uses: strangebasisdevs/strange_security/.github/workflows/trivy-image.yml@<40-hex-sha> # vX.Y.Z
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

Public images need no login and no secret. For a private image, set
`registry-login: true` and pass a read-only package token as the optional
`registry-token` secret: a personal access token (classic) with `read:packages`. GitHub Packages
only supports authentication with a classic personal access token, so a
GitHub App installation token or a fine-grained token is not documented to
work. The workflow then runs
`docker login ghcr.io` as `github.actor` with that token, through stdin (no
third-party action), before it pulls. It fails with a clear error when
`registry-login` is `true` and the secret is empty. `GITHUB_TOKEN` is never
used for the registry: the permissions cap has no `packages`, so it could not
read a private package anyway.

```yaml
  scan:
    uses: strangebasisdevs/strange_security/.github/workflows/trivy-image.yml@<40-hex-sha> # vX.Y.Z
    with:
      image: ghcr.io/strangebasisdevs/private_app
      digest: ${{ needs.publish.outputs.digest }}
      registry-login: true
    secrets:
      registry-token: ${{ secrets.GHCR_READ_TOKEN }}
```

Pull requests from forks, and Dependabot-triggered runs, do not receive the
caller's secrets, so a private-image scan with `registry-login` fails there on
the empty secret rather than scanning anonymously.

Pull requests from forks get a read-only `GITHUB_TOKEN`, so the SARIF upload
steps fail there even when the scans pass. Do not work around this with
`pull_request_target` or `workflow_run`: both run with write access next to
untrusted code.

### Scanning several images

`trivy-images.yml` scans a list of published images and gates each one with a
fail-closed script, for repositories that ship or depend on images (a release
bundle, a compose stack, a base-image list). It does not replace
`trivy-image.yml`, which stays the tool for the push, scan, then tag flow.

| Input | Type | Default | Effect |
| --- | --- | --- | --- |
| `images` | string | required | One reference per line: `repo:tag`, `repo@sha256:...` or `repo:tag@sha256:...`. Prefer a digest: a tag can move. At most 20, each repository once (each gets its own code scanning category). Whitespace inside a reference, shell metacharacters, uppercase letters, an empty list or a reference with neither tag nor digest fail before any scan. |
| `exceptions-file` | string | `.github/image-exceptions.json` | Path of the exceptions file in the caller's repository. Exceptions are not supported yet (see below): a file that exists and is not empty fails the job. |
| `upload-sarif` | boolean | `true` | As for the other workflows. |
| `timeout-minutes` | number | `30` | Timeout of each image's scan job, validated 1 to 360 by the first step. |
| `registry-login` | boolean | `false` | Log in to `ghcr.io` with the `registry-token` secret before pulling. |

The optional `registry-token` secret is a read-only package token, used only
when `registry-login` is `true` (see above). Uppercase letters are rejected
only in the repository part of a reference; tags follow Docker's tag rules, so
`alpine:Latest` is accepted. A secret name cannot contain a hyphen, so
`registry-token` cannot come through `secrets: inherit` and must be mapped
explicitly, for example `registry-token: ${{ secrets.GHCR_READ_TOKEN }}`.

```yaml
jobs:
  images:
    name: Trivy images
    permissions:
      actions: read
      contents: read
      security-events: write
    uses: strangebasisdevs/strange_security/.github/workflows/trivy-images.yml@<40-hex-sha> # vX.Y.Z
    with:
      images: |
        gcr.io/distroless/static-debian12@sha256:<64-hex-digest>
        ghcr.io/strangebasisdevs/strange_ringtone:1.4.2@sha256:<64-hex-digest>
```

Each image runs in its own job, named `Trivy image scan (<repository>)`, after
a `Plan image scans` job that validates the inputs. A branch protection rule
that requires these checks must list the names the caller job prefixes, for
example `Trivy images / Trivy image scan (gcr.io/distroless/static-debian12)`.

Rollout notes for a consumer:

- Pin by SHA as above, and grant the calling job the full permissions cap,
  also with `upload-sarif: false`, which a private user repository without
  code scanning should set.
- Start from digests you have looked at. The gate is the same as for
  `trivy-image.yml`: any secret, or any `HIGH` or `CRITICAL` vulnerability with
  a fix, fails that image. Images that pass today can fail tomorrow when the
  Trivy database learns of a new fixable CVE; rebuild or bump the image.
- Public images need no `registry-login` and no secret. For private ones,
  create a read-only package token, store it as a secret in the caller and pass
  it as `registry-token`; see the `trivy-image.yml` section above.
- Do not commit an exceptions file yet. Until the exception engine release, a
  non-empty `exceptions-file` is an error, not an ignored file. An empty file,
  or none, is fine.

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

### Trivy images

`trivy-images.yml` builds the pinned Trivy image, pulls each listed image with
the runner's Docker daemon and runs two scans per image, both writing Trivy
JSON with `--exit-code 0`: secrets in the layers (every severity), and
vulnerabilities (every severity, nothing filtered). It then runs
`scripts/trivy_images.py gate` as `python3 -I` on the two reports, which is
what decides the job:

- it fails on any secret, and on any `HIGH` or `CRITICAL` vulnerability that
  has a fixed version (the findings `trivy-image.yml` fails on);
- it fails closed on a missing or malformed report and on an unexpected
  severity, instead of passing;
- it fails when the exceptions file exists and is not empty, with a message
  that exceptions are not supported until the engine release;
- it writes a step summary listing each failing image with its fixable
  vulnerabilities (package, installed and fixed version) and its secrets
  (rule, file and line; the matched text is never printed).

Unlike `trivy-image.yml`, Trivy runs in an empty working directory, so a
caller's `.trivyignore` and `trivy.yaml` do not apply: the exceptions file is
the only suppression path, and it is not available yet. With `upload-sarif`
true, a second pass writes a secret and a `HIGH`/`CRITICAL` fixable
vulnerability SARIF per image (the gate does not depend on it), uploaded to the
`trivy-images-secret/<repository>` and `trivy-images/<repository>` categories,
which differ from those of `trivy-image.yml` so the two cannot overwrite each
other.

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
  `packages`, the registry token as the only credential of the login steps, the
  gate exercising the opt-outs on the `trivy-image` and `trivy-images` jobs);
- `scripts/trivy_images.py` in `tests/test_trivy_images.py`: image list
  validation, the fail-closed gate on Trivy JSON fixtures, exceptions-file
  handling, summary safety, the CLI under `python3 -I`, and the wiring of
  `trivy-images.yml` (the real registry-login steps of both image workflows run
  under bash against a stub `docker`);
- that every `uses:` in `.github/workflows` is a full 40-hex SHA with a
  `# vX.Y.Z` comment (only the gate's local calls are exempt);
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

Changes to these workflows reach every repository that moves its pin to them
(or still references `@main`). Review and test updates in this repository
before merging them to `main`.

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
`gcr.io/distroless/static-debian12`, and `trivy-images.yml` on that image plus
`registry.k8s.io/pause:3.10@sha256:...` (tag and digest), also digest-pinned, so every reusable workflow runs on
every pull request, with `upload-sarif: false` and a non-default
`timeout-minutes` so those inputs run too, and with the full cap granted (no
`packages`). The images are not tied to `scanner-images/trivy.Dockerfile`;
refresh their digests in `security_gate.yml` by hand (the comment there gives
the date they were resolved), and pick another small public image if one gains
a fixable `HIGH` or `CRITICAL` finding.
