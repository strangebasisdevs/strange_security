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
| `trivy-images.yml` | The same checks on a list of images (`repo:tag`, `repo@sha256:...`), each in its own job | The same, decided by a fail-closed gate script, unless a [reviewed, digest-bound, expiring exception](docs/IMAGE_EXCEPTIONS.md) covers the vulnerability (never a secret), or a [reviewed, digest-bound, expiring allowlist entry](#image-secret-allowlist) covers that one known-public secret finding (never a vulnerability); an expired entry in either file; an invalid exceptions or allowlist file |

All of them run on `ubuntu-24.04`, check out the caller repository, and upload
their SARIF reports even when a scan fails the job.

Semgrep and the Trivy workflows also check out this repository into
`.strange-security`, at the exact commit the called workflow file came from, so
they can build the Dependabot-pinned scanner images in `scanner-images/` (and
`trivy-images.yml` can run its script from `scripts/`). The checkout is
excluded from the scans. The commit comes from `job.workflow_repository` and
`job.workflow_sha`, not from the `github` context, which in a called workflow
describes the caller.

**The caller repository must not contain a `.strange-security` path** of any
kind, at any depth: no file, directory or symlink (dangling or not), in the
workspace root or in any subdirectory (`src/.strange-security/` counts). The
top-level `.git` directory is the only place not searched. `actions/checkout`
follows a symlink at its target path, and empties an existing directory that
has no `.git` before cloning into it. A committed `.strange-security -> sub`
would therefore send the shared checkout into the caller's own `sub/`, wipe
it, and leave a genuine-looking checkout there, while the scans exclude
`.strange-security` and so would scan the shared repository instead of `sub/`.
A real caller directory of that name would be wiped and excluded the same way,
never scanned. The depth rule exists because Semgrep's `--exclude` is
gitignore-style and unanchored: `--exclude .strange-security` also skips a
nested `src/.strange-security/handler.py`, so a caller directory of that name
anywhere in the tree would silently never be scanned by Semgrep. (Trivy's
`--skip-dirs` is relative to the scan root and does not have this problem, but
the rule is the same everywhere.) Each of these workflows therefore refuses
such a path, found by a `find` that does not follow symlinks, in a step
before the shared checkout; if that search itself fails (for example an
unreadable directory) the step fails too, since nothing can then be ruled out.
The job fails with an error naming up to 20 offending paths
(`gitleaks.yml` instead skips its findings report with a warning, because its
history scan does not need the shared checkout and still decides the job
alone). The verify step then also requires that `.strange-security` is not a
symlink, that its physical path is `<workspace>/.strange-security`, and that
it is the root of its own git repository (not a directory inside another
one), on top of being at the expected commit. Rename or remove the path if a
workflow of yours trips on it; the scans keep excluding `.strange-security`,
which after the checkout is the only path of that name in the tree and holds
the verified shared checkout.

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
| `upload-sarif` | boolean | `true` | Upload the SARIF reports to code scanning. `false` skips every upload step (the [findings report](#findings-report) still lists the findings); the caller still grants `security-events: write`, because the workflow's permissions cap requires it. Use it in private user repositories without code scanning. |
| `timeout-minutes` | number | `30` | Timeout of the scan job. The first step rejects anything but a whole number from 1 to 360 before any scan runs. |

`trivy-image.yml` adds `image`, `digest` (both required), `registry-login`
(boolean, default `false`) and the optional `registry-token` secret.
`trivy-images.yml` adds `images` (required), `exceptions-file`,
`secret-allowlist-file`, `registry-login` and the same secret. Both are
described below.

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
| `exceptions-file` | string | `.github/image-exceptions.json` | Path of the exceptions file in the caller's repository ([schema and process](#image-exceptions)). A missing file means no exceptions; a file that exists but is not valid fails the job. |
| `secret-allowlist-file` | string | `.github/image-secret-allowlist.json` | Path of the secret allowlist file in the caller's repository ([schema and process](#image-secret-allowlist)), a different file with a different schema than `exceptions-file`. A missing file means no allowlist; a file that exists but is not valid fails the job. |
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
- Without an exceptions file nothing is excepted, and that is the default. If
  an image cannot be fixed yet, add exceptions as described under
  [Image exceptions](#image-exceptions). A file that exists must be valid, an
  empty file included, or the job fails. List the image with its digest, or no
  exception can apply to it.
- A secret in an image layer fails the image, as before. Only a value that is
  public by design (a documented emulator key, for example) can be allowed, one
  finding at a time, through the separate
  [secret allowlist](#image-secret-allowlist). Without that file nothing
  changes for you. Rotate the value first if it is a real credential.

### Image exceptions

An exception lets `trivy-images.yml` pass a fixable `HIGH` or `CRITICAL`
vulnerability that cannot be fixed yet. It is for `trivy-images.yml` image
vulnerabilities only: never a secret (a known-public secret has its own
[allowlist](#image-secret-allowlist)), and never a filesystem (`trivy.yml`),
gitleaks, Semgrep or `trivy-image.yml` finding. The process (who reviews, the
monthly cadence, checking for a patched release, deleting stale entries and the
renew pull request) is written once, in
[docs/IMAGE_EXCEPTIONS.md](docs/IMAGE_EXCEPTIONS.md).

`exceptions-file` (default `.github/image-exceptions.json`) is JSON with exactly
one top-level key:

```json
{
  "exceptions": [
    {
      "image": "ghcr.io/example/app",
      "digest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      "id": "CVE-2026-0001",
      "package": "libfoo",
      "reason": "The vendor has not rebuilt the image on the fixed libfoo yet",
      "reviewer": "Your Name",
      "reviewed": "2026-11-03",
      "expires": "2026-12-03",
      "tracking": "https://github.com/example/app/issues/123"
    }
  ]
}
```

| Field | Required | Rule |
| --- | --- | --- |
| `image` | yes | The repository of the `images` line, without tag or digest, exactly as written there and lowercase (`ghcr.io/example/app`, `nextcloud`). |
| `digest` | yes | `sha256:` and 64 lowercase hex characters. The entry applies only to the image scanned at this digest, so the `images` line must carry it. A tag, `latest` or an image listed by tag alone cannot be excepted. |
| `id` | yes | The vulnerability id (`CVE-...`, `GHSA-...`, `GO-...`). A secret rule id is refused. |
| `package` | yes | The package name Trivy reports. |
| `reason` | yes | One line, 10 to 300 characters: why it is acceptable now. |
| `reviewer` | yes | The person who reviewed it, never a bot or an agent. |
| `reviewed` | yes | `YYYY-MM-DD` (UTC), not after today. |
| `expires` | yes | `YYYY-MM-DD`, on or after `reviewed` and at most 31 days after it. The last day it is live. |
| `tracking` | no | An `https://` link to the upstream issue or advisory. |

Any other field is refused, so are duplicate keys, wildcards (`*`, `?`, `[`,
`{`) in `image`, `digest`, `id` and `package`, duplicate entries and a field that
names a secret (`secret`, `rule`, `RuleID`). A file that breaks any rule fails
every image job; it is never partly applied. The gate excepts a finding only
when the image, digest, id and package are all equal and the entry has not
expired, and the Trivy report lists that digest. An entry that is expired fails
the job (renew or delete it); a live entry that matches nothing is a warning
(delete it). The step summary lists the excepted findings with their expiry,
reviewer and reason, the stale entries as warnings, and the failing findings.

`python3 -I scripts/image_exceptions.py validate FILE` checks a file, and
`python3 -I scripts/image_exceptions.py generate --scan REF REPORT ...` writes a
draft of entries from Trivy JSON reports for a person to review (see the
process document). The draft has no reason, and no reviewer or date unless you
give them; it does not validate until a person completes it, and the command
never overwrites a file.

### Image secret allowlist

A secret found in an image layer fails `trivy-images.yml` at any severity, and
a vulnerability exception can never cover it. The one way to let such a finding
pass is a secret allowlist entry, for a value that is **public by design**: a
documented emulator or test key, vendored in a third-party library, that opens
nothing. The motivating case is the public development storage key of the Azurite
emulator, which the Nextcloud image carries in a vendored Azure library and Trivy
reports as `azure-storage-account-key`. If the value is, or might be, a real
credential, rotate it first and rebuild the image; it never belongs in this file.
The process (what the reviewer checks, the monthly cadence, stale entries) is in
[docs/IMAGE_EXCEPTIONS.md](docs/IMAGE_EXCEPTIONS.md#known-public-secrets-the-secret-allowlist).

`secret-allowlist-file` (default `.github/image-secret-allowlist.json`) is a
different file from `exceptions-file`, with its own schema and its own
commands, and each file is refused where the other is expected. It is JSON with
exactly one top-level key (the digests below are placeholders; `generate-secrets`
writes the real ones from your scan):

```json
{
  "allowlist": [
    {
      "image": "nextcloud",
      "digest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      "rule": "azure-storage-account-key",
      "target": "var/www/html/3rdparty/microsoft/azure-storage-common/src/Common/Internal/Resources.php",
      "layer_diff_id": "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
      "start_line": 123,
      "match_sha256": "sha256:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
      "reason": "The documented Azurite emulator development key, public in the Microsoft docs; not a credential",
      "evidence": "https://learn.microsoft.com/en-us/azure/storage/common/storage-use-azurite",
      "reviewer": "Your Name",
      "reviewed": "2026-11-03",
      "expires": "2026-12-03"
    }
  ]
}
```

| Field | Required | Rule |
| --- | --- | --- |
| `image` | yes | The repository of the `images` line, without tag or digest, as for an exception. |
| `digest` | yes | `sha256:` and 64 lowercase hex characters. The entry applies only to the image scanned at this digest, which the `images` line must carry and the Trivy secret report must list in `Metadata.RepoDigests`. An image listed by tag alone is never allowed. |
| `rule` | yes | The Trivy secret rule id (`RuleID`), lowercase words joined by hyphens. |
| `target` | yes | The path of the one file inside the image where Trivy found it (the `Target` of the result), printable ASCII, exactly as Trivy writes it. |
| `layer_diff_id` | yes | The `DiffID` Trivy reports in the finding's `Layer`: the sha256 of the uncompressed layer, from the image configuration. It is used rather than `Layer.Digest` because Trivy does not report the compressed digest for an image read from the Docker daemon, which is how this workflow scans. |
| `start_line` | yes | The `StartLine` of the finding, a whole number from 1. |
| `match_sha256` | no | `sha256:` and the hash of Trivy's redacted `Match` line, to pin the content of the line. `generate-secrets` fills it. Required to tell two findings of one rule on one line apart. |
| `reason` | yes | One line, 10 to 300 characters: why the value is public and not a credential. |
| `evidence` | yes | An `https://` link, without credentials, to the public source that publishes the value (a vendor document, an upstream repository). |
| `reviewer` | yes | The person who reviewed it, never a bot or an agent. |
| `reviewed` | yes | `YYYY-MM-DD` (UTC), not after today. |
| `expires` | yes | `YYYY-MM-DD`, on or after `reviewed` and at most 31 days after it. The last day it is live. |

An entry matches **one finding**: the image, digest, rule, file, layer and line
must all equal what Trivy reports (compared exactly: no trimming, no
normalisation, no wildcards in any field), the Trivy secret report must list the
digest, and `match_sha256`, when the entry has it, must equal the hash of the
finding's `Match` line. A second finding with the same rule, file, layer and line
still fails. The same secret in another file, another layer or on another line of
the same image fails; so does a secret in a new image digest, until it is
reviewed again. Any other field is refused, so are duplicate keys, wildcards
(`*`, `?`, `[`, `]`, `{`, `}`), a missing or non-`https` evidence link, a
`reviewed` date in the future and a span of more than 31 days. A file that breaks
any rule fails every image job; it is never partly applied. An entry that has
expired fails every image job in the repository (renew or delete it); a live
entry that matches nothing is a warning (delete it).

It never applies to a vulnerability, to the filesystem scan (`trivy.yml`), to
gitleaks, to Semgrep or to `trivy-image.yml`, and no other workflow reads the
file. The matched text of a finding is never printed: the step summary and the
log list each allowlisted secret in a table of its own (rule, file, line, layer,
expiry, reviewer, evidence and reason), apart from the failing findings. The
SARIF pass is not filtered by the allowlist, so code scanning keeps showing the
alert.

`python3 -I scripts/image_secret_allowlist.py validate FILE` checks a file, and
`python3 -I scripts/image_secret_allowlist.py generate-secrets --scan REF REPORT ...`
writes a draft of entries from a Trivy secret JSON report for a person to
complete. The draft has an empty `reason`, `evidence` and `reviewer`, and no
dates, unless you give them (`--reason`, `--evidence`, `--reviewer`,
`--reviewed`); nothing defaults to today, it does not validate until a person
completes it, and the command never overwrites a file (`--output` must be a
new path, or the draft goes to standard output).

Rollout for a consumer that carries such a value (for example `strangeservers`
and the Azurite key in the `nextcloud` image):

1. Move the pin of `trivy-images.yml` to a release that has the
   `secret-allowlist-file` input. Without the file nothing is allowed.
2. List the image with its digest (`nextcloud@sha256:...`). Scan that image the
   way the workflow does, with `--scanners secret --format json`, and run
   `generate-secrets` on the report (see the process document).
3. Check the draft: one entry, rule `azure-storage-account-key`, the vendored
   `Resources.php` as `target`. Confirm in the published Azurite documentation
   that the value is the documented development key (compare them yourself; do
   not copy the value anywhere), and put that page in `evidence`. Write the
   `reason`, set `reviewer` and `reviewed`. Delete every other entry: a finding
   you cannot show to be public must stay failing.
4. Save it as `.github/image-secret-allowlist.json`, run `validate`, and open the
   pull request. The `Trivy images` check lists the secret under "Allowlisted
   secrets" and passes; the pull request diff is the review.
5. Renew it every month, and again when the image digest changes.

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

- it fails on any secret that no valid, unexpired allowlist entry bound to the
  image digest, layer, file, rule and line covers (one entry, one finding), and
  on any `HIGH` or `CRITICAL` vulnerability that has a fixed version (the
  findings `trivy-image.yml` fails on) and that no valid, unexpired exception
  bound to the image digest covers; neither file ever covers the other kind of
  finding;
- it fails closed on a missing or malformed report, an unexpected severity or
  a field of the wrong type (for example `Vulnerabilities` given as an object),
  instead of passing;
- it fails on an expired exception or allowlist entry, and on an exceptions
  file or an allowlist file that exists but is not valid; a missing file means
  no exceptions, or no allowlist;
- it writes a step summary listing the failing findings (package, installed
  and fixed version) and secrets (rule, file and line; the matched text is
  never printed), the excepted findings with their expiry and reviewer, the
  allowlisted secrets in a separate table (rule, file, line, layer, expiry,
  reviewer, evidence link and reason), and the stale entries as warnings.

Unlike `trivy-image.yml`, Trivy runs in an empty working directory, so a
caller's `.trivyignore` and `trivy.yaml` do not apply: the only ways to pass a
finding are the exceptions file for a vulnerability
([Image exceptions](#image-exceptions)) and the secret allowlist for a
known-public secret ([Image secret allowlist](#image-secret-allowlist)). With `upload-sarif`
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

### Findings report

`trivy.yml`, `semgrep.yml` and `gitleaks.yml` list what a failed check found,
so the job page names the package, rule and location even with
`upload-sarif: false` (no code scanning). After the scan, a `Report ... findings`
step (two in `trivy.yml`, one per scan, so each gets its own 10 annotations) runs with `if: always() && steps.shared_verified.outcome == 'success'` (so after a failed scan, also when `upload-sarif` is `true`, but only once the shared checkout was verified in that run) and renders
the SARIF the scan already wrote, using `scripts/sarif_report.py` under
`python3 -I`:

- the step summary gets a table per scan, most severe first, capped at 200
  rows with a truncation note;
- one `::error file=...,line=...::` annotation per finding, capped at 10 per
  scan (GitHub shows at most 10 error annotations per step).
  `file=` is the full literal path (only `%`, `:`, `,` and line breaks are escaped, nothing is trimmed or shortened);
  a path over 4096 bytes gets no `file=`, and the finding is still counted in the summary.

Shown per finding: tool, rule or vulnerability id, severity, file path, line;
for vulnerabilities also package, installed version, fixed version and title;
for Semgrep the rule's static description (`fullDescription`, else `shortDescription`, else nothing; truncated, escaped); for gitleaks
the short commit sha. **Never shown**: the matched secret text, Semgrep code
snippets, SARIF `snippet` and `contextRegion` fields, fingerprints, and, for
secret scanners (Trivy secrets, gitleaks) and Semgrep (which puts matched code in
it), the result message. Secrets show
rule, file and line only. Untrusted text goes through the same escaping as the
image summaries (`clean()` and `cell()` of `scripts/trivy_images.py`); `cell()` writes every source `&` as `&amp;`
first, so text like `&#x202e;` or `&rlm;` in a name is shown literally and never acts as a character reference. Paths are
repo-relative: a leading `/src/` (Semgrep's container mount) and `file://` are
stripped, and a path with a `..` component is not shown. Trivy writes its paths
percent-encoded (`dir/a%20b.env`), so for the Trivy reports (chosen by `--tool`, never by
the SARIF) the path is decoded once and then checked again (no `..`, control or Unicode format
character or absolute path); Semgrep and gitleaks paths are kept literal, but a path with a Unicode format character (bidi control, zero width) or a lone surrogate is refused for every tool, and such characters in any other rendered text are shown as visible `\uXXXX` escapes. The SARIF is read only
if it is a regular file (not a symlink, FIFO or device), at most 64 MiB are read, and anything else
is the same "report unavailable" warning.

The report is fail-safe and never decides the job: the scan step alone does
(it is not `continue-on-error`). The script exits 0 whatever happens. A
missing or malformed SARIF is stated in the summary and as a warning, and the
scan's own exit status stands. A failing report step cannot turn a passing job
red, and it cannot turn a failing job green.

`gitleaks` prints only a leak count to its log (no file, line or rule without
`--verbose`, which is not set), so it gets the same redacted report from its
SARIF. `gitleaks.yml` now also checks out this repository into
`.strange-security` to run the script; the history scan does not read it. A
caller-planted `.strange-security` path (see above) only skips that report,
with a warning; it never changes the scan's result.
`trivy-image.yml` and `trivy-images.yml` are unchanged: they have their own
summaries.

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
- `scripts/image_exceptions.py` in `tests/test_image_exceptions.py`: the strict
  schema, the digest binding, expiry and stale entries, the `generate` command
  (it never defaults a date or a reviewer and never overwrites a file),
  mutation checks that loosen the schema and the engine and expect the tests to
  notice, and the rule that only `trivy-images.yml` uses an exceptions file;
- `scripts/image_secret_allowlist.py` in `tests/test_image_secret_allowlist.py`
  and `tests/test_image_secret_gate.py`: the strict schema (evidence link,
  no wildcards, unknown fields), the binding of one entry to one finding (each
  of digest, image, layer, file, rule, line and content hash must match), expiry
  and stale entries, the `generate-secrets` command, mutation checks, that an
  entry never covers a vulnerability and a vulnerability exception never covers
  a secret, the summary escaping, the gate's exit status, and the rule that only
  `trivy-images.yml` uses an allowlist file;
- `scripts/trivy_images.py` in `tests/test_trivy_images.py`: image list
  validation, the fail-closed gate on Trivy JSON fixtures (including
  type-confused fields), the exception engine inside the gate, summary safety,
  the CLI under `python3 -I`, and the wiring of
  `trivy-images.yml` (the real registry-login steps of both image workflows run
  under bash against a stub `docker`);
- `scripts/sarif_report.py` in `tests/test_sarif_report.py`: rendering for each
  scanner, redaction (snippet, `contextRegion`, match, fingerprint and message
  fields must not leak), escaping of hostile paths and messages, row and
  annotation caps, missing and malformed input, an exit status of 0 in every
  case, and the wiring of the report steps (`if: always() && steps.shared_verified.outcome == 'success'`,
  and the same guard on every other `always()` step that runs a shared script, with
  mutation checks that removing it is caught; `python3 -I`, no
  `continue-on-error` on the scans, each run block executed under
  `bash -eo pipefail` with a failing `python3` stub and no SARIF, exit 0, and
  nothing in it but the `python3` command and its `|| echo` fallback);
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
