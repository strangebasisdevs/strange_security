# Image exceptions

This is the single process for `.github/image-exceptions.json`, the only way to
let `trivy-images.yml` pass an image that has a fixable `HIGH` or `CRITICAL`
vulnerability. An exception is a reviewed, written, expiring decision about one
vulnerability in one package of one exact image. It is not a suppression of the
kind [SUPPRESSIONS.md](SUPPRESSIONS.md) forbids: `.trivyignore` and
`trivy.yaml` stay unavailable, and nothing here changes that policy.

The schema is in the [README](../README.md#image-exceptions). The engine is
`scripts/image_exceptions.py`, run by `scripts/trivy_images.py` as
`python3 -I`; its exit status is the job status.

A secret that is public by design has its own file, schema, engine and process,
described under [Known-public secrets](#known-public-secrets-the-secret-allowlist)
below. The two never mix: nothing in this file covers a secret.

## What never qualifies

- **Secrets.** Any secret found in an image layer, at any severity, fails the
  image, and no vulnerability exception covers it (the one, narrow path for a
  value that is public by design is the separate secret allowlist below). An
  entry here is about a vulnerability id. The engine rejects an entry that
  has a `secret`, `rule` or `RuleID` field or an `id` that is not a
  vulnerability id (a secret rule id such as `aws-access-key-id`), and the
  secret report is never matched against entries. A leaked credential is
  exposed already: rotate it, then rebuild the image.
- **The filesystem scan** (`trivy.yml`), **gitleaks** and **Semgrep** findings.
  They never read the exceptions file. Their policy is in
  [SUPPRESSIONS.md](SUPPRESSIONS.md).
- **`trivy-image.yml`** (the push, scan, then tag flow). It does not read the
  exceptions file either.
- **Findings without a fix, or below `HIGH`.** The gate does not fail on them,
  so they need no entry.
- **An image that is listed without a digest.** An entry applies only to the
  exact `sha256:` digest it names, and the `images` line must carry that
  digest (`repo@sha256:...` or `repo:tag@sha256:...`). A tag-only line such as
  `repo:1.2.3` can move, so nothing is excepted for it.
- **A wildcard, a range, or a tag.** Every field is exact.
- **A decision that nobody reviewed, or one that has expired.**

## Who reviews

The reviewer is the person who read the finding, checked for a fix and accepts
the risk for the next month. The `reviewer` field names that person.

- In a repository with more than one maintainer the reviewer is not the author
  of the pull request that adds or renews the entry, and approves that pull
  request. In a one-maintainer repository the maintainer is the reviewer, and
  the pull request is still how the decision is recorded.
- An AI agent, a bot or a script is never the reviewer and never writes the
  `reason`. `generate` below produces a draft that does not validate until a
  person has written the reasons; it does not set `reviewed` to today.
- The pull request lists every added or renewed entry (image, id, package,
  reason, expiry), as for any suppression.

## Monthly cadence

Every entry expires at most 31 days after its `reviewed` date (all dates are
UTC). Review the whole file once a month, a few days before the earliest
expiry, on a fixed day. On the day after an entry's `expires` date every image
job in the repository fails with `Exception expired`, so a lapse is loud, not
silent. Renewing does not extend an entry: it replaces it with a new review.

## Before you renew: check for a patched release

For each entry, look at the `Fixed in` column of the draft and of the job
summary. A fix exists for every excepted finding, otherwise it would not need
an entry, so the question is why the image does not have it:

1. Is there a newer tag, or a rebuild of the same tag with a new digest, that
   includes the fixed package? Pull the newer image, scan it and bump the
   image line in the `images` list instead of renewing. That is the normal
   outcome and it makes the entry stale.
2. Is the fix in a newer base image or dependency that the vendor has not
   released yet? Look for the vendor's issue or advisory, and put its link in
   `tracking`.
3. Is the package not used or not reachable in this deployment? Say so in the
   reason, with how you know. Do not write "not exploitable" without a basis.

Renew only when no patched release exists or the update cannot be taken now,
and write down why. Prefer removing the image from use over a third renewal.

## Delete stale entries

A live entry that matches no finding is a warning in the job log and in the
step summary: `Stale exception (...)`. The reasons are that the finding is
gone, that the entry names another digest than the scanned one (the image was
bumped), or that the image is scanned without a digest. Delete stale entries in
the next pull request: an old entry for a vulnerability that comes back
unnoticed is exactly what the digest binding and the expiry are for. When you
remove an image from the `images` list, delete its entries in the same pull
request; they are no longer evaluated, and only their expiry reminds you.

## The renew pull request flow

`generate` snapshots the current fixable `HIGH`/`CRITICAL` findings into draft
entries. It never writes into the live file: the draft goes to standard output
or to an `--output` path that must not exist.

1. **Scan the pinned images** the way the workflow does, so the reports match
   what the gate sees. From a checkout of this repository, in a Linux shell:

   ```sh
   docker build --file scanner-images/trivy.Dockerfile --tag trivy-scanner .
   mkdir -p out cache
   docker pull "$REF"
   docker run --rm --volume /var/run/docker.sock:/var/run/docker.sock \
     --volume "$PWD/cache:/cache" --volume "$PWD/out:/out" --workdir /out \
     trivy-scanner image --cache-dir /cache --image-src docker --scanners vuln \
     --format json --output /out/image1.json --exit-code 0 "$REF"
   ```

   `$REF` is the exact line of the `images` list (with its digest). Repeat for
   each image that has findings, with a different output file.

2. **Generate the draft**, with the reviewer and the review date given
   explicitly (leave them out and they are left blank for you to fill in; the
   tool never uses today's date by itself):

   ```sh
   python3 -I scripts/image_exceptions.py generate \
     --scan "$REF1" out/image1.json --scan "$REF2" out/image2.json \
     --reviewer "Your Name" --reviewed 2026-11-03 --output draft.json
   ```

   The expiry is `--reviewed` plus 31 days (`--days` shortens it). It prints
   each finding with the version that fixes it to the terminal. The draft has an
   empty `reason` on every entry, so `validate` fails on it until a person has
   written them.

3. **Edit the draft by hand.** Check each entry for a patched release (above).
   Delete the entries you do not need. Write a one-line `reason` for each, add
   a `tracking` link where there is one, and check the `reviewer`, `reviewed`
   and `expires` fields.

4. **Replace the live file** with the edited draft in a branch, and validate it:

   ```sh
   python3 -I scripts/image_exceptions.py validate .github/image-exceptions.json
   ```

5. **Open the pull request.** The pull request diff is the review: a reviewer
   (see above) reads the reasons and approves. The `Trivy images` check on the
   pull request runs the gate with the new file and must be green before the
   merge.

6. Merge before the earliest expiry. Put the next review date in your calendar.

## What the job shows

Each image job writes to the step summary and the log:

- **Failing findings**: fixable `HIGH`/`CRITICAL` vulnerabilities no live entry
  covers, secrets, and expired entries. The job fails.
- **Excepted findings**: each with its expiry, reviewer and reason. The job can
  still pass; this table is the list of accepted risk.
- **Stale exceptions**: warnings, the job is unchanged.

A file that exists but is not valid (bad JSON, a duplicate key, an unknown
field, a wildcard, a future `reviewed` date, a span of more than 31 days, a
missing digest, an unreadable path) fails every image job: it is never half
applied. A missing file means no exceptions.

An entry matches a finding only when the repository name, the `sha256` digest,
the vulnerability id and the package name are all equal (compared exactly as
Trivy reports them: no trimming, no normalisation, so `a/b` never covers `a|b`
and a trailing space or control character never matches), and the Trivy report
confirms it scanned that digest (`Metadata.RepoDigests`). The repository name is
the text of the `images` line without tag or digest, so `nextcloud` and
`docker.io/library/nextcloud` are different. The same id and package in any
target of the image (for example both an OS package and a second copy in an
application bundle) is covered by the one entry.

## Known-public secrets (the secret allowlist)

`.github/image-secret-allowlist.json` (the `secret-allowlist-file` input of
`trivy-images.yml`) lets one Trivy secret finding in one layer of one exact image
pass, because the value is **public by design**: a documented emulator or test
key that is vendored in a library and opens nothing. The motivating case is the
public development storage key of the Azurite emulator in the vendored Azure
library of the Nextcloud image (rule `azure-storage-account-key`, file
`var/www/html/3rdparty/microsoft/azure-storage-common/src/Common/Internal/Resources.php`).
The schema is in the [README](../README.md#image-secret-allowlist). The engine
is `scripts/image_secret_allowlist.py`, run by `scripts/trivy_images.py` as
`python3 -I`; its exit status is the job status.

It is not a suppression of the kind [SUPPRESSIONS.md](SUPPRESSIONS.md) forbids:
secrets are still never suppressed in source, in gitleaks or in the filesystem
scan, and `.trivyignore` and `trivy.yaml` stay unavailable.

### What never qualifies

- **A real credential, or a value you are not sure about.** A leaked credential
  is exposed already. Rotate it, then rebuild the image. An entry is not a
  substitute for rotation, and "nobody will find it" is not a reason.
- **A vulnerability.** The engine only ever sees secret findings, and the
  vulnerability exceptions file refuses this file's shape (and the other way
  round): the same entry can never except a vulnerability.
- **The filesystem scan** (`trivy.yml`), **gitleaks**, **Semgrep** and
  **`trivy-image.yml`**. They never read the file.
- **An image listed without a digest.** An entry applies only to the exact
  `sha256:` digest it names, which the Trivy secret report must confirm in
  `Metadata.RepoDigests`.
- **A wildcard, a range, a directory or a whole rule.** Every field is exact.
  There is no way to allow "all secrets in `3rdparty/`" or "this rule".
- **A secret in another file, another layer or on another line of the same
  image**, and **a second finding** with the same rule, file, layer and line: an
  entry covers one finding. Two findings on one line are told apart by the
  `match_sha256` of each.
- **A decision that nobody reviewed, one with no evidence link, or one that has
  expired.**

### What an entry is bound to

`image`, `digest`, `rule` (Trivy's `RuleID`), `target` (the file path inside the
image), `layer_diff_id` and `start_line`, all compared exactly as Trivy reports
them, plus optionally `match_sha256`, the hash of Trivy's redacted `Match` line.

The layer is bound by its `DiffID` (the sha256 of the uncompressed layer, from
the image configuration), which Trivy writes in the `Layer` of every secret
finding. `Layer.Digest` (the compressed digest from the registry manifest) is
not used: Trivy does not report it for an image read from the Docker daemon,
which is how `trivy-images.yml` scans. A finding that has no `DiffID` cannot be
allowlisted. When the image is rebuilt or bumped, the digest changes and the
entry goes stale; the new image must be reviewed again.

The matched text is never read into the output: Trivy redacts it, the gate only
hashes the redacted line, and no log line, summary or draft prints it.

### Who reviews, and what the reviewer checks

The reviewer is the person who read the finding and accepts, for the next month,
that it is not a credential. The same rules as for exceptions apply: with more
than one maintainer the reviewer is not the author of the pull request and
approves it, an AI agent, a bot or a script is never the reviewer and never
writes the `reason`, and the pull request lists every added or renewed entry
(image, rule, file, reason, evidence, expiry), as for any suppression.

Before approving, check, and write down in the `reason`:

1. **The value is published.** The `evidence` link is the public source that
   shows this exact value as a development, demo or test value (a vendor
   document, an upstream repository), not the page of the library that merely
   uses it. Compare the value yourself; do not paste it into the entry, a
   comment or the pull request.
2. **It opens nothing.** The value is an emulator or test key that protects no
   real account, service or data in this deployment. If the same value could
   authenticate against something real, it is a credential: rotate.
3. **The location is what it claims.** The file is the vendored library file,
   in the layer where you expect it, not a file the image build wrote from a
   real secret.

The `reason` is 10 to 300 characters and says why the value is public, for
example "documented Azurite emulator key, public in the Microsoft docs".

### Monthly cadence, stale and expired entries

Every entry expires at most 31 days after its `reviewed` date (UTC). On the day
after `expires`, every image job in the repository fails with `Secret allowlist
entry expired`, so a lapse is loud. Renewing replaces the entry with a new
review: check that the value is still published as public, that a newer image
does not drop the vendored file, and that nothing about its use changed. A live
entry that matches no finding is a warning (`Stale secret allowlist entry`): the
finding is gone, the image was bumped to another digest, or the image is scanned
without a digest. Delete it in the next pull request. When you remove an image
from the `images` list, delete its entries in the same pull request.

### The pull request flow

`generate-secrets` snapshots the secret findings of a Trivy JSON report into
draft entries. It never writes into the live file: the draft goes to standard
output or to an `--output` path that must not exist.

1. **Scan the pinned image** the way the workflow does, for secrets, from a
   checkout of this repository in a Linux shell (`$REF` is the exact line of the
   `images` list, with its digest):

   ```sh
   docker build --file scanner-images/trivy.Dockerfile --tag trivy-scanner .
   mkdir -p out cache
   docker pull "$REF"
   docker run --rm --volume /var/run/docker.sock:/var/run/docker.sock \
     --volume "$PWD/cache:/cache" --volume "$PWD/out:/out" --workdir /out \
     trivy-scanner image --cache-dir /cache --image-src docker --scanners secret \
     --format json --output /out/secret1.json --exit-code 0 "$REF"
   ```

2. **Generate the draft.** The reason, evidence, reviewer and dates stay empty
   unless you give them, and the tool never uses today's date by itself:

   ```sh
   python3 -I scripts/image_secret_allowlist.py generate-secrets \
     --scan "$REF" out/secret1.json \
     --reviewer "Your Name" --reviewed 2026-11-03 \
     --evidence "https://example.org/the-public-source" --output draft.json
   ```

   The expiry is `--reviewed` plus 31 days (`--days` shortens it). The command
   lists each finding by rule, file, line and layer, and says which findings it
   skipped because Trivy gave no layer `DiffID`.

3. **Edit the draft by hand.** Delete every entry you cannot show to be public.
   Write the `reason` of each, check the `evidence`, `reviewer`, `reviewed` and
   `expires`.

4. **Replace the live file** in a branch and validate it:

   ```sh
   python3 -I scripts/image_secret_allowlist.py validate .github/image-secret-allowlist.json
   ```

5. **Open the pull request.** The diff is the review. The `Trivy images` check
   runs the gate with the new file and must be green before the merge.

### What the job shows

Each image job lists the allowlisted secrets in a table of their own in the step
summary ("Allowlisted secrets": rule, file, line, layer, expiry, reviewer,
evidence and reason) and in the log, apart from the failing findings. An
allowlisted secret is an accepted risk, not a pass: the job can still pass, and
this table is the list of what was accepted. Unlisted secrets, expired entries
and an invalid file fail the job; a stale entry is a warning. The SARIF pass is
not filtered by the allowlist, so code scanning keeps showing the alert.

A file that exists but is not valid (bad JSON, a duplicate key, an unknown field,
a wildcard, a missing or non-`https` evidence link, a future `reviewed` date, a
span of more than 31 days) fails every image job; it is never half applied. A
missing file means no allowlist.
