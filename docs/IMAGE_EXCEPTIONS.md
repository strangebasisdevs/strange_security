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

## What never qualifies

- **Secrets.** Any secret found in an image layer, at any severity, fails the
  image. An entry is about a vulnerability id. The engine rejects an entry that
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
the vulnerability id and the package name are all equal, and the Trivy report
confirms it scanned that digest (`Metadata.RepoDigests`). The repository name is
the text of the `images` line without tag or digest, so `nextcloud` and
`docker.io/library/nextcloud` are different. The same id and package in any
target of the image (for example both an OS package and a second copy in an
application bundle) is covered by the one entry.
