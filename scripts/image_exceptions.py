#!/usr/bin/env python3
"""Reviewed, expiring, digest-bound exceptions for the image gate (stdlib only).

Used ONLY by trivy-images.yml, through scripts/trivy_images.py. The filesystem
scan, gitleaks, Semgrep and trivy-image.yml never read an exceptions file, and
a secret finding can never be excepted: the engine only ever sees fixable
HIGH/CRITICAL vulnerabilities, and it rejects an entry that names a secret.

  image_exceptions.py validate FILE
      Schema check of an exceptions file (strict fields, no wildcards, digest
      bound, reviewed <= today, reviewed <= expires, expires at most 31 days
      after reviewed). An expiry in the past is not a schema error, so an
      expired entry never breaks the validation of an unrelated pull request;
      the image gate fails on it instead. Exit 0 valid, 1 invalid.

  image_exceptions.py generate --scan REFERENCE REPORT [--scan ...]
                      [--reviewer NAME] [--reviewed YYYY-MM-DD] [--days N]
                      [--output PATH]
      Snapshots the fixable HIGH/CRITICAL findings of Trivy JSON reports into
      DRAFT entries for a human to review. REFERENCE must carry the sha256
      digest that was scanned (repo@sha256:... or repo:tag@sha256:...). A draft
      never has a reason, and has no reviewer or dates unless they are given
      explicitly here: nothing defaults to today. Until a human has filled
      them in, the draft does not validate. The draft goes to stdout, or to
      --output, which must not exist yet: this command never overwrites a file,
      so it cannot rewrite the live exceptions file in place. Exit 0 or 2.

Why not Trivy's .trivyignore.yaml: it cannot bind an entry to one image digest,
and a repository-root ignore file would also be read by the filesystem scan.

Run as `python3 -I`: the script directory must not shadow stdlib modules.
"""
from __future__ import annotations

import argparse
import datetime
import importlib.util
import json
import os
import re
import sys

MAX_DAYS = 31
MAX_ENTRIES = 1000
MAX_BYTES = 2 * 1024 * 1024

REQUIRED = ("image", "digest", "id", "package", "reason", "reviewer", "reviewed", "expires")
OPTIONAL = ("tracking",)
# A field that would aim an entry at a secret finding. Never accepted.
SECRET_KEYS = ("secret", "secrets", "rule", "ruleid", "rule_id", "rule-id")

_COMPONENT = r"[a-z0-9]+(?:[._-]+[a-z0-9]+)*"
WILDCARD = re.compile(r"[*?\[\]{}]")
IMAGE = re.compile(r"%s(?::[0-9]{1,5})?(?:/%s)*" % (_COMPONENT, _COMPONENT), re.ASCII)
DIGEST = re.compile(r"sha256:[0-9a-f]{64}", re.ASCII)
# CVE-2026-0001, GO-2026-0001, RUSTSEC-2026-0001: starts with a capital letter and
# holds a digit, and may never begin with ghsa- in any case (every GHSA id goes
# through the exact form below). A GHSA id (GHSA-xxxx-xxxx-xxxx, three lowercase groups drawn from
# GitHub's alphabet 23456789cfghjmpqrvwx) may hold no digit at all, so it has its own
# exact form. Trivy secret rule ids are lowercase words and match neither.
VULN_ID = re.compile(r"GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}"
                     r"|(?![Gg][Hh][Ss][Aa]-)[A-Z][A-Za-z0-9]*-[A-Za-z0-9._-]*[0-9][A-Za-z0-9._-]*", re.ASCII)
PACKAGE = re.compile(r"[A-Za-z0-9@][A-Za-z0-9._+:@/~-]*", re.ASCII)
REVIEWER = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._@+-]*", re.ASCII)
REASON = re.compile(r"[^\x00-\x1f\x7f-\x9f\u2028\u2029]+")
TRACKING = re.compile(r"https://[\x21-\x7e]{1,280}", re.ASCII)
DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", re.ASCII)


class ExceptionsError(Exception):
    """An exceptions file or a request that cannot be trusted."""

    def __init__(self, message, errors=None):
        super().__init__(message)
        self.errors = list(errors) if errors else [message]


def today_utc() -> datetime.date:
    return datetime.datetime.now(datetime.timezone.utc).date()


def parse_date(value: object) -> datetime.date | None:
    if not isinstance(value, str) or not DATE.fullmatch(value):
        return None
    try:
        return datetime.date.fromisoformat(value)
    except ValueError:
        return None


def _show(value: object) -> str:
    text = repr(value)
    return text if len(text) <= 80 else text[:77] + "..."


# ---------------------------------------------------------------- the file


def _no_duplicate_keys(pairs):
    seen = {}
    for key, value in pairs:
        if key in seen:
            raise ValueError("duplicate key %s" % _show(key))
        seen[key] = value
    return seen


def _no_constant(name):
    raise ValueError("%s is not allowed in JSON" % name)


def read_entries(path: str) -> list:
    """The raw entry list of an exceptions file. Raises ExceptionsError."""
    try:
        with open(path, "rb") as handle:
            raw = handle.read(MAX_BYTES + 1)
    except OSError as error:
        raise ExceptionsError("cannot read %s: %s" % (_show(path), error.strerror or "error"))
    if len(raw) > MAX_BYTES:
        raise ExceptionsError("%s is larger than %d bytes" % (_show(path), MAX_BYTES))
    try:
        data = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_no_duplicate_keys, parse_constant=_no_constant)
    except (ValueError, RecursionError) as error:
        raise ExceptionsError("%s is not valid JSON: %s" % (_show(path), error))
    if not isinstance(data, dict) or set(data) != {"exceptions"} or not isinstance(data["exceptions"], list):
        raise ExceptionsError('%s: the top level must be exactly {"exceptions": [...]}' % _show(path))
    if len(data["exceptions"]) > MAX_ENTRIES:
        raise ExceptionsError("%s: more than %d entries" % (_show(path), MAX_ENTRIES))
    return data["exceptions"]


def schema_errors(entries: list, today: datetime.date) -> list[str]:
    errors: list[str] = []
    seen: set = set()
    for n, entry in enumerate(entries, 1):
        where = "entry %d" % n
        if not isinstance(entry, dict):
            errors.append("%s: not an object" % where)
            continue
        keys = set(entry)
        secretish = sorted(k for k in keys if isinstance(k, str) and k.lower() in SECRET_KEYS)
        if secretish:
            errors.append("%s: field %s targets a secret; secrets never qualify for an exception" % (where, secretish[0]))
            continue
        if keys - set(REQUIRED) - set(OPTIONAL) or set(REQUIRED) - keys:
            errors.append("%s: fields must be %s plus optional %s, got %s" % (
                where, list(REQUIRED), list(OPTIONAL), sorted(str(k) for k in keys)))
            continue
        for key in REQUIRED + tuple(k for k in OPTIONAL if k in entry):
            if not isinstance(entry[key], str) or not entry[key].strip():
                errors.append("%s: %s must be a non-empty string" % (where, key))
        text = {k: entry[k] for k in entry if isinstance(entry[k], str) and entry[k].strip()}

        for key in ("image", "digest", "id", "package"):
            if key in text and WILDCARD.search(text[key]):
                errors.append("%s: %s %s must be exact (no wildcards)" % (where, key, _show(text[key])))
                text.pop(key)
        image = text.get("image")
        if image is not None and (len(image) > 255 or not IMAGE.fullmatch(image) or ":" in image.rsplit("/", 1)[-1]):
            errors.append("%s: image %s must be a lowercase repository name without tag or digest" % (where, _show(image)))
        digest = text.get("digest")
        if digest is not None and not DIGEST.fullmatch(digest):
            errors.append("%s: digest %s must be sha256: followed by 64 lowercase hex characters; "
                          "an exception binds to one image digest, never to a tag" % (where, _show(digest)))
        vid = text.get("id")
        if vid is not None and (len(vid) > 100 or not VULN_ID.fullmatch(vid)):
            errors.append("%s: id %s is not a vulnerability id such as CVE-2026-0001; secrets never qualify "
                          "for an exception" % (where, _show(vid)))
        package = text.get("package")
        if package is not None and (len(package) > 200 or not PACKAGE.fullmatch(package)):
            errors.append("%s: package %s is not a package name" % (where, _show(package)))
        reason = text.get("reason")
        if reason is not None and (not 10 <= len(reason) <= 300 or reason != reason.strip() or not REASON.fullmatch(reason)):
            errors.append("%s: reason must be one line of 10 to 300 characters, without control characters" % where)
        reviewer = text.get("reviewer")
        if reviewer is not None and (len(reviewer) > 64 or reviewer != reviewer.strip() or not REVIEWER.fullmatch(reviewer)):
            errors.append("%s: reviewer must name a person (letters, digits, space and . _ @ + -, at most 64)" % where)
        tracking = text.get("tracking")
        if tracking is not None and not TRACKING.fullmatch(tracking):
            errors.append("%s: tracking must be an https:// link without spaces" % where)

        reviewed, expires = parse_date(entry.get("reviewed")), parse_date(entry.get("expires"))
        if reviewed is None or expires is None:
            errors.append("%s: reviewed and expires must be YYYY-MM-DD dates" % where)
        else:
            if reviewed > today:
                errors.append("%s: reviewed %s is in the future (today is %s, UTC)" % (where, reviewed, today))
            if expires < reviewed:
                errors.append("%s: expires %s is before reviewed %s" % (where, expires, reviewed))
            elif (expires - reviewed).days > MAX_DAYS:
                errors.append("%s: expires must be at most %d days after reviewed, got %d" % (
                    where, MAX_DAYS, (expires - reviewed).days))
        identity = tuple(repr(entry.get(k)) for k in ("image", "digest", "id", "package"))
        if identity in seen:
            errors.append("%s: duplicate of an earlier entry %s" % (where, ", ".join(identity)))
        seen.add(identity)
    return errors


def load_exceptions(path: str, today: datetime.date) -> list[dict]:
    """The valid entries of the file at path; none when the file does not exist.

    A file that exists must be a regular file (not a symlink) and pass the whole
    schema, otherwise ExceptionsError: a malformed file is never half-applied.
    """
    if not os.path.lexists(path):
        return []
    if os.path.islink(path) or not os.path.isfile(path):
        raise ExceptionsError("%s exists but is not a regular file" % _show(path))
    entries = read_entries(path)
    errors = schema_errors(entries, today)
    if errors:
        shown = errors[:10] + (["... and %d more" % (len(errors) - 10)] if len(errors) > 10 else [])
        raise ExceptionsError("%s is invalid: %s" % (_show(path), "; ".join(shown)), errors)
    return entries


# ---------------------------------------------------------------- the verdict


def reference_digest(reference: str) -> str | None:
    """The sha256 digest a reference names, or None for a tag-only reference."""
    _, at, digest = reference.partition("@")
    return digest if at and DIGEST.fullmatch(digest) else None


def report_digests(report: object) -> set[str]:
    """The image digests a Trivy report says it scanned (Metadata.RepoDigests)."""
    found: set[str] = set()
    metadata = report.get("Metadata") if isinstance(report, dict) else None
    listed = metadata.get("RepoDigests") if isinstance(metadata, dict) else None
    for item in listed if isinstance(listed, list) else []:
        if isinstance(item, str):
            digest = item.rpartition("@")[2]
            if DIGEST.fullmatch(digest):
                found.add(digest)
    return found


def evaluate(entries, repository, digest, findings, today, unbound_reason="the image has no digest"):
    """Split the fixable HIGH/CRITICAL findings of one image into excepted and failing.

    entries must have passed schema_errors. digest is the sha256 digest that was
    scanned, or None when it is not known: then no entry applies. An entry applies
    only when its image, digest, vulnerability id and package all equal the
    finding's raw Trivy strings (raw_id, raw_package), and it has not expired. Returns a dict with
      excepted  list of (finding, entry)
      failing   findings with no live entry
      expired   every expired entry of the file, for any image (each one fails)
      stale     (entry, why) for live entries of this image that matched nothing
    """
    expired = [e for e in entries if parse_date(e["expires"]) < today]
    mine = [e for e in entries if parse_date(e["expires"]) >= today and e["image"] == repository]
    bound = {} if digest is None else {(e["id"], e["package"]): e for e in mine if e["digest"] == digest}
    used: set = set()
    excepted, failing = [], []
    for finding in findings:
        # The raw Trivy strings, not the cleaned display copies (clean() maps "a|b" to
        # "a/b" and drops a trailing space or NUL). A finding without them (a test
        # double) falls back to its id and package.
        entry = bound.get((finding.get("raw_id", finding["id"]), finding.get("raw_package", finding["package"])))
        if entry is None:
            failing.append(finding)
        else:
            used.add(id(entry))
            excepted.append((finding, entry))
    stale = []
    for entry in mine:
        if id(entry) in used:
            continue
        if digest is None:
            why = "cannot apply: " + unbound_reason
        elif entry["digest"] != digest:
            why = "it names another digest than the scanned %s" % digest[:19]
        else:
            why = "it no longer matches a finding"
        stale.append((entry, why))
    return {"excepted": excepted, "failing": failing, "expired": expired, "stale": stale}


# ---------------------------------------------------------------- generate


def _trivy_images():
    """scripts/trivy_images.py, loaded by path: python3 -I has no script directory on sys.path."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "trivy_images.py")
    spec = importlib.util.spec_from_file_location("trivy_images", path)
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except (OSError, SyntaxError) as error:
        raise ExceptionsError("cannot load trivy_images.py: %s" % error)
    return module


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ExceptionsError("generate: " + message)


def draft(scans, reviewer, reviewed, days):
    """Draft entries for [(reference, report data)]. Raises ExceptionsError.

    No reason is ever filled in. reviewer, reviewed and expires stay empty unless
    the caller gives them, so a draft cannot be committed as it is.
    """
    ti = _trivy_images()
    expires = "" if reviewed is None else (reviewed + datetime.timedelta(days=days)).isoformat()
    entries, notes, seen = [], [], set()
    for reference, data in scans:
        try:
            _, repository = ti.parse_reference(reference)
            digest = reference_digest(reference)
            if digest is None:
                raise ExceptionsError("%s has no sha256 digest; an exception can only name an image by "
                                      "digest, so scan repo@sha256:... or repo:tag@sha256:..." % _show(reference))
            if digest not in report_digests(data):
                raise ExceptionsError("the report for %s does not list %s in Metadata.RepoDigests; it was "
                                      "not made from that image" % (_show(reference), digest[:19]))
            findings = ti.fixable_vulnerabilities(ti.results_of(data, "vulnerability"))
        except ti.InputError as error:
            raise ExceptionsError(str(error))
        for finding in findings:
            raw_id, raw_package = finding.get("raw_id", finding["id"]), finding.get("raw_package", finding["package"])
            key = (repository, digest, raw_id, raw_package)
            if key in seen:
                continue
            seen.add(key)
            entries.append({
                "image": repository, "digest": digest, "id": raw_id, "package": raw_package,
                "reason": "", "reviewer": reviewer or "",
                "reviewed": "" if reviewed is None else reviewed.isoformat(), "expires": expires,
            })
            notes.append("%s %s %s %s -> fixed in %s" % (
                repository, finding["id"], finding["package"], finding["installed"], finding["fixed"]))
    order = sorted(range(len(entries)), key=lambda i: (entries[i]["image"], entries[i]["id"], entries[i]["package"] or ""))
    return [entries[i] for i in order], [notes[i] for i in order]


def generate(argv, out, err, today):
    parser = _Parser(prog="image_exceptions.py generate", add_help=False, allow_abbrev=False)
    parser.add_argument("--scan", nargs=2, action="append", required=True, metavar=("REFERENCE", "REPORT"))
    parser.add_argument("--reviewer")
    parser.add_argument("--reviewed")
    parser.add_argument("--days", type=int, default=MAX_DAYS)
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    if args.reviewer is not None and not (len(args.reviewer) <= 64 and args.reviewer == args.reviewer.strip()
                                          and REVIEWER.fullmatch(args.reviewer)):
        raise ExceptionsError("generate: --reviewer must name a person (letters, digits, space and . _ @ + -)")
    reviewed = None
    if args.reviewed is not None:
        reviewed = parse_date(args.reviewed)
        if reviewed is None:
            raise ExceptionsError("generate: --reviewed must be a YYYY-MM-DD date")
        if reviewed > today:
            raise ExceptionsError("generate: --reviewed %s is in the future (today is %s, UTC)" % (reviewed, today))
    if not 0 <= args.days <= MAX_DAYS:
        raise ExceptionsError("generate: --days must be 0 to %d" % MAX_DAYS)
    ti = _trivy_images()
    scans = []
    for reference, report in args.scan:
        try:
            scans.append((reference, ti.load_report_data(report, "vulnerability")))
        except ti.InputError as error:
            raise ExceptionsError(str(error))
    entries, notes = draft(scans, args.reviewer, reviewed, args.days)
    text = json.dumps({"exceptions": entries}, indent=2) + "\n"
    if args.output is None:
        out.write(text)
    else:
        try:
            with open(args.output, "x", encoding="utf-8", newline="\n") as handle:
                handle.write(text)
        except FileExistsError:
            raise ExceptionsError("generate: %s already exists; this command never overwrites a file" % _show(args.output))
        except OSError as error:
            raise ExceptionsError("generate: cannot write %s: %s" % (_show(args.output), error.strerror or "error"))
    for line in notes:
        err.write("  %s\n" % line)
    missing = [name for name, value in (("reviewer", args.reviewer), ("reviewed and expires", reviewed)) if not value]
    err.write("%d draft entries for %d image(s). Before committing, a human must write the reason of every "
              "entry%s, check that no patched release exists, and delete what is no longer needed. "
              "The draft does not validate until then.\n" % (
                  len(entries), len(scans), "" if not missing else ", and fill in " + " and ".join(missing)))
    return 0


# ---------------------------------------------------------------- command line


def main(argv, out=None, err=None, today=None):
    out = sys.stdout if out is None else out
    err = sys.stderr if err is None else err
    today = today_utc() if today is None else today
    try:
        if len(argv) == 2 and argv[0] == "validate":
            if not os.path.lexists(argv[1]):
                raise ExceptionsError("%s does not exist" % _show(argv[1]))
            entries = load_exceptions(argv[1], today)
            out.write("ok: %d entries\n" % len(entries))
            return 0
        if argv and argv[0] == "generate":
            return generate(argv[1:], out, err, today)
    except ExceptionsError as error:
        lines = error.errors if len(error.errors) > 1 else [str(error)]
        for line in lines[:40]:
            err.write("ERROR: %s\n" % line)
        if len(lines) > 40:
            err.write("ERROR: ... and %d more\n" % (len(lines) - 40))
        return 1 if argv[0] == "validate" else 2
    err.write(__doc__ + "\n")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
