#!/usr/bin/env python3
"""Reviewed, expiring allowlist for KNOWN-PUBLIC secrets in image layers (stdlib only).

Used ONLY by trivy-images.yml, through scripts/trivy_images.py. It is a different
decision from a vulnerability exception (scripts/image_exceptions.py, which still
refuses every secret): it says that one Trivy secret finding in one layer of one
exact image is a value that is public by design, for example the documented
development key of a storage emulator, and not a credential. The filesystem
scan, gitleaks, Semgrep, trivy-image.yml and every vulnerability finding never
read this file. If the value is a real credential, rotate it first; this file
is not the place for it.

  image_secret_allowlist.py validate FILE
      Schema check of an allowlist file (strict fields, no wildcards, bound to
      one image digest, one layer, one file, one rule and one line; a reason, an
      https evidence link, a reviewer; reviewed <= today, expires at most 31
      days after reviewed). An expiry in the past is not a schema error, so an
      expired entry never breaks the validation of an unrelated pull request;
      the image gate fails on it instead. Exit 0 valid, 1 invalid.

  image_secret_allowlist.py generate-secrets --scan REFERENCE REPORT [--scan ...]
                      [--reason TEXT] [--evidence URL] [--reviewer NAME]
                      [--reviewed YYYY-MM-DD] [--days N] [--output PATH]
      Snapshots the secret findings of Trivy JSON reports into DRAFT entries
      for a human to complete. REFERENCE must carry the sha256 digest that was
      scanned (repo@sha256:... or repo:tag@sha256:...). The reason, the
      evidence link, the reviewer and the dates stay empty unless they are given
      explicitly here: nothing defaults to today. Until a human has filled them
      in, the draft does not validate. The matched text of a finding is never
      printed or stored (only the sha256 of Trivy's redacted Match line is). The
      draft goes to stdout, or to --output, which must not exist yet: this
      command never overwrites a file, so it cannot rewrite the live allowlist
      in place. Exit 0 or 2.

Which layer id: a finding is bound to Layer.DiffID, the sha256 of the
uncompressed layer from the image configuration. Trivy reports it for every
secret in every image source; Layer.Digest (the compressed manifest digest) is
missing for images read from the Docker daemon, which is how the workflow scans.

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

TOP_KEY = "allowlist"
REQUIRED = ("image", "digest", "rule", "target", "layer_diff_id", "start_line",
            "reason", "evidence", "reviewer", "reviewed", "expires")
OPTIONAL = ("match_sha256",)
MAX_LINE = 10_000_000
MAX_TARGET = 500

RULE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*", re.ASCII)
# A path inside the image as Trivy reports it: printable ASCII, no leading or
# trailing space. Wildcard characters are refused separately.
TARGET = re.compile(r"[\x21-\x7e](?:[\x20-\x7e]*[\x21-\x7e])?", re.ASCII)


class AllowlistError(Exception):
    """An allowlist file or a request that cannot be trusted."""

    def __init__(self, message, errors=None):
        super().__init__(message)
        self.errors = list(errors) if errors else [message]


def _sibling(name):
    """scripts/<name>.py, loaded by path: python3 -I has no script directory on sys.path."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), name + ".py")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except (OSError, SyntaxError) as error:
        raise AllowlistError("cannot load %s.py: %s" % (name, error))
    return module


# The date, reviewer, reason, digest, image and link rules are the ones of the
# vulnerability exceptions, shared so the two files cannot drift apart.
ie = _sibling("image_exceptions")
MAX_DAYS = ie.MAX_DAYS
today_utc = ie.today_utc
parse_date = ie.parse_date
reference_digest = ie.reference_digest
report_digests = ie.report_digests
_show = ie._show


def _trivy_images():
    return _sibling("trivy_images")


# ---------------------------------------------------------------- the file


def entry_key(entry):
    """What an entry is bound to, besides the image and its digest."""
    return (entry["rule"], entry["target"], entry["layer_diff_id"], entry["start_line"])


def _evidence_ok(url):
    if not ie.TRACKING.fullmatch(url):
        return False
    authority = url[len("https://"):].split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    return bool(authority) and "@" not in authority


def _is_line(value):
    return isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= MAX_LINE


def schema_errors(entries: list, today: datetime.date) -> list[str]:
    errors: list[str] = []
    groups: dict = {}
    for n, entry in enumerate(entries, 1):
        where = "entry %d" % n
        if not isinstance(entry, dict):
            errors.append("%s: not an object" % where)
            continue
        keys = set(entry)
        if keys - set(REQUIRED) - set(OPTIONAL) or set(REQUIRED) - keys:
            errors.append("%s: fields must be %s plus optional %s, got %s" % (
                where, list(REQUIRED), list(OPTIONAL), sorted(str(k) for k in keys)))
            continue
        strings = tuple(k for k in REQUIRED if k != "start_line") + tuple(k for k in OPTIONAL if k in entry)
        for key in strings:
            if not isinstance(entry[key], str) or not entry[key].strip():
                errors.append("%s: %s must be a non-empty string" % (where, key))
        if not _is_line(entry["start_line"]):
            errors.append("%s: start_line must be the whole line number Trivy reports (1 to %d)" % (where, MAX_LINE))
        text = {k: entry[k] for k in strings if isinstance(entry[k], str) and entry[k].strip()}

        for key in ("image", "digest", "rule", "target", "layer_diff_id", "match_sha256"):
            if key in text and ie.WILDCARD.search(text[key]):
                errors.append("%s: %s %s must be exact (no wildcards)" % (where, key, _show(text[key])))
                text.pop(key)
        image = text.get("image")
        if image is not None and (len(image) > 255 or not ie.IMAGE.fullmatch(image) or ":" in image.rsplit("/", 1)[-1]):
            errors.append("%s: image %s must be a lowercase repository name without tag or digest" % (where, _show(image)))
        for key, what in (("digest", "an image digest"), ("layer_diff_id", "a layer DiffID"),
                          ("match_sha256", "a hash of the Match line")):
            value = text.get(key)
            if value is not None and not ie.DIGEST.fullmatch(value):
                errors.append("%s: %s %s must be sha256: followed by 64 lowercase hex characters; "
                              "%s, never a tag" % (where, key, _show(value), what))
        rule = text.get("rule")
        if rule is not None and (len(rule) > 100 or not RULE.fullmatch(rule)):
            errors.append("%s: rule %s must be a Trivy secret rule id such as azure-storage-account-key" % (where, _show(rule)))
        target = text.get("target")
        if target is not None and (len(target) > MAX_TARGET or not TARGET.fullmatch(target)):
            errors.append("%s: target must be the path of one file inside the image, printable ASCII, "
                          "at most %d characters" % (where, MAX_TARGET))
        reason = text.get("reason")
        if reason is not None and (not 10 <= len(reason) <= 300 or reason != reason.strip()
                                   or not ie.REASON.fullmatch(reason)):
            errors.append("%s: reason must be one line of 10 to 300 characters, without control characters" % where)
        evidence = text.get("evidence")
        if evidence is not None and not _evidence_ok(evidence):
            errors.append("%s: evidence must be an https:// link to the public source of the value, "
                          "without spaces or credentials" % where)
        reviewer = text.get("reviewer")
        if reviewer is not None and (len(reviewer) > 64 or reviewer != reviewer.strip()
                                     or not ie.REVIEWER.fullmatch(reviewer)):
            errors.append("%s: reviewer must name a person (letters, digits, space and . _ @ + -, at most 64)" % where)

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
        # One entry per finding. Two findings of the same rule on the same line of the same
        # file and layer are told apart only by the hash of their Match line, so entries
        # that share everything else must each carry a different hash.
        identity = tuple(repr(entry.get(k)) for k in ("image", "digest") + ("rule", "target", "layer_diff_id", "start_line"))
        groups.setdefault(identity, []).append((n, entry.get("match_sha256")))
    for identity, members in groups.items():
        if len(members) < 2:
            continue
        hashes = [h for _, h in members]
        if None in hashes or len(set(map(repr, hashes))) != len(hashes):
            errors.append("entry %d: duplicate of an earlier entry %s (entries for the same finding must each "
                          "carry a different match_sha256)" % (members[1][0], ", ".join(identity)))
    return errors


def load_allowlist(path: str, today: datetime.date) -> list[dict]:
    """The valid entries of the file at path; none when the file does not exist.

    A file that exists must be a regular file (not a symlink) and pass the whole
    schema, otherwise AllowlistError: a malformed file is never half-applied.
    """
    if not os.path.lexists(path):
        return []
    if os.path.islink(path) or not os.path.isfile(path):
        raise AllowlistError("%s exists but is not a regular file" % _show(path))
    try:
        entries = ie.read_entries(path, TOP_KEY)
    except ie.ExceptionsError as error:
        raise AllowlistError(str(error))
    errors = schema_errors(entries, today)
    if errors:
        shown = errors[:10] + (["... and %d more" % (len(errors) - 10)] if len(errors) > 10 else [])
        raise AllowlistError("%s is invalid: %s" % (_show(path), "; ".join(shown)), errors)
    return entries


# ---------------------------------------------------------------- the verdict


def finding_key(finding):
    """The raw Trivy values a finding is matched on (None where Trivy gave none)."""
    return (finding.get("raw_rule"), finding.get("raw_target"), finding.get("raw_diff_id"), finding.get("raw_line"))


def evaluate(entries, repository, digest, findings, today, unbound_reason="the image has no digest"):
    """Split the secret findings of one image into allowlisted and failing.

    entries must have passed schema_errors. digest is the sha256 digest that was
    scanned, or None when it is not known: then no entry applies. An entry applies
    to one finding only, when its image, digest, rule, target, layer DiffID and
    line all equal the finding's raw Trivy values, its match_sha256 (if it has
    one) equals the hash of the finding's Match line, and it has not expired.
    A second finding with the same key stays failing. Returns a dict with
      allowed    list of (finding, entry)
      failing    findings with no live entry
      expired    every expired entry of the file, for any image (each one fails)
      stale      (entry, why) for live entries of this image that matched nothing
    """
    expired = [e for e in entries if parse_date(e["expires"]) < today]
    mine = [e for e in entries if parse_date(e["expires"]) >= today and e["image"] == repository]
    index: dict = {}
    if digest is not None:
        for e in mine:
            if e["digest"] == digest:
                index.setdefault(entry_key(e), []).append(e)
    used: set = set()
    allowed, failing = [], []
    for finding in findings:
        chosen = None
        for e in index.get(finding_key(finding), ()):
            if id(e) in used:
                continue
            if e.get("match_sha256") is not None and e["match_sha256"] != finding.get("match_sha256"):
                continue
            chosen = e
            break
        if chosen is None:
            failing.append(finding)
        else:
            used.add(id(chosen))
            allowed.append((finding, chosen))
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
    return {"allowed": allowed, "failing": failing, "expired": expired, "stale": stale}


# ---------------------------------------------------------------- generate-secrets


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise AllowlistError("generate-secrets: " + message)


def draft(scans, fields, reviewed, days):
    """Draft entries for [(reference, report data)]. Raises AllowlistError.

    fields holds the reason, evidence and reviewer the caller gave, if any. Every
    other value stays empty, so a draft cannot be committed as it is. Returns
    (entries, notes, skipped notes). A finding that cannot be allowlisted (Trivy
    gave no layer DiffID or no line number) is listed in the skipped notes.
    """
    ti = _trivy_images()
    expires = "" if reviewed is None else (reviewed + datetime.timedelta(days=days)).isoformat()
    entries, notes, skipped, seen = [], [], [], set()
    for reference, data in scans:
        try:
            _, repository = ti.parse_reference(reference)
            digest = reference_digest(reference)
            if digest is None:
                raise AllowlistError("%s has no sha256 digest; an allowlist entry can only name an image by "
                                     "digest, so scan repo@sha256:... or repo:tag@sha256:..." % _show(reference))
            if digest not in report_digests(data):
                raise AllowlistError("the report for %s does not list %s in Metadata.RepoDigests; it was "
                                     "not made from that image" % (_show(reference), digest[:19]))
            findings = ti.secret_findings(ti.results_of(data, "secret"))
        except ti.InputError as error:
            raise AllowlistError(str(error))
        for finding in findings:
            where = "%s %s %s line %s" % (repository, finding["rule"], finding["target"], finding["line"])
            if finding["raw_diff_id"] is None or finding["raw_line"] is None or finding["raw_rule"] is None \
                    or finding["raw_target"] is None or not ie.DIGEST.fullmatch(finding["raw_diff_id"]):
                skipped.append(where + ": Trivy gave no layer DiffID, rule, path or line number; it cannot be allowlisted")
                continue
            made = {
                "image": repository, "digest": digest, "rule": finding["raw_rule"], "target": finding["raw_target"],
                "layer_diff_id": finding["raw_diff_id"], "start_line": finding["raw_line"],
            }
            if finding["match_sha256"] is not None:
                made["match_sha256"] = finding["match_sha256"]
            key = tuple(sorted((k, repr(v)) for k, v in made.items()))
            if key in seen:
                continue
            seen.add(key)
            made.update({
                "reason": fields.get("reason") or "", "evidence": fields.get("evidence") or "",
                "reviewer": fields.get("reviewer") or "",
                "reviewed": "" if reviewed is None else reviewed.isoformat(), "expires": expires,
            })
            entries.append(made)
            notes.append("%s (layer %s)" % (where, finding["layer"][:19]))
    order = sorted(range(len(entries)), key=lambda i: (
        entries[i]["image"], entries[i]["target"], entries[i]["rule"], entries[i]["start_line"],
        entries[i].get("match_sha256", "")))
    return [entries[i] for i in order], [notes[i] for i in order], skipped


def generate_secrets(argv, out, err, today):
    parser = _Parser(prog="image_secret_allowlist.py generate-secrets", add_help=False, allow_abbrev=False)
    parser.add_argument("--scan", nargs=2, action="append", required=True, metavar=("REFERENCE", "REPORT"))
    parser.add_argument("--reason")
    parser.add_argument("--evidence")
    parser.add_argument("--reviewer")
    parser.add_argument("--reviewed")
    parser.add_argument("--days", type=int, default=MAX_DAYS)
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    if args.reviewer is not None and not (len(args.reviewer) <= 64 and args.reviewer == args.reviewer.strip()
                                          and ie.REVIEWER.fullmatch(args.reviewer)):
        raise AllowlistError("generate-secrets: --reviewer must name a person (letters, digits, space and . _ @ + -)")
    if args.reason is not None and not (10 <= len(args.reason) <= 300 and args.reason == args.reason.strip()
                                        and ie.REASON.fullmatch(args.reason)):
        raise AllowlistError("generate-secrets: --reason must be one line of 10 to 300 characters")
    if args.evidence is not None and not _evidence_ok(args.evidence):
        raise AllowlistError("generate-secrets: --evidence must be an https:// link without spaces or credentials")
    reviewed = None
    if args.reviewed is not None:
        reviewed = parse_date(args.reviewed)
        if reviewed is None:
            raise AllowlistError("generate-secrets: --reviewed must be a YYYY-MM-DD date")
        if reviewed > today:
            raise AllowlistError("generate-secrets: --reviewed %s is in the future (today is %s, UTC)" % (reviewed, today))
    if not 0 <= args.days <= MAX_DAYS:
        raise AllowlistError("generate-secrets: --days must be 0 to %d" % MAX_DAYS)
    ti = _trivy_images()
    scans = []
    for reference, report in args.scan:
        try:
            scans.append((reference, ti.load_report_data(report, "secret")))
        except ti.InputError as error:
            raise AllowlistError(str(error))
    given = {"reason": args.reason, "evidence": args.evidence, "reviewer": args.reviewer}
    entries, notes, skipped = draft(scans, given, reviewed, args.days)
    text = json.dumps({TOP_KEY: entries}, indent=2) + "\n"
    if args.output is None:
        out.write(text)
    else:
        try:
            with open(args.output, "x", encoding="utf-8", newline="\n") as handle:
                handle.write(text)
        except FileExistsError:
            raise AllowlistError("generate-secrets: %s already exists; this command never overwrites a file" % _show(args.output))
        except OSError as error:
            raise AllowlistError("generate-secrets: cannot write %s: %s" % (_show(args.output), error.strerror or "error"))
    for line in notes:
        err.write("  %s\n" % ti.clean(line, 300))
    for line in skipped:
        err.write("  skipped %s\n" % ti.clean(line, 300))
    missing = [name for name, value in (("reason", args.reason), ("evidence", args.evidence),
                                        ("reviewer", args.reviewer), ("reviewed and expires", reviewed)) if not value]
    err.write("%d draft entries for %d image(s). Before committing, a human must confirm that every value is "
              "public by design and not a credential (rotate it first if it is one)%s, and delete what is no "
              "longer needed. The draft does not validate until then.\n" % (
                  len(entries), len(scans), "" if not missing else ", and fill in " + ", ".join(missing)))
    return 0


# ---------------------------------------------------------------- command line


def main(argv, out=None, err=None, today=None):
    out = sys.stdout if out is None else out
    err = sys.stderr if err is None else err
    today = today_utc() if today is None else today
    try:
        if len(argv) == 2 and argv[0] == "validate":
            if not os.path.lexists(argv[1]):
                raise AllowlistError("%s does not exist" % _show(argv[1]))
            entries = load_allowlist(argv[1], today)
            out.write("ok: %d entries\n" % len(entries))
            return 0
        if argv and argv[0] == "generate-secrets":
            return generate_secrets(argv[1:], out, err, today)
    except AllowlistError as error:
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
