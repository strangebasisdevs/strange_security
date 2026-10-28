#!/usr/bin/env python3
"""Plan and gate the image scans of trivy-images.yml.

Usage (always as python3 -I, from the shared checkout):

  trivy_images.py plan
      Reads IMAGES (newline-separated references), EXCEPTIONS_FILE and
      SECRET_ALLOWLIST_FILE from the environment, validates them strictly and appends matrix=<json> to the
      file named by GITHUB_OUTPUT. Any invalid input exits non-zero.

  trivy_images.py gate --reference REF --vuln VULN.json --secret SECRET.json
                       --exceptions-file PATH [--secret-allowlist-file PATH]
                       [--summary FILE]
      Fail-closed verdict on one image from the two Trivy JSON reports. Exit 0
      only when the image has no HIGH or CRITICAL vulnerability with a fix that
      an exception does not cover, no secret at any severity that the secret
      allowlist does not cover, and no expired entry in either file. Writes a
      Markdown summary (failing, excepted and allowlisted findings, stale and
      expired entries) to --summary (the step summary file, when not given the
      GITHUB_STEP_SUMMARY variable).
      Exit 1: the image fails. Exit 2: the input cannot be trusted (missing or
      malformed report, invalid exceptions file); this fails the job too.

Exceptions (docs/IMAGE_EXCEPTIONS.md): a fixable HIGH/CRITICAL vulnerability is
excepted only by a valid, unexpired entry of the exceptions file that names the
same repository, the same sha256 digest (the reference must carry it), the same
vulnerability id and the same package. The engine is scripts/image_exceptions.py,
which this script loads by path (python3 -I has no script directory on sys.path).
A missing file means no exceptions; a file that is not valid fails the job. A
vulnerability exception never covers a secret. The caller's .trivyignore and
trivy.yaml are not read.

Secret allowlist (docs/IMAGE_EXCEPTIONS.md): a separate file, a separate schema
and a separate engine, scripts/image_secret_allowlist.py. A secret finding is
allowlisted only by a valid, unexpired entry that names the same repository, the
same sha256 digest (confirmed by the secret report's Metadata.RepoDigests), the
same Trivy rule id, the same file path inside the image, the same layer DiffID and
the same start line, one entry for one finding. The matched text is never printed.

Standard library only.
"""
import hashlib
import importlib.util
import json
import os
import re
import sys
import unicodedata

MAX_IMAGES = 20
MAX_ROWS = 100
GATE_SEVERITIES = ("HIGH", "CRITICAL")
ALL_SEVERITIES = ("UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL")

_COMPONENT = r"[a-z0-9]+(?:[._-]+[a-z0-9]+)*"
# A repository: an optional registry port on the first component, then path components.
_NAME = re.compile(r"^%s(?::[0-9]{1,5})?(?:/%s)*$" % (_COMPONENT, _COMPONENT))
_TAG = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_PATH = re.compile(r"^[A-Za-z0-9._/-]{1,255}$")


class InputError(Exception):
    """Input that cannot be trusted. Always fails the job."""


def escape_format(text):
    """text with every Unicode format character (category Cf: bidi controls such
    as U+202E, zero-width characters, U+FEFF) and every lone surrogate (category Cs, which
    cannot be encoded as UTF-8 and would make a write raise) written as a visible
    backslash-u escape, so nothing invisible can reorder or disguise what a reader sees
    and no field can break an output write. A valid astral character (emoji, CJK
    extension B) is one Python character outside the surrogate range and is unchanged."""
    return "".join(("\\u%04x" % ord(c) if ord(c) <= 0xFFFF else "\\U%08x" % ord(c))
                   if unicodedata.category(c) in ("Cf", "Cs") else c for c in text)


def clean(value, limit=200):
    """Untrusted text made safe for a log line and a Markdown table cell: no
    control characters, no invisible format characters (shown as backslash-u escapes), no
    workflow command (no "::" and no "##[" in the result, however long a run of colons or
    hashes the input holds), no pipe or backtick. Lone surrogates and format characters are
    escaped first by escape_format()."""
    text = escape_format("" if value is None else str(value))
    text = re.sub(r"[\x00-\x1f\x7f-\x9f  ]", " ", text)
    # Every run of 2+ colons gets a space between each pair of colons, so no "::" survives
    # (":::" would still hold one after a single replace("::", ": :")). Inserting a space
    # into "##[" cannot re-form the token, so one pass is enough there.
    text = re.sub(r":{2,}", lambda m: " ".join(m.group()), text)
    text = text.replace("##[", "# #[")
    text = text.replace("|", "/").replace("`", "'")
    text = text.strip()
    return text if len(text) <= limit else text[: limit - 3] + "..."


# Characters that start Markdown or HTML structure (a link, an image, a raw tag, an
# escape). In a step summary they are written as character references, which render
# as the same visible character but never open a link, an image or a tag.
_MARKDOWN_UNSAFE = {ord(c): "&#%d;" % ord(c) for c in "<>[]()!\\"}


def cell(value, limit=200):
    """Untrusted text for a Markdown table cell or list item of the step summary:
    everything clean() does, plus no raw < > [ ] ( ) ! or backslash, and no URL
    scheme separator or "www." that GitHub would turn into a link.

    Source ampersands become &amp; first, before this function writes any character
    reference of its own, so no source text can form an active reference (named,
    decimal or hex, with or without the semicolon, e.g. &#x202e; or &rlm;) and the
    references written below are the only ones in the result."""
    text = clean(value, limit).replace("&", "&amp;").replace("://", ":/ /")
    # GFM extended autolinks also turn a bare www.host into a link; the dot as a
    # character reference renders the same but is no longer a link.
    text = re.sub(r"(?i)(?<=www)\.", "&#46;", text)
    return text.translate(_MARKDOWN_UNSAFE)


# ---------------------------------------------------------------- plan


def parse_reference(line):
    """(reference, repository) of one validated image reference."""
    if not line or len(line) > 300:
        raise InputError("image reference is empty or too long")
    rest, digest = line, None
    if "@" in rest:
        rest, _, digest = rest.partition("@")
        if not _DIGEST.match(digest):
            raise InputError("digest must be sha256: followed by 64 lowercase hex characters: " + clean(line))
    last = rest.rsplit("/", 1)[-1]
    tag, name = None, rest
    if ":" in last:
        name = rest[: len(rest) - len(last)] + last.split(":", 1)[0]
        tag = last.split(":", 1)[1]
        if not _TAG.match(tag):
            raise InputError("invalid tag: " + clean(line))
    if not _NAME.match(name):
        raise InputError("invalid repository name: " + clean(line))
    if tag is None and digest is None:
        raise InputError("image needs a tag or a digest: " + clean(line))
    return line, name


def parse_images(text):
    """The matrix entries for a newline-separated list of references."""
    if not isinstance(text, str):
        raise InputError("images must be a string")
    if re.search(r"[^A-Za-z0-9._/:@\n-]", text):
        raise InputError(
            "images may only contain letters, digits and . _ / : @ -, one reference per line "
            "(no spaces, tabs, carriage returns or shell metacharacters)"
        )
    entries, seen = [], {}
    for line in text.split("\n"):
        if line == "":
            continue
        reference, repository = parse_reference(line)
        if repository in seen:
            raise InputError(
                "two references to the repository %s: each repository gets one code scanning "
                "category, so list it once" % repository
            )
        seen[repository] = reference
        entries.append({"reference": reference, "repository": repository})
    if not entries:
        raise InputError("images must list at least one image reference")
    if len(entries) > MAX_IMAGES:
        raise InputError("at most %d images per call, got %d" % (MAX_IMAGES, len(entries)))
    return entries


def validate_exceptions_path(path, label="exceptions-file"):
    """A relative path inside the caller's checkout, in a plain character set."""
    if not isinstance(path, str) or not _PATH.match(path):
        raise InputError("%s must be a relative path of letters, digits and . _ / -" % label)
    parts = path.split("/")
    if path.startswith("/") or path.startswith("-") or any(p in ("", ".", "..") for p in parts):
        raise InputError("%s must be a relative path inside the repository, without . or .. parts" % label)
    return path


def plan(env, out):
    entries = parse_images(env.get("IMAGES", ""))
    exceptions = validate_exceptions_path(env.get("EXCEPTIONS_FILE", ""))
    allowlist = validate_exceptions_path(env.get("SECRET_ALLOWLIST_FILE", ""), "secret-allowlist-file")
    if exceptions == allowlist:
        raise InputError("exceptions-file and secret-allowlist-file must be two different files: "
                         "they have different schemas")
    matrix = json.dumps({"include": entries}, separators=(",", ":"))
    for entry in entries:
        out.write("image: %s\n" % entry["reference"])
    target = env.get("GITHUB_OUTPUT")
    if not target:
        raise InputError("GITHUB_OUTPUT is not set")
    with open(target, "a", encoding="utf-8", newline="\n") as handle:
        handle.write("matrix=%s\n" % matrix)
    return 0


# ---------------------------------------------------------------- gate


def load_report_data(path, label):
    """The parsed, checked Trivy image report (a dict)."""
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError) as error:
        raise InputError("cannot read the %s report %s: %s" % (label, clean(path), clean(error)))
    if not isinstance(data, dict):
        raise InputError("the %s report is not a JSON object" % label)
    if data.get("SchemaVersion") != 2:
        raise InputError("the %s report has an unsupported SchemaVersion" % label)
    if data.get("ArtifactType") != "container_image":
        raise InputError("the %s report is not a container image report" % label)
    return data


def results_of(data, label):
    results = data.get("Results")
    if results is None:
        return []
    if not isinstance(results, list) or not all(isinstance(r, dict) for r in results):
        raise InputError("the %s report has malformed Results" % label)
    return results


def _items(result, key, label):
    items = result.get(key)
    if items is None:
        return []
    if not isinstance(items, list) or not all(isinstance(i, dict) for i in items):
        raise InputError("the %s report has malformed %s" % (label, key))
    return items


def fixable_vulnerabilities(results):
    """HIGH and CRITICAL findings that have a fix, the set trivy-image.yml fails on."""
    found = []
    for result in results:
        for vuln in _items(result, "Vulnerabilities", "vulnerability"):
            # Every field that decides pass or fail must have the right type, for
            # findings of any severity: a confused type is never read as "no fix".
            if not isinstance(vuln.get("VulnerabilityID"), str):
                raise InputError("a vulnerability has a missing or non-string VulnerabilityID")
            severity = vuln.get("Severity")
            if not isinstance(severity, str) or severity not in ALL_SEVERITIES:
                raise InputError("a vulnerability has an unknown severity: " + clean(severity))
            fixed = vuln.get("FixedVersion")
            if fixed is not None and not isinstance(fixed, str):
                raise InputError("a vulnerability has a non-string FixedVersion: " + clean(fixed))
            status = vuln.get("Status")
            if status is not None and not isinstance(status, str):
                raise InputError("a vulnerability has a non-string Status: " + clean(status))
            if severity not in GATE_SEVERITIES:
                continue
            if (fixed is not None and fixed.strip()) or status == "fixed":
                pkg = vuln.get("PkgName")
                found.append({
                    # id and package are for display only. An exception matches on the
                    # raw Trivy strings (raw_id, raw_package), never on the cleaned copies:
                    # clean() would make "a|b" equal "a/b" and drop a trailing space or NUL.
                    "id": clean(vuln.get("VulnerabilityID")),
                    "raw_id": vuln["VulnerabilityID"],
                    "severity": severity,
                    "package": clean(pkg),
                    "raw_package": pkg if isinstance(pkg, str) else None,
                    "installed": clean(vuln.get("InstalledVersion")),
                    "fixed": clean(fixed),
                    "target": clean(result.get("Target")),
                })
    return found


def _text(value):
    return value if isinstance(value, str) else None


def secret_findings(results):
    """Every secret, at any severity. The matched text is never printed.

    rule, severity, title, target, line and layer are display copies. The raw_*
    values are what a secret allowlist entry is matched on, exactly as Trivy
    reports them (None when Trivy gave none or a value of the wrong type), and
    match_sha256 is the hash of Trivy's redacted Match line: the line itself is
    hashed here and goes no further.
    """
    found = []
    for result in results:
        for secret in _items(result, "Secrets", "secret"):
            layer = secret.get("Layer")
            diff_id = layer.get("DiffID") if isinstance(layer, dict) else None
            line = secret.get("StartLine")
            match = secret.get("Match")
            found.append({
                "rule": clean(secret.get("RuleID")),
                "severity": clean(secret.get("Severity")),
                "title": clean(secret.get("Title")),
                "target": clean(result.get("Target")),
                "line": clean(line),
                "layer": clean(diff_id),
                "raw_rule": _text(secret.get("RuleID")),
                "raw_target": _text(result.get("Target")),
                "raw_line": line if isinstance(line, int) and not isinstance(line, bool) else None,
                "raw_diff_id": _text(diff_id),
                "match_sha256": _match_hash(match),
            })
    return found


def _match_hash(match):
    if not isinstance(match, str):
        return None
    return "sha256:" + hashlib.sha256(match.encode("utf-8", "surrogatepass")).hexdigest()


def load_engine():
    """scripts/image_exceptions.py, loaded by path next to this file."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "image_exceptions.py")
    spec = importlib.util.spec_from_file_location("image_exceptions", path)
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except (OSError, SyntaxError) as error:
        raise InputError("cannot load the exception engine: " + clean(error))
    return module


def load_allowlist_engine():
    """scripts/image_secret_allowlist.py, loaded by path next to this file."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "image_secret_allowlist.py")
    spec = importlib.util.spec_from_file_location("image_secret_allowlist", path)
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as error:  # the engine loads its siblings: any failure must fail closed
        raise InputError("cannot load the secret allowlist engine: " + clean(error))
    return module


def _more(lines, total):
    if total > MAX_ROWS:
        lines += ["", "... and %d more." % (total - MAX_ROWS)]


def render_summary(reference, failing, secrets, excepted=(), stale=(), expired=(),
                   allowlisted=(), allow_stale=(), allow_expired=()):
    lines = ["### Trivy image: %s" % cell(reference), ""]
    if not failing and not secrets and not expired and not allow_expired:
        text = "Passed: no fixable HIGH or CRITICAL vulnerability and no secret"
        if excepted or allowlisted:
            text = "Passed: no unexcepted fixable HIGH or CRITICAL vulnerability and no unlisted secret"
            notes = []
            if excepted:
                notes.append("%d fixable finding(s) are excepted" % len(excepted))
            if allowlisted:
                notes.append("%d secret(s) are allowlisted as known public values" % len(allowlisted))
            text += "; " + ", ".join(notes)
        lines.append(text + ".")
    else:
        text = "**Failed.** %d fixable HIGH/CRITICAL vulnerabilities, %d secrets" % (len(failing), len(secrets))
        if expired:
            text += ", %d expired exceptions" % len(expired)
        if allow_expired:
            text += ", %d expired secret allowlist entries" % len(allow_expired)
        if excepted:
            text += " (%d other finding(s) excepted)" % len(excepted)
        if allowlisted:
            text += " (%d other secret(s) allowlisted)" % len(allowlisted)
        lines.append(text + ".")
    if failing:
        lines += ["", "Failing findings:", "", "| Severity | Vulnerability | Package | Installed | Fixed in | Target |",
                  "| --- | --- | --- | --- | --- | --- |"]
        for v in failing[:MAX_ROWS]:
            lines.append("| %s | %s | %s | %s | %s | %s |" % (
                cell(v["severity"]), cell(v["id"]), cell(v["package"]), cell(v["installed"]), cell(v["fixed"]),
                cell(v["target"])))
        _more(lines, len(failing))
    if secrets:
        lines += ["", "| Severity | Rule | Title | File | Line |", "| --- | --- | --- | --- | --- |"]
        for s in secrets[:MAX_ROWS]:
            lines.append("| %s | %s | %s | %s | %s |" % (
                cell(s["severity"]), cell(s["rule"]), cell(s["title"]), cell(s["target"]), cell(s["line"])))
        _more(lines, len(secrets))
    if expired:
        lines += ["", "Expired exceptions (renew or delete them, see docs/IMAGE_EXCEPTIONS.md):", "",
                  "| Image | Vulnerability | Package | Expired | Reviewer |", "| --- | --- | --- | --- | --- |"]
        for e in expired[:MAX_ROWS]:
            lines.append("| %s | %s | %s | %s | %s |" % (
                cell(e["image"]), cell(e["id"]), cell(e["package"]), cell(e["expires"]), cell(e["reviewer"])))
        _more(lines, len(expired))
    if excepted:
        lines += ["", "Excepted findings (a reviewed, expiring decision, not a pass):", "",
                  "| Severity | Vulnerability | Package | Installed | Fixed in | Expires | Reviewer | Reason |",
                  "| --- | --- | --- | --- | --- | --- | --- | --- |"]
        for v, e in excepted[:MAX_ROWS]:
            lines.append("| %s | %s | %s | %s | %s | %s | %s | %s |" % (
                cell(v["severity"]), cell(v["id"]), cell(v["package"]), cell(v["installed"]), cell(v["fixed"]),
                cell(e["expires"]), cell(e["reviewer"]), cell(e["reason"], 100)))
        _more(lines, len(excepted))
    if stale:
        lines += ["", "Stale exceptions (warnings; delete them or fix them):", ""]
        for e, why in stale[:MAX_ROWS]:
            lines.append("- %s %s %s: %s" % (cell(e["image"]), cell(e["id"]), cell(e["package"]), cell(why)))
        _more(lines, len(stale))
    if allow_expired:
        lines += ["", "Expired secret allowlist entries (renew or delete them, see docs/IMAGE_EXCEPTIONS.md):", "",
                  "| Image | Rule | File | Line | Expired | Reviewer |", "| --- | --- | --- | --- | --- | --- |"]
        for e in allow_expired[:MAX_ROWS]:
            lines.append("| %s | %s | %s | %s | %s | %s |" % (
                cell(e["image"]), cell(e["rule"]), cell(e["target"]), cell(e["start_line"]), cell(e["expires"]),
                cell(e["reviewer"])))
        _more(lines, len(allow_expired))
    if allowlisted:
        lines += ["", "Allowlisted secrets (known-public values: a reviewed, expiring decision, not a pass; the "
                      "matched text is never shown):", "",
                  "| Rule | File | Line | Layer | Expires | Reviewer | Evidence | Reason |",
                  "| --- | --- | --- | --- | --- | --- | --- | --- |"]
        for s, e in allowlisted[:MAX_ROWS]:
            lines.append("| %s | %s | %s | %s | %s | %s | %s | %s |" % (
                cell(s["rule"]), cell(s["target"]), cell(s["line"]), cell(s["layer"]), cell(e["expires"]),
                cell(e["reviewer"]), cell(e["evidence"], 300), cell(e["reason"], 100)))
        _more(lines, len(allowlisted))
    if allow_stale:
        lines += ["", "Stale secret allowlist entries (warnings; delete them or fix them):", ""]
        for e, why in allow_stale[:MAX_ROWS]:
            lines.append("- %s %s %s: %s" % (cell(e["image"]), cell(e["rule"]), cell(e["target"]), cell(why)))
        _more(lines, len(allow_stale))
    return "\n".join(lines) + "\n"


def write_summary(path, text):
    if not path:
        return
    with open(path, "a", encoding="utf-8", newline="\n") as handle:
        handle.write(text + "\n")


def gate(args, out, err, env, today=None):
    summary = args.get("summary") or env.get("GITHUB_STEP_SUMMARY")
    reference = args["reference"]
    try:
        validate_exceptions_path(args["exceptions-file"])
        allow_path = args.get("secret-allowlist-file")
        if allow_path is not None:
            validate_exceptions_path(allow_path, "secret-allowlist-file")
            if allow_path == args["exceptions-file"]:
                raise InputError("the exceptions file and the secret allowlist file must be two different files")
        engine = load_engine()
        allow_engine = load_allowlist_engine()
        today = engine.today_utc() if today is None else today
        try:
            entries = engine.load_exceptions(args["exceptions-file"], today)
        except engine.ExceptionsError as error:
            raise InputError("the exceptions file is not valid: %s" % error)
        try:
            allow_entries = [] if allow_path is None else allow_engine.load_allowlist(allow_path, today)
        except allow_engine.AllowlistError as error:
            raise InputError("the secret allowlist file is not valid: %s" % error)
        vuln_data = load_report_data(args["vuln"], "vulnerability")
        vulns = fixable_vulnerabilities(results_of(vuln_data, "vulnerability"))
        secret_data = load_report_data(args["secret"], "secret")
        secrets = secret_findings(results_of(secret_data, "secret"))
        # An exception binds to the digest the reference names, and only when the
        # report confirms it scanned that digest. Otherwise none applies.
        digest, unbound = engine.reference_digest(reference), "the reference has no sha256 digest"
        if digest is not None and digest not in engine.report_digests(vuln_data):
            digest, unbound = None, "the Trivy report does not list the digest in Metadata.RepoDigests"
        verdict = engine.evaluate(entries, parse_reference(reference)[1], digest, vulns, today, unbound)
        # The secret allowlist has its own digest check, against the report its findings come from.
        secret_digest, secret_unbound = engine.reference_digest(reference), "the reference has no sha256 digest"
        if secret_digest is not None and secret_digest not in engine.report_digests(secret_data):
            secret_digest, secret_unbound = None, "the Trivy secret report does not list the digest in Metadata.RepoDigests"
        allowance = allow_engine.evaluate(allow_entries, parse_reference(reference)[1], secret_digest, secrets, today,
                                          secret_unbound)
    except InputError as error:
        message = "Trivy image %s: %s" % (clean(reference), error)
        err.write("::error::%s\n" % clean(message, 600))
        write_summary(summary, "### Trivy image: %s\n\n**Failed closed:** %s\n" % (cell(reference), cell(error, 600)))
        return 2
    failing, excepted, stale, expired = verdict["failing"], verdict["excepted"], verdict["stale"], verdict["expired"]
    secrets, allowlisted = allowance["failing"], allowance["allowed"]
    allow_stale, allow_expired = allowance["stale"], allowance["expired"]
    write_summary(summary, render_summary(reference, failing, secrets, excepted, stale, expired,
                                          allowlisted, allow_stale, allow_expired))
    for v in failing:
        out.write("fixable %s %s %s %s -> %s\n" % (v["severity"], v["id"], v["package"], v["installed"], v["fixed"]))
    for s in secrets:
        out.write("secret %s %s in %s line %s\n" % (s["severity"], s["rule"], s["target"], s["line"]))
    for v, e in excepted:
        out.write("excepted %s %s %s until %s, reviewed by %s\n" % (
            v["severity"], v["id"], v["package"], clean(e["expires"]), clean(e["reviewer"])))
    for s, e in allowlisted:
        out.write("allowlisted known-public %s %s in %s line %s, layer %s, until %s, reviewed by %s, evidence %s\n" % (
            s["severity"], s["rule"], s["target"], s["line"], s["layer"], clean(e["expires"]), clean(e["reviewer"]),
            clean(e["evidence"], 300)))
    for e, why in stale[:MAX_ROWS]:
        out.write("::warning::Stale exception (%s), remove it or fix it: %s %s %s\n" % (
            clean(why), clean(e["image"]), clean(e["id"]), clean(e["package"])))
    for e in expired[:MAX_ROWS]:
        err.write("::error::Exception expired on %s: %s %s %s (reviewer %s). Check for a patched release, then "
                  "renew or delete it (docs/IMAGE_EXCEPTIONS.md).\n" % (
                      clean(e["expires"]), clean(e["image"]), clean(e["id"]), clean(e["package"]), clean(e["reviewer"])))
    for e, why in allow_stale[:MAX_ROWS]:
        out.write("::warning::Stale secret allowlist entry (%s), remove it or fix it: %s %s %s\n" % (
            clean(why), clean(e["image"]), clean(e["rule"]), clean(e["target"])))
    for e in allow_expired[:MAX_ROWS]:
        err.write("::error::Secret allowlist entry expired on %s: %s %s %s line %s (reviewer %s). Check that the value "
                  "is still public by design, then renew or delete it (docs/IMAGE_EXCEPTIONS.md).\n" % (
                      clean(e["expires"]), clean(e["image"]), clean(e["rule"]), clean(e["target"]),
                      clean(e["start_line"]), clean(e["reviewer"])))
    if failing or secrets or expired or allow_expired:
        err.write("::error::Trivy image %s: %d fixable HIGH/CRITICAL vulnerabilities, %d secrets, %d expired exceptions, "
                  "%d expired secret allowlist entries\n"
                  % (clean(reference), len(failing), len(secrets), len(expired), len(allow_expired)))
        return 1
    out.write("passed: %s (%d excepted, %d secrets allowlisted)\n" % (clean(reference), len(excepted), len(allowlisted)))
    return 0


def parse_gate_args(argv):
    names = {"--reference": "reference", "--vuln": "vuln", "--secret": "secret",
             "--exceptions-file": "exceptions-file", "--secret-allowlist-file": "secret-allowlist-file",
             "--summary": "summary"}
    args, i = {}, 0
    while i < len(argv):
        key = names.get(argv[i])
        if key is None or key in args or i + 1 >= len(argv):
            raise InputError("bad gate arguments")
        args[key] = argv[i + 1]
        i += 2
    missing = {"reference", "vuln", "secret", "exceptions-file"} - set(args)
    if missing:
        raise InputError("missing gate arguments: " + ", ".join(sorted(missing)))
    return args


def main(argv, env=None, out=None, err=None, today=None):
    env = os.environ if env is None else env
    out = sys.stdout if out is None else out
    err = sys.stderr if err is None else err
    try:
        if len(argv) >= 1 and argv[0] == "plan" and len(argv) == 1:
            return plan(env, out)
        if len(argv) >= 1 and argv[0] == "gate":
            return gate(parse_gate_args(argv[1:]), out, err, env, today)
        raise InputError("usage: trivy_images.py plan | gate --reference R --vuln F --secret F --exceptions-file P "
                         "[--secret-allowlist-file P]")
    except InputError as error:
        err.write("::error::%s\n" % clean(error, 600))
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
