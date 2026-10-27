#!/usr/bin/env python3
"""Plan and gate the image scans of trivy-images.yml.

Usage (always as python3 -I, from the shared checkout):

  trivy_images.py plan
      Reads IMAGES (newline-separated references) and EXCEPTIONS_FILE from the
      environment, validates them strictly and appends matrix=<json> to the
      file named by GITHUB_OUTPUT. Any invalid input exits non-zero.

  trivy_images.py gate --reference REF --vuln VULN.json --secret SECRET.json
                       --exceptions-file PATH [--summary FILE]
      Fail-closed verdict on one image from the two Trivy JSON reports. Exit 0
      only when the image has no HIGH or CRITICAL vulnerability with a fix and
      no secret at any severity. Writes a Markdown summary to --summary (the
      step summary file, when not given the GITHUB_STEP_SUMMARY variable).
      Exit 1: the image fails. Exit 2: the input cannot be trusted (missing or
      malformed report, unsupported exceptions file); this fails the job too.

Exceptions are not supported yet: until the exception engine is released, an
exceptions file that exists and is not empty fails the gate instead of being
ignored. The caller's .trivyignore and trivy.yaml are not read either.

Standard library only; it imports nothing next to itself, so -I is enough.
"""
import json
import os
import re
import sys

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


def clean(value, limit=200):
    """Untrusted text made safe for a log line and a Markdown table cell: no
    control characters, no workflow command, no pipe or backtick."""
    text = "" if value is None else str(value)
    text = re.sub(r"[\x00-\x1f\x7f-\x9f  ]", " ", text)
    text = text.replace("::", ": :").replace("##[", "# #[")
    text = text.replace("|", "/").replace("`", "'")
    text = text.strip()
    return text if len(text) <= limit else text[: limit - 3] + "..."


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


def validate_exceptions_path(path):
    """A relative path inside the caller's checkout, in a plain character set."""
    if not isinstance(path, str) or not _PATH.match(path):
        raise InputError("exceptions-file must be a relative path of letters, digits and . _ / -")
    parts = path.split("/")
    if path.startswith("/") or path.startswith("-") or any(p in ("", ".", "..") for p in parts):
        raise InputError("exceptions-file must be a relative path inside the repository, without . or .. parts")
    return path


def plan(env, out):
    entries = parse_images(env.get("IMAGES", ""))
    validate_exceptions_path(env.get("EXCEPTIONS_FILE", ""))
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


def load_report(path, label):
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
            severity = vuln.get("Severity")
            if severity not in ALL_SEVERITIES:
                raise InputError("a vulnerability has an unknown severity: " + clean(severity))
            if severity not in GATE_SEVERITIES:
                continue
            fixed = vuln.get("FixedVersion")
            if (isinstance(fixed, str) and fixed.strip()) or vuln.get("Status") == "fixed":
                found.append({
                    "id": clean(vuln.get("VulnerabilityID")),
                    "severity": severity,
                    "package": clean(vuln.get("PkgName")),
                    "installed": clean(vuln.get("InstalledVersion")),
                    "fixed": clean(fixed),
                    "target": clean(result.get("Target")),
                })
    return found


def secret_findings(results):
    """Every secret, at any severity. The matched text is never read."""
    found = []
    for result in results:
        for secret in _items(result, "Secrets", "secret"):
            found.append({
                "rule": clean(secret.get("RuleID")),
                "severity": clean(secret.get("Severity")),
                "title": clean(secret.get("Title")),
                "target": clean(result.get("Target")),
                "line": clean(secret.get("StartLine")),
            })
    return found


def check_exceptions(path):
    """Exceptions are not supported yet: a non-empty file fails rather than being ignored."""
    validate_exceptions_path(path)
    if not os.path.lexists(path):
        return
    try:
        size = os.stat(path).st_size if os.path.isfile(path) else None
    except OSError:
        size = None
    if size == 0:
        return
    raise InputError(
        "%s exists and is not empty, but image exceptions are not supported until the exception "
        "engine release; it is not being ignored silently. Delete the file, or leave it empty, "
        "and fix the findings instead." % clean(path)
    )


def render_summary(reference, vulns, secrets):
    lines = ["### Trivy image: %s" % clean(reference), ""]
    if not vulns and not secrets:
        lines.append("Passed: no fixable HIGH or CRITICAL vulnerability and no secret.")
        return "\n".join(lines) + "\n"
    lines.append("**Failed.** %d fixable HIGH/CRITICAL vulnerabilities, %d secrets." % (len(vulns), len(secrets)))
    if vulns:
        lines += ["", "| Severity | Vulnerability | Package | Installed | Fixed in | Target |", "| --- | --- | --- | --- | --- | --- |"]
        for v in vulns[:MAX_ROWS]:
            lines.append("| %s | %s | %s | %s | %s | %s |" % (
                v["severity"], v["id"], v["package"], v["installed"], v["fixed"], v["target"]))
        if len(vulns) > MAX_ROWS:
            lines.append("")
            lines.append("... and %d more." % (len(vulns) - MAX_ROWS))
    if secrets:
        lines += ["", "| Severity | Rule | Title | File | Line |", "| --- | --- | --- | --- | --- |"]
        for s in secrets[:MAX_ROWS]:
            lines.append("| %s | %s | %s | %s | %s |" % (s["severity"], s["rule"], s["title"], s["target"], s["line"]))
        if len(secrets) > MAX_ROWS:
            lines.append("")
            lines.append("... and %d more." % (len(secrets) - MAX_ROWS))
    return "\n".join(lines) + "\n"


def write_summary(path, text):
    if not path:
        return
    with open(path, "a", encoding="utf-8", newline="\n") as handle:
        handle.write(text + "\n")


def gate(args, out, err, env):
    summary = args.get("summary") or env.get("GITHUB_STEP_SUMMARY")
    reference = args["reference"]
    try:
        check_exceptions(args["exceptions-file"])
        vulns = fixable_vulnerabilities(load_report(args["vuln"], "vulnerability"))
        secrets = secret_findings(load_report(args["secret"], "secret"))
    except InputError as error:
        message = "Trivy image %s: %s" % (clean(reference), error)
        err.write("::error::%s\n" % clean(message, 600))
        write_summary(summary, "### Trivy image: %s\n\n**Failed closed:** %s\n" % (clean(reference), clean(error, 600)))
        return 2
    write_summary(summary, render_summary(reference, vulns, secrets))
    for v in vulns:
        out.write("fixable %s %s %s %s -> %s\n" % (v["severity"], v["id"], v["package"], v["installed"], v["fixed"]))
    for s in secrets:
        out.write("secret %s %s in %s line %s\n" % (s["severity"], s["rule"], s["target"], s["line"]))
    if vulns or secrets:
        err.write("::error::Trivy image %s: %d fixable HIGH/CRITICAL vulnerabilities, %d secrets\n"
                  % (clean(reference), len(vulns), len(secrets)))
        return 1
    out.write("passed: %s\n" % clean(reference))
    return 0


def parse_gate_args(argv):
    names = {"--reference": "reference", "--vuln": "vuln", "--secret": "secret",
             "--exceptions-file": "exceptions-file", "--summary": "summary"}
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


def main(argv, env=None, out=None, err=None):
    env = os.environ if env is None else env
    out = sys.stdout if out is None else out
    err = sys.stderr if err is None else err
    try:
        if len(argv) >= 1 and argv[0] == "plan" and len(argv) == 1:
            return plan(env, out)
        if len(argv) >= 1 and argv[0] == "gate":
            return gate(parse_gate_args(argv[1:]), out, err, env)
        raise InputError("usage: trivy_images.py plan | gate --reference R --vuln F --secret F --exceptions-file P")
    except InputError as error:
        err.write("::error::%s\n" % clean(error, 600))
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
