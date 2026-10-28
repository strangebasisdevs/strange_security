#!/usr/bin/env python3
"""Failure-safe, redacted report of the findings in a scan's SARIF file.

Usage (always as python3 -I, from the shared checkout):

  sarif_report.py --tool trivy-vuln|trivy-secret|semgrep|gitleaks
                  --sarif PATH [--summary FILE]

Renders the findings of the SARIF file the scan already wrote into the step
summary (--summary, else the GITHUB_STEP_SUMMARY variable, else standard
output) and prints one ::error file=...,line=...:: annotation per finding on
standard output, capped. This makes a failed check name the package, rule and
location even when the SARIF is not uploaded to code scanning (upload-sarif:
false).

The report is for people, never for the gate. The scan step alone decides
whether the job passes: this script exits 0 whatever happens (a missing,
unreadable or malformed SARIF, an unexpected error, bad arguments), says so in
the summary and as a ::warning::, and so can neither turn a failing job green
nor a passing job red.

Never shown, by construction (only the fields below are read, nothing is copied
wholesale): the matched secret text, source snippets, SARIF snippet and
contextRegion fields, fingerprints, and for secret scanners (Trivy secrets,
gitleaks) the result message. Read fields: rule id, level, location uri and
start line, the rule's static description (fullDescription, else shortDescription;
never the result message, which Semgrep fills with matched code), and for Trivy vulnerabilities the
Package, Installed Version, Fixed Version and Severity lines of the message.
For gitleaks also the commit sha (first 12 hex digits) of the finding.

All untrusted text goes through clean() and cell() of scripts/trivy_images.py,
loaded by path (python3 -I has no script directory on sys.path), plus a few
extra neutralisations for Markdown autolinks.

Standard library only.
"""
import importlib.util
import json
import os
import re
import sys
import urllib.parse

MAX_ROWS = 200
MAX_ANNOTATIONS = 10  # GitHub shows at most 10 error annotations per step.
MAX_BYTES = 64 * 1024 * 1024
MESSAGE_LIMIT = 200

# tool -> (heading, kind). kind: vuln, secret (no message, ever) or code.
TOOLS = {
    "trivy-vuln": ("Trivy vulnerability findings", "Trivy", "vuln"),
    "trivy-secret": ("Trivy secret findings", "Trivy", "secret"),
    "semgrep": ("Semgrep findings", "Semgrep", "code"),
    "gitleaks": ("Gitleaks findings", "Gitleaks", "secret"),
}
SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "ERROR": 1, "MEDIUM": 2, "WARNING": 2, "LOW": 3, "INFO": 3,
                 "NOTE": 3, "UNKNOWN": 4}
TAG_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
_LEVELS = {"error": "ERROR", "warning": "WARNING", "note": "INFO", "none": "INFO"}
_SEVERITY_LINE = re.compile(r"^Severity:[ \t]*(CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN)[ \t]*$", re.M)
_FIELD_LINES = {
    "package": re.compile(r"^Package:[ \t]*(.*)$", re.M),
    "installed": re.compile(r"^Installed Version:[ \t]*(.*)$", re.M),
    "fixed": re.compile(r"^Fixed Version:[ \t]*(.*)$", re.M),
}
_COMMIT = re.compile(r"^[0-9a-f]{7,64}$")
_UNSAFE_PROPERTY = re.compile("[\x00-\x1f\x7f-\x9f\u2028\u2029]")


class ReportError(Exception):
    """The SARIF cannot be rendered; reported in the summary, never fatal."""


_HELPERS = []


def _helpers():
    """(clean, cell) of scripts/trivy_images.py, loaded by path once."""
    if not _HELPERS:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "trivy_images.py")
        spec = importlib.util.spec_from_file_location("trivy_images", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _HELPERS.extend([module.clean, module.cell])
    return _HELPERS


def clean(value, limit=200):
    return _helpers()[0](value, limit)


def _cell(value, limit=200):
    return _helpers()[1](value, limit)


def cell(value, limit=MESSAGE_LIMIT):
    """cell() plus the Markdown autolinks it does not cover: www. hosts and
    e-mail addresses or mentions."""
    text = _cell(value, limit)
    text = re.sub(r"(?i)www\.", lambda m: m.group(0)[:3] + "&#46;", text)
    return text.replace("@", "&#64;")


def prop(value, limit=300):
    """A workflow command property value (file=, title=): no control character,
    and % : , escaped so the value cannot end the property list or the command."""
    text = _UNSAFE_PROPERTY.sub(" ", "" if value is None else str(value)).strip()
    text = text if len(text) <= limit else text[: limit - 3] + "..."
    text = text.replace("##[", "# #[")
    return text.replace("%", "%25").replace(":", "%3A").replace(",", "%2C")


def data(value, limit=300):
    """A workflow command message: clean() (no :: or ##[) with % escaped."""
    return clean(value, limit).replace("%", "%25")


# ---------------------------------------------------------------- reading


def _dict(value):
    return value if isinstance(value, dict) else {}


def _text(value):
    """value["text"] of a SARIF message object, or "" for anything else."""
    text = _dict(value).get("text")
    return text if isinstance(text, str) else ""


def read_sarif(path):
    try:
        size = os.path.getsize(path)
    except OSError:
        return None
    if size > MAX_BYTES:
        raise ReportError("the SARIF file is larger than %d MiB" % (MAX_BYTES // (1024 * 1024)))
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
        return json.loads(raw.decode("utf-8-sig"))
    except OSError as error:
        raise ReportError("the SARIF file cannot be read: " + clean(error, 100))
    except (ValueError, RecursionError) as error:
        raise ReportError("the SARIF file is not valid JSON: " + clean(error, 100))


def path_of(uri):
    if not isinstance(uri, str):
        return ""
    text = urllib.parse.unquote(uri)
    if text.startswith("file://"):
        text = text[len("file://"):]
    # Semgrep scans /src inside its container: report repo-relative paths.
    if text.startswith("/src/"):
        text = text[len("/src/"):]
    while text.startswith("./"):
        text = text[2:]
    if ".." in re.split(r"[/\\]", text):
        return ""
    return text


def line_of(region):
    line = _dict(region).get("startLine")
    if isinstance(line, int) and not isinstance(line, bool) and 1 <= line <= 10000000:
        return line
    return None


def severity_of(result, rule, message):
    found = _SEVERITY_LINE.search(message)
    if found:
        return found.group(1)
    tags = _dict(rule.get("properties")).get("tags")
    if isinstance(tags, list):
        for tag in tags:
            if isinstance(tag, str) and tag.upper() in TAG_SEVERITIES:
                return tag.upper()
    level = result.get("level")
    if not isinstance(level, str):
        level = _dict(rule.get("defaultConfiguration")).get("level")
    if isinstance(level, str) and level in _LEVELS:
        return _LEVELS[level]
    return "UNKNOWN"


def findings_of(sarif, kind):
    """The findings of a parsed SARIF document, as plain dicts of the allowed fields."""
    runs = _dict(sarif).get("runs")
    if not isinstance(runs, list):
        raise ReportError("the SARIF file has no runs list")
    found = []
    for run in runs:
        run = _dict(run)
        rules = _dict(_dict(run.get("tool")).get("driver")).get("rules")
        rules = [_dict(r) for r in rules] if isinstance(rules, list) else []
        by_id = {r["id"]: r for r in rules if isinstance(r.get("id"), str)}
        results = run.get("results")
        for result in results if isinstance(results, list) else []:
            result = _dict(result)
            rule_id = result.get("ruleId")
            index = result.get("ruleIndex")
            rule = {}
            if isinstance(rule_id, str) and rule_id in by_id:
                rule = by_id[rule_id]
            elif isinstance(index, int) and not isinstance(index, bool) and 0 <= index < len(rules):
                rule = rules[index]
            if not isinstance(rule_id, str) or not rule_id:
                rule_id = rule.get("id") if isinstance(rule.get("id"), str) else "unknown"
            message = _text(result.get("message"))
            locations = result.get("locations")
            first = locations[0] if isinstance(locations, list) and locations else None
            location = _dict(_dict(first).get("physicalLocation"))
            item = {
                "rule": rule_id,
                "severity": severity_of(result, rule, message),
                "file": path_of(_dict(location.get("artifactLocation")).get("uri")),
                "line": line_of(location.get("region")),
            }
            if kind == "vuln":
                for name, pattern in _FIELD_LINES.items():
                    match = pattern.search(message)
                    item[name] = match.group(1) if match else ""
                item["message"] = _text(rule.get("shortDescription"))
            elif kind == "code":
                # Never the result message: Semgrep interpolates matched code into it.
                item["message"] = _text(rule.get("fullDescription")) or _text(rule.get("shortDescription"))
            else:
                item["message"] = ""
                commit = _dict(result.get("partialFingerprints")).get("commitSha")
                item["commit"] = commit[:12] if isinstance(commit, str) and _COMMIT.match(commit) else ""
            found.append(item)
    found.sort(key=lambda f: (SEVERITY_RANK.get(f["severity"], 4), f["file"], f["line"] or 0, f["rule"]))
    return found


# ---------------------------------------------------------------- rendering


def render(heading, tool_name, kind, sarif_name, findings=None, problem=None):
    """(summary markdown, annotation lines, warning lines)."""
    lines = ["### %s" % heading, ""]
    annotations, warnings = [], []
    if problem:
        lines.append("**No findings could be listed:** %s. The result of the scan step above is unchanged and "
                     "decides the job; open its log for the scanner's own output." % cell(problem, 300))
        warnings.append("%s report not available (%s)" % (tool_name, clean(problem, 200)))
        return "\n".join(lines) + "\n", annotations, warnings
    if not findings:
        lines.append("No findings in `%s`. The scan step alone decides whether the job passes." % cell(sarif_name, 100))
        return "\n".join(lines) + "\n", annotations, warnings
    total = len(findings)
    lines.append("**%d finding(s)** from `%s`. Secret values and code snippets are never shown here." % (
        total, cell(sarif_name, 100)))
    lines.append("")
    if kind == "vuln":
        lines += ["| Severity | Vulnerability | Package | Installed | Fixed in | File | Line | Title |",
                  "| --- | --- | --- | --- | --- | --- | --- | --- |"]
    elif kind == "secret":
        head = "| Severity | Rule | File | Line |" + (" Commit |" if tool_name == "Gitleaks" else "")
        lines += [head, "| --- | --- | --- | --- |" + (" --- |" if tool_name == "Gitleaks" else "")]
    else:
        lines += ["| Severity | Rule | File | Line | Message |", "| --- | --- | --- | --- | --- |"]
    for f in findings[:MAX_ROWS]:
        row = [cell(f["severity"]), cell(f["rule"])]
        if kind == "vuln":
            row += [cell(f["package"]), cell(f["installed"]), cell(f["fixed"])]
        row += [cell(f["file"]), cell(f["line"] if f["line"] else "")]
        if kind == "vuln":
            row.append(cell(f["message"], 120))
        elif kind == "code":
            row.append(cell(f["message"]))
        elif tool_name == "Gitleaks":
            row.append(cell(f["commit"]))
        lines.append("| " + " | ".join(row) + " |")
    if total > MAX_ROWS:
        lines += ["", "Truncated: %d of %d findings shown; the rest are in the scanner's own output." % (MAX_ROWS, total)]
    for f in findings[:MAX_ANNOTATIONS]:
        annotations.append(annotation(tool_name, kind, f))
    if total > MAX_ANNOTATIONS:
        lines += ["", "Annotations are capped at %d per scan." % MAX_ANNOTATIONS]
    return "\n".join(lines) + "\n", annotations, warnings


def annotation(tool_name, kind, f):
    if kind == "vuln":
        text = "%s %s in %s %s (fixed in %s)" % (f["severity"], f["rule"], f["package"] or "unknown package",
                                                 f["installed"] or "unknown version", f["fixed"] or "no fixed version")
    elif kind == "secret":
        text = "%s: secret detected by rule %s (value not shown)" % (f["severity"], f["rule"])
    else:
        text = "%s %s" % (f["severity"], f["rule"])
        if f["message"]:
            text += ": " + f["message"]
    props = []
    if f["file"]:
        props.append("file=" + prop(f["file"]))
        if f["line"]:
            props.append("line=%d" % f["line"])
    props.append("title=" + prop("%s %s" % (tool_name, f["rule"]), 120))
    return "::error %s::%s" % (",".join(props), data(text))


# ---------------------------------------------------------------- main


def report(tool, sarif_path, summary_path, out, env):
    heading, tool_name, kind = TOOLS[tool]
    name = os.path.basename(sarif_path.replace("\\", "/"))
    findings, problem = None, None
    try:
        sarif = read_sarif(sarif_path)
        if sarif is None:
            problem = "the SARIF file %s does not exist (the scan may have failed before writing it)" % name
        else:
            findings = findings_of(sarif, kind)
    except ReportError as error:
        problem = str(error)
    text, annotations, warnings = render(heading, tool_name, kind, name, findings, problem)
    target = summary_path or env.get("GITHUB_STEP_SUMMARY")
    if target:
        try:
            with open(target, "a", encoding="utf-8", newline="\n") as handle:
                handle.write(text + "\n")
        except OSError as error:
            warnings.append("cannot write the step summary: " + clean(error, 100))
    else:
        out.write(text + "\n")
    for line in annotations:
        out.write(line + "\n")
    for warning in warnings:
        out.write("::warning title=%s::%s\n" % (prop("Findings report"), data(warning)))


def parse_args(argv):
    names = {"--tool": "tool", "--sarif": "sarif", "--summary": "summary"}
    args, i = {}, 0
    while i < len(argv):
        key = names.get(argv[i])
        if key is None or key in args or i + 1 >= len(argv):
            raise ReportError("bad arguments")
        args[key] = argv[i + 1]
        i += 2
    if args.get("tool") not in TOOLS or "sarif" not in args:
        raise ReportError("usage: sarif_report.py --tool %s --sarif PATH [--summary FILE]" % "|".join(sorted(TOOLS)))
    return args


def main(argv, env=None, out=None):
    """Always 0: the scan step decides the job, this report never does."""
    env = os.environ if env is None else env
    out = sys.stdout if out is None else out
    try:
        args = parse_args(argv)
        report(args["tool"], args["sarif"], args.get("summary"), out, env)
    except Exception as error:  # noqa: BLE001 - nothing here may change the job result
        try:
            out.write("::warning title=Findings report::%s\n" % data("the findings report failed: %s" % error, 300))
        except Exception:  # noqa: BLE001
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
