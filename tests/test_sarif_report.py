"""scripts/sarif_report.py (the failure-safe, redacted findings report) and the
wiring of its steps in trivy.yml, semgrep.yml and gitleaks.yml."""
import importlib.util
import io
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import unicodedata
import unittest

from tests.test_trivy_image_validation import BASH, extract_run_block
from tests.test_workflows import read, step

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SCRIPT = os.path.join(HERE, "..", "scripts", "sarif_report.py")

spec = importlib.util.spec_from_file_location("sarif_report", SCRIPT)
sr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sr)

SECRET_TEXT = "AKIAIOSFODNN7EXAMPLE-live-secret-value"
SNIPPET = "password = 'hunter2-snippet'"
HOSTILE = "a|b`c::error::boom ##[group]x <img src=x> [l](http://e.com) ![i](u) www.evil.example (x) \\ @user\r\nnext"


def vuln_message(package="lodash", installed="4.17.0", fixed="4.17.21", severity="HIGH"):
    return ("Package: %s\nInstalled Version: %s\nVulnerability CVE-2021-23337\nSeverity: %s\n"
            "Fixed Version: %s\nLink: [CVE-2021-23337](https://avd.aquasec.com/nvd/cve-2021-23337)"
            % (package, installed, severity, fixed))


def result(rule_id, message, uri="package-lock.json", line=7, **extra):
    region = {"startLine": line, "snippet": {"text": SNIPPET}}
    region.update(extra.pop("region", {}))
    item = {
        "ruleId": rule_id,
        "level": "error",
        "message": {"text": message},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": uri, "uriBaseId": "ROOTPATH"},
            "region": region,
            "contextRegion": {"startLine": 1, "snippet": {"text": SNIPPET}},
        }}],
        "partialFingerprints": {"primaryLocationLineHash": SNIPPET, "commitSha": "0123456789abcdef" * 2 + "01234567",
                                "author": "Alice Author", "email": "alice@example.com",
                                "commitMessage": "add " + SECRET_TEXT},
        "properties": {"secret": SECRET_TEXT},
    }
    item.update(extra)
    return item


def sarif(results, rules=None):
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "t", "rules": rules or []}},
                                          "results": results}]}


class Runner:
    """Runs the script's main() on a SARIF document in a temp directory."""

    def __init__(self, case):
        self.dir = tempfile.TemporaryDirectory()
        case.addCleanup(self.dir.cleanup)
        self.sarif_path = os.path.join(self.dir.name, "scan.sarif")
        self.summary_path = os.path.join(self.dir.name, "summary.md")

    def write(self, document):
        text = document if isinstance(document, str) else json.dumps(document)
        with open(self.sarif_path, "w", encoding="utf-8") as handle:
            handle.write(text)

    def run(self, tool):
        out = io.StringIO()
        code = sr.main(["--tool", tool, "--sarif", self.sarif_path, "--summary", self.summary_path], env={}, out=out)
        summary = ""
        if os.path.exists(self.summary_path):
            with open(self.summary_path, encoding="utf-8") as handle:
                summary = handle.read()
        return code, summary, out.getvalue()


class Rendering(unittest.TestCase):
    def test_trivy_vulnerability_row_and_annotation(self):
        r = Runner(self)
        rules = [{"id": "CVE-2021-23337", "shortDescription": {"text": "lodash command injection"},
                  "properties": {"tags": ["vulnerability", "security", "HIGH"]}}]
        r.write(sarif([result("CVE-2021-23337", vuln_message())], rules))
        code, summary, out = r.run("trivy-vuln")
        self.assertEqual(code, 0)
        self.assertIn("| HIGH | CVE-2021-23337 | lodash | 4.17.0 | 4.17.21 | package-lock.json | 7 | "
                      "lodash command injection |", summary)
        self.assertIn("::error file=package-lock.json,line=7,title=Trivy CVE-2021-23337::"
                      "HIGH CVE-2021-23337 in lodash 4.17.0 (fixed in 4.17.21)", out)
        self.assertEqual(out.count("::error "), 1)

    def test_trivy_secret_shows_rule_file_line_only(self):
        r = Runner(self)
        message = "Artifact: .env\nType: \nSecret AWS Access Key ID\nSeverity: CRITICAL\nMatch: " + SECRET_TEXT
        r.write(sarif([result("aws-access-key-id", message, uri="config/.env", line=3)]))
        code, summary, out = r.run("trivy-secret")
        self.assertEqual(code, 0)
        self.assertIn("| CRITICAL | aws-access-key-id | config/.env | 3 |", summary)
        self.assertIn("::error file=config/.env,line=3,title=Trivy aws-access-key-id::"
                      "CRITICAL: secret detected by rule aws-access-key-id (value not shown)", out)
        for text in (summary, out):
            self.assertNotIn("Match", text)
            self.assertNotIn("Secret AWS", text)

    def test_semgrep_row_uses_the_static_rule_description(self):
        r = Runner(self)
        rules = [{"id": "python.lang.eval", "fullDescription": {"text": "Detected eval of user input"}}]
        r.write(sarif([result("python.lang.eval", "Detected eval of " + SECRET_TEXT, uri="src/app.py", line=12)],
                      rules))
        code, summary, out = r.run("semgrep")
        self.assertEqual(code, 0)
        self.assertIn("| ERROR | python.lang.eval | src/app.py | 12 | Detected eval of user input |", summary)
        self.assertIn("::error file=src/app.py,line=12,title=Semgrep python.lang.eval::"
                      "ERROR python.lang.eval: Detected eval of user input", out)
        self.assertNotIn(SECRET_TEXT, summary + out)

    def test_semgrep_never_renders_the_result_message(self):
        sentinel = "SENTINEL-MATCHED-CODE-" + SECRET_TEXT
        cases = {
            "neither": [{"id": "rule.x"}],
            "short": [{"id": "rule.x", "shortDescription": {"text": "short static"}}],
            "none": [],
        }
        for label, rules in cases.items():
            r = Runner(self)
            r.write(sarif([result("rule.x", sentinel, uri="a.py", line=1)], rules))
            code, summary, out = r.run("semgrep")
            self.assertEqual(code, 0)
            self.assertNotIn("SENTINEL-MATCHED-CODE", summary + out, label)
            self.assertNotIn(SECRET_TEXT, summary + out, label)
            self.assertIn("rule.x", summary)
        r = Runner(self)
        r.write(sarif([result("rule.x", sentinel, uri="a.py", line=1)], cases["short"]))
        _, summary, out = r.run("semgrep")
        self.assertIn("| ERROR | rule.x | a.py | 1 | short static |", summary)
        r = Runner(self)
        r.write(sarif([result("rule.x", sentinel, uri="a.py", line=1)], cases["neither"]))
        _, summary, out = r.run("semgrep")
        self.assertIn("| ERROR | rule.x | a.py | 1 |  |", summary)
        self.assertIn("title=Semgrep rule.x::ERROR rule.x\n", out)

    def test_full_description_wins_over_short(self):
        r = Runner(self)
        rules = [{"id": "rule.x", "fullDescription": {"text": "the full one"},
                  "shortDescription": {"text": "the short one"}}]
        r.write(sarif([result("rule.x", "msg", uri="a.py", line=1)], rules))
        _, summary, _ = r.run("semgrep")
        self.assertIn("the full one", summary)
        self.assertNotIn("the short one", summary)

    def test_paths_are_repo_relative(self):
        cases = {
            "/src/app/main.py": "app/main.py",
            "file:///src/app/main.py": "app/main.py",
            "file://src/app/main.py": "src/app/main.py",
            "./app/main.py": "app/main.py",
            "app/main.py": "app/main.py",
            "/src/./x.py": "x.py",
            "/src/a%20b.py": "a%20b.py",
            "file:///src/a%20b.py": "a b.py",
            "FILE:///src/a%20b.py": "a b.py",
            "config%20prod.env": "config%20prod.env",
        }
        for uri, expected in cases.items():
            self.assertEqual(sr.path_of(uri), expected, uri)

    def test_paths_with_dotdot_components_are_refused(self):
        for uri in ("/src/../etc/passwd", "../x.py", "a/../b.py", "file:///src/a/../../b", "a\\..\\b",
                    "file:///src/%2e%2e/x", "file:///src/%2E%2E/x", "..", "/src/.."):
            self.assertEqual(sr.path_of(uri), "", uri)
        self.assertEqual(sr.path_of("/src/a..b/c...py"), "a..b/c...py")
        # Plain paths are literal: a %2e%2e component is a name, not "..".
        self.assertEqual(sr.path_of("/src/%2e%2e/x"), "%2e%2e/x")

    def test_plain_paths_are_not_percent_decoded_for_semgrep_and_gitleaks(self):
        for tool in ("semgrep", "gitleaks"):
            r = Runner(self)
            r.write(sarif([result("rule.x", "m", uri="config%20prod.env", line=2),
                           result("rule.y", "m", uri="/src/%2e%2e/%2e%2e/x.py", line=3)]))
            code, summary, out = r.run(tool)
            self.assertEqual(code, 0)
            self.assertIn("config%20prod.env", summary, tool)
            self.assertNotIn("config prod.env", summary + out, tool)
            self.assertIn("%2e%2e/%2e%2e/x.py", summary, tool)

    def test_trivy_paths_are_percent_decoded_once(self):
        # Trivy writes artifact URIs through Go's url.Parse(...).String().
        cases = {
            "dir/a%20b.env": "dir/a b.env",
            "dir/a%2520b.env": "dir/a%20b.env",
            "file:///src/dir/a%20b.env": "dir/a b.env",
            "plain/x.env": "plain/x.env",
            "a%23b%3Fc.env": "a#b?c.env",
        }
        for uri, expected in cases.items():
            self.assertEqual(sr.path_of(uri, True), expected, uri)
        # Without the producer, a plain path stays literal.
        self.assertEqual(sr.path_of("dir/a%20b.env"), "dir/a%20b.env")
        self.assertEqual(sr.path_of("config%20prod.env"), "config%20prod.env")

    def test_decoded_trivy_paths_are_checked_again(self):
        for uri in ("%2e%2e/x", "%2E%2E/x", "a/%2e%2e/b", "a%2f%2e%2e%2fb", "a%5c..%5cb", "a%5c%2e%2e%5cb",
                    "%00", "a%00b", "a%0ab", "a%0db", "a%1bb", "a%7fb", "a%c2%85b", "a%e2%80%a8b",
                    "%2fetc/passwd", "%5cwindows", "C%3A/x", "file:///src/%2e%2e/x", "file:///etc/x"):
            self.assertEqual(sr.path_of(uri, True), "", uri)

    def test_format_characters_in_a_path_are_refused_like_control_characters(self):
        # Cf: bidi controls and zero-width characters, whatever the producer.
        for uri in ("a%E2%80%AEvne.yp", "%E2%80%8B", "a%e2%80%aeb", "a%EF%BB%BFb", "a%E2%81%A6b", "a%D8%9Cb",
                    "a%E2%80%8Eb", "a%E2%80%8Db", "a%E2%81%A0b", "file:///src/a%E2%80%AEb"):
            self.assertEqual(sr.path_of(uri, True), "", uri)
        for uri in ("a\u202evne.yp", "\u200b", "a\ufeffb", "/src/a\u2066b", "file:///src/a\u202eb", "a\u061cb"):
            self.assertEqual(sr.path_of(uri), "", ascii(uri))
            self.assertEqual(sr.path_of(uri, True), "", ascii(uri))
        # Other non-ASCII text is unchanged.
        self.assertEqual(sr.path_of("caf%C3%A9.env", True), "caf\u00e9.env")
        self.assertEqual(sr.path_of("%E6%97%A5%E6%9C%AC/%E8%AA%9E.env", True), "\u65e5\u672c/\u8a9e.env")
        self.assertEqual(sr.path_of("caf\u00e9.env"), "caf\u00e9.env")
        self.assertEqual(sr.path_of("\u65e5\u672c/\u8a9e.env"), "\u65e5\u672c/\u8a9e.env")

    def test_a_path_with_a_format_character_keeps_the_finding_with_an_empty_file(self):
        cases = {"trivy-vuln": "a%E2%80%AEvne.yp", "trivy-secret": "%E2%80%8B",
                 "semgrep": "a\u202evne.yp", "gitleaks": "\u200b"}
        for tool, uri in cases.items():
            r = Runner(self)
            r.write(sarif([result("rule.x", vuln_message(), uri=uri, line=2), result("rule.y", "m", line=3)]))
            code, summary, out = r.run(tool)
            self.assertEqual(code, 0)
            self.assertIn("2 finding(s)", summary, tool)
            self.assertIn("title=%s rule.x::" % sr.TOOLS[tool][1], out, tool)
            self.assertNotIn("file=a", out, tool)
            self.assertFalse([c for c in summary + out if unicodedata.category(c) == "Cf"], tool)

    def test_other_text_with_format_characters_renders_visible_escapes(self):
        bad = "x\u202ey\ufeffz\u200b"
        shown = r"x\u202ey\ufeffz\u200b"
        rules = [{"id": "r" + bad, "shortDescription": {"text": "t" + bad}, "fullDescription": {"text": "f" + bad}}]
        for tool in sr.TOOLS:
            r = Runner(self)
            r.write(sarif([result("r" + bad, vuln_message(package="p" + bad, installed="i" + bad, fixed="v" + bad),
                                  uri="ok.py", line=1)], rules))
            _, summary, out = r.run(tool)
            for text in (summary, out):
                self.assertFalse([c for c in text if unicodedata.category(c) == "Cf"], tool)
            self.assertIn("r" + shown.replace("\\", "&#92;"), summary, tool)
            self.assertIn("r" + shown, out, tool)
        self.assertEqual(sr.prop(bad), shown)
        self.assertEqual(sr.data(bad), shown)

    def test_the_producer_comes_only_from_the_tool_argument(self):
        # A Semgrep or gitleaks SARIF that names itself Trivy is not percent-decoded.
        for tool in ("semgrep", "gitleaks"):
            r = Runner(self)
            document = sarif([result("rule.x", "m", uri="a%20b%E2%80%AEc.env", line=2),
                              result("rule.y", "m", uri="dir/d%20e.env", line=3)])
            document["runs"][0]["tool"]["driver"]["name"] = "Trivy"
            r.write(document)
            _, summary, out = r.run(tool)
            self.assertIn("dir/d%20e.env", summary, tool)
            self.assertNotIn("d e.env", summary + out, tool)
            self.assertIn("a%20b%E2%80%AEc.env", summary, tool)

    def test_trivy_report_decodes_and_semgrep_gitleaks_stay_literal(self):
        results = [result("rule.x", "m", uri="dir/a%20b.env", line=2),
                   result("rule.y", "m", uri="%2e%2e/etc/passwd", line=3),
                   result("rule.z", "m", uri="a%0a::error::boom.env", line=4)]
        for tool in ("trivy-vuln", "trivy-secret"):
            r = Runner(self)
            r.write(sarif(results))
            code, summary, out = r.run(tool)
            self.assertEqual(code, 0)
            self.assertIn("dir/a b.env", summary, tool)
            self.assertIn("file=dir/a b.env,", out, tool)
            self.assertNotIn("passwd", summary + out, tool)
            self.assertNotIn("::error::boom", summary + out, tool)
        for tool in ("semgrep", "gitleaks"):
            r = Runner(self)
            r.write(sarif([result("rule.x", "m", uri="config%20prod.env", line=2)]))
            _, summary, out = r.run(tool)
            self.assertIn("config%20prod.env", summary, tool)
            self.assertNotIn("config prod.env", summary + out, tool)

    def test_file_uris_are_decoded_for_any_tool(self):
        for tool in sr.TOOLS:
            r = Runner(self)
            r.write(sarif([result("rule.x", "m", uri="file:///src/dir/a%20b.py", line=2),
                           result("rule.y", "m", uri="file:///src/%2e%2e/etc/passwd", line=3)]))
            code, summary, out = r.run(tool)
            self.assertEqual(code, 0)
            self.assertIn("dir/a b.py", summary, tool)
            self.assertNotIn("passwd", summary + out, tool)
        r = Runner(self)
        r.write(sarif([result("rule.x", "m", uri="/src/../etc/passwd", line=3)]))
        _, summary, out = r.run("semgrep")
        self.assertNotIn("passwd", summary + out)
        self.assertNotIn("file=", out)

    def test_src_prefix_is_stripped_in_summary_and_annotation(self):
        r = Runner(self)
        r.write(sarif([result("rule.x", "m", uri="file:///src/pkg/mod.py", line=9)]))
        _, summary, out = r.run("semgrep")
        self.assertIn("| pkg/mod.py | 9 |", summary)
        self.assertIn("::error file=pkg/mod.py,line=9,", out)
        self.assertNotIn("/src", summary + out)

    def test_gitleaks_shows_rule_file_line_and_commit_only(self):
        r = Runner(self)
        r.write(sarif([result("generic-api-key", "generic-api-key has detected secret for file x.", uri="x.txt",
                              line=4)]))
        code, summary, out = r.run("gitleaks")
        self.assertEqual(code, 0)
        self.assertIn("| Severity | Rule | File | Line | Commit |", summary)
        self.assertIn("| ERROR | generic-api-key | x.txt | 4 | 0123456789ab |", summary)
        self.assertNotIn("has detected", summary + out)
        for leaked in ("Alice", "alice@", "add "):
            self.assertNotIn(leaked, summary + out)

    def test_findings_are_sorted_most_severe_first(self):
        r = Runner(self)
        r.write(sarif([result("CVE-2", vuln_message(severity="LOW")), result("CVE-1", vuln_message(severity="CRITICAL"))]))
        _, summary, out = r.run("trivy-vuln")
        self.assertLess(summary.index("CVE-1"), summary.index("CVE-2"))
        self.assertLess(out.index("CVE-1"), out.index("CVE-2"))

    def test_severity_falls_back_to_tags_then_level(self):
        r = Runner(self)
        rules = [{"id": "CVE-9", "properties": {"tags": ["security", "medium"]}}]
        r.write(sarif([result("CVE-9", "Package: p"), result("CVE-8", "Package: q", level="warning")], rules))
        _, summary, _ = r.run("trivy-vuln")
        self.assertIn("| MEDIUM | CVE-9 |", summary)
        self.assertIn("| WARNING | CVE-8 |", summary)

    def test_rule_found_by_index_and_unusual_locations(self):
        r = Runner(self)
        doc = sarif([{"ruleIndex": 0, "message": {"text": "m"}, "locations": []},
                     result("r2", "m", uri="file:///work/a%20b.py", line=0)],
                    [{"id": "idx-rule", "fullDescription": {"text": "from rule"}}])
        r.write(doc)
        code, summary, out = r.run("semgrep")
        self.assertEqual(code, 0)
        self.assertIn("| UNKNOWN | idx-rule |  |  | from rule |", summary)
        self.assertIn("/work/a b.py", summary)
        self.assertIn("::error title=Semgrep idx-rule::", out)
        self.assertNotIn("line=0", out)

    def test_semgrep_severity_ignores_the_result_message(self):
        rules = [{"id": "r.err", "defaultConfiguration": {"level": "error"}},
                 {"id": "r.warn", "defaultConfiguration": {"level": "warning"}}]
        forged = "matched\nSeverity: LOW\nSeverity: CRITICAL"
        r = Runner(self)
        r.write(sarif([result("r.err", forged, level="error"), result("r.warn", forged, uri="b.py", level=None)],
                      rules))
        _, summary, out = r.run("semgrep")
        self.assertIn("| ERROR | r.err |", summary)
        self.assertIn("| WARNING | r.warn |", summary)
        self.assertNotIn("LOW", summary + out)
        self.assertNotIn("CRITICAL", summary + out)
        # Level none maps to INFO; a level that is not a string is UNKNOWN.
        r = Runner(self)
        r.write(sarif([result("r.none", forged, level="none"), result("r.zip", forged, uri="z.py", level=5)]))
        _, summary, _ = r.run("semgrep")
        self.assertIn("| INFO | r.none |", summary)
        self.assertIn("| UNKNOWN | r.zip |", summary)

    def test_gitleaks_severity_ignores_the_result_message(self):
        r = Runner(self)
        r.write(sarif([result("generic-api-key", "k has detected secret for file x\nSeverity: LOW", level="error")]))
        _, summary, _ = r.run("gitleaks")
        self.assertIn("| ERROR | generic-api-key |", summary)

    def test_trivy_tags_win_over_a_forged_severity_line(self):
        # A package or file name with a newline puts a Severity: line before the real one.
        rules = [{"id": "CVE-1", "properties": {"tags": ["vulnerability", "CRITICAL"]}},
                 {"id": "sec-1", "properties": {"tags": ["secret", "HIGH"]}}]
        r = Runner(self)
        r.write(sarif([result("CVE-1", "Package: x\nSeverity: LOW\ny\n" + vuln_message(severity="CRITICAL"))], rules))
        _, summary, _ = r.run("trivy-vuln")
        self.assertIn("| CRITICAL | CVE-1 |", summary)
        r = Runner(self)
        r.write(sarif([result("sec-1", "Artifact: a\nSeverity: LOW\nType: \nSeverity: HIGH\nMatch: m")], rules))
        _, summary, _ = r.run("trivy-secret")
        self.assertIn("| HIGH | sec-1 |", summary)
        # Without tags the message line is still used.
        r = Runner(self)
        r.write(sarif([result("CVE-2", vuln_message(severity="MEDIUM"))]))
        _, summary, _ = r.run("trivy-vuln")
        self.assertIn("| MEDIUM | CVE-2 |", summary)

    def test_no_findings(self):
        r = Runner(self)
        r.write(sarif([]))
        code, summary, out = r.run("semgrep")
        self.assertEqual(code, 0)
        self.assertIn("No findings in `scan.sarif`", summary)
        self.assertIn("scan step alone decides", summary)
        self.assertEqual(out, "")

    def test_summary_defaults_to_the_environment_then_stdout(self):
        r = Runner(self)
        r.write(sarif([]))
        out = io.StringIO()
        sr.main(["--tool", "semgrep", "--sarif", r.sarif_path], env={"GITHUB_STEP_SUMMARY": r.summary_path}, out=out)
        self.assertTrue(os.path.getsize(r.summary_path) > 0)
        self.assertEqual(out.getvalue(), "")
        out = io.StringIO()
        sr.main(["--tool", "semgrep", "--sarif", r.sarif_path], env={}, out=out)
        self.assertIn("### Semgrep findings", out.getvalue())


class Suppressions(unittest.TestCase):
    def with_suppressions(self, rule, suppressions, uri="a.py"):
        item = result(rule, "m", uri=uri, line=1)
        if suppressions is not None:
            item["suppressions"] = suppressions
        return item

    def test_accepted_suppressions_are_counted_not_listed(self):
        accepted = [
            [{"kind": "inSource"}],
            [{"kind": "inSource", "status": "accepted"}],
            [{"kind": "external", "status": "accepted"}],
            [{"kind": "inSource", "status": "rejected"}, {"kind": "external"}],
        ]
        for suppressions in accepted:
            r = Runner(self)
            r.write(sarif([self.with_suppressions("rule.hidden", suppressions),
                           self.with_suppressions("rule.shown", None, uri="b.py")]))
            code, summary, out = r.run("semgrep")
            self.assertEqual(code, 0)
            self.assertNotIn("rule.hidden", summary + out, suppressions)
            self.assertIn("rule.shown", summary)
            self.assertIn("**1 finding(s)**", summary)
            self.assertIn("1 suppressed finding(s)", summary)
            self.assertEqual(out.count("::error "), 1)

    def test_other_suppression_states_are_still_reported(self):
        for suppressions in ([{"kind": "inSource", "status": "rejected"}],
                             [{"kind": "inSource", "status": "underReview"}],
                             [{"kind": "inSource", "status": 5}], [], "x", [None, 3, "x"], {"status": "accepted"}):
            r = Runner(self)
            r.write(sarif([self.with_suppressions("rule.shown", suppressions)]))
            _, summary, out = r.run("semgrep")
            self.assertIn("rule.shown", summary, suppressions)
            self.assertNotIn("suppressed finding", summary)
            self.assertEqual(out.count("::error "), 1)

    def test_suppressed_results_do_not_consume_the_caps(self):
        hidden = [self.with_suppressions("hidden.%d" % n, [{"kind": "inSource"}], uri="a%03d.py" % n)
                  for n in range(sr.MAX_ROWS + 5)]
        shown = [self.with_suppressions("shown.%d" % n, None, uri="z%03d.py" % n) for n in range(3)]
        r = Runner(self)
        r.write(sarif(hidden + shown))
        _, summary, out = r.run("semgrep")
        self.assertEqual(summary.count("shown."), 3)
        self.assertEqual(out.count("::error "), 3)
        self.assertNotIn("hidden.", summary + out)
        self.assertNotIn("Truncated", summary)
        self.assertIn("%d suppressed finding(s)" % (sr.MAX_ROWS + 5), summary)

    def test_all_suppressed_says_so(self):
        r = Runner(self)
        r.write(sarif([self.with_suppressions("rule.hidden", [{"kind": "inSource"}])]))
        _, summary, out = r.run("semgrep")
        self.assertIn("No findings in `scan.sarif`.", summary)
        self.assertIn("1 suppressed finding(s)", summary)
        self.assertEqual(out, "")


class Redaction(unittest.TestCase):
    def test_nothing_but_the_allowed_fields_is_copied(self):
        sentinels = [SECRET_TEXT, SNIPPET, "hunter2", "Alice", "alice@example.com", "SENTINEL-HELP",
                     "SENTINEL-FULL", "SENTINEL-PROP", "SENTINEL-FIX", "SENTINEL-CODEFLOW", "SENTINEL-REGION"]
        rules = [{"id": "r1", "help": {"text": "SENTINEL-HELP", "markdown": "SENTINEL-HELP"},
                  "fullDescription": {"text": "static description"},
                  "properties": {"x": "SENTINEL-PROP"}}]
        extra = {"fixes": [{"description": {"text": "SENTINEL-FIX"}}],
                 "codeFlows": [{"message": {"text": "SENTINEL-CODEFLOW"}}],
                 "relatedLocations": [{"message": {"text": "SENTINEL-REGION"}}],
                 "region": {"snippet": {"text": SNIPPET}, "sourceLanguage": "SENTINEL-REGION"}}
        for tool in sr.TOOLS:
            r = Runner(self)
            message = "Match: %s\nPackage: p\nInstalled Version: 1\nFixed Version: 2\nSeverity: HIGH" % SECRET_TEXT
            r.write(sarif([result("r1", message, **dict(extra))], rules))
            code, summary, out = r.run(tool)
            self.assertEqual(code, 0)
            for text in sentinels:
                self.assertNotIn(text, summary + out, (tool, text))

    def test_run_level_and_result_level_properties_are_not_read(self):
        r = Runner(self)
        doc = sarif([result("r1", "m")])
        doc["runs"][0]["artifacts"] = [{"contents": {"text": SECRET_TEXT}}]
        doc["runs"][0]["properties"] = {"snippet": SECRET_TEXT}
        r.write(doc)
        for tool in sr.TOOLS:
            _, summary, out = r.run(tool)
            self.assertNotIn(SECRET_TEXT, summary + out)

    def test_secret_scanners_never_show_the_message(self):
        for tool in ("trivy-secret", "gitleaks"):
            r = Runner(self)
            rules = [{"id": "r1", "shortDescription": {"text": "SHORT-" + SECRET_TEXT},
                      "fullDescription": {"text": "FULL-" + SECRET_TEXT}}]
            r.write(sarif([result("r1", "MSG-" + SECRET_TEXT)], rules))
            _, summary, out = r.run(tool)
            for marker in ("SHORT-", "FULL-", "MSG-"):
                self.assertNotIn(marker, summary + out, (tool, marker))
            self.assertNotIn(SECRET_TEXT, summary + out)


class Hostile(unittest.TestCase):
    def check_table_row(self, summary):
        rows = [line for line in summary.split("\n") if line.startswith("| ") and "---" not in line][1:]
        self.assertEqual(len(rows), 1, summary)
        return rows[0]

    def test_hostile_text_cannot_inject_markdown_or_commands(self):
        for tool in sr.TOOLS:
            r = Runner(self)
            rules = [{"id": HOSTILE, "fullDescription": {"text": HOSTILE}, "shortDescription": {"text": HOSTILE}}]
            first = HOSTILE.split("\r")[0]
            message = "Package: %s\n" "Installed Version: %s\n" "Fixed Version: %s\n" "Severity: HIGH" % (first, first, first)
            r.write(sarif([result(HOSTILE, message, uri=HOSTILE, line=3)], rules))
            code, summary, out = r.run(tool)
            self.assertEqual(code, 0)
            row = self.check_table_row(summary)
            self.assertNotRegex(row, r"[<>\[\]()!\\`@]|::|##\[|www\.|://", (tool, row))
            # One annotation, on one line, whose only workflow command is its own.
            lines = [line for line in out.split("\n") if line]
            self.assertEqual(len(lines), 1, (tool, out))
            self.assertTrue(lines[0].startswith("::error "), lines[0])
            self.assertEqual(lines[0].count("::"), 1 + 1, lines[0])
            head = lines[0].split("::", 2)[1]
            self.assertNotIn(":", head.replace("%3A", ""))
            self.assertNotRegex(lines[0], r"##\[")
            self.assertNotIn("\r", out)

    def test_pipes_in_a_path_do_not_add_table_columns(self):
        r = Runner(self)
        r.write(sarif([result("r1", "m", uri="a|b|c.py")]))
        _, summary, _ = r.run("semgrep")
        row = self.check_table_row(summary)
        self.assertEqual(row.count("|"), 6)

    def test_annotation_property_escaping(self):
        self.assertEqual(sr.prop("a:b,c%d\ne"), "a%3Ab%2Cc%25d e")
        self.assertEqual(sr.data("x::error::y\n##[z]%"), "x: :error: :y ##[z]%25".replace("##[", "# #["))

    def test_long_values_are_truncated(self):
        r = Runner(self)
        r.write(sarif([result("r" * 500, "m" * 1000, uri="p" * 1000)]))
        _, summary, out = r.run("semgrep")
        self.assertLess(len(summary), 1500)
        self.assertLess(len(out), 1500)
        self.assertIn("...", summary)


class Caps(unittest.TestCase):
    def test_rows_and_annotations_are_capped(self):
        r = Runner(self)
        total = sr.MAX_ROWS + 50
        r.write(sarif([result("r%d" % i, "m", uri="f%d.py" % i, line=i + 1) for i in range(total)]))
        code, summary, out = r.run("semgrep")
        self.assertEqual(code, 0)
        self.assertIn("**%d finding(s)**" % total, summary)
        self.assertEqual(len([line for line in summary.split("\n") if line.startswith("| ERROR")]), sr.MAX_ROWS)
        self.assertIn("Truncated: %d of %d findings shown" % (sr.MAX_ROWS, total), summary)
        self.assertEqual(out.count("::error "), sr.MAX_ANNOTATIONS)
        self.assertIn("Annotations are capped at %d" % sr.MAX_ANNOTATIONS, summary)

    def test_no_truncation_note_at_the_cap(self):
        r = Runner(self)
        r.write(sarif([result("r%d" % i, "m") for i in range(sr.MAX_ROWS)]))
        _, summary, _ = r.run("semgrep")
        self.assertNotIn("Truncated", summary)


class FailSafe(unittest.TestCase):
    def assert_problem(self, r, tool="semgrep"):
        code, summary, out = r.run(tool)
        self.assertEqual(code, 0)
        self.assertIn("No findings could be listed", summary)
        self.assertIn("result of the scan step above is unchanged", summary)
        self.assertIn("::warning title=Findings report::", out)
        self.assertNotIn("::error", out)
        return summary

    def test_missing_file(self):
        r = Runner(self)
        summary = self.assert_problem(r)
        self.assertIn("does not exist", summary)

    def test_malformed_files(self):
        for text in ("", "not json", "{", "[1, 2]", "null", '{"runs": 5}', '{"runs": {"a": 1}}', "\x00\x01",
                     "[" * 100000):
            r = Runner(self)
            r.write(text)
            self.assert_problem(r)

    def test_binary_file(self):
        r = Runner(self)
        with open(r.sarif_path, "wb") as handle:
            handle.write(b"\xff\xfe\x00garbage")
        self.assert_problem(r)

    def test_type_confused_documents_do_not_crash(self):
        documents = [
            {"runs": [None, 1, "x", []]},
            {"runs": [{"results": "x"}]},
            {"runs": [{"results": [None, 1, "x", [], {}]}]},
            {"runs": [{"results": [{}]}]},
            {"runs": [{"tool": [], "results": [{"ruleId": 5, "ruleIndex": "a", "message": 7, "locations": "x",
                                                "suppressions": "x", "level": []}]}]},
            {"runs": [{"tool": {"driver": {"rules": "x"}}, "results": [{"ruleIndex": 3, "locations": [5]}]}]},
            {"runs": [{"tool": {"driver": {"rules": [None, 3, {"id": 4}]}},
                       "results": [{"ruleId": "a", "locations": [{"physicalLocation": {
                           "artifactLocation": {"uri": 5}, "region": {"startLine": True}}}],
                           "partialFingerprints": {"commitSha": 5}}]}]},
        ]
        for tool in sr.TOOLS:
            for document in documents:
                r = Runner(self)
                r.write(document)
                code, summary, _ = r.run(tool)
                self.assertEqual(code, 0)
                self.assertIn("###", summary)

    def test_wrong_types_for_runs_and_results_are_a_problem_not_no_findings(self):
        for document in ({"runs": [{"results": "corrupt"}]}, {"runs": [{"results": {"a": 1}}]},
                         {"runs": [{"results": 5}]}, {"runs": [{"results": True}]},
                         {"runs": [{"results": [{"ruleId": "a"}, "x"]}]}, {"runs": [{"results": [None]}]},
                         {"runs": [{"results": [[]]}]}, {"runs": [{"results": [1]}]},
                         {"runs": [None]}, {"runs": ["x"]}, {"runs": [[]]}, {"runs": [{"results": []}, 7]}):
            for tool in sr.TOOLS:
                r = Runner(self)
                r.write(document)
                summary = self.assert_problem(r, tool)
                self.assertNotIn("No findings in", summary)
                self.assertNotIn("unknown", summary)

    def test_absent_or_null_results_are_no_findings(self):
        for document in ({"runs": []}, {"runs": [{}]}, {"runs": [{"results": None}]}, {"runs": [{"results": []}]},
                         {"runs": [{"tool": {"driver": {"name": "x"}}}]}):
            r = Runner(self)
            r.write(document)
            code, summary, out = r.run("semgrep")
            self.assertEqual(code, 0)
            self.assertIn("No findings in `scan.sarif`", summary)
            self.assertEqual(out, "")

    def test_unwritable_summary_is_a_warning_not_a_failure(self):
        r = Runner(self)
        r.write(sarif([result("r", "m")]))
        out = io.StringIO()
        code = sr.main(["--tool", "semgrep", "--sarif", r.sarif_path,
                        "--summary", os.path.join(r.dir.name, "no-such-dir", "s.md")], env={}, out=out)
        self.assertEqual(code, 0)
        self.assertIn("::warning", out.getvalue())
        self.assertIn("::error ", out.getvalue())

    def test_bad_arguments_still_exit_zero(self):
        for argv in ([], ["--tool"], ["--tool", "nope", "--sarif", "x"], ["--tool", "semgrep"],
                     ["--tool", "semgrep", "--sarif", "x", "--tool", "semgrep"], ["--wat", "x"]):
            out = io.StringIO()
            self.assertEqual(sr.main(argv, env={}, out=out), 0)
            self.assertIn("::warning", out.getvalue())

    def test_unexpected_error_still_exits_zero(self):
        original = sr.findings_of
        sr.findings_of = lambda *a: 1 / 0
        try:
            r = Runner(self)
            r.write(sarif([]))
            out = io.StringIO()
            code = sr.main(["--tool", "semgrep", "--sarif", r.sarif_path, "--summary", r.summary_path], env={}, out=out)
        finally:
            sr.findings_of = original
        self.assertEqual(code, 0)
        self.assertIn("::warning title=Findings report::the findings report failed", out.getvalue())

    def run_path(self, path, tool="semgrep"):
        out = io.StringIO()
        summary = os.path.join(os.path.dirname(path), "summary.md")
        code = sr.main(["--tool", tool, "--sarif", path, "--summary", summary], env={}, out=out)
        text = ""
        if os.path.exists(summary):
            with open(summary, encoding="utf-8") as handle:
                text = handle.read()
        return code, text, out.getvalue()

    def small_limit(self, limit):
        original = sr.MAX_BYTES
        sr.MAX_BYTES = limit
        self.addCleanup(setattr, sr, "MAX_BYTES", original)

    def test_regular_file_within_the_limit_is_read(self):
        r = Runner(self)
        r.write(sarif([result("rule.x", "m", uri="a.py", line=1)]))
        code, summary, out = self.run_path(r.sarif_path)
        self.assertEqual(code, 0)
        self.assertIn("rule.x", summary)

    def test_file_of_exactly_max_bytes_is_read_and_one_more_is_refused(self):
        r = Runner(self)
        body = json.dumps(sarif([result("rule.x", "m", uri="a.py", line=1)]))
        self.small_limit(len(body) + 40)
        r.write(body + " " * 40)
        self.assertEqual(os.path.getsize(r.sarif_path), sr.MAX_BYTES)
        _, summary, out = self.run_path(r.sarif_path)
        self.assertIn("rule.x", summary)
        self.assertEqual(out.count("::warning"), 0)
        os.remove(os.path.join(r.dir.name, "summary.md"))
        r.write(body + " " * 41)
        _, summary, out = self.run_path(r.sarif_path)
        self.assertNotIn("rule.x", summary)
        self.assertIn("larger than", summary)
        self.assertIn("::warning", out)

    def test_read_never_reads_more_than_max_bytes_plus_one(self):
        r = Runner(self)
        self.small_limit(100)
        r.write("[" + " " * 5000 + "]")
        reads = []
        real_fdopen = os.fdopen

        def spy(fd, mode="r", *args, **kwargs):
            handle = real_fdopen(fd, mode, *args, **kwargs)
            real_read = handle.read

            class Spy:
                def read(self, size=-1):
                    reads.append(size)
                    return real_read(size)

                def __enter__(self):
                    return self

                def __exit__(self, *exc):
                    handle.close()

            return Spy()

        original = sr.os.fdopen
        sr.os.fdopen = spy
        try:
            with self.assertRaises(sr.ReportError):
                sr.read_sarif(r.sarif_path)
        finally:
            sr.os.fdopen = original
        self.assertEqual(reads, [101])

    def test_symlink_as_sarif_path_is_refused(self):
        r = Runner(self)
        outside = tempfile.TemporaryDirectory()
        self.addCleanup(outside.cleanup)
        target = os.path.join(outside.name, "real.sarif")
        with open(target, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(sarif([result("rule.x", "m", uri="a.py", line=1)])))
        try:
            os.symlink(target, r.sarif_path)
        except (OSError, NotImplementedError, AttributeError):
            self.skipTest("symlinks are not available here")
        code, summary, out = self.run_path(r.sarif_path)
        self.assertEqual(code, 0)
        self.assertNotIn("rule.x", summary)
        self.assertIn("symbolic link", summary)
        self.assertIn("::warning", out)

    def test_symlink_to_a_device_is_refused_without_reading(self):
        r = Runner(self)
        if not os.path.exists("/dev/zero"):
            self.skipTest("no /dev/zero")
        try:
            os.symlink("/dev/zero", r.sarif_path)
        except (OSError, NotImplementedError, AttributeError):
            self.skipTest("symlinks are not available here")
        code, summary, out = self.run_path(r.sarif_path)
        self.assertEqual(code, 0)
        self.assertIn("::warning", out)

    def test_fifo_as_sarif_path_is_refused_without_blocking(self):
        r = Runner(self)
        if not hasattr(os, "mkfifo"):
            self.skipTest("no mkfifo")
        os.mkfifo(r.sarif_path)
        code, summary, out = self.run_path(r.sarif_path)
        self.assertEqual(code, 0)
        self.assertIn("not a regular file", summary)
        self.assertIn("::warning", out)

    def test_special_file_swapped_in_after_the_check_is_refused(self):
        # fstat of the open descriptor decides, not only the earlier lstat.
        r = Runner(self)
        r.write("{}")
        original = sr.os.fstat
        mode = stat.S_IFIFO | 0o600
        sr.os.fstat = lambda fd: type("St", (), {"st_mode": mode})()
        try:
            with self.assertRaises(sr.ReportError):
                sr.read_sarif(r.sarif_path)
        finally:
            sr.os.fstat = original

    def test_directory_as_sarif_path(self):
        r = Runner(self)
        out = io.StringIO()
        code = sr.main(["--tool", "semgrep", "--sarif", r.dir.name, "--summary", r.summary_path], env={}, out=out)
        self.assertEqual(code, 0)

    def test_cli_under_python_dash_i(self):
        r = Runner(self)
        r.write(sarif([result("CVE-1", vuln_message())]))
        for sarif_path, expected in ((r.sarif_path, "::error file=package-lock.json"),
                                     (r.sarif_path + ".missing", "::warning")):
            done = subprocess.run([sys.executable, "-I", SCRIPT, "--tool", "trivy-vuln", "--sarif", sarif_path],
                                  capture_output=True, text=True, cwd=r.dir.name, check=False)
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertIn(expected, done.stdout)
            self.assertEqual(done.stderr, "")

    def test_cli_with_bad_arguments_under_python_dash_i(self):
        done = subprocess.run([sys.executable, "-I", SCRIPT, "--nope"], capture_output=True, text=True, check=False)
        self.assertEqual(done.returncode, 0)
        self.assertIn("::warning", done.stdout)


class SharedEscaping(unittest.TestCase):
    def test_uses_the_helpers_of_trivy_images(self):
        path = os.path.join(HERE, "..", "scripts", "trivy_images.py")
        spec2 = importlib.util.spec_from_file_location("trivy_images_for_test", path)
        ti = importlib.util.module_from_spec(spec2)
        spec2.loader.exec_module(ti)
        for value in (HOSTILE, None, 5, "x" * 500, "a://b", "[x](y)"):
            self.assertEqual(sr.clean(value), ti.clean(value))
            self.assertEqual(sr.cell(value, 50).replace("&#46;", ".").replace("&#64;", "@"),
                             re.sub(r"(?i)www\.", "www.", ti.cell(value, 50)))

    def test_script_is_ascii_and_stdlib_only(self):
        with open(SCRIPT, "rb") as handle:
            raw = handle.read()
        raw.decode("ascii")
        imports = set(re.findall(rb"^(?:import|from) (\w+)", raw, re.M))
        self.assertLessEqual(imports, {b"importlib", b"json", b"os", b"re", b"stat", b"sys", b"unicodedata", b"urllib"})


REPORT_STEPS = [
    ("trivy.yml", "Report Trivy secret findings", ["trivy-secret"]),
    ("trivy.yml", "Report Trivy vulnerability findings", ["trivy-vuln"]),
    ("semgrep.yml", "Report Semgrep findings", ["semgrep"]),
    ("gitleaks.yml", "Report gitleaks findings", ["gitleaks"]),
]
SCAN_STEPS = {
    "trivy.yml": ["Run Trivy secret scan", "Run Trivy vulnerability scan"],
    "semgrep.yml": ["Run Semgrep"],
    "gitleaks.yml": ["Run gitleaks history scan"],
}


# Every step that runs a script from the shared checkout under always()/!cancelled()/
# failure() must also require the verification step of its job to have succeeded in
# this run: python3 -I does not authenticate the script, the verified checkout does.
VERIFIED = "steps.shared_verified.outcome == 'success'"
REPORT_IF = {name: "always() && " + VERIFIED for name in ("trivy.yml", "semgrep.yml", "gitleaks.yml")}
# Workflows whose Verify shared workflow checkout step must carry id shared_verified,
# with the scripts the later steps run checked there.
VERIFY_FILES = {
    "trivy.yml": ["scripts/sarif_report.py"],
    "semgrep.yml": ["scripts/sarif_report.py", "scripts/check_suppressions.py"],
    "gitleaks.yml": ["scripts/sarif_report.py"],
}
ALWAYS_LIKE = re.compile(r"always\(\)|failure\(\)|cancelled\(\)")


def workflow_steps(text):
    """Each step of a workflow as its own text, split at every step list item
    (a line starting with a dash at the indentation of the list under a steps: key),
    named or not, so a step that starts with run:, uses: or if: is not missed."""
    steps, current, indent, steps_key = [], None, None, None
    for line in text.split("\n"):
        stripped = line.strip()
        here = len(line) - len(line.lstrip())
        if steps_key is not None and stripped and not stripped.startswith("#") and here <= steps_key \
                and not (here == steps_key and stripped.startswith("- ")):
            steps_key, indent = None, None
        if steps_key is None:
            current = None
            if re.match(r"^\s*steps:\s*$", line):
                steps_key, indent = here, None
            continue
        if indent is None and stripped.startswith("- "):
            indent = here
        if indent is not None and here == indent and stripped.startswith("- "):
            current = []
            steps.append(current)
        if current is not None:
            current.append(line)
    return ["\n".join(lines) for lines in steps]


def step_label(block):
    """The name of a step, or its first line if it has none."""
    named = re.search(r"(?m)^\s*(?:- )?name:\s*(.*?)\s*$", block)
    return named.group(1) if named else block.split("\n")[0].strip()


def step_conditions(block):
    """Every if: expression in a step block, folded and literal scalars joined."""
    found, lines = [], block.split("\n")
    for number, line in enumerate(lines):
        match = re.match(r"^(\s*)(?:- )?if:\s*(.*)$", line)
        if not match:
            continue
        value = match.group(2)
        if value[:1] in ("|", ">"):
            indent = len(match.group(1))
            body = []
            for following in lines[number + 1:]:
                if following.strip() and len(following) - len(following.lstrip()) <= indent:
                    break
                body.append(following.strip())
            value = " ".join(body)
        found.append(value)
    return found


# Configuration that merely names the shared checkout without running anything from it.
SHARED_CONFIG = re.compile(r"(?:--skip-dirs|--exclude)(?:[ \t]+|=)[\"']?(?:\./)?\.strange-security(?![\w-])"
                           r"|^[ \t]*(?:- )?path:[ \t]*[\"']?(?:\./)?\.strange-security[\"']?[ \t]*$", re.M)
SHARED_REFERENCE = re.compile(r"\.strange-security(?![\w-])")


def runs_shared_code(block):
    """True if the step refers to the shared checkout anywhere but in path:/--skip-dirs/--exclude
    configuration: a script of it (python, bash, node, ...), a cd into it, a docker build
    context, a local action (uses: ./.strange-security/...), a working-directory, ... Comment
    lines are ignored."""
    code = "\n".join(line for line in block.split("\n") if not line.lstrip().startswith("#"))
    return bool(SHARED_REFERENCE.search(SHARED_CONFIG.sub("", code)))


def unguarded_shared_script_steps(text):
    """Names of steps that run code from the shared checkout under always()/failure()/
    !cancelled() without requiring the verified checkout, whatever their if: or name look like."""
    bad = []
    for block in workflow_steps(text):
        if not runs_shared_code(block):
            continue
        for condition in step_conditions(block):
            if ALWAYS_LIKE.search(condition) and VERIFIED not in condition:
                bad.append(step_label(block))
                break
    return bad


# gitleaks.yml steps that are allowed (and required) to be non-gating.
PRECHECK = "Refuse caller-planted .strange-security path"
GITLEAKS_SETUP = ["Resolve shared workflow source", PRECHECK, "Checkout shared workflow repository",
                  "Verify shared workflow checkout"]


class WorkflowWiring(unittest.TestCase):
    def test_report_step_runs_always_with_python_dash_i(self):
        for name, title, tools in REPORT_STEPS:
            text = read(name)
            block = step(text, title)
            self.assertIn("\n        if: %s\n" % REPORT_IF.get(name, "always()"), block, name)
            self.assertNotIn("continue-on-error", block, name)
            for tool in tools:
                self.assertRegex(block, r"python3 -I \.strange-security/scripts/sarif_report\.py --tool %s " % tool, name)
            self.assertNotRegex(block, r"python3? (?!-I)[^\n]*sarif_report", name)
            self.assertEqual(block.count("sarif_report.py"), len(tools), name)

    def test_report_step_cannot_fail_the_job(self):
        for name, title, tools in REPORT_STEPS:
            block = step(read(name), title)
            self.assertEqual(block.count("|| echo \"::warning::"), len(tools), name)
            self.assertNotRegex(block, r"(?m)^\s*exit\b", name)

    def test_report_step_comes_after_every_scan_step(self):
        for name, title, _ in REPORT_STEPS:
            text = read(name)
            for scan in SCAN_STEPS[name]:
                self.assertGreater(text.index("- name: " + title), text.index("- name: " + scan), (name, scan))

    def test_scan_steps_are_not_continue_on_error(self):
        for name, scans in SCAN_STEPS.items():
            text = read(name)
            if name == "gitleaks.yml":
                # Only the report-script setup steps may be non-gating, never the scan.
                found = re.findall(r"(?m)^\s*continue-on-error:.*$", text)
                self.assertEqual(found, ["        continue-on-error: true"] * len(GITLEAKS_SETUP))
                for title in ("Validate timeout", "Checkout repository", "Install gitleaks", "Upload SARIF results"):
                    self.assertNotRegex(step(text, title), r"(?m)^\s*continue-on-error:", (name, title))
            else:
                self.assertNotIn("continue-on-error", text, name)
            for scan in scans:
                self.assertNotIn("continue-on-error", step(text, scan), (name, scan))
                if name == "gitleaks.yml":
                    self.assertNotRegex(step(text, scan), r"(?m)^        if:", (name, scan))

    def test_report_does_not_depend_on_upload_sarif(self):
        for name, title, _ in REPORT_STEPS:
            self.assertNotIn("upload-sarif", step(read(name), title), name)

    def test_report_reads_the_files_the_scans_write(self):
        trivy = read("trivy.yml")
        self.assertIn("--output /src/trivy-secret.sarif", step(trivy, "Run Trivy secret scan"))
        self.assertIn("--output /src/trivy-vuln.sarif", step(trivy, "Run Trivy vulnerability scan"))
        self.assertIn("--sarif trivy-secret.sarif", step(trivy, "Report Trivy secret findings"))
        self.assertIn("--sarif trivy-vuln.sarif", step(trivy, "Report Trivy vulnerability findings"))
        self.assertIn('--sarif "$RUNNER_TEMP/semgrep/semgrep.sarif"', step(read("semgrep.yml"), "Report Semgrep findings"))
        gitleaks = read("gitleaks.yml")
        self.assertIn("--report-path gitleaks.sarif", step(gitleaks, "Run gitleaks history scan"))
        self.assertIn("--sarif gitleaks.sarif", step(gitleaks, "Report gitleaks findings"))

    def test_semgrep_report_keeps_the_checker_last(self):
        text = read("semgrep.yml")
        self.assertGreater(text.index("name: Check Semgrep suppressions"), text.index("name: Report Semgrep findings"))

    def test_gitleaks_has_the_shared_checkout_before_the_scan(self):
        text = read("gitleaks.yml")
        checkout = step(text, "Checkout shared workflow repository")
        self.assertIn("path: .strange-security", checkout)
        self.assertIn("persist-credentials: false", checkout)
        self.assertLess(text.index("- name: Checkout shared workflow repository"),
                        text.index("- name: Run gitleaks history scan"))
        self.assertIn("sarif_report.py", step(text, "Verify shared workflow checkout"))

    def test_gitleaks_report_setup_is_non_gating_and_the_scan_always_runs(self):
        text = read("gitleaks.yml")
        ids = {"Resolve shared workflow source": "shared", PRECHECK: "shared_precheck",
               "Checkout shared workflow repository": "shared_checkout",
               "Verify shared workflow checkout": "shared_verified"}
        conditions = {"Resolve shared workflow source": None, PRECHECK: None,
                      "Checkout shared workflow repository":
                          "steps.shared.outcome == 'success' && steps.shared_precheck.outcome == 'success'",
                      "Verify shared workflow checkout": "steps.shared_checkout.outcome == 'success'"}
        for title in GITLEAKS_SETUP:
            block = step(text, title)
            self.assertRegex(block, r"(?m)^        continue-on-error: true$", title)
            self.assertRegex(block, r"(?m)^        id: %s$" % ids[title], title)
            if conditions[title]:
                self.assertRegex(block, r"(?m)^        if: %s$" % re.escape(conditions[title]), title)
            else:
                self.assertNotRegex(block, r"(?m)^        if:", title)
        # The scan and its install step run on the default success() of steps that
        # cannot fail the job, and do not depend on the setup outputs or outcomes.
        for title in ("Install gitleaks", "Run gitleaks history scan"):
            block = step(text, title)
            self.assertNotRegex(block, r"(?m)^        if:", title)
            self.assertNotIn("steps.shared", block, title)
        self.assertNotIn("steps.shared", step(text, "Upload SARIF results"))
        self.assertLess(text.index("- name: Verify shared workflow checkout"), text.index("- name: Install gitleaks"))

    def test_gitleaks_report_needs_the_verified_checkout_and_runs_after_a_failed_scan(self):
        block = step(read("gitleaks.yml"), "Report gitleaks findings")
        self.assertIn("if: always() && steps.shared_verified.outcome == 'success'", block)
        self.assertNotIn("continue-on-error", block)

    def test_every_always_step_running_shared_scripts_requires_the_verified_checkout(self):
        for name in sorted(os.listdir(os.path.join(ROOT, ".github", "workflows"))):
            if name.endswith(".yml"):
                self.assertEqual(unguarded_shared_script_steps(read(name)), [], name)

    def test_checker_step_in_semgrep_requires_the_verified_checkout(self):
        block = step(read("semgrep.yml"), "Check Semgrep suppressions")
        self.assertRegex(block, r"(?m)^        if: always\(\) && %s$" % re.escape(VERIFIED))
        self.assertNotIn("continue-on-error", block)

    def test_removing_a_guard_is_detected(self):
        for name, title, _ in REPORT_STEPS:
            text = read(name)
            self.assertEqual(unguarded_shared_script_steps(text), [], name)
            guarded = "        if: always() && " + VERIFIED + "\n"
            block = step(text, title)
            self.assertIn(guarded, block)
            for weaker in ("        if: always()\n", "        if: ${{ always() }}\n",
                           "        if: ${{ !cancelled() }}\n", "        if: failure()\n"):
                mutated = text.replace(block, block.replace(guarded, weaker))
                self.assertNotEqual(mutated, text)
                self.assertEqual(unguarded_shared_script_steps(mutated), [title], (name, weaker))
            # Dropping the verification step's id leaves a guard that is never true.
            mutated = text.replace("        id: shared_verified\n", "")
            self.assertNotEqual(mutated, text)
            self.assertRegex(step(read(name), "Verify shared workflow checkout"), r"(?m)^        id: shared_verified$")
            self.assertNotRegex(step(mutated, "Verify shared workflow checkout"), r"(?m)^        id: shared_verified$")
        semgrep = read("semgrep.yml")
        block = step(semgrep, "Check Semgrep suppressions")
        mutated = semgrep.replace(block, block.replace("always() && " + VERIFIED, "always()"))
        self.assertEqual(unguarded_shared_script_steps(mutated), ["Check Semgrep suppressions"])

    def test_verify_step_has_the_id_and_checks_the_scripts_it_guards(self):
        for name, scripts in VERIFY_FILES.items():
            text = read(name)
            block = step(text, "Verify shared workflow checkout")
            self.assertRegex(block, r"(?m)^        id: shared_verified$", name)
            self.assertIn("git -C .strange-security rev-parse HEAD", block, name)
            for script in scripts:
                self.assertIn("-f .strange-security/" + script, block, (name, script))
            # The id exists once, on that step only, and the guards refer to it.
            self.assertEqual(text.count("id: shared_verified"), 1, name)
            for other in workflow_steps(text):
                if re.search(r"(?m)^        if:.*steps\.shared_verified", other):
                    self.assertGreater(text.index(other), text.index(block), name)

    def test_trivy_and_semgrep_setup_stays_gating(self):
        # The scanner image is built from the shared checkout, so unlike gitleaks a
        # failed resolve, checkout or verify must fail the job, never skip the scan quietly.
        for name in ("trivy.yml", "semgrep.yml"):
            text = read(name)
            for title in GITLEAKS_SETUP:
                block = step(text, title)
                self.assertNotIn("continue-on-error", block, (name, title))
                self.assertNotRegex(block, r"(?m)^        if:", (name, title))
            build = step(text, "Build Trivy image" if name == "trivy.yml" else "Build Semgrep image")
            self.assertNotRegex(build, r"(?m)^        if:", name)
            self.assertLess(text.index("- name: Verify shared workflow checkout"), text.index("- name: Build "), name)

    def test_gitleaks_still_redacts(self):
        scan = step(read("gitleaks.yml"), "Run gitleaks history scan")
        scan = scan[:scan.index("\n\n")]
        self.assertIn("--redact", scan)
        self.assertNotRegex(scan, r"--verbose|\s-v\b")


def synthetic_workflow(*steps):
    return "name: x\njobs:\n  j:\n    runs-on: ubuntu-24.04\n    steps:\n" + "".join(steps)


class GuardDetection(unittest.TestCase):
    """The generic guard test must see every way a step can run shared code, named or not."""

    UNGUARDED = [
        ("python", "      - run: python3 -I .strange-security/scripts/x.py\n        if: always()\n"),
        ("python, other script dir", "      - name: n\n        if: always()\n        run: python3 .strange-security/tools/x.py\n"),
        ("bash", "      - name: n\n        if: failure()\n        run: bash .strange-security/run.sh\n"),
        ("dot slash", "      - name: n\n        if: ${{ !cancelled() }}\n        run: node ./.strange-security/x.js\n"),
        ("cd", "      - name: n\n        if: always()\n        run: |\n          cd .strange-security\n          ./go\n"),
        ("docker build context", "      - name: n\n        if: always()\n        run: |\n          docker build \\\n"
                                 "            --file Dockerfile \\\n            .strange-security\n"),
        ("local action", "      - uses: ./.strange-security/actions/a\n        if: always()\n"),
        ("if first", "      - if: ${{ always() }}\n        run: sh .strange-security/x.sh\n"),
        ("folded if", "      - name: n\n        if: >-\n          always() &&\n          inputs.x\n"
                      "        run: python3 .strange-security/a.py\n"),
        ("working directory", "      - name: n\n        if: always()\n        working-directory: .strange-security\n"
                              "        run: python3 -I scripts/x.py\n"),
        ("second condition", "      - name: n\n        if: inputs.x\n        run: python3 .strange-security/a.py\n"
                             "      - name: m\n        if: always() && steps.other.outcome == 'success'\n"
                             "        run: python3 .strange-security/a.py\n"),
    ]
    HARMLESS = [
        ("skip-dirs", "      - name: n\n        if: always()\n        run: trivy fs --skip-dirs .strange-security /src\n"),
        ("exclude", "      - name: n\n        if: always()\n        run: semgrep scan --exclude .strange-security /src\n"),
        ("checkout path", "      - uses: actions/checkout@" + "0" * 40 + " # v1.0.0\n        if: always()\n"
                          "        with:\n          path: .strange-security\n"),
        ("guarded", "      - name: n\n        if: always() && " + VERIFIED + "\n        run: python3 -I .strange-security/scripts/x.py\n"),
        ("folded guard", "      - name: n\n        if: >-\n          always() &&\n          " + VERIFIED + "\n"
                         "        run: python3 -I .strange-security/scripts/x.py\n"),
        ("default condition", "      - run: python3 -I .strange-security/scripts/x.py\n"),
        ("success condition", "      - name: n\n        if: ${{ inputs.x }}\n        run: bash .strange-security/x.sh\n"),
        ("comment only", "      - name: n\n        if: always()\n        run: |\n          # uses .strange-security/scripts/x.py\n          echo hi\n"),
        ("no reference", "      - run: echo hi\n        if: always()\n"),
    ]

    def test_every_way_of_running_shared_code_without_the_guard_is_found(self):
        for label, block in self.UNGUARDED:
            with self.subTest(label):
                self.assertEqual(len(unguarded_shared_script_steps(synthetic_workflow(block))), 1, block)

    def test_configuration_guarded_and_default_steps_are_not_flagged(self):
        for label, block in self.HARMLESS:
            with self.subTest(label):
                self.assertEqual(unguarded_shared_script_steps(synthetic_workflow(block)), [], block)

    def test_steps_are_split_at_every_list_item(self):
        text = synthetic_workflow("      - run: a\n", "      - uses: u@1\n", "      - name: n\n        run: b\n",
                                  "      - if: x\n        run: c\n")
        self.assertEqual(len(workflow_steps(text)), 4)
        self.assertEqual(step_label(workflow_steps(text)[0]), "- run: a")

    def test_lists_outside_steps_are_not_steps(self):
        text = "on:\n  push:\n    branches:\n      - main\njobs:\n  j:\n    steps:\n      - run: a\n  k:\n    steps:\n      - run: b\n"
        self.assertEqual([s.strip() for s in workflow_steps(text)], ["- run: a", "- run: b"])

    def test_an_unnamed_always_step_in_a_real_workflow_is_found(self):
        for name, title, _ in REPORT_STEPS:
            text = read(name)
            block = step(text, title)
            unnamed = re.sub(r"\A- name: .*\n        ", "- ", block)
            self.assertNotEqual(unnamed, block)
            mutated = text.replace(block, unnamed.replace("always() && " + VERIFIED, "always()"))
            self.assertEqual(len(unguarded_shared_script_steps(mutated)), 1, (name, title))
            self.assertEqual(unguarded_shared_script_steps(text), [], name)

    def test_the_real_workflows_still_pass_the_tightened_guard(self):
        shared_steps = 0
        for name in sorted(os.listdir(os.path.join(ROOT, ".github", "workflows"))):
            if name.endswith(".yml"):
                text = read(name)
                self.assertEqual(unguarded_shared_script_steps(text), [], name)
                shared_steps += sum(1 for block in workflow_steps(text) if runs_shared_code(block))
        self.assertGreater(shared_steps, 10)


@unittest.skipUnless(BASH, "bash is required")
class ReportStepsRunUnderBash(unittest.TestCase):
    """The real run blocks, under bash -eo pipefail, with python3 failing and no SARIF."""

    def block(self, name, title):
        return extract_run_block(os.path.join(ROOT, ".github", "workflows", name), title)

    def test_a_failing_python3_never_fails_the_step(self):
        for name, title, tools in REPORT_STEPS:
            with self.subTest(step=title):
                script = self.block(name, title)
                with tempfile.TemporaryDirectory() as tmp:
                    bindir = os.path.join(tmp, "bin")
                    work = os.path.join(tmp, "work")
                    os.makedirs(bindir)
                    os.makedirs(work)
                    stub = os.path.join(bindir, "python3")
                    with open(stub, "w", encoding="utf-8", newline="\n") as handle:
                        handle.write("#!/bin/sh\nexit 7\n")
                    os.chmod(stub, 0o755)
                    env = dict(os.environ, RUNNER_TEMP=tmp)
                    env["PATH"] = bindir + os.pathsep + env["PATH"]
                    done = subprocess.run([BASH, "-eo", "pipefail", "-c", script], cwd=work, env=env,
                                          capture_output=True, text=True)
                self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
                self.assertEqual(done.stdout.count("::warning::"), len(tools), done.stdout)

    def git(self, cwd, *args):
        done = subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.com", *args], cwd=cwd,
                              capture_output=True, text=True, check=True)
        return done.stdout.strip()

    def test_gitleaks_resolve_step_warns_and_fails_only_itself_when_empty(self):
        script = self.block("gitleaks.yml", "Resolve shared workflow source")
        for repository, sha, ok in (("o/r", "a" * 40, True), ("", "a" * 40, False), ("o/r", "", False),
                                    ("", "", False)):
            with tempfile.TemporaryDirectory() as tmp:
                out = os.path.join(tmp, "out")
                env = dict(os.environ, WORKFLOW_REPOSITORY=repository, WORKFLOW_SHA=sha, GITHUB_OUTPUT=out)
                done = subprocess.run([BASH, "-eo", "pipefail", "-c", script], cwd=tmp, env=env,
                                      capture_output=True, text=True)
                self.assertEqual(done.returncode == 0, ok, done.stdout + done.stderr)
                if ok:
                    with open(out, encoding="utf-8") as handle:
                        self.assertEqual(handle.read(), "repository=o/r\nsha=%s\n" % sha)
                else:
                    self.assertIn("::warning::", done.stdout)
                    self.assertNotIn("::error", done.stdout)
                    self.assertFalse(os.path.exists(out))

    def test_gitleaks_verify_step_is_strict_and_warns_when_it_fails(self):
        script = self.block("gitleaks.yml", "Verify shared workflow checkout")
        with tempfile.TemporaryDirectory() as tmp:
            repo = os.path.join(tmp, ".strange-security")
            os.makedirs(os.path.join(repo, "scripts"))
            self.git(repo, "init", "-q")
            with open(os.path.join(repo, "scripts", "sarif_report.py"), "w", encoding="utf-8") as handle:
                handle.write("# x\n")
            self.git(repo, "add", ".")
            self.git(repo, "commit", "-q", "-m", "x")
            sha = self.git(repo, "rev-parse", "HEAD")

            def run(workflow_sha):
                done = subprocess.run([BASH, "-eo", "pipefail", "-c", script], cwd=tmp,
                                      env=dict(os.environ, WORKFLOW_SHA=workflow_sha), capture_output=True, text=True)
                return done.returncode, done.stdout

            self.assertEqual(run(sha), (0, ""))
            for wrong in ("b" * 40, "", sha[:12]):
                code, out = run(wrong)
                self.assertNotEqual(code, 0, wrong)
                self.assertIn("::warning::", out)
            os.remove(os.path.join(repo, "scripts", "sarif_report.py"))
            code, out = run(sha)
            self.assertNotEqual(code, 0)
            self.assertIn("::warning::", out)
        with tempfile.TemporaryDirectory() as tmp:
            done = subprocess.run([BASH, "-eo", "pipefail", "-c", script], cwd=tmp,
                                  env=dict(os.environ, WORKFLOW_SHA="a" * 40), capture_output=True, text=True)
            self.assertNotEqual(done.returncode, 0)
            self.assertIn("::warning::", done.stdout)

    def test_run_blocks_hold_only_the_report_command_and_its_fallback(self):
        for name, title, tools in REPORT_STEPS:
            with self.subTest(step=title):
                script = self.block(name, title)
                joined = re.sub(r"[ \t]*\\\n\s*", " ", script).strip()
                pattern = (r"python3 -I \.strange-security/scripts/sarif_report\.py --tool (\S+) --sarif (\S+)"
                           r" \|\| echo \"::warning::[A-Za-z ]+\"")
                commands = joined.split("\n")
                self.assertEqual(len(commands), len(tools), joined)
                for command, tool in zip(commands, tools):
                    found = re.fullmatch(pattern, command)
                    self.assertIsNotNone(found, command)
                    self.assertEqual(found.group(1), tool)


if __name__ == "__main__":
    unittest.main()
