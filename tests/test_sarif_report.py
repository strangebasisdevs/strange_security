"""scripts/sarif_report.py (the failure-safe, redacted findings report) and the
wiring of its steps in trivy.yml, semgrep.yml and gitleaks.yml."""
import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import tempfile
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
            "/src/a%20b.py": "a b.py",
        }
        for uri, expected in cases.items():
            self.assertEqual(sr.path_of(uri), expected, uri)

    def test_paths_with_dotdot_components_are_refused(self):
        for uri in ("/src/../etc/passwd", "../x.py", "a/../b.py", "file:///src/a/../../b", "a\\..\\b",
                    "/src/%2e%2e/x", "..", "/src/.."):
            self.assertEqual(sr.path_of(uri), "", uri)
        self.assertEqual(sr.path_of("/src/a..b/c...py"), "a..b/c...py")
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
            {"runs": [{"tool": [], "results": [{"ruleId": 5, "ruleIndex": "a", "message": 7, "locations": "x"}]}]},
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
        self.assertLessEqual(imports, {b"importlib", b"json", b"os", b"re", b"sys", b"urllib"})


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


class WorkflowWiring(unittest.TestCase):
    def test_report_step_runs_always_with_python_dash_i(self):
        for name, title, tools in REPORT_STEPS:
            text = read(name)
            block = step(text, title)
            self.assertRegex(block, r"(?m)^        if: always\(\)$", name)
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
            self.assertNotIn("continue-on-error", text, name)
            for scan in scans:
                self.assertNotIn("continue-on-error", step(text, scan), (name, scan))

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
        self.assertIn("test -f .strange-security/scripts/sarif_report.py", step(text, "Verify shared workflow checkout"))

    def test_gitleaks_still_redacts(self):
        scan = step(read("gitleaks.yml"), "Run gitleaks history scan")
        scan = scan[:scan.index("\n\n")]
        self.assertIn("--redact", scan)
        self.assertNotRegex(scan, r"--verbose|\s-v\b")


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
