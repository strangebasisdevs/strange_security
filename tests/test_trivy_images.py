"""trivy-images.yml: the plan/gate script (scripts/trivy_images.py) and the
wiring of the workflow around it."""
import datetime
import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unicodedata
import unittest

from tests.test_inputs import input_block
from tests.test_trivy_image_validation import BASH, extract_run_block
from tests.test_workflows import WORKFLOWS, read, step

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "..", "scripts", "trivy_images.py")

spec = importlib.util.spec_from_file_location("trivy_images", SCRIPT)
ti = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ti)

DIGEST = "sha256:" + "0123456789abcdef" * 4
OTHER = "sha256:" + "f" * 64


class ParseImages(unittest.TestCase):
    def test_accepts_the_three_forms(self):
        text = "\n".join([
            "ghcr.io/org/app:1.2.3",
            "gcr.io/distroless/static-debian12@" + DIGEST,
            "registry.example.com:5000/team/app:v1@" + OTHER,
        ])
        entries = ti.parse_images(text)
        self.assertEqual([e["repository"] for e in entries], [
            "ghcr.io/org/app", "gcr.io/distroless/static-debian12", "registry.example.com:5000/team/app"])
        self.assertEqual(entries[0]["reference"], "ghcr.io/org/app:1.2.3")
        self.assertEqual(entries[2]["reference"], "registry.example.com:5000/team/app:v1@" + OTHER)

    def test_tolerates_blank_lines_and_a_trailing_newline(self):
        entries = ti.parse_images("\n\napp:1\n\nother:2\n")
        self.assertEqual([e["reference"] for e in entries], ["app:1", "other:2"])

    def test_a_port_is_not_a_tag(self):
        self.assertEqual(ti.parse_images("localhost:5000/app:1")[0]["repository"], "localhost:5000/app")
        self.assertEqual(ti.parse_images("app:5000")[0]["repository"], "app")
        self.assertRaises(ti.InputError, ti.parse_images, "localhost:5000/app")

    def rejects(self, text):
        with self.assertRaises(ti.InputError, msg=repr(text)):
            ti.parse_images(text)

    def test_rejects_an_empty_list(self):
        for text in ("", "\n", "\n\n\n"):
            with self.subTest(text=text):
                self.rejects(text)

    def test_rejects_whitespace_anywhere_in_a_line(self):
        for text in ("app :1", "app: 1", " app:1", "app:1 ", "app:1\t", "\tapp:1", "app:1\r", "app:1\r\napp2:1",
                     "app:1 app2:1", "app:1\u00a0", "   ", "app:1\n \napp2:1"):
            with self.subTest(text=text):
                self.rejects(text)

    def test_rejects_shell_metacharacters(self):
        for bad in (";", "&", "|", "$", "`", "'", '"', "(", ")", "<", ">", "*", "?", "!", "\\", "{", "}", "[", "#", "~", "=", "+", ",", "%"):
            with self.subTest(char=bad):
                self.rejects("app%s:1" % bad)
                self.rejects("app:1%s" % bad)
        self.rejects("app:1;id")
        self.rejects("app:$" + "(id)")
        self.rejects("app:`id`")
        self.rejects("app:1\n$" + "(id)")

    def test_rejects_malformed_references(self):
        for text in ("app", "ghcr.io/org/app", "App:1", "ghcr.io/Org/app:1", "-app:1", "/app:1", ".app:1", "app/:1",
                     "a//b:1", "a/../b:1", "a/./b:1", "app:", "app:-1", "app:.1", "app::1", "app:1:2", ":1",
                     "app@", "@" + DIGEST, "app@sha256", "app@sha256:abc", "app@sha512:" + "0" * 64,
                     "app@" + DIGEST.upper(), "app@sha256:" + "A" * 64, "app@" + DIGEST + "@" + DIGEST,
                     "app@" + DIGEST + "x", "app:" + "t" * 129, "a_" + "b/", "app__:1", "app:1@", "http://app:1"):
            with self.subTest(text=text):
                self.rejects(text)

    def test_a_tag_of_128_characters_is_the_longest(self):
        self.assertEqual(len(ti.parse_images("app:" + "t" * 128)), 1)

    def test_rejects_the_same_repository_twice(self):
        self.rejects("app:1\napp@" + DIGEST)
        self.rejects("ghcr.io/o/app:1\nghcr.io/o/app:2")
        self.assertEqual(len(ti.parse_images("o/app:1\nx/app:1")), 2)

    def test_limits_the_number_of_images(self):
        twenty = "\n".join("app%d:1" % i for i in range(20))
        self.assertEqual(len(ti.parse_images(twenty)), 20)
        self.rejects(twenty + "\napp20:1")

    def test_rejects_non_strings(self):
        for value in (None, 5, ["app:1"]):
            with self.assertRaises(ti.InputError):
                ti.parse_images(value)


class Clean(unittest.TestCase):
    def test_untrusted_text_cannot_form_a_workflow_command_or_break_a_table(self):
        for value in ("::error::x", "a::b", "##[error]x", "x\ny", "a|b", "a`b", "\x1b[31m", " x", "a\x00b"):
            cleaned = ti.clean(value)
            with self.subTest(value=value):
                self.assertNotIn("::", cleaned)
                self.assertNotIn("##[", cleaned)
                self.assertNotRegex(cleaned, "[|`\x00-\x1f\x7f-\x9f  ]")

    def test_format_characters_are_shown_as_visible_escapes(self):
        self.assertEqual(ti.clean("a\u202eb\u200bc\ufeffd\U000e0001"), r"a\u202eb\u200bc\ufeffd\U000e0001")
        self.assertEqual(ti.cell("a\u202eb"), "a&#92;u202eb")
        self.assertEqual(ti.clean("caf\u00e9 \u65e5\u672c"), "caf\u00e9 \u65e5\u672c")

    def test_long_text_is_cut_and_none_is_empty(self):
        self.assertEqual(len(ti.clean("x" * 500)), 200)
        self.assertEqual(ti.clean(None), "")


class ExceptionsPath(unittest.TestCase):
    def test_accepts_relative_paths(self):
        for path in (".github/image-exceptions.json", "a.json", "a/b/c-d_e.json"):
            self.assertEqual(ti.validate_exceptions_path(path), path)

    def test_rejects_everything_else(self):
        for path in ("", "/etc/passwd", "../x", "a/../x", "a/./x", "./x", "a//b", "a/", "-x", "a b", "a;b", "a$b",
                     "a\nb", "a\\b", "C:/x", "~/x", "x" * 256, None):
            with self.subTest(path=path):
                with self.assertRaises(ti.InputError):
                    ti.validate_exceptions_path(path)


class Plan(unittest.TestCase):
    def run_plan(self, images, exceptions=".github/image-exceptions.json"):
        with tempfile.TemporaryDirectory() as tmp:
            output = os.path.join(tmp, "output")
            env = {"IMAGES": images, "EXCEPTIONS_FILE": exceptions, "GITHUB_OUTPUT": output,
                   "SECRET_ALLOWLIST_FILE": ".github/image-secret-allowlist.json"}
            out, err = io.StringIO(), io.StringIO()
            code = ti.main(["plan"], env, out, err)
            written = slurp(output) if os.path.exists(output) else ""
        return code, written, err.getvalue()

    def test_writes_one_matrix_line(self):
        code, written, _ = self.run_plan("app:1\nx/y@" + DIGEST + "\n")
        self.assertEqual(code, 0)
        self.assertEqual(written.count("\n"), 1)
        self.assertTrue(written.startswith("matrix="))
        matrix = json.loads(written[len("matrix="):])
        self.assertEqual(matrix, {"include": [
            {"reference": "app:1", "repository": "app"},
            {"reference": "x/y@" + DIGEST, "repository": "x/y"}]})

    def test_invalid_input_writes_nothing_and_fails(self):
        for images, exceptions in (("", ".github/x.json"), ("app", ".github/x.json"), ("app:1", "../x"),
                                   ("app:1;id", ".github/x.json"), ("app:1\nreference=evil", ".github/x.json")):
            with self.subTest(images=images, exceptions=exceptions):
                code, written, err = self.run_plan(images, exceptions)
                self.assertEqual(code, 2)
                self.assertEqual(written, "")
                self.assertIn("::error::", err)

    def test_a_missing_output_file_variable_fails(self):
        out, err = io.StringIO(), io.StringIO()
        env = {"IMAGES": "app:1", "EXCEPTIONS_FILE": "x.json", "SECRET_ALLOWLIST_FILE": "y.json"}
        self.assertEqual(ti.main(["plan"], env, out, err), 2)

    def test_bad_usage_fails(self):
        for argv in ([], ["nope"], ["plan", "extra"], ["gate"]):
            with self.subTest(argv=argv):
                self.assertEqual(ti.main(argv, {}, io.StringIO(), io.StringIO()), 2)


def vuln(vid="CVE-2026-0001", severity="HIGH", fixed="1.2.4", **extra):
    item = {"VulnerabilityID": vid, "PkgName": "libfoo", "InstalledVersion": "1.2.3", "Severity": severity}
    if fixed is not None:
        item["FixedVersion"] = fixed
    item.update(extra)
    return item


def report(*results, **extra):
    data = {"SchemaVersion": 2, "ArtifactName": "app:1", "ArtifactType": "container_image"}
    if results:
        data["Results"] = list(results)
    data.update(extra)
    return data


def result(vulns=None, secrets=None, target="app:1 (debian 12)"):
    item = {"Target": target}
    if vulns is not None:
        item["Vulnerabilities"] = vulns
    if secrets is not None:
        item["Secrets"] = secrets
    return item


def secret(rule="aws-access-key-id", severity="CRITICAL", **extra):
    item = {"RuleID": rule, "Category": "AWS", "Severity": severity, "Title": "AWS Access Key ID",
            "StartLine": 3, "EndLine": 3, "Match": "AKIAIOSFODNN7EXAMPLE"}
    item.update(extra)
    return item


class Gate(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = self.tmp.name

    def write(self, name, data):
        path = os.path.join(self.dir, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(data if isinstance(data, str) else json.dumps(data))
        return path

    def run_gate(self, vuln_report=None, secret_report=None, exceptions=None, reference="app:1", today=None):
        vpath = self.write("vuln.json", report() if vuln_report is None else vuln_report)
        spath = self.write("secret.json", report() if secret_report is None else secret_report)
        summary = os.path.join(self.dir, "summary.md")
        argv = ["gate", "--reference", reference, "--vuln", vpath, "--secret", spath,
                "--exceptions-file", exceptions or "no-such-exceptions-file.json", "--summary", summary]
        out, err = io.StringIO(), io.StringIO()
        cwd = os.getcwd()
        os.chdir(self.dir)
        try:
            code = ti.main(argv, {}, out, err, today)
        finally:
            os.chdir(cwd)
        text = slurp(summary) if os.path.exists(summary) else ""
        return code, out.getvalue(), err.getvalue(), text

    def test_clean_image_passes(self):
        code, out, err, summary = self.run_gate()
        self.assertEqual((code, err), (0, ""))
        self.assertIn("Passed", summary)

    def test_empty_and_null_findings_pass(self):
        code, *_ = self.run_gate(report(result(), result(vulns=[], secrets=[]), result(vulns=None)))
        self.assertEqual(code, 0)

    def test_fixable_high_and_critical_fail(self):
        for severity in ("HIGH", "CRITICAL"):
            with self.subTest(severity=severity):
                code, out, err, summary = self.run_gate(report(result([vuln(severity=severity)])))
                self.assertEqual(code, 1)
                self.assertIn("CVE-2026-0001", out + summary)
                self.assertIn("libfoo", summary)
                self.assertIn("1.2.4", summary)
                self.assertIn("::error::", err)
                self.assertIn("Failed", summary)

    def test_unfixed_findings_and_lower_severities_pass(self):
        findings = [
            vuln("CVE-1", "HIGH", fixed=None),
            vuln("CVE-2", "CRITICAL", fixed=""),
            vuln("CVE-3", "HIGH", fixed="   ", Status="affected"),
            vuln("CVE-4", "MEDIUM", fixed="2.0"),
            vuln("CVE-5", "LOW", fixed="2.0"),
            vuln("CVE-6", "UNKNOWN", fixed="2.0"),
            vuln("CVE-7", "CRITICAL", fixed=None, Status="will_not_fix"),
        ]
        code, *_ = self.run_gate(report(result(findings)))
        self.assertEqual(code, 0)

    def test_status_fixed_counts_as_fixable(self):
        code, *_ = self.run_gate(report(result([vuln(fixed=None, Status="fixed")])))
        self.assertEqual(code, 1)

    def test_one_fixable_finding_among_unfixed_ones_fails(self):
        findings = [vuln("CVE-1", fixed=None), vuln("CVE-2"), vuln("CVE-3", "LOW")]
        code, out, _, summary = self.run_gate(report(result(findings)))
        self.assertEqual(code, 1)
        self.assertIn("CVE-2", summary)
        self.assertNotIn("CVE-1", summary)
        self.assertNotIn("CVE-3", summary)

    def test_any_secret_fails_at_any_severity(self):
        for severity in ("LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"):
            with self.subTest(severity=severity):
                code, out, err, summary = self.run_gate(secret_report=report(result(secrets=[secret(severity=severity)], target="etc/key")))
                self.assertEqual(code, 1)
                self.assertIn("aws-access-key-id", summary)
                self.assertIn("etc/key", summary)

    def test_secret_text_is_never_printed(self):
        code, out, err, summary = self.run_gate(secret_report=report(result(secrets=[secret(Code={"Lines": [{"Content": "TOPSECRETVALUE"}]})])))
        self.assertEqual(code, 1)
        for text in (out, err, summary):
            self.assertNotIn("AKIAIOSFODNN7EXAMPLE", text)
            self.assertNotIn("TOPSECRETVALUE", text)

    def test_vulnerabilities_in_the_secret_report_do_not_pass_or_fail_the_secret_gate(self):
        # Each report is only read for what it is: a stray key in the other one is ignored.
        code, *_ = self.run_gate(secret_report=report(result([vuln()])))
        self.assertEqual(code, 0)

    def test_malformed_reports_fail_closed(self):
        bad = {
            "not json": "{",
            "empty file": "",
            "list": "[]",
            "null": "null",
            "no schema": {"ArtifactType": "container_image"},
            "old schema": {"SchemaVersion": 1, "ArtifactType": "container_image"},
            "wrong artifact": {"SchemaVersion": 2, "ArtifactType": "filesystem"},
            "results object": report(Results={"a": 1}),
            "results string": report(Results="x"),
            "result not object": report(Results=["x"]),
            "vulns not list": report(result("x")),
            "vuln not object": report(result(["x"])),
            "unknown severity": report(result([vuln(severity="SEVERE")])),
            "missing severity": report(result([{"VulnerabilityID": "x", "FixedVersion": "1"}])),
            "lowercase severity": report(result([vuln(severity="high")])),
            "list severity": report(result([vuln(severity=["HIGH"])])),
            "null severity": report(result([vuln(severity=None)])),
            "list fixed version": report(result([vuln(fixed=["1.2.4"])])),
            "number fixed version": report(result([vuln(fixed=124)])),
            "object fixed version": report(result([vuln(fixed={"v": "1"})])),
            "list fixed version, low severity": report(result([vuln(severity="LOW", fixed=["1"])])),
            "list status": report(result([vuln(fixed=None, Status=["fixed"])])),
            "number status": report(result([vuln(fixed=None, Status=1)])),
            "list vulnerability id": report(result([vuln(vid=["CVE-1"])])),
            "missing vulnerability id": report(result([{"PkgName": "x", "Severity": "HIGH", "FixedVersion": "1"}])),
            "null vulnerability id": report(result([vuln(vid=None)])),
        }
        for label, data in bad.items():
            with self.subTest(label=label, report="vuln"):
                code, out, err, summary = self.run_gate(vuln_report=data)
                self.assertEqual(code, 2)
                self.assertIn("::error::", err)
                self.assertIn("Failed closed", summary)
            with self.subTest(label=label, report="secret"):
                if label in ("unknown severity", "missing severity", "lowercase severity", "vulns not list", "vuln not object") or label.startswith(("list ", "null ", "number ", "object ", "missing vuln")):
                    continue  # vulnerability-only shapes
                code, *_ = self.run_gate(secret_report=data)
                self.assertEqual(code, 2)

    def test_secrets_not_a_list_fails_closed(self):
        for bad in ("x", {"a": 1}, ["x"]):
            code, *_ = self.run_gate(secret_report=report(result(secrets=bad)))
            self.assertEqual(code, 2)

    def missing_report_run(self, vuln_present, secret_present):
        vpath = self.write("vuln.json", report()) if vuln_present else os.path.join(self.dir, "nope.json")
        spath = self.write("secret.json", report()) if secret_present else os.path.join(self.dir, "nope2.json")
        summary = os.path.join(self.dir, "summary.md")
        out, err = io.StringIO(), io.StringIO()
        argv = ["gate", "--reference", "app:1", "--vuln", vpath, "--secret", spath,
                "--exceptions-file", "x.json", "--summary", summary]
        return ti.main(argv, {}, out, err), err.getvalue(), slurp(summary)

    def test_a_missing_vulnerability_report_fails_closed(self):
        code, err, summary = self.missing_report_run(vuln_present=False, secret_present=True)
        self.assertEqual(code, 2)
        self.assertIn("::error::", err)
        self.assertIn("vulnerability report", err)
        self.assertIn("Failed closed", summary)

    def test_a_missing_secret_report_fails_closed(self):
        code, err, summary = self.missing_report_run(vuln_present=True, secret_present=False)
        self.assertEqual(code, 2)
        self.assertIn("::error::", err)
        self.assertIn("secret report", err)
        self.assertIn("Failed closed", summary)

    def test_both_reports_present_is_the_control_for_the_missing_report_tests(self):
        self.assertEqual(self.missing_report_run(True, True)[0], 0)

    def exceptions_run(self, content=None, make_dir=False):
        os.makedirs(os.path.join(self.dir, ".github"), exist_ok=True)
        path = os.path.join(self.dir, ".github", "image-exceptions.json")
        if make_dir:
            os.makedirs(path)
        elif content is not None:
            with open(path, "w", encoding="utf-8", newline="") as handle:
                handle.write(content)
        return self.run_gate(exceptions=".github/image-exceptions.json")

    def test_no_exceptions_file_means_no_exceptions(self):
        self.assertEqual(self.exceptions_run()[0], 0)
        code, *_ = self.run_gate(report(result([vuln()])), exceptions=".github/image-exceptions.json")
        self.assertEqual(code, 1)

    def test_a_file_that_is_not_valid_fails_closed_even_on_a_clean_image(self):
        for content in ("", "{}", "[]", " ", "\n", "x", '{"exceptions": []} x', '{"exceptions":[{"id":"CVE-1"}]}',
                        '{"exceptions": [], "exceptions": []}', '{"exceptions": [NaN]}', '{"other": []}'):
            with self.subTest(content=content):
                code, out, err, summary = self.exceptions_run(content)
                self.assertEqual(code, 2)
                self.assertIn("exceptions file is not valid", err)
                self.assertIn("Failed closed", summary)
                os.remove(os.path.join(self.dir, ".github", "image-exceptions.json"))

    def test_an_empty_list_is_valid_and_excepts_nothing(self):
        self.assertEqual(self.exceptions_run('{"exceptions": []}')[0], 0)
        code, *_ = self.run_gate(report(result([vuln()])), exceptions=".github/image-exceptions.json")
        self.assertEqual(code, 1)

    def test_a_directory_as_exceptions_file_fails(self):
        self.assertEqual(self.exceptions_run(make_dir=True)[0], 2)

    def test_a_bad_exceptions_path_fails(self):
        for path in ("../x.json", "/etc/passwd", "a b"):
            self.assertEqual(self.run_gate(exceptions=path)[0], 2)

    def test_summary_is_safe_for_markdown_and_workflow_commands(self):
        nasty = vuln("CVE-9")
        nasty["PkgName"] = "a|b`c\n::error::pwned"
        code, out, err, summary = self.run_gate(report(result([nasty], target="t\n::set-output name=x::y")),
                                                reference="app:1")
        self.assertEqual(code, 1)
        for text in (out, summary):
            for line in text.splitlines():
                self.assertFalse(line.lstrip().startswith("::"), line)
        for line in err.splitlines():
            self.assertTrue(line.startswith("::error::"), line)
        row = [l for l in summary.splitlines() if "CVE-9" in l][0]
        self.assertEqual(row.count("|"), 7)

    HOSTILE = "|`::<img src=x onerror=y> [x](y) ![i](https://e.example/x.png) \\"

    def assert_cell_is_inert(self, row, pipes):
        self.assertEqual(row.count("|"), pipes, row)
        for char in "`<>[]()!\\":
            self.assertNotIn(char, row)
        self.assertNotIn("::", row)
        self.assertNotIn("://", row)

    def test_untrusted_text_in_every_summary_cell_cannot_inject_markdown_or_html(self):
        # An excepted row: the reason is free text from the caller's exceptions file.
        reason = "ok" + self.HOSTILE + " end"
        data = report(result([vuln()]), result([vuln("CVE-2026-0002")], target="t" + self.HOSTILE))
        code, out, err, summary = self.excepted_run([self.entry(reason=reason)], data)
        self.assertEqual(code, 1)
        for line in summary.splitlines():
            self.assertFalse(line.lstrip().startswith("::"), line)
        excepted = [l for l in summary.splitlines() if "CVE-2026-0001" in l][0]
        self.assert_cell_is_inert(excepted, 9)
        self.assertIn("reviewer-one", excepted)
        self.assertIn("ok", excepted)  # the text is shown, only its markup is neutralised
        # A failing row with a hostile Target.
        failing = [l for l in summary.splitlines() if "CVE-2026-0002" in l][0]
        self.assert_cell_is_inert(failing, 7)
        # The same through a package, an installed version and a fixed version.
        hostile = vuln("CVE-2026-0003", PkgName="p" + self.HOSTILE, InstalledVersion="i" + self.HOSTILE,
                       FixedVersion="f" + self.HOSTILE)
        code, out, err, summary = self.run_gate(report(result([hostile], target="t")))
        self.assertEqual(code, 1)
        self.assert_cell_is_inert([l for l in summary.splitlines() if "CVE-2026-0003" in l][0], 7)

    def test_source_ampersands_cannot_form_character_references(self):
        for value in ("safe&#x202e;txt.exe", "config&#46;env", "&lt;b&gt;", "&amp;", "&#124;", "&#X202E",
                      "&rlm;", "&ZeroWidthSpace;", "pkg&amp"):
            cell = ti.cell(value)
            with self.subTest(value=value):
                self.assertNotRegex(cell, r"&(?!amp;|#\d{2,3};)")
                self.assertIn("&amp;", cell)
        self.assertEqual(ti.cell("&#46;"), "&amp;#46;")
        # helper-generated references stay single
        self.assertEqual(ti.cell("a&<b www.x"), "a&amp;&#60;b www&#46;x")
        self.assertEqual(ti.cell("a‮b&"), "a&#92;u202eb&amp;")
        # plain-text log output is not escaped
        self.assertEqual(ti.clean("a&b"), "a&b")

    def test_lone_surrogates_are_escaped_and_astral_characters_kept(self):
        self.assertEqual(ti.clean("a\ud800b\udfffc"), r"a\ud800b\udfffc")
        self.assertEqual(ti.cell("a\ud800b"), "a&#92;ud800b")
        self.assertEqual(ti.clean("a\U0001F600\U00020000"), "a\U0001F600\U00020000")
        self.assertEqual(ti.cell("a\U0001F600\U00020000"), "a\U0001F600\U00020000")

    def test_image_summary_renders_a_lone_surrogate_in_a_package_name(self):
        hostile = vuln("CVE-2026-0005", PkgName="p\ud800\U0001F600", InstalledVersion="i\udfff",
                       FixedVersion="f\ud800")
        code, out, err, summary = self.run_gate(report(result([hostile], target="t\ud800")))
        self.assertEqual(code, 1)
        row = [l for l in summary.splitlines() if "CVE-2026-0005" in l][0]
        self.assertIn("p&#92;ud800\U0001F600", row)
        for text in (out, err, summary):
            self.assertFalse([c for c in text if unicodedata.category(c) == "Cs"])

    def test_image_summary_neutralises_source_ampersands(self):
        entity = "x&#x202e;y&rlm;&ZeroWidthSpace;&#46;"
        hostile = vuln("CVE-2026-0004", PkgName="p" + entity, InstalledVersion="i" + entity,
                       FixedVersion="f" + entity)
        code, out, err, summary = self.run_gate(report(result([hostile], target="t" + entity)))
        self.assertEqual(code, 1)
        row = [l for l in summary.splitlines() if "CVE-2026-0004" in l][0]
        self.assertNotRegex(row, r"&(?!amp;|#\d{2,3};)")
        self.assertIn("px&amp;#x202e;y&amp;rlm;&amp;ZeroWidthSpace;&amp;#46;", row)

    def test_hostile_secret_fields_are_inert_in_the_summary(self):
        leaked = report(result(secrets=[secret(RuleID="r" + self.HOSTILE, Title="t" + self.HOSTILE)],
                               target="f" + self.HOSTILE))
        code, out, err, summary = self.run_gate(secret_report=leaked)
        self.assertEqual(code, 1)
        self.assert_cell_is_inert([l for l in summary.splitlines() if l.startswith("| CRITICAL")][0], 6)

    def test_stale_and_expired_rows_are_inert_in_the_summary(self):
        stale = self.entry(reason="ok" + self.HOSTILE + " end")
        code, out, err, summary = self.excepted_run([stale, self.entry(id="CVE-2026-0005", expires="2026-10-31")],
                                                    report())
        self.assertEqual(code, 1)
        self.assertIn("Stale exceptions", summary)
        self.assertIn("Expired exceptions", summary)
        for line in summary.splitlines():
            self.assertFalse(line.lstrip().startswith("::"), line)
            if line.startswith(("- ", "| example/app")):
                self.assert_cell_is_inert(line, line.count("|"))

    def test_long_lists_are_truncated_in_the_summary_only(self):
        findings = [vuln("CVE-%d" % i) for i in range(ti.MAX_ROWS + 5)]
        code, out, err, summary = self.run_gate(report(result(findings)))
        self.assertEqual(code, 1)
        self.assertIn("and 5 more", summary)
        self.assertEqual(out.count("fixable "), ti.MAX_ROWS + 5)
        self.assertIn("%d fixable" % (ti.MAX_ROWS + 5), err)

    def test_summary_appends_for_several_images(self):
        self.run_gate()
        self.run_gate(report(result([vuln()])))
        text = slurp(os.path.join(self.dir, "summary.md"))
        self.assertIn("Passed", text)
        self.assertIn("Failed", text)

    def test_summary_comes_from_the_environment_when_not_given(self):
        summary = os.path.join(self.dir, "env-summary.md")
        vpath, spath = self.write("v.json", report()), self.write("s.json", report())
        argv = ["gate", "--reference", "app:1", "--vuln", vpath, "--secret", spath, "--exceptions-file", "none.json"]
        os.chdir(self.dir)
        try:
            self.assertEqual(ti.main(argv, {"GITHUB_STEP_SUMMARY": summary}, io.StringIO(), io.StringIO()), 0)
        finally:
            os.chdir(HERE)
        self.assertTrue(os.path.exists(summary))

    def test_bad_gate_arguments_fail(self):
        base = ["gate", "--reference", "a", "--vuln", "v", "--secret", "s", "--exceptions-file", "e"]
        for argv in (base[:-2], base + ["--bogus", "x"], base + ["--vuln", "again"], base[:-1]):
            with self.subTest(argv=argv):
                self.assertEqual(ti.main(argv, {}, io.StringIO(), io.StringIO()), 2)

    # ---- the exception engine inside the gate

    REF = "example/app:1.2.3@" + DIGEST

    def entry(self, **over):
        base = {"image": "example/app", "digest": DIGEST, "id": "CVE-2026-0001", "package": "libfoo",
                "reason": "the vendor has not rebuilt the image", "reviewer": "reviewer-one",
                "reviewed": "2026-10-25", "expires": "2026-11-20"}
        base.update(over)
        return base

    def excepted_run(self, entries, vuln_report=None, reference=None, digests=(DIGEST,), secret_report=None):
        os.makedirs(os.path.join(self.dir, ".github"), exist_ok=True)
        with open(os.path.join(self.dir, ".github", "image-exceptions.json"), "w", encoding="utf-8") as handle:
            json.dump({"exceptions": entries}, handle)
        data = report(result([vuln()])) if vuln_report is None else vuln_report
        if isinstance(data, dict) and digests is not None:
            data["Metadata"] = {"RepoDigests": ["example/app@" + d for d in digests]}
        return self.run_gate(data, secret_report, exceptions=".github/image-exceptions.json",
                             reference=reference or self.REF, today=datetime.date(2026, 11, 1))

    def test_a_live_digest_bound_entry_excepts_the_finding(self):
        code, out, err, summary = self.excepted_run([self.entry()])
        self.assertEqual((code, err), (0, ""))
        self.assertIn("excepted HIGH CVE-2026-0001 libfoo until 2026-11-20, reviewed by reviewer-one", out)
        self.assertIn("Passed", summary)
        row = [l for l in summary.splitlines() if "CVE-2026-0001" in l][0]
        self.assertIn("| 2026-11-20 | reviewer-one |", row)
        self.assertIn("the vendor has not rebuilt the image", row)

    def test_a_digit_free_ghsa_entry_excepts_the_finding_in_the_gate(self):
        ghsa = "GHSA-cfgh-jmpq-rvwx"
        code, out, err, summary = self.excepted_run([self.entry(id=ghsa)], report(result([vuln(ghsa)])))
        self.assertEqual((code, err), (0, ""))
        self.assertIn("excepted HIGH %s libfoo until 2026-11-20" % ghsa, out)

    def test_an_entry_matches_the_raw_trivy_strings_not_the_cleaned_display_copies(self):
        # clean() turns "a|b" into "a/b" and drops a leading or trailing space and a NUL, so a
        # match on the cleaned copy would except a finding the entry does not name.
        # Each case: label, the entry's package, the finding's id and PkgName.
        cases = (("package a/b vs a|b", "a/b", "CVE-2026-0001", "a|b"),
                 ("package with a trailing NUL", "libfoo", "CVE-2026-0001", "libfoo\x00"),
                 ("package with a trailing space", "libfoo", "CVE-2026-0001", "libfoo "),
                 ("package with a leading space", "libfoo", "CVE-2026-0001", " libfoo"),
                 ("id with a trailing NUL", "libfoo", "CVE-2026-0001\x00", "libfoo"),
                 ("id with a trailing space", "libfoo", "CVE-2026-0001 ", "libfoo"),
                 ("id with a leading space", "libfoo", " CVE-2026-0001", "libfoo"))
        for label, entry_package, vid, package in cases:
            with self.subTest(label):
                code, out, err, summary = self.excepted_run(
                    [self.entry(package=entry_package)], report(result([vuln(vid, PkgName=package)])))
                self.assertEqual(code, 1)
                self.assertNotIn("excepted ", out)
                self.assertIn("fixable HIGH", out)
                self.assertIn("::warning::Stale exception", out)
        # The control: the same entry does except the finding that carries exactly its strings.
        code, out, *_ = self.excepted_run([self.entry(package="a/b")], report(result([vuln(PkgName="a/b")])))
        self.assertEqual(code, 0)
        self.assertIn("excepted HIGH CVE-2026-0001 a/b", out)

    def test_an_entry_covers_only_its_own_id_and_package(self):
        findings = [vuln("CVE-2026-0001"), vuln("CVE-2026-0002"), vuln("CVE-2026-0001", PkgName="libbar")]
        code, out, err, summary = self.excepted_run([self.entry()], report(result(findings)))
        self.assertEqual(code, 1)
        self.assertIn("fixable HIGH CVE-2026-0002 libfoo", out)
        self.assertIn("fixable HIGH CVE-2026-0001 libbar", out)
        self.assertNotIn("fixable HIGH CVE-2026-0001 libfoo", out)
        self.assertIn("2 fixable", err)
        self.assertIn("1 other finding(s) excepted", summary)

    def test_an_entry_for_another_digest_does_not_apply_and_is_stale(self):
        code, out, err, summary = self.excepted_run([self.entry(digest=OTHER)])
        self.assertEqual(code, 1)
        self.assertNotIn("excepted", out)
        self.assertIn("::warning::Stale exception (it names another digest", out)
        self.assertIn("Stale exceptions", summary)

    def test_an_entry_for_another_repository_does_not_apply_and_is_ignored(self):
        code, out, _, summary = self.excepted_run([self.entry(image="example/other")])
        self.assertEqual(code, 1)
        self.assertNotIn("::warning::", out)
        self.assertNotIn("Stale", summary)

    def test_a_tag_only_reference_cannot_be_excepted(self):
        code, out, err, summary = self.excepted_run([self.entry()], reference="example/app:1.2.3")
        self.assertEqual(code, 1)
        self.assertNotIn("excepted", out)
        self.assertIn("the reference has no sha256 digest", out)

    def test_a_report_that_does_not_confirm_the_digest_gets_no_exceptions(self):
        for digests in ((), (OTHER,), None):
            with self.subTest(digests=digests):
                code, out, *_ = self.excepted_run([self.entry()], digests=digests)
                self.assertEqual(code, 1)
                self.assertIn("does not list the digest", out)

    def test_an_expired_entry_fails_even_when_the_image_is_clean(self):
        code, out, err, summary = self.excepted_run([self.entry(expires="2026-10-31")], report())
        self.assertEqual(code, 1)
        self.assertIn("::error::Exception expired on 2026-10-31", err)
        self.assertIn("Expired exceptions", summary)

    def test_an_expired_entry_does_not_except_and_one_for_another_image_still_fails(self):
        code, out, err, _ = self.excepted_run([self.entry(expires="2026-10-31")])
        self.assertEqual(code, 1)
        self.assertNotIn("excepted", out)
        code, out, err, _ = self.excepted_run([self.entry(image="example/other", expires="2026-10-31")], report())
        self.assertEqual(code, 1)

    def test_the_expiry_day_is_still_live(self):
        code, *_ = self.excepted_run([self.entry(expires="2026-11-01")])
        self.assertEqual(code, 0)

    def test_a_stale_entry_warns_without_failing(self):
        code, out, err, summary = self.excepted_run([self.entry()], report())
        self.assertEqual((code, err), (0, ""))
        self.assertIn("::warning::Stale exception (it no longer matches a finding)", out)
        self.assertIn("Stale exceptions", summary)

    def test_an_invalid_entry_fails_the_job_even_for_other_findings(self):
        for label, bad in {
            "wildcard": self.entry(id="CVE-2026-*"),
            "tag instead of digest": {k: v for k, v in self.entry().items() if k != "digest"},
            "future review": self.entry(reviewed="2026-11-02", expires="2026-11-20"),
            "too long": self.entry(reviewed="2026-10-01", expires="2026-11-20"),
        }.items():
            with self.subTest(label):
                code, out, err, summary = self.excepted_run([bad, self.entry(id="CVE-2026-0009")])
                self.assertEqual(code, 2)
                self.assertIn("Failed closed", summary)

    def test_a_secret_is_never_excepted(self):
        leaked = report(result(secrets=[secret()], target="etc/key"))
        # A live entry for the finding of the same name, an entry that names the rule, and one
        # with a secret field: the secret still fails, or the file is refused.
        for label, entries, expected in (
                ("vulnerability entry", [self.entry()], 1),
                ("rule id as id", [self.entry(id="aws-access-key-id")], 2),
                ("rule field", [self.entry(rule="aws-access-key-id")], 2),
                ("secret field", [self.entry(secret="etc/key")], 2)):
            with self.subTest(label):
                code, out, err, summary = self.excepted_run(entries, report(), secret_report=leaked)
                self.assertEqual(code, expected)
                if code == 1:
                    self.assertIn("secret CRITICAL aws-access-key-id in etc/key", out)
                    self.assertIn("1 secrets", err)
        # A secret next to a finding that is excepted: only the finding is excepted.
        code, out, *_ = self.excepted_run([self.entry()], report(result([vuln()])), secret_report=leaked)
        self.assertEqual(code, 1)
        self.assertIn("secret CRITICAL aws-access-key-id", out)
        self.assertIn("excepted HIGH CVE-2026-0001", out)

    def test_unfixed_and_low_findings_need_no_entry_and_unmatched_ones_are_not_hidden(self):
        findings = [vuln("CVE-1", fixed=None), vuln("CVE-2", "LOW"), vuln("CVE-2026-0001")]
        code, out, *_ = self.excepted_run([self.entry()], report(result(findings)))
        self.assertEqual(code, 0)
        self.assertEqual(out.count("excepted "), 1)

    def test_vulnerabilities_given_as_a_json_object_fail_closed(self):
        # Not a list: never read as "no findings". Trivy emits a list or null.
        for label, value in {"populated object": {"VulnerabilityID": "CVE-2026-0001", "Severity": "HIGH", "FixedVersion": "2"},
                             "empty object": {}, "string": "CVE-2026-0001", "number": 1, "true": True}.items():
            with self.subTest(label):
                code, out, err, summary = self.run_gate(report(result(value)))
                self.assertEqual(code, 2)
                self.assertIn("malformed Vulnerabilities", err)
                self.assertIn("Failed closed", summary)
        # Also with a matching exception on file: an exception cannot turn a confused shape into a pass.
        code, *_ = self.excepted_run([self.entry()], report(result({"VulnerabilityID": "CVE-2026-0001"})))
        self.assertEqual(code, 2)

    def test_an_engine_that_cannot_be_loaded_fails_closed(self):
        real = ti.importlib.util.spec_from_file_location
        ti.importlib.util.spec_from_file_location = lambda name, path: real(name, os.path.join(self.dir, "missing.py"))
        try:
            code, out, err, summary = self.run_gate()
        finally:
            ti.importlib.util.spec_from_file_location = real
        self.assertEqual(code, 2)
        self.assertIn("cannot load the exception engine", err)


class Cli(unittest.TestCase):
    """The script as the workflow runs it: python3 -I, arguments and environment only."""

    def run_cli(self, args, env_extra, cwd):
        env = {k: v for k, v in os.environ.items() if not k.startswith(("IMAGES", "EXCEPTIONS_FILE", "SECRET_ALLOWLIST_FILE", "GITHUB_"))}
        env.update(env_extra)
        return subprocess.run([sys.executable, "-I", SCRIPT] + args, env=env, cwd=cwd, capture_output=True, text=True)

    def test_plan_and_gate_under_isolated_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = os.path.join(tmp, "out")
            result_ = self.run_cli(["plan"], {"IMAGES": "app@" + DIGEST + "\n", "EXCEPTIONS_FILE": ".github/e.json",
                                              "SECRET_ALLOWLIST_FILE": ".github/a.json", "GITHUB_OUTPUT": output}, tmp)
            self.assertEqual(result_.returncode, 0, result_.stderr)
            self.assertIn("matrix=", slurp(output))
            for name in ("v.json", "s.json"):
                with open(os.path.join(tmp, name), "w", encoding="utf-8") as handle:
                    json.dump(report(), handle)
            summary = os.path.join(tmp, "summary.md")
            gate = ["gate", "--reference", "app@" + DIGEST, "--vuln", "v.json", "--secret", "s.json",
                    "--exceptions-file", ".github/e.json"]
            self.assertEqual(self.run_cli(gate, {"GITHUB_STEP_SUMMARY": summary}, tmp).returncode, 0)
            with open(os.path.join(tmp, "v.json"), "w", encoding="utf-8") as handle:
                json.dump(report(result([vuln()])), handle)
            failed = self.run_cli(gate, {"GITHUB_STEP_SUMMARY": summary}, tmp)
            self.assertEqual(failed.returncode, 1)
            self.assertIn("CVE-2026-0001", failed.stdout)

    def test_a_planted_module_next_to_the_working_directory_is_not_imported(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "json.py"), "w", encoding="utf-8") as handle:
                handle.write("raise SystemExit(99)\n")
            output = os.path.join(tmp, "out")
            result_ = self.run_cli(["plan"], {"IMAGES": "app:1", "EXCEPTIONS_FILE": "e.json", "SECRET_ALLOWLIST_FILE": "a.json",
                                              "GITHUB_OUTPUT": output}, tmp)
            self.assertEqual(result_.returncode, 0, result_.stderr)


WORKFLOW = "trivy-images.yml"


def slurp(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def run_text(step_text):
    """Everything after the run: key of a step (run is always its last key)."""
    return step_text[step_text.index("run:"):] if "run:" in step_text else ""


def steps_of(text):
    return re.split(r"\n(?=      - name: |\n  \S)", text)


class Workflow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = read(WORKFLOW)
        cls.plan = cls.text[cls.text.index("\n  plan:\n"):cls.text.index("\n  scan:\n")]
        cls.scan = cls.text[cls.text.index("\n  scan:\n"):]

    def test_inputs(self):
        block = input_block(self.text, "images")
        self.assertRegex(block, r"required:\s*true\b")
        self.assertRegex(block, r"type:\s*string\b")
        block = input_block(self.text, "exceptions-file")
        self.assertRegex(block, r"default:\s*\.github/image-exceptions\.json\b")
        self.assertRegex(block, r"required:\s*false\b")
        self.assertRegex(block, r"type:\s*string\b")
        block = input_block(self.text, "registry-login")
        self.assertRegex(block, r"default:\s*false\b")
        self.assertRegex(block, r"required:\s*false\b")
        self.assertRegex(block, r"type:\s*boolean\b")

    def test_registry_token_is_an_optional_secret(self):
        secrets = self.text[self.text.index("    secrets:\n"):self.text.index("\n# Declared cap")]
        self.assertRegex(secrets, r"(?m)^      registry-token:\n")
        self.assertRegex(secrets, r"required:\s*false\b")
        self.assertEqual(len(re.findall(r"(?m)^      [\w-]+:\n", secrets)), 1)

    def test_plan_job_validates_the_timeout_first_and_scan_applies_it(self):
        first = steps_of(self.plan)
        self.assertTrue(first[1].startswith("      - name: Validate timeout"))
        self.assertEqual(self.text.count("timeout-minutes: ${{ inputs.timeout-minutes }}"), 1)
        self.assertIn("timeout-minutes: ${{ inputs.timeout-minutes }}", self.scan)
        self.assertRegex(self.plan, r"(?m)^    timeout-minutes: \d+$")
        self.assertRegex(self.scan, r"(?m)^    needs: plan$")

    def test_scan_is_a_matrix_over_the_plan_that_does_not_stop_early(self):
        self.assertIn("fail-fast: false", self.scan)
        self.assertIn("matrix: ${{ fromJSON(needs.plan.outputs.matrix) }}", self.scan)
        self.assertIn("matrix: ${{ steps.plan.outputs.matrix }}", self.plan)

    def test_the_script_runs_isolated_and_nothing_else_runs_python(self):
        self.assertEqual(self.text.count("python3 -I .strange-security/scripts/trivy_images.py"), 2)
        self.assertNotRegex(self.text, r"python3?\s+(?!-I)")

    def test_no_expression_reaches_a_shell_script(self):
        for each in steps_of(self.text):
            script = run_text(each)
            with self.subTest(step=each.splitlines()[0]):
                self.assertNotIn("${{", script)

    def test_untrusted_values_travel_in_environment_variables(self):
        for each in steps_of(self.text):
            for match in re.finditer(r"\$\{\{\s*(inputs|matrix)\.[\w.-]+\s*\}\}", each):
                before = each[:match.start()].splitlines()[-1]
                allowed = ("env" in each[:match.start()] and re.match(r"\s+[A-Z_]+: $", before)) or \
                    re.match(r"\s+(if|category|sarif_file|name|timeout-minutes|matrix):", before)
                self.assertTrue(allowed, before + match.group(0))

    def test_trivy_never_exits_non_zero_and_the_gate_decides(self):
        runs = re.findall(r"--exit-code (\d)", self.text)
        self.assertEqual(len(runs), 4)
        self.assertEqual(set(runs), {"0"})
        self.assertNotIn("continue-on-error", self.text)

    def test_json_reports_are_unfiltered(self):
        for name in ("Run Trivy secret scan", "Run Trivy vulnerability scan"):
            script = run_text(step(self.text, name))
            self.assertIn("--format json", script)
            self.assertNotIn("--severity", script)
            self.assertNotIn("--ignore-unfixed", script)
        self.assertIn("--scanners secret", run_text(step(self.text, "Run Trivy secret scan")))
        self.assertIn("--scanners vuln", run_text(step(self.text, "Run Trivy vulnerability scan")))

    def test_the_callers_checkout_is_not_the_scan_working_directory(self):
        scans = [run_text(each) for each in steps_of(self.scan) if "docker run" in each]
        self.assertEqual(len(scans), 4)
        for script in scans:
            self.assertIn("--workdir /out", script)
            self.assertNotIn("$PWD", script)
            self.assertNotIn("/src", script)

    def test_gate_runs_after_the_json_scans_and_before_the_sarif_passes(self):
        order = [m.group(1) for m in re.finditer(r"(?m)^      - name: (.*)$", self.scan)]
        gate = order.index("Gate image")
        self.assertLess(order.index("Run Trivy secret scan"), order.index("Run Trivy vulnerability scan"))
        self.assertLess(order.index("Run Trivy vulnerability scan"), gate)
        self.assertLess(gate, order.index("Write secret scan SARIF"))
        self.assertLess(gate, order.index("Upload secret scan SARIF"))
        gate_step = step(self.text, "Gate image")
        self.assertNotIn("if:", gate_step[:gate_step.index("run:")])
        self.assertNotIn("always()", gate_step)

    def test_the_engine_exit_status_is_the_job_status(self):
        # The run block of the Gate image step is the python3 -I gate call and nothing else: no
        # operator that could swallow its exit status, and no continue-on-error on the step.
        script = extract_run_block(os.path.join(WORKFLOWS, WORKFLOW), "Gate image")
        self.assertEqual(script.rstrip("\n") + "\n", (
            "python3 -I .strange-security/scripts/trivy_images.py gate \\\n"
            '  --reference "$REFERENCE" \\\n'
            '  --vuln "$RUNNER_TEMP/trivy-images/out/vuln.json" \\\n'
            '  --secret "$RUNNER_TEMP/trivy-images/out/secret.json" \\\n'
            '  --exceptions-file "$EXCEPTIONS_FILE" \\\n'
            '  --secret-allowlist-file "$SECRET_ALLOWLIST_FILE"\n'))
        for token in ("||", "&&", ";", "set +e", "|| true", "|", "&", "trap", "exit", "$?"):
            self.assertNotIn(token, script)
        lines = [l for l in step(self.text, "Gate image").splitlines() if not l.lstrip().startswith("#")]
        self.assertNotIn("continue-on-error", "\n".join(lines))

    def test_the_scan_job_checks_the_engine_out_and_the_gate_is_what_reads_the_exceptions(self):
        self.assertIn("test -f .strange-security/scripts/image_exceptions.py", self.scan)
        gate_step = step(self.text, "Gate image")
        self.assertIn('--exceptions-file "$EXCEPTIONS_FILE"', gate_step)
        self.assertIn("EXCEPTIONS_FILE: ${{ inputs.exceptions-file }}", gate_step)
        # No other step of the scan job reads the exceptions file or runs the engine.
        others = [each for each in steps_of(self.scan)
                  if "Gate image" not in each.splitlines()[0] and "Verify shared workflow" not in each.splitlines()[0]]
        for each in others:
            with self.subTest(step=each.splitlines()[0]):
                self.assertNotIn("EXCEPTIONS_FILE", each)
                self.assertNotIn("image_exceptions", each)
        self.assertNotIn("image_exceptions.py", self.plan)

    def test_the_exceptions_input_describes_the_digest_binding_and_the_missing_file(self):
        description = " ".join(input_block(self.text, "exceptions-file").split())
        for phrase in ("missing file means no exceptions", "digest", "31 days", "never applies to a secret"):
            self.assertIn(phrase, description)
        self.assertNotIn("not supported", description)

    def test_sarif_is_optional_and_per_image(self):
        for name in ("Write secret scan SARIF", "Write vulnerability scan SARIF"):
            self.assertIn("inputs.upload-sarif", step(self.text, name).split("env:")[0])
        for name, prefix in (("Upload secret scan SARIF", "trivy-images-secret/"), ("Upload vulnerability scan SARIF", "trivy-images/")):
            self.assertIn("category: %s${{ matrix.repository }}" % prefix, step(self.text, name))
        # Apart from the categories of trivy-image.yml, so the two cannot overwrite each other.
        self.assertNotIn("category: trivy-image/", self.text)
        self.assertNotIn("category: trivy-image-secret/", self.text)

    def test_sarif_passes_use_the_filters_of_trivy_image(self):
        script = run_text(step(self.text, "Write vulnerability scan SARIF"))
        self.assertIn("--severity HIGH,CRITICAL --ignore-unfixed", script)
        secret_script = run_text(step(self.text, "Write secret scan SARIF"))
        self.assertNotIn("--severity", secret_script)

    def test_login_uses_the_secret_not_github_token(self):
        code = "\n".join(l for l in self.text.splitlines() if not l.lstrip().startswith("#"))
        self.assertNotRegex(code, r"secrets\.GITHUB_TOKEN|github\.token")
        self.assertEqual(code.count("secrets.registry-token"), 1)
        login = step(self.text, "Log in to GitHub Container Registry")
        self.assertIn("if: ${{ inputs.registry-login }}", login[:login.index("run:")])
        self.assertIn("REGISTRY_TOKEN: ${{ secrets.registry-token }}", login)
        self.assertNotIn("docker/login-action", self.text)


@unittest.skipUnless(BASH, "bash is required")
class RegistryLogin(unittest.TestCase):
    """The real login step of both image workflows, run under bash against a stub docker."""

    NAME = "Log in to GitHub Container Registry"

    def run_login(self, workflow, token):
        script = extract_run_block(os.path.join(WORKFLOWS, workflow), self.NAME)
        with tempfile.TemporaryDirectory() as tmp:
            bindir = os.path.join(tmp, "bin")
            os.makedirs(bindir)
            record = os.path.join(tmp, "record")
            stub = os.path.join(bindir, "docker")
            with open(stub, "w", encoding="utf-8", newline="\n") as handle:
                handle.write('#!/usr/bin/env bash\nprintf "%s\\n" "$*" >> "$RECORD"\ncat >> "$RECORD.stdin"\n')
            os.chmod(stub, 0o755)
            env = dict(os.environ, RECORD=record, REGISTRY_USER="octocat", REGISTRY_TOKEN=token)
            env["PATH"] = bindir + os.pathsep + env["PATH"]
            result_ = subprocess.run([BASH, "-c", script], env=env, capture_output=True, text=True)
            args = slurp(record) if os.path.exists(record) else None
            stdin = slurp(record + ".stdin") if os.path.exists(record + ".stdin") else None
        return result_, args, stdin

    def test_logs_in_through_stdin_only(self):
        for workflow in ("trivy-image.yml", WORKFLOW):
            with self.subTest(workflow=workflow):
                result_, args, stdin = self.run_login(workflow, "tok-123")
                self.assertEqual(result_.returncode, 0, result_.stdout + result_.stderr)
                self.assertEqual(args.strip(), "login ghcr.io --username octocat --password-stdin")
                self.assertEqual(stdin, "tok-123")
                self.assertNotIn("tok-123", args)

    def test_an_empty_token_is_a_clear_error_and_never_calls_docker(self):
        for workflow in ("trivy-image.yml", WORKFLOW):
            with self.subTest(workflow=workflow):
                result_, args, stdin = self.run_login(workflow, "")
                self.assertNotEqual(result_.returncode, 0)
                self.assertIn("registry-login is true but the registry-token secret is empty", result_.stdout)
                self.assertIsNone(args)


if __name__ == "__main__":
    unittest.main()
