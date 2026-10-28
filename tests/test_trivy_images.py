"""trivy-images.yml: the plan/gate script (scripts/trivy_images.py) and the
wiring of the workflow around it."""
import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import tempfile
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
            env = {"IMAGES": images, "EXCEPTIONS_FILE": exceptions, "GITHUB_OUTPUT": output}
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
        self.assertEqual(ti.main(["plan"], {"IMAGES": "app:1", "EXCEPTIONS_FILE": "x.json"}, out, err), 2)

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

    def run_gate(self, vuln_report=None, secret_report=None, exceptions=None, reference="app:1"):
        vpath = self.write("vuln.json", report() if vuln_report is None else vuln_report)
        spath = self.write("secret.json", report() if secret_report is None else secret_report)
        summary = os.path.join(self.dir, "summary.md")
        argv = ["gate", "--reference", reference, "--vuln", vpath, "--secret", spath,
                "--exceptions-file", exceptions or "no-such-exceptions-file.json", "--summary", summary]
        out, err = io.StringIO(), io.StringIO()
        cwd = os.getcwd()
        os.chdir(self.dir)
        try:
            code = ti.main(argv, {}, out, err)
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

    def test_missing_reports_fail_closed(self):
        out, err = io.StringIO(), io.StringIO()
        argv = ["gate", "--reference", "app:1", "--vuln", os.path.join(self.dir, "nope.json"),
                "--secret", os.path.join(self.dir, "nope2.json"), "--exceptions-file", "x.json"]
        self.assertEqual(ti.main(argv, {}, out, err), 2)
        self.assertIn("::error::", err.getvalue())

    def exceptions_run(self, content=None, make_dir=False):
        os.makedirs(os.path.join(self.dir, ".github"), exist_ok=True)
        path = os.path.join(self.dir, ".github", "image-exceptions.json")
        if make_dir:
            os.makedirs(path)
        elif content is not None:
            with open(path, "w", encoding="utf-8", newline="") as handle:
                handle.write(content)
        return self.run_gate(exceptions=".github/image-exceptions.json")

    def test_no_exceptions_file_is_fine(self):
        self.assertEqual(self.exceptions_run()[0], 0)

    def test_an_empty_exceptions_file_is_fine(self):
        self.assertEqual(self.exceptions_run("")[0], 0)

    def test_a_non_empty_exceptions_file_fails_even_on_a_clean_image(self):
        for content in ("{}", "[]", '{"exceptions": []}', " ", "\n", "x", '{"exceptions":[{"id":"CVE-1"}]}'):
            with self.subTest(content=content):
                code, out, err, summary = self.exceptions_run(content)
                self.assertEqual(code, 2)
                self.assertIn("not supported", err)
                self.assertIn("exception", summary)
                os.remove(os.path.join(self.dir, ".github", "image-exceptions.json"))

    def test_an_exceptions_file_never_suppresses_a_finding(self):
        os.makedirs(os.path.join(self.dir, ".github"))
        with open(os.path.join(self.dir, ".github", "image-exceptions.json"), "w", encoding="utf-8") as handle:
            handle.write('{"exceptions":[{"id":"CVE-2026-0001"}]}')
        code, *_ = self.run_gate(report(result([vuln()])), exceptions=".github/image-exceptions.json")
        self.assertEqual(code, 2)

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


class Cli(unittest.TestCase):
    """The script as the workflow runs it: python3 -I, arguments and environment only."""

    def run_cli(self, args, env_extra, cwd):
        env = {k: v for k, v in os.environ.items() if not k.startswith(("IMAGES", "EXCEPTIONS_FILE", "GITHUB_"))}
        env.update(env_extra)
        return subprocess.run([sys.executable, "-I", SCRIPT] + args, env=env, cwd=cwd, capture_output=True, text=True)

    def test_plan_and_gate_under_isolated_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = os.path.join(tmp, "out")
            result_ = self.run_cli(["plan"], {"IMAGES": "app@" + DIGEST + "\n", "EXCEPTIONS_FILE": ".github/e.json",
                                              "GITHUB_OUTPUT": output}, tmp)
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
            result_ = self.run_cli(["plan"], {"IMAGES": "app:1", "EXCEPTIONS_FILE": "e.json", "GITHUB_OUTPUT": output}, tmp)
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
