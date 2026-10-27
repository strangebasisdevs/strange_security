"""Inputs shared by every reusable workflow: upload-sarif, timeout-minutes, and
the registry login of trivy-image.yml. The timeout step is extracted from each
workflow and run under bash, so the tests cannot drift from what CI executes."""
import os
import re
import subprocess
import unittest

from tests.test_trivy_image_validation import BASH, extract_run_block
from tests.test_workflows import WORKFLOWS, read, reusable

STEP = "Validate timeout"


def scan_workflows():
    return [n for n in reusable()]


def input_block(text, name):
    """The indented block of one workflow_call input."""
    match = re.search(r"^      %s:\n((?:        .*\n|\n)+)" % re.escape(name), text, re.M)
    assert match, "input not found: " + name
    return match.group(1)


def declared_permissions(text):
    """The permissions block as {scope: level}; empty when there is none."""
    match = re.search(r"(?m)^\s*permissions:[ \t]*\n((?:[ \t]+[a-z-]+:[ \t]*\w+[ \t]*(?:#.*)?\n)+)", text)
    if not match:
        return {}
    return dict(re.findall(r"([a-z-]+):[ \t]*(\w+)", match.group(1)))


def permission_count(text):
    return len(re.findall(r"(?m)^\s*permissions:", text))


def expected_cap(text):
    """actions and contents read, plus security-events write where SARIF is uploaded."""
    cap = {"actions": "read", "contents": "read"}
    if "upload-sarif@" in text:
        cap["security-events"] = "write"
    return cap


def cap_problems(text):
    """What is wrong with a workflow's permissions cap; empty when it is exact."""
    problems = []
    if permission_count(text) != 1:
        problems.append("not exactly one permissions block")
    if declared_permissions(text) != expected_cap(text):
        problems.append("cap differs from the expected one")
    return problems


FULL_CAP = "permissions:\n  actions: read\n  contents: read\n  security-events: write\n\njobs:\n  a:\n    uses: x\n"


class Inputs(unittest.TestCase):
    def test_every_reusable_workflow_has_the_common_inputs(self):
        self.assertEqual(len(scan_workflows()), 4)
        for name in scan_workflows():
            text = read(name)
            with self.subTest(workflow=name):
                block = input_block(text, "upload-sarif")
                self.assertRegex(block, r"type:\s*boolean\b")
                self.assertRegex(block, r"default:\s*true\b")
                self.assertRegex(block, r"required:\s*false\b")
                block = input_block(text, "timeout-minutes")
                self.assertRegex(block, r"type:\s*number\b")
                self.assertRegex(block, r"default:\s*30\b")
                self.assertRegex(block, r"required:\s*false\b")

    def test_timeout_is_applied_to_the_scan_job_and_validated_first(self):
        for name in scan_workflows():
            text = read(name)
            with self.subTest(workflow=name):
                self.assertEqual(text.count("timeout-minutes: ${{ inputs.timeout-minutes }}"), 1)
                jobs = text[text.index("\njobs:"):]
                self.assertLess(jobs.index("timeout-minutes:"), jobs.index("steps:"))
                self.assertLess(jobs.index("steps:"), jobs.index("name: " + STEP))
                self.assertEqual(jobs.index("- name:"), jobs.index("- name: " + STEP))

    def test_every_upload_step_honours_upload_sarif(self):
        for name in scan_workflows():
            text = read(name)
            found = list(re.finditer(r"^      - name: (.*)\n((?:        .*\n)+)", text, re.M))
            steps = [m for m in found if "upload-sarif@" in m.group(2)]
            with self.subTest(workflow=name):
                self.assertGreaterEqual(len(steps), 1)
                for m in steps:
                    self.assertIn("if: ${{ always() && inputs.upload-sarif }}", m.group(2), m.group(1))
                self.assertEqual(len(steps), text.count("upload-sarif@"))

    def test_each_workflow_declares_exactly_the_permissions_cap(self):
        for name in scan_workflows():
            text = read(name)
            with self.subTest(workflow=name):
                self.assertEqual(cap_problems(text), [])
                self.assertNotIn("packages", declared_permissions(text))
                self.assertEqual(declared_permissions(text)["security-events"], "write")
                self.assertNotRegex(text, r"(?m)^\s*packages:")

    def test_cap_check_rejects_missing_extra_and_write_permissions(self):
        sarif = "uses: github/codeql-action/upload-sarif@x\n"
        self.assertEqual(cap_problems(FULL_CAP + sarif), [])
        bad = {
            "missing block": "jobs:\n  a:\n    uses: x\n" + sarif,
            "missing actions": FULL_CAP.replace("  actions: read\n", ""),
            "write contents": FULL_CAP.replace("contents: read", "contents: write"),
            "write actions": FULL_CAP.replace("actions: read", "actions: write"),
            "read security-events": FULL_CAP.replace("security-events: write", "security-events: read"),
            "packages": FULL_CAP.replace("\n\njobs", "  packages: read\n\njobs"),
            "extra write": FULL_CAP.replace("\n\njobs", "  id-token: write\n\njobs"),
            "job-level block": FULL_CAP + "    permissions:\n      contents: read\n",
        }
        for label, text in bad.items():
            with self.subTest(case=label):
                self.assertNotEqual(cap_problems(text + sarif), [])
        # Without a SARIF upload the cap would not include security-events.
        self.assertNotEqual(cap_problems(FULL_CAP), [])

    def test_gate_contract_job_requires_the_cap(self):
        gate = read("security_gate.yml")
        job = gate[gate.index("  contract:"):gate.index("  semgrep:")]
        self.assertIn("expected='actions: read,contents: read,'", job)
        self.assertIn("security-events: write,", job)
        self.assertIn("upload-sarif@", job)
        self.assertNotIn("forces callers", job)
        self.assertNotIn("declare no permissions", job)

    def test_gate_exercises_the_opt_out_inputs(self):
        gate = read("security_gate.yml")
        start = gate.index("\n  trivy-image:\n")
        end = gate.index("\n  tests:\n")
        job = gate[start:end]
        # Comments are not configuration: only real keys of this job count.
        code = "\n".join(line for line in job.splitlines() if not line.lstrip().startswith("#"))
        self.assertRegex(code, r"(?m)^      upload-sarif:[ \t]*false[ \t]*$")
        match = re.search(r"(?m)^      timeout-minutes:[ \t]*(\d+)[ \t]*$", code)
        self.assertTrue(match)
        self.assertNotEqual(match.group(1), "30")
        self.assertNotIn("registry-login", code)
        # The called workflow keeps its cap, so the call grants all of it even with upload-sarif: false.
        self.assertEqual(declared_permissions(code), {"actions": "read", "contents": "read", "security-events": "write"})
        self.assertNotIn("packages", code)
        # Every other call inherits the gate's top-level grant, which must cover the cap.
        top = gate[gate.index("\npermissions:"):gate.index("\njobs:")].lstrip("\n")
        self.assertEqual(declared_permissions(top + "\n"), {"actions": "read", "contents": "read", "security-events": "write"})

    def test_gate_opt_out_comment_does_not_satisfy_the_job_assertions(self):
        gate = read("security_gate.yml")
        job = gate[gate.index("\n  trivy-image:\n"):gate.index("\n  tests:\n")]
        comments = "\n".join(l for l in job.splitlines() if l.lstrip().startswith("#"))
        self.assertNotRegex(comments, r"upload-sarif:\s*false")
        self.assertNotRegex(comments, r"timeout-minutes:\s*\d")

    def test_login_is_the_only_token_use_and_avoids_login_action(self):
        text = read("trivy-image.yml")
        self.assertNotIn("docker/login-action", text)
        self.assertEqual(text.count("secrets.GITHUB_TOKEN"), 1)
        self.assertEqual(len(re.findall(r"github\.token", text)), 0)
        login = text[text.index("- name: Log in to GitHub Container Registry"):]
        login = login[:login.index("run:")]
        self.assertIn("secrets.GITHUB_TOKEN", login)
        self.assertIn("if: ${{ inputs.registry-login }}", login)
        self.assertRegex(input_block(text, "registry-login"), r"default:\s*false\b")


@unittest.skipUnless(BASH, "bash is required")
class ValidateTimeout(unittest.TestCase):
    def run_step(self, workflow, value):
        script = extract_run_block(os.path.join(WORKFLOWS, workflow), STEP)
        env = dict(os.environ, TIMEOUT_MINUTES=value)
        return subprocess.run([BASH, "-c", script], env=env, capture_output=True, text=True)

    def test_accepts_whole_minutes_from_1_to_360(self):
        for workflow in scan_workflows():
            for value in ("1", "20", "30", "99", "100", "360"):
                with self.subTest(workflow=workflow, value=value):
                    self.assertEqual(self.run_step(workflow, value).returncode, 0)

    def test_rejects_everything_else(self):
        values = ("", "0", "-1", "361", "1000", "030", "01", "1.5", "30.0", "1e2", "abc",
                  "0x10", " 30", "30 ", "30\n", "30\n40", "3;id", "$(id)", "+5", "NaN", "Infinity")
        for workflow in scan_workflows():
            for value in values:
                with self.subTest(workflow=workflow, value=value):
                    result = self.run_step(workflow, value)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("timeout-minutes must be", result.stdout)

    def test_the_step_is_identical_in_every_workflow(self):
        scripts = {extract_run_block(os.path.join(WORKFLOWS, w), STEP) for w in scan_workflows()}
        self.assertEqual(len(scripts), 1)


if __name__ == "__main__":
    unittest.main()
