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

    def test_no_permission_that_forces_callers_to_grant_it(self):
        for name in scan_workflows():
            text = read(name)
            with self.subTest(workflow=name):
                self.assertNotRegex(text, r"(?m)^\s*permissions:")
                self.assertNotRegex(text, r"(?m)^\s*(packages|security-events):\s*(read|write|none)")

    def test_gate_exercises_the_opt_out_inputs(self):
        gate = read("security_gate.yml")
        self.assertRegex(gate, r"upload-sarif:\s*false\b")
        match = re.search(r"timeout-minutes:\s*(\d+)\s*\n", gate)
        self.assertTrue(match)
        self.assertNotEqual(match.group(1), "30")
        job = gate[gate.index("  trivy-image:"):gate.index("  tests:")]
        self.assertNotIn("security-events", job)
        self.assertNotIn("packages", job)
        self.assertNotIn("registry-login:", job)

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
