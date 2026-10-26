"""Pin structural promises of the workflow files so they cannot drift silently."""
import glob
import os
import re
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
WORKFLOWS = os.path.join(HERE, "..", ".github", "workflows")


def read(name):
    with open(os.path.join(WORKFLOWS, name), encoding="utf-8") as handle:
        return handle.read()


def gate_pattern():
    """The ERE the security gate's contract job uses to spot reusable workflows."""
    match = re.search(r"grep -qE '([^']*workflow_call[^']*)' \"\$file\" \|\| continue", read("security_gate.yml"))
    assert match, "contract job no longer greps for workflow_call"
    return match.group(1)


def is_reusable(text):
    return bool(re.search(gate_pattern(), text, re.M))


def reusable():
    return sorted(
        os.path.basename(p)
        for p in glob.glob(os.path.join(WORKFLOWS, "*.yml"))
        if is_reusable(read(os.path.basename(p)))
    )


def step(text, name):
    """The text of one workflow step, from its name line to the next step."""
    start = text.index("- name: " + name)
    end = text.find("\n      - name:", start + 1)
    return text[start:] if end < 0 else text[start:end]


class Workflows(unittest.TestCase):
    def test_semgrep_runs_checker_isolated(self):
        text = read("semgrep.yml")
        self.assertRegex(text, r"python3 -I \.strange-security/scripts/check_suppressions\.py")
        self.assertNotRegex(text, r"python3? (?!-I)[^\n]*check_suppressions")

    def test_semgrep_checker_cannot_skip_scan_or_upload(self):
        text = read("semgrep.yml")
        check = text.index("name: Check Semgrep suppressions")
        self.assertGreater(check, text.index("name: Run Semgrep"))
        self.assertGreater(check, text.index("name: Upload SARIF results"))
        self.assertIn("if: always()", text[check:text.index("run:", check)])
        upload = text.index("name: Upload SARIF results")
        self.assertIn("if: always()", text[upload:text.index("uses:", upload)])

    def test_semgrep_checker_step_is_not_continue_on_error(self):
        text = read("semgrep.yml")
        self.assertNotIn("continue-on-error", text)
        self.assertNotIn("continue-on-error", step(text, "Check Semgrep suppressions"))

    def test_semgrep_sarif_is_outside_the_workspace(self):
        text = read("semgrep.yml")
        run = step(text, "Run Semgrep")
        self.assertIn('--volume "$RUNNER_TEMP:/out"', run)
        self.assertIn("--output /out/semgrep.sarif", run)
        self.assertNotRegex(run, r"--output\s+/src")
        upload = step(text, "Upload SARIF results")
        self.assertIn("sarif_file: ${{ runner.temp }}/semgrep.sarif", upload)
        self.assertNotRegex(text, r"sarif_file:\s*(\./)?semgrep\.sarif")

    def test_registry_login_step_is_conditional(self):
        login = step(read("trivy-image.yml"), "Log in to GitHub Container Registry")
        self.assertIn("if: ${{ inputs.registry-login }}", login[:login.index("run:")])

    def test_reusable_detection_recognises_every_form(self):
        forms = {
            "block": "name: X\non:\n  workflow_call:\n    inputs: {}\n",
            "block with other triggers": "on:\n  push:\n  workflow_call:\n",
            "inline": "name: X\non: workflow_call\njobs: {}\n",
            "list": "on: [push, workflow_call]\n",
            "list first": "on: [workflow_call, push]\n",
            "list only": "on: [workflow_call]\n",
        }
        for label, text in forms.items():
            with self.subTest(form=label):
                self.assertTrue(is_reusable(text))
        for label, text in {
            "push": "on:\n  push:\n",
            "inline push": "on: push\n",
            "list push": "on: [push, pull_request]\n",
            "comment": "# on: workflow_call\non: push\n",
            "similar name": "on: [my_workflow_call]\n",
        }.items():
            with self.subTest(form=label):
                self.assertFalse(is_reusable(text))

    def test_gate_calls_every_reusable_workflow(self):
        gate = read("security_gate.yml")
        called = set(re.findall(r"uses:\s*\./\.github/workflows/([\w.-]+\.yml)", gate))
        names = reusable()
        self.assertIn("trivy-image.yml", names)
        self.assertIn("semgrep.yml", names)
        self.assertEqual(called, set(names) - {"security_gate.yml"})

    def test_registry_login_defaults_to_false(self):
        text = read("trivy-image.yml")
        block = text[text.index("registry-login:"):]
        block = block[:block.index("type:")]
        self.assertRegex(block, r"default:\s*false\b")
        self.assertRegex(block, r"required:\s*false\b")

    def test_gate_image_is_pinned_by_digest(self):
        gate = read("security_gate.yml")
        self.assertRegex(gate, r"digest:\s*sha256:[0-9a-f]{64}\s*\n")
        self.assertNotIn("aquasec/trivy", gate.replace("trivy.Dockerfile", ""))


if __name__ == "__main__":
    unittest.main()
