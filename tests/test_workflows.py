"""Pin structural promises of the workflow files so they cannot drift silently."""
import glob
import os
import re
import shutil
import subprocess
import tempfile
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
    """Apply the pattern the way grep -E does: to one line at a time."""
    pattern = re.compile(gate_pattern())
    return any(pattern.search(line) for line in text.split("\n"))


def find_grep():
    found = shutil.which("grep")
    if found:
        return found
    for candidate in ("C:/Program Files/Git/usr/bin/grep.exe", "C:/Program Files (x86)/Git/usr/bin/grep.exe"):
        if os.path.exists(candidate):
            return candidate
    return None


def grep_reusable(text):
    """Run the real 'grep -qE <pattern from security_gate.yml>' on text."""
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "workflow.yml")
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
        return subprocess.run([find_grep(), "-qE", gate_pattern(), path], check=False).returncode == 0


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
        self.assertIn('mkdir -p "$RUNNER_TEMP/semgrep"', run)
        self.assertIn('--volume "$RUNNER_TEMP/semgrep:/out"', run)
        self.assertNotIn('--volume "$RUNNER_TEMP:/out"', run)
        self.assertIn('--volume "$PWD:/src:ro"', run)
        self.assertIn("--output /out/semgrep.sarif", run)
        self.assertNotRegex(run, r"--output\s+/src")
        upload = step(text, "Upload SARIF results")
        self.assertIn("sarif_file: ${{ runner.temp }}/semgrep/semgrep.sarif", upload)
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
            "double-quoted key": "\"on\": workflow_call\n",
            "single-quoted key": "'on': [workflow_call]\n",
            "quoted key block": "\"on\":\n  workflow_call:\n",
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
            "other key ending in on": "iron: workflow_call\n",
            "quoted comment": "# 'on': workflow_call\n",
        }.items():
            with self.subTest(form=label):
                self.assertFalse(is_reusable(text))

    def test_gate_pattern_is_matched_per_line(self):
        # [^#]* must not run across a newline: a comment on one line followed
        # by workflow_call on the next is not the inline form.
        self.assertFalse(is_reusable("on: push # x\nname: workflow_call\n"))
        self.assertFalse(is_reusable("on:\n  push:\nname: a workflow_call b\n"))

    @unittest.skipUnless(find_grep(), "grep is not available")
    def test_real_grep_agrees_with_the_emulation(self):
        texts = {
            "block": "on:\n  workflow_call:\n",
            "inline": "on: workflow_call\n",
            "list": "on: [push, workflow_call]\n",
            "quoted": "'on': [workflow_call]\n",
            "quoted double": "\"on\": workflow_call\n",
            "push": "on:\n  push:\n",
            "comment": "# on: workflow_call\non: push\n",
            "similar": "on: [my_workflow_call]\n",
            "newline spill": "on: push # x\nname: workflow_call\n",
        }
        for name in sorted(glob.glob(os.path.join(WORKFLOWS, "*.yml"))):
            texts[os.path.basename(name)] = read(os.path.basename(name))
        for label, text in texts.items():
            with self.subTest(text=label):
                self.assertEqual(grep_reusable(text), is_reusable(text))
        self.assertTrue(grep_reusable(texts["block"]))
        self.assertTrue(grep_reusable(texts["semgrep.yml"]))
        self.assertFalse(grep_reusable(texts["security_gate.yml"]))

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
