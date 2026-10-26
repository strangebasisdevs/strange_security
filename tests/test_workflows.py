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


def reusable():
    return sorted(
        os.path.basename(p)
        for p in glob.glob(os.path.join(WORKFLOWS, "*.yml"))
        if re.search(r"^on:\s*\n(?:[ \t]+.*\n|\n)*?[ \t]+workflow_call:", read(os.path.basename(p)), re.M)
    )


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
