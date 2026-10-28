"""Inputs shared by every reusable workflow: upload-sarif, timeout-minutes, and
the registry login of trivy-image.yml. The timeout step is extracted from each
workflow and run under bash, so the tests cannot drift from what CI executes."""
import os
import re
import subprocess
import tempfile
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


# A permissions key in any spelling: bare, "double" or 'single' quoted, with
# spaces or tabs before the colon. Group 1 is the indent. Quotes are matched
# loosely on purpose, so a mismatched pair still counts and fails closed.
_KEY = r"^([ \t]*)[\"']?permissions[\"']?[ \t]*:"
_ID = r"[A-Za-z-]+"
_TOKEN = r"(?:\"%s\"|'%s'|%s)" % (_ID, _ID, _ID)
_ENTRY = re.compile(r"^(%s)[ \t]*:[ \t]+(%s)$" % (_TOKEN, _TOKEN))


def _unquote(token):
    return token[1:-1] if token[:1] in "\"'" else token


def parse_permissions(text):
    """Every permissions block of a workflow as (entries, errors).

    A block is all lines indented deeper than its permissions: key, up to the
    next line at the same or lower indent; only blank and full-line comment
    lines are skipped. Entries are (scope, level) with quotes and trailing
    comments removed. Anything that does not parse as key: value, and any
    inline (flow-style or scalar) value, is an error."""
    lines = text.replace("\r", "").split("\n")
    entries, errors = [], []
    for i, line in enumerate(lines):
        match = re.match(_KEY + r"(.*)$", line)
        if not match:
            continue
        indent = len(match.group(1))
        inline = re.sub(r"^#.*|[ \t]+#.*$", "", match.group(2).strip()).strip()
        if inline:
            errors.append("inline permissions: " + inline)
            continue
        for raw in lines[i + 1:]:
            if not raw.strip() or raw.lstrip().startswith("#"):
                continue
            if len(raw) - len(raw.lstrip()) <= indent:
                break
            entry = re.sub(r"[ \t]+#.*$", "", raw.strip()).strip()
            parsed = _ENTRY.match(entry)
            if parsed:
                entries.append((_unquote(parsed.group(1)), _unquote(parsed.group(2))))
            else:
                errors.append("unparsable entry: " + entry)
    return entries, errors


def declared_permissions(text):
    """The permissions block as {scope: level}; empty when there is none."""
    return dict(parse_permissions(text)[0])


def permission_count(text):
    return len(re.findall(_KEY, text, re.M))


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
    entries, errors = parse_permissions(text)
    problems.extend(errors)
    keys = [key for key, _ in entries]
    problems.extend("duplicate key: " + key for key in sorted({k for k in keys if keys.count(k) > 1}))
    if dict(entries) != expected_cap(text):
        problems.append("cap differs from the expected one")
    return problems


FULL_CAP = "permissions:\n  actions: read\n  contents: read\n  security-events: write\n\njobs:\n  a:\n    uses: x\n"


def _in_job(extra):
    return FULL_CAP.replace("    uses: x\n", "    " + extra + "\n    uses: x\n")


def _with_extra(extra):
    return FULL_CAP.replace("\n\njobs", "\n" + extra + "\n\njobs")


# Each of these must be rejected by the python helper and by the gate shell.
MUTATIONS = {
    "quoted packages": _with_extra('  "packages": read'),
    "quoted id-token": _with_extra("  'id-token': write"),
    "extra scope after a blank line": FULL_CAP.replace("\n\njobs", "\n\n  issues: write\n\njobs"),
    "extra scope after a comment line": _with_extra("  # note\n  issues: write"),
    "flow style": "permissions: { actions: read, contents: read, security-events: write }\n\njobs:\n  a:\n    uses: x\n",
    "write-all": "permissions: write-all\n\njobs:\n  a:\n    uses: x\n",
    "read-all": "permissions: read-all # all\n\njobs:\n  a:\n    uses: x\n",
    "duplicate key": _with_extra("  contents: read"),
    "unparsable line": _with_extra("  issues write"),
    "job-level double-quoted key": _in_job('"permissions": write-all'),
    "job-level single-quoted key": _in_job("'permissions': write-all"),
    "job-level key with space before colon": _in_job("permissions : write-all"),
    "job-level key with tab before colon": _in_job("permissions\t: write-all"),
    "second column-0 quoted key": _with_extra('"permissions":\n  issues: write'),
    "second column-0 key with space": _with_extra("permissions :\n  issues: write"),
    "quoted value": FULL_CAP.replace("contents: read", 'contents: "write"'),
}
# Valid spellings of the exact cap.
ACCEPTED = {
    "trailing comments": FULL_CAP.replace("actions: read", "actions: read # needed").replace("write\n", "write   # sarif\n"),
    "quoted keys and values": FULL_CAP.replace("actions: read", "\"actions\": 'read'").replace("contents: read", "'contents': \"read\""),
    "column-0 double-quoted key": FULL_CAP.replace("permissions:", '"permissions":', 1),
    "column-0 key with space before colon": FULL_CAP.replace("permissions:", "permissions :", 1),
    "blank and comment lines inside": FULL_CAP.replace("  contents", "\n  # c\n  contents"),
}


class Inputs(unittest.TestCase):
    def test_every_reusable_workflow_has_the_common_inputs(self):
        self.assertEqual(len(scan_workflows()), 5)
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
            **MUTATIONS,
        }
        for label, text in bad.items():
            with self.subTest(case=label):
                self.assertNotEqual(cap_problems(text + sarif), [])
        # Without a SARIF upload the cap would not include security-events.
        self.assertNotEqual(cap_problems(FULL_CAP), [])

    def test_cap_check_accepts_valid_spellings(self):
        sarif = "uses: github/codeql-action/upload-sarif@x\n"
        for label, text in ACCEPTED.items():
            with self.subTest(case=label):
                self.assertEqual(cap_problems(text + sarif), [])

    def test_gate_contract_job_requires_the_cap(self):
        gate = read("security_gate.yml")
        job = gate[gate.index("  contract:"):gate.index("  semgrep:")]
        self.assertIn("expected='actions: read,contents: read,'", job)
        self.assertIn("security-events: write,", job)
        self.assertIn("upload-sarif@", job)
        self.assertNotIn("forces callers", job)
        self.assertNotIn("declare no permissions", job)

    def gate_job(self, name):
        """One job of the security gate, from its key to the next job."""
        gate = read("security_gate.yml")
        start = gate.index("\n  %s:\n" % name)
        end = re.search(r"\n  [\w-]+:\n", gate[start + 1:])
        return gate[start:start + 1 + end.start()] if end else gate[start:]

    def test_gate_exercises_the_opt_out_inputs(self):
        gate = read("security_gate.yml")
        for name in ("trivy-image", "trivy-images"):
            job = self.gate_job(name)
            with self.subTest(job=name):
                # Comments are not configuration: only real keys of this job count.
                code = "\n".join(line for line in job.splitlines() if not line.lstrip().startswith("#"))
                self.assertRegex(code, r"(?m)^      upload-sarif:[ \t]*false[ \t]*$")
                match = re.search(r"(?m)^      timeout-minutes:[ \t]*(\d+)[ \t]*$", code)
                self.assertTrue(match)
                self.assertNotEqual(match.group(1), "30")
                self.assertNotIn("registry-login", code)
                self.assertNotIn("registry-token", code)
                # The called workflow keeps its cap, so the call grants all of it even with upload-sarif: false.
                self.assertEqual(declared_permissions(code), {"actions": "read", "contents": "read", "security-events": "write"})
                self.assertNotIn("packages", code)
        # Every other call inherits the gate's top-level grant, which must cover the cap.
        top = gate[gate.index("\npermissions:"):gate.index("\njobs:")].lstrip("\n")
        self.assertEqual(declared_permissions(top + "\n"), {"actions": "read", "contents": "read", "security-events": "write"})

    def test_gate_scans_two_public_images_pinned_by_digest(self):
        job = self.gate_job("trivy-images")
        code = "\n".join(l for l in job.splitlines() if not l.lstrip().startswith("#"))
        images = re.search(r"(?m)^      images: \|\n((?:        .*\n?)+)", code).group(1).split()
        self.assertGreaterEqual(len(images), 2)
        for ref in images:
            with self.subTest(image=ref):
                self.assertRegex(ref, r"^[a-z0-9][a-z0-9._/-]*(:[A-Za-z0-9_][A-Za-z0-9._-]{0,127})?@sha256:[0-9a-f]{64}$")
        # Both digest forms run in CI: repo@digest and repo:tag@digest.
        self.assertTrue(any(r.startswith("gcr.io/distroless/static-debian12@sha256:") for r in images))
        self.assertTrue(any(r.startswith("registry.k8s.io/pause:3.10@sha256:") for r in images))
        self.assertEqual(len({r.split("@")[0].split(":")[0] for r in images}), len(images))
        # The dated comment above the job says when the digests were resolved.
        self.assertRegex(read("security_gate.yml"), r"resolved from the registry\s+#\s+API on 20\d\d-\d\d-\d\d")

    def test_gate_opt_out_comment_does_not_satisfy_the_job_assertions(self):
        for name in ("trivy-image", "trivy-images"):
            job = self.gate_job(name)
            comments = chr(10).join(l for l in job.splitlines() if l.lstrip().startswith("#"))
            with self.subTest(job=name):
                self.assertNotRegex(comments, r"upload-sarif:\s*false")
                self.assertNotRegex(comments, r"timeout-minutes:\s*\d")

    def test_login_uses_the_registry_token_secret_and_nothing_else(self):
        for name in ("trivy-image.yml", "trivy-images.yml"):
            text = read(name)
            with self.subTest(workflow=name):
                self.assertNotIn("docker/login-action", text)
                # Comments and descriptions may name GITHUB_TOKEN; no expression may use it.
                self.assertNotRegex(text, r"secrets\.GITHUB_TOKEN")
                self.assertEqual(len(re.findall(r"github\.token", text)), 0)
                self.assertEqual(text.count("secrets.registry-token"), 1)
                login = text[text.index("- name: Log in to GitHub Container Registry"):]
                login = login[:login.index("run:")]
                self.assertIn("secrets.registry-token", login)
                self.assertIn("if: ${{ inputs.registry-login }}", login)
                self.assertRegex(input_block(text, "registry-login"), r"default:\s*false\b")
                secrets = text[text.index("    secrets:\n"):text.index("\n# Declared cap")]
                self.assertRegex(secrets, r"(?m)^      registry-token:\n")
                self.assertRegex(secrets, r"required:\s*false\b")

    def test_only_the_image_workflows_take_the_secret(self):
        for name in scan_workflows():
            with self.subTest(workflow=name):
                self.assertEqual("    secrets:\n" in read(name), name in ("trivy-image.yml", "trivy-images.yml"))


@unittest.skipUnless(BASH, "bash is required")
class GateContractShell(unittest.TestCase):
    """Run the gate's contract step itself on temp copies of a workflow dir."""

    STEP_NAME = "Check how shared workflows locate themselves"

    def run_contract(self, workflow_text):
        script = extract_run_block(os.path.join(WORKFLOWS, "security_gate.yml"), self.STEP_NAME)
        with tempfile.TemporaryDirectory() as tmp:
            flows = os.path.join(tmp, ".github", "workflows")
            os.makedirs(flows)
            with open(os.path.join(flows, "a.yml"), "w", encoding="utf-8", newline="") as handle:
                handle.write("on:\n  workflow_call:\n" + workflow_text)
            return subprocess.run([BASH, "-c", script], cwd=tmp, capture_output=True, text=True)

    def test_accepts_the_exact_cap_in_every_spelling(self):
        sarif = "uses: github/codeql-action/upload-sarif@x\n"
        for label, text in {"plain": FULL_CAP, **ACCEPTED}.items():
            with self.subTest(case=label):
                result = self.run_contract(text + sarif)
                self.assertEqual(result.returncode, 0, result.stdout)

    def test_rejects_every_entry_outside_the_cap(self):
        sarif = "uses: github/codeql-action/upload-sarif@x\n"
        for label, text in MUTATIONS.items():
            with self.subTest(case=label):
                result = self.run_contract(text + sarif)
                self.assertNotEqual(result.returncode, 0, label)
                self.assertIn("permissions", result.stdout)

    def test_rejects_a_missing_entry_and_crlf_does_not_hide_one(self):
        sarif = "uses: github/codeql-action/upload-sarif@x\n"
        self.assertNotEqual(self.run_contract(FULL_CAP.replace("  actions: read\n", "") + sarif).returncode, 0)
        self.assertEqual(self.run_contract((FULL_CAP + sarif).replace("\n", "\r\n")).returncode, 0)
        extra = _with_extra('  "packages": read') + sarif
        self.assertNotEqual(self.run_contract(extra.replace("\n", "\r\n")).returncode, 0)


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
