"""Run the real validation step of trivy-image.yml under bash.

The step's run block is extracted from the workflow file, so the tests cannot
drift from what CI executes.
"""
import os
import re
import shutil
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
WORKFLOW = os.path.join(HERE, "..", ".github", "workflows", "trivy-image.yml")
STEP_NAME = "Validate image reference"
DIGEST = "sha256:" + "0123456789abcdef" * 4
BACKTICK = chr(96)
QUOTE = chr(39)


def find_bash():
    """bash on PATH, skipping the Windows WSL launchers, which cannot run these scripts."""
    candidates = [shutil.which("bash")]
    if os.name == "nt":
        for base in (os.environ.get("ProgramFiles"), os.environ.get("ProgramW6432")):
            if base:
                candidates.insert(0, os.path.join(base, "Git", "bin", "bash.exe"))
    for path in candidates:
        if path and os.path.isfile(path) and not re.search(r"system32|windowsapps", path, re.I):
            return path
    return None


BASH = find_bash()


def extract_run_block(path, step_name):
    """Return the run script of the named step, dedented."""
    with open(path, encoding="utf-8") as handle:
        lines = handle.read().splitlines()
    start = next(
        (i for i, line in enumerate(lines) if re.match(r"\s*- name: " + re.escape(step_name) + r"\s*$", line)),
        None,
    )
    if start is None:
        raise AssertionError("step not found: " + step_name)
    run = None
    for i in range(start + 1, len(lines)):
        if re.match(r"\s*- name:", lines[i]):
            break
        if re.match(r"\s*run: \|\s*$", lines[i]):
            run = i
            break
    if run is None:
        raise AssertionError("no run block in step: " + step_name)
    indent = len(lines[run]) - len(lines[run].lstrip())
    body = []
    for line in lines[run + 1:]:
        if line.strip() and len(line) - len(line.lstrip()) <= indent:
            break
        body.append(line)
    base = min(len(l) - len(l.lstrip()) for l in body if l.strip())
    return "\n".join(l[base:] for l in body) + "\n"


@unittest.skipUnless(BASH, "bash is required")
class ValidateImageReference(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.script = extract_run_block(WORKFLOW, STEP_NAME)

    def run_step(self, image, digest):
        with tempfile.TemporaryDirectory() as tmp:
            output = os.path.join(tmp, "output")
            open(output, "w").close()
            env = dict(os.environ, IMAGE=image, DIGEST=digest, GITHUB_OUTPUT=output)
            result = subprocess.run(
                [BASH, "-c", self.script], env=env, capture_output=True, text=True
            )
            with open(output) as handle:
                written = handle.read()
        return result.returncode, written

    def accepts(self, image, digest=DIGEST):
        code, written = self.run_step(image, digest)
        self.assertEqual(code, 0, "should accept %r %r" % (image, digest))
        self.assertEqual(written, "reference=%s@%s\n" % (image, digest))

    def rejects(self, image, digest=DIGEST):
        code, written = self.run_step(image, digest)
        self.assertNotEqual(code, 0, "should reject %r %r" % (image, digest))
        self.assertEqual(written, "", "rejected input must write no output")

    def test_accepts_plain_references(self):
        for image in (
            "aquasec/trivy",
            "ghcr.io/strangebasisdevs/strange_ringtone",
            "registry.example.com:5000/team/app",
            "localhost/app",
            "a",
            "app-1.2_x",
        ):
            with self.subTest(image=image):
                self.accepts(image)

    def test_rejects_tag_or_digest_in_image(self):
        for image in ("aquasec/trivy:0.76.0", "app:latest", "aquasec/trivy@" + DIGEST):
            with self.subTest(image=image):
                self.rejects(image)

    def test_rejects_bad_image_characters(self):
        for image in ("", "-app", "/app", ".app", "App", "ghcr.io/Org/app", "app name",
                      "app;id", "app$" + "(id)", "app" + BACKTICK + "id" + BACKTICK,
                      "app|x", "app&x", "a\b", "app" + QUOTE + "x"):
            with self.subTest(image=image):
                self.rejects(image)

    def test_rejects_multiline_image(self):
        for image in (
            "app\nreference=evil@" + DIGEST,
            "app\n",
            "\napp",
            "app\r\nx",
            "aquasec/trivy\nghcr.io/x/y",
        ):
            with self.subTest(image=image):
                self.rejects(image)

    def test_accepts_valid_digest_only(self):
        self.accepts("app", "sha256:" + "f" * 64)
        self.accepts("app", "sha256:" + "0" * 64)

    def test_rejects_bad_digest(self):
        for digest in (
            "",
            "sha256:",
            "sha256:" + "0" * 63,
            "sha256:" + "0" * 65,
            "sha256:" + "A" * 64,
            "sha256:" + "g" * 64,
            "sha512:" + "0" * 64,
            "SHA256:" + "0" * 64,
            "0" * 64,
            " sha256:" + "0" * 64,
            "sha256:" + "0" * 64 + " ",
        ):
            with self.subTest(digest=digest):
                self.rejects("app", digest)

    def test_rejects_multiline_digest(self):
        for digest in (
            DIGEST + "\nreference=evil",
            DIGEST + "\n",
            "\n" + DIGEST,
            "x\n" + DIGEST,
            DIGEST + "\r\n",
        ):
            with self.subTest(digest=digest):
                self.rejects("app", digest)


class ExtractRunBlock(unittest.TestCase):
    def test_extracts_the_validation_step(self):
        script = extract_run_block(WORKFLOW, STEP_NAME)
        self.assertIn("GITHUB_OUTPUT", script)
        self.assertNotIn("Checkout repository", script)

    def test_missing_step_is_an_error(self):
        with self.assertRaises(AssertionError):
            extract_run_block(WORKFLOW, "No such step")


if __name__ == "__main__":
    unittest.main()
