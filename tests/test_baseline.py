"""Pin the organization security baseline: the catalogue, the consumer templates and their rules."""
import glob
import os
import re
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
TEMPLATES = os.path.join(ROOT, "baseline", "templates")
TEMPLATE_FILES = ("security_gate.yml", "dependabot.yml", "SECURITY.md", "CODEOWNERS")
CATALOGUE = os.path.join(ROOT, "docs", "ORG_BASELINE.md")


def read_path(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as handle:
        return handle.read()


def template(name):
    with open(os.path.join(TEMPLATES, name), encoding="utf-8") as handle:
        return handle.read()


def active(text):
    """The lines of a YAML or CODEOWNERS file that are not blank and not full-line comments."""
    return [line for line in text.split("\n") if line.strip() and not line.lstrip().startswith("#")]


def active_text(name):
    return "\n".join(active(template(name)))


# The reusable workflows of this repository, pinned by a full 40-hex SHA and a release comment.
GATE_WORKFLOWS = ("semgrep", "trivy", "gitleaks")
GATE_USES = re.compile(
    r"^\s*uses:\s*strangebasisdevs/strange_security/\.github/workflows/(?P<name>[a-z]+)\.yml"
    r"@(?P<sha>[0-9a-f]{40}) # v\d+\.\d+\.\d+\s*$"
)
PINNED_REF = re.compile(r"^\S+@[0-9a-f]{40}$")


def uses_lines(text):
    return [line for line in active(text) if re.match(r"^\s*(?:-\s+)?[\"']?uses[\"']?\s*:", line)]


def mutable_references(text):
    """Active `uses:` lines whose reference is not pinned by a full 40-hex commit SHA (branch, tag, short SHA, none)."""
    found = []
    for line in uses_lines(text):
        ref = re.sub(r"^\s*(?:-\s+)?[\"']?uses[\"']?\s*:\s*", "", line).split()[0:1]
        if not ref or not PINNED_REF.match(ref[0]):
            found.append(line.strip())
    return found


# Repositories of the organization that the public catalogue and templates must never name.
PRIVATE_NAMES = (
    "strange_ringtone", "strangeservers", "strange_practice", "strange_archive", "strange_workbench",
    "strange_spectra", "GUDEsktop", "chaos_coordinator", "chaos-coordinator", "PeakVacationPlanner",
    "time_decomposes", "strange_elements", "strange_waves", "strange_governance",
)
# Whole tokens only. "strangebasis" is a repository name only when it is not part of
# "strangebasisdevs" (the organization) or the handle "@strangebasis".
NAME_PATTERN = re.compile(
    r"(?<![\w@-])(?:%s|strangebasis)(?![\w-])" % "|".join(re.escape(name) for name in PRIVATE_NAMES)
)
RULESET_ID = re.compile(r"(?<![0-9A-Za-z])[0-9]{8}(?![0-9A-Za-z])")


def private_findings(text):
    return NAME_PATTERN.findall(text) + RULESET_ID.findall(text)


def public_files():
    return [CATALOGUE] + [os.path.join(TEMPLATES, name) for name in TEMPLATE_FILES]


class GateTemplate(unittest.TestCase):
    def test_gate_calls_the_three_workflows_pinned_by_full_sha(self):
        lines = uses_lines(template("security_gate.yml"))
        self.assertEqual(len(lines), 3, "the gate template must hold exactly three uses: lines: %r" % lines)
        names, shas = [], set()
        for line in lines:
            match = GATE_USES.match(line)
            self.assertIsNotNone(
                match, "not strangebasisdevs/strange_security/.github/workflows/<file>.yml@<40 hex> # vX.Y.Z: " + line.strip())
            names.append(match.group("name"))
            shas.add(match.group("sha"))
        self.assertEqual(sorted(names), sorted(GATE_WORKFLOWS), "the gate must call semgrep, trivy and gitleaks once each")
        self.assertEqual(len(shas), 1, "the three calls must be pinned to the same SHA, found %s" % sorted(shas))

    def test_gate_has_no_mutable_reference(self):
        self.assertEqual(mutable_references(template("security_gate.yml")), [])
        for name in TEMPLATE_FILES:
            with self.subTest(template=name):
                self.assertEqual(mutable_references(template(name)), [])

    def test_mutable_reference_detector_notices_mutable_references(self):
        base = "    uses: strangebasisdevs/strange_security/.github/workflows/trivy.yml"
        for ref in ("@main", "@v1", "@v1.2.1", "@3d3c42e", "@" + "g" * 40, "@" + "a" * 41, "@" + "A" * 40, ""):
            with self.subTest(ref=ref):
                self.assertTrue(mutable_references(base + ref + " # v1.2.1"), ref)
        self.assertTrue(mutable_references("      - uses: actions/checkout@main"))
        self.assertEqual(mutable_references(base + "@" + "a" * 40 + " # v1.2.1"), [])
        # Prose in a comment is not a reference.
        self.assertEqual(mutable_references("# uses: x/y/z.yml@main\n"), [])
        # The strict line pattern rejects the same forms.
        for ref in ("@main", "@v1", "@3d3c42e", "@" + "a" * 41):
            with self.subTest(strict=ref):
                self.assertIsNone(GATE_USES.match(base + ref + " # v1.2.1"))
        self.assertIsNone(GATE_USES.match(base + "@" + "a" * 40))
        self.assertIsNone(GATE_USES.match(base + "@" + "a" * 40 + " # v1"))
        self.assertIsNotNone(GATE_USES.match(base + "@" + "a" * 40 + " # v1.2.1"))

    def test_gate_names_and_triggers(self):
        text = template("security_gate.yml")
        self.assertRegex(text, r"(?m)^name: Security gate$")
        for key, name in (("semgrep", "Semgrep"), ("trivy", "Trivy"), ("gitleaks", "Gitleaks")):
            self.assertRegex(text, r"(?m)^  %s:\n    name: %s\n    uses: " % (key, name),
                             "the %s job must be named %s: the required check names derive from it" % (key, name))
        on = re.search(r"(?m)^on:\n((?:[ ]+.*\n)+)", text)
        self.assertIsNotNone(on, "the gate template has no on: block")
        self.assertEqual(
            [line.rstrip() for line in on.group(1).split("\n") if line.strip()],
            ["  pull_request:", "  push:", "    branches:", "      - main"],
            "the gate must trigger on pull_request and on push to main only")

    def test_gate_permissions_are_exactly_the_cap(self):
        text = template("security_gate.yml")
        block = re.search(r"(?m)^permissions:\n((?:[ ]+\S.*\n)+)", text)
        self.assertIsNotNone(block, "the gate template has no top-level permissions block")
        self.assertEqual(
            [line.strip() for line in block.group(1).split("\n") if line.strip()],
            ["actions: read", "contents: read", "security-events: write"],
        )
        self.assertEqual(len(re.findall(r"(?m)^\s*permissions\s*:", text)), 1,
                         "permissions must be declared once, at the top level")

    def test_gate_header_documents_what_to_change(self):
        header = template("security_gate.yml").split("name: Security gate")[0]
        self.assertTrue(header.startswith("#"), "the template must start with a header comment")
        for needle in ("gh api repos/strangebasisdevs/strange_security/git/ref/tags/", "upload-sarif: false",
                       ".github/workflows/security_gate.yml", "Semgrep / Semgrep scan",
                       "Trivy / Trivy filesystem scan", "Gitleaks / Gitleaks history scan"):
            self.assertIn(needle, header)

    def test_no_dangerous_trigger_in_any_template(self):
        for name in TEMPLATE_FILES:
            text = template(name)
            for trigger in ("pull_request_target", "workflow_run"):
                with self.subTest(template=name, trigger=trigger):
                    self.assertNotIn(trigger, text, "%s must not appear in %s" % (trigger, name))


class DependabotTemplate(unittest.TestCase):
    def test_active_lines_carry_the_schedule_cooldown_and_limit(self):
        text = active_text("dependabot.yml")
        self.assertRegex(text, r"(?m)^version: 2$")
        self.assertRegex(text, r"(?m)^  - package-ecosystem: github-actions$")
        self.assertRegex(text, r"(?m)^    directory: /$")
        self.assertRegex(text, r"(?m)^    schedule:\n      interval: weekly\n      day: monday\n"
                               r"      time: \"09:00\"\n      timezone: Etc/UTC$")
        self.assertRegex(text, r"(?m)^    open-pull-requests-limit: 10$")
        self.assertRegex(text, r"(?m)^    cooldown:\n      default-days: 7$")
        self.assertRegex(text, r"(?m)^    labels:\n      - dependencies\n      - github-actions$")

    def test_every_active_entry_has_a_cooldown_and_the_same_schedule(self):
        text = active_text("dependabot.yml")
        entries = re.split(r"(?m)^  - package-ecosystem: ", text)[1:]
        self.assertGreaterEqual(len(entries), 1)
        for entry in entries:
            with self.subTest(entry=entry.split("\n")[0]):
                self.assertIn("default-days: 7", entry)
                self.assertIn("interval: weekly", entry)
                self.assertIn("open-pull-requests-limit: 10", entry)

    def test_the_second_ecosystem_example_stays_commented_out(self):
        text = template("dependabot.yml")
        self.assertIn("# - package-ecosystem: pip", text)
        self.assertEqual(len(re.findall(r"(?m)^  - package-ecosystem: ", text)), 1)

    def test_header_tells_the_consumer_what_to_change(self):
        header = template("dependabot.yml").split("version: 2")[0]
        for needle in ("package ecosystem", "cooldown", "exception"):
            self.assertIn(needle, header)


class PolicyTemplates(unittest.TestCase):
    def test_codeowners_default_rule_comes_first(self):
        self.assertEqual(active(template("CODEOWNERS"))[0], "* @strangebasis")
        self.assertTrue(template("CODEOWNERS").startswith("#"), "CODEOWNERS template needs a header comment")

    def test_security_template_header_and_content(self):
        text = template("SECURITY.md")
        self.assertTrue(text.startswith("<!--"), "SECURITY.md template needs an HTML comment header")
        header = text[:text.index("-->")]
        self.assertIn("strangebasisdevs/.github", header)
        self.assertIn("Private", header)
        for needle in ("Supported versions", "Report a vulnerability", "Scope"):
            self.assertIn(needle, text)

    def test_every_template_starts_with_a_header_comment(self):
        for name in TEMPLATE_FILES:
            with self.subTest(template=name):
                self.assertRegex(template(name), r"\A(#|<!--)")


class PublicContent(unittest.TestCase):
    def test_no_repository_name_or_ruleset_id_in_public_files(self):
        for path in public_files():
            with self.subTest(file=os.path.relpath(path, ROOT)):
                with open(path, encoding="utf-8") as handle:
                    self.assertEqual(private_findings(handle.read()), [],
                                     "names a private repository or carries a ruleset id")

    def test_name_detector(self):
        for bad in PRIVATE_NAMES + ("strangebasis",):
            for text in (bad, "see " + bad + ".", "strangebasisdevs/" + bad, "(%s)" % bad, "`%s`" % bad):
                with self.subTest(text=text):
                    self.assertTrue(NAME_PATTERN.search(text), text)
        for good in ("strangebasisdevs", "strangebasisdevs/strange_security", "strangebasisdevs/.github",
                     "* @strangebasis", "@strangebasis", "strange_security", "strange_archived", "my_strange_archive",
                     "strange_archive-extra", "xstrangebasis"):
            with self.subTest(text=good):
                self.assertIsNone(NAME_PATTERN.search(good), good)

    def test_ruleset_id_detector(self):
        for bad in ("ruleset 12345678", "id=12345678.", "(87654321)", "12345678"):
            with self.subTest(text=bad):
                self.assertTrue(RULESET_ID.search(bad), bad)
        for good in ("1234567", "123456789", "2026-11-01", "b3a6732ecbe1796fb2e7eaeedb228c705962db44",
                     "a" * 8 + "12345678"):
            with self.subTest(text=good):
                self.assertIsNone(RULESET_ID.search(good), good)

    def test_catalogue_has_the_required_structure(self):
        text = read_path("docs", "ORG_BASELINE.md")
        controls = re.split(r"(?m)^### ", text.split("\n## Controls\n")[1].split("\n## Consumer files")[0])[1:]
        self.assertGreaterEqual(len(controls), 20)
        fields = ("Control ID", "Statement", "Rationale", "GitHub implementation", "Portable equivalent", "Verification")
        ids = []
        for control in controls:
            title = control.split("\n")[0]
            with self.subTest(control=title):
                positions = [control.find("- **%s:**" % field) for field in fields]
                self.assertNotIn(-1, positions, "missing field in " + title)
                self.assertEqual(positions, sorted(positions), "fields out of order in " + title)
                for field in fields:
                    self.assertEqual(control.count("- **%s:**" % field), 1, field)
                ids.append(re.search(r"- \*\*Control ID:\*\* (\S+)", control).group(1))
        self.assertEqual(len(ids), len(set(ids)), "duplicate control ID")
        for expected in ("Branch-Protection", "Code-Review", "Pinned-Dependencies", "Token-Permissions",
                         "Dangerous-Workflow", "Dependency-Update-Tool", "Vulnerabilities", "SAST", "Security-Policy"):
            self.assertIn(expected, ids)
        for number in range(1, 12):
            self.assertIn("ORG-%02d" % number, ids)

    def test_catalogue_ends_with_the_consumer_files_section(self):
        text = read_path("docs", "ORG_BASELINE.md")
        self.assertIn("\n## Consumer files\n", text)
        self.assertTrue(text.rstrip().endswith(
            "Changes to this document go through a pull request reviewed like any other\nsecurity change."))
        self.assertIn("baseline/templates/", text.split("\n## Consumer files\n")[1])

    def test_catalogue_names_and_finds_each_template(self):
        text = read_path("docs", "ORG_BASELINE.md")
        for name in TEMPLATE_FILES:
            with self.subTest(template=name):
                self.assertIn("baseline/templates/" + name, text)
                self.assertTrue(os.path.isfile(os.path.join(TEMPLATES, name)), name + " is missing")

    def test_repository_files_point_at_the_baseline(self):
        self.assertIn("* @strangebasis", read_path(".github", "CODEOWNERS").split("\n"))
        self.assertFalse(os.path.exists(os.path.join(ROOT, "CODEOWNERS")), "use .github/CODEOWNERS, not a root file")
        self.assertIn("(docs/ORG_BASELINE.md)", read_path("README.md"))
        self.assertIn("(baseline/templates/)", read_path("README.md"))
        self.assertIn("Report a vulnerability", read_path("SECURITY.md"))


class OutsideTheWorkflowDirectory(unittest.TestCase):
    def test_nothing_under_baseline_is_under_dot_github(self):
        found = []
        for dirpath, dirnames, filenames in os.walk(os.path.join(ROOT, "baseline")):
            relative = os.path.relpath(dirpath, ROOT).replace(os.sep, "/")
            if ".github" in relative.split("/"):
                found.append(relative)
            found.extend(os.path.join(relative, n) for n in dirnames + filenames if n == ".github")
        self.assertEqual(found, [], "baseline/ must stay outside .github/")
        self.assertTrue(os.path.isdir(TEMPLATES))

    def test_workflow_glob_does_not_reach_the_templates(self):
        workflows = os.path.join(ROOT, ".github", "workflows")
        reached = {os.path.realpath(path) for path in glob.glob(os.path.join(workflows, "*.yml"))}
        for name in TEMPLATE_FILES:
            self.assertNotIn(os.path.realpath(os.path.join(TEMPLATES, name)), reached, name)
        self.assertNotIn("security_gate.yml", [os.path.basename(p) for p in glob.glob(os.path.join(TEMPLATES, "*"))
                                              if os.path.dirname(p) == workflows])

    def test_contract_job_and_workflow_tests_only_read_dot_github_workflows(self):
        gate = read_path(".github", "workflows", "security_gate.yml")
        self.assertIn("for file in .github/workflows/*.yml; do", gate,
                      "the contract job must keep iterating .github/workflows/*.yml only")
        self.assertEqual(len(re.findall(r"(?m)^\s*for file in ", gate)), 1)
        tests = read_path("tests", "test_workflows.py")
        self.assertIn('WORKFLOWS = os.path.join(HERE, "..", ".github", "workflows")', tests)
        self.assertEqual(len(re.findall(r"glob\.glob\(", tests)), len(re.findall(r"glob\.glob\(os\.path\.join\(WORKFLOWS, ", tests)),
                         "every glob in test_workflows.py must be rooted at WORKFLOWS")
        self.assertNotIn("baseline", tests)


if __name__ == "__main__":
    unittest.main()
