"""Pin the organization security baseline: the catalogue, the consumer templates and their rules."""
import glob
import hashlib
import os
import re
import unicodedata
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
TEMPLATES = os.path.join(ROOT, "baseline", "templates")
TEMPLATE_FILES = ("security_gate.yml", "dependabot.yml", "SECURITY.md", "CODEOWNERS")
CATALOGUE = os.path.join(ROOT, "docs", "ORG_BASELINE.md")


def read_file(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def read_path(*parts):
    return read_file(os.path.join(ROOT, *parts))


def template(name):
    return read_file(os.path.join(TEMPLATES, name))


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


# The public catalogue and templates name the organization, this repository and @-mentions of the
# code owner handle, and no other repository of the organization. Two detectors enforce it without
# listing a single name here. (1) Anything that starts with "strange" other than the organization
# and this repository is a finding: it catches misspellings and repositories created later.
# (2) PRIVATE_NAME_DIGESTS holds the salted SHA-256 digest of every other organization repository
# name (15 digests, computed over NAME_SALT + ":" + the lower-cased name), so names that do not
# start with "strange" are caught too. A digest cannot be turned back into a name without guessing
# it. The private audit, which reads the real inventory, remains the complete check. Matching is
# case-insensitive and sees through Markdown escapes, width variants and zero-width characters.
ALLOWED_TOKENS = ("strangebasisdevs", "strange_security")
ALLOWED_HANDLES = ("strangebasis",)
NAME_SALT = "strangebasisdevs-org-baseline-2026-11-01"
PRIVATE_NAME_DIGESTS = (
    "ddd55e597ead4833f2471b4e23472021ad292bc1698768655532acfd548c46e7",
    "a021b3d94806c8597530fe094544185f66a97ebbdbcefdab27541c5a97b747d4",
    "2f8ff6412010ceb15ca5fa2e66afaaddfa374024cebfcef9a22e6ce5b42989d7",
    "6092608a66c4e305356d308d555d3d36d343c59b5214e606f284d619d4847fb2",
    "462eef925b5766ac480ff8e721dec4bc5fc928b5c9f4aa43348274418d631d04",
    "872d4e387724f27b47dcc5ba5ba4b1d9521c1292669eb60cd00cb8aebc8891de",
    "53528c40a7bcb70bf90a61c701867e50bae305397649538071d300bac274f5be",
    "d76e61c22a746a9538bd843265b5c7802297a79e8622d4da115fff73a8d03999",
    "e0e7eebd1f4524ea587df07af7ce093fe1ee065a0b92f5c598eefa1f7849ae9c",
    "b2ac980de93c00d116585505559746763746896951f5b6141fe14828c77100c9",
    "7a8f86d220c5a1dde88ffd56c30a9c6ed085e66bafd0940ca57175401031594c",
    "79425cfdd85a6693cfa0fc3e64b863c1ed7759bda43777bcce2025a297080edb",
    "39e6f5f274a9c38cf0ee1d95a17b86cbb297a1c9e8e589c19c43442a308f4065",
    "43810f1f35d7a270d9980be186e9a8ada4906203c5bdae4d17f4f061dcf540dc",
    "9c0cb6f786a5f5dbd6c0e5418ac631803456b24f9d92ec9e8cade9e54cb06dc9",
)
NAME_PATTERN = re.compile(r"(?<![\w@-])strange[\w-]*")
TOKEN_PATTERN = re.compile(r"[a-z0-9_-]+")
ZERO_WIDTH = re.compile("[\u00ad\u200b-\u200f\u2060\ufeff]")
RULESET_ID = re.compile(r"(?<![0-9A-Za-z])[0-9]{8}(?![0-9A-Za-z])")


def normalise(text):
    """Fold what hides a name from a plain search: width and case variants, Markdown escapes, zero-width characters."""
    text = ZERO_WIDTH.sub("", unicodedata.normalize("NFKC", text))
    return text.replace("\\", "").lower()


def name_digest(name):
    return hashlib.sha256((NAME_SALT + ":" + name.lower()).encode("utf-8")).hexdigest()


def digest_tokens(line, digests):
    """Tokens of a normalised line whose salted digest is in `digests`.

    A token is a maximal run of [a-z0-9_-]; every other character, "/" included, separates tokens. A token is also
    tried without leading and trailing "-" and "_". The handle written as @<handle> is the code owner, not a name.
    """
    found = []
    for match in TOKEN_PATTERN.finditer(line):
        token = match.group(0)
        if token in ALLOWED_HANDLES and line[:match.start()].endswith("@"):
            continue
        for candidate in {token, token.strip("-_")}:
            if candidate and name_digest(candidate) in digests:
                found.append(token)
                break
    return found


def private_findings(text, digests=None):
    """Findings as "line N: token" for tokens that start with "strange" and are not allowed, tokens whose salted digest
    is a private repository name, and 8-digit ids (ruleset ids)."""
    digests = PRIVATE_NAME_DIGESTS if digests is None else digests
    found = []
    for number, line in enumerate(text.split("\n"), 1):
        line = normalise(line)
        tokens = [token for token in NAME_PATTERN.findall(line) if token not in ALLOWED_TOKENS]
        for token in digest_tokens(line, digests) + RULESET_ID.findall(line):
            if token not in tokens:
                tokens.append(token)
        found.extend("line %d: %s" % (number, token) for token in tokens)
    return found


def template_paths():
    """Every file under baseline/templates/, hidden files included."""
    found = glob.glob(os.path.join(TEMPLATES, "**", "*"), recursive=True)
    found += glob.glob(os.path.join(TEMPLATES, "**", ".*"), recursive=True)
    return sorted({path for path in found if os.path.isfile(path)})


def public_files():
    return [CATALOGUE] + template_paths()


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
        for path in template_paths():
            with self.subTest(template=os.path.relpath(path, ROOT)):
                self.assertEqual(mutable_references(read_file(path)), [])

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
            self.assertRegex(
                text,
                r"(?m)^  %s:\n    name: %s\n    uses: strangebasisdevs/strange_security/\.github/workflows/%s\.yml@"
                % (key, name, key),
                "the %s job must be named %s and call %s.yml: the required check names derive from both" % (key, name, key))
        on = re.search(r"(?m)^on:\n((?:[ ]+.*\n)+)", text)
        self.assertIsNotNone(on, "the gate template has no on: block")
        self.assertEqual(
            [line.rstrip() for line in on.group(1).split("\n") if line.strip()],
            ["  pull_request:", "  push:", "    branches:", "      - main"],
            "the gate must trigger on pull_request and on push to main only")

    def test_gate_jobs_are_exactly_the_three_block_style_calls(self):
        text = template("security_gate.yml")
        for line in active(text):
            for flow in ("{", "["):
                self.assertNotIn(flow, line, "flow-style YAML hides jobs from the line checks: " + line.strip())
        jobs = active(text.split("\njobs:\n", 1)[1])
        for line in jobs:
            self.assertTrue(
                re.match(r"  (?:semgrep|trivy|gitleaks):$", line) or re.match(r"    name: (?:Semgrep|Trivy|Gitleaks)$", line)
                or GATE_USES.match(line),
                "only the three jobs with a name and a uses line are allowed, found: " + line.strip())
        self.assertEqual(len(jobs), 9, "three jobs of three lines each, found %d lines" % len(jobs))

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
                       ".github/workflows/security_gate.yml", "default branch", "Semgrep / Semgrep scan",
                       "Trivy / Trivy filesystem scan", "Gitleaks / Gitleaks history scan"):
            self.assertIn(needle, header)

    def test_no_dangerous_trigger_in_any_template(self):
        for path in template_paths():
            text = read_file(path)
            for trigger in ("pull_request_target", "workflow_run"):
                with self.subTest(template=os.path.relpath(path, ROOT), trigger=trigger):
                    self.assertNotIn(trigger, text, "%s must not appear in %s" % (trigger, path))

    def test_the_templates_directory_holds_exactly_the_four_files(self):
        found = sorted(os.path.relpath(path, TEMPLATES).replace(os.sep, "/") for path in template_paths())
        self.assertEqual(found, sorted(TEMPLATE_FILES),
                         "a new template must be added on purpose: update TEMPLATE_FILES and the catalogue together")


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
        lines = active(template("CODEOWNERS"))
        self.assertTrue(lines and lines[0] == "* @strangebasis",
                        "the CODEOWNERS template must start with '* @strangebasis', found %r" % lines[:1])
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
                self.assertEqual(private_findings(read_file(path)), [],
                                 "%s names a private repository or carries a ruleset id" % os.path.relpath(path, ROOT))

    def test_the_digest_list_is_well_formed(self):
        self.assertEqual(len(PRIVATE_NAME_DIGESTS), 15)
        self.assertEqual(len(set(PRIVATE_NAME_DIGESTS)), 15, "duplicate digest")
        for digest in PRIVATE_NAME_DIGESTS:
            self.assertRegex(digest, r"\A[0-9a-f]{64}\Z")

    def test_digest_detector_catches_a_name_known_only_by_its_digest(self):
        # A made-up name stands in for a real one. Its digest is computed here and added to a copy of the tuple
        # under test, so no real name is written anywhere in this file.
        digests = PRIVATE_NAME_DIGESTS + (name_digest("example_private_repo"),)
        for text in ("Example\\_Private\\_Repo", "example_private_repo", "EXAMPLE_PRIVATE_REPO.", "see `Example_Private_Repo`",
                     "strangebasisdevs/example_private_repo", "[example_private_repo](x)", "x/example_private_repo/y",
                     "example\u200b_private_repo", "\uff45xample_private_repo", "-example_private_repo-"):
            with self.subTest(text=text):
                self.assertEqual(private_findings("first line\n" + text, digests)[0][:8], "line 2: ", text)
                self.assertNotEqual(private_findings(text, digests), [], text)
                self.assertEqual(private_findings(text), [], "the shipped digest list must not know the made-up name")
        finding = private_findings("a\nb\nsee Example\\_Private\\_Repo here", digests)
        self.assertEqual(finding, ["line 3: example_private_repo"])
        for text in ("example_private", "example_private_repository", "my_example_private_repo", "example private repo",
                     "example_private_repo_x"):
            with self.subTest(text=text):
                self.assertEqual(private_findings(text, digests), [], text)

    def test_name_detector(self):
        # Fictitious names stand in for real ones: the prefix detector keys on "strange", not on a list.
        for bad in ("strange_example", "strangeexample", "strange-example", "strangebasis", "Strange_Example",
                    "STRANGEEXAMPLE", "strange\\_example", "strange\\-example", "strange\u200b_example",
                    "\uff53trange_example"):
            for text in ("%s", "see %s.", "strangebasisdevs/%s", "(%s)", "`%s`", "[%s](x)"):
                with self.subTest(text=text % bad):
                    self.assertNotEqual(private_findings(text % bad), [], text % bad)
        for good in ("strangebasisdevs", "StrangeBasisDevs", "strangebasisdevs/strange_security",
                     "strangebasisdevs/.github", "* @strangebasis", "@strangebasis", "strange_security",
                     "my_strange_example", "xstrangebasis", "unstrange"):
            with self.subTest(text=good):
                self.assertEqual(private_findings(good), [], good)

    def test_ruleset_id_detector(self):
        for bad in ("ruleset 12345678", "id=12345678.", "(87654321)", "12345678"):
            with self.subTest(text=bad):
                self.assertTrue(RULESET_ID.search(bad), bad)
        for good in ("1234567", "123456789", "2026-11-01", "b3a6732ecbe1796fb2e7eaeedb228c705962db44",
                     "a" * 8 + "12345678"):
            with self.subTest(text=good):
                self.assertIsNone(RULESET_ID.search(good), good)

    def test_catalogue_has_the_required_structure(self):
        text = read_file(CATALOGUE)
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
        text = read_file(CATALOGUE)
        self.assertIn("\n## Consumer files\n", text)
        self.assertTrue(text.rstrip().endswith(
            "Changes to this document go through a pull request reviewed like any other\nsecurity change."),
            "ORG_BASELINE.md must end with 'Changes to this document go through a pull request reviewed like any "
            "other security change.'")
        self.assertIn("baseline/templates/", text.split("\n## Consumer files\n")[1])

    def test_catalogue_names_and_finds_each_template(self):
        text = read_file(CATALOGUE)
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
        for path in template_paths():
            self.assertNotIn(os.path.realpath(path), reached, path)
        self.assertFalse((os.path.realpath(TEMPLATES) + os.sep).startswith(os.path.realpath(workflows) + os.sep),
                         "the templates directory must not sit under .github/workflows")

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
