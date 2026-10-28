"""The image exception engine (scripts/image_exceptions.py): the strict schema, the
digest binding, expiry and stale entries, the generate command, mutation checks that
prove these tests would notice a loosened engine, and the rule that only
trivy-images.yml may use an exceptions file. The engine inside the gate is also
tested in tests/test_trivy_images.py.
"""
import copy
import datetime
import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import types
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
SCRIPT = os.path.join(ROOT, "scripts", "image_exceptions.py")
WORKFLOWS = os.path.join(ROOT, ".github", "workflows")


def load_module(source=None):
    """The engine, from SCRIPT or from modified source text (for the mutation checks)."""
    if source is None:
        spec = importlib.util.spec_from_file_location("image_exceptions", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    module = types.ModuleType("image_exceptions_mutant")
    module.__file__ = os.path.abspath(SCRIPT)
    exec(compile(source, SCRIPT, "exec"), module.__dict__)
    return module


ie = load_module()

TODAY = datetime.date(2026, 11, 1)
DIGEST = "sha256:" + "a" * 64
OTHER = "sha256:" + "b" * 64
REF = "example/app:1.2.3@" + DIGEST


def entry(**over):
    base = {"image": "example/app", "digest": DIGEST, "id": "CVE-2026-0001", "package": "libfoo",
            "reason": "the vendor has not rebuilt the image", "reviewer": "reviewer-one",
            "reviewed": "2026-10-25", "expires": "2026-11-20"}
    base.update(over)
    return base


def finding(vid="CVE-2026-0001", package="libfoo"):
    return {"id": vid, "severity": "HIGH", "package": package, "installed": "1", "fixed": "2", "target": "t"}


def vuln(vid="CVE-2026-0001", package="libfoo", severity="HIGH", fixed="2"):
    item = {"VulnerabilityID": vid, "PkgName": package, "InstalledVersion": "1", "Severity": severity}
    if fixed is not None:
        item["FixedVersion"] = fixed
    return item


def report(vulns=(), digest=DIGEST, repo="example/app"):
    return {"SchemaVersion": 2, "ArtifactType": "container_image",
            "Metadata": {"RepoDigests": [repo + "@" + digest]},
            "Results": [{"Target": "app (debian 12)", "Vulnerabilities": list(vulns)}]}


def evaluate(entries, findings, digest=DIGEST, repo="example/app", today=TODAY):
    return ie.evaluate(entries, repo, digest, findings, today, "no digest")


class Schema(unittest.TestCase):
    def errors(self, *entries, today=TODAY):
        return ie.schema_errors(list(entries), today)

    def test_good_entries(self):
        self.assertEqual(self.errors(entry(), entry(id="GHSA-2345-jmpq-rvw2", tracking="https://example.org/x"),
                                     entry(package="@scope/pkg"), entry(package="github.com/a/b"),
                                     entry(image="localhost:5000/a/b", reviewer="Jane Doe")), [])

    def test_rejections(self):
        missing_digest = entry()
        del missing_digest["digest"]
        bad = {
            "wildcard id": entry(id="CVE-2026-*"),
            "wildcard image": entry(image="example/*"),
            "wildcard package": entry(package="lib*"),
            "wildcard digest": entry(digest="sha256:" + "a" * 63 + "*"),
            "question mark": entry(package="lib?"),
            "brackets": entry(package="lib[0-9]"),
            "braces": entry(package="lib{a,b}"),
            "no digest": missing_digest,
            "tag instead of digest": entry(digest="1.2.3"),
            "latest instead of digest": entry(digest="latest"),
            "short digest": entry(digest="sha256:" + "a" * 63),
            "long digest": entry(digest="sha256:" + "a" * 65),
            "uppercase digest": entry(digest="sha256:" + "A" * 64),
            "sha512 digest": entry(digest="sha512:" + "a" * 64),
            "digest with newline": entry(digest=DIGEST + "\n"),
            "image with tag": entry(image="example/app:1.2.3"),
            "image with digest": entry(image="example/app@" + DIGEST),
            "uppercase image": entry(image="Example/App"),
            "id of a secret rule": entry(id="aws-access-key-id"),
            "id with spaces": entry(id="CVE-2026-0001 x"),
            "id with newline": entry(id="CVE-2026-0001\n"),
            "id without digit": entry(id="CVE-ABC"),
            "ghsa wrong group length": entry(id="GHSA-cfgh-jmpq-rvw"),
            "ghsa long group": entry(id="GHSA-cfgh-jmpq-rvwxx"),
            "ghsa extra group": entry(id="GHSA-cfgh-jmpq-rvwx-cfgh"),
            "ghsa missing group": entry(id="GHSA-cfgh-jmpq"),
            "ghsa uppercase groups": entry(id="GHSA-CFGH-JMPQ-RVWX"),
            "ghsa lowercase prefix": entry(id="ghsa-cfgh-jmpq-rvwx"),
            "ghsa letter outside the alphabet": entry(id="GHSA-cfgh-jmpq-rvwa"),
            "ghsa bare digit": entry(id="GHSA-2"),
            "ghsa uppercase digit groups": entry(id="GHSA-CFGH-JMPQ-RVW2"),
            "ghsa digit outside the alphabet": entry(id="GHSA-cfgh-jmpq-rvw1"),
            "ghsa two groups with digit": entry(id="GHSA-2345-jmpq"),
            "ghsa four groups with digit": entry(id="GHSA-2345-jmpq-rvw2-cfgh"),
            "ghsa mixed-case prefix": entry(id="Ghsa-2345-jmpq-rvw2"),
            "ghsa wildcard": entry(id="GHSA-cfgh-jmpq-rv*x"),
            "ghsa trailing newline": entry(id="GHSA-cfgh-jmpq-rvwx\n"),
            "empty package": entry(package=" "),
            "package with space": entry(package="lib foo"),
            "empty reason": entry(reason=" "),
            "short reason": entry(reason="no"),
            "long reason": entry(reason="x" * 301),
            "multiline reason": entry(reason="a long reason\nsecond line"),
            "control character in reason": entry(reason="a long reason\x1b[31m"),
            "line separator in reason": entry(reason="a long reason" + chr(0x2028) + "more"),
            "reason with padding": entry(reason=" a long enough reason"),
            "empty reviewer": entry(reviewer=""),
            "reviewer with newline": entry(reviewer="Jane\nDoe"),
            "reviewer with padding": entry(reviewer="Jane "),
            "reviewer that is a command": entry(reviewer="::error::x"),
            "bad date": entry(expires="2026-13-40"),
            "soon": entry(expires="soon"),
            "date with newline": entry(expires="2026-11-20\n"),
            "date with other digits": entry(expires="\u0662\u0660\u0662\u0666-\u0661\u0661-\u0662\u0660"),
            "date with time": entry(expires="2026-11-20T00:00:00"),
            "32 days": entry(expires="2026-11-26"),
            "expires before review": entry(expires="2026-10-24"),
            "reviewed tomorrow": entry(reviewed="2026-11-02", expires="2026-11-10"),
            "reviewed far in the future": entry(reviewed="2027-01-01", expires="2027-01-10"),
            "http tracking": entry(tracking="http://example.org"),
            "tracking with space": entry(tracking="https://example.org/a b"),
            "number as reason": entry(reason=12345678901),
            "list as image": entry(image=["example/app"]),
            "dict as id": entry(id={"a": 1}),
            "null digest": entry(digest=None),
            "bool reviewer": entry(reviewer=True),
            "extra field": entry(note="x"),
            "tag field": entry(tag="1.2.3"),
            "secret field": entry(secret="etc/key"),
            "rule field": entry(rule="aws-access-key-id"),
            "rule id field": entry(RuleID="aws-access-key-id"),
            "not an object": "CVE-2026-0001",
        }
        for name, e in bad.items():
            with self.subTest(name):
                self.assertTrue(self.errors(e), name)

    def test_a_digit_free_ghsa_id_validates(self):
        self.assertEqual(self.errors(entry(id="GHSA-cfgh-jmpq-rvwx")), [])

    def test_every_positive_ghsa_example_matches_the_strict_pattern(self):
        # Every GHSA id used as a valid example in the tests and docs is listed here.
        strict = re.compile(r"GHSA(-[23456789cfghjmpqrvwx]{4}){3}")
        for ghsa in ("GHSA-2345-jmpq-rvw2", "GHSA-cfgh-jmpq-rvwx"):
            with self.subTest(ghsa):
                self.assertTrue(strict.fullmatch(ghsa))
                self.assertTrue(ie.VULN_ID.fullmatch(ghsa))
                self.assertEqual(self.errors(entry(id=ghsa)), [])

    def test_secret_rule_ids_stay_refused_beside_ghsa(self):
        for rid in ("aws-access-key-id", "github-pat", "ghsa-cfgh-jmpq-rvwx", "gitlab-pat-v2", "private-key"):
            with self.subTest(rid):
                self.assertIn("secrets never qualify", self.errors(entry(id=rid))[0])

    def test_secret_targeting_entries_say_why(self):
        for key in ("secret", "rule", "RuleID", "rule_id"):
            self.assertIn("secrets never qualify", self.errors(entry(**{key: "x"}))[0])
        self.assertIn("secrets never qualify", self.errors(entry(id="github-pat"))[0])

    def test_missing_fields(self):
        for key in ("image", "digest", "id", "package", "reason", "reviewer", "reviewed", "expires"):
            e = entry()
            del e[key]
            with self.subTest(key):
                self.assertTrue(self.errors(e))

    def test_date_rules(self):
        self.assertEqual(self.errors(entry(reviewed="2026-11-01", expires="2026-11-01")), [])  # reviewed == today == expires
        self.assertEqual(self.errors(entry(reviewed="2026-10-01", expires="2026-11-01")), [])  # exactly 31 days
        self.assertTrue(self.errors(entry(reviewed="2026-10-01", expires="2026-11-02")))  # 32 days
        self.assertEqual(self.errors(entry(reviewed="2026-10-25", expires="2026-10-25")), [])  # reviewed == expires
        self.assertTrue(self.errors(entry(reviewed="2026-11-02", expires="2026-11-02")))  # reviewed > today
        self.assertEqual(self.errors(entry(reviewed="2026-11-02", expires="2026-11-02"), today=datetime.date(2026, 11, 2)), [])

    def test_an_expiry_in_the_past_is_not_a_schema_error(self):
        self.assertEqual(self.errors(entry(reviewed="2026-01-01", expires="2026-01-31")), [])

    def test_duplicates(self):
        self.assertTrue(self.errors(entry(), entry(reason="another long reason")))
        self.assertEqual(self.errors(entry(), entry(digest=OTHER), entry(package="libbar"), entry(id="CVE-2026-0002"),
                                     entry(image="example/other")), [])

    def test_unhashable_values_do_not_crash_the_duplicate_check(self):
        self.assertTrue(self.errors(entry(image=["a"]), entry(image=["a"])))


class Files(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def write(self, text, name="e.json", binary=False):
        path = os.path.join(self.tmp.name, name)
        with open(path, "wb" if binary else "w", **({} if binary else {"encoding": "utf-8", "newline": ""})) as handle:
            handle.write(text)
        return path

    def load(self, text):
        return ie.load_exceptions(self.write(text), TODAY)

    def test_a_missing_file_means_no_exceptions(self):
        self.assertEqual(ie.load_exceptions(os.path.join(self.tmp.name, "nope.json"), TODAY), [])

    def test_a_valid_file_loads(self):
        self.assertEqual(self.load(json.dumps({"exceptions": [entry()]})), [entry()])
        self.assertEqual(self.load('{"exceptions": []}'), [])
        self.assertEqual(len(self.load("\ufeff" + json.dumps({"exceptions": [entry()]}))), 1)

    def test_everything_else_is_refused(self):
        good = json.dumps(entry())
        for label, text in {
            "empty": "", "blank": " \n", "not json": "x", "list": "[]", "object without key": "{}",
            "other key": '{"other": []}', "extra key": '{"exceptions": [], "x": 1}', "null": "null",
            "exceptions not a list": '{"exceptions": {}}', "trailing text": '{"exceptions": []} x',
            "duplicate top-level key": '{"exceptions": [], "exceptions": []}',
            "duplicate entry key": '{"exceptions": [' + good[:-1] + ', "id": "CVE-2026-0002"}]}',
            "NaN": '{"exceptions": [NaN]}', "Infinity": '{"exceptions": [Infinity]}',
            "deep nesting": "[" * 100000,
            "invalid entry": json.dumps({"exceptions": [entry(id="CVE-*")]}),
            "one bad among good": json.dumps({"exceptions": [entry(), entry(id="CVE-2026-0002", digest="latest")]}),
            "too many": json.dumps({"exceptions": [entry(id="CVE-2026-%04d" % i) for i in range(ie.MAX_ENTRIES + 1)]}),
        }.items():
            with self.subTest(label):
                with self.assertRaises(ie.ExceptionsError):
                    self.load(text)

    def test_invalid_utf8_and_oversize_files_are_refused(self):
        with self.assertRaises(ie.ExceptionsError):
            ie.load_exceptions(self.write(b'{"exceptions": ["\xff"]}', binary=True), TODAY)
        with self.assertRaises(ie.ExceptionsError):
            ie.load_exceptions(self.write(b" " * (ie.MAX_BYTES + 1), "big.json", binary=True), TODAY)

    def test_a_directory_is_refused(self):
        os.mkdir(os.path.join(self.tmp.name, "d.json"))
        with self.assertRaises(ie.ExceptionsError):
            ie.load_exceptions(os.path.join(self.tmp.name, "d.json"), TODAY)

    def test_a_symlink_is_refused(self):
        target = self.write('{"exceptions": []}')
        link = os.path.join(self.tmp.name, "link.json")
        try:
            os.symlink(target, link)
        except (OSError, NotImplementedError):
            # Skipped only where the OS lacks symlink support (Windows without the privilege);
            # on Linux and macOS (the ubuntu CI runner) a failure here is a failure of the test.
            if os.name != "nt":
                raise
            self.skipTest("symlinks are not available here")
        with self.assertRaises(ie.ExceptionsError):
            ie.load_exceptions(link, TODAY)


class Evaluate(unittest.TestCase):
    def test_a_live_digest_bound_entry_excepts_its_finding(self):
        v = evaluate([entry()], [finding()])
        self.assertEqual((len(v["excepted"]), v["failing"], v["expired"], v["stale"]), (1, [], [], []))

    def test_a_new_finding_fails(self):
        v = evaluate([entry()], [finding(), finding("CVE-2026-0002", "libbar")])
        self.assertEqual([f["id"] for f in v["failing"]], ["CVE-2026-0002"])

    def test_the_same_id_in_another_package_is_not_covered(self):
        self.assertEqual(len(evaluate([entry()], [finding(package="libbaz")])["failing"]), 1)

    def test_another_id_in_the_same_package_is_not_covered(self):
        self.assertEqual(len(evaluate([entry()], [finding("CVE-2026-0003")])["failing"]), 1)

    def test_another_digest_does_not_apply(self):
        v = evaluate([entry(digest=OTHER)], [finding()])
        self.assertEqual(len(v["failing"]), 1)
        self.assertEqual(len(v["stale"]), 1)
        self.assertIn("another digest", v["stale"][0][1])

    def test_a_tag_only_image_is_never_excepted(self):
        v = evaluate([entry()], [finding()], digest=None)
        self.assertEqual((len(v["failing"]), v["excepted"]), (1, []))
        self.assertIn("no digest", v["stale"][0][1])

    def test_another_image_does_not_apply_and_is_not_stale_here(self):
        v = evaluate([entry(image="example/other")], [finding()])
        self.assertEqual((len(v["failing"]), v["stale"]), (1, []))

    def test_an_expired_entry_fails_and_does_not_except(self):
        v = evaluate([entry(expires="2026-10-31")], [finding()])
        self.assertEqual((len(v["failing"]), len(v["expired"]), v["excepted"]), (1, 1, []))

    def test_an_expired_entry_is_reported_for_any_image(self):
        self.assertEqual(len(evaluate([entry(image="example/other", expires="2026-10-31")], [])["expired"]), 1)

    def test_an_expired_entry_fails_even_when_it_matches_nothing(self):
        self.assertEqual(len(evaluate([entry(expires="2026-10-31")], [])["expired"]), 1)

    def test_the_expiry_day_is_still_live(self):
        v = evaluate([entry(expires="2026-11-01")], [finding()])
        self.assertEqual((len(v["excepted"]), v["expired"]), (1, []))

    def test_a_stale_entry_is_reported(self):
        v = evaluate([entry()], [])
        self.assertEqual(len(v["stale"]), 1)
        self.assertIn("no longer matches", v["stale"][0][1])

    def test_the_same_finding_twice_is_excepted_twice(self):
        self.assertEqual(len(evaluate([entry()], [finding(), finding()])["excepted"]), 2)

    def test_no_entries_no_exceptions(self):
        v = evaluate([], [finding()])
        self.assertEqual((len(v["failing"]), v["excepted"], v["stale"], v["expired"]), (1, [], [], []))


class Generate(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def path(self, name):
        return os.path.join(self.tmp.name, name)

    def save(self, data, name="r.json"):
        with open(self.path(name), "w", encoding="utf-8") as handle:
            json.dump(data, handle)
        return self.path(name)

    def run_generate(self, *args, today=TODAY):
        out, err = io.StringIO(), io.StringIO()
        code = ie.main(["generate", *args], out, err, today)
        return code, out.getvalue(), err.getvalue()

    def default_report(self):
        return self.save(report([vuln(), vuln("CVE-2026-0002", "libbar", "CRITICAL"), vuln("CVE-9", severity="LOW"),
                                 vuln("CVE-8", fixed=None)]))

    def test_a_draft_has_no_reason_reviewer_or_dates_unless_given(self):
        code, out, err = self.run_generate("--scan", REF, self.default_report())
        self.assertEqual(code, 0, err)
        entries = json.loads(out)["exceptions"]
        self.assertEqual([(e["id"], e["package"]) for e in entries], [("CVE-2026-0001", "libfoo"), ("CVE-2026-0002", "libbar")])
        for e in entries:
            self.assertEqual((e["image"], e["digest"]), ("example/app", DIGEST))
            self.assertEqual((e["reason"], e["reviewer"], e["reviewed"], e["expires"]), ("", "", "", ""))
        self.assertTrue(ie.schema_errors(entries, TODAY))
        self.assertIn("2 draft entries", err)
        self.assertIn("1 -> fixed in 2", err)

    def test_nothing_defaults_to_today(self):
        code, out, _ = self.run_generate("--scan", REF, self.default_report(), "--reviewer", "reviewer-one")
        for e in json.loads(out)["exceptions"]:
            self.assertEqual((e["reviewed"], e["expires"]), ("", ""))
            self.assertNotIn(TODAY.isoformat(), json.dumps(e))

    def test_explicit_reviewer_and_date_are_used_but_the_reason_is_still_missing(self):
        code, out, err = self.run_generate("--scan", REF, self.default_report(), "--reviewer", "reviewer-one",
                                           "--reviewed", "2026-10-27")
        entries = json.loads(out)["exceptions"]
        self.assertEqual({(e["reviewer"], e["reviewed"], e["expires"]) for e in entries},
                         {("reviewer-one", "2026-10-27", "2026-11-27")})
        errors = ie.schema_errors(entries, TODAY)
        self.assertTrue(errors)
        self.assertTrue(all("reason" in line for line in errors), errors)
        for e in entries:
            e["reason"] = "the vendor has not rebuilt the image"
        self.assertEqual(ie.schema_errors(entries, TODAY), [])
        self.assertEqual(len(evaluate(entries, [finding(), finding("CVE-2026-0002", "libbar")])["excepted"]), 2)

    def test_a_drafted_digit_free_ghsa_entry_validates_once_completed_and_excepts(self):
        ghsa = "GHSA-cfgh-jmpq-rvwx"
        path = self.save(report([vuln(ghsa)]))
        code, out, err = self.run_generate("--scan", REF, path, "--reviewer", "reviewer-one", "--reviewed", "2026-10-27")
        self.assertEqual(code, 0, err)
        entries = json.loads(out)["exceptions"]
        self.assertEqual([e["id"] for e in entries], [ghsa])
        entries[0]["reason"] = "the vendor has not rebuilt the image"
        self.assertEqual(ie.schema_errors(entries, TODAY), [])
        verdict = evaluate(entries, [finding(ghsa)])
        self.assertEqual((len(verdict["excepted"]), verdict["failing"]), (1, []))

    def test_days_sets_the_expiry(self):
        _, out, _ = self.run_generate("--scan", REF, self.default_report(), "--reviewed", "2026-10-27", "--days", "7")
        self.assertEqual({e["expires"] for e in json.loads(out)["exceptions"]}, {"2026-11-03"})

    def test_bad_options_fail(self):
        report_path = self.default_report()
        for label, args in {
            "future reviewed": ["--reviewed", "2026-11-02"],
            "bad reviewed": ["--reviewed", "yesterday"],
            "days over the cap": ["--reviewed", "2026-10-27", "--days", "32"],
            "negative days": ["--reviewed", "2026-10-27", "--days", "-1"],
            "days not a number": ["--days", "x"],
            "bad reviewer": ["--reviewer", "::error::x"],
            "unknown option": ["--bogus", "x"],
            "abbreviation": ["--review", "x"],
        }.items():
            with self.subTest(label):
                code, out, err = self.run_generate("--scan", REF, report_path, *args)
                self.assertEqual((code, out), (2, ""))
                self.assertIn("ERROR", err)

    def test_a_scan_is_required(self):
        self.assertEqual(self.run_generate()[0], 2)
        self.assertEqual(self.run_generate("--scan", REF)[0], 2)

    def test_a_tag_only_reference_cannot_be_drafted(self):
        code, out, err = self.run_generate("--scan", "example/app:1.2.3", self.default_report())
        self.assertEqual((code, out), (2, ""))
        self.assertIn("no sha256 digest", err)

    def test_a_report_of_another_image_is_refused(self):
        code, out, err = self.run_generate("--scan", "example/app@" + OTHER, self.default_report())
        self.assertEqual((code, out), (2, ""))
        self.assertIn("RepoDigests", err)

    def test_a_malformed_report_is_refused(self):
        for label, data in {"list": [], "wrong artifact": {"SchemaVersion": 2, "ArtifactType": "filesystem"},
                            "vulns as object": report()["Results"] and {**report(), "Results": [{"Vulnerabilities": {"a": 1}}]},
                            "severity confused": report([vuln(severity=["HIGH"])]),
                            "fixed confused": report([vuln(fixed=["2"])])}.items():
            with self.subTest(label):
                code, out, err = self.run_generate("--scan", REF, self.save(data))
                self.assertEqual((code, out), (2, ""))
        self.assertEqual(self.run_generate("--scan", REF, self.path("missing.json"))[0], 2)

    def test_secrets_in_a_report_never_become_entries(self):
        data = report([vuln()])
        data["Results"].append({"Target": "etc/key", "Secrets": [{"RuleID": "aws-access-key-id", "Severity": "CRITICAL",
                                                                    "Title": "AWS", "StartLine": 1, "Match": "AKIAEXAMPLE"}]})
        code, out, err = self.run_generate("--scan", REF, self.save(data))
        self.assertEqual(code, 0)
        self.assertEqual([e["id"] for e in json.loads(out)["exceptions"]], ["CVE-2026-0001"])
        self.assertNotIn("aws-access-key-id", out + err)
        self.assertNotIn("AKIAEXAMPLE", out + err)

    def test_several_images_and_repeated_findings(self):
        two = report([vuln(), vuln()])
        two["Results"].append({"Target": "node", "Vulnerabilities": [vuln()]})
        other = report([vuln("CVE-2026-0005", "libz")], OTHER, "example/zzz")
        code, out, err = self.run_generate("--scan", REF, self.save(two), "--scan", "example/zzz:1@" + OTHER,
                                           self.save(other, "r2.json"))
        self.assertEqual(code, 0, err)
        self.assertEqual([(e["image"], e["id"]) for e in json.loads(out)["exceptions"]],
                         [("example/app", "CVE-2026-0001"), ("example/zzz", "CVE-2026-0005")])

    def test_output_goes_to_a_new_file_and_never_over_an_existing_one(self):
        target = self.path("draft.json")
        code, out, err = self.run_generate("--scan", REF, self.default_report(), "--output", target)
        self.assertEqual((code, out), (0, ""))
        with open(target, encoding="utf-8") as handle:
            self.assertEqual(len(json.load(handle)["exceptions"]), 2)
        live = self.path("image-exceptions.json")
        with open(live, "w", encoding="utf-8") as handle:
            handle.write('{"exceptions": []}')
        for path in (live, target):
            code, out, err = self.run_generate("--scan", REF, self.default_report(), "--output", path)
            self.assertEqual(code, 2)
            self.assertIn("never overwrites", err)
        with open(live, encoding="utf-8") as handle:
            self.assertEqual(handle.read(), '{"exceptions": []}')

    def test_the_draft_goes_to_stdout_by_default_and_writes_no_file(self):
        report_path = self.default_report()
        before = set(os.listdir(self.tmp.name))
        self.run_generate("--scan", REF, report_path)
        self.assertEqual(set(os.listdir(self.tmp.name)), before)


class Cli(unittest.TestCase):
    """The script as it is run by hand and by the workflow: python3 -I."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def run_cli(self, *args, cwd=None):
        return subprocess.run([sys.executable, "-I", SCRIPT, *args], capture_output=True, text=True,
                              cwd=cwd or self.tmp.name)

    def test_validate_and_generate_under_isolated_mode(self):
        live = os.path.join(self.tmp.name, "live.json")
        with open(live, "w", encoding="utf-8") as handle:
            json.dump({"exceptions": [entry(reviewed="2026-10-25", expires="2026-11-20")]}, handle)
        # The real clock is used here, so only check what holds on any day: a past review.
        result = self.run_cli("validate", live)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("ok: 1 entries", result.stdout)
        with open(os.path.join(self.tmp.name, "r.json"), "w", encoding="utf-8") as handle:
            json.dump(report([vuln()]), handle)
        result = self.run_cli("generate", "--scan", REF, "r.json")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["exceptions"][0]["id"], "CVE-2026-0001")
        self.assertEqual(self.run_cli("validate", "missing.json").returncode, 1)
        self.assertEqual(self.run_cli().returncode, 2)
        self.assertEqual(self.run_cli("nope").returncode, 2)

    def test_a_planted_module_in_the_working_directory_is_not_imported(self):
        with open(os.path.join(self.tmp.name, "json.py"), "w", encoding="utf-8") as handle:
            handle.write("raise SystemExit(99)\n")
        with open(os.path.join(self.tmp.name, "e.json"), "w", encoding="utf-8") as handle:
            handle.write('{"exceptions": []}')
        self.assertEqual(self.run_cli("validate", "e.json").returncode, 0)

    def test_a_future_review_date_is_refused_by_validate(self):
        future = (datetime.datetime.now(datetime.timezone.utc).date() + datetime.timedelta(days=2)).isoformat()
        path = os.path.join(self.tmp.name, "f.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump({"exceptions": [entry(reviewed=future, expires=future)]}, handle)
        result = self.run_cli("validate", path)
        self.assertEqual(result.returncode, 1)
        self.assertIn("in the future", result.stderr)


# ---------------------------------------------------------------- mutation checks


def probes(m):
    """The engine's promises, each True when kept. A mutated engine must break at least one."""
    ev = lambda entries, findings, digest=DIGEST, repo="example/app": m.evaluate(entries, repo, digest, findings, TODAY, "no digest")
    errs = lambda *entries: m.schema_errors(list(entries), TODAY)
    kept = {}

    def attempt(name, check):
        try:
            kept[name] = bool(check())
        except Exception:  # a crashing engine has broken the promise
            kept[name] = False

    attempt("valid entry is accepted", lambda: errs(entry()) == [])
    attempt("excepts the exact finding", lambda: len(ev([entry()], [finding()])["excepted"]) == 1)
    attempt("digest binding", lambda: len(ev([entry(digest=OTHER)], [finding()])["failing"]) == 1)
    attempt("tag-only never excepted", lambda: len(ev([entry()], [finding()], digest=None)["failing"]) == 1)
    attempt("image binding", lambda: len(ev([entry(image="example/other")], [finding()])["failing"]) == 1)
    attempt("id binding", lambda: len(ev([entry()], [finding("CVE-2026-0003")])["failing"]) == 1)
    attempt("package binding", lambda: len(ev([entry()], [finding(package="libbaz")])["failing"]) == 1)
    # The display copy equals the entry, the raw Trivy string does not (clean() maps "a|b" to "a/b",
    # and drops a trailing NUL): the raw string decides.
    attempt("raw strings decide", lambda: len(ev([entry(package="a/b")], [dict(finding(package="a/b"), raw_package="a|b")])["failing"]) == 1
            and len(ev([entry()], [dict(finding(), raw_id="CVE-2026-0001\x00")])["failing"]) == 1
            and len(ev([entry()], [dict(finding(), raw_package="libfoo ")])["failing"]) == 1)
    attempt("expired fails", lambda: len(ev([entry(expires="2026-10-31")], [])["expired"]) == 1)
    attempt("expired does not except", lambda: len(ev([entry(expires="2026-10-31")], [finding()])["failing"]) == 1)
    attempt("expiry day is live", lambda: len(ev([entry(expires="2026-11-01")], [finding()])["excepted"]) == 1)
    attempt("stale is reported", lambda: len(ev([entry()], [])["stale"]) == 1)
    attempt("reviewed after today", lambda: bool(errs(entry(reviewed="2026-11-02", expires="2026-11-10"))))
    attempt("expires before reviewed", lambda: bool(errs(entry(expires="2026-10-24"))))
    attempt("31 day cap", lambda: bool(errs(entry(reviewed="2026-10-01", expires="2026-11-02"))) and errs(entry(reviewed="2026-10-01", expires="2026-11-01")) == [])
    attempt("no wildcards", lambda: bool(errs(entry(id="CVE-2026-*"))) and bool(errs(entry(image="example/*"))))
    attempt("digest format", lambda: bool(errs(entry(digest="latest"))) and bool(errs(entry(digest="1.2.3"))))
    attempt("reviewer required", lambda: bool(errs(entry(reviewer=""))))
    attempt("reason required", lambda: bool(errs(entry(reason=""))))
    attempt("duplicates rejected", lambda: bool(errs(entry(), entry())))
    attempt("secret field refused", lambda: "secrets never qualify" in "".join(errs(entry(rule="aws-access-key-id"))))
    attempt("secret id refused", lambda: bool(errs(entry(id="aws-access-key-id"))))
    attempt("extra field refused", lambda: bool(errs(entry(note="x"))))

    def missing_file():
        with tempfile.TemporaryDirectory() as tmp:
            return m.load_exceptions(os.path.join(tmp, "none.json"), TODAY) == []
    attempt("missing file is no exceptions", missing_file)

    def draft_defaults():
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "r.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(report([vuln()]), handle)
            out, err = io.StringIO(), io.StringIO()
            code = m.main(["generate", "--scan", REF, path], out, err, TODAY)
            e = json.loads(out.getvalue())["exceptions"][0]
            return code == 0 and (e["reviewed"], e["expires"], e["reviewer"], e["reason"]) == ("", "", "", "")
    attempt("generate sets nothing silently", draft_defaults)

    def no_overwrite():
        with tempfile.TemporaryDirectory() as tmp:
            path, target = os.path.join(tmp, "r.json"), os.path.join(tmp, "live.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(report([vuln()]), handle)
            with open(target, "w", encoding="utf-8") as handle:
                handle.write("keep")
            code = m.main(["generate", "--scan", REF, path, "--output", target], io.StringIO(), io.StringIO(), TODAY)
            with open(target, encoding="utf-8") as handle:
                return code == 2 and handle.read() == "keep"
    attempt("generate never overwrites", no_overwrite)

    def tag_only_draft():
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "r.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(report([vuln()]), handle)
            return m.main(["generate", "--scan", "example/app:1.2.3", path], io.StringIO(), io.StringIO(), TODAY) == 2
    attempt("generate needs a digest", tag_only_draft)
    return kept


RAW_GET = '.get((finding.get("raw_id", finding["id"]), finding.get("raw_package", finding["package"])))'

MUTATIONS = [
    # (name, [(old, new)], the promise it must break)
    ("digest ignored", [('for e in mine if e["digest"] == digest}', "for e in mine}")], "digest binding"),
    ("unknown digest matches any entry", [("bound = {} if digest is None else {", "bound = {"),
                                          ('if e["digest"] == digest}', 'if digest is None or e["digest"] == digest}')], "tag-only never excepted"),
    ("image ignored", [('>= today and e["image"] == repository]', ">= today]")], "image binding"),
    ("id ignored", [('(e["id"], e["package"]): e for', 'e["package"]: e for'), (RAW_GET, '.get(finding["raw_package"])')], "id binding"),
    ("package ignored", [('(e["id"], e["package"]): e for', 'e["id"]: e for'), (RAW_GET, '.get(finding["raw_id"])')], "package binding"),
    ("cleaned copy matched", [(RAW_GET, '.get((finding["id"], finding["package"]))')], "raw strings decide"),
    ("expired not reported", [('expired = [e for e in entries if parse_date(e["expires"]) < today]', "expired = []")], "expired fails"),
    ("expired still live", [('parse_date(e["expires"]) >= today and e["image"] == repository', 'e["image"] == repository')], "expired does not except"),
    ("expiry day expired", [('parse_date(e["expires"]) >= today', 'parse_date(e["expires"]) > today')], "expiry day is live"),
    ("stale not reported", [("stale.append((entry, why))", "pass")], "stale is reported"),
    ("future review allowed", [("if reviewed > today:\n                errors.append(", "if False:\n                errors.append(")], "reviewed after today"),
    ("expires before review allowed", [("if expires < reviewed:", "if False:")], "expires before reviewed"),
    ("cap raised", [("MAX_DAYS = 31", "MAX_DAYS = 93")], "31 day cap"),
    ("wildcards allowed", [(r'WILDCARD = re.compile(r"[*?\[\]{}]")', 'WILDCARD = re.compile(r"(?!)")'),
                           ("if vid is not None and (len(vid) > 100 or not VULN_ID.fullmatch(vid)):", "if False:")], "no wildcards"),
    ("secret id accepted", [("if vid is not None and (len(vid) > 100 or not VULN_ID.fullmatch(vid)):", "if False:")], "secret id refused"),
    ("any digest string", [('DIGEST = re.compile(r"sha256:[0-9a-f]{64}", re.ASCII)', 'DIGEST = re.compile(r".+", re.ASCII)')], "digest format"),
    ("empty reviewer allowed", [("if not isinstance(entry[key], str) or not entry[key].strip():", "if not isinstance(entry[key], str):")], "reviewer required"),
    ("duplicates allowed", [("if identity in seen:", "if False:")], "duplicates rejected"),
    ("secret keys not named", [("k.lower() in SECRET_KEYS", "k.lower() in ()")], "secret field refused"),
    ("empty reason allowed", [("if not isinstance(entry[key], str) or not entry[key].strip():", "if not isinstance(entry[key], str):")], "reason required"),
    ("unknown fields allowed", [("keys - set(REQUIRED) - set(OPTIONAL) or set(REQUIRED) - keys", "set(REQUIRED) - keys")], "extra field refused"),
    ("missing file is an error", [("if not os.path.lexists(path):\n        return []", "if False:\n        return []")], "missing file is no exceptions"),
    ("draft sets today", [('"reviewed": "" if reviewed is None else reviewed.isoformat(), "expires": expires,',
                           '"reviewed": (reviewed or today_utc()).isoformat(), "expires": expires,')], "generate sets nothing silently"),
    ("draft overwrites", [('open(args.output, "x"', 'open(args.output, "w"')], "generate never overwrites"),
    ("draft accepts a tag", [("if digest is None:\n                raise ExceptionsError", "if False:\n                raise ExceptionsError"),
                             ("if digest not in report_digests(data):", "if False:")], "generate needs a digest"),
]


class Mutations(unittest.TestCase):
    """A schema or engine that is loosened must fail these tests, not pass silently."""

    @classmethod
    def setUpClass(cls):
        with open(SCRIPT, encoding="utf-8") as handle:
            cls.source = handle.read()

    def test_the_real_engine_keeps_every_promise(self):
        broken = [name for name, ok in probes(ie).items() if not ok]
        self.assertEqual(broken, [])

    def test_every_loosened_engine_breaks_a_promise(self):
        for name, edits, promise in MUTATIONS:
            with self.subTest(name):
                source = self.source
                for old, new in edits:
                    self.assertEqual(source.count(old), 1, "mutation target is gone or not unique: " + old)
                    source = source.replace(old, new)
                broken = [p for p, ok in probes(load_module(source)).items() if not ok]
                self.assertIn(promise, broken)

    def test_every_promise_is_attacked_by_some_mutation(self):
        attacked = {promise for _, _, promise in MUTATIONS}
        unattacked = [name for name in probes(ie) if name not in attacked]
        self.assertEqual(unattacked, ["valid entry is accepted", "excepts the exact finding"])  # the positive controls

    def test_the_schema_rejects_each_mutated_copy_of_a_good_file(self):
        """The validate.sh block of the old repository, run through the real command."""
        good = {"exceptions": [entry(), entry(id="CVE-2026-0002", package="libbar")]}
        mutations = {
            "wildcard-id": lambda e: e[0].update(id="CVE-2026-*"),
            "wildcard-image": lambda e: e[0].update(image="*"),
            "too-long": lambda e: e[0].update(reviewed="2026-01-01", expires="2026-03-01"),
            "no-reason": lambda e: e[0].pop("reason"),
            "no-reviewer": lambda e: e[0].pop("reviewer"),
            "no-digest": lambda e: e[0].pop("digest"),
            "tag-not-digest": lambda e: e[0].update(digest="1.2.3"),
            "duplicate": lambda e: e.append(copy.deepcopy(e[0])),
            "bad-date": lambda e: e[0].update(expires="soon"),
            "expires-before-reviewed": lambda e: e[0].update(expires="2026-10-01"),
            "reviewed-in-the-future": lambda e: e[0].update(reviewed="2999-01-01", expires="2999-01-02"),
            "secret-rule": lambda e: e[0].update(rule="aws-access-key-id"),
        }
        with tempfile.TemporaryDirectory() as tmp:
            def run(name, mutate):
                data = copy.deepcopy(good)
                mutate(data["exceptions"])
                path = os.path.join(tmp, "exceptions-%s.json" % name)
                with open(path, "w", encoding="utf-8") as handle:
                    json.dump(data, handle)
                return subprocess.run([sys.executable, "-I", SCRIPT, "validate", path], capture_output=True).returncode

            # The real clock is used by the command, so the unmutated copy needs dates that are valid on any day.
            good["exceptions"] = [dict(e, reviewed="2026-10-25", expires="2026-11-20") for e in good["exceptions"]]
            self.assertEqual(run("ok", lambda e: None), 0, "the unmutated copy must pass")
            for name, mutate in mutations.items():
                with self.subTest(name):
                    self.assertNotEqual(run(name, mutate), 0)


# ---------------------------------------------------------------- scope


def code_of(text):
    return "\n".join(line for line in text.replace("\r\n", "\n").split("\n") if not line.lstrip().startswith("#"))


def violations(workflows):
    """Where an exceptions file is read other than by trivy-images.yml, or not read there."""
    found = []
    for name, text in workflows.items():
        code = code_of(text)
        if name == "trivy-images.yml":
            if not re.search(r"python3 -I \.strange-security/scripts/trivy_images\.py gate\b", code):
                found.append("trivy-images.yml does not run the gate script")
            if "--exceptions-file" not in code:
                found.append("trivy-images.yml does not pass the exceptions file to the gate")
            if re.search(r"--ignorefile|TRIVY_IGNOREFILE|trivyignore|trivy\.yaml|--config\b", code):
                found.append("trivy-images.yml reads an ignore file or a Trivy config")
        elif re.search(r"image[-_]exceptions|exceptions-file|IMAGE_EXCEPTIONS", code):
            found.append("%s uses the image exceptions" % name)
    return found


class Scope(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflows = {}
        for name in sorted(os.listdir(WORKFLOWS)):
            if name.endswith(".yml"):
                with open(os.path.join(WORKFLOWS, name), encoding="utf-8") as handle:
                    cls.workflows[name] = handle.read()

    def test_only_trivy_images_uses_the_exceptions(self):
        self.assertIn("trivy-images.yml", self.workflows)
        self.assertEqual(violations(self.workflows), [])

    def test_filesystem_gitleaks_semgrep_and_single_image_scans_never_see_them(self):
        for name in ("trivy.yml", "gitleaks.yml", "semgrep.yml", "trivy-image.yml", "security_gate.yml"):
            with self.subTest(name):
                self.assertIn(name, self.workflows)
                self.assertNotRegex(code_of(self.workflows[name]), r"image[-_]exceptions|exceptions-file|IMAGE_EXCEPTIONS")

    def test_other_scripts_do_not_use_the_engine(self):
        for name in sorted(os.listdir(os.path.join(ROOT, "scripts"))):
            if name.endswith(".py") and name not in ("image_exceptions.py", "trivy_images.py"):
                with open(os.path.join(ROOT, "scripts", name), encoding="utf-8") as handle:
                    self.assertNotRegex(handle.read(), r"image[-_]exceptions", name)

    def test_a_committed_exceptions_file_of_this_repository_is_valid(self):
        path = os.path.join(ROOT, ".github", "image-exceptions.json")
        if os.path.exists(path):
            ie.load_exceptions(path, ie.today_utc())

    def test_mutation_another_workflow_given_the_file_is_caught(self):
        for name in ("trivy.yml", "gitleaks.yml", "semgrep.yml", "trivy-image.yml"):
            with self.subTest(name):
                mutated = dict(self.workflows)
                mutated[name] += "\n          exceptions-file: .github/image-exceptions.json\n"
                self.assertTrue(violations(mutated))

    def test_mutation_the_image_workflow_without_the_gate_is_caught(self):
        mutated = dict(self.workflows)
        mutated["trivy-images.yml"] = mutated["trivy-images.yml"].replace("trivy_images.py gate", "gone.py gate")
        self.assertTrue(violations(mutated))
        mutated["trivy-images.yml"] = self.workflows["trivy-images.yml"].replace("--exceptions-file", "--other")
        self.assertTrue(violations(mutated))

    def test_mutation_the_image_workflow_given_an_ignore_file_is_caught(self):
        for extra in ("--ignorefile .trivyignore", "TRIVY_IGNOREFILE: x", "--config trivy.yaml"):
            with self.subTest(extra):
                mutated = dict(self.workflows)
                mutated["trivy-images.yml"] += "\n            " + extra + "\n"
                self.assertTrue(violations(mutated))

    def test_the_comments_that_name_ignore_files_are_not_violations(self):
        self.assertEqual(violations({"trivy-images.yml": "# a caller's .trivyignore and trivy.yaml\n"
                                     "run: python3 -I .strange-security/scripts/trivy_images.py gate --exceptions-file x\n"}), [])


class Docs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        def read(*parts):
            with open(os.path.join(ROOT, *parts), encoding="utf-8") as handle:
                return handle.read().replace("\r\n", "\n")
        cls.readme, cls.process, cls.suppressions = read("README.md"), read("docs", "IMAGE_EXCEPTIONS.md"), read("docs", "SUPPRESSIONS.md")

    def test_the_readme_example_is_a_valid_file(self):
        match = re.search(r"```json\n(.*?)\n```", self.readme, re.S)
        self.assertIsNotNone(match)
        entries = json.loads(match.group(1))["exceptions"]
        self.assertEqual(ie.schema_errors(entries, datetime.date(2026, 11, 3)), [])

    def test_the_readme_and_the_suppression_policy_link_the_process(self):
        self.assertIn("(docs/IMAGE_EXCEPTIONS.md)", self.readme)
        self.assertIn("(IMAGE_EXCEPTIONS.md)", self.suppressions)
        self.assertIn("No suppressions, ever.", self.suppressions)  # not loosened

    def test_the_readme_documents_every_field(self):
        for key in ie.REQUIRED + ie.OPTIONAL:
            self.assertIn("| `%s` |" % key, self.readme)

    def test_the_process_covers_what_it_must(self):
        for phrase in ("## Who reviews", "## Monthly cadence", "patched release", "## Delete stale entries",
                       "## The renew pull request flow", "## What never qualifies", "generate", "Secrets.",
                       "filesystem scan", "gitleaks", "Semgrep", "31 days"):
            self.assertIn(phrase, self.process)


if __name__ == "__main__":
    unittest.main()
