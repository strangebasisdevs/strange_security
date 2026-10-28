"""The image secret allowlist engine (scripts/image_secret_allowlist.py): the strict
schema, the binding of one entry to one finding (digest, layer, file, rule, line),
expiry and stale entries, the generate-secrets command, mutation checks that prove
these tests would notice a loosened engine, and the rule that only trivy-images.yml
may use an allowlist file. The engine inside the gate is tested in
tests/test_image_secret_gate.py.
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
SCRIPT = os.path.join(ROOT, "scripts", "image_secret_allowlist.py")
WORKFLOWS = os.path.join(ROOT, ".github", "workflows")


def load_module(source=None):
    """The engine, from SCRIPT or from modified source text (for the mutation checks)."""
    if source is None:
        spec = importlib.util.spec_from_file_location("image_secret_allowlist", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    module = types.ModuleType("image_secret_allowlist_mutant")
    module.__file__ = os.path.abspath(SCRIPT)
    exec(compile(source, SCRIPT, "exec"), module.__dict__)
    return module


sa = load_module()

TODAY = datetime.date(2026, 11, 1)
DIGEST = "sha256:" + "a" * 64
OTHER = "sha256:" + "b" * 64
LAYER = "sha256:" + "c" * 64
OTHER_LAYER = "sha256:" + "d" * 64
MATCH = "sha256:" + "e" * 64
OTHER_MATCH = "sha256:" + "f" * 64
RULE = "azure-storage-account-key"
TARGET = "var/www/html/3rdparty/vendor/azure/Resources.php"
EVIDENCE = "https://learn.microsoft.com/en-us/azure/storage/common/storage-use-azurite"
REASON = "the documented Azurite emulator key, public in Microsoft's docs; not a credential"
REF = "example/app:1.2.3@" + DIGEST


def entry(**over):
    base = {"image": "example/app", "digest": DIGEST, "rule": RULE, "target": TARGET, "layer_diff_id": LAYER,
            "start_line": 42, "reason": REASON, "evidence": EVIDENCE, "reviewer": "reviewer-one",
            "reviewed": "2026-10-25", "expires": "2026-11-20"}
    base.update(over)
    return base


def finding(**over):
    """A secret finding as trivy_images.secret_findings produces it."""
    base = {"rule": RULE, "severity": "CRITICAL", "title": "Azure key", "target": TARGET, "line": "42", "layer": LAYER,
            "raw_rule": RULE, "raw_target": TARGET, "raw_line": 42, "raw_diff_id": LAYER, "match_sha256": MATCH}
    base.update(over)
    return base


def leak(rule=RULE, line=42, diff=LAYER, match="AccountKey=*****", **extra):
    """A secret as Trivy writes it in the JSON report (the Match line is already redacted)."""
    item = {"RuleID": rule, "Category": "Azure", "Severity": "CRITICAL", "Title": "Azure Storage Account Key",
            "StartLine": line, "EndLine": line, "Match": match}
    if diff is not None:
        item["Layer"] = {"DiffID": diff, "Digest": "sha256:" + "9" * 64}
    item.update(extra)
    return item


def sreport(secrets=(), digest=DIGEST, repo="example/app", target=TARGET):
    return {"SchemaVersion": 2, "ArtifactType": "container_image",
            "Metadata": {"RepoDigests": [repo + "@" + digest]},
            "Results": [{"Target": target, "Class": "secret", "Secrets": list(secrets)}]}


def evaluate(entries, findings, digest=DIGEST, repo="example/app", today=TODAY):
    return sa.evaluate(entries, repo, digest, findings, today, "no digest")


class Schema(unittest.TestCase):
    def errors(self, *entries, today=TODAY):
        return sa.schema_errors(list(entries), today)

    def test_good_entries(self):
        self.assertEqual(self.errors(
            entry(), entry(match_sha256=MATCH, start_line=44), entry(rule="aws-access-key-id", start_line=1),
            entry(target="a b/c.txt"), entry(image="localhost:5000/a/b", reviewer="Jane Doe"),
            entry(start_line=sa.MAX_LINE), entry(start_line=45, evidence="https://example.org/a?b=c#d")), [])

    def test_rejections(self):
        missing_layer = entry()
        del missing_layer["layer_diff_id"]
        bad = {
            "wildcard image": entry(image="example/*"),
            "wildcard rule": entry(rule="azure-*"),
            "wildcard target star": entry(target="var/www/*"),
            "wildcard target question": entry(target="var/www/?.php"),
            "wildcard target brackets": entry(target="var/www/[a].php"),
            "wildcard target braces": entry(target="var/www/{a,b}.php"),
            "wildcard digest": entry(digest="sha256:" + "a" * 63 + "*"),
            "wildcard layer": entry(layer_diff_id="sha256:" + "c" * 63 + "*"),
            "wildcard match hash": entry(match_sha256="sha256:" + "e" * 63 + "?"),
            "no layer": missing_layer,
            "tag instead of digest": entry(digest="1.2.3"),
            "latest instead of digest": entry(digest="latest"),
            "short digest": entry(digest="sha256:" + "a" * 63),
            "uppercase digest": entry(digest="sha256:" + "A" * 64),
            "digest with newline": entry(digest=DIGEST + "\n"),
            "layer as a tag": entry(layer_diff_id="latest"),
            "layer without prefix": entry(layer_diff_id="c" * 64),
            "short layer": entry(layer_diff_id="sha256:" + "c" * 63),
            "uppercase layer": entry(layer_diff_id="sha256:" + "C" * 64),
            "layer with newline": entry(layer_diff_id=LAYER + "\n"),
            "match hash without prefix": entry(match_sha256="e" * 64),
            "short match hash": entry(match_sha256="sha256:" + "e" * 10),
            "empty match hash": entry(match_sha256=""),
            "image with tag": entry(image="example/app:1.2.3"),
            "image with digest": entry(image="example/app@" + DIGEST),
            "uppercase image": entry(image="Example/App"),
            "uppercase rule": entry(rule="Azure-Key"),
            "rule with space": entry(rule="azure key"),
            "rule with trailing hyphen": entry(rule="azure-"),
            "rule with newline": entry(rule=RULE + "\n"),
            "rule of a vulnerability shape": entry(rule="CVE-2026-0001"),
            "empty rule": entry(rule=" "),
            "empty target": entry(target=" "),
            "target with leading space": entry(target=" var/www/a.php"),
            "target with trailing space": entry(target="var/www/a.php "),
            "target with newline": entry(target="var/www/a.php\nx"),
            "target with a control character": entry(target="var/www/a\x1b.php"),
            "target with a non-ascii character": entry(target="var/www/" + chr(0xe9) + ".php"),
            "target too long": entry(target="a" * (sa.MAX_TARGET + 1)),
            "line zero": entry(start_line=0),
            "negative line": entry(start_line=-1),
            "line as a string": entry(start_line="42"),
            "line as a float": entry(start_line=42.0),
            "line as a bool": entry(start_line=True),
            "line as null": entry(start_line=None),
            "line as a list": entry(start_line=[42]),
            "huge line": entry(start_line=sa.MAX_LINE + 1),
            "no evidence": {k: v for k, v in entry().items() if k != "evidence"},
            "empty evidence": entry(evidence=""),
            "blank evidence": entry(evidence=" "),
            "http evidence": entry(evidence="http://example.org/azurite"),
            "ftp evidence": entry(evidence="ftp://example.org/azurite"),
            "javascript evidence": entry(evidence="javascript:alert(1)"),
            "evidence without a scheme": entry(evidence="learn.microsoft.com/azurite"),
            "evidence with a space": entry(evidence="https://example.org/a b"),
            "evidence with a newline": entry(evidence="https://example.org/a\nb"),
            "evidence with credentials": entry(evidence="https://user:pass@example.org/a"),
            "evidence with a user": entry(evidence="https://user@example.org/a"),
            "evidence without a host": entry(evidence="https:///path"),
            "evidence that is only the scheme": entry(evidence="https://"),
            "evidence too long": entry(evidence="https://example.org/" + "a" * 300),
            "evidence as a list": entry(evidence=[EVIDENCE]),
            "no reason": {k: v for k, v in entry().items() if k != "reason"},
            "empty reason": entry(reason=" "),
            "short reason": entry(reason="no"),
            "long reason": entry(reason="x" * 301),
            "multiline reason": entry(reason="a long reason\nsecond line"),
            "control character in reason": entry(reason="a long reason\x1b[31m"),
            "reason with padding": entry(reason=" a long enough reason"),
            "number as reason": entry(reason=12345678901),
            "empty reviewer": entry(reviewer=""),
            "reviewer with newline": entry(reviewer="Jane\nDoe"),
            "reviewer that is a command": entry(reviewer="::error::x"),
            "bool reviewer": entry(reviewer=True),
            "bad date": entry(expires="2026-13-40"),
            "soon": entry(expires="soon"),
            "date with newline": entry(expires="2026-11-20\n"),
            "32 days": entry(expires="2026-11-26"),
            "expires before review": entry(expires="2026-10-24"),
            "reviewed tomorrow": entry(reviewed="2026-11-02", expires="2026-11-10"),
            "reviewed far in the future": entry(reviewed="2027-01-01", expires="2027-01-10"),
            "list as image": entry(image=["example/app"]),
            "null digest": entry(digest=None),
            "extra field": entry(note="x"),
            "tag field": entry(tag="1.2.3"),
            "vulnerability id field": entry(id="CVE-2026-0001"),
            "package field": entry(package="libfoo"),
            "secret field": entry(secret="x"),
            "not an object": "azure-storage-account-key",
        }
        for name, e in bad.items():
            with self.subTest(name):
                self.assertTrue(self.errors(e), name)

    def test_missing_fields(self):
        for key in sa.REQUIRED:
            e = entry()
            del e[key]
            with self.subTest(key):
                self.assertTrue(self.errors(e))

    def test_a_blank_required_string_is_refused(self):
        for key in sa.REQUIRED:
            if key == "start_line":
                continue
            with self.subTest(key):
                self.assertTrue(self.errors(entry(**{key: ""})))

    def test_date_rules(self):
        self.assertEqual(self.errors(entry(reviewed="2026-11-01", expires="2026-11-01")), [])
        self.assertEqual(self.errors(entry(reviewed="2026-10-01", expires="2026-11-01")), [])  # exactly 31 days
        self.assertTrue(self.errors(entry(reviewed="2026-10-01", expires="2026-11-02")))  # 32 days
        self.assertTrue(self.errors(entry(reviewed="2026-11-02", expires="2026-11-02")))  # reviewed > today
        self.assertEqual(self.errors(entry(reviewed="2026-11-02", expires="2026-11-02"), today=datetime.date(2026, 11, 2)), [])

    def test_an_expiry_in_the_past_is_not_a_schema_error(self):
        self.assertEqual(self.errors(entry(reviewed="2026-01-01", expires="2026-01-31")), [])

    def test_the_cap_is_the_one_of_the_vulnerability_exceptions(self):
        self.assertEqual(sa.MAX_DAYS, 31)
        self.assertEqual(sa.MAX_DAYS, sa.ie.MAX_DAYS)

    def test_duplicates(self):
        self.assertTrue(self.errors(entry(), entry(reason="another long reason")))
        self.assertEqual(self.errors(entry(), entry(digest=OTHER), entry(rule="other-rule"), entry(target="other.php"),
                                     entry(layer_diff_id=OTHER_LAYER), entry(start_line=43),
                                     entry(image="example/other")), [])

    def test_two_findings_on_one_line_need_a_hash_each(self):
        self.assertEqual(self.errors(entry(match_sha256=MATCH), entry(match_sha256=OTHER_MATCH)), [])
        self.assertTrue(self.errors(entry(match_sha256=MATCH), entry(match_sha256=MATCH)))
        self.assertTrue(self.errors(entry(), entry(match_sha256=MATCH)))
        self.assertTrue(self.errors(entry(match_sha256=MATCH), entry()))

    def test_unhashable_values_do_not_crash_the_duplicate_check(self):
        self.assertTrue(self.errors(entry(image=["a"]), entry(image=["a"])))
        self.assertTrue(self.errors(entry(start_line=[1]), entry(start_line=[1])))


class Files(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def write(self, text, name="a.json", binary=False):
        path = os.path.join(self.tmp.name, name)
        with open(path, "wb" if binary else "w", **({} if binary else {"encoding": "utf-8", "newline": ""})) as handle:
            handle.write(text)
        return path

    def load(self, text):
        return sa.load_allowlist(self.write(text), TODAY)

    def test_a_missing_file_means_no_allowlist(self):
        self.assertEqual(sa.load_allowlist(os.path.join(self.tmp.name, "nope.json"), TODAY), [])

    def test_a_valid_file_loads(self):
        self.assertEqual(self.load(json.dumps({"allowlist": [entry()]})), [entry()])
        self.assertEqual(self.load('{"allowlist": []}'), [])
        self.assertEqual(len(self.load(chr(0xfeff) + json.dumps({"allowlist": [entry()]}))), 1)

    def test_everything_else_is_refused(self):
        good = json.dumps(entry())
        for label, text in {
            "empty": "", "blank": " \n", "not json": "x", "list": "[]", "object without key": "{}",
            "other key": '{"other": []}', "extra key": '{"allowlist": [], "x": 1}', "null": "null",
            "allowlist not a list": '{"allowlist": {}}', "trailing text": '{"allowlist": []} x',
            "the vulnerability exceptions shape": json.dumps({"exceptions": [entry()]}),
            "both keys": '{"allowlist": [], "exceptions": []}',
            "duplicate top-level key": '{"allowlist": [], "allowlist": []}',
            "duplicate entry key": '{"allowlist": [' + good[:-1] + ', "rule": "other-rule"}]}',
            "NaN": '{"allowlist": [NaN]}', "deep nesting": "[" * 100000,
            "invalid entry": json.dumps({"allowlist": [entry(target="*")]}),
            "one bad among good": json.dumps({"allowlist": [entry(), entry(start_line=43, evidence="http://x.example")]}),
            "too many": json.dumps({"allowlist": [entry(start_line=i + 1) for i in range(sa.ie.MAX_ENTRIES + 1)]}),
        }.items():
            with self.subTest(label):
                with self.assertRaises(sa.AllowlistError):
                    self.load(text)

    def test_the_two_files_are_not_interchangeable(self):
        exceptions = self.write(json.dumps({"exceptions": [{"image": "x"}]}), "e.json")
        with self.assertRaises(sa.AllowlistError):
            sa.load_allowlist(exceptions, TODAY)
        allowlist = self.write(json.dumps({"allowlist": [entry()]}), "a2.json")
        with self.assertRaises(sa.ie.ExceptionsError):
            sa.ie.load_exceptions(allowlist, TODAY)

    def test_invalid_utf8_and_oversize_files_are_refused(self):
        with self.assertRaises(sa.AllowlistError):
            sa.load_allowlist(self.write(b'{"allowlist": ["\xff"]}', binary=True), TODAY)
        with self.assertRaises(sa.AllowlistError):
            sa.load_allowlist(self.write(b" " * (sa.ie.MAX_BYTES + 1), "big.json", binary=True), TODAY)

    def test_a_directory_is_refused(self):
        os.mkdir(os.path.join(self.tmp.name, "d.json"))
        with self.assertRaises(sa.AllowlistError):
            sa.load_allowlist(os.path.join(self.tmp.name, "d.json"), TODAY)

    def test_a_symlink_is_refused(self):
        target = self.write('{"allowlist": []}')
        link = os.path.join(self.tmp.name, "link.json")
        try:
            os.symlink(target, link)
        except (OSError, NotImplementedError):
            if os.name != "nt":
                raise
            self.skipTest("symlinks are not available here")
        with self.assertRaises(sa.AllowlistError):
            sa.load_allowlist(link, TODAY)


class Evaluate(unittest.TestCase):
    def test_a_live_bound_entry_allows_its_finding(self):
        v = evaluate([entry()], [finding()])
        self.assertEqual((len(v["allowed"]), v["failing"], v["expired"], v["stale"]), (1, [], [], []))

    def test_every_binding_must_match(self):
        # Each mismatch alone must make the finding fail, and leave the entry stale.
        mismatches = {
            "image": (dict(image="example/other"), {}),
            "digest": (dict(digest=OTHER), {}),
            "rule": (dict(rule="other-rule"), {}),
            "target": (dict(target="var/www/other.php"), {}),
            "layer": (dict(layer_diff_id=OTHER_LAYER), {}),
            "line": (dict(start_line=43), {}),
            "match hash": (dict(match_sha256=OTHER_MATCH), {}),
            "finding rule": ({}, dict(raw_rule="other-rule")),
            "finding target": ({}, dict(raw_target="var/www/other.php")),
            "finding layer": ({}, dict(raw_diff_id=OTHER_LAYER)),
            "finding line": ({}, dict(raw_line=43)),
            "finding match": (dict(match_sha256=MATCH), dict(match_sha256=OTHER_MATCH)),
            "finding without a match line": (dict(match_sha256=MATCH), dict(match_sha256=None)),
        }
        for label, (entry_change, finding_change) in mismatches.items():
            with self.subTest(label):
                v = evaluate([entry(**entry_change)], [finding(**finding_change)])
                self.assertEqual(len(v["failing"]), 1)
                self.assertEqual(v["allowed"], [])
                if label != "image":
                    self.assertEqual(len(v["stale"]), 1)

    def test_a_finding_without_the_trivy_values_is_never_allowed(self):
        for key in ("raw_rule", "raw_target", "raw_diff_id", "raw_line"):
            with self.subTest(key):
                self.assertEqual(len(evaluate([entry()], [finding(**{key: None})])["failing"]), 1)
        self.assertEqual(len(evaluate([entry()], [{"rule": RULE, "target": TARGET, "line": "42", "layer": LAYER}])["failing"]), 1)

    def test_the_display_copy_does_not_count(self):
        # clean() maps "a|b" to "a/b" and drops a trailing space: only the raw Trivy string decides.
        shown = finding(target="a/b", raw_target="a|b")
        self.assertEqual(len(evaluate([entry(target="a/b")], [shown])["failing"]), 1)
        shown = finding(target="var/www/a.php", raw_target="var/www/a.php ")
        self.assertEqual(len(evaluate([entry(target="var/www/a.php")], [shown])["failing"]), 1)
        self.assertEqual(len(evaluate([entry(target="a/b")], [finding(target="a|b", raw_target="a/b")])["allowed"]), 1)

    def test_a_tag_only_image_is_never_allowed(self):
        v = evaluate([entry()], [finding()], digest=None)
        self.assertEqual((len(v["failing"]), v["allowed"]), (1, []))
        self.assertIn("no digest", v["stale"][0][1])

    def test_a_matching_hash_allows_and_no_hash_means_the_content_is_not_pinned(self):
        self.assertEqual(len(evaluate([entry(match_sha256=MATCH)], [finding()])["allowed"]), 1)
        self.assertEqual(len(evaluate([entry()], [finding(match_sha256=OTHER_MATCH)])["allowed"]), 1)
        self.assertEqual(len(evaluate([entry()], [finding(match_sha256=None)])["allowed"]), 1)

    def test_one_entry_allows_one_finding_only(self):
        v = evaluate([entry()], [finding(), finding()])
        self.assertEqual((len(v["allowed"]), len(v["failing"])), (1, 1))

    def test_two_findings_on_one_line_are_told_apart_by_their_hash(self):
        entries = [entry(match_sha256=MATCH), entry(match_sha256=OTHER_MATCH)]
        v = evaluate(entries, [finding(), finding(match_sha256=OTHER_MATCH)])
        self.assertEqual((len(v["allowed"]), v["failing"], v["stale"]), (2, [], []))
        v = evaluate(entries, [finding(), finding(match_sha256="sha256:" + "1" * 64)])
        self.assertEqual((len(v["allowed"]), len(v["failing"]), len(v["stale"])), (1, 1, 1))

    def test_a_secret_in_another_file_or_layer_of_the_same_image_still_fails(self):
        v = evaluate([entry()], [finding(), finding(raw_target="var/www/other.php", target="var/www/other.php"),
                                 finding(raw_diff_id=OTHER_LAYER, layer=OTHER_LAYER), finding(raw_line=43, line="43")])
        self.assertEqual(len(v["allowed"]), 1)
        self.assertEqual([f["raw_target"] for f in v["failing"]],
                         ["var/www/other.php", TARGET, TARGET])
        self.assertEqual([f["raw_diff_id"] for f in v["failing"]], [LAYER, OTHER_LAYER, LAYER])

    def test_an_entry_for_another_image_is_ignored_and_not_stale_here(self):
        v = evaluate([entry(image="example/other")], [finding()])
        self.assertEqual((len(v["failing"]), v["stale"]), (1, []))

    def test_an_expired_entry_fails_and_does_not_allow(self):
        v = evaluate([entry(expires="2026-10-31")], [finding()])
        self.assertEqual((len(v["failing"]), len(v["expired"]), v["allowed"]), (1, 1, []))

    def test_an_expired_entry_is_reported_for_any_image_and_when_it_matches_nothing(self):
        self.assertEqual(len(evaluate([entry(image="example/other", expires="2026-10-31")], [])["expired"]), 1)
        self.assertEqual(len(evaluate([entry(expires="2026-10-31")], [])["expired"]), 1)

    def test_the_expiry_day_is_still_live(self):
        v = evaluate([entry(expires="2026-11-01")], [finding()])
        self.assertEqual((len(v["allowed"]), v["expired"]), (1, []))

    def test_a_stale_entry_is_reported(self):
        v = evaluate([entry()], [])
        self.assertEqual(len(v["stale"]), 1)
        self.assertIn("no longer matches", v["stale"][0][1])
        v = evaluate([entry(digest=OTHER)], [finding()])
        self.assertIn("another digest", v["stale"][0][1])

    def test_no_entries_no_allowance(self):
        v = evaluate([], [finding()])
        self.assertEqual((len(v["failing"]), v["allowed"], v["stale"], v["expired"]), (1, [], [], []))


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
        code = sa.main(["generate-secrets", *args], out, err, today)
        return code, out.getvalue(), err.getvalue()

    def default_report(self):
        return self.save(sreport([leak(), leak(rule="other-rule", line=7), leak(diff=OTHER_LAYER, line=9)]))

    def test_a_draft_has_no_reason_evidence_reviewer_or_dates_unless_given(self):
        code, out, err = self.run_generate("--scan", REF, self.default_report())
        self.assertEqual(code, 0, err)
        entries = json.loads(out)["allowlist"]
        self.assertEqual([(e["rule"], e["start_line"], e["layer_diff_id"]) for e in entries],
                         [(RULE, 9, OTHER_LAYER), (RULE, 42, LAYER), ("other-rule", 7, LAYER)])
        for e in entries:
            self.assertEqual((e["image"], e["digest"], e["target"]), ("example/app", DIGEST, TARGET))
            self.assertEqual((e["reason"], e["evidence"], e["reviewer"], e["reviewed"], e["expires"]), ("", "", "", "", ""))
            self.assertRegex(e["match_sha256"], r"^sha256:[0-9a-f]{64}$")
        self.assertTrue(sa.schema_errors(entries, TODAY))
        self.assertIn("3 draft entries", err)

    def test_the_draft_uses_the_layer_diff_id_not_the_compressed_digest(self):
        _, out, _ = self.run_generate("--scan", REF, self.save(sreport([leak()])))
        entry_ = json.loads(out)["allowlist"][0]
        self.assertEqual(entry_["layer_diff_id"], LAYER)
        self.assertNotIn("9" * 64, out)

    def test_nothing_defaults_to_today(self):
        code, out, _ = self.run_generate("--scan", REF, self.default_report(), "--reviewer", "reviewer-one")
        for e in json.loads(out)["allowlist"]:
            self.assertEqual((e["reviewed"], e["expires"]), ("", ""))
            self.assertNotIn(TODAY.isoformat(), json.dumps(e))

    def test_given_values_are_used_and_the_draft_then_validates_and_allows(self):
        code, out, err = self.run_generate(
            "--scan", REF, self.save(sreport([leak()])), "--reason", REASON, "--evidence", EVIDENCE,
            "--reviewer", "reviewer-one", "--reviewed", "2026-10-27")
        self.assertEqual(code, 0, err)
        entries = json.loads(out)["allowlist"]
        self.assertEqual({(e["reviewer"], e["reviewed"], e["expires"], e["evidence"]) for e in entries},
                         {("reviewer-one", "2026-10-27", "2026-11-27", EVIDENCE)})
        self.assertEqual(sa.schema_errors(entries, TODAY), [])
        h = entries[0]["match_sha256"]
        self.assertEqual(len(evaluate(entries, [finding(match_sha256=h)])["allowed"]), 1)
        self.assertEqual(len(evaluate(entries, [finding(match_sha256=OTHER_MATCH)])["failing"]), 1)

    def test_a_partial_draft_does_not_validate(self):
        _, out, _ = self.run_generate("--scan", REF, self.save(sreport([leak()])), "--reviewer", "reviewer-one",
                                      "--reviewed", "2026-10-27")
        errors = sa.schema_errors(json.loads(out)["allowlist"], TODAY)
        self.assertTrue(errors)
        self.assertTrue(all(("reason" in line or "evidence" in line) for line in errors), errors)

    def test_the_matched_text_is_never_printed_or_stored(self):
        data = sreport([leak(match="AccountKey=*****TOPSECRETVALUE", Code={"Lines": [{"Content": "TOPSECRETVALUE"}]})])
        code, out, err = self.run_generate("--scan", REF, self.save(data))
        self.assertEqual(code, 0)
        self.assertNotIn("TOPSECRETVALUE", out + err)
        self.assertNotIn("AccountKey", out + err)

    def test_days_sets_the_expiry(self):
        _, out, _ = self.run_generate("--scan", REF, self.default_report(), "--reviewed", "2026-10-27", "--days", "7")
        self.assertEqual({e["expires"] for e in json.loads(out)["allowlist"]}, {"2026-11-03"})

    def test_bad_options_fail(self):
        report_path = self.default_report()
        for label, args in {
            "future reviewed": ["--reviewed", "2026-11-02"],
            "bad reviewed": ["--reviewed", "yesterday"],
            "days over the cap": ["--reviewed", "2026-10-27", "--days", "32"],
            "negative days": ["--reviewed", "2026-10-27", "--days", "-1"],
            "bad reviewer": ["--reviewer", "::error::x"],
            "short reason": ["--reason", "no"],
            "http evidence": ["--evidence", "http://example.org/x"],
            "evidence with credentials": ["--evidence", "https://u:p@example.org/x"],
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
                            "secrets as object": {**sreport(), "Results": [{"Target": "t", "Secrets": {"a": 1}}]},
                            "results as string": {**sreport(), "Results": "x"}}.items():
            with self.subTest(label):
                code, out, err = self.run_generate("--scan", REF, self.save(data))
                self.assertEqual((code, out), (2, ""))
        self.assertEqual(self.run_generate("--scan", REF, self.path("missing.json"))[0], 2)

    def test_a_finding_without_a_layer_or_line_is_skipped_with_a_note(self):
        data = sreport([leak(diff=None), leak(line="x"), leak(line=True), leak(diff="latest"), leak(line=5)])
        code, out, err = self.run_generate("--scan", REF, self.save(data))
        self.assertEqual(code, 0, err)
        self.assertEqual([e["start_line"] for e in json.loads(out)["allowlist"]], [5])
        self.assertEqual(err.count("skipped"), 4)
        self.assertIn("cannot be allowlisted", err)

    def test_vulnerabilities_in_a_report_never_become_entries(self):
        data = sreport([leak()])
        data["Results"].append({"Target": "app (debian 12)", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-2026-0001", "PkgName": "libfoo", "Severity": "HIGH", "FixedVersion": "2"}]})
        _, out, err = self.run_generate("--scan", REF, self.save(data))
        self.assertEqual([e["rule"] for e in json.loads(out)["allowlist"]], [RULE])
        self.assertNotIn("CVE-2026-0001", out + err)

    def test_repeated_findings_are_listed_once_and_several_images_are_sorted(self):
        two = sreport([leak(), leak()])
        other = sreport([leak(line=3)], OTHER, "example/zzz")
        code, out, err = self.run_generate("--scan", REF, self.save(two), "--scan", "example/zzz:1@" + OTHER,
                                           self.save(other, "r2.json"))
        self.assertEqual(code, 0, err)
        self.assertEqual([(e["image"], e["start_line"]) for e in json.loads(out)["allowlist"]],
                         [("example/app", 42), ("example/zzz", 3)])

    def test_the_output_goes_to_a_new_file_and_never_over_an_existing_one(self):
        target = self.path("draft.json")
        code, out, err = self.run_generate("--scan", REF, self.default_report(), "--output", target)
        self.assertEqual((code, out), (0, ""))
        with open(target, encoding="utf-8") as handle:
            self.assertEqual(len(json.load(handle)["allowlist"]), 3)
        live = self.path("image-secret-allowlist.json")
        with open(live, "w", encoding="utf-8") as handle:
            handle.write('{"allowlist": []}')
        for path in (live, target):
            code, out, err = self.run_generate("--scan", REF, self.default_report(), "--output", path)
            self.assertEqual(code, 2)
            self.assertIn("never overwrites", err)
        with open(live, encoding="utf-8") as handle:
            self.assertEqual(handle.read(), '{"allowlist": []}')

    def test_the_draft_goes_to_stdout_by_default_and_writes_no_file(self):
        report_path = self.default_report()
        before = set(os.listdir(self.tmp.name))
        self.run_generate("--scan", REF, report_path)
        self.assertEqual(set(os.listdir(self.tmp.name)), before)

    def test_hostile_text_in_the_notes_cannot_make_a_workflow_command(self):
        data = sreport([leak()], target="t\n::error::x")
        code, out, err = self.run_generate("--scan", REF, self.save(data))
        self.assertEqual(code, 0, err)
        for line in err.splitlines():
            self.assertFalse(line.lstrip().startswith("::"), line)


class Cli(unittest.TestCase):
    """The script as it is run by hand: python3 -I."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def run_cli(self, *args):
        return subprocess.run([sys.executable, "-I", SCRIPT, *args], capture_output=True, text=True, cwd=self.tmp.name)

    def test_validate_and_generate_secrets_under_isolated_mode(self):
        live = os.path.join(self.tmp.name, "live.json")
        with open(live, "w", encoding="utf-8") as handle:
            json.dump({"allowlist": [entry()]}, handle)
        result = self.run_cli("validate", live)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("ok: 1 entries", result.stdout)
        with open(os.path.join(self.tmp.name, "r.json"), "w", encoding="utf-8") as handle:
            json.dump(sreport([leak()]), handle)
        result = self.run_cli("generate-secrets", "--scan", REF, "r.json")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["allowlist"][0]["rule"], RULE)
        self.assertEqual(self.run_cli("validate", "missing.json").returncode, 1)
        self.assertEqual(self.run_cli().returncode, 2)
        self.assertEqual(self.run_cli("nope").returncode, 2)
        self.assertEqual(self.run_cli("generate", "--scan", REF, "r.json").returncode, 2)

    def test_a_vulnerability_exceptions_file_is_not_a_valid_allowlist(self):
        path = os.path.join(self.tmp.name, "e.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump({"exceptions": []}, handle)
        self.assertEqual(self.run_cli("validate", path).returncode, 1)

    def test_a_planted_module_in_the_working_directory_is_not_imported(self):
        for planted in ("json.py", "image_exceptions.py", "trivy_images.py"):
            with open(os.path.join(self.tmp.name, planted), "w", encoding="utf-8") as handle:
                handle.write("raise SystemExit(99)\n")
        with open(os.path.join(self.tmp.name, "a.json"), "w", encoding="utf-8") as handle:
            handle.write('{"allowlist": []}')
        self.assertEqual(self.run_cli("validate", "a.json").returncode, 0)

    def test_a_future_review_date_is_refused_by_validate(self):
        future = (datetime.datetime.now(datetime.timezone.utc).date() + datetime.timedelta(days=2)).isoformat()
        path = os.path.join(self.tmp.name, "f.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump({"allowlist": [entry(reviewed=future, expires=future)]}, handle)
        result = self.run_cli("validate", path)
        self.assertEqual(result.returncode, 1)
        self.assertIn("in the future", result.stderr)


# ---------------------------------------------------------------- mutation checks


def probes(m):
    """The engine's promises, each True when kept. A mutated engine must break at least one."""
    ev = lambda entries, findings, digest=DIGEST, repo="example/app": m.evaluate(entries, repo, digest, findings, TODAY, "no digest")
    errs = lambda *entries: m.schema_errors(list(entries), TODAY)
    failing = lambda entries, findings, **kw: len(ev(entries, findings, **kw)["failing"]) == 1
    kept = {}

    def attempt(name, check):
        try:
            kept[name] = bool(check())
        except Exception:  # a crashing engine has broken the promise
            kept[name] = False

    attempt("valid entry is accepted", lambda: errs(entry()) == [] and errs(entry(match_sha256=MATCH)) == [])
    attempt("allows the exact finding", lambda: len(ev([entry()], [finding()])["allowed"]) == 1)
    attempt("digest binding", lambda: failing([entry(digest=OTHER)], [finding()]))
    attempt("tag-only never allowed", lambda: failing([entry()], [finding()], digest=None))
    attempt("image binding", lambda: failing([entry(image="example/other")], [finding()]))
    attempt("rule binding", lambda: failing([entry()], [finding(raw_rule="other-rule")]))
    attempt("target binding", lambda: failing([entry()], [finding(raw_target="var/www/other.php")]))
    attempt("layer binding", lambda: failing([entry()], [finding(raw_diff_id=OTHER_LAYER)]))
    attempt("line binding", lambda: failing([entry()], [finding(raw_line=43)]))
    attempt("match hash binding", lambda: failing([entry(match_sha256=MATCH)], [finding(match_sha256=OTHER_MATCH)]))
    attempt("one entry one finding", lambda: len(ev([entry()], [finding(), finding()])["allowed"]) == 1)
    attempt("raw strings decide", lambda: failing([entry(target="a/b")], [finding(target="a/b", raw_target="a|b")])
            and failing([entry(rule="r-1")], [finding(rule="r-1", raw_rule="r-1 ")]))
    attempt("expired fails", lambda: len(ev([entry(expires="2026-10-31")], [])["expired"]) == 1)
    attempt("expired does not allow", lambda: failing([entry(expires="2026-10-31")], [finding()]))
    attempt("expiry day is live", lambda: len(ev([entry(expires="2026-11-01")], [finding()])["allowed"]) == 1)
    attempt("stale is reported", lambda: len(ev([entry()], [])["stale"]) == 1)
    attempt("reviewed after today", lambda: bool(errs(entry(reviewed="2026-11-02", expires="2026-11-10"))))
    attempt("expires before reviewed", lambda: bool(errs(entry(expires="2026-10-24"))))
    attempt("31 day cap", lambda: bool(errs(entry(reviewed="2026-10-01", expires="2026-11-02")))
            and errs(entry(reviewed="2026-10-01", expires="2026-11-01")) == [])
    attempt("no wildcards", lambda: bool(errs(entry(target="var/*"))) and bool(errs(entry(image="example/*")))
            and bool(errs(entry(rule="azure-*"))) and bool(errs(entry(layer_diff_id="sha256:" + "c" * 63 + "*"))))
    attempt("digest format", lambda: bool(errs(entry(digest="latest"))) and bool(errs(entry(layer_diff_id="latest"))))
    attempt("line is a whole number", lambda: bool(errs(entry(start_line=True))) and bool(errs(entry(start_line="42")))
            and bool(errs(entry(start_line=0))))
    attempt("evidence required", lambda: bool(errs({k: v for k, v in entry().items() if k != "evidence"})))
    attempt("evidence not empty", lambda: bool(errs(entry(evidence=""))))
    attempt("evidence https only", lambda: bool(errs(entry(evidence="http://example.org/x")))
            and bool(errs(entry(evidence="javascript:alert(1)"))))
    attempt("evidence without credentials", lambda: bool(errs(entry(evidence="https://u:p@example.org/x"))))
    attempt("reviewer required", lambda: bool(errs(entry(reviewer=""))))
    attempt("reason required", lambda: bool(errs(entry(reason=""))))
    attempt("duplicates rejected", lambda: bool(errs(entry(), entry())) and bool(errs(entry(), entry(match_sha256=MATCH))))
    attempt("extra field refused", lambda: bool(errs(entry(note="x"))) and bool(errs(entry(id="CVE-2026-0001"))))

    def missing_file():
        with tempfile.TemporaryDirectory() as tmp:
            return m.load_allowlist(os.path.join(tmp, "none.json"), TODAY) == []
    attempt("missing file is no allowlist", missing_file)

    def exceptions_shape_refused():
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "e.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump({"exceptions": []}, handle)
            try:
                m.load_allowlist(path, TODAY)
            except m.AllowlistError:
                return True
            return False
    attempt("exceptions file shape refused", exceptions_shape_refused)

    def with_report(args, check):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "r.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(sreport([leak(match="AccountKey=*****TOPSECRETVALUE")]), handle)
            out, err = io.StringIO(), io.StringIO()
            code = m.main(["generate-secrets", "--scan", *args(path)], out, err, TODAY)
            return check(code, out.getvalue(), err.getvalue(), tmp)

    def draft_defaults(code, out, err, tmp):
        e = json.loads(out)["allowlist"][0]
        return code == 0 and (e["reviewed"], e["expires"], e["reviewer"], e["reason"], e["evidence"]) == ("", "", "", "", "")
    attempt("generate sets nothing silently", lambda: with_report(lambda p: [REF, p], draft_defaults))
    attempt("generate never prints the match text",
            lambda: with_report(lambda p: [REF, p], lambda code, out, err, tmp: code == 0 and "TOPSECRETVALUE" not in out + err))
    attempt("generate needs a digest",
            lambda: with_report(lambda p: ["example/app:1.2.3", p], lambda code, out, err, tmp: code == 2))
    attempt("generate checks the report digest",
            lambda: with_report(lambda p: ["example/app@" + OTHER, p], lambda code, out, err, tmp: code == 2))

    def no_overwrite():
        with tempfile.TemporaryDirectory() as tmp:
            path, target = os.path.join(tmp, "r.json"), os.path.join(tmp, "live.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(sreport([leak()]), handle)
            with open(target, "w", encoding="utf-8") as handle:
                handle.write("keep")
            code = m.main(["generate-secrets", "--scan", REF, path, "--output", target], io.StringIO(), io.StringIO(), TODAY)
            with open(target, encoding="utf-8") as handle:
                return code == 2 and handle.read() == "keep"
    attempt("generate never overwrites", no_overwrite)
    return kept


MUTATIONS = [
    # (name, [(old, new)], the promise it must break)
    ("digest ignored", [('if e["digest"] == digest:', "if True:")], "digest binding"),
    ("unknown digest matches any entry", [("if digest is not None:\n        for e in mine:", "if True:\n        for e in mine:"),
                                          ('if e["digest"] == digest:', 'if digest is None or e["digest"] == digest:')],
     "tag-only never allowed"),
    ("image ignored", [(' and e["image"] == repository]', "]")], "image binding"),
    ("rule ignored", [('return (entry["rule"], entry["target"], entry["layer_diff_id"], entry["start_line"])',
                       'return (entry["target"], entry["layer_diff_id"], entry["start_line"])'),
                      ('return (finding.get("raw_rule"), finding.get("raw_target"), finding.get("raw_diff_id"), finding.get("raw_line"))',
                       'return (finding.get("raw_target"), finding.get("raw_diff_id"), finding.get("raw_line"))')], "rule binding"),
    ("target ignored", [('return (entry["rule"], entry["target"], entry["layer_diff_id"], entry["start_line"])',
                         'return (entry["rule"], entry["layer_diff_id"], entry["start_line"])'),
                        ('return (finding.get("raw_rule"), finding.get("raw_target"), finding.get("raw_diff_id"), finding.get("raw_line"))',
                         'return (finding.get("raw_rule"), finding.get("raw_diff_id"), finding.get("raw_line"))')], "target binding"),
    ("layer ignored", [('return (entry["rule"], entry["target"], entry["layer_diff_id"], entry["start_line"])',
                        'return (entry["rule"], entry["target"], entry["start_line"])'),
                       ('return (finding.get("raw_rule"), finding.get("raw_target"), finding.get("raw_diff_id"), finding.get("raw_line"))',
                        'return (finding.get("raw_rule"), finding.get("raw_target"), finding.get("raw_line"))')], "layer binding"),
    ("line ignored", [('return (entry["rule"], entry["target"], entry["layer_diff_id"], entry["start_line"])',
                       'return (entry["rule"], entry["target"], entry["layer_diff_id"])'),
                      ('return (finding.get("raw_rule"), finding.get("raw_target"), finding.get("raw_diff_id"), finding.get("raw_line"))',
                       'return (finding.get("raw_rule"), finding.get("raw_target"), finding.get("raw_diff_id"))')], "line binding"),
    ("match hash ignored", [('if e.get("match_sha256") is not None and e["match_sha256"] != finding.get("match_sha256"):', "if False:")],
     "match hash binding"),
    ("an entry can be used twice", [("if id(e) in used:\n                continue", "if False:\n                continue")], "one entry one finding"),
    ("cleaned copy matched", [('finding.get("raw_target"), finding.get("raw_diff_id"), finding.get("raw_line"))',
                              'finding.get("target"), finding.get("raw_diff_id"), finding.get("raw_line"))'),
                              ('return (finding.get("raw_rule"),', 'return (finding.get("rule"),')], "raw strings decide"),
    ("expired not reported", [('expired = [e for e in entries if parse_date(e["expires"]) < today]', "expired = []")], "expired fails"),
    ("expired still live", [('parse_date(e["expires"]) >= today and e["image"] == repository', 'e["image"] == repository')],
     "expired does not allow"),
    ("expiry day expired", [('parse_date(e["expires"]) >= today', 'parse_date(e["expires"]) > today')], "expiry day is live"),
    ("stale not reported", [("stale.append((entry, why))", "pass")], "stale is reported"),
    ("future review allowed", [("if reviewed > today:\n                errors.append(", "if False:\n                errors.append(")],
     "reviewed after today"),
    ("expires before review allowed", [("if expires < reviewed:", "if False:")], "expires before reviewed"),
    ("cap raised", [("MAX_DAYS = ie.MAX_DAYS", "MAX_DAYS = 93")], "31 day cap"),
    ("wildcards allowed", [("if key in text and ie.WILDCARD.search(text[key]):", "if False:"),
                           ('TARGET = re.compile(r"[\\x21-\\x7e](?:[\\x20-\\x7e]*[\\x21-\\x7e])?", re.ASCII)', 'TARGET = re.compile(r".+", re.ASCII)'),
                           ('RULE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*", re.ASCII)', 'RULE = re.compile(r".+", re.ASCII)'),
                           ('if value is not None and not ie.DIGEST.fullmatch(value):', "if False:"),
                           ("(len(image) > 255 or not ie.IMAGE.fullmatch(image) or", "(len(image) > 255 or")], "no wildcards"),
    ("any digest string", [("if value is not None and not ie.DIGEST.fullmatch(value):", "if False:")], "digest format"),
    ("line type loose", [("isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= MAX_LINE", "True")],
     "line is a whole number"),
    ("evidence optional", [('"reason", "evidence", "reviewer", "reviewed", "expires")', '"reason", "reviewer", "reviewed", "expires")')],
     "evidence required"),
    ("empty evidence allowed", [("if not isinstance(entry[key], str) or not entry[key].strip():", "if not isinstance(entry[key], str):"),
                                ("if evidence is not None and not _evidence_ok(evidence):", "if False:")], "evidence not empty"),
    ("any evidence scheme", [("if not ie.TRACKING.fullmatch(url):", "if not url:")], "evidence https only"),
    ("evidence credentials allowed", [('return bool(authority) and "@" not in authority', "return True")], "evidence without credentials"),
    ("empty reviewer allowed", [("if not isinstance(entry[key], str) or not entry[key].strip():", "if not isinstance(entry[key], str):")],
     "reviewer required"),
    ("empty reason allowed", [("if not isinstance(entry[key], str) or not entry[key].strip():", "if not isinstance(entry[key], str):")],
     "reason required"),
    ("duplicates allowed", [("if None in hashes or len(set(map(repr, hashes))) != len(hashes):", "if False:")], "duplicates rejected"),
    ("unknown fields allowed", [("keys - set(REQUIRED) - set(OPTIONAL) or set(REQUIRED) - keys", "set(REQUIRED) - keys")],
     "extra field refused"),
    ("missing file is an error", [("if not os.path.lexists(path):\n        return []", "if False:\n        return []")],
     "missing file is no allowlist"),
    ("exceptions shape accepted", [('TOP_KEY = "allowlist"', 'TOP_KEY = "exceptions"')], "exceptions file shape refused"),
    ("draft sets today", [('"reviewed": "" if reviewed is None else reviewed.isoformat(), "expires": expires,',
                           '"reviewed": (reviewed or today_utc()).isoformat(), "expires": expires,')], "generate sets nothing silently"),
    ("draft prints the match line", [('notes.append("%s (layer %s)" % (where, finding["layer"][:19]))',
                                      'notes.append("%s %s" % (data["Results"][0]["Secrets"][0]["Match"], where))')],
     "generate never prints the match text"),
    ("draft overwrites", [('open(args.output, "x"', 'open(args.output, "w"')], "generate never overwrites"),
    ("draft accepts a tag", [("if digest is None:\n                raise AllowlistError", "if False:\n                raise AllowlistError"),
                             ("if digest not in report_digests(data):", "if False:")], "generate needs a digest"),
    ("draft ignores the report digest", [("if digest not in report_digests(data):", "if False:")], "generate checks the report digest"),
]


class Mutations(unittest.TestCase):
    """A schema or engine that is loosened must fail these tests, not pass silently."""

    @classmethod
    def setUpClass(cls):
        with open(SCRIPT, encoding="utf-8") as handle:
            cls.source = handle.read()

    def test_the_real_engine_keeps_every_promise(self):
        broken = [name for name, ok in probes(sa).items() if not ok]
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
        unattacked = [name for name in probes(sa) if name not in attacked]
        self.assertEqual(unattacked, ["valid entry is accepted", "allows the exact finding"])  # the positive controls

    def test_the_schema_rejects_each_mutated_copy_of_a_good_file(self):
        good = {"allowlist": [entry(), entry(start_line=43)]}
        mutations = {
            "wildcard-target": lambda e: e[0].update(target="var/www/*"),
            "wildcard-image": lambda e: e[0].update(image="*"),
            "too-long": lambda e: e[0].update(reviewed="2026-01-01", expires="2026-03-01"),
            "no-reason": lambda e: e[0].pop("reason"),
            "no-evidence": lambda e: e[0].pop("evidence"),
            "http-evidence": lambda e: e[0].update(evidence="http://example.org/x"),
            "no-reviewer": lambda e: e[0].pop("reviewer"),
            "no-digest": lambda e: e[0].pop("digest"),
            "no-layer": lambda e: e[0].pop("layer_diff_id"),
            "no-line": lambda e: e[0].pop("start_line"),
            "no-target": lambda e: e[0].pop("target"),
            "no-rule": lambda e: e[0].pop("rule"),
            "tag-not-digest": lambda e: e[0].update(digest="1.2.3"),
            "duplicate": lambda e: e.append(copy.deepcopy(e[0])),
            "bad-date": lambda e: e[0].update(expires="soon"),
            "expires-before-reviewed": lambda e: e[0].update(expires="2026-10-01"),
            "reviewed-in-the-future": lambda e: e[0].update(reviewed="2999-01-01", expires="2999-01-02"),
            "vulnerability-id": lambda e: e[0].update(id="CVE-2026-0001"),
        }
        with tempfile.TemporaryDirectory() as tmp:
            def run(name, mutate):
                data = copy.deepcopy(good)
                mutate(data["allowlist"])
                path = os.path.join(tmp, "allowlist-%s.json" % name)
                with open(path, "w", encoding="utf-8") as handle:
                    json.dump(data, handle)
                return subprocess.run([sys.executable, "-I", SCRIPT, "validate", path], capture_output=True).returncode

            # The real clock is used by the command, so the unmutated copy needs dates that are valid on any day.
            good["allowlist"] = [dict(e, reviewed="2026-10-25", expires="2026-11-20") for e in good["allowlist"]]
            self.assertEqual(run("ok", lambda e: None), 0, "the unmutated copy must pass")
            for name, mutate in mutations.items():
                with self.subTest(name):
                    self.assertNotEqual(run(name, mutate), 0)


# ---------------------------------------------------------------- scope


def code_of(text):
    return "\n".join(line for line in text.replace("\r\n", "\n").split("\n") if not line.lstrip().startswith("#"))


MENTION = r"image[-_]secret[-_]allowlist|secret-allowlist-file|SECRET_ALLOWLIST"


def violations(workflows):
    """Where the secret allowlist is read other than by trivy-images.yml, or not read there."""
    found = []
    for name, text in workflows.items():
        code = code_of(text)
        if name == "trivy-images.yml":
            if not re.search(r"python3 -I \.strange-security/scripts/trivy_images\.py gate\b", code):
                found.append("trivy-images.yml does not run the gate script")
            if "--secret-allowlist-file" not in code:
                found.append("trivy-images.yml does not pass the secret allowlist file to the gate")
            if re.search(r"--ignorefile|TRIVY_IGNOREFILE|trivyignore|trivy\.yaml|--config\b", code):
                found.append("trivy-images.yml reads an ignore file or a Trivy config")
        elif re.search(MENTION, code):
            found.append("%s uses the secret allowlist" % name)
    return found


class Scope(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflows = {}
        for name in sorted(os.listdir(WORKFLOWS)):
            if name.endswith(".yml"):
                with open(os.path.join(WORKFLOWS, name), encoding="utf-8") as handle:
                    cls.workflows[name] = handle.read()

    def test_only_trivy_images_uses_the_allowlist(self):
        self.assertIn("trivy-images.yml", self.workflows)
        self.assertEqual(violations(self.workflows), [])

    def test_filesystem_gitleaks_semgrep_and_single_image_scans_never_see_it(self):
        for name in ("trivy.yml", "gitleaks.yml", "semgrep.yml", "trivy-image.yml", "security_gate.yml"):
            with self.subTest(name):
                self.assertIn(name, self.workflows)
                self.assertNotRegex(code_of(self.workflows[name]), MENTION)

    def test_the_filesystem_scan_and_gitleaks_stay_free_of_every_ignore_mechanism(self):
        for name in ("trivy.yml", "gitleaks.yml", "trivy-image.yml"):
            with self.subTest(name):
                self.assertNotRegex(code_of(self.workflows[name]), r"allowlist|exceptions-file|image-exceptions")

    def test_other_scripts_do_not_use_the_engine(self):
        for name in sorted(os.listdir(os.path.join(ROOT, "scripts"))):
            if name.endswith(".py") and name not in ("image_exceptions.py", "trivy_images.py", "image_secret_allowlist.py"):
                with open(os.path.join(ROOT, "scripts", name), encoding="utf-8") as handle:
                    self.assertNotRegex(handle.read(), r"image[-_]secret[-_]allowlist|secret.allowlist", name)

    def test_the_vulnerability_engine_does_not_know_the_allowlist(self):
        with open(os.path.join(ROOT, "scripts", "image_exceptions.py"), encoding="utf-8") as handle:
            code = code_of(handle.read())
        # It names the sibling only in prose; it never loads it or reads its file.
        self.assertNotIn("image_secret_allowlist.py\"", code)
        self.assertNotIn("allowlist\"", code)

    def test_a_committed_allowlist_of_this_repository_is_valid(self):
        path = os.path.join(ROOT, ".github", "image-secret-allowlist.json")
        if os.path.exists(path):
            sa.load_allowlist(path, sa.today_utc())

    def test_mutation_another_workflow_given_the_file_is_caught(self):
        for name in ("trivy.yml", "gitleaks.yml", "semgrep.yml", "trivy-image.yml"):
            with self.subTest(name):
                mutated = dict(self.workflows)
                mutated[name] += "\n          secret-allowlist-file: .github/image-secret-allowlist.json\n"
                self.assertTrue(violations(mutated))

    def test_mutation_the_image_workflow_without_the_flag_is_caught(self):
        mutated = dict(self.workflows)
        mutated["trivy-images.yml"] = mutated["trivy-images.yml"].replace("--secret-allowlist-file", "--other")
        self.assertTrue(violations(mutated))

    def test_mutation_the_image_workflow_given_an_ignore_file_is_caught(self):
        for extra in ("--ignorefile .trivyignore", "TRIVY_IGNOREFILE: x", "--config trivy.yaml"):
            with self.subTest(extra):
                mutated = dict(self.workflows)
                mutated["trivy-images.yml"] += "\n            " + extra + "\n"
                self.assertTrue(violations(mutated))

    def test_the_comments_that_name_the_file_are_not_violations(self):
        self.assertEqual(violations({"trivy-images.yml": "run: python3 -I .strange-security/scripts/trivy_images.py gate --secret-allowlist-file x\n",
                                     "trivy.yml": "# image-secret-allowlist is not read here\n"}), [])


class Docs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        def read(*parts):
            with open(os.path.join(ROOT, *parts), encoding="utf-8") as handle:
                return handle.read().replace("\r\n", "\n")
        cls.readme, cls.process, cls.suppressions = read("README.md"), read("docs", "IMAGE_EXCEPTIONS.md"), read("docs", "SUPPRESSIONS.md")

    def test_the_readme_example_is_a_valid_file(self):
        blocks = re.findall(r"```json\n(.*?)\n```", self.readme, re.S)
        examples = [json.loads(b) for b in blocks if '"allowlist"' in b]
        self.assertEqual(len(examples), 1)
        self.assertEqual(sa.schema_errors(examples[0]["allowlist"], datetime.date(2026, 11, 3)), [])

    def test_the_readme_documents_every_field(self):
        for key in sa.REQUIRED + sa.OPTIONAL:
            self.assertIn("| `%s` |" % key, self.readme)

    def test_the_policy_documents_say_what_they_must(self):
        self.assertIn("secret-allowlist-file", self.readme)
        self.assertIn("image-secret-allowlist.json", self.readme)
        for phrase in ("## Known-public secrets", "evidence", "rotate", "DiffID", "one finding", "generate-secrets",
                       "image_secret_allowlist.py", "never"):
            self.assertIn(phrase, self.process)
        self.assertIn("No suppressions, ever.", self.suppressions)
        for phrase in ("## Secrets", "allowlist", "evidence", "rotate", ".gitleaksignore", "filesystem"):
            self.assertIn(phrase, self.suppressions)

    def test_the_process_example_commands_are_valid_cli_usage(self):
        commands = re.findall(r"image_secret_allowlist\.py (validate|generate-secrets)", self.process)
        self.assertIn("validate", commands)
        self.assertIn("generate-secrets", commands)


if __name__ == "__main__":
    unittest.main()
