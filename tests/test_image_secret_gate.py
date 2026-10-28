"""The secret allowlist inside the image gate (scripts/trivy_images.py gate) and the
wiring of trivy-images.yml around it: what an entry allows, what it never allows,
the summary and the exit status. The engine alone is tested in
tests/test_image_secret_allowlist.py; the vulnerability exceptions in
tests/test_trivy_images.py.
"""
import datetime
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest

from tests.test_image_secret_allowlist import (
    DIGEST, EVIDENCE, LAYER, OTHER, OTHER_LAYER, REASON, REF, RULE, TARGET, TODAY, entry, leak, sreport)
from tests.test_inputs import input_block
from tests.test_trivy_images import SCRIPT, report, result, slurp, ti, vuln
from tests.test_workflows import read, step

ALLOWLIST = ".github/image-secret-allowlist.json"
EXCEPTIONS = ".github/image-exceptions.json"
HOSTILE = "|`::<img src=x onerror=y> (y) !i \\"


def vreport(*vulns, digest=DIGEST):
    """A vulnerability report of example/app, with the digest Trivy lists."""
    data = report(result(list(vulns))) if vulns else report()
    data["Metadata"] = {"RepoDigests": ["example/app@" + digest]}
    return data


class GateBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = self.tmp.name
        os.makedirs(os.path.join(self.dir, ".github"))

    def put(self, name, data):
        path = os.path.join(self.dir, name)
        with open(path, "w", encoding="utf-8", newline="") as handle:
            handle.write(data if isinstance(data, str) else json.dumps(data))
        return path

    def allowlist(self, entries):
        self.put(ALLOWLIST, {"allowlist": entries})

    def run_gate(self, secrets=None, vulns=None, entries=None, reference=REF, today=TODAY, allowlist=ALLOWLIST,
                 exceptions=EXCEPTIONS, secret_report=None):
        if entries is not None:
            self.allowlist(entries)
        sdata = secret_report if secret_report is not None else sreport(secrets or [])
        argv = ["gate", "--reference", reference, "--vuln", self.put("vuln.json", vulns if vulns is not None else vreport()),
                "--secret", self.put("secret.json", sdata), "--exceptions-file", exceptions,
                "--summary", os.path.join(self.dir, "summary.md")]
        if allowlist is not None:
            argv += ["--secret-allowlist-file", allowlist]
        out, err = io.StringIO(), io.StringIO()
        cwd = os.getcwd()
        os.chdir(self.dir)
        try:
            code = ti.main(argv, {}, out, err, today)
        finally:
            os.chdir(cwd)
        summary = os.path.join(self.dir, "summary.md")
        return code, out.getvalue(), err.getvalue(), slurp(summary) if os.path.exists(summary) else ""


class Allowed(GateBase):
    def test_a_listed_secret_passes_and_is_listed_separately(self):
        code, out, err, summary = self.run_gate([leak()], entries=[entry()])
        self.assertEqual((code, err), (0, ""))
        self.assertIn("passed: " + REF + " (0 excepted, 1 secrets allowlisted)", out)
        self.assertIn("allowlisted known-public CRITICAL %s in %s line 42, layer %s, until 2026-11-20, reviewed by reviewer-one"
                      % (RULE, TARGET, LAYER), out)
        self.assertNotIn("secret CRITICAL", out)
        self.assertIn("Passed", summary)
        self.assertIn("1 secret(s) are allowlisted as known public values", summary)
        self.assertIn("Allowlisted secrets", summary)
        row = [line for line in summary.splitlines() if line.startswith("| " + RULE)][0]
        for cell in (TARGET, "| 42 |", LAYER, "2026-11-20", "reviewer-one", "learn.microsoft.com", "Azurite"):
            self.assertIn(cell, row)
        self.assertEqual(row.count("|"), 9)
        # Not in the failing tables, not a failure.
        self.assertNotIn("| Severity | Rule | Title |", summary)
        self.assertNotIn("Failed", summary)

    def test_the_matched_text_is_never_printed(self):
        data = leak(match="AccountKey=*****TOPSECRETVALUE", Code={"Lines": [{"Content": "TOPSECRETVALUE"}]})
        for entries in ([entry()], []):
            code, out, err, summary = self.run_gate([data], entries=entries)
            self.assertEqual(code, 0 if entries else 1)
            for text in (out, err, summary):
                self.assertNotIn("TOPSECRETVALUE", text)
                self.assertNotIn("AccountKey", text)

    def test_the_hash_pins_the_content_of_the_line(self):
        h = ti.secret_findings(ti.results_of(sreport([leak()]), "secret"))[0]["match_sha256"]
        self.assertEqual(self.run_gate([leak()], entries=[entry(match_sha256=h)])[0], 0)
        code, out, *_ = self.run_gate([leak(match="AccountKey=*****changed")], entries=[entry(match_sha256=h)])
        self.assertEqual(code, 1)
        self.assertIn("secret CRITICAL " + RULE, out)
        self.assertIn("::warning::Stale secret allowlist entry (it no longer matches a finding)", out)

    def test_every_binding_must_match_in_the_gate(self):
        entry_changes = {
            "image": dict(image="example/other"),
            "digest": dict(digest=OTHER),
            "rule": dict(rule="other-rule"),
            "target": dict(target="var/www/other.php"),
            "layer": dict(layer_diff_id=OTHER_LAYER),
            "line": dict(start_line=43),
        }
        self.assertEqual(set(entry_changes), {"image", "digest", "rule", "target", "layer", "line"})
        for label, change in entry_changes.items():
            with self.subTest("entry " + label):
                code, out, err, summary = self.run_gate([leak()], entries=[entry(**change)])
                self.assertEqual(code, 1)
                self.assertIn("secret CRITICAL %s in %s line 42" % (RULE, TARGET), out)
                self.assertNotIn("allowlisted", out)
        for label, data in {"rule": leak(rule="other-rule"), "line": leak(line=43), "layer": leak(diff=OTHER_LAYER),
                            "no layer": leak(diff=None), "digest-only layer": leak(diff=None, Layer={"Digest": "sha256:" + "9" * 64})}.items():
            with self.subTest("finding " + label):
                code, out, *_ = self.run_gate([data], entries=[entry()])
                self.assertEqual(code, 1)
                self.assertNotIn("allowlisted", out)
        with self.subTest("finding target"):
            code, out, *_ = self.run_gate(secret_report=sreport([leak()], target="var/www/other.php"), entries=[entry()])
            self.assertEqual(code, 1)

    def test_a_secret_in_another_file_or_layer_of_the_same_image_still_fails(self):
        data = sreport([leak()])
        data["Results"].append({"Target": "var/www/other.php", "Class": "secret", "Secrets": [leak(), leak(diff=OTHER_LAYER)]})
        code, out, err, summary = self.run_gate(secret_report=data, entries=[entry()])
        self.assertEqual(code, 1)
        self.assertEqual(out.count("secret CRITICAL"), 2)
        self.assertEqual(out.count("allowlisted known-public"), 1)
        self.assertIn("secret CRITICAL %s in var/www/other.php line 42" % RULE, out)
        self.assertIn("2 secrets", err)
        self.assertIn("1 other secret(s) allowlisted", summary)

    def test_one_entry_allows_one_finding(self):
        code, out, err, _ = self.run_gate([leak(), leak()], entries=[entry()])
        self.assertEqual(code, 1)
        self.assertEqual((out.count("secret CRITICAL"), out.count("allowlisted known-public")), (1, 1))

    def test_a_secret_next_to_an_excepted_vulnerability(self):
        os.makedirs(os.path.join(self.dir, ".github"), exist_ok=True)
        self.put(EXCEPTIONS, {"exceptions": [{
            "image": "example/app", "digest": DIGEST, "id": "CVE-2026-0001", "package": "libfoo",
            "reason": "the vendor has not rebuilt the image", "reviewer": "reviewer-one",
            "reviewed": "2026-10-25", "expires": "2026-11-20"}]})
        code, out, err, summary = self.run_gate([leak()], vulns=vreport(vuln()), entries=[entry()])
        self.assertEqual((code, err), (0, ""))
        self.assertIn("excepted HIGH CVE-2026-0001 libfoo", out)
        self.assertIn("allowlisted known-public CRITICAL " + RULE, out)
        self.assertIn("1 fixable finding(s) are excepted, 1 secret(s) are allowlisted", summary)

    def test_the_tag_form_of_the_reference_with_a_digest_is_bound_the_same(self):
        for reference in ("example/app@" + DIGEST, "example/app:1.2.3@" + DIGEST):
            with self.subTest(reference):
                self.assertEqual(self.run_gate([leak()], entries=[entry()], reference=reference)[0], 0)

    def test_a_tag_only_reference_never_matches(self):
        code, out, err, summary = self.run_gate([leak()], entries=[entry()], reference="example/app:1.2.3")
        self.assertEqual(code, 1)
        self.assertNotIn("allowlisted", out)
        self.assertIn("Stale secret allowlist entry (cannot apply: the reference has no sha256 digest)", out)

    def test_a_secret_report_that_does_not_confirm_the_digest_gets_no_allowance(self):
        for digests in ((OTHER,), ()):
            with self.subTest(digests=digests):
                data = sreport([leak()])
                data["Metadata"] = {"RepoDigests": ["example/app@" + d for d in digests]}
                code, out, *_ = self.run_gate(secret_report=data, entries=[entry()])
                self.assertEqual(code, 1)
                self.assertIn("the Trivy secret report does not list the digest", out)
        data = sreport([leak()])
        del data["Metadata"]
        self.assertEqual(self.run_gate(secret_report=data, entries=[entry()])[0], 1)

    def test_the_vulnerability_report_digest_is_not_what_decides_for_secrets(self):
        code, *_ = self.run_gate([leak()], vulns=vreport(digest=OTHER), entries=[entry()])
        self.assertEqual(code, 0)


class Lifecycle(GateBase):
    def test_an_expired_entry_fails_even_when_the_image_is_clean(self):
        code, out, err, summary = self.run_gate([], entries=[entry(expires="2026-10-31")])
        self.assertEqual(code, 1)
        self.assertIn("::error::Secret allowlist entry expired on 2026-10-31", err)
        self.assertIn("1 expired secret allowlist entries", err)
        self.assertIn("Expired secret allowlist entries", summary)
        self.assertIn("Failed", summary)

    def test_an_expired_entry_fails_every_image_job_and_does_not_allow(self):
        code, out, err, _ = self.run_gate([], entries=[entry(image="example/other", expires="2026-10-31")])
        self.assertEqual(code, 1)
        self.assertIn("expired", err)
        code, out, err, _ = self.run_gate([leak()], entries=[entry(expires="2026-10-31")])
        self.assertEqual(code, 1)
        self.assertIn("secret CRITICAL", out)
        self.assertNotIn("allowlisted known-public", out)
        self.assertIn("1 secrets", err)

    def test_the_expiry_day_is_still_live(self):
        self.assertEqual(self.run_gate([leak()], entries=[entry(expires="2026-11-01")])[0], 0)

    def test_a_stale_entry_warns_without_failing(self):
        code, out, err, summary = self.run_gate([], entries=[entry()])
        self.assertEqual((code, err), (0, ""))
        self.assertIn("::warning::Stale secret allowlist entry (it no longer matches a finding)", out)
        self.assertIn("Stale secret allowlist entries", summary)

    def test_an_entry_for_another_digest_is_stale_and_does_not_apply(self):
        code, out, err, summary = self.run_gate([leak()], entries=[entry(digest=OTHER)])
        self.assertEqual(code, 1)
        self.assertIn("Stale secret allowlist entry (it names another digest", out)

    def test_an_entry_for_another_image_is_ignored_and_not_stale(self):
        code, out, _, summary = self.run_gate([leak()], entries=[entry(image="example/other")])
        self.assertEqual(code, 1)
        self.assertNotIn("::warning::", out)
        self.assertNotIn("Stale", summary)

    def test_a_missing_file_means_no_allowlist(self):
        self.assertEqual(self.run_gate([])[0], 0)
        code, out, *_ = self.run_gate([leak()])
        self.assertEqual(code, 1)
        self.assertIn("secret CRITICAL", out)

    def test_no_allowlist_argument_means_no_allowlist(self):
        self.allowlist([entry()])
        code, out, *_ = self.run_gate([leak()], allowlist=None)
        self.assertEqual(code, 1)
        self.assertNotIn("allowlisted", out)

    def test_a_file_that_is_not_valid_fails_closed_even_on_a_clean_image(self):
        good = json.dumps(entry())
        for label, content in {
            "empty": "", "blank": " ", "braces": "{}", "list": "[]", "not json": "x", "trailing text": '{"allowlist": []} x',
            "duplicate key": '{"allowlist": [], "allowlist": []}', "NaN": '{"allowlist": [NaN]}',
            "exceptions shape": '{"exceptions": []}', "other key": '{"other": []}',
            "bad entry": json.dumps({"allowlist": [entry(), entry(start_line=43, evidence="http://example.org/x")]}),
            "wildcard": json.dumps({"allowlist": [entry(target="var/www/*")]}),
            "future review": json.dumps({"allowlist": [entry(reviewed="2026-11-02", expires="2026-11-10")]}),
            "too long": json.dumps({"allowlist": [entry(reviewed="2026-10-01", expires="2026-11-20")]}),
            "duplicate entry key": '{"allowlist": [' + good[:-1] + ', "rule": "other-rule"}]}',
        }.items():
            with self.subTest(label):
                self.put(ALLOWLIST, content)
                code, out, err, summary = self.run_gate([])
                self.assertEqual(code, 2)
                self.assertIn("the secret allowlist file is not valid", err)
                self.assertIn("Failed closed", summary)

    def test_a_directory_or_a_bad_path_fails(self):
        os.makedirs(os.path.join(self.dir, ALLOWLIST))
        self.assertEqual(self.run_gate([])[0], 2)
        for path in ("../x.json", "/etc/passwd", "a b", "a;b", "", "-x"):
            with self.subTest(path):
                code, out, err, _ = self.run_gate([], allowlist=path)
                self.assertEqual(code, 2)
                self.assertIn("secret-allowlist-file", err)

    def test_the_two_files_must_differ(self):
        code, out, err, _ = self.run_gate([], allowlist=EXCEPTIONS)
        self.assertEqual(code, 2)
        self.assertIn("two different files", err)

    def test_an_engine_that_cannot_be_loaded_fails_closed(self):
        real = ti.importlib.util.spec_from_file_location
        ti.importlib.util.spec_from_file_location = lambda name, path: real(name, os.path.join(self.dir, "missing.py"))
        try:
            code, out, err, summary = self.run_gate([])
        finally:
            ti.importlib.util.spec_from_file_location = real
        self.assertEqual(code, 2)


class NeverMore(GateBase):
    """What an allowlist entry can never do."""

    def test_it_never_excepts_a_vulnerability(self):
        # A secret rule id that looks like the id of the finding, an entry that fits the secret, and a live file.
        finding = vuln("CVE-2026-0001")
        entries = [entry(), entry(rule="cve-2026-0001", start_line=1), entry(target="app (debian 12)", start_line=2)]
        code, out, err, summary = self.run_gate([leak()], vulns=vreport(finding), entries=entries)
        self.assertEqual(code, 1)
        self.assertIn("fixable HIGH CVE-2026-0001 libfoo", out)
        self.assertNotIn("excepted", out)
        self.assertIn("1 fixable", err)

    def test_vulnerability_exceptions_still_refuse_secrets(self):
        for label, bad in {
            "rule field": {"rule": RULE}, "secret field": {"secret": TARGET}, "rule id as id": {"id": RULE},
        }.items():
            with self.subTest(label):
                exception = {"image": "example/app", "digest": DIGEST, "id": "CVE-2026-0001", "package": "libfoo",
                             "reason": "the vendor has not rebuilt the image", "reviewer": "reviewer-one",
                             "reviewed": "2026-10-25", "expires": "2026-11-20"}
                exception.update(bad)
                self.put(EXCEPTIONS, {"exceptions": [exception]})
                code, out, err, _ = self.run_gate([leak()])
                self.assertEqual(code, 2)
                self.assertIn("exceptions file is not valid", err)

    def test_a_vulnerability_exception_does_not_allow_a_secret(self):
        self.put(EXCEPTIONS, {"exceptions": [{
            "image": "example/app", "digest": DIGEST, "id": "CVE-2026-0001", "package": "libfoo",
            "reason": "the vendor has not rebuilt the image", "reviewer": "reviewer-one",
            "reviewed": "2026-10-25", "expires": "2026-11-20"}]})
        code, out, *_ = self.run_gate([leak()], vulns=vreport(vuln()))
        self.assertEqual(code, 1)
        self.assertIn("secret CRITICAL", out)

    def test_the_two_files_are_not_interchangeable_in_the_gate(self):
        self.put(EXCEPTIONS, {"allowlist": [entry()]})
        code, out, err, _ = self.run_gate([])
        self.assertEqual(code, 2)
        self.assertIn("exceptions file is not valid", err)
        os.remove(os.path.join(self.dir, EXCEPTIONS))
        self.put(ALLOWLIST, {"exceptions": []})
        code, out, err, _ = self.run_gate([])
        self.assertEqual(code, 2)
        self.assertIn("secret allowlist file is not valid", err)

    def test_a_secret_in_a_vulnerability_report_is_not_read_and_a_vulnerability_in_the_secret_report_is_ignored(self):
        data = sreport([])
        data["Results"].append({"Target": "app (debian 12)", "Vulnerabilities": [vuln()]})
        self.assertEqual(self.run_gate(secret_report=data, entries=[entry()])[0], 0)
        both = vreport()
        both["Results"] = [{"Target": TARGET, "Secrets": [leak()]}]
        code, out, *_ = self.run_gate([], vulns=both, entries=[entry()])
        self.assertEqual(code, 0)
        self.assertNotIn("allowlisted known-public", out)


class Summary(GateBase):
    def hostile_entry(self):
        return entry(target="t" + HOSTILE, reason="ok" + HOSTILE + " end",
                     evidence="https://e.example/a" + HOSTILE.replace(" ", "") + "[x](y)")

    def assert_inert(self, row, pipes):
        self.assertEqual(row.count("|"), pipes, row)
        for char in "`<>[]()!\\":
            self.assertNotIn(char, row)
        self.assertNotIn("::", row)
        self.assertNotIn("://", row)

    def test_untrusted_text_in_the_allowlisted_row_cannot_inject_markdown_or_html(self):
        e = self.hostile_entry()
        data = sreport([leak()], target=e["target"])
        code, out, err, summary = self.run_gate(secret_report=data, entries=[e])
        self.assertEqual((code, err), (0, ""))
        row = [line for line in summary.splitlines() if line.startswith("| " + RULE)][0]
        self.assert_inert(row, 9)
        self.assertIn("reviewer-one", row)
        self.assertIn("ok", row)  # shown, only its markup is neutralised
        for text in (out, summary):
            for line in text.splitlines():
                self.assertFalse(line.lstrip().startswith("::"), line)

    def test_untrusted_text_in_the_stale_and_expired_rows_is_inert(self):
        e = self.hostile_entry()
        code, out, err, summary = self.run_gate([], entries=[e, entry(start_line=7, target="x" + HOSTILE, expires="2026-10-31")])
        self.assertEqual(code, 1)
        self.assertIn("Stale secret allowlist entries", summary)
        self.assertIn("Expired secret allowlist entries", summary)
        for line in summary.splitlines():
            self.assertFalse(line.lstrip().startswith("::"), line)
            if line.startswith("- example/app") or line.startswith("| example/app"):
                self.assert_inert(line, line.count("|"))
        for line in (out + err).splitlines():
            self.assertTrue(line.startswith(("::warning::", "::error::", "allowlisted", "secret ", "fixable", "excepted", "passed")), line)

    def test_a_failing_secret_row_with_hostile_text_stays_inert(self):
        data = sreport([leak(rule="r-1", Title="t" + HOSTILE)], target="f" + HOSTILE)
        code, out, err, summary = self.run_gate(secret_report=data)
        self.assertEqual(code, 1)
        self.assert_inert([line for line in summary.splitlines() if line.startswith("| CRITICAL")][0], 6)

    def test_long_lists_are_truncated_in_the_summary_only(self):
        n = ti.MAX_ROWS + 3
        entries = [entry(start_line=i + 1) for i in range(n)]
        data = sreport([leak(line=i + 1) for i in range(n)])
        code, out, err, summary = self.run_gate(secret_report=data, entries=entries)
        self.assertEqual(code, 0)
        self.assertIn("and 3 more", summary)
        self.assertEqual(out.count("allowlisted known-public"), n)

    def test_a_failed_image_still_lists_what_is_allowlisted(self):
        code, out, err, summary = self.run_gate([leak(), leak(line=9)], entries=[entry()])
        self.assertEqual(code, 1)
        self.assertIn("**Failed.**", summary)
        self.assertIn("Allowlisted secrets", summary)
        self.assertIn("| %s | %s | 42 |" % (RULE, TARGET), summary)


class ExitStatus(unittest.TestCase):
    """The script as the workflow runs it: python3 -I, arguments only."""

    def test_the_exit_status_under_isolated_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, ".github"))
            for name, data in (("v.json", vreport()), ("s.json", sreport([leak()]))):
                with open(os.path.join(tmp, name), "w", encoding="utf-8") as handle:
                    json.dump(data, handle)
            day = datetime.datetime.now(datetime.timezone.utc).date()
            live = entry(reviewed=day.isoformat(), expires=(day + datetime.timedelta(days=5)).isoformat())
            with open(os.path.join(tmp, ALLOWLIST), "w", encoding="utf-8") as handle:
                json.dump({"allowlist": [live]}, handle)
            gate = [sys.executable, "-I", SCRIPT, "gate", "--reference", REF, "--vuln", "v.json", "--secret", "s.json",
                    "--exceptions-file", EXCEPTIONS, "--secret-allowlist-file", ALLOWLIST]
            env = {k: v for k, v in os.environ.items() if not k.startswith("GITHUB_")}
            passed = subprocess.run(gate, cwd=tmp, env=env, capture_output=True, text=True)
            self.assertEqual(passed.returncode, 0, passed.stderr)
            self.assertIn("1 secrets allowlisted", passed.stdout)
            # Without the file the same reports fail the job (the exit status is the job status).
            os.remove(os.path.join(tmp, ALLOWLIST))
            failed = subprocess.run(gate, cwd=tmp, env=env, capture_output=True, text=True)
            self.assertEqual(failed.returncode, 1)
            with open(os.path.join(tmp, ALLOWLIST), "w", encoding="utf-8") as handle:
                handle.write("{")
            broken = subprocess.run(gate, cwd=tmp, env=env, capture_output=True, text=True)
            self.assertEqual(broken.returncode, 2)

    def test_the_plan_checks_both_paths(self):
        for env_extra, expected in (
                ({}, 0),
                ({"SECRET_ALLOWLIST_FILE": "../x.json"}, 2),
                ({"SECRET_ALLOWLIST_FILE": ""}, 2),
                ({"SECRET_ALLOWLIST_FILE": "a b"}, 2),
                ({"SECRET_ALLOWLIST_FILE": EXCEPTIONS}, 2),
                ({"SECRET_ALLOWLIST_FILE": None}, 2)):
            with self.subTest(env_extra), tempfile.TemporaryDirectory() as tmp:
                env = {"IMAGES": "app@" + DIGEST, "EXCEPTIONS_FILE": EXCEPTIONS, "SECRET_ALLOWLIST_FILE": ALLOWLIST,
                       "GITHUB_OUTPUT": os.path.join(tmp, "out")}
                for key, value in env_extra.items():
                    if value is None:
                        env.pop(key)
                    else:
                        env[key] = value
                out, err = io.StringIO(), io.StringIO()
                self.assertEqual(ti.main(["plan"], env, out, err), expected, err.getvalue())
                if expected:
                    self.assertFalse(os.path.exists(os.path.join(tmp, "out")))


class SecretFindings(unittest.TestCase):
    def findings(self, secrets, target=TARGET):
        return ti.secret_findings(ti.results_of(sreport(secrets, target=target), "secret"))

    def test_the_raw_values_are_the_ones_trivy_reports(self):
        f = self.findings([leak()])[0]
        self.assertEqual((f["raw_rule"], f["raw_target"], f["raw_line"], f["raw_diff_id"]), (RULE, TARGET, 42, LAYER))
        self.assertRegex(f["match_sha256"], r"^sha256:[0-9a-f]{64}$")
        self.assertEqual(f["layer"], LAYER)

    def test_the_diff_id_is_used_not_the_compressed_digest(self):
        f = self.findings([leak(Layer={"Digest": "sha256:" + "9" * 64, "DiffID": LAYER})])[0]
        self.assertEqual(f["raw_diff_id"], LAYER)
        f = self.findings([leak(Layer={"Digest": "sha256:" + "9" * 64})])[0]
        self.assertIsNone(f["raw_diff_id"])

    def test_values_of_the_wrong_type_are_never_raw_values(self):
        f = self.findings([leak(line=True, Layer="x", Match=5, RuleID=7)])[0]
        self.assertEqual((f["raw_line"], f["raw_diff_id"], f["match_sha256"], f["raw_rule"]), (None, None, None, None))
        f = self.findings([leak(line="3")])[0]
        self.assertIsNone(f["raw_line"])
        f = self.findings([leak(line=3.0)])[0]
        self.assertIsNone(f["raw_line"])

    def test_the_hash_is_of_the_redacted_line_and_no_text_is_kept(self):
        a = self.findings([leak(match="AccountKey=*****")])[0]
        b = self.findings([leak(match="AccountKey=*****x")])[0]
        self.assertNotEqual(a["match_sha256"], b["match_sha256"])
        self.assertNotIn("AccountKey", json.dumps(a))

    def test_a_lone_surrogate_in_the_match_does_not_crash_the_gate(self):
        data = sreport([leak()])
        text = json.dumps(data).replace("AccountKey=*****", "Account" + chr(92) + "ud800Key")
        f = ti.secret_findings(ti.results_of(json.loads(text), "secret"))[0]
        self.assertRegex(f["match_sha256"], r"^sha256:[0-9a-f]{64}$")


class Workflow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = read("trivy-images.yml")

    def test_the_input(self):
        block = input_block(self.text, "secret-allowlist-file")
        self.assertRegex(block, r"default:\s*\.github/image-secret-allowlist\.json\b")
        self.assertRegex(block, r"required:\s*false\b")
        self.assertRegex(block, r"type:\s*string\b")
        description = " ".join(block.split())
        for phrase in ("missing file means no allowlist", "digest", "31 days", "never applies to a vulnerability",
                       "evidence", "known-public"):
            self.assertIn(phrase, description)

    def test_the_two_inputs_have_different_defaults(self):
        self.assertNotEqual(input_block(self.text, "exceptions-file").split("default:")[1].split()[0],
                            input_block(self.text, "secret-allowlist-file").split("default:")[1].split()[0])

    def test_the_plan_and_the_gate_receive_it_through_the_environment(self):
        for name in ("Validate images", "Gate image"):
            with self.subTest(name):
                self.assertIn("SECRET_ALLOWLIST_FILE: ${{ inputs.secret-allowlist-file }}", step(self.text, name))
        self.assertEqual(self.text.count("inputs.secret-allowlist-file"), 2)
        gate = step(self.text, "Gate image")
        self.assertIn('--secret-allowlist-file "$SECRET_ALLOWLIST_FILE"', gate)

    def test_no_other_step_reads_the_allowlist_or_runs_the_engine(self):
        for each in self.text.split("\n      - name: ")[1:]:
            title = each.splitlines()[0]
            if title in ("Validate images", "Gate image", "Verify shared workflow checkout"):
                continue
            with self.subTest(title):
                self.assertNotIn("SECRET_ALLOWLIST_FILE", each)
                self.assertNotIn("image_secret_allowlist", each)
                self.assertNotIn("secret-allowlist-file", each)

    def test_the_scan_job_checks_the_engine_out(self):
        self.assertIn("test -f .strange-security/scripts/image_secret_allowlist.py", self.text)

    def test_trivy_still_reads_no_ignore_file_and_the_sarif_is_unfiltered_by_it(self):
        code = "\n".join(line for line in self.text.splitlines() if not line.lstrip().startswith("#"))
        self.assertNotRegex(code, r"--ignorefile|TRIVY_IGNOREFILE|trivyignore|trivy\.yaml|--config\b")
        self.assertNotIn("allowlist", step(self.text, "Run Trivy secret scan"))
        self.assertNotIn("allowlist", step(self.text, "Write secret scan SARIF"))


class ExampleFromTheDocs(unittest.TestCase):
    def test_the_nextcloud_azurite_example_validates_and_allows_its_finding(self):
        """The entry strangeservers adds, with this fixture's digests, validates and covers the finding."""
        e = entry(image="nextcloud", target="var/www/html/3rdparty/microsoft/azure-storage-common/src/Common/Internal/Resources.php",
                  reason="Azurite development storage key, documented by Microsoft for the emulator; not a credential",
                  evidence=EVIDENCE)
        self.assertEqual(ti.load_allowlist_engine().schema_errors([e], TODAY), [])
        engine = ti.load_allowlist_engine()
        findings = ti.secret_findings(ti.results_of(sreport([leak()], repo="nextcloud", target=e["target"]), "secret"))
        verdict = engine.evaluate([e], "nextcloud", DIGEST, findings, TODAY)
        self.assertEqual((len(verdict["allowed"]), verdict["failing"]), (1, []))
        self.assertTrue(REASON)


if __name__ == "__main__":
    unittest.main()
