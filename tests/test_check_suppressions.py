import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "..", "scripts", "check_suppressions.py")

spec = importlib.util.spec_from_file_location("check_suppressions", SCRIPT)
cs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cs)

K = "no" + "semgrep"  # keep the keyword out of this file
SHORT = "no" + "sem"
RULE = "python.lang.security.audit.dangerous-subprocess-use-audit"
REASON = "argument list, no shell, fixed binary path, validated inputs, timeout"


def lines_of(*lines):
    return "\n".join(lines) + "\n"


class CheckText(unittest.TestCase):
    def ok(self, text, ext=""):
        self.assertEqual(cs.check_text(text, ext), [])

    def bad(self, text, count=1, ext=""):
        self.assertEqual(len(cs.check_text(text, ext)), count, cs.check_text(text, ext))

    def test_valid_hash(self):
        self.ok(lines_of("# " + REASON, "run(cmd)  # %s: %s" % (K, RULE)))

    def test_valid_slash(self):
        self.ok(lines_of("// " + REASON, "run(cmd); // %s: %s" % (K, RULE)))

    def test_valid_sql_and_lua(self):
        self.ok(lines_of("-- " + REASON, "select 1 -- %s: %s" % (K, RULE)), ".sql")
        self.ok(lines_of("-- " + REASON, "x = 1 -- %s: %s" % (K, RULE)), ".lua")

    def test_valid_block_comments(self):
        self.ok(lines_of("/* " + REASON + " */", "run(cmd); /* %s: %s */" % (K, RULE)))
        self.ok(lines_of("/**", " * " + REASON, "run(cmd); /* %s: %s */" % (K, RULE)))
        self.ok(lines_of("<!-- " + REASON + " -->", "<x/> <!-- %s: %s -->" % (K, RULE)))

    def test_ambiguous_markers_depend_on_extension(self):
        cases = {
            ";": (".ini", ".asm", ".el", ".lisp", ".clj"),
            "%": (".tex", ".erl", ".m"),
            "--": (".sql", ".lua", ".hs", ".ada"),
        }
        for marker, exts in cases.items():
            text = lines_of(marker + " " + REASON, "code 1 %s %s: %s" % (marker, K, RULE))
            for ext in exts:
                with self.subTest(marker=marker, ext=ext):
                    self.ok(text, ext)
            for ext in ("", ".py", ".js", ".c", ".java", ".go"):
                with self.subTest(marker=marker, ext=ext):
                    self.bad(text, 1, ext)

    def test_semicolon_line_in_js_is_code_not_reason(self):
        self.bad(lines_of("; eval(userInput);", "run(cmd)  // %s: %s" % (K, RULE)), ext=".js")
        self.bad(lines_of("; " + REASON, "run(cmd)  // %s: %s" % (K, RULE)), ext=".js")

    def test_inline_block_comment_then_code_is_not_reason(self):
        self.bad(lines_of("/* " + REASON + " */ eval(y)", "run(cmd); // %s: %s" % (K, RULE)))
        self.bad(lines_of("<!-- " + REASON + " --> <script>x()</script>", "<x/> <!-- %s: %s -->" % (K, RULE)))
        self.ok(lines_of("/* " + REASON + " */", "run(cmd); // %s: %s" % (K, RULE)))

    def test_star_line_after_closed_block_is_code(self):
        self.bad(lines_of("/* closed comment here */", " * " + REASON, "run(); // %s: %s" % (K, RULE)))
        self.bad(lines_of("/*", " * " + REASON, " */", " * " + REASON, "run(); // %s: %s" % (K, RULE)))
        self.bad(lines_of("/*", " * " + REASON + " */", " * " + REASON, "run(); // %s: %s" % (K, RULE)))

    def test_only_newline_splits_lines(self):
        for sep in ("\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029"):
            with self.subTest(sep=repr(sep)):
                text = lines_of("# " + REASON, "run(cmd)  # %s: a.b%sc.d" % (K, sep))
                self.bad(text)

    def test_control_chars_on_suppression_line_fail(self):
        for ch in ("\x00", "\x01", "\x08", "\x0b", "\x0c", "\x0e", "\x1f", "\x7f", "\x85", "\u2028", "\u2029"):
            with self.subTest(ch=repr(ch)):
                self.bad(lines_of("# " + REASON, "run(cmd)%s  # %s: %s" % (ch, K, RULE)))

    def test_control_chars_on_reason_line_fail(self):
        for ch in ("\x00", "\x0b", "\x0c", "\x1c", "\x7f", "\x85", "\u2028", "\u2029"):
            with self.subTest(ch=repr(ch)):
                self.bad(lines_of("# " + REASON + ch + "more", "run(cmd)  # %s: %s" % (K, RULE)))

    def test_tab_and_cr_still_fine(self):
        self.ok("# %s\r\nrun(cmd)\t# %s: %s\r\n" % (REASON, K, RULE))

    def test_bare_fails(self):
        self.bad(lines_of("# " + REASON, "run(cmd)  # " + K))

    def test_bare_with_trailing_text_fails(self):
        self.bad(lines_of("# " + REASON, "run(cmd)  # %s because it is fine" % K))

    def test_colon_without_rule_fails(self):
        self.bad(lines_of("# " + REASON, "run(cmd)  # %s:" % K))

    def test_two_rules_fail(self):
        self.bad(lines_of("# " + REASON, "run(cmd)  # %s: a.b, c.d" % K))
        self.bad(lines_of("# " + REASON, "run(cmd)  # %s: a.b c.d" % K))

    def test_not_a_comment_fails(self):
        self.bad(lines_of("# " + REASON, "%s: %s" % (K, RULE)))

    def test_missing_reason_fails(self):
        self.bad(lines_of("run(cmd)  # %s: %s" % (K, RULE)))
        self.bad(lines_of("x = 1", "run(cmd)  # %s: %s" % (K, RULE)))

    def test_blank_line_above_fails(self):
        self.bad(lines_of("# " + REASON, "", "run(cmd)  # %s: %s" % (K, RULE)))

    def test_empty_or_tiny_reason_fails(self):
        self.bad(lines_of("#", "run(cmd)  # %s: %s" % (K, RULE)))
        self.bad(lines_of("# ok", "run(cmd)  # %s: %s" % (K, RULE)))
        self.bad(lines_of("# ------------", "run(cmd)  # %s: %s" % (K, RULE)))

    def test_reason_line_cannot_be_another_suppression(self):
        text = lines_of(
            "# " + REASON,
            "a()  # %s: %s" % (K, RULE),
            "b()  # %s: %s" % (K, RULE),
        )
        self.bad(text)

    def test_reason_line_itself_a_suppression_fails(self):
        # Previously surviving mutation: the line above is a suppression comment.
        self.bad(lines_of("# %s: %s" % (K, RULE), "a()  # %s: %s" % (K, RULE)), 2)
        self.bad(lines_of("// %s: %s %s" % (K, RULE, REASON), "a()  // %s: %s" % (K, RULE)), 2)

    def test_code_line_above_is_not_a_reason(self):
        self.bad(lines_of("x = call_something_long_enough()", "a()  # %s: %s" % (K, RULE)))
        self.bad(lines_of("*ptr = value_long_enough;", "a(); // %s: %s" % (K, RULE)))
        self.bad(lines_of("  * value_long_enough = 1;", "a(); // %s: %s" % (K, RULE)))

    def test_comma_list_fails(self):
        self.bad(lines_of("# " + REASON, "a()  # %s: a.b,c.d" % K))
        self.bad(lines_of("# " + REASON, "a()  # %s: a.b ,c.d" % K))

    def test_short_and_uppercase_forms_fail(self):
        for word in (SHORT, SHORT.upper(), K.upper(), K.capitalize(), SHORT + "grep"[:2]):
            with self.subTest(word=word):
                self.bad(lines_of("# " + REASON, "a()  # %s: %s" % (word, RULE)))
        self.bad(lines_of("# " + REASON, "a()  # " + SHORT))

    def test_two_keywords_on_one_line_fail(self):
        self.bad(lines_of("# " + REASON, "a()  # %s: a.b # %s: c.d" % (K, K)))
        self.bad(lines_of("# " + REASON, "a()  # %s: a.b  # %s" % (K, SHORT)))

    def test_standalone_previous_line_form_fails(self):
        self.bad(lines_of("# " + REASON, "# %s: %s" % (K, RULE), "a()"))
        self.bad(lines_of("# " + REASON, "// %s: %s" % (K, RULE), "a()"))
        self.bad(lines_of("# " + REASON, "## %s: %s" % (K, RULE)))

    def test_star_reason_only_inside_block_comment(self):
        self.ok(lines_of("/*", " * " + REASON, " * more text here", "run(); // %s: %s" % (K, RULE)))
        self.bad(lines_of(" * " + REASON, "run(); // %s: %s" % (K, RULE)))

    def test_two_suppressions_each_with_reason(self):
        self.ok(lines_of(
            "# " + REASON, "a()  # %s: %s" % (K, RULE),
            "# " + REASON, "b()  # %s: %s" % (K, RULE),
        ))

    def test_first_line_fails(self):
        self.bad(lines_of("run(cmd)  # %s: %s" % (K, RULE)))

    def test_crlf_ok(self):
        self.ok("# %s\r\nrun(cmd)  # %s: %s\r\n" % (REASON, K, RULE))

    def test_line_numbers(self):
        self.assertEqual(cs.check_text(lines_of("x", "y  # " + K))[0][0], 2)

    def test_no_keyword_no_problem(self):
        self.ok("print('hello')\n")


class CheckTree(unittest.TestCase):
    BAD = "x()  # " + K + "\n"

    def make(self, files):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        for rel, content in files.items():
            path = os.path.join(tmp.name, *rel.split("/"))
            os.makedirs(os.path.dirname(path), exist_ok=True)
            mode = "wb" if isinstance(content, bytes) else "w"
            with open(path, mode) as handle:
                handle.write(content)
        return tmp.name

    def test_finds_violation_in_caller_code(self):
        root = self.make({"src/app.py": self.BAD})
        self.assertEqual([(p, n) for p, n, _ in cs.check_tree(root)], [("src/app.py", 1)])

    def test_skips_shared_checkout_and_git(self):
        root = self.make({
            ".strange-security/x.py": self.BAD,
            ".git/hooks/x": self.BAD,
            "ok.py": "print(1)\n",
        })
        self.assertEqual(cs.check_tree(root), [])

    def test_only_top_level_shared_checkout_is_skipped(self):
        root = self.make({"src/.strange-security/x.py": self.BAD})
        self.assertEqual(len(cs.check_tree(root)), 1)

    def test_skips_markdown_and_binary(self):
        root = self.make({"README.md": self.BAD, "blob.bin": b"\0\0" + self.BAD.encode()})
        self.assertEqual(cs.check_tree(root), [])

    def test_valid_file_passes(self):
        root = self.make({"a.py": "# %s\nrun()  # %s: %s\n" % (REASON, K, RULE)})
        self.assertEqual(cs.check_tree(root), [])


class Cli(unittest.TestCase):
    def run_cli(self, root):
        return subprocess.run(
            [sys.executable, "-I", SCRIPT, root], capture_output=True, text=True
        )

    def test_exit_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "a.py"), "w") as handle:
                handle.write("print(1)\n")
            self.assertEqual(self.run_cli(tmp).returncode, 0)
            with open(os.path.join(tmp, "b.py"), "w") as handle:
                handle.write("x()  # " + K + "\n")
            result = self.run_cli(tmp)
            self.assertEqual(result.returncode, 1)
            self.assertIn("b.py", result.stdout)

    def test_bad_root(self):
        self.assertEqual(self.run_cli(os.path.join(HERE, "no-such-dir")).returncode, 2)

    def test_this_repository_is_clean(self):
        self.assertEqual(self.run_cli(os.path.join(HERE, "..")).returncode, 0)


if __name__ == "__main__":
    unittest.main()
