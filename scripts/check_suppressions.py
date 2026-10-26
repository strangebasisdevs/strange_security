#!/usr/bin/env python3
"""Fail on Semgrep suppressions that break docs/SUPPRESSIONS.md.

Usage: python3 -I check_suppressions.py [ROOT]

A suppression must be exactly one inline comment naming one rule, and the line
directly above it must be a comment giving the reason:

    # why this call is safe: argument list, no shell, fixed binary, timeout
    subprocess.run(cmd)  # <marker>: python.lang.security.audit.dangerous-subprocess-use-audit

where <marker> is the Semgrep suppression keyword (spelled out in the policy).
Comment syntaxes: #  //  /* */  <!-- -->  everywhere; ";" only in .ini/.asm/.el/
.lisp/.clj and similar, "%" only in .tex/.erl/.m, "--" only in .sql/.lua/.hs/
.ada. Lines split on newline only, as Semgrep reads them; control characters on
a suppression or reason line are rejected.

Not scanned: .git, a top-level .strange-security (the shared checkout), binary
files, symlinks, and Markdown/reStructuredText (documentation, not source).
Uses the standard library only.
"""
import os
import re
import sys

# Spelled in parts so this file does not contain the keyword itself.
KEYWORD = "no" + "semgrep"
# Detect it the way Semgrep does: the long or short spelling, any case. A line
# Semgrep would honour but the policy form does not match is reported.
DETECT = re.compile("no" + "sem(?:grep)?", re.IGNORECASE)

SKIP_DIRS_ANYWHERE = {".git"}
SKIP_DIRS_TOP = {".strange-security"}
SKIP_SUFFIXES = (".md", ".markdown", ".rst")
MAX_BYTES = 2 * 1024 * 1024

RULE_ID = r"[A-Za-z0-9_][A-Za-z0-9_.\-]*"
MIN_REASON_CHARS = 8

# Always comment markers. The ambiguous ones are decided by file extension:
# ';' is code in C-like languages, '%' is an operator, '--' is a decrement.
BASE_MARKERS = ("#", "//", "/*", "<!--")
EXTRA_MARKERS = {
    ";": (".ini", ".asm", ".s", ".nasm", ".el", ".lisp", ".lsp", ".scm", ".clj", ".cljs", ".cljc", ".edn"),
    "%": (".tex", ".sty", ".erl", ".hrl", ".m"),
    "--": (".sql", ".lua", ".hs", ".ada", ".adb", ".ads"),
}

# Physical lines as Semgrep reads them: split on "\n" only. These characters
# would let one line hide a second suppression or reason from a reader that
# splits differently, so they are rejected on suppression and reason lines.
CONTROL = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\x85  ]")
STAR_LINE = re.compile(r"^[ \t]*\*(?!/)")
BLOCK_OPEN = re.compile(r"^[ \t]*/\*")
COMMENT_END = re.compile(r"[ \t]*(?:\*+/|-->)[ \t]*$")


class Syntax:
    """Comment syntax for one file, chosen by extension."""

    def __init__(self, ext=""):
        ext = ext.lower()
        markers = list(BASE_MARKERS) + [m for m, exts in EXTRA_MARKERS.items() if ext in exts]
        start = "(?:" + "|".join(re.escape(m) for m in markers) + ")"
        # Code, then one inline comment naming one rule, lowercase keyword,
        # nothing after it except a closing comment marker.
        self.valid = re.compile(
            r"^[ \t]*\S[^\n]*?" + start + r"[ \t]*" + KEYWORD + r":[ \t]*" + RULE_ID
            + r"[ \t]*(?:\*/|-->)?[ \t]*$"
        )
        self.comment_line = re.compile(r"^[ \t]*" + start)
        strip = [r"#+", r"//+", r"/\*+", r"\*+", "<!--"]
        strip += [re.escape(m) + "+" for m in markers if m in (";", "%", "--")]
        self.strip = re.compile(r"^[ \t]*(?:" + "|".join(strip) + r")[ \t]*")


def split_lines(text):
    """Split on newline only, dropping one trailing carriage return per line."""
    return [line[:-1] if line.endswith("\r") else line for line in text.split("\n")]


def in_block_comment(lines, i):
    """True if lines[i], which starts with '*', continues an open /* comment."""
    j = i - 1
    while j >= 0 and STAR_LINE.match(lines[j]):
        if "*/" in lines[j]:
            return False
        j -= 1
    return j >= 0 and bool(BLOCK_OPEN.match(lines[j])) and "*/" not in lines[j][lines[j].index("/*") + 2:]


def closes_with_code(line, opener, closer):
    """True if a comment opened at the start of line closes and code follows."""
    rest = line.lstrip(" \t")[len(opener):]
    end = rest.find(closer)
    return end >= 0 and rest[end + len(closer):].strip() != ""


def reason_of(lines, i, syntax):
    """Return the reason text if lines[i] is a comment line, else None."""
    line = lines[i]
    if DETECT.search(line) or CONTROL.search(line):
        return None
    if STAR_LINE.match(line):
        if not in_block_comment(lines, i):
            return None
    elif not syntax.comment_line.match(line):
        return None
    else:
        body = line.lstrip(" \t")
        if body.startswith("/*") and closes_with_code(line, "/*", "*/"):
            return None
        if body.startswith("<!--") and closes_with_code(line, "<!--", "-->"):
            return None
    text = COMMENT_END.sub("", syntax.strip.sub("", line, count=1))
    return text.strip()


def check_text(text, ext=""):
    """Return a list of (line_number, message) for one file's text."""
    problems = []
    syntax = Syntax(ext)
    lines = split_lines(text)
    for i, line in enumerate(lines):
        found = DETECT.findall(line)
        if not found:
            continue
        number = i + 1
        if CONTROL.search(line):
            problems.append((number, "control character on a suppression line; remove it"))
            continue
        standalone = syntax.comment_line.match(line) or STAR_LINE.match(line)
        if len(found) != 1 or standalone or not syntax.valid.search(line):
            problems.append(
                (number, "bare or malformed suppression; use code, then one lowercase inline comment naming exactly one rule id")
            )
            continue
        reason = reason_of(lines, i - 1, syntax) if i > 0 else None
        if not reason or len(re.sub(r"\W", "", reason)) < MIN_REASON_CHARS:
            problems.append(
                (number, "no reason comment on the line directly above; say why it is safe and name the guards")
            )
    return problems


def iter_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        top = os.path.normpath(dirpath) == os.path.normpath(root)
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in SKIP_DIRS_ANYWHERE and not (top and d in SKIP_DIRS_TOP)
            and not os.path.islink(os.path.join(dirpath, d))
        )
        for name in sorted(filenames):
            path = os.path.join(dirpath, name)
            if name.lower().endswith(SKIP_SUFFIXES) or os.path.islink(path):
                continue
            yield path


def read_text(path):
    try:
        if os.path.getsize(path) > MAX_BYTES:
            return None
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError:
        return None
    if b"\0" in data[:8192]:
        return None
    return data.decode("utf-8", errors="replace")


def check_tree(root):
    """Return a list of (path, line_number, message) under root."""
    found = []
    for path in iter_files(root):
        text = read_text(path)
        if text is None or not DETECT.search(text):
            continue
        for number, message in check_text(text, os.path.splitext(path)[1]):
            found.append((os.path.relpath(path, root).replace(os.sep, "/"), number, message))
    return found


def main(argv):
    if len(argv) > 2:
        print("usage: check_suppressions.py [ROOT]", file=sys.stderr)
        return 2
    root = argv[1] if len(argv) == 2 else "."
    if not os.path.isdir(root):
        print("not a directory: " + root, file=sys.stderr)
        return 2
    problems = check_tree(root)
    for path, number, message in problems:
        print("::error file=%s,line=%d::%s (see docs/SUPPRESSIONS.md)" % (path, number, message))
    if problems:
        print("%d suppression(s) break the policy in docs/SUPPRESSIONS.md" % len(problems), file=sys.stderr)
        return 1
    print("Suppression check passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
