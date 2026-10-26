#!/usr/bin/env python3
"""Fail on Semgrep suppressions that break docs/SUPPRESSIONS.md.

Usage: python3 -I check_suppressions.py [ROOT]

A suppression must be exactly one inline comment naming one rule, and the line
directly above it must be a comment giving the reason:

    # why this call is safe: argument list, no shell, fixed binary, timeout
    subprocess.run(cmd)  # <marker>: python.lang.security.audit.dangerous-subprocess-use-audit

where <marker> is the Semgrep suppression keyword (spelled out in the policy).
Comment syntaxes handled: #  //  --  ;  %  /* */  <!-- -->.

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

COMMENT_START = r"(?:#|//|--|;|%|/\*|<!--)"
RULE_ID = r"[A-Za-z0-9_][A-Za-z0-9_.\-]*"
# Code, then one inline comment naming one rule, lowercase keyword, nothing
# after it except a closing comment marker.
VALID = re.compile(
    r"^[ \t]*\S[^\n]*?" + COMMENT_START + r"[ \t]*" + KEYWORD + r":[ \t]*" + RULE_ID
    + r"[ \t]*(?:\*/|-->)?[ \t]*$"
)
# A line whose first non-blank text is a comment marker (not a '*' continuation).
COMMENT_LINE = re.compile(r"^[ \t]*(?:#|//|--|;|%|/\*|<!--)")
STAR_LINE = re.compile(r"^[ \t]*\*(?!/)")
BLOCK_OPEN = re.compile(r"^[ \t]*/\*")
COMMENT_STRIP = re.compile(r"^[ \t]*(?:#+|//+|--+|;+|%+|/\*+|\*+|<!--)[ \t]*")
COMMENT_END = re.compile(r"[ \t]*(?:\*+/|-->)[ \t]*$")
MIN_REASON_CHARS = 8


def in_block_comment(lines, i):
    """True if lines[i], which starts with '*', continues an open /* comment."""
    j = i - 1
    while j >= 0 and STAR_LINE.match(lines[j]):
        j -= 1
    return j >= 0 and bool(BLOCK_OPEN.match(lines[j])) and "*/" not in lines[j][lines[j].index("/*") + 2:]


def reason_of(lines, i):
    """Return the reason text if lines[i] is a comment line, else None."""
    line = lines[i]
    if DETECT.search(line):
        return None
    if STAR_LINE.match(line):
        if not in_block_comment(lines, i):
            return None
    elif not COMMENT_LINE.match(line):
        return None
    text = COMMENT_END.sub("", COMMENT_STRIP.sub("", line, count=1))
    return text.strip()


def check_text(text):
    """Return a list of (line_number, message) for one file's text."""
    problems = []
    lines = text.splitlines()
    for i, line in enumerate(lines):
        found = DETECT.findall(line)
        if not found:
            continue
        number = i + 1
        standalone = COMMENT_LINE.match(line) or STAR_LINE.match(line)
        if len(found) != 1 or standalone or not VALID.search(line):
            problems.append(
                (number, "bare or malformed suppression; use code, then one lowercase inline comment naming exactly one rule id")
            )
            continue
        reason = reason_of(lines, i - 1) if i > 0 else None
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
        for number, message in check_text(text):
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
