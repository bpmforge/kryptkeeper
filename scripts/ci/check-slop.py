#!/usr/bin/env python3
"""Fails on clear-cut AI slop in the lines a change adds.

Usage: scripts/ci/check-slop.py [base-ref]   (default: merge base with origin/main)
       scripts/ci/check-slop.py --staged      (the index, for the pre-commit hook)

Only added lines are checked, so existing code does not fail every change.
A line can opt out with a `slop:allow <reason>` marker, which keeps every
exemption a reviewed, greppable decision (the same pattern as secret-scan).
Judgment calls (narrating comments, design smells) are left to review.
"""
import re
import subprocess
import sys

JUNK_FILE = re.compile(r"(\.(bak|orig|rej|tmp|swp)|~|(^|/)\.DS_Store)$")
GENERATED = re.compile(r"(^|/)(ui/src/generated/|node_modules/|testdata/)|(_gen\.go|\.pb\.go)$")

GO_RULES = [
    (re.compile(r'panic\(\s*"(not implemented|unimplemented|todo|implement me)', re.I), "unimplemented stub (panic)"),
    (re.compile(r"\bTODO:?\s*implement\b", re.I), "unimplemented stub (TODO implement)"),  # slop:allow the rule itself
    (re.compile(r"^\s*_\s*=\s*err\s*$"), "swallowed error (_ = err)"),
    (re.compile(r"if\s+err\s*!=\s*nil\s*\{\s*\}"), "swallowed error (empty if err != nil)"),
]
TS_RULES = [
    (re.compile(r"catch\s*(\([^)]*\))?\s*\{\s*\}"), "swallowed error (empty catch)"),
    (re.compile(r"\bconsole\.log\("), "debug output (console.log)"),
    (re.compile(r"lorem ipsum|coming soon", re.I), "placeholder text"),
]
ANY_RULES = [
    (re.compile(r"\bTODO:?\s*implement\b", re.I), "unimplemented stub (TODO implement)"),  # slop:allow the rule itself
]


def git(*args):
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout


def rules_for(path):
    if path.endswith(".go") and not path.endswith("_test.go"):
        return GO_RULES
    if path.startswith("ui/src/") and re.search(r"\.(ts|tsx)$", path) and not re.search(r"\.test\.tsx?$|/test/", path):
        return TS_RULES
    return ANY_RULES


def main():
    arg = sys.argv[1] if len(sys.argv) > 1 else ""
    if arg == "--staged":
        diff_args, names_args = ["diff", "--cached", "-U0"], ["diff", "--cached", "--name-only", "--diff-filter=A"]
    else:
        base = arg or git("merge-base", "HEAD", "origin/main").strip()
        diff_args, names_args = ["diff", "-U0", f"{base}...HEAD"], ["diff", "--name-only", "--diff-filter=A", f"{base}...HEAD"]

    problems = []
    for path in git(*names_args).splitlines():
        if JUNK_FILE.search(path):
            problems.append(f"{path}: committed scratch or backup file")

    path, line = None, 0
    for raw in git(*diff_args).splitlines():
        if raw.startswith("+++ "):
            path = raw[6:] if raw.startswith("+++ b/") else None
            continue
        m = re.match(r"@@ -\S+ \+(\d+)", raw)
        if m:
            line = int(m.group(1))
            continue
        if path is None or GENERATED.search(path) or not raw.startswith("+"):
            continue
        text = raw[1:]
        if "slop:allow" not in text:
            for pattern, what in rules_for(path):
                if pattern.search(text):
                    problems.append(f"{path}:{line}: {what}: {text.strip()[:120]}")
                    break
        line += 1

    if problems:
        print(f"check-slop: {len(problems)} problem(s) in added lines:")
        for p in problems:
            print("  " + p)
        print("Fix them, or mark a deliberate case with `slop:allow <reason>` on the line.")
        return 1
    print("check-slop: no slop in added lines")
    return 0


if __name__ == "__main__":
    sys.exit(main())
