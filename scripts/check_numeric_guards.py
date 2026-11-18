#!/usr/bin/env python3
"""Numeric comparisons must be guarded with is_number (#300).

In Rego a string sorts above every number and null below every number, so an unguarded `x >= 2` passes on
"1" and `x <= 30` passes on null. This lint finds comparisons of a value against a numeric literal where the
same rule body neither calls is_number(<value>) nor binds the value from a numeric expression (count, sum,
to_number, time.*, ...). Existing occurrences are recorded in scripts/numeric_guard_baseline.txt; CI fails on
any new one, so the baseline only shrinks.

    python3 scripts/check_numeric_guards.py               # summary
    python3 scripts/check_numeric_guards.py --check       # exit 1 on an unguarded comparison not in the baseline
    python3 scripts/check_numeric_guards.py --write-baseline

Fixing one: in a rule that passes on the comparison, add `is_number(x)` before it; in a rule that reports a
violation, add a sibling finding for `not is_number(object.get(..., null))` so a non-number is reported.
"""
from __future__ import annotations
import collections, pathlib, re, sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
BASELINE = ROOT / "scripts" / "numeric_guard_baseline.txt"
CMP = re.compile(r'^\s*(?P<lhs>[A-Za-z_][\w.\[\]"]*)\s*(?:>=|<=|>|<)\s*-?\d+(?:\.\d+)?\s*(?:#.*)?$')
NUMERIC = re.compile(r'(count|sum|max|min|to_number|time\.|units\.|abs|round|ceil|floor|numbers\.|indexof|strings\.count|-?\d)')
SKIP_DIRS = ("converters/", ".github/", "tests/")


def scan():
    hits = []
    for p in sorted(ROOT.rglob("*.rego")):
        rel = p.relative_to(ROOT).as_posix()
        if "/tests/" in rel or rel.startswith(SKIP_DIRS) or re.search(r"(^|/)test_|_test\.rego$", rel):
            continue
        lines = p.read_text(errors="ignore").splitlines()
        start, depth = 0, 0
        for i, line in enumerate(lines):
            depth += line.count("{") - line.count("}")
            if depth != 0:
                continue
            body, start = lines[start:i + 1], i + 1
            text = "\n".join(body)
            for b in body:
                m = CMP.match(b)
                if not m:
                    continue
                lhs = m["lhs"]
                if re.search(r"is_number\(\s*" + re.escape(lhs) + r"\s*\)", text):
                    continue
                bound = re.search(r"\b" + re.escape(lhs) + r"\s*:?=\s*(.+)", text)
                if bound and NUMERIC.match(bound.group(1).strip()):
                    continue
                hits.append(f"{rel}\t{b.strip()}")
    return hits


def main():
    hits = scan()
    if "--write-baseline" in sys.argv:
        BASELINE.write_text("# Unguarded numeric comparisons that predate the lint (#300). Fix them; never add to this file.\n"
                            + "\n".join(sorted(hits)) + "\n")
        print(f"wrote {len(hits)} entries to {BASELINE.relative_to(ROOT)}")
        return 0
    base = collections.Counter(l for l in BASELINE.read_text().splitlines() if l and not l.startswith("#")) if BASELINE.exists() else collections.Counter()
    new = collections.Counter(hits) - base
    fixed = sum((base - collections.Counter(hits)).values())
    print(f"numeric guards: {len(hits)} unguarded comparisons, {sum(new.values())} new, {fixed} fixed since the baseline")
    for h in sorted(new):
        f, line = h.split("\t", 1)
        print(f"  NEW unguarded comparison in {f}: {line}  (add is_number; see the docstring)")
    if fixed and "--check" in sys.argv:
        print("  baseline has fixed entries; shrink it with: python3 scripts/check_numeric_guards.py --write-baseline")
    return 1 if "--check" in sys.argv and new else 0


if __name__ == "__main__":
    sys.exit(main())
