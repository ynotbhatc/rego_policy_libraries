#!/usr/bin/env python3
"""Count control-level checks across the library (not files).

The README counts policy FILES. A file is one to a few hundred controls, so
comparisons with libraries that count one rule per setting need the control
count. This counts, in every non-test .rego file:

  bodies      - `violation(s)|deny|warn|finding(s) contains <x> if` rule bodies
  object rows - entries of top-level tables whose values are objects
                (controls / items / standards tables: one row = one control)
  string rows - entries of top-level check tables whose values are the
                violation message (the *_checks / _notice / _consent ... maps)

Tables that are not controls (sections, chapters, groups, deadlines, report
scaffolding) are excluded by name. A violation body that iterates a table is
counted once in addition to the rows it iterates; that over-counts by one per
table, which is noise at this scale.

Usage: python3 scripts/count_controls.py [root]   (default: repo root)
Make:  make count
"""
import re, sys, pathlib
_args = [a for a in sys.argv[1:] if not a.startswith("--")]
root = pathlib.Path(_args[0]) if _args else pathlib.Path(__file__).resolve().parent.parent
body_re = re.compile(r'^\s*(violations?|deny|warn|findings?)\s+contains\s+\w+\s+if\b')
map_start = re.compile(r'^([A-Za-z_][A-Za-z0-9_]*)\s*:=\s*\{\s*$')
obj_row = re.compile(r'^\s*"[A-Za-z0-9][A-Za-z0-9._ -]*":\s*\{')
str_row = re.compile(r'^\s*"[A-Za-z0-9][A-Za-z0-9._ -]*":\s*"')
include = re.compile(r'(check|notice|consent|obligation|security|breach|retention|right|transfer|government|lawful|flag|field|timing|submission|report|auditor|certification|sdf|children|appeal|exception|opt_out|access|registration|vasp|reporting|coordination|logging|annexure|requirement|control|item|standard|ksi|activit|component)', re.I)
exclude = re.compile(r'^(sections|chapters|groups|first_report_deadline|notification_clocks|rules_commencement|dated_obligations|compliance_report|availability_targets|penalty|legacy|_in)$')
bodies = obj = strs = files = 0
for f in root.rglob('*.rego'):
    rel = f.relative_to(root).as_posix()
    if re.search(r'(^|/)(test_|.*_test\.rego$)', rel) or '/tests/' in rel: continue
    files += 1
    cur = None
    for line in f.read_text(errors='ignore').splitlines():
        if body_re.match(line): bodies += 1; continue
        m = map_start.match(line)
        if m: cur = m.group(1); continue
        if line.strip() == '}': cur = None; continue
        if cur and not exclude.match(cur):
            if obj_row.match(line): obj += 1
            elif str_row.match(line) and include.search(cur): strs += 1
total = bodies + obj + strs
print(f"files={files} bodies={bodies} table_object_rows={obj} table_string_rows={strs} total={total}")
if "--check-readme" in sys.argv:
    readme = (root / "README.md").read_text(errors="ignore")
    quoted = [int(x.replace(",", "")) for x in re.findall(r"\*\*([0-9][0-9,]+) control-level checks", readme)]
    if not quoted:
        print("README.md quotes no control-level count"); sys.exit(1)
    bad = [q for q in quoted if q != total]
    if bad:
        print(f"README.md quotes {bad} control-level checks; make count says {total}. Restamp the README."); sys.exit(1)
    print(f"README.md control-level count matches ({total}).")
