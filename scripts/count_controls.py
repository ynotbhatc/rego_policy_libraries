#!/usr/bin/env python3
"""Count control-level checks across the library, from OPA's own parser (scripts/rego_ast.py holds the rule):
per module, every distinct control id it evaluates, plus each violation rule or check entry that carries no id.

Usage: python3 scripts/count_controls.py [root] [--write-json] [--check-readme]
       --write-json   writes docs/metrics.json (shields.io endpoint schema) for the README badge
       --check-readme fails if README.md or docs/metrics.json disagree with the count (CI)
Make:  make count
"""
import json, re, sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from rego_ast import parse_tree, checks, items

args = [a for a in sys.argv[1:] if not a.startswith("--")]
root = pathlib.Path(args[0]) if args else pathlib.Path(__file__).resolve().parent.parent
asts = parse_tree(root)
total = cited = uncited = 0
for rel, ast in asts.items():
    n, ids, u = checks(ast)
    total += n; cited += len(ids); uncited += u
print(f"files={len(asts)} cited_controls={cited} uncited_checks={uncited} total={total}")
METRICS = root / "docs" / "metrics.json"
metrics = {"schemaVersion": 1, "label": "control-level checks", "message": f"{total:,}", "color": "blue"}
if "--write-json" in sys.argv:
    METRICS.parent.mkdir(exist_ok=True)
    METRICS.write_text(json.dumps(metrics, indent=2) + "\n")
    print(f"wrote {METRICS.relative_to(root)}")
if "--check-readme" in sys.argv:
    if METRICS.exists():
        current = json.loads(METRICS.read_text())
        if current.get("message") != metrics["message"]:
            print(f"docs/metrics.json says {current.get('message')}; make count says {metrics['message']}. Run: python3 scripts/count_controls.py --write-json"); sys.exit(1)
    else:
        print("docs/metrics.json missing; run: python3 scripts/count_controls.py --write-json"); sys.exit(1)
    readme = (root / "README.md").read_text(errors="ignore")
    quoted = [int(x.replace(",", "")) for x in re.findall(r"\*\*([0-9][0-9,]+) control-level checks", readme)]
    if not quoted:
        print("README.md quotes no control-level count"); sys.exit(1)
    bad = [q for q in quoted if q != total]
    if bad:
        print(f"README.md quotes {bad} control-level checks; make count says {total}. Restamp the README."); sys.exit(1)
    print(f"README.md control-level count matches ({total}).")
