#!/usr/bin/env python3
"""Count control-level checks across the library, from OPA's own parser (scripts/rego_ast.py holds the rule):
per module, every distinct control id it evaluates, plus each violation rule or check entry that carries no id.

Usage: python3 scripts/count_controls.py [root] [--write-json] [--check-readme]
       --write-json   writes docs/metrics.json (shields.io endpoint schema) for the README badge
       --check-readme fails if README.md or docs/metrics.json disagree with the count (CI); also checks the
                      README's policy-file counts, the What's-in-the-box category rows, the STIG platform
                      count and the OSCAL catalog figures against the tree and dist/catalogs/index.json
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

    # The other numbers the README states, each measured the same way every time.
    def quote(pattern, label):
        m = re.search(pattern, readme)
        if not m:
            print(f"README.md no longer states {label} (pattern {pattern!r})"); sys.exit(1)
        return int(m.group(1).replace(",", ""))

    problems = []
    def expect(label, stated, actual):
        if stated != actual:
            problems.append(f"{label}: README says {stated:,}, tree says {actual:,}")

    rels = [pathlib.Path(r).as_posix() for r in asts]
    expect("production-ready Rego policies", quote(r"\*\*([0-9,]+) production-ready Rego policies\*\*", "the policy-file count"), len(rels))
    all_rego = sum(1 for f in root.rglob("*.rego") if ".git" not in f.parts and "node_modules" not in f.parts)
    expect(".rego files including tests", quote(r"\(([0-9,]+) including tests", "the including-tests count"), all_rego)

    def under(*prefixes):
        return sum(1 for r in rels if any(r == pfx or r.startswith(pfx + "/") for pfx in prefixes))
    rows = {
        "CIS Benchmarks + DISA STIGs": under("benchmarks/cis", "benchmarks/stig"),
        "Federal & K8s hardening baselines": under("benchmarks/scuba", "benchmarks/nsa_cisa", "benchmarks/pss", "benchmarks/supply_chain"),
        "Regulatory Frameworks": under("frameworks"),
        "Enforcement": under("enforcement"),
        "Governance": under("governance"),
        "Crosswalks": under("crosswalk"),
        "Threat Detection": under("threat_detection"),
    }
    for label, actual in rows.items():
        expect(f"What's-in-the-box row {label!r}", quote(r"\| \*\*" + re.escape(label) + r"\*\* \| ([0-9,]+) \|", f"the {label!r} row"), actual)
    if sum(rows.values()) != len(rels):
        problems.append(f"What's-in-the-box rows sum to {sum(rows.values())}, policy files are {len(rels)}: a directory is missing from the row map in count_controls.py")

    stig_dirs = sorted(d.name for d in (root / "benchmarks" / "stig").iterdir() if d.is_dir() and not d.name.startswith("_") and d.name != "tests")
    expect("DISA STIG platforms", quote(r"DISA STIGs — ([0-9]+) platforms", "the STIG platform count"), len(stig_dirs))

    index = root / "converters" / "exports" / "oscal" / "dist" / "catalogs" / "index.json"
    if index.exists():
        idx = json.loads(index.read_text())
        n_cat, n_ctl = idx["frameworks"], sum(r["controls"] for r in idx["catalogs"])
        expect("framework catalogs on the claim line", quote(r"across ([0-9,]+) framework catalogs", "the catalog count on the claim line"), n_cat)
        expect("OSCAL catalogs in the Continuous ATO table", quote(r"one per framework, ([0-9,]+) catalogs, [0-9,]+ controls", "the Continuous ATO catalog count"), n_cat)
        expect("OSCAL controls in the Continuous ATO table", quote(r"one per framework, [0-9,]+ catalogs, ([0-9,]+) controls", "the Continuous ATO control count"), n_ctl)
    else:
        problems.append("converters/exports/oscal/dist/catalogs/index.json missing; run make oscal")
    if problems:
        print("README.md numbers drifted from the tree:"); [print("  - " + x) for x in problems]
        print("Fix the README (or the row map in scripts/count_controls.py if a directory moved)."); sys.exit(1)
    print(f"README.md figures match the tree: {len(rels)} policies, {all_rego} .rego files, {len(stig_dirs)} STIG platforms, {rows['CIS Benchmarks + DISA STIGs']}/{rows['Federal & K8s hardening baselines']}/{rows['Regulatory Frameworks']}/{rows['Enforcement']}/{rows['Governance']}/{rows['Crosswalks']}/{rows['Threat Detection']} per category, OSCAL catalogs as published.")
