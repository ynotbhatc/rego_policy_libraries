#!/usr/bin/env python3
"""Scan every policy module and write what it holds into its own METADATA, so density and gaps are
validated by CI instead of rediscovered.

    python3 scripts/coverage_stamp.py            # stamp custom.coverage in every module that has a METADATA block
    python3 scripts/coverage_stamp.py --check    # recompute and fail if any stamp is stale (CI)
    python3 scripts/coverage_stamp.py --report docs/COVERAGE_SCAN.md   # the human report

What is stamped (custom.coverage):
  checks     control-level checks the module holds (the same rule as `make count`: scripts/rego_ast.py)
  cited      how many of those carry a citable control id (CIS 1.3.1, §7122(a)(1), RHEL-09-611010, ...)
  expected   the total the module itself declares in its report literal (total_controls: 172), when it does
  found      what is compared with expected: the module's own checks, or (scope: directory) the sum over the
             directory when the declaring file is an orchestrator with no checks of its own
  density    full | partial | sparse | stub | orchestrator | unrecognised
             with expected: checks/expected >= 0.9 full, >= 0.5 partial, else sparse
             without:       >= 10 checks ok -> "full" is not claimed; "sized" means no basis to judge, so the
                            label is by size: >= 10 "sized", 3..9 "sparse", 1..2 "stub"
             orchestrator   0 checks and the file only aggregates section modules (<name>_main / _complete)
             unrecognised   0 checks in a shape the counter does not read: a work item for the counter
  basis      declared-total | size | role
  tested     a test file exists for the package
  entrypoint compliance_report | report | none
  as_of      library version the scan was made at (CHANGELOG)
Nothing here is an opinion about quality; it is what the parser sees, and --check keeps it true.
"""
from __future__ import annotations
import argparse, collections, json, pathlib, re, sys
HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
from rego_ast import parse_tree, checks, tables, package, rule_name  # noqa: E402

ORCH = re.compile(r"(_main|_complete|_simplified)\.rego$")
TOTAL_KEYS = ("total_controls", "controls_total", "total_recommendations", "total_checks")
KEYS = ("checks", "cited", "expected", "found", "scope", "density", "basis", "tested", "entrypoint", "as_of")


def version():
    m = re.search(r"^## \[(\d+\.\d+\.\d+)\]", (ROOT / "CHANGELOG.md").read_text(), re.M)
    return "v" + (m.group(1) if m else "0.0.0")


def tested_packages():
    out = set()
    for f in ROOT.rglob("*.rego"):
        rel = f.relative_to(ROOT).as_posix()
        if re.search(r"(^|/)(test_|.*_test\.rego$)", rel) or "/tests/" in rel:
            m = re.search(r"^package\s+([\w.]+)", f.read_text(errors="ignore"), re.M)
            if m:
                p = m.group(1)
                out.add(p); out.add(re.sub(r"(_test|\.test|\.tests?)$", "", p)); out.add(p.rsplit(".", 1)[0])
    return out


def scan(root=ROOT):
    asts = parse_tree(root)
    tested = tested_packages()
    ver = version()
    rows = {}
    for rel, ast in asts.items():
        n, ids, uncited = checks(ast)
        names = {rule_name(r) for r in ast.get("rules", [])}
        entry = "compliance_report" if "compliance_report" in names else ("report" if "report" in names else "none")
        expected = None
        for name, trows in tables(ast):
            if name in ("compliance_report", "report"):
                for k, v in trows:
                    if k in TOTAL_KEYS and v["type"] == "number":
                        expected = int(v["value"])
        pkg = package(ast)
        rows[rel] = {"checks": n, "cited": len(ids), "expected": expected, "found": None, "scope": None,
                     "tested": pkg in tested, "entrypoint": entry, "as_of": ver,
                     "_package": pkg, "_uncited": uncited, "_has_meta": "# METADATA" in (root / rel).read_text(errors="ignore")}
    # density. An orchestrator declares the whole framework's total while its controls live in sibling modules,
    # so a declaring file with no checks of its own is judged on its directory's sum (scope: directory).
    by_dir = collections.Counter()
    for rel, r in rows.items():
        by_dir[rel.rsplit("/", 1)[0]] += r["checks"]
    for rel, r in rows.items():
        n, expected = r["checks"], r["expected"]
        if n == 0 and expected:
            found, scope = by_dir[rel.rsplit("/", 1)[0]], "directory"
        else:
            found, scope = n, "module"
        if expected:
            ratio = found / expected
            density, basis = ("full" if ratio >= 0.9 else "partial" if ratio >= 0.5 else "sparse"), "declared-total"
            r["found"], r["scope"] = found, scope
        elif n == 0:
            density, basis = ("orchestrator", "role") if ORCH.search(rel) else ("unrecognised", "role")
        else:
            density, basis = ("sized" if n >= 10 else "sparse" if n >= 3 else "stub"), "size"
        r["density"], r["basis"] = density, basis
    return rows


def render_block(cov):
    lines = ["#   coverage:"]
    for k in KEYS:
        v = cov.get(k)
        if v is None:
            continue
        lines.append(f"#     {k}: {str(v).lower() if isinstance(v, bool) else v}")
    return "\n".join(lines) + "\n"


CUSTOM_RE = re.compile(r"(?m)^# custom:\n((?:#   [^\n]*\n|#     [^\n]*\n)*)")
COV_RE = re.compile(r"(?m)^#   coverage:\n(?:#     [^\n]*\n)*")


def stamp(root=ROOT):
    rows = scan(root)
    changed, skipped = 0, []
    for rel, cov in rows.items():
        if not cov["_has_meta"]:
            skipped.append(rel); continue
        p = root / rel; src = p.read_text()
        m = CUSTOM_RE.search(src)
        if not m:
            skipped.append(rel); continue
        block = render_block(cov)
        # remove every existing coverage block wherever it sits (a misplaced one from an earlier run included),
        # then write exactly one inside the custom block
        src = COV_RE.sub("", src)
        m = CUSTOM_RE.search(src)
        new_src = src[:m.end(1)] + block + src[m.end(1):]
        if new_src != src:
            p.write_text(new_src); changed += 1
    return rows, changed, skipped


def parse_stamp(src):
    m = COV_RE.search(src)
    if not m:
        return None
    out = {}
    for line in m.group(0).splitlines()[1:]:
        k, _, v = line[6:].partition(": ")
        out[k.strip()] = v.strip()
    return out


def check(root=ROOT):
    rows = scan(root)
    stale = []
    for rel, cov in rows.items():
        if not cov["_has_meta"]:
            continue
        text = (root / rel).read_text()
        if len(COV_RE.findall(text)) != 1:
            stale.append((rel, f"{len(COV_RE.findall(text))} coverage blocks; exactly one expected inside custom")); continue
        got = parse_stamp(text)
        want = {k: (str(cov[k]).lower() if isinstance(cov[k], bool) else str(cov[k])) for k in KEYS if cov.get(k) is not None}
        if got is None:
            stale.append((rel, "no coverage stamp")); continue
        diff = {k: (got.get(k), want[k]) for k in want if got.get(k) != want[k] and k != "as_of"}
        if diff:
            stale.append((rel, diff))
    return stale


def report(rows, out_path):
    ver = version()
    by_density = collections.Counter(r["density"] for r in rows.values())
    total = sum(r["checks"] for r in rows.values())
    fw = collections.defaultdict(lambda: {"files": 0, "checks": 0, "expected": 0, "declared": 0, "tested": 0})
    for rel, r in rows.items():
        key = "/".join(rel.split("/")[:3]) if rel.startswith(("benchmarks/", "frameworks/")) else "/".join(rel.split("/")[:2])
        f = fw[key]; f["files"] += 1; f["checks"] += r["checks"]; f["tested"] += r["tested"]
        if r["expected"]:
            f["expected"] += r["expected"]; f["declared"] += 1
    L = [f"# Coverage scan — every module, what the parser sees", "",
         f"**As of:** {ver} · **Modules:** {len(rows)} · **Control-level checks:** {total:,} · generated by `scripts/coverage_stamp.py --report`; the same numbers are stamped into each module's `# METADATA` (`custom.coverage`) and verified by CI (`--check`).", "",
         "## How to read it", "",
         "- **checks**: distinct control ids a module evaluates plus any violation rule without an id (the `make count` rule, `scripts/rego_ast.py`).",
         "- **expected**: only when the module itself declares a total in its report literal (`total_controls: 172`). We do not invent expectations.",
         "- **density**: `full` / `partial` / `sparse` against a declared total; without one, `sized` (≥ 10), `sparse` (3–9), `stub` (1–2) say only how big the module is. `orchestrator` aggregates section modules and holds no checks of its own. `unrecognised` means zero checks in a shape the counter does not read yet: a counter work item, not a verdict on the policy.", "",
         "## Distribution", "", "| density | modules |", "|---|---|"]
    for k in ("full", "partial", "sparse", "stub", "sized", "orchestrator", "unrecognised"):
        L.append(f"| {k} | {by_density.get(k, 0)} |")
    L += ["", "## By family", "", "| family | modules | checks | declared total (modules declaring) | tested modules |", "|---|---|---|---|---|"]
    for k, f in sorted(fw.items(), key=lambda x: -x[1]["checks"]):
        L.append(f"| `{k}` | {f['files']} | {f['checks']:,} | {f['expected'] or '—'} ({f['declared']}) | {f['tested']}/{f['files']} |")
    gaps = [(rel, r) for rel, r in rows.items() if r["expected"] and r["found"] < 0.9 * r["expected"]]
    L += ["", "## Modules below their own declared total", "", "The module says how many controls the standard has; the parser finds fewer. These are the concrete \"missing controls\" the scan can prove.", "",
          "| module | declared | found | scope | gap | density |", "|---|---|---|---|---|---|"]
    for rel, r in sorted(gaps, key=lambda x: x[1]["found"] - x[1]["expected"]):
        L.append(f"| `{rel}` | {r['expected']} | {r['found']} | {r['scope']} | {r['expected'] - r['found']} | {r['density']} |")
    if not gaps:
        L.append("| — | | | | | |")
    thin = [(rel, r) for rel, r in rows.items() if r["density"] in ("sparse", "stub") and r["basis"] == "size"]
    L += ["", f"## Sparse and stub modules without a declared total ({len(thin)})", "", "Small by size; whether that is a gap depends on the standard, which these modules do not declare. Declaring `total_controls` in the report literal moves them into the table above.", "",
          "| module | checks | cited | tested |", "|---|---|---|---|"]
    for rel, r in sorted(thin, key=lambda x: (x[1]["checks"], x[0])):
        L.append(f"| `{rel}` | {r['checks']} | {r['cited']} | {'yes' if r['tested'] else 'no'} |")
    unrec = [rel for rel, r in rows.items() if r["density"] == "unrecognised"]
    L += ["", f"## Unrecognised shapes ({len(unrec)})", "", "Zero checks found, not an orchestrator. Either the module expresses checks in a form `scripts/rego_ast.py` does not read yet (extend the counter) or it is an overlay with no checks of its own (crosswalk, supply-chain substrate, enforcement gates with computed messages).", ""]
    L += [f"- `{rel}`" for rel in sorted(unrec)]
    untested = [rel for rel, r in rows.items() if not r["tested"] and r["checks"] > 0]
    L += ["", f"## Modules with checks but no test file ({len(untested)})", "", "Work queue, same as docs/COVERAGE.md.", ""]
    L += [f"- `{rel}`" for rel in sorted(untested)]
    nometa = [rel for rel, r in rows.items() if not r["_has_meta"]]
    L += ["", f"## Modules without a METADATA block ({len(nometa)}) — not stamped", ""] + [f"- `{rel}`" for rel in sorted(nometa)]
    pathlib.Path(out_path).write_text("\n".join(L) + "\n")
    return len(gaps), len(thin), len(unrec), len(untested)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true"); ap.add_argument("--report", default=None); ap.add_argument("--json", default=None)
    a = ap.parse_args()
    if a.check:
        stale = check()
        for rel, why in stale[:30]:
            print(f"STALE {rel}: {why}")
        print(f"coverage stamps: {'all current' if not stale else str(len(stale)) + ' stale — run: python3 scripts/coverage_stamp.py'}")
        return 1 if stale else 0
    rows, changed, skipped = stamp()
    print(f"stamped {changed} modules ({len(rows)} scanned, {len(skipped)} without a METADATA block skipped)")
    if a.json:
        pathlib.Path(a.json).write_text(json.dumps(rows, indent=1))
    if a.report:
        g, t, u, n = report(rows, a.report)
        print(f"report -> {a.report}: {g} below declared total, {t} sparse/stub by size, {u} unrecognised, {n} untested")
    return 0


if __name__ == "__main__":
    sys.exit(main())
