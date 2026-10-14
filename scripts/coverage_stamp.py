#!/usr/bin/env python3
"""Scan every policy module and write what it holds into its own METADATA, so density and gaps are
validated by CI instead of rediscovered.

    python3 scripts/coverage_stamp.py            # stamp custom.coverage in every module that has a METADATA block
    python3 scripts/coverage_stamp.py --check    # recompute and fail if any stamp is stale (CI)
    python3 scripts/coverage_stamp.py --report docs/COVERAGE_SCAN.md   # the human report

What is stamped (custom.coverage):
  checks     control-level checks the module holds (the same rule as `make count`: scripts/rego_ast.py)
  cited      how many of those carry a citable control id (CIS 1.3.1, §7122(a)(1), RHEL-09-611010, ...)
  expected   the standard's own count when the module declares it (`standard_total`, cited to the standard's text),
             else the total the module declares for its own table (`total_controls: 172`)
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
  guard      where fail-closed is enforced for this module, measured by evaluating the whole tree on empty input:
             self          the module's own report is not compliant (or it emits violations) on empty input
             orchestrator  the module is silent on empty input, but an orchestrator in its tree that references
                           its package is not compliant on empty input, so the gap is caught one level up
             none          the module is silent on empty input and nothing above it catches that: fail-open
             n/a           overlays, gates and modules with no report or violations rule
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
TOTAL_KEYS = ("standard_total", "total_controls", "controls_total", "total_recommendations", "total_checks")  # first match wins
# Modules legitimately below their own declared total, with the reason. Everything else below 90 % fails --check.
KNOWN_GAPS = {
    "frameworks/privacy/iso27701/iso27701_main.rego": "ISO/IEC 27701 text is licensed; 67 of 134 controls written from public summaries",
    "benchmarks/cis/windows_11/cis_windows_11.rego": "CIS Windows 11 benchmark text is licensed; 210 of 267 recommendations implemented",
}
KEYS = ("checks", "cited", "expected", "found", "scope", "density", "basis", "tested", "entrypoint", "guard", "as_of")
# modules that evaluate nothing of their own by design
OVERLAYS = {"benchmarks/supply_chain/", "crosswalk/"}
GATES = {"enforcement/", "governance/ai/action_classification.rego", "governance/ai/context_validation.rego", "governance/ai/authorization.rego",
         "governance/exceptions/", "governance/mcp/", "governance/oidc/"}


def version():
    m = re.search(r"^## \[(\d+\.\d+\.\d+)\]", (ROOT / "CHANGELOG.md").read_text(), re.M)
    return "v" + (m.group(1) if m else "0.0.0")


def empty_input_state(root=ROOT):
    """{package: (compliant, violation_count, has_report)} from one `opa eval` of the whole policy tree on {}."""
    import json, subprocess, tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        f.write("{}"); empty = f.name
    trees = [d for d in ("benchmarks", "frameworks", "governance", "enforcement", "threat_detection", "crosswalk") if (root / d).is_dir()]
    cmd = ["opa", "eval", "-f", "json", "--ignore", ".github", "--ignore", "converters", "--ignore", "tests", "-i", empty, "data"]
    for d in trees:
        cmd += ["-d", str(root / d)]
    out = subprocess.run(cmd, capture_output=True, text=True)
    if out.returncode != 0:
        raise SystemExit("opa eval on empty input failed:\n" + out.stderr[:500])
    data = json.loads(out.stdout)["result"][0]["expressions"][0]["value"]
    state = {}
    def lookup(pkg):
        node = data
        for seg in pkg.split("."):
            if not isinstance(node, dict) or seg not in node:
                return None
            node = node[seg]
        return node if isinstance(node, dict) else None
    def record(pkg):
        node = lookup(pkg)
        if node is None:
            state[pkg] = (None, None, False); return
        rep = node.get("compliance_report", node.get("report"))
        comp = rep.get("compliant") if isinstance(rep, dict) else None
        if comp is None and isinstance(rep, dict):
            comp = rep.get("overall_compliant")
        if comp is None:
            comp = node.get("compliant")   # modules with no report object expose a bare `compliant` rule
        v = node.get("violations")
        if not isinstance(v, (list, dict)) and isinstance(rep, dict):
            v = rep.get("violations")   # orchestrators that only publish a report (m365 v7)
            if not isinstance(v, (list, dict)) and isinstance(rep.get("violation_count"), int):
                v = [None] * rep["violation_count"]
        state[pkg] = (comp, (len(v) if isinstance(v, (list, dict)) else None), isinstance(rep, dict))
    return record, state


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
    record, state = empty_input_state(root)
    rows = {}
    for rel, ast in asts.items():
        n, ids, uncited = checks(ast)
        names = {rule_name(r) for r in ast.get("rules", [])}
        entry = "compliance_report" if "compliance_report" in names else ("report" if "report" in names else "none")
        expected = None; expected_key = None
        for name, trows in tables(ast):
            if name in ("compliance_report", "report"):
                found_keys = {k: v for k, v in trows if k in TOTAL_KEYS and v["type"] == "number"}
                for k in TOTAL_KEYS:
                    if k in found_keys:
                        expected = int(found_keys[k]["value"]); expected_key = k; break
        pkg = package(ast)
        record(pkg)
        rows[rel] = {"checks": n, "cited": len(ids), "expected": expected, "found": None, "scope": None, "_expected_key": expected_key, "_ids": ids,
                     "tested": pkg in tested, "entrypoint": entry, "guard": None, "as_of": ver,
                     "_package": pkg, "_uncited": uncited, "_has_meta": "# METADATA" in (root / rel).read_text(errors="ignore")}
    # density. An orchestrator declares the whole framework's total while its controls live in sibling modules,
    # so a declaring file with no checks of its own is judged on its directory's sum (scope: directory).
    # An orchestrator (<name>_main / _complete / _simplified) declares the whole framework's total while the
    # controls live in sibling modules and sub-directories, so it is judged on its directory subtree (scope:
    # directory); any other declaring module is judged on itself.
    orch_dirs = {rel.rsplit("/", 1)[0] + "/" for rel in rows if ORCH.search(rel) and not rel.startswith(tuple(OVERLAYS))}
    def has_orchestrator(rel):
        return (not ORCH.search(rel)) and any(rel.startswith(d) and rel != d for d in orch_dirs)
    def siblings(rel):
        d = rel.rsplit("/", 1)[0] + "/"
        return sum(1 for rel2 in rows if rel2.startswith(d) and rel2 != rel)
    def subtree(rel, units):
        d = rel.rsplit("/", 1)[0] + "/"
        if units == "ids":
            return len(set().union(*(r2["_ids"] for rel2, r2 in rows.items() if rel2.startswith(d))))
        return sum(r2["checks"] for rel2, r2 in rows.items() if rel2.startswith(d))
    for rel, r in rows.items():
        n, expected = r["checks"], r["expected"]
        # a standard_total counts the standard's controls, so it is compared with distinct cited ids;
        # a module's own total_controls counts its checks, so it is compared with checks
        units = "ids" if r["_expected_key"] == "standard_total" else "checks"
        own = len(r["_ids"]) if units == "ids" else n
        if expected and (ORCH.search(rel) or n == 0):
            found, scope = subtree(rel, units), "directory"
        else:
            found, scope = own, "module"
        if expected:
            ratio = found / expected
            density, basis = ("full" if ratio >= 0.9 else "partial" if ratio >= 0.5 else "sparse"), "declared-total"
            r["found"], r["scope"] = found, scope
        elif any(rel.startswith(o) for o in OVERLAYS):
            density, basis = "overlay", "role"        # scores or correlates other modules; holds no checks of its own
        elif any(rel.startswith(g) for g in GATES):
            density, basis = "gate", "role"           # allow/deny decision for an operational gate, not control findings
        elif ORCH.search(rel) and (n == 0 or siblings(rel) > 0):
            density, basis = "orchestrator", "role"   # aggregates section modules; its few own checks are fail-closed notices
        elif n == 0:
            density, basis = "unrecognised", "role"
        elif n < 10 and has_orchestrator(rel):
            density, basis = "section", "role"        # one section of a framework whose orchestrator aggregates it
        else:
            density, basis = ("sized" if n >= 10 else "sparse" if n >= 3 else "stub"), "size"
        r["density"], r["basis"] = density, basis
    # guard: where fail-closed is enforced, from the empty-input evaluation
    orch_files = {rel2: rows[rel2]["_package"] for rel2 in rows if ORCH.search(rel2)}
    orch_src = {rel2: (root / rel2).read_text(errors="ignore") for rel2 in orch_files}
    for rel, r in rows.items():
        pkg = r["_package"]; comp, vn, has_rep = state.get(pkg, (None, None, False))
        if r["density"] in ("overlay", "gate") or (not has_rep and r["entrypoint"] == "none" and vn is None):
            r["guard"] = "n/a"; continue
        if comp is False or (vn or 0) > 0:
            r["guard"] = "self"; continue
        # silent on empty input: is an orchestrator above it fail-closed and does it reference this package?
        guarded = False
        for orel, opkg in orch_files.items():
            if orel == rel or not rel.startswith(orel.rsplit("/", 1)[0] + "/"):
                continue
            ocomp, ovn, _ = state.get(opkg, (None, None, False))
            if (ocomp is False or (ovn or 0) > 0) and (pkg in orch_src[orel] or pkg.rsplit(".", 1)[-1] in orch_src[orel]):
                guarded = True; break
        r["guard"] = "orchestrator" if guarded else "none"
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
         "- **density**: `full` / `partial` / `sparse` against a declared total; without one, `sized` (≥ 10), `sparse` (3–9), `stub` (1–2) say only how big the module is. `section` is a small module that an orchestrator in the same tree aggregates (judged there). `orchestrator` aggregates section modules and holds no checks of its own. `overlay` scores or correlates other modules (supply chain, crosswalk) and `gate` is an allow/deny decision; both hold no control checks by design. `unrecognised` means zero checks in a shape the counter does not read yet: a counter work item, not a verdict on the policy.", "",
         "## Distribution", "", "| density | modules |", "|---|---|"]
    for k in ("full", "partial", "sparse", "stub", "sized", "section", "orchestrator", "overlay", "gate", "unrecognised"):
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
    none = sorted(rel for rel, r in rows.items() if r["guard"] == "none")
    byg = collections.Counter(r["guard"] for r in rows.values())
    L += ["", f"## Fail-closed guard ({byg.get('self', 0)} self, {byg.get('orchestrator', 0)} by orchestrator, {byg.get('none', 0)} none, {byg.get('n/a', 0)} n/a)", "",
          "Measured by evaluating the whole tree on empty input. `self`: the module's own report is not compliant on empty input. `orchestrator`: the module is silent on empty input, but an orchestrator in its tree that references it is fail-closed, so the gap is caught one level up (by design for sectioned benchmarks). `none`: silent on empty input and nothing above it catches that — **these are fail-open**, the work queue for the library's fail-closed rule.", "",
          f"### Fail-open modules, no guard ({len(none)})", ""] + [f"- `{rel}`" for rel in none]
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
        # the counting rule is validated against every module's own declared total: a module that declares
        # total_controls and is found below 90 % of it is either a real gap (named here) or a counter regression
        rows = scan()
        below = sorted(rel for rel, r in rows.items() if r["expected"] and r["found"] < 0.9 * r["expected"])
        unexpected = [rel for rel in below if rel not in KNOWN_GAPS]
        print(f"declared totals: {sum(1 for r in rows.values() if r['expected']) - len(below)} of {sum(1 for r in rows.values() if r['expected'])} modules within 10 % of their own declared total; known gaps: {len(KNOWN_GAPS)}")
        if unexpected:
            for rel in unexpected:
                print(f"BELOW DECLARED {rel}: found {rows[rel]['found']} of {rows[rel]['expected']} — a real gap (add to KNOWN_GAPS with its reason) or a counter regression")
        return 1 if (stale or unexpected) else 0
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
