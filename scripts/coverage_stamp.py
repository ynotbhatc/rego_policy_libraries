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
  found      what is compared with expected, counted so that nothing is counted twice: distinct control ids
             (control_ids(): a bare snake_case word among numbered ids is a section or report key; "CSF DE.AE-02" beside
             "DE.AE-02" is one control), or, for a module whose own total counts checks rather than ids, distinct
             (id, text) checks. With scope: directory (the declaring file is an orchestrator) the ids and checks of
             the directory are united, not summed, so a control two files evaluate is one.
  density    full | over | partial | sparse | stub | orchestrator | unrecognised
             with expected: found == expected full; found < expected partial (>= half) or sparse, always with
                            the real number, and --check fails unless the module is in KNOWN_GAPS with its reason;
                            found > expected "over": the module holds more than it declares (extension checks,
                            fail-closed notices, or a stale declaration), which is not evidence that every
                            declared control is there, so it is not called full.
                            (Until 2026-11-23 anything at or above 90 % of the declared total, with no upper
                            bound, was "full": 399 of 400 and 198 of 7 both read as full.)
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
  as_of      the library version (latest release heading in CHANGELOG) at which this module's stamp content last
             changed. It is NOT "the version of the last scan": a re-scan that finds the same checks, cited, expected,
             found, scope, density, basis, tested, entrypoint and guard keeps the existing as_of, so a normal
             re-stamp touches only the modules whose numbers moved and does not rewrite ~830 files at each release.
             --check fails on an as_of that is missing, malformed or newer than the changelog's latest release;
             a stamp whose content moved is stale in any case (and gets the current version when re-stamped).
Nothing here is an opinion about quality; it is what the parser sees, and --check keeps it true.
"""
from __future__ import annotations
import argparse, collections, json, pathlib, re, sys
HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
from rego_ast import parse_tree, checks, items, tables, package, rule_name  # noqa: E402

ORCH = re.compile(r"(_main|_complete|_simplified)\.rego$")
TOTAL_KEYS = ("standard_total", "total_controls", "controls_total", "total_recommendations", "total_checks")  # first match wins
# Modules found below their own declared total, each with the reason. Any other module below its declared total
# (by any amount: there is no tolerance) fails --check. An entry whose module is no longer below is reported, not failed.
_WIN_MANUAL = ("the two Manual recommendations are decided by attestation (attestation_validation.rego, "
               "REQUIRES_ATTESTATION), a table shape the counter does not read as control ids; the module's own "
               "CONTROL_INDEX lists every recommendation")
KNOWN_GAPS = {
    "benchmarks/cis/windows_10_modular/cis_windows_10_main.rego": _WIN_MANUAL,
    "benchmarks/cis/windows_11_modular/cis_windows_11_main.rego": _WIN_MANUAL,
    "benchmarks/cis/windows_server_2016_modular/cis_windows_2016_main.rego": _WIN_MANUAL,
    "benchmarks/cis/windows_server_2019_modular/cis_windows_2019_main.rego": _WIN_MANUAL,
    "benchmarks/cis/windows_server_2022_modular/cis_windows_2022_main.rego": _WIN_MANUAL,
    "benchmarks/cis/windows_server_2025_modular/cis_windows_2025_main.rego": _WIN_MANUAL,
    "frameworks/compliance/ncsc_caf/caf_main.rego":
        "different units: the section modules cite no Contributing Outcome ids, so 22 uncited violation rules are "
        "set against the 23 outcomes the orchestrator declares, and caf_a3_asset_management.rego is in a shape the "
        "counter does not read. Open work: cite the outcome id in each finding",
    "frameworks/regulatory/cfr_part_11/cfr_part_11_main.rego":
        "42 distinct checks found for a declared 43 (weekly audit 2026-11-23); the declared total is being "
        "reconciled in the module",
}
KEYS = ("checks", "cited", "expected", "found", "scope", "density", "basis", "tested", "entrypoint", "guard", "as_of")
# modules that evaluate nothing of their own by design
OVERLAYS = {"benchmarks/supply_chain/", "crosswalk/"}
GATES = {"enforcement/", "governance/ai/action_classification.rego", "governance/ai/context_validation.rego", "governance/ai/authorization.rego",
         "governance/exceptions/", "governance/mcp/", "governance/oidc/"}


def control_ids(ids):
    """The ids that stand for controls, each once. Beside numbered ids, a bare snake_case word is a section name
    or a report key the counter picked up ("logging", "risk_breakdown"), not a control; and "<word> <id>" beside
    a bare "<id>" is the same control cited two ways ("CSF DE.AE-02" / "DE.AE-02"). Used only for the comparison
    with a declared total; the published check count (`make count`) is not changed by this."""
    kept = {i.strip() for i in ids}
    if any(re.search(r"\d", i) for i in kept):
        kept = {i for i in kept if not re.fullmatch(r"[a-z_]+", i)}
    out = set()
    for i in kept:
        word, _, rest = i.partition(" ")
        out.add(rest.strip() if rest.strip() in kept and word.rstrip(":").isalpha() else i)
    return out


def density_of(found, expected):
    """Label for a module with a declared total. No tolerance either way: equal is full, short is short."""
    if found == expected:
        return "full"
    if found > expected:
        return "over"
    return "partial" if found * 2 >= expected else "sparse"


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
        its = items(ast)
        rows[rel] = {"checks": n, "cited": len(ids), "expected": expected, "found": None, "scope": None, "_expected_key": expected_key, "_ids": ids,
                     "_pairs": {(cid, (text or "").strip()) for cid, text, _ in its if cid},
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
    def counted(members):
        """(distinct control ids, distinct checks) over the given rows. Ids and (id, text) checks are united, so a
        control or a check that two files of one directory hold is counted once; uncited checks have no identity
        to compare and are added per file."""
        ids = control_ids(set().union(*(m["_ids"] for m in members)))
        pairs = set().union(*(m["_pairs"] for m in members))
        return len(ids), len(pairs) + sum(m["_uncited"] for m in members)
    for rel, r in rows.items():
        n, expected = r["checks"], r["expected"]
        if expected and (ORCH.search(rel) or n == 0):
            d = rel.rsplit("/", 1)[0] + "/"
            members, scope = [r2 for rel2, r2 in rows.items() if rel2.startswith(d)], "directory"
        else:
            members, scope = [r], "module"
        if expected:
            n_ids, n_checks = counted(members)
            # a standard_total counts the standard's controls, so it is compared with distinct control ids. A
            # module's own total_controls counts either its controls or its checks: ids when they match it
            # exactly (several checks per control), else its checks.
            found = n_ids if (r["_expected_key"] == "standard_total" or n_ids == expected) else n_checks
            density, basis = density_of(found, expected), "declared-total"
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
        # as_of records when the stamp content last changed: keep the existing value while nothing else moved
        old = parse_stamp(src)
        if old and old.get("as_of") and all(old.get(k) == _want(cov).get(k) for k in KEYS if k != "as_of" and (cov.get(k) is not None or old.get(k) is not None)):
            cov = dict(cov, as_of=old["as_of"])
        block = render_block(cov)
        # remove every existing coverage block wherever it sits (a misplaced one from an earlier run included),
        # then write exactly one inside the custom block
        src = COV_RE.sub("", src)
        m = CUSTOM_RE.search(src)
        new_src = src[:m.end(1)] + block + src[m.end(1):]
        if new_src != src:
            p.write_text(new_src); changed += 1
    return rows, changed, skipped


def _want(cov):
    return {k: (str(cov[k]).lower() if isinstance(cov[k], bool) else str(cov[k])) for k in KEYS if cov.get(k) is not None}


def _ver_tuple(v):
    m = re.fullmatch(r"v(\d+)\.(\d+)\.(\d+)", v or "")
    return tuple(int(x) for x in m.groups()) if m else None


def parse_stamp(src):
    m = COV_RE.search(src)
    if not m:
        return None
    out = {}
    for line in m.group(0).splitlines()[1:]:
        k, _, v = line[6:].partition(": ")
        out[k.strip()] = v.strip()
    return out


def check(root=ROOT, rows=None):
    rows = scan(root) if rows is None else rows
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
            continue
        # content is current, so as_of must be the version it last changed at: well-formed and not from the future
        got_v, cur_v = _ver_tuple(got.get("as_of")), _ver_tuple(cov.get("as_of"))
        if got_v is None:
            stale.append((rel, f"as_of {got.get('as_of')!r} is missing or not vX.Y.Z"))
        elif cur_v and got_v > cur_v:
            stale.append((rel, f"as_of {got.get('as_of')} is newer than the latest release {cov['as_of']}"))
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
         "- **found**: what is compared with a declared total: distinct control ids (a bare snake_case word among numbered ids is a section or report key, not a control; one control cited two ways is one), or distinct checks where the module's own total counts checks. Within a directory ids and checks are united, not summed, so nothing is counted twice.",
         "- **density**: against a declared total, `full` only when found equals it; `partial` / `sparse` when found is below it (any shortfall, listed below with the real number); `over` when found is above it, which says the module holds more than it declares and is not a claim that every declared control is present. Without a declared total, `sized` (≥ 10), `sparse` (3–9), `stub` (1–2) say only how big the module is. `section` is a small module that an orchestrator in the same tree aggregates (judged there). `orchestrator` aggregates section modules and holds no checks of its own. `overlay` scores or correlates other modules (supply chain, crosswalk) and `gate` is an allow/deny decision; both hold no control checks by design. `unrecognised` means zero checks in a shape the counter does not read yet: a counter work item, not a verdict on the policy.", "",
         "## Distribution", "", "| density | modules |", "|---|---|"]
    for k in ("full", "over", "partial", "sparse", "stub", "sized", "section", "orchestrator", "overlay", "gate", "unrecognised"):
        L.append(f"| {k} | {by_density.get(k, 0)} |")
    L += ["", "## By family", "", "| family | modules | checks | declared total (modules declaring) | tested modules |", "|---|---|---|---|---|"]
    for k, f in sorted(fw.items(), key=lambda x: -x[1]["checks"]):
        L.append(f"| `{k}` | {f['files']} | {f['checks']:,} | {f['expected'] or '—'} ({f['declared']}) | {f['tested']}/{f['files']} |")
    gaps = [(rel, r) for rel, r in rows.items() if r["expected"] and r["found"] < r["expected"]]
    L += ["", f"## Modules below their own declared total ({len(gaps)})", "", "The module says how many controls the standard has; the parser finds fewer, by any amount. Each is either a real gap or a shape the counter does not read; the reason is recorded in `KNOWN_GAPS` (`scripts/coverage_stamp.py`), and CI fails on one that is not.", "",
          "| module | declared | found | scope | gap | density | reason |", "|---|---|---|---|---|---|---|"]
    for rel, r in sorted(gaps, key=lambda x: x[1]["found"] - x[1]["expected"]):
        L.append(f"| `{rel}` | {r['expected']} | {r['found']} | {r['scope']} | {r['expected'] - r['found']} | {r['density']} | {KNOWN_GAPS.get(rel, 'not recorded')} |")
    if not gaps:
        L.append("| — | | | | | | |")
    over = [(rel, r) for rel, r in rows.items() if r["expected"] and r["found"] > r["expected"]]
    L += ["", f"## Modules above their own declared total ({len(over)})", "", "The parser finds more than the module declares: extension checks beside the standard's own, fail-closed and input-contract notices that carry an id, several checks per control where the total counts controls, or a declaration that is out of date. The count cannot show that every declared control is present, so these are labelled `over`, not `full`.", "",
          "| module | declared | found | scope | excess |", "|---|---|---|---|---|"]
    for rel, r in sorted(over, key=lambda x: (x[1]["expected"] - x[1]["found"], x[0])):
        L.append(f"| `{rel}` | {r['expected']} | {r['found']} | {r['scope']} | {r['found'] - r['expected']} |")
    if not over:
        L.append("| — | | | | |")
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
    L += ["", f"## Modules with checks but no test file ({len(untested)})", "", "Work queue, same as COVERAGE.md.", ""]
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
        rows = scan()
        stale = check(rows=rows)
        for rel, why in stale[:30]:
            print(f"STALE {rel}: {why}")
        print(f"coverage stamps: {'all current' if not stale else str(len(stale)) + ' stale — run: python3 scripts/coverage_stamp.py'}")
        # the counting rule is validated against every module's own declared total: a module that declares a
        # total and is found below it, by any amount, is either a real gap or a shape the counter does not read.
        # Either way it is named in KNOWN_GAPS with its reason, or the check fails.
        declaring = {rel: r for rel, r in rows.items() if r["expected"]}
        below = sorted(rel for rel, r in declaring.items() if r["found"] < r["expected"])
        above = sorted(rel for rel, r in declaring.items() if r["found"] > r["expected"])
        unexpected = [rel for rel in below if rel not in KNOWN_GAPS]
        print(f"declared totals: {len(declaring)} modules declare one; {len(declaring) - len(below) - len(above)} equal, "
              f"{len(above)} above (labelled over), {len(below)} below ({len(below) - len(unexpected)} with a recorded reason)")
        for rel in unexpected:
            print(f"BELOW DECLARED {rel}: found {rows[rel]['found']} of {rows[rel]['expected']} — a real gap or a counter regression; fix it, or add it to KNOWN_GAPS with its reason")
        for rel in sorted(set(KNOWN_GAPS) - set(below)):
            print(f"note: KNOWN_GAPS lists {rel}, which is {'no longer below its declared total' if rel in rows else 'not in the tree'}; remove the entry")
        return 1 if (stale or unexpected) else 0
    rows, changed, skipped = stamp()
    print(f"stamped {changed} modules ({len(rows)} scanned, {len(skipped)} without a METADATA block skipped)")
    if a.json:
        pathlib.Path(a.json).write_text(json.dumps(rows, indent=1, default=sorted))
    if a.report:
        g, t, u, n = report(rows, a.report)
        print(f"report -> {a.report}: {g} below declared total, {t} sparse/stub by size, {u} unrecognised, {n} untested")
    return 0


if __name__ == "__main__":
    sys.exit(main())
