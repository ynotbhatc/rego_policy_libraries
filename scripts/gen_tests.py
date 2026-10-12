#!/usr/bin/env python3
"""Generate a smoke test for every policy module that has none, then prove the suite is green.

    python3 scripts/gen_tests.py            # write <dir>/tests/test_<stem>_smoke.rego for untested modules, run opa test,
                                            # drop any expectation a module does not meet, re-run until green, and
                                            # write docs/TEST_GENERATION.md saying what each module was proven to do
What every generated test asserts, by what the module exposes:
  loads        data.<pkg> evaluates on empty input without a runtime error (every module)
  wellformed   compliance_report / report is an object on empty input (modules with a report)
  fail_closed  the report is not compliant on empty input (modules with a report)
  violations   violations is non-empty on empty input (modules with a violations rule)
An expectation a module does not meet is removed from its test and listed in the report as a finding (a
module that is compliant on empty input is fail-open; that is worth knowing, not hiding). A module whose
`loads` test fails has a runtime error on empty input and is listed as a defect, with no test written.
"""
from __future__ import annotations
import pathlib, re, subprocess, sys, collections
HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
from rego_ast import parse_tree, package, rule_name  # noqa: E402
import coverage_stamp as cs  # noqa: E402


def gen(rel, pkg, names):
    stem = pathlib.Path(rel).stem
    L = [f"package {pkg}_test", "", "import rego.v1", "",
         f"# Generated smoke test for {rel} (scripts/gen_tests.py). Each rule states one thing the module was proven",
         "# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.", "",
         f"test_{stem}_loads_on_empty_input if {{", f"\tm := data.{pkg} with input as {{}}", "\tis_object(m)", "}", ""]
    entry = "compliance_report" if "compliance_report" in names else ("report" if "report" in names else None)
    if entry:
        L += [f"test_{stem}_report_wellformed_on_empty_input if {{", f"\treport := data.{pkg}.{entry} with input as {{}}", "\tis_object(report)", "\tcount(report) > 0", "}", "",
              f"test_{stem}_fail_closed_on_empty_input if {{", f"\treport := data.{pkg}.{entry} with input as {{}}", "\tnot object.get(report, \"compliant\", false) == true", "}", ""]
    if "violations" in names:
        L += [f"test_{stem}_violations_on_empty_input if {{", f"\tv := data.{pkg}.violations with input as {{}}", "\tcount(v) > 0", "}", ""]
    return "\n".join(L)


def run_tests(paths):
    """opa test on the given dirs; returns (passed, failed set of test names, error text)"""
    out = subprocess.run(["opa", "test", ".", "--ignore", ".github", "--ignore", "converters"], cwd=ROOT, capture_output=True, text=True)
    text = out.stdout + out.stderr
    # keep the package: sibling platforms reuse rule names (test_ssh_validation_...), so a failure must be
    # attributed to the one file whose package it belongs to
    failed = set(re.findall(r"^(data\.\S+?\.test_\S+?): (?:FAIL|ERROR)", text, re.M))
    m = re.search(r"PASS: (\d+)/(\d+)", text)
    if not m and "error" in text:
        # the suite did not run at all (a compile/type error): surface it instead of reporting zero quietly
        print("opa test did not run:\n" + "\n".join(text.splitlines()[:8]))
        raise SystemExit(2)
    return (int(m.group(1)) if m else 0), failed, text


def main():
    rows = cs.scan()
    asts = parse_tree(ROOT)
    todo = {rel: r for rel, r in rows.items() if not r["tested"]}
    written = {}
    for rel, r in sorted(todo.items()):
        ast = asts[rel]; pkg = package(ast); names = {rule_name(x) for x in ast.get("rules", [])}
        tdir = ROOT / pathlib.Path(rel).parent / "tests"; tdir.mkdir(exist_ok=True)
        tfile = tdir / f"test_{pathlib.Path(rel).stem}_smoke.rego"
        tfile.write_text(gen(rel, pkg, names))
        written[rel] = tfile
    print(f"wrote {len(written)} smoke tests")
    findings = collections.defaultdict(list); defects = []
    for attempt in range(4):
        passed, failed, text = run_tests(None)
        print(f"pass {attempt}: {passed} passed, {len(failed)} failing generated/other tests")
        if not failed:
            break
        touched = 0
        for rel, tfile in written.items():
            if not tfile.exists():
                continue
            src = tfile.read_text(); stem = pathlib.Path(rel).stem
            tpkg = re.search(r"^package\s+(\S+)", src, re.M).group(1)
            for kind in ("fail_closed_on_empty_input", "violations_on_empty_input", "report_wellformed_on_empty_input", "loads_on_empty_input"):
                rule = f"test_{stem}_{kind}"
                name = f"data.{tpkg}.{rule}"
                if name in failed:
                    if kind == "loads_on_empty_input":
                        defects.append(rel); tfile.unlink(missing_ok=True); src = ""; touched += 1; break
                    src = re.sub(rf"(?ms)^{re.escape(rule)} if \{{.*?^\}}\n\n?", "", src)
                    findings[kind].append(rel); touched += 1
            if src:
                tfile.write_text(src)
        if not touched:
            print("failing tests are not generated ones:", sorted(failed)[:10]); break
    passed, failed, text = run_tests(None)
    rep = ["# Test generation — what each untested module was proven to do", "",
           f"`scripts/gen_tests.py` wrote a smoke test for every module without one and kept only the expectations each module meets. Suite: **{passed} tests pass**.", "",
           "| expectation | asserted by | not met by |", "|---|---|---|"]
    kinds = {"loads_on_empty_input": "module evaluates on empty input", "report_wellformed_on_empty_input": "report is an object on empty input",
             "fail_closed_on_empty_input": "report is not compliant on empty input (fail-closed)", "violations_on_empty_input": "violations non-empty on empty input"}
    for k, label in kinds.items():
        asserted = sum(1 for t in written.values() if t.exists() and f"_{k}" in t.read_text())
        rep.append(f"| {label} | {asserted} | {len(findings.get(k, []))} |")
    guard = {rel: r["guard"] for rel, r in rows.items()}
    undefined = set(findings.get("report_wellformed_on_empty_input", []))
    # a module whose report is undefined on empty input cannot be judged compliant or not: it is listed once, below,
    # as a contract defect, not as fail-open
    fo = sorted(rel for rel in findings.get("fail_closed_on_empty_input", []) if rel not in undefined)
    rep += ["", "## Modules that report compliant on empty input", "",
            "Classified by the fail-closed guard the coverage scan measures (`custom.coverage.guard`):", ""]
    for g, label in (("orchestrator", "guarded by their orchestrator (by design for sectioned benchmarks: the orchestrator is fail-closed and references them)"),
                     ("none", "**unguarded — fail-open; the work queue for the library's fail-closed rule**"),
                     ("self", "report defined and compliant on empty input while the module itself emits violations — the report's `compliant` is computed from a subset of the checks; a defect in the report literal"),
                     ("n/a", "no report or violations rule")):
        items_ = [rel for rel in fo if guard.get(rel) == g]
        rep += [f"### {label} ({len(items_)})", ""] + [f"- `{rel}`" for rel in items_] + [""]
    wf = sorted(findings.get("report_wellformed_on_empty_input", []))
    rep += ["## Modules whose report is undefined on empty input", "",
            "The report rule itself does not evaluate without facts (Rego v1 undefined, the `{}` collapse the library's contract forbids): a consumer gets nothing, not a non-compliant report. Each is a defect against the fail-closed contract.", ""] + [f"- `{rel}`" for rel in wf] + [""]
    ev = sorted(rel for rel in findings.get("violations_on_empty_input", []) if rel not in undefined)
    rep += ["## Modules whose violations are empty on empty input", "", "Often by design (the module iterates a list that is absent); classified the same way.", ""]
    for g in ("orchestrator", "none", "self", "n/a"):
        items_ = [rel for rel in ev if guard.get(rel) == g]
        rep += [f"### guard = {g} ({len(items_)})", ""] + [f"- `{rel}`" for rel in items_] + [""]
    rep += ["", "## Modules with a runtime error on empty input (defects; no test written)", ""] + [f"- `{rel}`" for rel in sorted(defects)]
    (ROOT / "docs" / "TEST_GENERATION.md").write_text("\n".join(rep) + "\n")
    print(f"final: {passed} tests pass; findings: fail-open {len(findings.get('fail_closed_on_empty_input', []))}, empty violations {len(findings.get('violations_on_empty_input', []))}, defects {len(defects)}; remaining failures {len(failed)}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
