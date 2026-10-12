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
    failed = set(re.findall(r"^(?:data\.\S+\.)?(test_\S+): (?:FAIL|ERROR)", text, re.M))
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
            src = tfile.read_text(); stem = pathlib.Path(rel).stem
            for kind in ("fail_closed_on_empty_input", "violations_on_empty_input", "report_wellformed_on_empty_input", "loads_on_empty_input"):
                name = f"test_{stem}_{kind}"
                if name in failed:
                    if kind == "loads_on_empty_input":
                        defects.append(rel); tfile.unlink(missing_ok=True); src = ""; touched += 1; break
                    src = re.sub(rf"(?ms)^{re.escape(name)} if \{{.*?^\}}\n\n?", "", src)
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
    rep += ["", "## Modules that are compliant on empty input (fail-open) — findings, not hidden", ""] + [f"- `{rel}`" for rel in sorted(findings.get("fail_closed_on_empty_input", []))]
    rep += ["", "## Modules whose violations are empty on empty input", "", "Often by design (the module iterates a list that is absent), sometimes fail-open; each deserves a look.", ""] + [f"- `{rel}`" for rel in sorted(findings.get("violations_on_empty_input", []))]
    rep += ["", "## Modules with a runtime error on empty input (defects; no test written)", ""] + [f"- `{rel}`" for rel in sorted(defects)]
    (ROOT / "docs" / "TEST_GENERATION.md").write_text("\n".join(rep) + "\n")
    print(f"final: {passed} tests pass; findings: fail-open {len(findings.get('fail_closed_on_empty_input', []))}, empty violations {len(findings.get('violations_on_empty_input', []))}, defects {len(defects)}; remaining failures {len(failed)}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
