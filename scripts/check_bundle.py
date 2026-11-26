#!/usr/bin/env python3
"""Check the bundle that scripts/build_bundle.sh produced before it is published.

    python3 scripts/check_bundle.py bundle.tar.gz

Fails (exit 1) when:
  - a data file (data.json / data.yaml / data.yml) exists in the tree outside crosswalk/ and outside the
    trees the build ignores: it would be loaded into the bundle as data nobody reviewed;
  - the bundle holds a test module;
  - the bundle's data document has a root other than `crosswalk`, or lacks one of the crosswalk data sets;
  - with the bundle loaded, the crosswalk spine is not loaded, or FedRAMP given a benchmark finding answers
    "crosswalk is not loaded" instead of a verdict taken from the benchmark result.
"""
from __future__ import annotations
import json, os, pathlib, re, subprocess, sys, tarfile, tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
IGNORED_TREES = {"docs", "scripts", "tools", "standard", "schemas", "converters", "examples", ".github", ".git",
                 ".claude", "tests", "_framework_key_tests"}
DATA_NAMES = {"data.json", "data.yaml", "data.yml"}
CROSSWALK_SETS = {"stig_800_53", "framework_maps", "attack_800_53"}
TEST_RE = re.compile(r"(^|/)(test_[^/]*\.rego|[^/]*_test\.rego)$|/tests/")


def stray_data_files(root: pathlib.Path) -> list[str]:
    out = []
    for p in root.rglob("*"):
        if p.name not in DATA_NAMES or not p.is_file():
            continue
        parts = p.relative_to(root).parts
        if any(part in IGNORED_TREES for part in parts) or parts[0] == "crosswalk":
            continue
        out.append("/".join(parts))
    return sorted(out)


def bundle_problems(bundle: pathlib.Path) -> list[str]:
    errs = []
    with tarfile.open(bundle) as tar:
        names = [m.name.lstrip("/") for m in tar.getmembers()]
        tests = [n for n in names if TEST_RE.search("/" + n)]
        if tests:
            errs.append(f"{len(tests)} test module(s) in the bundle, first: {tests[0]}")
        member = next((m for m in tar.getmembers() if m.name.lstrip("/") == "data.json"), None)
        data = json.load(tar.extractfile(member)) if member else {}
    roots = set(data)
    if roots != {"crosswalk"}:
        errs.append(f"bundle data roots are {sorted(roots)}; expected only ['crosswalk']")
    missing = CROSSWALK_SETS - set(data.get("crosswalk", {}))
    if missing:
        errs.append(f"crosswalk data sets missing from the bundle: {sorted(missing)}")
    return errs


def eval_problems(bundle: pathlib.Path, opa: str) -> list[str]:
    errs = []
    inp = {"impact_level": "moderate", "findings": [{"stig_id": "RHEL-09-411075", "status": "Open"}]}
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(inp, f)
    try:
        def ev(query):
            res = subprocess.run([opa, "eval", "-b", str(bundle), "-i", f.name, "--format", "json", query],
                                 capture_output=True, text=True)
            if res.returncode != 0:
                return None, res.stderr.strip()[:300]
            result = json.loads(res.stdout).get("result") or []
            return (result[0]["expressions"][0]["value"] if result else None), ""
        spine, err = ev("data.crosswalk.correlation.spine_loaded")
        if spine is not True:
            errs.append(f"data.crosswalk.correlation.spine_loaded is {spine!r}, expected true {err}")
        viol, err = ev("data.fedramp.main.compliance_report.violations")
        text = json.dumps(viol or [])
        if "FAIL-CLOSED" in text and "crosswalk" in text.lower():
            errs.append("fedramp.main answers FAIL-CLOSED (crosswalk not loaded) when given a benchmark finding")
        if "RHEL-09-411075" not in text:
            errs.append("fedramp.main did not report the benchmark gap for RHEL-09-411075 (AC-7) " + err)
    finally:
        os.unlink(f.name)
    return errs


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    bundle = pathlib.Path(sys.argv[1])
    opa = os.environ.get("OPA", "opa")
    errs = [f"data file outside crosswalk/: {p}" for p in stray_data_files(ROOT)]
    errs += bundle_problems(bundle)
    if not errs:
        errs += eval_problems(bundle, opa)
    for e in errs:
        print("ERROR:", e)
    if errs:
        return 1
    print(f"bundle ok: {bundle} carries the crosswalk and no test module; fedramp reads benchmark results from it")
    return 0


if __name__ == "__main__":
    sys.exit(main())
