#!/usr/bin/env python3
"""Generate COVERAGE.md — which policy packages have tests, and which do not.

Run from the repository root:

    python3 scripts/coverage_report.py > COVERAGE.md
    python3 scripts/coverage_report.py --check   # CI (via make check-coverage): fail if COVERAGE.md is stale

The untested list is a work queue, not an accusation. Every entry is a small,
self-contained, verifiable contribution: copy the shape of an existing test,
write cases for the violations the policy defines, and `opa test` either passes
or it does not. See CONTRIBUTING.md for the pattern.
"""

import collections
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SKIP = {".git", ".github", "scripts"}


def is_test(p: pathlib.Path) -> bool:
    return p.name.startswith("test_") or p.name.endswith("_test.rego")


def package_of(p: pathlib.Path) -> str:
    m = re.search(r"^package\s+([\w.]+)", p.read_text(errors="ignore"), re.M)
    return m.group(1) if m else ""


def main() -> int:
    # Tracked files only, so ignored build output (converters/packaging/*/out) never counts; CI sees the same set.
    tracked = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-co", "--exclude-standard", "*.rego"],
                             capture_output=True, text=True, check=True).stdout.split()
    regos = [ROOT / f for f in tracked
             if (ROOT / f).is_file() and not any(part in SKIP for part in pathlib.Path(f).parts)]
    policies = [p for p in regos if not is_test(p)]
    tests = [p for p in regos if is_test(p)]

    tested = {package_of(p).replace("_test", "") for p in tests}
    untested = sorted(p for p in policies if package_of(p) not in tested)

    total = len(policies)
    covered = total - len(untested)
    pct = round(covered / total * 100) if total else 0

    out = []
    w = out.append
    w("# Test coverage\n")
    w("> **Generated** — do not edit by hand. Refresh with "
      "`python3 scripts/coverage_report.py > COVERAGE.md`\n")
    w(f"**{covered} of {total} policy files have tests ({pct}%).** "
      f"{len(tests)} test files, {len(untested)} policies still uncovered.\n")
    w("## Why this file exists\n")
    w("This library is maintained on a best-effort basis and it is free. Publishing")
    w("the gap is cheaper than hiding it, and it answers \"where can I help?\"")
    w("directly — every uncovered policy below is a real, bounded,")
    w("mergeable contribution.\n")
    w("**Each one is small.** Copy the shape of a test that already exists next to")
    w("a covered policy, write cases for the violations the policy defines, and run")
    w("`opa test`. It passes or it does not — there is no judgement call. See")
    w("[CONTRIBUTING.md](CONTRIBUTING.md).\n")
    w("Pick anything below, open a PR, and say in the description which file you")
    w("took so two people do not write the same test.\n")

    by_area = collections.Counter()
    for p in untested:
        rel = p.relative_to(ROOT)
        by_area["/".join(rel.parts[:2])] += 1

    w("## Where the gaps are\n")
    w("| area | policies without tests |")
    w("|---|---|")
    for area, n in by_area.most_common():
        w(f"| `{area}` | {n} |")
    w("")

    w("## The queue\n")
    grouped = collections.defaultdict(list)
    for p in untested:
        rel = p.relative_to(ROOT)
        grouped["/".join(rel.parts[:-1])].append(rel.name)
    for d in sorted(grouped):
        w(f"<details><summary><code>{d}</code> — {len(grouped[d])} file(s)</summary>\n")
        for name in sorted(grouped[d]):
            w(f"- `{name}`")
        w("\n</details>\n")

    text = "\n".join(out) + "\n"
    if "--check" in sys.argv:
        current = (ROOT / "COVERAGE.md").read_text() if (ROOT / "COVERAGE.md").exists() else ""
        if current != text:
            print("COVERAGE.md is stale; run: python3 scripts/coverage_report.py > COVERAGE.md")
            return 1
        print(f"COVERAGE.md current: {covered} of {total} policy files have tests")
        return 0
    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
