#!/usr/bin/env python3
"""Mutation testing for one module directory (#306).

A mutant is the module with one small change: a comparison flipped, a boundary moved, a boolean literal
inverted, a `not` dropped or one line of a rule body deleted. Each mutant is written into a scratch copy of
the directory and the directory's own tests are run against it. A test that fails "kills" the mutant; a
mutant every test still passes "survives" -- that change to the rule went unnoticed, so the tests do not
check what that line does. A mutant that no longer compiles is counted as "invalid", and a run in which a test
hit --timeout as "timeout" (usually a loaded machine: rerun with fewer --jobs); both are left out of the score.

    python3 scripts/mutation_test.py benchmarks/stig/rhel_9
    python3 scripts/mutation_test.py frameworks/financial/pci_dss --file 'requirement_8*'
    python3 scripts/mutation_test.py benchmarks/cis/rhel_9 --ops eq,bool --json /tmp/m.json --jobs 4
    make mutation MODULE=frameworks/federal/nist/sp_800_53/access_control

Operators (--ops, comma-separated; default all):
    eq      `==` <-> `!=`
    bound   `>=` -> `>`, `<=` -> `<`, `>` -> `>=`, `<` -> `<=`
    bool    `true` <-> `false`
    not     drop one `not`
    drop    delete one expression line of a rule body

Policy files are the non-test .rego files under MODULE (recursively; test_*.rego, *_test.rego and files in a
tests/ directory are tests). The test run is `opa test <copy of MODULE>`: the module's tests must be able to
run on that directory alone, which is how this library lays them out. Comments and string literals are never
mutated. Some survivors are equivalent mutants (a change that cannot alter any result, such as `>=` -> `>` on
a value that is never equal to the bound); read the survivor list rather than chasing 100%.

Not wired into CI: a module of a few thousand lines yields a thousand mutants or more. Exit status is 0
unless --min-score is given and the score is below it.
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import fnmatch
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
OPA = os.environ.get("OPA", "opa")
ALL_OPS = ("eq", "bound", "bool", "not", "drop")


def is_test(path: pathlib.Path) -> bool:
    return "tests" in path.parts or path.name.startswith("test_") or path.name.endswith("_test.rego")


def mask(line: str) -> str:
    """The line with string literals and the comment replaced by spaces (same length), so offsets still match."""
    out, i, n = [], 0, len(line)
    while i < n:
        c = line[i]
        if c == "#":
            out.append(" " * (n - i))
            break
        if c == '"':
            j = i + 1
            while j < n and line[j] != '"':
                j += 2 if line[j] == "\\" else 1
            j = min(j + 1, n)
            out.append('"' + " " * max(j - i - 2, 0) + ('"' if j - i >= 2 else ""))
            i = j
            continue
        if c == "`":
            j = line.find("`", i + 1)
            j = n if j < 0 else j + 1
            out.append("`" + " " * max(j - i - 2, 0) + ("`" if j - i >= 2 else ""))
            i = j
            continue
        out.append(c)
        i += 1
    return "".join(out)[:n].ljust(n)


TOKEN_OPS = {
    "eq": [(re.compile(r"(?<![=!<>:])==(?!=)"), "!="), (re.compile(r"!="), "==")],
    "bound": [
        (re.compile(r">="), ">"),
        (re.compile(r"<="), "<"),
        (re.compile(r"(?<![-=<>])>(?!=)"), ">="),
        (re.compile(r"(?<![<])<(?![=<-])"), "<="),
    ],
    "bool": [(re.compile(r"\btrue\b"), "false"), (re.compile(r"\bfalse\b"), "true")],
    "not": [(re.compile(r"\bnot\s+"), "")],
}

BODY_OPEN = re.compile(r"(\bif|\belse|\bevery\b.*)\s*\{\s*$")


def mutants_for(path: pathlib.Path, ops: set[str]):
    """Yield (line_no, op, original_line, mutated_line) for every mutant of one policy file."""
    lines = path.read_text().splitlines(keepends=True)
    stack: list[str] = []  # "body" or "lit" for each open brace / bracket / paren
    in_raw = False
    for idx, raw in enumerate(lines):
        line = raw.rstrip("\n")
        m = mask(line)
        stripped = m.strip()
        top_before = stack[-1] if stack else None
        # raw string spanning lines: skip mutation inside it
        if in_raw:
            if "`" in line:
                in_raw = False
            continue
        if m.count("`") % 2 == 1:
            in_raw = True
        skip = (not stripped) or stripped.startswith(("package ", "import "))
        if not skip:
            for op in ops & set(TOKEN_OPS):
                for rx, repl in TOKEN_OPS[op]:
                    for mm in rx.finditer(m):
                        new = line[: mm.start()] + repl + line[mm.end():]
                        if op == "not" and top_before is None:
                            continue  # `not` outside a body is a rule name fragment, not negation
                        yield idx + 1, op, line, new
            if "drop" in ops and top_before == "body" and _droppable(m):
                yield idx + 1, "drop", line, None
        # update the bracket stack from this line
        for ch_i, ch in enumerate(m):
            if ch in "{[(":
                kind = "lit"
                if ch == "{" and BODY_OPEN.search(m[: ch_i + 1]):
                    kind = "body"
                stack.append(kind)
            elif ch in "}])" and stack:
                stack.pop()


def _droppable(m: str) -> bool:
    s = m.strip()
    if not s or s[0] in "}])" or s.endswith(("{", "[", "(", ",", "|", "+", "-", "*", "/", "&")):
        return False
    depth = 0
    for ch in s:
        depth += ch in "{[("
        depth -= ch in "}])"
    if depth != 0:
        return False
    if s.startswith(("some ", "every ")):
        return False
    return True


def classify(out: str, rc: int) -> str:
    if re.search(r"rego_(parse|compile|type|unsafe_var|recursion)_error|\d+ errors? occurred", out):
        return "invalid"
    if "eval_cancel_error" in out:
        return "timeout"  # a test hit --timeout: a loaded machine, not a detection; rerun with fewer --jobs
    if rc == 0:
        return "survived"
    return "killed"


def run_one(job):
    module, rel, line_no, op, orig, new, timeout = job
    with tempfile.TemporaryDirectory(prefix="mut-") as td:
        dst = pathlib.Path(td) / "m"
        shutil.copytree(module, dst, ignore=shutil.ignore_patterns(".git"))
        target = dst / rel
        lines = target.read_text().splitlines(keepends=True)
        if new is None:
            lines[line_no - 1] = "\n"
        else:
            lines[line_no - 1] = new + "\n"
        target.write_text("".join(lines))
        try:
            p = subprocess.run([OPA, "test", str(dst), "--timeout", f"{timeout}s"], capture_output=True, text=True,
                               timeout=timeout * 4)
            status = classify(p.stdout + p.stderr, p.returncode)
        except subprocess.TimeoutExpired:
            status = "timeout"
    return {"file": rel, "line": line_no, "op": op, "original": orig.strip(),
            "mutant": "<line deleted>" if new is None else new.strip(), "status": status}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("module", help="module directory (policy files and their tests)")
    ap.add_argument("--file", action="append", default=[], help="only mutate policy files matching this glob (repeatable)")
    ap.add_argument("--ops", default=",".join(ALL_OPS), help="operators to apply (default: all)")
    ap.add_argument("--jobs", type=int, default=2, help="concurrent opa test runs (default 2; each run is itself multi-threaded)")
    ap.add_argument("--timeout", type=int, default=30, help="opa test --timeout per run, seconds")
    ap.add_argument("--json", help="write every mutant's result to this file")
    ap.add_argument("--show", type=int, default=200, help="survivors to print (default 200)")
    ap.add_argument("--min-score", type=float, help="exit 1 when the kill score (percent) is below this")
    a = ap.parse_args()

    module = pathlib.Path(a.module)
    if not module.is_absolute():
        module = (pathlib.Path.cwd() / module).resolve()
    if not module.is_dir():
        sys.exit(f"not a directory: {a.module}")
    ops = {o.strip() for o in a.ops.split(",") if o.strip()}
    bad = ops - set(ALL_OPS)
    if bad:
        sys.exit(f"unknown operator(s): {', '.join(sorted(bad))}")

    base = subprocess.run([OPA, "test", str(module), "--timeout", f"{a.timeout}s"], capture_output=True, text=True)
    if base.returncode != 0:
        print(base.stdout[-2000:] + base.stderr[-2000:])
        sys.exit("the unmutated module's tests do not pass; fix them first")

    files = sorted(p for p in module.rglob("*.rego") if not is_test(p.relative_to(module)))
    if a.file:
        files = [p for p in files if any(fnmatch.fnmatch(p.name, g) for g in a.file)]
    jobs = []
    for p in files:
        rel = str(p.relative_to(module))
        for line_no, op, orig, new in mutants_for(p, ops):
            jobs.append((module, rel, line_no, op, orig, new, a.timeout))
    if not jobs:
        sys.exit("no mutants generated")

    try:
        label = module.relative_to(ROOT)
    except ValueError:
        label = module
    print(f"{label}: {len(files)} policy file(s), {len(jobs)} mutants, {a.jobs} jobs", flush=True)
    results = []
    with cf.ThreadPoolExecutor(max_workers=a.jobs) as ex:
        for i, r in enumerate(ex.map(run_one, jobs), 1):
            results.append(r)
            if i % 100 == 0:
                print(f"  {i}/{len(jobs)}", flush=True)

    by = {k: [r for r in results if r["status"] == k] for k in ("killed", "survived", "invalid", "timeout")}
    valid = len(by["killed"]) + len(by["survived"])
    score = 100.0 * len(by["killed"]) / valid if valid else 100.0
    print(f"\nkilled {len(by['killed'])}  survived {len(by['survived'])}  invalid {len(by['invalid'])}  "
          f"timeout {len(by['timeout'])}  score {score:.1f}%")
    per_op = {}
    for r in results:
        if r["status"] in ("killed", "survived"):
            k, s = per_op.get(r["op"], (0, 0))
            per_op[r["op"]] = (k + (r["status"] == "killed"), s + (r["status"] == "survived"))
    for op in ALL_OPS:
        if op in per_op:
            k, s = per_op[op]
            print(f"  {op:6} killed {k:5}  survived {s:5}")
    if by["survived"]:
        print(f"\nsurvivors (first {min(a.show, len(by['survived']))} of {len(by['survived'])}):")
        for r in sorted(by["survived"], key=lambda r: (r["file"], r["line"]))[: a.show]:
            print(f"  {r['file']}:{r['line']} [{r['op']}] {r['original']}  ->  {r['mutant']}")
    if a.json:
        pathlib.Path(a.json).write_text(json.dumps({"module": str(label), "score": round(score, 1),
                                                    "killed": len(by["killed"]), "survived": len(by["survived"]),
                                                    "invalid": len(by["invalid"]), "timeout": len(by["timeout"]),
                                                    "mutants": results}, indent=1))
    if a.min_score is not None and score < a.min_score:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
