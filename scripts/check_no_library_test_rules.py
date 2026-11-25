#!/usr/bin/env python3
"""No library file defines a rule named test_*.

`opa test` runs every rule whose name starts with `test_`, in any file it is given, and the library is loaded
whole into the product's OPA. A `test_*` rule in a policy file is therefore executed as a test by anyone who runs
`opa test` on the library, is published as part of the package's data document (`data.<package>.test_x`), and is
counted by nothing. Tests belong in tests/ directories, test_*.rego or *_test.rego files, in a package of their own.

A library file is a .rego file that is not under a tests/ directory and is not named test_*.rego or *_test.rego
(the definition scripts/check_bad_input_fails.py uses). Comments and string contents are not read as rules.

ALLOWED lists the rules that exist today, each with the reason it has not been moved. An entry whose rule is gone
is an error, so the list cannot outlive what it describes.

    python3 scripts/check_no_library_test_rules.py            # exit 1 on a rule that is not allowed
    python3 scripts/check_no_library_test_rules.py --list     # print every test_* rule found in a library file
"""
from __future__ import annotations
import pathlib, re, sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from check_bad_input_fails import TEST_RE, TREES, strip_rego  # noqa: E402

# a rule head at the start of a line: test_x if / test_x := / test_x = / test_x contains / test_x { / test_x(
HEAD = re.compile(r"^(?:default\s+)?(test_[A-Za-z0-9_]*)\s*(?=if\b|:=|=|contains\b|\{|\(|\[|$)", re.M)

_PROTECTED = ("enforcement/git/ is a protected path (Approved-By trailer): moving these five self-tests to "
              "enforcement/git/tests/ needs the owner's go")
ALLOWED = {
    ("enforcement/git/approval_policy.rego", "test_approved_change"): _PROTECTED,
    ("enforcement/git/approval_policy.rego", "test_placeholder_approver_is_rejected"): _PROTECTED,
    ("enforcement/git/approval_policy.rego", "test_any_example_com_address_is_rejected"): _PROTECTED,
    ("enforcement/git/approval_policy.rego", "test_unapproved_change"): _PROTECTED,
    ("enforcement/git/approval_policy.rego", "test_non_protected_change"): _PROTECTED,
}


def test_rules(text):
    """Names of the test_* rules a source defines, in order, once each."""
    code, _ = strip_rego(text)
    return list(dict.fromkeys(HEAD.findall(code)))


def is_library(rel):
    return not TEST_RE.search(rel)


def scan(root=ROOT, trees=TREES):
    """[(relative path, rule name)] for every test_* rule in a library file."""
    out = []
    for t in trees:
        for f in sorted((root / t).rglob("*.rego")):
            rel = f.relative_to(root).as_posix()
            if is_library(rel):
                out += [(rel, name) for name in test_rules(f.read_text(errors="ignore"))]
    return out


def problems(found, allowed=None):
    allowed = ALLOWED if allowed is None else allowed
    errs = [f"{rel}: rule `{name}` is named test_*: `opa test` runs it and the library publishes it. Move it to a "
            "tests/ file in a test package, or rename it." for rel, name in found if (rel, name) not in allowed]
    errs += [f"ALLOWED entry {rel} {name} matches no rule now: remove it from scripts/check_no_library_test_rules.py"
             for rel, name in sorted(set(allowed) - set(found))]
    return errs


def main():
    found = scan()
    if "--list" in sys.argv:
        for rel, name in found:
            print(f"{rel} {name}" + ("  (allowed)" if (rel, name) in ALLOWED else ""))
        return 0
    errs = problems(found)
    for e in errs:
        print(e)
    print(f"library test rules: {len(found)} test_* rules in library files, {len(found) - len([e for e in errs if 'ALLOWED' not in e])} "
          f"allowed with a reason, {len(errs)} errors")
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
