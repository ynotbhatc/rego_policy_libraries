#!/usr/bin/env python3
"""Assert that every benchmark recommendation is accounted for exactly once.

This is the guard for the defect found on 2026-08-25: the m365_v7 modules
evaluated 138 controls, the attestation ledger claimed 6 more as requiring
attestation and 10 as unresolved -- and the remaining **six** (1.2.2,
1.3.3, 2.4.1, 5.1.6.1, 5.3.4, 5.3.5) were in no category at all. They were
not evaluated, not attested, not flagged, and so appeared nowhere in the
assessment. The report described a 154-recommendation benchmark.

Two of the six were even documented as excluded in a module comment
("they are reported by the attestation module as unresolved") -- a promise
the code did not keep. A comment is invisible to whoever reads the report.

Why the existing guards could not catch it:

  check_cis_ids.py  verifies that every id we *do* cite is real and that
                    the message matches. It is a correctness guard. A
                    control we never mention is, to it, simply not there.

  opa test          asserts against the ids the modules declare. A control
                    absent from every module is absent from every test.

Only a check against the benchmark's own enumeration can find a control
that nothing mentions -- the same reasoning that motivated check_cis_ids.py,
applied to coverage rather than to citation.

The check is a set partition, not an arithmetic one. Counts summing to 160
is strictly weaker: two buckets could double-claim a control while a third
lost one, and the total would still balance.

Two boundaries worth knowing:

  Absent package is a FAILURE here, deliberately diverging from
  check_cis_ids.py, which returns 0 when a tree cites no ids at all
  ("nothing to check"). That early-out is right for a citation guard and
  wrong for a coverage one: a tree with no buckets accounts for nothing,
  which is the maximal version of the defect. Pointed at a tree without
  the package, this reports four undefined buckets and exits 1.

  `evaluated` is self-declared. It flattens the section modules' static
  `controls` arrays, so this proves the declared ids partition the
  benchmark -- not that each has a violation rule behind it. An id added
  to a `controls` array with no logic would still count. check_cis_ids.py
  closes part of that gap (a control with a real message gets its id and
  wording checked), but an id appearing only in a `controls` array and a
  lookup table passes both. Evaluating that would mean asserting on rule
  bodies; for now it is a known limit rather than a silent one.

Usage:
    check_cis_coverage.py --enumeration <enum.json> --policy-dir <dir>
                          [--package cis_m365_v7] [--opa opa]

Exit 0 if the buckets exactly partition the enumeration, 1 otherwise.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import shutil
import subprocess
import sys


# Bucket name -> Rego path, relative to the policy package. `evaluated`
# is flattened from the section reports; the other three are the ledger's
# own maps, whose keys are control ids.
BUCKETS = {
    "evaluated": "main.compliance_report.evaluated_control_ids",
    "requires_attestation": "attestation.REQUIRES_ATTESTATION",
    "unresolved": "attestation.UNRESOLVED",
    "not_implemented": "attestation.NOT_IMPLEMENTED",
}


def sort_key(control_id: str):
    """Order ids numerically per component: 5.3.10 sorts after 5.3.9."""
    return tuple(int(p) for p in control_id.split("."))


def opa_eval(opa: str, policy_dir: pathlib.Path, query: str):
    """Evaluate a query against the policy tree with empty input.

    Empty input is deliberate: bucket membership is static, and evaluating
    with facts would make the guard depend on a fixture.
    """
    proc = subprocess.run(
        [opa, "eval", "-d", str(policy_dir), "-I", "--format", "raw", query],
        input="{}",
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        sys.stderr.write(f"opa eval failed for {query}:\n{proc.stderr}\n")
        raise SystemExit(2)
    # An undefined rule exits 0 with empty output. That is not an error to
    # opa, but it is one here: a bucket that does not exist claims nothing,
    # so every control it should have held becomes unaccounted. Report it
    # as a named failure rather than crashing on the empty string.
    if not proc.stdout.strip():
        return None
    return json.loads(proc.stdout)


def collect(opa: str, policy_dir: pathlib.Path, package: str):
    """Return {bucket_name: set_of_control_ids}.

    A list result is used as-is; an object result contributes its keys,
    which is how the three ledger maps are shaped.
    """
    found, undefined = {}, []
    for name, path in BUCKETS.items():
        value = opa_eval(opa, policy_dir, f"data.{package}.{path}")
        if value is None:
            undefined.append((name, f"data.{package}.{path}"))
            found[name] = set()
        else:
            found[name] = set(value) if isinstance(value, (list, dict)) else set()
    return found, undefined


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--enumeration", required=True, type=pathlib.Path)
    ap.add_argument("--policy-dir", required=True, type=pathlib.Path)
    ap.add_argument("--package", default="cis_m365_v7")
    ap.add_argument("--opa", default="opa")
    args = ap.parse_args()

    opa = shutil.which(args.opa)
    if not opa:
        sys.stderr.write(f"opa not found on PATH (looked for {args.opa!r})\n")
        return 2

    doc = json.loads(args.enumeration.read_text(encoding="utf-8"))
    enumerated = {r["control_id"] for r in doc["recommendations"]}
    label = f"{doc['benchmark']} v{doc['version']}"

    buckets, undefined = collect(opa, args.policy_dir, args.package)

    print(f"benchmark : {label} ({len(enumerated)} recommendations)")
    print(f"policies  : {args.policy_dir}")
    for name in BUCKETS:
        mark = "  (undefined)" if name in {n for n, _ in undefined} else ""
        print(f"  {name:22} {len(buckets[name]):>4}{mark}")
    print(f"  {'TOTAL':22} {sum(len(v) for v in buckets.values()):>4}\n")

    failures = []

    if undefined:
        failures.append("undefined")
        print(f"FAIL: {len(undefined)} bucket(s) do not exist in the policy tree")
        for name, path in undefined:
            print(f"    {name:22} {path}")
        print("      A bucket that is undefined claims nothing, so the controls")
        print("      it should hold fall out of the accounting entirely.\n")

    # Check 1: nothing may be claimed by two buckets. A control both
    # evaluated and listed as unresolved would inflate the total and hide
    # a genuine gap elsewhere.
    seen: dict[str, str] = {}
    overlaps: list[tuple[str, str, str]] = []
    for name in BUCKETS:
        for cid in sorted(buckets[name], key=sort_key):
            if cid in seen:
                overlaps.append((cid, seen[cid], name))
            else:
                seen[cid] = name
    if overlaps:
        failures.append("overlap")
        print(f"FAIL: {len(overlaps)} control(s) claimed by more than one bucket")
        for cid, first, second in overlaps:
            print(f"    {cid:10} in both {first} and {second}")
        print()

    # Check 2: every bucket entry must be a real recommendation. Catches a
    # typo'd id in a hand-maintained ledger map, which would otherwise
    # silently substitute for the control it was meant to represent.
    for name in BUCKETS:
        stray = sorted(buckets[name] - enumerated, key=sort_key)
        if stray:
            failures.append("stray")
            print(f"FAIL: {name} names {len(stray)} id(s) absent from the benchmark")
            for cid in stray:
                print(f"    {cid}  -- no such control")
            print()

    # Check 3: the defect this guard exists for. Anything the benchmark
    # defines and no bucket claims is missing from the report entirely,
    # and an omitted control reads exactly like a passing one.
    unaccounted = sorted(enumerated - set(seen), key=sort_key)
    if unaccounted:
        failures.append("unaccounted")
        print(f"FAIL: {len(unaccounted)} recommendation(s) are in no bucket at all")
        print("      Not evaluated, not attested, not flagged -- absent from the")
        print("      assessment, which is indistinguishable from passing.\n")
        by_section: dict[int, list[str]] = {}
        sections = {r["control_id"]: r for r in doc["recommendations"]}
        for cid in unaccounted:
            by_section.setdefault(sections[cid]["section"], []).append(cid)
        for sec in sorted(by_section):
            name = sections[by_section[sec][0]]["section_name"]
            print(f"  section {sec} -- {name}")
            for cid in by_section[sec]:
                rec = sections[cid]
                kws = " ".join(rec.get("title_keywords", []))
                print(f"    {cid:10} {rec['assessment']:10} {kws}")
        print()
        print("      Add each to a section module (if collectable) or to the")
        print("      appropriate map in attestation_validation.rego. A control")
        print("      we cannot yet collect is still reported -- never dropped.")
        print()

    if failures:
        print(f"FAILED: {len(set(failures))} check(s) -- the buckets do not partition the benchmark")
        return 1

    print(f"OK: all {len(enumerated)} recommendations accounted for exactly once")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
