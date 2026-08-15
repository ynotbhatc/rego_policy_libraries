#!/usr/bin/env python3
"""Assert that every CIS control id cited in a Rego violation message
actually exists in the benchmark.

This is the guard for the defect found on 2026-08-14: the original
cis_m365 modules invented their own section topology, so five of seven
modules cited control numbers that name a different requirement than the
one being evaluated. Unit tests could not catch it -- they assert against
the same invented numbers. Only a check against the benchmark's own
enumeration can.

Usage:
    check_cis_ids.py --enumeration <enum.json> --policy-dir <dir> [--prefix CIS]

Exit 0 if every cited id is in the enumeration, 1 otherwise.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys


STOPWORDS = frozenset(
    """ensure is are be set to the a an of on off and or not with for in that
    only has have been configured enable enabled disable disabled restrict
    restricted allow allowed default defaults policy policies use used using
    all any from at by it its this these those than then which who whom""".split()
)
WORD = re.compile(r"[a-z0-9']+")


def keywords(text: str) -> set[str]:
    """Tokenise, stripping surrounding quotes.

    CIS quotes setting names in its titles -- "Ensure 'AuditBypassEnabled'
    is not enabled on mailboxes". Without stripping, the token is
    "'auditbypassenabled'" and never matches the same word written
    unquoted in a violation message, so the coherence check fails on
    correct messages. CIS quotes setting names constantly, so this was a
    false-positive generator across the whole benchmark.
    """
    out = set()
    for w in WORD.findall(text.lower()):
        w = w.strip("'")
        if w and w not in STOPWORDS and len(w) > 2:
            out.add(w)
    return out


def load_enumeration(path: pathlib.Path):
    """Accept either enumeration form.

    The public index carries `title_keywords` (a derived keyword digest)
    instead of verbatim CIS titles, so that the library can ship the guard
    without redistributing portions of the benchmark. The full form carries
    `title` and is kept outside the public repo. Both support the coherence
    check, which only ever compares keyword sets.
    """
    doc = json.loads(path.read_text(encoding="utf-8"))
    kw, display = {}, {}
    for r in doc["recommendations"]:
        cid = r["control_id"]
        if "title" in r:
            kw[cid] = keywords(r["title"])
            display[cid] = r["title"]
        else:
            kw[cid] = set(r.get("title_keywords", []))
            display[cid] = "keywords: " + ", ".join(sorted(kw[cid])[:6])
    label = f"{doc['benchmark']} v{doc['version']}"
    return kw, display, label


def scan(policy_dir: pathlib.Path, prefix: str):
    """Yield (file, line_no, control_id) for every cited id.

    Matches the house convention for violation messages, e.g.
        msg := "CIS 1.1.1: Ensure Administrative accounts are cloud-only"
    """
    pattern = re.compile(rf"\b{re.escape(prefix)}\s+(\d+(?:\.\d+)+)\s*:?\s*(.*)")
    for rego in sorted(policy_dir.rglob("*.rego")):
        if rego.name.startswith("test_") or rego.name.endswith("_test.rego"):
            continue
        for n, line in enumerate(rego.read_text(encoding="utf-8").splitlines(), 1):
            for m in pattern.finditer(line):
                yield rego, n, m.group(1), m.group(2).rstrip('"').strip()


SECTION_DECL = re.compile(r'"section":\s*"(\d+)"')
SECTION_TOTAL = re.compile(r'"section_total_controls":\s*(\d+)')
# A control id that appears as a quoted STRING rather than inside a
# `CIS <id>` message. Three shapes, all of which have bitten this guard:
#
#   as a key    REQUIRES_ATTESTATION := {"5.2.4.1": "..."}
#   as a value  SETTING_CONTROLS := {"PublishToWeb": "9.1.4"}
#   in a list   "controls": ["9.1.1", "9.1.2", ...]
#
# None appear in a `CIS <id>` literal when the message is built with
# sprintf, so the citation scan cannot see any of them. Matching any
# quoted id covers all three -- narrowing to one shape is what let the
# section 9 ids through unverified.
QUOTED_ID = re.compile(r'"(\d+(?:\.\d+)+)"')
# Version strings are dotted numbers too. "benchmark_version": "7.0.0"
# is not a citation of control 7.0.0 -- exclude those lines rather than
# narrowing the id pattern, which would reintroduce the blind spot.
VERSION_LINE = re.compile(r'(benchmark_version|benchmark_released|"version")')


def keyed_ids(policy_dir: pathlib.Path):
    """Yield (file, line_no, control_id) for ids appearing as quoted
    strings anywhere in a policy file."""
    for rego in sorted(policy_dir.rglob("*.rego")):
        if rego.name.startswith("test_") or rego.name.endswith("_test.rego"):
            continue
        for n, line in enumerate(rego.read_text(encoding="utf-8").splitlines(), 1):
            if VERSION_LINE.search(line):
                continue
            for m in QUOTED_ID.finditer(line):
                yield rego, n, m.group(1)


def check_section_totals(policy_dir: pathlib.Path, enum_path: pathlib.Path):
    """Each section module hardcodes `section_total_controls`. Nothing else
    ties that number to the benchmark, so regenerating the enumeration could
    silently leave the modules claiming stale denominators -- the same drift
    class this guard exists to prevent. Cross-check them.

    Returns a list of (file, section, declared, actual) mismatches.
    """
    doc = json.loads(enum_path.read_text(encoding="utf-8"))
    actual: dict[str, int] = {}
    for r in doc["recommendations"]:
        key = str(r["section"])
        actual[key] = actual.get(key, 0) + 1

    problems = []
    for rego in sorted(policy_dir.rglob("*.rego")):
        if rego.name.startswith("test_") or rego.name.endswith("_test.rego"):
            continue
        text = rego.read_text(encoding="utf-8")
        sec = SECTION_DECL.search(text)
        tot = SECTION_TOTAL.search(text)
        if not sec or not tot:
            continue
        declared, real = int(tot.group(1)), actual.get(sec.group(1))
        if real is None or declared != real:
            problems.append((rego, sec.group(1), declared, real))
    return problems


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--enumeration", required=True, type=pathlib.Path)
    ap.add_argument("--policy-dir", required=True, type=pathlib.Path)
    ap.add_argument("--prefix", default="CIS")
    args = ap.parse_args()

    kw, display, label = load_enumeration(args.enumeration)
    cited = list(scan(args.policy_dir, args.prefix))
    if not cited:
        print(f"no {args.prefix} ids cited under {args.policy_dir} -- nothing to check")
        return 0

    distinct = {c for _, _, c, _ in cited}
    print(f"benchmark : {label} ({len(kw)} recommendations)")
    print(f"policies  : {args.policy_dir}")
    print(f"citations : {len(cited)} ({len(distinct)} distinct ids)\n")

    # Check 1: the cited id must exist at all.
    unknown = [(f, n, c) for f, n, c, _ in cited if c not in kw]

    # Check 2 -- the one that actually catches the 2026-08-14 defect. An id
    # can exist and still be the WRONG id: 'CIS 1.1.1: Security Defaults...'
    # cites a real control that is named 'Ensure Administrative accounts are
    # cloud-only'. Require the message to share at least one substantive word
    # with the benchmark's own title for that id.
    incoherent = []
    for f, n, c, msg in cited:
        if c not in kw or not msg:
            continue
        if not (keywords(msg) & kw[c]):
            incoherent.append((f, n, c, msg, display[c]))

    if unknown:
        print(f"FAIL [1/2]: {len(unknown)} citation(s) reference ids absent from the benchmark")
        by_file: dict[pathlib.Path, list[tuple[int, str]]] = {}
        for f, n, c in unknown:
            by_file.setdefault(f, []).append((n, c))
        for f in sorted(by_file):
            print(f"  {f.name}")
            for n, c in by_file[f]:
                print(f"    line {n}: {args.prefix} {c}  -- no such control")
        print()

    if incoherent:
        print(f"FAIL [2/2]: {len(incoherent)} citation(s) cite a real id whose")
        print("            benchmark title shares no keyword with the message")
        for f, n, c, msg, title in incoherent:
            print(f"  {f.name}:{n}")
            print(f"    cites   : {args.prefix} {c} -- {title!r}")
            print(f"    message : {msg[:88]!r}")
        print()

    # Check 3: ids used as object keys (sprintf-built messages) must exist.
    keyed = list(keyed_ids(args.policy_dir))
    bad_keys = [(f, n, c) for f, n, c in keyed if c not in kw]
    if keyed:
        print(f"keyed ids  : {len({c for _, _, c in keyed})} distinct (lookup tables)")
    if bad_keys:
        print(f"\nFAIL [3/4]: {len(bad_keys)} lookup-table id(s) absent from the benchmark")
        for f, n, c in bad_keys:
            print(f"  {f.name}:{n}: {c}  -- no such control")
        print()

    # Check 4: declared per-section denominators must match the benchmark.
    drift = check_section_totals(args.policy_dir, args.enumeration)
    if drift:
        print(f"FAIL [4/4]: {len(drift)} module(s) declare a stale section_total_controls")
        for f, sec, declared, real in drift:
            print(f"  {f.name}: section {sec} declares {declared}, benchmark has {real}")
        print()

    if unknown or incoherent or drift or bad_keys:
        print(
            "Auditors read violation messages, not the source. A message citing a\n"
            "control number that names a different requirement is an evidence defect,\n"
            "and unit tests cannot catch it -- they assert the same wrong numbers."
        )
        return 1

    print(f"OK: all {len(distinct)} distinct ids exist in {label} and are coherent")
    print(f"OK: per-section control totals match the benchmark")
    if keyed:
        print(f"OK: all lookup-table ids exist in the benchmark")
    return 0


if __name__ == "__main__":
    sys.exit(main())
