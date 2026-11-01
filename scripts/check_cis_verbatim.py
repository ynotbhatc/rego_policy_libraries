#!/usr/bin/env python3
"""Fail if a CIS recommendation title is copied back into benchmarks/cis.

CIS benchmark text is not redistributed with this Apache-2.0 library. The
house style is the control id plus original wording (see
benchmarks/cis/saas/m365_v7/ and tools/cis_generators/neutralize.py). The
benchmark's own recommendations are almost all imperative sentences that
start with "Ensure" or "Ensure that". This script flags that shape.

Allowlist: scripts/cis_verbatim_allowlist.txt, one regular expression per
line, searched against "relative/path:line contents".

Usage: python3 scripts/check_cis_verbatim.py [benchmarks/cis]
Exit 0 when clean, 1 otherwise.
"""
from __future__ import annotations

import pathlib
import re
import sys

TITLE = re.compile(r"(?<![A-Za-z0-9_])Ensure(?:\s+that)?\s+\S")
SKIP_DIRS = {".git"}


def allowlist(root: pathlib.Path) -> list[re.Pattern[str]]:
    path = root / "scripts" / "cis_verbatim_allowlist.txt"
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        out.append(re.compile(line))
    return out


def scan(policy_root: pathlib.Path, repo: pathlib.Path, patterns: list[re.Pattern[str]]):
    hits = []
    for path in sorted(policy_root.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix.lower() not in {".rego", ".md", ".json", ".txt"}:
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        rel = path.relative_to(repo).as_posix()
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except UnicodeError:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        for n, line in enumerate(lines, 1):
            # Setting names we keep are quoted. A title is unquoted "Ensure".
            visible = re.sub(r"'[^']*'", "''", line)
            if not TITLE.search(visible):
                continue
            key = f"{rel}:{line}"
            if any(p.search(key) for p in patterns):
                continue
            hits.append((rel, n, line.strip()[:160]))
    return hits


def main() -> int:
    repo = pathlib.Path(__file__).resolve().parent.parent
    policy = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else repo / "benchmarks" / "cis"
    if not policy.is_absolute():
        policy = repo / policy
    hits = scan(policy, repo, allowlist(repo))
    if hits:
        print(f"FAIL: {len(hits)} CIS-style recommendation title(s) under {policy}")
        print("Write the control id and an original description of the check.")
        print("Do not copy the benchmark sentence. See CONTRIBUTING.md.")
        for rel, n, text in hits[:80]:
            print(f"  {rel}:{n}: {text}")
        if len(hits) > 80:
            print(f"  ... {len(hits) - 80} more")
        return 1
    print(f"OK: no CIS recommendation titles under {policy}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
