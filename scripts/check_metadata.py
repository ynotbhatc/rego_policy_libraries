#!/usr/bin/env python3
"""Fail if any policy file lacks a conforming `# METADATA` annotation.

Every package declared by a non-test .rego file must carry exactly one
package-scoped OPA annotation block (see CLAUDE.md "Skill: policy metadata").
OPA permits one such block per package, so when a package spans several files
one file owns the block and the others point at it. The block carries:

    title                     non-empty string
    custom.class              one of vocabulary["class"]
    custom.framework          non-empty slug  [a-z0-9_]+
    custom.source             one of vocabulary["source"]
    custom.domains            non-empty list, every item in vocabulary["domains"]

The vocabulary lives in scripts/metadata_vocabulary.json. Annotations are
read with `opa inspect -a`, so what is checked is exactly what OPA parses.

Usage: python3 scripts/check_metadata.py [--dirs d1 d2 ...] [--json]
Exit 0 when clean, 1 when any file fails.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

DEFAULT_DIRS = ["benchmarks", "frameworks", "governance", "enforcement", "threat_detection", "crosswalk"]
SLUG = re.compile(r"^[a-z0-9_]+$")


def is_test(path: Path) -> bool:
    return path.name.startswith("test_") or path.name.endswith("_test.rego") or "tests" in path.parts


def policy_files(dirs: list[str]) -> list[Path]:
    out: list[Path] = []
    for d in dirs:
        for p in Path(d).rglob("*.rego"):
            if ".github" in p.parts or is_test(p):
                continue
            out.append(p)
    return sorted(out)


PKG_RE = re.compile(r"^package\s+([A-Za-z0-9_.]+)", re.M)


def package_of(path: Path) -> str | None:
    m = PKG_RE.search(path.read_text(encoding="utf-8", errors="replace"))
    return m.group(1) if m else None


def inspect_annotations(root: str = ".") -> dict[str, list[dict]]:
    """Return {package path: [package-scoped annotation dicts]} for the whole tree.

    One invocation on the repo root, so a package redeclared across trees
    (which OPA rejects) is caught here rather than at load time.
    """
    res = subprocess.run(["opa", "inspect", "-a", "-f", "json", root], capture_output=True, text=True)
    if res.returncode != 0:
        sys.exit(f"opa inspect failed:\n{res.stderr}")
    by_pkg: dict[str, list[dict]] = {}
    for ann in json.loads(res.stdout).get("annotations") or []:
        if ann.get("annotations", {}).get("scope") != "package":
            continue
        pkg = ".".join(str(seg["value"]) for seg in ann["path"][1:])
        by_pkg.setdefault(pkg, []).append(ann["annotations"])
    return by_pkg


def check_file(path: Path, anns: list[dict], vocab: dict) -> list[str]:
    errs: list[str] = []
    if not anns:
        return ["package has no `# METADATA` block (add one above `package` in this or the owning file)"]
    if len(anns) > 1:
        errs.append(f"package has {len(anns)} package-scoped METADATA blocks; OPA allows exactly 1")
    a = anns[0]
    title = a.get("title")
    if not isinstance(title, str) or not title.strip():
        errs.append("title: missing or empty")
    c = a.get("custom")
    if not isinstance(c, dict):
        return errs + ["custom: block missing"]
    cls = c.get("class")
    if cls not in vocab["class"]:
        errs.append(f"custom.class: {cls!r} not in {sorted(vocab['class'])}")
    fw = c.get("framework")
    if not isinstance(fw, str) or not SLUG.match(fw):
        errs.append(f"custom.framework: {fw!r} must match {SLUG.pattern}")
    src = c.get("source")
    if src not in vocab["source"]:
        errs.append(f"custom.source: {src!r} not in vocabulary")
    doms = c.get("domains")
    if not isinstance(doms, list) or not doms:
        errs.append("custom.domains: must be a non-empty list")
    else:
        bad = [d for d in doms if d not in vocab["domains"]]
        if bad:
            errs.append(f"custom.domains: {bad} not in vocabulary")
    return errs


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dirs", nargs="+", default=DEFAULT_DIRS)
    ap.add_argument("--vocab", default="scripts/metadata_vocabulary.json")
    ap.add_argument("--json", action="store_true", help="emit {file: annotation} for every clean file")
    args = ap.parse_args()

    vocab = json.loads(Path(args.vocab).read_text())
    files = policy_files(args.dirs)
    anns = inspect_annotations()

    failures: dict[str, list[str]] = {}
    clean: dict[str, dict] = {}
    for p in files:
        key = str(p)
        pkg = package_of(p)
        if pkg is None:
            failures[key] = ["no `package` declaration"]
            continue
        errs = check_file(p, anns.get(pkg, []), vocab)
        if errs:
            failures[key] = errs
        else:
            clean[key] = dict(anns[pkg][0], package=pkg)

    if args.json:
        print(json.dumps(clean, indent=1, sort_keys=True))
    else:
        for f, errs in failures.items():
            for e in errs:
                print(f"{f}: {e}")
        print(f"\n{len(clean)} of {len(files)} policy files resolve to conforming METADATA; {len(failures)} fail.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
