#!/usr/bin/env python3
"""Rego → Conftest policy directory (packaging). Trivy, KICS and Regula need adapters; see README.

Conftest executes Rego and recognises `deny`, `violation` and `warn` rules in any
package when told the namespace. Every enforcement policy in this library already
exposes one of those, so the Conftest layout is a copy of enforcement/ (tests
excluded) plus a namespace index. Output: out/conftest/policy/ and
out/conftest/NAMESPACES.md.
"""
from __future__ import annotations
import pathlib, re, shutil, sys

ROOT = pathlib.Path(__file__).resolve().parents[3]
OUT = pathlib.Path(__file__).resolve().parent / "out" / "conftest"
RULE_RE = re.compile(r"^(deny|violation|warn)\b", re.M)
PKG_RE = re.compile(r"^package\s+([a-z0-9_.]+)", re.M)


def main():
    pol = OUT / "policy"
    if pol.exists():
        shutil.rmtree(pol)
    rows = []
    for src in sorted((ROOT / "enforcement").rglob("*.rego")):
        rel = src.relative_to(ROOT)
        if src.name.startswith("test_") or src.name.endswith("_test.rego") or "tests" in rel.parts:
            continue
        text = src.read_text()
        pkg = PKG_RE.search(text); rules = sorted(set(RULE_RE.findall(text)))
        if not pkg or not rules:
            continue
        dst = pol / rel.relative_to("enforcement"); dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(text)
        rows.append((pkg.group(1), ", ".join(rules), rel.as_posix()))
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "NAMESPACES.md").write_text("# Conftest namespaces\n\n| namespace (`--namespace`) | rules | source |\n|---|---|---|\n" + "\n".join(f"| `{p}` | {r} | `{s}` |" for p, r, s in rows) + "\n")
    for p, r, s in rows:
        print(f"{p:<34} {r:<22} {s}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
