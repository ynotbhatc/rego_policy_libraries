#!/usr/bin/env python3
"""Generate the OPA bundle .manifest with explicit roots.

Why this exists: `opa build` without a declared manifest produces a bundle
whose single root is "" (the whole `data` namespace). Such a bundle cannot
be activated alongside ANY other bundle — OPA rejects overlapping roots —
so a consumer cannot load our policies *and* supply their own site config
(e.g. `data.aac.aap.config`). See ericcames/sales.demos#841.

This computes one root per top-level policy namespace from the actual
`package` declarations, so the manifest never goes stale as frameworks are
added. The one special case is `aac`: the AAP policies live at
`data.aac.aap.policy` and read their settings from `data.aac.aap.config`,
which the CONSUMER provides. Declaring the broad root `aac` (or `aac/aap`)
would re-capture that config path and defeat composition — so we declare
the specific sub-roots `aac/aap/policy` and `aac/repo`, leaving
`aac/aap/config` free for the site bundle.

Test packages (package ends in `_test`, or any `tests` path segment) are
excluded — they are ignored at build time and must not claim a root.

Usage: gen_bundle_manifest.py <revision> [policy_dir ...]
Writes ./.manifest.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

DEFAULT_DIRS = ["benchmarks", "frameworks", "enforcement", "governance", "threat_detection"]
_PKG = re.compile(r"^package\s+([A-Za-z0-9_.]+)", re.MULTILINE)


def _is_test(segments: list[str]) -> bool:
    return segments[-1].endswith("_test") or "tests" in segments


def root_for(package: str) -> str | None:
    seg = package.split(".")
    if _is_test(seg):
        return None
    if seg[0] == "aac":
        # Keep data.aac.aap.config free for the consumer's site bundle.
        return "aac/aap/policy" if len(seg) > 1 and seg[1] == "aap" else "/".join(seg[:2])
    return seg[0]


def collect_roots(dirs: list[str]) -> list[str]:
    roots: set[str] = set()
    for d in dirs:
        for rego in Path(d).rglob("*.rego"):
            for pkg in _PKG.findall(rego.read_text(encoding="utf-8", errors="replace")):
                r = root_for(pkg)
                if r:
                    roots.add(r)
    return sorted(roots)


def main() -> int:
    revision = sys.argv[1] if len(sys.argv) > 1 else ""
    dirs = sys.argv[2:] or DEFAULT_DIRS
    roots = collect_roots(dirs)
    if not roots:
        print("ERROR: no package roots found — refusing to write an empty manifest", file=sys.stderr)
        return 1
    manifest = {"revision": revision, "roots": roots}
    Path(".manifest").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"wrote .manifest: {len(roots)} roots, revision={revision!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
