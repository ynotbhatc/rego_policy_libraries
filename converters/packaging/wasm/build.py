#!/usr/bin/env python3
"""Build WebAssembly bundles of the library: one per OPA class plus one with everything.

Rego → WASM is packaging, not translation: `opa build -t wasm` compiles every
entrypoint into policy.wasm, which the OPA WASM SDKs evaluate in Go, JavaScript,
Python, Java, .NET and Rust with no OPA server. Entrypoints are every
`<framework>.main` package (the compliance_report orchestrators) plus the
Kubernetes admission package, discovered from the tree so nothing goes stale.

Output: out/<class>.tar.gz (policy.wasm + data + .manifest), out/manifest.json
(entrypoints, sha256, size per bundle). Run from anywhere:

    python3 converters/packaging/wasm/build.py [--out DIR] [--classes security,compliance,ot]
"""
from __future__ import annotations
import argparse, hashlib, json, pathlib, re, subprocess, sys

ROOT = pathlib.Path(__file__).resolve().parents[3]
VOCAB = json.loads((ROOT / "scripts" / "metadata_vocabulary.json").read_text())
CONTAINER_FOR_CLASS = VOCAB["container_for_class"]          # opa-security -> [security] ...
TEST_RE = re.compile(r"(^|/)(test_|.*_test\.rego$)")
PKG_RE = re.compile(r"^package\s+([a-z0-9_.]+)\s*$", re.M)
CLASS_RE = re.compile(r"^#\s*class:\s*([a-z-]+)\s*$", re.M)
ENTRY_SUFFIXES = (".main",)
EXTRA_ENTRY_PKGS = {"kubernetes.admission"}
RULES = ("compliance_report", "deny")  # one report entrypoint per framework; deny for admission


def policy_files():
    for p in sorted(ROOT.rglob("*.rego")):
        rel = p.relative_to(ROOT).as_posix()
        if TEST_RE.search(rel) or "/tests/" in rel or rel.startswith(("converters/", ".git/")):
            continue
        yield p, rel


def discover():
    """Return {class: {"dirs": set, "entrypoints": set}}."""
    by_class = {}
    for p, rel in policy_files():
        src = p.read_text(errors="ignore")
        pkg = PKG_RE.search(src)
        cls = CLASS_RE.search(src)
        if not pkg or not cls:
            continue
        c = cls.group(1)
        top = rel.split("/")[0] if rel.count("/") == 0 else "/".join(rel.split("/")[:2])
        entry = by_class.setdefault(c, {"dirs": set(), "entrypoints": set()})
        entry["dirs"].add(rel.rsplit("/", 1)[0])
        name = pkg.group(1)
        if name.endswith(ENTRY_SUFFIXES) or name in EXTRA_ENTRY_PKGS:
            for r in RULES:
                # a rule can be an entrypoint; a function (`violations(x) := ...`) cannot
                if re.search(rf"^{r}\b", src, re.M) and not re.search(rf"^{r}\s*\(", src, re.M):
                    entry["entrypoints"].add(name.replace(".", "/") + "/" + r)
    return by_class


def build(classes_for_bundle, name, out, by_class):
    dirs, eps = set(), set()
    for c in classes_for_bundle:
        if c in by_class:
            dirs |= by_class[c]["dirs"]
            eps |= by_class[c]["entrypoints"]
    if not eps:
        return None
    target = out / f"{name}.tar.gz"
    cmd = ["opa", "build", "-t", "wasm", "-o", str(target)]
    for e in sorted(eps):
        cmd += ["-e", e]
    # pass top-level dirs that contain this class's policies; opa ignores tests by name
    for d in sorted({d.split("/")[0] for d in dirs}):
        cmd.append(str(ROOT / d))
    subprocess.run(cmd, check=True, cwd=ROOT)
    data = target.read_bytes()
    return {"bundle": target.name, "classes": sorted(classes_for_bundle), "entrypoints": sorted(eps),
            "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(pathlib.Path(__file__).resolve().parent / "out"))
    ap.add_argument("--classes", default="")
    a = ap.parse_args()
    out = pathlib.Path(a.out); out.mkdir(parents=True, exist_ok=True)
    by_class = discover()
    manifest = {"library": "rego_policy_libraries", "revision": subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip(), "bundles": []}
    wanted = [c for c in a.classes.split(",") if c] or list(CONTAINER_FOR_CLASS)
    for container in wanted:
        classes = CONTAINER_FOR_CLASS.get(container, [container])
        r = build(classes, container, out, by_class)
        if r:
            manifest["bundles"].append(r)
    r = build(list(by_class), "all", out, by_class)
    if r:
        manifest["bundles"].append(r)
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    for b in manifest["bundles"]:
        print(f"{b['bundle']:<24} {len(b['entrypoints']):>4} entrypoints  {b['bytes']/1e6:6.1f} MB  {b['sha256'][:12]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
