#!/usr/bin/env python3
"""Build WebAssembly bundles of the library: one per OPA class plus one with everything.

Rego → WASM is packaging, not translation: `opa build -t wasm` compiles every
entrypoint into policy.wasm, which the OPA WASM SDKs evaluate in Go, JavaScript,
Python, Java, .NET and Rust with no OPA server. Entrypoints are every
`<framework>.main` package (the compliance_report orchestrators) plus the
Kubernetes admission package, discovered from the tree so nothing goes stale.

Output: out/<class>.tar.gz (policy.wasm + data + .manifest), out/manifest.json
(entrypoints, sha256, size per bundle). Run from anywhere:

    python3 converters/packaging/wasm/build.py [--out DIR] [--classes security,compliance,ot] [--no-all]

--no-all skips the combined bundle. Pull-request CI uses it: the combined build peaks near
the 16 GB of a GitHub-hosted runner, while each per-class bundle stays at or under ~10 GB.
The release workflow (converters.yml) still builds and publishes the combined bundle.

Data files: a data.json / data.yaml in the tree lands in the bundle's data.json at its path from the
repository root (crosswalk/stig_800_53/data.json -> data.crosswalk.stig_800_53), which is where the modules read
it and where `opa eval -d .` and a `-b .` bundle put it. Each top-level directory is therefore passed to opa as
`<dir>:<path>`; a bare path would root the data at the directory itself (data.stig_800_53) and the crosswalk
would read as not loaded. Every build checks its own data.json and fails if a data file is not at that path.
`--check-data-paths` runs the same check on a plain (non-wasm) bundle of the directories that hold data files: a
few seconds, any opa binary; `make check-converters` runs it.
"""
from __future__ import annotations
import argparse, hashlib, json, pathlib, re, subprocess, sys, tarfile, tempfile

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


DATA_NAMES = ("data.json", "data.yaml", "data.yml")


def root_args(tops):
    """opa path arguments for top-level directories: `<dir>:<abs path>`, so a data file under the directory is
    rooted at data.<dir>.<its path>, the same as from the repository root. Rego files are unaffected."""
    return [f"{d}:{ROOT / d}" for d in sorted(tops)]


def data_files(tops):
    """(document path, file) for every data file under the given top-level directories, tests aside."""
    found = []
    for d in sorted(tops):
        for p in sorted((ROOT / d).rglob("data.*")):
            rel = p.relative_to(ROOT).parts
            if p.name in DATA_NAMES and "tests" not in rel:
                found.append((rel[:-1], p))
    return found


def check_data_paths(bundle, tops):
    """Fail unless every data file under `tops` is in the bundle's data.json at its repository path, with the
    same top-level keys as the file. Returns the document paths checked."""
    with tarfile.open(bundle) as tar:
        member = next((m for m in tar.getmembers() if m.name.lstrip("/") == "data.json"), None)
        data = json.load(tar.extractfile(member)) if member else {}
    checked, problems = [], []
    for parts, src in data_files(tops):
        dotted = "data." + ".".join(parts)
        if src.suffix != ".json":
            problems.append(f"{src.relative_to(ROOT)}: only data.json is checked; convert it or extend check_data_paths")
            continue
        node = data
        for part in parts:
            node = node.get(part) if isinstance(node, dict) else None
        want = json.loads(src.read_text())
        if not isinstance(node, dict) or any(node.get(k) != v for k, v in want.items()):
            problems.append(f"{src.relative_to(ROOT)} is not at {dotted} in {pathlib.Path(bundle).name} "
                            f"(top-level data keys: {sorted(data)[:8]})")
        checked.append(dotted)
    if problems:
        raise SystemExit("bundle data is not at the documented path:\n  " + "\n  ".join(problems))
    return checked


def check_data_paths_quick():
    """The data-path check without the wasm compile: a plain bundle of every top-level directory that holds a
    data file, built with the same path arguments the wasm bundles use."""
    tops = sorted({p.relative_to(ROOT).parts[0] for p, _ in policy_files()})
    tops = [d for d in tops if data_files([d])]
    if not tops:
        print("data paths: no data files in the policy tree")
        return 0
    with tempfile.TemporaryDirectory() as tmp:
        target = pathlib.Path(tmp) / "data-paths.tar.gz"
        subprocess.run(["opa", "build", "-o", str(target), "--ignore", "tests", *root_args(tops)], check=True, cwd=ROOT)
        checked = check_data_paths(target, tops)
    print(f"data paths ok: {', '.join(checked)}")
    return 0


def build(classes_for_bundle, name, out, by_class):
    dirs, eps = set(), set()
    for c in classes_for_bundle:
        if c in by_class:
            dirs |= by_class[c]["dirs"]
            eps |= by_class[c]["entrypoints"]
    if not eps:
        return None
    target = out / f"{name}.tar.gz"
    # test modules never belong in a wasm bundle: opa only skips *_test.rego by itself, and this repo's tests are
    # tests/test_*.rego, whose helper functions (`f(x) := r if { r := ... with input as x }`) the wasm planner rejects
    cmd = ["opa", "build", "-t", "wasm", "-o", str(target), "--ignore", "tests", "--ignore", "test_*.rego"]
    for e in sorted(eps):
        cmd += ["-e", e]
    # pass top-level dirs that contain this class's policies; opa ignores tests by name
    tops = {d.split("/")[0] for d in dirs}
    cmd += root_args(tops)
    subprocess.run(cmd, check=True, cwd=ROOT)
    check_data_paths(target, tops)
    data = target.read_bytes()
    return {"bundle": target.name, "classes": sorted(classes_for_bundle), "entrypoints": sorted(eps),
            "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(pathlib.Path(__file__).resolve().parent / "out"))
    ap.add_argument("--classes", default="")
    ap.add_argument("--no-all", action="store_true", help="skip the combined bundle (pull-request CI)")
    ap.add_argument("--check-data-paths", action="store_true",
                    help="only check that data files land at their repository path in a bundle (no wasm build)")
    a = ap.parse_args()
    if a.check_data_paths:
        return check_data_paths_quick()
    out = pathlib.Path(a.out); out.mkdir(parents=True, exist_ok=True)
    by_class = discover()
    manifest = {"library": "rego_policy_libraries", "revision": subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip(), "bundles": []}
    wanted = [c for c in a.classes.split(",") if c] or list(CONTAINER_FOR_CLASS)
    for container in wanted:
        classes = CONTAINER_FOR_CLASS.get(container, [container])
        r = build(classes, container, out, by_class)
        if r:
            manifest["bundles"].append(r)
    if not a.no_all:
        r = build(list(by_class), "all", out, by_class)
        if r:
            manifest["bundles"].append(r)
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    for b in manifest["bundles"]:
        print(f"{b['bundle']:<24} {len(b['entrypoints']):>4} entrypoints  {b['bytes']/1e6:6.1f} MB  {b['sha256'][:12]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
