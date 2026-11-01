#!/usr/bin/env python3
"""Prove every policy module loads into a running OPA server one file at a time.

Why this gate exists
--------------------
The AAC product does not hand OPA a directory. Its loader walks each framework
directory and uploads every non-test ``.rego`` file individually with
``PUT /v1/policies/<id>`` into an OPA server that started empty. OPA compiles
the whole store on every upload, so a module is rejected (HTTP 400,
``rego_type_error: undefined ref`` / ``undefined function``) when it refers to a
rule it cannot see yet: a helper defined in a sibling file of the same package
that has not been uploaded, or a rule whose body the type checker can prove is
unsatisfiable. Two modules that refer to each other can never be loaded in any
order. ``opa check <dir>`` and ``opa test`` compile the directory as one unit
and never see this, which is how a whole framework (HIPAA Part 160/162,
2026-11-01) went missing from the product's OPA while CI stayed green.

What it does
------------
1. Starts a throwaway OPA server (``opa run --server --addr 127.0.0.1:<port>``
   with the ``opa`` binary on PATH or ``--opa <path>``; or, with
   ``--podman-image``, ``podman run --rm -p <port>:8181 <image> run --server``).
2. For every directory given (default: the trees the product loads --
   ``benchmarks frameworks governance enforcement threat_detection``) uploads
   each non-test ``.rego`` file in sorted path order with ``PUT /v1/policies/<id>``,
   where ``<id>`` is the path with ``/`` replaced by ``_`` and the ``.rego``
   suffix dropped, exactly as the product's loader and the Makefile
   ``load-*`` targets do.
3. Reports every file whose upload was rejected, with the HTTP status and OPA's
   message, and exits 1 if there was at least one.

Non-test means: not under a ``tests/`` directory, not ``test_*.rego``, not
``*_test.rego``. Test modules are never uploaded by the product.

Store scope and cost
--------------------
OPA recompiles the whole store on every upload, so loading N files into one
store costs O(N^2): the whole library (865 files) takes about 90 minutes on a
GitHub runner. By default the store is emptied before each directory
(``--store-scope dir``), which is also the product's own unit of loading, and
the run takes a few minutes. This hides nothing that matters: a module's
siblings are still present, and a reference into a package that is *absent*
from the store is never an error in OPA (only a missing rule of a package
that is present is), so a cross-directory reference can only fail with a
bigger store, and that case is already covered by ``opa check --strict`` over
the whole tree in CI. ``--store-scope tree`` empties the store once per
top-level tree, ``--store-scope all`` never does (the exhaustive run).

Limitation
----------
The order of files *within* a directory is the ``find`` order of the host the
product's loader runs on. This script uploads in sorted order, so it proves
the sorted order works and catches every module that can never load (mutual
references, unsatisfiable bodies). It does not prove every possible ``find``
order works: a module that only loads because a sibling sorts before it is
still a latent failure. Make each module self-contained (every rule it refers
to lives in the same file, or in a package that is loaded before the
directory is) and the order stops mattering.

Usage
-----
    python3 scripts/check_per_file_load.py                 # default trees
    python3 scripts/check_per_file_load.py frameworks/privacy/hipaa
    python3 scripts/check_per_file_load.py --podman-image docker.io/openpolicyagent/opa:latest
    make check-per-file-load
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

DEFAULT_TREES = ["benchmarks", "frameworks", "governance", "enforcement", "threat_detection"]
TEST_DIR_NAMES = {"tests", "test"}


def is_test_file(path: Path) -> bool:
    if any(part in TEST_DIR_NAMES for part in path.parts[:-1]):
        return True
    name = path.name
    return name.startswith("test_") or name.endswith("_test.rego")


def policy_files(root: Path, tree: str) -> list[Path]:
    base = root / tree
    if base.is_file():
        return [] if is_test_file(base.relative_to(root)) else [base.relative_to(root)]
    files = sorted(p.relative_to(root) for p in base.rglob("*.rego") if ".git" not in p.parts)
    return [p for p in files if not is_test_file(p)]


def policy_id(rel: Path) -> str:
    return rel.as_posix().replace("/", "_").removesuffix(".rego")


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class OpaServer:
    def __init__(self, port: int, opa: str | None, podman_image: str | None, log: Path):
        self.port = port
        self.base = f"http://127.0.0.1:{port}"
        self.log = log
        if podman_image:
            runtime = shutil.which("podman") or "podman"
            self.cmd = [
                runtime, "run", "--rm", "-p", f"127.0.0.1:{port}:8181", podman_image,
                "run", "--server", "--addr", "0.0.0.0:8181", "--log-level", "error",
            ]
        else:
            binary = opa or shutil.which("opa")
            if not binary:
                sys.exit("error: no `opa` binary on PATH; pass --opa <path> or --podman-image <image>")
            self.cmd = [binary, "run", "--server", "--addr", f"127.0.0.1:{port}", "--log-level", "error"]
        self.proc: subprocess.Popen | None = None
        self.loaded: list[str] = []

    def __enter__(self) -> "OpaServer":
        self._log = open(self.log, "ab")
        self.proc = subprocess.Popen(self.cmd, stdout=self._log, stderr=subprocess.STDOUT)
        deadline = time.time() + 60
        while time.time() < deadline:
            if self.proc.poll() is not None:
                sys.exit(f"error: OPA server exited early (rc={self.proc.returncode}); see {self.log}")
            try:
                with urllib.request.urlopen(f"{self.base}/health", timeout=2) as r:
                    if r.status == 200:
                        return self
            except (urllib.error.URLError, ConnectionError, OSError):
                time.sleep(0.2)
        self.__exit__(None, None, None)
        sys.exit(f"error: OPA server did not become healthy on {self.base}; see {self.log}")

    def __exit__(self, *_exc) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self._log.close()

    def put_policy(self, pid: str, body: bytes) -> tuple[int, str]:
        req = urllib.request.Request(
            f"{self.base}/v1/policies/{pid}", data=body, method="PUT",
            headers={"Content-Type": "text/plain"},
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                self.loaded.append(pid)
                return r.status, ""
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8", "replace")
            try:
                payload = json.loads(raw)
                errors = payload.get("errors") or []
                msg = "; ".join(
                    f"{err.get('code', '')}: {err.get('message', '')}"
                    + (f" ({err['location']['file']}:{err['location']['row']})" if err.get("location") else "")
                    for err in errors
                ) or payload.get("message", raw)
            except ValueError:
                msg = raw
            return e.code, msg
        except (urllib.error.URLError, ConnectionError, http.client.HTTPException, TimeoutError) as e:
            rc = self.proc.poll() if self.proc else None
            why = f"OPA server exited with rc={rc}" if rc is not None else f"OPA server did not answer ({e})"
            sys.exit(f"error: {why} while uploading {pid}; a container killed with rc=137 ran out of memory "
                     f"(the whole store is recompiled on every upload). See {self.log}")

    def delete_all(self) -> None:
        """Empty the store. A module that a still-present module refers to cannot be
        deleted (400), so delete in reverse upload order and retry leftovers."""
        pending = list(reversed(self.loaded))
        while pending:
            left = []
            for pid in pending:
                req = urllib.request.Request(f"{self.base}/v1/policies/{pid}", method="DELETE")
                try:
                    urllib.request.urlopen(req, timeout=60).close()
                except urllib.error.HTTPError as e:
                    if e.code == 404:
                        continue
                    left.append(pid)
            if len(left) == len(pending):
                print(f"  warning: could not empty the store, {len(left)} modules left: {' '.join(left)}", file=sys.stderr)
                break
            pending = left
        self.loaded = []

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    ap.add_argument("trees", nargs="*", default=DEFAULT_TREES,
                    help="directories (or single .rego files) to upload, relative to --root")
    ap.add_argument("--root", default=Path(__file__).resolve().parent.parent, type=Path,
                    help="library root (default: the repo this script lives in)")
    ap.add_argument("--opa", help="path to the opa binary (default: `opa` on PATH)")
    ap.add_argument("--podman-image", help="run OPA from this container image with podman instead of a local binary")
    ap.add_argument("--port", type=int, default=0, help="port for the throwaway server (default: a free one)")
    ap.add_argument("--store-scope", choices=["dir", "tree", "all"], default="dir",
                    help="empty the store before each directory (default; the product's unit of loading), "
                         "before each top-level tree, or never (exhaustive, O(N^2) in the library size)")
    ap.add_argument("--quiet", action="store_true", help="print failures only")
    args = ap.parse_args()

    root: Path = args.root.resolve()
    port = args.port or free_port()
    log = Path(os.environ.get("TMPDIR", "/tmp")) / f"check_per_file_load_opa_{port}.log"

    failures: list[tuple[Path, int, str]] = []
    uploaded = 0
    with OpaServer(port, args.opa, args.podman_image, log) as srv:
        for tree in args.trees:
            files = policy_files(root, tree)
            if not files:
                print(f"warning: no policy files under {tree}", file=sys.stderr)
                continue
            if args.store_scope != "all":
                srv.delete_all()
            if not args.quiet:
                print(f"== {tree}: {len(files)} policy files")
            current_dir = None
            for rel in files:
                if args.store_scope == "dir" and rel.parent != current_dir:
                    if current_dir is not None:
                        srv.delete_all()
                    current_dir = rel.parent
                status, msg = srv.put_policy(policy_id(rel), (root / rel).read_bytes())
                uploaded += 1
                if status != 200:
                    failures.append((rel, status, msg))
                    print(f"FAIL {rel} -> HTTP {status}: {msg}")
                elif not args.quiet and uploaded % 100 == 0:
                    print(f"   ... {uploaded} uploaded")

    print()
    print(f"uploaded {uploaded} policy files, {len(failures)} rejected")
    if failures:
        print("Files the product's per-file loader cannot load:")
        for rel, status, _ in failures:
            print(f"  {rel} (HTTP {status})")
        print("Fix: make each module self-contained -- every rule it refers to must be defined in the same file")
        print("(or in a package that is already loaded), and no rule body may be provably unsatisfiable.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
