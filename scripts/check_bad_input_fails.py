#!/usr/bin/env python3
"""Bad input never passes (issue #301): every compliance_report entrypoint, evaluated on input that is empty,
missing fields, null, or carries strings where numbers or booleans belong, must not report a pass.

Entrypoints come from the wasm build's discovery (the same list `make check-no-data` uses). Per entrypoint:

  base cases (every entrypoint)
    empty            {}
    no_input         no input document at all
    keys_null        every top-level input key the module's own files read (input.<key>) set to null
    keys_str_true    ... set to the string "true"
    keys_str_num     ... set to the string "1"

  reference cases (every entrypoint whose sources read at least one input path; no fixture needed)
    The module's own source says which facts it reads. scripts/input_refs.py walks OPA's parse of the module's
    files (its directory, plus every package those files reference) and collects each `input.a.b.c` path,
    following local and rule aliases, helper parameters, object.get and keys taken from literal tables. One
    document is built in which every leaf path holds the same bad value; a path the rule iterates
    (`input.items[_].x`) is a one-element list.
    refs_str_false   every leaf the string "false"
    refs_str_true    every leaf the string "true"
    refs_str_no      every leaf the string "no"
    refs_null        every leaf null
    The same document with every leaf the boolean false is evaluated as the control (it is not a case: all
    false is a legitimate answer). A reference case fails when the report passes (kind pass), and also when
    it holds FEWER violations or failed controls than the control does (kind fewer-findings): a string or a
    null made findings that boolean false produces go away, while one or two unrelated findings keep
    `compliant` false. That is the shape `not input.x` leaves behind, since `not "false"` is false. The count
    compared is len(violations), else violation_count; failed_controls / failed is compared as well when the
    report carries it. fewer-findings is a kind of its own, not a pass: the verdict is still "not compliant",
    and what is wrong is the per-control result. A presence test on a fact that really is a string
    (`not input.dpo_contact`) reads the same way; such an entry stays listed until the module types the fact.

  fixture cases (entrypoints whose tests hold an all-pass fixture)
    The fixture is found by evaluation, not by reading literals: every complete rule of the test packages
    under the module's directory is fetched from an OPA server that has the library and its tests loaded
    (test packages never share a name with a library package), and the object-valued one with the most
    leaves on which the entrypoint reports a pass is the module's all-pass fixture. Single-key wrappers ({"bsi_c5": {...}}) are descended, so "fields"
    are the keys of the first object with more than one key.
    drop:<field>     that field removed
    null:<field>     that field set to null
    boolstr:<path>   one boolean leaf replaced by its string form ("true" / "false")
    boolopp:<path>   ... by the opposite string (true -> "false", false -> "true")
    boolno:<path>    ... by the string "no"
    null:<path>      ... by null (the leaf itself, not its top-level field)
    drop:<path>      ... removed
    numstr:<path>    one number leaf replaced by its string form (90 -> "90")
    The five boolean mutations are tried on the same sampled leaves.
    Fields whose name never appears in the module's own source are skipped (the module does not read them,
    so dropping them is no test; the same holds for a leaf whose key never appears), and so are report metadata fields (META_FIELD: ids, timestamps, names,
    profile and level selectors) for drop/null; their leaves are still type-swapped. Leaf swaps and fields
    are capped per module (LEAF_CAP, FIELD_CAP) so the run stays CI-sized; the sample is chosen by a stable
    hash of the case id, not by position, so editing a fixture does not reshuffle the known-failures list.

A report passes if compliant == true, or its score (compliance_percentage / compliance_score / score) is
>= 100, or, with neither field, it has no violations and no failed controls. A mutated fixture also fails
the check if its score rises above the fixture's own (kind score-rise). Undefined reports and evaluation errors are recorded
as their own kinds: they are not passes, but the product drops the row, so they are tracked too.

Kinds: pass, fewer-findings (reference cases), score-rise (fixture cases), undefined, error.

Known failures: scripts/bad_input_known_failures.txt, one `<package> <case> <kind>: <reason>` per line.
Other work is fixing these; the target fails only on a failure that is not listed, and prints listed
entries that now hold (stale) so the list can be regenerated.

    python3 scripts/check_bad_input_fails.py                 # report
    python3 scripts/check_bad_input_fails.py --check         # exit 1 on an unlisted failure
    python3 scripts/check_bad_input_fails.py --write-known   # rewrite the known-failures list
    python3 scripts/check_bad_input_fails.py --only cmmc.main --verbose
    python3 scripts/check_bad_input_fails.py --summary new.txt   # unlisted failures per package, by kind

The logic of this script and of scripts/input_refs.py is unit-tested in scripts/tests/ (`make check-bad-input`
runs those first).
"""
from __future__ import annotations
import argparse, collections, concurrent.futures as cf, hashlib, json, os, pathlib, re, socket, subprocess, sys
import tempfile, time
import urllib.error, urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import check_no_data_fails as nodata  # noqa: E402
import input_refs  # noqa: E402

KNOWN = ROOT / "scripts" / "bad_input_known_failures.txt"
TREES = ["benchmarks", "frameworks", "governance", "threat_detection", "crosswalk", "enforcement"]
TEST_RE = re.compile(r"(^|/)(test_[^/]*|[^/]*_test\.rego)$|/tests/")
SCORE_KEYS = ("compliance_percentage", "compliance_score", "score")
LEAF_CAP = 40
FIELD_CAP = 40
# drop/null of report metadata (ids, timestamps, names, profile/level selectors) is not evidence going missing
META_FIELD = re.compile(r"(^|_)(id|time|timestamp|date|as_of|name|hostname|version|profile|level)$", re.I)
WORKERS = max(2, min(16, (os.cpu_count() or 4)))
# reference cases: (case id, value every leaf holds). CONTROL is evaluated for the comparison only.
REF_VALUES = [("refs_str_false", "false"), ("refs_str_true", "true"), ("refs_str_no", "no"), ("refs_null", None)]
CONTROL = "~refs_bool_false"
PARSE_CHUNK = 40


# ---------------------------------------------------------------- discovery
def rego_files():
    for t in TREES:
        for f in sorted((ROOT / t).rglob("*.rego")):
            yield f


def module_layout(eps):
    """{entrypoint: (module_dir, source_text_of_module_files, [test files])}"""
    pkg_file = {}
    srcs, tests = [], []
    for f in rego_files():
        rel = f.relative_to(ROOT).as_posix()
        (tests if TEST_RE.search(rel) else srcs).append(f)
    for f in srcs:
        m = re.search(r"^package\s+([\w.]+)", f.read_text(errors="ignore"), re.M)
        if m:
            pkg_file.setdefault(m.group(1), f)
    out = {}
    for e in eps:
        pkg = e.rsplit("/", 1)[0].replace("/", ".")
        f = pkg_file.get(pkg)
        if f is None:
            continue
        d = f.parent
        if d.name in ("main", "lib"):
            d = d.parent
        text = "\n".join(s.read_text(errors="ignore") for s in srcs if d in s.parents)
        out[e] = (d, text, [t for t in tests if d in t.parents])
    return out


def input_keys(text):
    keys = set(re.findall(r"\binput\.([A-Za-z_][A-Za-z0-9_]*)", text))
    keys |= set(re.findall(r"\binput\[\"([^\"]+)\"\]", text))
    keys |= set(re.findall(r"object\.get\(\s*input\s*,\s*\"([^\"]+)\"", text))
    return sorted(keys)


RULE_RE = re.compile(r"^([a-z_][A-Za-z0-9_]*)\s*(?::=|=)\s*[^=]", re.M)


def candidate_rules(test_files):
    """[(test_package_path, rule)] for complete rules (not tests, not functions) in these test files."""
    out = []
    for t in test_files:
        src = t.read_text(errors="ignore")
        m = re.search(r"^package\s+([\w.]+)", src, re.M)
        if not m:
            continue
        for name in sorted(set(RULE_RE.findall(src))):
            if not name.startswith("test_") and name != "default":
                out.append((m.group(1).replace(".", "/"), name))
    return out


# ---------------------------------------------------------------- server
def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class External:
    """An already-running OPA server that has the library and its tests loaded (--server URL)."""
    def __init__(self, base):
        self.base = base.rstrip("/")

    def wait(self):
        return self

    def stop(self):
        pass

    def query(self, *a, **k):
        return Server.query(self, *a, **k)

    def parse_modules(self, sources):
        return Server.parse_modules(self, sources)


class Server:
    def __init__(self, with_tests):
        self.port = free_port()
        self.base = f"http://127.0.0.1:{self.port}"
        cmd = [os.environ.get("OPA", "opa"), "run", "--server", "--addr", f"127.0.0.1:{self.port}", "--log-level", "error"]
        if not with_tests:
            cmd += ["--ignore", "tests", "--ignore", "test_*", "--ignore", "*_test.rego"]
        cmd += [str(ROOT / t) for t in TREES if (ROOT / t).exists()]
        self.log = tempfile.TemporaryFile()
        self.proc = subprocess.Popen(cmd, stdout=self.log, stderr=subprocess.STDOUT)

    def wait(self):
        deadline = time.time() + float(os.environ.get("BAD_INPUT_START_TIMEOUT", "900"))
        while time.time() < deadline:
            if self.proc.poll() is not None:
                self.log.seek(0)
                sys.exit("OPA server exited early:\n" + self.log.read().decode(errors="replace")[-3000:])
            try:
                with urllib.request.urlopen(f"{self.base}/health", timeout=2) as r:
                    if r.status == 200:
                        return self
            except (urllib.error.URLError, ConnectionError, OSError):
                time.sleep(0.3)
        sys.exit("OPA server did not become healthy")

    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.proc.kill()

    def query(self, path, inp=None, has_input=True):
        """('ok', value) | ('undefined', None) | ('error', message)"""
        body = json.dumps({"input": inp} if has_input else {}).encode()
        req = urllib.request.Request(f"{self.base}/v1/data/{path}", data=body, method="POST",
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=300) as r:
                res = json.loads(r.read())
        except urllib.error.HTTPError as e:
            try:
                msg = json.loads(e.read()).get("errors", [{}])[0].get("message") or str(e)
            except Exception:  # noqa: BLE001
                msg = str(e)
            return "error", msg.splitlines()[0][:160]
        except Exception as e:  # noqa: BLE001
            return "error", str(e)[:160]
        return ("ok", res["result"]) if "result" in res else ("undefined", None)

    def parse_modules(self, sources):
        """{name: AST} through the server's rego.parse_module: the parse `opa parse --format json` prints."""
        body = json.dumps({"query": input_refs.PARSE_QUERY, "input": sources}).encode()
        req = urllib.request.Request(f"{self.base}/v1/query", data=body, method="POST",
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=300) as r:
            return json.loads(r.read())["result"][0]["x"]


# ---------------------------------------------------------------- verdicts
def score(r):
    for k in SCORE_KEYS:
        v = r.get(k)
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            return v
    return None


def passes(r):
    if not isinstance(r, dict):
        return False
    if r.get("compliant") is True:
        return True
    s = score(r)
    if s is not None and s >= 100:
        return True
    if "compliant" in r or s is not None:
        return False
    v = r.get("violations")
    n = len(v) if isinstance(v, (list, dict)) else r.get("violation_count", 1)
    return n == 0 and r.get("failed_controls", 0) in (0, None)


def findings(r):
    """(violations, failed controls) a report holds; None for a count the report does not carry."""
    if not isinstance(r, dict):
        return None, None
    v = r.get("violations")
    n = len(v) if isinstance(v, (list, dict)) else r.get("violation_count")
    f = next((r[k] for k in ("failed_controls", "failed") if k in r), None)
    num = lambda x: x if isinstance(x, (int, float)) and not isinstance(x, bool) else None  # noqa: E731
    return num(n), num(f)


def fewer(case, control):
    """Why a reference case holds fewer findings than its control, or None."""
    (cv, cf_), (bv, bf) = findings(case), findings(control)
    if cv is not None and bv is not None and cv < bv:
        return f"{cv} violations, {bv} with every fact boolean false"
    if cf_ is not None and bf is not None and cf_ < bf:
        return f"{cf_} failed controls, {bf} with every fact boolean false"
    return None


def leaves(o, path=()):
    if isinstance(o, dict):
        if not o:
            return
        for k in sorted(o):
            yield from leaves(o[k], path + (k,))
    elif isinstance(o, list):
        for i, v in enumerate(o):
            yield from leaves(v, path + (i,))
    else:
        yield path, o


def fmt(path):
    """Stable case id for a path; spaces and % are percent-encoded so an id is one token in the known list."""
    s = ""
    for p in path:
        s += f"[{p}]" if isinstance(p, int) else (("." if s else "") + str(p))
    return s.replace("%", "%25").replace(" ", "%20")


def setp(o, path, value, drop=False):
    o = json.loads(json.dumps(o))
    cur = o
    for p in path[:-1]:
        cur = cur[p]
    if drop:
        del cur[path[-1]]
    else:
        cur[path[-1]] = value
    return o


def field_root(fx):
    """Descend single-key object wrappers; return the path of the first object with more than one key."""
    path, cur = (), fx
    while isinstance(cur, dict) and len(cur) == 1 and isinstance(next(iter(cur.values())), dict):
        k = next(iter(cur))
        path, cur = path + (k,), cur[k]
    return path, cur


def spread(items, cap, key):
    """Up to cap items, chosen by a stable hash of each case id: adding or removing one leaf in a fixture
    changes at most one sampled case, so the known-failures list does not churn."""
    if len(items) <= cap:
        return items
    ranked = sorted(items, key=lambda it: hashlib.sha1(key(it).encode()).hexdigest())[:cap]
    return sorted(ranked, key=key)


def fixture_cases(fx, src):
    cases = []
    root, obj = field_root(fx)
    if isinstance(obj, dict):
        named = [k for k in sorted(obj) if re.search(rf"\b{re.escape(k)}\b", src) and not META_FIELD.search(k)]
        for k in spread(named, FIELD_CAP, lambda k: fmt(root + (k,))):
            cases.append((f"drop:{fmt(root + (k,))}", setp(fx, root + (k,), None, drop=True)))
            cases.append((f"null:{fmt(root + (k,))}", setp(fx, root + (k,), None)))
    bools, nums = [], []
    for p, v in leaves(fx):
        name = next((k for k in reversed(p) if isinstance(k, str)), None)
        if name is None or not re.search(rf"\b{re.escape(name)}\b", src):
            continue  # the module never names this leaf, so it cannot read it: swapping it is no test
        if isinstance(v, bool):
            bools.append((p, v))
        elif isinstance(v, (int, float)):
            nums.append((p, str(v)))
    for p, s in spread(nums, LEAF_CAP, lambda t: fmt(t[0])):
        cases.append((f"numstr:{fmt(p)}", setp(fx, p, s)))
    seen = {c for c, _ in cases}
    for p, v in spread(bools, LEAF_CAP, lambda t: fmt(t[0])):
        own, opp = ("true", "false") if v else ("false", "true")
        for cid, doc in ((f"boolstr:{fmt(p)}", setp(fx, p, own)), (f"boolopp:{fmt(p)}", setp(fx, p, opp)),
                         (f"boolno:{fmt(p)}", setp(fx, p, "no")), (f"null:{fmt(p)}", setp(fx, p, None)),
                         (f"drop:{fmt(p)}", setp(fx, p, None, drop=True))):
            if cid not in seen:      # a boolean that is itself a top-level field already has drop: / null:
                seen.add(cid)
                cases.append((cid, doc))
    return cases


def ref_cases(paths):
    """[(case id, document)] for the reference cases, the control first; nothing when no path was found."""
    if not paths:
        return []
    return [(CONTROL, input_refs.document(paths, False))] + [(c, input_refs.document(paths, v)) for c, v in REF_VALUES]


def module_refs(eps, layout, ev):
    """{entrypoint: [leaf input paths]} from the sources of each entrypoint's module and what they reference."""
    files = [f for f in rego_files() if not TEST_RE.search(f.relative_to(ROOT).as_posix())]
    chunks = [files[i:i + PARSE_CHUNK] for i in range(0, len(files), PARSE_CHUNK)]
    asts = {}
    with cf.ThreadPoolExecutor(WORKERS) as ex:
        for chunk, res in zip(chunks, ex.map(
                lambda ch: ev.parse_modules({str(f): f.read_text(errors="ignore") for f in ch}), chunks)):
            for f in chunk:
                asts[f] = res[str(f)]
    scan = input_refs.Scan(asts).run()
    out = {}
    for e in eps:
        if e not in layout:
            continue
        d = layout[e][0]
        cl = input_refs.closure(scan, [f for f in files if d in f.parents])
        out[e] = input_refs.maximal(set().union(*(scan.paths[f] for f in cl)) if cl else set())
    return out


def base_cases(keys):
    cases = [("empty", {}), ("no_input", None)]
    if keys:
        cases += [("keys_null", {k: None for k in keys}), ("keys_str_true", {k: "true" for k in keys}),
                  ("keys_str_num", {k: "1" for k in keys})]
    return cases


# ---------------------------------------------------------------- main
def run(args):
    eps = nodata.entrypoints()
    if args.only:
        eps = [e for e in eps if e.rsplit("/", 1)[0].replace("/", ".") in args.only]
    layout = module_layout(eps)
    # one server with the tests loaded: fixtures are test-package rules, and test packages never share a
    # name with a library package, so the entrypoints evaluate as they do under `opa test`
    ev = ts = External(args.server) if args.server else Server(True)
    try:
        ev.wait()
        t0 = time.time()
        # 1. candidate fixture values (tests loaded)
        cands = {e: candidate_rules(layout[e][2]) for e in eps if e in layout}
        allc = sorted({c for v in cands.values() for c in v})
        with cf.ThreadPoolExecutor(WORKERS) as ex:
            vals = dict(zip(allc, ex.map(lambda c: ts.query(f"{c[0]}/{c[1]}", has_input=False), allc)))
        # 2. which candidates pass their entrypoint (no tests loaded)
        trials = []
        for e, cl in cands.items():
            for c in cl:
                kind, v = vals[c]
                if kind == "ok" and isinstance(v, dict) and v and len(json.dumps(v)) < 2_000_000:
                    trials.append((e, c, v))
        with cf.ThreadPoolExecutor(WORKERS) as ex:
            res = list(ex.map(lambda t: ev.query(t[0], t[2]), trials))
        fixtures = {}
        for (e, c, v), (kind, r) in zip(trials, res):
            if kind == "ok" and passes(r):
                n = sum(1 for _ in leaves(v))
                if e not in fixtures or n > fixtures[e][2]:
                    fixtures[e] = (c, v, n, score(r))
        t_fix = time.time()
        # 3. the input paths each module reads (parsed by the same server)
        refs = module_refs(eps, layout, ev)
        t_refs = time.time()
        # 4. cases
        jobs = []
        for e in eps:
            text = layout[e][1] if e in layout else ""
            for cid, inp in base_cases(input_keys(text)):
                jobs.append((e, cid, inp, None))
            for cid, inp in ref_cases(refs.get(e)):
                jobs.append((e, cid, inp, None))
            if e in fixtures:
                for cid, inp in fixture_cases(fixtures[e][1], text):
                    jobs.append((e, cid, inp, fixtures[e][3]))
        with cf.ThreadPoolExecutor(WORKERS) as ex:
            out = list(ex.map(lambda j: ev.query(j[0], j[2], has_input=j[1] != "no_input"), jobs))
    finally:
        ev.stop()
    failures = {}
    control = {e: (kind, r) for (e, cid, _, _), (kind, r) in zip(jobs, out) if cid == CONTROL}
    for (e, cid, inp, base), (kind, r) in zip(jobs, out):
        pkg = e.rsplit("/", 1)[0].replace("/", ".")
        if cid == CONTROL:
            continue
        if kind == "error":
            failures[(pkg, cid)] = f"error: {r}"
        elif kind == "undefined":
            failures[(pkg, cid)] = "undefined: compliance_report is undefined"
        elif passes(r):
            failures[(pkg, cid)] = f"pass: compliant={json.dumps(r.get('compliant'))} score={json.dumps(score(r))}"
            if cid.startswith("refs_") and control.get(e, ("", None))[0] == "ok" and passes(control[e][1]):
                failures[(pkg, cid)] += " (every fact boolean false passes too)"
        elif base is not None and score(r) is not None and score(r) > base:
            failures[(pkg, cid)] = f"score-rise: {score(r)} > fixture {base}"
        elif cid.startswith("refs_") and control.get(e, ("", None))[0] == "ok" and fewer(r, control[e][1]):
            failures[(pkg, cid)] = f"fewer-findings: {fewer(r, control[e][1])}"
    ncases = sum(1 for j in jobs if j[1] != CONTROL)
    stats = {"entrypoints": len(eps), "with_fixture": len(fixtures), "cases": ncases,
             "with_refs": sum(1 for e in eps if refs.get(e)), "leaves": sum(len(v) for v in refs.values()),
             "seconds": round(time.time() - t0, 1), "fixture_seconds": round(t_fix - t0, 1),
             "scan_seconds": round(t_refs - t_fix, 1), "case_seconds": round(time.time() - t_refs, 1)}
    return eps, fixtures, failures, stats, refs


def load_known():
    known = {}
    if KNOWN.exists():
        for line in KNOWN.read_text().splitlines():
            if line.strip() and not line.startswith("#"):
                pkg, cid, reason = line.split(" ", 2)
                known[(pkg, cid)] = reason
    return known


def write_known(failures, fixtures, eps, stats):
    pkgs = {e.rsplit("/", 1)[0].replace("/", ".") for e in eps}
    withfx = {e.rsplit("/", 1)[0].replace("/", ".") for e in fixtures}
    lines = ["# Generated by scripts/check_bad_input_fails.py --write-known. Known bad-input failures (issue #301):",
             "# entrypoints that pass, go undefined or error on empty / missing / null / string-typed input.",
             "# `make check-bad-input` fails only on a failure NOT listed here. Fix the module, then regenerate.",
             "# Format: <package> <case> <kind>: <detail>. Kinds: pass, fewer-findings, score-rise, undefined, error.",
             f"# {stats['entrypoints']} entrypoints, {stats['with_fixture']} with an all-pass fixture, "
             f"{stats['cases']} cases, {len(failures)} failures in {len({p for p, _ in failures})} packages.",
             "# Entrypoints without an all-pass fixture (base and reference cases only): "
             + str(len(pkgs - withfx)) + f"; entrypoints with reference cases: {stats['with_refs']}", ""]
    lines += [f"{p} {c} {r}" for (p, c), r in sorted(failures.items())]
    KNOWN.write_text("\n".join(lines) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--write-known", action="store_true")
    ap.add_argument("--only", nargs="*")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--summary", help="write the new failures per package, split by kind, to this file")
    ap.add_argument("--server", help="use this running OPA server (library + tests loaded) instead of starting one")
    args = ap.parse_args()
    eps, fixtures, failures, stats, refs = run(args)
    if args.write_known:
        write_known(failures, fixtures, eps, stats)
        print(f"wrote {KNOWN.relative_to(ROOT)}: {len(failures)} failures")
        return 0
    known = load_known()
    scope = {e.rsplit("/", 1)[0].replace("/", ".") for e in eps}
    new = {k: v for k, v in failures.items() if k not in known}
    stale = sorted(k for k in known if k[0] in scope and k not in failures)
    print(f"bad input: {stats['entrypoints']} entrypoints, {stats['with_fixture']} with an all-pass fixture, "
          f"{stats['with_refs']} with reference cases ({stats['leaves']} input paths), "
          f"{stats['cases']} cases in {stats['seconds']}s (fixtures {stats['fixture_seconds']}s, source scan "
          f"{stats['scan_seconds']}s, cases {stats['case_seconds']}s); {len(failures)} failures "
          f"({len(failures) - len(new)} known, {len(new)} new); {len(stale)} known entries now hold")
    kinds = collections.Counter(r.split(":", 1)[0] for r in failures.values())
    print("  by kind: " + ", ".join(f"{k} {n}" for k, n in sorted(kinds.items())))
    for (p, c), r in sorted(new.items()):
        print(f"  NEW {p} {c} {r}")
    if stale:
        print("  stale known entries (module fixed; run --write-known):")
        for p, c in stale[:50]:
            print(f"    {p} {c}")
    if args.verbose:
        for e, (c, _, n, s) in sorted(fixtures.items()):
            print(f"  fixture {e}: data.{c[0].replace('/', '.')}.{c[1]} ({n} leaves, score {s})")
        for e in eps:
            print(f"  refs {e}: {len(refs.get(e) or [])} input paths")
    if args.summary:
        per = collections.defaultdict(collections.Counter)
        for (pk, _), r in new.items():
            per[pk][r.split(":", 1)[0]] += 1
        lines = [f"{pk} " + " ".join(f"{k}={n}" for k, n in sorted(c.items())) for pk, c in sorted(per.items())]
        pathlib.Path(args.summary).write_text("\n".join(lines) + "\n")
    return 1 if args.check and new else 0


if __name__ == "__main__":
    sys.exit(main())
