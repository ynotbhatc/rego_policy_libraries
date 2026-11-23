#!/usr/bin/env python3
"""Input schemas: one JSON Schema (draft 2020-12) per framework key for the facts its module reads.

    python3 scripts/gen_input_schemas.py              # write schemas/input/<key>/schema.json and schemas/index.json
    python3 scripts/gen_input_schemas.py --check      # fail if a committed schema is stale, or a self-test fails
    python3 scripts/gen_input_schemas.py --self-test  # self-tests only, on freshly generated schemas
    python3 scripts/gen_input_schemas.py --only stig.rhel_9 cis_rhel9 --self-test

A framework key is the `<key>` of `data.<key>.main.compliance_report` (the wasm build's entrypoint discovery,
the list `make check-no-data` uses). Nothing here is written by hand: every schema comes from a source the
library already keeps, and records which one in `x-derivation`, strongest first:

  table                  the reviewed Linux STIG rule tables, through the collector contract's extraction
                         (tools/stig_generators/gen_collector_contract.py collect()): every path a rule reads,
                         the types its accessor accepts and its pass fixture holds, the rules that read it, and
                         `required` from each rule's evidence list (`ev`). A rule with a Not Applicable clause
                         needs its evidence only when it applies, so those paths are listed in
                         `x-required-when-applicable` and not in `required`.
  manifest               the Windows CIS modules' data/collector_manifest.json: every registry value, audit
                         subcategory and secedit key the checks read. The manifest carries no types and no
                         required list; leaf types are the ones seen in the module's passing test fixtures
                         (`x-type-source: fixture`) and nothing is `required`.
  static-scan+fixture    every `input.<path>` / `object.get(input, [...])` reference in the module's own
                         non-test sources (the same scan the collector contract cross-check uses), plus the
                         shape and types of the module's all-pass test fixture, found by evaluation exactly as
                         scripts/check_bad_input_fails.py finds it. Nothing is `required`: a scan cannot tell
                         required evidence from optional. A module that reads through a local alias
                         (`cfg := input.ssh_config`) contributes those nested names only through its fixture.
  paths-only             the static scan alone (no all-pass fixture was found): names, no types.

The top level stays open (`additionalProperties: true`): callers send shared fact documents. Misnamed keys are
found from the closed list of names the module reads (`x-known-paths`, and the `properties` of each object) by
scripts/validate_input.py.

Self-tests (run by --check and --self-test), per schema: every all-pass fixture found for the key validates;
the fixture with one key re-spelled is flagged MISNAMED at that key; the fixture with one value of a type the
schema excludes is flagged TYPE at that value; for the table schemas, the fixture without one required path is
flagged MISSING, and every rule's own pass fixture validates as a partial document.

OPA is needed for the fixture search (one server with the library and its tests loaded, as `make
check-bad-input` starts); the table schemas need none. Schemas live one directory per key because `opa test .`
loads every JSON file under the root as data, by directory: files sharing a directory would collide on `$id`.
"""
from __future__ import annotations
import argparse, concurrent.futures as cf, importlib, json, pathlib, re, sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tools" / "stig_generators"))
import check_bad_input_fails as bad  # noqa: E402  (entrypoints, module layout, fixture candidates, OPA server)
import gen_collector_contract as contract  # noqa: E402  (collect(), refs(): the one path extraction)
import validate_input as vi  # noqa: E402

OUT = ROOT / "schemas"
BASE_ID = "https://ynotbhatc.github.io/rego_policy_libraries/schemas/input/"
ME = "scripts/gen_input_schemas.py"
EX_STR, EX_ARR = 300, 3


# ---------------------------------------------------------------- the tree every derivation fills
def new():
    return {"types": set(), "props": {}, "items": None, "var": None, "varname": None, "ex": None, "desc": None,
            "req": set(), "x": {}, "tsrc": False, "null": False}


def step(cur, k, typed=True):
    """The child of cur for one path element: a name, `[]` (array member) or `<var>` (a key the rule supplies)."""
    if k == "[]":
        if typed:
            cur["types"].add("array")
        cur["items"] = cur["items"] or new()
        return cur["items"]
    if k.startswith("<"):
        if cur["items"] is not None and not cur["props"]:
            return cur["items"]  # the fixture shows an array here: the variable is its index
        cur["var"] = cur["var"] or new()
        cur["varname"] = cur["varname"] or k
        return cur["var"]
    if typed:
        cur["types"].add("object")
    return cur["props"].setdefault(k, new())


def walk(root, path, typed=True):
    cur = root
    for k in path:
        cur = step(cur, k, typed)
    return cur


def example(v):
    if isinstance(v, str):
        return v if len(v) <= EX_STR else None
    if isinstance(v, list):
        if any(isinstance(x, (dict, list)) for x in v) or any(isinstance(x, str) and len(x) > EX_STR for x in v):
            return None
        return v[:EX_ARR]
    return v


def add_fixture(n, v, mark):
    """Shape, types and examples of a passing fixture value."""
    if v is None:
        n["null"] = True  # a passing fixture holds null here: it is an accepted value, not a type error
        return
    t = vi.jtype(v)
    n["types"].add(t)
    if isinstance(v, dict):
        for k in sorted(v):
            child = n["props"][k] if k in n["props"] else (n["var"] if n["var"] is not None else n["props"].setdefault(k, new()))
            add_fixture(child, v[k], mark)
        return
    if isinstance(v, list):
        n["items"] = n["items"] or new()
        for x in v:
            add_fixture(n["items"], x, mark)
    if mark:
        n["tsrc"] = True
    if n["ex"] is None:
        n["ex"] = example(v)


def to_schema(n, closed_when_listed, required=False):
    s = {}
    if n["desc"]:
        s["description"] = n["desc"]
    t = set(n["types"])
    if "number" in t:
        t.discard("integer")
    if t and n["null"] and not required:  # required evidence is never null: null reads as not collected
        t.add("null")
    if t:
        s["type"] = sorted(t)[0] if len(t) == 1 else sorted(t)
        if n["tsrc"]:
            s["x-type-source"] = "fixture"
    if n["props"]:
        s["properties"] = {k: to_schema(n["props"][k], closed_when_listed, k in n["req"]) for k in sorted(n["props"])}
    if n["req"]:
        s["required"] = sorted(n["req"])
    if n["items"] is not None:
        items = to_schema(n["items"], closed_when_listed)
        if items:
            s["items"] = items
    if n["var"] is not None and not (closed_when_listed and n["props"]):
        # the rule supplies the key from a variable; where the table also lists the concrete keys, those are the contract
        s["additionalProperties"] = to_schema(n["var"], closed_when_listed) or True
        s["x-variable-key"] = n["varname"]
    if n["ex"] is not None:
        s["examples"] = [n["ex"]]
    for k in sorted(n["x"]):
        s[k] = n["x"][k]
    return s


def known_paths(s, path=()):
    out = []
    for k, sub in (s.get("properties") or {}).items():
        out.append(path + (k,))
        out += known_paths(sub, path + (k,))
    if isinstance(s.get("items"), dict):
        out += known_paths(s["items"], path + ("[]",))
    if isinstance(s.get("additionalProperties"), dict):
        out += known_paths(s["additionalProperties"], path + (s.get("x-variable-key") or "<key>",))
    return out


def count_required(s):
    n = len(s.get("required", []))
    for sub in (s.get("properties") or {}).values():
        n += count_required(sub)
    for k in ("items", "additionalProperties"):
        if isinstance(s.get(k), dict):
            n += count_required(s[k])
    return n


def finish(key, root, derivation, sources, title, notes, fixture=None, closed_when_listed=False):
    body = to_schema(root, closed_when_listed)
    s = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"{BASE_ID}{key}/schema.json",
        "title": f"Input facts for {key}" + (f": {title}" if title else ""),
        "description": notes,
        "x-framework-key": key,
        "x-entrypoint": f"data.{key}.main.compliance_report",
        "x-derivation": derivation,
        "x-source": sources,
        "x-generated-by": ME,
    }
    if fixture:
        s["x-fixture"] = fixture
    s["type"] = "object"
    s["properties"] = body.get("properties", {})
    if body.get("required"):
        s["required"] = body["required"]
    s["additionalProperties"] = True
    s["x-known-paths"] = sorted({vi.fmt(p) for p in known_paths(s)})
    return s


# ---------------------------------------------------------------- table: the Linux STIG rule tables
def table_platforms():
    return dict(contract.gen_rhel9.PLATFORMS)


def table_collect(plat):
    """contract.collect() for one platform, so types, examples and meanings are that platform's own."""
    allp = contract.gen_rhel9.PLATFORMS
    contract.gen_rhel9.PLATFORMS = {plat: allp[plat]}
    try:
        paths, rules = contract.collect()
    finally:
        contract.gen_rhel9.PLATFORMS = allp
    return paths, rules[plat]


def table_types(e):
    out, item = set(), set()
    for t in e["types"]:
        if t == "null":
            continue
        if t.startswith("array"):
            out.add("array")
            item |= set(t[len("array of "):].split("/")) if " of " in t else set()  # "array of string/number"
        else:
            out.add(t)
    acc = e["acc"] - {"attest"}
    if acc and acc <= {"_collected"}:
        return None, set()  # presence only: any non-null value
    if acc & {"_str", "_kw"}:
        out |= {"string", "integer"}
    if "_num" in acc:
        out |= {"number", "string"}
    if "attest" in e["acc"]:
        out.add("boolean")
    return out, item if item <= {"string", "number", "boolean"} else set()  # members typed only when all are scalars


def ids(rs, n=6):
    rs = sorted(rs)
    return ", ".join(rs) if len(rs) <= n else ", ".join(rs[: n - 1]) + f" and {len(rs) - n + 1} more"


def table_schema(key, plat):
    paths, rules = table_collect(plat)
    root = new()
    concrete = [p for p in paths if not any(k.startswith("<") for k in p)]
    for p in sorted(paths):
        e = paths[p]
        if any(k.startswith("<") for k in p) and any(contract.matches(p, q) for q in concrete):
            continue  # the concrete keys are listed (`modprobe["usb-storage"]` for `modprobe.<mod>`)
        n = walk(root, p)
        types, item = table_types(e)
        n["null"] = n["null"] or "null" in e["types"]
        read = set().union(*e["rules"].values())
        d = []
        if e["means"]:
            d.append(e["means"].rstrip(".") + ".")
        d.append(f"Read by {ids(read)}.")
        acc = sorted(a for a in e["acc"] if a != "attest")
        if acc:
            d.append("Accepted: " + "; ".join(contract.ACCESSORS[a] for a in acc) + ".")
        if p[0] == "attest" and len(p) == 2:
            d = [f"Attestation (true when attested; absent means not attested). Read by {ids(read)}."]
        n["desc"] = " ".join(d)
        n["x"]["x-read-by"] = sorted(read)
        if types is None:
            n["x"]["x-accepted"] = "any non-null value (presence)"
        else:
            n["types"] |= types
            if len(item) == 1 and "array" in types:
                n["items"] = n["items"] or new()
                n["items"]["types"] |= item
        if e["ex"] is not None and n["ex"] is None:
            n["ex"] = example(e["ex"])
    for sid, spec in rules:
        for p in spec["ev"]:
            p = tuple(p)
            if any(k == "[]" or k.startswith("<") for k in p):
                continue
            leaf = walk(root, p)
            tag = "x-required-when-applicable" if spec.get("na") else "x-required-by"
            leaf["x"].setdefault(tag, []).append(sid)
            if not spec.get("na"):
                cur = root
                for k in p:
                    cur["req"].add(k)
                    cur = cur["props"][k]
    for n in iter_nodes(root):
        for tag in ("x-required-by", "x-required-when-applicable"):
            if tag in n["x"]:
                n["x"][tag] = sorted(set(n["x"][tag]))
    tbl = contract.gen_rhel9.PLATFORMS[plat]["table"]
    notes = (f"Facts the DISA STIG module for {contract.NAMES[plat]} reads, from its reviewed rule table ({len(rules)} rules). "
             "`required` lists the evidence of rules that always apply: absent or null, the rule is Open with "
             "'evidence missing'. Evidence of a rule with a Not Applicable clause is in x-required-when-applicable. "
             "Collect the observed value, not a verdict. Human-readable form: benchmarks/stig/LINUX_COLLECTOR_CONTRACT.md.")
    return finish(key, root, "table", [f"tools/stig_generators/{tbl}.py", "tools/stig_generators/gen_collector_contract.py"],
                  f"DISA STIG, {contract.NAMES[plat]}", notes, closed_when_listed=True), rules


def iter_nodes(n):
    yield n
    for c in n["props"].values():
        yield from iter_nodes(c)
    for c in (n["items"], n["var"]):
        if c is not None:
            yield from iter_nodes(c)


# ---------------------------------------------------------------- shared: static scan of a module's sources
def code(text):
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def static_paths(mdir):
    """{path: [files]} for every input reference in the module directory's non-test sources."""
    out = {}
    for f in sorted(mdir.rglob("*.rego")):
        rel = f.relative_to(ROOT).as_posix()
        if bad.TEST_RE.search(rel):
            continue
        src = code(f.read_text(errors="ignore"))
        found = {p for p, _ in contract.refs(src)} | {(k,) for k in bad.input_keys(src)}
        for p in found:
            if p and not p[0].startswith("<"):
                out.setdefault(p, []).append(rel)
    return out


def add_static(root, spaths, typed):
    for p in sorted(spaths):
        cur, real = root, True
        for k in p:
            # a container type is certain only for a named child of a named parent; a `[var]` may index an array
            cur = step(cur, k, typed and real and not k.startswith("<") and k != "[]")
            real = not k.startswith("<")
        files = sorted(set(spaths[p]))
        names = [pathlib.PurePosixPath(f).name for f in files]
        cur["read_in"] = ", ".join(names[:4]) + (f" and {len(names) - 4} more" if len(names) > 4 else "")


FIXTURE_ONLY = "From the all-pass test fixture; no direct input reference found by the static scan."


def describe_scan(root, fixture_only=FIXTURE_ONLY):
    for n in iter_nodes(root):
        if n is root or n["desc"]:
            continue
        n["desc"] = f"Read in {n['read_in']}." if n.get("read_in") else fixture_only


# ---------------------------------------------------------------- manifest: the Windows CIS modules
MANIFEST_LISTS = {"registry", "registry_keys", "registry_users", "audit_policy_guids", "secedit_system_access", "privilege_rights"}


def manifest_schema(key, mdir, fixtures):
    f = mdir / "data" / "collector_manifest.json"
    m = json.loads(f.read_text())["collector_manifest"]
    extra = set(m) - MANIFEST_LISTS - {"benchmark", "contract"}
    if extra:
        raise SystemExit(f"{f.relative_to(ROOT)}: manifest sections this generator does not map: {sorted(extra)}")
    root = new()
    for k, text in sorted(m["contract"].items()):
        walk(root, (k,))["desc"] = text
    val = "Value the benchmark's checks read (collector_manifest.json); omit a value that does not exist."
    for path, name in m.get("registry", []):
        walk(root, ("registry", path, name))["desc"] = val
    for path in m.get("registry_keys", []):
        walk(root, ("registry", path))["desc"] = "Key whose existence or value list the checks read (collector_manifest.json)."
    for path, name in m.get("registry_users", []):
        walk(root, ("registry_users", "<user SID>", path, name))["desc"] = val
    for g in m.get("audit_policy_guids", []):
        walk(root, ("audit_policy", g))["desc"] = "Audit subcategory the checks read (collector_manifest.json)."
    for k in m.get("secedit_system_access", []):
        walk(root, ("secedit", "system_access", k))["desc"] = "secedit [System Access] key the checks read (collector_manifest.json)."
    for k in m.get("privilege_rights", []):
        walk(root, ("secedit", "privilege_rights", k))["desc"] = "User right the checks read (collector_manifest.json)."
    spaths = {p: v for p, v in static_paths(mdir).items() if len(p) == 1 and p[0] not in root["props"]}
    add_static(root, spaths, True)  # a top-level key the module reads that the manifest contract does not name
    for _, v in fixtures:
        add_fixture(root, v, True)
    for n, text in ((root["props"].get("registry"), "Registry key the checks read (collector_manifest.json)."),
                    ((root["props"].get("registry_users") or new())["var"], None)):
        if n is None:
            continue
        n["desc"] = n["desc"] or "One loaded user profile hive, keyed by the user's SID."
        for c in n["props"].values():
            c["desc"] = c["desc"] or text or "Registry key below the user's hive that the checks read (collector_manifest.json)."
    sec = root["props"].get("secedit")
    if sec:
        for k, text in (("system_access", "secedit [System Access] keys."), ("privilege_rights", "User rights, each a list of SIDs.")):
            if k in sec["props"]:
                sec["props"][k]["desc"] = text
    describe_scan(root, "From a passing test fixture; not listed in the collector manifest.")
    notes = (f"Facts the module for {m['benchmark']} reads, from its collector manifest: every registry value, audit "
             "subcategory, secedit key and user right the checks read. The manifest states no types and no required "
             "list: leaf types are those of the module's passing test fixtures (x-type-source: fixture) and nothing "
             "is marked required (a value that does not exist is omitted, and its control is then not assessed).")
    return finish(key, root, "manifest", [f.relative_to(ROOT).as_posix()], m["benchmark"], notes,
                  fixture=fixtures[0][0] if fixtures else None)


# ---------------------------------------------------------------- static scan (+ fixture)
def scan_schema(key, mdir, fixtures):
    spaths = static_paths(mdir)
    if not spaths and not fixtures:
        return None
    root = new()
    for _, v in fixtures:
        add_fixture(root, v, True)
    add_static(root, spaths, bool(fixtures))
    describe_scan(root)
    rel = mdir.relative_to(ROOT).as_posix()
    if fixtures:
        notes = (f"Facts the module in {rel}/ reads: every input reference found in its sources, with the shape and "
                 "types of its all-pass test fixture (x-type-source: fixture). Nothing is marked required: a static "
                 "scan cannot tell required evidence from optional. Names the module reads through a local alias "
                 "appear only if the fixture carries them.")
        return finish(key, root, "static-scan+fixture", [rel + "/"], None, notes, fixture=fixtures[0][0])
    notes = (f"Input paths referenced in the sources of {rel}/. No all-pass test fixture was found for this key, so "
             "no types are given and nothing is marked required. Names the module reads through a local alias are "
             "not listed.")
    return finish(key, root, "paths-only", [rel + "/"], None, notes)


# ---------------------------------------------------------------- keys and fixtures
def key_of(ep):
    return ep.rsplit("/", 2)[0].replace("/", ".")


def find_fixtures(eps, layout, server=None):
    """{entrypoint: [(data ref of the fixture rule, value)]}: every object-valued test rule the entrypoint passes
    on, largest first (the search check_bad_input_fails.py runs; that script keeps only the largest)."""
    srv = bad.External(server) if server else bad.Server(True)
    try:
        srv.wait()
        cands = {e: bad.candidate_rules(layout[e][2]) for e in eps if e in layout}
        allc = sorted({c for v in cands.values() for c in v})
        with cf.ThreadPoolExecutor(bad.WORKERS) as ex:
            vals = dict(zip(allc, ex.map(lambda c: srv.query(f"{c[0]}/{c[1]}", has_input=False), allc)))
        trials = []
        for e in sorted(cands):
            for c in cands[e]:
                kind, v = vals[c]
                if kind == "ok" and isinstance(v, dict) and v and len(json.dumps(v)) < 2_000_000:
                    trials.append((e, c, v))
        with cf.ThreadPoolExecutor(bad.WORKERS) as ex:
            res = list(ex.map(lambda t: srv.query(t[0], t[2]), trials))
    finally:
        srv.stop()
    out = {}
    for (e, c, v), (kind, r) in zip(trials, res):
        if kind == "ok" and bad.passes(r):
            out.setdefault(e, []).append((sum(1 for _ in bad.leaves(v)), f"data.{c[0].replace('/', '.')}.{c[1]}", v))
    return {e: [(ref, v) for _, ref, v in sorted(fx, key=lambda t: (-t[0], t[1]))] for e, fx in out.items()}


def generate(only=None, server=None, cache=None):
    eps = bad.nodata.entrypoints()
    layout = bad.module_layout(eps)
    plats = {(ROOT / "benchmarks" / "stig" / p).resolve(): p for p in table_platforms()}
    chosen = [e for e in eps if not only or key_of(e) in only]
    if cache and pathlib.Path(cache).exists():
        fixtures = {e: [tuple(x) for x in v] for e, v in json.loads(pathlib.Path(cache).read_text()).items()}
    else:
        fixtures = find_fixtures(chosen, layout, server)
        if cache:
            pathlib.Path(cache).write_text(json.dumps(fixtures))
    schemas, skipped, tables = {}, {}, {}
    for e in chosen:
        key = key_of(e)
        if e not in layout:
            skipped[key] = "no source file found for the entrypoint package"
            continue
        mdir, fx = layout[e][0], fixtures.get(e, [])
        if mdir.resolve() in plats:
            schemas[key], tables[key] = table_schema(key, plats[mdir.resolve()])
        elif (mdir / "data" / "collector_manifest.json").exists():
            schemas[key] = manifest_schema(key, mdir, fx)
        else:
            s = scan_schema(key, mdir, fx)
            if s is None:
                skipped[key] = f"no input reference and no all-pass fixture found under {mdir.relative_to(ROOT).as_posix()}/"
            else:
                schemas[key] = s
    return schemas, skipped, {key_of(e): v for e, v in fixtures.items()}, tables, len(chosen)


def index(schemas, skipped, total):
    by = {}
    for s in schemas.values():
        by[s["x-derivation"]] = by.get(s["x-derivation"], 0) + 1
    return {
        "generated_by": ME,
        "entrypoints": total,
        "with_schema": len(schemas),
        "by_derivation": {k: by[k] for k in ("table", "manifest", "static-scan+fixture", "paths-only") if k in by},
        "schemas": {k: {"derivation": s["x-derivation"], "schema": f"schemas/input/{k}/schema.json",
                        "known_paths": len(s["x-known-paths"]), "required_paths": count_required(s),
                        "source": s["x-source"]} for k, s in sorted(schemas.items())},
        "without_schema": dict(sorted(skipped.items())),
    }


def dump(o):
    return json.dumps(o, indent=1, ensure_ascii=False) + "\n"


def files(schemas, skipped, total):
    out = {OUT / "input" / k / "schema.json": dump(s) for k, s in schemas.items()}
    out[OUT / "index.json"] = dump(index(schemas, skipped, total))
    return out


# ---------------------------------------------------------------- self-tests
def respell(k):
    if "_" in k:
        return k.replace("_", "-")
    return k.lower() if k.lower() != k else k.upper()


def targets(schema, doc):
    """(a key to re-spell, a leaf to give a wrong type) chosen from the fixture, first in sorted order."""
    name, leaf = None, None

    def go(s, v, path):
        nonlocal name, leaf
        if isinstance(v, dict):
            props = s.get("properties") or {}
            for k in sorted(v):
                if k not in props:
                    continue
                alt = respell(k)
                if name is None and len(vi.norm(k)) >= 4 and alt not in v and alt not in props and v[k] is not None:
                    name = (path, k, alt)
                go(props[k], v[k], path + (k,))
        elif isinstance(v, list):
            if isinstance(s.get("items"), dict):
                for i, x in enumerate(v[:1]):
                    go(s["items"], x, path + (i,))
        if leaf is None and s.get("type") and v is not None and path:
            wrong = next((w for w in (True, "x", 7, [], {}) if not vi.type_ok(w, s["type"])), None)
            if wrong is not None:
                leaf = (path, wrong)
    go(schema, doc, ())
    return name, leaf


def put(doc, path, value=None, rename=None, drop=False):
    doc = json.loads(json.dumps(doc))
    cur = doc
    for k in path[:-1]:
        cur = cur[k]
    if rename:
        cur[rename] = cur.pop(path[-1])
    elif drop:
        del cur[path[-1]]
    else:
        cur[path[-1]] = value
    return doc


def errors(schema, doc, partial=False):
    return [f for f in vi.validate(schema, doc, partial) if f["level"] == "error"]


def self_test(schemas, fixtures, tables):
    bad_, ran = [], {"fixture": 0, "misnamed": 0, "type": 0, "missing": 0, "rule fixtures": 0, "synthetic misnamed": 0}
    for key, s in sorted(schemas.items()):
        fx = fixtures.get(key, [])
        for ref, v in fx:
            ran["fixture"] += 1
            for f in errors(s, v):
                bad_.append(f"{key}: all-pass fixture {ref} does not validate: {f['kind']} {f['path']}: {f['message']}")
        if not fx:
            # no fixture: a document holding one known top-level key, re-spelled, must still be flagged
            k = next((k for k in sorted(s["properties"]) if len(vi.norm(k)) >= 4 and respell(k) not in s["properties"]), None)
            if k:
                ran["synthetic misnamed"] += 1
                if not any(f["kind"] == "misnamed" and f["path"] == vi.fmt((respell(k),)) for f in errors(s, {respell(k): 1})):
                    bad_.append(f"{key}: re-spelled key {respell(k)!r} (for {k!r}) is not flagged")
            continue
        doc = fx[0][1]
        name, leaf = targets(s, doc)
        if name is None:
            bad_.append(f"{key}: no key in the fixture to re-spell")
        else:
            path, k, alt = name
            ran["misnamed"] += 1
            got = errors(s, put(doc, path + (k,), rename=alt), partial=True)
            if not any(f["kind"] == "misnamed" and f["path"] == vi.fmt(path + (alt,)) for f in got):
                bad_.append(f"{key}: misnamed key {vi.fmt(path + (alt,))} (for {k}) is not flagged")
        if leaf is None:
            bad_.append(f"{key}: no typed value in the fixture to give a wrong type")
        else:
            path, wrong = leaf
            ran["type"] += 1
            got = errors(s, put(doc, path, wrong), partial=True)
            if not any(f["kind"] == "type" and f["path"] == vi.fmt(path) for f in got):
                bad_.append(f"{key}: wrong type at {vi.fmt(path)} ({json.dumps(wrong)}) is not flagged")
        if s.get("required"):
            r = s["required"][0]
            ran["missing"] += 1
            if not any(f["kind"] == "missing" and f["path"].startswith(vi.fmt((r,))) for f in errors(s, put(doc, (r,), drop=True))):
                bad_.append(f"{key}: required path {r} removed from the fixture is not flagged")
    for key, rules in sorted(tables.items()):
        for sid, spec in rules:
            for v in [spec["green"]] + spec.get("pass_cases", []) + spec.get("na_cases", []) + ([spec["green_na"]] if spec.get("green_na") else []):
                ran["rule fixtures"] += 1
                for f in errors(schemas[key], v, partial=True):
                    bad_.append(f"{key}: pass fixture of {sid} does not validate: {f['kind']} {f['path']}: {f['message']}")
    return bad_, ran


# ---------------------------------------------------------------- main
def main(argv=None):
    ap = argparse.ArgumentParser(description="Generate the per-framework input schemas (schemas/input/<key>/schema.json).")
    ap.add_argument("--check", action="store_true", help="fail on a stale schema or a failing self-test; write nothing")
    ap.add_argument("--self-test", action="store_true", help="run the self-tests on freshly generated schemas; write nothing")
    ap.add_argument("--only", nargs="*", help="framework keys (no index written, no stale-file sweep)")
    ap.add_argument("--server", help="use this running OPA server (library + tests loaded) instead of starting one")
    ap.add_argument("--fixture-cache", help="development aid: reuse the fixture search result saved in this file")
    a = ap.parse_args(argv)
    schemas, skipped, fixtures, tables, total = generate(set(a.only) if a.only else None, a.server, a.fixture_cache)
    want = files(schemas, skipped, total)
    if a.only:
        want.pop(OUT / "index.json")
    rc = 0
    if a.check or a.self_test:
        fails, ran = self_test(schemas, fixtures, tables)
        for f in fails[:60]:
            print("ERROR:", f)
        if len(fails) > 60:
            print(f"ERROR: ... and {len(fails) - 60} more")
        rc = 1 if fails else 0
        print("input schema self-tests: " + ", ".join(f"{v} {k}" for k, v in ran.items()) + f"; {len(fails)} failures")
    if a.check:
        stale = [p for p, text in sorted(want.items()) if not p.exists() or p.read_text() != text]
        if not a.only:
            stale += [p for p in sorted((OUT / "input").glob("*/schema.json")) if p not in want]
        for p in stale[:40]:
            print(f"ERROR: {p.relative_to(ROOT)} is stale: run python3 {ME}")
        rc = rc or (1 if stale else 0)
        if not rc:
            print(f"input schemas current ({len(schemas)} of {total} framework keys)")
    elif not a.self_test:
        for p, text in want.items():
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)
        if not a.only:
            for p in sorted((OUT / "input").glob("*/schema.json")):
                if p not in want:
                    p.unlink()
                    p.parent.rmdir()
        ix = index(schemas, skipped, total)
        print(f"wrote {len(schemas)} schemas under schemas/input/ ({total} framework keys): "
              + ", ".join(f"{v} {k}" for k, v in ix["by_derivation"].items()) + f"; {len(skipped)} without a schema")
    return rc


if __name__ == "__main__":
    sys.exit(main())
