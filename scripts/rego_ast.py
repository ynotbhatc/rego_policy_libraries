"""Parse the policy tree with OPA's own parser (`opa parse --format json`) and expose the two things the
library counts and catalogs: control tables and violation rule bodies. Shared by count_controls.py and
inventory_controls.py so the published count and every export read the same facts.

What counts as a control-level check (the published rule):
  * a multi-value rule named violations / violation / deny / warn / findings / finding ("<name> contains x if")
  * a leaf object row of a top-level table (`name := { "id": { ... } }`): an object row whose value contains no
    further object-valued rows is one control; a row that groups further id-keyed object rows is not itself
    counted, its leaves are (nested tables like "9.2": {"9.2.1": {...}})
  * a string row of a top-level table whose name says it is a check table (include regex) and is not report
    scaffolding (report / *_report / *_metadata / metadata / summary): `"qualified": "CCPA §7122(a)(1): ..."`
Fields inside an object row ("text": "...") are never checks, whatever the file's line layout.
Tests (test_*, *_test.rego, tests/), converters/ (generated copies and adapters) and non-.rego data are excluded.
"""
from __future__ import annotations
import json, re, subprocess, pathlib, concurrent.futures as cf

BODY_NAMES = {"violations", "violation", "deny", "warn", "findings", "finding"}
INCLUDE = re.compile(r"(check|notice|consent|obligation|security|breach|retention|right|transfer|government|lawful|flag|field|timing|submission|report|auditor|certification|sdf|children|appeal|exception|opt_out|access|registration|vasp|reporting|coordination|logging|annexure|requirement|control|item|standard|ksi|activit|component)", re.I)
EXCLUDE = re.compile(r"^(sections|chapters|groups|first_report_deadline|notification_clocks|rules_commencement|dated_obligations|compliance_report|availability_targets|penalty|legacy|_in)$")
SCAFFOLD = re.compile(r"^(report|.*_report|.*_metadata|metadata|summary)$")
ID_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]*$")
TEST_RE = re.compile(r"(^|/)(test_|.*_test\.rego$)")


def policy_files(root):
    root = pathlib.Path(root)
    for f in sorted(root.rglob("*.rego")):
        rel = f.relative_to(root).as_posix()
        if TEST_RE.search(rel) or "/tests/" in rel or rel.startswith(("converters/", ".git/")):
            continue
        yield rel


def parse(path):
    out = subprocess.run(["opa", "parse", "--format", "json", str(path)], capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(f"opa parse failed for {path}: {out.stderr.strip()[:300]}")
    return json.loads(out.stdout)


def parse_tree(root, workers=8):
    """{rel: ast} for every policy file, parsed in parallel."""
    root = pathlib.Path(root)
    rels = list(policy_files(root))
    with cf.ThreadPoolExecutor(workers) as ex:
        asts = list(ex.map(lambda r: parse(root / r), rels))
    return dict(zip(rels, asts))


def rule_name(rule):
    h = rule["head"]
    if "name" in h:
        return h["name"]
    ref = h.get("ref") or []
    return ref[0]["value"] if ref and isinstance(ref[0].get("value"), str) else None


def package(ast):
    return ".".join(t["value"] for t in ast["package"]["path"][1:])


def tables(ast):
    """(name, [(key, value_term)]) for every top-level `name := { object literal }` rule."""
    for r in ast.get("rules", []):
        h = r["head"]
        if "value" in h and h["value"]["type"] == "object" and "key" not in h and not r.get("default"):
            rows = [(k["value"], v) for k, v in h["value"]["value"] if k["type"] == "string"]
            yield rule_name(r), rows


def bodies(ast):
    """rules that are multi-value violation sets: (name, rule)"""
    for r in ast.get("rules", []):
        if "key" in r["head"] and rule_name(r) in BODY_NAMES:
            yield rule_name(r), r


def _is_row_group(value_term):
    """an object row whose value holds further id-keyed object rows is a group, not a control"""
    if value_term["type"] != "object":
        return False
    return any(k["type"] == "string" and ID_KEY.match(k["value"]) and v["type"] == "object" and _looks_like_row(v)
               for k, v in value_term["value"])


def _looks_like_row(obj_term):
    # a row object has string fields (text/req/title...) or is itself a group; a bare {} does not count
    return bool(obj_term["value"])


def leaf_rows(key, value_term):
    """yield (key, value_term) for every leaf object row under this row (the row itself when it is a leaf)"""
    if _is_row_group(value_term):
        for k, v in value_term["value"]:
            if k["type"] == "string" and ID_KEY.match(k["value"]) and v["type"] == "object" and _looks_like_row(v):
                yield from leaf_rows(k["value"], v)
    else:
        yield key, value_term


def count_table(name, rows):
    """(object_leaf_rows, string_rows) counted for one table under the published rule"""
    if not name or EXCLUDE.match(name):
        return 0, 0
    obj = strs = 0
    for k, v in rows:
        if not ID_KEY.match(k):
            continue
        if v["type"] == "object" and _looks_like_row(v):
            obj += sum(1 for _ in leaf_rows(k, v))
        elif v["type"] == "string" and INCLUDE.search(name) and not SCAFFOLD.match(name):
            strs += 1
    return obj, strs


def first_message(rule):
    """the violation message of a multi-value rule: the set element itself when it is a string literal
    (`violations contains "CIS L2 1.5: ..." if`) or an object with a string "msg" (`deny contains {"msg": "..."}`),
    else the first string literal (or sprintf format) assigned in the body; None when there is none."""
    key = rule["head"].get("key")
    if key:
        if key["type"] == "string":
            return key["value"]
        if key["type"] == "object":
            for k, v in key["value"]:
                if k["type"] == "string" and k["value"] == "msg" and v["type"] == "string":
                    return v["value"]
                if k["type"] == "string" and k["value"] == "msg" and v["type"] == "call" and v["value"][0].get("value", [{}])[0].get("value") == "sprintf" and v["value"][1]["type"] == "string":
                    return v["value"][1]["value"]
    for expr in rule.get("body", []):
        terms = expr.get("terms")
        if not isinstance(terms, list) or len(terms) < 3:
            continue
        op = terms[0]
        if op.get("type") == "ref" and op["value"][0].get("value") in ("assign", "eq"):
            rhs = terms[2]
            if rhs["type"] == "string":
                return rhs["value"]
            if rhs["type"] == "call" and rhs["value"][0].get("value", [{}])[0].get("value") == "sprintf":
                fmt = rhs["value"][1]
                if fmt["type"] == "string":
                    return fmt["value"]
    return None
