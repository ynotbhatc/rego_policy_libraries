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


# ---------------------------------------------------------------------------------------------
# v3: every shape the library uses to express a check, normalised to (control id | None, text, shape)
# ---------------------------------------------------------------------------------------------
SET_SUFFIXES = ("_violations", "_findings", "_deny", "_failures")
ID_KEYS = ("stig_id", "control_id", "id", "control", "practice", "requirement", "rule_id", "recommendation")
TEXT_KEYS = ("text", "title", "desc", "description", "name", "req", "requirement_text", "summary")
CHECKMAP_SKIP = {"compliant", "violations", "achievement", "status", "summary", "report", "total", "score", "level",
                 "findings", "passed", "failed", "percentage", "compliance_percentage", "details", "input", "data"}
# report plumbing never counts as a check, whatever object it sits in
CHECKMAP_SKIP_RE = re.compile(
    r"(^|_)(summary|total|totals|section|sections|count|counts|percentage|status|result|results|assessed|evaluated|compliant|"
    r"timestamp|version|benchmark|framework|standard|domain|name|title|description|severity|remediation|recommendation|"
    r"gaps|not_covered|satisfied|approved|requires_approval|achieved|maturity|list|score|modules|partitions|cluster|"
    r"requirements_met|violations|findings)(_|$)", re.I)
CITE = re.compile(r"^([A-Za-z0-9§][A-Za-z0-9 §.\-()/_]{0,58}?)\s*:\s+(.+)$")


def split_citation(msg):
    """'CIS 1.3.1: AIDE is not installed' -> ('CIS 1.3.1', 'AIDE is not installed'); a prefix must hold a digit
    (control ids do; 'Note: ...' does not). Returns (None, msg) when there is no citation."""
    m = CITE.match(msg or "")
    if m and re.search(r"\d", m.group(1)):
        return m.group(1).strip(), m.group(2).strip()
    m = LEAD_NUM.match(msg or "")   # "1.1.1 Ensure NGINX is installed ..." (no colon)
    if m:
        return m.group(1), m.group(2).strip()
    return None, (msg or "").strip()


def _text_of(obj_term):
    fields = {k["value"]: v for k, v in obj_term["value"] if k["type"] == "string"}
    for k in TEXT_KEYS:
        v = fields.get(k)
        if v and v["type"] == "string":
            return v["value"]
    return ""


LEAD_NUM = re.compile(r"^(\d+(?:\.\d+)+)\s+(.+)$")


def _msg_of(obj_term):
    fields = {k["value"]: v for k, v in obj_term["value"] if k["type"] == "string"}
    for k in ("msg", "message", "finding", "violation"):
        v = fields.get(k)
        if v and v["type"] == "string":
            return v["value"]
    return None


def _id_of(obj_term):
    fields = {k["value"]: v for k, v in obj_term["value"] if k["type"] == "string"}
    for k in ID_KEYS:
        v = fields.get(k)
        if v and v["type"] == "string" and v["value"].strip():
            return v["value"].strip()
    return None


def _walk_terms(term, out, top_report=False):
    """collect check items from array literals and check maps anywhere in a term tree (head values and body
    expressions). top_report: this object is a report literal itself, so its own keys are plumbing, not checks."""
    if not isinstance(term, dict):
        return
    t = term.get("type")
    if t == "array":
        for el in term["value"]:
            if el["type"] == "object":
                cid = _id_of(el)
                if cid:
                    out.append((cid, _text_of(el), "array-object"))
                else:
                    msg = _msg_of(el)
                    if msg:
                        mid, text = split_citation(msg)
                        out.append((mid, text, "array-object"))
            elif el["type"] == "arraycomprehension":
                head = el["value"].get("term", {})
                if head.get("type") == "string":
                    cid, text = split_citation(head["value"])
                    out.append((cid, text or head["value"], "array-comprehension"))
            elif el["type"] == "string":
                cid, text = split_citation(el["value"])
                if cid:
                    out.append((cid, text, "array-string"))
        for el in term["value"]:
            _walk_terms(el, out)
    elif t in ("arraycomprehension", "setcomprehension", "objectcomprehension"):
        for expr in term["value"].get("body", []):
            for x in (expr.get("terms") if isinstance(expr.get("terms"), list) else [expr.get("terms")]):
                _walk_terms(x, out)
    elif t == "call":
        for x in term["value"][1:]:
            _walk_terms(x, out)
    elif t == "object":
        # a bare rule name is a "var" term in OPA's AST; a dotted one is a one-element "ref"
        refs = [(k["value"], v) for k, v in term["value"] if k["type"] == "string" and k["value"] not in CHECKMAP_SKIP
                and not CHECKMAP_SKIP_RE.search(k["value"]) and not top_report
                and (v["type"] == "var" or (v["type"] == "ref" and len(v["value"]) == 1 and v["value"][0]["type"] == "var"))
                and not str(v.get("value", "")).startswith("_")]
        if len(refs) >= 3:
            for k, v in refs:
                out.append((None, k.replace("_", " "), "check-map:" + k))
        for k, v in term["value"]:
            _walk_terms(v, out)


def items(ast):
    """Every check a module expresses, as (control id or None, text, shape). The published rule (v3):
      set-rule         a multi-value rule named violations/violation/deny/warn/findings/finding or ending in
                       _violations/_findings/_deny/_failures: one item, id from the message citation if any
      table-row        a leaf object row of a top-level table, or a string row of a check table (not scaffolding)
      finding-rule     a value rule named finding_* whose value is an object with an id key (STIG modules)
      array-*          inside any array literal (head or body): an object with an id key, a single-element
                       comprehension whose string carries a citation, or a cited string literal
    Items are later de-duplicated per file by control id: a control evaluated by several rules is one check;
    only set-rules without a citation count individually."""
    out = []
    for r in ast.get("rules", []):
        h = r["head"]; name = rule_name(r) or ""
        if "key" in h and (name in BODY_NAMES or name.endswith(SET_SUFFIXES) or name.startswith(("violation_", "violations_", "deny_"))):
            msg = first_message(r)
            cid, text = split_citation(msg) if msg else (None, "")
            out.append((cid, text or (msg or ""), "set-rule"))
            continue
        if "value" in h and h["value"]["type"] == "object" and "key" not in h and not r.get("default"):
            if name.startswith("finding_"):
                cid = _id_of(h["value"])
                if cid:
                    out.append((cid, _text_of(h["value"]), "finding-rule"))
                continue
            _walk_terms(h["value"], out, top_report=bool(name and (EXCLUDE.match(name) or SCAFFOLD.match(name))))
            if name and not EXCLUDE.match(name):
                for k, v in [(k["value"], v) for k, v in h["value"]["value"] if k["type"] == "string"]:
                    if not ID_KEY.match(k):
                        continue
                    if v["type"] == "object" and v["value"]:
                        for lk, lv in leaf_rows(k, v):
                            out.append((lk, _text_of(lv), "table-row"))
                    elif v["type"] == "string" and INCLUDE.search(name) and not SCAFFOLD.match(name):
                        cid, text = split_citation(v["value"])
                        out.append((cid or k, text, "table-row"))
            continue
        # arrays in head values and bodies (STIG findings lists, CMMC practices, comprehension-of-arrays modules)
        if "value" in h:
            _walk_terms(h["value"], out)
        for expr in r.get("body", []):
            terms = expr.get("terms")
            for x in (terms if isinstance(terms, list) else [terms]):
                _walk_terms(x, out)
    return out


def checks(ast):
    """(count, cited_ids, uncited): per module, every distinct check. A check is a distinct (control id, text)
    pair — several rules citing the same article paragraph with different requirements ("Art.21(2)(c): BCP not
    documented" / "...not tested annually") are several checks of that control, while a row re-listed with the
    same text is one — plus each uncited item counted on its own. cited_ids is the set of distinct control ids."""
    its = items(ast)
    cited = {(cid, (text or "").strip()) for cid, text, _ in its if cid}
    ids = {cid for cid, _ in cited}
    uncited = sum(1 for cid, _, shape in its if not cid and (shape in ("set-rule", "array-comprehension", "array-object") or shape.startswith("check-map:")))
    return len(cited) + uncited, ids, uncited
