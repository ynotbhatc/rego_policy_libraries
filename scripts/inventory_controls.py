#!/usr/bin/env python3
"""Shared control inventory for the exports: every control the library evaluates, with its id, text,
framework, class, source, domains, package and file — read from OPA's parser (scripts/rego_ast.py), never
hand-kept, under exactly the rule scripts/count_controls.py publishes, so sum(checks) == make count.

  table object rows    "9.1.5": {"text": "..."}                 -> id "9.1.5", text (leaf rows only)
  table string rows    "qualified": "CCPA §7122(a)(1): ..."     -> id from the message prefix, text
  rule bodies          msg := "CIS 1.3.1: AIDE is not installed" -> id "CIS 1.3.1", text after the colon
                       msg := sprintf("CIS 1.4.2: ... %s", ...)  -> id "CIS 1.4.2", format text

A control id is the message prefix up to the first ':' when that prefix looks like a citation; otherwise the
id is synthesised as <package>#<n>. Messages that share an id are one control with several checks.

Usage: python3 scripts/inventory_controls.py [--json out.json] [--summary]
Import: from inventory_controls import inventory; inventory(root) -> list[dict]
"""
from __future__ import annotations
import json, re, sys, pathlib
from collections import OrderedDict
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from rego_ast import parse_tree, tables, bodies, leaf_rows, first_message, package, INCLUDE, EXCLUDE, SCAFFOLD, ID_KEY

ROOT_DEFAULT = pathlib.Path(__file__).resolve().parent.parent
META_RE = re.compile(r"^#\s*(title|class|framework|source|domains):\s*(.+?)\s*$", re.M)
ID_PREFIX = re.compile(r"^([A-Za-z][A-Za-z0-9 §.\-()/_]{1,58}?)\s*:\s+(.+)$")
TEXT_KEYS = ("text", "req", "title", "description", "name")


def _meta(src):
    m = dict(META_RE.findall(src))
    if "domains" in m:
        m["domains"] = [d.strip() for d in m["domains"].strip("[]").split(",") if d.strip()]
    m["title"] = m.get("title", "").strip('"')
    return m


def _title(meta_title, src, pkg):
    """METADATA titles were inserted mechanically and dozens are the next code comment ("Defaults so ...",
    "DERIVED from ..."); prefer the first prose comment that names a standard, else the package path."""
    def ok(x):
        return bool(x) and x[:1].isupper() and not x.startswith(("Defaults", "DERIVED", "Query", "Usage", "Input", "Rego ")) and len(x) <= 110
    if ok(meta_title):
        return meta_title
    for line in src.splitlines():
        if line.startswith("# ") and not line.startswith(("# METADATA", "# title", "# custom", "#   ")):
            cand = line[2:].strip().rstrip(".")
            if ok(cand) and re.search(r"[A-Z]{2,}|[0-9]", cand):
                return cand
    return pkg.replace("_", " ").replace(".", " / ")


def _split(msg):
    m = ID_PREFIX.match(msg)
    if m:
        return m.group(1).strip(), m.group(2).strip()
    return None, msg.strip()


def _obj_text(obj_term):
    fields = {k["value"]: v for k, v in obj_term["value"] if k["type"] == "string"}
    for k in TEXT_KEYS:
        v = fields.get(k)
        if v and v["type"] == "string":
            return v["value"]
    return ""


def inventory(root=ROOT_DEFAULT):
    root = pathlib.Path(root)
    out = []
    for rel, ast in parse_tree(root).items():
        src = (root / rel).read_text(errors="ignore")
        pkg = package(ast)
        meta = _meta(src)
        controls = OrderedDict()
        synth = 0
        for name, rule in bodies(ast):
            msg = first_message(rule)
            cid, text = _split(msg) if msg else (None, "")
            if not cid:
                synth += 1; cid = f"{pkg}#{synth}"
            controls.setdefault(cid, {"id": cid, "texts": []})["texts"].append(text)
        for name, rows in tables(ast):
            if not name or EXCLUDE.match(name):
                continue
            for k, v in rows:
                if not ID_KEY.match(k):
                    continue
                if v["type"] == "object" and v["value"]:
                    for lk, lv in leaf_rows(k, v):
                        controls.setdefault(lk, {"id": lk, "texts": []})["texts"].append(_obj_text(lv))
                elif v["type"] == "string" and INCLUDE.search(name) and not SCAFFOLD.match(name):
                    pid, text = _split(v["value"])
                    cid = pid or k
                    controls.setdefault(cid, {"id": cid, "texts": []})["texts"].append(text)
        if controls:
            out.append({"file": rel, "package": pkg, "title": _title(meta.get("title", ""), src, pkg),
                        "class": meta.get("class", ""), "framework": meta.get("framework", ""), "source": meta.get("source", ""),
                        "domains": meta.get("domains", []), "controls": list(controls.values())})
    # OPA allows one package-scoped METADATA block per package, so a second file of the same package
    # (mas_trm_controls_a.rego beside mas_trm_main.rego) carries none: inherit from the sibling that has it.
    by_pkg = {}
    for e in out:
        if e["framework"]:
            by_pkg.setdefault(e["package"], e)
    for e in out:
        if not e["framework"]:
            sib = by_pkg.get(e["package"])
            if sib:
                e.update({k: sib[k] for k in ("class", "framework", "source", "domains")})
            else:
                e["framework"] = "_".join(e["file"].split("/")[:2]).replace("-", "_")  # enforcement/aap -> enforcement_aap
    return out


def main():
    inv = inventory()
    if "--json" in sys.argv:
        pathlib.Path(sys.argv[sys.argv.index("--json") + 1]).write_text(json.dumps(inv, indent=1))
    n = sum(len(e["controls"]) for e in inv)
    checks = sum(len(c["texts"]) for e in inv for c in e["controls"])
    distinct = len({(e["framework"], c["id"]) for e in inv for c in e["controls"]})
    fws = sorted({e["framework"] for e in inv})
    print(f"files={len(inv)} frameworks={len(fws)} checks={checks} controls_per_file={n} distinct_controls={distinct}")
    if "--summary" in sys.argv:
        by = {}
        for e in inv:
            by[e["framework"]] = by.get(e["framework"], 0) + len(e["controls"])
        for k, v in sorted(by.items(), key=lambda x: -x[1])[:15]:
            print(f"  {k:<32} {v}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
