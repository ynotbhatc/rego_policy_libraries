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

  control index        CONTROL_INDEX := [{"id": "9.1.1", ...}, ...]  (the per-control-results index a module
                       publishes) -> every listed id the literal-text rules above did not find (ids cited through
                       sprintf("CIS %s: ...", [id]) or a lookup table, attestation-ledger ids). Added with shape
                       "control-index", in the label form the benchmark's messages use ("CIS 9.1.1" or "9.1.1"),
                       attributed to the module that names the id. These are ids, not extra checks: `make count`
                       does not see them, so sum(checks) == make count holds over the other shapes.

Usage: python3 scripts/inventory_controls.py [--json out.json] [--summary]
Import: from inventory_controls import inventory; inventory(root) -> list[dict]
"""
from __future__ import annotations
import json, re, sys, pathlib
from collections import OrderedDict
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from rego_ast import parse_tree, items, package, rule_name, split_citation as _split

ROOT_DEFAULT = pathlib.Path(__file__).resolve().parent.parent
META_RE = re.compile(r"^#\s*(title|class|framework|source|domains):\s*(.+?)\s*$", re.M)
ID_PREFIX = re.compile(r"^([A-Za-z][A-Za-z0-9 §.\-()/_]{1,58}?)\s*:\s+(.+)$")


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




CITED = re.compile(r"^CIS\s+(?:L[12]\s+)?")


def _norm_ids(cid):
    """'CIS 5.3.4/5.3.5' -> {'5.3.4', '5.3.5'}; '6.2.1.1' -> {'6.2.1.1'}."""
    return {x.strip() for x in CITED.sub("", cid).split("/") if x.strip()}


def control_index(ast):
    """[(id, row)] from a top-level `CONTROL_INDEX := [{"id": ...}, ...]`, else []."""
    for r in ast.get("rules", []):
        h = r["head"]
        if rule_name(r) == "CONTROL_INDEX" and "value" in h and h["value"]["type"] == "array":
            rows = []
            for t in h["value"]["value"]:
                if t["type"] != "object":
                    continue
                row = {k["value"]: v for k, v in t["value"] if k["type"] == "string"}
                if row.get("id", {}).get("type") == "string":
                    rows.append((row["id"]["value"], row))
            return rows
    return []


def _index_text(cid, row, src, file):
    """What the module says about an index id: a table row keyed by it ("1.1.2": "emergency access accounts
    defined"), else the setting a table maps to it ("PublishToWeb": "9.1.4"), plus the evidence paths the index
    row lists."""
    m = re.search(r'"' + re.escape(cid) + r'"\s*:\s*"([^"]{3,})"', src)
    text = m.group(1) if m else ""
    if not text:
        names = re.findall(r'"([A-Za-z_][A-Za-z0-9_]*)"\s*:\s*"' + re.escape(cid) + r'"', src)
        names = [n for n in names if n not in ("id", "control")]
        if names:
            text = "checks " + ", ".join(dict.fromkeys(names)) + " (table-driven rule; id from the module's CONTROL_INDEX)"
    ev = [t["value"] for t in row.get("evidence", {}).get("value", []) if isinstance(t, dict) and t.get("type") == "string"] \
        if row.get("evidence", {}).get("type") == "array" else []
    if ev:
        text = (text + "; " if text else "") + "evidence: " + ", ".join(ev)
    return text or f"evaluated in {file} by a table-driven rule (id from the module's CONTROL_INDEX)"


def _add_index_controls(root, trees, out):
    """Add the CONTROL_INDEX ids the literal-text rules missed (see the module docstring)."""
    by_file = {e["file"]: e for e in out}
    for rel, ast in trees.items():
        rows = control_index(ast)
        if not rows:
            continue
        head = package(ast).split(".")[0]
        base = str(pathlib.PurePosixPath(rel).parent)
        fam = [e for e in out if e["package"].split(".")[0] == head and e["file"].startswith(base + "/")]
        have, cited = set(), 0
        for e in fam:
            for c in e["controls"]:
                if c["id"].startswith(e["package"] + "#"):
                    continue
                have |= _norm_ids(c["id"])
                cited += 1
        prefix = "CIS " if fam and sum(c["id"].startswith("CIS ") for e in fam for c in e["controls"]) * 2 > cited else ""
        others = [(f, (root / f).read_text(errors="ignore")) for f in sorted(trees) if f != rel and f.startswith(base + "/")
                  and package(trees[f]).split(".")[0] == head]
        own = (root / rel).read_text(errors="ignore")
        for cid, row in rows:
            if cid in have:
                continue
            have.add(cid)
            needle = f'"{cid}"'
            file, src = next(((f, s) for f, s in others if needle in s), (rel, own))
            e = by_file.get(file)
            if e is None:
                meta = _meta(src)
                e = {"file": file, "package": package(trees[file]), "title": _title(meta.get("title", ""), src, package(trees[file])),
                     "class": meta.get("class", ""), "framework": meta.get("framework", ""), "source": meta.get("source", ""),
                     "domains": meta.get("domains", []), "controls": []}
                out.append(e); by_file[file] = e
            e["controls"].append({"id": prefix + cid, "texts": [_index_text(cid, row, src, file)], "shape": "control-index"})


def inventory(root=ROOT_DEFAULT):
    root = pathlib.Path(root)
    out = []
    trees = parse_tree(root)
    for rel, ast in trees.items():
        src = (root / rel).read_text(errors="ignore")
        pkg = package(ast)
        meta = _meta(src)
        controls = OrderedDict()
        synth = 0
        for cid, text, shape in items(ast):
            if not cid:
                synth += 1
                cid = f"{pkg}#{synth}"
            controls.setdefault(cid, {"id": cid, "texts": [], "shape": shape.split(":")[0]})["texts"].append(text)
        if controls:
            out.append({"file": rel, "package": pkg, "title": _title(meta.get("title", ""), src, pkg),
                        "class": meta.get("class", ""), "framework": meta.get("framework", ""), "source": meta.get("source", ""),
                        "domains": meta.get("domains", []), "controls": list(controls.values())})
    _add_index_controls(root, trees, out)
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
    checks = sum(len(c["texts"]) for e in inv for c in e["controls"] if c["shape"] != "control-index")
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
