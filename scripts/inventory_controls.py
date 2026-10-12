#!/usr/bin/env python3
"""Shared control inventory for the exports: every control the library evaluates, with its id, text,
framework, class, source, domains, package and file — derived from the Rego tree, never hand-kept.

Same recognition rules as scripts/count_controls.py (table-object rows, named check-table rows,
violation rule bodies), plus id/text extraction:

  table object rows    "9.1.5": {"text": "..."}                 -> id "9.1.5", text
  table string rows    "qualified": "CCPA §7122(a)(1): ..."     -> id from the message prefix, text
  rule bodies          msg := "CIS 1.3.1: AIDE is not installed" -> id "CIS 1.3.1", text after the colon
                       msg := sprintf("CIS 1.4.2: ... %s", ...)  -> id "CIS 1.4.2", format text

A control id is the message prefix up to the first ':' when that prefix looks like a citation
(letters/digits/§/./-/spaces/parentheses, <= 60 chars); otherwise the whole message is the text and the id
is synthesised as <package>#<n>. Messages that share an id are one control with several findings.

Usage: python3 scripts/inventory_controls.py [--json out.json] [--summary]
Import: from inventory_controls import inventory; inventory(root) -> list[dict]
"""
from __future__ import annotations
import json, re, sys, pathlib
from collections import OrderedDict

ROOT_DEFAULT = pathlib.Path(__file__).resolve().parent.parent
TEST_RE = re.compile(r"(^|/)(test_|.*_test\.rego$)")
PKG_RE = re.compile(r"^package\s+([a-z0-9_.]+)", re.M)
META_RE = re.compile(r"^#\s*(title|class|framework|source|domains):\s*(.+?)\s*$", re.M)
BODY_RE = re.compile(r"^\s*(violations?|deny|warn|findings?)\s+contains\s+\w+\s+if\b")
MAP_START = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*:=\s*\{\s*$")
OBJ_ROW = re.compile(r'^\s*"([A-Za-z0-9][A-Za-z0-9._ -]*)":\s*\{(.*)$')
STR_ROW = re.compile(r'^\s*"([A-Za-z0-9][A-Za-z0-9._ -]*)":\s*"((?:[^"\\]|\\.)*)"')
MSG_RE = re.compile(r'msg\s*:=\s*(?:sprintf\()?\s*"((?:[^"\\]|\\.)*)"')
INCLUDE = re.compile(r"(check|notice|consent|obligation|security|breach|retention|right|transfer|government|lawful|flag|field|timing|submission|report|auditor|certification|sdf|children|appeal|exception|opt_out|access|registration|vasp|reporting|coordination|logging|annexure|requirement|control|item|standard|ksi|activit|component)", re.I)
EXCLUDE = re.compile(r"^(sections|chapters|groups|first_report_deadline|notification_clocks|rules_commencement|dated_obligations|compliance_report|availability_targets|penalty|legacy|_in)$")
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


def _obj_text(rest):
    for k in TEXT_KEYS:
        mm = re.search(rf'"{k}":\s*"((?:[^"\\]|\\.)*)"', rest)
        if mm:
            return mm.group(1)
    return ""


def inventory(root=ROOT_DEFAULT):
    root = pathlib.Path(root)
    out = []
    for f in sorted(root.rglob("*.rego")):
        rel = f.relative_to(root).as_posix()
        if TEST_RE.search(rel) or "/tests/" in rel or rel.startswith(("converters/", ".git/")):
            continue
        src = f.read_text(errors="ignore")
        pkg = PKG_RE.search(src)
        if not pkg:
            continue
        meta = _meta(src)
        controls = OrderedDict()
        cur = None
        synth = 0
        lines = src.splitlines()
        for i, line in enumerate(lines):
            if BODY_RE.match(line):
                # find the message literal within the next 40 lines of this body
                window = "\n".join(lines[i:i + 40])
                mm = MSG_RE.search(window)
                if mm:
                    cid, text = _split(mm.group(1))
                else:
                    cid, text = None, ""
                if not cid:
                    synth += 1; cid = f"{pkg.group(1)}#{synth}"
                controls.setdefault(cid, {"id": cid, "texts": []})["texts"].append(text)
                continue
            m = MAP_START.match(line)
            if m:
                cur = m.group(1); continue
            if line.strip() == "}":
                cur = None; continue
            if cur and not EXCLUDE.match(cur):
                mo = OBJ_ROW.match(line)
                if mo:
                    cid = mo.group(1); text = _obj_text(mo.group(2))
                    controls.setdefault(cid, {"id": cid, "texts": []})["texts"].append(text)
                    continue
                ms = STR_ROW.match(line)
                if ms and INCLUDE.search(cur):
                    pid, text = _split(ms.group(2))
                    cid = pid or ms.group(1)
                    controls.setdefault(cid, {"id": cid, "texts": []})["texts"].append(text)
        if controls:
            out.append({"file": rel, "package": pkg.group(1), "title": _title(meta.get("title", ""), src, pkg.group(1)),
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
