#!/usr/bin/env python3
"""Parse DISA XCCDF manual benchmarks into the catalog JSON the generators read.

    python3 tools/stig_generators/parse_xccdf.py <key>=<path/to/*_Manual-xccdf.xml> ...

Writes tools/stig_generators/catalogs/<key>.json:
  {benchmark, version, release, release_date, status_date, rules: [{vuln_id, stig_id, severity,
   title, check, fix, ccis}]}
with the FULL check text (no truncation) — the generators' catalog ID hard-gate and the
crosswalk's CCI join both read this file. Catalogs are not committed (the XCCDF is DISA's
and ~2 MB per platform); regenerate from the current SRG-STIG Library compilation.
"""
import json, os, re, sys
import xml.etree.ElementTree as ET

NS = {"x": "http://checklists.nist.gov/xccdf/1.1"}
CATS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "catalogs")


def text(el, path):
    f = el.find(path, NS)
    return (f.text or "").strip() if f is not None else ""


def parse(path):
    root = ET.parse(path).getroot()
    rel = text(root, "x:plain-text[@id='release-info']")
    m = re.search(r"Release:\s*(\d+)\s*Benchmark Date:\s*(.+)$", rel)
    rules = []
    for g in root.findall("x:Group", NS):
        r = g.find("x:Rule", NS)
        if r is None:
            continue
        rules.append({
            "vuln_id": g.get("id"),
            "stig_id": text(r, "x:version"),
            "severity": r.get("severity"),
            "title": text(r, "x:title"),
            "check": text(r, "x:check/x:check-content"),
            "fix": text(r, "x:fixtext"),
            "ccis": [i.text for i in r.findall("x:ident", NS) if (i.text or "").startswith("CCI-")],
        })
    st = root.find("x:status", NS)
    return {
        "benchmark": text(root, "x:title"),
        "version": f"V{text(root, 'x:version')}R{m.group(1)}" if m else text(root, "x:version"),
        "release": m.group(1) if m else "",
        "release_date": m.group(2).strip() if m else "",
        "status_date": st.get("date") if st is not None else "",
        "rules": rules,
    }


def main(args):
    os.makedirs(CATS, exist_ok=True)
    for a in args:
        key, path = a.split("=", 1)
        cat = parse(path)
        out = os.path.join(CATS, f"{key}.json")
        json.dump(cat, open(out, "w"), indent=1)
        sev = {}
        for r in cat["rules"]:
            sev[r["severity"]] = sev.get(r["severity"], 0) + 1
        print(f"{key:18s} {cat['benchmark'][:58]:58s} {cat['version']:6s} {cat['release_date']:12s} rules={len(cat['rules']):4d} {sev}")


if __name__ == "__main__":
    main(sys.argv[1:])
