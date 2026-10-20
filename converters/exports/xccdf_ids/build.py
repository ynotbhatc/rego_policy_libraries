#!/usr/bin/env python3
"""CIS-CAT / XCCDF join table for the CIS modules.

CIS-CAT Pro and the CIS XCCDF benchmarks name a rule
    xccdf_org.cisecurity.benchmarks_rule_<section number>_<Title_with_underscores>
The section number is the join key we can state honestly: our CIS controls carry it ("CIS 1.3.1"), the title
we do not have (the benchmark PDFs are licensed), so dist/cis_xccdf_ids.csv gives, per CIS control the library
evaluates: platform, Rego package, benchmark name and version the module declares, the section number, our
OSCAL control id, and the XCCDF rule-id prefix to join on (`startswith`). Modules that are DERIVED from a
sibling benchmark (Debian 11 from Ubuntu 20.04, Ubuntu 24.04 from 22.04) say so in `derived_from`, because a
CIS-CAT scan of Debian 11 against the Debian benchmark will not share section numbers with the Ubuntu one.
"""
from __future__ import annotations
import csv, re, sys, json, pathlib, argparse, collections

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(HERE.parent))
from inventory_controls import inventory  # noqa: E402
from _lib.findings import token          # noqa: E402

BENCH = re.compile(r'"benchmark":\s*"([^"]+)"')
VER = re.compile(r'"version":\s*"(v?[0-9][^"]*)"')
SECTION = re.compile(r"^CIS\s+(?:L[12]\s+)?(\d+(?:\.\d+)*)\b")
# Workbook-generated packages cite the bare recommendation number ("6.2.1.1"). Accept that only as the whole id
# and only in modules whose ids were checked against the CIS workbook (2026-10-20); elsewhere a bare number may
# be an invented id, and joining it to a CIS-CAT rule would be wrong.
BARE = re.compile(r"^(\d+(?:\.\d+)+)$")
WORKBOOK_VERIFIED = (
    "benchmarks/cis/rhel_9/", "benchmarks/cis/suse_16/", "benchmarks/cis/ubuntu_26_04/",
    "benchmarks/cis/windows_server_2019_modular/", "benchmarks/cis/windows_server_2022_modular/",
    "benchmarks/cis/gcp/", "benchmarks/cis/eks/", "benchmarks/cis/nginx/", "benchmarks/cis/mcp_server/",
    "benchmarks/cis/sql_server_2025/", "benchmarks/cis/intune_defender_antivirus/",
    "benchmarks/cis/oracle/cis_oracle_23ai.rego", "benchmarks/cis/oracle/cis_oracle_26ai.rego",
    "benchmarks/cis/postgresql/cis_postgresql_17.rego",
    "benchmarks/cis/network_devices/arista/", "benchmarks/cis/network_devices/pfsense/",
    "benchmarks/cis/network_devices/opnsense/", "benchmarks/cis/network_devices/fortinet/",
)


def section_of(file, cid):
    """CIS section number for a cited control id, or None."""
    m = SECTION.match(cid)
    if m:
        return m.group(1)
    if file.startswith(WORKBOOK_VERIFIED):
        m = BARE.match(cid)
        if m:
            return m.group(1)
    return None
DERIVED = re.compile(r"DERIVED from (CIS [^(—]+?)\s*(?:\(|—)")


def module_benchmarks():
    """benchmark name/version per package, from the compliance_report literals; the main module of a platform
    wins over section modules that abbreviate the name."""
    by_pkg = {}
    for f in sorted((ROOT / "benchmarks" / "cis").rglob("*.rego")):
        if "_test" in f.name:
            continue
        src = f.read_text(errors="ignore")
        pkg = re.search(r"^package\s+([a-z0-9_.]+)", src, re.M)
        b = BENCH.search(src); v = VER.search(src)
        if pkg and b:
            name = b.group(1)
            version = v.group(1) if v else (re.search(r"\bv\d+\.\d+(\.\d+)?", name).group(0) if re.search(r"\bv\d+\.\d+", name) else "")
            cur = by_pkg.get(pkg.group(1))
            if not cur or (len(name) > len(cur[0]) and not name.startswith("DERIVED")) or f.name.endswith("_main.rego"):
                by_pkg[pkg.group(1)] = (name, version)
    return by_pkg


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--out", default=None); a = ap.parse_args()
    out = pathlib.Path(a.out) if a.out else HERE / "dist"
    out.mkdir(parents=True, exist_ok=True)
    bench = module_benchmarks()
    rows, seen = [], set()
    for e in sorted(inventory(ROOT), key=lambda x: (x["framework"], x["file"])):
        if not e["file"].startswith("benchmarks/cis/"):
            continue
        platform = e["file"].split("/")[2]
        # platform-level benchmark: the package's own literal, else any package of the same platform dir
        name, version = bench.get(e["package"], ("", ""))
        if not name:
            for p, (n, v) in bench.items():
                if p.split(".")[0] == e["package"].split(".")[0]:
                    name, version = n, v; break
        derived = DERIVED.search(name)
        for c in e["controls"]:
            sec = section_of(e["file"], c["id"])
            if not sec:
                continue
            key = (platform, sec)
            if key in seen:
                continue
            seen.add(key)
            rows.append([platform, e["package"], name, version, sec, c["id"], token(f"{token(e['framework'])}-{c['id']}"),
                         f"xccdf_org.cisecurity.benchmarks_rule_{sec}_", derived.group(1).strip() if derived else "", e["file"]])
    with (out / "cis_xccdf_ids.csv").open("w", newline="") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(["platform", "rego_package", "benchmark", "benchmark_version", "section", "control_id", "oscal_control_id", "xccdf_rule_id_prefix", "derived_from", "rego_file"])
        w.writerows(rows)
    per = collections.Counter(r[0] for r in rows)
    (out / "index.json").write_text(json.dumps({"rows": len(rows), "platforms": dict(sorted(per.items())),
                                                "join": "CIS-CAT rule id startswith xccdf_rule_id_prefix, same platform and benchmark version"}, indent=1) + "\n")
    print(f"xccdf_ids: {len(rows)} CIS sections across {len(per)} platforms -> {out / 'cis_xccdf_ids.csv'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
