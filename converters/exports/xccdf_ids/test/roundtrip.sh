#!/usr/bin/env bash
# Round-trip for the XCCDF join table (CONTRACT.md): every CIS control with a section number appears once per
# platform, prefixes are well-formed, a known rule joins, and benchmark names are present.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"; ROOT="$(cd "$HERE/../../.." && pwd)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
python3 "$HERE/build.py" --out "$TMP" >/dev/null
python3 - "$ROOT" "$TMP" <<'PY'
import sys, csv, re, pathlib
root, tmp = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
sys.path.insert(0, str(root / "scripts"))
from inventory_controls import inventory
sys.path.insert(0, str(root / "converters" / "exports" / "xccdf_ids"))
from build import section_of
want = {(e["file"].split("/")[2], e["package"].split(".")[0], section_of(e["file"], c["id"])) for e in inventory(root) if e["file"].startswith("benchmarks/cis/") for c in e["controls"] if section_of(e["file"], c["id"])}
with (tmp / "cis_xccdf_ids.csv").open(newline="") as f:
    rows = list(csv.DictReader(f))
got = {(r["platform"], r["rego_package"].split(".")[0], r["section"]) for r in rows}
assert got == want, f"rows {len(got)} vs inventory sections {len(want)}: missing {sorted(want - got)[:3]} extra {sorted(got - want)[:3]}"
assert len(rows) == len(got), "duplicate benchmark/section rows"
# #322: ids a module cites through sprintf or a lookup table come from its CONTROL_INDEX, so a benchmark that
# publishes one exports every id in it (CIS M365 v7: all 160, not the 111 literal-text ids)
sys.path.insert(0, str(root / "scripts"))
from rego_ast import parse_tree, package
from inventory_controls import control_index
for rel, ast in parse_tree(root).items():
    idx = {i for i, _ in control_index(ast)}
    if not idx or not rel.startswith("benchmarks/cis/"):
        continue
    head = package(ast).split(".")[0]
    have = {r["section"] for r in rows if r["rego_package"].split(".")[0] == head}
    assert idx <= have, f"{rel}: {len(idx - have)} CONTROL_INDEX ids not exported, e.g. {sorted(idx - have)[:5]}"
m365 = {r["section"] for r in rows if r["rego_package"].startswith("cis_m365_v7.")}
assert len(m365) == 160, f"CIS M365 v7 exports {len(m365)} of 160 ids"

assert all(re.fullmatch(r"xccdf_org\.cisecurity\.benchmarks_rule_\d+(\.\d+)*_", r["xccdf_rule_id_prefix"]) for r in rows)
assert all((root / r["rego_file"]).exists() for r in rows)
named = sum(1 for r in rows if r["benchmark"])
assert named / len(rows) >= 0.9, f"only {named}/{len(rows)} rows carry a benchmark name"
hit = [r for r in rows if r["platform"] == "rhel_9" and r["section"] == "6.3.1"]
assert hit and "xccdf_org.cisecurity.benchmarks_rule_6.3.1_Ensure_AIDE_is_installed".startswith(hit[0]["xccdf_rule_id_prefix"]), "RHEL 9 6.3.1 (v3.0.0: AIDE installed) does not join"
assert hit[0]["benchmark"].startswith("CIS Red Hat Enterprise Linux 9"), hit[0]["benchmark"]
deb = [r for r in rows if r["platform"] == "debian_11"]
assert deb and all(r["derived_from"].startswith("CIS Ubuntu") for r in deb), "Debian 11 rows must say they derive from the Ubuntu benchmark"
print(f"PASS roundtrip: {len(rows)} CIS sections on {len({r['platform'] for r in rows})} platforms; {named} with a benchmark name; RHEL 9 6.3.1 joins CIS-CAT by prefix")
PY
