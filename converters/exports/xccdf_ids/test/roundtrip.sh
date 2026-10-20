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
want = {(e["file"].split("/")[2], section_of(e["file"], c["id"])) for e in inventory(root) if e["file"].startswith("benchmarks/cis/") for c in e["controls"] if section_of(e["file"], c["id"])}
with (tmp / "cis_xccdf_ids.csv").open(newline="") as f:
    rows = list(csv.DictReader(f))
got = {(r["platform"], r["section"]) for r in rows}
assert got == want, f"rows {len(got)} vs inventory sections {len(want)}: missing {sorted(want - got)[:3]} extra {sorted(got - want)[:3]}"
assert len(rows) == len(got), "duplicate platform/section rows"
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
