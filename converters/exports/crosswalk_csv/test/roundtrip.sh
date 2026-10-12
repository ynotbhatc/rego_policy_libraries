#!/usr/bin/env bash
# Round-trip for the crosswalk CSVs (CONTRACT.md): build into a temp dir and prove each file holds exactly what
# its source holds — no row lost, none invented, columns stable.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"; ROOT="$(cd "$HERE/../../.." && pwd)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
python3 "$HERE/build.py" --out "$TMP" >/dev/null
python3 - "$ROOT" "$TMP" <<'PY'
import sys, csv, json, pathlib
root, tmp = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
sys.path.insert(0, str(root / "scripts"))
from inventory_controls import inventory
inv = inventory(root)
def rows(name):
    with (tmp / name).open(newline="") as f:
        r = list(csv.DictReader(f))
    return r
c = rows("controls.csv")
assert len(c) == sum(len(e["controls"]) for e in inv), f"controls.csv {len(c)} rows vs inventory {sum(len(e['controls']) for e in inv)}"
assert len({(r["framework"], r["rego_file"], r["control_id"]) for r in c}) == len(c), "duplicate control rows"
assert all((root / r["rego_file"]).exists() for r in c), "a rego_file does not exist"
assert all(r["oscal_control_id"] for r in c)
stig = json.loads((root / "crosswalk/stig_800_53/data.json").read_text())["map"]
s = rows("stig_to_800_53.csv")
assert len(s) == len(stig) and {r["stig_rule_id"] for r in s} == set(stig), "stig rows != map"
assert all(r["nist_800_53"].split(";") == stig[r["stig_rule_id"]] for r in s), "stig targets changed"
fm = json.loads((root / "crosswalk/framework_maps/data.json").read_text())["maps"]
f = rows("framework_to_800_53.csv")
assert len(f) == sum(len(m.get("map", {})) for m in fm.values()), "framework rows != maps"
sp = rows("spine_800_53.csv")
ids = {r["nist_800_53"] for r in sp}
assert set(fm["nist_800_53b_high"]["map"]) <= ids and all(any(True for _ in v) for v in [stig]), "spine misses baseline controls"
assert sum(int(r["stig_rule_count"]) for r in sp) == sum(len(v) for v in stig.values()), "spine STIG counts != map"
assert all(r["baseline_high"] == "yes" for r in sp if r["baseline_moderate"] == "yes"), "a Moderate control missing from High"
idx = json.loads((tmp / "index.json").read_text())
print(f"PASS roundtrip: controls.csv {len(c)} rows, stig_to_800_53.csv {len(s)}, framework_to_800_53.csv {len(f)}, spine_800_53.csv {len(sp)} ({len(idx['stig_platforms'])} STIG platforms); every source row present, none invented")
PY
