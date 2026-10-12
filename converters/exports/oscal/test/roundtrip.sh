#!/usr/bin/env bash
# Round-trip for the OSCAL export (CONTRACT.md): build into a temp dir, prove nothing was lost or invented,
# and validate every catalog against the NIST schema. SKIP (exit 0 locally) only if jsonschema is missing;
# CI greps for SKIP and fails.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"; ROOT="$(cd "$HERE/../../.." && pwd)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
python3 "$HERE/build.py" --out "$TMP" >/dev/null
python3 - "$ROOT" "$TMP" <<'PY'
import sys, json, pathlib
root, tmp = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
sys.path.insert(0, str(root / "scripts"))
from inventory_controls import inventory
inv = inventory(root)
want = {}
for e in inv:
    for c in e["controls"]:
        want.setdefault(e["framework"], set()).add(c["id"])
idx = json.loads((tmp / "catalogs" / "index.json").read_text())
got_total, ids_seen = 0, set()
for row in idx["catalogs"]:
    cat = json.loads((tmp / row["file"]).read_text())["catalog"]
    labels, n = set(), 0
    for g in cat["groups"]:
        for c in g["controls"]:
            n += 1
            assert c["id"] not in ids_seen, f"duplicate control id {c['id']}"
            ids_seen.add(c["id"])
            assert c["parts"] and all(p.get("prose") for p in c["parts"]), f"{c['id']} has an empty part"
            assert any(l["rel"] == "implementation" for l in c["links"]), f"{c['id']} has no implementation link"
            labels.add(next(p["value"] for p in c["props"] if p["name"] == "label"))
    res = {r["uuid"] for r in cat["back-matter"]["resources"]}
    for g in cat["groups"]:
        for c in g["controls"]:
            for l in c["links"]:
                assert l["href"][1:] in res, f"{c['id']} links to a missing resource"
    for r in cat["back-matter"]["resources"]:
        rel = r["rlinks"][0]["href"].split("/blob/")[1].split("/", 1)[1]
        assert (root / rel).exists(), f"resource points at a file that does not exist: {rel}"
    assert labels == want[row["framework"]], f"{row['framework']}: catalog labels != inventory ids (missing {sorted(want[row['framework']] - labels)[:3]}, extra {sorted(labels - want[row['framework']])[:3]})"
    assert n == row["controls"], f"{row['framework']}: index says {row['controls']}, catalog has {n}"
    got_total += n
assert got_total == sum(len(v) for v in want.values()), f"catalogs hold {got_total} controls, inventory has {sum(len(v) for v in want.values())}"
combined = json.loads((tmp / "all.json").read_text())["catalog"]
m = sum(len(g2["controls"]) for g in combined["groups"] for g2 in g["groups"])
assert m == got_total, f"all.json holds {m}, per-framework catalogs hold {got_total}"
# a known control survives with its text
rhel = json.loads((tmp / "catalogs" / "cis_rhel_9.json").read_text())["catalog"]
hit = [c for g in rhel["groups"] for c in g["controls"] if c["id"] == "cis_rhel_9-CIS-1.3.1"]
assert hit and "AIDE" in hit[0]["parts"][0]["prose"], "CIS RHEL 9 1.3.1 did not round-trip"
print(f"PASS roundtrip: {idx['frameworks']} catalogs, {got_total} controls, all.json {m}, every control linked to an existing Rego file")
PY
# schema validation of every catalog + the combined one
out="$(python3 "$HERE/validate.py" $(ls "$TMP"/catalogs/*.json | grep -v index.json) "$TMP/all.json" 2>&1 | grep -v '^ok ' || true)"
if [[ "$out" == *SKIP* ]]; then echo "SKIP schema validation: jsonschema not installed"; exit 0; fi
if [[ "$out" == *FAIL* ]]; then printf '%s\n' "$out" | sed -n '1,20p'; exit 1; fi
echo "PASS schema: every catalog validates against OSCAL ${OSCAL_VERSION:-1.2.3}"
