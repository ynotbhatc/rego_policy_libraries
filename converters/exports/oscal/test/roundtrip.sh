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
# component-definition: one implemented-requirement per catalog control, every control-id resolves
python3 "$HERE/build_component.py" --out "$TMP" --catalogs "$TMP/catalogs" >/dev/null
# assessment-results from live evaluations (fail-closed on empty input), targets resolve to catalog statement parts
echo '{}' > "$TMP/empty.json"
opa eval -f json -d "$ROOT/benchmarks/cis/rhel_9" -i "$TMP/empty.json" 'data.cis_rhel9.main.compliance_report' > "$TMP/cis.json"
opa eval -f json -d "$ROOT/frameworks/privacy/ccpa" -i "$TMP/empty.json" 'data.ccpa' > "$TMP/ccpa.json"
opa eval -f json -d "$ROOT/benchmarks/stig/oracle_database_19c" -i "$TMP/empty.json" 'data.stig.oracle_database_19c.main.compliance_report' > "$TMP/stig.json"
python3 "$HERE/build_assessment_results.py" "$TMP/cis.json" "$TMP/ccpa.json" "$TMP/stig.json" -o "$TMP/assessment-results.json" --time 2026-10-12T00:00:00Z --subject roundtrip --catalogs "$TMP/catalogs" >/dev/null
python3 - "$TMP" <<'PY'
import sys, json, pathlib
tmp = pathlib.Path(sys.argv[1])
idx = json.loads((tmp / "catalogs" / "index.json").read_text())
parts, ids = set(), set()
for row in idx["catalogs"]:
    for g in json.loads((tmp / row["file"]).read_text())["catalog"]["groups"]:
        for c in g["controls"]:
            ids.add(c["id"]); parts.update(p["id"] for p in c["parts"])
cd = json.loads((tmp / "component-definition.json").read_text())["component-definition"]
reqs = [r for ci in cd["components"][0]["control-implementations"] if not any(p["name"] == "baseline" for p in ci["props"]) for r in ci["implemented-requirements"]]
assert len(reqs) == idx["controls"] == len(ids), f"{len(reqs)} implemented-requirements vs {idx['controls']} catalog controls"
assert {r["control-id"] for r in reqs} == ids, "implemented-requirements do not cover the catalogs exactly"
assert len({r["uuid"] for r in reqs}) == len(reqs), "duplicate implemented-requirement uuids"
ar = json.loads((tmp / "assessment-results.json").read_text())["assessment-results"]
res = ar["results"][0]
obs = {o["uuid"] for o in res["observations"]}
assert res["findings"] and len(res["findings"]) == len(res["observations"]) > 50
for f in res["findings"]:
    assert f["target"]["status"]["state"] == "not-satisfied"
    assert all(ro["observation-uuid"] in obs for ro in f["related-observations"])
    if f["target"]["type"] == "objective-id":
        assert f["target"]["target-id"] in parts, f["target"]["target-id"]
mapped = sum(1 for f in res["findings"] if f["target"]["type"] == "objective-id")
assert mapped / len(res["findings"]) >= 0.6, f"only {mapped}/{len(res['findings'])} findings target a catalog statement"
stig = [f for f in res["findings"] if f["target"]["target-id"] == "stig_oracle_database_19c-O19C-00-009200_stmt"]
assert stig and stig[0]["target"]["type"] == "objective-id" and "REMOTE_OS_ROLES" in stig[0]["description"], "STIG object finding did not target its catalog statement"
reviewed = sum(len(s.get("include-controls", [])) for s in res["reviewed-controls"]["control-selections"])
assert reviewed >= mapped
print(f"PASS roundtrip: component-definition {len(reqs)} implemented-requirements == catalogs; assessment-results {len(res['findings'])} findings ({mapped} on catalog statements), {reviewed} reviewed controls")
PY
# profiles: sources fetched (pinned + sha256-verified, cached), every selected control resolves in the NIST catalog
rc=0; python3 "$HERE/build_profiles.py" --out "$TMP" >"$TMP/profiles.log" || rc=$?
if [[ $rc -eq 3 ]]; then cat "$TMP/profiles.log"; PROFILES=skip
elif [[ $rc -ne 0 ]]; then cat "$TMP/profiles.log"; echo "FAIL profiles: build_profiles.py exited $rc"; exit 1
else
PROFILES=ok
python3 - "$HERE" "$TMP" <<'PY'
import sys, json, pathlib
here, tmp = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
sys.path.insert(0, str(here))
import build_profiles as bp
cache = bp.CACHE
def walk(node, ids):
    for c in node.get("controls", []):
        ids.add(c["id"]); walk(c, ids)
    for g in node.get("groups", []):
        walk(g, ids)
cat = json.loads(bp.cached_path(cache, bp.CATALOG).read_text())["catalog"]
known = set(); walk(cat, known)
idx = json.loads((tmp / "profiles" / "index.json").read_text())
assert len(idx["profiles"]) == len(bp.SOURCES) == 8, f"{len(idx['profiles'])} profiles in index.json"
total = 0
for row in idx["profiles"]:
    src = next(s for s in bp.SOURCES if s["key"] == row["key"])
    prof = json.loads((tmp / row["file"]).read_text())["profile"]
    assert len(prof["imports"]) == 1 and prof["imports"][0]["href"] == bp.CATALOG["url"], f"{row['key']}: import is not the pinned NIST catalog"
    ids = bp.with_ids(prof)
    missing = [i for i in ids if i not in known]
    assert not missing, f"{row['key']}: {len(missing)} selected controls not in the NIST catalog (e.g. {missing[:3]})"
    assert len(ids) == len(set(ids)), f"{row['key']}: duplicate selections"
    assert len(ids) == row["controls"], f"{row['key']}: index says {row['controls']}, profile selects {len(ids)}"
    srcdoc = json.loads(bp.cached_path(cache, src).read_text())["profile"]
    assert ids == bp.with_ids(srcdoc), f"{row['key']}: selection differs from the source profile"
    assert not any(k in prof for k in ("modify",)), f"{row['key']}: carries a modify section"
    total += len(ids)
print(f"PASS profiles: {len(idx['profiles'])} baselines, every selected control resolves in the NIST SP 800-53 Rev 5 catalog ({total} selections)")
PY
# baseline coverage: library checks -> NIST 800-53 ids -> covered/uncovered controls per imported baseline
python3 "$HERE/build_baseline_coverage.py" --out "$TMP" --catalogs "$TMP/catalogs" >"$TMP/coverage.log"
python3 "$HERE/build_component.py" --out "$TMP" --catalogs "$TMP/catalogs" >/dev/null
python3 "$ROOT/converters/exports/crosswalk_csv/build.py" --out "$TMP/crosswalk" >/dev/null
python3 - "$HERE" "$TMP" <<'PY'
import sys, json, csv, pathlib, collections
here, tmp = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
sys.path.insert(0, str(here))
import build_baseline_coverage as bc
import build_profiles as bp
rows = list(csv.DictReader((tmp / "profiles" / "coverage.csv").open()))
summ = json.loads((tmp / "profiles" / "coverage_summary.json").read_text())
idx = json.loads((tmp / "profiles" / "index.json").read_text())
withids = {r["key"]: bp.with_ids(json.loads((tmp / r["file"]).read_text())["profile"]) for r in idx["profiles"]}
labels = {f"{fw}:{lb}" for fw, lb in bc.catalog_controls(tmp / "catalogs")}
by = collections.defaultdict(list)
for r in rows:
    by[r["baseline_key"]].append(r)
assert set(by) == set(withids) == set(summ["baselines"]), "coverage baselines != profiles"
base_only = {"stig-cci"}
for k, rs in by.items():
    assert [r["control_id"] for r in rs] == withids[k], f"{k}: coverage rows are not the profile's with-ids in order"
    n = {"base": [0, 0], "enhancement": [0, 0]}
    for r in rs:
        assert r["kind"] == ("enhancement" if "." in r["control_id"] else "base")
        chk = r["checks"].split(";") if r["checks"] else []
        assert (r["covered"] == "yes") == bool(chk) and int(r["check_count"]) == len(chk) and chk == sorted(chk)
        missing = [c for c in chk if c not in labels]
        assert not missing, f"{k} {r['control_id']}: checks not in the catalogs: {missing[:3]}"
        if r["kind"] == "enhancement" and r["covered"] == "yes":
            assert set(r["sources"].split(";")) - base_only, f"{k} {r['control_id']}: enhancement covered by a base-control-only source"
        n[r["kind"]][0] += r["covered"] == "yes"; n[r["kind"]][1] += 1
    s = summ["baselines"][k]
    assert (s["base"]["covered"], s["base"]["total"], s["enhancement"]["covered"], s["enhancement"]["total"]) == (*n["base"], *n["enhancement"]), f"{k}: summary != csv"
    assert s["controls"] == len(withids[k]) == next(r["controls"] for r in idx["profiles"] if r["key"] == k)
covered_ids = {r["control_id"] for r in rows if r["covered"] == "yes"}
# the label-is-800-53 mapping must equal spine_800_53.csv library_controls
spine = {}
for r in csv.DictReader((tmp / "crosswalk" / "spine_800_53.csv").open()):
    for c in filter(None, r["library_controls"].split(";")):
        spine.setdefault(bc.oscal_id(r["nist_800_53"]), set()).add(c)
mp, stats = bc.build_mapping(tmp / "catalogs")
mine = {cid: {c for c, src in v.items() if "label-is-800-53" in src} for cid, v in mp.items()}
mine = {cid: v for cid, v in mine.items() if v}
assert mine == spine, f"label-is-800-53 mapping differs from spine_800_53.csv library_controls ({len(mine)} vs {len(spine)} ids)"
assert summ["excluded_topic_rows"] == stats["excluded_topic_rows"] == 24, f"excluded topic rows: {summ['excluded_topic_rows']}"
# component-definition: baseline control-implementations hold exactly the covered controls
cd = json.loads((tmp / "component-definition.json").read_text())["component-definition"]
bimpl = [ci for ci in cd["components"][0]["control-implementations"] if any(p["name"] == "baseline" for p in ci["props"])]
assert len(bimpl) == len(summ["baselines"]) == 8
for ci in bimpl:
    k = next(p["value"] for p in ci["props"] if p["name"] == "baseline")
    assert ci["source"].endswith(f"/dist/profiles/{k}.json")
    assert len(ci["implemented-requirements"]) == summ["baselines"][k]["covered"], f"{k}: component has {len(ci['implemented-requirements'])} requirements, summary says {summ['baselines'][k]['covered']}"
    assert {r["control-id"] for r in ci["implemented-requirements"]} <= set(withids[k])
    for r in ci["implemented-requirements"]:
        g = next(p["value"] for p in r["props"] if p["name"] == "granularity")
        assert g == ("enhancement" if "." in r["control-id"] else "base-control")
fm = summ["baselines"]["fedramp_rev5_moderate"]
print(f"PASS baseline coverage: {len(by)} baselines; FedRAMP Moderate {fm['covered']}/{fm['controls']} controls ({fm['base']['covered']}/{fm['base']['total']} base, {fm['enhancement']['covered']}/{fm['enhancement']['total']} enhancements); label-is-800-53 == spine ({len(spine)} ids); {len(bimpl)} baseline control-implementations match; {summ['excluded_topic_rows']} topic rows excluded")
PY
fi
# schema validation of every catalog + the combined one + the two documents
out="$(python3 "$HERE/validate.py" $(ls "$TMP"/catalogs/*.json | grep -v index.json) "$TMP/all.json" "$TMP/component-definition.json" "$TMP/assessment-results.json" $(ls "$TMP"/profiles/*.json 2>/dev/null | grep -v index.json) 2>&1 | grep -v '^ok ' || true)"
if [[ "$out" == *SKIP* ]]; then echo "SKIP schema validation: jsonschema not installed"; exit 0; fi
if [[ "$out" == *FAIL* ]]; then printf '%s\n' "$out" | sed -n '1,20p'; exit 1; fi
echo "PASS schema: every catalog, the component-definition, the assessment-results and the profiles validate against OSCAL ${OSCAL_VERSION:-1.2.3}"
