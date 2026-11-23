#!/usr/bin/env python3
"""Generate the FedRAMP Rev 5 entries of crosswalk/framework_maps/data.json.

FedRAMP's baselines select NIST SP 800-53 Rev 5 controls under the catalog's own ids, so each map is the identity:
FedRAMP control id -> [the same 800-53 id], for exactly the ids the baseline's OSCAL profile selects (controls and
enhancements; ac-2.1 is written AC-2(1), as the framework modules write ids). Nothing is added, dropped or mapped
to a different control.

Source: converters/exports/oscal/dist/profiles/fedramp_rev5_<level>.json (committed; built by
converters/exports/oscal/build_profiles.py from the FedRAMP OSCAL baseline profiles at a pinned commit, each
verified against a pinned sha256). Each map's `source` cites the pinned URL, commit and sha256 recorded in that
profile. No network access.

Only the fedramp_rev5_* entries are written; every other entry of data.json is left as it is. Deterministic.
    python3 scripts/gen_fedramp_framework_maps.py            # write
    python3 scripts/gen_fedramp_framework_maps.py --check    # exit 1 if the committed file is stale
"""
import json, pathlib, re, sys
ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "crosswalk/framework_maps/data.json"
PROFILES = ROOT / "converters/exports/oscal/dist/profiles"
LEVELS = ["low", "moderate", "high", "li_saas"]
NS_PROPS = ("source-url", "source-commit", "source-sha256", "source-title")
ID = re.compile(r"^([a-z]{2})-(\d+)(?:\.(\d+))?$")
GENERATOR = "scripts/gen_fedramp_framework_maps.py"


def to_id(oscal):
    m = ID.match(oscal)
    assert m, oscal
    return f"{m[1].upper()}-{m[2]}" + (f"({m[3]})" if m[3] else "")


def sort_key(i):
    m = re.match(r"^([A-Z]{2})-(\d+)(?:\((\d+)\))?$", i)
    return (m[1], int(m[2]), int(m[3] or 0))


def entry(level):
    key = f"fedramp_rev5_{level}"
    p = json.loads((PROFILES / f"{key}.json").read_text())["profile"]
    props = {x["name"]: x["value"] for x in p["metadata"]["props"]}
    missing = [n for n in NS_PROPS if not props.get(n)]
    if missing:
        raise SystemExit(f"{key}: profile metadata lacks {missing}; rebuild it with converters/exports/oscal/build_profiles.py")
    ids = [to_id(i) for imp in p["imports"] for inc in imp.get("include-controls", []) for i in inc["with-ids"]]
    if not ids or len(ids) != len(set(ids)):
        raise SystemExit(f"{key}: profile selects no controls or repeats one")
    ids.sort(key=sort_key)
    base = sum(1 for i in ids if "(" not in i)
    return key, {
        "name": f"{props['source-title']} ({len(ids)} controls: {base} base controls, {len(ids) - base} enhancements)",
        "source": (f"FedRAMP OSCAL baseline profile \"{props['source-title']}\" (FedRAMP PMO, fedramp-automation "
                   f"dist/content/rev5/baselines/json): {props['source-url']} (commit {props['source-commit']}, sha256 "
                   f"{props['source-sha256']}), as selected in converters/exports/oscal/dist/profiles/{key}.json"),
        "status": "authoritative",
        "granularity": ("identity: each control or enhancement the baseline selects maps to the same NIST SP 800-53 Rev 5 "
                        "id. The STIG -> 800-53 spine is at base-control granularity, so an enhancement never gets a "
                        "verdict through it"),
        "generated_by": GENERATOR,
        "map": {i: [i] for i in ids},
    }


def build():
    doc = json.loads(OUT.read_text())
    maps = {k: v for k, v in doc["maps"].items() if not k.startswith("fedramp_rev5_")}
    out = {}
    for k, v in maps.items():
        out[k] = v
        if k == "nist_800_53b_high":  # the FedRAMP baselines sit after the 800-53B baselines they derive from
            out.update(entry(level) for level in LEVELS)
    if not any(k.startswith("fedramp_rev5_") for k in out):
        out.update(entry(level) for level in LEVELS)
    doc["maps"] = out
    return json.dumps(doc, indent=0)


if __name__ == "__main__":
    text = build()
    if "--check" in sys.argv:
        sys.exit(0 if OUT.read_text() == text else f"{OUT.relative_to(ROOT)} is stale: run {GENERATOR}")
    OUT.write_text(text)
    print(f"wrote {OUT.relative_to(ROOT)}")
