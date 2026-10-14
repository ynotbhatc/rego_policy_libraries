#!/usr/bin/env python3
"""Crosswalk CSVs for GRC platforms (Vanta, Drata, Secureframe, Hyperproof, ServiceNow IRM) and spreadsheets.

Four files under dist/ (committed; deterministic):

  controls.csv            every inventory control, one row each: framework, control id, OSCAL id, statement,
                          class, source, domains, Rego package, Rego file. The "control set" import.
  stig_to_800_53.csv      DISA STIG rule id -> NIST SP 800-53 controls (crosswalk/stig_800_53/data.json), one row
                          per STIG rule with the platform prefix split out.
  framework_to_800_53.csv framework control id -> 800-53 controls for every map in crosswalk/framework_maps
                          (status column says authoritative or pending; pending maps have no rows yet).
  spine_800_53.csv        the SCF-style pivot: one row per 800-53 control, one column per mapped source
                          (Low/Moderate/High baseline membership, STIG rules per platform, library controls whose
                          id is that 800-53 control), so a GRC tool can see what evidence lands on each control.

Nothing is invented: a cell is empty when no map says otherwise.
"""
from __future__ import annotations
import csv, json, re, sys, pathlib, argparse, collections

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(HERE.parent))
from inventory_controls import inventory  # noqa: E402
from _lib.findings import token          # noqa: E402

FAMILIES = "AC|AT|AU|CA|CM|CP|IA|IR|MA|MP|PE|PL|PM|PS|PT|RA|SA|SC|SI|SR"  # SP 800-53 Rev 5 families
ID_800_53 = re.compile(rf"^(?:{FAMILIES})-[1-9]\d*(\([1-9]\d*\))?$")  # no leading zeros: BSI C5 "PS-01" is not 800-53 PS-1


def write(path, header, rows):
    with path.open("w", newline="") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(header)
        w.writerows(rows)
    return len(rows)


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--out", default=None); a = ap.parse_args()
    out = pathlib.Path(a.out) if a.out else HERE / "dist"
    out.mkdir(parents=True, exist_ok=True)
    inv = inventory(ROOT)
    n = {}

    # 1. controls.csv
    rows = []
    for e in sorted(inv, key=lambda x: (x["framework"], x["file"])):
        fw_tok = token(e["framework"])
        for c in e["controls"]:
            if c["id"].startswith(e["package"] + "#"):
                oscal_id = token(f"{fw_tok}-{e['package']}-{c['id'].split('#')[1]}")
            else:
                oscal_id = token(f"{fw_tok}-{c['id']}")
            text = next((t for t in c["texts"] if t), "")
            rows.append([e["framework"], c["id"], oscal_id, text, e["class"], e["source"], " ".join(e["domains"]), e["package"], e["file"]])
    n["controls.csv"] = write(out / "controls.csv", ["framework", "control_id", "oscal_control_id", "statement", "class", "source", "domains", "rego_package", "rego_file"], rows)

    # 2. stig_to_800_53.csv
    stig = json.loads((ROOT / "crosswalk" / "stig_800_53" / "data.json").read_text())
    src = stig["meta"].get("source", "")
    rows = [[sid, sid.split("-")[0], ";".join(ctls), len(ctls), src] for sid, ctls in sorted(stig["map"].items())]
    n["stig_to_800_53.csv"] = write(out / "stig_to_800_53.csv", ["stig_rule_id", "platform_prefix", "nist_800_53", "control_count", "source"], rows)

    # 3. framework_to_800_53.csv
    fm = json.loads((ROOT / "crosswalk" / "framework_maps" / "data.json").read_text())["maps"]
    rows = []
    for name, m in sorted(fm.items()):
        for cid, ctls in sorted(m.get("map", {}).items()):
            rows.append([name, m.get("name", name), m.get("status", ""), cid, ";".join(ctls), m.get("granularity", ""), m.get("source", "")])
    n["framework_to_800_53.csv"] = write(out / "framework_to_800_53.csv", ["map", "map_name", "status", "framework_control_id", "nist_800_53", "granularity", "source"], rows)
    pending = sorted(k for k, m in fm.items() if m.get("status") != "authoritative")

    # 4. spine_800_53.csv
    spine = collections.defaultdict(lambda: {"low": "", "moderate": "", "high": "", "stig": collections.defaultdict(list), "lib": []})
    for name, key in (("nist_800_53b_low", "low"), ("nist_800_53b_moderate", "moderate"), ("nist_800_53b_high", "high")):
        for cid in fm.get(name, {}).get("map", {}):
            spine[cid][key] = "yes"
    for sid, ctls in stig["map"].items():
        for c in ctls:
            spine[c]["stig"][sid.split("-")[0]].append(sid)
    for e in inv:
        for c in e["controls"]:
            if ID_800_53.match(c["id"]):  # only ids in a real 800-53 family (CJIS "AA-1" is not one)
                spine[c["id"]]["lib"].append(f"{e['framework']}:{c['id']}")
    for cid in [k for k in spine if not ID_800_53.match(k)]:
        del spine[cid]
    platforms = sorted({p for s in spine.values() for p in s["stig"]})
    rows = []
    def sortkey(cid):
        m = re.match(r"([A-Z]{2})-(\d+)(?:\((\d+)\))?", cid)
        return (m.group(1), int(m.group(2)), int(m.group(3) or 0)) if m else (cid, 0, 0)
    for cid in sorted(spine, key=sortkey):
        s = spine[cid]
        rows.append([cid, s["low"], s["moderate"], s["high"], sum(len(v) for v in s["stig"].values()), ";".join(sorted(s["lib"]))]
                    + [";".join(sorted(s["stig"].get(p, []))) for p in platforms])
    n["spine_800_53.csv"] = write(out / "spine_800_53.csv", ["nist_800_53", "baseline_low", "baseline_moderate", "baseline_high", "stig_rule_count", "library_controls"] + [f"stig_{p}" for p in platforms], rows)

    (out / "index.json").write_text(json.dumps({"files": n, "stig_platforms": platforms, "pending_maps": pending,
                                                "note": "pending maps are listed in framework_to_800_53.csv with status=pending and no rows; nothing is invented"}, indent=1) + "\n")
    print("crosswalk_csv: " + ", ".join(f"{k} {v} rows" for k, v in n.items()) + f"; {len(platforms)} STIG platforms; pending maps: {len(pending)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
