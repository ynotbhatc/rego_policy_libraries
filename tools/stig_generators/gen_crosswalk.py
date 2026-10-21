#!/usr/bin/env python3
"""Merge STIG rule -> NIST SP 800-53 (Rev 5) entries into crosswalk/stig_800_53/data.json.

    python3 tools/stig_generators/gen_crosswalk.py <path/to/U_CCI_List.xml> <catalog key> ...

Join: stig_id -> CCI (XCCDF <ident>, carried in the catalog) -> 800-53 Rev 5 index (U_CCI_List.xml), control
id normalised to family-number (enhancements fold into their base control, as the existing map does).
Existing entries for other platforms are kept; entries for the given catalogs' prefixes are replaced.
"""
import datetime, json, os, re, sys
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
CATS = os.path.join(HERE, "catalogs")
DATA = os.path.join(HERE, "..", "..", "crosswalk", "stig_800_53", "data.json")
NS = {"c": "http://iase.disa.mil/cci"}
# provenance appended to meta.source when a platform is (re)joined from a newer compilation
SOURCE_NOTES = {
    "oracle_linux_9": "Oracle platforms from the October 2026 compilation",
    "kubernetes": "Kubernetes V2R6 and RGS RKE2 V2R7 from DISA's standalone STIG zips (2026-10-21)",
    "rke2": "Kubernetes V2R6 and RGS RKE2 V2R7 from DISA's standalone STIG zips (2026-10-21)",
}


def cci_map(path):
    root = ET.parse(path).getroot()
    out = {}
    for it in root.findall(".//c:cci_item", NS):
        refs = [r.get("index") for r in it.findall("c:references/c:reference", NS) if r.get("version") == "5"]
        ctls = sorted({m.group(1) for idx in refs for m in [re.match(r"([A-Z]{2}-\d+)", idx or "")] if m})
        out[it.get("id")] = ctls
    ver = root.find("c:metadata/c:version", NS)
    return out, (ver.text if ver is not None else "")


def main(cci_path, keys):
    ccis, cci_ver = cci_map(cci_path)
    data = json.load(open(DATA))
    for key in keys:
        cat = json.load(open(os.path.join(CATS, f"{key}.json")))
        # family prefix = the stig_id minus its number ("CNTR-K8", "CNTR-R2", "OL09"): CNTR-K8, CNTR-R2 and
        # CNTR-OS share the first segment, so splitting on the first "-" would wipe the other platforms.
        prefixes = sorted({r["stig_id"].rsplit("-", 1)[0] for r in cat["rules"]})
        prefix = prefixes[0]
        fresh = {}
        for r in cat["rules"]:
            ctls = sorted({c for cci in r["ccis"] for c in ccis.get(cci, [])})
            if ctls:
                fresh[r["stig_id"]] = ctls
        n = len(fresh)
        # replace this platform's entries in place (keeps the file's order, so a re-join diffs only real changes)
        merged = {}
        for k, v in data["map"].items():
            if k.rsplit("-", 1)[0] not in prefixes:
                merged[k] = v
            elif k in fresh:
                merged[k] = fresh.pop(k)
        merged.update(fresh)
        data["map"] = merged
        print(f"{key}: {n} of {len(cat['rules'])} rules mapped ({prefix}), {cat['benchmark'][:50]} {cat['version']}")
        data["meta"].setdefault("platforms", {})[prefix] = f"{cat['benchmark']} {cat['version']} ({cat['release_date']})"
    data["meta"]["rule_count"] = len(data["map"])
    data["meta"]["cci_list"] = cci_ver
    data["meta"]["generated"] = datetime.date.today().isoformat()
    for k in keys:
        note = SOURCE_NOTES.get(k)
        if note and note not in data["meta"]["source"]:
            data["meta"]["source"] += "; " + note
    data["meta"]["note"] = "Regenerate with tools/stig_generators/parse_xccdf.py + gen_crosswalk.py (per platform) from the current SRG-STIG Library compilation."
    open(DATA, "w").write(json.dumps(data, indent=0) + "\n")   # the file's existing layout: one key per line, no indent


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2:])
