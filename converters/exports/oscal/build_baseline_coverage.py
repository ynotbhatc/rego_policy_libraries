#!/usr/bin/env python3
"""Baseline coverage bridge: for each imported baseline profile (dist/profiles/<key>.json), which of the baseline's
NIST SP 800-53 Rev 5 controls does this library evaluate with at least one executable check, and which not.

Outputs (committed, deterministic)
  dist/profiles/coverage.csv           one row per (baseline, control id): kind, covered, check_count, checks, sources
  dist/profiles/coverage_summary.json  per baseline: totals, base / enhancement split, covered counts, percentages

Mapping (library check -> 800-53 control id) uses exactly three sources and nothing else. A check is written
`<framework>:<label>`, the label being the control id the catalogs keep in their `label` prop.
  stig-cci            crosswalk/stig_800_53/data.json maps a STIG rule id to 800-53 BASE controls (via CCI). Every stig_*
                      catalog control's label is that rule id. Base control only: the map cannot tell enhancements apart,
                      so this source never covers an enhancement.
  label-is-800-53     a library control whose label is itself an 800-53 id (`AC-2`, `AC-2(1)`, same rule and family list as
                      crosswalk_csv spine_800_53.csv `library_controls`): `AC-2` -> ac-2, `AC-2(1)` -> ac-2.1.
                      800-53 overlay catalogs (OVERLAY_CATALOGS, e.g. CMS MARS-E) are excluded: they restate the controls.
  nist-800-53-module  our own nist_sp_800_53 module, labels `NIST AC-2`, `NIST IA-2(1)`, `NIST SC-7/8` (= sc-7 and sc-8).
                      The `nist.sp800_53.access_control#N` rows are topic rows, not attributable to a control: excluded,
                      counted in the summary as excluded_topic_rows.
Out of scope: crosswalk/framework_maps has only the three 800-53B baseline maps authoritative (baseline membership, not
library mappings); the five framework maps (800-171 R3, CSF 2.0, ISO 27001, PCI DSS v4, CIS v8) are pending with no rows.

Covered: a base control is covered when any check maps to that exact id; an enhancement only when a check maps to that exact
enhancement id (source label-is-800-53 / nist-800-53-module with `(n)`). A base-control mapping never covers an enhancement.
Ids are OSCAL tokens as the NIST catalog writes them (ac-2, ac-2.1); an id containing a dot is an enhancement.

    python3 build_baseline_coverage.py [--out DIR] [--catalogs DIR] [--profiles DIR]
default: reads dist/catalogs and dist/profiles, writes dist/profiles/coverage.{csv,json}; --out DIR reads and writes
DIR/profiles; --catalogs defaults to dist/catalogs.
"""
from __future__ import annotations
import csv, json, re, sys, pathlib, argparse, collections

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(HERE))
from build import version_and_date  # noqa: E402
from build_profiles import SOURCES, CATALOG, with_ids  # noqa: E402

FAMILIES = "AC|AT|AU|CA|CM|CP|IA|IR|MA|MP|PE|PL|PM|PS|PT|RA|SA|SC|SI|SR"  # same list as crosswalk_csv/build.py
ID_800_53 = re.compile(rf"^(?:{FAMILIES})-[1-9]\d*(\([1-9]\d*\))?$")  # no leading zeros: BSI C5 "PS-01" is not 800-53 PS-1
# 800-53 overlay catalogs restate 800-53 controls under the same ids; their rows say nothing about what the library checks
OVERLAY_CATALOGS = {"cms_mars_e"}
NIST_MODULE = re.compile(rf"^NIST ((?:{FAMILIES}))-(\d+(?:/\d+)*)(?:\((\d+)\))?$")
TOPIC_ROW = re.compile(r"^nist\.sp800_53\.[a-z_]+#\d+$")
HEADER = ["baseline_key", "control_id", "kind", "covered", "check_count", "checks", "sources"]


def oscal_id(label):
    """AC-2 -> ac-2, AC-2(1) -> ac-2.1"""
    m = re.match(r"^([A-Z]{2})-(\d+)(?:\((\d+)\))?$", label)
    return f"{m.group(1).lower()}-{m.group(2)}" + (f".{m.group(3)}" if m.group(3) else "")


def kind(cid):
    return "enhancement" if "." in cid else "base"


def catalog_controls(cat_dir):
    """[(framework, label)] for every control of every catalog, in catalog order."""
    out = []
    for row in json.loads((cat_dir / "index.json").read_text())["catalogs"]:
        fw = row["framework"]
        for g in json.loads((cat_dir / f"{fw}.json").read_text())["catalog"]["groups"]:
            for c in g["controls"]:
                out.append((fw, next(p["value"] for p in c["props"] if p["name"] == "label")))
    return out


def build_mapping(cat_dir):
    """Returns ({nist id: {check: {sources}}}, stats). check = '<framework>:<label>'."""
    stig = json.loads((ROOT / "crosswalk" / "stig_800_53" / "data.json").read_text())["map"]
    mp = collections.defaultdict(lambda: collections.defaultdict(set))
    stats = collections.Counter()
    seen_rules = set()
    for fw, label in catalog_controls(cat_dir):
        check = f"{fw}:{label}"
        if fw.startswith("stig_"):
            stats["stig_catalog_controls"] += 1
            if label in stig:
                seen_rules.add(label)
                stats["stig_controls_mapped"] += 1
                for base in stig[label]:
                    assert ID_800_53.match(base) and "(" not in base, f"STIG map value {base!r} is not a base control"
                    mp[oscal_id(base)][check].add("stig-cci")
            else:
                stats["stig_catalog_controls_not_in_map"] += 1
        if ID_800_53.match(label) and fw not in OVERLAY_CATALOGS:
            mp[oscal_id(label)][check].add("label-is-800-53")
            stats["label_is_800_53_controls"] += 1
        if fw == "nist_sp_800_53":
            m = NIST_MODULE.match(label)
            if m:
                stats["nist_module_controls_mapped"] += 1
                enh = f".{m.group(3)}" if m.group(3) else ""
                for n in m.group(2).split("/"):
                    mp[f"{m.group(1).lower()}-{n}{enh}"][check].add("nist-800-53-module")
            else:
                assert TOPIC_ROW.match(label), f"nist_sp_800_53 label {label!r} is neither a control nor a topic row"
                stats["excluded_topic_rows"] += 1
    stats["stig_map_rules"] = len(stig)
    stats["stig_map_rules_without_catalog_control"] = len(set(stig) - seen_rules)
    return mp, stats


def load_coverage(prof_dir):
    """(summary doc, {baseline key: [csv row dicts of covered controls, in with-ids order]}) from a written coverage set,
    or None when the set is absent."""
    prof_dir = pathlib.Path(prof_dir)
    if not (prof_dir / "coverage.csv").exists() or not (prof_dir / "coverage_summary.json").exists():
        return None
    covered = collections.defaultdict(list)
    with (prof_dir / "coverage.csv").open(newline="") as f:
        for r in csv.DictReader(f):
            if r["covered"] == "yes":
                covered[r["baseline_key"]].append(r)
    return json.loads((prof_dir / "coverage_summary.json").read_text()), covered


def pct(a, b):
    return round(100.0 * a / b, 1) if b else 0.0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=None, help="output root (profiles are read from and written to OUT/profiles)")
    ap.add_argument("--catalogs", default=None); ap.add_argument("--profiles", default=None)
    a = ap.parse_args()
    version, stamp = version_and_date()
    cat_dir = pathlib.Path(a.catalogs) if a.catalogs else HERE / "dist" / "catalogs"
    prof_dir = pathlib.Path(a.profiles) if a.profiles else (pathlib.Path(a.out) / "profiles" if a.out else HERE / "dist" / "profiles")
    out_dir = pathlib.Path(a.out) / "profiles" if a.out else prof_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    mp, stats = build_mapping(cat_dir)

    rows, summary = [], {}
    for row in json.loads((prof_dir / "index.json").read_text())["profiles"]:
        key = row["key"]
        ids = with_ids(json.loads((prof_dir / row["file"].split("/", 1)[1]).read_text())["profile"])
        t = {"base": 0, "enhancement": 0}; c = {"base": 0, "enhancement": 0}
        for cid in ids:
            k, checks = kind(cid), mp.get(cid, {})
            t[k] += 1
            if checks:
                c[k] += 1
            rows.append([key, cid, k, "yes" if checks else "no", len(checks), ";".join(sorted(checks)),
                         ";".join(sorted({s for v in checks.values() for s in v}))])
        n, cov = t["base"] + t["enhancement"], c["base"] + c["enhancement"]
        title = next(s["title"] for s in SOURCES if s["key"] == key)
        summary[key] = {"title": title, "controls": n, "covered": cov, "covered_pct": pct(cov, n),
                        "base": {"total": t["base"], "covered": c["base"], "covered_pct": pct(c["base"], t["base"])},
                        "enhancement": {"total": t["enhancement"], "covered": c["enhancement"], "covered_pct": pct(c["enhancement"], t["enhancement"])}}
    rows.sort(key=lambda r: r[0])  # stable: keeps with-ids (catalog) order inside a baseline
    with (out_dir / "coverage.csv").open("w", newline="") as f:
        w = csv.writer(f, lineterminator="\n"); w.writerow(HEADER); w.writerows(rows)
    doc = {"generated-from": {"library-version": version, "last-modified": stamp, "nist-catalog-commit": CATALOG["commit"],
                              "generator": "converters/exports/oscal/build_baseline_coverage.py"},
           "mapping-sources": ["stig-cci", "label-is-800-53", "nist-800-53-module"],
           "granularity-note": "stig-cci maps to base controls only; an enhancement counts as covered only on an exact enhancement mapping",
           "excluded_topic_rows": stats["excluded_topic_rows"],
           "mapping": {k: stats[k] for k in sorted(stats) if k != "excluded_topic_rows"} | {"nist_ids_with_a_check": len(mp)},
           "baselines": {k: summary[k] for k in sorted(summary)}}
    (out_dir / "coverage_summary.json").write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n")
    s = summary["fedramp_rev5_moderate"]
    print(f"oscal baseline coverage: {len(summary)} baselines; e.g. FedRAMP Moderate {s['covered']}/{s['controls']} controls "
          f"({s['base']['covered']}/{s['base']['total']} base, {s['enhancement']['covered']}/{s['enhancement']['total']} enhancements) "
          f"-> {out_dir / 'coverage.csv'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
