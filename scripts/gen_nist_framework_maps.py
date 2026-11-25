#!/usr/bin/env python3
"""Generate the NIST-published entries of crosswalk/framework_maps/data.json: download -> verify -> parse -> write.

Maps written (each `<framework id> -> [NIST SP 800-53 Rev 5 ids]`, ids as the library writes them: AC-2(3)):

  nist_csf_2_0      CSF 2.0 Subcategory -> 800-53 Rev 5.2.0, from NIST's OLIR informative reference 186 (xlsx).
  nist_800_171_r3   SP 800-171 Rev 3 requirement -> its source controls, from NIST's CPRT export of SP 800-171r3 (JSON).
  iso_27001_2022    ISO/IEC 27001:2022 clause / Annex A control -> 800-53 Rev 5, from NIST's own mapping (OLIR
                    informative reference 155, xlsx). The file maps 800-53 -> ISO; it is inverted here. It carries
                    ISO identifiers only, no ISO text.

and `catalog_800_53` (top level of data.json): every control and enhancement id of the NIST SP 800-53 Rev 5.2.0
OSCAL catalog, active and withdrawn, so a mapped id can be checked against the catalog. Every mapped id must be an
active catalog id or the build stops.

All four sources are works of NIST (US government, not subject to copyright in the United States). Each is fetched
from a pinned URL and verified against a pinned sha256; a source that no longer matches stops the build, so a change
upstream is reviewed, never taken silently. Downloads are cached outside the repository (default
~/.cache/rego_policy_libraries/framework_maps, or --cache DIR).

NOT written to the shipped file:

  cis_controls_v8   CIS publishes "CIS Controls v8.1 Mapping to NIST SP 800-53 Rev 5" under CC BY-NC-ND 4.0
                    (NonCommercial, NoDerivatives). An id map extracted from it is a derivative and this repository
                    is Apache-2.0, so the map is not vendored. Download the workbook yourself and build a local copy:
                        python3 scripts/gen_nist_framework_maps.py --cis-file <workbook.xlsx> --out <dir>/data.json
                    then load that file at data.crosswalk.framework_maps in place of the shipped one. --out may not
                    be a path inside this repository.
  pci_dss_v4        no source whose licence allows it; stays pending (see the entry's `source`).

Only the keys above are written; every other entry of data.json is left as it is. Deterministic.
    python3 scripts/gen_nist_framework_maps.py            # fetch (or reuse the cache), verify, write
    python3 scripts/gen_nist_framework_maps.py --check    # offline: exit 1 if a generated map was edited by hand
                                                          # (map_sha256), and, when the verified sources are in
                                                          # the cache, if the committed file is not what they build
"""
from __future__ import annotations
import argparse, hashlib, html, json, os, pathlib, re, sys, urllib.request, zipfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "crosswalk/framework_maps/data.json"
GENERATOR = "scripts/gen_nist_framework_maps.py"
DEFAULT_CACHE = pathlib.Path(os.environ.get("XDG_CACHE_HOME", pathlib.Path.home() / ".cache")) / "rego_policy_libraries/framework_maps"
UA = "Mozilla/5.0 (rego_policy_libraries framework-map generator)"
NIST_LICENCE = "Work of the US government (NIST); not subject to copyright in the United States (17 U.S.C. 105)"
VERIFIED = "2026-11-24"  # the day the pins below were fetched and checked

# The catalog pin is the one converters/exports/oscal/build_profiles.py uses for the baseline profiles.
SOURCES = {
    "catalog": {
        "url": "https://raw.githubusercontent.com/usnistgov/oscal-content/78650f02ad9321bb7b817846f8fbd4f2bcd620de/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json",
        "sha256": "01f37cf90ea99d92242c936cbfbdebcc338eef1f71454e2acac36cc56e9bc062",
        "file": "NIST_SP-800-53_rev5_catalog.json",
        "title": "NIST SP 800-53 Rev 5.2.0 OSCAL catalog (usnistgov/oscal-content, commit 78650f02ad9321bb7b817846f8fbd4f2bcd620de)",
        "published": "2026-05-11",  # catalog metadata last-modified; checked against the file on every build
    },
    "nist_csf_2_0": {
        "url": "https://csrc.nist.gov/csrc/media/projects/olir/documents/submissions/Cybersecurity_Framework_v2-0_Concept_Crosswalk_800-53_5_2_0_draft.xlsx",
        "sha256": "5521fa73ace64d8a3014a7b1e971f0f20d32df5ff5e174632723bda09e7e908f",
        "file": "Cybersecurity_Framework_v2-0_Concept_Crosswalk_800-53_5_2_0_draft.xlsx",
        "title": "Cybersecurity-Framework-v2.0-to-SP-800-53-Rev-5-2-0, version 1.0.0 (NIST OLIR informative reference 186, status Final, developer NIST)",
        "published": "2025-11-17",  # OLIR catalog posted date
        "catalog_page": "https://csrc.nist.gov/projects/olir/informative-reference-catalog/details?referenceId=186",
    },
    "nist_800_171_r3": {
        "url": "https://csrc.nist.gov/extensions/nudp/services/json/nudp/framework/version/sp_800_171_3_0_0/export/json?element=all",
        "sha256": "19d18ef88700e468f273a4bb0a00e76f1dab762f5639e5de75592fda4e61c4fa",
        "file": "cprt-sp_800_171_3_0_0.json",
        "title": "NIST SP 800-171 Rev 3 (version 3.0.0), Cybersecurity and Privacy Reference Tool (CPRT) JSON export, external_reference relationships to SP 800-53 Rev 5.1.1",
        "published": "2024-05",  # SP 800-171 Rev 3 date published (csrc.nist.gov/pubs/sp/800/171/r3/final)
        "catalog_page": "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_171_3_0_0/home",
    },
    "iso_27001_2022": {
        "url": "https://csrc.nist.gov/csrc/media/Projects/olir/documents/submissions/sp800-53r5-to-iso-27001-mapping-2022-OLIR-2023-10-12-UPDATED.xlsx",
        "sha256": "e631de234a1fac057991773f015c221226940540f5602e1b70a3768eaff5cbd9",
        "file": "sp800-53r5-to-iso-27001-mapping-2022-OLIR-2023-10-12-UPDATED.xlsx",
        "title": "800-53-Rev5-to-ISO 27001-2022, version 1.0.0 (NIST OLIR informative reference 155, status Final, developer NIST)",
        "published": "2023-11-13",  # OLIR catalog posted date
        "catalog_page": "https://csrc.nist.gov/projects/olir/informative-reference-catalog/details?referenceId=155",
    },
}
CIS_PAGE = "https://www.cisecurity.org/insights/white-papers/cis-controls-v8-1-mapping-to-nist-sp-800-53-rev-5"
CIS_LICENCE = ("Creative Commons Attribution-NonCommercial-NoDerivatives 4.0 International (CC BY-NC-ND 4.0), as stated on "
               "the workbook's 'License for Use' sheet: redistribution for non-commercial purposes only, and modified "
               "material may not be distributed")
GENERATED_KEYS = ("nist_csf_2_0", "nist_800_171_r3", "iso_27001_2022")
FAMILIES = "AC|AT|AU|CA|CM|CP|IA|IR|MA|MP|PE|PL|PM|PS|PT|RA|SA|SC|SI|SR"
ID_PADDED = re.compile(rf"^({FAMILIES})-(\d+)(?:\((\d+)\))?$")


class Stop(SystemExit):
    pass


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def fetch(key, cache, offline=False):
    """The verified bytes of a pinned source, from the cache or the network; None when offline and not cached."""
    src = SOURCES[key]
    p = pathlib.Path(cache) / src["file"]
    if p.exists() and sha256(p.read_bytes()) == src["sha256"]:
        return p.read_bytes()
    if offline:
        return None
    req = urllib.request.Request(src["url"], headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            b = r.read()
    except Exception as e:  # noqa: BLE001
        raise Stop(f"{key}: could not fetch {src['url']}: {e}")
    if sha256(b) != src["sha256"]:
        raise Stop(f"{key}: {src['url']} no longer matches the pinned sha256 (got {sha256(b)}, pinned {src['sha256']}). "
                   f"The source changed upstream: review it, then update the pin in {GENERATOR}.")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(b)
    return b


# ---- xlsx without third-party packages: {sheet name: [ {column letter: text} per row ]}
def xlsx_sheets(path_or_bytes):
    import io
    z = zipfile.ZipFile(io.BytesIO(path_or_bytes) if isinstance(path_or_bytes, bytes) else path_or_bytes)
    shared = []
    if "xl/sharedStrings.xml" in z.namelist():
        for si in re.findall(r"<si>(.*?)</si>", z.read("xl/sharedStrings.xml").decode("utf-8"), re.S):
            shared.append(html.unescape("".join(re.findall(r"<t[^>]*>(.*?)</t>", si, re.S))))
    rels = {}
    for tag in re.findall(r"<Relationship [^>]*>", z.read("xl/_rels/workbook.xml.rels").decode("utf-8")):
        rels[re.search(r'Id="([^"]+)"', tag)[1]] = re.search(r'Target="([^"]+)"', tag)[1]
    out = {}
    for tag in re.findall(r"<sheet [^>]*>", z.read("xl/workbook.xml").decode("utf-8")):
        name = html.unescape(re.search(r'name="([^"]+)"', tag)[1])
        target = rels[re.search(r'r:id="([^"]+)"', tag)[1]].lstrip("/")
        xml = z.read(target if target.startswith("xl/") else "xl/" + target).decode("utf-8")
        rows = []
        for row in re.findall(r"<row[^>]*>(.*?)</row>", xml, re.S):
            cells = {}
            for col, attrs, body in re.findall(r'<c r="([A-Z]+)\d+"([^>]*?)(?:/>|>(.*?)</c>)', row, re.S):
                v = re.search(r"<v>(.*?)</v>", body or "", re.S)
                t = re.search(r"<t[^>]*>(.*?)</t>", body or "", re.S)
                if 't="s"' in attrs and v:
                    cells[col] = shared[int(v[1])]
                elif t:
                    cells[col] = html.unescape(t[1])
                elif v:
                    cells[col] = html.unescape(v[1])
            rows.append(cells)
        out[name] = rows
    return out


def unpad(i, where):
    """AC-02(03) -> AC-2(3)."""
    m = ID_PADDED.match(i.strip())
    if not m:
        raise Stop(f"{where}: {i!r} is not an SP 800-53 control id")
    return f"{m[1]}-{int(m[2])}" + (f"({int(m[3])})" if m[3] else "")


def ctl_key(i):
    m = ID_PADDED.match(i)
    return (m[1], int(m[2]), int(m[3] or 0))


def dotted_key(i):
    return [(0, int(p)) if p.isdigit() else (1, p) for p in re.split(r"[.\-]", i)]


# ---- the catalog
def parse_catalog(b):
    cat = json.loads(b)["catalog"]
    active, withdrawn = [], []

    def to_id(o):
        m = re.match(r"^([a-z]{2})-(\d+)(?:\.(\d+))?$", o)
        if not m:
            raise Stop(f"catalog: unexpected control id {o!r}")
        return f"{m[1].upper()}-{m[2]}" + (f"({m[3]})" if m[3] else "")

    def walk(node):
        for c in node.get("controls", []):
            gone = any(p["name"] == "status" and p["value"] == "withdrawn" for p in c.get("props", []))
            (withdrawn if gone else active).append(to_id(c["id"]))
            walk(c)

    for g in cat["groups"]:
        walk(g)
    src = SOURCES["catalog"]
    if cat["metadata"]["version"] != "5.2.0" or not cat["metadata"]["last-modified"].startswith(src["published"]):
        raise Stop("catalog: version or last-modified is not what the pin records")
    active.sort(key=ctl_key)
    withdrawn.sort(key=ctl_key)
    return {
        "name": f"NIST SP 800-53 Rev 5.2.0 control and enhancement ids ({len(active)} active, {len(withdrawn)} withdrawn)",
        "source": f"{src['title']}: {src['url']} (sha256 {src['sha256']})",
        "meta": meta_block("catalog", {"active": len(active), "withdrawn": len(withdrawn),
                                       "base_controls_active": sum(1 for i in active if "(" not in i)}),
        "generated_by": GENERATOR,
        "active": active,
        "withdrawn": withdrawn,
    }


def meta_block(key, counts, extra=None):
    src = SOURCES[key]
    m = {"publisher": "National Institute of Standards and Technology (NIST)", "source_title": src["title"],
         "source_url": src["url"], "source_sha256": src["sha256"], "publication_date": src["published"],
         "verified": VERIFIED, "licence": NIST_LICENCE}
    if src.get("catalog_page"):
        m["catalog_page"] = src["catalog_page"]
    m.update(extra or {})
    m["counts"] = counts
    return m


def check_ids(key, fmap, catalog):
    """Every mapped id must be in the catalog. A reference to a control the catalog marks withdrawn is not carried
    (it can never be assessed) and is listed in meta; it is not redirected to the control that replaced it, because
    the source does not say that. An id the catalog does not know stops the build."""
    active, withdrawn = set(catalog["active"]), set(catalog["withdrawn"])
    unknown = sorted({c for v in fmap.values() for c in v if c not in active and c not in withdrawn})
    if unknown:
        raise Stop(f"{key}: mapped ids that are not in the 800-53 Rev 5.2.0 catalog: {', '.join(unknown)}")
    dropped = sorted(f"{k} -> {c}" for k, v in fmap.items() for c in v if c in withdrawn)
    kept = {k: [c for c in v if c in active] for k, v in fmap.items()}
    empty = sorted(k for k, v in kept.items() if not v)
    if empty:
        raise Stop(f"{key}: framework ids left with no active control: {empty}")
    return kept, dropped


def finish(key, name, source, granularity, fmap, counts, extra, catalog):
    fmap, dropped = check_ids(key, fmap, catalog)
    fmap = {k: sorted(set(v), key=ctl_key) for k, v in sorted(fmap.items(), key=lambda kv: dotted_key(kv[0]))}
    ids = {c for v in fmap.values() for c in v}
    counts = dict(counts, framework_ids=len(fmap), pairs=sum(len(v) for v in fmap.values()), distinct_800_53_ids=len(ids),
                  distinct_800_53_base_controls=len({c.split("(")[0] for c in ids}),
                  framework_ids_with_a_base_control=sum(1 for v in fmap.values() if any("(" not in c for c in v)),
                  references_to_withdrawn_controls_not_carried=len(dropped))
    meta = meta_block(key, counts, dict(extra or {}, withdrawn_references_not_carried=dropped))
    meta["map_sha256"] = map_sha(fmap)
    return {"name": name, "source": source, "status": "authoritative", "granularity": granularity,
            "generated_by": GENERATOR, "meta": meta, "map": fmap}


def map_sha(fmap):
    return sha256(json.dumps(fmap, sort_keys=True, separators=(",", ":")).encode())


SPINE_NOTE = ("The STIG -> 800-53 spine is at base-control granularity, so a mapped enhancement never gets a verdict "
              "through it and a framework id that maps to one is never 'satisfied' on benchmark results alone")


# ---- CSF 2.0
def build_csf(b, catalog):
    key = "nist_csf_2_0"
    rows = xlsx_sheets(b)["Relationships"]
    if [rows[0].get(c, "").split()[0] for c in "AC"] != ["Focal", "Reference"]:
        raise Stop(f"{key}: unexpected header row")
    fmap, subs, skipped = {}, set(), []
    for r in rows[1:]:
        a, c = r.get("A", "").strip(), r.get("C", "").strip()
        if re.fullmatch(r"(GV|ID|PR|DE|RS|RC)\.[A-Z]{2}-\d\d", a):
            subs.add(a)
            if re.fullmatch(FAMILIES, c):  # a reference to a whole 800-53 family; a family is not a control
                skipped.append(f"{a} -> {c} (family)")
            elif c:
                fmap.setdefault(a, []).append(unpad(c, f"{key} {a}"))
        elif re.fullmatch(r"(GV|ID|PR|DE|RS|RC)(\.[A-Z]{2})?", a):
            if c:  # Function and Category rows: not a Subcategory, and NIST maps them to whole families
                skipped.append(f"{a} -> {c} (Category row)")
        elif a:
            raise Stop(f"{key}: unexpected focal element {a!r}")
    if subs - set(fmap):
        raise Stop(f"{key}: Subcategories without a reference: {sorted(subs - set(fmap))}")
    src = SOURCES[key]
    return finish(
        key, f"NIST Cybersecurity Framework 2.0 Subcategory -> NIST SP 800-53 Rev 5.2.0 ({len(fmap)} Subcategories)",
        f"NIST OLIR informative reference 186, \"{src['title']}\": {src['url']} (sha256 {src['sha256']}, posted {src['published']})",
        "CSF Subcategory -> the 800-53 controls and enhancements NIST lists for it. " + SPINE_NOTE,
        fmap, {"subcategories_in_source": len(subs), "family_or_category_rows_not_carried": len(skipped)},
        {"relationship": ("NIST informative reference (concept crosswalk): the listed controls relate to the Subcategory's "
                          "outcome. NIST states no relationship type or strength in this file, and it is not a claim that "
                          "the controls together achieve the outcome"),
         "not_carried": skipped,
         "olir_hash_note": ("the OLIR catalog records sha256 fd71716b33adb4323e0e493e19501f6413489fb533f9b741e8a462145385fcf2 "
                            "for this reference; the file NIST serves at source_url has source_sha256. Its "
                            "Subcategory rows were checked equal to the 'SP 800-53 Rev 5.2.0' references in "
                            "NIST's CSF 2.0 Reference Tool export on the verified date")},
        catalog)


# ---- SP 800-171 Rev 3
def build_171(b, catalog):
    key = "nist_800_171_r3"
    el = json.loads(b)["response"]["elements"]
    doc = el["documents"][0]
    if doc["doc_identifier"] != "SP_800_171_3_0_0" or doc["version"] != "3.0.0":
        raise Stop(f"{key}: not the SP 800-171 Rev 3 (3.0.0) export")
    reqs = {e["element_identifier"] for e in el["elements"] if e["element_type"] == "requirement"}
    # a withdrawn requirement has a withdraw_reason element WR-<id> ("Incorporated into ..." / "Addressed by ...")
    withdrawn = {e["element_identifier"][3:] for e in el["elements"] if e["element_type"] == "withdraw_reason"}
    if not withdrawn <= reqs:
        raise Stop(f"{key}: a withdraw reason names something that is not a requirement")
    fmap = {}
    for r in el["relationships"]:
        if r["relationship_identifier"] != "external_reference":
            continue
        if r["dest_doc_identifier"] != "SP_800_53_5_1_1" or r["source_element_identifier"] not in reqs:
            raise Stop(f"{key}: unexpected external reference {r}")
        s = r["source_element_identifier"]
        fmap.setdefault(s, []).append(unpad(r["dest_element_identifier"], f"{key} {s}"))
    if not all(re.fullmatch(r"03\.\d\d\.\d\d", k) for k in reqs):
        raise Stop(f"{key}: unexpected requirement id")
    if set(fmap) & withdrawn or (reqs - withdrawn) != set(fmap):
        raise Stop(f"{key}: the requirements with source controls are not exactly the requirements that are not withdrawn")
    src = SOURCES[key]
    return finish(
        key, f"NIST SP 800-171 Rev 3 security requirement -> source NIST SP 800-53 Rev 5 controls ({len(fmap)} requirements)",
        f"NIST CPRT export of SP 800-171 Rev 3: {src['url']} (sha256 {src['sha256']}); the export's external_reference "
        f"relationships to SP 800-53 Rev 5.1.1 are the requirement's source controls",
        "171 requirement (03.FF.NN) -> the 800-53 controls and enhancements NIST gives as its source controls. " + SPINE_NOTE,
        fmap, {"requirements_in_source": len(reqs), "requirements_withdrawn_not_carried": len(withdrawn)},
        {"relationship": ("source controls: the SP 800-53 Rev 5 controls the requirement was derived from by tailoring the "
                          "Moderate baseline. A requirement is not the whole of its source control"),
         "reference_800_53_version": "5.1.1; every id is also an active id of the 5.2.0 catalog"},
        catalog)


# ---- ISO/IEC 27001:2022
def iso_id(raw, where):
    s = raw.strip()
    if re.fullmatch(r"A\.[5-8]\.\d{1,2}", s) or re.fullmatch(r"\d{1,2}\.\d\.\d", s):
        return s
    if re.fullmatch(r"\d{1,2}\.\d+", s):  # a two-part clause number stored as a spreadsheet number: 4.0999999999999996
        f = round(float(s), 1)
        if abs(f - float(s)) > 1e-9:
            raise Stop(f"{where}: clause number {raw!r} is not a one-decimal number")
        return repr(f)
    raise Stop(f"{where}: {raw!r} is not an ISO/IEC 27001 clause or Annex A id")


def build_iso(b, catalog):
    key = "iso_27001_2022"
    sheets = xlsx_sheets(b)
    fmap, rows_with_ref, source_controls = {}, 0, set()
    for name, rows in sheets.items():
        if name == "Definitions":
            continue
        if not rows[0].get("D", "").startswith("Reference Document Element"):
            raise Stop(f"{key}: unexpected header on sheet {name!r}")
        for r in rows[1:]:
            a, d = r.get("A", "").strip(), r.get("D", "").strip()
            if not a:
                continue
            c = unpad(a, f"{key} sheet {name}")
            source_controls.add(c)
            if d:
                rows_with_ref += 1
                fmap.setdefault(iso_id(d, f"{key} {a}"), []).append(c)
    src = SOURCES[key]
    annex = sum(1 for k in fmap if k.startswith("A."))
    return finish(
        key, f"ISO/IEC 27001:2022 clause or Annex A control -> NIST SP 800-53 Rev 5 ({annex} Annex A controls, {len(fmap) - annex} clauses), NIST's mapping inverted",
        f"NIST OLIR informative reference 155, \"{src['title']}\": {src['url']} (sha256 {src['sha256']}, equal to the hash "
        f"the OLIR catalog records; posted {src['published']})",
        "ISO clause (4.1 ... 10.2) or Annex A control (A.5.1 ... A.8.34) -> the 800-53 controls and enhancements NIST maps "
        "to it. " + SPINE_NOTE,
        fmap, {"rows_with_a_reference": rows_with_ref, "800_53_ids_in_source": len(source_controls),
               "annex_a_controls": annex, "clauses": len(fmap) - annex},
        {"relationship": ("NIST maps each 800-53 control to the ISO/IEC 27001:2022 requirements and controls that relate to "
                          "it; this map is that table inverted. NIST states no relationship type or strength, and warns "
                          "that the mappings are not always one-to-one and that control equivalency must not be assumed"),
         "direction_in_source": "SP 800-53 Rev 5.1.1 control -> ISO/IEC 27001:2022 element",
         "content": "ISO identifiers only; the source file carries no ISO text and none is reproduced here"},
        catalog)


# ---- CIS Controls v8.1 (user-supplied workbook; never written to the shipped file)
def build_cis(path, catalog):
    key = "cis_controls_v8"
    b = pathlib.Path(path).read_bytes()
    sheets = xlsx_sheets(b)
    lic = " ".join(v for r in sheets.get("License for Use", []) for v in r.values())
    rows = sheets.get("All CIS Controls & Safeguards")
    if rows is None or [rows[0].get(c) for c in "BCL"] != ["CIS Control", "CIS Safeguard", "Control Identifier"]:
        raise Stop(f"{key}: {path} is not the CIS Controls v8.1 to NIST SP 800-53 Rev 5 workbook")
    fmap, last, safeguards, rel = {}, {}, set(), {}
    for r in rows[1:]:
        ctl, sg = r.get("B", "").strip(), r.get("C", "").strip()
        if not sg:
            continue
        # safeguard numbers are spreadsheet numbers, so 4.10 is stored as 4.1: within a control they only ascend
        n = int(repr(round(float(sg), 2)).split(".")[1]) if "." in sg else None
        if n is None or repr(round(float(sg), 2)).split(".")[0] != ctl:
            raise Stop(f"{key}: unexpected safeguard number {sg!r} under control {ctl!r}")
        if n == 1 and last.get(ctl, 0) > 1:
            n = 10
        if n < last.get(ctl, 0):
            raise Stop(f"{key}: safeguard {ctl}.{n} is out of order")
        last[ctl] = n
        sid = f"{ctl}.{n}"
        safeguards.add(sid)
        c = r.get("L", "").strip()
        if c:
            fmap.setdefault(sid, []).append(unpad(c, f"{key} {sid}"))
            rel[r.get("K", "").strip() or "unstated"] = rel.get(r.get("K", "").strip() or "unstated", 0) + 1
    SOURCES[key] = {"title": "CIS Controls v8.1 Mapping to NIST SP 800-53 Rev 5", "url": CIS_PAGE, "sha256": sha256(b),
                    "published": "see the workbook's Introduction sheet"}
    e = finish(
        key, f"CIS Controls v8.1 Safeguard -> NIST SP 800-53 Rev 5 ({len(fmap)} of {len(safeguards)} Safeguards mapped), LOCAL BUILD",
        f"CIS Controls v8.1 Mapping to NIST SP 800-53 Rev 5 (Center for Internet Security), obtained by the user from "
        f"{CIS_PAGE}; workbook sha256 {sha256(b)}",
        "CIS Safeguard -> the 800-53 controls and enhancements CIS maps to it. " + SPINE_NOTE,
        fmap, {"safeguards_in_source": len(safeguards), "safeguards_unmapped": len(safeguards - set(fmap)),
               "relationships": dict(sorted(rel.items()))},
        {"relationship": "CIS states Subset, Superset or Equivalent per pair; the type is not carried into the map"},
        catalog)
    del SOURCES[key]
    e["meta"].update({"publisher": "Center for Internet Security (CIS)", "licence": CIS_LICENCE,
                      "licence_text_in_workbook": lic[:400],
                      "local_build": "built from a workbook the user downloaded; do not commit or redistribute this map"})
    e["meta"].pop("verified", None)
    return e


PENDING = {
    "pci_dss_v4": {
        "name": "pci_dss_v4",
        "source": ("NO source whose licence allows it. PCI SSC publishes no PCI DSS v4 -> SP 800-53 mapping and its "
                   "documents are not freely redistributable. NIST's OLIR catalog lists one PCI DSS 4.0.1 -> CSF 2.0 "
                   "reference (id 183, posted 2025-12-23), submitted by an independent third party, not by PCI SSC or "
                   "NIST; chaining it through CSF 2.0 to 800-53 would be a derived mapping from a non-authoritative "
                   "source. Checked 2026-11-24."),
        "status": "pending",
        "map": {},
    },
    "cis_controls_v8": {
        "name": "cis_controls_v8",
        "source": (f"CIS Controls v8.1 Mapping to NIST SP 800-53 Rev 5 (Center for Internet Security), {CIS_PAGE}. "
                   f"Licence: {CIS_LICENCE}. An id map extracted from it is a derivative and this repository is "
                   f"Apache-2.0, so the map is NOT shipped. Build it locally from a workbook you download: "
                   f"python3 {GENERATOR} --cis-file <workbook.xlsx> --out <dir outside the repository>/data.json. "
                   f"Checked 2026-11-24."),
        "status": "pending",
        "local_build": f"{GENERATOR} --cis-file",
        "map": {},
    },
}


def build_doc(doc, blobs, cis_file=None):
    catalog = parse_catalog(blobs["catalog"])
    new = {"nist_csf_2_0": build_csf(blobs["nist_csf_2_0"], catalog),
           "nist_800_171_r3": build_171(blobs["nist_800_171_r3"], catalog),
           "iso_27001_2022": build_iso(blobs["iso_27001_2022"], catalog)}
    new.update(PENDING)
    if cis_file:
        new["cis_controls_v8"] = build_cis(cis_file, catalog)
    maps = {k: new.get(k, v) for k, v in doc["maps"].items()}
    for k, v in new.items():
        maps.setdefault(k, v)
    out = {}
    for k, v in doc.items():
        if k != "catalog_800_53":
            out[k] = v
    out["maps"] = maps
    out["catalog_800_53"] = catalog
    return out


def dump(doc):
    return json.dumps(doc, indent=0)


def hand_edit_check(doc):
    """Offline: every generated map still hashes to the map_sha256 its meta records, and cites the pinned source."""
    problems = []
    for k in GENERATED_KEYS:
        e = doc["maps"].get(k, {})
        m = e.get("meta", {})
        if e.get("status") != "authoritative" or e.get("generated_by") != GENERATOR:
            problems.append(f"{k}: not the generated entry")
        elif m.get("map_sha256") != map_sha(e["map"]):
            problems.append(f"{k}: the map does not match its recorded map_sha256 (edited by hand?)")
        elif m.get("source_sha256") != SOURCES[k]["sha256"] or m.get("source_url") != SOURCES[k]["url"]:
            problems.append(f"{k}: the recorded source is not the one pinned in {GENERATOR}")
    for k, e in PENDING.items():
        if doc["maps"].get(k) != e:
            problems.append(f"{k}: the shipped entry must stay pending and empty, as {GENERATOR} writes it")
    cat = doc.get("catalog_800_53", {})
    if cat.get("meta", {}).get("source_sha256") != SOURCES["catalog"]["sha256"]:
        problems.append("catalog_800_53: missing, or not from the pinned catalog")
    return problems


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--cache", default=str(DEFAULT_CACHE))
    ap.add_argument("--cis-file", help="the CIS Controls v8.1 -> SP 800-53 Rev 5 workbook you downloaded (local build only)")
    ap.add_argument("--out", help="where to write the local copy of data.json when --cis-file is given (outside the repository)")
    a = ap.parse_args()
    doc = json.loads(OUT.read_text())

    if a.cis_file:
        if not a.out:
            raise Stop("--cis-file needs --out: the CIS map is a local build and is never written to the shipped file")
        out = pathlib.Path(a.out).resolve()
        if out == ROOT or ROOT in out.parents:
            raise Stop("--out must be outside this repository: the CIS mapping is CC BY-NC-ND 4.0 and is not vendored here")
        blobs = {k: fetch(k, a.cache) for k in SOURCES}
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(dump(build_doc(doc, blobs, a.cis_file)))
        e = json.loads(out.read_text())["maps"]["cis_controls_v8"]
        print(f"wrote {out}: cis_controls_v8 {e['meta']['counts']['framework_ids']} Safeguards mapped "
              f"({e['meta']['counts']['pairs']} pairs). Local use only; do not commit or redistribute.")
        return

    if a.check:
        problems = hand_edit_check(doc)
        blobs = {k: fetch(k, a.cache, offline=True) for k in SOURCES}
        if all(v is not None for v in blobs.values()):
            if OUT.read_text() != dump(build_doc(doc, blobs)):
                problems.append(f"{OUT.relative_to(ROOT)} is not what the pinned sources build: run {GENERATOR}")
            mode = "rebuilt from the cached, sha256-verified sources"
        else:
            mode = "sources not in the cache: map_sha256 and pins checked only"
        if problems:
            sys.exit("\n".join(problems))
        print(f"NIST framework maps current ({mode})")
        return

    blobs = {k: fetch(k, a.cache) for k in SOURCES}
    OUT.write_text(dump(build_doc(doc, blobs)))
    d = json.loads(OUT.read_text())
    for k in GENERATED_KEYS:
        print(f"  {k}: {d['maps'][k]['meta']['counts']}")
    print(f"  catalog_800_53: {d['catalog_800_53']['meta']['counts']}")
    print(f"wrote {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
