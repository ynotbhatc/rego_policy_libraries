#!/usr/bin/env python3
"""Generate the TX-RAMP entries of crosswalk/framework_maps/data.json and the generated index of the txramp module.

TX-RAMP (Texas Risk and Authorization Management Program, Texas Department of Information Resources) publishes its own
control baselines, written in NIST SP 800-53 Rev 5 terms: Level 1 (117 controls and enhancements) and Level 2 (223).
Level 1 is inside Level 2. Each baseline control is a NIST SP 800-53 Rev 5 control or enhancement under the catalog's
own id, so each map is the identity: TX-RAMP control id -> [the same 800-53 id].

Two maps are written, both authoritative, both identity:
    txramp_level_1, txramp_level_2

The same lists are written as sets into frameworks/federal/txramp/txramp_index.rego (package txramp.index), which the
module reads: a data file is not part of the policy directories the product and the bad-input harness load, a rego file
is. The index also carries CONTROL_INDEX, the ids as the findings write them, so the exporters know the controls.
Formatting goes through `opa fmt` ($OPA, as the Makefile sets it).

Source of the id lists: scripts/txramp_baselines.json (committed, everything under one top-level key because every
JSON file of the tree is loaded as data by `opa test .`, and two files must not share a top-level key; ids and provenance only, no TX-RAMP text and no TX-RAMP
parameter values), produced from the publisher's workbook, which is not in this repository:
    python3 scripts/gen_txramp_framework_maps.py --from-xlsx <dir>   # refresh scripts/txramp_baselines.json
        <dir> holds the workbook named in the "sources" block of that file (any sub-directories are searched); it is
        checked against the sha256 the file records unless --accept-new-hashes is given (use it when the publisher has
        issued a new version, then update the version, url and date by hand and review the diff). The Combined sheet's
        Level 1 / Level 2 columns are cross-checked against the Level 1 and Level 2 sheets, and the counts (total and per
        family) against the figures Appendix A of the Program Manual publishes (recorded in the JSON file).
    python3 scripts/gen_txramp_framework_maps.py                     # write data.json and the index from the committed list
    python3 scripts/gen_txramp_framework_maps.py --check             # exit 1 if data.json, the index or the list is stale
No network access in any mode; standard library only. Only the txramp_* entries of data.json are written; every other
entry is left as it is. Deterministic.
"""
import hashlib, json, os, pathlib, re, subprocess, sys, zipfile
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "crosswalk/framework_maps/data.json"
LIST = ROOT / "scripts/txramp_baselines.json"
INDEX = ROOT / "frameworks/federal/txramp/txramp_index.rego"
OPA = os.environ.get("OPA", "opa")   # the Makefile's OPA; the `opa` on PATH otherwise
LEVELS = ["level_1", "level_2"]
GENERATOR = "scripts/gen_txramp_framework_maps.py"
NS = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
      "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships"}
ID = re.compile(r"^([A-Z]{2})-(\d+)(?:\s*\((\d+)\))?$")


def norm(raw):
    m = ID.match(raw.strip())
    if not m:
        raise SystemExit(f"not a control id: {raw!r}")
    return f"{m[1]}-{int(m[2])}" + (f"({int(m[3])})" if m[3] else "")


def sort_key(i):
    m = re.match(r"^([A-Z]{2})-(\d+)(?:\((\d+)\))?$", i)
    return (m[1], int(m[2]), int(m[3] or 0))


# ---- a minimal .xlsx reader (zip + xml), so the script needs nothing installed -----------------------------------
def _col(ref):
    n = 0
    for ch in re.match(r"[A-Z]+", ref).group():
        n = n * 26 + ord(ch) - 64
    return n - 1


def read_xlsx(path):
    z = zipfile.ZipFile(path)
    shared = []
    if "xl/sharedStrings.xml" in z.namelist():
        for si in ET.fromstring(z.read("xl/sharedStrings.xml")).findall("m:si", NS):
            shared.append("".join(t.text or "" for t in si.iter("{%s}t" % NS["m"])))
    wb = ET.fromstring(z.read("xl/workbook.xml"))
    rels = {r.get("Id"): r.get("Target") for r in ET.fromstring(z.read("xl/_rels/workbook.xml.rels"))}
    sheets = {}
    for s in wb.find("m:sheets", NS):
        target = rels[s.get("{%s}id" % NS["r"])].lstrip("/")
        target = target if target.startswith("xl/") else "xl/" + target
        rows = []
        for r in ET.fromstring(z.read(target)).iter("{%s}row" % NS["m"]):
            cells = {}
            for c in r.findall("m:c", NS):
                v, t = c.find("m:v", NS), c.get("t")
                if t == "inlineStr":
                    cells[_col(c.get("r"))] = "".join(x.text or "" for x in c.iter("{%s}t" % NS["m"]))
                elif v is not None:
                    cells[_col(c.get("r"))] = shared[int(v.text)] if t == "s" else v.text
            if cells:
                rows.append([cells.get(i, "") for i in range(max(cells) + 1)])
        sheets[s.get("name")] = rows
    return sheets


def find(root, name):
    hits = sorted(p for p in root.rglob(name) if p.is_file())
    if not hits:
        raise SystemExit(f"{name} not found under {root}")
    return hits[0]


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def selected(cell):
    """The workbook marks a selected control "x" and an unselected one "Not Selected"; anything else is an error."""
    v = cell.strip()
    if v.lower() == "x":
        return True
    if v == "Not Selected":
        return False
    raise SystemExit(f"unexpected level cell {cell!r}")


def refresh(directory, accept_new):
    doc = json.loads(LIST.read_text())["txramp_baselines"]
    src = doc["sources"]["baselines"]
    path = find(pathlib.Path(directory), src["file"])
    got = sha256(path)
    if src["sha256"] and got != src["sha256"] and not accept_new:
        raise SystemExit(f"{src['file']}: sha256 {got} differs from the recorded {src['sha256']}; the publisher changed "
                         f"the file. Re-run with --accept-new-hashes, then update version/url/date and review the diff")
    src["sha256"] = got
    sheets = read_xlsx(path)
    rows = [r + [""] * (11 - len(r)) for r in sheets["Combined"][1:] if r and r[1].strip()]
    head = sheets["Combined"][0]
    if head[:7] != ["Control Family", "Control ID", "ID", "SORT ID", "Control Name", "Level 1", "Level 2"]:
        raise SystemExit(f"the Combined sheet's columns changed: {head[:7]}")
    ids = [norm(r[2]) for r in rows]
    if len(ids) != len(set(ids)):
        raise SystemExit("the Combined sheet repeats a control")
    levels = {"level_1": sorted((norm(r[2]) for r in rows if selected(r[5])), key=sort_key),
              "level_2": sorted((norm(r[2]) for r in rows if selected(r[6])), key=sort_key)}
    if not set(levels["level_1"]) <= set(levels["level_2"]):
        raise SystemExit("Level 1 selects a control Level 2 does not")
    # the per-level sheets must list the same controls as the Combined columns (they are keyed by SORT ID)
    sort_to_id = {r[3].strip(): norm(r[2]) for r in rows}
    for level, sheet in (("level_1", "Level 1"), ("level_2", "Level 2")):
        listed = sorted((sort_to_id[r[1].strip()] for r in sheets[sheet][1:] if r and r[1].strip()), key=sort_key)
        if listed != levels[level]:
            raise SystemExit(f"{level}: the sheet {sheet!r} differs from the Combined sheet's column")
    # the counts the Program Manual (Appendix A) publishes
    pub = doc["published_counts"]
    for level in LEVELS:
        if len(levels[level]) != pub["total"][level]:
            raise SystemExit(f"{level}: {len(levels[level])} controls, Appendix A publishes {pub['total'][level]}")
    for fam, (n1, n2) in pub["families"].items():
        c1 = sum(1 for x in levels["level_1"] if x[:2] == fam)
        c2 = sum(1 for x in levels["level_2"] if x[:2] == fam)
        if (c1, c2) != (n1, n2):
            raise SystemExit(f"family {fam}: {(c1, c2)} controls, Appendix A publishes {(n1, n2)}")
    doc["levels"] = levels
    LIST.write_text(json.dumps({"txramp_baselines": doc}, indent=1) + "\n")
    print(f"wrote {LIST.relative_to(ROOT)}: level_1 {len(levels['level_1'])}, level_2 {len(levels['level_2'])}")


# ---- data.json ---------------------------------------------------------------------------------------------------
def entries(doc):
    src = doc["sources"]["baselines"]
    out = {}
    for level in LEVELS:
        ids = doc["levels"][level]
        base = sum(1 for i in ids if "(" not in i)
        out[f"txramp_{level}"] = {
            "name": f"TX-RAMP {level.replace('_', ' ').capitalize()} ({len(ids)} controls: {base} base controls, {len(ids) - base} enhancements)",
            "source": (f"TX-RAMP Control Baselines 2.0, column {level.replace('_', ' ').capitalize()} ({src['url']}, sha256 {src['sha256']}, "
                       f"fetched {doc['fetched']}); the counts are those of Appendix A of the TX-RAMP Program Manual 4.0 "
                       f"({doc['sources']['manual']['url']}). Control ids only; TX-RAMP's parameter values and text are not "
                       f"reproduced. Id list: scripts/txramp_baselines.json"),
            "status": "authoritative",
            "granularity": ("identity: each control or enhancement selected maps to the same NIST SP 800-53 Rev 5 id. The "
                            "STIG -> 800-53 spine is at base-control granularity, so an enhancement never gets a "
                            "verdict through it"),
            "generated_by": GENERATOR,
            "map": {i: [i] for i in ids},
        }
    return out


def rego_set(ids, indent):
    lines, cur = [], ""
    for i in sorted(ids, key=sort_key):
        tok = json.dumps(i) + ", "
        if len(cur) + len(tok) > 110:
            lines.append(cur.rstrip()); cur = ""
        cur += tok
    if cur:
        lines.append(cur.rstrip())
    return "{\n" + "\n".join(indent + l for l in lines) + "\n" + indent[:-1] + "}"


def build_index(doc):
    out = ['# METADATA',
           '# title: "TX-RAMP — static index of the controls each certification level selects; generated"',
           '# custom:', '#   class: compliance', '#   framework: txramp', '#   source: txramp', '#   domains: [us-state, cloud]',
           'package txramp.index', '', 'import rego.v1', '',
           '# GENERATED by scripts/gen_txramp_framework_maps.py from scripts/txramp_baselines.json: do not edit; re-run the script.',
           '# Control ids only, taken from the publisher\'s TX-RAMP Control Baselines 2.0 workbook (version, URL and sha256 in the JSON file).', '',
           '# The controls each certification level selects (Level 1 is inside Level 2).',
           'scopes := {']
    for level in LEVELS:
        out.append(f'\t"{level}": {rego_set(doc["levels"][level], chr(9) * 2)},')
    out.append('}')
    # The findings of the controls are built from the 800-53 module's rows at run time ("TX-RAMP AC-2: ..."), so no literal
    # message carries the ids. The exporters (OSCAL catalog, SARIF, assessment results) learn them from this index.
    out += ['', '# Every control any TX-RAMP baseline selects, as the findings write it. Read by scripts/inventory_controls.py so the',
            '# OSCAL catalog and the exports know the controls; no rule reads it.', 'CONTROL_INDEX := [']
    out += [f'\t{{"id": {json.dumps("TX-RAMP " + i)}}},' for i in sorted(doc["levels"]["level_2"], key=sort_key)]
    out += [']']
    r = subprocess.run([OPA, "fmt"], input="\n".join(out) + "\n", capture_output=True, text=True, check=True)
    return keep_stamp(r.stdout)


def keep_stamp(text):
    """Carry over the coverage block scripts/coverage_stamp.py writes into the METADATA: the stamp is the stamper's."""
    if not INDEX.exists():
        return text
    block, on = [], False
    for l in INDEX.read_text().splitlines():
        if l == "#   coverage:":
            on = True
        elif on and not l.startswith("#     "):
            break
        if on:
            block.append(l)
    if not block:
        return text
    t = text.splitlines()
    i = t.index("#   domains: [us-state, cloud]") + 1
    return "\n".join(t[:i] + block + t[i:]) + "\n"


def build(doc):
    data = json.loads(OUT.read_text())
    maps = {k: v for k, v in data["maps"].items() if not k.startswith("txramp_")}
    new = entries(doc)
    anchor = [k for k in maps if k.startswith("govramp_")]
    if not anchor:
        raise SystemExit("anchor maps govramp_* not found in data.json")
    out = {}
    for k, v in maps.items():
        out[k] = v
        if k == anchor[-1]:  # after the GovRAMP baselines
            out.update(new)
    data["maps"] = out
    return json.dumps(data, indent=0)


def main(argv):
    if "--from-xlsx" in argv:
        refresh(argv[argv.index("--from-xlsx") + 1], "--accept-new-hashes" in argv)
        return 0
    doc = json.loads(LIST.read_text())["txramp_baselines"]
    problems = []
    for level in LEVELS:
        n = len(doc["levels"].get(level, []))
        if n != doc["published_counts"]["total"][level]:
            problems.append(f"{level}: {n} controls, Appendix A of the Program Manual publishes {doc['published_counts']['total'][level]}")
    if problems:
        print("\n".join(problems), file=sys.stderr)
        return 1
    text = build(doc)
    current = OUT.read_text()
    index = build_index(doc)
    if "--check" in argv:
        if text != current or not INDEX.exists() or index != INDEX.read_text():
            print("crosswalk/framework_maps/data.json or frameworks/federal/txramp/txramp_index.rego is stale: run scripts/gen_txramp_framework_maps.py", file=sys.stderr)
            return 1
        print("txramp framework maps current: " + ", ".join(f"{lv} {len(doc['levels'][lv])}" for lv in LEVELS))
        return 0
    OUT.write_text(text)
    INDEX.parent.mkdir(parents=True, exist_ok=True)
    INDEX.write_text(index)
    print("wrote the txramp_* maps of crosswalk/framework_maps/data.json and frameworks/federal/txramp/txramp_index.rego")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
