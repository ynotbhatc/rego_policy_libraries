#!/usr/bin/env python3
"""Generate the GovRAMP (formerly StateRAMP) entries of crosswalk/framework_maps/data.json.

GovRAMP's Low, Moderate and High baselines select NIST SP 800-53 Rev 5 controls under the catalog's own ids, so each
map is the identity: GovRAMP control id -> [the same 800-53 id]. The control lists are NOT FedRAMP's: the publisher's
own Controls Matrix workbooks select 153 (Low), 319 (Moderate) and 406 (High) controls, FedRAMP Rev 5 selects 156 /
323 / 410 (IA-2(12), IA-8(1) and SA-4(10) at every level, CA-8(2) at Moderate and High are not selected by GovRAMP).

Seven maps are written, all authoritative, all identity:
    govramp_low, govramp_moderate, govramp_high           the controls of the Authorized / Provisionally Authorized
                                                          review at that impact level (every control the matrix lists)
    govramp_low_ready, govramp_moderate_ready,
    govramp_high_ready                                    the controls the matrix marks "Required for Ready"
    govramp_moderate_core                                 the controls the Moderate matrix marks "Required for Core"
                                                          (Core exists at Moderate only)

The same lists are written as sets into frameworks/federal/govramp/govramp_index.rego (package govramp.index), which the
module reads: a data file is not part of the policy directories the product and the bad-input harness load, a rego file is.
Formatting goes through `opa fmt` ($OPA, as the Makefile sets it).

Source of the id lists: scripts/govramp_baselines.json (committed; ids and provenance only, no GovRAMP text or
parameter values), produced from the publisher's workbooks, which are not in this repository:
    python3 scripts/gen_govramp_framework_maps.py --from-xlsx <dir>   # refresh scripts/govramp_baselines.json
        <dir> holds the workbooks named in the "sources" block of that file (any sub-directories are searched); each is
        checked against the sha256 the file records unless --accept-new-hashes is given (use it when the publisher
        has issued a new version, then update the version, url and date by hand and review the diff)
    python3 scripts/gen_govramp_framework_maps.py                     # write data.json from the committed list
    python3 scripts/gen_govramp_framework_maps.py --check             # exit 1 if data.json or the list is stale
No network access in any mode; standard library only. Only the govramp_* entries of data.json are written; every
other entry is left as it is. Deterministic.
"""
import hashlib, json, os, pathlib, re, subprocess, sys, zipfile
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "crosswalk/framework_maps/data.json"
LIST = ROOT / "scripts/govramp_baselines.json"
INDEX = ROOT / "frameworks/federal/govramp/govramp_index.rego"
OPA = os.environ.get("OPA", "opa")   # the Makefile's OPA; the `opa` on PATH otherwise
LEVELS = ["low", "moderate", "high"]
GENERATOR = "scripts/gen_govramp_framework_maps.py"
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


def matrix_rows(path, sheet):
    """[(id, {column header: value})] of the control rows (the first column is the running count)."""
    rows = read_xlsx(path)[sheet]
    head = next(r for r in rows if r and r[0].strip().startswith("Count"))
    out = []
    for r in rows:
        if r and r[0].strip().isdigit():
            r = r + [""] * (len(head) - len(r))
            cells = {h.strip(): v for h, v in zip(head, r)}
            out.append((norm(cells["ID"]), cells))
    return out


def refresh(directory, accept_new):
    doc = json.loads(LIST.read_text())
    root = pathlib.Path(directory)
    files = {}
    for key, src in doc["sources"].items():
        path = find(root, src["file"])
        got = sha256(path)
        if src["sha256"] and got != src["sha256"] and not accept_new:
            raise SystemExit(f"{src['file']}: sha256 {got} differs from the recorded {src['sha256']}; the publisher "
                             f"changed the file. Re-run with --accept-new-hashes, then update version/url/date and "
                             f"review the diff")
        src["sha256"] = got
        files[key] = path
    levels = {}
    for level in LEVELS:
        src = doc["sources"][f"matrix_{level}"]
        rows = matrix_rows(files[f"matrix_{level}"], src["sheet"])
        ids = [i for i, _ in rows]
        if len(ids) != len(set(ids)):
            raise SystemExit(f"{level}: the matrix repeats a control")
        entry = {"authorized": sorted(ids, key=sort_key),
                 "ready": sorted((i for i, c in rows if c["Required for Ready"] == "Yes"), key=sort_key)}
        if level == "moderate":
            entry["core"] = sorted((i for i, c in rows if c.get("Required for Core") == "Yes"), key=sort_key)
        if any(c["Required for Authorized"] != "Yes" for _, c in rows):
            raise SystemExit(f"{level}: a listed control is not 'Required for Authorized'")
        levels[level] = entry
    # cross-check the Moderate Ready list against the publisher's Ready mandatory-requirements workbook
    mand = [norm(r[4]) for r in read_xlsx(files["ready_mandates"])[doc["sources"]["ready_mandates"]["sheet"]]
            if r and r[0].strip().isdigit()]
    if sorted(mand, key=sort_key) != levels["moderate"]["ready"]:
        raise SystemExit("the Moderate Ready list of the matrix differs from the Ready mandatory-requirements workbook")
    # the Federal Overlay: controls whose GovRAMP requirement or parameter differs from FedRAMP's (not the "Not
    # Selected" rows, which the matrices already settle)
    over = read_xlsx(files["federal_overlay"])
    deltas = {}
    for level in LEVELS:
        tab = over[f"{level.capitalize()} Overlay"]
        ids = []
        for r in tab:
            if r and r[0].strip().isdigit():
                r = r + [""] * (12 - len(r))
                text = (r[10] + " " + r[11]).strip()
                if "Control Not Selected by GovRAMP" not in text:
                    ids.append(norm(r[6]))
        deltas[level] = sorted(set(ids), key=sort_key)
    doc["levels"] = levels
    doc["federal_overlay_deltas"] = deltas
    doc["federal_overlay_not_selected"] = {
        level: sorted({norm(r[6]) for r in over[f"{level.capitalize()} Overlay"]
                       if r and r[0].strip().isdigit() and len(r) > 10 and "Control Not Selected by GovRAMP" in (r[10] + (r[11] if len(r) > 11 else ""))},
                      key=sort_key) for level in LEVELS}
    LIST.write_text(json.dumps(doc, indent=1) + "\n")
    print(f"wrote {LIST.relative_to(ROOT)}: " + ", ".join(
        f"{lv} {len(levels[lv]['authorized'])}/{len(levels[lv]['ready'])}" + (f"/{len(levels[lv]['core'])}" if 'core' in levels[lv] else "")
        for lv in LEVELS) + " (authorized/ready/core)")


# ---- data.json ---------------------------------------------------------------------------------------------------
def entries(doc):
    fed = json.loads(OUT.read_text())["maps"]
    out = {}
    for level in LEVELS:
        lv = doc["levels"][level]
        mat = doc["sources"][f"matrix_{level}"]
        fedids = set(fed[f"fedramp_rev5_{level}"]["map"])
        auth = lv["authorized"]
        for scope, ids in [("authorized", auth), ("ready", lv["ready"]), ("core", lv.get("core"))]:
            if ids is None:
                continue
            key = f"govramp_{level}" + ("" if scope == "authorized" else f"_{scope}")
            if not set(ids) <= set(auth):
                raise SystemExit(f"{key}: selects a control the {level} baseline does not")
            col = {"authorized": "the controls the matrix lists (every one is marked Required for Authorized)",
                   "ready": "the controls the matrix marks Required for Ready",
                   "core": "the controls the matrix marks Required for Core"}[scope]
            base = sum(1 for i in ids if "(" not in i)
            out[key] = {
                "name": f"GovRAMP {level.capitalize()} impact, {scope.capitalize() if scope != 'authorized' else 'Authorized / Provisionally Authorized'} ({len(ids)} controls: {base} base controls, {len(ids) - base} enhancements)",
                "source": (f"GovRAMP Controls Matrix, {level.capitalize()} impact, {mat['version']} ({mat['url']}, "
                           f"sha256 {mat['sha256']}, fetched {doc['fetched']}): {col}. Control ids only; GovRAMP's "
                           f"parameter values and guidance text are not reproduced. Id list: scripts/govramp_baselines.json"),
                "status": "authoritative",
                "granularity": ("identity: each control or enhancement selected maps to the same NIST SP 800-53 Rev 5 id. The "
                                "STIG -> 800-53 spine is at base-control granularity, so an enhancement never gets a "
                                "verdict through it"),
                "generated_by": GENERATOR,
                "map": {i: [i] for i in ids},
            }
            if scope == "authorized":
                out[key]["not_selected_from_fedramp_rev5"] = sorted(fedids - set(ids), key=sort_key)
                out[key]["federal_overlay_differs_from_fedramp"] = doc["federal_overlay_deltas"][level]
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
    fed = json.loads(OUT.read_text())["maps"]
    out = ['# METADATA',
           '# title: "GovRAMP — static index of the controls each impact level and verified status selects; generated"',
           '# custom:', '#   class: compliance', '#   framework: govramp', '#   source: govramp', '#   domains: [us-state, cloud]',
           'package govramp.index', '', 'import rego.v1', '',
           '# GENERATED by scripts/gen_govramp_framework_maps.py from scripts/govramp_baselines.json: do not edit; re-run the script.',
           '# Control ids only, taken from the publisher\'s Controls Matrices (versions, URLs and sha256 in the JSON file).', '',
           '# The controls each status of each impact level selects. authorized is every control the matrix lists (Authorized and',
           '# Provisionally Authorized); ready is the Required-for-Ready column; core is the Required-for-Core column (Moderate only).',
           'scopes := {']
    for level in LEVELS:
        lv = doc["levels"][level]
        out.append(f'\t"{level}": {{')
        for kind in ("authorized", "ready", "core"):
            if kind in lv:
                out.append(f'\t\t"{kind}": {rego_set(lv[kind], chr(9) * 3)},')
        out.append('\t},')
    out.append('}')
    out += ['', '# What FedRAMP Rev 5 selects at the same level and GovRAMP does not.', 'not_selected_from_fedramp_rev5 := {']
    for level in LEVELS:
        ids = sorted(set(fed[f"fedramp_rev5_{level}"]["map"]) - set(doc["levels"][level]["authorized"]), key=sort_key)
        out.append(f'\t"{level}": [{", ".join(json.dumps(i) for i in ids)}],')
    out.append('}')
    out += ['', '# Controls whose GovRAMP requirement or parameter differs from FedRAMP\'s in the Federal Overlay v1.0.',
            'federal_overlay_differs_from_fedramp := {']
    for level in LEVELS:
        out.append(f'\t"{level}": [{", ".join(json.dumps(i) for i in doc["federal_overlay_deltas"][level])}],')
    out.append('}')
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
    maps = {k: v for k, v in data["maps"].items() if not k.startswith("govramp_")}
    new = entries(doc)
    out = {}
    for k, v in maps.items():
        out[k] = v
        if k == "fedramp_rev5_li_saas":  # after the FedRAMP baselines they are compared with
            out.update(new)
    if not any(k.startswith("govramp_") for k in out):
        raise SystemExit("anchor map fedramp_rev5_li_saas not found in data.json")
    data["maps"] = out
    return json.dumps(data, indent=0)


def main(argv):
    if "--from-xlsx" in argv:
        refresh(argv[argv.index("--from-xlsx") + 1], "--accept-new-hashes" in argv)
        return 0
    doc = json.loads(LIST.read_text())
    problems = []
    for level in LEVELS:
        lv = doc["levels"][level]
        if len(lv["authorized"]) != doc["expected_sizes"][level]:
            problems.append(f"{level}: {len(lv['authorized'])} controls, the publisher's matrix count recorded is {doc['expected_sizes'][level]}")
    text = build(doc)
    current = OUT.read_text()
    index = build_index(doc)
    if "--check" in argv:
        if problems or text != current or not INDEX.exists() or index != INDEX.read_text():
            print("\n".join(problems) or "crosswalk/framework_maps/data.json or frameworks/federal/govramp/govramp_index.rego is stale: run scripts/gen_govramp_framework_maps.py", file=sys.stderr)
            return 1
        print("govramp framework maps current: " + ", ".join(f"{lv} {len(doc['levels'][lv]['authorized'])}" for lv in LEVELS))
        return 0
    if problems:
        raise SystemExit("\n".join(problems))
    OUT.write_text(text)
    INDEX.write_text(index)
    print("wrote the govramp_* maps of crosswalk/framework_maps/data.json and frameworks/federal/govramp/govramp_index.rego")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
