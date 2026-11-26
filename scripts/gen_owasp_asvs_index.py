#!/usr/bin/env python3
"""Generate the OWASP ASVS 5.0.0 requirement index of governance/owasp_asvs/.

The module (package owasp_asvs.main) needs, for each of the 345 requirements of ASVS 5.0.0, only its id, chapter,
section and level. Those come from the machine-readable release file published by the standard's authors; no
requirement text is read into this repository (the standard is CC BY-SA 4.0, this library is Apache-2.0, see NOTICE).

    python3 scripts/gen_owasp_asvs_index.py --from-json <dir>   # refresh scripts/owasp_asvs_requirements.json
        <dir> holds OWASP_Application_Security_Verification_Standard_5.0.0_en.json (the release asset of tag
        v5.0.0_release, https://github.com/OWASP/ASVS/releases/tag/v5.0.0_release); its sha256 must equal the one
        recorded in the committed file unless --accept-new-hashes is given (use it for a new release, then update
        the tag, date, commit and URL by hand and review the diff). The file is only read as data (json module).
    python3 scripts/gen_owasp_asvs_index.py                      # write governance/owasp_asvs/owasp_asvs_index.rego
    python3 scripts/gen_owasp_asvs_index.py --check              # exit 1 if the index or the committed list is stale
No network access in any mode; standard library only. Formatting goes through `opa fmt` ($OPA, as the Makefile sets
it). Deterministic.

Committed list (scripts/owasp_asvs_requirements.json; everything sits under one top-level key, "owasp_asvs", because
`opa test .` loads the JSON files of scripts/ as data.scripts.<top-level key> and two files may not share one): provenance (tag, date, tag commit, URL, sha256 of the source
file, licence), the expected counts, our own short chapter labels (not the standard's chapter titles) and one
[id, chapter, section, level] row per requirement. Level is the lowest level that includes the requirement: an L1
requirement is also required at L2 and L3, an L2 one at L3 (the standard's "What is the ASVS", Levels section: "all of
the L1 and L2 requirements" for L2).
"""
import hashlib, json, os, pathlib, re, subprocess, sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
LIST = ROOT / "scripts/owasp_asvs_requirements.json"
INDEX = ROOT / "governance/owasp_asvs/owasp_asvs_index.rego"
OPA = os.environ.get("OPA", "opa")
SOURCE_FILE = "OWASP_Application_Security_Verification_Standard_5.0.0_en.json"
ID = re.compile(r"^V(\d+)\.(\d+)\.(\d+)$")

# Our own short labels, one per chapter. They paraphrase what the chapter is about; they are not the standard's titles.
CHAPTER_LABELS = {
    "V1": "Output encoding and injection defences",
    "V2": "Input validation and business-logic controls",
    "V3": "Browser-side (frontend) security",
    "V4": "API and web-service security",
    "V5": "File upload, storage and download handling",
    "V6": "Authentication",
    "V7": "Session management",
    "V8": "Authorization",
    "V9": "Self-contained tokens",
    "V10": "OAuth 2 and OpenID Connect",
    "V11": "Cryptography",
    "V12": "Transport security (TLS)",
    "V13": "Application and service configuration",
    "V14": "Protection of sensitive data",
    "V15": "Secure coding practices and architecture",
    "V16": "Security logging and error handling",
    "V17": "WebRTC security",
}


def key(i):
    m = ID.match(i)
    return tuple(int(x) for x in m.groups())


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load():
    return json.loads(LIST.read_text())["owasp_asvs"]


def refresh(directory, accept_new):
    doc = load()
    src = pathlib.Path(directory) / SOURCE_FILE
    if not src.is_file():
        raise SystemExit(f"{SOURCE_FILE} not found in {directory}")
    got = sha256(src)
    if doc["source"]["sha256"] and got != doc["source"]["sha256"] and not accept_new:
        raise SystemExit(f"sha256 {got} differs from the recorded {doc['source']['sha256']}; the release changed. "
                         f"Re-run with --accept-new-hashes, then update tag/date/commit/url by hand and review the diff")
    data = json.loads(src.read_text())
    if data.get("ShortName") != "ASVS" or data.get("Version") != doc["version"]:
        raise SystemExit(f"source is {data.get('ShortName')} {data.get('Version')}, expected ASVS {doc['version']}")
    rows = []
    for ch in data["Requirements"]:
        for sec in ch["Items"]:
            for r in sec["Items"]:
                if not ID.match(r["Shortcode"]) or r["L"] not in ("1", "2", "3"):
                    raise SystemExit(f"unexpected requirement row {r['Shortcode']!r} L={r['L']!r}")
                rows.append([r["Shortcode"], ch["Shortcode"], sec["Shortcode"], int(r["L"])])
    ids = [r[0] for r in rows]
    if len(set(ids)) != len(ids):
        raise SystemExit("the source repeats a requirement id")
    rows.sort(key=lambda r: key(r[0]))
    doc["source"]["sha256"] = got
    doc["expected"] = counts(rows)
    doc["chapters"] = {c: CHAPTER_LABELS[c] for c in sorted({r[1] for r in rows}, key=lambda c: int(c[1:]))}
    doc["requirements"] = rows
    LIST.write_text(dump(doc))
    print(f"wrote {LIST.relative_to(ROOT)}: {doc['expected']}")


def counts(rows):
    lv = {1: 0, 2: 0, 3: 0}
    for r in rows:
        lv[r[3]] += 1
    return {"chapters": len({r[1] for r in rows}), "sections": len({r[2] for r in rows}), "requirements": len(rows),
            "only_level_1": lv[1], "only_level_2": lv[2], "only_level_3": lv[3],
            "in_scope_level_1": lv[1], "in_scope_level_2": lv[1] + lv[2], "in_scope_level_3": len(rows)}


def dump(doc):
    """One requirement per line, everything else indented JSON, so the diff of a new release is readable."""
    head = {k: v for k, v in doc.items() if k != "requirements"}
    text = json.dumps({"owasp_asvs": head}, indent=1)
    rows = ",\n".join("   " + json.dumps(r) for r in doc["requirements"])
    return text[:-len("\n }\n}")] + ',\n  "requirements": [\n' + rows + "\n  ]\n }\n}\n"


def problems(doc):
    out = []
    rows = doc["requirements"]
    ids = [r[0] for r in rows]
    if len(set(ids)) != len(ids):
        out.append("a requirement id is repeated")
    if ids != sorted(ids, key=key):
        out.append("requirements are not in natural id order")
    for i, ch, sec, lv in rows:
        m = ID.match(i)
        if not m or ch != f"V{m[1]}" or sec != f"V{m[1]}.{m[2]}" or lv not in (1, 2, 3):
            out.append(f"{i}: id, chapter, section or level malformed")
    if counts(rows) != doc["expected"]:
        out.append(f"counts {counts(rows)} differ from the recorded {doc['expected']}")
    if set(doc["chapters"]) != {r[1] for r in rows} or any(doc["chapters"][c] != CHAPTER_LABELS[c] for c in doc["chapters"]):
        out.append("chapter labels differ from CHAPTER_LABELS or cover other chapters than the requirements")
    return out


def rego_str(s):
    return json.dumps(s)


def build_index(doc):
    rows = doc["requirements"]
    ex = doc["expected"]
    o = ['# METADATA',
         '# title: "OWASP ASVS 5.0.0 — static index of the 345 requirements (id, chapter, section, level); generated"',
         '# custom:', '#   class: governance', '#   framework: owasp_asvs', '#   source: owasp', '#   domains: [secure-development]',
         'package owasp_asvs.index', '', 'import rego.v1', '',
         '# GENERATED by scripts/gen_owasp_asvs_index.py from scripts/owasp_asvs_requirements.json: do not edit; re-run the script.',
         f'# Source: OWASP Application Security Verification Standard {doc["version"]}, release tag {doc["source"]["tag"]} '
         f'({doc["source"]["tag_commit"][:12]}), file {doc["source"]["file"]}, sha256 {doc["source"]["sha256"]}.',
         '# Only ids, chapter and section numbers and levels are taken from the standard; no requirement text. The chapter labels are',
         '# this library\'s own words. ASVS is © The OWASP Foundation, CC BY-SA 4.0 (see NOTICE).', '',
         '# levels: the requirements whose lowest level is 1, 2 or 3. Level N assesses the union of levels 1 to N.',
         '# Chapter V<c> and section V<c>.<s> of V<c>.<s>.<r> are read from the id itself.',
         'levels := {']
    for n in (1, 2, 3):
        ids = ", ".join(rego_str(r[0]) for r in rows if r[3] == n)
        o.append(f'\t"{n}": {{{ids}}},')
    o += ['}', '', '# The requirement ids in the standard\'s own order.', 'order := [']
    o += [f'\t{rego_str(r[0])},' for r in rows]
    o += [']', '', '# The requirement ids of each chapter, in the standard\'s order.', 'by_chapter := {']
    for c in doc["chapters"]:
        o.append(f'\t{rego_str(c)}: [{", ".join(rego_str(r[0]) for r in rows if r[1] == c)}],')
    o += ['}', '', '# This library\'s own short chapter labels.', 'chapters := {']
    o += [f'\t{rego_str(c)}: {rego_str(l)},' for c, l in doc["chapters"].items()]
    o += ['}', '', '# Requirements in scope at each level (a fixed property of the standard; the module and its tests read these).',
          'in_scope_totals := {', f'\t"1": {ex["in_scope_level_1"]},', f'\t"2": {ex["in_scope_level_2"]},', f'\t"3": {ex["in_scope_level_3"]},', '}',
          '', '# Every requirement, as the findings write it. Read by scripts/inventory_controls.py so the OSCAL catalog and the',
          '# exports know the requirements; no rule reads it.', 'CONTROL_INDEX := [']
    o += [f'\t{{"id": {rego_str("OWASP ASVS " + r[0])}, "level": {r[3]}}},' for r in rows]
    o += [']']
    r = subprocess.run([OPA, "fmt"], input="\n".join(o) + "\n", capture_output=True, text=True, check=True)
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
    i = t.index("#   domains: [secure-development]") + 1
    return "\n".join(t[:i] + block + t[i:]) + "\n"


def main(argv):
    if "--from-json" in argv:
        refresh(argv[argv.index("--from-json") + 1], "--accept-new-hashes" in argv)
    doc = load()
    bad = problems(doc)
    if "--check" in argv:
        if not bad and (LIST.read_text() != dump(doc)):
            bad.append("scripts/owasp_asvs_requirements.json is not in the generator's layout")
        index = build_index(doc)
        if bad or not INDEX.exists() or index != INDEX.read_text():
            print("\n".join(bad) or "governance/owasp_asvs/owasp_asvs_index.rego is stale: run scripts/gen_owasp_asvs_index.py", file=sys.stderr)
            return 1
        e = doc["expected"]
        print(f"owasp_asvs index current: {e['requirements']} requirements, in scope L1 {e['in_scope_level_1']} / L2 {e['in_scope_level_2']} / L3 {e['in_scope_level_3']}")
        return 0
    if bad:
        raise SystemExit("\n".join(bad))
    INDEX.write_text(build_index(doc))
    print("wrote governance/owasp_asvs/owasp_asvs_index.rego")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
