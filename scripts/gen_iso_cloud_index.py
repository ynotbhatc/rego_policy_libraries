#!/usr/bin/env python3
"""Generate the control indexes of the two ISO cloud delta modules: iso_27017 and iso_27018.

    ISO/IEC 27017:2026   frameworks/management/iso_27017/iso_27017_index.rego   (4 additional cloud controls)
    ISO/IEC 27018:2019   frameworks/privacy/iso_27018/iso_27018_index.rego      (25 Annex A extended controls)

Both modules are deltas on ISO/IEC 27001 Annex A / ISO/IEC 27002: their scope is only what the standard adds. The
control identifiers come from the publishers' public previews and a national standards body's public table of
contents (URL, fetch date and sha256 of each file are recorded in scripts/iso_cloud_controls.json); no ISO text is read
into or written to this repository (ISO texts are copyrighted and are not licensed for reproduction). The labels are
this library's own short words, not the standards' titles.

    python3 scripts/gen_iso_cloud_index.py           # write both index files
    python3 scripts/gen_iso_cloud_index.py --check   # exit 1 if an index or the committed list is stale or malformed
No network access in any mode; standard library only. Formatting goes through `opa fmt` ($OPA, as the Makefile sets
it). Deterministic.

Committed list (scripts/iso_cloud_controls.json; everything sits under one top-level key, "iso_cloud_controls", because
`opa test .` loads the JSON files of scripts/ as data.scripts.<top-level key> and two files may not share one): per
standard the edition, its sources, the facts that could NOT be verified, the expected counts and one row per control.
"""
import json, os, pathlib, re, subprocess, sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
LIST = ROOT / "scripts/iso_cloud_controls.json"
OPA = os.environ.get("OPA", "opa")
TOP = "iso_cloud_controls"
ID_27017 = re.compile(r"^([58])\.(\d+)$")
ID_27018 = re.compile(r"^(A\.\d+)\.(\d+)$")
TARGETS = {
    "iso_27017": ROOT / "frameworks/management/iso_27017/iso_27017_index.rego",
    "iso_27018": ROOT / "frameworks/privacy/iso_27018/iso_27018_index.rego",
}


def load():
    return json.loads(LIST.read_text())[TOP]


def dump(doc):
    """One control per line, everything else indented JSON, so a later edition's diff is readable."""
    stub = {k: (v if k == "_comment" else {**v, "controls": "@@" + k}) for k, v in doc.items()}
    text = json.dumps({TOP: stub}, indent=1)
    for k, v in doc.items():
        if k != "_comment":
            rows = ",\n".join("     " + json.dumps(r) for r in v["controls"])
            text = text.replace(json.dumps("@@" + k), "[\n" + rows + "\n    ]")
    return text + "\n"


def nat(i):
    return tuple(int(x) for x in re.findall(r"\d+", i))


def problems(doc):
    out = []
    for key in ("iso_27017", "iso_27018"):
        sec = doc.get(key)
        if not sec:
            out.append(f"{key}: section missing")
            continue
        rows = sec["controls"]
        ids = [r[0] for r in rows]
        if len(set(ids)) != len(ids):
            out.append(f"{key}: a control id is repeated")
        if ids != sorted(ids, key=nat):
            out.append(f"{key}: controls are not in natural id order")
        for r in rows:
            if len(r) != 3 or not all(isinstance(x, str) and x.strip() for x in r):
                out.append(f"{key}: row {r} is not [id, group, label]")
        if not sec["sources"] or any(not x["url"].startswith("https://") or not x["fetched"] for x in sec["sources"]):
            out.append(f"{key}: every source needs an https url and a fetch date")
        if not sec["unverified"]:
            out.append(f"{key}: the UNVERIFIED list is empty")
        if key == "iso_27017":
            for i, g, _ in rows:
                if not ID_27017.match(i) or g != {"5": "organizational", "8": "technological"}[i[0]]:
                    out.append(f"{i}: id or theme malformed")
            exp = {"controls": len(rows), "organizational": sum(r[1] == "organizational" for r in rows),
                   "technological": sum(r[1] == "technological" for r in rows)}
        else:
            for i, g, _ in rows:
                m = ID_27018.match(i)
                if not m or g != m[1] or g not in sec["groups"]:
                    out.append(f"{i}: id or group malformed")
            exp = {"controls": len(rows), "groups": len({r[1] for r in rows})}
            if set(sec["groups"]) != {r[1] for r in rows}:
                out.append("iso_27018: group labels cover other groups than the controls")
        if exp != sec["expected"]:
            out.append(f"{key}: counts {exp} differ from the recorded {sec['expected']}")
    return out


def s(x):
    return json.dumps(x)


def build_27017(sec):
    rows = sec["controls"]
    o = ['# METADATA', '# title: "ISO/IEC 27017:2026 — static index of the 4 additional cloud controls (id, theme, own label); generated"',
         '# custom:', '#   class: compliance', '#   framework: iso_27017', '#   source: iso', '#   domains: [cloud, isms]',
         'package iso_27017.index', '', 'import rego.v1', '',
         '# GENERATED by scripts/gen_iso_cloud_index.py from scripts/iso_cloud_controls.json: do not edit; re-run the script.',
         '# Source: the contents of ISO/IEC 27017:2026 (second edition, 2026-07) in the publisher\'s public preview, see the list file for',
         '# URL, fetch date and sha256. Only the four identifiers of the additional (CLD) controls are taken; no ISO text.',
         '# The labels are this library\'s own words.', '',
         '# The additional controls in the standard\'s order.', 'order := [']
    o += [f'\t{s(r[0])},' for r in rows]
    o += [']', '', '# Theme of each control (the ISO/IEC 27002:2022 clause its number sits in).', 'themes := {']
    o += [f'\t{s(r[0])}: {s(r[1])},' for r in rows]
    o += ['}', '', '# This library\'s own short labels.', 'labels := {']
    o += [f'\t{s(r[0])}: {s(r[2])},' for r in rows]
    o += ['}', '', '# Every control, as the findings write it. Read by scripts/inventory_controls.py so the OSCAL catalog and the',
          '# exports know the controls; no rule reads it.', 'CONTROL_INDEX := [']
    o += [f'\t{{"id": {s("ISO/IEC 27017 " + r[0])}, "theme": {s(r[1])}}},' for r in rows]
    o += [']']
    return fmt(o, TARGETS["iso_27017"], "#   domains: [cloud, isms]")


def build_27018(sec):
    rows = sec["controls"]
    o = ['# METADATA', '# title: "ISO/IEC 27018:2019 — static index of the 25 Annex A extended controls (id, group, own label); generated"',
         '# custom:', '#   class: compliance', '#   framework: iso_27018', '#   source: iso', '#   domains: [privacy, cloud]',
         'package iso_27018.index', '', 'import rego.v1', '',
         '# GENERATED by scripts/gen_iso_cloud_index.py from scripts/iso_cloud_controls.json: do not edit; re-run the script.',
         '# Source: the Annex A contents of ISO/IEC 27018:2019 (second edition, 2019-01) as published by DIN, see the list file for URL,',
         '# fetch date and sha256. Only the 25 identifiers are taken; no ISO text. The labels are this library\'s own words.',
         '# The 2025 third edition is not covered: its Annex A identifiers are unverified (see the module header).', '',
         '# The extended controls in the standard\'s order.', 'order := [']
    o += [f'\t{s(r[0])},' for r in rows]
    o += [']', '', '# Group (Annex A subclause, one per privacy principle) of each control.', 'groups := {']
    o += [f'\t{s(r[0])}: {s(r[1])},' for r in rows]
    o += ['}', '', '# The controls of each group, in the standard\'s order.', 'by_group := {']
    for g in sec["groups"]:
        o.append(f'\t{s(g)}: [{", ".join(s(r[0]) for r in rows if r[1] == g)}],')
    o += ['}', '', '# This library\'s own short group labels.', 'group_labels := {']
    o += [f'\t{s(g)}: {s(l)},' for g, l in sec["groups"].items()]
    o += ['}', '', '# This library\'s own short control labels.', 'labels := {']
    o += [f'\t{s(r[0])}: {s(r[2])},' for r in rows]
    o += ['}', '', '# Every control, as the findings write it. Read by scripts/inventory_controls.py so the OSCAL catalog and the',
          '# exports know the controls; no rule reads it.', 'CONTROL_INDEX := [']
    o += [f'\t{{"id": {s("ISO/IEC 27018 " + r[0])}, "group": {s(r[1])}}},' for r in rows]
    o += [']']
    return fmt(o, TARGETS["iso_27018"], "#   domains: [privacy, cloud]")


def fmt(lines, path, anchor):
    r = subprocess.run([OPA, "fmt"], input="\n".join(lines) + "\n", capture_output=True, text=True, check=True)
    return keep_stamp(r.stdout, path, anchor)


def keep_stamp(text, path, anchor):
    """Carry over the coverage block scripts/coverage_stamp.py writes into the METADATA: the stamp is the stamper's."""
    if not path.exists():
        return text
    block, on = [], False
    for l in path.read_text().splitlines():
        if l == "#   coverage:":
            on = True
        elif on and not l.startswith("#     "):
            break
        if on:
            block.append(l)
    if not block:
        return text
    t = text.splitlines()
    i = t.index(anchor) + 1
    return "\n".join(t[:i] + block + t[i:]) + "\n"


def main(argv):
    doc = load()
    bad = problems(doc)
    built = {} if bad else {"iso_27017": build_27017(doc["iso_27017"]), "iso_27018": build_27018(doc["iso_27018"])}
    if "--check" in argv:
        if not bad and LIST.read_text() != dump(doc):
            bad.append("scripts/iso_cloud_controls.json is not in the generator's layout")
        for k, p in TARGETS.items():
            if not bad and (not p.exists() or p.read_text() != built[k]):
                bad.append(f"{p.relative_to(ROOT)} is stale: run scripts/gen_iso_cloud_index.py")
        if bad:
            print("\n".join(bad), file=sys.stderr)
            return 1
        a, b = doc["iso_27017"]["expected"], doc["iso_27018"]["expected"]
        print(f"iso cloud indexes current: ISO/IEC 27017:{doc['iso_27017']['edition']} {a['controls']} controls, "
              f"ISO/IEC 27018:{doc['iso_27018']['edition']} {b['controls']} controls")
        return 0
    if bad:
        raise SystemExit("\n".join(bad))
    for k, p in TARGETS.items():
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(built[k])
        print(f"wrote {p.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
