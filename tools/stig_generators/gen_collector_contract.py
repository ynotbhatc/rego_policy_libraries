#!/usr/bin/env python3
"""The Linux STIG collector contract: every input fact path the gen_rhel9.py modules read, from the reviewed tables.

    python3 tools/stig_generators/gen_collector_contract.py           # writes benchmarks/stig/LINUX_COLLECTOR_CONTRACT.md
    python3 tools/stig_generators/gen_collector_contract.py --check   # fails if the file is stale, or if a generated
                                                                       # module reads an input path the document lacks

Sources (no XCCDF catalog needed): the RULES and SECTION_HELPERS of every table in gen_rhel9.PLATFORMS
(rhel9_rules.py, ol9_rules.py, ol8_rules.py, rhel10_rules.py). Per rule:
  - required evidence: spec["ev"] (absent or null -> Open "evidence missing");
  - read paths: every path literal in the rule's bodies (alts, attestation alternatives, Not Applicable clauses) and
    in the section helpers those bodies reference, transitively: `_str/_kw/_num/_collected([...])`,
    `object.get(input, [...], ...)`, `input.a.b["c"]`, `_attested("key")`;
  - types and example values: the rule's pass fixture (`green`, `green_na`, `pass_cases`, `na_cases`).
The cross-check scans the generated section modules under benchmarks/stig/<platform>/ for the same reference
forms and fails on a path the document does not list (the tables and the modules must agree).
"""
import importlib, json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
OUT = os.path.join(ROOT, "benchmarks", "stig", "LINUX_COLLECTOR_CONTRACT.md")

import gen_rhel9  # noqa: E402  (PLATFORMS, SECTIONS, HELPERS: importing it runs nothing)
from linux_stig_table import _chunks, _idents  # noqa: E402

NAMES = {"rhel_9": "RHEL 9", "oracle_linux_9": "Oracle Linux 9", "oracle_linux_8": "Oracle Linux 8", "rhel_10": "RHEL 10"}
SHORT = {"rhel_9": "R9", "oracle_linux_9": "OL9", "oracle_linux_8": "OL8", "rhel_10": "R10"}
ACCESSORS = {
    "_str": "string, or integer (read as its decimal text); trimmed",
    "_kw": "string, or integer; trimmed and compared case-insensitively",
    "_num": "number, or string holding a decimal integer",
    "_collected": "any non-null value (presence)",
}

# a path argument: a JSON-ish list literal whose elements are strings or Rego variables
_LIST = r"\[((?:[^\[\]]|\[[^\[\]]*\])*)\]"
RE_ACC = re.compile(r"\b(_str|_kw|_num|_collected)\(\s*" + _LIST + r"\s*\)")
RE_GET = re.compile(r"object\.get\(\s*input\s*,\s*" + _LIST)
RE_INPUT = re.compile(r"\binput((?:\.[A-Za-z_][A-Za-z0-9_]*|\[\"[^\"]+\"\]|\[[A-Za-z_][A-Za-z0-9_]*\])+)")
RE_ATTEST = re.compile(r"_attested\(\s*\"([^\"]+)\"\s*\)")


def _elems(s):
    out = []
    for e in [x.strip() for x in s.split(",") if x.strip()]:
        out.append(json.loads(e) if e.startswith('"') else "<" + e + ">")
    return tuple(out)


def _input_path(s):
    out = []
    for m in re.finditer(r"\.([A-Za-z_][A-Za-z0-9_]*)|\[\"([^\"]+)\"\]|\[([A-Za-z_][A-Za-z0-9_]*)\]", s):
        out.append(m.group(1) or m.group(2) or "<" + m.group(3) + ">")
    return tuple(out)


def refs(text):
    """(path tuple, accessor or None) for every input reference in Rego text."""
    found = []
    for m in RE_ACC.finditer(text):
        found.append((_elems(m.group(2)), m.group(1)))
    for m in RE_GET.finditer(text):
        found.append((_elems(m.group(1)), None))
    for m in RE_INPUT.finditer(text):
        p = _input_path(m.group(1))
        if p and p[0] == "attest" and (len(p) == 1 or p[1].startswith("<")):
            continue  # `input.attest[key]` inside the _attested helper: the call sites name the keys
        found.append((p, None))
    for m in RE_ATTEST.finditer(text):
        found.append((("attest", m.group(1)), "attest"))
    # a variable element is a parameter (`path`, `key`), not a fact: the call sites name the fact
    return [(p, a) for p, a in found if p and not (len(p) == 1 and p[0].startswith("<"))]


def jtype(v):
    if isinstance(v, bool):
        return "boolean"
    if isinstance(v, (int, float)):
        return "number"
    if isinstance(v, str):
        return "string"
    if v is None:
        return "null"
    if isinstance(v, list):
        kinds = sorted({jtype(x) for x in v})
        return "array" + (" of " + "/".join(kinds) if kinds else "")
    return "object"


def leaves(obj, prefix=()):
    """(path, value) for each leaf of a fixture; an array of objects contributes `path[]` and its members' keys."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from leaves(v, prefix + (k,))
        return
    yield prefix, obj
    if isinstance(obj, list) and obj and all(isinstance(x, dict) for x in obj):
        for x in obj:
            for k, v in x.items():
                yield from leaves(v, prefix + ("[]", k))


def rule_paths(spec, pool):
    """Every (path, accessor) the rule reads: its bodies plus the helpers they reference, transitively."""
    bodies = "\n".join("\n".join(alt) for alt in spec["alts"] + spec.get("attest_alts", []) + spec.get("na", []))
    seen, todo, text = set(), _idents(bodies), [bodies]
    while todo:
        n = todo.pop()
        if n in seen:
            continue
        seen.add(n)
        for name, para in pool:
            if name == n:
                text.append(para)
                todo |= _idents(para) - seen
    return refs("\n".join(text))


def collect():
    paths = {}   # path -> {"types": set, "acc": set, "ex": value, "rules": {plat: set}, "required": set}
    rules = {}   # plat -> [(sid, spec, evidence paths)]
    for plat, cfg in gen_rhel9.PLATFORMS.items():
        tbl = importlib.import_module(cfg["table"])
        base = _chunks(gen_rhel9.HELPERS)
        rules[plat] = []
        for sid, spec in tbl.RULES.items():
            pool = base + _chunks(tbl.SECTION_HELPERS.get(spec["sec"], ""))
            rules[plat].append((sid, spec))

            def add(p, acc=None, val=None, typed=False, required=False):
                e = paths.setdefault(p, {"types": set(), "acc": set(), "ex": None, "rules": {}, "required": set(), "means": None})
                e["rules"].setdefault(plat, set()).add(sid)
                if acc:
                    e["acc"].add(acc)
                if typed:
                    e["types"].add(jtype(val))
                    if e["ex"] is None and val is not None:
                        e["ex"] = val
                if required:
                    e["required"].add(plat)
                    if e["means"] is None:
                        e["means"] = f"{sid}: " + (spec.get("comment") or spec["expect"])
            for p in spec["ev"]:
                add(tuple(p), required=True)
            read = rule_paths(spec, pool)
            for p, acc in read:
                add(p, acc)
            for fx in [spec["green"], spec.get("green_na") or {}] + spec.get("pass_cases", []) + spec.get("na_cases", []):
                for p, v in leaves(fx):
                    # a fixture key a helper reads through a variable (`_kw(["sshd_runtime", k])`) takes its accessor
                    accs = {a for q, a in read if a and a != "attest" and matches(q, p)}
                    add(p, val=v, typed=True)
                    for a in accs:
                        add(p, a)
    return paths, rules


def matches(q, p):
    """q (which may hold `<var>` elements) names the same fact as p."""
    return len(q) == len(p) and all(a == b or a.startswith("<") or b.startswith("<") for a, b in zip(q, p))


def type_of(types):
    t = set(types) - {"null"}
    if any(x.startswith("array of") for x in t):
        t.discard("array")
    return "/".join(sorted(t))


def fmt_path(p):
    out = ""
    for k in p:
        if k == "[]":
            out += "[]"
        elif re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", k) or k.startswith("<"):
            out += ("." if out else "") + k
        else:
            out += f'["{k}"]'
    return out


def cell(s, n=70):
    s = str(s).replace("|", "\\|").replace("\n", " ")
    return s if len(s) <= n else s[: n - 1] + "…"


def ex(v):
    if v is None:
        return ""
    return "`" + cell(json.dumps(v, ensure_ascii=False), 60).replace("`", "'") + "`"


def ids(rs):
    rs = sorted(rs)
    return ", ".join(rs) if len(rs) <= 6 else ", ".join(rs[:5]) + f" … (+{len(rs) - 5})"


HEAD = """# Linux STIG collector contract

<!-- Generated by tools/stig_generators/gen_collector_contract.py from the reviewed rule tables. Do not edit:
     change the table, regenerate the modules (gen_rhel9.py) and this file; `make check-generated` fails when stale. -->

The input document the DISA STIG modules for RHEL 9, Oracle Linux 9, Oracle Linux 8 and RHEL 10 evaluate
(`data.stig.<platform>.main.compliance_report`). All four are generated by `tools/stig_generators/gen_rhel9.py`
from their reviewed tables; this file lists every fact path those rules read, so a collector can be built
and checked against it. Paths are nested JSON objects under `input` (`fips.fips_enabled` is
`{"fips": {"fips_enabled": "1"}}`), never flat dotted keys and never renamed facts (a `fips_mode` boolean
is not read by any rule: RHEL-09-671010 reports `evidence missing — fips.fips_enabled not collected`).

## How the rules read a fact

- **Required evidence** (column *Req*): a rule lists these paths; when one is absent or `null` the finding is
  `Open` with detail `<STIG-ID>: evidence missing — <path> not collected`. Other read paths are conditional
  (read only in a branch, e.g. a service's config when its package is installed).
- **Accepted** (from the helper the rule reads it through):
  `_str` string or integer (decimal text), trimmed; `_kw` the same, compared case-insensitively;
  `_num` a number or a string holding a decimal integer (anything else is not a pass);
  `_collected` presence only. A path read directly (`input.x`) takes the fixture type; a boolean passes only
  on `true` (or the literal the rule compares with).
- **Collect the observed value, not a verdict**: the policy holds the expected value (`"1"`, `"masked"`, a
  minimum length); the collector reports the raw setting, file content or offender list.
- **Attestations** (`attest.<key>`, boolean `true`): the check's "ask the SA / documented with the ISSO"
  clauses. Absent means not attested. They are listed separately below.
- **Type** and **Example** come from the rule's pass fixture (the generated tests use the same values).
  `[]` marks the members of an array of objects. `<name>` is a key the rule supplies from a variable
  (e.g. one sysctl name per rule).
"""


def render(paths, rules):
    plats = list(gen_rhel9.PLATFORMS)
    facts = {p: e for p, e in paths.items() if p[0] != "attest"}
    att = {p: e for p, e in paths.items() if p[0] == "attest"}
    o = [HEAD]
    o.append("## Rule counts\n")
    o.append("| Platform | Table | Rules | Fact paths read | Attestation keys |")
    o.append("|---|---|---:|---:|---:|")
    for plat in plats:
        n_f = sum(1 for e in facts.values() if plat in e["rules"])
        n_a = sum(1 for e in att.values() if plat in e["rules"])
        o.append(f"| {NAMES[plat]} (`{plat}`) | `{gen_rhel9.PLATFORMS[plat]['table']}.py` | {len(rules[plat])} | {n_f} | {n_a} |")
    o.append("")
    o.append("## Fact paths\n")
    o.append("Platforms: " + ", ".join(f"{SHORT[p]} = {NAMES[p]}" for p in plats) + ". *Req* lists the platforms "
             "where at least one rule names the path as required evidence.\n")
    o.append("| Path | Type | Accepted | Req | Example (pass) | Meaning (first rule that requires it) | Read by |")
    o.append("|---|---|---|---|---|---|---|")
    for p in sorted(facts, key=lambda q: tuple(x.lower() for x in q)):
        e = facts[p]
        variable = any(k.startswith("<") for k in p)
        if variable and any(q != p and not any(k.startswith("<") for k in q) and matches(p, q) for q in facts):
            continue  # the concrete keys are listed (`modprobe["usb-storage"]` for `modprobe.<mod>`)
        types = type_of(e["types"]) or ("object" if any(
            len(q) > len(p) and q[: len(p)] == p for q in facts) else "")
        acc = "; ".join(sorted(a for a in e["acc"] if a != "attest"))
        req = " ".join(SHORT[x] for x in plats if x in e["required"])
        by = "<br>".join(f"{SHORT[x]}: {ids(e['rules'][x])}" for x in plats if x in e["rules"])
        means = cell(e["means"], 140) if e["means"] else ""
        o.append(f"| `{cell(fmt_path(p), 90)}` | {types} | {acc} | {req} | {ex(e['ex'])} | {means} | {by} |")
    o.append("")
    o.append("## Attestation keys\n")
    o.append("Each is `input.attest.<key> == true`; the rule id is in the key.\n")
    o.append("| Key | Platforms |")
    o.append("|---|---|")
    for p in sorted(att):
        o.append(f"| `{p[1]}` | {' '.join(SHORT[x] for x in plats if x in att[p]['rules'])} |")
    o.append("")
    for plat in plats:
        o.append(f"## {NAMES[plat]} rules ({len(rules[plat])})\n")
        o.append("| Rule | Section | Required evidence | The check requires |")
        o.append("|---|---|---|---|")
        for sid, spec in sorted(rules[plat]):
            ev = ", ".join(f"`{fmt_path(tuple(p))}`" for p in spec["ev"]) or "(attestation / Not Applicable facts only)"
            o.append(f"| {sid} | {spec['sec']} | {ev} | {cell(spec['expect'], 160)} |")
        o.append("")
    return "\n".join(o).rstrip() + "\n"


def module_refs():
    """Input paths the generated section modules read (the same reference forms), per platform."""
    out = {}
    for plat in gen_rhel9.PLATFORMS:
        for sec in gen_rhel9.SECTIONS:
            f = os.path.join(ROOT, "benchmarks", "stig", plat, f"{sec}.rego")
            if os.path.exists(f):
                for p, _ in refs(open(f).read()):
                    out.setdefault(p, set()).add(f"{plat}/{sec}.rego")
    return out


def main(argv):
    paths, rules = collect()
    text = render(paths, rules)
    if "--check" not in argv:
        open(OUT, "w").write(text)
        print(f"wrote {os.path.relpath(OUT, ROOT)}: {sum(1 for p in paths if p[0] != 'attest')} fact paths, "
              + ", ".join(f"{p} {len(r)} rules" for p, r in rules.items()))
        return 0
    bad = []
    if not os.path.exists(OUT) or open(OUT).read() != text:
        bad.append(f"{os.path.relpath(OUT, ROOT)} is stale: run python3 tools/stig_generators/gen_collector_contract.py")
    for p, files in sorted(module_refs().items()):
        # a module reference is covered when the document lists the path, or one under it, or (for a
        # variable element) a sibling at that depth
        if not any(q[: len(p)] == p or matches(p, q) for q in paths):
            bad.append(f"{fmt_path(p)} is read by {', '.join(sorted(files))} but is not in the contract")
    for b in bad:
        print("ERROR:", b)
    if not bad:
        print("Linux STIG collector contract current")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
