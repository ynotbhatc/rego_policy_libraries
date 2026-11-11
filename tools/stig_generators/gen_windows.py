#!/usr/bin/env python3
"""Generate Rego STIG modules for the Windows family from parsed XCCDF catalogs.

    python3 tools/stig_generators/parse_xccdf.py windows_11=<xml> windows_server_2022=<xml> ...
    python3 tools/stig_generators/gen_windows.py            # every platform in PLATFORMS
    python3 tools/stig_generators/gen_windows.py windows_11 # one platform

Derives deterministic registry checks from DISA's own check-content blocks:
    Registry Hive: HKEY_LOCAL_MACHINE
    Registry Path: \\SYSTEM\\...\\
    Value Name: X
    Type: REG_DWORD
    Value: 0x00000001 (1)            [optionally "(or less)" / "(or greater)"]

The Value line is read as DISA writes it (2026-11-10, after the WN22/WN25-CC-000130
hand fix in PR #248 showed the first-number-only reading inverted a rule):
  - alternatives     "0x00000001 (1), 0x00000003 (3), or 0x00000008 (8)"  -> value in {1, 3, 8}
  - bounds           "(or less)" / "or greater"                            -> <= / >=
  - excluded zero    "(or less, excluding 0)" / "(or less, but not 0)"     -> <= N and > 0
  - absent allowed   "(or if the Value Name does not exist)"               -> a second rule body
                     passes when registry facts were collected and the value is absent
  - REG_SZ numbers   "10 (or less)", "1 (Lock Workstation) or 2 (Force Logoff)"
                     -> to_number(value) <= 10 / in {1, 2}; other REG_SZ values compare exactly

Only rules whose registry blocks all derive cleanly are emitted (all-or-nothing per rule:
a partial derivation could invert the rule); OR-alternatives between blocks, MULTI_SZ,
BINARY and prose values are left for hand-written modules. Emits per platform:
  - registry_*.rego modules grouped by STIG-ID section (each with its METADATA block)
  - a master orchestrator (rhel_9 stig_assessment shape)
  - the framework-key alias with the fail-closed gate
  - a smoke + green-fixture test file
Hand-written tests in <platform>/tests/ (test_driver_load_policy.rego) are left alone.
"""
import json, re, sys, os
from collections import defaultdict

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "benchmarks", "stig")
CATS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "catalogs")

LIBRARY = "October 2026"      # DISA SRG-STIG Library compilation the catalogs were parsed from
VERIFIED = "2026-11-10"       # date the rule IDs were verified against it

# cat_key -> (package, platform label)
PLATFORMS = {
    "windows_11": ("windows_11", "Windows 11"),
    "windows_server_2016": ("windows_server_2016", "Windows Server 2016"),
    "windows_server_2019": ("windows_server_2019", "Windows Server 2019"),
    "windows_server_2022": ("windows_server_2022", "Windows Server 2022"),
    "windows_server_2025": ("windows_server_2025", "Windows Server 2025"),
}

SEV = {"high": "CAT I", "medium": "CAT II", "low": "CAT III"}   # DISA XCCDF severity -> STIG category

HIVE_ALIAS = {"HKEY_LOCAL_MACHINE": "HKLM", "HKEY_CURRENT_USER": "HKCU", "HKEY_USERS": "HKU"}

# One "Registry Hive / Registry Path" header followed by one or more value blocks
# (Value Name / Type / Value); DISA writes a rule with two values under one path as
# a header and two value blocks (Hardened UNC Paths, Virtualization Based Security).
HEAD_RE = re.compile(
    r"Registry Hive:\s*(?P<hive>HKEY_[A-Z_]+)\s*"
    r"Registry Path:\s*(?P<path>\\[^\r\n]+?)\s*[\r\n]", re.IGNORECASE)
VALUE_RE = re.compile(
    r"Value Name:\s*(?P<name>[^\r\n]+?)\s*[\r\n]+"
    r"(?:\s*Value Type:\s*(?P<type2>REG_[A-Z_]+)\s*|\s*Type:\s*(?P<type>REG_[A-Z_]+)\s*)"
    r"Value:\s*(?P<value>[^\r\n]+)", re.IGNORECASE)
VALUE_NAME_RE = re.compile(r"Value Name:", re.IGNORECASE)


def find_blocks(txt):
    """Every (hive, path, name, type2, type, value) block in a check text."""
    heads = list(HEAD_RE.finditer(txt))
    out = []
    for i, h in enumerate(heads):
        seg = txt[h.end():heads[i + 1].start() if i + 1 < len(heads) else len(txt)]
        for v in VALUE_RE.finditer(seg):
            out.append((h.group("hive"), h.group("path"), v.group("name"), v.group("type2"), v.group("type"), v.group("value")))
    return out


HEX_ALT_RE = re.compile(r"0x[0-9a-fA-F]+\s*\((\d+)\)")
PAREN_RE = re.compile(r"\([^)]*\)")


def parse_values(value):
    """Read a DISA Value line. Returns {nums, op, exclude_zero, allow_absent} or None.

    nums are the accepted values (several for "X, Y, or Z"); op is "==" (membership when
    several), "<=" or ">=". A bound with several numbers is ambiguous and returns None.
    """
    v = value.strip()
    low = v.lower()
    allow_absent = "does not exist" in low
    exclude_zero = bool(re.search(r'(excluding|but not)\s+"?0"?', low))
    op = "=="
    if "or less" in low:
        op = "<="
    if "or greater" in low:
        op = ">="
    nums = [int(x) for x in HEX_ALT_RE.findall(v)]
    if not nums:
        # bare numbers: drop parenthetical prose, split on comma / "or"
        bare = PAREN_RE.sub(" ", v)
        if not re.fullmatch(r"[\d\s,]+(?:or[\d\s,]+)*", bare.strip()):
            return None
        for tok in re.split(r",|\bor\b", bare):
            tok = tok.strip()
            if tok:
                if not tok.isdigit():
                    return None
                nums.append(int(tok))
    if not nums:
        return None
    if op != "==" and len(nums) > 1:
        return None
    if exclude_zero and op != "<=":
        return None
    return {"nums": nums, "op": op, "exclude_zero": exclude_zero, "allow_absent": allow_absent}


def _one_block(block, mode):
    hive, path, name, t2, t, value = block
    rtype = (t or t2).upper()
    hive = HIVE_ALIAS.get(hive.upper())
    if not hive:
        return None
    path = path.strip().rstrip("\\")
    name = name.strip()
    value = value.strip()
    key = hive + path
    if mode == "absent":
        return {"key": key, "name": name, "mode": "absent", "type": rtype}
    if rtype == "REG_DWORD":
        pv = parse_values(value)
        if not pv:
            return None
        return dict(key=key, name=name, mode="dword", type=rtype, **pv)
    if rtype in ("REG_SZ", "REG_EXPAND_SZ"):
        v = value.splitlines()[0].strip()
        pv = parse_values(v)
        if pv:
            # a numeric REG_SZ ("10 (or less)", "1 (Lock Workstation) or 2 (Force Logoff)"):
            # compare the number, so "10" and 10 both satisfy it
            return dict(key=key, name=name, mode="sz_num", type=rtype, **pv)
        v = v.strip('"')
        if not v or len(v) > 120 or "this is a finding" in v.lower() or "(or " in v.lower():
            return None
        return {"key": key, "name": name, "mode": "sz", "str": v, "type": rtype}
    return None  # MULTI_SZ / BINARY etc: hand-write later


def derive(rule):
    """Return a list of derived expectations (AND semantics), or None."""
    txt = rule["check"]
    blocks = find_blocks(txt)
    if not blocks:
        return None
    # a value block the parser did not read would leave a partial (over-lenient) rule
    if len(VALUE_NAME_RE.findall(txt)) != len(blocks):
        return None
    # OR-alternatives between blocks are ambiguous — leave to hand modules.
    if re.search(r"one of the following registry values", txt, re.I):
        return None
    if re.search(r"value exists.{0,40}this is a finding", txt, re.I | re.S):
        mode = "absent"
    else:
        mode = "present"
    outs = []
    for b in blocks:
        d = _one_block(b, mode)
        if d is None:
            return None  # all-or-nothing: partial derivation could invert semantics
        outs.append(d)
    # "absent is not a finding" needs a second rule body over the one block; with several
    # blocks the AND of present-or-absent clauses is not what DISA wrote — hand-write those.
    if len(outs) > 1 and any(d.get("allow_absent") for d in outs):
        return None
    return outs


def rego_ident(stig_id):
    return "r_" + re.sub(r"[^a-z0-9]+", "_", stig_id.lower()).strip("_")


def esc(s):
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _fixture_value(d):
    n = d["nums"][0]
    return str(n) if d["mode"] == "sz_num" else n


def _condition(ref, d):
    """The Rego condition line(s) for one derived block."""
    if d["mode"] == "sz_num":
        ref = f"to_number({ref})"
    nums = d["nums"]
    if d["op"] == "==":
        if len(nums) == 1:
            return [f"\t{ref} == {nums[0]}"]
        return [f"\t{ref} in {{{', '.join(str(n) for n in nums)}}}"]
    lines = [f"\t{ref} {d['op']} {nums[0]}"]
    if d["exclude_zero"]:
        lines.append(f"\t{ref} > 0")
    return lines


def metadata(title, pkg_key):
    return ["# METADATA", f'# title: "{esc(title)}"', "# custom:", "#   class: security",
            f"#   framework: stig_{pkg_key}", "#   source: disa", "#   domains: [windows]"]


def gen_platform(cat_key, pkg, title_prefix, existing_modules):
    cat = json.load(open(f"{CATS}/{cat_key}.json"))
    bench, ver = cat["benchmark"], cat["version"]
    release = f"Release: {cat['release']} Benchmark Date: {cat['release_date']}"
    derived, skipped = [], 0
    for r in cat["rules"]:
        d = derive(r)
        if d:
            derived.append((r, d))
        else:
            skipped += 1
    # group by section: WN22-CC / WN22-SO / etc → module per leading section
    groups = defaultdict(list)
    for r, d in derived:
        sec = r["stig_id"].split("-")[1] if "-" in r["stig_id"] else "misc"
        groups[sec.lower()].append((r, d))
    # merge small groups into 'other'
    modules = {}
    for sec, items in groups.items():
        tgt = sec if len(items) >= 8 else "other"
        modules.setdefault(tgt, []).extend(items)
    outdir = os.path.join(REPO, cat_key)
    os.makedirs(os.path.join(outdir, "tests"), exist_ok=True)
    fixture_reg = {}
    module_names = []
    for sec, items in sorted(modules.items()):
        mod = f"registry_{sec}"
        module_names.append(mod)
        lines = metadata(f"DISA STIG — {bench} — auto-derived registry checks ({mod})", cat_key)
        lines += [f"package stig.{pkg}.{mod}", "",
                  f"# DISA STIG — {bench}",
                  f"# {ver} | {release}",
                  f"# Auto-derived registry checks ({len(items)} rules) — value expectations",
                  f"# taken verbatim from the XCCDF check-content ({LIBRARY} library).",
                  "# Generated by tools/stig_generators/gen_windows.py — regenerate, don't hand-edit.",
                  "# Input contract: input.registry[\"HKLM\\\\Path\"][\"ValueName\"] = number|string",
                  "", "import rego.v1", ""]
        finds = []
        for r, d in sorted(items, key=lambda x: x[0]["stig_id"]):
            ident = rego_ident(r["stig_id"])
            sev = SEV[r["severity"]]
            lines.append(f"# {r['stig_id']} | {r['vuln_id']} | {sev}")
            lines.append(f"default {ident} := false")
            body = []
            absent_ok = None
            for dd in d:
                key, name = esc(dd["key"]), esc(dd["name"])
                ref = f'input.registry["{key}"]["{name}"]'
                if dd["mode"] == "absent":
                    body.append(f"\tnot {ref}")
                    continue
                if dd["mode"] == "sz":
                    body.append(f'\t{ref} == "{esc(dd["str"])}"')
                    fixture_reg.setdefault(dd["key"], {})[dd["name"]] = dd["str"]
                    continue
                body.extend(_condition(ref, dd))
                fixture_reg.setdefault(dd["key"], {})[dd["name"]] = _fixture_value(dd)
                if dd.get("allow_absent"):
                    absent_ok = ref
            if absent_ok:
                lines.append("# Check text: an absent value is not a finding. Absent counts only when registry")
                lines.append("# facts were collected at all; any other value is open.")
            lines.append(ident + " if {")
            lines.extend(body)
            lines.append("}")
            if absent_ok:
                lines += ["", ident + " if {", "\tis_object(input.registry)", "\tcount(input.registry) > 0",
                          f"\tnot _{ident[2:]}_value_set", "}", "",
                          f"_{ident[2:]}_value_set if {{", f"\t_ := {absent_ok}", "}"]
            lines.append("")
            title = esc(" ".join(r["title"].split())[:220])
            lines.append(f'finding_{ident} := {{')
            lines.append(f'\t"vuln_id": "{r["vuln_id"]}",')
            lines.append(f'\t"stig_id": "{r["stig_id"]}",')
            lines.append(f'\t"severity": "{sev}",')
            lines.append(f'\t"rule_title": "{title}",')
            lines.append(f'\t"status": status_{ident},')
            lines.append("}")
            lines.append(f'status_{ident} := "Not_a_Finding" if {ident}')
            lines.append(f'status_{ident} := "Open" if not {ident}')
            lines.append("")
            finds.append(f"finding_{ident}")
        lines.append("findings := [")
        for f in finds:
            lines.append(f"\t{f},")
        lines.append("]")
        lines.append("")
        lines.append("default compliant := false")
        lines.append("")
        lines.append('compliant if count([f | some f in findings; f.status == "Open"]) == 0')
        open(os.path.join(outdir, f"{mod}.rego"), "w").write("\n".join(lines) + "\n")

    # orchestrator
    all_mods = existing_modules + module_names
    o = metadata(f"DISA STIG — {bench} — Master Aggregator", cat_key)
    o += [f"package stig.{pkg}", "",
          f"# DISA STIG — {bench} — Master Aggregator",
          f"# {ver} | {release}",
          f"# Coverage: {len(derived)} auto-derived registry rules across "
          f"{len(module_names)} generated modules"
          + (f" + hand-written modules: {', '.join(existing_modules)}" if existing_modules else "")
          + f"; {skipped} rules of {len(cat['rules'])} not yet implemented (non-registry or complex).",
          f"# Rule IDs verified against the {LIBRARY} SRG-STIG library on {VERIFIED}.",
          "", "import rego.v1", ""]
    for mname in all_mods:
        o.append(f"import data.stig.{pkg}.{mname}")
    o.append("")
    for i, mname in enumerate(all_mods):
        o.append(f"_f_{i} := {mname}.findings")
    o.append("")
    prev = "_f_0"
    for i in range(1, len(all_mods)):
        cur = f"_acc_{i}"
        o.append(f"{cur} := array.concat({prev}, _f_{i})")
        prev = cur
    o.append(f"all_findings := {prev}" if len(all_mods) > 1 else "all_findings := _f_0")
    o += ["", 'open_findings := [f | some f in all_findings; f.status == "Open"]',
          'cat_i_open := [f | some f in open_findings; f.severity == "CAT I"]',
          "", "default overall_compliant := false",
          "overall_compliant if count(cat_i_open) == 0",
          "default fully_compliant := false",
          "fully_compliant if count(open_findings) == 0", "",
          "stig_assessment := {",
          '\t"metadata": {',
          f'\t\t"stig_title": "{esc(bench)}",',
          f'\t\t"version": "{ver}",',
          f'\t\t"release": "{esc(release)}",',
          f'\t\t"platform": "{esc(title_prefix)}",',
          '\t\t"assessed_host": object.get(input, ["system_info", "hostname"], "unknown"),',
          "\t},",
          '\t"summary": {',
          '\t\t"total_findings": count(all_findings),',
          '\t\t"open": count(open_findings),',
          '\t\t"not_a_finding": count(all_findings) - count(open_findings),',
          '\t\t"cat_i_open": count(cat_i_open),',
          '\t\t"overall_compliant": overall_compliant,',
          '\t\t"fully_compliant": fully_compliant,',
          "\t},",
          '\t"findings": all_findings,',
          "}", "",
          "# Uniform library entrypoint contract (consumed by the .main alias's",
          "# fail-closed gate).",
          "compliance_report := {",
          '\t"total_controls": count(all_findings),',
          '\t"open_findings": open_findings,',
          '\t"passed_controls": count(all_findings) - count(open_findings),',
          '\t"failed_controls": count(open_findings),',
          '\t"compliant": fully_compliant,',
          "}"]
    open(os.path.join(outdir, f"stig_{cat_key}_complete.rego"), "w").write("\n".join(o) + "\n")

    # tests: smoke + green fixture
    fixture = json.dumps({"registry": fixture_reg}, indent=1).replace("\n", "\n\t")
    t = [f"package stig.{pkg}_test", "", "import rego.v1", f"import data.stig.{pkg}", "",
         "# Contract smoke: aggregate report is well-formed on empty input.",
         "test_report_wellformed_on_empty_input if {",
         f"\treport := {pkg}.stig_assessment with input as {{}}",
         "\tis_object(report)",
         "\treport.summary.total_findings > 0",
         "\treport.summary.open == report.summary.total_findings - report.summary.not_a_finding",
         "}", "",
         "# Green path: a registry set satisfying every auto-derived expectation",
         "# closes every generated finding (hand-written modules may stay open).",
         f"green_fixture := {fixture}", "",
         "test_generated_registry_rules_pass_on_green_fixture if {",
         f"\treport := {pkg}.stig_assessment with input as green_fixture",
         "\topen_reg := [f | some f in report.findings;",
         '\t\tf.status == "Open"',
         f'\t\tstartswith(f.stig_id, "{cat["rules"][0]["stig_id"].split("-")[0]}-")',
         "\t\tregistry_rule_ids[f.stig_id]",
         "\t]",
         "\tcount(open_reg) == 0",
         "}", "",
         "registry_rule_ids := {"]
    for sec, items in sorted(modules.items()):
        for r, d in items:
            t.append(f'\t"{r["stig_id"]}",')
    t.append("}")
    open(os.path.join(outdir, "tests", f"test_stig_{cat_key}.rego"), "w").write("\n".join(t) + "\n")
    write_alias(outdir, cat_key, pkg, bench)
    print(f"{cat_key}: {ver} ({cat['release_date']}): {len(derived)} derived / {len(cat['rules'])} total; "
          f"modules: {module_names}; fixture keys: {len(fixture_reg)}")


from gen_k8s import ALIAS_TMPL


def write_alias(outdir, key, pkg, bench):
    alias = ALIAS_TMPL.format(pkg=pkg)
    meta = "\n".join(metadata(f"Framework-key entrypoint alias with the fail-closed gate — {bench}", key))
    alias = alias.replace("package stig.", meta + "\npackage stig.", 1)   # METADATA must sit directly above package
    open(os.path.join(outdir, f"stig_{key}_main.rego"), "w").write(alias)


if __name__ == "__main__":
    keys = sys.argv[1:] or list(PLATFORMS)
    for key in keys:
        pkg, label = PLATFORMS[key]
        gen_platform(key, pkg, label, [])
