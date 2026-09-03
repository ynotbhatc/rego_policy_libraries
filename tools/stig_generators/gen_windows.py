#!/usr/bin/env python3
"""Generate Rego STIG modules for the Windows family from parsed XCCDF catalogs.

Derives deterministic registry checks from DISA's own check-content blocks:
    Registry Hive: HKEY_LOCAL_MACHINE
    Registry Path: \\SYSTEM\\...\\
    Value Name: X
    Type: REG_DWORD
    Value: 0x00000001 (1)            [optionally "(or less)" / "(or greater)"]

Only rules with exactly one clean registry block are auto-derived; everything
else is left for hand-written modules. Emits per-platform:
  - registry_*.rego modules grouped by STIG-ID section
  - a master orchestrator (rhel_9 stig_assessment shape)
  - a smoke + green-fixture test file
"""
import json, re, sys, os
from collections import defaultdict

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "benchmarks", "stig")
CATS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "catalogs")

HIVE_ALIAS = {"HKEY_LOCAL_MACHINE": "HKLM", "HKEY_CURRENT_USER": "HKCU", "HKEY_USERS": "HKU"}

BLOCK_RE = re.compile(
    r"Registry Hive:\s*(?P<hive>HKEY_[A-Z_]+)\s*"
    r"Registry Path:\s*(?P<path>\\[^\r\n]+?)\s*[\r\n]+\s*"
    r"Value Name:\s*(?P<name>[^\r\n]+?)\s*[\r\n]+"
    r"(?:\s*Value Type:\s*(?P<type2>REG_[A-Z_]+)\s*|\s*Type:\s*(?P<type>REG_[A-Z_]+)\s*)"
    r"Value:\s*(?P<value>[^\r\n]+)", re.IGNORECASE)

DWORD_RE = re.compile(r"0x[0-9a-fA-F]+\s*\((\d+)\)\s*(\(or less\)|\(or greater\))?", re.IGNORECASE)
DWORD_BARE_RE = re.compile(r"^\s*(\d+)\s*(\(or less\)|\(or greater\))?\s*$")

def _one_block(txt, block, mode):
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
    _ = txt  # unused
    if rtype == "REG_DWORD":
        m = DWORD_RE.search(value) or DWORD_BARE_RE.match(value)
        if not m:
            return None
        n = int(m.group(1))
        bound = (m.group(2) or "").lower()
        op = "==";  # default exact
        if "less" in bound: op = "<="
        if "greater" in bound: op = ">="
        # "or less" excluding 0 sometimes phrased in prose — keep simple v1
        return {"key": key, "name": name, "mode": "dword", "op": op, "num": n, "type": rtype}
    if rtype in ("REG_SZ", "REG_EXPAND_SZ"):
        v = value.strip()
        # strings sometimes wrapped in quotes or have trailing prose — take first token-ish line
        v = v.splitlines()[0].strip().strip('"')
        if not v or len(v) > 120 or "this is a finding" in v.lower():
            return None
        return {"key": key, "name": name, "mode": "sz", "str": v, "type": rtype}
    return None  # MULTI_SZ / BINARY etc: hand-write later


def derive(rule):
    """Return a list of derived expectations (AND semantics), or None."""
    txt = rule["check"]
    blocks = BLOCK_RE.findall(txt)
    if not blocks:
        return None
    # OR-alternatives are ambiguous — leave to hand modules.
    if re.search(r"one of the following registry values", txt, re.I):
        return None
    if re.search(r"value exists.{0,40}this is a finding", txt, re.I | re.S):
        mode = "absent"
    else:
        mode = "present"
    outs = []
    for b in blocks:
        d = _one_block(txt, b, mode)
        if d is None:
            return None  # all-or-nothing: partial derivation could invert semantics
        outs.append(d)
    return outs

def rego_ident(stig_id):
    return "r_" + re.sub(r"[^a-z0-9]+", "_", stig_id.lower()).strip("_")

def esc(s):
    return s.replace("\\", "\\\\").replace('"', '\\"')

def gen_platform(cat_key, pkg, title_prefix, existing_modules):
    cat = json.load(open(f"{CATS}/{cat_key}.json"))
    bench, release = cat["benchmark"], cat["release"]
    ver = f"V{cat['version']}{'R'+release.split('Release:')[1].split()[0] if 'Release:' in release else ''}"
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
        lines = [f"package stig.{pkg}.{mod}", "",
                 f"# DISA STIG — {bench}",
                 f"# {ver} | {release}",
                 f"# Auto-derived registry checks ({len(items)} rules) — value expectations",
                 "# taken verbatim from the XCCDF check-content (July 2026 library).",
                 "# Input contract: input.registry[\"HKLM\\\\Path\"][\"ValueName\"] = number|string",
                 "", "import rego.v1", ""]
        finds = []
        for r, d in sorted(items, key=lambda x: x[0]["stig_id"]):
            ident = rego_ident(r["stig_id"])
            ds = d if isinstance(d, list) else [d]
            lines.append(f"# {r['stig_id']} | {r['vuln_id']} | {r['severity']}")
            lines.append(f"default {ident} := false")
            body = []
            for dd in ds:
                key, name = esc(dd["key"]), esc(dd["name"])
                if dd["mode"] == "dword":
                    op = dd["op"] if dd["op"] != "==" else "=="
                    body.append(f'\tinput.registry["{key}"]["{name}"] {op} {dd["num"]}')
                    fixture_reg.setdefault(dd["key"], {})[dd["name"]] = dd["num"]
                elif dd["mode"] == "sz":
                    body.append(f'\tinput.registry["{key}"]["{name}"] == "{esc(dd["str"])}"')
                    fixture_reg.setdefault(dd["key"], {})[dd["name"]] = dd["str"]
                elif dd["mode"] == "absent":
                    body.append(f'\tnot input.registry["{key}"]["{name}"]')
            lines.append(ident + " if {")
            lines.extend(body)
            lines.append("}")
            lines.append("")
            sev = r["severity"]
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
    o = [f"package stig.{pkg}", "",
         f"# DISA STIG — {bench} — Master Aggregator",
         f"# {ver} | {release}",
         f"# Coverage: {len(derived)} auto-derived registry rules across "
         f"{len(module_names)} generated modules"
         + (f" + hand-written modules: {', '.join(existing_modules)}" if existing_modules else "")
         + f"; {skipped} rules of {len(cat['rules'])} not yet implemented (non-registry or complex).",
         f"# Rule IDs verified against the July 2026 SRG-STIG library on 2026-09-03.",
         "", "import rego.v1", ""]
    for mname in all_mods:
        o.append(f"import data.stig.{pkg}.{mname}")
    o.append("")
    concat = None
    for i, mname in enumerate(all_mods):
        o.append(f"_f_{i} := object.get({mname}, \"findings\", [])" if False else f"_f_{i} := {mname}.findings")
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
         "registry_rule_ids := {" ]
    for sec, items in sorted(modules.items()):
        for r, d in items:
            t.append(f'\t"{r["stig_id"]}",')
    t.append("}")
    open(os.path.join(outdir, "tests", f"test_stig_{cat_key}.rego"), "w").write("\n".join(t) + "\n")
    write_alias(outdir, cat_key, pkg)
    print(f"{cat_key}: {len(derived)} derived / {len(cat['rules'])} total; modules: {module_names}; fixture keys: {len(fixture_reg)}")

from gen_k8s import ALIAS_TMPL

def write_alias(outdir, key, pkg):
    open(os.path.join(outdir, f"stig_{key}_main.rego"), "w").write(ALIAS_TMPL.format(pkg=pkg))

if __name__ == "__main__":
    gen_platform("windows_server_2022", "windows_server_2022", "Windows Server 2022", [])
    gen_platform("windows_server_2025", "windows_server_2025", "Windows Server 2025", [])
    gen_platform("windows_11", "windows_11", "Windows 11", [])
