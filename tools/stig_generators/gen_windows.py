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
                     -> the value is a string of decimal digits and to_number(value) <= 10 / in {1, 2};
                     other REG_SZ values compare exactly

Rules whose check text asks for more than the registry block are written as DISA states them
(2026-11-24, from the XCCDF check text of the pinned releases):
  - LegalNoticeText   the value must be the Standard Mandatory DoD Notice and Consent Banner the
                      check prints, compared after white-space normalisation (see BANNER_NOTE)
  - LegalNoticeCaption one of the titles the check names, or an organization-defined title whose
                      manual review is attested (input.attest.<id>_organization_defined_title)
  - Win32_DeviceGuard the finding conditions are the WMI properties; the check says the registry
                      values "alone do not ensure proper function", so those rules read
                      input.device_guard and not the policy registry values
  - Transcript output directory: the registry value and an attested review of the directory
                      permissions (input.attest.<id>_transcript_directory_acl)

Only rules whose registry blocks all derive cleanly are emitted (all-or-nothing per rule:
a partial derivation could invert the rule); OR-alternatives between blocks, MULTI_SZ,
BINARY and prose values are left for hand-written modules. Emits per platform:
  - registry_*.rego modules grouped by STIG-ID section (each with its METADATA block)
  - a master orchestrator (rhel_9 stig_assessment shape)
  - the framework-key alias with the fail-closed gate
  - a smoke + green-fixture test file, and tests/test_stig_<platform>_check_text.rego for the
    rules above and the absent-allowed rules
Each module's coverage block (written by `make coverage`) is carried over from the file on disk, and
the output is formatted with `opa fmt` ($OPA, else `opa` on PATH), so a run on an unchanged catalog
reproduces the committed files byte for byte.
Hand-written tests in <platform>/tests/ (test_driver_load_policy.rego) are left alone.
"""
import hashlib, json, re, shutil, subprocess, sys, os
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
    r"Value:\s*(?P<value>[^\r\n]+(?:\r?\n[ \t]*0x[0-9a-fA-F]+[^\r\n]*)*)", re.IGNORECASE)
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


def clean_path(path):
    """DISA pads paths with prose and stray spaces ("\\  (For GPO-managed systems)", "\\SOFTWARE\\ Policies"):
    drop trailing parenthetical prose and whitespace around separators so the key can match a fact."""
    path = re.sub(r"\\\s*\(.*$", "", path.strip())
    path = re.sub(r"\s*\\\s*", r"\\", path)
    return path.strip().rstrip("\\")


# The Standard Mandatory DoD Notice and Consent Banner, as every pinned Windows STIG prints it in the
# LegalNoticeText check (identical in Windows 11 V2R11, Server 2016 V2R10, 2019 V3R9, 2022 V2R11 and
# 2025 V1R4). The text is read from the catalog; this is the SHA-256 of its normalised form, so a
# release that changes the wording stops generation until the change has been read.
BANNER_SHA256 = "89f65c08830eb33b159ed8c86b4d1624c05245b33cb02fd30837fe3cef9cd98e"
BANNER_START = "You are accessing a U.S. Government (USG) Information System (IS)"
BANNER_NOTE = [
    "# Check text: the value must be the Standard Mandatory DoD Notice and Consent Banner the check prints.",
    "# The collected REG_SZ is compared with that text after one normalisation: every run of the ASCII",
    "# white-space characters space, tab, line feed, form feed and carriage return becomes one space, and",
    "# leading and trailing spaces are removed. Case, punctuation and hyphens must match as printed; a part of",
    "# the banner, the banner with other text added, or any other text is a finding.",
]


def normalise_space(s):
    """The normalisation the generated _normalise_space applies (ASCII white space only)."""
    return re.sub(r"[ \t\n\f\r]+", " ", s).strip(" ")


def banner_paragraphs(txt):
    """The banner in a LegalNoticeText check, one normalised string per paragraph."""
    if BANNER_START not in txt:
        raise SystemExit("LegalNoticeText check without the DoD banner text: read the check and update the generator")
    body = txt[txt.index(BANNER_START):]
    paras = [normalise_space(p) for p in re.split(r"\r?\n[ \t]*\r?\n", body) if p.strip()]
    got = hashlib.sha256(" ".join(paras).encode()).hexdigest()
    if got != BANNER_SHA256:
        raise SystemExit(f"the banner text in the LegalNoticeText check changed (sha256 {got}): read it, then update BANNER_SHA256")
    return paras


CAPTION_LINE_RE = re.compile(r'^(.*"[^"]+".*organization-defined equivalent.*)$', re.M)


def caption_titles(txt):
    """The titles a LegalNoticeCaption check names. The check allows "an organization-defined equivalent"
    and says a manual review is then required; anything else in the text stops generation."""
    m = CAPTION_LINE_RE.search(txt)
    if not m or "manual review will be required" not in txt:
        raise SystemExit("LegalNoticeCaption check text is not the titles-or-equivalent form: read it and update the generator")
    titles = re.findall(r'"([^"]+)"', m.group(1))
    if not titles:
        raise SystemExit("LegalNoticeCaption check names no title")
    return titles


# Win32_DeviceGuard finding conditions, as the check words them
DG_INCLUDES_RE = re.compile(r'If "(\w+)" does not include a value of "(\d+)"')
DG_EQUALS_RE = re.compile(r'If "(\w+)" is not a value of "(\d+)"')


def device_guard(txt):
    """The WMI conditions of a Win32_DeviceGuard check (the PowerShell half; the System Information half
    after "Alternately:" states the same conditions in display words)."""
    part = txt.split("Alternately:")[0]
    conds = [(p, "includes", int(n)) for p, n in DG_INCLUDES_RE.findall(part)]
    conds += [(p, "equals", int(n)) for p, n in DG_EQUALS_RE.findall(part)]
    stated = len(re.findall(r'If "\w+" (?:does not|is not)', part))
    if not conds or stated != len(conds) or "this is a finding" not in part:
        raise SystemExit("Win32_DeviceGuard check text has a condition the generator does not read")
    return conds


def transcript_acl(txt):
    """True when the check also judges the permissions of the transcript output directory (icacls)."""
    return "Transcript output directory" in txt and "icacls" in txt

def _one_block(block, mode):
    hive, path, name, t2, t, value = block
    rtype = (t or t2).upper()
    hive = HIVE_ALIAS.get(hive.upper())
    if not hive:
        return None
    path = clean_path(path)
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
        if name == "LegalNoticeText":
            return {"key": key, "name": name, "mode": "banner", "type": rtype}
        if name == "LegalNoticeCaption":
            return {"key": key, "name": name, "mode": "caption", "type": rtype}
        v = value.splitlines()[0].strip()
        pv = parse_values(v)
        if pv:
            # a numeric REG_SZ ("10 (or less)", "1 (Lock Workstation) or 2 (Force Logoff)"):
            # a string of decimal digits, compared as a number
            return dict(key=key, name=name, mode="sz_num", type=rtype, **pv)
        v = v.strip('"')
        if not v or len(v) > 120 or "this is a finding" in v.lower() or "(or " in v.lower():
            return None
        return {"key": key, "name": name, "mode": "sz", "str": v, "type": rtype}
    return None  # MULTI_SZ / BINARY etc: hand-write later


def derive(rule):
    """Return a list of derived expectations (AND semantics), or None."""
    txt = rule["check"]
    if "Win32_DeviceGuard" in txt:
        return [{"mode": "device_guard", "conds": device_guard(txt)}]
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
    for d in outs:
        if d["mode"] == "banner":
            d["paragraphs"] = banner_paragraphs(txt)
        if d["mode"] == "caption":
            d["titles"] = caption_titles(txt)
            d["attest"] = rego_ident(rule["stig_id"])[2:] + "_organization_defined_title"
    if transcript_acl(txt):
        outs.append({"mode": "attest", "attest": rego_ident(rule["stig_id"])[2:] + "_transcript_directory_acl"})
    return outs


def rego_ident(stig_id):
    return "r_" + re.sub(r"[^a-z0-9]+", "_", stig_id.lower()).strip("_")


def esc(s):
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _fixture_value(d):
    n = d["nums"][0]
    return str(n) if d["mode"] == "sz_num" else n


def _condition(ref, d):
    """The Rego condition line(s) for one derived block.

    Every ordering comparison is guarded by the value's type. Rego orders values of different types (null and
    booleans sort below every number, strings and collections above), so an unguarded `x >= 6` holds for any
    string and `x <= 10` for null or a boolean; to_number() reads null as 0 and true as 1. A REG_DWORD is a
    number, a number held as REG_SZ is a string, and anything else fails the rule."""
    if d["mode"] == "sz_num":
        # a string of decimal digits only: to_number() would also read "1e1", "0x4" and " 4"
        guard = [f"\tis_string({ref})", f"\tregex.match(`^[0-9]+$`, {ref})"]
        ref = f"to_number({ref})"
    else:
        guard = []
    nums = d["nums"]
    if d["op"] == "==":
        if len(nums) == 1:
            return guard + [f"\t{ref} == {nums[0]}"]
        return guard + [f"\t{ref} in {{{', '.join(str(n) for n in nums)}}}"]
    if d["mode"] != "sz_num":
        guard = [f"\tis_number({ref})"]
    lines = guard + [f"\t{ref} {d['op']} {nums[0]}"]
    if d["exclude_zero"]:
        lines.append(f"\t{ref} > 0")
    return lines


def metadata(title, pkg_key):
    return ["# METADATA", f'# title: "{esc(title)}"', "# custom:", "#   class: security",
            f"#   framework: stig_{pkg_key}", "#   source: disa", "#   domains: [windows]"]


def check_text_tests(pkg, derived, absent_ids):
    """tests/test_stig_<platform>_check_text.rego: the rules written from more of the check text than its
    registry block, and the absent-allowed rules, each against values that must and must not pass."""
    q = lambda v: json.dumps(v)
    t = [f"package stig.{pkg}_check_text_test", "",
         "# Generated by tools/stig_generators/gen_windows.py — regenerate, don't hand-edit.",
         "# Each rule below is written from more of DISA's check text than its registry block; these tests hold the",
         "# values the check text accepts and values it does not.", "",
         "import rego.v1", "",
         f"import data.stig.{pkg}",
         f"import data.stig.{pkg}_test.green_fixture", "",
         "open_rules(facts) := {f.stig_id |",
         f"\tsome f in {pkg}.stig_assessment.findings with input as facts",
         '\tf.status == "Open"', "}", "",
         "_other_facts := object.remove(green_fixture, {\"registry\"})", "",
         "# the green fixture with one registry key replaced",
         "_with_key(key, value) := object.union(_other_facts, {\"registry\": object.union(object.remove(green_fixture.registry, {key}), {key: value})})", "",
         "# the green fixture with one registry value replaced",
         "_with_value(key, name, value) := _with_key(key, object.union(object.remove(green_fixture.registry[key], {name}), {name: value}))", "",
         "# the green fixture without one registry value (the key stays, as an object)",
         "_without_value(key, name) := _with_key(key, object.remove(green_fixture.registry[key], {name}))", "",
         "test_the_green_fixture_opens_nothing if {", "\tcount(open_rules(green_fixture)) == 0", "}", ""]
    for r, d in derived:
        sid = r["stig_id"]
        for dd in d:
            if dd["mode"] == "banner":
                key, name = q(dd["key"]), q(dd["name"])
                t += [f"# {sid}: the Standard Mandatory DoD Notice and Consent Banner, white space normalised, nothing else",
                      f"_banner := green_fixture.registry[{key}][{name}]", "",
                      '_banner_one_line := replace(_banner, "\\r\\n\\r\\n", " ")', "",
                      "test_banner_passes_however_its_lines_are_broken if {",
                      "\tevery text in [",
                      "\t\t_banner,", "\t\t_banner_one_line,",
                      '\t\treplace(_banner, "\\r\\n\\r\\n", "\\n"),',
                      '\t\treplace(_banner, "\\r\\n\\r\\n", "\\n\\n"),',
                      '\t\treplace(_banner, "\\r\\n\\r\\n", " \\t\\r\\n"),',
                      '\t\tconcat("", ["\\r\\n  ", replace(_banner_one_line, " ", "  "), " \\n"]),',
                      "\t] {",
                      f"\t\tnot {q(sid)} in open_rules(_with_value({key}, {name}, text))",
                      "\t}", "}", "",
                      "test_text_that_is_not_the_banner_is_a_finding if {",
                      "\tevery text in [",
                      '\t\t"",', '\t\t"   ",', '\t\t"true",', '\t\t"false",', '\t\t"no",',
                      '\t\t"<banner text as configured>",',
                      '\t\t"Authorized use only.",',
                      "\t\t# part of the banner, and the banner with text added",
                      "\t\tsubstring(_banner_one_line, 0, 111),",
                      '\t\tsplit(_banner, "\\r\\n\\r\\n")[0],',
                      '\t\tconcat(" ", [_banner_one_line, "Have a nice day."]),',
                      '\t\tconcat(" ", ["WARNING:", _banner_one_line]),',
                      "\t\t# wording, case, punctuation and paragraphs run together",
                      '\t\treplace(_banner_one_line, "USG-authorized use only", "authorized use only"),',
                      '\t\treplace(_banner_one_line, "may inspect and seize", "may not inspect or seize"),',
                      "\t\tlower(_banner_one_line),", "\t\tupper(_banner_one_line),",
                      '\t\treplace(_banner_one_line, "-The USG", "- The USG"),',
                      '\t\treplace(_banner_one_line, "--", "-"),',
                      '\t\treplace(_banner, "\\r\\n\\r\\n", ""),',
                      "\t\t# a non-breaking space is not ASCII white space",
                      '\t\treplace(_banner_one_line, "You are", "You\\u00a0are"),',
                      "\t] {",
                      f"\t\t{q(sid)} in open_rules(_with_value({key}, {name}, text))",
                      "\t}", "}", "",
                      "test_a_banner_that_is_not_a_string_is_a_finding if {",
                      '\tevery bad in [null, true, 1, split(_banner, "\\r\\n\\r\\n"), {"text": _banner}] {',
                      f"\t\t{q(sid)} in open_rules(_with_value({key}, {name}, bad))",
                      "\t}",
                      f"\t{q(sid)} in open_rules(_without_value({key}, {name}))",
                      "}", ""]
            if dd["mode"] == "caption":
                key, name = q(dd["key"]), q(dd["name"])
                titles = ", ".join(q(x) for x in dd["titles"])
                att = dd["attest"]
                t += [f"# {sid}: the titles the check names, or an organization-defined title with its manual review attested",
                      "test_each_named_title_passes if {",
                      f"\tevery title in [{titles}] {{",
                      f"\t\tnot {q(sid)} in open_rules(_with_value({key}, {name}, title))",
                      f'\t\tnot {q(sid)} in open_rules(_with_value({key}, {name}, concat("", ["  ", title, "\\r\\n"])))',
                      "\t}", "}", "",
                      "test_another_title_is_a_finding_until_its_review_is_attested if {",
                      '\tevery title in ["Notice", "true", "false", "no", "dod notice and consent banner", "DoD Notice and Consent Banner (updated)"] {',
                      f"\t\tfacts := _with_value({key}, {name}, title)",
                      f"\t\t{q(sid)} in open_rules(facts)",
                      f'\t\tnot {q(sid)} in open_rules(object.union(facts, {{"attest": object.union(object.get(facts, "attest", {{}}), {{{q(att)}: true}})}}))',
                      "\t\t# only the boolean true attests",
                      '\t\tevery word in ["true", "yes", 1, null, false] {',
                      f'\t\t\t{q(sid)} in open_rules(object.union(facts, {{"attest": object.union(object.get(facts, "attest", {{}}), {{{q(att)}: word}})}}))',
                      "\t\t}", "\t}", "}", "",
                      "test_a_title_that_is_empty_or_not_a_string_is_a_finding_even_when_attested if {",
                      '\tevery bad in ["", "  ", null, true, 1, ["DoD Notice and Consent Banner"]] {',
                      f"\t\tfacts := _with_value({key}, {name}, bad)",
                      f'\t\t{q(sid)} in open_rules(object.union(facts, {{"attest": object.union(object.get(facts, "attest", {{}}), {{{q(att)}: true}})}}))',
                      "\t}",
                      f"\t{q(sid)} in open_rules(_without_value({key}, {name}))",
                      "}", ""]
    dg = [(r["stig_id"], dd["conds"]) for r, d in derived for dd in d if dd["mode"] == "device_guard"]
    if dg:
        t += ["# Win32_DeviceGuard rules: [rule, property, how the check reads it, value]",
              "device_guard_conditions := ["]
        t += [f"\t[{q(sid)}, {q(prop)}, {q(how)}, {n}]," for sid, conds in dg for prop, how, n in conds]
        t += ["]", "",
              "_with_device_guard(value) := object.union(object.remove(green_fixture, {\"device_guard\"}), {\"device_guard\": value})", "",
              "test_device_guard_rules_need_the_wmi_properties if {",
              "\tevery c in device_guard_conditions {",
              "\t\tc[0] in open_rules(object.remove(green_fixture, {\"device_guard\"}))",
              '\t\tevery bad in [null, {}, "Running", [1, 2], true] {',
              "\t\t\tc[0] in open_rules(_with_device_guard(bad))",
              "\t\t}",
              "\t\tc[0] in open_rules(_with_device_guard(object.remove(green_fixture.device_guard, {c[1]})))",
              "\t}", "}", "",
              "test_a_device_guard_property_of_the_wrong_value_or_type_is_a_finding if {",
              "\tevery c in device_guard_conditions {",
              "\t\tbad_values := _bad_device_guard_values(c[2], c[3])",
              "\t\tcount(bad_values) > 5",
              "\t\tevery bad in bad_values {",
              "\t\t\tc[0] in open_rules(_with_device_guard(object.union(green_fixture.device_guard, {c[1]: bad})))",
              "\t\t}", "\t}", "}", "",
              "# a list that must include n: the list without n, n outside a list, n as text, and an object holding n",
              '_bad_device_guard_values("includes", n) := [[], [n + 1], [sprintf("%d", [n])], n, sprintf("{%d}", [n]), {"value": n}, null, true]', "",
              "# a number that must be n",
              '_bad_device_guard_values("equals", n) := [n - 1, n + 1, sprintf("%d", [n]), [n], {"value": n}, null, true]', "",
              "test_the_registry_alone_does_not_close_a_device_guard_rule if {",
              "\tfacts := object.union(object.remove(green_fixture, {\"device_guard\"}), {\"registry\": object.union(green_fixture.registry, {\"HKLM\\\\SOFTWARE\\\\Policies\\\\Microsoft\\\\Windows\\\\DeviceGuard\": {",
              '\t\t"EnableVirtualizationBasedSecurity": 1,', '\t\t"RequirePlatformSecurityFeatures": 1,',
              '\t\t"LsaCfgFlags": 1,', '\t\t"HypervisorEnforcedCodeIntegrity": 1,', "\t}})})",
              "\tevery c in device_guard_conditions {", "\t\tc[0] in open_rules(facts)", "\t}", "}", ""]
    att = [(r["stig_id"], dd["attest"]) for r, d in derived for dd in d if dd["mode"] == "attest"]
    for sid, key in att:
        t += [f"# {sid}: the registry value and the attested review of the transcript directory permissions",
              "test_transcription_is_open_until_the_directory_review_is_attested if {",
              f"\t{q(sid)} in open_rules(object.remove(green_fixture, {{\"attest\"}}))",
              '\tevery word in ["true", "yes", 1, null, false] {',
              f'\t\t{q(sid)} in open_rules(object.union(green_fixture, {{"attest": object.union(green_fixture.attest, {{{q(key)}: word}})}}))',
              "\t}", "}", ""]
    if absent_ids:
        t += ["# Rules whose check text says an absent value is not a finding: [rule, key, value name]",
              "absent_allowed := ["]
        t += [f"\t[{q(sid)}, {q(key)}, {q(name)}]," for sid, _mod, key, name, _v in absent_ids]
        t += ["]", "",
              "test_an_absent_value_is_not_a_finding if {",
              "\tevery a in absent_allowed {",
              "\t\t# the key is there without the value, or the key itself does not exist",
              "\t\tnot a[0] in open_rules(_without_value(a[1], a[2]))",
              "\t\tfacts := object.union(_other_facts, {\"registry\": object.remove(green_fixture.registry, {a[1]})})",
              "\t\tnot a[0] in open_rules(facts)",
              "\t}", "}", "",
              "test_a_key_that_was_not_read_is_a_finding if {",
              "\tevery a in absent_allowed {",
              '\t\tevery bad in [null, "", "not found", [], true, 0] {',
              "\t\t\ta[0] in open_rules(_with_key(a[1], bad))",
              "\t\t}", "\t}", "}", "",
              "test_a_value_that_is_there_but_wrong_is_a_finding if {",
              "\tevery a in absent_allowed {",
              "\t\tgood := green_fixture.registry[a[1]][a[2]]",
              '\t\tevery bad in [null, "", sprintf("%d", [good]), true, false, [good], 9999] {',
              "\t\t\ta[0] in open_rules(_with_value(a[1], a[2], bad))",
              "\t\t}", "\t}", "}", "",
              "test_absence_counts_only_when_registry_facts_were_collected if {",
              "\tevery a in absent_allowed {",
              "\t\ta[0] in open_rules(_other_facts)",
              '\t\tevery bad in [{}, null, "collected", []] {',
              "\t\t\ta[0] in open_rules(object.union(_other_facts, {\"registry\": bad}))",
              "\t\t}", "\t}", "}", ""]
    return t[:-1] if t[-1] == "" else t


COVERAGE_RE = re.compile(r"^#   coverage:\n(?:#     .*\n)+", re.M)


def write_module(path, lines):
    """Write a generated file, keeping the coverage block `make coverage` stamped into the file on disk
    (it sits at the end of the METADATA comment, directly above `package`)."""
    text = "\n".join(lines) + "\n"
    if os.path.exists(path):
        stamp = COVERAGE_RE.search(open(path).read())
        if stamp and "#   coverage:" not in text:
            text = re.sub(r"^package ", lambda m: stamp.group(0) + m.group(0), text, count=1, flags=re.M)
    open(path, "w").write(text)
    return path


def opa_fmt(paths):
    """opa fmt is the canonical layout; the generated files are committed formatted."""
    opa = os.environ.get("OPA") or shutil.which("opa")
    if not opa:
        raise SystemExit("opa not found ($OPA or PATH): the generated files must be formatted with opa fmt")
    subprocess.run([opa, "fmt", "-w"] + paths, check=True)


def fixture_literal(fixture):
    """The green fixture as a Rego literal in the layout the committed tests have: a key holding one value on
    one line, a key holding several over several lines (opa fmt keeps both)."""
    def obj(d, depth):
        tab = "\t" * depth
        if len(d) == 1:
            (k, v), = d.items()
            return "{" + f"{json.dumps(k)}: {json.dumps(v)}" + "}"
        return "{\n" + "".join(f"{tab}\t{json.dumps(k)}: {json.dumps(v)},\n" for k, v in d.items()) + tab + "}"
    reg = "{\n" + "".join(f"\t{json.dumps(k)}: {obj(v, 1)},\n" for k, v in fixture["registry"].items()) + "}"
    if len(fixture) == 1:
        return '{"registry": ' + reg + "}"
    rest = "".join(f"\t{json.dumps(k)}: {obj(v, 1)},\n" for k, v in fixture.items() if k != "registry")
    reg = reg.replace("\n\t", "\n\t\t").replace("\n}", "\n\t}")
    return "{\n\t\"registry\": " + reg + ",\n" + rest + "}"


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
    written = []
    fixture_reg = {}
    fixture = {"registry": fixture_reg}      # plus device_guard / attest when a rule reads them
    device_guard_ids, absent_ids, banner_text = [], [], [None]
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
                  "# (REG_DWORD as a JSON number, REG_SZ as a string); rules written from a Win32_DeviceGuard check read",
                  "# input.device_guard, and an attested review is input.attest.<key> == true.",
                  "", "import rego.v1", ""]
        finds = []
        helpers = set()
        for r, d in sorted(items, key=lambda x: x[0]["stig_id"]):
            ident = rego_ident(r["stig_id"])
            sev = SEV[r["severity"]]
            lines.append(f"# {r['stig_id']} | {r['vuln_id']} | {sev}")
            body, notes, extra = [], [], []
            absent_ok = None
            for dd in d:
                if dd["mode"] == "device_guard":
                    notes += ["# Check text: the finding conditions are the Win32_DeviceGuard properties (Get-CimInstance -ClassName",
                              "# Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard), sent as input.device_guard. The check",
                              "# says the policy registry values \"alone do not ensure proper function\", so they are not read here."]
                    for prop, how, n in dd["conds"]:
                        ref = f"input.device_guard.{prop}"
                        if how == "includes":
                            body += [f"\tis_array({ref})", f"\t{n} in {ref}"]
                            fx = fixture.setdefault("device_guard", {}).setdefault(prop, [])
                            if n not in fx:
                                fx.append(n)
                                fx.sort()
                        else:
                            body.append(f"\t{ref} == {n}")
                            fixture.setdefault("device_guard", {})[prop] = n
                    device_guard_ids.append(r["stig_id"])
                    continue
                if dd["mode"] == "attest":
                    notes += ["# Check text: the transcript output directory must not permit read or modify access by nonprivileged",
                              "# users (icacls). The permissions are not collected; the rule is open until that review is attested",
                              f"# (input.attest.{dd['attest']} == true)."]
                    body.append(f"\tinput.attest.{dd['attest']} == true")
                    fixture.setdefault("attest", {})[dd["attest"]] = True
                    continue
                key, name = esc(dd["key"]), esc(dd["name"])
                ref = f'input.registry["{key}"]["{name}"]'
                if dd["key"].startswith("HKCU"):
                    notes += ["# Check text: the check is made for each interactive user profile. This rule reads the one",
                              "# HKCU hive the collector sends."]
                if dd["mode"] == "absent":
                    body.append(f"\tnot {ref}")
                    continue
                if dd["mode"] == "banner":
                    notes += BANNER_NOTE
                    helpers |= {"normalise", "banner"}
                    banner_text[0] = dd["paragraphs"]
                    body.append(f"\tis_string({ref})")
                    body.append(f"\t_normalise_space({ref}) == _dod_banner")
                    # the fixture holds the banner as a host stores it: paragraphs separated by CR LF pairs
                    fixture_reg.setdefault(dd["key"], {})[dd["name"]] = "\r\n\r\n".join(dd["paragraphs"])
                    continue
                if dd["mode"] == "caption":
                    titles = ", ".join(f'"{esc(t)}"' for t in dd["titles"])
                    notes += ["# Check text: one of the titles the check names, or an organization-defined equivalent, for which",
                              "# \"a manual review will be required\": such a title counts only when that review is attested",
                              f"# (input.attest.{dd['attest']} == true). Titles are compared after the same white-space",
                              "# normalisation as the banner text."]
                    helpers.add("normalise")
                    body.append(f"\tis_string({ref})")
                    body.append(f"\t_normalise_space({ref}) in {{{titles}}}")
                    extra += ["", ident + " if {", f"\tis_string({ref})", f'\t_normalise_space({ref}) != ""',
                              f"\tinput.attest.{dd['attest']} == true", "}"]
                    fixture_reg.setdefault(dd["key"], {})[dd["name"]] = dd["titles"][0]
                    continue
                if dd["mode"] == "sz":
                    body.append(f'\t{ref} == "{esc(dd["str"])}"')
                    fixture_reg.setdefault(dd["key"], {})[dd["name"]] = dd["str"]
                    continue
                body.extend(_condition(ref, dd))
                fixture_reg.setdefault(dd["key"], {})[dd["name"]] = _fixture_value(dd)
                if dd.get("allow_absent"):
                    absent_ok = (ref, f'input.registry["{key}"]')
                    absent_ids.append((r["stig_id"], mod, dd["key"], dd["name"], _fixture_value(dd)))
            if absent_ok:
                notes += ["# Check text: an absent value is not a finding. Absent counts only when registry facts were",
                          "# collected and the key is either not there or an object without the value; a key sent as",
                          "# null or as anything but an object was not read, and any other value is open."]
            lines.append(f"default {ident} := false")
            if notes:
                lines.append("")
                lines.extend(dict.fromkeys(notes))
            lines.append(ident + " if {")
            lines.extend(body)
            lines.append("}")
            lines.extend(extra)
            if absent_ok:
                lines += ["", ident + " if {", "\tis_object(input.registry)", "\tcount(input.registry) > 0",
                          f"\tnot _{ident[2:]}_key_unreadable",
                          f"\tnot _{ident[2:]}_value_set", "}", "",
                          f"_{ident[2:]}_key_unreadable if {{", f"\tkey := {absent_ok[1]}", "\tnot is_object(key)", "}", "",
                          f"_{ident[2:]}_value_set if {{", f"\t_ := {absent_ok[0]}", "}"]
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
        if "normalise" in helpers:
            lines += ["# Every run of ASCII white space (space, tab, line feed, form feed, carriage return) becomes one",
                      "# space; leading and trailing spaces are removed. Nothing else is changed.",
                      '_normalise_space(s) := trim(regex.replace(s, `[ \\t\\n\\f\\r]+`, " "), " ")', ""]
        if "banner" in helpers:
            lines += ["# The Standard Mandatory DoD Notice and Consent Banner as the check text prints it (public U.S.",
                      "# Government text), one string per paragraph, joined by single spaces: its normalised form.",
                      '_dod_banner := concat(" ", [']
            lines += [f'\t"{esc(para)}",' for para in banner_text[0]]
            lines += ["])", ""]
        lines.append("findings := [")
        for f in finds:
            lines.append(f"\t{f},")
        lines.append("]")
        lines.append("")
        lines.append("default compliant := false")
        lines.append("")
        lines.append('compliant if count([f | some f in findings; f.status == "Open"]) == 0')
        written.append(write_module(os.path.join(outdir, f"{mod}.rego"), lines))

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
          "\t# every rule's DISA status (Not_a_Finding, Open, Not_Applicable, Not_Reviewed), for rollups such as",
          "\t# crosswalk.correlation; violations stay the open findings",
          '\t"rule_results": [{"rule": f.stig_id, "status": f.status} | some f in all_findings],',
          '\t"total_controls": count(all_findings),',
          '\t"open_findings": open_findings,',
          '\t"passed_controls": count(all_findings) - count(open_findings),',
          '\t"failed_controls": count(open_findings),',
          '\t"compliant": fully_compliant,',
          "}"]
    written.append(write_module(os.path.join(outdir, f"stig_{cat_key}_complete.rego"), o))

    # tests: smoke + green fixture
    fixture_text = fixture_literal(fixture)
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
         f"green_fixture := {fixture_text}", "",
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
    t += ["", "# rules that read input.device_guard and not the registry",
          "device_guard_rule_ids := {" + ", ".join(f'"{i}"' for i in device_guard_ids) + "}"]
    written.append(write_module(os.path.join(outdir, "tests", f"test_stig_{cat_key}.rego"), t))
    written.append(write_module(os.path.join(outdir, "tests", f"test_stig_{cat_key}_check_text.rego"),
                                check_text_tests(pkg, derived, absent_ids)))
    written.append(write_alias(outdir, cat_key, pkg, bench))
    opa_fmt(written)
    print(f"{cat_key}: {ver} ({cat['release_date']}): {len(derived)} derived / {len(cat['rules'])} total; "
          f"modules: {module_names}; fixture keys: {len(fixture_reg)}")


from gen_k8s import ALIAS_TMPL


def write_alias(outdir, key, pkg, bench):
    alias = ALIAS_TMPL.format(pkg=pkg)
    meta = "\n".join(metadata(f"Framework-key entrypoint alias with the fail-closed gate — {bench}", key))
    alias = alias.replace("package stig.", meta + "\npackage stig.", 1)   # METADATA must sit directly above package
    return write_module(os.path.join(outdir, f"stig_{key}_main.rego"), alias.rstrip("\n").split("\n"))


if __name__ == "__main__":
    keys = sys.argv[1:] or list(PLATFORMS)
    for key in keys:
        pkg, label = PLATFORMS[key]
        gen_platform(key, pkg, label, [])
