#!/usr/bin/env python3
"""Generate the CIS Microsoft Windows 10 Enterprise Benchmark v5.0.0 module from the benchmark's own workbook.

    python3 tools/cis_generators/gen_windows_10.py <CIS_Microsoft_Windows_10_Enterprise_Benchmark_v5.0.0.xlsx>

The workbook is CIS-licensed and is not committed. This is the Windows Server 2022 generator
(gen_windows_server_2022.py) pointed at a workstation workbook: the sheet reader, the derivation of each check from
its audit procedure, the per-row emission and the fixture builder are imported from it unchanged. This file holds
what differs for the Enterprise (workstation) benchmarks, and gen_windows_11.py in turn points it at the Windows 11
workbook:

  * Profiles. The workstation benchmarks have no server role. CIS publishes Level 1, Level 2 (which includes
    Level 1), BitLocker (BL) and -- Windows 10 only -- Next Generation Windows Security (NG) profiles; the Combined
    Profiles sheet lists a BL or NG recommendation once per combined profile that includes it ("BitLocker (BL)",
    "Level 1 (L1) + BitLocker (BL)", ...). The loader folds those rows into one recommendation tagged with the one
    profile every listing shares. `input.cis_profile` is {level: 1|2, bitlocker: bool, next_generation: bool};
    BitLocker and Next Generation are opt-in, as in the server modules.
  * Hand-written tables: account policy (`secedit`), the two Manual recommendations, the registry checks whose
    audit text the generic derivation cannot read (a stray character in the stated value, the two remotely
    accessible registry path lists, the device-setup-class deny list held as numbered values under one key, a
    value that must not exist or be blank, a value that must be anything other than one number).
  * Two evaluator additions: a numeric "must not equal" comparison and a `reg_key_values` kind (every listed
    string must appear among the values of one registry key).

Writes benchmarks/cis/windows_10_modular/ (section modules, lib.rego, attestation, aggregation, main, data/ index
and collector manifest, README.md, tests/). The run aborts on any count, status, section, logic or title-keyword
mismatch with the workbook.
"""
from __future__ import annotations

import datetime
import json
import pathlib
import re
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import gen_windows_server_2022 as base  # noqa: E402
import gen_windows_server_2022_tests as basetests  # noqa: E402

ROOT = HERE.parent.parent

# ---------------------------------------------------------------------------------------------------------------
# What differs per benchmark. gen_windows_11.py overrides these before calling generate().
# ---------------------------------------------------------------------------------------------------------------

BENCHMARK = "CIS Microsoft Windows 10 Enterprise Benchmark"
SHORT = "Windows 10 Enterprise"
VERSION = "5.0.0"
PKG = "cis_windows_10"
DIR = "windows_10_modular"
TOTAL_RECS = 501
INDEX_NAME = "cis_windows_10_v5_0_index.json"
GENERATOR = "tools/cis_generators/gen_windows_10.py"

EQ, NE, GE, LE, LE_NOT0, GE_OR_FOREVER, RANGE, SET = "eq", "ne", "ge", "le", "le_not0", "ge_or_forever", "range", "set"

# Section 1 and the secedit-backed security options: `secedit /export /areas SECURITYPOLICY`, [System Access].
SECEDIT = {
    "1.1.1": ("PasswordHistorySize", GE, 24),
    "1.1.2": ("MaximumPasswordAge", LE_NOT0, 365),
    "1.1.3": ("MinimumPasswordAge", GE, 1),
    "1.1.4": ("MinimumPasswordLength", GE, 14),
    "1.1.5": ("PasswordComplexity", EQ, 1),
    "1.1.7": ("ClearTextPassword", EQ, 0),
    "1.2.1": ("LockoutDuration", GE_OR_FOREVER, 15),
    "1.2.2": ("LockoutBadCount", LE_NOT0, 5),
    "1.2.4": ("ResetLockoutCount", GE, 15),
    "2.3.1.2": ("EnableGuestAccount", EQ, 0),
    "2.3.1.4": ("NewAdministratorName", NE, "Administrator"),
    "2.3.1.5": ("NewGuestName", NE, "Guest"),
    "2.3.10.1": ("LSAAnonymousNameLookup", EQ, 0),
}

# CIS marks these Manual. They are reported as requiring attestation, never evaluated.
MANUAL = {
    "1.2.3": "Administrator account lockout allowed",
    "2.3.11.6": "users forced off when logon hours expire",
}

# Registry paths a remote client may read through the winreg pipe (Microsoft's default lists, as the audit text
# states them). Compared as sets, case-insensitively.
WINREG_EXACT_PATHS = [
    "System\\CurrentControlSet\\Control\\ProductOptions",
    "System\\CurrentControlSet\\Control\\Server Applications",
    "Software\\Microsoft\\Windows NT\\CurrentVersion",
]
WINREG_PATHS = [
    "System\\CurrentControlSet\\Control\\Print\\Printers",
    "System\\CurrentControlSet\\Services\\Eventlog",
    "Software\\Microsoft\\OLAP Server",
    "Software\\Microsoft\\Windows NT\\CurrentVersion\\Print",
    "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
    "System\\CurrentControlSet\\Control\\ContentIndex",
    "System\\CurrentControlSet\\Control\\Terminal Server",
    "System\\CurrentControlSet\\Control\\Terminal Server\\UserConfig",
    "System\\CurrentControlSet\\Control\\Terminal Server\\DefaultUserConfiguration",
    "Software\\Microsoft\\Windows NT\\CurrentVersion\\Perflib",
    "System\\CurrentControlSet\\Services\\SysmonLog",
]
# Device setup class GUIDs of IEEE 1394 controllers and the protocols that ride on them (Microsoft's class ids).
IEEE_1394_CLASSES = [
    "{d48179be-ec20-11d1-b6b8-00c04fa372a7}",
    "{7ebefbc0-3200-11d2-b4c2-00a0c9697d07}",
    "{c06ff265-ae09-48f0-812c-16753d7cba83}",
    "{6bdd1fc1-810f-11d0-bec7-08002be2092f}",
]

# Registry-backed recommendations the generic derivation cannot read unaided. The generator confirms the one
# location each names appears in that recommendation's audit text.
REGISTRY_OVERRIDES = {
    "2.3.7.1": ("reg", EQ, 0),               # the stated value carries a stray character the value regex trips on
    "2.3.7.6": ("reg", LE, 4),               # CachedLogonsCount is REG_SZ holding a number
    "2.3.7.7": ("reg", RANGE, [5, 14]),
    "2.3.10.7": ("reg", SET, WINREG_EXACT_PATHS),
    "2.3.10.8": ("reg", SET, WINREG_PATHS),  # the audit text says REG_DWORD; the value is a REG_MULTI_SZ list
    "18.9.19.5": ("reg_absent", None, None),      # the value must not exist
    "18.10.10.1.1": ("reg_absent", None, None),   # REG_SZ that must be blank or unset
    "18.10.16.7": ("reg", EQ, 0),            # the audit text gives no value; the title says Disabled
    "18.10.17.1": ("reg", NE, 3),            # anything other than 3 (Internet peering)
}

# Numbered values under one key: every listed string must be among them.
KEY_VALUES = {
    "18.9.7.1.5": IEEE_1394_CLASSES,
}

# A keyword of the title for every hand-written entry: the generic derivation would also accept these ids under
# another meaning, so a renumbered workbook aborts the run instead of mislabelling a check.
TITLE_WORDS = {
    "1.1.1": "password history",
    "1.1.2": "Maximum password age",
    "1.1.3": "Minimum password age",
    "1.1.4": "Minimum password length' is",
    "1.1.5": "complexity requirements",
    "1.1.7": "reversible encryption",
    "1.2.1": "lockout duration",
    "1.2.2": "lockout threshold",
    "1.2.4": "Reset account lockout counter",
    "1.2.3": "Administrator account lockout",
    "2.3.1.2": "Guest account status",
    "2.3.1.4": "Rename administrator",
    "2.3.1.5": "Rename guest",
    "2.3.7.1": "CTRL+ALT+DEL",
    "2.3.7.6": "previous logons to cache",
    "2.3.7.7": "between 5 and 14",
    "2.3.10.1": "anonymous SID/Name",
    "2.3.10.7": "registry paths' is",
    "2.3.10.8": "sub-paths",
    "2.3.11.6": "logon hours expire",
    "18.9.7.1.5": "IEEE 1394",
    "18.9.19.5": "background refresh",
    "18.10.10.1.1": "earlier versions of Windows",
    "18.10.16.7": "Insider builds",
    "18.10.17.1": "Download Mode",
}

# Principals section 2.2 names beyond the server tables, and one more right.
EXTRA_SIDS = {
    "Users": "S-1-5-32-545",
    # restricted-service SID: S-1-5-99 followed by the SHA-1 of the upper-cased service name (see the 2019 generator)
    "RESTRICTED SERVICES\\PrintSpoolerService": "S-1-5-99-216390572-1995538116-3857911515-2404958512-2623887229",
}
EXTRA_PRIVILEGES = {"Log on as a service": "SeServiceLogonRight"}

PROFILE_TAGS = {"L1", "L2", "BL", "NG"}
TAG = re.compile(r"\((L1|L2|BL|NG)\)")


# ---------------------------------------------------------------------------------------------------------------
# Shared plumbing
# ---------------------------------------------------------------------------------------------------------------

def _sub(text, pairs, what):
    for old, new in pairs:
        if old not in text:
            sys.exit(f"{what}: expected text not found: {old[:70]!r}")
        text = text.replace(old, new)
    return text


def _rename(text):
    for old, new in [
        ("gen_windows_server_2022.py", pathlib.Path(GENERATOR).name),
        ("windows_server_2022_modular", DIR),
        ("cis_windows_server_2022", PKG),
        ("CIS Microsoft Windows Server 2022 Benchmark", BENCHMARK),
        ("Windows Server 2022", SHORT),
        ("v5.1.0", "v" + VERSION),
        ('"5.1.0"', f'"{VERSION}"'),
    ]:
        text = text.replace(old, new)
    return text


def header():
    return f"# Generated by {GENERATOR} from the CIS workbook -- do not edit.\n# {BENCHMARK} v{VERSION}\n"


def metadata(title):
    return (f'# METADATA\n# title: "{title}"\n# custom:\n#   class: security\n#   framework: {PKG}_modular\n'
            "#   source: cis\n#   domains: [windows]\n")


def configure():
    """Point the 2022 generator's module-level tables at this benchmark's; its functions read them at call time."""
    base.BENCHMARK, base.VERSION, base.PKG, base.OUT = BENCHMARK, VERSION, PKG, ROOT / "benchmarks" / "cis" / DIR
    base.SECEDIT, base.MANUAL = SECEDIT, MANUAL
    base.REGISTRY_OVERRIDES = {k: v for k, v in REGISTRY_OVERRIDES.items()}
    base.SIDS = {**base.SIDS, **EXTRA_SIDS}
    base.PRIVILEGES = {**base.PRIVILEGES, **EXTRA_PRIVILEGES}
    base.HEADER, base.METADATA = header(), metadata("{title}")  # the 2022 emitters .format() these
    base.ATTESTATION_BODY = _rename(_sub(base.ATTESTATION_BODY, [
        ("# In the selected profile. With the server role unknown, a recommendation for either role is in scope.\n",
         "# In the selected profile (level; BitLocker and Next Generation when opted in).\n"),
    ], "ATTESTATION_BODY"))


# ---------------------------------------------------------------------------------------------------------------
# Workbook: the Combined Profiles sheet, folded to one row per recommendation
# ---------------------------------------------------------------------------------------------------------------

def load(path):
    rows = base.read_sheet(path, "Combined Profiles")
    ix = {h: i for i, h in enumerate(rows[0])}
    recs, section_names, listings = {}, {}, {}
    for r in rows[1:]:
        cell = lambda name: (r[ix[name]] if ix[name] < len(r) else None) or ""  # noqa: E731
        sec, rid = cell("Section #"), cell("Recommendation #")
        if sec and not rid and "." not in sec:
            section_names[sec] = cell("Title")
        if not rid:
            continue
        tags = set(TAG.findall(cell("Profile")))
        if not tags or not tags <= PROFILE_TAGS:
            sys.exit(f"{rid}: unrecognised profile {cell('Profile')!r}")
        rec = {"id": rid, "title": " ".join(cell("Title").split()), "status": cell("Assessment Status"),
               "audit": cell("Audit Procedure"), "section": rid.split(".")[0]}
        if rid in recs:
            if recs[rid] != rec:
                sys.exit(f"{rid}: listed twice with different content")
            listings[rid].append(tags)
        else:
            recs[rid] = rec
            listings[rid] = [tags]
    for rid, rec in recs.items():
        common = set.intersection(*listings[rid])
        if len(common) != 1:
            sys.exit(f"{rid}: cannot tell its profile from {listings[rid]}")
        rec["profiles"] = sorted(common)
    return recs, section_names


# ---------------------------------------------------------------------------------------------------------------
# Derivation: the 2022 logic plus the numbered-values kind
# ---------------------------------------------------------------------------------------------------------------

def derive(rec):
    rid = rec["id"]
    if rid in KEY_VALUES:
        locs = base.registry_locations(rec["audit"])
        if len(locs) != 1 or locs[0][0] != "machine":
            sys.exit(f"{rid}: expected one machine location, found {locs}")
        return {"kind": "reg_key_values", "path": locs[0][1], "values": KEY_VALUES[rid]}
    return base.derive(rec)


# ---------------------------------------------------------------------------------------------------------------
# lib.rego: the 2022 evaluator with the Enterprise profile model and two more comparisons
# ---------------------------------------------------------------------------------------------------------------

PROFILE_BLOCK = """# ---------------------------------------------------------------------------------------------------------------
# Profile. Level defaults to 2, the stricter selection (Level 2 includes Level 1), so a missing level never
# narrows the assessment. BitLocker and Next Generation Windows Security are opt-in: CIS publishes each as a
# separate profile added to Level 1 or Level 2.
# ---------------------------------------------------------------------------------------------------------------

# defaulted so the report stays defined when OPA is queried with no input document at all
default _cis_profile := {}

_cis_profile := p if {
	p := input.cis_profile
	is_object(p)
}

default level := 2

level := l if {
	l := _cis_profile.level
	l in {1, 2}
}

default level_defaulted := true

level_defaulted := false if _cis_profile.level in {1, 2}

default bitlocker := false

bitlocker if _cis_profile.bitlocker == true

default next_generation := false

next_generation if _cis_profile.next_generation == true

profile := {
	"level": level,
	"level_defaulted": level_defaulted,
	"bitlocker": bitlocker,
	"next_generation": next_generation,
}

_tier_selected(tier) if tier == "L1"

_tier_selected(tier) if {
	tier == "L2"
	level >= 2
}

_tier_selected(tier) if {
	tier == "BL"
	bitlocker
}

_tier_selected(tier) if {
	tier == "NG"
	next_generation
}

in_scope(profiles) if {
	some p in profiles
	_tier_selected(p)
}

"""

LIB_CHANGES = [
    ("""# Each in-scope row resolves to exactly one of pass, fail or not_assessed. Not assessed means the facts that row
# reads were not collected, or the row is specific to a server role and input.cis_profile.role was not given;
# the report counts it as failed.
""", """# Each in-scope row resolves to exactly one of pass, fail or not_assessed. Not assessed means the facts that row
# reads were not collected; the report counts it as failed.
"""),
    ("""	"auditpol": ["audit_policy"],
}
""", """	"auditpol": ["audit_policy"],
	"reg_key_values": ["registry"],
}
"""),
    ("""_assessable(c) if {
	not _role_undecided(c.profiles)
	_collected(c.kind)
}
""", """_assessable(c) if _collected(c.kind)
"""),
    ("""_cmp(v, "ne", want) if {
	is_string(v)
	_str(v) != ""
	_str(v) != lower(want)
}
""", """_cmp(v, "ne", want) if {
	is_string(want)
	is_string(v)
	_str(v) != ""
	_str(v) != lower(want)
}

# a configured number that must be anything other than the one the benchmark rules out
_cmp(v, "ne", want) if {
	is_number(want)
	_num(v) != want
}
"""),
    ("""# auditpol /backup Setting Value: 1 success, 2 failure, 3 both. The benchmark's setting is a minimum.
_passes(c) if {
	c.kind == "auditpol"
""", """# numbered values under one key (DenyDeviceClasses\\1, \\2, ...): every listed string must be among them
_key_values(path) := {lower(trim_space(v)) |
	some _, v in object.get(input.registry, path, {})
	is_string(v)
}

_passes(c) if {
	c.kind == "reg_key_values"
	every x in c.values {
		lower(x) in _key_values(c.path)
	}
}

# auditpol /backup Setting Value: 1 success, 2 failure, 3 both. The benchmark's setting is a minimum.
_passes(c) if {
	c.kind == "auditpol"
"""),
    ("""_found(c) := sprintf("%v", [object.get(input.audit_policy, c.guid, null)]) if c.kind == "auditpol"
""", """_found(c) := sprintf("%v", [object.get(input.audit_policy, c.guid, null)]) if c.kind == "auditpol"

_found(c) := sprintf("%v", [sort(_key_values(c.path))]) if c.kind == "reg_key_values"
"""),
    ("""_why_not_assessed(c) := "the server role (input.cis_profile.role) was not supplied and this recommendation applies to one role only" if _role_undecided(c.profiles)

_why_not_assessed(c) := sprintf("input.%s was not collected (for registry_users: no S-1-5-21 user hive)", [INPUT_KEY[c.kind]]) if not _role_undecided(c.profiles)
""", """_why_not_assessed(c) := sprintf("input.%s was not collected (for registry_users: no S-1-5-21 user hive)", [INPUT_KEY[c.kind]])
"""),
    ("""			results[cid] == "not_assessed"
			not _role_undecided(c.profiles)
		}),
""", """			results[cid] == "not_assessed"
		}),
"""),
    ("""# Copied into benchmarks/cis/windows_server_2022_modular/lib.rego by tools/cis_generators/gen_windows_server_2022.py
# -- edit the copy under tools/, not the generated one.
""", f"""# Written into benchmarks/cis/{DIR}/lib.rego by {GENERATOR} from
# tools/cis_generators/windows_lib.rego.tmpl, with the workstation profile model and two more comparisons
# substituted (LIB_CHANGES in the generator) -- edit those, not this copy.
"""),
]


def lib_text():
    lib = (HERE / "windows_lib.rego.tmpl").read_text()
    start, end = lib.index("# ------", lib.index("import rego.v1")), lib.index("# ------", lib.index("# Facts") - 200)
    if "# Profile." not in lib[start:end] or "_role_undecided(profiles) if" not in lib[start:end]:
        sys.exit("windows_lib.rego.tmpl: the profile block moved")
    lib = lib[:start] + PROFILE_BLOCK + lib[end:]
    lib = _sub(lib, LIB_CHANGES, "windows_lib.rego.tmpl")
    lib = _rename(lib)
    lib = lib.replace("{{SECTIONS}}", "\n".join(f'\t"{p}": data.{PKG}.{p}.SECTION,' for p in base.SECTIONS.values()))
    lib = lib.replace("{{TABLES}}", "\n".join(f'\t"{p}": data.{PKG}.{p}.controls,' for p in base.SECTIONS.values()))
    return lib


# ---------------------------------------------------------------------------------------------------------------
# Aggregation and the report entrypoint
# ---------------------------------------------------------------------------------------------------------------

def complete_module(recs):
    sections = base.SECTIONS
    imports = "\n".join(f"import data.{PKG}.{sections[s]}" for s in sections)
    reports = "\n".join(f"\t{sections[s]}.compliance_report," for s in sections)
    tables = "\n".join(f"\t{sections[s]}.controls," for s in sections)
    return (header() + metadata(f"{BENCHMARK} v{VERSION} - every section, aggregated")
            + f"package {PKG}\n\nimport data.{PKG}.attestation\n{imports}\nimport rego.v1\n\n"
            + f"BENCHMARK_TOTAL_CONTROLS := {len(recs)}\n\n"
            + f"section_reports := [\n{reports}\n]\n\n"
            + f"_tables := [\n{tables}\n]\n\n"
            + base.COMPLETE_BODY)


def main_module():
    body = _sub(base.MAIN_BODY, [
        ("(input.cis_profile: role,\n# level, next_generation), out of the benchmark's 408.",
         f"(input.cis_profile: level,\n# bitlocker, next_generation), out of the benchmark's {TOTAL_RECS}."),
        ("could not be assessed (its facts were not collected, the role was not supplied, or a Manual one was not\n# attested)",
         "could not be assessed (its facts were not collected, or a Manual one was not attested)"),
        ('"standard_total": 408', f'"standard_total": {TOTAL_RECS}'),
        ('"controls_basis": "recommendations in scope for input.cis_profile (role, level, next_generation)"',
         '"controls_basis": "recommendations in scope for input.cis_profile (level, bitlocker, next_generation)"'),
    ], "MAIN_BODY")
    return (header() + metadata(f"{BENCHMARK} v{VERSION} - compliance_report entrypoint")
            + f"package {PKG}.main\n\nimport data.{PKG} as bench\nimport data.{PKG}.attestation\nimport data.{PKG}.lib\nimport rego.v1\n\n"
            + _rename(body))


def manifest(checks):
    m = base.manifest(checks)
    m["contract"]["cis_profile"] = "{level: 1|2, bitlocker: bool, next_generation: bool}"
    m["registry_keys"] = sorted({c["path"] for c in checks.values() if c["kind"] == "reg_key_values"})
    return m


# ---------------------------------------------------------------------------------------------------------------
# Tests. The 2022 fixture builder is reused per row; the fixture itself is one compliant workstation with every
# profile opted in, so each recommendation is in scope exactly once.
# ---------------------------------------------------------------------------------------------------------------

INPUT_REMOVE = {
    "reg": "registry", "reg_all": "registry", "reg_absent": "registry", "reg_key_values": "registry",
    "ureg": "registry_users", "secedit": "secedit/system_access", "rights": "secedit/privilege_rights",
    "auditpol": "audit_policy",
}

_base_good, _base_facts = basetests._good, basetests._facts


def _good(op, value):
    if op == "ne" and isinstance(value, int):
        return 1 if value != 1 else 0
    return _base_good(op, value)


def _facts(c, good):
    if c["kind"] == "reg_key_values":
        vals = c["values"] if good else ["BROKEN"] * len(c["values"])
        return {"registry": {c["path"]: {str(i + 1): v for i, v in enumerate(vals)}}}
    return _base_facts(c, good)


basetests._good, basetests._facts = _good, _facts

FULL_PROFILE = {"level": 2, "bitlocker": True, "next_generation": True}


def fixture(checks, recs):
    fx = {"cis_profile": dict(FULL_PROFILE), "registry": {}, "registry_users": {basetests.USER_SID: {}},
          "audit_policy": {}, "secedit": {"system_access": {}, "privilege_rights": {}}}
    owners = {}
    for rid, c in checks.items():
        if c["kind"] != "manual":
            basetests._merge(fx, _facts(c, True), (), rid, owners)
    fx["attestations"] = [{"control_id": rid, "attested_by": "test", "attested_on": "2026-11-10",
                           "evidence_ref": "test"} for rid in sorted(MANUAL)]
    return fx


def _scope(recs, level, bitlocker, next_generation):
    tiers = {"L1"} | ({"L2"} if level == 2 else set()) | ({"BL"} if bitlocker else set()) | ({"NG"} if next_generation else set())
    return sum(1 for r in recs.values() if set(r["profiles"]) & tiers)


def _first(order, recs, checks, tag, kinds_not=("manual",)):
    return next((rid for rid in order if recs[rid]["profiles"] == [tag] and checks[rid]["kind"] not in kinds_not), None)


def tests(recs, checks):
    order = sorted(recs, key=lambda i: [int(p) for p in i.split(".")])
    sections = base.SECTIONS
    head = f"# Generated by {GENERATOR} -- do not edit.\n"
    fx = f"data.{PKG}.fixtures_test.fixture_all"
    sec = lambda rid: sections[rid.split(".")[0]]  # noqa: E731
    files = {}

    files["test_fixtures.rego"] = "\n".join([
        head + f"package {PKG}.fixtures_test\n\nimport rego.v1\n",
        "# A compliant workstation with every profile opted in, synthesised from the check rows: every recommendation\n"
        "# is in scope and passes.\n",
        f"fixture_all := {json.dumps(fixture(checks, recs), indent=1, sort_keys=True)}\n"])

    for sec_no, name in sections.items():
        body = [head + f"package {PKG}.{name}_test\n\nimport rego.v1\n"]
        for rid in order:
            c = checks[rid]
            if c["kind"] == "manual" or recs[rid]["section"] != sec_no:
                continue
            t = rid.replace(".", "_")
            # object.union merges objects recursively and replaces arrays: only this recommendation's facts change.
            # lib.results is looked up by id, so only this row is evaluated.
            body.append(f"""test_{t}_passes_on_a_compliant_host if {{
	data.{PKG}.lib.results["{rid}"] == "pass" with input as {fx}
}}

test_{t}_fails_when_its_facts_do_not_comply if {{
	data.{PKG}.lib.results["{rid}"] == "fail" with input as object.union({fx}, {json.dumps(_facts(c, False))})
}}

test_{t}_evidence_missing_is_not_a_pass if {{
	data.{PKG}.lib.results["{rid}"] == "not_assessed" with input as json.remove({fx}, ["{INPUT_REMOVE[c['kind']]}"])
}}
""")
        files[f"test_{name}.rego"] = "\n".join(body)

    total = len(recs)
    l1, l2, l2_bl = _scope(recs, 1, False, False), _scope(recs, 2, False, False), _scope(recs, 2, True, False)
    l2_only, bl_only, ng_only = _first(order, recs, checks, "L2"), _first(order, recs, checks, "BL"), _first(order, recs, checks, "NG")
    if not l2_only or not bl_only:
        sys.exit("no Level 2 or BitLocker recommendation to test profile selection with")
    body = [head + f"package {PKG}.main_test\n\nimport rego.v1\n", f"""test_compliant_fixture_passes_every_recommendation if {{
	r := data.{PKG}.main.compliance_report with input as {fx}
	r.total_controls == {total}
	r.failed_controls == 0
	r.passed_controls == {total}
	r.compliant == true
	r.assessment_coverage_percentage == 100
	count(r.violations) == 0
}}

test_empty_input_fails_closed if {{
	r := data.{PKG}.main.compliance_report with input as {{}}
	r.compliant == false
	r.passed_controls == 0
	r.failed_controls == r.total_controls
	r.total_controls > 0
	some v in r.violations
	startswith(v, "FAIL-CLOSED")
}}

test_no_input_document_fails_closed if {{
	r := data.{PKG}.main.compliance_report
	r.compliant == false
	r.passed_controls == 0
}}

test_coverage_accounting_partitions_the_benchmark if {{
	r := data.{PKG}.main.compliance_report with input as {{}}
	r.coverage_accounting.balanced == true
	r.coverage_accounting.accounted == {total}
}}

test_level_1_scope_matches_the_workbook if {{
	fx := json.patch({fx}, [{{"op": "replace", "path": "/cis_profile", "value": {{"level": 1}}}}])
	r := data.{PKG}.main.compliance_report with input as fx
	r.total_controls == {l1}
	r.compliant == true
	r.profile.level == 1
	r.profile.bitlocker == false
}}

test_level_2_scope_matches_the_workbook if {{
	fx := json.patch({fx}, [{{"op": "replace", "path": "/cis_profile", "value": {{"level": 2}}}}])
	r := data.{PKG}.main.compliance_report with input as fx
	r.total_controls == {l2}
	r.compliant == true
}}

test_level_2_with_bitlocker_scope_matches_the_workbook if {{
	fx := json.patch({fx}, [{{"op": "replace", "path": "/cis_profile", "value": {{"level": 2, "bitlocker": true}}}}])
	r := data.{PKG}.main.compliance_report with input as fx
	r.total_controls == {l2_bl}
	r.compliant == true
}}

test_missing_profile_defaults_to_level_2_without_the_opt_in_profiles if {{
	fx := json.remove({fx}, ["cis_profile"])
	r := data.{PKG}.main.compliance_report with input as fx
	r.total_controls == {l2}
	r.profile.level_defaulted == true
}}

test_level_1_excludes_level_2_recommendations if {{
	fx := json.patch({fx}, [{{"op": "replace", "path": "/cis_profile/level", "value": 1}}])
	r := data.{PKG}.{sec(l2_only)}.compliance_report with input as fx
	r.results["{l2_only}"] == "not_applicable"
}}

test_bitlocker_is_opt_in if {{
	fx := json.remove({fx}, ["cis_profile/bitlocker"])
	r := data.{PKG}.{sec(bl_only)}.compliance_report with input as fx
	r.results["{bl_only}"] == "not_applicable"
	data.{PKG}.lib.results["{bl_only}"] == "pass" with input as {fx}
}}

test_missing_audit_policy_is_reported_not_assessed if {{
	fx := json.remove({fx}, ["audit_policy"])
	r := data.{PKG}.main.compliance_report with input as fx
	"Advanced Audit Policy Configuration" in r.sections_not_assessed
	r.missing_inputs["Advanced Audit Policy Configuration"] == ["audit_policy"]
	r.compliant == false
}}

test_a_failed_recommendation_is_counted_and_named if {{
	fx := object.union({fx}, {json.dumps(_facts(checks["1.1.1"], False))})
	r := data.{PKG}.main.compliance_report with input as fx
	r.compliant == false
	r.failed_controls == 1
	some v in r.violations
	startswith(v, "CIS 1.1.1:")
}}
"""]
    if ng_only:
        body.append(f"""test_next_generation_is_opt_in if {{
	fx := json.remove({fx}, ["cis_profile/next_generation"])
	r := data.{PKG}.{sec(ng_only)}.compliance_report with input as fx
	r.results["{ng_only}"] == "not_applicable"
	data.{PKG}.lib.results["{ng_only}"] == "pass" with input as {fx}
}}
""")
    files["test_main.rego"] = "\n".join(body)

    automated = sum(1 for c in checks.values() if c["kind"] != "manual")
    files["test_complete.rego"] = head + f"""package {PKG}_test

import rego.v1

test_every_automated_recommendation_has_a_row if {{
	count(data.{PKG}.evaluated_control_ids) == {automated}
}}

test_full_scope_matches_the_workbook if {{
	count(data.{PKG}.applicable_ids) == {total} with input as {fx}
}}

test_level_1_scope_matches_the_workbook if {{
	fx := json.patch({fx}, [{{"op": "replace", "path": "/cis_profile", "value": {{"level": 1}}}}])
	count(data.{PKG}.applicable_ids) == {l1} with input as fx
}}
"""

    manual_in_l1 = sum(1 for rid in MANUAL if recs[rid]["profiles"] == ["L1"])
    attest = [head + f"""package {PKG}.attestation_test

import rego.v1

test_unattested_manual_recommendation_is_a_violation if {{
	fx := json.remove({fx}, ["attestations"])
	r := data.{PKG}.main.compliance_report with input as fx
	r.compliant == false
	r.unattested_controls == {len(MANUAL)}
}}

test_manual_recommendations_are_level_1 if {{
	fx := json.patch(json.remove({fx}, ["attestations"]), [{{"op": "replace", "path": "/cis_profile", "value": {{"level": 1}}}}])
	r := data.{PKG}.main.compliance_report with input as fx
	r.unattested_controls == {manual_in_l1}
}}

test_incomplete_attestation_is_not_evidence if {{
	fx := json.patch({fx}, [{{"op": "replace", "path": "/attestations/0/evidence_ref", "value": null}}])
	r := data.{PKG}.attestation.compliance_report with input as fx
	some v in r.violations
	contains(v, "not admissible evidence")
}}

test_complete_attestation_passes if {{
	r := data.{PKG}.attestation.compliance_report with input as {fx}
	r.compliant == true
}}
"""]
    for rid in sorted(MANUAL):
        t = rid.replace(".", "_")
        attest.append(f"""test_{t}_attested_passes if {{
	r := data.{PKG}.attestation.compliance_report with input as {fx}
	"{rid}" in r.passed_control_ids
}}

test_{t}_unattested_is_a_violation if {{
	fx := json.patch({fx}, [{{"op": "replace", "path": "/attestations", "value": []}}])
	r := data.{PKG}.attestation.compliance_report with input as fx
	not "{rid}" in r.passed_control_ids
	some v in r.violations
	startswith(v, "CIS {rid}:")
}}
""")
    files["test_attestation.rego"] = "\n".join(attest)

    files["test_lib.rego"] = lib_tests()
    return files


LIB_TEST_CHANGES = [
    ('ms := {"role": "member_server", "level": 2}', 'ms := {"level": 2}'),
    ('"profiles": ["L1_DC", "L1_MS"]', '"profiles": ["L1"]'),
    ('"profiles": ["L1_MS"]', '"profiles": ["L1"]'),
    ('"profiles": ["L2_MS"]', '"profiles": ["L2"]'),
    ('{"cis_profile": {"role": "member_server", "level": 1}, ', '{"cis_profile": {"level": 1}, '),
    ("""test_role_specific_row_is_not_assessed_without_a_role if {
	row := {"kind": "reg", "profiles": ["L1"], "path": "HKLM\\\\X", "name": "V", "op": "eq", "value": 1}
	status(row) == "not_assessed" with input as {"registry": {"HKLM\\\\X": {"V": 1}}}
}

test_row_for_both_roles_is_assessed_without_a_role if {
	status(reg("eq", 1)) == "pass" with input as {"registry": {"HKLM\\\\X": {"V": 1}}}
}
""", """test_row_is_assessed_without_a_profile if {
	status(reg("eq", 1)) == "pass" with input as {"registry": {"HKLM\\\\X": {"V": 1}}}
}

test_bitlocker_row_needs_the_opt_in if {
	row := {"kind": "reg", "profiles": ["BL"], "path": "HKLM\\\\X", "name": "V", "op": "eq", "value": 1}
	status(row) == "not_applicable" with input as with_value(1)
	status(row) == "pass" with input as {"cis_profile": {"level": 2, "bitlocker": true}, "registry": {"HKLM\\\\X": {"V": 1}}}
	status(row) == "fail" with input as {"cis_profile": {"level": 1, "bitlocker": true}, "registry": {"HKLM\\\\X": {"V": 0}}}
}

test_next_generation_row_needs_the_opt_in if {
	row := {"kind": "reg", "profiles": ["NG"], "path": "HKLM\\\\X", "name": "V", "op": "eq", "value": 1}
	status(row) == "not_applicable" with input as with_value(1)
	status(row) == "pass" with input as {"cis_profile": {"level": 1, "next_generation": true}, "registry": {"HKLM\\\\X": {"V": 1}}}
}

test_numeric_ne_rejects_the_ruled_out_value_only if {
	status(reg("ne", 3)) == "fail" with input as with_value(3)
	status(reg("ne", 3)) == "fail" with input as with_value("3")
	status(reg("ne", 3)) == "pass" with input as with_value(1)
	status(reg("ne", 3)) == "fail" with input as {"cis_profile": ms, "registry": {"HKLM\\\\Other": {"V": 1}}}
}

test_key_values_need_every_listed_string if {
	row := {"kind": "reg_key_values", "profiles": ["L1"], "path": "HKLM\\\\K", "values": ["{a}", "{b}"]}
	status(row) == "pass" with input as {"cis_profile": ms, "registry": {"HKLM\\\\K": {"1": "{A}", "2": "{b}", "3": "{c}"}}}
	status(row) == "fail" with input as {"cis_profile": ms, "registry": {"HKLM\\\\K": {"1": "{a}"}}}
	status(row) == "fail" with input as {"cis_profile": ms, "registry": {"HKLM\\\\Other": {"1": "{a}"}}}
}
"""),
    ("""# Copied into benchmarks/cis/windows_server_2022_modular/tests/test_lib.rego by
# tools/cis_generators/gen_windows_server_2022.py -- edit the copy under tools/.
""", f"""# Written into benchmarks/cis/{DIR}/tests/test_lib.rego by {GENERATOR} from
# tools/cis_generators/windows_lib_test.rego.tmpl with the workstation profile model substituted -- edit those.
"""),
]


def lib_tests():
    return _rename(_sub((HERE / "windows_lib_test.rego.tmpl").read_text(), LIB_TEST_CHANGES, "windows_lib_test.rego.tmpl"))


# ---------------------------------------------------------------------------------------------------------------
# README
# ---------------------------------------------------------------------------------------------------------------

def readme(recs, checks, section_names):
    kinds = {}
    for c in checks.values():
        kinds[c["kind"]] = kinds.get(c["kind"], 0) + 1
    tiers = {t: sum(1 for r in recs.values() if r["profiles"] == [t]) for t in ("L1", "L2", "BL", "NG")}
    rows = []
    for s, name in base.SECTIONS.items():
        n = sum(1 for r in recs.values() if r["section"] == s)
        m = sum(1 for rid in MANUAL if recs[rid]["section"] == s)
        rows.append(f"| {s} {section_names[s].split(' (')[0]} | `{name}_validation.rego` | {n}{f' ({m} Manual)' if m else ''} |")
    ng = (f"| `next_generation` | `true` to add the Next Generation Windows Security profile ({tiers['NG']} recommendations) | off |\n"
          if tiers["NG"] else
          "| `next_generation` | accepted for parity with the Windows 10 module; this benchmark publishes no Next Generation profile | off |\n")
    manual = ", ".join(sorted(MANUAL, key=lambda i: [int(p) for p in i.split(".")]))
    return f"""# {BENCHMARK} v{VERSION}

**Version:** v1.0 · generated {datetime.date.today().isoformat()} by `{GENERATOR}` from the CIS workbook

All {len(recs)} recommendations: {len(recs) - len(MANUAL)} evaluated from facts, and the {len(MANUAL)} that CIS marks Manual ({manual})
reported as requiring operator attestation. CI checks every cited id and its wording against the benchmark's
enumeration (`data/{INDEX_NAME}`, keyword digest, no CIS prose) and proves the evaluated rows and the attestation
ledger account for every recommendation exactly once.

Query: `POST /v1/data/{PKG}/main/compliance_report`

## Sections

| Section | Module | Recommendations |
|---|---|---|
{chr(10).join(rows)}

Each section module is a `controls` table, one row per recommendation; `lib.rego` evaluates every row by its
`kind`. The section names come from the workbook.

## Profile

`input.cis_profile` selects the recommendations in scope. The workstation benchmarks have no server role.

| Field | Values | When absent |
|---|---|---|
| `level` | `1`, `2` (Level 2 includes Level 1) | `2`, the stricter selection; the report says `level_defaulted: true` |
| `bitlocker` | `true` to add the BitLocker profile ({tiers['BL']} recommendations) | off: CIS publishes it as a separate profile |
{ng}
`total_controls` is the number in scope: {tiers['L1']} at Level 1, {tiers['L1'] + tiers['L2']} at Level 2, every opt-in adds its own, out of
`benchmark_total_controls` {len(recs)}.

## Facts

The same shape the Windows Server modules and the Windows STIG modules read, so one collector feeds them all.
`data/collector_manifest.json` lists every value the checks read.

| Input | Shape | Source |
|---|---|---|
| `registry` | `{{"HKLM\\\\<path>": {{"<value>": <int, string or list>}}}}`, paths exactly as listed in the manifest | registry |
| `registry_users` | `{{"<user SID>": {{"<path below HKU\\\\<SID>>": {{"<value>": ...}}}}}}`, every loaded user hive | section 19 |
| `audit_policy` | `{{"<subcategory GUID, lower case, braces>": <0 none, 1 success, 2 failure, 3 both>}}` | `auditpol /backup` |
| `secedit` | `{{"system_access": {{<key>: <value>}}, "privilege_rights": {{<constant>: [<SID>]}}}}` | `secedit /export` |
| `attestations` | `[{{control_id, attested_by, attested_on, evidence_ref}}]`, each a non-empty string | operator, for the {len(MANUAL)} Manual recommendations |

A recommendation whose input is missing or empty is **not assessed** (counted as failed, and the section is
listed in `sections_not_assessed` with the missing input). A value missing from a collected key fails: the
benchmark's state is a configured value, not the operating system default.

## How each recommendation is decided

- **Registry** ({kinds.get('reg', 0)} single values, {kinds.get('reg_all', 0)} multi-value, {kinds.get('reg_absent', 0)} must-not-exist, {kinds.get('ureg', 0)} per-user, {kinds.get('reg_key_values', 0)} numbered-values key). The value is the one
  the audit procedure states; the operator comes from the title: "or more" `>=`, "or fewer" `<=`, "but not 0"
  excludes 0 (and negatives), "between 5 and 14" a range, "NOT set to" a numeric must-not-equal, otherwise
  equality. Where the audit procedure lists several accepted values, any of them passes. Numbers held as `REG_SZ`
  compare numerically. "Is configured" text values pass when non-empty; the two remotely accessible registry path
  lists are compared as sets. Per-user values must hold in every loaded user hive.
- **Account policy and secedit-backed security options** ({kinds.get('secedit', 0)}): the `[System Access]` key named in
  `SECEDIT` in the generator. `LockoutDuration` 0 or -1 (locked until an administrator unlocks) passes the
  "15 or more minutes" recommendation. Names are compared without secedit's double quotes.
- **User rights** ({kinds.get('rights', 0)}): Microsoft's privilege constants and well-known SIDs. "Is set to" lists the only principals
  allowed to hold the right (a narrower assignment passes); "to include" needs every named principal; "No One"
  needs an empty assignment.
- **Audit policy** ({kinds.get('auditpol', 0)}): the subcategory GUID from the audit procedure. The setting is a minimum.

## Regenerating

```
python3 {GENERATOR} <workbook>.xlsx
python3 scripts/coverage_stamp.py
```

The workbook is CIS-licensed and is not committed. The generator aborts if the recommendation count, a Manual
status, a section or a hand-written entry's title keyword differs from the workbook, if a recommendation has no
logic, if a check names a registry value its audit procedure does not, or if the compliant fixture it
synthesises for the tests would need two values for one fact.

## Tests

`tests/` (generated): a compliant workstation with every profile opted in, on which every recommendation passes and
the report counts the whole benchmark; per recommendation, the same host with that recommendation's facts broken
(must fail) and with its input not collected (must be not assessed); profile scopes against the workbook's
counts; empty input fails closed; attestation behaviour. `tests/test_lib.rego` pins the evaluator's comparisons.

Co-authored with Claude (Anthropic).
"""


# ---------------------------------------------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------------------------------------------

def generate(workbook):
    configure()
    out = base.OUT
    recs, section_names = load(pathlib.Path(workbook))
    base.TOTAL.clear()
    base.TOTAL.update(recs)
    if len(recs) != TOTAL_RECS:
        sys.exit(f"workbook has {len(recs)} recommendations, expected {TOTAL_RECS}")
    for table, label in ((SECEDIT, "SECEDIT"), (MANUAL, "MANUAL"), (REGISTRY_OVERRIDES, "REGISTRY_OVERRIDES"),
                         (KEY_VALUES, "KEY_VALUES"), (TITLE_WORDS, "TITLE_WORDS")):
        stray = sorted(set(table) - set(recs))
        if stray:
            sys.exit(f"{label} names ids the workbook does not contain: {stray}")
    manual = {rid for rid, r in recs.items() if r["status"] == "Manual"}
    if manual != set(MANUAL):
        sys.exit(f"Manual recommendations changed: workbook {sorted(manual)}, table {sorted(MANUAL)}")
    if set(base.SECTIONS) != {r["section"] for r in recs.values()}:
        sys.exit(f"sections changed: {sorted({r['section'] for r in recs.values()})}")
    hand = set(SECEDIT) | set(MANUAL) | set(REGISTRY_OVERRIDES) | set(KEY_VALUES)
    if hand - set(TITLE_WORDS):
        sys.exit(f"hand-written entries without a title keyword: {sorted(hand - set(TITLE_WORDS))}")
    for rid, words in TITLE_WORDS.items():
        if words not in recs[rid]["title"]:
            sys.exit(f"{rid}: title no longer matches the hand-written logic ({recs[rid]['title']!r})")

    checks = {rid: derive(rec) for rid, rec in recs.items()}
    for rid, c in checks.items():
        names = ([c["name"]] if "name" in c else []) + [i[1] for i in c.get("items", [])]
        for n in names:
            if n not in recs[rid]["audit"]:
                sys.exit(f"{rid}: checks {n!r}, which its audit procedure does not name")

    files = {}
    for sec in base.SECTIONS:
        in_sec = {rid: r for rid, r in recs.items() if r["section"] == sec}
        files[f"{base.SECTIONS[sec]}_validation.rego"] = base.section_module(sec, section_names[sec], in_sec, checks)
    files["attestation_validation.rego"] = base.attestation_module(recs)
    files[f"{PKG}_complete.rego"] = complete_module(recs)
    files[f"{PKG}_main.rego"] = main_module()
    files["lib.rego"] = lib_text()
    test_files = tests(recs, checks)

    stale = ["2022", "408", "member_server", "domain_controller", "server role", "_MS", "_DC"]
    if VERSION != "5.1.0":
        stale.append("5.1.0")
    for name, text in list(files.items()) + list(test_files.items()):
        for s in stale:
            if s in text:
                sys.exit(f"{name}: still mentions {s!r}")

    for old in list(out.glob("*.rego")) + list((out / "tests").glob("*.rego")):
        old.unlink()
    (out / "data").mkdir(parents=True, exist_ok=True)
    (out / "tests").mkdir(exist_ok=True)
    for name, text in files.items():
        (out / name).write_text(text)
    for name, text in test_files.items():
        (out / "tests" / name).write_text(text)
    (out / "data" / INDEX_NAME).write_text(json.dumps(base.index_doc(recs, section_names), indent=2) + "\n")
    (out / "data" / "collector_manifest.json").write_text(
        json.dumps({"collector_manifest": manifest(checks)}, indent=2) + "\n")
    (out / "README.md").write_text(readme(recs, checks, section_names))

    kinds = {}
    for c in checks.values():
        kinds[c["kind"]] = kinds.get(c["kind"], 0) + 1
    tiers = {t: sum(1 for r in recs.values() if r["profiles"] == [t]) for t in ("L1", "L2", "BL", "NG")}
    print(f"{BENCHMARK} v{VERSION}: {len(recs)} recommendations ({len(recs) - len(MANUAL)} Automated, {len(MANUAL)} Manual), "
          f"profiles {tiers} -> {kinds}")


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    generate(sys.argv[1])


if __name__ == "__main__":
    main()
