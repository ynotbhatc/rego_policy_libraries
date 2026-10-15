#!/usr/bin/env python3
"""Generate the CIS Microsoft Windows Server 2022 Benchmark v5.1.0 module from the benchmark's own workbook.

    python3 tools/cis_generators/gen_windows_server_2022.py <CIS_Microsoft_Windows_Server_2022_Benchmark_v5.1.0.xlsx>

The workbook is CIS-licensed and is not committed. This script reads its "Combined Profiles" sheet with the
standard library (no openpyxl), derives one check per recommendation, and writes:

  benchmarks/cis/windows_server_2022_modular/
    <section>.rego                 one module per benchmark section; a `controls` table, one row per recommendation
    lib.rego                       the evaluator every section shares
    attestation_validation.rego    the two recommendations CIS marks Manual
    cis_windows_server_2022_complete.rego, cis_windows_2022_main.rego   aggregation and the report contract
    data/cis_windows_server_2022_v5_1_index.json    keyword-digest enumeration (no verbatim CIS prose)
    data/collector_manifest.json   every registry value, audit subcategory and secedit key the checks read
    tests/test_cis_windows_server_2022_generated.rego

Derivation. 283 recommendations state one registry value in their audit procedure; the comparison operator comes
from the title ("or more", "or fewer, but not 0", "between 5 and 14"), never from the literal alone, because the
audit text gives only the recommended value. Recommendations whose audit text names several values, a value that
must not exist, or a list, are derived from that text too. The rest have no registry location (account policy,
user rights, a few security options, audit subcategories) and take their logic from the hand-written tables
below. Every recommendation must end up with exactly one check: a recommendation with no logic, or logic for an
id the workbook does not contain, aborts the run.
"""
from __future__ import annotations

import json
import pathlib
import re
import sys
import xml.etree.ElementTree as ET
import zipfile

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
OUT = ROOT / "benchmarks" / "cis" / "windows_server_2022_modular"
sys.path.insert(0, str(ROOT / "scripts"))
from check_cis_ids import keywords  # noqa: E402  the same tokeniser the guard uses

BENCHMARK = "CIS Microsoft Windows Server 2022 Benchmark"
VERSION = "5.1.0"
PKG = "cis_windows_server_2022"

SECTIONS = {  # section number -> (package, file stem)
    "1": "account_policies",
    "2": "local_policies",
    "5": "system_services",
    "9": "firewall",
    "17": "advanced_audit",
    "18": "admin_templates_computer",
    "19": "admin_templates_user",
}

PROFILE_CODES = {
    "Level 1 - Domain Controller": "L1_DC",
    "Level 1 - Member Server": "L1_MS",
    "Level 2 - Domain Controller": "L2_DC",
    "Level 2 - Member Server": "L2_MS",
    "Next Generation Windows Security - Domain Controller": "NG_DC",
    "Next Generation Windows Security - Member Server": "NG_MS",
}

# ---------------------------------------------------------------------------------------------------------------
# Hand-written logic: recommendations whose audit procedure names no registry value.
# ---------------------------------------------------------------------------------------------------------------

# Section 1 and the secedit-backed security options: `secedit /export /areas SECURITYPOLICY`, [System Access].
SECEDIT = {
    "1.1.1": ("PasswordHistorySize", "ge", 24),
    "1.1.2": ("MaximumPasswordAge", "le_not0", 365),     # -1 (never expires) fails, as 0 does
    "1.1.3": ("MinimumPasswordAge", "ge", 1),
    "1.1.4": ("MinimumPasswordLength", "ge", 14),
    "1.1.5": ("PasswordComplexity", "eq", 1),
    "1.1.7": ("ClearTextPassword", "eq", 0),
    "1.2.1": ("LockoutDuration", "ge_or_forever", 15),   # 0 or -1 = locked until an administrator unlocks: stricter
    "1.2.2": ("LockoutBadCount", "le_not0", 5),
    "1.2.4": ("ResetLockoutCount", "ge", 15),
    "2.3.1.1": ("EnableGuestAccount", "eq", 0),
    "2.3.1.3": ("NewAdministratorName", "ne", "Administrator"),
    "2.3.1.4": ("NewGuestName", "ne", "Guest"),
    "2.3.10.1": ("LSAAnonymousNameLookup", "eq", 0),
}

# CIS marks these Manual. They are reported as requiring attestation, never evaluated.
MANUAL = {
    "1.2.3": "Administrator account lockout allowed",
    "2.3.11.6": "users forced off when logon hours expire",
}

# Section 2.2: user rights, `secedit /export /areas USER_RIGHTS`, [Privilege Rights]. Microsoft's constants.
PRIVILEGES = {
    "Access Credential Manager as a trusted caller": "SeTrustedCredManAccessPrivilege",
    "Access this computer from the network": "SeNetworkLogonRight",
    "Act as part of the operating system": "SeTcbPrivilege",
    "Add workstations to domain": "SeMachineAccountPrivilege",
    "Adjust memory quotas for a process": "SeIncreaseQuotaPrivilege",
    "Allow log on locally": "SeInteractiveLogonRight",
    "Allow log on through Remote Desktop Services": "SeRemoteInteractiveLogonRight",
    "Back up files and directories": "SeBackupPrivilege",
    "Change the system time": "SeSystemtimePrivilege",
    "Create a pagefile": "SeCreatePagefilePrivilege",
    "Create a token object": "SeCreateTokenPrivilege",
    "Create global objects": "SeCreateGlobalPrivilege",
    "Create permanent shared objects": "SeCreatePermanentPrivilege",
    "Create symbolic links": "SeCreateSymbolicLinkPrivilege",
    "Debug programs": "SeDebugPrivilege",
    "Deny access to this computer from the network": "SeDenyNetworkLogonRight",
    "Deny log on as a batch job": "SeDenyBatchLogonRight",
    "Deny log on as a service": "SeDenyServiceLogonRight",
    "Deny log on locally": "SeDenyInteractiveLogonRight",
    "Deny log on through Remote Desktop Services": "SeDenyRemoteInteractiveLogonRight",
    "Enable computer and user accounts to be trusted for delegation": "SeEnableDelegationPrivilege",
    "Force shutdown from a remote system": "SeRemoteShutdownPrivilege",
    "Generate security audits": "SeAuditPrivilege",
    "Impersonate a client after authentication": "SeImpersonatePrivilege",
    "Increase scheduling priority": "SeIncreaseBasePriorityPrivilege",
    "Load and unload device drivers": "SeLoadDriverPrivilege",
    "Lock pages in memory": "SeLockMemoryPrivilege",
    "Log on as a batch job": "SeBatchLogonRight",
    "Manage auditing and security log": "SeSecurityPrivilege",
    "Modify an object label": "SeRelabelPrivilege",
    "Modify firmware environment values": "SeSystemEnvironmentPrivilege",
    "Perform volume maintenance tasks": "SeManageVolumePrivilege",
    "Profile single process": "SeProfileSingleProcessPrivilege",
    "Profile system performance": "SeSystemProfilePrivilege",
    "Replace a process level token": "SeAssignPrimaryTokenPrivilege",
    "Restore files and directories": "SeRestorePrivilege",
    "Shut down the system": "SeShutdownPrivilege",
    "Synchronize directory service data": "SeSyncAgentPrivilege",
    "Take ownership of files or other objects": "SeTakeOwnershipPrivilege",
}

# Principals named in section 2.2 titles -> SIDs as secedit exports them (leading '*' stripped by the collector).
# NT SERVICE\WdiServiceHost is a service SID: S-1-5-80- followed by the SHA-1 of the upper-cased service name.
SIDS = {
    "Administrators": "S-1-5-32-544",
    "Authenticated Users": "S-1-5-11",
    "ENTERPRISE DOMAIN CONTROLLERS": "S-1-5-9",
    "Guests": "S-1-5-32-546",
    "LOCAL SERVICE": "S-1-5-19",
    "Local account": "S-1-5-113",
    "Local account and member of Administrators group": "S-1-5-114",
    "NETWORK SERVICE": "S-1-5-20",
    "NT SERVICE\\WdiServiceHost": "S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420",
    "NT VIRTUAL MACHINE\\Virtual Machines": "S-1-5-83-0",
    "Remote Desktop Users": "S-1-5-32-555",
    "SERVICE": "S-1-5-6",
    "Window Manager\\Window Manager Group": "S-1-5-90-0",
}

# Registry-backed recommendations the generic derivation cannot read unaided. Each names the value(s) it checks;
# the generator confirms every named value appears in that recommendation's audit text.
REGISTRY_OVERRIDES = {
    # "or less, but not 0" written without backticks around the type
    "2.3.6.5": ("reg", "le_not0", 30),
    "2.3.7.3": ("reg", "le_not0", 900),
    "2.3.7.6": ("reg", "le", 4),               # CachedLogonsCount is REG_SZ holding a number
    "2.3.7.7": ("reg", "range", [5, 14]),
    "18.10.57.3.10.1": ("reg", "le_not0", 900000),
    # the value must not exist (or, for the MULTI_SZ, be empty)
    "2.3.5.2": ("reg_absent", None, None),
    "2.3.10.12": ("reg_absent", None, None),
    "18.9.19.5": ("reg_absent", None, None),
    # the audit procedure gives no value; the title says 'Enabled', which this policy writes as 1
    "19.7.8.5": ("ureg", "eq", 1),
}

TITLE_STATES = {"Enabled": 1, "Disabled": 0}


# ---------------------------------------------------------------------------------------------------------------
# Workbook
# ---------------------------------------------------------------------------------------------------------------

def read_sheet(path: pathlib.Path, wanted: str):
    ns = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
          "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships"}
    z = zipfile.ZipFile(path)
    strings = []
    if "xl/sharedStrings.xml" in z.namelist():
        for si in ET.fromstring(z.read("xl/sharedStrings.xml")).findall("m:si", ns):
            strings.append("".join(t.text or "" for t in si.iter("{%s}t" % ns["m"])))
    rels = {r.get("Id"): r.get("Target") for r in ET.fromstring(z.read("xl/_rels/workbook.xml.rels"))}
    for s in ET.fromstring(z.read("xl/workbook.xml")).find("m:sheets", ns):
        if s.get("name") != wanted:
            continue
        target = rels[s.get("{%s}id" % ns["r"])].lstrip("/")
        target = target if target.startswith("xl/") else "xl/" + target
        rows = []
        for row in ET.fromstring(z.read(target)).iter("{%s}row" % ns["m"]):
            cells = {}
            for c in row.findall("m:c", ns):
                col = 0
                for ch in re.match(r"[A-Z]+", c.get("r")).group():
                    col = col * 26 + ord(ch) - 64
                v, t = c.find("m:v", ns), c.get("t")
                if t == "inlineStr":
                    cells[col - 1] = "".join(x.text or "" for x in c.iter("{%s}t" % ns["m"]))
                elif v is not None:
                    cells[col - 1] = strings[int(v.text)] if t == "s" else v.text
            if cells:
                rows.append([cells.get(i) for i in range(max(cells) + 1)])
        return rows
    sys.exit(f"sheet {wanted!r} not found in {path}")


def load(path):
    rows = read_sheet(path, "Combined Profiles")
    ix = {h: i for i, h in enumerate(rows[0])}
    recs, section_names = {}, {}
    for r in rows[1:]:
        cell = lambda name: (r[ix[name]] if ix[name] < len(r) else None) or ""  # noqa: E731
        sec, rid = cell("Section #"), cell("Recommendation #")
        if sec and not rid and "." not in sec:
            section_names[sec] = cell("Title")
        if not rid:
            continue
        if rid in recs:
            sys.exit(f"{rid} appears twice in Combined Profiles")
        profiles = sorted(PROFILE_CODES[p.strip()] for p in cell("Profile").split(" + "))
        recs[rid] = {"id": rid, "title": " ".join(cell("Title").split()), "status": cell("Assessment Status"),
                     "profiles": profiles, "audit": cell("Audit Procedure"), "section": rid.split(".")[0]}
    return recs, section_names


# ---------------------------------------------------------------------------------------------------------------
# Derivation
# ---------------------------------------------------------------------------------------------------------------

HIVES = {"HKEY_LOCAL_MACHINE": "HKLM", "HKLM": "HKLM"}
USER_PREFIX = re.compile(r"^(HKU|HKEY_USERS)\\\[USER SID\]\\", re.I)


def registry_locations(audit):
    """Every hive\\path:value line inside the audit procedure's code fences, as (scope, path, name)."""
    out = []
    for block in re.findall(r"```(.*?)```", audit, re.S):
        for line in block.splitlines():
            line = line.strip()
            if not line.upper().startswith("HK"):
                continue
            path, _, name = line.rpartition(":")
            if not path or not name:
                continue
            if USER_PREFIX.match(path):
                out.append(("user", USER_PREFIX.sub("", path), name))
                continue
            hive, _, rest = path.partition("\\")
            if hive.upper() not in HIVES:
                sys.exit(f"unrecognised hive in {line!r}")
            out.append(("machine", HIVES[hive.upper()] + "\\" + rest, name))
    return out


def stated_values(audit):
    """The values the audit text states: [(type, value)] and per-name pairs {name: value}."""
    # "value of `1`", "value of `1` or `2`", "value of `1`, `2`, or `3`": every listed value is accepted
    single = []
    for rtype, listed in re.findall(
            r"`(REG_[A-Z_]+)`(?: or `REG_[A-Z_]+`)? value (?:of|that is) ((?:`[^`]*`(?:\s*,\s*or\s*|\s*,\s*|\s*or\s*)?)+)",
            audit):
        vals = re.findall(r"`([^`]*)`", listed)
        single.append((rtype, vals[0] if len(vals) == 1 else vals))
    named = dict((n, v) for v, n in re.findall(r"`([^`]+)` \((\w+)\)", audit))
    return single, named


def literal(rtype, raw):
    if rtype == "REG_DWORD":
        return int(raw)
    if rtype == "REG_MULTI_SZ":
        return [p for p in raw.split(",") if p]
    return raw


def op_from_title(title, value):
    m = re.search(r"between (\d+) and (\d+)", title)
    if m:
        return "range", [int(m.group(1)), int(m.group(2))]
    t = title.lower()
    if re.search(r"or (more|greater)", t):
        return "ge", value
    if re.search(r"or (fewer|less)", t):
        return ("le_not0" if "but not" in t else "le"), value
    return "eq", value


def derive_registry(rec):
    locs = registry_locations(rec["audit"])
    if not locs:
        return None
    single, named = stated_values(rec["audit"])
    scope = {s for s, _, _ in locs}
    if len(scope) != 1:
        sys.exit(f"{rec['id']}: mixes machine and per-user locations")
    user = scope == {"user"}
    title = rec["title"]

    if rec["id"] in REGISTRY_OVERRIDES:
        kind, op, value = REGISTRY_OVERRIDES[rec["id"]]
        if len(locs) != 1:
            sys.exit(f"{rec['id']}: override expects one location, found {len(locs)}")
        _, path, name = locs[0]
        if kind == "reg_absent":
            return {"kind": "reg_absent", "path": path, "name": name}
        return {"kind": "ureg" if user else "reg", "path": path, "name": name, "op": op, "value": value}

    # one location, one stated value
    if len(locs) == 1 and len(single) == 1 and isinstance(single[0][1], list):
        rtype, raws = single[0]
        _, path, name = locs[0]
        if not all(re.fullmatch(r"\d+", r) for r in raws):
            sys.exit(f"{rec['id']}: non-numeric alternatives {raws}")
        return {"kind": "ureg" if user else "reg", "path": path, "name": name, "op": "in",
                "value": [int(r) for r in raws]}

    if len(locs) == 1 and len(single) == 1:
        rtype, raw = single[0]
        _, path, name = locs[0]
        if rtype in ("REG_SZ", "REG_EXPAND_SZ") and (raw == "text" or "<" in raw):
            return {"kind": "reg", "path": path, "name": name, "op": "nonempty", "value": ""}
        if rtype == "REG_MULTI_SZ":
            if raw == "blank":
                return {"kind": "reg_absent", "path": path, "name": name}
            return {"kind": "reg", "path": path, "name": name, "op": "set", "value": literal(rtype, raw)}
        op, value = op_from_title(title, literal(rtype, raw))
        if rtype == "REG_SZ" and op == "eq" and re.fullmatch(r"\d+", raw):
            value = int(raw)  # "0"/"1" held as REG_SZ: compared numerically, either representation passes
        return {"kind": "ureg" if user else "reg", "path": path, "name": name, "op": op, "value": value}

    # several locations: one shared value, or a value per name
    if len(locs) > 1 and not user:
        items = []
        if named:
            for _, path, name in locs:
                if name not in named:
                    sys.exit(f"{rec['id']}: no stated value for {name}")
                raw = named[name]
                items.append([path, name, "eq", int(raw) if re.fullmatch(r"\d+", raw) else raw])
        elif len(single) >= 1 and all(isinstance(v, str) for _, v in single) and len({v for _, v in single}) == 1:
            rtype, raw = single[0]
            if rtype == "REG_SZ" and "=" in raw:  # hardened UNC paths: a flag list, compared flag by flag
                flags = [p.strip() for p in raw.split(",")]
                items = [[path, name, "has_all", flags] for _, path, name in locs]
            else:
                items = [[path, name, "eq", int(raw)] for _, path, name in locs]
        else:
            return None
        return {"kind": "reg_all", "items": items}
    return None


def derive_audit(rec):
    guids = re.findall(r"\{[0-9a-fA-F-]{36}\}", rec["audit"])
    m = re.search(r"(?:is set to|to include) '(Success and Failure|Success|Failure)'", rec["title"])
    if len(set(g.lower() for g in guids)) != 1 or not m:
        sys.exit(f"{rec['id']}: cannot derive the audit subcategory or setting")
    # auditpol /backup reports a bitmask: 1 success, 2 failure, 3 both. The benchmark's setting is a minimum:
    # auditing more than it asks is never weaker, so the required bits must all be set.
    bits = {"Success": 1, "Failure": 2, "Success and Failure": 3}[m.group(1)]
    return {"kind": "auditpol", "guid": guids[0].lower(), "bits": bits}


def derive_rights(rec):
    m = re.match(r"Ensure '([^']+)'\s+(is set to|to include) '([^']+)'", rec["title"])
    if not m:
        sys.exit(f"{rec['id']}: cannot parse the user-rights title {rec['title']!r}")
    right, verb, who = m.groups()
    if right not in PRIVILEGES:
        sys.exit(f"{rec['id']}: no privilege constant for {right!r}")
    if who == "No One":
        return {"kind": "rights", "privilege": PRIVILEGES[right], "mode": "none", "sids": []}
    names = [n.strip() for n in who.split(",")]
    missing = [n for n in names if n not in SIDS]
    if missing:
        sys.exit(f"{rec['id']}: no SID for {missing}")
    # "is set to" lists the only principals allowed to hold the right; "to include" lists principals that must.
    return {"kind": "rights", "privilege": PRIVILEGES[right], "mode": "only" if verb == "is set to" else "include",
            "sids": [SIDS[n] for n in names]}


def derive(rec):
    rid = rec["id"]
    if rid in MANUAL:
        return {"kind": "manual"}
    if rid in SECEDIT:
        key, op, value = SECEDIT[rid]
        return {"kind": "secedit", "key": key, "op": op, "value": value}
    if rec["section"] == "17":
        return derive_audit(rec)
    if rid.startswith("2.2."):
        return derive_rights(rec)
    check = derive_registry(rec)
    if check is None:
        sys.exit(f"{rid}: no logic derived and no hand-written rule ({rec['title']})")
    return check


# ---------------------------------------------------------------------------------------------------------------
# Rego emission
# ---------------------------------------------------------------------------------------------------------------

def rego(value):
    """JSON is valid Rego for every term this module emits."""
    return json.dumps(value)


HEADER = """# Generated by tools/cis_generators/gen_windows_server_2022.py from the CIS workbook -- do not edit.
# {benchmark} v{version}
"""

METADATA = """# METADATA
# title: "{title}"
# custom:
#   class: security
#   framework: cis_windows_server_2022_modular
#   source: cis
#   domains: [windows]
"""


def section_module(sec, name, recs, checks):
    rows = []
    for rid in sorted(recs, key=lambda i: [int(p) for p in i.split(".")]):
        rec, check = recs[rid], checks[rid]
        if check["kind"] == "manual":
            continue
        row = {"msg": f"CIS {rid}: {rec['title']}", "profiles": rec["profiles"], **check}
        body = ", ".join(f"{rego(k)}: {rego(v)}" for k, v in row.items())
        rows.append(f"\t{rego(rid)}: {{{body}}},")
    title = f"{BENCHMARK} v{VERSION} - Section {sec}: {name}"
    return (HEADER.format(benchmark=BENCHMARK, version=VERSION)
            + METADATA.format(title=title)
            + f"package {PKG}.{SECTIONS[sec]}\n\nimport data.{PKG}.lib\nimport rego.v1\n\n"
            + "SECTION := {\n"
            + f'\t"section": "{sec}",\n\t"name": {rego(name)},\n'
            + f'\t"section_total_controls": {len(recs)},\n'
            + "}\n\n"
            + "# One row per recommendation; lib.rego evaluates each row by its `kind`.\n"
            + "controls := {\n" + "\n".join(rows) + "\n}\n\n"
            + f"compliance_report := lib.section_reports.{SECTIONS[sec]}\n")


def attestation_module(recs):
    req = {rid: MANUAL[rid] for rid in sorted(MANUAL)}
    profiles = {rid: recs[rid]["profiles"] for rid in sorted(MANUAL)}
    return (HEADER.format(benchmark=BENCHMARK, version=VERSION)
            + METADATA.format(title=f"{BENCHMARK} v{VERSION} - recommendations CIS marks Manual")
            + f"package {PKG}.attestation\n\nimport data.{PKG}.lib\nimport rego.v1\n\n"
            + "# CIS marks these two recommendations Manual. They are never evaluated from facts: each needs an\n"
            + "# operator attestation (control_id, attested_by, attested_on, evidence_ref) in input.attestations,\n"
            + "# and without one it is reported as a violation, never as a pass.\n"
            + "REQUIRES_ATTESTATION := " + json.dumps(req, indent="\t").replace("\n}", ",\n}") + "\n\n"
            + "UNRESOLVED := {}\n\nNOT_IMPLEMENTED := {}\n\n"
            + "PROFILES := " + json.dumps(profiles, indent="\t").replace("\n}", ",\n}") + "\n\n"
            + ATTESTATION_BODY)


ATTESTATION_BODY = r"""default attestations := []

attestations := a if {
	a := input.attestations
	is_array(a)
}

# each field must be a non-empty string: a null or false field is present but is not evidence
_given(v) if {
	is_string(v)
	trim_space(v) != ""
}

attested_ids := {a.control_id |
	some a in attestations
	_given(a.attested_by)
	_given(a.attested_on)
	_given(a.evidence_ref)
}

incomplete_ids := {a.control_id |
	some a in attestations
	a.control_id in object.keys(REQUIRES_ATTESTATION)
	not a.control_id in attested_ids
}

# In the selected profile. With the server role unknown, a recommendation for either role is in scope.
in_scope_ids := lib.attestation_in_scope_ids

violation contains msg if {
	some cid in in_scope_ids
	not cid in attested_ids
	not cid in incomplete_ids
	msg := sprintf("CIS %s: %s -- CIS marks this recommendation Manual, so it requires operator attestation and none has been recorded (this is not a pass)", [cid, REQUIRES_ATTESTATION[cid]])
}

violation contains msg if {
	some cid in incomplete_ids
	cid in in_scope_ids
	msg := sprintf("CIS %s: %s -- an attestation was supplied but is missing attested_by, attested_on or evidence_ref, so it is not admissible evidence (this is not a pass)", [cid, REQUIRES_ATTESTATION[cid]])
}

passed_ids := {cid | some cid in in_scope_ids; cid in attested_ids}

default compliant := false

compliant if count(violation) == 0

compliance_report := {
	"benchmark": "CIS Microsoft Windows Server 2022 Benchmark",
	"benchmark_version": "5.1.0",
	"section": "attestation",
	"name": "Recommendations CIS marks Manual",
	"requires_attestation": REQUIRES_ATTESTATION,
	"requires_attestation_count": count(REQUIRES_ATTESTATION),
	"in_scope_control_ids": in_scope_ids,
	"attested_control_ids": attested_ids,
	"passed_control_ids": passed_ids,
	"evidence_source": "attested",
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}
"""


def complete_module(section_names):
    if len(TOTAL) != 408:
        sys.exit(f"the main report literal states standard_total 408; the workbook has {len(TOTAL)}")
    imports = "\n".join(f"import data.{PKG}.{SECTIONS[s]}" for s in SECTIONS)
    reports = "\n".join(f"\t{SECTIONS[s]}.compliance_report," for s in SECTIONS)
    tables = "\n".join(f"\t{SECTIONS[s]}.controls," for s in SECTIONS)
    return (HEADER.format(benchmark=BENCHMARK, version=VERSION)
            + METADATA.format(title=f"{BENCHMARK} v{VERSION} - every section, aggregated")
            + f"package {PKG}\n\nimport data.{PKG}.attestation\n{imports}\nimport rego.v1\n\n"
            + f"BENCHMARK_TOTAL_CONTROLS := {len(TOTAL)}\n\n"
            + f"section_reports := [\n{reports}\n]\n\n"
            + f"_tables := [\n{tables}\n]\n\n"
            + COMPLETE_BODY)


COMPLETE_BODY = r"""# Static: every recommendation with a check row, whatever the facts or profile. check_cis_coverage.py reads
# this (with empty input) to prove the rows and the attestation ledger partition the benchmark.
evaluated_control_ids := sort([cid | some t in _tables; some cid, _ in t])

results := object.union_n([r.results | some r in section_reports])

applicable_ids := {cid | some cid, s in results; s != "not_applicable"} | attestation.in_scope_ids

passed_ids := {cid | some cid, s in results; s == "pass"} | attestation.passed_ids

failed_ids := {cid | some cid, s in results; s == "fail"}

not_assessed_ids := {cid | some cid, s in results; s == "not_assessed"}

# Unattested Manual recommendations count against the host: unverified is not passed.
unattested_ids := attestation.in_scope_ids - attestation.passed_ids

all_violations := array.concat(
	[v | some r in section_reports; some v in r.violations],
	[v | some v in attestation.violation],
)

# Sections that could assess nothing in scope, and the inputs each one lacked.
not_assessed_sections := [r.name |
	some r in section_reports
	count(r.in_scope) > 0
	count(r.assessed) == 0
]

missing_inputs := {r.name: r.missing_inputs |
	some r in section_reports
	count(r.missing_inputs) > 0
}

section_compliance := {r.name: {
	"in_scope": count(r.in_scope),
	"passed": count(r.passed),
	"failed": count(r.failed),
	"not_assessed": count(r.not_assessed),
} | some r in section_reports}
"""


def main_module():
    return (HEADER.format(benchmark=BENCHMARK, version=VERSION)
            + METADATA.format(title=f"{BENCHMARK} v{VERSION} - compliance_report entrypoint")
            + f"package {PKG}.main\n\nimport data.{PKG} as bench\nimport data.{PKG}.attestation\nimport data.{PKG}.lib\nimport rego.v1\n\n"
            + MAIN_BODY)


MAIN_BODY = r"""# OPA query path: /v1/data/cis_windows_server_2022/main/compliance_report
#
# total_controls is the number of recommendations in scope for the host's profile (input.cis_profile: role,
# level, next_generation), out of the benchmark's 408. Every one in scope is counted: a recommendation that
# could not be assessed (its facts were not collected, the role was not supplied, or a Manual one was not
# attested) is failed, never omitted -- an omitted control reads exactly like a passing one.

default _facts_supplied := false

_facts_supplied if count(object.keys(input)) > 0

_no_facts_msg := "FAIL-CLOSED: no facts supplied for cis_windows_server_2022 — the assessment could not be evaluated. This is NOT a passing result; check that fact collection ran and produced input."

_not_assessed_msgs := [sprintf("NOT ASSESSED: %s — required input not collected: %s", [name, concat(", ", bench.missing_inputs[name])]) |
	some name in bench.not_assessed_sections
	bench.missing_inputs[name]
]

_violations := array.concat(bench.all_violations, [_no_facts_msg]) if not _facts_supplied

_violations := array.concat(bench.all_violations, _not_assessed_msgs) if _facts_supplied

_total := count(bench.applicable_ids)

_passed := count(bench.passed_ids) if _facts_supplied

default _passed := 0

_failed := _total - _passed

# attested Manual recommendations are in passed_ids; unattested ones were not assessed
_assessed := count(bench.passed_ids | bench.failed_ids)

default _percentage := 0

_percentage := round((_passed * 100000) / _total) / 1000 if _total > 0

default _coverage := 0

_coverage := round((_assessed * 100000) / _total) / 1000 if {
	_facts_supplied
	_total > 0
}

default _assessed_percentage := 0

_assessed_percentage := round((count(bench.passed_ids) * 100000) / count(bench.passed_ids | bench.failed_ids)) / 1000 if {
	count(bench.passed_ids | bench.failed_ids) > 0
}

default _compliant := false

_compliant if {
	_facts_supplied
	_total > 0
	_failed == 0
}

_accounted := (count(bench.evaluated_control_ids) + count(attestation.REQUIRES_ATTESTATION)) + (count(attestation.UNRESOLVED) + count(attestation.NOT_IMPLEMENTED))

compliance_report := {
	"framework": "cis_windows_server_2022",
	"benchmark": "CIS Microsoft Windows Server 2022 Benchmark v5.1.0",
	"version": "v5.1.0",
	"profile": lib.profile,
	"benchmark_total_controls": bench.BENCHMARK_TOTAL_CONTROLS,
	"standard_total": 408,
	"total_controls": _total,
	"controls_basis": "recommendations in scope for input.cis_profile (role, level, next_generation)",
	"passed_controls": _passed,
	"failed_controls": _failed,
	"not_assessed_controls": count(bench.not_assessed_ids),
	"unattested_controls": count(bench.unattested_ids),
	"compliance_percentage": _percentage,
	"section_compliance_percentage": _assessed_percentage,
	"compliant": _compliant,
	"violations": _violations,
	"section_results": bench.section_compliance,
	"sections_not_assessed": bench.not_assessed_sections,
	"missing_inputs": bench.missing_inputs,
	"assessment_coverage_percentage": _coverage,
	"evaluated_control_ids": bench.evaluated_control_ids,
	"coverage_accounting": {
		"benchmark_total": bench.BENCHMARK_TOTAL_CONTROLS,
		"evaluated": count(bench.evaluated_control_ids),
		"requires_attestation": count(attestation.REQUIRES_ATTESTATION),
		"unresolved": count(attestation.UNRESOLVED),
		"not_implemented": count(attestation.NOT_IMPLEMENTED),
		"accounted": _accounted,
		"balanced": _accounted == bench.BENCHMARK_TOTAL_CONTROLS,
	},
	"no_collector_path": attestation.compliance_report,
}
"""

TOTAL: dict = {}


def index_doc(recs, section_names):
    out = []
    for rid in sorted(recs, key=lambda i: [int(p) for p in i.split(".")]):
        r = recs[rid]
        out.append({"control_id": rid, "section": int(r["section"]), "section_name": section_names[r["section"]],
                    "assessment": r["status"], "profiles": r["profiles"],
                    "title_keywords": sorted(keywords(r["title"]))})
    return {"benchmark": BENCHMARK, "version": VERSION,
            "source": "official CIS workbook (Combined Profiles sheet)",
            "sections": {s: section_names[s] for s in SECTIONS},
            "total_recommendations": len(out),
            "form": "keyword-digest (no verbatim CIS titles)",
            "recommendations": out}


def manifest(checks):
    reg, ureg, guids, secedit, rights = set(), set(), set(), set(), set()
    for c in checks.values():
        k = c["kind"]
        if k in ("reg", "reg_absent"):
            reg.add((c["path"], c["name"]))
        elif k == "reg_all":
            reg.update((i[0], i[1]) for i in c["items"])
        elif k == "ureg":
            ureg.add((c["path"], c["name"]))
        elif k == "auditpol":
            guids.add(c["guid"])
        elif k == "secedit":
            secedit.add(c["key"])
        elif k == "rights":
            rights.add(c["privilege"])
    return {
        "benchmark": f"{BENCHMARK} v{VERSION}",
        "contract": {
            "cis_profile": "{role: member_server|domain_controller, level: 1|2, next_generation: bool}",
            "registry": "{'<HKLM path as listed>': {'<value name>': <REG_DWORD int | REG_SZ string | REG_MULTI_SZ list>}}; omit a value that does not exist",
            "registry_users": "{'<user SID, S-1-5-21-...>': {'<path below HKU\\\\<SID>\\\\ as listed>': {'<value name>': <value>}}} for every loaded user profile hive; other HKU keys are ignored",
            "audit_policy": "{'<subcategory GUID, lower case, braces>': <auditpol /backup Setting Value: 0 none, 1 success, 2 failure, 3 both>}",
            "secedit": "{system_access: {<key>: <int|string>}, privilege_rights: {<constant>: [<SID without '*'>]}} from secedit /export",
            "attestations": "[{control_id, attested_by, attested_on, evidence_ref}] for the Manual recommendations",
        },
        "registry": [list(x) for x in sorted(reg)],
        "registry_users": [list(x) for x in sorted(ureg)],
        "audit_policy_guids": sorted(guids),
        "secedit_system_access": sorted(secedit),
        "privilege_rights": sorted(rights),
    }


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    recs, section_names = load(pathlib.Path(sys.argv[1]))
    TOTAL.update(recs)
    for table, label in ((SECEDIT, "SECEDIT"), (MANUAL, "MANUAL"), (REGISTRY_OVERRIDES, "REGISTRY_OVERRIDES")):
        stray = sorted(set(table) - set(recs))
        if stray:
            sys.exit(f"{label} names ids the workbook does not contain: {stray}")
    manual = {rid for rid, r in recs.items() if r["status"] == "Manual"}
    if manual != set(MANUAL):
        sys.exit(f"Manual recommendations changed: workbook {sorted(manual)}, table {sorted(MANUAL)}")
    if set(SECTIONS) != {r["section"] for r in recs.values()}:
        sys.exit(f"sections changed: {sorted({r['section'] for r in recs.values()})}")

    checks = {rid: derive(rec) for rid, rec in recs.items()}

    # every value a registry check names must appear in that recommendation's audit text
    for rid, c in checks.items():
        names = ([c["name"]] if "name" in c else []) + [i[1] for i in c.get("items", [])]
        for n in names:
            if n not in recs[rid]["audit"]:
                sys.exit(f"{rid}: checks {n!r}, which its audit procedure does not name")

    for old in list(OUT.glob("*.rego")) + list((OUT / "tests").glob("*.rego")):
        old.unlink()
    (OUT / "data").mkdir(parents=True, exist_ok=True)
    (OUT / "tests").mkdir(exist_ok=True)
    for sec in SECTIONS:
        in_sec = {rid: r for rid, r in recs.items() if r["section"] == sec}
        (OUT / f"{SECTIONS[sec]}_validation.rego").write_text(section_module(sec, section_names[sec], in_sec, checks))
    (OUT / "attestation_validation.rego").write_text(attestation_module(recs))
    (OUT / "cis_windows_server_2022_complete.rego").write_text(complete_module(section_names))
    (OUT / "cis_windows_2022_main.rego").write_text(main_module())
    lib = (pathlib.Path(__file__).parent / "windows_lib.rego.tmpl").read_text()
    lib = lib.replace("{{SECTIONS}}", "\n".join(f'\t"{p}": data.{PKG}.{p}.SECTION,' for p in SECTIONS.values()))
    lib = lib.replace("{{TABLES}}", "\n".join(f'\t"{p}": data.{PKG}.{p}.controls,' for p in SECTIONS.values()))
    (OUT / "lib.rego").write_text(lib)
    (OUT / "data" / "cis_windows_server_2022_v5_1_index.json").write_text(
        json.dumps(index_doc(recs, section_names), indent=2) + "\n")
    # nested under its own key: OPA loads every JSON file in data/ at the same path, and a second top-level
    # "benchmark" key would collide with the index's
    (OUT / "data" / "collector_manifest.json").write_text(
        json.dumps({"collector_manifest": manifest(checks)}, indent=2) + "\n")
    import gen_windows_server_2022_tests as t  # noqa: E402  kept separate: fixtures are their own logic
    for name, content in t.tests(PKG, SECTIONS, recs, checks, MANUAL).items():
        (OUT / "tests" / name).write_text(content)
    (OUT / "tests" / "test_lib.rego").write_text((pathlib.Path(__file__).parent / "windows_lib_test.rego.tmpl").read_text())

    kinds = {}
    for c in checks.values():
        kinds[c["kind"]] = kinds.get(c["kind"], 0) + 1
    print(f"{BENCHMARK} v{VERSION}: {len(recs)} recommendations -> {kinds}")


if __name__ == "__main__":
    main()
