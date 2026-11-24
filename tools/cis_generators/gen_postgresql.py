"""Generate a CIS PostgreSQL benchmark module (16, 17 or 18) from its CIS workbook.

The per-control logic is the PostgreSQL 17 table in postgresql_17_spec.py; postgresql_versions.py holds, per
version, the workbook name, the recommendations that are dropped or decided differently, and the files written.

usage: python3 gen_postgresql.py <16|17|18> <workbook.xlsx> <out_dir>
(gen_postgresql_16.py / _17.py / _18.py are one-line wrappers that fix the version.)
"""
import copy
import json
import os
import sys

import openpyxl

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from postgresql_versions import VERSIONS, spec_for  # noqa: E402
from neutralize import publish_titles  # noqa: E402

# Set per run by configure(); the emitters below read them.
CFG = {}
SPEC = {}
BENCH = ""
SKIP = {"License", "Overview", "Combined Profiles"}
SECTIONS = [
    ("1", "installation", "Installation and Patches"),
    ("2", "directory_file_permissions", "Directory and File Permissions"),
    ("3", "logging", "Logging And Auditing"),
    ("4", "user_access", "User Access and Authorization"),
    ("5", "connection_ssl", "Connection and Login"),
    ("6", "postgresql_settings", "PostgreSQL Settings"),
    ("7", "replication", "Replication"),
    ("8", "special_requirements", "Special Configuration Considerations"),
]


def read(wb_path):
    wb = openpyxl.load_workbook(wb_path, read_only=True)
    recs = {}
    combined = set()
    for ws in wb.worksheets:
        rows = list(ws.iter_rows(values_only=True))
        hdr = [str(h) if h else "" for h in rows[0]]
        for r in rows[1:]:
            d = dict(zip(hdr, r))
            rid = d.get("Recommendation #")
            if not rid:
                continue
            rid = str(rid).strip()
            if ws.title == "Combined Profiles":
                combined.add(rid)
                continue
            if ws.title in SKIP:
                continue
            x = recs.setdefault(rid, {"title": str(d["Title"]).strip(), "status": str(d["Assessment Status"]).strip(),
                                      "profiles": []})
            x["profiles"].append(ws.title)
    assert set(recs) == combined, (set(recs) ^ combined)
    assert set(recs) == set(SPEC), ("spec mismatch", set(recs) ^ set(SPEC))
    for rid, x in recs.items():
        want = "auto" if x["status"] == "Automated" else "manual"
        assert SPEC[rid]["kind"] == want, (rid, x["status"])
    return dict(sorted(recs.items(), key=lambda kv: [int(p) for p in kv[0].split(".")]))


def q(s):
    return json.dumps(s, ensure_ascii=False)


def ident(rid):
    return rid.replace(".", "_")


def path_arr(dotted):
    return "[" + ", ".join(q(p) for p in ["postgresql"] + dotted.split(".")) + "]"


HELPERS = r'''
# ── helpers ──────────────────────────────────────────────────────────────────
# Evidence presence. Called with literal paths so a missing key is a false result, never an undefined argument.
_present(p) if object.get(input, p, null) != null

_is_arr(p) if is_array(object.get(input, p, null))

_nonempty_obj(p) if {
	o := object.get(input, p, null)
	is_object(o)
	count(o) > 0
}

# SHOW-style booleans: "on"/"off" as PostgreSQL prints them; true/false and yes/no/1/0 are accepted as well.
_on(v) if lower(sprintf("%v", [v])) in {"on", "true", "yes", "1"}

_off(v) if lower(sprintf("%v", [v])) in {"off", "false", "no", "0"}

_nonempty_string(s) if {
	is_string(s)
	trim_space(s) != ""
}

# A list setting arrives as a comma-separated string (SHOW output) or as an array.
_as_list(v) := [lower(trim_space(x)) | some x in v; trim_space(x) != ""] if is_array(v)

_as_list(v) := [lower(trim_space(x)) | some x in split(v, ","); trim_space(x) != ""] if is_string(v)

# Organization logging/authorization policy (optional): input.postgresql.policy.*
_policy := p if {
	p := input.postgresql.policy
	is_object(p)
} else := {}

_policy_list(k) := l if {
	l := _policy[k]
	is_array(l)
} else := []

_policy_match(k, _) if not _policy[k]

_policy_match(k, v) if _policy[k] == v

# Parse an octal permission string ("644", "0644", "0o644") to an integer; undefined if not octal.
octal(s) := n if {
	t := trim_prefix(lower(trim_space(sprintf("%v", [s]))), "0o")
	regex.match(`^[0-7]{1,4}$`, t)
	p := concat("", [substring("0000", 0, 4 - count(t)), t])
	ds := [to_number(substring(p, i, 1)) | some i in numbers.range(0, 3)]
	n := ((ds[0] * 512) + (ds[1] * 64)) + ((ds[2] * 8) + ds[3])
}

# true when mode grants nothing beyond max (both octal strings)
mode_within(mode, max) if bits.and(octal(mode), bits.and(bits.negate(octal(max)), 4095)) == 0

# PostgreSQL time setting to minutes; a bare number is minutes (log_rotation_age's unit).
_duration_minutes(raw) := m if {
	parts := regex.find_all_string_submatch_n(`^\s*([0-9]+)\s*(ms|s|min|h|d)?\s*$`, sprintf("%v", [raw]), 1)[0]
	mult := {"": 1, "ms": 1 / 60000, "s": 1 / 60, "min": 1, "h": 60, "d": 1440}[parts[2]]
	m := to_number(parts[1]) * mult
}

# PostgreSQL size setting ("10MB", "1GB", "512kB"; a bare number is kB) to kB.
size_to_kb(raw) := kb if {
	m := regex.find_all_string_submatch_n(`^\s*([0-9]+)\s*(kB|MB|GB|TB)?\s*$`, sprintf("%v", [raw]), 1)[0]
	mult := {"": 1, "kB": 1, "MB": 1024, "GB": 1048576, "TB": 1073741824}[m[2]]
	kb := to_number(m[1]) * mult
}

# Message levels from most to least verbose; "at least <level>" = that level or a more verbose one.
_levels := ["debug5", "debug4", "debug3", "debug2", "debug1", "info", "notice", "warning", "error", "log", "fatal", "panic"]

_level_at_most(v, max) if {
	some i, l in _levels
	l == lower(v)
	some j, k in _levels
	k == max
	i <= j
}

# log_line_prefix escapes in use (padding like %-10u normalised; %% is a literal percent).
_prefix_escapes(s) := {concat("", ["%", substring(t, count(t) - 1, 1)]) | some t in regex.find_n(`%-?[0-9]*.`, s, -1)}

_syslog_only if {
	dests := _as_list(input.postgresql.logging.log_destination)
	count(dests) > 0
	every d in dests {
		d in {"syslog", "eventlog"}
	}
}

_required_prefix_escapes := {"%u", "%d", "%a", "%h"} if {
	_syslog_only
} else := {"%m", "%p", "%l", "%d", "%u", "%a", "%h"}

_log_timezone_ok(tz) if upper(tz) in {"GMT", "UTC", "ETC/GMT", "ETC/UTC"}

_log_timezone_ok(tz) if tz in _policy_list("log_timezones")

# pgaudit.log classes the organization requires; the benchmark's own example (ddl, write) when no policy is given.
_pgaudit_required := [lower(c) | some c in _policy_list("pgaudit_log_classes")] if {
	count(_policy_list("pgaudit_log_classes")) > 0
} else := ["ddl", "write"]

_pgaudit_covers(classes, r) if r in classes

_pgaudit_covers(classes, r) if {
	"all" in classes
	not concat("", ["-", r]) in classes
}

# a row of security_definer_functions counts as SECURITY DEFINER unless prosecdef says otherwise (false, "f",
# "false"): a missing, null or unreadable prosecdef does not take the function off the list
_not_secdef(f) if f.prosecdef == false

_not_secdef(f) if {
	is_string(f.prosecdef)
	lower(trim_space(f.prosecdef)) in {"f", "false"}
}

# schema and name are tested inside this helper: under `not`, a missing f.schema or f.name would make the
# whole expression undefined and drop the row, so the function would count as authorized
_authorized_secdef(f) if {
	is_string(f.schema)
	is_string(f.name)
	sprintf("%s.%s", [f.schema, f.name]) in _policy_list("authorized_security_definer_functions")
}

_unauthorized_secdef(f) if {
	not _not_secdef(f)
	not _authorized_secdef(f)
}

# 5.5: a predefined role (pg_*) is exempt; every other row, a row without a name included, needs a numeric
# connection limit other than -1
_role_limit_ok(r) if {
	is_string(r.name)
	startswith(r.name, "pg_")
}

_role_limit_ok(r) if {
	is_number(r.connection_limit)
	r.connection_limit != -1
}

@@APPROVED@@

_cipher_list(s) := [c | some c in regex.split(`[:, ]+`, trim_space(s)); c != ""]

_archive_value_set(v) if {
	is_string(v)
	t := trim_space(v)
	t != ""
	t != "(disabled)"
}

_archive_target_set(a) if _archive_value_set(a.archive_command)

_archive_target_set(a) if _archive_value_set(a.archive_library)
'''

# Approved cipher names per version: 17 lists the four ECDHE GCM suites the benchmark allows for TLS 1.2;
# 16 and 18 list the three TLS 1.3 suite names.
APPROVED = {
    "tls12_ecdhe": ["ECDHE-ECDSA-AES256-GCM-SHA384", "ECDHE-RSA-AES256-GCM-SHA384",
                    "ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-RSA-AES128-GCM-SHA256"],
    "tls13": ["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256", "TLS_AES_128_CCM_SHA256"],
}


def approved_block():
    body = "".join(f'\t"{c}",\n' for c in APPROVED[CFG["ciphers"]])
    return "_approved_ciphers := {\n" + body + "}"


def helpers_text():
    t = HELPERS.replace("@@APPROVED@@", approved_block())
    return t + CFG.get("extra_helpers", "")


def fix(text):
    """Version the text that the 17 templates spell out."""
    v = CFG["ver"]
    return (text.replace("postgresql_17", f"postgresql_{v}").replace("CIS PostgreSQL 17:", f"CIS PostgreSQL {v}:")
            .replace("gen_postgresql_17.py", CFG["gen_name"]))


def gen_rego(recs):
    n = len(recs)
    na = sum(1 for x in recs.values() if x["status"] == "Automated")
    out = [f'''# METADATA
# title: "{BENCH}"
# custom:
#   class: security
#   framework: cis_postgresql
#   source: cis
#   domains: [database, postgresql]
#   coverage:
#     checks: {n}
#     cited: {n}
#     expected: {n}
#     found: {n}
#     scope: module
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package cis.postgresql_17

# {BENCH}
# {n} recommendations ({na} Automated, {n - na} Manual), every one in the CIS workbook; ids,
# Automated/Manual status and profile (Level 1 - PostgreSQL / Level 1 - PostgreSQL on Linux) are read from
# the workbook, the logic is written from each recommendation's audit procedure. Generated by gen_postgresql_17.py.{CFG.get('note', '')}
#
# Fail closed: an Automated recommendation whose evidence is absent yields
#   "<id>: evidence missing — <field> not collected"; a Manual one needs input.postgresql.attest.<key> == true.
#
# Input contract (field names shared with cis_postgresql_15.rego where the check is the same):
#   input.postgresql.logging.<GUC>          : SHOW values ("on"/"off", "1d", "1GB", "0600", ...)
#   input.postgresql.settings.shared_preload_libraries, input.postgresql.pgaudit.log
#   input.postgresql.ssl.{{enabled, ssl_min_protocol_version, ssl_ciphers}} (+ optional runtime session lists)
#   input.postgresql.authentication.pg_hba_entries[] : {{connection_type, auth_method, ...}} (pg_hba_file_rules)
#   input.postgresql.backend_settings       : pg_settings name -> setting for context backend/superuser-backend
#   input.postgresql.roles[]                : {{name, connection_limit}} (pg_roles.rolconnlimit)
#   input.postgresql.system.*, cluster.*, service.enabled, cryptography.*, archive_settings.*, backup_methods[]
#   input.postgresql.policy.*               : optional organization policy (log_destinations, log_directory,
#                                             log_filename, syslog_ident, log_timezones, pgaudit_log_classes,
#                                             authorized_superusers, authorized_security_definer_functions,
#                                             max_log_rotation_age_minutes, max_log_rotation_size_kb)
#   input.postgresql.attest.<key>           : attestation booleans for the Manual recommendations{CFG.get('contract_extra', '')}

import rego.v1
''']
    out.append("# ── recommendations (from the CIS workbook) ─────────────────────────────────")
    out.append("controls := {")
    for rid, x in recs.items():
        s = SPEC[rid]
        e = {"title": x["title"], "section": rid.split(".")[0], "profiles": x["profiles"], "level": 1,
             "assessment": x["status"]}
        if s["kind"] == "manual":
            e["attest"] = s["attest"]
        out.append(f"\t{q(rid)}: {json.dumps(e, ensure_ascii=False)},")
    out.append("}\n")
    out.append(helpers_text())
    out.append("# ── per-recommendation logic ─────────────────────────────────────────────────")
    for rid, x in recs.items():
        s = SPEC[rid]
        out.append(f"# {rid} ({x['status']})")
        if s["kind"] == "manual":
            out.append(f"passed contains {q(rid)} if input.postgresql.attest.{s['attest']} == true\n")
            continue
        for path, kind in s["fields"]:
            fn = {"val": "_present", "arr": "_is_arr", "obj": "_nonempty_obj"}[kind]
            out.append(f'missing contains {{"id": {q(rid)}, "field": {q("postgresql." + path)}}} if not {fn}({path_arr(path)})\n')
        out.append(f"passed contains {q(rid)} if {{")
        out.append("\tpg := input.postgresql")
        for line in s["body"]:
            out.append("\t" + line)
        out.append("}\n")
    out.append('''# ── results ──────────────────────────────────────────────────────────────────
_missing_ids := {m.id | some m in missing}

failures contains {"id": m.id, "msg": sprintf("%s: evidence missing — %s not collected", [m.id, m.field])} if {
	some m in missing
}

failures contains {"id": id, "msg": sprintf("%s: %s — requirement not met", [id, c.title])} if {
	some id, c in controls
	c.assessment == "Automated"
	not id in _missing_ids
	not id in passed
}

failures contains {"id": id, "msg": sprintf("%s: %s — manual review not attested (postgresql.attest.%s)", [id, c.title, c.attest])} if {
	some id, c in controls
	c.assessment == "Manual"
	not id in passed
}

failures contains {"id": "input", "msg": "CIS PostgreSQL 17: FAIL-CLOSED - facts 'input.postgresql' were not supplied; the server was not evaluated"} if {
	not _nonempty_obj(["postgresql"])
}

violations := sort([f.msg | some f in failures])

default compliant := false

compliant if count(failures) == 0

_failed_ids := {f.id | some f in failures}
''')
    out.append("_section_keys := {")
    for num, key, title in SECTIONS:
        out.append(f"\t{q(num)}: {{\"key\": {q(key)}, \"title\": {q(title)}}},")
    out.append("}\n")
    out.append(f'''sections := {{s.key: {{
	"title": s.title,
	"violations": count([id | some id in _failed_ids; id != "input"; split(id, ".")[0] == num]),
	"controls": count([id | some id, c in controls; c.section == num]),
}} | some num, s in _section_keys}}

compliance_report := {{
	"benchmark": "{BENCH}",
	"timestamp": time.now_ns(),
	"total_controls": count(controls),
	"standard_total": {n},
	"standard_total_source": "{BENCH}, recommendations counted from the CIS workbook (Combined Profiles)",
	"automated_controls": count([id | some id, c in controls; c.assessment == "Automated"]),
	"manual_controls": count([id | some id, c in controls; c.assessment == "Manual"]),
	"passed_controls": count(passed),
	"compliant": compliant,
	"violations_count": count(violations),
	"violations": violations,
	"sections": sections,
}}
''')
    return fix("\n".join(out))


# ── tests ────────────────────────────────────────────────────────────────────
def setp(d, dotted, v):
    ks = dotted.split(".")
    for k in ks[:-1]:
        d = d.setdefault(k, {})
    d[ks[-1]] = v


def ptr(dotted):
    return "/postgresql/" + dotted.replace(".", "/")


def green_fixture():
    pg = {}
    for rid, s in SPEC.items():
        if s["kind"] == "manual":
            setp(pg, "attest." + s["attest"], True)
        else:
            for p, v in s["fx"]:
                setp(pg, p, copy.deepcopy(v))
    return {"postgresql": pg}


def patch(ops):
    return json.dumps(ops, ensure_ascii=False)


def gen_tests(recs):
    g = green_fixture()
    # every fixture path must be valid json-pointer-wise for "add"
    out = ['''package cis.postgresql_17_test

import rego.v1

import data.cis.postgresql_17 as b

# Generated by gen_postgresql_17.py: every recommendation has a pass and a fail case, every Automated one an
# evidence-missing case; the green fixture below satisfies the whole benchmark.
''']
    out.append("green := " + json.dumps(g, indent="\t", ensure_ascii=False) + "\n")
    out.append('''_has_prefix(vs, p) if {
	some v in vs
	startswith(v, p)
}

test_green_is_compliant if {
	r := b.compliance_report with input as green
	r.compliant == true
	r.violations_count == 0
	r.passed_controls == @N@
}

test_total_controls if {
	r := b.compliance_report with input as {}
	r.total_controls == @N@
	r.standard_total == @N@
	r.automated_controls + r.manual_controls == @N@
}

test_failing_control_keeps_report_populated if {
	inp := json.patch(green, [{"op": "replace", "path": "/postgresql/logging/log_hostname", "value": "on"}])
	r := b.compliance_report with input as inp
	r.compliant == false
	r.violations_count == 1
	r.sections.logging.violations == 1
	r.sections.logging.controls == @S3@
	r.sections.installation.violations == 0
}

test_nothing_passes_on_empty_input if {
	count(b.passed) == 0 with input as {}
	count(b.passed) == 0 with input as {"postgresql": {"attest": {}}}
}

test_section_control_counts if {
	s := b.compliance_report.sections with input as {}
@SECTION_COUNTS@}
''')
    for rid, x in recs.items():
        s = SPEC[rid]
        i = ident(rid)
        out.append(f"# {rid} {x['title']}")
        out.append(f"test_{i}_pass if {{\n\t{q(rid)} in b.passed with input as green\n}}\n")
        if s["kind"] == "manual":
            path = ptr("attest." + s["attest"])
            out.append(f'test_{i}_fail_not_attested if {{\n\tinp := json.patch(green, [{{"op": "replace", "path": {q(path)}, "value": false}}])\n'
                       f'\tnot {q(rid)} in b.passed with input as inp\n'
                       f'\tvs := b.violations with input as inp\n\t_has_prefix(vs, {q(rid + ": ")})\n}}\n')
            out.append(f'test_{i}_fail_attest_absent if {{\n\tinp := json.patch(green, [{{"op": "remove", "path": {q(path)}}}])\n'
                       f'\tnot {q(rid)} in b.passed with input as inp\n}}\n')
            continue
        for k, muts in enumerate(s["fails"]):
            ops = [{"op": "add", "path": ptr(p), "value": v} for p, v in muts]
            out.append(f"test_{i}_fail_{k + 1} if {{\n\tinp := json.patch(green, {patch(ops)})\n"
                       f"\tnot {q(rid)} in b.passed with input as inp\n"
                       f"\tvs := b.violations with input as inp\n"
                       f"\t{q(rid + ': ' + x['title'] + ' — requirement not met')} in vs\n}}\n")
        for k, (p, _) in enumerate(s["fields"]):
            msg = f"{rid}: evidence missing — postgresql.{p} not collected"
            out.append(f'test_{i}_evidence_missing_{k + 1} if {{\n\tinp := json.patch(green, [{{"op": "remove", "path": {q(ptr(p))}}}])\n'
                       f"\tnot {q(rid)} in b.passed with input as inp\n"
                       f"\tvs := b.violations with input as inp\n\t{q(msg)} in vs\n"
                       f"\tnot {q(rid + ': ' + x['title'] + ' — requirement not met')} in vs\n"
                       f"\tr := b.compliance_report with input as inp\n\tr.compliant == false\n}}\n")
    text = "\n".join(out)
    n = len(recs)
    counts = {num: sum(1 for r in recs if r.split(".")[0] == num) for num, _, _ in SECTIONS}
    text = text.replace("@N@", str(n)).replace("@S3@", str(counts["3"]))
    lines = "".join(f"\ts.{key}.controls == {counts[num]}\n" for num, key, _ in SECTIONS)
    return fix(text.replace("@SECTION_COUNTS@", lines))


SMOKE = '''package cis.postgresql_17_test

import rego.v1

# Smoke tests in the same form as the other PostgreSQL versions: on empty input the module loads, reports and fails closed.

test_cis_postgresql_17_loads_on_empty_input if {
	m := data.cis.postgresql_17 with input as {}
	is_object(m)
}

test_cis_postgresql_17_report_wellformed_on_empty_input if {
	report := data.cis.postgresql_17.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_cis_postgresql_17_fail_closed_on_empty_input if {
	report := data.cis.postgresql_17.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_cis_postgresql_17_violations_on_empty_input if {
	v := data.cis.postgresql_17.violations with input as {}
	count(v) > 0
	"CIS PostgreSQL 17: FAIL-CLOSED - facts 'input.postgresql' were not supplied; the server was not evaluated" in v
}
'''


def configure(ver):
    global CFG, SPEC, BENCH
    CFG = VERSIONS[ver]
    SPEC = spec_for(ver)
    BENCH = CFG["bench"]


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)


MAIN_BRIDGE = '''# METADATA
# title: "CIS PostgreSQL @V@ - compliance_report entrypoint (@BENCH@)"
# custom:
#   class: security
#   framework: cis_postgresql_@V@
#   source: cis
#   domains: [database, postgresql]
#   coverage:
#     checks: 0
#     cited: 0
#     density: orchestrator
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package cis_postgresql_@V@.main

# Generated by @GEN@. OPA query path: /v1/data/cis_postgresql_@V@/main/compliance_report
# Pinned to this version: the version-agnostic key cis_postgresql resolves to the latest version the library
# carries (see benchmarks/cis/postgresql/cis_postgresql_main.rego); this key always means PostgreSQL @V@.

import data.cis.postgresql_@V@ as bench
import rego.v1

default _facts_supplied := false

_facts_supplied if count(object.keys(input)) > 0

# Bridge fields shared by every cis_*.main report (see _framework_key_tests).
_failed_ids := {id | some id, _ in bench.controls; not id in bench.passed}

_total := count(bench.controls)

default _pct := 0

_pct := round(((_total - count(_failed_ids)) * 100) / _total) if _total > 0

_no_facts_msg := sprintf(
	"FAIL-CLOSED: no facts supplied for %s — the assessment could not be evaluated. This is NOT a passing result; check that fact collection ran and produced input.",
	["cis_postgresql_@V@"],
)

_report_violations := array.concat(bench.violations, [_no_facts_msg]) if not _facts_supplied

_report_violations := bench.violations if _facts_supplied

compliance_report := object.union(bench.compliance_report, {
	"facts_supplied": _facts_supplied,
	"framework": "cis_postgresql_@V@",
	"benchmark_package": "cis.postgresql_@V@",
	"passed_controls": _total - count(_failed_ids),
	"failed_controls": count(_failed_ids),
	"compliance_percentage": _pct,
	"violation_count": count(_report_violations),
	"violations": _report_violations,
})

compliant := bench.compliant

violations := bench.violations
'''

MAIN_TEST = '''package cis_postgresql_@V@.main_test

import rego.v1

# Generated by @GEN@: the framework-key contract on empty input and with one attested control.

test_report_is_this_version if {
	r := data.cis_postgresql_@V@.main.compliance_report with input as {}
	r.benchmark == "@BENCH@"
	r.total_controls == @N@
	r.framework == "cis_postgresql_@V@"
}

test_empty_input_fails_closed if {
	r := data.cis_postgresql_@V@.main.compliance_report with input as {}
	r.compliant == false
	r.passed_controls == 0
	r.failed_controls == r.total_controls
	r.violation_count == count(r.violations)
	some v in r.violations
	startswith(v, "FAIL-CLOSED: no facts supplied for cis_postgresql_@V@")
}

test_counts_are_consistent_on_empty_input if {
	r := data.cis_postgresql_@V@.main.compliance_report with input as {}
	r.failed_controls >= 0
	r.failed_controls <= r.total_controls
	is_array(r.violations)
}

test_attested_control_counts_as_passed if {
	r := data.cis_postgresql_@V@.main.compliance_report with input as {"postgresql": {"attest": {"latest_security_patches_applied": true}}}
	r.passed_controls == 1
	r.failed_controls == r.total_controls - 1
	not "FAIL-CLOSED: no facts supplied for cis_postgresql_@V@ — the assessment could not be evaluated. This is NOT a passing result; check that fact collection ran and produced input." in r.violations
}
'''


def readme_text(recs):
    n = len(recs)
    na = sum(1 for x in recs.values() if x["status"] == "Automated")
    v = CFG["ver"]
    prof = {}
    for x in recs.values():
        k = " + ".join(sorted(x["profiles"]))
        prof[k] = prof.get(k, 0) + 1
    plines = "\n".join(f"- {c} recommendations: {k}" for k, c in sorted(prof.items()))
    diffs = "\n".join(f"- {d}" for d in CFG["differences"])
    return f"""# CIS PostgreSQL {v} ({BENCH.split(" Benchmark ")[1]})

Rego for the CIS PostgreSQL {v} Benchmark. {n} recommendations ({na} Automated, {n - na} Manual); every one
has a rule. Ids, Automated/Manual status and profile are read from the benchmark workbook; the check logic
and every message are written here from the audit procedure, not copied from the benchmark.

{plines}

Entrypoints:

- `data.cis_postgresql_{v}.main.compliance_report` is the framework-key report (`compliant`, `total_controls`,
  `failed_controls`, `violations`, `violation_count`). On empty input it fails closed: `compliant` is false and
  `failed_controls == total_controls`.
- `data.cis.postgresql_{v}` is the benchmark package itself (`controls`, `passed`, `violations`, `sections`).

Input is `input.postgresql.*`, the same fact contract as the PostgreSQL 17 module (`benchmarks/cis/postgresql`);
a collector that feeds one feeds the other. An Automated recommendation whose fact is absent reports
`<id>: evidence missing`; a Manual one passes only when `input.postgresql.attest.<key>` is true.

How PostgreSQL {v} differs from the PostgreSQL 17 module:

{diffs}

Generated. Do not edit by hand; regenerate with:

```
/usr/bin/python3 tools/cis_generators/gen_postgresql_{v}.py <CIS_PostgreSQL_{v}_workbook.xlsx> benchmarks/cis/postgresql_{v}
opa fmt -w benchmarks/cis/postgresql_{v}
```
"""


def main(ver, workbook, out):
    configure(ver)
    recs = publish_titles(read(workbook))
    v = CFG["ver"]
    write(os.path.join(out, f"cis_postgresql_{v}.rego"), gen_rego(recs))
    write(os.path.join(out, "tests", f"test_cis_postgresql_{v}_controls.rego"), gen_tests(recs))
    write(os.path.join(out, "tests", f"test_cis_postgresql_{v}_smoke.rego"), fix(SMOKE))
    if CFG.get("own_dir"):
        rep = {"@V@": str(v), "@BENCH@": BENCH, "@GEN@": CFG["gen_name"], "@N@": str(len(recs))}
        for name, tpl in ((f"cis_postgresql_{v}_main.rego", MAIN_BRIDGE),
                          (os.path.join("tests", f"test_cis_postgresql_{v}_main.rego"), MAIN_TEST)):
            for k, x in rep.items():
                tpl = tpl.replace(k, x)
            write(os.path.join(out, name), tpl)
        write(os.path.join(out, "README.md"), readme_text(recs))
    print(len(recs), "recommendations;", sum(1 for x in recs.values() if x["status"] == "Automated"), "automated")


if __name__ == "__main__":
    main(int(sys.argv[1]), sys.argv[2], sys.argv[3])
