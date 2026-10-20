"""Generate benchmarks/cis/postgresql/cis_postgresql_17.rego and its tests from the CIS workbook + postgresql_17_spec.py.

usage: python -I gen.py <workbook.xlsx> <out_dir (benchmarks/cis/postgresql)>
"""
import copy
import json
import os
import sys

import openpyxl

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from postgresql_17_spec import SPEC  # noqa: E402

BENCH = "CIS PostgreSQL 17 Benchmark v1.1.0"
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

_secdef(f) if f.prosecdef == true

_secdef(f) if lower(sprintf("%v", [f.prosecdef])) in {"t", "true"}

_unauthorized_secdef(f) if {
	_secdef(f)
	not sprintf("%s.%s", [f.schema, f.name]) in _policy_list("authorized_security_definer_functions")
}

_approved_ciphers := {
	"ECDHE-ECDSA-AES256-GCM-SHA384",
	"ECDHE-RSA-AES256-GCM-SHA384",
	"ECDHE-ECDSA-AES128-GCM-SHA256",
	"ECDHE-RSA-AES128-GCM-SHA256",
}

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
# {n} recommendations ({na} Automated, {n - na} Manual), every one in the CIS workbook; ids, titles,
# Automated/Manual status and profile (Level 1 - PostgreSQL / Level 1 - PostgreSQL on Linux) are read from
# the workbook, the logic is written from each recommendation's audit procedure. Generated by gen_postgresql_17.py.
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
#   input.postgresql.attest.<key>           : attestation booleans for the Manual recommendations

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
    out.append(HELPERS)
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
    return "\n".join(out)


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
	r.passed_controls == 72
}

test_total_controls if {
	r := b.compliance_report with input as {}
	r.total_controls == 72
	r.standard_total == 72
	r.automated_controls + r.manual_controls == 72
}

test_failing_control_keeps_report_populated if {
	inp := json.patch(green, [{"op": "replace", "path": "/postgresql/logging/log_hostname", "value": "on"}])
	r := b.compliance_report with input as inp
	r.compliant == false
	r.violations_count == 1
	r.sections.logging.violations == 1
	r.sections.logging.controls == 26
	r.sections.installation.violations == 0
}

test_nothing_passes_on_empty_input if {
	count(b.passed) == 0 with input as {}
	count(b.passed) == 0 with input as {"postgresql": {"attest": {}}}
}

test_section_control_counts if {
	s := b.compliance_report.sections with input as {}
	s.installation.controls == 7
	s.directory_file_permissions.controls == 4
	s.logging.controls == 26
	s.user_access.controls == 10
	s.connection_ssl.controls == 6
	s.postgresql_settings.controls == 11
	s.replication.controls == 5
	s.special_requirements.controls == 3
}
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
    return "\n".join(out)


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


def main():
    recs = read(sys.argv[1])
    out = sys.argv[2]
    with open(os.path.join(out, "cis_postgresql_17.rego"), "w") as f:
        f.write(gen_rego(recs))
    with open(os.path.join(out, "tests", "test_cis_postgresql_17_controls.rego"), "w") as f:
        f.write(gen_tests(recs))
    with open(os.path.join(out, "tests", "test_cis_postgresql_17_smoke.rego"), "w") as f:
        f.write(SMOKE)
    print(len(recs), "recommendations;", sum(1 for x in recs.values() if x["status"] == "Automated"), "automated")


main()
