#!/usr/bin/env python3
"""CIS Microsoft SQL Server 2022 Benchmark v1.3.0: every recommendation, from the benchmark's own workbook.

    python3 gen_sql_server_2022.py CIS_Microsoft_SQL_Server_2022_Benchmark_v1.3.0.xlsx <repo root>

Needs openpyxl (the output is passed through `opa fmt` when opa is on the PATH). Emits benchmarks/cis/sql_server_2022/
cis_sql_server_2022.rego, cis_sql_server_2022_main.rego and tests/test_cis_sql_server_2022.rego.

The 2022 benchmark has the same ids, titles, statuses and profiles as SQL Server 2025 v1.0.0 minus 3.15 (the external
REST endpoint review, new in 2025); the audit procedures of the other 48 are the same queries and checks (2.10, 2.12 name the
version in Configuration Manager, 3.2 and 3.12 differ in wording only). The one real difference is 6.2: the 2022 query
filters to permission_set > 1 and passes on no rows, the 2025 query lists every user assembly and passes when all are
SAFE_ACCESS. The shared fact sql.user_assemblies[] serves both: a row whose permission_set_desc is not SAFE_ACCESS fails,
so a collector may supply either list. So this generator imports gen_sql_server_2025.py unmodified (reader, logic table,
helpers, profile/helper Rego) and holds only what differs: the key and package names, the 48-entry check (no 3.15),
a title keyword per logic entry (the generator aborts when the workbook disagrees), the per-profile counts, and the
emitted report bridge (failed_controls, passed_controls, compliance_percentage).

Same input contract as sql_server_2025 (root input.sql; input.cis_profile selects Database Engine or AWS RDS, level 1 or 2).
"""
import json
import pathlib
import shutil
import subprocess
import sys

import gen_sql_server_2025 as g
from neutralize import publish_titles

BENCH = "CIS Microsoft SQL Server 2022 Benchmark v1.3.0"
PKG = "cis.sql_server_2022"
KEY = "cis_sql_server_2022"
EXPECTED_TOTAL = 48
EXPECTED_MANUAL = 11
EXPECTED_PROFILE_COUNTS = {g.DE1: 45, g.RDS1: 30, g.DE2: 3}
DE1, RDS1, DE2 = g.DE1, g.RDS1, g.DE2

RULES = {k: v for k, v in g.RULES.items() if k != "3.15"}

# One lowercase keyword per logic entry, matched against the raw workbook title: logic cannot attach to a renumbered id.
KEYWORDS = {
    "1.1": "cumulative", "1.2": "single-function", "2.1": "ad hoc distributed", "2.2": "clr enabled",
    "2.3": "cross db ownership", "2.4": "database mail", "2.5": "ole automation", "2.6": "remote access",
    "2.7": "remote admin", "2.8": "scan for startup", "2.9": "trustworthy", "2.10": "protocols",
    "2.11": "non-standard ports", "2.12": "hide instance", "2.13": "'sa' login account is set to 'disabled'",
    "2.14": "renamed", "2.15": "auto_close", "2.16": "no login exists", "2.17": "clr strict security",
    "3.1": "server authentication", "3.2": "guest", "3.3": "orphaned", "3.4": "contained databases",
    "3.5": "mssql service account", "3.6": "sqlagent", "3.7": "full-text", "3.8": "default permissions",
    "3.9": "builtin", "3.10": "local groups", "3.11": "msdb", "3.12": "sysadmin", "3.13": "no admin role",
    "3.14": "control server", "4.1": "must_change", "4.2": "check_expiration", "4.3": "check_policy",
    "5.1": "error log", "5.2": "default trace", "5.3": "login auditing", "5.4": "sql server audit",
    "6.1": "sanitized", "6.2": "clr assembly", "7.1": "symmetric key", "7.2": "asymmetric key",
    "7.3": "backups", "7.4": "network encryption", "7.5": "tde", "8.1": "browser",
}
STATUS = {rid: ("Manual" if s["kind"] == "attest" else "Automated") for rid, s in RULES.items()}

ident, key, rego_str, rule_lines = g.ident, g.key, g.rego_str, g.rule_lines


def main(xlsx, root):
    out = pathlib.Path(root) / "benchmarks" / "cis" / "sql_server_2022"
    recs, all_sections = g.read_workbook(xlsx)
    missing = sorted(set(recs) - set(RULES), key=key)
    extra = sorted(set(RULES) - set(recs), key=key)
    if missing or extra or set(KEYWORDS) != set(RULES):
        raise SystemExit(f"logic table out of step with the workbook: missing {missing} extra {extra}")
    if len(recs) != EXPECTED_TOTAL:
        raise SystemExit(f"workbook has {len(recs)} recommendations, expected {EXPECTED_TOTAL}")
    for rid, r in recs.items():
        if r["status"] != STATUS[rid]:
            raise SystemExit(f"{rid} is {r['status']} in the workbook but the logic table says {STATUS[rid]}")
        if KEYWORDS[rid] not in r["title"].lower():
            raise SystemExit(f"{rid}: title {r['title']!r} lacks the keyword {KEYWORDS[rid]!r}; the id was renumbered")
    ids = sorted(recs, key=key)
    tops = sorted({rid.split(".")[0] for rid in ids}, key=int)
    sections = {s: all_sections[s] for s in tops}
    n_auto = sum(1 for r in recs.values() if r["status"] == "Automated")
    n_manual = len(ids) - n_auto
    by_prof = {p: [r for r in ids if p in recs[r]["profiles"]] for p in (DE1, RDS1, DE2)}
    if n_manual != EXPECTED_MANUAL or {p: len(v) for p, v in by_prof.items()} != EXPECTED_PROFILE_COUNTS:
        raise SystemExit(f"status/profile counts differ from the expected {EXPECTED_MANUAL} Manual and {EXPECTED_PROFILE_COUNTS}")
    recs = publish_titles(recs)

    L = ["# METADATA", f'# title: "{BENCH}"', "# custom:", "#   class: security", f"#   framework: {KEY}",
         "#   source: cis", "#   domains: [database, mssql]", f"package {PKG}", "",
         f"# {BENCH}.",
         f"# {len(ids)} recommendations ({n_auto} Automated, {n_manual} Manual), every one in the benchmark; ids,",
         "# status and profiles read from the CIS workbook and the logic written from each audit procedure",
         "# (generated by gen_sql_server_2022.py, which reuses gen_sql_server_2025.py's logic table and helpers).",
         f"# Profiles: '{DE1}' ({len(by_prof[DE1])}), '{RDS1}' ({len(by_prof[RDS1])}, a subset),",
         f"# '{DE2}' ({len(by_prof[DE2])}: {', '.join(by_prof[DE2])}).",
         "# input.cis_profile selects the recommendations in scope:",
         "#   platform: \"database_engine\" (default) | \"aws_rds\"; level: 1 | 2 (default 2; Level 2 includes Level 1).",
         f"#   The default selection is the strictest one: all {len(ids)}. Out-of-scope recommendations raise nothing.",
         "#   aws_rds also turns on the RDS allowances the audit procedures name (3.2 rdsadmin, 3.9 BUILTIN\\Administrators,",
         "#   4.2 rdsa).",
         f"# {n_manual} Manual reviews carry an attestation boolean (not attested => violation).",
         "# Automated checks fail closed: facts not collected => '<id>: evidence missing — <field> not collected'.",
         "#",
         "# Input contract: identical to cis.sql_server_2025 (root input.sql, as benchmarks/stig/ms_sql_2016;",
         "# sql.sa_account_disabled is shared with it), so one collector feeds both. 6.2: sql.user_assemblies[] may be",
         "# every user-defined assembly or only those above SAFE_ACCESS; any row not SAFE_ACCESS fails.",
         "#   sql.configurations[<name>] = {value_configured, value_in_use}  : sys.configurations rows (name any case)",
         "#   sql.is_clustered (bool)                     : SERVERPROPERTY('IsClustered') = 1 (2.7 is N/A on a cluster)",
         "#   sql.tcp_port_1433_count (number)            : 2.11 query result",
         "#   sql.hide_instance (number)                  : SuperSocketNetLib HideInstance",
         "#   sql.sa_account_disabled (bool)              : sid 0x01 login is_disabled = 1",
         "#   sql.sa_login_name (string)                  : name of the sid 0x01 login",
         "#   sql.is_integrated_security_only (number)    : SERVERPROPERTY('IsIntegratedSecurityOnly')",
         "#   sql.num_error_logs (number)                 : NumErrorLogs, -1 when no limit is configured",
         "#   sql.login_audit_level (string)              : xp_loginconfig 'audit level' config_value",
         "#   sql.server_audit_actions[] = {audit_action_name, audit_enabled, specification_enabled, audited_result}",
         "#   sql.has_contained_databases (bool)",
         "#   sql.user_assemblies[] / symmetric_keys[] / asymmetric_keys[] : user-defined assemblies and non-system-db keys",
         "#   sql.connection_encrypt_options[]            : 7.4 query result (distinct encrypt_option values)",
         "#   sql.<offender list>[]                       : rows the audit query must not return ([] = none; missing = not collected):",
         "#     databases_trustworthy_on, contained_databases_auto_close_on, logins_named_sa, guest_connect_grants,",
         "#     orphaned_users, contained_db_sql_auth_users, public_role_extra_permissions, builtin_logins,",
         "#     local_group_logins, msdb_public_proxy_grants, msdb_admin_role_members,",
         "#     sysadmin_logins_without_expiration_check, sql_logins_without_check_policy, unencrypted_backups,",
         "#     databases_without_tde",
         "#   sql.attest.*                                : attestation booleans for the Manual recommendations",
         "", "import rego.v1", "",
         "# ── profile ──────────────────────────────────────────────────────────────────",
         "default _cis_profile := {}", "", "_cis_profile := p if {", "\tp := input.cis_profile", "\tis_object(p)", "}", "",
         'default platform := "database_engine"', "", 'platform := "aws_rds" if _cis_profile.platform == "aws_rds"', "",
         "default level := 2", "", "level := 1 if _cis_profile.level == 1", "",
         "default _rds := false", "", '_rds if platform == "aws_rds"', "",
         f'_selected_profiles := {{"{RDS1}"}} if _rds', "",
         f'_selected_profiles := {{"{DE1}"}} if {{', "\tnot _rds", "\tlevel == 1", "}", "",
         f'_selected_profiles := {{"{DE1}", "{DE2}"}} if {{', "\tnot _rds", "\tlevel == 2", "}", "",
         "in_scope contains id if {", "\tsome id, r in recommendations", "\tsome p in r.profiles", "\tp in _selected_profiles", "}", "",
         "default compliant := false", "", "compliant if {", "\tinput.sql", "\tcount(violations) == 0", "}",
         g.HELPERS.rstrip(), ""]
    fx = {}
    for rid in ids:
        r, s, i = recs[rid], RULES[rid], ident(rid)
        L += [f"# {rid} ({r['status']}, {'; '.join(r['profiles'])})", f"default r_{i} := false"]
        L += rule_lines(f"r_{i}", s["body"])
        if s["kind"] == "attest":
            L += [f"violations contains {rego_str(rid + ': ' + r['title'] + ' (manual review not attested)')} if {{",
                  f'\t"{rid}" in in_scope', f"\tnot r_{i}", "}", ""]
        else:
            L += [f"default e_{i} := false"] + rule_lines(f"e_{i}", s["ev"])
            L += [f"violations contains {rego_str(rid + ': evidence missing — ' + s['field'] + ' not collected')} if {{",
                  f'\t"{rid}" in in_scope', f"\tnot e_{i}", "}", "",
                  f"violations contains {rego_str(rid + ': ' + r['title'])} if {{", f'\t"{rid}" in in_scope', f"\te_{i}", f"\tnot r_{i}", "}", ""]
        for path, val in s["fx"]:
            d = fx
            parts = path if isinstance(path, list) else path.split(".")
            for p in parts[:-1]:
                d = d.setdefault(p, {})
            d[parts[-1]] = val
    recmap = {rid: {"title": recs[rid]["title"], "level": recs[rid]["level"], "assessment": recs[rid]["status"],
                    "profiles": recs[rid]["profiles"]} for rid in ids}
    L += ['violations contains "CIS SQL Server 2022: FAIL-CLOSED - facts \'input.sql\' were not supplied; the instance was not evaluated" if {',
          "\tnot input.sql", "}", "",
          "sections := " + json.dumps(sections, indent=1, ensure_ascii=False), "",
          "# id -> CIS title, level, Automated/Manual status and the workbook profiles it belongs to",
          "recommendations := " + json.dumps(recmap, indent=1, ensure_ascii=False), "",
          "compliance_report := {", f'\t"benchmark": "{BENCH}",', '\t"profile": {"platform": platform, "level": level},',
          '\t"total_controls": count(in_scope),', f'\t"standard_total": {len(ids)},',
          f'\t"standard_total_source": "{BENCH}, recommendations counted from the CIS workbook",',
          '\t"sections": sections,', '\t"compliant": compliant,', '\t"violation_count": count(violations),', '\t"violations": violations,', "}", ""]
    out.mkdir(parents=True, exist_ok=True)
    (out / "cis_sql_server_2022.rego").write_text("\n".join(L))

    M = ["# METADATA", f'# title: "{BENCH} - compliance_report entrypoint"', "# custom:", "#   class: security",
         f"#   framework: {KEY}", "#   source: cis", "#   domains: [database, mssql]", f"package {PKG}.main", "",
         f"# OPA query path: /v1/data/{PKG.replace('.', '/')}/main/compliance_report",
         f"# Thin alias of data.{PKG}; that package already fails closed when input.sql is absent.", "",
         f"import data.{PKG} as bench", "import rego.v1", "",
         "default _facts_supplied := false", "", "_facts_supplied if count(object.keys(input)) > 0", "",
         "# Bridge fields shared by every cis_*.main report (see _framework_key_tests): distinct failing",
         '# in-scope controls, parsed from the "<id>: ..." message prefix; violations as a sorted array.',
         "_failed_ids := {id |", "\tsome v in bench.violations", '\tid := split(v, ":")[0]', "\tid in bench.in_scope", "}", "",
         "_total := count(bench.in_scope)", "", "default _pct := 0", "",
         "_pct := round(((_total - count(_failed_ids)) * 100) / _total) if _total > 0", "",
         "compliance_report := object.union(bench.compliance_report, {",
         '\t"facts_supplied": _facts_supplied,', f'\t"framework": "{KEY}",',
         '\t"passed_controls": _total - count(_failed_ids),', '\t"failed_controls": count(_failed_ids),',
         '\t"compliance_percentage": _pct,', '\t"violations": _report_violations,', "})", "",
         "compliant := bench.compliant", "", "violations := bench.violations", "",
         "# FAIL-CLOSED gate (see benchmarks/cis/network_devices/pfsense/cis_pfsense_main.rego): with no facts at all the",
         "# report says so explicitly, so an empty assessment can never read as a result.",
         "_no_facts_msg := sprintf(", '\t"FAIL-CLOSED: no facts supplied for %s — the assessment could not be evaluated. This is NOT a passing result; check that fact collection ran and produced input.",',
         f'\t["{KEY}"],', ")", "",
         "_report_violations := array.concat(sort([v | some v in bench.violations]), [_no_facts_msg]) if not _facts_supplied", "",
         "_report_violations := sort([v | some v in bench.violations]) if _facts_supplied", ""]
    (out / f"cis_sql_server_2022_main.rego").write_text("\n".join(M))

    fxs = json.dumps(fx, indent=1, ensure_ascii=False).replace("\n", "\n\t")
    p_rds = {"cis_profile": {"platform": "aws_rds", "level": 1}}
    T = [f"package {PKG}_test", "", "import rego.v1", "", f"import data.{PKG} as b", f"import data.{PKG}.main as m", "",
         f"green := {fxs}", "",
         "test_green_instance_is_compliant if {", "\tr := b.compliance_report with input as green", "\tr.compliant == true",
         "\tcount(r.violations) == 0", f"\tr.total_controls == {len(ids)}", f"\tr.standard_total == {len(ids)}", "}", "",
         "test_main_alias_matches if {", "\tr := m.compliance_report with input as green", "\tr.compliant == true",
         "\tr.facts_supplied == true", "\tr.failed_controls == 0", f"\tr.passed_controls == {len(ids)}",
         "\tm.compliant with input as green", "}", "",
         "test_fail_closed_on_empty_input if {", "\tr := b.compliance_report with input as {}", "\tr.compliant == false",
         "\tcount(r.violations) > 0", "\tm.compliance_report.facts_supplied == false with input as {}", "}", "",
         "test_main_contract_on_empty_input if {", "\tr := m.compliance_report with input as {}", "\tr.compliant == false",
         f"\tr.total_controls == {len(ids)}", "\tr.failed_controls == r.total_controls", "\tr.violation_count > 0",
         f'\tr.framework == "{KEY}"',
         f'\tm.compliance_report.total_controls == {len(by_prof[DE1])} with input as {{"cis_profile": {{"level": 1}}}}',
         f'\tm.compliance_report.failed_controls == {len(by_prof[DE1])} with input as {{"cis_profile": {{"level": 1}}}}',
         f"\tm.compliance_report.total_controls == {len(by_prof[RDS1])} with input as {json.dumps(p_rds)}",
         f"\tm.compliance_report.failed_controls == {len(by_prof[RDS1])} with input as {json.dumps(p_rds)}", "}", "",
         "test_every_recommendation_fires_without_facts if {", '\tv := b.violations with input as {"sql": {}}',
         '\tids := {id | some msg in v; id := split(msg, ":")[0]}', f"\tcount(ids) == {len(ids)}", "}", "",
         "test_recommendations_cover_the_workbook if {", f"\tcount(b.recommendations) == {len(ids)}",
         f'\tcount([r | some r in b.recommendations; r.assessment == "Manual"]) == {n_manual}',
         f'\tcount([r | some r in b.recommendations; r.level == 2]) == {len(by_prof[DE2])}', "}", "",
         "test_profile_scopes if {", f"\tcount(b.in_scope) == {len(ids)} with input as green",
         f'\tcount(b.in_scope) == {len(by_prof[DE1])} with input as object.union(green, {{"cis_profile": {{"level": 1}}}})',
         f"\tcount(b.in_scope) == {len(by_prof[RDS1])} with input as object.union(green, {json.dumps(p_rds)})", "}", "",
         "test_out_of_scope_recommendation_is_silent if {",
         '\tbad := json.patch(green, [{"op": "remove", "path": "/sql/databases_without_tde"}])',
         '\tv := b.violations with input as object.union(bad, {"cis_profile": {"level": 1}})',
         '\tcount([msg | some msg in v; startswith(msg, "7.5:")]) == 0', "}", "",
         "test_rds_allowances_only_apply_on_rds if {",
         '\tg := json.patch(green, [{"op": "replace", "path": "/sql/guest_connect_grants", "value": [{"database": "rdsadmin"}]}, '
         '{"op": "replace", "path": "/sql/builtin_logins", "value": [{"name": "[BUILTIN]\\\\Administrators"}]}, '
         '{"op": "replace", "path": "/sql/sysadmin_logins_without_expiration_check", "value": [{"name": "rdsa"}]}])',
         f"\tb.compliant with input as object.union(g, {json.dumps(p_rds)})",
         "\tv := b.violations with input as g",
         '\tcount([msg | some msg in v; regex.match(`^(3\\.2|3\\.9|4\\.2):`, msg)]) == 3', "}", "",
         "test_2_2_not_applicable_when_clr_strict_security_on if {",
         '\tok := json.patch(green, [{"op": "add", "path": "/sql/configurations/clr enabled", "value": {"value_configured": 1, "value_in_use": 1}}])',
         "\tb.compliant with input as ok", "}", "",
         "test_2_7_not_applicable_on_cluster if {",
         '\tok := json.patch(green, [{"op": "replace", "path": "/sql/is_clustered", "value": true}, {"op": "remove", "path": "/sql/configurations/remote admin connections"}])',
         "\tb.compliant with input as ok", "}", "",
         "test_config_names_match_case_insensitively if {",
         '\tok := json.patch(green, [{"op": "remove", "path": "/sql/configurations/database mail xps"}, '
         '{"op": "add", "path": "/sql/configurations/Database Mail XPs", "value": {"value_configured": "0", "value_in_use": "0"}}])',
         "\tb.compliant with input as ok", "}", "",
         "test_5_1_unlimited_error_logs_passes if {",
         '\tok := json.patch(green, [{"op": "replace", "path": "/sql/num_error_logs", "value": -1}])', "\tb.compliant with input as ok", "}", "",
         "test_5_3_all_logins_passes if {",
         '\tok := json.patch(green, [{"op": "replace", "path": "/sql/login_audit_level", "value": "ALL"}])', "\tb.compliant with input as ok", "}", "",
         "test_6_2_only_non_safe_assemblies_listed_fails if {",
         '\tbad := json.patch(green, [{"op": "replace", "path": "/sql/user_assemblies", "value": [{"database": "AppDB", "name": "ExtLib", "permission_set_desc": "EXTERNAL_ACCESS"}]}])',
         '\tcount([msg | some msg in b.violations with input as bad; startswith(msg, "6.2:")]) == 1', "}", "",
         "test_6_2_no_user_assemblies_passes if {",
         '\tok := json.patch(green, [{"op": "replace", "path": "/sql/user_assemblies", "value": []}])', "\tb.compliant with input as ok", "}", "",
         "test_5_4_contained_groups_satisfy_contained_requirement if {",
         f'\trows := array.concat(green.sql.server_audit_actions, [{{"audit_action_name": g, "audit_enabled": true, "specification_enabled": true, "audited_result": "SUCCESS AND FAILURE"}} | some g in {json.dumps(g.CONTAINED_AUDIT_GROUPS)}])',
         '\tok := json.patch(green, [{"op": "replace", "path": "/sql/has_contained_databases", "value": true}, {"op": "replace", "path": "/sql/server_audit_actions", "value": rows}])',
         "\tb.compliant with input as ok", "}", ""]
    for rid in ids:
        r, s, i = recs[rid], RULES[rid], ident(rid)
        T += [f"# {rid} ({r['status']})", f"test_{i}_pass if {{", "\tv := b.violations with input as green",
              f'\tcount([msg | some msg in v; startswith(msg, "{rid}:")]) == 0', "}", ""]
        fail_msg = rid + ": " + r["title"] + (" (manual review not attested)" if s["kind"] == "attest" else "")
        for n, ops in enumerate(s["fails"], 1):
            suffix = "" if len(s["fails"]) == 1 else f"_{n}"
            T += [f"test_{i}_fail{suffix} if {{", f"\tbad := json.patch(green, {json.dumps(ops, ensure_ascii=False)})",
                  f"\t{rego_str(fail_msg)} in b.violations with input as bad", "}", ""]
        if s["kind"] != "attest":
            T += [f"test_{i}_evidence_missing if {{", f"\tbad := json.patch(green, {json.dumps(s['miss'], ensure_ascii=False)})",
                  f"\t{rego_str(rid + ': evidence missing — ' + s['field'] + ' not collected')} in b.violations with input as bad", "}", ""]
    (out / "tests").mkdir(exist_ok=True)
    (out / "tests" / "test_cis_sql_server_2022.rego").write_text("\n".join(T))
    if shutil.which("opa"):
        subprocess.run(["opa", "fmt", "-w", str(out)], check=True)
    print(f"{KEY}: {len(ids)} recommendations ({n_auto} Automated, {n_manual} Manual); "
          f"profiles {', '.join(f'{p}={len(v)}' for p, v in by_prof.items())}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
