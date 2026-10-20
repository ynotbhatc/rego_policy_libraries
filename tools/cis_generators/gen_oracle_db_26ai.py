#!/usr/bin/env python3
"""CIS Oracle Database 26ai Benchmark v1.0.0: every recommendation, from the benchmark's own workbook.

    python3 tools/cis_generators/gen_oracle_db_26ai.py CIS_Oracle_Database_26ai_Benchmark_v1.0.0.xlsx

Needs openpyxl. Reads the recommendation list (id, title, Assessment Status, profile) out of the CIS
workbook (CIS-licensed, never committed), checks the ids against the logic table below, and emits
benchmarks/cis/oracle/cis_oracle_26ai.rego plus tests/test_cis_oracle_26ai.rego.

Adapted from gen_oracle_db_23ai.py (CIS renamed 23ai to 26ai; 87 recommendations carried over, seven new).
Differences from the 23ai generator:
  * ids, titles, Automated/Manual status and profiles come from the workbook, not PDF text;
  * every Automated check fails closed with its own "<id>: evidence missing — <field> not collected"
    message when the facts it reads were not collected (an empty settings object is not evidence);
  * every Manual review without a decidable fact is an attestation boolean (not attested => violation);
  * the tests carry a pass, a fail and (Automated) an evidence-missing case for every recommendation.
The logic table is hand-authored from the audit procedures. Input contract matches the 23ai module.
"""
import json
import pathlib
import sys

import openpyxl

HERE = pathlib.Path(__file__).resolve().parent
OUT = HERE.parent.parent / "benchmarks" / "cis" / "oracle"
BENCH = "CIS Oracle Database 26ai Benchmark v1.0.0"
EXPECTED_TOTAL = 94
PROFILE_SHEETS = {  # workbook sheet (names are truncated to 31 chars) -> profile name used in the rego
    "Level 1 - RDBMS": "Level 1 - RDBMS",
    "Level 1 - RDBMS On Linux Host": "Level 1 - RDBMS On Linux Host OS",
    "Level 1 - RDBMS On Windows Ser": "Level 1 - RDBMS On Windows Server Host OS",
}


def ptr(path):
    """dotted path or list of keys -> JSON pointer"""
    parts = path if isinstance(path, list) else path.split(".")
    return "/" + "/".join(p.replace("~", "~0").replace("/", "~1") for p in parts)


def rep(path, value):
    return {"op": "replace", "path": ptr(path), "value": value}


def add(path, value):
    return {"op": "add", "path": ptr(path), "value": value}


def rm(path):
    return {"op": "remove", "path": ptr(path)}


def spec(body, fx, ev, field, fails, miss, kind="automated"):
    """body: rego lines for r_<id>; fx: green fixture entries [(path, value)]; ev: rego lines proving the
    facts were collected; field: name used in the evidence-missing message; fails: list of json.patch op
    lists, each of which must make the check fail; miss: json.patch ops that remove the evidence."""
    return {"body": body, "fx": fx, "ev": ev, "field": field, "fails": fails, "miss": miss, "kind": kind}


NONEMPTY = lambda p: [f"is_object(input.{p})", f"count(input.{p}) > 0"]  # noqa: E731  {} is not evidence


# ── fact constructors ──
def param_eq(name, val, bad="BOGUS"):
    return spec([f'upper(input.oracle.parameters["{name}"]) == "{val.upper()}"'], [(f"oracle.parameters.{name}", val)],
                [f'"{name}" in object.keys(input.oracle.parameters)'], f"oracle.parameters.{name}",
                [[rep(f"oracle.parameters.{name}", bad)]], [rm(f"oracle.parameters.{name}")])


def param_in(name, vals, fx):
    s = ", ".join(f'"{v.upper()}"' for v in vals)
    return spec([f'upper(input.oracle.parameters["{name}"]) in {{{s}}}'], [(f"oracle.parameters.{name}", fx)],
                [f'"{name}" in object.keys(input.oracle.parameters)'], f"oracle.parameters.{name}",
                [[rep(f"oracle.parameters.{name}", "(DROP,10)")]], [rm(f"oracle.parameters.{name}")])


def param_le(name, n, fx):
    return spec([f'to_number(input.oracle.parameters["{name}"]) <= {n}'], [(f"oracle.parameters.{name}", fx)],
                [f'"{name}" in object.keys(input.oracle.parameters)'], f"oracle.parameters.{name}",
                [[rep(f"oracle.parameters.{name}", str(n + 1))]], [rm(f"oracle.parameters.{name}")])


def param_not(name, bad, fx):  # parameter may be unset; if set it must not equal `bad`
    return spec([f'upper(object.get(input.oracle.parameters, "{name}", "")) != "{bad.upper()}"'],
                [(f"oracle.parameters.{name}", fx)], NONEMPTY("oracle.parameters"), "oracle.parameters",
                [[rep(f"oracle.parameters.{name}", bad)]], [rep("oracle.parameters", {})])


def param_empty(name):
    return spec([f'object.get(input.oracle.parameters, "{name}", "") == ""'], [(f"oracle.parameters.{name}", "")],
                NONEMPTY("oracle.parameters"), "oracle.parameters",
                [[rep(f"oracle.parameters.{name}", "lsnr-scan:1521")]], [rep("oracle.parameters", {})])


def sqlnet_eq(name, val):
    return spec([f'upper(input.oracle.sqlnet["{name}"]) == "{val.upper()}"'], [(["oracle", "sqlnet", name], val)],
                NONEMPTY("oracle.sqlnet"), "oracle.sqlnet",
                [[rep(["oracle", "sqlnet", name], "BOGUS")], [rm(["oracle", "sqlnet", name])]], [rep("oracle.sqlnet", {})])


def sqlnet_not_true(name):  # absent is compliant, but only when sqlnet.ora was collected
    return spec([f'upper(object.get(input.oracle.sqlnet, "{name}", "FALSE")) != "TRUE"'], [],
                NONEMPTY("oracle.sqlnet"), "oracle.sqlnet",
                [[add(["oracle", "sqlnet", name], "TRUE")]], [rep("oracle.sqlnet", {})])


def listener_not_true(name):
    return spec([f'upper(object.get(input.oracle.listener_ora, "{name}", "FALSE")) != "TRUE"'], [],
                NONEMPTY("oracle.listener_ora"), "oracle.listener_ora",
                [[add(["oracle", "listener_ora", name], "TRUE")]], [rep("oracle.listener_ora", {})])


def _profile(call, res, fx, bad):
    return spec([call], [(f"oracle.profiles.ORA_STIG_PROFILE.{res}", fx)], NONEMPTY("oracle.profiles"), "oracle.profiles",
                [[rep(f"oracle.profiles.ORA_STIG_PROFILE.{res}", bad)]], [rep("oracle.profiles", {})])


def profile_le(res, n, fx):
    return _profile(f'profiles_every_le("{res}", {n})', res, fx, str(n + 1))


def profile_ge(res, n, fx):
    return _profile(f'profiles_every_ge("{res}", {n})', res, fx, str(n - 1))


def profile_eq(res, val):
    return _profile(f'profiles_every_eq("{res}", "{val}")', res, val, "10")


def profile_set(res, fx):
    return _profile(f'profiles_every_set("{res}")', res, fx, "NULL")


def empty(path, row):  # the audit query's rows; an empty list is "no rows", a missing list is no evidence
    return spec([f"count(input.{path}) == 0"], [(path, [])], [f"is_array(input.{path})"], path,
                [[rep(path, [row])]], [rm(path)])


def boolfact(path, val=True):
    return spec([f"input.{path} == {str(val).lower()}"], [(path, val)], [f"is_boolean(input.{path})"], path,
                [[rep(path, not val)]], [rm(path)])


def attest(name):
    path = f"oracle.attest.{name}"
    return spec([f"input.{path} == true"], [(path, True)], None, path, [[rep(path, False)], [rm(path)]], None, kind="attest")


def _grant_row(key, value, **extra):
    return {"grantee": "APP_USER", key: value, "oracle_maintained": "N", **extra}


def sys_privs(call, privs, **extra):  # one failing test per privilege the check covers
    return spec(call, [], ["is_array(input.oracle.grants.sys_privs)"], "oracle.grants.sys_privs",
                [[rep("oracle.grants.sys_privs", [_grant_row("privilege", p, **extra)])] for p in privs],
                [rm("oracle.grants.sys_privs")])


def sys_priv(*names):
    return sys_privs([f'no_unauthorized_sys_priv("{n}")' for n in names], list(names))


def role(name):
    return spec([f'no_unauthorized_role("{name}")'], [], ["is_array(input.oracle.grants.role_privs)"], "oracle.grants.role_privs",
                [[rep("oracle.grants.role_privs", [_grant_row("granted_role", name)])]], [rm("oracle.grants.role_privs")])


def audit_list(path, required, bad):
    return spec([f"every a in {json.dumps(required)} {{ a in input.{path} }}"], [(path, list(required))],
                [f"is_array(input.{path})"], path, [[rep(path, bad)]], [rm(path)])


HELPERS = """
# ── helpers ──────────────────────────────────────────────────────────────────
# Profiles: every profile the collector reports must satisfy the limit (DEFAULT resolved by the collector
# to the DEFAULT profile's value, as the benchmark's own DECODE does; UNLIMITED fails numeric comparisons).
profiles_every_le(resource, max) if {
	count(input.oracle.profiles) > 0
	every _, p in input.oracle.profiles {
		to_number(p[resource]) <= max
	}
}

profiles_every_ge(resource, min) if {
	count(input.oracle.profiles) > 0
	every _, p in input.oracle.profiles {
		to_number(p[resource]) >= min
	}
}

profiles_every_eq(resource, val) if {
	count(input.oracle.profiles) > 0
	every _, p in input.oracle.profiles {
		upper(p[resource]) == val
	}
}

profiles_every_set(resource) if {
	count(input.oracle.profiles) > 0
	every _, p in input.oracle.profiles {
		not upper(p[resource]) in {"NULL", "DEFAULT", ""}
	}
}

# 3.3: a password limit in days; UNLIMITED counts as 9999 days (so it always fails), as the benchmark does.
# A missing or non-numeric limit is undefined, so the profile fails.
_limit_days(v) := 9999 if upper(sprintf("%v", [v])) == "UNLIMITED"

_limit_days(v) := to_number(v) if upper(sprintf("%v", [v])) != "UNLIMITED"

profiles_every_life_plus_grace_le(max) if {
	count(input.oracle.profiles) > 0
	every _, p in input.oracle.profiles {
		_limit_days(p.PASSWORD_LIFE_TIME) + _limit_days(p.PASSWORD_GRACE_TIME) <= max
	}
}

# Privileges: the benchmark's queries list grants to grantees that are not ORACLE_MAINTAINED; a grant to a
# grantee the organization has authorized (input.oracle.authorized_grantees) is not a finding. The queries
# also follow role hierarchies; the collector is expected to flatten role-inherited grants into these rows.
# ORACLE_MAINTAINED arrives as the view's 'Y'/'N' or as a boolean; anything else (missing, "N", false) is not Oracle's
_oracle_maintained(g) if g.oracle_maintained == true

_oracle_maintained(g) if upper(g.oracle_maintained) == "Y"

_unauthorized(g) if {
	not _oracle_maintained(g)
	not g.grantee in input.oracle.authorized_grantees
}

no_unauthorized_sys_priv(priv) if {
	is_array(input.oracle.grants.sys_privs)
	count([g | some g in input.oracle.grants.sys_privs; g.privilege == priv; _unauthorized(g)]) == 0
}

no_unauthorized_sys_priv_like(frag) if {
	is_array(input.oracle.grants.sys_privs)
	count([g | some g in input.oracle.grants.sys_privs; contains(g.privilege, frag); _unauthorized(g)]) == 0
}

no_unauthorized_role(r) if {
	is_array(input.oracle.grants.role_privs)
	count([g | some g in input.oracle.grants.role_privs; g.granted_role == r; _unauthorized(g)]) == 0
}
"""

CRITICAL_PACKAGES = ["DBMS_AW", "DBMS_CRYPTO", "DBMS_FGA", "DBMS_JAVA_TEST", "DBMS_JOB", "DBMS_LOGMNR", "DBMS_NETWORK_ACL_ADMIN",
                     "DBMS_REDACT", "DBMS_REDEFINITION", "DBMS_RLS", "DBMS_SCHEDULER", "DBMS_SQL_TRANSLATOR", "DBMS_SYS_SQL",
                     "DBMS_TSDP_MANAGE", "DBMS_TSDP_PROTECT", "DBMS_XMLGEN", "DBMS_XMLSTORE", "OWA_UTIL"]
SENSITIVE_TABLES = ["CDB_LOCAL_ADMINAUTH$", "DEFAULT_PWD$", "ENC$", "HISTGRM$", "HIST_HEAD$", "LINK$", "PDB_SYNC$",
                    "SCHEDULER$_CREDENTIAL", "USER$", "USER_HISTORY$", "XS$VERIFIERS"]
SYS_USERS = ["SYS", "SYSBACKUP", "SYSDG", "SYSKM", "SYSRAC", "PUBLIC"]

RULES = {
    "1.1": boolfact("oracle.patches.latest_cpu_applied"),
    "2.1.1": boolfact("oracle.listener.extproc_configured", False),
    "2.1.2": listener_not_true("ACCEPT_MD5_CERTS"), "2.1.3": listener_not_true("ACCEPT_SHA1_CERTS"),
    "2.1.4": listener_not_true("ALLOWED_WEAK_CERT_ALGORITHMS"),
    "2.2.1": sqlnet_not_true("ACCEPT_MD5_CERTS"), "2.2.2": sqlnet_not_true("ACCEPT_SHA1_CERTS"),
    "2.2.3": sqlnet_not_true("ALLOWED_WEAK_CERT_ALGORITHMS"),
    "2.2.4": sqlnet_eq("SQLNET.ALLOWED_LOGON_VERSION_CLIENT", "12a"), "2.2.5": sqlnet_eq("SQLNET.ALLOWED_LOGON_VERSION_SERVER", "12a"),
    "2.2.6": sqlnet_eq("SQLNET.ENCRYPTION_CLIENT", "REQUIRED"), "2.2.7": sqlnet_eq("SQLNET.ENCRYPTION_SERVER", "REQUIRED"),
    "2.2.8": sqlnet_eq("SQLNET.ENCRYPTION_TYPES_CLIENT", "AES256"), "2.2.9": sqlnet_eq("SQLNET.ENCRYPTION_TYPES_SERVER", "AES256"),
    "2.2.10": sqlnet_eq("SQLNET.CRYPTO_CHECKSUM_CLIENT", "REQUIRED"), "2.2.11": sqlnet_eq("SQLNET.CRYPTO_CHECKSUM_SERVER", "REQUIRED"),
    "2.2.12": sqlnet_eq("SSL_CERT_REVOCATION", "REQUIRED"),
    "2.3.1": param_not("background_core_dump", "FULL", "PARTIAL"), "2.3.2": param_not("shadow_core_dump", "FULL", "PARTIAL"),
    "2.3.3": param_eq("mle_prog_languages", "OFF"), "2.3.4": param_eq("allow_group_access_to_sga", "FALSE", "TRUE"),
    "2.3.5": attest("underscore_parameters_reviewed"),
    "2.3.6": param_eq("os_roles", "FALSE", "TRUE"), "2.3.7": param_eq("remote_os_roles", "FALSE", "TRUE"),
    "2.3.8": param_le("sec_max_failed_login_attempts", 3, "3"),
    "2.3.9": param_in("sec_protocol_error_further_action", ["(DROP,3)", "(DROP, 3)"], "(DROP,3)"),
    "2.3.10": param_eq("sec_protocol_error_trace_action", "LOG", "NONE"), "2.3.11": param_eq("sec_return_server_release_banner", "FALSE", "TRUE"),
    "2.3.12": param_eq("remote_login_passwordfile", "NONE", "EXCLUSIVE"), "2.3.13": param_empty("remote_listener"),
    "2.3.14": param_eq("resource_limit", "TRUE", "FALSE"),
    "3.1": profile_le("FAILED_LOGIN_ATTEMPTS", 5, "3"), "3.2": profile_ge("PASSWORD_LOCK_TIME", 1, "1"),
    "3.3": spec(["profiles_every_life_plus_grace_le(365)"],
                [("oracle.profiles.ORA_STIG_PROFILE.PASSWORD_LIFE_TIME", "60"), ("oracle.profiles.ORA_STIG_PROFILE.PASSWORD_GRACE_TIME", "5")],
                NONEMPTY("oracle.profiles"), "oracle.profiles",
                [[rep("oracle.profiles.ORA_STIG_PROFILE.PASSWORD_LIFE_TIME", "UNLIMITED")],
                 [rep("oracle.profiles.ORA_STIG_PROFILE.PASSWORD_LIFE_TIME", "360"), rep("oracle.profiles.ORA_STIG_PROFILE.PASSWORD_GRACE_TIME", "6")],
                 [rm("oracle.profiles.ORA_STIG_PROFILE.PASSWORD_GRACE_TIME")]],
                [rep("oracle.profiles", {})]),
    "3.4": profile_eq("PASSWORD_REUSE_MAX", "UNLIMITED"), "3.5": profile_set("PASSWORD_VERIFY_FUNCTION", "ORA12C_STIG_VERIFY_FUNCTION"),
    "3.6": attest("password_verify_function_meets_cis"), "3.7": profile_le("PASSWORD_ROLLOVER_TIME", 0, "0"),
    "3.8": profile_le("INACTIVE_ACCOUNT_TIME", 120, "35"),
    "4.1": empty("oracle.users_with_default_password", "SCOTT"), "4.2": empty("oracle.custom_oracle_maintained_users", "APP_OWNER"),
    "4.3": attest("ras_users_reviewed"),
    "4.4": empty("oracle.users_with_old_password_versions", "LEGACY_USER"),
    "4.5": spec(['input.oracle.password_file_format == "12.2"'], [("oracle.password_file_format", "12.2")],
                ["is_string(input.oracle.password_file_format)"], "oracle.password_file_format",
                [[rep("oracle.password_file_format", "12")]], [rm("oracle.password_file_format")]),
    # 4.6 was a Manual review in 23ai; 26ai makes it Automated (password-file users missing on some RAC instance)
    "4.6": empty("oracle.pwfile_users_not_on_all_instances", "C##ADMIN"),
    "4.7": empty("oracle.public_db_links", "REMOTE_DB"), "4.8": empty("oracle.db_links_with_legacy_password_encryption", "OLD_LINK"),
    "5.1": empty("oracle.audit.unaudited_system_actions", "CREATE TABLE"),
    "5.2": audit_list("oracle.audit.enabled_options", ["LOGON", "LOGOFF"], ["LOGON"]),
    "5.3": audit_list("oracle.audit.audited_packages", CRITICAL_PACKAGES, CRITICAL_PACKAGES[:-1]),
    "5.4": audit_list("oracle.audit.enabled_options", ["EXPORT"], ["LOGON", "LOGOFF"]),
    "5.5": audit_list("oracle.audit.all_actions_audited_users", SYS_USERS, SYS_USERS[:-1]),
    "6.1.1": sys_privs(['no_unauthorized_sys_priv_like("ANY")'], ["SELECT ANY TABLE"]),
    "6.1.2": sys_privs(['count([g | some g in input.oracle.grants.sys_privs; g.admin_option == true; _unauthorized(g)]) == 0'],
                       ["CREATE SESSION"], admin_option=True),
    "6.1.3": sys_priv("EXPORT FULL DATABASE", "IMPORT FULL DATABASE"),
    "6.1.4": sys_priv("CREATE EXTERNAL JOB"), "6.1.5": sys_priv("BECOME USER"), "6.1.6": sys_priv("TEXT DATASTORE ACCESS"),
    "6.1.7": sys_priv("CREATE PUBLIC DATABASE LINK", "ALTER PUBLIC DATABASE LINK", "DROP PUBLIC DATABASE LINK"),
    "6.1.8": sys_priv("LOGMINING"), "6.1.9": sys_priv("ALTER SYSTEM"), "6.1.10": sys_priv("CREATE LIBRARY"),
    "6.1.11": sys_privs(['count([g | some g in input.oracle.grants.sys_privs; _unauthorized(g)]) == 0'], ["CREATE SESSION"]),
    "6.2.1": role("DBA"), "6.2.2": role("EXP_FULL_DATABASE"), "6.2.3": role("IMP_FULL_DATABASE"), "6.2.4": role("DATAPUMP_EXP_FULL_DATABASE"),
    "6.2.5": role("DATAPUMP_IMP_FULL_DATABASE"), "6.2.6": role("DV_ADMIN"), "6.2.7": role("DV_AUDIT_CLEANUP"), "6.2.8": role("OLAP_DBA"),
    "6.2.9": role("LBAC_DBA"), "6.2.10": role("JAVA_ADMIN"), "6.2.11": role("JAVASYSPRIVS"), "6.2.12": role("LOGSTDBY_ADMINISTRATOR"),
    "6.2.13": role("SQL_FIREWALL_ADMIN"), "6.2.14": role("MAINTPLAN_APP"), "6.2.15": role("JAVADEBUGPRIV"), "6.2.16": role("DV_PATCH_ADMIN"),
    "6.2.17": role("DV_POLICY_OWNER"), "6.2.18": role("AUDIT_ADMIN"), "6.2.19": role("AUDIT_VIEWER"), "6.2.20": role("PDB_DBA"),
    "6.2.21": role("SELECT_CATALOG_ROLE"), "6.2.22": role("EXECUTE_CATALOG_ROLE"),
    "6.3.1": attest("schema_privileges_reviewed"),
    "6.4.1": spec([f'count([g | some g in input.oracle.grants.tab_privs; g.owner == "SYS"; g.table_name in {json.dumps(SENSITIVE_TABLES)}; '
                   'g.privilege == "ALL"]) == 0'], [], ["is_array(input.oracle.grants.tab_privs)"], "oracle.grants.tab_privs",
                  [[rep("oracle.grants.tab_privs", [{"grantee": "APP_USER", "owner": "SYS", "table_name": "USER$", "privilege": "ALL"}])]],
                  [rm("oracle.grants.tab_privs")]),
    "6.5.1": attest("column_privileges_reviewed"), "6.6.1": attest("proxy_user_privileges_reviewed"),
    "6.7.1": attest("custom_java_privileges_reviewed"), "6.8.1": attest("directory_object_access_reviewed"),
    "6.8.2": attest("directory_object_privileges_reviewed"), "6.8.3": attest("external_table_preprocessors_reviewed"),
    "6.8.4": attest("external_tables_reviewed"),
}


def key(rid):
    return [int(p) for p in rid.split(".")]


def ident(rid):
    return rid.replace(".", "_")


def rego_str(s):
    return json.dumps(s, ensure_ascii=False)  # a JSON string literal is a valid Rego string literal


def read_workbook(path):
    wb = openpyxl.load_workbook(path, read_only=True)
    recs, sections = {}, {}
    for sheet, profile in PROFILE_SHEETS.items():
        rows = list(wb[sheet].iter_rows(values_only=True))
        h = rows[0]
        ci = {c: h.index(c) for c in ("Section #", "Recommendation #", "Title", "Assessment Status")}
        for r in rows[1:]:
            rid, title, status = r[ci["Recommendation #"]], r[ci["Title"]], r[ci["Assessment Status"]]
            if not rid:
                sec = str(r[ci["Section #"]] or "")
                if sec and "." not in sec:
                    sections[sec] = " ".join(str(title).split())
                continue
            rid = str(rid).strip()
            title = " ".join(str(title).split()).replace('"', "'")
            if rid in recs:
                if recs[rid]["title"] != title or recs[rid]["status"] != status:
                    raise SystemExit(f"{rid}: title/status differ between profile sheets")
                recs[rid]["profiles"].append(profile)
            else:
                recs[rid] = {"title": title, "status": status, "level": 1, "profiles": [profile]}
    linux = {r for r, v in recs.items() if PROFILE_SHEETS["Level 1 - RDBMS On Linux Host"] in v["profiles"]}
    windows = {r for r, v in recs.items() if PROFILE_SHEETS["Level 1 - RDBMS On Windows Ser"] in v["profiles"]}
    if linux != windows:
        raise SystemExit(f"Linux and Windows host profiles differ: {sorted(linux ^ windows)}")
    return recs, sections


def main(xlsx):
    recs, all_sections = read_workbook(xlsx)
    missing = sorted(set(recs) - set(RULES), key=key)
    extra = sorted(set(RULES) - set(recs), key=key)
    if missing or extra:
        raise SystemExit(f"logic table out of step with the workbook: missing {missing} extra {extra}")
    if len(recs) != EXPECTED_TOTAL:
        raise SystemExit(f"workbook has {len(recs)} recommendations, expected {EXPECTED_TOTAL}")
    for rid, r in recs.items():  # every attestation must be a Manual recommendation
        if RULES[rid]["kind"] == "attest" and r["status"] != "Manual":
            raise SystemExit(f"{rid} is {r['status']} in the workbook but the logic table attests it")
    ids = sorted(recs, key=key)
    tops = sorted({rid.split(".")[0] for rid in ids}, key=int)
    sections = {s: all_sections[s] for s in tops}
    n_auto = sum(1 for r in recs.values() if r["status"] == "Automated")
    n_manual = len(ids) - n_auto
    n_attest = sum(1 for r in RULES.values() if r["kind"] == "attest")
    rdbms = [r for r in ids if recs[r]["profiles"] == ["Level 1 - RDBMS"]]
    host = [r for r in ids if r not in rdbms]
    host_sections = sorted({".".join(r.split(".")[:2]) for r in host}, key=key)

    L = ["# METADATA", f'# title: "{BENCH}"', "# custom:", "#   class: security", "#   framework: cis_oracle_26ai",
         "#   source: cis", "#   domains: [database, oracle]", "package cis.oracle_26ai", "",
         f"# {BENCH} (CIS renamed the Oracle Database 23ai benchmark to 26ai; supersedes cis.oracle_23ai).",
         f"# {len(ids)} recommendations ({n_auto} Automated, {n_manual} Manual), every one in the benchmark; ids, titles,",
         "# status and profiles read from the CIS workbook and the logic written from each audit procedure",
         "# (tools/cis_generators/gen_oracle_db_26ai.py). All recommendations are Level 1.",
         f"# Profiles: {len(rdbms)} are 'Level 1 - RDBMS'; the {len(host)} host-file recommendations ({', '.join(host_sections)})",
         "# are 'Level 1 - RDBMS On Linux Host OS' and, identically, 'Level 1 - RDBMS On Windows Server Host OS'.",
         "# As in 23ai, one package evaluates every profile; `recommendations` lists each id's status and profiles.",
         f"# {n_attest} Manual reviews carry an attestation boolean (not attested => violation). 1.1 and 2.2.9 are",
         "# Manual in the workbook but have a decidable fact, so they are checked like Automated ones.",
         "# Automated checks fail closed: facts not collected => '<id>: evidence missing — <field> not collected'.",
         "#",
         "# Input contract (same as cis.oracle_23ai and benchmarks/stig/oracle_database_19c, so one collector feeds all):",
         "#   input.oracle.parameters[<name>]           : V$SYSTEM_PARAMETER value, name lowercase",
         "#   input.oracle.sqlnet[<PARAM>] / listener_ora[<PARAM>] : sqlnet.ora and listener.ora entries",
         "#   input.oracle.profiles[<profile>][<RESOURCE>] : DBA_PROFILES limits (DEFAULT resolved by the collector)",
         "#   input.oracle.grants.{sys_privs,role_privs,tab_privs}[] : {grantee, privilege|granted_role|table_name, owner,",
         "#                                               admin_option, oracle_maintained}",
         "#   input.oracle.authorized_grantees[]         : grantees the organization has authorized for restricted privileges",
         "#   input.oracle.audit.enabled_options[] / audited_packages[] / all_actions_audited_users[] / unaudited_system_actions[]",
         "#   input.oracle.<query result>                : rows the audit query must not return (lists), flags",
         "#   input.oracle.attest.*                      : attestation booleans for the Manual recommendations",
         "", "import rego.v1", "", "default compliant := false", "", "compliant if {", "\tinput.oracle", "\tcount(violations) == 0", "}",
         HELPERS.rstrip(), ""]
    fx = {}
    for rid in ids:
        r, s, i = recs[rid], RULES[rid], ident(rid)
        L += [f"# {rid} ({r['status']}, {'; '.join(r['profiles'])})", f"default r_{i} := false", f"r_{i} if {{"]
        L += ["\t" + b for b in s["body"]] + ["}", ""]
        if s["kind"] == "attest":
            L += [f"violations contains {rego_str(rid + ': ' + r['title'] + ' (manual review not attested)')} if {{", f"\tnot r_{i}", "}", ""]
        else:
            L += [f"default e_{i} := false", f"e_{i} if {{"] + ["\t" + b for b in s["ev"]] + ["}", "",
                  f"violations contains {rego_str(rid + ': evidence missing — ' + s['field'] + ' not collected')} if {{", f"\tnot e_{i}", "}", "",
                  f"violations contains {rego_str(rid + ': ' + r['title'])} if {{", f"\te_{i}", f"\tnot r_{i}", "}", ""]
        for path, val in s["fx"]:
            d = fx
            parts = path if isinstance(path, list) else path.split(".")
            for p in parts[:-1]:
                d = d.setdefault(p, {})
            if isinstance(val, list) and isinstance(d.get(parts[-1]), list):
                d[parts[-1]] = sorted(set(d[parts[-1]]) | set(val))
            else:
                d[parts[-1]] = val
    recmap = {rid: {"title": recs[rid]["title"], "level": 1, "assessment": recs[rid]["status"], "profiles": recs[rid]["profiles"]}
              for rid in ids}
    L += ['violations contains "CIS Oracle 26ai: FAIL-CLOSED - facts \'input.oracle\' were not supplied; the database was not evaluated" if {',
          "\tnot input.oracle", "}", "",
          "sections := " + json.dumps(sections, indent=1, ensure_ascii=False), "",
          "# id -> CIS title, level, Automated/Manual status and the workbook profiles it belongs to",
          "recommendations := " + json.dumps(recmap, indent=1, ensure_ascii=False), "",
          "compliance_report := {", f'\t"benchmark": "{BENCH}",', f'\t"total_controls": {len(ids)},',
          f'\t"standard_total": {len(ids)},', f'\t"standard_total_source": "{BENCH}, recommendations counted from the CIS workbook",',
          '\t"sections": sections,', '\t"compliant": compliant,', '\t"violation_count": count(violations),', '\t"violations": violations,', "}", ""]
    (OUT / "cis_oracle_26ai.rego").write_text("\n".join(L))

    # green fixture: complete the lists the privilege helpers read and give each settings object a real entry
    o = fx.setdefault("oracle", {})
    o.setdefault("grants", {}).update({"sys_privs": [], "role_privs": [], "tab_privs": []})
    o["authorized_grantees"] = ["DBA_TEAM"]
    o["listener_ora"] = {"ADMIN_RESTRICTIONS_LISTENER": "ON"}
    o["sqlnet"].setdefault("ACCEPT_MD5_CERTS", "FALSE")
    fxs = json.dumps(fx, indent=1, ensure_ascii=False).replace("\n", "\n\t")
    T = ["package cis.oracle_26ai_test", "", "import rego.v1", "", "import data.cis.oracle_26ai as b", "",
         f"green := {fxs}", "",
         "test_green_database_is_compliant if {", "\tr := b.compliance_report with input as green", "\tr.compliant == true",
         "\tcount(r.violations) == 0", f"\tr.total_controls == {len(ids)}", "}", "",
         "test_fail_closed_on_empty_input if {", "\tr := b.compliance_report with input as {}", "\tr.compliant == false", "\tcount(r.violations) > 0", "}", "",
         "test_every_recommendation_fires_without_facts if {", '\tv := b.violations with input as {"oracle": {}}',
         '\tids := {id | some m in v; id := split(m, ":")[0]}', f"\tcount(ids) == {len(ids)}", "}", "",
         "test_recommendations_cover_the_workbook if {", f"\tcount(b.recommendations) == {len(ids)}",
         f'\tcount([r | some r in b.recommendations; r.assessment == "Manual"]) == {n_manual}',
         f'\tcount([r | some r in b.recommendations; "Level 1 - RDBMS On Windows Server Host OS" in r.profiles]) == {len(host)}', "}", "",
         "test_authorized_dba_grant_is_not_a_finding if {",
         '\tok := json.patch(green, [{"op": "replace", "path": "/oracle/grants/role_privs", "value": [{"grantee": "DBA_TEAM", "granted_role": "DBA", "oracle_maintained": false}]}])',
         "\tb.compliant with input as ok", "}", "",
         "test_oracle_maintained_grant_is_not_a_finding if {",
         '\tok := json.patch(green, [{"op": "replace", "path": "/oracle/grants/role_privs", "value": [{"grantee": "SYS", "granted_role": "DBA", "oracle_maintained": "Y"}]}])',
         "\tb.compliant with input as ok", "}", "",
         "test_grant_row_without_oracle_maintained_flag_is_a_finding if {",
         '\tbad := json.patch(green, [{"op": "replace", "path": "/oracle/grants/role_privs", "value": [{"grantee": "APP_USER", "granted_role": "DBA"}]}])',
         f'\t{rego_str("6.2.1: " + recs["6.2.1"]["title"])} in b.violations with input as bad', "}", "",
         "test_3_3_unlimited_grace_fails if {",
         '\tbad := json.patch(green, [{"op": "replace", "path": "/oracle/profiles/ORA_STIG_PROFILE/PASSWORD_GRACE_TIME", "value": "UNLIMITED"}])',
         f'\t{rego_str("3.3: " + recs["3.3"]["title"])} in b.violations with input as bad', "}", "",
         "test_3_3_exactly_365_days_passes if {",
         '\tok := json.patch(green, [{"op": "replace", "path": "/oracle/profiles/ORA_STIG_PROFILE/PASSWORD_LIFE_TIME", "value": "360"}])',
         "\tb.compliant with input as ok", "}", ""]
    for rid in ids:
        r, s, i = recs[rid], RULES[rid], ident(rid)
        T += [f"# {rid} ({r['status']})", f"test_{i}_pass if {{", "\tv := b.violations with input as green",
              f'\tcount([m | some m in v; startswith(m, "{rid}:")]) == 0', "}", ""]
        fail_msg = rid + ": " + r["title"] + (" (manual review not attested)" if s["kind"] == "attest" else "")
        for n, ops in enumerate(s["fails"], 1):
            suffix = "" if len(s["fails"]) == 1 else f"_{n}"
            T += [f"test_{i}_fail{suffix} if {{", f"\tbad := json.patch(green, {json.dumps(ops, ensure_ascii=False)})",
                  f"\t{rego_str(fail_msg)} in b.violations with input as bad", "}", ""]
        if s["kind"] != "attest":
            T += [f"test_{i}_evidence_missing if {{", f"\tbad := json.patch(green, {json.dumps(s['miss'], ensure_ascii=False)})",
                  f"\t{rego_str(rid + ': evidence missing — ' + s['field'] + ' not collected')} in b.violations with input as bad", "}", ""]
    (OUT / "tests").mkdir(exist_ok=True)
    (OUT / "tests" / "test_cis_oracle_26ai.rego").write_text("\n".join(T))
    print(f"cis_oracle_26ai: {len(ids)} recommendations ({n_auto} Automated, {n_manual} Manual, {n_attest} attested) "
          f"-> {OUT / 'cis_oracle_26ai.rego'}")


if __name__ == "__main__":
    main(sys.argv[1])
