#!/usr/bin/env python3
"""CIS Oracle Database 23ai Benchmark v1.0.0 — every recommendation, from the benchmark's own audit SQL.

    pdftotext -layout CIS_Oracle_Database_23ai_Benchmark_v1.0.0.pdf 23ai.txt
    python3 tools/cis_generators/gen_oracle_db_23ai.py 23ai.txt

Reads the recommendation list and each audit procedure out of the extracted text (the PDF itself is
CIS-licensed and not committed), checks the ids and titles against the table below, and emits
benchmarks/cis/oracle/cis_oracle_23ai.rego plus its tests. The logic table is hand-authored from the
audit SQL: parameter and profile checks read the queried value; privilege checks read the rows the
query returns (grants to non-Oracle-maintained grantees outside input.oracle.authorized_grantees);
audit checks read the enabled unified-audit options; the six Manual recommendations whose audit is a
human review are attestation booleans. Input contract matches the Oracle Database 19c STIG module
(benchmarks/stig/oracle_database_19c) so one collector feeds both.
"""
import json, re, sys, pathlib

HERE = pathlib.Path(__file__).resolve().parent
OUT = HERE.parent.parent / "benchmarks" / "cis" / "oracle"

# ── fact constructors → (rego body lines, green fixture entries [(dotted path, value)]) ──
def param_eq(name, val, fx=None):
    return ([f'upper(input.oracle.parameters["{name}"]) == "{val.upper()}"'], [(f"oracle.parameters.{name}", fx or val)])

def param_in(name, vals, fx):
    s = ", ".join(f'"{v.upper()}"' for v in vals)
    return ([f'upper(input.oracle.parameters["{name}"]) in {{{s}}}'], [(f"oracle.parameters.{name}", fx)])

def param_not(name, bad, fx):          # parameter may be unset; if set it must not equal `bad`
    return (['is_object(input.oracle.parameters)', f'upper(object.get(input.oracle.parameters, "{name}", "")) != "{bad.upper()}"'], [(f"oracle.parameters.{name}", fx)])

def param_empty(name):
    return (['is_object(input.oracle.parameters)', f'object.get(input.oracle.parameters, "{name}", "") == ""'], [(f"oracle.parameters.{name}", "")])

def param_le(name, n, fx):
    return ([f'to_number(input.oracle.parameters["{name}"]) <= {n}'], [(f"oracle.parameters.{name}", fx)])

def sqlnet_eq(name, val):
    return (['is_object(input.oracle.sqlnet)', f'upper(input.oracle.sqlnet["{name}"]) == "{val.upper()}"'], [(["oracle", "sqlnet", name], val)])

def sqlnet_not_true(name):                # absent is compliant, but only when sqlnet.ora was collected
    return (['is_object(input.oracle.sqlnet)', f'upper(object.get(input.oracle.sqlnet, "{name}", "FALSE")) != "TRUE"'], [])

def listener_not_true(name):
    return (['is_object(input.oracle.listener_ora)', f'upper(object.get(input.oracle.listener_ora, "{name}", "FALSE")) != "TRUE"'], [])

def profile_le(res, n, fx):
    return ([f'profiles_every_le("{res}", {n})'], [(f"oracle.profiles.ORA_STIG_PROFILE.{res}", fx)])

def profile_ge(res, n, fx):
    return ([f'profiles_every_ge("{res}", {n})'], [(f"oracle.profiles.ORA_STIG_PROFILE.{res}", fx)])

def profile_eq(res, val):
    return ([f'profiles_every_eq("{res}", "{val}")'], [(f"oracle.profiles.ORA_STIG_PROFILE.{res}", val)])

def profile_set(res, fx):
    return ([f'profiles_every_set("{res}")'], [(f"oracle.profiles.ORA_STIG_PROFILE.{res}", fx)])

def empty(path):
    return ([f"count(input.{path}) == 0"], [(path, [])])

def boolfact(path, val=True):
    return ([f"input.{path} == {str(val).lower()}"], [(path, val)])

def attest(path):
    return ([f"input.{path} == true"], [(path, True)])

def sys_priv(name):                    # a system privilege held by a non-Oracle grantee outside the authorized list
    return ([f'no_unauthorized_sys_priv("{name}")'], [])

def sys_priv_like(frag):
    return ([f'no_unauthorized_sys_priv_like("{frag}")'], [])

def role(name):
    return ([f'no_unauthorized_role("{name}")'], [])

def audit_opts(names):
    s = ", ".join(f'"{n}"' for n in names)
    return ([f"every a in {{{s}}} {{ a in input.oracle.audit.enabled_options }}"], [("oracle.audit.enabled_options", list(names))])

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

# Privileges: the benchmark's queries list grants to grantees that are not ORACLE_MAINTAINED; a grant to a
# grantee the organization has authorized (input.oracle.authorized_grantees) is not a finding.
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

RULES = {
    "1.1": boolfact("oracle.patches.latest_cpu_applied"),
    "2.1.1": boolfact("oracle.listener.extproc_configured", False),
    "2.1.2": listener_not_true("ACCEPT_MD5_CERTS"), "2.1.3": listener_not_true("ACCEPT_SHA1_CERTS"), "2.1.4": listener_not_true("ALLOWED_WEAK_CERT_ALGORITHMS"),
    "2.2.1": sqlnet_not_true("ACCEPT_MD5_CERTS"), "2.2.2": sqlnet_not_true("ACCEPT_SHA1_CERTS"), "2.2.3": sqlnet_not_true("ALLOWED_WEAK_CERT_ALGORITHMS"),
    "2.2.4": sqlnet_eq("SQLNET.ALLOWED_LOGON_VERSION_CLIENT", "12a"), "2.2.5": sqlnet_eq("SQLNET.ALLOWED_LOGON_VERSION_SERVER", "12a"),
    "2.2.6": sqlnet_eq("SQLNET.ENCRYPTION_CLIENT", "REQUIRED"), "2.2.7": sqlnet_eq("SQLNET.ENCRYPTION_SERVER", "REQUIRED"),
    "2.2.8": sqlnet_eq("SQLNET.ENCRYPTION_TYPES_CLIENT", "AES256"), "2.2.9": sqlnet_eq("SQLNET.ENCRYPTION_TYPES_SERVER", "AES256"),
    "2.2.10": sqlnet_eq("SQLNET.CRYPTO_CHECKSUM_CLIENT", "REQUIRED"), "2.2.11": sqlnet_eq("SQLNET.CRYPTO_CHECKSUM_SERVER", "REQUIRED"),
    "2.2.12": sqlnet_eq("SSL_CERT_REVOCATION", "REQUIRED"),
    "2.3.1": param_not("background_core_dump", "FULL", "PARTIAL"), "2.3.2": param_not("shadow_core_dump", "FULL", "PARTIAL"),
    "2.3.3": param_eq("mle_prog_languages", "OFF"), "2.3.4": param_eq("allow_group_access_to_sga", "FALSE"),
    "2.3.6": param_eq("os_roles", "FALSE"), "2.3.7": param_eq("remote_os_roles", "FALSE"),
    "2.3.8": param_le("sec_max_failed_login_attempts", 3, "3"), "2.3.9": param_in("sec_protocol_error_further_action", ["(DROP,3)", "(DROP, 3)"], "(DROP,3)"),
    "2.3.10": param_eq("sec_protocol_error_trace_action", "LOG"), "2.3.11": param_eq("sec_return_server_release_banner", "FALSE"),
    "2.3.12": param_eq("remote_login_passwordfile", "NONE"), "2.3.13": param_empty("remote_listener"), "2.3.14": param_eq("resource_limit", "TRUE"),
    "3.1": profile_le("FAILED_LOGIN_ATTEMPTS", 5, "3"), "3.2": profile_ge("PASSWORD_LOCK_TIME", 1, "1"),
    "3.4": profile_eq("PASSWORD_REUSE_MAX", "UNLIMITED"), "3.5": profile_set("PASSWORD_VERIFY_FUNCTION", "ORA12C_STIG_VERIFY_FUNCTION"),
    "3.6": attest("oracle.attest.password_verify_function_meets_cis"), "3.7": profile_le("PASSWORD_ROLLOVER_TIME", 0, "0"),
    "3.8": profile_le("INACTIVE_ACCOUNT_TIME", 120, "35"),
    "4.1": empty("oracle.users_with_default_password"), "4.2": empty("oracle.custom_oracle_maintained_users"),
    "4.4": empty("oracle.users_with_old_password_versions"), "4.5": (['input.oracle.password_file_format == "12.2"'], [("oracle.password_file_format", "12.2")]),
    "4.6": attest("oracle.attest.rac_password_files_identical"), "4.7": empty("oracle.public_db_links"), "4.8": empty("oracle.db_links_with_legacy_password_encryption"),
    "5.1": empty("oracle.audit.unaudited_system_actions"), "5.2": audit_opts(["LOGON", "LOGOFF"]),
    "5.3": ([f"every p in {json.dumps(CRITICAL_PACKAGES)} {{ p in input.oracle.audit.audited_packages }}"], [("oracle.audit.audited_packages", CRITICAL_PACKAGES)]),
    "5.4": audit_opts(["EXPORT"]),
    "5.5": (['every u in {"SYS", "SYSBACKUP", "SYSDG", "SYSKM", "SYSRAC", "PUBLIC"} { u in input.oracle.audit.all_actions_audited_users }'],
            [("oracle.audit.all_actions_audited_users", ["SYS", "SYSBACKUP", "SYSDG", "SYSKM", "SYSRAC", "PUBLIC"])]),
    "6.1.1": sys_priv_like("ANY"), "6.1.2": (['is_array(input.oracle.grants.sys_privs)', 'count([g | some g in input.oracle.grants.sys_privs; g.admin_option == true; _unauthorized(g)]) == 0'], []),
    "6.1.3": (['no_unauthorized_sys_priv("EXPORT FULL DATABASE")', 'no_unauthorized_sys_priv("IMPORT FULL DATABASE")'], []),
    "6.1.4": sys_priv("CREATE EXTERNAL JOB"), "6.1.5": sys_priv("BECOME USER"), "6.1.6": sys_priv("TEXT DATASTORE ACCESS"),
    "6.1.8": sys_priv("LOGMINING"), "6.1.9": sys_priv("ALTER SYSTEM"), "6.1.10": sys_priv("CREATE LIBRARY"),
    "6.1.11": (['is_array(input.oracle.grants.sys_privs)', 'count([g | some g in input.oracle.grants.sys_privs; _unauthorized(g)]) == 0'], []),
    "6.2.1": role("DBA"), "6.2.2": role("EXP_FULL_DATABASE"), "6.2.3": role("IMP_FULL_DATABASE"), "6.2.4": role("DATAPUMP_EXP_FULL_DATABASE"),
    "6.2.5": role("DATAPUMP_IMP_FULL_DATABASE"), "6.2.6": role("DV_ADMIN"), "6.2.7": role("DV_AUDIT_CLEANUP"), "6.2.8": role("OLAP_DBA"),
    "6.2.9": role("LBAC_DBA"), "6.2.10": role("JAVA_ADMIN"), "6.2.11": role("JAVASYSPRIVS"), "6.2.12": role("LOGSTDBY_ADMINISTRATOR"),
    "6.2.13": role("SQL_FIREWALL_ADMIN"), "6.2.14": role("MAINTPLAN_APP"), "6.2.15": role("JAVADEBUGPRIV"), "6.2.16": role("DV_PATCH_ADMIN"),
    "6.2.17": role("DV_POLICY_OWNER"), "6.2.18": role("AUDIT_ADMIN"), "6.2.19": role("AUDIT_VIEWER"), "6.2.20": role("PDB_DBA"),
    "6.2.21": role("SELECT_CATALOG_ROLE"), "6.2.22": role("EXECUTE_CATALOG_ROLE"),
    "6.3.1": attest("oracle.attest.schema_privileges_reviewed"),
    "6.4.1": (['is_array(input.oracle.grants.tab_privs)', f'count([g | some g in input.oracle.grants.tab_privs; g.owner == "SYS"; g.table_name in {json.dumps(SENSITIVE_TABLES)}; g.privilege == "ALL"]) == 0'], []),
    "6.5.1": attest("oracle.attest.column_privileges_reviewed"), "6.6.1": attest("oracle.attest.proxy_user_privileges_reviewed"),
    "6.7.1": attest("oracle.attest.custom_java_privileges_reviewed"), "6.8.1": attest("oracle.attest.directory_object_access_reviewed"),
}
SECTIONS = {"1": "Oracle Database Installation and Patching Requirements", "2": "Oracle Parameter Settings", "3": "Oracle Connection and Login Restrictions",
            "4": "Oracle User Access and Authorization Restrictions", "5": "Audit/Logging Policies and Procedures", "6": "Oracle Privileges"}


def recommendations(text):
    t = re.sub(r"\n\s+(?=[a-z'(])", " ", text)
    out = {}
    for m in re.finditer(r"(?m)^\s*(\d+(?:\.\d+){1,3})\s+(Ensure .+?)\s*\((Automated|Manual)\)", t):
        out.setdefault(m.group(1), (re.sub(r"\s+", " ", m.group(2)).strip(), m.group(3)))
    return out


def ident(rid):
    return "r_" + rid.replace(".", "_")


def main(txt):
    recs = recommendations(open(txt).read())
    missing = sorted(set(recs) - set(RULES), key=lambda x: [int(p) for p in x.split(".")])
    extra = sorted(set(RULES) - set(recs))
    if missing or extra:
        raise SystemExit(f"logic table out of step with the benchmark text: missing {missing} extra {extra}")
    key = lambda x: [int(p) for p in x.split(".")]
    ids = sorted(RULES, key=key)
    L = ["# METADATA", '# title: "CIS Oracle Database 23ai Benchmark v1.0.0"', "# custom:", "#   class: security", "#   framework: cis_oracle_23ai",
         "#   source: cis", "#   domains: [database, oracle]", "package cis.oracle_23ai", "",
         "# CIS Oracle Database 23ai Benchmark v1.0.0 (CIS lists v1.1.0 as current; a typo/version-text update)",
         f"# {len(ids)} recommendations, every one in the benchmark; ids and titles read from the benchmark text and the",
         "# logic written from each recommendation's own audit SQL (tools/cis_generators/gen_oracle_db_23ai.py).",
         f"# {sum(1 for r in RULES.values() if any('.attest.' in l for l in r[0]))} recommendations are Manual reviews and carry an attestation boolean.",
         "#",
         "# Input contract (shared with benchmarks/stig/oracle_database_19c so one collector feeds both):",
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
        title, status = recs[rid]
        body, entries = RULES[rid]
        L += [f"# {rid} ({status})", f"default {ident(rid)} := false", f"{ident(rid)} if {{"] + ["\t" + b for b in body] + ["}", "",
              f'violations contains "{rid}: {title.replace(chr(34), chr(39))}" if {{', f"\tnot {ident(rid)}", "}", ""]
        for path, val in entries:
            d = fx
            parts = path if isinstance(path, list) else path.split(".")
            for p in parts[:-1]:
                d = d.setdefault(p, {})
            if isinstance(val, list) and isinstance(d.get(parts[-1]), list):
                d[parts[-1]] = sorted(set(d[parts[-1]]) | set(val))
            else:
                d[parts[-1]] = val
    L += ['violations contains "CIS Oracle 23ai: FAIL-CLOSED - facts \'input.oracle\' were not supplied; the database was not evaluated" if {',
          "\tnot input.oracle", "}", "",
          "sections := " + json.dumps(SECTIONS, indent=1).replace("\n", "\n").replace('"', '"'), "",
          "compliance_report := {", '\t"benchmark": "CIS Oracle Database 23ai Benchmark v1.0.0",', f'\t"total_controls": {len(ids)},',
          f'\t"standard_total": {len(ids)},', '\t"standard_total_source": "CIS Oracle Database 23ai Benchmark v1.0.0, recommendations counted from the benchmark text",',
          '\t"sections": sections,', '\t"compliant": compliant,', '\t"violation_count": count(violations),', '\t"violations": violations,', "}", ""]
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "cis_oracle_23ai.rego").write_text("\n".join(L))
    # green fixture completes the lists the privilege helpers read
    fx.setdefault("oracle", {}).setdefault("grants", {}).update({"sys_privs": [], "role_privs": [], "tab_privs": []})
    fx["oracle"]["authorized_grantees"] = ["DBA_TEAM"]
    fx["oracle"]["listener_ora"] = {}
    fx["oracle"]["sqlnet"].setdefault("ACCEPT_MD5_CERTS", "FALSE")
    fxs = json.dumps(fx, indent=1).replace("\n", "\n\t")
    T = ["package cis.oracle_23ai_test", "", "import rego.v1", "", "import data.cis.oracle_23ai as b", "",
         f"green := {fxs}", "",
         "test_green_database_is_compliant if {", "\tr := b.compliance_report with input as green", "\tr.compliant == true", "\tcount(r.violations) == 0", "}", "",
         "test_fail_closed_on_empty_input if {", "\tr := b.compliance_report with input as {}", "\tr.compliant == false", "\tcount(r.violations) > 0", "}", "",
         "test_remote_os_roles_true_is_2_3_7 if {",
         '\tbad := json.patch(green, [{"op": "replace", "path": "/oracle/parameters/remote_os_roles", "value": "TRUE"}])',
         f'\t"2.3.7: {recs["2.3.7"][0]}" in b.violations with input as bad', "}", "",
         "test_unauthorized_dba_grant_is_6_2_1 if {",
         '\tbad := json.patch(green, [{"op": "replace", "path": "/oracle/grants/role_privs", "value": [{"grantee": "APP_USER", "granted_role": "DBA", "oracle_maintained": false}]}])',
         f'\t"6.2.1: {recs["6.2.1"][0]}" in b.violations with input as bad', "}", "",
         "test_authorized_dba_grant_is_not_a_finding if {",
         '\tok := json.patch(green, [{"op": "replace", "path": "/oracle/grants/role_privs", "value": [{"grantee": "DBA_TEAM", "granted_role": "DBA", "oracle_maintained": false}]}])',
         "\tb.compliant with input as ok", "}", "",
         "test_every_recommendation_fires_without_facts if {",
         '\tv := b.violations with input as {"oracle": {}}',
         "\tids := {id | some m in v; id := split(m, \":\")[0]}", f"\tcount(ids) >= {len(ids)}", "}", ""]
    (OUT / "tests" / "test_cis_oracle_23ai.rego").parent.mkdir(exist_ok=True)
    (OUT / "tests" / "test_cis_oracle_23ai.rego").write_text("\n".join(T))
    print(f"cis_oracle_23ai: {len(ids)} recommendations ({sum(1 for r in recs.values() if r[1] == 'Automated')} Automated, "
          f"{sum(1 for r in recs.values() if r[1] == 'Manual')} Manual) -> {OUT / 'cis_oracle_23ai.rego'}")


if __name__ == "__main__":
    main(sys.argv[1])
