#!/usr/bin/env python3
"""Oracle Database 19c and Oracle MySQL 8.0 STIG modules — every rule in the catalog.

    python3 tools/stig_generators/gen_oracle_db.py            # both platforms

Same emission shape as gen_apps.py (core.rego + aggregator + fail-closed main alias + green-fixture
tests). Where DISA's check is a query, the rule reads the queried value from the input contract;
where DISA's check is a documentation/procedure review, the rule is an explicit attestation boolean
named for what a human verified — never silently passed. Catalog ID hard-gate: a rule id missing
from the current XCCDF aborts generation.
"""
import json, os, re, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gen_k8s import ALIAS_TMPL
from gen_apps import rego_ident, esc, build_fixture

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.join(HERE, "..", "..", "benchmarks", "stig")
CATS = os.path.join(HERE, "catalogs")
SEV = {"high": "CAT I", "medium": "CAT II", "low": "CAT III"}


# ── fact constructors: (rego body lines, fixture entries) ──────────────────────────────────────
def attest(path):                       # organizational review → named attestation boolean
    return ([f"input.{path} == true"], [("BOOL", path, True)])

def boolfact(path, val=True):
    return ([f"input.{path} == {str(val).lower()}"], [("BOOL", path, val)])

def empty_list(path, sample=None):      # a query that must return no rows; the collector supplies the rows
    return ([f"count(input.{path}) == 0"], [("BOOL", path, [])])

def num_ge(path, n, fx):
    return ([f"to_number(input.{path}) >= {n}"], [("BOOL", path, fx)])

def num_gt(path, n, fx):
    return ([f"to_number(input.{path}) > {n}"], [("BOOL", path, fx)])

def ora_param(name, val, fx=None):      # V$PARAMETER value, compared case-insensitively
    return ([f'lower(input.oracle.parameters["{name}"]) == "{val.lower()}"'], [("MAP2", "oracle.parameters", name, fx or val)])

def ora_param_in(name, vals, fx):
    s = ", ".join(f'"{v}"' for v in vals)
    return ([f'lower(input.oracle.parameters["{name}"]) in {{{s}}}'], [("MAP2", "oracle.parameters", name, fx)])

def ora_param_absent_or(name, val):     # parameter may be unset; if set it must equal val
    return ([f'lower(object.get(input.oracle.parameters, "{name}", "{val.lower()}")) == "{val.lower()}"'], [])

def profile_le(resource, n, fx):
    return ([f'profiles_every_le("{resource}", {n})'], [("BOOL", f"oracle.profiles.ORA_STIG_PROFILE.{resource}", fx)])

def profile_eq(resource, val):
    return ([f'profiles_every_eq("{resource}", "{val}")'], [("BOOL", f"oracle.profiles.ORA_STIG_PROFILE.{resource}", val)])

def profile_set(resource, fx):
    return ([f'profiles_every_set("{resource}")'], [("BOOL", f"oracle.profiles.ORA_STIG_PROFILE.{resource}", fx)])

def profile_bounded(resource, fx):      # numeric, not UNLIMITED
    return ([f'profiles_every_numeric("{resource}")'], [("BOOL", f"oracle.profiles.ORA_STIG_PROFILE.{resource}", fx)])

def my_var(name, val, fx=None):
    return ([f'upper(input.mysql.variables["{name}"]) == "{val.upper()}"'], [("MAP2", "mysql.variables", name, fx or val)])

def my_var_in(name, vals, fx):
    s = ", ".join(f'"{v}"' for v in vals)
    return ([f'upper(input.mysql.variables["{name}"]) in {{{s}}}'], [("MAP2", "mysql.variables", name, fx)])

def my_var_num_ge(name, n, fx):
    return ([f'to_number(input.mysql.variables["{name}"]) >= {n}'], [("MAP2", "mysql.variables", name, fx)])

def my_var_num_gt(name, n, fx):
    return ([f'to_number(input.mysql.variables["{name}"]) > {n}'], [("MAP2", "mysql.variables", name, fx)])

def my_plugin_active(name):
    return ([f'upper(input.mysql.plugins["{name}"]) == "ACTIVE"'], [("BOOL", f"mysql.plugins.{name}", "ACTIVE")])

def both(*parts):                       # AND of several constructors
    return ([l for p in parts for l in p[0]], [e for p in parts for e in p[1]])

def either(name, *parts):               # OR: emitted as extra rule clauses; fixture from the first alternative
    return ("OR", name, parts)


# Helpers emitted once per platform (shared by rules)
ORA_HELPERS = """
# ── profile helpers: every profile the collector reports must satisfy the limit (DEFAULT must be
# resolved by the collector to the DEFAULT profile's value; UNLIMITED fails numeric comparisons) ──
profiles_every_le(resource, max) if {
	count(input.oracle.profiles) > 0
	every _, p in input.oracle.profiles {
		to_number(p[resource]) <= max
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

profiles_every_numeric(resource) if {
	count(input.oracle.profiles) > 0
	every _, p in input.oracle.profiles {
		to_number(p[resource]) >= 0
	}
}

# effective password lifetime = PASSWORD_LIFE_TIME + PASSWORD_GRACE_TIME (the STIG's own script)
profiles_every_effective_life_le(max) if {
	count(input.oracle.profiles) > 0
	every _, p in input.oracle.profiles {
		to_number(p.PASSWORD_LIFE_TIME) + to_number(p.PASSWORD_GRACE_TIME) <= max
	}
}

# standard auditing on, or at least one unified audit policy enabled
audit_enabled if {
	lower(input.oracle.parameters.audit_trail) != "none"
}

audit_enabled if {
	count(input.oracle.unified_audit_policies_enabled) > 0
}
"""

MY_HELPERS = """
# ── audit helpers: the audit_log plugin must be active and at least one audit filter defined ──
audit_log_active if {
	upper(input.mysql.plugins.audit_log) == "ACTIVE"
}

audit_configured if {
	audit_log_active
	count(input.mysql.audit.filters) > 0
}

fips_mode if {
	upper(input.mysql.variables.ssl_fips_mode) in {"ON", "STRICT"}
}

# an organization-level authentication plugin (LDAP, Kerberos, PAM) is active
external_auth_plugin_active if {
	some name, status in input.mysql.plugins
	regex.match("(?i)^authentication_(ldap|kerberos|pam|openid)", name)
	upper(status) == "ACTIVE"
}
"""

ORA_AUDIT = (["audit_enabled"], [("BOOL", "oracle.parameters.audit_trail", "DB"), ("BOOL", "oracle.unified_audit_policies_enabled", ["ORA_SECURECONFIG"])])
ORA_TLS = boolfact("oracle.network.tls_or_native_encryption_required")
ORA_FIPS = ora_param("dbfips_140", "TRUE")
MY_AUDIT = (["audit_configured"], [("BOOL", "mysql.plugins.audit_log", "ACTIVE"), ("BOOL", "mysql.audit.filters", ["log_all"])])
MY_FIPS = (["fips_mode"], [("BOOL", "mysql.variables.ssl_fips_mode", "ON")])
MY_TLS = my_var("require_secure_transport", "ON")
MY_AUDIT_ADMINS = empty_list("mysql.unauthorized_audit_admins")
MY_AT_REST = either("at_rest", boolfact("mysql.encryption.all_tablespaces_encrypted"), attest("mysql.attest.data_at_rest_encryption_not_required"))

PLATFORMS = {
    "oracle_database_19c": {
        "pkg": "oracle_database_19c", "platform": "Oracle Database 19c", "domains": "[database, oracle]",
        "contract": [
            "input.oracle.parameters[<name>]            : V$PARAMETER / GV$PARAMETER value (name lowercase)",
            "input.oracle.profiles[<profile>][<RESOURCE>]: DBA_PROFILES limits, DEFAULT resolved by the collector",
            "input.oracle.<query result>                : rows the STIG query must not return (lists), counts, flags",
            "input.oracle.attest.*                      : attestation booleans (documented reviews)",
        ],
        "helpers": ORA_HELPERS,
        "rules": {
            "O19C-00-000100": profile_bounded("SESSIONS_PER_USER", "10"),
            "O19C-00-000200": boolfact("oracle.listener.rate_limit_configured"),
            "O19C-00-000300": num_gt("oracle.parameters.max_idle_time", 0, "15"),
            "O19C-00-000500": attest("oracle.attest.security_labeling_implemented_or_not_required"),
            "O19C-00-000800": attest("oracle.attest.org_level_auth_integrated"),
            "O19C-00-001000": attest("oracle.attest.authorizations_enforced"),
            "O19C-00-001700": attest("oracle.attest.shared_account_users_individually_identified"),
            "O19C-00-001800": ORA_AUDIT,
            "O19C-00-001900": attest("oracle.attest.audit_event_selection_by_designated_personnel"),
            "O19C-00-002000": both(ORA_AUDIT, attest("oracle.attest.dod_auditable_events_configured")),
            "O19C-00-005600": attest("oracle.attest.additional_audit_information_configured"),
            "O19C-00-005700": attest("oracle.attest.audit_storage_capacity_allocated"),
            "O19C-00-005800": attest("oracle.attest.audit_offloaded_continuously"),
            "O19C-00-005900": attest("oracle.attest.audit_storage_warning_at_75_percent"),
            "O19C-00-006000": attest("oracle.attest.audit_failure_realtime_alert"),
            "O19C-00-006600": attest("oracle.attest.audit_data_access_restricted"),
            "O19C-00-006900": attest("oracle.attest.audit_tools_access_restricted"),
            "O19C-00-007300": boolfact("oracle.filesystem.oracle_home_world_accessible", False),
            "O19C-00-007400": attest("oracle.attest.vendor_supported_version"),
            "O19C-00-007700": attest("oracle.attest.software_change_monitoring_in_place"),
            "O19C-00-007900": attest("oracle.attest.software_library_access_restricted"),
            "O19C-00-008000": attest("oracle.attest.install_account_restricted"),
            "O19C-00-008100": attest("oracle.attest.software_directories_dedicated"),
            "O19C-00-008200": empty_list("oracle.unauthorized_object_owners"),
            "O19C-00-008300": empty_list("oracle.direct_admin_privilege_grantees"),
            "O19C-00-008400": attest("oracle.attest.configured_per_dod_guidance"),
            "O19C-00-008600": (["not contains(input.oracle.instance_name, split(input.oracle.version, \".\")[0])"],
                               [("BOOL", "oracle.instance_name", "PRODDB"), ("BOOL", "oracle.version", "19.0.0.0.0")]),
            "O19C-00-008700": empty_list("oracle.unauthorized_db_links"),
            "O19C-00-009000": empty_list("oracle.grantable_privileges_non_dba"),
            "O19C-00-009200": ora_param("remote_os_roles", "FALSE"),
            "O19C-00-009300": ora_param("sql92_security", "TRUE"),
            "O19C-00-009400": ora_param_in("remote_login_passwordfile", ["exclusive", "none"], "EXCLUSIVE"),
            "O19C-00-009500": empty_list("oracle.unauthorized_admin_option_system_privileges"),
            "O19C-00-009600": empty_list("oracle.public_system_privileges"),
            "O19C-00-009700": empty_list("oracle.unauthorized_admin_option_roles"),
            "O19C-00-009800": empty_list("oracle.unauthorized_public_object_privileges"),
            "O19C-00-009900": boolfact("oracle.listener.admin_authentication_required"),
            "O19C-00-010000": empty_list("oracle.public_granted_roles"),
            "O19C-00-010100": empty_list("oracle.unauthorized_default_admin_roles"),
            "O19C-00-010400": boolfact("oracle.filesystem.archive_log_dirs_world_accessible", False),
            "O19C-00-010500": ora_param_absent_or("_trace_files_public", "FALSE"),
            "O19C-00-010600": attest("oracle.attest.developers_excluded_from_dba_group"),
            "O19C-00-010700": attest("oracle.attest.install_account_use_logged"),
            "O19C-00-010800": attest("oracle.attest.data_log_audit_files_in_dedicated_directories"),
            "O19C-00-011200": boolfact("oracle.network.access_restriction_enforced"),
            "O19C-00-011300": either("sys_audit", ora_param("audit_sys_operations", "TRUE"),
                                     (["count(input.oracle.unified_audit_sys_policies) > 0"], [])),
            "O19C-00-011500": boolfact("oracle.filesystem.diag_dir_world_accessible", False),
            "O19C-00-011600": either("cman", boolfact("oracle.cman.present", False),
                                     (['lower(input.oracle.cman.remote_admin) == "no"'], [])),
            "O19C-00-011700": (['startswith(input.oracle.sqlnet.allowed_logon_version_server, "12")'],
                               [("BOOL", "oracle.sqlnet.allowed_logon_version_server", "12")]),
            "O19C-00-011800": both(boolfact("oracle.os.root_in_dba_group", False), attest("oracle.attest.dba_os_accounts_least_privilege")),
            "O19C-00-011900": empty_list("oracle.users_with_default_password"),
            "O19C-00-012000": attest("oracle.attest.temporary_accounts_identified"),
            "O19C-00-012100": attest("oracle.attest.temporary_accounts_expire_within_72h"),
            "O19C-00-012200": attest("oracle.attest.developers_no_elevated_privileges_on_shared_hosts"),
            "O19C-00-012300": profile_eq("PASSWORD_LOCK_TIME", "UNLIMITED"),
            "O19C-00-012400": profile_le("FAILED_LOGIN_ATTEMPTS", 3, "3"),
            "O19C-00-012500": profile_le("INACTIVE_ACCOUNT_TIME", 35, "35"),
            "O19C-00-012900": empty_list("oracle.sample_schemas_present"),
            "O19C-00-013000": empty_list("oracle.unused_components_installed"),
            "O19C-00-013100": empty_list("oracle.unused_integrated_options_enabled"),
            "O19C-00-013200": attest("oracle.attest.extproc_os_accounts_least_privilege"),
            "O19C-00-013300": attest("oracle.attest.external_executables_authorized"),
            "O19C-00-013400": either("extproc", boolfact("oracle.listener.extproc_configured", False),
                                     attest("oracle.attest.extproc_use_authorized")),
            "O19C-00-013500": attest("oracle.attest.ppsm_functions_ports_protocols_approved"),
            "O19C-00-013700": attest("oracle.attest.shared_accounts_require_individual_authentication"),
            "O19C-00-013800": attest("oracle.attest.organizational_users_uniquely_identified"),
            "O19C-00-013900": profile_set("PASSWORD_VERIFY_FUNCTION", "ORA12C_STIG_VERIFY_FUNCTION"),
            "O19C-00-014600": attest("oracle.attest.temporary_password_procedures_documented"),
            "O19C-00-014700": (["profiles_every_effective_life_le(180)"],
                               [("BOOL", "oracle.profiles.ORA_STIG_PROFILE.PASSWORD_LIFE_TIME", "60"),
                                ("BOOL", "oracle.profiles.ORA_STIG_PROFILE.PASSWORD_GRACE_TIME", "5")]),
            "O19C-00-014800": empty_list("oracle.users_with_10g_password_verifier"),
            "O19C-00-014900": ORA_TLS,
            "O19C-00-015200": attest("oracle.attest.pki_private_key_access_restricted"),
            "O19C-00-015300": attest("oracle.attest.pki_identity_mapped_to_accounts"),
            "O19C-00-015400": attest("oracle.attest.cli_plaintext_password_tools_mitigated_and_approved"),
            "O19C-00-015500": ORA_FIPS,
            "O19C-00-015600": attest("oracle.attest.nonorganizational_users_uniquely_identified"),
            "O19C-00-016000": either("fips_or_na", ORA_FIPS, attest("oracle.attest.encryption_not_required")),
            "O19C-00-016100": attest("oracle.attest.admin_functionality_separated_from_users"),
            "O19C-00-016700": (['upper(input.oracle.log_mode) == "ARCHIVELOG"'], [("BOOL", "oracle.log_mode", "ARCHIVELOG")]),
            "O19C-00-016800": either("tde", boolfact("oracle.tde.enabled"), attest("oracle.attest.data_at_rest_encryption_not_required")),
            "O19C-00-016900": either("tde_integrity", boolfact("oracle.tde.enabled"), attest("oracle.attest.information_at_rest_integrity_protection_not_required")),
            "O19C-00-017100": attest("oracle.attest.security_functions_isolated"),
            "O19C-00-017400": attest("oracle.attest.production_data_transfer_controlled"),
            "O19C-00-017600": boolfact("oracle.filesystem.database_files_world_accessible", False),
            "O19C-00-017700": ORA_TLS,
            "O19C-00-017900": attest("oracle.attest.input_validation_implemented"),
            "O19C-00-018000": attest("oracle.attest.dynamic_code_execution_justified"),
            "O19C-00-018100": attest("oracle.attest.dynamic_code_injection_protected"),
            "O19C-00-018300": attest("oracle.attest.error_messages_minimal"),
            "O19C-00-018400": attest("oracle.attest.error_messages_restricted_to_authorized_personnel"),
            "O19C-00-018600": boolfact("oracle.patches.latest_cpu_applied"),
            "O19C-00-019800": attest("oracle.attest.compromised_password_list_checked"),
            "O19C-00-019900": attest("oracle.attest.password_change_required_on_account_recovery"),
            "O19C-00-020400": attest("oracle.attest.trust_store_contains_only_approved_anchors"),
            "O19C-00-020500": (["count(input.oracle.control_files) >= 3"], [("BOOL", "oracle.control_files", ["/u01/oradata/control01.ctl", "/u02/oradata/control02.ctl", "/u03/oradata/control03.ctl"])]),
            "O19C-00-020600": (["count(input.oracle.redo_log_groups) >= 3", "every g in input.oracle.redo_log_groups { count(g.members) >= 2 }"],
                               [("BOOL", "oracle.redo_log_groups", [{"group": 1, "members": ["/u01/redo01a.log", "/u02/redo01b.log"]}, {"group": 2, "members": ["/u01/redo02a.log", "/u02/redo02b.log"]}, {"group": 3, "members": ["/u01/redo03a.log", "/u02/redo03b.log"]}])]),
        },
    },
    "oracle_mysql_8": {
        "pkg": "oracle_mysql_8", "platform": "Oracle MySQL 8.0", "domains": "[database, mysql]",
        "contract": [
            "input.mysql.variables[<name>]  : performance_schema.global_variables / SHOW VARIABLES (name lowercase)",
            "input.mysql.plugins[<name>]    : INFORMATION_SCHEMA.PLUGINS status",
            "input.mysql.audit.*            : audit_log filters and startup mode",
            "input.mysql.users[]            : mysql.user rows {user, host, plugin}",
            "input.mysql.<query result>     : rows the STIG query must not return (lists), flags",
            "input.mysql.attest.*           : attestation booleans (documented reviews)",
        ],
        "helpers": MY_HELPERS,
        "rules": {
            "MYS8-00-000100": either("org_auth", (["external_auth_plugin_active"], [("BOOL", "mysql.plugins.authentication_ldap_simple", "ACTIVE")]),
                                     attest("mysql.attest.org_level_auth_integrated")),
            "MYS8-00-000200": my_var_num_gt("max_user_connections", 0, "50"),
            "MYS8-00-000300": MY_AUDIT, "MYS8-00-000800": MY_AUDIT,
            "MYS8-00-001200": boolfact("mysql.filesystem.audit_log_permissions_restricted"),
            "MYS8-00-001300": boolfact("mysql.filesystem.audit_log_permissions_restricted"),
            "MYS8-00-001400": boolfact("mysql.filesystem.audit_log_permissions_restricted"),
            "MYS8-00-001500": attest("mysql.attest.no_shared_accounts_or_individually_identified"),
            "MYS8-00-001600": MY_AUDIT,
            "MYS8-00-001700": MY_AUDIT_ADMINS,
            **{f"MYS8-00-00{n}": MY_AUDIT for n in ("1800", "1900", "2000", "2100", "2200", "2300", "2400", "2500", "2600", "2700", "2800", "2900",
                                                     "3000", "3100", "3200", "3300", "3400", "3500", "3600", "3700", "3800", "3900",
                                                     "4000", "4100", "4200", "4300", "4400", "4500", "4600")},
            "MYS8-00-004700": attest("mysql.attest.pki_certificate_path_and_revocation_validated"),
            "MYS8-00-004800": boolfact("mysql.filesystem.ssl_key_permissions_restricted"),
            "MYS8-00-004900": attest("mysql.attest.pki_identity_mapped_to_accounts"),
            "MYS8-00-005000": both(my_plugin_active("validate_password"), my_var_num_ge("validate_password.length", 15, "15"),
                                   my_var_in("validate_password.policy", ["MEDIUM", "STRONG"], "STRONG")),
            "MYS8-00-005100": (['every u in input.mysql.users { u.plugin in {"caching_sha2_password", "sha256_password"} }'],
                               [("BOOL", "mysql.users", [{"user": "app", "host": "%", "plugin": "caching_sha2_password"}])]),
            "MYS8-00-005200": MY_TLS,
            "MYS8-00-005300": attest("mysql.attest.authentication_feedback_obscured"),
            "MYS8-00-005400": attest("mysql.attest.authorizations_enforced"),
            "MYS8-00-005500": attest("mysql.attest.configured_per_dod_guidance"),
            "MYS8-00-005600": empty_list("mysql.sample_schemas_present"),
            "MYS8-00-005700": empty_list("mysql.unused_plugins_installed"),
            "MYS8-00-005800": empty_list("mysql.unused_integrated_components_enabled"),
            "MYS8-00-006000": attest("mysql.attest.ppsm_functions_ports_protocols_approved"),
            "MYS8-00-006100": attest("mysql.attest.organizational_users_uniquely_identified"),
            "MYS8-00-006200": MY_FIPS,
            "MYS8-00-006300": attest("mysql.attest.nonorganizational_users_uniquely_identified"),
            "MYS8-00-006400": attest("mysql.attest.admin_functionality_separated_from_users"),
            "MYS8-00-006500": attest("mysql.attest.security_functions_isolated"),
            "MYS8-00-006600": attest("mysql.attest.production_data_transfer_controlled"),
            "MYS8-00-006800": boolfact("mysql.filesystem.datadir_permissions_restricted"),
            "MYS8-00-007000": both(MY_TLS, MY_FIPS),
            "MYS8-00-007200": MY_AT_REST,
            "MYS8-00-007300": attest("mysql.attest.input_validation_implemented"),
            "MYS8-00-007400": attest("mysql.attest.dynamic_code_execution_justified"),
            "MYS8-00-007500": attest("mysql.attest.dynamic_code_injection_protected"),
            "MYS8-00-007800": both((["audit_log_active"], [("BOOL", "mysql.plugins.audit_log", "ACTIVE")]), boolfact("mysql.audit.force_plus_permanent")),
            "MYS8-00-008000": MY_AUDIT_ADMINS, "MYS8-00-008100": MY_AUDIT_ADMINS, "MYS8-00-008200": MY_AUDIT_ADMINS,
            "MYS8-00-008300": attest("mysql.attest.software_module_change_privileges_restricted"),
            "MYS8-00-008400": attest("mysql.attest.install_account_restricted"),
            "MYS8-00-008500": attest("mysql.attest.software_directories_dedicated"),
            "MYS8-00-008700": empty_list("mysql.unauthorized_ddl_grantees"),
            "MYS8-00-009000": attest("mysql.attest.network_ports_protocols_approved"),
            "MYS8-00-009100": empty_list("mysql.unauthorized_create_routine_grantees"),
            "MYS8-00-009200": attest("mysql.attest.configuration_change_access_restricted"),
            "MYS8-00-009300": MY_AUDIT,
            "MYS8-00-009600": both(my_var_num_gt("audit_log_rotate_on_size", 0, "1073741824"), attest("mysql.attest.audit_storage_capacity_allocated")),
            "MYS8-00-009700": attest("mysql.attest.audit_offloaded_continuously"),
            "MYS8-00-009800": attest("mysql.attest.audit_storage_warning_at_75_percent"),
            "MYS8-00-009900": attest("mysql.attest.audit_failure_realtime_alert"),
            "MYS8-00-010300": attest("mysql.attest.cached_authenticator_lifetime_limited"),
            "MYS8-00-010400": attest("mysql.attest.reauthentication_circumstances_enforced"),
            "MYS8-00-010500": attest("mysql.attest.discretionary_access_control_enforced"),
            "MYS8-00-010600": empty_list("mysql.unauthorized_definer_routines"),
            "MYS8-00-010700": empty_list("mysql.unauthorized_definer_routines"),
            "MYS8-00-010800": attest("mysql.attest.security_labeling_implemented_or_not_required"),
            "MYS8-00-010900": attest("mysql.attest.security_labeling_implemented_or_not_required"),
            "MYS8-00-011000": attest("mysql.attest.security_labeling_implemented_or_not_required"),
            "MYS8-00-011100": attest("mysql.attest.session_termination_conditions_enforced"),
            "MYS8-00-011300": MY_TLS,
            "MYS8-00-011500": attest("mysql.attest.nsa_approved_cryptography_for_classified_or_not_required"),
            "MYS8-00-011600": MY_FIPS, "MYS8-00-011700": MY_FIPS, "MYS8-00-011800": MY_FIPS,
            "MYS8-00-011900": attest("mysql.attest.server_certificate_issued_by_dod_pki"),
            "MYS8-00-012000": MY_AT_REST, "MYS8-00-012100": MY_AT_REST,
            "MYS8-00-012300": attest("mysql.attest.security_updates_applied_within_policy"),
            "MYS8-00-012500": attest("mysql.attest.invalid_input_handling_documented"),
            "MYS8-00-012600": attest("mysql.attest.vendor_supported_version"),
        },
    },
}


def emit(key, cfg):
    cat = json.load(open(os.path.join(CATS, f"{key}.json")))
    by = {r["stig_id"]: r for r in cat["rules"]}
    missing = [sid for sid in cfg["rules"] if sid not in by]
    if missing:
        raise SystemExit(f"{key}: rule IDs not in current XCCDF: {missing}")
    uncovered = [sid for sid in by if sid not in cfg["rules"]]
    if uncovered:
        raise SystemExit(f"{key}: catalog rules without logic: {uncovered}")
    bench, ver = cat["benchmark"], cat["version"]
    release = f"Release: {cat['release']} Benchmark Date: {cat['release_date']}"
    outdir = os.path.join(REPO, key)
    os.makedirs(os.path.join(outdir, "tests"), exist_ok=True)
    attests = sum(1 for sid, r in cfg["rules"].items() if r[0] != "OR" and all(".attest." in l for l in r[0]))
    meta = ["# METADATA", f'# title: "DISA STIG — {esc(bench)}"', "# custom:", "#   class: security",
            f"#   framework: stig_{key}", "#   source: disa", f"#   domains: {cfg['domains']}"]
    lines = meta + [f"package stig.{cfg['pkg']}.core", "",
             f"# DISA STIG — {bench}", f"# {ver} | {release}",
             f"# {len(cfg['rules'])} rules — every rule in the catalog; {attests} are attestation-only (DISA's check is a",
             "# documentation or procedure review). IDs/severities/titles verified against the October 2026",
             "# SRG-STIG library XCCDF on 2026-10-13 (tools/stig_generators/gen_oracle_db.py).",
             "# Organizational rules are explicit attestation booleans — named for what",
             "# a human verified, never silently passed. Input contract:"]
    lines += [f"#   {c}" for c in cfg["contract"]]
    lines += ["", "import rego.v1", cfg["helpers"].rstrip(), ""]
    finds, fixture_entries = [], []
    for sid in sorted(cfg["rules"]):
        spec = cfg["rules"][sid]
        r = by[sid]
        ident = rego_ident(sid)
        sev = SEV[r["severity"]]
        lines.append(f"# {sid} | {r['vuln_id']} | {sev}")
        lines.append(f"default {ident} := false")
        if spec[0] == "OR":
            for body, fx in spec[2]:
                lines.append(ident + " if {")
                lines += ["\t" + b for b in body]
                lines.append("}")
                lines.append("")
            fixture_entries += spec[2][0][1]
        else:
            body, fx = spec
            lines.append(ident + " if {")
            lines += ["\t" + b for b in body]
            lines.append("}")
            lines.append("")
            fixture_entries += fx
        title = esc(" ".join(r["title"].split())[:220])
        lines += [f"finding_{ident} := {{",
                  f'\t"vuln_id": "{r["vuln_id"]}",', f'\t"stig_id": "{sid}",', f'\t"severity": "{sev}",',
                  f'\t"rule_title": "{title}",', f'\t"status": status_{ident},', "}",
                  f'status_{ident} := "Not_a_Finding" if {ident}', f'status_{ident} := "Open" if not {ident}', ""]
        finds.append(f"finding_{ident}")
    lines.append("findings := [")
    lines += [f"\t{f}," for f in finds]
    lines += ["]", "", "default compliant := false", "", 'compliant if count([f | some f in findings; f.status == "Open"]) == 0']
    open(os.path.join(outdir, "core.rego"), "w").write("\n".join(lines) + "\n")

    cat1 = sum(1 for sid in cfg["rules"] if by[sid]["severity"] == "high")
    o = meta[:1] + [f'# title: "DISA STIG — {esc(bench)} — Master Aggregator"'] + meta[2:] + [
         f"package stig.{cfg['pkg']}", "",
         f"# DISA STIG — {bench} — Master Aggregator", f"# {ver} | {release}",
         f"# Coverage: {len(cfg['rules'])} of {len(cat['rules'])} rules ({cat1} CAT I), {attests} attestation-only.",
         "# Rule IDs verified against the October 2026 SRG-STIG library on 2026-10-13.",
         "", "import rego.v1", "", f"import data.stig.{cfg['pkg']}.core", "",
         "all_findings := core.findings", "",
         'open_findings := [f | some f in all_findings; f.status == "Open"]',
         'cat_i_open := [f | some f in open_findings; f.severity == "CAT I"]', "",
         "default overall_compliant := false", "overall_compliant if count(cat_i_open) == 0",
         "default fully_compliant := false", "fully_compliant if count(open_findings) == 0", "",
         "stig_assessment := {", '\t"metadata": {',
         f'\t\t"stig_title": "{esc(bench)}",', f'\t\t"version": "{ver}",', f'\t\t"release": "{esc(release)}",',
         f'\t\t"platform": "{esc(cfg["platform"])}",',
         '\t\t"assessed_host": object.get(input, ["system_info", "hostname"], "unknown"),', "\t},",
         '\t"summary": {', '\t\t"total_findings": count(all_findings),', '\t\t"open": count(open_findings),',
         '\t\t"not_a_finding": count(all_findings) - count(open_findings),', '\t\t"cat_i_open": count(cat_i_open),',
         '\t\t"overall_compliant": overall_compliant,', '\t\t"fully_compliant": fully_compliant,', "\t},",
         '\t"findings": all_findings,', "}", "",
         "# Uniform library entrypoint contract.", "compliance_report := {",
         '\t"total_controls": count(all_findings),', '\t"open_findings": open_findings,',
         '\t"passed_controls": count(all_findings) - count(open_findings),', '\t"failed_controls": count(open_findings),',
         '\t"compliant": fully_compliant,', "}"]
    open(os.path.join(outdir, f"stig_{key}_complete.rego"), "w").write("\n".join(o) + "\n")

    fx = build_fixture(fixture_entries)
    fxs = json.dumps(fx, indent=1).replace("\n", "\n\t")
    t = [f"package stig.{cfg['pkg']}_test", "", "import rego.v1", f"import data.stig.{cfg['pkg']}", "",
         "test_report_wellformed_on_empty_input if {", f"\treport := {cfg['pkg']}.stig_assessment with input as {{}}",
         "\tis_object(report)", "\treport.summary.total_findings > 0", "}", "",
         f"green_fixture := {fxs}", "",
         "test_fully_compliant_on_green_fixture if {", f"\treport := {cfg['pkg']}.stig_assessment with input as green_fixture",
         "\treport.summary.fully_compliant == true", "}", "",
         "test_main_alias_fail_closed_on_empty if {", f"\trep := data.stig.{cfg['pkg']}.main.compliance_report with input as {{}}",
         "\trep.compliant == false", "\trep.facts_supplied == false", "}", "",
         "test_single_bad_fact_opens_a_finding if {",
         f"\treport := {cfg['pkg']}.stig_assessment with input as object.union(green_fixture, {json.dumps(cfg['probe'][0])})",
         f'\tsome f in report.findings', f'\tf.stig_id == "{cfg["probe"][1]}"', '\tf.status == "Open"', "}"]
    open(os.path.join(outdir, "tests", f"test_stig_{key}.rego"), "w").write("\n".join(t) + "\n")
    alias = ALIAS_TMPL.format(pkg=cfg["pkg"])
    meta_alias = "\n".join(meta[:1] + [f'# title: "Framework-key entrypoint alias with the fail-closed gate — {esc(bench)}"'] + meta[2:])
    alias = alias.replace("package stig.", meta_alias + "\npackage stig.", 1)   # METADATA must sit directly above package
    open(os.path.join(outdir, f"stig_{key}_main.rego"), "w").write(alias)
    print(f"{key}: {len(cfg['rules'])} of {len(cat['rules'])} rules ({cat1} CAT I), {attests} attestation-only; {ver} {cat['release_date']}")


PLATFORMS["oracle_database_19c"]["probe"] = ({"oracle": {"parameters": {"remote_os_roles": "TRUE"}}}, "O19C-00-009200")
PLATFORMS["oracle_mysql_8"]["probe"] = ({"mysql": {"variables": {"require_secure_transport": "OFF"}}}, "MYS8-00-005200")

if __name__ == "__main__":
    for key, cfg in PLATFORMS.items():
        emit(key, cfg)
