# METADATA
# title: "DISA STIG — Oracle Database 19c Security Technical Implementation Guide"
# custom:
#   class: security
#   framework: stig_oracle_database_19c
#   source: disa
#   domains: [database, oracle]
#   coverage:
#     checks: 96
#     cited: 96
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: none
#     guard: n/a
#     as_of: v2.4.0
package stig.oracle_database_19c.core

# DISA STIG — Oracle Database 19c Security Technical Implementation Guide
# V1R6 | Release: 6 Benchmark Date: 30 Sep 2026
# 96 rules — every rule in the catalog; 45 are attestation-only (DISA's check is a
# documentation or procedure review). IDs/severities/titles verified against the October 2026
# SRG-STIG library XCCDF on 2026-10-13 (tools/stig_generators/gen_oracle_db.py).
# Organizational rules are explicit attestation booleans — named for what
# a human verified, never silently passed. Input contract:
#   input.oracle.parameters[<name>]            : V$PARAMETER / GV$PARAMETER value (name lowercase)
#   input.oracle.profiles[<profile>][<RESOURCE>]: DBA_PROFILES limits, DEFAULT resolved by the collector
#   input.oracle.<query result>                : rows the STIG query must not return (lists), counts, flags
#   input.oracle.attest.*                      : attestation booleans (documented reviews)

import rego.v1

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

# O19C-00-000100 | V-270495 | CAT II
default r_o19c_00_000100 := false
r_o19c_00_000100 if {
	profiles_every_numeric("SESSIONS_PER_USER")
}

finding_r_o19c_00_000100 := {
	"vuln_id": "V-270495",
	"stig_id": "O19C-00-000100",
	"severity": "CAT II",
	"rule_title": "Oracle Database must limit the number of concurrent sessions for each system account to an organization-defined number of sessions.",
	"status": status_r_o19c_00_000100,
}
status_r_o19c_00_000100 := "Not_a_Finding" if r_o19c_00_000100
status_r_o19c_00_000100 := "Open" if not r_o19c_00_000100

# O19C-00-000200 | V-270496 | CAT II
default r_o19c_00_000200 := false
r_o19c_00_000200 if {
	input.oracle.listener.rate_limit_configured == true
}

finding_r_o19c_00_000200 := {
	"vuln_id": "V-270496",
	"stig_id": "O19C-00-000200",
	"severity": "CAT II",
	"rule_title": "Oracle Database must protect against or limit the effects of organization-defined types of denial-of-service (DoS) attacks.",
	"status": status_r_o19c_00_000200,
}
status_r_o19c_00_000200 := "Not_a_Finding" if r_o19c_00_000200
status_r_o19c_00_000200 := "Open" if not r_o19c_00_000200

# O19C-00-000300 | V-270497 | CAT II
default r_o19c_00_000300 := false
r_o19c_00_000300 if {
	to_number(input.oracle.parameters.max_idle_time) > 0
}

finding_r_o19c_00_000300 := {
	"vuln_id": "V-270497",
	"stig_id": "O19C-00-000300",
	"severity": "CAT II",
	"rule_title": "Oracle Database must automatically terminate a user session after organization-defined conditions or trigger events requiring session disconnect.",
	"status": status_r_o19c_00_000300,
}
status_r_o19c_00_000300 := "Not_a_Finding" if r_o19c_00_000300
status_r_o19c_00_000300 := "Open" if not r_o19c_00_000300

# O19C-00-000500 | V-270498 | CAT II
default r_o19c_00_000500 := false
r_o19c_00_000500 if {
	input.oracle.attest.security_labeling_implemented_or_not_required == true
}

finding_r_o19c_00_000500 := {
	"vuln_id": "V-270498",
	"stig_id": "O19C-00-000500",
	"severity": "CAT II",
	"rule_title": "Oracle Database must associate organization-defined types of security labels having organization-defined security label values with information in storage.",
	"status": status_r_o19c_00_000500,
}
status_r_o19c_00_000500 := "Not_a_Finding" if r_o19c_00_000500
status_r_o19c_00_000500 := "Open" if not r_o19c_00_000500

# O19C-00-000800 | V-270499 | CAT I
default r_o19c_00_000800 := false
r_o19c_00_000800 if {
	input.oracle.attest.org_level_auth_integrated == true
}

finding_r_o19c_00_000800 := {
	"vuln_id": "V-270499",
	"stig_id": "O19C-00-000800",
	"severity": "CAT I",
	"rule_title": "Oracle Database must integrate with an organization-level authentication/access mechanism providing account management and automation for all users, groups, roles, and any other principals.",
	"status": status_r_o19c_00_000800,
}
status_r_o19c_00_000800 := "Not_a_Finding" if r_o19c_00_000800
status_r_o19c_00_000800 := "Open" if not r_o19c_00_000800

# O19C-00-001000 | V-270500 | CAT I
default r_o19c_00_001000 := false
r_o19c_00_001000 if {
	input.oracle.attest.authorizations_enforced == true
}

finding_r_o19c_00_001000 := {
	"vuln_id": "V-270500",
	"stig_id": "O19C-00-001000",
	"severity": "CAT I",
	"rule_title": "Oracle Database must enforce approved authorizations for logical access to the system in accordance with applicable policy.",
	"status": status_r_o19c_00_001000,
}
status_r_o19c_00_001000 := "Not_a_Finding" if r_o19c_00_001000
status_r_o19c_00_001000 := "Open" if not r_o19c_00_001000

# O19C-00-001700 | V-270501 | CAT III
default r_o19c_00_001700 := false
r_o19c_00_001700 if {
	input.oracle.attest.shared_account_users_individually_identified == true
}

finding_r_o19c_00_001700 := {
	"vuln_id": "V-270501",
	"stig_id": "O19C-00-001700",
	"severity": "CAT III",
	"rule_title": "Oracle Database must protect against an individual who uses a shared account falsely denying having performed a particular action.",
	"status": status_r_o19c_00_001700,
}
status_r_o19c_00_001700 := "Not_a_Finding" if r_o19c_00_001700
status_r_o19c_00_001700 := "Open" if not r_o19c_00_001700

# O19C-00-001800 | V-270502 | CAT II
default r_o19c_00_001800 := false
r_o19c_00_001800 if {
	audit_enabled
}

finding_r_o19c_00_001800 := {
	"vuln_id": "V-270502",
	"stig_id": "O19C-00-001800",
	"severity": "CAT II",
	"rule_title": "Oracle Database must provide audit record generation capability for organization-defined auditable events within the database.",
	"status": status_r_o19c_00_001800,
}
status_r_o19c_00_001800 := "Not_a_Finding" if r_o19c_00_001800
status_r_o19c_00_001800 := "Open" if not r_o19c_00_001800

# O19C-00-001900 | V-270503 | CAT II
default r_o19c_00_001900 := false
r_o19c_00_001900 if {
	input.oracle.attest.audit_event_selection_by_designated_personnel == true
}

finding_r_o19c_00_001900 := {
	"vuln_id": "V-270503",
	"stig_id": "O19C-00-001900",
	"severity": "CAT II",
	"rule_title": "Oracle Database must allow designated organizational personnel to select which auditable events are to be audited by the database.",
	"status": status_r_o19c_00_001900,
}
status_r_o19c_00_001900 := "Not_a_Finding" if r_o19c_00_001900
status_r_o19c_00_001900 := "Open" if not r_o19c_00_001900

# O19C-00-002000 | V-270504 | CAT II
default r_o19c_00_002000 := false
r_o19c_00_002000 if {
	audit_enabled
	input.oracle.attest.dod_auditable_events_configured == true
}

finding_r_o19c_00_002000 := {
	"vuln_id": "V-270504",
	"stig_id": "O19C-00-002000",
	"severity": "CAT II",
	"rule_title": "Oracle Database must generate audit records for the DoW-selected list of auditable events, when successfully accessed, added, modified, or deleted, to the extent such information is available.",
	"status": status_r_o19c_00_002000,
}
status_r_o19c_00_002000 := "Not_a_Finding" if r_o19c_00_002000
status_r_o19c_00_002000 := "Open" if not r_o19c_00_002000

# O19C-00-005600 | V-270505 | CAT II
default r_o19c_00_005600 := false
r_o19c_00_005600 if {
	input.oracle.attest.additional_audit_information_configured == true
}

finding_r_o19c_00_005600 := {
	"vuln_id": "V-270505",
	"stig_id": "O19C-00-005600",
	"severity": "CAT II",
	"rule_title": "Oracle Database must include organization-defined additional, more detailed information in the audit records for audit events identified by type, location, or subject.",
	"status": status_r_o19c_00_005600,
}
status_r_o19c_00_005600 := "Not_a_Finding" if r_o19c_00_005600
status_r_o19c_00_005600 := "Open" if not r_o19c_00_005600

# O19C-00-005700 | V-270506 | CAT II
default r_o19c_00_005700 := false
r_o19c_00_005700 if {
	input.oracle.attest.audit_storage_capacity_allocated == true
}

finding_r_o19c_00_005700 := {
	"vuln_id": "V-270506",
	"stig_id": "O19C-00-005700",
	"severity": "CAT II",
	"rule_title": "Oracle Database must allocate audit record storage capacity in accordance with organization-defined audit record storage requirements.",
	"status": status_r_o19c_00_005700,
}
status_r_o19c_00_005700 := "Not_a_Finding" if r_o19c_00_005700
status_r_o19c_00_005700 := "Open" if not r_o19c_00_005700

# O19C-00-005800 | V-270507 | CAT II
default r_o19c_00_005800 := false
r_o19c_00_005800 if {
	input.oracle.attest.audit_offloaded_continuously == true
}

finding_r_o19c_00_005800 := {
	"vuln_id": "V-270507",
	"stig_id": "O19C-00-005800",
	"severity": "CAT II",
	"rule_title": "Oracle Database must off-load audit data to a separate log management facility; this must be continuous and in near-real-time for systems with a network connection to the storage facility, and weekly or more often for st",
	"status": status_r_o19c_00_005800,
}
status_r_o19c_00_005800 := "Not_a_Finding" if r_o19c_00_005800
status_r_o19c_00_005800 := "Open" if not r_o19c_00_005800

# O19C-00-005900 | V-270508 | CAT II
default r_o19c_00_005900 := false
r_o19c_00_005900 if {
	input.oracle.attest.audit_storage_warning_at_75_percent == true
}

finding_r_o19c_00_005900 := {
	"vuln_id": "V-270508",
	"stig_id": "O19C-00-005900",
	"severity": "CAT II",
	"rule_title": "The Oracle Database, or the logging or alerting mechanism the application uses, must provide a warning when allocated audit record storage volume record storage volume reaches 75 percent of maximum audit record storage c",
	"status": status_r_o19c_00_005900,
}
status_r_o19c_00_005900 := "Not_a_Finding" if r_o19c_00_005900
status_r_o19c_00_005900 := "Open" if not r_o19c_00_005900

# O19C-00-006000 | V-270509 | CAT II
default r_o19c_00_006000 := false
r_o19c_00_006000 if {
	input.oracle.attest.audit_failure_realtime_alert == true
}

finding_r_o19c_00_006000 := {
	"vuln_id": "V-270509",
	"stig_id": "O19C-00-006000",
	"severity": "CAT II",
	"rule_title": "Oracle Database must provide an immediate real-time alert to appropriate support staff of all audit log failures.",
	"status": status_r_o19c_00_006000,
}
status_r_o19c_00_006000 := "Not_a_Finding" if r_o19c_00_006000
status_r_o19c_00_006000 := "Open" if not r_o19c_00_006000

# O19C-00-006600 | V-270510 | CAT II
default r_o19c_00_006600 := false
r_o19c_00_006600 if {
	input.oracle.attest.audit_data_access_restricted == true
}

finding_r_o19c_00_006600 := {
	"vuln_id": "V-270510",
	"stig_id": "O19C-00-006600",
	"severity": "CAT II",
	"rule_title": "The audit information produced by the Oracle Database must be protected from unauthorized access, modification, or deletion.",
	"status": status_r_o19c_00_006600,
}
status_r_o19c_00_006600 := "Not_a_Finding" if r_o19c_00_006600
status_r_o19c_00_006600 := "Open" if not r_o19c_00_006600

# O19C-00-006900 | V-270511 | CAT II
default r_o19c_00_006900 := false
r_o19c_00_006900 if {
	input.oracle.attest.audit_tools_access_restricted == true
}

finding_r_o19c_00_006900 := {
	"vuln_id": "V-270511",
	"stig_id": "O19C-00-006900",
	"severity": "CAT II",
	"rule_title": "The system must protect audit tools from unauthorized access, modification, or deletion.",
	"status": status_r_o19c_00_006900,
}
status_r_o19c_00_006900 := "Not_a_Finding" if r_o19c_00_006900
status_r_o19c_00_006900 := "Open" if not r_o19c_00_006900

# O19C-00-007300 | V-270512 | CAT II
default r_o19c_00_007300 := false
r_o19c_00_007300 if {
	input.oracle.filesystem.oracle_home_world_accessible == false
}

finding_r_o19c_00_007300 := {
	"vuln_id": "V-270512",
	"stig_id": "O19C-00-007300",
	"severity": "CAT II",
	"rule_title": "Oracle Database must support enforcement of logical access restrictions associated with changes to the database management system (DBMS) configuration and to the database itself.",
	"status": status_r_o19c_00_007300,
}
status_r_o19c_00_007300 := "Not_a_Finding" if r_o19c_00_007300
status_r_o19c_00_007300 := "Open" if not r_o19c_00_007300

# O19C-00-007400 | V-270513 | CAT I
default r_o19c_00_007400 := false
r_o19c_00_007400 if {
	input.oracle.attest.vendor_supported_version == true
}

finding_r_o19c_00_007400 := {
	"vuln_id": "V-270513",
	"stig_id": "O19C-00-007400",
	"severity": "CAT I",
	"rule_title": "Oracle Database products must be a version supported by the vendor.",
	"status": status_r_o19c_00_007400,
}
status_r_o19c_00_007400 := "Not_a_Finding" if r_o19c_00_007400
status_r_o19c_00_007400 := "Open" if not r_o19c_00_007400

# O19C-00-007700 | V-270514 | CAT II
default r_o19c_00_007700 := false
r_o19c_00_007700 if {
	input.oracle.attest.software_change_monitoring_in_place == true
}

finding_r_o19c_00_007700 := {
	"vuln_id": "V-270514",
	"stig_id": "O19C-00-007700",
	"severity": "CAT II",
	"rule_title": "Database software, applications, and configuration files must be monitored to discover unauthorized changes.",
	"status": status_r_o19c_00_007700,
}
status_r_o19c_00_007700 := "Not_a_Finding" if r_o19c_00_007700
status_r_o19c_00_007700 := "Open" if not r_o19c_00_007700

# O19C-00-007900 | V-270515 | CAT II
default r_o19c_00_007900 := false
r_o19c_00_007900 if {
	input.oracle.attest.software_library_access_restricted == true
}

finding_r_o19c_00_007900 := {
	"vuln_id": "V-270515",
	"stig_id": "O19C-00-007900",
	"severity": "CAT II",
	"rule_title": "The OS must limit privileges to change the database management system (DBMS) software resident within software libraries (including privileged programs).",
	"status": status_r_o19c_00_007900,
}
status_r_o19c_00_007900 := "Not_a_Finding" if r_o19c_00_007900
status_r_o19c_00_007900 := "Open" if not r_o19c_00_007900

# O19C-00-008000 | V-270516 | CAT I
default r_o19c_00_008000 := false
r_o19c_00_008000 if {
	input.oracle.attest.install_account_restricted == true
}

finding_r_o19c_00_008000 := {
	"vuln_id": "V-270516",
	"stig_id": "O19C-00-008000",
	"severity": "CAT I",
	"rule_title": "The Oracle Database software installation account must be restricted to authorized users.",
	"status": status_r_o19c_00_008000,
}
status_r_o19c_00_008000 := "Not_a_Finding" if r_o19c_00_008000
status_r_o19c_00_008000 := "Open" if not r_o19c_00_008000

# O19C-00-008100 | V-270517 | CAT II
default r_o19c_00_008100 := false
r_o19c_00_008100 if {
	input.oracle.attest.software_directories_dedicated == true
}

finding_r_o19c_00_008100 := {
	"vuln_id": "V-270517",
	"stig_id": "O19C-00-008100",
	"severity": "CAT II",
	"rule_title": "Database software directories, including database management system (DBMS) configuration files, must be stored in dedicated directories, or DASD pools, separate from the host OS and other applications.",
	"status": status_r_o19c_00_008100,
}
status_r_o19c_00_008100 := "Not_a_Finding" if r_o19c_00_008100
status_r_o19c_00_008100 := "Open" if not r_o19c_00_008100

# O19C-00-008200 | V-270518 | CAT II
default r_o19c_00_008200 := false
r_o19c_00_008200 if {
	count(input.oracle.unauthorized_object_owners) == 0
}

finding_r_o19c_00_008200 := {
	"vuln_id": "V-270518",
	"stig_id": "O19C-00-008200",
	"severity": "CAT II",
	"rule_title": "Database objects must be owned by accounts authorized for ownership.",
	"status": status_r_o19c_00_008200,
}
status_r_o19c_00_008200 := "Not_a_Finding" if r_o19c_00_008200
status_r_o19c_00_008200 := "Open" if not r_o19c_00_008200

# O19C-00-008300 | V-270519 | CAT II
default r_o19c_00_008300 := false
r_o19c_00_008300 if {
	count(input.oracle.direct_admin_privilege_grantees) == 0
}

finding_r_o19c_00_008300 := {
	"vuln_id": "V-270519",
	"stig_id": "O19C-00-008300",
	"severity": "CAT II",
	"rule_title": "The role(s)/group(s) used to modify database structure (including but not necessarily limited to tables, indexes, storage, etc.) and logic modules (stored procedures, functions, triggers, links to software external to th",
	"status": status_r_o19c_00_008300,
}
status_r_o19c_00_008300 := "Not_a_Finding" if r_o19c_00_008300
status_r_o19c_00_008300 := "Open" if not r_o19c_00_008300

# O19C-00-008400 | V-270520 | CAT II
default r_o19c_00_008400 := false
r_o19c_00_008400 if {
	input.oracle.attest.configured_per_dod_guidance == true
}

finding_r_o19c_00_008400 := {
	"vuln_id": "V-270520",
	"stig_id": "O19C-00-008400",
	"severity": "CAT II",
	"rule_title": "Oracle Database must be configured in accordance with the security configuration settings based on DoW security configuration and implementation guidance, including STIGs, NSA configuration guides, CTOs, DTMs, and IAVMs.",
	"status": status_r_o19c_00_008400,
}
status_r_o19c_00_008400 := "Not_a_Finding" if r_o19c_00_008400
status_r_o19c_00_008400 := "Open" if not r_o19c_00_008400

# O19C-00-008600 | V-270521 | CAT II
default r_o19c_00_008600 := false
r_o19c_00_008600 if {
	not contains(input.oracle.instance_name, split(input.oracle.version, ".")[0])
}

finding_r_o19c_00_008600 := {
	"vuln_id": "V-270521",
	"stig_id": "O19C-00-008600",
	"severity": "CAT II",
	"rule_title": "Oracle instance names must not contain Oracle version numbers.",
	"status": status_r_o19c_00_008600,
}
status_r_o19c_00_008600 := "Not_a_Finding" if r_o19c_00_008600
status_r_o19c_00_008600 := "Open" if not r_o19c_00_008600

# O19C-00-008700 | V-270522 | CAT II
default r_o19c_00_008700 := false
r_o19c_00_008700 if {
	count(input.oracle.unauthorized_db_links) == 0
}

finding_r_o19c_00_008700 := {
	"vuln_id": "V-270522",
	"stig_id": "O19C-00-008700",
	"severity": "CAT II",
	"rule_title": "Fixed user and PUBLIC Database links must be authorized for use.",
	"status": status_r_o19c_00_008700,
}
status_r_o19c_00_008700 := "Not_a_Finding" if r_o19c_00_008700
status_r_o19c_00_008700 := "Open" if not r_o19c_00_008700

# O19C-00-009000 | V-270523 | CAT II
default r_o19c_00_009000 := false
r_o19c_00_009000 if {
	count(input.oracle.grantable_privileges_non_dba) == 0
}

finding_r_o19c_00_009000 := {
	"vuln_id": "V-270523",
	"stig_id": "O19C-00-009000",
	"severity": "CAT II",
	"rule_title": "The Oracle WITH GRANT OPTION privilege must be limited when granted to nondatabase administrator (DBA) or nonapplication administrator user accounts.",
	"status": status_r_o19c_00_009000,
}
status_r_o19c_00_009000 := "Not_a_Finding" if r_o19c_00_009000
status_r_o19c_00_009000 := "Open" if not r_o19c_00_009000

# O19C-00-009200 | V-270524 | CAT II
default r_o19c_00_009200 := false
r_o19c_00_009200 if {
	lower(input.oracle.parameters["remote_os_roles"]) == "false"
}

finding_r_o19c_00_009200 := {
	"vuln_id": "V-270524",
	"stig_id": "O19C-00-009200",
	"severity": "CAT II",
	"rule_title": "The Oracle REMOTE_OS_ROLES parameter must be set to FALSE.",
	"status": status_r_o19c_00_009200,
}
status_r_o19c_00_009200 := "Not_a_Finding" if r_o19c_00_009200
status_r_o19c_00_009200 := "Open" if not r_o19c_00_009200

# O19C-00-009300 | V-270525 | CAT II
default r_o19c_00_009300 := false
r_o19c_00_009300 if {
	lower(input.oracle.parameters["sql92_security"]) == "true"
}

finding_r_o19c_00_009300 := {
	"vuln_id": "V-270525",
	"stig_id": "O19C-00-009300",
	"severity": "CAT II",
	"rule_title": "The Oracle SQL92_SECURITY parameter must be set to TRUE.",
	"status": status_r_o19c_00_009300,
}
status_r_o19c_00_009300 := "Not_a_Finding" if r_o19c_00_009300
status_r_o19c_00_009300 := "Open" if not r_o19c_00_009300

# O19C-00-009400 | V-270526 | CAT II
default r_o19c_00_009400 := false
r_o19c_00_009400 if {
	lower(input.oracle.parameters["remote_login_passwordfile"]) in {"exclusive", "none"}
}

finding_r_o19c_00_009400 := {
	"vuln_id": "V-270526",
	"stig_id": "O19C-00-009400",
	"severity": "CAT II",
	"rule_title": "The Oracle password file ownership and permissions should be limited and the REMOTE_LOGIN_PASSWORDFILE parameter must be set to EXCLUSIVE or NONE.",
	"status": status_r_o19c_00_009400,
}
status_r_o19c_00_009400 := "Not_a_Finding" if r_o19c_00_009400
status_r_o19c_00_009400 := "Open" if not r_o19c_00_009400

# O19C-00-009500 | V-270527 | CAT II
default r_o19c_00_009500 := false
r_o19c_00_009500 if {
	count(input.oracle.unauthorized_admin_option_system_privileges) == 0
}

finding_r_o19c_00_009500 := {
	"vuln_id": "V-270527",
	"stig_id": "O19C-00-009500",
	"severity": "CAT II",
	"rule_title": "System privileges granted using the WITH ADMIN OPTION must not be granted to unauthorized user accounts.",
	"status": status_r_o19c_00_009500,
}
status_r_o19c_00_009500 := "Not_a_Finding" if r_o19c_00_009500
status_r_o19c_00_009500 := "Open" if not r_o19c_00_009500

# O19C-00-009600 | V-270528 | CAT II
default r_o19c_00_009600 := false
r_o19c_00_009600 if {
	count(input.oracle.public_system_privileges) == 0
}

finding_r_o19c_00_009600 := {
	"vuln_id": "V-270528",
	"stig_id": "O19C-00-009600",
	"severity": "CAT II",
	"rule_title": "System Privileges must not be granted to PUBLIC.",
	"status": status_r_o19c_00_009600,
}
status_r_o19c_00_009600 := "Not_a_Finding" if r_o19c_00_009600
status_r_o19c_00_009600 := "Open" if not r_o19c_00_009600

# O19C-00-009700 | V-270529 | CAT II
default r_o19c_00_009700 := false
r_o19c_00_009700 if {
	count(input.oracle.unauthorized_admin_option_roles) == 0
}

finding_r_o19c_00_009700 := {
	"vuln_id": "V-270529",
	"stig_id": "O19C-00-009700",
	"severity": "CAT II",
	"rule_title": "Oracle roles granted using the WITH ADMIN OPTION must not be granted to unauthorized accounts.",
	"status": status_r_o19c_00_009700,
}
status_r_o19c_00_009700 := "Not_a_Finding" if r_o19c_00_009700
status_r_o19c_00_009700 := "Open" if not r_o19c_00_009700

# O19C-00-009800 | V-270530 | CAT II
default r_o19c_00_009800 := false
r_o19c_00_009800 if {
	count(input.oracle.unauthorized_public_object_privileges) == 0
}

finding_r_o19c_00_009800 := {
	"vuln_id": "V-270530",
	"stig_id": "O19C-00-009800",
	"severity": "CAT II",
	"rule_title": "Object permissions granted to PUBLIC must be restricted.",
	"status": status_r_o19c_00_009800,
}
status_r_o19c_00_009800 := "Not_a_Finding" if r_o19c_00_009800
status_r_o19c_00_009800 := "Open" if not r_o19c_00_009800

# O19C-00-009900 | V-270531 | CAT I
default r_o19c_00_009900 := false
r_o19c_00_009900 if {
	input.oracle.listener.admin_authentication_required == true
}

finding_r_o19c_00_009900 := {
	"vuln_id": "V-270531",
	"stig_id": "O19C-00-009900",
	"severity": "CAT I",
	"rule_title": "The Oracle Listener must be configured to require administration authentication.",
	"status": status_r_o19c_00_009900,
}
status_r_o19c_00_009900 := "Not_a_Finding" if r_o19c_00_009900
status_r_o19c_00_009900 := "Open" if not r_o19c_00_009900

# O19C-00-010000 | V-270532 | CAT II
default r_o19c_00_010000 := false
r_o19c_00_010000 if {
	count(input.oracle.public_granted_roles) == 0
}

finding_r_o19c_00_010000 := {
	"vuln_id": "V-270532",
	"stig_id": "O19C-00-010000",
	"severity": "CAT II",
	"rule_title": "Application role permissions must not be assigned to the Oracle PUBLIC role.",
	"status": status_r_o19c_00_010000,
}
status_r_o19c_00_010000 := "Not_a_Finding" if r_o19c_00_010000
status_r_o19c_00_010000 := "Open" if not r_o19c_00_010000

# O19C-00-010100 | V-270533 | CAT II
default r_o19c_00_010100 := false
r_o19c_00_010100 if {
	count(input.oracle.unauthorized_default_admin_roles) == 0
}

finding_r_o19c_00_010100 := {
	"vuln_id": "V-270533",
	"stig_id": "O19C-00-010100",
	"severity": "CAT II",
	"rule_title": "Oracle application administration roles must be disabled if not required and authorized.",
	"status": status_r_o19c_00_010100,
}
status_r_o19c_00_010100 := "Not_a_Finding" if r_o19c_00_010100
status_r_o19c_00_010100 := "Open" if not r_o19c_00_010100

# O19C-00-010400 | V-270534 | CAT II
default r_o19c_00_010400 := false
r_o19c_00_010400 if {
	input.oracle.filesystem.archive_log_dirs_world_accessible == false
}

finding_r_o19c_00_010400 := {
	"vuln_id": "V-270534",
	"stig_id": "O19C-00-010400",
	"severity": "CAT II",
	"rule_title": "The directories assigned to the LOG_ARCHIVE_DEST* parameters must be protected from unauthorized access.",
	"status": status_r_o19c_00_010400,
}
status_r_o19c_00_010400 := "Not_a_Finding" if r_o19c_00_010400
status_r_o19c_00_010400 := "Open" if not r_o19c_00_010400

# O19C-00-010500 | V-270535 | CAT II
default r_o19c_00_010500 := false
r_o19c_00_010500 if {
	lower(object.get(input.oracle.parameters, "_trace_files_public", "false")) == "false"
}

finding_r_o19c_00_010500 := {
	"vuln_id": "V-270535",
	"stig_id": "O19C-00-010500",
	"severity": "CAT II",
	"rule_title": "The Oracle _TRACE_FILES_PUBLIC parameter if present must be set to FALSE.",
	"status": status_r_o19c_00_010500,
}
status_r_o19c_00_010500 := "Not_a_Finding" if r_o19c_00_010500
status_r_o19c_00_010500 := "Open" if not r_o19c_00_010500

# O19C-00-010600 | V-270536 | CAT II
default r_o19c_00_010600 := false
r_o19c_00_010600 if {
	input.oracle.attest.developers_excluded_from_dba_group == true
}

finding_r_o19c_00_010600 := {
	"vuln_id": "V-270536",
	"stig_id": "O19C-00-010600",
	"severity": "CAT II",
	"rule_title": "Oracle Database production application and data directories must be protected from developers on shared production/development database management system (DBMS) host systems.",
	"status": status_r_o19c_00_010600,
}
status_r_o19c_00_010600 := "Not_a_Finding" if r_o19c_00_010600
status_r_o19c_00_010600 := "Open" if not r_o19c_00_010600

# O19C-00-010700 | V-270537 | CAT II
default r_o19c_00_010700 := false
r_o19c_00_010700 if {
	input.oracle.attest.install_account_use_logged == true
}

finding_r_o19c_00_010700 := {
	"vuln_id": "V-270537",
	"stig_id": "O19C-00-010700",
	"severity": "CAT II",
	"rule_title": "Use of the Oracle Database installation account must be logged.",
	"status": status_r_o19c_00_010700,
}
status_r_o19c_00_010700 := "Not_a_Finding" if r_o19c_00_010700
status_r_o19c_00_010700 := "Open" if not r_o19c_00_010700

# O19C-00-010800 | V-270538 | CAT II
default r_o19c_00_010800 := false
r_o19c_00_010800 if {
	input.oracle.attest.data_log_audit_files_in_dedicated_directories == true
}

finding_r_o19c_00_010800 := {
	"vuln_id": "V-270538",
	"stig_id": "O19C-00-010800",
	"severity": "CAT II",
	"rule_title": "The Oracle Database data files, transaction logs and audit files must be stored in dedicated directories or disk partitions separate from software or other application files.",
	"status": status_r_o19c_00_010800,
}
status_r_o19c_00_010800 := "Not_a_Finding" if r_o19c_00_010800
status_r_o19c_00_010800 := "Open" if not r_o19c_00_010800

# O19C-00-011200 | V-270539 | CAT II
default r_o19c_00_011200 := false
r_o19c_00_011200 if {
	input.oracle.network.access_restriction_enforced == true
}

finding_r_o19c_00_011200 := {
	"vuln_id": "V-270539",
	"stig_id": "O19C-00-011200",
	"severity": "CAT II",
	"rule_title": "Network access to Oracle Database must be restricted to authorized personnel.",
	"status": status_r_o19c_00_011200,
}
status_r_o19c_00_011200 := "Not_a_Finding" if r_o19c_00_011200
status_r_o19c_00_011200 := "Open" if not r_o19c_00_011200

# O19C-00-011300 | V-270540 | CAT II
default r_o19c_00_011300 := false
r_o19c_00_011300 if {
	lower(input.oracle.parameters["audit_sys_operations"]) == "true"
}

r_o19c_00_011300 if {
	count(input.oracle.unified_audit_sys_policies) > 0
}

finding_r_o19c_00_011300 := {
	"vuln_id": "V-270540",
	"stig_id": "O19C-00-011300",
	"severity": "CAT II",
	"rule_title": "Changes to configuration options must be audited.",
	"status": status_r_o19c_00_011300,
}
status_r_o19c_00_011300 := "Not_a_Finding" if r_o19c_00_011300
status_r_o19c_00_011300 := "Open" if not r_o19c_00_011300

# O19C-00-011500 | V-270541 | CAT II
default r_o19c_00_011500 := false
r_o19c_00_011500 if {
	input.oracle.filesystem.diag_dir_world_accessible == false
}

finding_r_o19c_00_011500 := {
	"vuln_id": "V-270541",
	"stig_id": "O19C-00-011500",
	"severity": "CAT II",
	"rule_title": "The /diag subdirectory under the directory assigned to the DIAGNOSTIC_DEST parameter must be protected from unauthorized access.",
	"status": status_r_o19c_00_011500,
}
status_r_o19c_00_011500 := "Not_a_Finding" if r_o19c_00_011500
status_r_o19c_00_011500 := "Open" if not r_o19c_00_011500

# O19C-00-011600 | V-270542 | CAT II
default r_o19c_00_011600 := false
r_o19c_00_011600 if {
	input.oracle.cman.present == false
}

r_o19c_00_011600 if {
	lower(input.oracle.cman.remote_admin) == "no"
}

finding_r_o19c_00_011600 := {
	"vuln_id": "V-270542",
	"stig_id": "O19C-00-011600",
	"severity": "CAT II",
	"rule_title": "Remote administration must be disabled for the Oracle connection manager.",
	"status": status_r_o19c_00_011600,
}
status_r_o19c_00_011600 := "Not_a_Finding" if r_o19c_00_011600
status_r_o19c_00_011600 := "Open" if not r_o19c_00_011600

# O19C-00-011700 | V-270543 | CAT II
default r_o19c_00_011700 := false
r_o19c_00_011700 if {
	startswith(input.oracle.sqlnet.allowed_logon_version_server, "12")
}

finding_r_o19c_00_011700 := {
	"vuln_id": "V-270543",
	"stig_id": "O19C-00-011700",
	"severity": "CAT II",
	"rule_title": "Network client connections must be restricted to supported versions.",
	"status": status_r_o19c_00_011700,
}
status_r_o19c_00_011700 := "Not_a_Finding" if r_o19c_00_011700
status_r_o19c_00_011700 := "Open" if not r_o19c_00_011700

# O19C-00-011800 | V-270544 | CAT I
default r_o19c_00_011800 := false
r_o19c_00_011800 if {
	input.oracle.os.root_in_dba_group == false
	input.oracle.attest.dba_os_accounts_least_privilege == true
}

finding_r_o19c_00_011800 := {
	"vuln_id": "V-270544",
	"stig_id": "O19C-00-011800",
	"severity": "CAT I",
	"rule_title": "Database administrator (DBA) OS accounts must be granted only those host system privileges necessary for the administration of the Oracle Database.",
	"status": status_r_o19c_00_011800,
}
status_r_o19c_00_011800 := "Not_a_Finding" if r_o19c_00_011800
status_r_o19c_00_011800 := "Open" if not r_o19c_00_011800

# O19C-00-011900 | V-270545 | CAT I
default r_o19c_00_011900 := false
r_o19c_00_011900 if {
	count(input.oracle.users_with_default_password) == 0
}

finding_r_o19c_00_011900 := {
	"vuln_id": "V-270545",
	"stig_id": "O19C-00-011900",
	"severity": "CAT I",
	"rule_title": "Oracle Database default accounts must be assigned custom passwords.",
	"status": status_r_o19c_00_011900,
}
status_r_o19c_00_011900 := "Not_a_Finding" if r_o19c_00_011900
status_r_o19c_00_011900 := "Open" if not r_o19c_00_011900

# O19C-00-012000 | V-270546 | CAT II
default r_o19c_00_012000 := false
r_o19c_00_012000 if {
	input.oracle.attest.temporary_accounts_identified == true
}

finding_r_o19c_00_012000 := {
	"vuln_id": "V-270546",
	"stig_id": "O19C-00-012000",
	"severity": "CAT II",
	"rule_title": "Oracle Database must provide a mechanism to automatically identify accounts designated as temporary or emergency accounts.",
	"status": status_r_o19c_00_012000,
}
status_r_o19c_00_012000 := "Not_a_Finding" if r_o19c_00_012000
status_r_o19c_00_012000 := "Open" if not r_o19c_00_012000

# O19C-00-012100 | V-270547 | CAT II
default r_o19c_00_012100 := false
r_o19c_00_012100 if {
	input.oracle.attest.temporary_accounts_expire_within_72h == true
}

finding_r_o19c_00_012100 := {
	"vuln_id": "V-270547",
	"stig_id": "O19C-00-012100",
	"severity": "CAT II",
	"rule_title": "Oracle Database must provide a mechanism to automatically remove or disable temporary user accounts after 72 hours.",
	"status": status_r_o19c_00_012100,
}
status_r_o19c_00_012100 := "Not_a_Finding" if r_o19c_00_012100
status_r_o19c_00_012100 := "Open" if not r_o19c_00_012100

# O19C-00-012200 | V-270548 | CAT II
default r_o19c_00_012200 := false
r_o19c_00_012200 if {
	input.oracle.attest.developers_no_elevated_privileges_on_shared_hosts == true
}

finding_r_o19c_00_012200 := {
	"vuln_id": "V-270548",
	"stig_id": "O19C-00-012200",
	"severity": "CAT II",
	"rule_title": "Oracle Database must be protected from unauthorized access by developers on shared production/development host systems.",
	"status": status_r_o19c_00_012200,
}
status_r_o19c_00_012200 := "Not_a_Finding" if r_o19c_00_012200
status_r_o19c_00_012200 := "Open" if not r_o19c_00_012200

# O19C-00-012300 | V-270549 | CAT II
default r_o19c_00_012300 := false
r_o19c_00_012300 if {
	profiles_every_eq("PASSWORD_LOCK_TIME", "UNLIMITED")
}

finding_r_o19c_00_012300 := {
	"vuln_id": "V-270549",
	"stig_id": "O19C-00-012300",
	"severity": "CAT II",
	"rule_title": "Oracle Database must verify account lockouts persist until reset by an administrator.",
	"status": status_r_o19c_00_012300,
}
status_r_o19c_00_012300 := "Not_a_Finding" if r_o19c_00_012300
status_r_o19c_00_012300 := "Open" if not r_o19c_00_012300

# O19C-00-012400 | V-270550 | CAT II
default r_o19c_00_012400 := false
r_o19c_00_012400 if {
	profiles_every_le("FAILED_LOGIN_ATTEMPTS", 3)
}

finding_r_o19c_00_012400 := {
	"vuln_id": "V-270550",
	"stig_id": "O19C-00-012400",
	"severity": "CAT II",
	"rule_title": "Oracle Database must set the maximum number of consecutive invalid logon attempts to three.",
	"status": status_r_o19c_00_012400,
}
status_r_o19c_00_012400 := "Not_a_Finding" if r_o19c_00_012400
status_r_o19c_00_012400 := "Open" if not r_o19c_00_012400

# O19C-00-012500 | V-270551 | CAT II
default r_o19c_00_012500 := false
r_o19c_00_012500 if {
	profiles_every_le("INACTIVE_ACCOUNT_TIME", 35)
}

finding_r_o19c_00_012500 := {
	"vuln_id": "V-270551",
	"stig_id": "O19C-00-012500",
	"severity": "CAT II",
	"rule_title": "Oracle Database must disable user accounts after 35 days of inactivity.",
	"status": status_r_o19c_00_012500,
}
status_r_o19c_00_012500 := "Not_a_Finding" if r_o19c_00_012500
status_r_o19c_00_012500 := "Open" if not r_o19c_00_012500

# O19C-00-012900 | V-270552 | CAT II
default r_o19c_00_012900 := false
r_o19c_00_012900 if {
	count(input.oracle.sample_schemas_present) == 0
}

finding_r_o19c_00_012900 := {
	"vuln_id": "V-270552",
	"stig_id": "O19C-00-012900",
	"severity": "CAT II",
	"rule_title": "Oracle Database default demonstration and sample databases, database objects, and applications must be removed.",
	"status": status_r_o19c_00_012900,
}
status_r_o19c_00_012900 := "Not_a_Finding" if r_o19c_00_012900
status_r_o19c_00_012900 := "Open" if not r_o19c_00_012900

# O19C-00-013000 | V-270553 | CAT II
default r_o19c_00_013000 := false
r_o19c_00_013000 if {
	count(input.oracle.unused_components_installed) == 0
}

finding_r_o19c_00_013000 := {
	"vuln_id": "V-270553",
	"stig_id": "O19C-00-013000",
	"severity": "CAT II",
	"rule_title": "Unused database components, database management system (DBMS) software, and database objects must be removed.",
	"status": status_r_o19c_00_013000,
}
status_r_o19c_00_013000 := "Not_a_Finding" if r_o19c_00_013000
status_r_o19c_00_013000 := "Open" if not r_o19c_00_013000

# O19C-00-013100 | V-270554 | CAT II
default r_o19c_00_013100 := false
r_o19c_00_013100 if {
	count(input.oracle.unused_integrated_options_enabled) == 0
}

finding_r_o19c_00_013100 := {
	"vuln_id": "V-270554",
	"stig_id": "O19C-00-013100",
	"severity": "CAT II",
	"rule_title": "Unused database components that are integrated in the database management system (DBMS) and cannot be uninstalled must be disabled.",
	"status": status_r_o19c_00_013100,
}
status_r_o19c_00_013100 := "Not_a_Finding" if r_o19c_00_013100
status_r_o19c_00_013100 := "Open" if not r_o19c_00_013100

# O19C-00-013200 | V-270555 | CAT II
default r_o19c_00_013200 := false
r_o19c_00_013200 if {
	input.oracle.attest.extproc_os_accounts_least_privilege == true
}

finding_r_o19c_00_013200 := {
	"vuln_id": "V-270555",
	"stig_id": "O19C-00-013200",
	"severity": "CAT II",
	"rule_title": "OS accounts used to run external procedures called by Oracle Database must have limited privileges.",
	"status": status_r_o19c_00_013200,
}
status_r_o19c_00_013200 := "Not_a_Finding" if r_o19c_00_013200
status_r_o19c_00_013200 := "Open" if not r_o19c_00_013200

# O19C-00-013300 | V-270556 | CAT II
default r_o19c_00_013300 := false
r_o19c_00_013300 if {
	input.oracle.attest.external_executables_authorized == true
}

finding_r_o19c_00_013300 := {
	"vuln_id": "V-270556",
	"stig_id": "O19C-00-013300",
	"severity": "CAT II",
	"rule_title": "Use of external executables must be authorized.",
	"status": status_r_o19c_00_013300,
}
status_r_o19c_00_013300 := "Not_a_Finding" if r_o19c_00_013300
status_r_o19c_00_013300 := "Open" if not r_o19c_00_013300

# O19C-00-013400 | V-270557 | CAT II
default r_o19c_00_013400 := false
r_o19c_00_013400 if {
	input.oracle.listener.extproc_configured == false
}

r_o19c_00_013400 if {
	input.oracle.attest.extproc_use_authorized == true
}

finding_r_o19c_00_013400 := {
	"vuln_id": "V-270557",
	"stig_id": "O19C-00-013400",
	"severity": "CAT II",
	"rule_title": "Access to external executables must be disabled or restricted.",
	"status": status_r_o19c_00_013400,
}
status_r_o19c_00_013400 := "Not_a_Finding" if r_o19c_00_013400
status_r_o19c_00_013400 := "Open" if not r_o19c_00_013400

# O19C-00-013500 | V-270558 | CAT II
default r_o19c_00_013500 := false
r_o19c_00_013500 if {
	input.oracle.attest.ppsm_functions_ports_protocols_approved == true
}

finding_r_o19c_00_013500 := {
	"vuln_id": "V-270558",
	"stig_id": "O19C-00-013500",
	"severity": "CAT II",
	"rule_title": "Oracle Database must be configured to prohibit or restrict the use of organization-defined functions, ports, protocols, and/or services, as defined in the Ports, Protocols, and Services Management Category Assurance List",
	"status": status_r_o19c_00_013500,
}
status_r_o19c_00_013500 := "Not_a_Finding" if r_o19c_00_013500
status_r_o19c_00_013500 := "Open" if not r_o19c_00_013500

# O19C-00-013700 | V-270559 | CAT II
default r_o19c_00_013700 := false
r_o19c_00_013700 if {
	input.oracle.attest.shared_accounts_require_individual_authentication == true
}

finding_r_o19c_00_013700 := {
	"vuln_id": "V-270559",
	"stig_id": "O19C-00-013700",
	"severity": "CAT II",
	"rule_title": "Oracle Database must ensure users are authenticated with an individual authenticator prior to using a shared authenticator.",
	"status": status_r_o19c_00_013700,
}
status_r_o19c_00_013700 := "Not_a_Finding" if r_o19c_00_013700
status_r_o19c_00_013700 := "Open" if not r_o19c_00_013700

# O19C-00-013800 | V-270560 | CAT II
default r_o19c_00_013800 := false
r_o19c_00_013800 if {
	input.oracle.attest.organizational_users_uniquely_identified == true
}

finding_r_o19c_00_013800 := {
	"vuln_id": "V-270560",
	"stig_id": "O19C-00-013800",
	"severity": "CAT II",
	"rule_title": "Oracle Database must uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users).",
	"status": status_r_o19c_00_013800,
}
status_r_o19c_00_013800 := "Not_a_Finding" if r_o19c_00_013800
status_r_o19c_00_013800 := "Open" if not r_o19c_00_013800

# O19C-00-013900 | V-270561 | CAT II
default r_o19c_00_013900 := false
r_o19c_00_013900 if {
	profiles_every_set("PASSWORD_VERIFY_FUNCTION")
}

finding_r_o19c_00_013900 := {
	"vuln_id": "V-270561",
	"stig_id": "O19C-00-013900",
	"severity": "CAT II",
	"rule_title": "Oracle Database must enforce the DoW standards for password complexity.",
	"status": status_r_o19c_00_013900,
}
status_r_o19c_00_013900 := "Not_a_Finding" if r_o19c_00_013900
status_r_o19c_00_013900 := "Open" if not r_o19c_00_013900

# O19C-00-014600 | V-270562 | CAT II
default r_o19c_00_014600 := false
r_o19c_00_014600 if {
	input.oracle.attest.temporary_password_procedures_documented == true
}

finding_r_o19c_00_014600 := {
	"vuln_id": "V-270562",
	"stig_id": "O19C-00-014600",
	"severity": "CAT II",
	"rule_title": "Procedures for establishing temporary passwords that meet DoW password requirements for new accounts must be defined, documented, and implemented.",
	"status": status_r_o19c_00_014600,
}
status_r_o19c_00_014600 := "Not_a_Finding" if r_o19c_00_014600
status_r_o19c_00_014600 := "Open" if not r_o19c_00_014600

# O19C-00-014700 | V-270563 | CAT II
default r_o19c_00_014700 := false
r_o19c_00_014700 if {
	profiles_every_effective_life_le(180)
}

finding_r_o19c_00_014700 := {
	"vuln_id": "V-270563",
	"stig_id": "O19C-00-014700",
	"severity": "CAT II",
	"rule_title": "Oracle Database must enforce password maximum lifetime restrictions.",
	"status": status_r_o19c_00_014700,
}
status_r_o19c_00_014700 := "Not_a_Finding" if r_o19c_00_014700
status_r_o19c_00_014700 := "Open" if not r_o19c_00_014700

# O19C-00-014800 | V-270564 | CAT I
default r_o19c_00_014800 := false
r_o19c_00_014800 if {
	count(input.oracle.users_with_10g_password_verifier) == 0
}

finding_r_o19c_00_014800 := {
	"vuln_id": "V-270564",
	"stig_id": "O19C-00-014800",
	"severity": "CAT I",
	"rule_title": "Oracle Database must, for password-based authentication, store passwords using an approved salted key derivation function, preferably using a keyed hash.",
	"status": status_r_o19c_00_014800,
}
status_r_o19c_00_014800 := "Not_a_Finding" if r_o19c_00_014800
status_r_o19c_00_014800 := "Open" if not r_o19c_00_014800

# O19C-00-014900 | V-270565 | CAT II
default r_o19c_00_014900 := false
r_o19c_00_014900 if {
	input.oracle.network.tls_or_native_encryption_required == true
}

finding_r_o19c_00_014900 := {
	"vuln_id": "V-270565",
	"stig_id": "O19C-00-014900",
	"severity": "CAT II",
	"rule_title": "If passwords are used for authentication, the Oracle Database must transmit only encrypted representations of passwords.",
	"status": status_r_o19c_00_014900,
}
status_r_o19c_00_014900 := "Not_a_Finding" if r_o19c_00_014900
status_r_o19c_00_014900 := "Open" if not r_o19c_00_014900

# O19C-00-015200 | V-270566 | CAT I
default r_o19c_00_015200 := false
r_o19c_00_015200 if {
	input.oracle.attest.pki_private_key_access_restricted == true
}

finding_r_o19c_00_015200 := {
	"vuln_id": "V-270566",
	"stig_id": "O19C-00-015200",
	"severity": "CAT I",
	"rule_title": "Oracle Database, when using public key infrastructure (PKI)-based authentication, must enforce authorized access to the corresponding private key.",
	"status": status_r_o19c_00_015200,
}
status_r_o19c_00_015200 := "Not_a_Finding" if r_o19c_00_015200
status_r_o19c_00_015200 := "Open" if not r_o19c_00_015200

# O19C-00-015300 | V-270567 | CAT II
default r_o19c_00_015300 := false
r_o19c_00_015300 if {
	input.oracle.attest.pki_identity_mapped_to_accounts == true
}

finding_r_o19c_00_015300 := {
	"vuln_id": "V-270567",
	"stig_id": "O19C-00-015300",
	"severity": "CAT II",
	"rule_title": "Oracle Database must map the authenticated identity to the user account using public key infrastructure (PKI)-based authentication.",
	"status": status_r_o19c_00_015300,
}
status_r_o19c_00_015300 := "Not_a_Finding" if r_o19c_00_015300
status_r_o19c_00_015300 := "Open" if not r_o19c_00_015300

# O19C-00-015400 | V-270568 | CAT I
default r_o19c_00_015400 := false
r_o19c_00_015400 if {
	input.oracle.attest.cli_plaintext_password_tools_mitigated_and_approved == true
}

finding_r_o19c_00_015400 := {
	"vuln_id": "V-270568",
	"stig_id": "O19C-00-015400",
	"severity": "CAT I",
	"rule_title": "When using command-line tools such as Oracle SQL*Plus, which can accept a plain-text password, users must use an alternative logon method that does not expose the password.",
	"status": status_r_o19c_00_015400,
}
status_r_o19c_00_015400 := "Not_a_Finding" if r_o19c_00_015400
status_r_o19c_00_015400 := "Open" if not r_o19c_00_015400

# O19C-00-015500 | V-270569 | CAT I
default r_o19c_00_015500 := false
r_o19c_00_015500 if {
	lower(input.oracle.parameters["dbfips_140"]) == "true"
}

finding_r_o19c_00_015500 := {
	"vuln_id": "V-270569",
	"stig_id": "O19C-00-015500",
	"severity": "CAT I",
	"rule_title": "Oracle Database must use NIST-validated FIPS 140-2/140-3 compliant cryptography for authentication mechanisms.",
	"status": status_r_o19c_00_015500,
}
status_r_o19c_00_015500 := "Not_a_Finding" if r_o19c_00_015500
status_r_o19c_00_015500 := "Open" if not r_o19c_00_015500

# O19C-00-015600 | V-270570 | CAT II
default r_o19c_00_015600 := false
r_o19c_00_015600 if {
	input.oracle.attest.nonorganizational_users_uniquely_identified == true
}

finding_r_o19c_00_015600 := {
	"vuln_id": "V-270570",
	"stig_id": "O19C-00-015600",
	"severity": "CAT II",
	"rule_title": "Oracle Database must uniquely identify and authenticate nonorganizational users (or processes acting on behalf of nonorganizational users).",
	"status": status_r_o19c_00_015600,
}
status_r_o19c_00_015600 := "Not_a_Finding" if r_o19c_00_015600
status_r_o19c_00_015600 := "Open" if not r_o19c_00_015600

# O19C-00-016000 | V-270571 | CAT I
default r_o19c_00_016000 := false
r_o19c_00_016000 if {
	lower(input.oracle.parameters["dbfips_140"]) == "true"
}

r_o19c_00_016000 if {
	input.oracle.attest.encryption_not_required == true
}

finding_r_o19c_00_016000 := {
	"vuln_id": "V-270571",
	"stig_id": "O19C-00-016000",
	"severity": "CAT I",
	"rule_title": "Oracle Database must implement NIST FIPS 140-2/140-3 validated cryptographic modules to protect unclassified information requiring confidentiality and cryptographic protection, in accordance with the data owner's require",
	"status": status_r_o19c_00_016000,
}
status_r_o19c_00_016000 := "Not_a_Finding" if r_o19c_00_016000
status_r_o19c_00_016000 := "Open" if not r_o19c_00_016000

# O19C-00-016100 | V-270572 | CAT II
default r_o19c_00_016100 := false
r_o19c_00_016100 if {
	input.oracle.attest.admin_functionality_separated_from_users == true
}

finding_r_o19c_00_016100 := {
	"vuln_id": "V-270572",
	"stig_id": "O19C-00-016100",
	"severity": "CAT II",
	"rule_title": "Oracle Database must separate user functionality (including user interface services) from database management functionality.",
	"status": status_r_o19c_00_016100,
}
status_r_o19c_00_016100 := "Not_a_Finding" if r_o19c_00_016100
status_r_o19c_00_016100 := "Open" if not r_o19c_00_016100

# O19C-00-016700 | V-270573 | CAT II
default r_o19c_00_016700 := false
r_o19c_00_016700 if {
	upper(input.oracle.log_mode) == "ARCHIVELOG"
}

finding_r_o19c_00_016700 := {
	"vuln_id": "V-270573",
	"stig_id": "O19C-00-016700",
	"severity": "CAT II",
	"rule_title": "Oracle Database must preserve any organization-defined system state information in the event of a system failure.",
	"status": status_r_o19c_00_016700,
}
status_r_o19c_00_016700 := "Not_a_Finding" if r_o19c_00_016700
status_r_o19c_00_016700 := "Open" if not r_o19c_00_016700

# O19C-00-016800 | V-270574 | CAT I
default r_o19c_00_016800 := false
r_o19c_00_016800 if {
	input.oracle.tde.enabled == true
}

r_o19c_00_016800 if {
	input.oracle.attest.data_at_rest_encryption_not_required == true
}

finding_r_o19c_00_016800 := {
	"vuln_id": "V-270574",
	"stig_id": "O19C-00-016800",
	"severity": "CAT I",
	"rule_title": "Oracle Database must take steps to protect data at rest and ensure confidentiality and integrity of application data.",
	"status": status_r_o19c_00_016800,
}
status_r_o19c_00_016800 := "Not_a_Finding" if r_o19c_00_016800
status_r_o19c_00_016800 := "Open" if not r_o19c_00_016800

# O19C-00-016900 | V-270575 | CAT I
default r_o19c_00_016900 := false
r_o19c_00_016900 if {
	input.oracle.tde.enabled == true
}

r_o19c_00_016900 if {
	input.oracle.attest.information_at_rest_integrity_protection_not_required == true
}

finding_r_o19c_00_016900 := {
	"vuln_id": "V-270575",
	"stig_id": "O19C-00-016900",
	"severity": "CAT I",
	"rule_title": "Oracle Database must implement cryptographic mechanisms to prevent unauthorized modification of organization-defined information at rest (to include, at a minimum, PII and classified information) on organization-defined ",
	"status": status_r_o19c_00_016900,
}
status_r_o19c_00_016900 := "Not_a_Finding" if r_o19c_00_016900
status_r_o19c_00_016900 := "Open" if not r_o19c_00_016900

# O19C-00-017100 | V-270576 | CAT II
default r_o19c_00_017100 := false
r_o19c_00_017100 if {
	input.oracle.attest.security_functions_isolated == true
}

finding_r_o19c_00_017100 := {
	"vuln_id": "V-270576",
	"stig_id": "O19C-00-017100",
	"severity": "CAT II",
	"rule_title": "Oracle Database must isolate security functions from nonsecurity functions by means of separate security domains.",
	"status": status_r_o19c_00_017100,
}
status_r_o19c_00_017100 := "Not_a_Finding" if r_o19c_00_017100
status_r_o19c_00_017100 := "Open" if not r_o19c_00_017100

# O19C-00-017400 | V-270577 | CAT II
default r_o19c_00_017400 := false
r_o19c_00_017400 if {
	input.oracle.attest.production_data_transfer_controlled == true
}

finding_r_o19c_00_017400 := {
	"vuln_id": "V-270577",
	"stig_id": "O19C-00-017400",
	"severity": "CAT II",
	"rule_title": "Oracle Database contents must be protected from unauthorized and unintended information transfer by enforcement of a data-transfer policy.",
	"status": status_r_o19c_00_017400,
}
status_r_o19c_00_017400 := "Not_a_Finding" if r_o19c_00_017400
status_r_o19c_00_017400 := "Open" if not r_o19c_00_017400

# O19C-00-017600 | V-270578 | CAT II
default r_o19c_00_017600 := false
r_o19c_00_017600 if {
	input.oracle.filesystem.database_files_world_accessible == false
}

finding_r_o19c_00_017600 := {
	"vuln_id": "V-270578",
	"stig_id": "O19C-00-017600",
	"severity": "CAT II",
	"rule_title": "Access to Oracle Database files must be limited to relevant processes and to authorized, administrative users.",
	"status": status_r_o19c_00_017600,
}
status_r_o19c_00_017600 := "Not_a_Finding" if r_o19c_00_017600
status_r_o19c_00_017600 := "Open" if not r_o19c_00_017600

# O19C-00-017700 | V-270579 | CAT I
default r_o19c_00_017700 := false
r_o19c_00_017700 if {
	input.oracle.network.tls_or_native_encryption_required == true
}

finding_r_o19c_00_017700 := {
	"vuln_id": "V-270579",
	"stig_id": "O19C-00-017700",
	"severity": "CAT I",
	"rule_title": "Oracle Database must employ cryptographic mechanisms preventing the unauthorized disclosure of information during transmission unless the transmitted data is otherwise protected by alternative physical measures.",
	"status": status_r_o19c_00_017700,
}
status_r_o19c_00_017700 := "Not_a_Finding" if r_o19c_00_017700
status_r_o19c_00_017700 := "Open" if not r_o19c_00_017700

# O19C-00-017900 | V-270580 | CAT II
default r_o19c_00_017900 := false
r_o19c_00_017900 if {
	input.oracle.attest.input_validation_implemented == true
}

finding_r_o19c_00_017900 := {
	"vuln_id": "V-270580",
	"stig_id": "O19C-00-017900",
	"severity": "CAT II",
	"rule_title": "Oracle Database must check the validity of data inputs.",
	"status": status_r_o19c_00_017900,
}
status_r_o19c_00_017900 := "Not_a_Finding" if r_o19c_00_017900
status_r_o19c_00_017900 := "Open" if not r_o19c_00_017900

# O19C-00-018000 | V-270581 | CAT II
default r_o19c_00_018000 := false
r_o19c_00_018000 if {
	input.oracle.attest.dynamic_code_execution_justified == true
}

finding_r_o19c_00_018000 := {
	"vuln_id": "V-270581",
	"stig_id": "O19C-00-018000",
	"severity": "CAT II",
	"rule_title": "The database management system (DBMS) and associated applications must reserve the use of dynamic code execution for situations that require it.",
	"status": status_r_o19c_00_018000,
}
status_r_o19c_00_018000 := "Not_a_Finding" if r_o19c_00_018000
status_r_o19c_00_018000 := "Open" if not r_o19c_00_018000

# O19C-00-018100 | V-270582 | CAT II
default r_o19c_00_018100 := false
r_o19c_00_018100 if {
	input.oracle.attest.dynamic_code_injection_protected == true
}

finding_r_o19c_00_018100 := {
	"vuln_id": "V-270582",
	"stig_id": "O19C-00-018100",
	"severity": "CAT II",
	"rule_title": "The database management system (DBMS) and associated applications, when making use of dynamic code execution, must take steps against invalid values that may be used in a SQL injection attack, therefore resulting in step",
	"status": status_r_o19c_00_018100,
}
status_r_o19c_00_018100 := "Not_a_Finding" if r_o19c_00_018100
status_r_o19c_00_018100 := "Open" if not r_o19c_00_018100

# O19C-00-018300 | V-270583 | CAT II
default r_o19c_00_018300 := false
r_o19c_00_018300 if {
	input.oracle.attest.error_messages_minimal == true
}

finding_r_o19c_00_018300 := {
	"vuln_id": "V-270583",
	"stig_id": "O19C-00-018300",
	"severity": "CAT II",
	"rule_title": "Oracle Database must only generate error messages that provide information necessary for corrective actions without revealing organization-defined sensitive or potentially harmful information in error logs and administra",
	"status": status_r_o19c_00_018300,
}
status_r_o19c_00_018300 := "Not_a_Finding" if r_o19c_00_018300
status_r_o19c_00_018300 := "Open" if not r_o19c_00_018300

# O19C-00-018400 | V-270584 | CAT II
default r_o19c_00_018400 := false
r_o19c_00_018400 if {
	input.oracle.attest.error_messages_restricted_to_authorized_personnel == true
}

finding_r_o19c_00_018400 := {
	"vuln_id": "V-270584",
	"stig_id": "O19C-00-018400",
	"severity": "CAT II",
	"rule_title": "Oracle Database must restrict error messages so only authorized personnel may view them.",
	"status": status_r_o19c_00_018400,
}
status_r_o19c_00_018400 := "Not_a_Finding" if r_o19c_00_018400
status_r_o19c_00_018400 := "Open" if not r_o19c_00_018400

# O19C-00-018600 | V-270585 | CAT I
default r_o19c_00_018600 := false
r_o19c_00_018600 if {
	input.oracle.patches.latest_cpu_applied == true
}

finding_r_o19c_00_018600 := {
	"vuln_id": "V-270585",
	"stig_id": "O19C-00-018600",
	"severity": "CAT I",
	"rule_title": "Oracle Database software must be evaluated and patched against newly found vulnerabilities.",
	"status": status_r_o19c_00_018600,
}
status_r_o19c_00_018600 := "Not_a_Finding" if r_o19c_00_018600
status_r_o19c_00_018600 := "Open" if not r_o19c_00_018600

# O19C-00-019800 | V-270587 | CAT II
default r_o19c_00_019800 := false
r_o19c_00_019800 if {
	input.oracle.attest.compromised_password_list_checked == true
}

finding_r_o19c_00_019800 := {
	"vuln_id": "V-270587",
	"stig_id": "O19C-00-019800",
	"severity": "CAT II",
	"rule_title": "Oracle Database must, for password-based authentication, verify that when users create or update passwords, the passwords are not found on the list of commonly used, expected, or compromised passwords in IA-5 (1) (a).",
	"status": status_r_o19c_00_019800,
}
status_r_o19c_00_019800 := "Not_a_Finding" if r_o19c_00_019800
status_r_o19c_00_019800 := "Open" if not r_o19c_00_019800

# O19C-00-019900 | V-270588 | CAT II
default r_o19c_00_019900 := false
r_o19c_00_019900 if {
	input.oracle.attest.password_change_required_on_account_recovery == true
}

finding_r_o19c_00_019900 := {
	"vuln_id": "V-270588",
	"stig_id": "O19C-00-019900",
	"severity": "CAT II",
	"rule_title": "Oracle Database must, for password-based authentication, require immediate selection of a new password upon account recovery.",
	"status": status_r_o19c_00_019900,
}
status_r_o19c_00_019900 := "Not_a_Finding" if r_o19c_00_019900
status_r_o19c_00_019900 := "Open" if not r_o19c_00_019900

# O19C-00-020400 | V-270589 | CAT II
default r_o19c_00_020400 := false
r_o19c_00_020400 if {
	input.oracle.attest.trust_store_contains_only_approved_anchors == true
}

finding_r_o19c_00_020400 := {
	"vuln_id": "V-270589",
	"stig_id": "O19C-00-020400",
	"severity": "CAT II",
	"rule_title": "Oracle Database must include only approved trust anchors in trust stores or certificate stores managed by the organization.",
	"status": status_r_o19c_00_020400,
}
status_r_o19c_00_020400 := "Not_a_Finding" if r_o19c_00_020400
status_r_o19c_00_020400 := "Open" if not r_o19c_00_020400

# O19C-00-020500 | V-275999 | CAT II
default r_o19c_00_020500 := false
r_o19c_00_020500 if {
	count(input.oracle.control_files) >= 3
}

finding_r_o19c_00_020500 := {
	"vuln_id": "V-275999",
	"stig_id": "O19C-00-020500",
	"severity": "CAT II",
	"rule_title": "A minimum of three Oracle Control Files must be created and each stored on a separate physical and logical device.",
	"status": status_r_o19c_00_020500,
}
status_r_o19c_00_020500 := "Not_a_Finding" if r_o19c_00_020500
status_r_o19c_00_020500 := "Open" if not r_o19c_00_020500

# O19C-00-020600 | V-276000 | CAT II
default r_o19c_00_020600 := false
r_o19c_00_020600 if {
	count(input.oracle.redo_log_groups) >= 3
	every g in input.oracle.redo_log_groups { count(g.members) >= 2 }
}

finding_r_o19c_00_020600 := {
	"vuln_id": "V-276000",
	"stig_id": "O19C-00-020600",
	"severity": "CAT II",
	"rule_title": "A minimum of three Oracle redo log groups/files must be defined and configured to be stored on separate, archived physical disks or archived directories on a RAID device. In addition, each Oracle redo log group must have",
	"status": status_r_o19c_00_020600,
}
status_r_o19c_00_020600 := "Not_a_Finding" if r_o19c_00_020600
status_r_o19c_00_020600 := "Open" if not r_o19c_00_020600

findings := [
	finding_r_o19c_00_000100,
	finding_r_o19c_00_000200,
	finding_r_o19c_00_000300,
	finding_r_o19c_00_000500,
	finding_r_o19c_00_000800,
	finding_r_o19c_00_001000,
	finding_r_o19c_00_001700,
	finding_r_o19c_00_001800,
	finding_r_o19c_00_001900,
	finding_r_o19c_00_002000,
	finding_r_o19c_00_005600,
	finding_r_o19c_00_005700,
	finding_r_o19c_00_005800,
	finding_r_o19c_00_005900,
	finding_r_o19c_00_006000,
	finding_r_o19c_00_006600,
	finding_r_o19c_00_006900,
	finding_r_o19c_00_007300,
	finding_r_o19c_00_007400,
	finding_r_o19c_00_007700,
	finding_r_o19c_00_007900,
	finding_r_o19c_00_008000,
	finding_r_o19c_00_008100,
	finding_r_o19c_00_008200,
	finding_r_o19c_00_008300,
	finding_r_o19c_00_008400,
	finding_r_o19c_00_008600,
	finding_r_o19c_00_008700,
	finding_r_o19c_00_009000,
	finding_r_o19c_00_009200,
	finding_r_o19c_00_009300,
	finding_r_o19c_00_009400,
	finding_r_o19c_00_009500,
	finding_r_o19c_00_009600,
	finding_r_o19c_00_009700,
	finding_r_o19c_00_009800,
	finding_r_o19c_00_009900,
	finding_r_o19c_00_010000,
	finding_r_o19c_00_010100,
	finding_r_o19c_00_010400,
	finding_r_o19c_00_010500,
	finding_r_o19c_00_010600,
	finding_r_o19c_00_010700,
	finding_r_o19c_00_010800,
	finding_r_o19c_00_011200,
	finding_r_o19c_00_011300,
	finding_r_o19c_00_011500,
	finding_r_o19c_00_011600,
	finding_r_o19c_00_011700,
	finding_r_o19c_00_011800,
	finding_r_o19c_00_011900,
	finding_r_o19c_00_012000,
	finding_r_o19c_00_012100,
	finding_r_o19c_00_012200,
	finding_r_o19c_00_012300,
	finding_r_o19c_00_012400,
	finding_r_o19c_00_012500,
	finding_r_o19c_00_012900,
	finding_r_o19c_00_013000,
	finding_r_o19c_00_013100,
	finding_r_o19c_00_013200,
	finding_r_o19c_00_013300,
	finding_r_o19c_00_013400,
	finding_r_o19c_00_013500,
	finding_r_o19c_00_013700,
	finding_r_o19c_00_013800,
	finding_r_o19c_00_013900,
	finding_r_o19c_00_014600,
	finding_r_o19c_00_014700,
	finding_r_o19c_00_014800,
	finding_r_o19c_00_014900,
	finding_r_o19c_00_015200,
	finding_r_o19c_00_015300,
	finding_r_o19c_00_015400,
	finding_r_o19c_00_015500,
	finding_r_o19c_00_015600,
	finding_r_o19c_00_016000,
	finding_r_o19c_00_016100,
	finding_r_o19c_00_016700,
	finding_r_o19c_00_016800,
	finding_r_o19c_00_016900,
	finding_r_o19c_00_017100,
	finding_r_o19c_00_017400,
	finding_r_o19c_00_017600,
	finding_r_o19c_00_017700,
	finding_r_o19c_00_017900,
	finding_r_o19c_00_018000,
	finding_r_o19c_00_018100,
	finding_r_o19c_00_018300,
	finding_r_o19c_00_018400,
	finding_r_o19c_00_018600,
	finding_r_o19c_00_019800,
	finding_r_o19c_00_019900,
	finding_r_o19c_00_020400,
	finding_r_o19c_00_020500,
	finding_r_o19c_00_020600,
]

default compliant := false

compliant if count([f | some f in findings; f.status == "Open"]) == 0
