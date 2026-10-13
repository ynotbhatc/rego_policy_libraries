# METADATA
# title: "DISA STIG — Oracle MySQL 8.0 Security Technical Implementation Guide"
# custom:
#   class: security
#   framework: stig_oracle_mysql_8
#   source: disa
#   domains: [database, mysql]
#   coverage:
#     checks: 100
#     cited: 100
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: none
#     guard: n/a
#     as_of: v2.4.0
package stig.oracle_mysql_8.core

# DISA STIG — Oracle MySQL 8.0 Security Technical Implementation Guide
# V2R3 | Release: 3 Benchmark Date: 30 Sep 2026
# 100 rules — every rule in the catalog; 35 are attestation-only (DISA's check is a
# documentation or procedure review). IDs/severities/titles verified against the October 2026
# SRG-STIG library XCCDF on 2026-10-13 (tools/stig_generators/gen_oracle_db.py).
# Organizational rules are explicit attestation booleans — named for what
# a human verified, never silently passed. Input contract:
#   input.mysql.variables[<name>]  : performance_schema.global_variables / SHOW VARIABLES (name lowercase)
#   input.mysql.plugins[<name>]    : INFORMATION_SCHEMA.PLUGINS status
#   input.mysql.audit.*            : audit_log filters and startup mode
#   input.mysql.users[]            : mysql.user rows {user, host, plugin}
#   input.mysql.<query result>     : rows the STIG query must not return (lists), flags
#   input.mysql.attest.*           : attestation booleans (documented reviews)

import rego.v1

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

# MYS8-00-000100 | V-235095 | CAT I
default r_mys8_00_000100 := false
r_mys8_00_000100 if {
	external_auth_plugin_active
}

r_mys8_00_000100 if {
	input.mysql.attest.org_level_auth_integrated == true
}

finding_r_mys8_00_000100 := {
	"vuln_id": "V-235095",
	"stig_id": "MYS8-00-000100",
	"severity": "CAT I",
	"rule_title": "MySQL Database Server 8.0 must integrate with an organization-level authentication/access mechanism providing account management and automation for all users, groups, roles, and any other principals.",
	"status": status_r_mys8_00_000100,
}
status_r_mys8_00_000100 := "Not_a_Finding" if r_mys8_00_000100
status_r_mys8_00_000100 := "Open" if not r_mys8_00_000100

# MYS8-00-000200 | V-235096 | CAT II
default r_mys8_00_000200 := false
r_mys8_00_000200 if {
	to_number(input.mysql.variables["max_user_connections"]) > 0
}

finding_r_mys8_00_000200 := {
	"vuln_id": "V-235096",
	"stig_id": "MYS8-00-000200",
	"severity": "CAT II",
	"rule_title": "MySQL Database Server 8.0 must limit the number of concurrent sessions to an organization-defined number per user for all accounts and/or account types.",
	"status": status_r_mys8_00_000200,
}
status_r_mys8_00_000200 := "Not_a_Finding" if r_mys8_00_000200
status_r_mys8_00_000200 := "Open" if not r_mys8_00_000200

# MYS8-00-000300 | V-235097 | CAT II
default r_mys8_00_000300 := false
r_mys8_00_000300 if {
	audit_configured
}

finding_r_mys8_00_000300 := {
	"vuln_id": "V-235097",
	"stig_id": "MYS8-00-000300",
	"severity": "CAT II",
	"rule_title": "MySQL Database Server 8.0 must produce audit records containing sufficient information to establish what type of events occurred.",
	"status": status_r_mys8_00_000300,
}
status_r_mys8_00_000300 := "Not_a_Finding" if r_mys8_00_000300
status_r_mys8_00_000300 := "Open" if not r_mys8_00_000300

# MYS8-00-000800 | V-235098 | CAT II
default r_mys8_00_000800 := false
r_mys8_00_000800 if {
	audit_configured
}

finding_r_mys8_00_000800 := {
	"vuln_id": "V-235098",
	"stig_id": "MYS8-00-000800",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must include additional, more detailed, organizationally defined information in the audit records for audit events identified by type, location, or subject.",
	"status": status_r_mys8_00_000800,
}
status_r_mys8_00_000800 := "Not_a_Finding" if r_mys8_00_000800
status_r_mys8_00_000800 := "Open" if not r_mys8_00_000800

# MYS8-00-001200 | V-235099 | CAT II
default r_mys8_00_001200 := false
r_mys8_00_001200 if {
	input.mysql.filesystem.audit_log_permissions_restricted == true
}

finding_r_mys8_00_001200 := {
	"vuln_id": "V-235099",
	"stig_id": "MYS8-00-001200",
	"severity": "CAT II",
	"rule_title": "The audit information produced by the MySQL Database Server 8.0 must be protected from unauthorized read access.",
	"status": status_r_mys8_00_001200,
}
status_r_mys8_00_001200 := "Not_a_Finding" if r_mys8_00_001200
status_r_mys8_00_001200 := "Open" if not r_mys8_00_001200

# MYS8-00-001300 | V-235100 | CAT II
default r_mys8_00_001300 := false
r_mys8_00_001300 if {
	input.mysql.filesystem.audit_log_permissions_restricted == true
}

finding_r_mys8_00_001300 := {
	"vuln_id": "V-235100",
	"stig_id": "MYS8-00-001300",
	"severity": "CAT II",
	"rule_title": "The audit information produced by the MySQL Database Server 8.0 must be protected from unauthorized modification.",
	"status": status_r_mys8_00_001300,
}
status_r_mys8_00_001300 := "Not_a_Finding" if r_mys8_00_001300
status_r_mys8_00_001300 := "Open" if not r_mys8_00_001300

# MYS8-00-001400 | V-235101 | CAT II
default r_mys8_00_001400 := false
r_mys8_00_001400 if {
	input.mysql.filesystem.audit_log_permissions_restricted == true
}

finding_r_mys8_00_001400 := {
	"vuln_id": "V-235101",
	"stig_id": "MYS8-00-001400",
	"severity": "CAT II",
	"rule_title": "The audit information produced by the MySQL Database Server 8.0 must be protected from unauthorized deletion.",
	"status": status_r_mys8_00_001400,
}
status_r_mys8_00_001400 := "Not_a_Finding" if r_mys8_00_001400
status_r_mys8_00_001400 := "Open" if not r_mys8_00_001400

# MYS8-00-001500 | V-235102 | CAT II
default r_mys8_00_001500 := false
r_mys8_00_001500 if {
	input.mysql.attest.no_shared_accounts_or_individually_identified == true
}

finding_r_mys8_00_001500 := {
	"vuln_id": "V-235102",
	"stig_id": "MYS8-00-001500",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must protect against a user falsely repudiating having performed organization-defined actions.",
	"status": status_r_mys8_00_001500,
}
status_r_mys8_00_001500 := "Not_a_Finding" if r_mys8_00_001500
status_r_mys8_00_001500 := "Open" if not r_mys8_00_001500

# MYS8-00-001600 | V-235103 | CAT II
default r_mys8_00_001600 := false
r_mys8_00_001600 if {
	audit_configured
}

finding_r_mys8_00_001600 := {
	"vuln_id": "V-235103",
	"stig_id": "MYS8-00-001600",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must be configured to provide audit record generation capability for DoW-defined auditable events within all database components.",
	"status": status_r_mys8_00_001600,
}
status_r_mys8_00_001600 := "Not_a_Finding" if r_mys8_00_001600
status_r_mys8_00_001600 := "Open" if not r_mys8_00_001600

# MYS8-00-001700 | V-235104 | CAT II
default r_mys8_00_001700 := false
r_mys8_00_001700 if {
	count(input.mysql.unauthorized_audit_admins) == 0
}

finding_r_mys8_00_001700 := {
	"vuln_id": "V-235104",
	"stig_id": "MYS8-00-001700",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must allow only the Information System Security Manager (ISSM) (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited.",
	"status": status_r_mys8_00_001700,
}
status_r_mys8_00_001700 := "Not_a_Finding" if r_mys8_00_001700
status_r_mys8_00_001700 := "Open" if not r_mys8_00_001700

# MYS8-00-001800 | V-235105 | CAT II
default r_mys8_00_001800 := false
r_mys8_00_001800 if {
	audit_configured
}

finding_r_mys8_00_001800 := {
	"vuln_id": "V-235105",
	"stig_id": "MYS8-00-001800",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must be able to generate audit records when privileges/permissions are retrieved.",
	"status": status_r_mys8_00_001800,
}
status_r_mys8_00_001800 := "Not_a_Finding" if r_mys8_00_001800
status_r_mys8_00_001800 := "Open" if not r_mys8_00_001800

# MYS8-00-001900 | V-235106 | CAT II
default r_mys8_00_001900 := false
r_mys8_00_001900 if {
	audit_configured
}

finding_r_mys8_00_001900 := {
	"vuln_id": "V-235106",
	"stig_id": "MYS8-00-001900",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must be able to generate audit records when unsuccessful attempts to retrieve privileges/permissions occur.",
	"status": status_r_mys8_00_001900,
}
status_r_mys8_00_001900 := "Not_a_Finding" if r_mys8_00_001900
status_r_mys8_00_001900 := "Open" if not r_mys8_00_001900

# MYS8-00-002000 | V-235107 | CAT II
default r_mys8_00_002000 := false
r_mys8_00_002000 if {
	audit_configured
}

finding_r_mys8_00_002000 := {
	"vuln_id": "V-235107",
	"stig_id": "MYS8-00-002000",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must be able to generate audit records when security objects are accessed.",
	"status": status_r_mys8_00_002000,
}
status_r_mys8_00_002000 := "Not_a_Finding" if r_mys8_00_002000
status_r_mys8_00_002000 := "Open" if not r_mys8_00_002000

# MYS8-00-002100 | V-235108 | CAT II
default r_mys8_00_002100 := false
r_mys8_00_002100 if {
	audit_configured
}

finding_r_mys8_00_002100 := {
	"vuln_id": "V-235108",
	"stig_id": "MYS8-00-002100",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must generate audit records when unsuccessful attempts to access security objects occur.",
	"status": status_r_mys8_00_002100,
}
status_r_mys8_00_002100 := "Not_a_Finding" if r_mys8_00_002100
status_r_mys8_00_002100 := "Open" if not r_mys8_00_002100

# MYS8-00-002200 | V-235109 | CAT II
default r_mys8_00_002200 := false
r_mys8_00_002200 if {
	audit_configured
}

finding_r_mys8_00_002200 := {
	"vuln_id": "V-235109",
	"stig_id": "MYS8-00-002200",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must generate audit records when categories of information (e.g., classification levels/security levels) are accessed.",
	"status": status_r_mys8_00_002200,
}
status_r_mys8_00_002200 := "Not_a_Finding" if r_mys8_00_002200
status_r_mys8_00_002200 := "Open" if not r_mys8_00_002200

# MYS8-00-002300 | V-235110 | CAT II
default r_mys8_00_002300 := false
r_mys8_00_002300 if {
	audit_configured
}

finding_r_mys8_00_002300 := {
	"vuln_id": "V-235110",
	"stig_id": "MYS8-00-002300",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must generate audit records when unsuccessful attempts to access categories of information (e.g., classification levels/security levels) occur.",
	"status": status_r_mys8_00_002300,
}
status_r_mys8_00_002300 := "Not_a_Finding" if r_mys8_00_002300
status_r_mys8_00_002300 := "Open" if not r_mys8_00_002300

# MYS8-00-002400 | V-235111 | CAT II
default r_mys8_00_002400 := false
r_mys8_00_002400 if {
	audit_configured
}

finding_r_mys8_00_002400 := {
	"vuln_id": "V-235111",
	"stig_id": "MYS8-00-002400",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must generate audit records when privileges/permissions are added.",
	"status": status_r_mys8_00_002400,
}
status_r_mys8_00_002400 := "Not_a_Finding" if r_mys8_00_002400
status_r_mys8_00_002400 := "Open" if not r_mys8_00_002400

# MYS8-00-002500 | V-235112 | CAT II
default r_mys8_00_002500 := false
r_mys8_00_002500 if {
	audit_configured
}

finding_r_mys8_00_002500 := {
	"vuln_id": "V-235112",
	"stig_id": "MYS8-00-002500",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must generate audit records when unsuccessful attempts to add privileges/permissions occur.",
	"status": status_r_mys8_00_002500,
}
status_r_mys8_00_002500 := "Not_a_Finding" if r_mys8_00_002500
status_r_mys8_00_002500 := "Open" if not r_mys8_00_002500

# MYS8-00-002600 | V-235113 | CAT II
default r_mys8_00_002600 := false
r_mys8_00_002600 if {
	audit_configured
}

finding_r_mys8_00_002600 := {
	"vuln_id": "V-235113",
	"stig_id": "MYS8-00-002600",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must generate audit records when privileges/permissions are modified.",
	"status": status_r_mys8_00_002600,
}
status_r_mys8_00_002600 := "Not_a_Finding" if r_mys8_00_002600
status_r_mys8_00_002600 := "Open" if not r_mys8_00_002600

# MYS8-00-002700 | V-235114 | CAT II
default r_mys8_00_002700 := false
r_mys8_00_002700 if {
	audit_configured
}

finding_r_mys8_00_002700 := {
	"vuln_id": "V-235114",
	"stig_id": "MYS8-00-002700",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must generate audit records when unsuccessful attempts to modify privileges/permissions occur.",
	"status": status_r_mys8_00_002700,
}
status_r_mys8_00_002700 := "Not_a_Finding" if r_mys8_00_002700
status_r_mys8_00_002700 := "Open" if not r_mys8_00_002700

# MYS8-00-002800 | V-235115 | CAT II
default r_mys8_00_002800 := false
r_mys8_00_002800 if {
	audit_configured
}

finding_r_mys8_00_002800 := {
	"vuln_id": "V-235115",
	"stig_id": "MYS8-00-002800",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must generate audit records when security objects are modified.",
	"status": status_r_mys8_00_002800,
}
status_r_mys8_00_002800 := "Not_a_Finding" if r_mys8_00_002800
status_r_mys8_00_002800 := "Open" if not r_mys8_00_002800

# MYS8-00-002900 | V-235116 | CAT II
default r_mys8_00_002900 := false
r_mys8_00_002900 if {
	audit_configured
}

finding_r_mys8_00_002900 := {
	"vuln_id": "V-235116",
	"stig_id": "MYS8-00-002900",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must generate audit records when unsuccessful attempts to modify security objects occur.",
	"status": status_r_mys8_00_002900,
}
status_r_mys8_00_002900 := "Not_a_Finding" if r_mys8_00_002900
status_r_mys8_00_002900 := "Open" if not r_mys8_00_002900

# MYS8-00-003000 | V-235117 | CAT II
default r_mys8_00_003000 := false
r_mys8_00_003000 if {
	audit_configured
}

finding_r_mys8_00_003000 := {
	"vuln_id": "V-235117",
	"stig_id": "MYS8-00-003000",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must generate audit records when categories of information (e.g., classification levels/security levels) are modified.",
	"status": status_r_mys8_00_003000,
}
status_r_mys8_00_003000 := "Not_a_Finding" if r_mys8_00_003000
status_r_mys8_00_003000 := "Open" if not r_mys8_00_003000

# MYS8-00-003100 | V-235118 | CAT II
default r_mys8_00_003100 := false
r_mys8_00_003100 if {
	audit_configured
}

finding_r_mys8_00_003100 := {
	"vuln_id": "V-235118",
	"stig_id": "MYS8-00-003100",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must generate audit records when unsuccessful attempts to modify categories of information (e.g., classification levels/security levels) occur.",
	"status": status_r_mys8_00_003100,
}
status_r_mys8_00_003100 := "Not_a_Finding" if r_mys8_00_003100
status_r_mys8_00_003100 := "Open" if not r_mys8_00_003100

# MYS8-00-003200 | V-235119 | CAT II
default r_mys8_00_003200 := false
r_mys8_00_003200 if {
	audit_configured
}

finding_r_mys8_00_003200 := {
	"vuln_id": "V-235119",
	"stig_id": "MYS8-00-003200",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must generate audit records when privileges/permissions are deleted.",
	"status": status_r_mys8_00_003200,
}
status_r_mys8_00_003200 := "Not_a_Finding" if r_mys8_00_003200
status_r_mys8_00_003200 := "Open" if not r_mys8_00_003200

# MYS8-00-003300 | V-235120 | CAT II
default r_mys8_00_003300 := false
r_mys8_00_003300 if {
	audit_configured
}

finding_r_mys8_00_003300 := {
	"vuln_id": "V-235120",
	"stig_id": "MYS8-00-003300",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must generate audit records when unsuccessful attempts to delete privileges/permissions occur.",
	"status": status_r_mys8_00_003300,
}
status_r_mys8_00_003300 := "Not_a_Finding" if r_mys8_00_003300
status_r_mys8_00_003300 := "Open" if not r_mys8_00_003300

# MYS8-00-003400 | V-235121 | CAT II
default r_mys8_00_003400 := false
r_mys8_00_003400 if {
	audit_configured
}

finding_r_mys8_00_003400 := {
	"vuln_id": "V-235121",
	"stig_id": "MYS8-00-003400",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must generate audit records when security objects are deleted.",
	"status": status_r_mys8_00_003400,
}
status_r_mys8_00_003400 := "Not_a_Finding" if r_mys8_00_003400
status_r_mys8_00_003400 := "Open" if not r_mys8_00_003400

# MYS8-00-003500 | V-235122 | CAT II
default r_mys8_00_003500 := false
r_mys8_00_003500 if {
	audit_configured
}

finding_r_mys8_00_003500 := {
	"vuln_id": "V-235122",
	"stig_id": "MYS8-00-003500",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must generate audit records when unsuccessful attempts to delete security objects occur.",
	"status": status_r_mys8_00_003500,
}
status_r_mys8_00_003500 := "Not_a_Finding" if r_mys8_00_003500
status_r_mys8_00_003500 := "Open" if not r_mys8_00_003500

# MYS8-00-003600 | V-235123 | CAT II
default r_mys8_00_003600 := false
r_mys8_00_003600 if {
	audit_configured
}

finding_r_mys8_00_003600 := {
	"vuln_id": "V-235123",
	"stig_id": "MYS8-00-003600",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must generate audit records when categories of information (e.g., classification levels/security levels) are deleted.",
	"status": status_r_mys8_00_003600,
}
status_r_mys8_00_003600 := "Not_a_Finding" if r_mys8_00_003600
status_r_mys8_00_003600 := "Open" if not r_mys8_00_003600

# MYS8-00-003700 | V-235124 | CAT II
default r_mys8_00_003700 := false
r_mys8_00_003700 if {
	audit_configured
}

finding_r_mys8_00_003700 := {
	"vuln_id": "V-235124",
	"stig_id": "MYS8-00-003700",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must generate audit records when unsuccessful attempts to delete categories of information (e.g., classification levels/security levels) occur.",
	"status": status_r_mys8_00_003700,
}
status_r_mys8_00_003700 := "Not_a_Finding" if r_mys8_00_003700
status_r_mys8_00_003700 := "Open" if not r_mys8_00_003700

# MYS8-00-003800 | V-235125 | CAT II
default r_mys8_00_003800 := false
r_mys8_00_003800 if {
	audit_configured
}

finding_r_mys8_00_003800 := {
	"vuln_id": "V-235125",
	"stig_id": "MYS8-00-003800",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must generate audit records when successful logons or connections occur.",
	"status": status_r_mys8_00_003800,
}
status_r_mys8_00_003800 := "Not_a_Finding" if r_mys8_00_003800
status_r_mys8_00_003800 := "Open" if not r_mys8_00_003800

# MYS8-00-003900 | V-235126 | CAT II
default r_mys8_00_003900 := false
r_mys8_00_003900 if {
	audit_configured
}

finding_r_mys8_00_003900 := {
	"vuln_id": "V-235126",
	"stig_id": "MYS8-00-003900",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must generate audit records when unsuccessful logons or connection attempts occur.",
	"status": status_r_mys8_00_003900,
}
status_r_mys8_00_003900 := "Not_a_Finding" if r_mys8_00_003900
status_r_mys8_00_003900 := "Open" if not r_mys8_00_003900

# MYS8-00-004000 | V-235127 | CAT II
default r_mys8_00_004000 := false
r_mys8_00_004000 if {
	audit_configured
}

finding_r_mys8_00_004000 := {
	"vuln_id": "V-235127",
	"stig_id": "MYS8-00-004000",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must generate audit records for all privileged activities or other system-level access.",
	"status": status_r_mys8_00_004000,
}
status_r_mys8_00_004000 := "Not_a_Finding" if r_mys8_00_004000
status_r_mys8_00_004000 := "Open" if not r_mys8_00_004000

# MYS8-00-004100 | V-235128 | CAT II
default r_mys8_00_004100 := false
r_mys8_00_004100 if {
	audit_configured
}

finding_r_mys8_00_004100 := {
	"vuln_id": "V-235128",
	"stig_id": "MYS8-00-004100",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must generate audit records when unsuccessful attempts to execute privileged activities or other system-level access occur.",
	"status": status_r_mys8_00_004100,
}
status_r_mys8_00_004100 := "Not_a_Finding" if r_mys8_00_004100
status_r_mys8_00_004100 := "Open" if not r_mys8_00_004100

# MYS8-00-004200 | V-235129 | CAT II
default r_mys8_00_004200 := false
r_mys8_00_004200 if {
	audit_configured
}

finding_r_mys8_00_004200 := {
	"vuln_id": "V-235129",
	"stig_id": "MYS8-00-004200",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must generate audit records showing starting and ending time for user access to the database(s).",
	"status": status_r_mys8_00_004200,
}
status_r_mys8_00_004200 := "Not_a_Finding" if r_mys8_00_004200
status_r_mys8_00_004200 := "Open" if not r_mys8_00_004200

# MYS8-00-004300 | V-235130 | CAT II
default r_mys8_00_004300 := false
r_mys8_00_004300 if {
	audit_configured
}

finding_r_mys8_00_004300 := {
	"vuln_id": "V-235130",
	"stig_id": "MYS8-00-004300",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must generate audit records when concurrent logons/connections by the same user from different workstations.",
	"status": status_r_mys8_00_004300,
}
status_r_mys8_00_004300 := "Not_a_Finding" if r_mys8_00_004300
status_r_mys8_00_004300 := "Open" if not r_mys8_00_004300

# MYS8-00-004400 | V-235131 | CAT II
default r_mys8_00_004400 := false
r_mys8_00_004400 if {
	audit_configured
}

finding_r_mys8_00_004400 := {
	"vuln_id": "V-235131",
	"stig_id": "MYS8-00-004400",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must be able to generate audit records when successful accesses to objects occur.",
	"status": status_r_mys8_00_004400,
}
status_r_mys8_00_004400 := "Not_a_Finding" if r_mys8_00_004400
status_r_mys8_00_004400 := "Open" if not r_mys8_00_004400

# MYS8-00-004500 | V-235132 | CAT II
default r_mys8_00_004500 := false
r_mys8_00_004500 if {
	audit_configured
}

finding_r_mys8_00_004500 := {
	"vuln_id": "V-235132",
	"stig_id": "MYS8-00-004500",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must generate audit records when unsuccessful accesses to objects occur.",
	"status": status_r_mys8_00_004500,
}
status_r_mys8_00_004500 := "Not_a_Finding" if r_mys8_00_004500
status_r_mys8_00_004500 := "Open" if not r_mys8_00_004500

# MYS8-00-004600 | V-235133 | CAT II
default r_mys8_00_004600 := false
r_mys8_00_004600 if {
	audit_configured
}

finding_r_mys8_00_004600 := {
	"vuln_id": "V-235133",
	"stig_id": "MYS8-00-004600",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must generate audit records for all direct access to the database(s).",
	"status": status_r_mys8_00_004600,
}
status_r_mys8_00_004600 := "Not_a_Finding" if r_mys8_00_004600
status_r_mys8_00_004600 := "Open" if not r_mys8_00_004600

# MYS8-00-004700 | V-235134 | CAT II
default r_mys8_00_004700 := false
r_mys8_00_004700 if {
	input.mysql.attest.pki_certificate_path_and_revocation_validated == true
}

finding_r_mys8_00_004700 := {
	"vuln_id": "V-235134",
	"stig_id": "MYS8-00-004700",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0, when utilizing PKI-based authentication, must validate certificates by performing RFC 5280-compliant certification path validation.",
	"status": status_r_mys8_00_004700,
}
status_r_mys8_00_004700 := "Not_a_Finding" if r_mys8_00_004700
status_r_mys8_00_004700 := "Open" if not r_mys8_00_004700

# MYS8-00-004800 | V-235135 | CAT I
default r_mys8_00_004800 := false
r_mys8_00_004800 if {
	input.mysql.filesystem.ssl_key_permissions_restricted == true
}

finding_r_mys8_00_004800 := {
	"vuln_id": "V-235135",
	"stig_id": "MYS8-00-004800",
	"severity": "CAT I",
	"rule_title": "The MySQL Database Server 8.0 must enforce authorized access to all PKI private keys stored/utilized by the MySQL Database Server 8.0.",
	"status": status_r_mys8_00_004800,
}
status_r_mys8_00_004800 := "Not_a_Finding" if r_mys8_00_004800
status_r_mys8_00_004800 := "Open" if not r_mys8_00_004800

# MYS8-00-004900 | V-235136 | CAT II
default r_mys8_00_004900 := false
r_mys8_00_004900 if {
	input.mysql.attest.pki_identity_mapped_to_accounts == true
}

finding_r_mys8_00_004900 := {
	"vuln_id": "V-235136",
	"stig_id": "MYS8-00-004900",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must map the PKI-authenticated identity to an associated user account.",
	"status": status_r_mys8_00_004900,
}
status_r_mys8_00_004900 := "Not_a_Finding" if r_mys8_00_004900
status_r_mys8_00_004900 := "Open" if not r_mys8_00_004900

# MYS8-00-005000 | V-235137 | CAT I
default r_mys8_00_005000 := false
r_mys8_00_005000 if {
	upper(input.mysql.plugins["validate_password"]) == "ACTIVE"
	to_number(input.mysql.variables["validate_password.length"]) >= 15
	upper(input.mysql.variables["validate_password.policy"]) in {"MEDIUM", "STRONG"}
}

finding_r_mys8_00_005000 := {
	"vuln_id": "V-235137",
	"stig_id": "MYS8-00-005000",
	"severity": "CAT I",
	"rule_title": "If Database Management System (DBMS) authentication using passwords is employed, the DBMS must enforce the DoW standards for password complexity and lifetime.",
	"status": status_r_mys8_00_005000,
}
status_r_mys8_00_005000 := "Not_a_Finding" if r_mys8_00_005000
status_r_mys8_00_005000 := "Open" if not r_mys8_00_005000

# MYS8-00-005100 | V-235138 | CAT II
default r_mys8_00_005100 := false
r_mys8_00_005100 if {
	every u in input.mysql.users { u.plugin in {"caching_sha2_password", "sha256_password"} }
}

finding_r_mys8_00_005100 := {
	"vuln_id": "V-235138",
	"stig_id": "MYS8-00-005100",
	"severity": "CAT II",
	"rule_title": "If passwords are used for authentication, the MySQL Database Server 8.0 must store only hashed, salted representations of passwords.",
	"status": status_r_mys8_00_005100,
}
status_r_mys8_00_005100 := "Not_a_Finding" if r_mys8_00_005100
status_r_mys8_00_005100 := "Open" if not r_mys8_00_005100

# MYS8-00-005200 | V-235139 | CAT I
default r_mys8_00_005200 := false
r_mys8_00_005200 if {
	upper(input.mysql.variables["require_secure_transport"]) == "ON"
}

finding_r_mys8_00_005200 := {
	"vuln_id": "V-235139",
	"stig_id": "MYS8-00-005200",
	"severity": "CAT I",
	"rule_title": "If passwords are used for authentication, the MySQL Database Server 8.0 must transmit only encrypted representations of passwords.",
	"status": status_r_mys8_00_005200,
}
status_r_mys8_00_005200 := "Not_a_Finding" if r_mys8_00_005200
status_r_mys8_00_005200 := "Open" if not r_mys8_00_005200

# MYS8-00-005300 | V-235140 | CAT I
default r_mys8_00_005300 := false
r_mys8_00_005300 if {
	input.mysql.attest.authentication_feedback_obscured == true
}

finding_r_mys8_00_005300 := {
	"vuln_id": "V-235140",
	"stig_id": "MYS8-00-005300",
	"severity": "CAT I",
	"rule_title": "The MySQL Database Server 8.0 must obscure feedback of authentication information during the authentication process to protect the information from possible exploitation/use by unauthorized individuals.",
	"status": status_r_mys8_00_005300,
}
status_r_mys8_00_005300 := "Not_a_Finding" if r_mys8_00_005300
status_r_mys8_00_005300 := "Open" if not r_mys8_00_005300

# MYS8-00-005400 | V-235141 | CAT I
default r_mys8_00_005400 := false
r_mys8_00_005400 if {
	input.mysql.attest.authorizations_enforced == true
}

finding_r_mys8_00_005400 := {
	"vuln_id": "V-235141",
	"stig_id": "MYS8-00-005400",
	"severity": "CAT I",
	"rule_title": "The MySQL Database Server 8.0 must enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.",
	"status": status_r_mys8_00_005400,
}
status_r_mys8_00_005400 := "Not_a_Finding" if r_mys8_00_005400
status_r_mys8_00_005400 := "Open" if not r_mys8_00_005400

# MYS8-00-005500 | V-235142 | CAT II
default r_mys8_00_005500 := false
r_mys8_00_005500 if {
	input.mysql.attest.configured_per_dod_guidance == true
}

finding_r_mys8_00_005500 := {
	"vuln_id": "V-235142",
	"stig_id": "MYS8-00-005500",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must be configured in accordance with the security configuration settings based on DoW security configuration and implementation guidance, including STIGs, NSA configuration guides, CTOs, DT",
	"status": status_r_mys8_00_005500,
}
status_r_mys8_00_005500 := "Not_a_Finding" if r_mys8_00_005500
status_r_mys8_00_005500 := "Open" if not r_mys8_00_005500

# MYS8-00-005600 | V-235143 | CAT II
default r_mys8_00_005600 := false
r_mys8_00_005600 if {
	count(input.mysql.sample_schemas_present) == 0
}

finding_r_mys8_00_005600 := {
	"vuln_id": "V-235143",
	"stig_id": "MYS8-00-005600",
	"severity": "CAT II",
	"rule_title": "Default demonstration and sample databases, database objects, and applications must be removed.",
	"status": status_r_mys8_00_005600,
}
status_r_mys8_00_005600 := "Not_a_Finding" if r_mys8_00_005600
status_r_mys8_00_005600 := "Open" if not r_mys8_00_005600

# MYS8-00-005700 | V-235144 | CAT II
default r_mys8_00_005700 := false
r_mys8_00_005700 if {
	count(input.mysql.unused_plugins_installed) == 0
}

finding_r_mys8_00_005700 := {
	"vuln_id": "V-235144",
	"stig_id": "MYS8-00-005700",
	"severity": "CAT II",
	"rule_title": "Unused database components, MySQL Database Server 8.0 software, and database objects must be removed.",
	"status": status_r_mys8_00_005700,
}
status_r_mys8_00_005700 := "Not_a_Finding" if r_mys8_00_005700
status_r_mys8_00_005700 := "Open" if not r_mys8_00_005700

# MYS8-00-005800 | V-235145 | CAT II
default r_mys8_00_005800 := false
r_mys8_00_005800 if {
	count(input.mysql.unused_integrated_components_enabled) == 0
}

finding_r_mys8_00_005800 := {
	"vuln_id": "V-235145",
	"stig_id": "MYS8-00-005800",
	"severity": "CAT II",
	"rule_title": "Unused database components which are integrated in the MySQL Database Server 8.0 and cannot be uninstalled must be disabled.",
	"status": status_r_mys8_00_005800,
}
status_r_mys8_00_005800 := "Not_a_Finding" if r_mys8_00_005800
status_r_mys8_00_005800 := "Open" if not r_mys8_00_005800

# MYS8-00-006000 | V-235146 | CAT II
default r_mys8_00_006000 := false
r_mys8_00_006000 if {
	input.mysql.attest.ppsm_functions_ports_protocols_approved == true
}

finding_r_mys8_00_006000 := {
	"vuln_id": "V-235146",
	"stig_id": "MYS8-00-006000",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must be configured to prohibit or restrict the use of organization-defined functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.",
	"status": status_r_mys8_00_006000,
}
status_r_mys8_00_006000 := "Not_a_Finding" if r_mys8_00_006000
status_r_mys8_00_006000 := "Open" if not r_mys8_00_006000

# MYS8-00-006100 | V-235147 | CAT II
default r_mys8_00_006100 := false
r_mys8_00_006100 if {
	input.mysql.attest.organizational_users_uniquely_identified == true
}

finding_r_mys8_00_006100 := {
	"vuln_id": "V-235147",
	"stig_id": "MYS8-00-006100",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users).",
	"status": status_r_mys8_00_006100,
}
status_r_mys8_00_006100 := "Not_a_Finding" if r_mys8_00_006100
status_r_mys8_00_006100 := "Open" if not r_mys8_00_006100

# MYS8-00-006200 | V-235148 | CAT I
default r_mys8_00_006200 := false
r_mys8_00_006200 if {
	fips_mode
}

finding_r_mys8_00_006200 := {
	"vuln_id": "V-235148",
	"stig_id": "MYS8-00-006200",
	"severity": "CAT I",
	"rule_title": "The MySQL Database Server 8.0 must use NIST FIPS 140-2 or 140-3 validated cryptographic modules for cryptographic operations.",
	"status": status_r_mys8_00_006200,
}
status_r_mys8_00_006200 := "Not_a_Finding" if r_mys8_00_006200
status_r_mys8_00_006200 := "Open" if not r_mys8_00_006200

# MYS8-00-006300 | V-235149 | CAT II
default r_mys8_00_006300 := false
r_mys8_00_006300 if {
	input.mysql.attest.nonorganizational_users_uniquely_identified == true
}

finding_r_mys8_00_006300 := {
	"vuln_id": "V-235149",
	"stig_id": "MYS8-00-006300",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must uniquely identify and authenticate non-organizational users (or processes acting on behalf of non-organizational users).",
	"status": status_r_mys8_00_006300,
}
status_r_mys8_00_006300 := "Not_a_Finding" if r_mys8_00_006300
status_r_mys8_00_006300 := "Open" if not r_mys8_00_006300

# MYS8-00-006400 | V-235150 | CAT II
default r_mys8_00_006400 := false
r_mys8_00_006400 if {
	input.mysql.attest.admin_functionality_separated_from_users == true
}

finding_r_mys8_00_006400 := {
	"vuln_id": "V-235150",
	"stig_id": "MYS8-00-006400",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must separate user functionality (including user interface services) from database management functionality.",
	"status": status_r_mys8_00_006400,
}
status_r_mys8_00_006400 := "Not_a_Finding" if r_mys8_00_006400
status_r_mys8_00_006400 := "Open" if not r_mys8_00_006400

# MYS8-00-006500 | V-235151 | CAT II
default r_mys8_00_006500 := false
r_mys8_00_006500 if {
	input.mysql.attest.security_functions_isolated == true
}

finding_r_mys8_00_006500 := {
	"vuln_id": "V-235151",
	"stig_id": "MYS8-00-006500",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must isolate security functions from non-security functions.",
	"status": status_r_mys8_00_006500,
}
status_r_mys8_00_006500 := "Not_a_Finding" if r_mys8_00_006500
status_r_mys8_00_006500 := "Open" if not r_mys8_00_006500

# MYS8-00-006600 | V-235152 | CAT II
default r_mys8_00_006600 := false
r_mys8_00_006600 if {
	input.mysql.attest.production_data_transfer_controlled == true
}

finding_r_mys8_00_006600 := {
	"vuln_id": "V-235152",
	"stig_id": "MYS8-00-006600",
	"severity": "CAT II",
	"rule_title": "Database contents must be protected from unauthorized and unintended information transfer by enforcement of a data-transfer policy.",
	"status": status_r_mys8_00_006600,
}
status_r_mys8_00_006600 := "Not_a_Finding" if r_mys8_00_006600
status_r_mys8_00_006600 := "Open" if not r_mys8_00_006600

# MYS8-00-006800 | V-235153 | CAT II
default r_mys8_00_006800 := false
r_mys8_00_006800 if {
	input.mysql.filesystem.datadir_permissions_restricted == true
}

finding_r_mys8_00_006800 := {
	"vuln_id": "V-235153",
	"stig_id": "MYS8-00-006800",
	"severity": "CAT II",
	"rule_title": "Access to database files must be limited to relevant processes and to authorized, administrative users.",
	"status": status_r_mys8_00_006800,
}
status_r_mys8_00_006800 := "Not_a_Finding" if r_mys8_00_006800
status_r_mys8_00_006800 := "Open" if not r_mys8_00_006800

# MYS8-00-007000 | V-235154 | CAT II
default r_mys8_00_007000 := false
r_mys8_00_007000 if {
	upper(input.mysql.variables["require_secure_transport"]) == "ON"
	fips_mode
}

finding_r_mys8_00_007000 := {
	"vuln_id": "V-235154",
	"stig_id": "MYS8-00-007000",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must maintain the authenticity of communications sessions by guarding against man-in-the-middle attacks that guess at Session ID values.",
	"status": status_r_mys8_00_007000,
}
status_r_mys8_00_007000 := "Not_a_Finding" if r_mys8_00_007000
status_r_mys8_00_007000 := "Open" if not r_mys8_00_007000

# MYS8-00-007200 | V-235155 | CAT I
default r_mys8_00_007200 := false
r_mys8_00_007200 if {
	input.mysql.encryption.all_tablespaces_encrypted == true
}

r_mys8_00_007200 if {
	input.mysql.attest.data_at_rest_encryption_not_required == true
}

finding_r_mys8_00_007200 := {
	"vuln_id": "V-235155",
	"stig_id": "MYS8-00-007200",
	"severity": "CAT I",
	"rule_title": "The MySQL Database Server 8.0 must protect the confidentiality and integrity of all information at rest.",
	"status": status_r_mys8_00_007200,
}
status_r_mys8_00_007200 := "Not_a_Finding" if r_mys8_00_007200
status_r_mys8_00_007200 := "Open" if not r_mys8_00_007200

# MYS8-00-007300 | V-235156 | CAT II
default r_mys8_00_007300 := false
r_mys8_00_007300 if {
	input.mysql.attest.input_validation_implemented == true
}

finding_r_mys8_00_007300 := {
	"vuln_id": "V-235156",
	"stig_id": "MYS8-00-007300",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must check the validity of all data inputs except those specifically identified by the organization.",
	"status": status_r_mys8_00_007300,
}
status_r_mys8_00_007300 := "Not_a_Finding" if r_mys8_00_007300
status_r_mys8_00_007300 := "Open" if not r_mys8_00_007300

# MYS8-00-007400 | V-235157 | CAT II
default r_mys8_00_007400 := false
r_mys8_00_007400 if {
	input.mysql.attest.dynamic_code_execution_justified == true
}

finding_r_mys8_00_007400 := {
	"vuln_id": "V-235157",
	"stig_id": "MYS8-00-007400",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 and associated applications must reserve the use of dynamic code execution for situations that require it.",
	"status": status_r_mys8_00_007400,
}
status_r_mys8_00_007400 := "Not_a_Finding" if r_mys8_00_007400
status_r_mys8_00_007400 := "Open" if not r_mys8_00_007400

# MYS8-00-007500 | V-235158 | CAT II
default r_mys8_00_007500 := false
r_mys8_00_007500 if {
	input.mysql.attest.dynamic_code_injection_protected == true
}

finding_r_mys8_00_007500 := {
	"vuln_id": "V-235158",
	"stig_id": "MYS8-00-007500",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 and associated applications, when making use of dynamic code execution, must scan input data for invalid values that may indicate a code injection attack.",
	"status": status_r_mys8_00_007500,
}
status_r_mys8_00_007500 := "Not_a_Finding" if r_mys8_00_007500
status_r_mys8_00_007500 := "Open" if not r_mys8_00_007500

# MYS8-00-007800 | V-235159 | CAT II
default r_mys8_00_007800 := false
r_mys8_00_007800 if {
	audit_log_active
	input.mysql.audit.force_plus_permanent == true
}

finding_r_mys8_00_007800 := {
	"vuln_id": "V-235159",
	"stig_id": "MYS8-00-007800",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must initiate session auditing upon startup.",
	"status": status_r_mys8_00_007800,
}
status_r_mys8_00_007800 := "Not_a_Finding" if r_mys8_00_007800
status_r_mys8_00_007800 := "Open" if not r_mys8_00_007800

# MYS8-00-008000 | V-235160 | CAT II
default r_mys8_00_008000 := false
r_mys8_00_008000 if {
	count(input.mysql.unauthorized_audit_admins) == 0
}

finding_r_mys8_00_008000 := {
	"vuln_id": "V-235160",
	"stig_id": "MYS8-00-008000",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must protect its audit features from unauthorized access.",
	"status": status_r_mys8_00_008000,
}
status_r_mys8_00_008000 := "Not_a_Finding" if r_mys8_00_008000
status_r_mys8_00_008000 := "Open" if not r_mys8_00_008000

# MYS8-00-008100 | V-235161 | CAT II
default r_mys8_00_008100 := false
r_mys8_00_008100 if {
	count(input.mysql.unauthorized_audit_admins) == 0
}

finding_r_mys8_00_008100 := {
	"vuln_id": "V-235161",
	"stig_id": "MYS8-00-008100",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must protect its audit configuration from unauthorized modification.",
	"status": status_r_mys8_00_008100,
}
status_r_mys8_00_008100 := "Not_a_Finding" if r_mys8_00_008100
status_r_mys8_00_008100 := "Open" if not r_mys8_00_008100

# MYS8-00-008200 | V-235162 | CAT II
default r_mys8_00_008200 := false
r_mys8_00_008200 if {
	count(input.mysql.unauthorized_audit_admins) == 0
}

finding_r_mys8_00_008200 := {
	"vuln_id": "V-235162",
	"stig_id": "MYS8-00-008200",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must protect its audit features from unauthorized removal.",
	"status": status_r_mys8_00_008200,
}
status_r_mys8_00_008200 := "Not_a_Finding" if r_mys8_00_008200
status_r_mys8_00_008200 := "Open" if not r_mys8_00_008200

# MYS8-00-008300 | V-235163 | CAT II
default r_mys8_00_008300 := false
r_mys8_00_008300 if {
	input.mysql.attest.software_module_change_privileges_restricted == true
}

finding_r_mys8_00_008300 := {
	"vuln_id": "V-235163",
	"stig_id": "MYS8-00-008300",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must limit privileges to change software modules, to include stored procedures, functions and triggers, and links to software external to the MySQL Database Server 8.0.",
	"status": status_r_mys8_00_008300,
}
status_r_mys8_00_008300 := "Not_a_Finding" if r_mys8_00_008300
status_r_mys8_00_008300 := "Open" if not r_mys8_00_008300

# MYS8-00-008400 | V-235164 | CAT II
default r_mys8_00_008400 := false
r_mys8_00_008400 if {
	input.mysql.attest.install_account_restricted == true
}

finding_r_mys8_00_008400 := {
	"vuln_id": "V-235164",
	"stig_id": "MYS8-00-008400",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 software installation account must be restricted to authorized users.",
	"status": status_r_mys8_00_008400,
}
status_r_mys8_00_008400 := "Not_a_Finding" if r_mys8_00_008400
status_r_mys8_00_008400 := "Open" if not r_mys8_00_008400

# MYS8-00-008500 | V-235165 | CAT II
default r_mys8_00_008500 := false
r_mys8_00_008500 if {
	input.mysql.attest.software_directories_dedicated == true
}

finding_r_mys8_00_008500 := {
	"vuln_id": "V-235165",
	"stig_id": "MYS8-00-008500",
	"severity": "CAT II",
	"rule_title": "Database software, including MySQL Database Server 8.0 configuration files, must be stored in dedicated directories, or DASD pools (remove), separate from the host OS and other applications.",
	"status": status_r_mys8_00_008500,
}
status_r_mys8_00_008500 := "Not_a_Finding" if r_mys8_00_008500
status_r_mys8_00_008500 := "Open" if not r_mys8_00_008500

# MYS8-00-008700 | V-235166 | CAT II
default r_mys8_00_008700 := false
r_mys8_00_008700 if {
	count(input.mysql.unauthorized_ddl_grantees) == 0
}

finding_r_mys8_00_008700 := {
	"vuln_id": "V-235166",
	"stig_id": "MYS8-00-008700",
	"severity": "CAT II",
	"rule_title": "The role(s)/group(s) used to modify database structure (including but not necessarily limited to tables, indexes, storage, etc.) and logic modules (stored procedures, functions, triggers, links to software external to th",
	"status": status_r_mys8_00_008700,
}
status_r_mys8_00_008700 := "Not_a_Finding" if r_mys8_00_008700
status_r_mys8_00_008700 := "Open" if not r_mys8_00_008700

# MYS8-00-009000 | V-235167 | CAT II
default r_mys8_00_009000 := false
r_mys8_00_009000 if {
	input.mysql.attest.network_ports_protocols_approved == true
}

finding_r_mys8_00_009000 := {
	"vuln_id": "V-235167",
	"stig_id": "MYS8-00-009000",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must disable network functions, ports, protocols, and services deemed by the organization to be nonsecure, in accord with the Ports, Protocols, and Services Management (PPSM) guidance.",
	"status": status_r_mys8_00_009000,
}
status_r_mys8_00_009000 := "Not_a_Finding" if r_mys8_00_009000
status_r_mys8_00_009000 := "Open" if not r_mys8_00_009000

# MYS8-00-009100 | V-235168 | CAT II
default r_mys8_00_009100 := false
r_mys8_00_009100 if {
	count(input.mysql.unauthorized_create_routine_grantees) == 0
}

finding_r_mys8_00_009100 := {
	"vuln_id": "V-235168",
	"stig_id": "MYS8-00-009100",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must prohibit user installation of logic modules (stored procedures, functions, triggers, views, etc.) without explicit privileged status.",
	"status": status_r_mys8_00_009100,
}
status_r_mys8_00_009100 := "Not_a_Finding" if r_mys8_00_009100
status_r_mys8_00_009100 := "Open" if not r_mys8_00_009100

# MYS8-00-009200 | V-235169 | CAT II
default r_mys8_00_009200 := false
r_mys8_00_009200 if {
	input.mysql.attest.configuration_change_access_restricted == true
}

finding_r_mys8_00_009200 := {
	"vuln_id": "V-235169",
	"stig_id": "MYS8-00-009200",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must enforce access restrictions associated with changes to the configuration of the MySQL Database Server 8.0 or database(s).",
	"status": status_r_mys8_00_009200,
}
status_r_mys8_00_009200 := "Not_a_Finding" if r_mys8_00_009200
status_r_mys8_00_009200 := "Open" if not r_mys8_00_009200

# MYS8-00-009300 | V-235170 | CAT II
default r_mys8_00_009300 := false
r_mys8_00_009300 if {
	audit_configured
}

finding_r_mys8_00_009300 := {
	"vuln_id": "V-235170",
	"stig_id": "MYS8-00-009300",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must produce audit records of its enforcement of access restrictions associated with changes to the configuration of the MySQL Database Server 8.0 or database(s).",
	"status": status_r_mys8_00_009300,
}
status_r_mys8_00_009300 := "Not_a_Finding" if r_mys8_00_009300
status_r_mys8_00_009300 := "Open" if not r_mys8_00_009300

# MYS8-00-009600 | V-235173 | CAT II
default r_mys8_00_009600 := false
r_mys8_00_009600 if {
	to_number(input.mysql.variables["audit_log_rotate_on_size"]) > 0
	input.mysql.attest.audit_storage_capacity_allocated == true
}

finding_r_mys8_00_009600 := {
	"vuln_id": "V-235173",
	"stig_id": "MYS8-00-009600",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must allocate audit record storage capacity in accordance with organization-defined audit record storage requirements.",
	"status": status_r_mys8_00_009600,
}
status_r_mys8_00_009600 := "Not_a_Finding" if r_mys8_00_009600
status_r_mys8_00_009600 := "Open" if not r_mys8_00_009600

# MYS8-00-009700 | V-235174 | CAT II
default r_mys8_00_009700 := false
r_mys8_00_009700 if {
	input.mysql.attest.audit_offloaded_continuously == true
}

finding_r_mys8_00_009700 := {
	"vuln_id": "V-235174",
	"stig_id": "MYS8-00-009700",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must off-load audit data to a separate log management facility; this must be continuous and in near real time for systems with a network connection to the storage facility and weekly or more",
	"status": status_r_mys8_00_009700,
}
status_r_mys8_00_009700 := "Not_a_Finding" if r_mys8_00_009700
status_r_mys8_00_009700 := "Open" if not r_mys8_00_009700

# MYS8-00-009800 | V-235175 | CAT II
default r_mys8_00_009800 := false
r_mys8_00_009800 if {
	input.mysql.attest.audit_storage_warning_at_75_percent == true
}

finding_r_mys8_00_009800 := {
	"vuln_id": "V-235175",
	"stig_id": "MYS8-00-009800",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must provide a warning to appropriate support staff when allocated audit record storage volume reaches 75 percent of maximum audit record storage capacity.",
	"status": status_r_mys8_00_009800,
}
status_r_mys8_00_009800 := "Not_a_Finding" if r_mys8_00_009800
status_r_mys8_00_009800 := "Open" if not r_mys8_00_009800

# MYS8-00-009900 | V-235176 | CAT II
default r_mys8_00_009900 := false
r_mys8_00_009900 if {
	input.mysql.attest.audit_failure_realtime_alert == true
}

finding_r_mys8_00_009900 := {
	"vuln_id": "V-235176",
	"stig_id": "MYS8-00-009900",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must provide an immediate real-time alert to appropriate support staff of all audit log failures.",
	"status": status_r_mys8_00_009900,
}
status_r_mys8_00_009900 := "Not_a_Finding" if r_mys8_00_009900
status_r_mys8_00_009900 := "Open" if not r_mys8_00_009900

# MYS8-00-010300 | V-235177 | CAT II
default r_mys8_00_010300 := false
r_mys8_00_010300 if {
	input.mysql.attest.cached_authenticator_lifetime_limited == true
}

finding_r_mys8_00_010300 := {
	"vuln_id": "V-235177",
	"stig_id": "MYS8-00-010300",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must prohibit the use of cached authenticators after an organization-defined time period.",
	"status": status_r_mys8_00_010300,
}
status_r_mys8_00_010300 := "Not_a_Finding" if r_mys8_00_010300
status_r_mys8_00_010300 := "Open" if not r_mys8_00_010300

# MYS8-00-010400 | V-235178 | CAT II
default r_mys8_00_010400 := false
r_mys8_00_010400 if {
	input.mysql.attest.reauthentication_circumstances_enforced == true
}

finding_r_mys8_00_010400 := {
	"vuln_id": "V-235178",
	"stig_id": "MYS8-00-010400",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must require users to reauthenticate when organization-defined circumstances or situations require reauthentication.",
	"status": status_r_mys8_00_010400,
}
status_r_mys8_00_010400 := "Not_a_Finding" if r_mys8_00_010400
status_r_mys8_00_010400 := "Open" if not r_mys8_00_010400

# MYS8-00-010500 | V-235179 | CAT II
default r_mys8_00_010500 := false
r_mys8_00_010500 if {
	input.mysql.attest.discretionary_access_control_enforced == true
}

finding_r_mys8_00_010500 := {
	"vuln_id": "V-235179",
	"stig_id": "MYS8-00-010500",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must enforce discretionary access control policies, as defined by the data owner, over defined subjects and objects.",
	"status": status_r_mys8_00_010500,
}
status_r_mys8_00_010500 := "Not_a_Finding" if r_mys8_00_010500
status_r_mys8_00_010500 := "Open" if not r_mys8_00_010500

# MYS8-00-010600 | V-235180 | CAT II
default r_mys8_00_010600 := false
r_mys8_00_010600 if {
	count(input.mysql.unauthorized_definer_routines) == 0
}

finding_r_mys8_00_010600 := {
	"vuln_id": "V-235180",
	"stig_id": "MYS8-00-010600",
	"severity": "CAT II",
	"rule_title": "Execution of software modules (to include stored procedures, functions, and triggers) with elevated privileges must be restricted to necessary cases only.",
	"status": status_r_mys8_00_010600,
}
status_r_mys8_00_010600 := "Not_a_Finding" if r_mys8_00_010600
status_r_mys8_00_010600 := "Open" if not r_mys8_00_010600

# MYS8-00-010700 | V-235181 | CAT II
default r_mys8_00_010700 := false
r_mys8_00_010700 if {
	count(input.mysql.unauthorized_definer_routines) == 0
}

finding_r_mys8_00_010700 := {
	"vuln_id": "V-235181",
	"stig_id": "MYS8-00-010700",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must prevent non-privileged users from executing privileged functions, to include disabling, circumventing, or altering implemented security safeguards/countermeasures.",
	"status": status_r_mys8_00_010700,
}
status_r_mys8_00_010700 := "Not_a_Finding" if r_mys8_00_010700
status_r_mys8_00_010700 := "Open" if not r_mys8_00_010700

# MYS8-00-010800 | V-235182 | CAT II
default r_mys8_00_010800 := false
r_mys8_00_010800 if {
	input.mysql.attest.security_labeling_implemented_or_not_required == true
}

finding_r_mys8_00_010800 := {
	"vuln_id": "V-235182",
	"stig_id": "MYS8-00-010800",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must associate organization-defined types of security labels having organization-defined security label values with information in storage.",
	"status": status_r_mys8_00_010800,
}
status_r_mys8_00_010800 := "Not_a_Finding" if r_mys8_00_010800
status_r_mys8_00_010800 := "Open" if not r_mys8_00_010800

# MYS8-00-010900 | V-235183 | CAT II
default r_mys8_00_010900 := false
r_mys8_00_010900 if {
	input.mysql.attest.security_labeling_implemented_or_not_required == true
}

finding_r_mys8_00_010900 := {
	"vuln_id": "V-235183",
	"stig_id": "MYS8-00-010900",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must associate organization-defined types of security labels having organization-defined security label values with information in process.",
	"status": status_r_mys8_00_010900,
}
status_r_mys8_00_010900 := "Not_a_Finding" if r_mys8_00_010900
status_r_mys8_00_010900 := "Open" if not r_mys8_00_010900

# MYS8-00-011000 | V-235184 | CAT II
default r_mys8_00_011000 := false
r_mys8_00_011000 if {
	input.mysql.attest.security_labeling_implemented_or_not_required == true
}

finding_r_mys8_00_011000 := {
	"vuln_id": "V-235184",
	"stig_id": "MYS8-00-011000",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must associate organization-defined types of security labels having organization-defined security label values with information in transmission.",
	"status": status_r_mys8_00_011000,
}
status_r_mys8_00_011000 := "Not_a_Finding" if r_mys8_00_011000
status_r_mys8_00_011000 := "Open" if not r_mys8_00_011000

# MYS8-00-011100 | V-235185 | CAT II
default r_mys8_00_011100 := false
r_mys8_00_011100 if {
	input.mysql.attest.session_termination_conditions_enforced == true
}

finding_r_mys8_00_011100 := {
	"vuln_id": "V-235185",
	"stig_id": "MYS8-00-011100",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must automatically terminate a user session after organization-defined conditions or trigger events requiring session disconnect.",
	"status": status_r_mys8_00_011100,
}
status_r_mys8_00_011100 := "Not_a_Finding" if r_mys8_00_011100
status_r_mys8_00_011100 := "Open" if not r_mys8_00_011100

# MYS8-00-011300 | V-235186 | CAT II
default r_mys8_00_011300 := false
r_mys8_00_011300 if {
	upper(input.mysql.variables["require_secure_transport"]) == "ON"
}

finding_r_mys8_00_011300 := {
	"vuln_id": "V-235186",
	"stig_id": "MYS8-00-011300",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must maintain the confidentiality and integrity of information during preparation for transmission.",
	"status": status_r_mys8_00_011300,
}
status_r_mys8_00_011300 := "Not_a_Finding" if r_mys8_00_011300
status_r_mys8_00_011300 := "Open" if not r_mys8_00_011300

# MYS8-00-011500 | V-235187 | CAT II
default r_mys8_00_011500 := false
r_mys8_00_011500 if {
	input.mysql.attest.nsa_approved_cryptography_for_classified_or_not_required == true
}

finding_r_mys8_00_011500 := {
	"vuln_id": "V-235187",
	"stig_id": "MYS8-00-011500",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must use NSA-approved cryptography to protect classified information in accordance with the data owner's requirements.",
	"status": status_r_mys8_00_011500,
}
status_r_mys8_00_011500 := "Not_a_Finding" if r_mys8_00_011500
status_r_mys8_00_011500 := "Open" if not r_mys8_00_011500

# MYS8-00-011600 | V-235188 | CAT II
default r_mys8_00_011600 := false
r_mys8_00_011600 if {
	fips_mode
}

finding_r_mys8_00_011600 := {
	"vuln_id": "V-235188",
	"stig_id": "MYS8-00-011600",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must implement NIST FIPS 140-2 or 140-3 validated cryptographic modules to provision digital signatures.",
	"status": status_r_mys8_00_011600,
}
status_r_mys8_00_011600 := "Not_a_Finding" if r_mys8_00_011600
status_r_mys8_00_011600 := "Open" if not r_mys8_00_011600

# MYS8-00-011700 | V-235189 | CAT I
default r_mys8_00_011700 := false
r_mys8_00_011700 if {
	fips_mode
}

finding_r_mys8_00_011700 := {
	"vuln_id": "V-235189",
	"stig_id": "MYS8-00-011700",
	"severity": "CAT I",
	"rule_title": "The MySQL Database Server 8.0 must implement NIST FIPS 140-2 or 140-3 validated cryptographic modules to generate and validate cryptographic hashes.",
	"status": status_r_mys8_00_011700,
}
status_r_mys8_00_011700 := "Not_a_Finding" if r_mys8_00_011700
status_r_mys8_00_011700 := "Open" if not r_mys8_00_011700

# MYS8-00-011800 | V-235190 | CAT II
default r_mys8_00_011800 := false
r_mys8_00_011800 if {
	fips_mode
}

finding_r_mys8_00_011800 := {
	"vuln_id": "V-235190",
	"stig_id": "MYS8-00-011800",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must implement NIST FIPS 140-2 or 140-3 validated cryptographic modules to protect unclassified information requiring confidentiality and cryptographic protection, in accordance with the dat",
	"status": status_r_mys8_00_011800,
}
status_r_mys8_00_011800 := "Not_a_Finding" if r_mys8_00_011800
status_r_mys8_00_011800 := "Open" if not r_mys8_00_011800

# MYS8-00-011900 | V-235191 | CAT II
default r_mys8_00_011900 := false
r_mys8_00_011900 if {
	input.mysql.attest.server_certificate_issued_by_dod_pki == true
}

finding_r_mys8_00_011900 := {
	"vuln_id": "V-235191",
	"stig_id": "MYS8-00-011900",
	"severity": "CAT II",
	"rule_title": "The MySQL Database Server 8.0 must only accept end entity certificates issued by DoW PKI or DoW-approved PKI Certification Authorities (CAs) for the establishment of all encrypted sessions.",
	"status": status_r_mys8_00_011900,
}
status_r_mys8_00_011900 := "Not_a_Finding" if r_mys8_00_011900
status_r_mys8_00_011900 := "Open" if not r_mys8_00_011900

# MYS8-00-012000 | V-235192 | CAT I
default r_mys8_00_012000 := false
r_mys8_00_012000 if {
	input.mysql.encryption.all_tablespaces_encrypted == true
}

r_mys8_00_012000 if {
	input.mysql.attest.data_at_rest_encryption_not_required == true
}

finding_r_mys8_00_012000 := {
	"vuln_id": "V-235192",
	"stig_id": "MYS8-00-012000",
	"severity": "CAT I",
	"rule_title": "The MySQL Database Server 8.0 must implement cryptographic mechanisms to prevent unauthorized modification of organization-defined information at rest (to include, at a minimum, PII and classified information) on organiz",
	"status": status_r_mys8_00_012000,
}
status_r_mys8_00_012000 := "Not_a_Finding" if r_mys8_00_012000
status_r_mys8_00_012000 := "Open" if not r_mys8_00_012000

# MYS8-00-012100 | V-235193 | CAT I
default r_mys8_00_012100 := false
r_mys8_00_012100 if {
	input.mysql.encryption.all_tablespaces_encrypted == true
}

r_mys8_00_012100 if {
	input.mysql.attest.data_at_rest_encryption_not_required == true
}

finding_r_mys8_00_012100 := {
	"vuln_id": "V-235193",
	"stig_id": "MYS8-00-012100",
	"severity": "CAT I",
	"rule_title": "The MySQL Database Server 8.0 must implement cryptographic mechanisms preventing the unauthorized disclosure of organization-defined information at rest on organization-defined information system components.",
	"status": status_r_mys8_00_012100,
}
status_r_mys8_00_012100 := "Not_a_Finding" if r_mys8_00_012100
status_r_mys8_00_012100 := "Open" if not r_mys8_00_012100

# MYS8-00-012300 | V-235194 | CAT II
default r_mys8_00_012300 := false
r_mys8_00_012300 if {
	input.mysql.attest.security_updates_applied_within_policy == true
}

finding_r_mys8_00_012300 := {
	"vuln_id": "V-235194",
	"stig_id": "MYS8-00-012300",
	"severity": "CAT II",
	"rule_title": "Security-relevant software updates to the MySQL Database Server 8.0 must be installed within the time period directed by an authoritative source (e.g., IAVM, CTOs, DTMs, and STIGs).",
	"status": status_r_mys8_00_012300,
}
status_r_mys8_00_012300 := "Not_a_Finding" if r_mys8_00_012300
status_r_mys8_00_012300 := "Open" if not r_mys8_00_012300

# MYS8-00-012500 | V-235195 | CAT II
default r_mys8_00_012500 := false
r_mys8_00_012500 if {
	input.mysql.attest.invalid_input_handling_documented == true
}

finding_r_mys8_00_012500 := {
	"vuln_id": "V-235195",
	"stig_id": "MYS8-00-012500",
	"severity": "CAT II",
	"rule_title": "When invalid inputs are received, the MySQL Database Server 8.0 must behave in a predictable and documented manner that reflects organizational and system objectives.",
	"status": status_r_mys8_00_012500,
}
status_r_mys8_00_012500 := "Not_a_Finding" if r_mys8_00_012500
status_r_mys8_00_012500 := "Open" if not r_mys8_00_012500

# MYS8-00-012600 | V-265876 | CAT I
default r_mys8_00_012600 := false
r_mys8_00_012600 if {
	input.mysql.attest.vendor_supported_version == true
}

finding_r_mys8_00_012600 := {
	"vuln_id": "V-265876",
	"stig_id": "MYS8-00-012600",
	"severity": "CAT I",
	"rule_title": "MySQL database products must be a version supported by the vendor.",
	"status": status_r_mys8_00_012600,
}
status_r_mys8_00_012600 := "Not_a_Finding" if r_mys8_00_012600
status_r_mys8_00_012600 := "Open" if not r_mys8_00_012600

findings := [
	finding_r_mys8_00_000100,
	finding_r_mys8_00_000200,
	finding_r_mys8_00_000300,
	finding_r_mys8_00_000800,
	finding_r_mys8_00_001200,
	finding_r_mys8_00_001300,
	finding_r_mys8_00_001400,
	finding_r_mys8_00_001500,
	finding_r_mys8_00_001600,
	finding_r_mys8_00_001700,
	finding_r_mys8_00_001800,
	finding_r_mys8_00_001900,
	finding_r_mys8_00_002000,
	finding_r_mys8_00_002100,
	finding_r_mys8_00_002200,
	finding_r_mys8_00_002300,
	finding_r_mys8_00_002400,
	finding_r_mys8_00_002500,
	finding_r_mys8_00_002600,
	finding_r_mys8_00_002700,
	finding_r_mys8_00_002800,
	finding_r_mys8_00_002900,
	finding_r_mys8_00_003000,
	finding_r_mys8_00_003100,
	finding_r_mys8_00_003200,
	finding_r_mys8_00_003300,
	finding_r_mys8_00_003400,
	finding_r_mys8_00_003500,
	finding_r_mys8_00_003600,
	finding_r_mys8_00_003700,
	finding_r_mys8_00_003800,
	finding_r_mys8_00_003900,
	finding_r_mys8_00_004000,
	finding_r_mys8_00_004100,
	finding_r_mys8_00_004200,
	finding_r_mys8_00_004300,
	finding_r_mys8_00_004400,
	finding_r_mys8_00_004500,
	finding_r_mys8_00_004600,
	finding_r_mys8_00_004700,
	finding_r_mys8_00_004800,
	finding_r_mys8_00_004900,
	finding_r_mys8_00_005000,
	finding_r_mys8_00_005100,
	finding_r_mys8_00_005200,
	finding_r_mys8_00_005300,
	finding_r_mys8_00_005400,
	finding_r_mys8_00_005500,
	finding_r_mys8_00_005600,
	finding_r_mys8_00_005700,
	finding_r_mys8_00_005800,
	finding_r_mys8_00_006000,
	finding_r_mys8_00_006100,
	finding_r_mys8_00_006200,
	finding_r_mys8_00_006300,
	finding_r_mys8_00_006400,
	finding_r_mys8_00_006500,
	finding_r_mys8_00_006600,
	finding_r_mys8_00_006800,
	finding_r_mys8_00_007000,
	finding_r_mys8_00_007200,
	finding_r_mys8_00_007300,
	finding_r_mys8_00_007400,
	finding_r_mys8_00_007500,
	finding_r_mys8_00_007800,
	finding_r_mys8_00_008000,
	finding_r_mys8_00_008100,
	finding_r_mys8_00_008200,
	finding_r_mys8_00_008300,
	finding_r_mys8_00_008400,
	finding_r_mys8_00_008500,
	finding_r_mys8_00_008700,
	finding_r_mys8_00_009000,
	finding_r_mys8_00_009100,
	finding_r_mys8_00_009200,
	finding_r_mys8_00_009300,
	finding_r_mys8_00_009600,
	finding_r_mys8_00_009700,
	finding_r_mys8_00_009800,
	finding_r_mys8_00_009900,
	finding_r_mys8_00_010300,
	finding_r_mys8_00_010400,
	finding_r_mys8_00_010500,
	finding_r_mys8_00_010600,
	finding_r_mys8_00_010700,
	finding_r_mys8_00_010800,
	finding_r_mys8_00_010900,
	finding_r_mys8_00_011000,
	finding_r_mys8_00_011100,
	finding_r_mys8_00_011300,
	finding_r_mys8_00_011500,
	finding_r_mys8_00_011600,
	finding_r_mys8_00_011700,
	finding_r_mys8_00_011800,
	finding_r_mys8_00_011900,
	finding_r_mys8_00_012000,
	finding_r_mys8_00_012100,
	finding_r_mys8_00_012300,
	finding_r_mys8_00_012500,
	finding_r_mys8_00_012600,
]

default compliant := false

compliant if count([f | some f in findings; f.status == "Open"]) == 0
