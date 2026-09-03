package stig.ms_sql_2016.core

# DISA STIG — MS SQL Server 2016 Instance Security Technical Implementation Guide
# V3R6 | Release: 6 Benchmark Date: 05 Jan 2026
# 13 rules (all CAT I + selected CAT II); IDs/severities/titles
# verified against the July 2026 SRG-STIG library XCCDF on 2026-09-03.
# Organizational rules are explicit attestation booleans — named for what
# a human verified, never silently passed. Input contract:
#   input.sql.*                        : instance facts + attestation booleans

import rego.v1

# SQL6-D0-003700 | V-213930 | CAT I
default r_sql6_d0_003700 := false
r_sql6_d0_003700 if {
	input.sql.org_level_auth_integrated == true
}

finding_r_sql6_d0_003700 := {
	"vuln_id": "V-213930",
	"stig_id": "SQL6-D0-003700",
	"severity": "CAT I",
	"rule_title": "SQL Server must integrate with an organization-level authentication/access mechanism providing account management and automation for all users, groups, roles, and any other principals.",
	"status": status_r_sql6_d0_003700,
}
status_r_sql6_d0_003700 := "Not_a_Finding" if r_sql6_d0_003700
status_r_sql6_d0_003700 := "Open" if not r_sql6_d0_003700

# SQL6-D0-003900 | V-213932 | CAT I
default r_sql6_d0_003900 := false
r_sql6_d0_003900 if {
	input.sql.authorizations_enforced == true
}

finding_r_sql6_d0_003900 := {
	"vuln_id": "V-213932",
	"stig_id": "SQL6-D0-003900",
	"severity": "CAT I",
	"rule_title": "SQL Server must enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.",
	"status": status_r_sql6_d0_003900,
}
status_r_sql6_d0_003900 := "Not_a_Finding" if r_sql6_d0_003900
status_r_sql6_d0_003900 := "Open" if not r_sql6_d0_003900

# SQL6-D0-006700 | V-213952 | CAT I
default r_sql6_d0_006700 := false
r_sql6_d0_006700 if {
	input.sql.install_account_restricted == true
}

finding_r_sql6_d0_006700 := {
	"vuln_id": "V-213952",
	"stig_id": "SQL6-D0-006700",
	"severity": "CAT I",
	"rule_title": "SQL Server software installation account must be restricted to authorized users.",
	"status": status_r_sql6_d0_006700,
}
status_r_sql6_d0_006700 := "Not_a_Finding" if r_sql6_d0_006700
status_r_sql6_d0_006700 := "Open" if not r_sql6_d0_006700

# SQL6-D0-007900 | V-213964 | CAT I
default r_sql6_d0_007900 := false
r_sql6_d0_007900 if {
	input.sql.password_standards_enforced == true
}

finding_r_sql6_d0_007900 := {
	"vuln_id": "V-213964",
	"stig_id": "SQL6-D0-007900",
	"severity": "CAT I",
	"rule_title": "If DBMS authentication using passwords is employed, SQL Server must enforce the DOD standards for password complexity and lifetime.",
	"status": status_r_sql6_d0_007900,
}
status_r_sql6_d0_007900 := "Not_a_Finding" if r_sql6_d0_007900
status_r_sql6_d0_007900 := "Open" if not r_sql6_d0_007900

# SQL6-D0-008200 | V-213966 | CAT I
default r_sql6_d0_008200 := false
r_sql6_d0_008200 if {
	input.sql.encrypted_password_transmission == true
}

finding_r_sql6_d0_008200 := {
	"vuln_id": "V-213966",
	"stig_id": "SQL6-D0-008200",
	"severity": "CAT I",
	"rule_title": "If passwords are used for authentication, SQL Server must transmit only encrypted representations of passwords.",
	"status": status_r_sql6_d0_008200,
}
status_r_sql6_d0_008200 := "Not_a_Finding" if r_sql6_d0_008200
status_r_sql6_d0_008200 := "Open" if not r_sql6_d0_008200

# SQL6-D0-008300 | V-213967 | CAT I
default r_sql6_d0_008300 := false
r_sql6_d0_008300 if {
	input.sql.tls_for_transmission == true
}

finding_r_sql6_d0_008300 := {
	"vuln_id": "V-213967",
	"stig_id": "SQL6-D0-008300",
	"severity": "CAT I",
	"rule_title": "Confidentiality of information during transmission is controlled through the use of an approved TLS version.",
	"status": status_r_sql6_d0_008300,
}
status_r_sql6_d0_008300 := "Not_a_Finding" if r_sql6_d0_008300
status_r_sql6_d0_008300 := "Open" if not r_sql6_d0_008300

# SQL6-D0-008400 | V-213968 | CAT I
default r_sql6_d0_008400 := false
r_sql6_d0_008400 if {
	input.sql.pki_keys_access_enforced == true
}

finding_r_sql6_d0_008400 := {
	"vuln_id": "V-213968",
	"stig_id": "SQL6-D0-008400",
	"severity": "CAT I",
	"rule_title": "SQL Server must enforce authorized access to all PKI private keys stored/utilized by SQL Server.",
	"status": status_r_sql6_d0_008400,
}
status_r_sql6_d0_008400 := "Not_a_Finding" if r_sql6_d0_008400
status_r_sql6_d0_008400 := "Open" if not r_sql6_d0_008400

# SQL6-D0-008700 | V-213969 | CAT I
default r_sql6_d0_008700 := false
r_sql6_d0_008700 if {
	input.sql.fips_modules_in_use == true
}

finding_r_sql6_d0_008700 := {
	"vuln_id": "V-213969",
	"stig_id": "SQL6-D0-008700",
	"severity": "CAT I",
	"rule_title": "SQL Server must use NIST FIPS 140-2/140-3-validated cryptographic operations for encryption, hashing, and signing.",
	"status": status_r_sql6_d0_008700,
}
status_r_sql6_d0_008700 := "Not_a_Finding" if r_sql6_d0_008700
status_r_sql6_d0_008700 := "Open" if not r_sql6_d0_008700

# SQL6-D0-009500 | V-213972 | CAT I
default r_sql6_d0_009500 := false
r_sql6_d0_009500 if {
	input.sql.data_at_rest_protected == true
}

finding_r_sql6_d0_009500 := {
	"vuln_id": "V-213972",
	"stig_id": "SQL6-D0-009500",
	"severity": "CAT I",
	"rule_title": "SQL Server must protect the confidentiality and integrity of all information at rest.",
	"status": status_r_sql6_d0_009500,
}
status_r_sql6_d0_009500 := "Not_a_Finding" if r_sql6_d0_009500
status_r_sql6_d0_009500 := "Open" if not r_sql6_d0_009500

# SQL6-D0-016200 | V-214028 | CAT I
default r_sql6_d0_016200 := false
r_sql6_d0_016200 if {
	input.sql.sa_account_disabled == true
}

finding_r_sql6_d0_016200 := {
	"vuln_id": "V-214028",
	"stig_id": "SQL6-D0-016200",
	"severity": "CAT I",
	"rule_title": "The SQL Server default account [sa] must be disabled.",
	"status": status_r_sql6_d0_016200,
}
status_r_sql6_d0_016200 := "Not_a_Finding" if r_sql6_d0_016200
status_r_sql6_d0_016200 := "Open" if not r_sql6_d0_016200

# SQL6-D0-018100 | V-214045 | CAT I
default r_sql6_d0_018100 := false
r_sql6_d0_018100 if {
	input.sql.sqlcmd_no_cleartext_credentials == true
}

finding_r_sql6_d0_018100 := {
	"vuln_id": "V-214045",
	"stig_id": "SQL6-D0-018100",
	"severity": "CAT I",
	"rule_title": "When using command-line tools such as SQLCMD in a mixed-mode authentication environment, users must use a logon method that does not expose the password.",
	"status": status_r_sql6_d0_018100,
}
status_r_sql6_d0_018100 := "Not_a_Finding" if r_sql6_d0_018100
status_r_sql6_d0_018100 := "Open" if not r_sql6_d0_018100

# SQL6-D0-018200 | V-214046 | CAT I
default r_sql6_d0_018200 := false
r_sql6_d0_018200 if {
	input.sql.auth_feedback_obscured == true
}

finding_r_sql6_d0_018200 := {
	"vuln_id": "V-214046",
	"stig_id": "SQL6-D0-018200",
	"severity": "CAT I",
	"rule_title": "Applications must obscure feedback of authentication information during the authentication process to protect the information from possible exploitation/use by unauthorized individuals.",
	"status": status_r_sql6_d0_018200,
}
status_r_sql6_d0_018200 := "Not_a_Finding" if r_sql6_d0_018200
status_r_sql6_d0_018200 := "Open" if not r_sql6_d0_018200

# SQL6-D0-018300 | V-265870 | CAT I
default r_sql6_d0_018300 := false
r_sql6_d0_018300 if {
	input.sql.vendor_supported_version == true
}

finding_r_sql6_d0_018300 := {
	"vuln_id": "V-265870",
	"stig_id": "SQL6-D0-018300",
	"severity": "CAT I",
	"rule_title": "Microsoft SQL Server products must be a version supported by the vendor.",
	"status": status_r_sql6_d0_018300,
}
status_r_sql6_d0_018300 := "Not_a_Finding" if r_sql6_d0_018300
status_r_sql6_d0_018300 := "Open" if not r_sql6_d0_018300

findings := [
	finding_r_sql6_d0_003700,
	finding_r_sql6_d0_003900,
	finding_r_sql6_d0_006700,
	finding_r_sql6_d0_007900,
	finding_r_sql6_d0_008200,
	finding_r_sql6_d0_008300,
	finding_r_sql6_d0_008400,
	finding_r_sql6_d0_008700,
	finding_r_sql6_d0_009500,
	finding_r_sql6_d0_016200,
	finding_r_sql6_d0_018100,
	finding_r_sql6_d0_018200,
	finding_r_sql6_d0_018300,
]

default compliant := false

compliant if count([f | some f in findings; f.status == "Open"]) == 0
