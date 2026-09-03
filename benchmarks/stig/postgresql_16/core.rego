package stig.postgresql_16.core

# DISA STIG — Crunchy Data Postgres 16 Security Technical Implementation Guide
# V1R3 | Release: 3 Benchmark Date: 01 Jul 2026
# 13 rules (all CAT I + selected CAT II); IDs/severities/titles
# verified against the July 2026 SRG-STIG library XCCDF on 2026-09-03.
# Organizational rules are explicit attestation booleans — named for what
# a human verified, never silently passed. Input contract:
#   input.pg_settings[<name>]          : SHOW <name> value
#   input.pg.*                         : attestation booleans (documented reviews)

import rego.v1

# CD16-00-000200 | V-261858 | CAT I
default r_cd16_00_000200 := false
r_cd16_00_000200 if {
	input.pg.org_level_auth_integrated == true
}

finding_r_cd16_00_000200 := {
	"vuln_id": "V-261858",
	"stig_id": "CD16-00-000200",
	"severity": "CAT I",
	"rule_title": "PostgreSQL must integrate with an organization-level authentication/access mechanism providing account management and automation for all users, groups, roles, and any other principals.",
	"status": status_r_cd16_00_000200,
}
status_r_cd16_00_000200 := "Not_a_Finding" if r_cd16_00_000200
status_r_cd16_00_000200 := "Open" if not r_cd16_00_000200

# CD16-00-000300 | V-261859 | CAT I
default r_cd16_00_000300 := false
r_cd16_00_000300 if {
	input.pg.authorizations_enforced == true
}

finding_r_cd16_00_000300 := {
	"vuln_id": "V-261859",
	"stig_id": "CD16-00-000300",
	"severity": "CAT I",
	"rule_title": "PostgreSQL must enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.",
	"status": status_r_cd16_00_000300,
}
status_r_cd16_00_000300 := "Not_a_Finding" if r_cd16_00_000300
status_r_cd16_00_000300 := "Open" if not r_cd16_00_000300

# CD16-00-002700 | V-261882 | CAT I
default r_cd16_00_002700 := false
r_cd16_00_002700 if {
	input.pg.install_account_restricted == true
}

finding_r_cd16_00_002700 := {
	"vuln_id": "V-261882",
	"stig_id": "CD16-00-002700",
	"severity": "CAT I",
	"rule_title": "The PostgreSQL software installation account must be restricted to authorized users.",
	"status": status_r_cd16_00_002700,
}
status_r_cd16_00_002700 := "Not_a_Finding" if r_cd16_00_002700
status_r_cd16_00_002700 := "Open" if not r_cd16_00_002700

# CD16-00-003800 | V-261891 | CAT I
default r_cd16_00_003800 := false
r_cd16_00_003800 if {
	input.pg_settings["password_encryption"] == "scram-sha-256"
}

finding_r_cd16_00_003800 := {
	"vuln_id": "V-261891",
	"stig_id": "CD16-00-003800",
	"severity": "CAT I",
	"rule_title": "If passwords are used for authentication, PostgreSQL must store only hashed, salted representations of passwords.",
	"status": status_r_cd16_00_003800,
}
status_r_cd16_00_003800 := "Not_a_Finding" if r_cd16_00_003800
status_r_cd16_00_003800 := "Open" if not r_cd16_00_003800

# CD16-00-003900 | V-261892 | CAT I
default r_cd16_00_003900 := false
r_cd16_00_003900 if {
	input.pg_settings["ssl"] == "on"
}

finding_r_cd16_00_003900 := {
	"vuln_id": "V-261892",
	"stig_id": "CD16-00-003900",
	"severity": "CAT I",
	"rule_title": "If passwords are used for authentication, PostgreSQL must transmit only encrypted representations of passwords.",
	"status": status_r_cd16_00_003900,
}
status_r_cd16_00_003900 := "Not_a_Finding" if r_cd16_00_003900
status_r_cd16_00_003900 := "Open" if not r_cd16_00_003900

# CD16-00-004100 | V-261894 | CAT I
default r_cd16_00_004100 := false
r_cd16_00_004100 if {
	input.pg.pki_keys_access_enforced == true
}

finding_r_cd16_00_004100 := {
	"vuln_id": "V-261894",
	"stig_id": "CD16-00-004100",
	"severity": "CAT I",
	"rule_title": "PostgreSQL must enforce authorized access to all PKI private keys stored/used by PostgreSQL.",
	"status": status_r_cd16_00_004100,
}
status_r_cd16_00_004100 := "Not_a_Finding" if r_cd16_00_004100
status_r_cd16_00_004100 := "Open" if not r_cd16_00_004100

# CD16-00-004400 | V-261896 | CAT I
default r_cd16_00_004400 := false
r_cd16_00_004400 if {
	input.pg.fips_modules_in_use == true
}

finding_r_cd16_00_004400 := {
	"vuln_id": "V-261896",
	"stig_id": "CD16-00-004400",
	"severity": "CAT I",
	"rule_title": "PostgreSQL must use NIST FIPS 140-2/140-3 validated cryptographic modules for cryptographic operations.",
	"status": status_r_cd16_00_004400,
}
status_r_cd16_00_004400 := "Not_a_Finding" if r_cd16_00_004400
status_r_cd16_00_004400 := "Open" if not r_cd16_00_004400

# CD16-00-005200 | V-261901 | CAT I
default r_cd16_00_005200 := false
r_cd16_00_005200 if {
	input.pg.data_at_rest_protected == true
}

finding_r_cd16_00_005200 := {
	"vuln_id": "V-261901",
	"stig_id": "CD16-00-005200",
	"severity": "CAT I",
	"rule_title": "PostgreSQL must protect the confidentiality and integrity of all information at rest.",
	"status": status_r_cd16_00_005200,
}
status_r_cd16_00_005200 := "Not_a_Finding" if r_cd16_00_005200
status_r_cd16_00_005200 := "Open" if not r_cd16_00_005200

# CD16-00-008300 | V-261928 | CAT I
default r_cd16_00_008300 := false
r_cd16_00_008300 if {
	input.pg.nsa_crypto_for_classified == true
}

finding_r_cd16_00_008300 := {
	"vuln_id": "V-261928",
	"stig_id": "CD16-00-008300",
	"severity": "CAT I",
	"rule_title": "PostgreSQL must use NSA-approved cryptography to protect classified information in accordance with the data owner's requirements.",
	"status": status_r_cd16_00_008300,
}
status_r_cd16_00_008300 := "Not_a_Finding" if r_cd16_00_008300
status_r_cd16_00_008300 := "Open" if not r_cd16_00_008300

# CD16-00-008500 | V-261930 | CAT I
default r_cd16_00_008500 := false
r_cd16_00_008500 if {
	input.pg.crypto_integrity_mechanisms == true
}

finding_r_cd16_00_008500 := {
	"vuln_id": "V-261930",
	"stig_id": "CD16-00-008500",
	"severity": "CAT I",
	"rule_title": "PostgreSQL must implement cryptographic mechanisms to prevent unauthorized modification of organization-defined information at rest (to include, at a minimum, PII and classified information) on organization-defined infor",
	"status": status_r_cd16_00_008500,
}
status_r_cd16_00_008500 := "Not_a_Finding" if r_cd16_00_008500
status_r_cd16_00_008500 := "Open" if not r_cd16_00_008500

# CD16-00-009300 | V-283674 | CAT I
default r_cd16_00_009300 := false
r_cd16_00_009300 if {
	input.pg.vendor_supported_version == true
}

finding_r_cd16_00_009300 := {
	"vuln_id": "V-283674",
	"stig_id": "CD16-00-009300",
	"severity": "CAT I",
	"rule_title": "PostgreSQL products must be a version supported by the vendor.",
	"status": status_r_cd16_00_009300,
}
status_r_cd16_00_009300 := "Not_a_Finding" if r_cd16_00_009300
status_r_cd16_00_009300 := "Open" if not r_cd16_00_009300

# CD16-00-011800 | V-261962 | CAT II
default r_cd16_00_011800 := false
r_cd16_00_011800 if {
	input.pg.audit_successful_object_access == true
}

finding_r_cd16_00_011800 := {
	"vuln_id": "V-261962",
	"stig_id": "CD16-00-011800",
	"severity": "CAT II",
	"rule_title": "PostgreSQL must be able to generate audit records when successful accesses to objects occur.",
	"status": status_r_cd16_00_011800,
}
status_r_cd16_00_011800 := "Not_a_Finding" if r_cd16_00_011800
status_r_cd16_00_011800 := "Open" if not r_cd16_00_011800

# CD16-00-011900 | V-261963 | CAT II
default r_cd16_00_011900 := false
r_cd16_00_011900 if {
	input.pg.audit_unsuccessful_object_access == true
}

finding_r_cd16_00_011900 := {
	"vuln_id": "V-261963",
	"stig_id": "CD16-00-011900",
	"severity": "CAT II",
	"rule_title": "PostgreSQL must generate audit records when unsuccessful accesses to objects occur.",
	"status": status_r_cd16_00_011900,
}
status_r_cd16_00_011900 := "Not_a_Finding" if r_cd16_00_011900
status_r_cd16_00_011900 := "Open" if not r_cd16_00_011900

findings := [
	finding_r_cd16_00_000200,
	finding_r_cd16_00_000300,
	finding_r_cd16_00_002700,
	finding_r_cd16_00_003800,
	finding_r_cd16_00_003900,
	finding_r_cd16_00_004100,
	finding_r_cd16_00_004400,
	finding_r_cd16_00_005200,
	finding_r_cd16_00_008300,
	finding_r_cd16_00_008500,
	finding_r_cd16_00_009300,
	finding_r_cd16_00_011800,
	finding_r_cd16_00_011900,
]

default compliant := false

compliant if count([f | some f in findings; f.status == "Open"]) == 0
