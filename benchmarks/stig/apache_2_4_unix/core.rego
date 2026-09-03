package stig.apache_2_4_unix.core

# DISA STIG — Apache Server 2.4 UNIX Server Security Technical Implementation Guide
# V3R3 | Release: 3 Benchmark Date: 01 Jul 2026
# 10 rules (all CAT I + selected CAT II); IDs/severities/titles
# verified against the July 2026 SRG-STIG library XCCDF on 2026-09-03.
# Organizational rules are explicit attestation booleans — named for what
# a human verified, never silently passed. Input contract:
#   input.apache.*                     : parsed httpd facts + attestations

import rego.v1

# AS24-U1-000030 | V-214230 | CAT II
default r_as24_u1_000030 := false
r_as24_u1_000030 if {
	input.apache.remote_session_crypto_enabled == true
}

finding_r_as24_u1_000030 := {
	"vuln_id": "V-214230",
	"stig_id": "AS24-U1-000030",
	"severity": "CAT II",
	"rule_title": "The Apache web server must use cryptography to protect the integrity of remote sessions.",
	"status": status_r_as24_u1_000030,
}
status_r_as24_u1_000030 := "Not_a_Finding" if r_as24_u1_000030
status_r_as24_u1_000030 := "Open" if not r_as24_u1_000030

# AS24-U1-000180 | V-214235 | CAT II
default r_as24_u1_000180 := false
r_as24_u1_000180 if {
	input.apache.log_files_privileged_only == true
}

finding_r_as24_u1_000180 := {
	"vuln_id": "V-214235",
	"stig_id": "AS24-U1-000180",
	"severity": "CAT II",
	"rule_title": "The Apache web server log files must only be accessible by privileged users.",
	"status": status_r_as24_u1_000180,
}
status_r_as24_u1_000180 := "Not_a_Finding" if r_as24_u1_000180
status_r_as24_u1_000180 := "Open" if not r_as24_u1_000180

# AS24-U1-000230 | V-214238 | CAT II
default r_as24_u1_000230 := false
r_as24_u1_000230 if {
	input.apache.modules_reviewed_and_signed == true
}

finding_r_as24_u1_000230 := {
	"vuln_id": "V-214238",
	"stig_id": "AS24-U1-000230",
	"severity": "CAT II",
	"rule_title": "Expansion modules must be fully reviewed, tested, and signed before they can exist on a production Apache web server.",
	"status": status_r_as24_u1_000230,
}
status_r_as24_u1_000230 := "Not_a_Finding" if r_as24_u1_000230
status_r_as24_u1_000230 := "Open" if not r_as24_u1_000230

# AS24-U1-000270 | V-214242 | CAT I
default r_as24_u1_000270 := false
r_as24_u1_000270 if {
	input.apache.documentation_excluded == true
}

finding_r_as24_u1_000270 := {
	"vuln_id": "V-214242",
	"stig_id": "AS24-U1-000270",
	"severity": "CAT I",
	"rule_title": "The Apache web server must provide install options to exclude the installation of documentation, sample code, example applications, and tutorials.",
	"status": status_r_as24_u1_000270,
}
status_r_as24_u1_000270 := "Not_a_Finding" if r_as24_u1_000270
status_r_as24_u1_000270 := "Open" if not r_as24_u1_000270

# AS24-U1-000310 | V-214244 | CAT II
default r_as24_u1_000310 := false
r_as24_u1_000310 if {
	input.apache.unused_script_mappings_removed == true
}

finding_r_as24_u1_000310 := {
	"vuln_id": "V-214244",
	"stig_id": "AS24-U1-000310",
	"severity": "CAT II",
	"rule_title": "The Apache web server must allow the mappings to unused and vulnerable scripts to be removed.",
	"status": status_r_as24_u1_000310,
}
status_r_as24_u1_000310 := "Not_a_Finding" if r_as24_u1_000310
status_r_as24_u1_000310 := "Open" if not r_as24_u1_000310

# AS24-U1-000440 | V-214248 | CAT I
default r_as24_u1_000440 := false
r_as24_u1_000440 if {
	input.apache.app_dirs_admin_only == true
}

finding_r_as24_u1_000440 := {
	"vuln_id": "V-214248",
	"stig_id": "AS24-U1-000440",
	"severity": "CAT I",
	"rule_title": "Apache web server application directories, libraries, and configuration files must only be accessible to privileged users.",
	"status": status_r_as24_u1_000440,
}
status_r_as24_u1_000440 := "Not_a_Finding" if r_as24_u1_000440
status_r_as24_u1_000440 := "Open" if not r_as24_u1_000440

# AS24-U1-000520 | V-214253 | CAT I
default r_as24_u1_000520 := false
r_as24_u1_000520 if {
	input.apache.session_id_full_charset == true
}

finding_r_as24_u1_000520 := {
	"vuln_id": "V-214253",
	"stig_id": "AS24-U1-000520",
	"severity": "CAT I",
	"rule_title": "The Apache web server must generate a session ID using as much of the character set as possible to reduce the risk of brute force.",
	"status": status_r_as24_u1_000520,
}
status_r_as24_u1_000520 := "Not_a_Finding" if r_as24_u1_000520
status_r_as24_u1_000520 := "Open" if not r_as24_u1_000520

# AS24-U1-000650 | V-214258 | CAT II
default r_as24_u1_000650 := false
r_as24_u1_000650 if {
	input.apache.session_inactive_timeout_set == true
}

finding_r_as24_u1_000650 := {
	"vuln_id": "V-214258",
	"stig_id": "AS24-U1-000650",
	"severity": "CAT II",
	"rule_title": "The Apache web server must set an inactive timeout for sessions.",
	"status": status_r_as24_u1_000650,
}
status_r_as24_u1_000650 := "Not_a_Finding" if r_as24_u1_000650
status_r_as24_u1_000650 := "Open" if not r_as24_u1_000650

# AS24-U1-000940 | V-214271 | CAT I
default r_as24_u1_000940 := false
r_as24_u1_000940 if {
	input.apache.service_account_no_login_shell == true
}

finding_r_as24_u1_000940 := {
	"vuln_id": "V-214271",
	"stig_id": "AS24-U1-000940",
	"severity": "CAT I",
	"rule_title": "The account used to run the Apache web server must not have a valid login shell and password defined.",
	"status": status_r_as24_u1_000940,
}
status_r_as24_u1_000940 := "Not_a_Finding" if r_as24_u1_000940
status_r_as24_u1_000940 := "Open" if not r_as24_u1_000940

# AS24-U1-000960 | V-214273 | CAT I
default r_as24_u1_000960 := false
r_as24_u1_000960 if {
	input.apache.vendor_supported_version == true
}

finding_r_as24_u1_000960 := {
	"vuln_id": "V-214273",
	"stig_id": "AS24-U1-000960",
	"severity": "CAT I",
	"rule_title": "The Apache web server software must be a vendor-supported version.",
	"status": status_r_as24_u1_000960,
}
status_r_as24_u1_000960 := "Not_a_Finding" if r_as24_u1_000960
status_r_as24_u1_000960 := "Open" if not r_as24_u1_000960

findings := [
	finding_r_as24_u1_000030,
	finding_r_as24_u1_000180,
	finding_r_as24_u1_000230,
	finding_r_as24_u1_000270,
	finding_r_as24_u1_000310,
	finding_r_as24_u1_000440,
	finding_r_as24_u1_000520,
	finding_r_as24_u1_000650,
	finding_r_as24_u1_000940,
	finding_r_as24_u1_000960,
]

default compliant := false

compliant if count([f | some f in findings; f.status == "Open"]) == 0
