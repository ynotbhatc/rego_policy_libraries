package stig.rhel_8.ssh_config

# DISA STIG for RHEL 8 - SSH Configuration Module
# STIG Version: V1R13 | Released: July 2024

import rego.v1

default compliant := false

# =============================================================================
# CAT I
# =============================================================================

# RHEL-08-040160 | V-230555 | CAT I - SSH must not allow root login
default no_root_login := false
no_root_login if { lower(input.ssh_config.PermitRootLogin) == "no" }

status_rhel_08_040160 := "Not_a_Finding" if { no_root_login } else := "Open"
finding_rhel_08_040160 := {
	"vuln_id": "V-230555",
	"stig_id": "RHEL-08-040160",
	"severity": "CAT I",
	"rule_title": "RHEL 8 must not permit direct logons to the root account using remote access via SSH",
	"status": status_rhel_08_040160,
	"fix_text": "Set PermitRootLogin no in /etc/ssh/sshd_config",
}

# RHEL-08-040170 | V-230556 | CAT I - SSH must use FIPS ciphers
default ssh_fips_ciphers := false
ssh_fips_ciphers if {
	ciphers := input.ssh_config.Ciphers
	not contains(ciphers, "3des")
	not contains(ciphers, "arcfour")
	not contains(ciphers, "blowfish")
}

status_rhel_08_040170 := "Not_a_Finding" if { ssh_fips_ciphers } else := "Open"
finding_rhel_08_040170 := {
	"vuln_id": "V-230556",
	"stig_id": "RHEL-08-040170",
	"severity": "CAT I",
	"rule_title": "RHEL 8 must implement DoD-approved encryption in the OpenSSH client",
	"status": status_rhel_08_040170,
	"fix_text": "Set Ciphers aes256-ctr,aes192-ctr,aes128-ctr in /etc/ssh/sshd_config",
}

# =============================================================================
# CAT II
# =============================================================================

# RHEL-08-040180 | V-230557 | CAT II - SSH must not allow empty passwords
default no_empty_passwords := false
no_empty_passwords if { lower(input.ssh_config.PermitEmptyPasswords) == "no" }

status_rhel_08_040180 := "Not_a_Finding" if { no_empty_passwords } else := "Open"
finding_rhel_08_040180 := {
	"vuln_id": "V-230557",
	"stig_id": "RHEL-08-040180",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must not allow blank or null passwords",
	"status": status_rhel_08_040180,
	"fix_text": "Set PermitEmptyPasswords no in /etc/ssh/sshd_config",
}

# RHEL-08-040190 | V-230558 | CAT II - MaxAuthTries must be 4 or less
default max_auth_tries := false
max_auth_tries if { to_number(input.ssh_config.MaxAuthTries) <= 4 }

status_rhel_08_040190 := "Not_a_Finding" if { max_auth_tries } else := "Open"
finding_rhel_08_040190 := {
	"vuln_id": "V-230558",
	"stig_id": "RHEL-08-040190",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must limit the number of SSH login attempts",
	"status": status_rhel_08_040190,
	"fix_text": "Set MaxAuthTries 4 in /etc/ssh/sshd_config",
}

# RHEL-08-040200 | V-230559 | CAT II - ClientAliveInterval must be 600 or less
default client_alive := false
client_alive if {
	to_number(input.ssh_config.ClientAliveInterval) <= 600
	to_number(input.ssh_config.ClientAliveInterval) > 0
}

status_rhel_08_040200 := "Not_a_Finding" if { client_alive } else := "Open"
finding_rhel_08_040200 := {
	"vuln_id": "V-230559",
	"stig_id": "RHEL-08-040200",
	"severity": "CAT II",
	"rule_title": "RHEL 8 SSH client alive interval must be configured",
	"status": status_rhel_08_040200,
	"fix_text": "Set ClientAliveInterval 600 in /etc/ssh/sshd_config",
}

# RHEL-08-040210 | V-230560 | CAT II - SSH must use FIPS MACs
default ssh_fips_macs := false
ssh_fips_macs if {
	macs := input.ssh_config.MACs
	contains(macs, "hmac-sha2")
	not contains(macs, "hmac-md5")
	not contains(macs, "hmac-sha1")
}

status_rhel_08_040210 := "Not_a_Finding" if { ssh_fips_macs } else := "Open"
finding_rhel_08_040210 := {
	"vuln_id": "V-230560",
	"stig_id": "RHEL-08-040210",
	"severity": "CAT II",
	"rule_title": "RHEL 8 SSH server must be configured to use only MACs employing FIPS-validated algorithms",
	"status": status_rhel_08_040210,
	"fix_text": "Set MACs hmac-sha2-512,hmac-sha2-256 in /etc/ssh/sshd_config",
}

# RHEL-08-040220 | V-230561 | CAT II - IgnoreRhosts must be yes
default ignore_rhosts := false
ignore_rhosts if { lower(input.ssh_config.IgnoreRhosts) == "yes" }

status_rhel_08_040220 := "Not_a_Finding" if { ignore_rhosts } else := "Open"
finding_rhel_08_040220 := {
	"vuln_id": "V-230561",
	"stig_id": "RHEL-08-040220",
	"severity": "CAT II",
	"rule_title": "RHEL 8 SSH daemon must not allow rhosts-based authentication",
	"status": status_rhel_08_040220,
	"fix_text": "Set IgnoreRhosts yes in /etc/ssh/sshd_config",
}

# RHEL-08-040230 | V-230562 | CAT II - HostbasedAuthentication must be no
default no_hostbased := false
no_hostbased if { lower(input.ssh_config.HostbasedAuthentication) == "no" }

status_rhel_08_040230 := "Not_a_Finding" if { no_hostbased } else := "Open"
finding_rhel_08_040230 := {
	"vuln_id": "V-230562",
	"stig_id": "RHEL-08-040230",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must not allow host-based authentication via SSH",
	"status": status_rhel_08_040230,
	"fix_text": "Set HostbasedAuthentication no in /etc/ssh/sshd_config",
}

# RHEL-08-040240 | V-230563 | CAT II - UsePAM must be yes
default use_pam := false
use_pam if { lower(input.ssh_config.UsePAM) == "yes" }

status_rhel_08_040240 := "Not_a_Finding" if { use_pam } else := "Open"
finding_rhel_08_040240 := {
	"vuln_id": "V-230563",
	"stig_id": "RHEL-08-040240",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must enable PAM for SSH",
	"status": status_rhel_08_040240,
	"fix_text": "Set UsePAM yes in /etc/ssh/sshd_config",
}

# RHEL-08-040250 | V-230564 | CAT II - Banner must be set
default ssh_banner := false
ssh_banner if {
	input.ssh_config.Banner != ""
	input.ssh_config.Banner != "none"
}

status_rhel_08_040250 := "Not_a_Finding" if { ssh_banner } else := "Open"
finding_rhel_08_040250 := {
	"vuln_id": "V-230564",
	"stig_id": "RHEL-08-040250",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must display the Standard Mandatory DoD Notice and Consent Banner before SSH access",
	"status": status_rhel_08_040250,
	"fix_text": "Set Banner /etc/issue in /etc/ssh/sshd_config",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

cat_i_findings := [
	finding_rhel_08_040160,
	finding_rhel_08_040170,
]

cat_ii_findings := [
	finding_rhel_08_040180,
	finding_rhel_08_040190,
	finding_rhel_08_040200,
	finding_rhel_08_040210,
	finding_rhel_08_040220,
	finding_rhel_08_040230,
	finding_rhel_08_040240,
	finding_rhel_08_040250,
]

findings := array.concat(cat_i_findings, cat_ii_findings)

violations contains finding.stig_id if {
	some finding in findings
	finding.status == "Open"
}

open_cat_i contains f if {
	some f in cat_i_findings
	f.status == "Open"
}

compliant if { count(open_cat_i) == 0 }

compliance_report := {
	"module": "ssh_config",
	"total_findings": count(findings),
	"open_findings": count(violations),
	"cat_i_open": count(open_cat_i),
	"findings": findings,
	"compliant": compliant,
}
