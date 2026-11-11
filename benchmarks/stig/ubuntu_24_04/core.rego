# METADATA
# title: "DISA STIG — Canonical Ubuntu 24.04 LTS Security Technical Implementation Guide"
# custom:
#   class: security
#   framework: stig_ubuntu_24_04
#   source: disa
#   domains: [linux, ubuntu]
#   coverage:
#     checks: 22
#     cited: 22
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: none
#     guard: n/a
#     as_of: v2.4.2
package stig.ubuntu_24_04.core

# DISA STIG — Canonical Ubuntu 24.04 LTS Security Technical Implementation Guide
# V1R7 | Release: 7 Benchmark Date: 30 Sep 2026
# 22 rules (all CAT I + selected CAT II). Rule IDs, severities and
# titles verified against the October 2026 SRG-STIG library XCCDF on 2026-11-10.
# Input contract: see gen_linux.py header / tests fixture.

import rego.v1

# UBTU-24-100030 | V-270647 | CAT I
default r_ubtu_24_100030 := false

r_ubtu_24_100030 if {
	not "telnet" in input.packages
}

finding_r_ubtu_24_100030 := {
	"vuln_id": "V-270647",
	"stig_id": "UBTU-24-100030",
	"severity": "CAT I",
	"rule_title": "Ubuntu 24.04 LTS must not have the telnet package installed.",
	"status": status_r_ubtu_24_100030,
}

status_r_ubtu_24_100030 := "Not_a_Finding" if r_ubtu_24_100030
status_r_ubtu_24_100030 := "Open" if not r_ubtu_24_100030

# UBTU-24-100040 | V-270648 | CAT I
default r_ubtu_24_100040 := false

r_ubtu_24_100040 if {
	not "rsh-server" in input.packages
}

finding_r_ubtu_24_100040 := {
	"vuln_id": "V-270648",
	"stig_id": "UBTU-24-100040",
	"severity": "CAT I",
	"rule_title": "Ubuntu 24.04 LTS must not have the rsh-server package installed.",
	"status": status_r_ubtu_24_100040,
}

status_r_ubtu_24_100040 := "Not_a_Finding" if r_ubtu_24_100040
status_r_ubtu_24_100040 := "Open" if not r_ubtu_24_100040

# UBTU-24-100800 | V-270665 | CAT I
default r_ubtu_24_100800 := false

r_ubtu_24_100800 if {
	"openssh-server" in input.packages
}

finding_r_ubtu_24_100800 := {
	"vuln_id": "V-270665",
	"stig_id": "UBTU-24-100800",
	"severity": "CAT I",
	"rule_title": "Ubuntu 24.04 LTS must have SSH installed.",
	"status": status_r_ubtu_24_100800,
}

status_r_ubtu_24_100800 := "Not_a_Finding" if r_ubtu_24_100800
status_r_ubtu_24_100800 := "Open" if not r_ubtu_24_100800

# UBTU-24-100810 | V-270666 | CAT I
default r_ubtu_24_100810 := false

r_ubtu_24_100810 if {
	input.services.ssh.active == true
}

finding_r_ubtu_24_100810 := {
	"vuln_id": "V-270666",
	"stig_id": "UBTU-24-100810",
	"severity": "CAT I",
	"rule_title": "Ubuntu 24.04 LTS must use SSH to protect the confidentiality and integrity of transmitted information.",
	"status": status_r_ubtu_24_100810,
}

status_r_ubtu_24_100810 := "Not_a_Finding" if r_ubtu_24_100810
status_r_ubtu_24_100810 := "Open" if not r_ubtu_24_100810

# UBTU-24-100820 | V-270667 | CAT II
default r_ubtu_24_100820 := false

r_ubtu_24_100820 if {
	input.sshd_config.Ciphers == "aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes128-ctr"
}

finding_r_ubtu_24_100820 := {
	"vuln_id": "V-270667",
	"stig_id": "UBTU-24-100820",
	"severity": "CAT II",
	"rule_title": "Ubuntu 24.04 LTS must configure the SSH daemon to use FIPS 140-3 approved ciphers to prevent the unauthorized disclosure of information and/or detect changes to information during transmission.",
	"status": status_r_ubtu_24_100820,
}

status_r_ubtu_24_100820 := "Not_a_Finding" if r_ubtu_24_100820
status_r_ubtu_24_100820 := "Open" if not r_ubtu_24_100820

# UBTU-24-100830 | V-270668 | CAT II
default r_ubtu_24_100830 := false

r_ubtu_24_100830 if {
	input.sshd_config.MACs == "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256"
}

finding_r_ubtu_24_100830 := {
	"vuln_id": "V-270668",
	"stig_id": "UBTU-24-100830",
	"severity": "CAT II",
	"rule_title": "Ubuntu 24.04 LTS must configure the SSH daemon to use Message Authentication Codes (MACs) employing FIPS 140-3 approved cryptographic hashes to prevent the unauthorized disclosure of information and/or detect changes to ",
	"status": status_r_ubtu_24_100830,
}

status_r_ubtu_24_100830 := "Not_a_Finding" if r_ubtu_24_100830
status_r_ubtu_24_100830 := "Open" if not r_ubtu_24_100830

# UBTU-24-102000 | V-270675 | CAT I
default r_ubtu_24_102000 := false

r_ubtu_24_102000 if {
	input.grub.password_required == true
}

finding_r_ubtu_24_102000 := {
	"vuln_id": "V-270675",
	"stig_id": "UBTU-24-102000",
	"severity": "CAT I",
	"rule_title": "Ubuntu 24.04 LTS when booted must require authentication upon booting into single-user and maintenance modes.",
	"status": status_r_ubtu_24_102000,
}

status_r_ubtu_24_102000 := "Not_a_Finding" if r_ubtu_24_102000
status_r_ubtu_24_102000 := "Open" if not r_ubtu_24_102000

# UBTU-24-300022 | V-270708 | CAT I
default r_ubtu_24_300022 := false

r_ubtu_24_300022 if {
	input.sshd_config.X11Forwarding == "no"
}

finding_r_ubtu_24_300022 := {
	"vuln_id": "V-270708",
	"stig_id": "UBTU-24-300022",
	"severity": "CAT I",
	"rule_title": "Ubuntu 24.04 LTS must be configured so that remote X connections are disabled, unless to fulfill documented and validated mission requirements.",
	"status": status_r_ubtu_24_300022,
}

status_r_ubtu_24_300022 := "Not_a_Finding" if r_ubtu_24_300022
status_r_ubtu_24_300022 := "Open" if not r_ubtu_24_300022

# UBTU-24-300023 | V-270709 | CAT II
default r_ubtu_24_300023 := false

r_ubtu_24_300023 if {
	input.sshd_config.X11UseLocalhost == "yes"
}

finding_r_ubtu_24_300023 := {
	"vuln_id": "V-270709",
	"stig_id": "UBTU-24-300023",
	"severity": "CAT II",
	"rule_title": "Ubuntu 24.04 LTS SSH daemon must prevent remote hosts from connecting to the proxy display.",
	"status": status_r_ubtu_24_300023,
}

status_r_ubtu_24_300023 := "Not_a_Finding" if r_ubtu_24_300023
status_r_ubtu_24_300023 := "Open" if not r_ubtu_24_300023

# UBTU-24-300025 | V-270711 | CAT I
default r_ubtu_24_300025 := false

r_ubtu_24_300025 if {
	input.gdm.ctrl_alt_del_disabled == true
}

finding_r_ubtu_24_300025 := {
	"vuln_id": "V-270711",
	"stig_id": "UBTU-24-300025",
	"severity": "CAT I",
	"rule_title": "Ubuntu 24.04 LTS must disable the x86 Ctrl-Alt-Delete key sequence if a graphical user interface is installed.",
	"status": status_r_ubtu_24_300025,
}

status_r_ubtu_24_300025 := "Not_a_Finding" if r_ubtu_24_300025
status_r_ubtu_24_300025 := "Open" if not r_ubtu_24_300025

# UBTU-24-300026 | V-270712 | CAT I
default r_ubtu_24_300026 := false

r_ubtu_24_300026 if {
	input.systemd.ctrl_alt_del_masked == true
}

finding_r_ubtu_24_300026 := {
	"vuln_id": "V-270712",
	"stig_id": "UBTU-24-300026",
	"severity": "CAT I",
	"rule_title": "Ubuntu 24.04 LTS must disable the x86 Ctrl-Alt-Delete key sequence.",
	"status": status_r_ubtu_24_300026,
}

status_r_ubtu_24_300026 := "Not_a_Finding" if r_ubtu_24_300026
status_r_ubtu_24_300026 := "Open" if not r_ubtu_24_300026

# UBTU-24-300027 | V-270713 | CAT I
default r_ubtu_24_300027 := false

r_ubtu_24_300027 if {
	count(input.passwd.blank_password_accounts) == 0
}

finding_r_ubtu_24_300027 := {
	"vuln_id": "V-270713",
	"stig_id": "UBTU-24-300027",
	"severity": "CAT I",
	"rule_title": "Ubuntu 24.04 LTS must not have accounts configured with blank or null passwords.",
	"status": status_r_ubtu_24_300027,
}

status_r_ubtu_24_300027 := "Not_a_Finding" if r_ubtu_24_300027
status_r_ubtu_24_300027 := "Open" if not r_ubtu_24_300027

# UBTU-24-300028 | V-270714 | CAT I
default r_ubtu_24_300028 := false

r_ubtu_24_300028 if {
	input.pam.nullok_present == false
}

finding_r_ubtu_24_300028 := {
	"vuln_id": "V-270714",
	"stig_id": "UBTU-24-300028",
	"severity": "CAT I",
	"rule_title": "Ubuntu 24.04 LTS must not allow accounts configured in Pluggable Authentication Modules (PAM) with blank or null passwords.",
	"status": status_r_ubtu_24_300028,
}

status_r_ubtu_24_300028 := "Not_a_Finding" if r_ubtu_24_300028
status_r_ubtu_24_300028 := "Open" if not r_ubtu_24_300028

# UBTU-24-300031 | V-270717 | CAT I
default r_ubtu_24_300031 := false

r_ubtu_24_300031 if {
	input.sshd_config.PermitEmptyPasswords == "no"
	input.sshd_config.PermitUserEnvironment == "no"
}

finding_r_ubtu_24_300031 := {
	"vuln_id": "V-270717",
	"stig_id": "UBTU-24-300031",
	"severity": "CAT I",
	"rule_title": "Ubuntu 24.04 LTS must not allow unattended or automatic login via SSH.",
	"status": status_r_ubtu_24_300031,
}

status_r_ubtu_24_300031 := "Not_a_Finding" if r_ubtu_24_300031
status_r_ubtu_24_300031 := "Open" if not r_ubtu_24_300031

# UBTU-24-400370 | V-270736 | CAT I
default r_ubtu_24_400370 := false

r_ubtu_24_400370 if {
	input.sssd.pki_mapping_configured == true
}

finding_r_ubtu_24_400370 := {
	"vuln_id": "V-270736",
	"stig_id": "UBTU-24-400370",
	"severity": "CAT I",
	"rule_title": "Ubuntu 24.04 LTS must map the authenticated identity to the user or group account for PKI-based authentication.",
	"status": status_r_ubtu_24_400370,
}

status_r_ubtu_24_400370 := "Not_a_Finding" if r_ubtu_24_400370
status_r_ubtu_24_400370 := "Open" if not r_ubtu_24_400370

# UBTU-24-600000 | V-270742 | CAT II
default r_ubtu_24_600000 := false

r_ubtu_24_600000 if {
	input.sshd_config.ClientAliveCountMax == 1
}

finding_r_ubtu_24_600000 := {
	"vuln_id": "V-270742",
	"stig_id": "UBTU-24-600000",
	"severity": "CAT II",
	"rule_title": "Ubuntu 24.04 LTS must immediately terminate all network connections associated with SSH traffic after a period of inactivity.",
	"status": status_r_ubtu_24_600000,
}

status_r_ubtu_24_600000 := "Not_a_Finding" if r_ubtu_24_600000
status_r_ubtu_24_600000 := "Open" if not r_ubtu_24_600000

# UBTU-24-600010 | V-270743 | CAT II
default r_ubtu_24_600010 := false

r_ubtu_24_600010 if {
	input.sshd_config.ClientAliveInterval <= 600
	input.sshd_config.ClientAliveInterval > 0
}

finding_r_ubtu_24_600010 := {
	"vuln_id": "V-270743",
	"stig_id": "UBTU-24-600010",
	"severity": "CAT II",
	"rule_title": "Ubuntu 24.04 LTS must immediately terminate all network connections associated with SSH traffic at the end of the session or after 10 minutes of inactivity.",
	"status": status_r_ubtu_24_600010,
}

status_r_ubtu_24_600010 := "Not_a_Finding" if r_ubtu_24_600010
status_r_ubtu_24_600010 := "Open" if not r_ubtu_24_600010

# UBTU-24-600030 | V-270744 | CAT I
default r_ubtu_24_600030 := false

r_ubtu_24_600030 if {
	input.fips.enabled == true
}

finding_r_ubtu_24_600030 := {
	"vuln_id": "V-270744",
	"stig_id": "UBTU-24-600030",
	"severity": "CAT I",
	"rule_title": "Ubuntu 24.04 LTS must implement NIST FIPS-validated cryptography to protect classified information and for the following: To provision digital signatures, to generate cryptographic hashes, and to protect unclassified inf",
	"status": status_r_ubtu_24_600030,
}

status_r_ubtu_24_600030 := "Not_a_Finding" if r_ubtu_24_600030
status_r_ubtu_24_600030 := "Open" if not r_ubtu_24_600030

# UBTU-24-600070 | V-270746 | CAT II
default r_ubtu_24_600070 := false

r_ubtu_24_600070 if {
	input.services["kdump-tools"].masked == true
}

finding_r_ubtu_24_600070 := {
	"vuln_id": "V-270746",
	"stig_id": "UBTU-24-600070",
	"severity": "CAT II",
	"rule_title": "Ubuntu 24.04 LTS must disable kernel core dumps.",
	"status": status_r_ubtu_24_600070,
}

status_r_ubtu_24_600070 := "Not_a_Finding" if r_ubtu_24_600070
status_r_ubtu_24_600070 := "Open" if not r_ubtu_24_600070

# UBTU-24-600130 | V-270748 | CAT I
default r_ubtu_24_600130 := false

r_ubtu_24_600130 if {
	input.sudo.only_required_members == true
}

finding_r_ubtu_24_600130 := {
	"vuln_id": "V-270748",
	"stig_id": "UBTU-24-600130",
	"severity": "CAT I",
	"rule_title": "Ubuntu 24.04 LTS must ensure only users who need access to security functions are part of sudo group.",
	"status": status_r_ubtu_24_600130,
}

status_r_ubtu_24_600130 := "Not_a_Finding" if r_ubtu_24_600130
status_r_ubtu_24_600130 := "Open" if not r_ubtu_24_600130

# UBTU-24-600140 | V-270749 | CAT III
default r_ubtu_24_600140 := false

r_ubtu_24_600140 if {
	input.sysctl["kernel.dmesg_restrict"] == 1
}

finding_r_ubtu_24_600140 := {
	"vuln_id": "V-270749",
	"stig_id": "UBTU-24-600140",
	"severity": "CAT III",
	"rule_title": "Ubuntu 24.04 LTS must restrict access to the kernel message buffer.",
	"status": status_r_ubtu_24_600140,
}

status_r_ubtu_24_600140 := "Not_a_Finding" if r_ubtu_24_600140
status_r_ubtu_24_600140 := "Open" if not r_ubtu_24_600140

# UBTU-24-700400 | V-278917 | CAT I
default r_ubtu_24_700400 := false

r_ubtu_24_700400 if {
	input.os.vendor_supported == true
}

finding_r_ubtu_24_700400 := {
	"vuln_id": "V-278917",
	"stig_id": "UBTU-24-700400",
	"severity": "CAT I",
	"rule_title": "Ubuntu 24.04 LTS must be a vendor-supported release.",
	"status": status_r_ubtu_24_700400,
}

status_r_ubtu_24_700400 := "Not_a_Finding" if r_ubtu_24_700400
status_r_ubtu_24_700400 := "Open" if not r_ubtu_24_700400

findings := [
	finding_r_ubtu_24_100030,
	finding_r_ubtu_24_100040,
	finding_r_ubtu_24_100800,
	finding_r_ubtu_24_100810,
	finding_r_ubtu_24_100820,
	finding_r_ubtu_24_100830,
	finding_r_ubtu_24_102000,
	finding_r_ubtu_24_300022,
	finding_r_ubtu_24_300023,
	finding_r_ubtu_24_300025,
	finding_r_ubtu_24_300026,
	finding_r_ubtu_24_300027,
	finding_r_ubtu_24_300028,
	finding_r_ubtu_24_300031,
	finding_r_ubtu_24_400370,
	finding_r_ubtu_24_600000,
	finding_r_ubtu_24_600010,
	finding_r_ubtu_24_600030,
	finding_r_ubtu_24_600070,
	finding_r_ubtu_24_600130,
	finding_r_ubtu_24_600140,
	finding_r_ubtu_24_700400,
]

default compliant := false

compliant if count([f | some f in findings; f.status == "Open"]) == 0
