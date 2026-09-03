package stig.ubuntu_22_04.core

# DISA STIG — Canonical Ubuntu 22.04 LTS Security Technical Implementation Guide
# V2R9 | Release: 9 Benchmark Date: 01 Jul 2026
# 22 rules (all CAT I + selected CAT II). Rule IDs, severities and
# titles verified against the July 2026 SRG-STIG library XCCDF on 2026-09-03.
# Input contract: see gen_linux.py header / tests fixture.

import rego.v1

# UBTU-22-211000 | V-278951 | CAT I
default r_ubtu_22_211000 := false
r_ubtu_22_211000 if {
	input.os.vendor_supported == true
}

finding_r_ubtu_22_211000 := {
	"vuln_id": "V-278951",
	"stig_id": "UBTU-22-211000",
	"severity": "CAT I",
	"rule_title": "Ubuntu 22.04 LTS must be a vendor-supported release.",
	"status": status_r_ubtu_22_211000,
}
status_r_ubtu_22_211000 := "Not_a_Finding" if r_ubtu_22_211000
status_r_ubtu_22_211000 := "Open" if not r_ubtu_22_211000

# UBTU-22-211015 | V-260469 | CAT I
default r_ubtu_22_211015 := false
r_ubtu_22_211015 if {
	input.systemd.ctrl_alt_del_masked == true
}

finding_r_ubtu_22_211015 := {
	"vuln_id": "V-260469",
	"stig_id": "UBTU-22-211015",
	"severity": "CAT I",
	"rule_title": "Ubuntu 22.04 LTS must disable the x86 Ctrl-Alt-Delete key sequence.",
	"status": status_r_ubtu_22_211015,
}
status_r_ubtu_22_211015 := "Not_a_Finding" if r_ubtu_22_211015
status_r_ubtu_22_211015 := "Open" if not r_ubtu_22_211015

# UBTU-22-212010 | V-260470 | CAT I
default r_ubtu_22_212010 := false
r_ubtu_22_212010 if {
	input.grub.password_required == true
}

finding_r_ubtu_22_212010 := {
	"vuln_id": "V-260470",
	"stig_id": "UBTU-22-212010",
	"severity": "CAT I",
	"rule_title": "Ubuntu 22.04 LTS, when booted, must require authentication upon booting into single-user and maintenance modes.",
	"status": status_r_ubtu_22_212010,
}
status_r_ubtu_22_212010 := "Not_a_Finding" if r_ubtu_22_212010
status_r_ubtu_22_212010 := "Open" if not r_ubtu_22_212010

# UBTU-22-213010 | V-260472 | CAT III
default r_ubtu_22_213010 := false
r_ubtu_22_213010 if {
	input.sysctl["kernel.dmesg_restrict"] == 1
}

finding_r_ubtu_22_213010 := {
	"vuln_id": "V-260472",
	"stig_id": "UBTU-22-213010",
	"severity": "CAT III",
	"rule_title": "Ubuntu 22.04 LTS must restrict access to the kernel message buffer.",
	"status": status_r_ubtu_22_213010,
}
status_r_ubtu_22_213010 := "Not_a_Finding" if r_ubtu_22_213010
status_r_ubtu_22_213010 := "Open" if not r_ubtu_22_213010

# UBTU-22-213015 | V-260473 | CAT II
default r_ubtu_22_213015 := false
r_ubtu_22_213015 if {
	input.services["kdump-tools"].masked == true
}

finding_r_ubtu_22_213015 := {
	"vuln_id": "V-260473",
	"stig_id": "UBTU-22-213015",
	"severity": "CAT II",
	"rule_title": "Ubuntu 22.04 LTS must disable kernel core dumps so that it can fail to a secure state if system initialization fails, shutdown fails or aborts fail.",
	"status": status_r_ubtu_22_213015,
}
status_r_ubtu_22_213015 := "Not_a_Finding" if r_ubtu_22_213015
status_r_ubtu_22_213015 := "Open" if not r_ubtu_22_213015

# UBTU-22-215030 | V-260482 | CAT I
default r_ubtu_22_215030 := false
r_ubtu_22_215030 if {
	not "rsh-server" in input.packages
}

finding_r_ubtu_22_215030 := {
	"vuln_id": "V-260482",
	"stig_id": "UBTU-22-215030",
	"severity": "CAT I",
	"rule_title": "Ubuntu 22.04 LTS must not have the \"rsh-server\" package installed.",
	"status": status_r_ubtu_22_215030,
}
status_r_ubtu_22_215030 := "Not_a_Finding" if r_ubtu_22_215030
status_r_ubtu_22_215030 := "Open" if not r_ubtu_22_215030

# UBTU-22-215035 | V-260483 | CAT I
default r_ubtu_22_215035 := false
r_ubtu_22_215035 if {
	not "telnet" in input.packages
}

finding_r_ubtu_22_215035 := {
	"vuln_id": "V-260483",
	"stig_id": "UBTU-22-215035",
	"severity": "CAT I",
	"rule_title": "Ubuntu 22.04 LTS must not have the \"telnet\" package installed.",
	"status": status_r_ubtu_22_215035,
}
status_r_ubtu_22_215035 := "Not_a_Finding" if r_ubtu_22_215035
status_r_ubtu_22_215035 := "Open" if not r_ubtu_22_215035

# UBTU-22-255010 | V-260523 | CAT I
default r_ubtu_22_255010 := false
r_ubtu_22_255010 if {
	"openssh-server" in input.packages
}

finding_r_ubtu_22_255010 := {
	"vuln_id": "V-260523",
	"stig_id": "UBTU-22-255010",
	"severity": "CAT I",
	"rule_title": "Ubuntu 22.04 LTS must have SSH installed.",
	"status": status_r_ubtu_22_255010,
}
status_r_ubtu_22_255010 := "Not_a_Finding" if r_ubtu_22_255010
status_r_ubtu_22_255010 := "Open" if not r_ubtu_22_255010

# UBTU-22-255015 | V-260524 | CAT I
default r_ubtu_22_255015 := false
r_ubtu_22_255015 if {
	input.services["ssh"].active == true
}

finding_r_ubtu_22_255015 := {
	"vuln_id": "V-260524",
	"stig_id": "UBTU-22-255015",
	"severity": "CAT I",
	"rule_title": "Ubuntu 22.04 LTS must use SSH to protect the confidentiality and integrity of transmitted information.",
	"status": status_r_ubtu_22_255015,
}
status_r_ubtu_22_255015 := "Not_a_Finding" if r_ubtu_22_255015
status_r_ubtu_22_255015 := "Open" if not r_ubtu_22_255015

# UBTU-22-255025 | V-260526 | CAT I
default r_ubtu_22_255025 := false
r_ubtu_22_255025 if {
	input.sshd_config.PermitEmptyPasswords == "no"
	input.sshd_config.PermitUserEnvironment == "no"
}

finding_r_ubtu_22_255025 := {
	"vuln_id": "V-260526",
	"stig_id": "UBTU-22-255025",
	"severity": "CAT I",
	"rule_title": "Ubuntu 22.04 LTS must not allow unattended or automatic login via SSH.",
	"status": status_r_ubtu_22_255025,
}
status_r_ubtu_22_255025 := "Not_a_Finding" if r_ubtu_22_255025
status_r_ubtu_22_255025 := "Open" if not r_ubtu_22_255025

# UBTU-22-255030 | V-260527 | CAT II
default r_ubtu_22_255030 := false
r_ubtu_22_255030 if {
	input.sshd_config.ClientAliveCountMax == 1
}

finding_r_ubtu_22_255030 := {
	"vuln_id": "V-260527",
	"stig_id": "UBTU-22-255030",
	"severity": "CAT II",
	"rule_title": "Ubuntu 22.04 LTS must be configured so that all network connections associated with SSH traffic terminate after becoming unresponsive.",
	"status": status_r_ubtu_22_255030,
}
status_r_ubtu_22_255030 := "Not_a_Finding" if r_ubtu_22_255030
status_r_ubtu_22_255030 := "Open" if not r_ubtu_22_255030

# UBTU-22-255035 | V-260528 | CAT II
default r_ubtu_22_255035 := false
r_ubtu_22_255035 if {
	input.sshd_config.ClientAliveInterval <= 600
	input.sshd_config.ClientAliveInterval > 0
}

finding_r_ubtu_22_255035 := {
	"vuln_id": "V-260528",
	"stig_id": "UBTU-22-255035",
	"severity": "CAT II",
	"rule_title": "Ubuntu 22.04 LTS must be configured so that all network connections associated with SSH traffic are terminated after 10 minutes of becoming unresponsive.",
	"status": status_r_ubtu_22_255035,
}
status_r_ubtu_22_255035 := "Not_a_Finding" if r_ubtu_22_255035
status_r_ubtu_22_255035 := "Open" if not r_ubtu_22_255035

# UBTU-22-255040 | V-260529 | CAT I
default r_ubtu_22_255040 := false
r_ubtu_22_255040 if {
	input.sshd_config.X11Forwarding == "no"
}

finding_r_ubtu_22_255040 := {
	"vuln_id": "V-260529",
	"stig_id": "UBTU-22-255040",
	"severity": "CAT I",
	"rule_title": "Ubuntu 22.04 LTS must be configured so that remote X connections are disabled, unless to fulfill documented and validated mission requirements.",
	"status": status_r_ubtu_22_255040,
}
status_r_ubtu_22_255040 := "Not_a_Finding" if r_ubtu_22_255040
status_r_ubtu_22_255040 := "Open" if not r_ubtu_22_255040

# UBTU-22-255045 | V-260530 | CAT II
default r_ubtu_22_255045 := false
r_ubtu_22_255045 if {
	input.sshd_config.X11UseLocalhost == "yes"
}

finding_r_ubtu_22_255045 := {
	"vuln_id": "V-260530",
	"stig_id": "UBTU-22-255045",
	"severity": "CAT II",
	"rule_title": "Ubuntu 22.04 LTS SSH daemon must prevent remote hosts from connecting to the proxy display.",
	"status": status_r_ubtu_22_255045,
}
status_r_ubtu_22_255045 := "Not_a_Finding" if r_ubtu_22_255045
status_r_ubtu_22_255045 := "Open" if not r_ubtu_22_255045

# UBTU-22-255050 | V-260531 | CAT II
default r_ubtu_22_255050 := false
r_ubtu_22_255050 if {
	input.sshd_config.Ciphers == "aes256-ctr,aes256-gcm@openssh.com,aes128-ctr,aes128-gcm@openssh.com"
}

finding_r_ubtu_22_255050 := {
	"vuln_id": "V-260531",
	"stig_id": "UBTU-22-255050",
	"severity": "CAT II",
	"rule_title": "Ubuntu 22.04 LTS must configure the SSH daemon to use FIPS 140-3-approved ciphers to prevent the unauthorized disclosure of information and/or detect changes to information during transmission.",
	"status": status_r_ubtu_22_255050,
}
status_r_ubtu_22_255050 := "Not_a_Finding" if r_ubtu_22_255050
status_r_ubtu_22_255050 := "Open" if not r_ubtu_22_255050

# UBTU-22-255055 | V-260532 | CAT II
default r_ubtu_22_255055 := false
r_ubtu_22_255055 if {
	input.sshd_config.MACs == "hmac-sha2-512,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-256-etm@openssh.com"
}

finding_r_ubtu_22_255055 := {
	"vuln_id": "V-260532",
	"stig_id": "UBTU-22-255055",
	"severity": "CAT II",
	"rule_title": "Ubuntu 22.04 LTS must configure the SSH daemon to use Message Authentication Codes (MACs) employing FIPS 140-3-approved cryptographic hashes to prevent the unauthorized disclosure of information and/or detect changes to ",
	"status": status_r_ubtu_22_255055,
}
status_r_ubtu_22_255055 := "Not_a_Finding" if r_ubtu_22_255055
status_r_ubtu_22_255055 := "Open" if not r_ubtu_22_255055

# UBTU-22-271030 | V-260539 | CAT I
default r_ubtu_22_271030 := false
r_ubtu_22_271030 if {
	input.gdm.ctrl_alt_del_disabled == true
}

finding_r_ubtu_22_271030 := {
	"vuln_id": "V-260539",
	"stig_id": "UBTU-22-271030",
	"severity": "CAT I",
	"rule_title": "Ubuntu 22.04 LTS must disable the x86 Ctrl-Alt-Delete key sequence if a graphical user interface is installed.",
	"status": status_r_ubtu_22_271030,
}
status_r_ubtu_22_271030 := "Not_a_Finding" if r_ubtu_22_271030
status_r_ubtu_22_271030 := "Open" if not r_ubtu_22_271030

# UBTU-22-432015 | V-260559 | CAT I
default r_ubtu_22_432015 := false
r_ubtu_22_432015 if {
	input.sudo.only_required_members == true
}

finding_r_ubtu_22_432015 := {
	"vuln_id": "V-260559",
	"stig_id": "UBTU-22-432015",
	"severity": "CAT I",
	"rule_title": "Ubuntu 22.04 LTS must ensure only users who need access to security functions are part of sudo group.",
	"status": status_r_ubtu_22_432015,
}
status_r_ubtu_22_432015 := "Not_a_Finding" if r_ubtu_22_432015
status_r_ubtu_22_432015 := "Open" if not r_ubtu_22_432015

# UBTU-22-611060 | V-260570 | CAT I
default r_ubtu_22_611060 := false
r_ubtu_22_611060 if {
	input.pam.nullok_present == false
}

finding_r_ubtu_22_611060 := {
	"vuln_id": "V-260570",
	"stig_id": "UBTU-22-611060",
	"severity": "CAT I",
	"rule_title": "Ubuntu 22.04 LTS must not allow accounts configured with blank or null passwords.",
	"status": status_r_ubtu_22_611060,
}
status_r_ubtu_22_611060 := "Not_a_Finding" if r_ubtu_22_611060
status_r_ubtu_22_611060 := "Open" if not r_ubtu_22_611060

# UBTU-22-611065 | V-260571 | CAT I
default r_ubtu_22_611065 := false
r_ubtu_22_611065 if {
	count(input.passwd.blank_password_accounts) == 0
}

finding_r_ubtu_22_611065 := {
	"vuln_id": "V-260571",
	"stig_id": "UBTU-22-611065",
	"severity": "CAT I",
	"rule_title": "Ubuntu 22.04 LTS must not have accounts configured with blank or null passwords.",
	"status": status_r_ubtu_22_611065,
}
status_r_ubtu_22_611065 := "Not_a_Finding" if r_ubtu_22_611065
status_r_ubtu_22_611065 := "Open" if not r_ubtu_22_611065

# UBTU-22-612040 | V-260579 | CAT I
default r_ubtu_22_612040 := false
r_ubtu_22_612040 if {
	input.sssd.pki_mapping_configured == true
}

finding_r_ubtu_22_612040 := {
	"vuln_id": "V-260579",
	"stig_id": "UBTU-22-612040",
	"severity": "CAT I",
	"rule_title": "Ubuntu 22.04 LTS must map the authenticated identity to the user or group account for PKI-based authentication.",
	"status": status_r_ubtu_22_612040,
}
status_r_ubtu_22_612040 := "Not_a_Finding" if r_ubtu_22_612040
status_r_ubtu_22_612040 := "Open" if not r_ubtu_22_612040

# UBTU-22-671010 | V-260650 | CAT I
default r_ubtu_22_671010 := false
r_ubtu_22_671010 if {
	input.fips.enabled == true
}

finding_r_ubtu_22_671010 := {
	"vuln_id": "V-260650",
	"stig_id": "UBTU-22-671010",
	"severity": "CAT I",
	"rule_title": "Ubuntu 22.04 LTS must implement NIST FIPS-validated cryptography to protect classified information and for the following: To provision digital signatures, to generate cryptographic hashes, and to protect unclassified inf",
	"status": status_r_ubtu_22_671010,
}
status_r_ubtu_22_671010 := "Not_a_Finding" if r_ubtu_22_671010
status_r_ubtu_22_671010 := "Open" if not r_ubtu_22_671010

findings := [
	finding_r_ubtu_22_211000,
	finding_r_ubtu_22_211015,
	finding_r_ubtu_22_212010,
	finding_r_ubtu_22_213010,
	finding_r_ubtu_22_213015,
	finding_r_ubtu_22_215030,
	finding_r_ubtu_22_215035,
	finding_r_ubtu_22_255010,
	finding_r_ubtu_22_255015,
	finding_r_ubtu_22_255025,
	finding_r_ubtu_22_255030,
	finding_r_ubtu_22_255035,
	finding_r_ubtu_22_255040,
	finding_r_ubtu_22_255045,
	finding_r_ubtu_22_255050,
	finding_r_ubtu_22_255055,
	finding_r_ubtu_22_271030,
	finding_r_ubtu_22_432015,
	finding_r_ubtu_22_611060,
	finding_r_ubtu_22_611065,
	finding_r_ubtu_22_612040,
	finding_r_ubtu_22_671010,
]

default compliant := false

compliant if count([f | some f in findings; f.status == "Open"]) == 0
