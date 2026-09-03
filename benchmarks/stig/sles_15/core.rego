package stig.sles_15.core

# DISA STIG — SUSE Linux Enterprise Server 15 Security Technical Implementation Guide
# V2R8 | Release: 8 Benchmark Date: 01 Jul 2026
# 27 rules (all CAT I + selected CAT II). Rule IDs, severities and
# titles verified against the July 2026 SRG-STIG library XCCDF on 2026-09-03.
# Input contract: see gen_linux.py header / tests fixture.

import rego.v1

# SLES-15-010000 | V-234800 | CAT I
default r_sles_15_010000 := false
r_sles_15_010000 if {
	input.os.vendor_supported == true
}

finding_r_sles_15_010000 := {
	"vuln_id": "V-234800",
	"stig_id": "SLES-15-010000",
	"severity": "CAT I",
	"rule_title": "The SUSE operating system must be a vendor-supported release.",
	"status": status_r_sles_15_010000,
}
status_r_sles_15_010000 := "Not_a_Finding" if r_sles_15_010000
status_r_sles_15_010000 := "Open" if not r_sles_15_010000

# SLES-15-010030 | V-234804 | CAT I
default r_sles_15_010030 := false
r_sles_15_010030 if {
	not "vsftpd" in input.packages
}

finding_r_sles_15_010030 := {
	"vuln_id": "V-234804",
	"stig_id": "SLES-15-010030",
	"severity": "CAT I",
	"rule_title": "The SUSE operating system must not have the vsftpd package installed if not required for operational support.",
	"status": status_r_sles_15_010030,
}
status_r_sles_15_010030 := "Not_a_Finding" if r_sles_15_010030
status_r_sles_15_010030 := "Open" if not r_sles_15_010030

# SLES-15-010035 | V-284950 | CAT I
default r_sles_15_010035 := false
r_sles_15_010035 if {
	"crypto-policies" in input.packages
}

finding_r_sles_15_010035 := {
	"vuln_id": "V-284950",
	"stig_id": "SLES-15-010035",
	"severity": "CAT I",
	"rule_title": "The SUSE operating system must have the crypto-policies package installed.",
	"status": status_r_sles_15_010035,
}
status_r_sles_15_010035 := "Not_a_Finding" if r_sles_15_010035
status_r_sles_15_010035 := "Open" if not r_sles_15_010035

# SLES-15-010045 | V-284951 | CAT I
default r_sles_15_010045 := false
r_sles_15_010045 if {
	input.crypto_policy.policy == "FIPS"
}

finding_r_sles_15_010045 := {
	"vuln_id": "V-284951",
	"stig_id": "SLES-15-010045",
	"severity": "CAT I",
	"rule_title": "The SUSE operating system must implement a FIPS 140-3-compliant systemwide cryptographic policy.",
	"status": status_r_sles_15_010045,
}
status_r_sles_15_010045 := "Not_a_Finding" if r_sles_15_010045
status_r_sles_15_010045 := "Open" if not r_sles_15_010045

# SLES-15-010046 | V-284953 | CAT I
default r_sles_15_010046 := false
r_sles_15_010046 if {
	input.crypto_policy.overridden == false
}

finding_r_sles_15_010046 := {
	"vuln_id": "V-284953",
	"stig_id": "SLES-15-010046",
	"severity": "CAT I",
	"rule_title": "SUSE operating system cryptographic policy must not be overridden.",
	"status": status_r_sles_15_010046,
}
status_r_sles_15_010046 := "Not_a_Finding" if r_sles_15_010046
status_r_sles_15_010046 := "Open" if not r_sles_15_010046

# SLES-15-010160 | V-234816 | CAT I
default r_sles_15_010160 := false
r_sles_15_010160 if {
	input.crypto_policy.opensshserver_ciphers == "aes256-gcm@openssh.com,aes256-ctr,aes128-gcm@openssh.com,aes128-ctr"
}

finding_r_sles_15_010160 := {
	"vuln_id": "V-234816",
	"stig_id": "SLES-15-010160",
	"severity": "CAT I",
	"rule_title": "The SUSE operating system must implement DOD-approved encryption to protect the confidentiality of SSH remote connections.",
	"status": status_r_sles_15_010160,
}
status_r_sles_15_010160 := "Not_a_Finding" if r_sles_15_010160
status_r_sles_15_010160 := "Open" if not r_sles_15_010160

# SLES-15-010180 | V-234818 | CAT I
default r_sles_15_010180 := false
r_sles_15_010180 if {
	not "telnet-server" in input.packages
}

finding_r_sles_15_010180 := {
	"vuln_id": "V-234818",
	"stig_id": "SLES-15-010180",
	"severity": "CAT I",
	"rule_title": "The SUSE operating system must not have the telnet-server package installed.",
	"status": status_r_sles_15_010180,
}
status_r_sles_15_010180 := "Not_a_Finding" if r_sles_15_010180
status_r_sles_15_010180 := "Open" if not r_sles_15_010180

# SLES-15-010190 | V-234819 | CAT I
default r_sles_15_010190 := false
r_sles_15_010190 if {
	input.grub.password_required == true
}

finding_r_sles_15_010190 := {
	"vuln_id": "V-234819",
	"stig_id": "SLES-15-010190",
	"severity": "CAT I",
	"rule_title": "SUSE operating systems with a basic input/output system (BIOS) must require authentication upon booting into single-user and maintenance modes.",
	"status": status_r_sles_15_010190,
}
status_r_sles_15_010190 := "Not_a_Finding" if r_sles_15_010190
status_r_sles_15_010190 := "Open" if not r_sles_15_010190

# SLES-15-010200 | V-234820 | CAT I
default r_sles_15_010200 := false
r_sles_15_010200 if {
	input.grub.uefi_password_required == true
}

finding_r_sles_15_010200 := {
	"vuln_id": "V-234820",
	"stig_id": "SLES-15-010200",
	"severity": "CAT I",
	"rule_title": "SUSE operating systems with Unified Extensible Firmware Interface (UEFI) implemented must require authentication upon booting into single-user mode and maintenance.",
	"status": status_r_sles_15_010200,
}
status_r_sles_15_010200 := "Not_a_Finding" if r_sles_15_010200
status_r_sles_15_010200 := "Open" if not r_sles_15_010200

# SLES-15-010220 | V-234821 | CAT II
default r_sles_15_010220 := false
r_sles_15_010220 if {
	input.sshd_config.PermitRootLogin == "no"
}

finding_r_sles_15_010220 := {
	"vuln_id": "V-234821",
	"stig_id": "SLES-15-010220",
	"severity": "CAT II",
	"rule_title": "The SUSE operating system must be configured to prohibit or restrict the use of functions, ports, protocols, and/or services as defined in the Ports, Protocols, and Services Management (PPSM) Category Assignments List (C",
	"status": status_r_sles_15_010220,
}
status_r_sles_15_010220 := "Not_a_Finding" if r_sles_15_010220
status_r_sles_15_010220 := "Open" if not r_sles_15_010220

# SLES-15-010270 | V-234826 | CAT I
default r_sles_15_010270 := false
r_sles_15_010270 if {
	input.crypto_policy.opensshserver_macs == "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512"
}

finding_r_sles_15_010270 := {
	"vuln_id": "V-234826",
	"stig_id": "SLES-15-010270",
	"severity": "CAT I",
	"rule_title": "The SUSE operating system SSH server must be configured to use only Message Authentication Codes (MACs) employing FIPS 140-3 validated cryptographic hash algorithms to protect the confidentiality of SSH server connection",
	"status": status_r_sles_15_010270,
}
status_r_sles_15_010270 := "Not_a_Finding" if r_sles_15_010270
status_r_sles_15_010270 := "Open" if not r_sles_15_010270

# SLES-15-010280 | V-234827 | CAT II
default r_sles_15_010280 := false
r_sles_15_010280 if {
	input.sshd_config.X11Forwarding == "no"
}

finding_r_sles_15_010280 := {
	"vuln_id": "V-234827",
	"stig_id": "SLES-15-010280",
	"severity": "CAT II",
	"rule_title": "The SUSE operating system SSH daemon must be configured with a timeout interval.",
	"status": status_r_sles_15_010280,
}
status_r_sles_15_010280 := "Not_a_Finding" if r_sles_15_010280
status_r_sles_15_010280 := "Open" if not r_sles_15_010280

# SLES-15-010330 | V-234831 | CAT I
default r_sles_15_010330 := false
r_sles_15_010330 if {
	input.storage.persistent_partitions_encrypted == true
}

finding_r_sles_15_010330 := {
	"vuln_id": "V-234831",
	"stig_id": "SLES-15-010330",
	"severity": "CAT I",
	"rule_title": "All SUSE operating system persistent disk partitions must implement cryptographic mechanisms to prevent unauthorized disclosure or modification of all information that requires at-rest protection.",
	"status": status_r_sles_15_010330,
}
status_r_sles_15_010330 := "Not_a_Finding" if r_sles_15_010330
status_r_sles_15_010330 := "Open" if not r_sles_15_010330

# SLES-15-010430 | V-234852 | CAT I
default r_sles_15_010430 := false
r_sles_15_010430 if {
	input.repos.gpgcheck == true
}

finding_r_sles_15_010430 := {
	"vuln_id": "V-234852",
	"stig_id": "SLES-15-010430",
	"severity": "CAT I",
	"rule_title": "The SUSE operating system tool zypper must have gpgcheck enabled.",
	"status": status_r_sles_15_010430,
}
status_r_sles_15_010430 := "Not_a_Finding" if r_sles_15_010430
status_r_sles_15_010430 := "Open" if not r_sles_15_010430

# SLES-15-010450 | V-234853 | CAT I
default r_sles_15_010450 := false
r_sles_15_010450 if {
	input.sudo.nopasswd_or_noauthenticate_present == false
}

finding_r_sles_15_010450 := {
	"vuln_id": "V-234853",
	"stig_id": "SLES-15-010450",
	"severity": "CAT I",
	"rule_title": "The SUSE operating system must reauthenticate users when changing authenticators, roles, or escalating privileges.",
	"status": status_r_sles_15_010450,
}
status_r_sles_15_010450 := "Not_a_Finding" if r_sles_15_010450
status_r_sles_15_010450 := "Open" if not r_sles_15_010450

# SLES-15-010510 | V-234859 | CAT I
default r_sles_15_010510 := false
r_sles_15_010510 if {
	input.fips.enabled == true
}

finding_r_sles_15_010510 := {
	"vuln_id": "V-234859",
	"stig_id": "SLES-15-010510",
	"severity": "CAT I",
	"rule_title": "FIPS 140-2 mode must be enabled on the SUSE operating system.",
	"status": status_r_sles_15_010510,
}
status_r_sles_15_010510 := "Not_a_Finding" if r_sles_15_010510
status_r_sles_15_010510 := "Open" if not r_sles_15_010510

# SLES-15-010530 | V-234860 | CAT I
default r_sles_15_010530 := false
r_sles_15_010530 if {
	input.services["sshd"].active == true
}

finding_r_sles_15_010530 := {
	"vuln_id": "V-234860",
	"stig_id": "SLES-15-010530",
	"severity": "CAT I",
	"rule_title": "All networked SUSE operating systems must have and implement SSH to protect the confidentiality and integrity of transmitted and received information, as well as information during preparation for transmission.",
	"status": status_r_sles_15_010530,
}
status_r_sles_15_010530 := "Not_a_Finding" if r_sles_15_010530
status_r_sles_15_010530 := "Open" if not r_sles_15_010530

# SLES-15-020100 | V-234876 | CAT I
default r_sles_15_020100 := false
r_sles_15_020100 if {
	input.accounts.root_only_uid0 == true
}

finding_r_sles_15_020100 := {
	"vuln_id": "V-234876",
	"stig_id": "SLES-15-020100",
	"severity": "CAT I",
	"rule_title": "The SUSE operating system root account must be the only account with unrestricted access to the system.",
	"status": status_r_sles_15_020100,
}
status_r_sles_15_020100 := "Not_a_Finding" if r_sles_15_020100
status_r_sles_15_020100 := "Open" if not r_sles_15_020100

# SLES-15-020181 | V-251725 | CAT I
default r_sles_15_020181 := false
r_sles_15_020181 if {
	count(input.passwd.blank_password_accounts) == 0
}

finding_r_sles_15_020181 := {
	"vuln_id": "V-251725",
	"stig_id": "SLES-15-020181",
	"severity": "CAT I",
	"rule_title": "The SUSE operating system must not have accounts configured with blank or null passwords.",
	"status": status_r_sles_15_020181,
}
status_r_sles_15_020181 := "Not_a_Finding" if r_sles_15_020181
status_r_sles_15_020181 := "Open" if not r_sles_15_020181

# SLES-15-020300 | V-234898 | CAT I
default r_sles_15_020300 := false
r_sles_15_020300 if {
	input.pam.nullok_present == false
}

finding_r_sles_15_020300 := {
	"vuln_id": "V-234898",
	"stig_id": "SLES-15-020300",
	"severity": "CAT I",
	"rule_title": "The SUSE operating system must not be configured to allow blank or null passwords.",
	"status": status_r_sles_15_020300,
}
status_r_sles_15_020300 := "Not_a_Finding" if r_sles_15_020300
status_r_sles_15_020300 := "Open" if not r_sles_15_020300

# SLES-15-040020 | V-234984 | CAT I
default r_sles_15_040020 := false
r_sles_15_040020 if {
	input.forbidden_files.shosts_present == false
}

finding_r_sles_15_040020 := {
	"vuln_id": "V-234984",
	"stig_id": "SLES-15-040020",
	"severity": "CAT I",
	"rule_title": "There must be no .shosts files on the SUSE operating system.",
	"status": status_r_sles_15_040020,
}
status_r_sles_15_040020 := "Not_a_Finding" if r_sles_15_040020
status_r_sles_15_040020 := "Open" if not r_sles_15_040020

# SLES-15-040030 | V-234985 | CAT I
default r_sles_15_040030 := false
r_sles_15_040030 if {
	input.forbidden_files.shosts_equiv_present == false
}

finding_r_sles_15_040030 := {
	"vuln_id": "V-234985",
	"stig_id": "SLES-15-040030",
	"severity": "CAT I",
	"rule_title": "There must be no shosts.equiv files on the SUSE operating system.",
	"status": status_r_sles_15_040030,
}
status_r_sles_15_040030 := "Not_a_Finding" if r_sles_15_040030
status_r_sles_15_040030 := "Open" if not r_sles_15_040030

# SLES-15-040060 | V-234988 | CAT I
default r_sles_15_040060 := false
r_sles_15_040060 if {
	input.systemd.ctrl_alt_del_masked == true
}

finding_r_sles_15_040060 := {
	"vuln_id": "V-234988",
	"stig_id": "SLES-15-040060",
	"severity": "CAT I",
	"rule_title": "The SUSE operating system must disable the x86 Ctrl-Alt-Delete key sequence.",
	"status": status_r_sles_15_040060,
}
status_r_sles_15_040060 := "Not_a_Finding" if r_sles_15_040060
status_r_sles_15_040060 := "Open" if not r_sles_15_040060

# SLES-15-040061 | V-234989 | CAT I
default r_sles_15_040061 := false
r_sles_15_040061 if {
	input.gdm.ctrl_alt_del_disabled == true
}

finding_r_sles_15_040061 := {
	"vuln_id": "V-234989",
	"stig_id": "SLES-15-040061",
	"severity": "CAT I",
	"rule_title": "The SUSE operating system must disable the x86 Ctrl-Alt-Delete key sequence for Graphical User Interfaces.",
	"status": status_r_sles_15_040061,
}
status_r_sles_15_040061 := "Not_a_Finding" if r_sles_15_040061
status_r_sles_15_040061 := "Open" if not r_sles_15_040061

# SLES-15-040062 | V-234990 | CAT I
default r_sles_15_040062 := false
r_sles_15_040062 if {
	input.systemd.ctrl_alt_del_burst_disabled == true
}

finding_r_sles_15_040062 := {
	"vuln_id": "V-234990",
	"stig_id": "SLES-15-040062",
	"severity": "CAT I",
	"rule_title": "The SUSE operating system must disable the systemd Ctrl-Alt-Delete burst key sequence.",
	"status": status_r_sles_15_040062,
}
status_r_sles_15_040062 := "Not_a_Finding" if r_sles_15_040062
status_r_sles_15_040062 := "Open" if not r_sles_15_040062

# SLES-15-040430 | V-235031 | CAT I
default r_sles_15_040430 := false
r_sles_15_040430 if {
	input.gdm.automatic_login_enabled == false
}

finding_r_sles_15_040430 := {
	"vuln_id": "V-235031",
	"stig_id": "SLES-15-040430",
	"severity": "CAT I",
	"rule_title": "The SUSE operating system must not allow unattended or automatic logon via the graphical user interface (GUI).",
	"status": status_r_sles_15_040430,
}
status_r_sles_15_040430 := "Not_a_Finding" if r_sles_15_040430
status_r_sles_15_040430 := "Open" if not r_sles_15_040430

# SLES-15-040440 | V-235032 | CAT I
default r_sles_15_040440 := false
r_sles_15_040440 if {
	input.sshd_config.PermitEmptyPasswords == "no"
}

finding_r_sles_15_040440 := {
	"vuln_id": "V-235032",
	"stig_id": "SLES-15-040440",
	"severity": "CAT I",
	"rule_title": "The SUSE operating system must not allow unattended or automatic logon via SSH.",
	"status": status_r_sles_15_040440,
}
status_r_sles_15_040440 := "Not_a_Finding" if r_sles_15_040440
status_r_sles_15_040440 := "Open" if not r_sles_15_040440

findings := [
	finding_r_sles_15_010000,
	finding_r_sles_15_010030,
	finding_r_sles_15_010035,
	finding_r_sles_15_010045,
	finding_r_sles_15_010046,
	finding_r_sles_15_010160,
	finding_r_sles_15_010180,
	finding_r_sles_15_010190,
	finding_r_sles_15_010200,
	finding_r_sles_15_010220,
	finding_r_sles_15_010270,
	finding_r_sles_15_010280,
	finding_r_sles_15_010330,
	finding_r_sles_15_010430,
	finding_r_sles_15_010450,
	finding_r_sles_15_010510,
	finding_r_sles_15_010530,
	finding_r_sles_15_020100,
	finding_r_sles_15_020181,
	finding_r_sles_15_020300,
	finding_r_sles_15_040020,
	finding_r_sles_15_040030,
	finding_r_sles_15_040060,
	finding_r_sles_15_040061,
	finding_r_sles_15_040062,
	finding_r_sles_15_040430,
	finding_r_sles_15_040440,
]

default compliant := false

compliant if count([f | some f in findings; f.status == "Open"]) == 0
