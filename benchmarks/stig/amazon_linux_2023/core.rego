package stig.amazon_linux_2023.core

# DISA STIG — Amazon Linux 2023 Security Technical Implementation Guide
# V1R4 | Release: 4 Benchmark Date: 01 Jul 2026
# 23 rules (all CAT I + selected CAT II). Rule IDs, severities and
# titles verified against the July 2026 SRG-STIG library XCCDF on 2026-09-03.
# Input contract: see gen_linux.py header / tests fixture.

import rego.v1

# AZLX-23-000050 | V-283441 | CAT I
default r_azlx_23_000050 := false
r_azlx_23_000050 if {
	input.fips.enabled == true
}

finding_r_azlx_23_000050 := {
	"vuln_id": "V-283441",
	"stig_id": "AZLX-23-000050",
	"severity": "CAT I",
	"rule_title": "Amazon Linux 2023 must enable FIPS mode.",
	"status": status_r_azlx_23_000050,
}
status_r_azlx_23_000050 := "Not_a_Finding" if r_azlx_23_000050
status_r_azlx_23_000050 := "Open" if not r_azlx_23_000050

# AZLX-23-000100 | V-273994 | CAT I
default r_azlx_23_000100 := false
r_azlx_23_000100 if {
	input.storage.persistent_partitions_encrypted == true
}

finding_r_azlx_23_000100 := {
	"vuln_id": "V-273994",
	"stig_id": "AZLX-23-000100",
	"severity": "CAT I",
	"rule_title": "Amazon Linux 2023 local disk partitions must implement cryptographic mechanisms to prevent unauthorized disclosure or modification of all information that requires at rest protection.",
	"status": status_r_azlx_23_000100,
}
status_r_azlx_23_000100 := "Not_a_Finding" if r_azlx_23_000100
status_r_azlx_23_000100 := "Open" if not r_azlx_23_000100

# AZLX-23-000115 | V-273996 | CAT I
default r_azlx_23_000115 := false
r_azlx_23_000115 if {
	input.repos.localpkg_gpgcheck == true
}

finding_r_azlx_23_000115 := {
	"vuln_id": "V-273996",
	"stig_id": "AZLX-23-000115",
	"severity": "CAT I",
	"rule_title": "Amazon Linux 2023 must check the GPG signature of locally installed software packages before installation.",
	"status": status_r_azlx_23_000115,
}
status_r_azlx_23_000115 := "Not_a_Finding" if r_azlx_23_000115
status_r_azlx_23_000115 := "Open" if not r_azlx_23_000115

# AZLX-23-000120 | V-273997 | CAT I
default r_azlx_23_000120 := false
r_azlx_23_000120 if {
	input.repos.gpgcheck == true
}

finding_r_azlx_23_000120 := {
	"vuln_id": "V-273997",
	"stig_id": "AZLX-23-000120",
	"severity": "CAT I",
	"rule_title": "Amazon Linux 2023 must check the GPG signature of software packages originating from external software repositories before installation.",
	"status": status_r_azlx_23_000120,
}
status_r_azlx_23_000120 := "Not_a_Finding" if r_azlx_23_000120
status_r_azlx_23_000120 := "Open" if not r_azlx_23_000120

# AZLX-23-000125 | V-273998 | CAT I
default r_azlx_23_000125 := false
r_azlx_23_000125 if {
	input.repos.all_repos_gpgcheck == true
}

finding_r_azlx_23_000125 := {
	"vuln_id": "V-273998",
	"stig_id": "AZLX-23-000125",
	"severity": "CAT I",
	"rule_title": "Amazon Linux 2023 must have GPG signature verification enabled for all software repositories.",
	"status": status_r_azlx_23_000125,
}
status_r_azlx_23_000125 := "Not_a_Finding" if r_azlx_23_000125
status_r_azlx_23_000125 := "Open" if not r_azlx_23_000125

# AZLX-23-000130 | V-273999 | CAT I
default r_azlx_23_000130 := false
r_azlx_23_000130 if {
	input.os.vendor_supported == true
}

finding_r_azlx_23_000130 := {
	"vuln_id": "V-273999",
	"stig_id": "AZLX-23-000130",
	"severity": "CAT I",
	"rule_title": "Amazon Linux 2023 must be a vendor-supported release.",
	"status": status_r_azlx_23_000130,
}
status_r_azlx_23_000130 := "Not_a_Finding" if r_azlx_23_000130
status_r_azlx_23_000130 := "Open" if not r_azlx_23_000130

# AZLX-23-000200 | V-274001 | CAT II
default r_azlx_23_000200 := false
r_azlx_23_000200 if {
	input.sysctl["kernel.dmesg_restrict"] == 1
}

finding_r_azlx_23_000200 := {
	"vuln_id": "V-274001",
	"stig_id": "AZLX-23-000200",
	"severity": "CAT II",
	"rule_title": "Amazon Linux 2023 must restrict access to the kernel message buffer.",
	"status": status_r_azlx_23_000200,
}
status_r_azlx_23_000200 := "Not_a_Finding" if r_azlx_23_000200
status_r_azlx_23_000200 := "Open" if not r_azlx_23_000200

# AZLX-23-000225 | V-274006 | CAT II
default r_azlx_23_000225 := false
r_azlx_23_000225 if {
	input.sysctl["kernel.randomize_va_space"] == 2
}

finding_r_azlx_23_000225 := {
	"vuln_id": "V-274006",
	"stig_id": "AZLX-23-000225",
	"severity": "CAT II",
	"rule_title": "Amazon Linux 2023 must implement address space layout randomization (ASLR) to protect its memory from unauthorized code execution.",
	"status": status_r_azlx_23_000225,
}
status_r_azlx_23_000225 := "Not_a_Finding" if r_azlx_23_000225
status_r_azlx_23_000225 := "Open" if not r_azlx_23_000225

# AZLX-23-000300 | V-274007 | CAT I
default r_azlx_23_000300 := false
r_azlx_23_000300 if {
	not "vsftpd" in input.packages
}

finding_r_azlx_23_000300 := {
	"vuln_id": "V-274007",
	"stig_id": "AZLX-23-000300",
	"severity": "CAT I",
	"rule_title": "Amazon Linux 2023 must not have the vsftpd package installed.",
	"status": status_r_azlx_23_000300,
}
status_r_azlx_23_000300 := "Not_a_Finding" if r_azlx_23_000300
status_r_azlx_23_000300 := "Open" if not r_azlx_23_000300

# AZLX-23-001180 | V-274038 | CAT I
default r_azlx_23_001180 := false
r_azlx_23_001180 if {
	"openssh-server" in input.packages
}

finding_r_azlx_23_001180 := {
	"vuln_id": "V-274038",
	"stig_id": "AZLX-23-001180",
	"severity": "CAT I",
	"rule_title": "Amazon Linux 2023 must have SSH installed.",
	"status": status_r_azlx_23_001180,
}
status_r_azlx_23_001180 := "Not_a_Finding" if r_azlx_23_001180
status_r_azlx_23_001180 := "Open" if not r_azlx_23_001180

# AZLX-23-001185 | V-274039 | CAT I
default r_azlx_23_001185 := false
r_azlx_23_001185 if {
	input.services["sshd"].active == true
}

finding_r_azlx_23_001185 := {
	"vuln_id": "V-274039",
	"stig_id": "AZLX-23-001185",
	"severity": "CAT I",
	"rule_title": "Amazon Linux 2023 must implement SSH to protect the confidentiality and integrity of transmitted and received information, as well as information during preparation for transmission.",
	"status": status_r_azlx_23_001185,
}
status_r_azlx_23_001185 := "Not_a_Finding" if r_azlx_23_001185
status_r_azlx_23_001185 := "Open" if not r_azlx_23_001185

# AZLX-23-001195 | V-274040 | CAT I
default r_azlx_23_001195 := false
r_azlx_23_001195 if {
	"crypto-policies" in input.packages
}

finding_r_azlx_23_001195 := {
	"vuln_id": "V-274040",
	"stig_id": "AZLX-23-001195",
	"severity": "CAT I",
	"rule_title": "Amazon Linux 2023 must have the crypto-policies package installed.",
	"status": status_r_azlx_23_001195,
}
status_r_azlx_23_001195 := "Not_a_Finding" if r_azlx_23_001195
status_r_azlx_23_001195 := "Open" if not r_azlx_23_001195

# AZLX-23-001205 | V-274042 | CAT I
default r_azlx_23_001205 := false
r_azlx_23_001205 if {
	input.crypto_policy.opensshserver_ciphers == "aes256-gcm@openssh.com,aes256-ctr,aes128-gcm@openssh.com,aes128-ctr"
}

finding_r_azlx_23_001205 := {
	"vuln_id": "V-274042",
	"stig_id": "AZLX-23-001205",
	"severity": "CAT I",
	"rule_title": "Amazon Linux 2023 server must be configured to use only DOD-approved encryption ciphers employing FIPS 140-2/140-3 validated cryptographic hash algorithms to protect the confidentiality of SSH server connections.",
	"status": status_r_azlx_23_001205,
}
status_r_azlx_23_001205 := "Not_a_Finding" if r_azlx_23_001205
status_r_azlx_23_001205 := "Open" if not r_azlx_23_001205

# AZLX-23-001206 | V-283442 | CAT I
default r_azlx_23_001206 := false
r_azlx_23_001206 if {
	input.crypto_policy.openssh_client_ciphers == "aes256-gcm@openssh.com,aes256-ctr,aes128-gcm@openssh.com,aes128-ctr"
}

finding_r_azlx_23_001206 := {
	"vuln_id": "V-283442",
	"stig_id": "AZLX-23-001206",
	"severity": "CAT I",
	"rule_title": "The Amazon Linux 2023 SSH client must be configured to use only DOD-approved encryption ciphers employing FIPS 140-3-validated cryptographic hash algorithms to protect the confidentiality of SSH client connections.",
	"status": status_r_azlx_23_001206,
}
status_r_azlx_23_001206 := "Not_a_Finding" if r_azlx_23_001206
status_r_azlx_23_001206 := "Open" if not r_azlx_23_001206

# AZLX-23-001210 | V-274043 | CAT I
default r_azlx_23_001210 := false
r_azlx_23_001210 if {
	input.crypto_policy.opensshserver_macs == "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512"
}

finding_r_azlx_23_001210 := {
	"vuln_id": "V-274043",
	"stig_id": "AZLX-23-001210",
	"severity": "CAT I",
	"rule_title": "Amazon Linux 2023 SSH server must be configured to use only Message Authentication Codes (MACs) employing FIPS 140-2/140-3 validated cryptographic hash algorithms to protect the confidentiality of SSH server connections.",
	"status": status_r_azlx_23_001210,
}
status_r_azlx_23_001210 := "Not_a_Finding" if r_azlx_23_001210
status_r_azlx_23_001210 := "Open" if not r_azlx_23_001210

# AZLX-23-001211 | V-283443 | CAT I
default r_azlx_23_001211 := false
r_azlx_23_001211 if {
	input.crypto_policy.openssh_client_macs == "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512"
}

finding_r_azlx_23_001211 := {
	"vuln_id": "V-283443",
	"stig_id": "AZLX-23-001211",
	"severity": "CAT I",
	"rule_title": "The Amazon Linux 2023 SSH client must be configured to use only DOD-approved Message Authentication Codes (MACs) employing FIPS 140-3-validated cryptographic hash algorithms to protect the confidentiality of SSH client c",
	"status": status_r_azlx_23_001211,
}
status_r_azlx_23_001211 := "Not_a_Finding" if r_azlx_23_001211
status_r_azlx_23_001211 := "Open" if not r_azlx_23_001211

# AZLX-23-001225 | V-274046 | CAT I
default r_azlx_23_001225 := false
r_azlx_23_001225 if {
	input.sshd_config.RekeyLimit == "1G 1h"
}

finding_r_azlx_23_001225 := {
	"vuln_id": "V-274046",
	"stig_id": "AZLX-23-001225",
	"severity": "CAT I",
	"rule_title": "Amazon Linux 2023 must force a frequent session key renegotiation for SSH connections to the server.",
	"status": status_r_azlx_23_001225,
}
status_r_azlx_23_001225 := "Not_a_Finding" if r_azlx_23_001225
status_r_azlx_23_001225 := "Open" if not r_azlx_23_001225

# AZLX-23-001235 | V-274048 | CAT II
default r_azlx_23_001235 := false
r_azlx_23_001235 if {
	input.sshd_config.PermitEmptyPasswords == "no"
}

finding_r_azlx_23_001235 := {
	"vuln_id": "V-274048",
	"stig_id": "AZLX-23-001235",
	"severity": "CAT II",
	"rule_title": "Amazon Linux 2023 SSHD must not allow blank passwords.",
	"status": status_r_azlx_23_001235,
}
status_r_azlx_23_001235 := "Not_a_Finding" if r_azlx_23_001235
status_r_azlx_23_001235 := "Open" if not r_azlx_23_001235

# AZLX-23-001240 | V-274049 | CAT II
default r_azlx_23_001240 := false
r_azlx_23_001240 if {
	input.sshd_config.PermitRootLogin == "no"
}

finding_r_azlx_23_001240 := {
	"vuln_id": "V-274049",
	"stig_id": "AZLX-23-001240",
	"severity": "CAT II",
	"rule_title": "Amazon Linux 2023 must not permit direct logons to the root account using remote access via SSH.",
	"status": status_r_azlx_23_001240,
}
status_r_azlx_23_001240 := "Not_a_Finding" if r_azlx_23_001240
status_r_azlx_23_001240 := "Open" if not r_azlx_23_001240

# AZLX-23-001255 | V-274052 | CAT I
default r_azlx_23_001255 := false
r_azlx_23_001255 if {
	input.sshd_config.UsePAM == "yes"
}

finding_r_azlx_23_001255 := {
	"vuln_id": "V-274052",
	"stig_id": "AZLX-23-001255",
	"severity": "CAT I",
	"rule_title": "Amazon Linux 2023 must enable the Pluggable Authentication Module (PAM) interface for SSHD.",
	"status": status_r_azlx_23_001255,
}
status_r_azlx_23_001255 := "Not_a_Finding" if r_azlx_23_001255
status_r_azlx_23_001255 := "Open" if not r_azlx_23_001255

# AZLX-23-001270 | V-283452 | CAT I
default r_azlx_23_001270 := false
r_azlx_23_001270 if {
	input.crypto_policy.policy == "FIPS"
}

finding_r_azlx_23_001270 := {
	"vuln_id": "V-283452",
	"stig_id": "AZLX-23-001270",
	"severity": "CAT I",
	"rule_title": "Amazon Linux 2023 must implement a FIPS 140-2/140-3 compliant systemwide cryptographic policy.",
	"status": status_r_azlx_23_001270,
}
status_r_azlx_23_001270 := "Not_a_Finding" if r_azlx_23_001270
status_r_azlx_23_001270 := "Open" if not r_azlx_23_001270

# AZLX-23-001285 | V-274058 | CAT I
default r_azlx_23_001285 := false
r_azlx_23_001285 if {
	input.crypto_policy.overridden == false
}

finding_r_azlx_23_001285 := {
	"vuln_id": "V-274058",
	"stig_id": "AZLX-23-001285",
	"severity": "CAT I",
	"rule_title": "Amazon Linux 2023 crypto policy must not be overridden.",
	"status": status_r_azlx_23_001285,
}
status_r_azlx_23_001285 := "Not_a_Finding" if r_azlx_23_001285
status_r_azlx_23_001285 := "Open" if not r_azlx_23_001285

# AZLX-23-002450 | V-274153 | CAT I
default r_azlx_23_002450 := false
r_azlx_23_002450 if {
	input.selinux.enforcing == true
}

finding_r_azlx_23_002450 := {
	"vuln_id": "V-274153",
	"stig_id": "AZLX-23-002450",
	"severity": "CAT I",
	"rule_title": "Amazon Linux 2023 must use a Linux Security Module configured to enforce limits on system services.",
	"status": status_r_azlx_23_002450,
}
status_r_azlx_23_002450 := "Not_a_Finding" if r_azlx_23_002450
status_r_azlx_23_002450 := "Open" if not r_azlx_23_002450

findings := [
	finding_r_azlx_23_000050,
	finding_r_azlx_23_000100,
	finding_r_azlx_23_000115,
	finding_r_azlx_23_000120,
	finding_r_azlx_23_000125,
	finding_r_azlx_23_000130,
	finding_r_azlx_23_000200,
	finding_r_azlx_23_000225,
	finding_r_azlx_23_000300,
	finding_r_azlx_23_001180,
	finding_r_azlx_23_001185,
	finding_r_azlx_23_001195,
	finding_r_azlx_23_001205,
	finding_r_azlx_23_001206,
	finding_r_azlx_23_001210,
	finding_r_azlx_23_001211,
	finding_r_azlx_23_001225,
	finding_r_azlx_23_001235,
	finding_r_azlx_23_001240,
	finding_r_azlx_23_001255,
	finding_r_azlx_23_001270,
	finding_r_azlx_23_001285,
	finding_r_azlx_23_002450,
]

default compliant := false

compliant if count([f | some f in findings; f.status == "Open"]) == 0
