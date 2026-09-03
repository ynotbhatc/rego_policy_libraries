package stig.windows_server_2025.registry_so

# DISA STIG — Microsoft Windows Server 2025 Security Technical Implementation Guide
# V1R2 | Release: 2 Benchmark Date: 01 Jul 2026
# Auto-derived registry checks (39 rules) — value expectations
# taken verbatim from the XCCDF check-content (July 2026 library).
# Input contract: input.registry["HKLM\\Path"]["ValueName"] = number|string

import rego.v1

# WN25-SO-000020 | V-278196 | CAT I
default r_wn25_so_000020 := false
r_wn25_so_000020 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa"]["LimitBlankPasswordUse"] == 1
}

finding_r_wn25_so_000020 := {
	"vuln_id": "V-278196",
	"stig_id": "WN25-SO-000020",
	"severity": "CAT I",
	"rule_title": "Windows Server 2025 must prevent local accounts with blank passwords from being used from the network.",
	"status": status_r_wn25_so_000020,
}
status_r_wn25_so_000020 := "Not_a_Finding" if r_wn25_so_000020
status_r_wn25_so_000020 := "Open" if not r_wn25_so_000020

# WN25-SO-000050 | V-278199 | CAT II
default r_wn25_so_000050 := false
r_wn25_so_000050 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa"]["SCENoApplyLegacyAuditPolicy"] == 1
}

finding_r_wn25_so_000050 := {
	"vuln_id": "V-278199",
	"stig_id": "WN25-SO-000050",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 must force audit policy subcategory settings to override audit policy category settings.",
	"status": status_r_wn25_so_000050,
}
status_r_wn25_so_000050 := "Not_a_Finding" if r_wn25_so_000050
status_r_wn25_so_000050 := "Open" if not r_wn25_so_000050

# WN25-SO-000060 | V-278200 | CAT II
default r_wn25_so_000060 := false
r_wn25_so_000060 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters"]["RequireSignOrSeal"] == 1
}

finding_r_wn25_so_000060 := {
	"vuln_id": "V-278200",
	"stig_id": "WN25-SO-000060",
	"severity": "CAT II",
	"rule_title": "The Windows Server 2025 setting Domain member: Digitally encrypt or sign secure channel data (always) must be configured to Enabled.",
	"status": status_r_wn25_so_000060,
}
status_r_wn25_so_000060 := "Not_a_Finding" if r_wn25_so_000060
status_r_wn25_so_000060 := "Open" if not r_wn25_so_000060

# WN25-SO-000070 | V-278201 | CAT II
default r_wn25_so_000070 := false
r_wn25_so_000070 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters"]["SealSecureChannel"] == 1
}

finding_r_wn25_so_000070 := {
	"vuln_id": "V-278201",
	"stig_id": "WN25-SO-000070",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 setting Domain member: Digitally encrypt secure channel data (when possible) must be configured to Enabled.",
	"status": status_r_wn25_so_000070,
}
status_r_wn25_so_000070 := "Not_a_Finding" if r_wn25_so_000070
status_r_wn25_so_000070 := "Open" if not r_wn25_so_000070

# WN25-SO-000080 | V-278202 | CAT II
default r_wn25_so_000080 := false
r_wn25_so_000080 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters"]["SignSecureChannel"] == 1
}

finding_r_wn25_so_000080 := {
	"vuln_id": "V-278202",
	"stig_id": "WN25-SO-000080",
	"severity": "CAT II",
	"rule_title": "The Windows Server 2025 setting Domain member: Digitally sign secure channel data (when possible) must be configured to Enabled.",
	"status": status_r_wn25_so_000080,
}
status_r_wn25_so_000080 := "Not_a_Finding" if r_wn25_so_000080
status_r_wn25_so_000080 := "Open" if not r_wn25_so_000080

# WN25-SO-000090 | V-278203 | CAT II
default r_wn25_so_000090 := false
r_wn25_so_000090 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters"]["DisablePasswordChange"] == 0
}

finding_r_wn25_so_000090 := {
	"vuln_id": "V-278203",
	"stig_id": "WN25-SO-000090",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 computer account password must not be prevented from being reset.",
	"status": status_r_wn25_so_000090,
}
status_r_wn25_so_000090 := "Not_a_Finding" if r_wn25_so_000090
status_r_wn25_so_000090 := "Open" if not r_wn25_so_000090

# WN25-SO-000100 | V-278204 | CAT II
default r_wn25_so_000100 := false
r_wn25_so_000100 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters"]["MaximumPasswordAge"] == 30
}

finding_r_wn25_so_000100 := {
	"vuln_id": "V-278204",
	"stig_id": "WN25-SO-000100",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 maximum age for machine account passwords must be configured to 30 days or less.",
	"status": status_r_wn25_so_000100,
}
status_r_wn25_so_000100 := "Not_a_Finding" if r_wn25_so_000100
status_r_wn25_so_000100 := "Open" if not r_wn25_so_000100

# WN25-SO-000110 | V-278205 | CAT II
default r_wn25_so_000110 := false
r_wn25_so_000110 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters"]["RequireStrongKey"] == 1
}

finding_r_wn25_so_000110 := {
	"vuln_id": "V-278205",
	"stig_id": "WN25-SO-000110",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 must be configured to require a strong session key.",
	"status": status_r_wn25_so_000110,
}
status_r_wn25_so_000110 := "Not_a_Finding" if r_wn25_so_000110
status_r_wn25_so_000110 := "Open" if not r_wn25_so_000110

# WN25-SO-000120 | V-278206 | CAT II
default r_wn25_so_000120 := false
r_wn25_so_000120 if {
	input.registry["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"]["InactivityTimeoutSecs"] == 900
}

finding_r_wn25_so_000120 := {
	"vuln_id": "V-278206",
	"stig_id": "WN25-SO-000120",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 machine inactivity limit must be set to 15 minutes or less, locking the system with the screen saver.",
	"status": status_r_wn25_so_000120,
}
status_r_wn25_so_000120 := "Not_a_Finding" if r_wn25_so_000120
status_r_wn25_so_000120 := "Open" if not r_wn25_so_000120

# WN25-SO-000130 | V-278207 | CAT II
default r_wn25_so_000130 := false
r_wn25_so_000130 if {
	input.registry["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"]["LegalNoticeText"] == "See message text below"
}

finding_r_wn25_so_000130 := {
	"vuln_id": "V-278207",
	"stig_id": "WN25-SO-000130",
	"severity": "CAT II",
	"rule_title": "The Windows Server 2025 required legal notice must be configured to display before console logon.",
	"status": status_r_wn25_so_000130,
}
status_r_wn25_so_000130 := "Not_a_Finding" if r_wn25_so_000130
status_r_wn25_so_000130 := "Open" if not r_wn25_so_000130

# WN25-SO-000140 | V-278208 | CAT III
default r_wn25_so_000140 := false
r_wn25_so_000140 if {
	input.registry["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"]["LegalNoticeCaption"] == "See message title options below"
}

finding_r_wn25_so_000140 := {
	"vuln_id": "V-278208",
	"stig_id": "WN25-SO-000140",
	"severity": "CAT III",
	"rule_title": "Windows Server 2025 title for legal banner dialog box must be configured with the appropriate text.",
	"status": status_r_wn25_so_000140,
}
status_r_wn25_so_000140 := "Not_a_Finding" if r_wn25_so_000140
status_r_wn25_so_000140 := "Open" if not r_wn25_so_000140

# WN25-SO-000150 | V-278209 | CAT II
default r_wn25_so_000150 := false
r_wn25_so_000150 if {
	input.registry["HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"]["scremoveoption"] == "1 (Lock Workstation) or 2 (Force Logoff)"
}

finding_r_wn25_so_000150 := {
	"vuln_id": "V-278209",
	"stig_id": "WN25-SO-000150",
	"severity": "CAT II",
	"rule_title": "The Windows Server 2025 Smart Card removal option must be configured to Force Logoff or Lock Workstation.",
	"status": status_r_wn25_so_000150,
}
status_r_wn25_so_000150 := "Not_a_Finding" if r_wn25_so_000150
status_r_wn25_so_000150 := "Open" if not r_wn25_so_000150

# WN25-SO-000160 | V-278210 | CAT II
default r_wn25_so_000160 := false
r_wn25_so_000160 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters"]["RequireSecuritySignature"] == 1
}

finding_r_wn25_so_000160 := {
	"vuln_id": "V-278210",
	"stig_id": "WN25-SO-000160",
	"severity": "CAT II",
	"rule_title": "The Windows Server 2025 setting Microsoft network client: Digitally sign communications (always) must be configured to Enabled.",
	"status": status_r_wn25_so_000160,
}
status_r_wn25_so_000160 := "Not_a_Finding" if r_wn25_so_000160
status_r_wn25_so_000160 := "Open" if not r_wn25_so_000160

# WN25-SO-000170 | V-278211 | CAT II
default r_wn25_so_000170 := false
r_wn25_so_000170 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters"]["EnableSecuritySignature"] == 1
}

finding_r_wn25_so_000170 := {
	"vuln_id": "V-278211",
	"stig_id": "WN25-SO-000170",
	"severity": "CAT II",
	"rule_title": "The Windows Server 2025 setting Microsoft network client: Digitally sign communications (if server agrees) must be configured to Enabled.",
	"status": status_r_wn25_so_000170,
}
status_r_wn25_so_000170 := "Not_a_Finding" if r_wn25_so_000170
status_r_wn25_so_000170 := "Open" if not r_wn25_so_000170

# WN25-SO-000190 | V-278213 | CAT II
default r_wn25_so_000190 := false
r_wn25_so_000190 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters"]["RequireSecuritySignature"] == 1
}

finding_r_wn25_so_000190 := {
	"vuln_id": "V-278213",
	"stig_id": "WN25-SO-000190",
	"severity": "CAT II",
	"rule_title": "The Windows Server 2025 setting Microsoft network server: Digitally sign communications (always) must be configured to Enabled.",
	"status": status_r_wn25_so_000190,
}
status_r_wn25_so_000190 := "Not_a_Finding" if r_wn25_so_000190
status_r_wn25_so_000190 := "Open" if not r_wn25_so_000190

# WN25-SO-000200 | V-278214 | CAT II
default r_wn25_so_000200 := false
r_wn25_so_000200 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters"]["EnableSecuritySignature"] == 1
}

finding_r_wn25_so_000200 := {
	"vuln_id": "V-278214",
	"stig_id": "WN25-SO-000200",
	"severity": "CAT II",
	"rule_title": "The Windows Server 2025 setting Microsoft network server: Digitally sign communications (if client agrees) must be configured to Enabled.",
	"status": status_r_wn25_so_000200,
}
status_r_wn25_so_000200 := "Not_a_Finding" if r_wn25_so_000200
status_r_wn25_so_000200 := "Open" if not r_wn25_so_000200

# WN25-SO-000220 | V-278216 | CAT I
default r_wn25_so_000220 := false
r_wn25_so_000220 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa"]["RestrictAnonymousSAM"] == 1
}

finding_r_wn25_so_000220 := {
	"vuln_id": "V-278216",
	"stig_id": "WN25-SO-000220",
	"severity": "CAT I",
	"rule_title": "Windows Server 2025 must not allow anonymous enumeration of Security Account Manager (SAM) accounts.",
	"status": status_r_wn25_so_000220,
}
status_r_wn25_so_000220 := "Not_a_Finding" if r_wn25_so_000220
status_r_wn25_so_000220 := "Open" if not r_wn25_so_000220

# WN25-SO-000230 | V-278217 | CAT I
default r_wn25_so_000230 := false
r_wn25_so_000230 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa"]["RestrictAnonymous"] == 1
}

finding_r_wn25_so_000230 := {
	"vuln_id": "V-278217",
	"stig_id": "WN25-SO-000230",
	"severity": "CAT I",
	"rule_title": "Windows Server 2025 must not allow anonymous enumeration of shares.",
	"status": status_r_wn25_so_000230,
}
status_r_wn25_so_000230 := "Not_a_Finding" if r_wn25_so_000230
status_r_wn25_so_000230 := "Open" if not r_wn25_so_000230

# WN25-SO-000240 | V-278218 | CAT II
default r_wn25_so_000240 := false
r_wn25_so_000240 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa"]["EveryoneIncludesAnonymous"] == 0
}

finding_r_wn25_so_000240 := {
	"vuln_id": "V-278218",
	"stig_id": "WN25-SO-000240",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 must be configured to prevent anonymous users from having the same permissions as the Everyone group.",
	"status": status_r_wn25_so_000240,
}
status_r_wn25_so_000240 := "Not_a_Finding" if r_wn25_so_000240
status_r_wn25_so_000240 := "Open" if not r_wn25_so_000240

# WN25-SO-000250 | V-278219 | CAT I
default r_wn25_so_000250 := false
r_wn25_so_000250 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters"]["RestrictNullSessAccess"] == 1
}

finding_r_wn25_so_000250 := {
	"vuln_id": "V-278219",
	"stig_id": "WN25-SO-000250",
	"severity": "CAT I",
	"rule_title": "Windows Server 2025 must restrict anonymous access to Named Pipes and Shares.",
	"status": status_r_wn25_so_000250,
}
status_r_wn25_so_000250 := "Not_a_Finding" if r_wn25_so_000250
status_r_wn25_so_000250 := "Open" if not r_wn25_so_000250

# WN25-SO-000260 | V-278220 | CAT II
default r_wn25_so_000260 := false
r_wn25_so_000260 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Control\\LSA"]["UseMachineId"] == 1
}

finding_r_wn25_so_000260 := {
	"vuln_id": "V-278220",
	"stig_id": "WN25-SO-000260",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 services using Local System that use Negotiate when reverting to NTLM authentication must use the computer identity instead of authenticating anonymously.",
	"status": status_r_wn25_so_000260,
}
status_r_wn25_so_000260 := "Not_a_Finding" if r_wn25_so_000260
status_r_wn25_so_000260 := "Open" if not r_wn25_so_000260

# WN25-SO-000270 | V-278221 | CAT II
default r_wn25_so_000270 := false
r_wn25_so_000270 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Control\\LSA\\MSV1_0"]["allownullsessionfallback"] == 0
}

finding_r_wn25_so_000270 := {
	"vuln_id": "V-278221",
	"stig_id": "WN25-SO-000270",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 must prevent NTLM from falling back to a Null session.",
	"status": status_r_wn25_so_000270,
}
status_r_wn25_so_000270 := "Not_a_Finding" if r_wn25_so_000270
status_r_wn25_so_000270 := "Open" if not r_wn25_so_000270

# WN25-SO-000280 | V-278222 | CAT II
default r_wn25_so_000280 := false
r_wn25_so_000280 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Control\\LSA\\pku2u"]["AllowOnlineID"] == 0
}

finding_r_wn25_so_000280 := {
	"vuln_id": "V-278222",
	"stig_id": "WN25-SO-000280",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 must prevent PKU2U authentication using online identities.",
	"status": status_r_wn25_so_000280,
}
status_r_wn25_so_000280 := "Not_a_Finding" if r_wn25_so_000280
status_r_wn25_so_000280 := "Open" if not r_wn25_so_000280

# WN25-SO-000290 | V-278223 | CAT II
default r_wn25_so_000290 := false
r_wn25_so_000290 if {
	input.registry["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters"]["SupportedEncryptionTypes"] == 2147483640
}

finding_r_wn25_so_000290 := {
	"vuln_id": "V-278223",
	"stig_id": "WN25-SO-000290",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 Kerberos encryption types must be configured to prevent the use of DES and RC4 encryption suites.",
	"status": status_r_wn25_so_000290,
}
status_r_wn25_so_000290 := "Not_a_Finding" if r_wn25_so_000290
status_r_wn25_so_000290 := "Open" if not r_wn25_so_000290

# WN25-SO-000310 | V-278225 | CAT I
default r_wn25_so_000310 := false
r_wn25_so_000310 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa"]["LmCompatibilityLevel"] == 5
}

finding_r_wn25_so_000310 := {
	"vuln_id": "V-278225",
	"stig_id": "WN25-SO-000310",
	"severity": "CAT I",
	"rule_title": "Windows Server 2025 LAN Manager authentication level must be configured to send NTLMv2 response only and to refuse LM and NTLM.",
	"status": status_r_wn25_so_000310,
}
status_r_wn25_so_000310 := "Not_a_Finding" if r_wn25_so_000310
status_r_wn25_so_000310 := "Open" if not r_wn25_so_000310

# WN25-SO-000320 | V-278226 | CAT II
default r_wn25_so_000320 := false
r_wn25_so_000320 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Services\\LDAP"]["LDAPClientIntegrity"] == 1
}

finding_r_wn25_so_000320 := {
	"vuln_id": "V-278226",
	"stig_id": "WN25-SO-000320",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 must be configured to at least negotiate signing for LDAP client signing.",
	"status": status_r_wn25_so_000320,
}
status_r_wn25_so_000320 := "Not_a_Finding" if r_wn25_so_000320
status_r_wn25_so_000320 := "Open" if not r_wn25_so_000320

# WN25-SO-000330 | V-278227 | CAT II
default r_wn25_so_000330 := false
r_wn25_so_000330 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0"]["NTLMMinClientSec"] == 537395200
}

finding_r_wn25_so_000330 := {
	"vuln_id": "V-278227",
	"stig_id": "WN25-SO-000330",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 session security for NTLM SSP-based clients must be configured to require NTLMv2 session security and 128-bit encryption.",
	"status": status_r_wn25_so_000330,
}
status_r_wn25_so_000330 := "Not_a_Finding" if r_wn25_so_000330
status_r_wn25_so_000330 := "Open" if not r_wn25_so_000330

# WN25-SO-000340 | V-278228 | CAT II
default r_wn25_so_000340 := false
r_wn25_so_000340 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0"]["NTLMMinServerSec"] == 537395200
}

finding_r_wn25_so_000340 := {
	"vuln_id": "V-278228",
	"stig_id": "WN25-SO-000340",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 session security for NTLM SSP-based servers must be configured to require NTLMv2 session security and 128-bit encryption.",
	"status": status_r_wn25_so_000340,
}
status_r_wn25_so_000340 := "Not_a_Finding" if r_wn25_so_000340
status_r_wn25_so_000340 := "Open" if not r_wn25_so_000340

# WN25-SO-000350 | V-278229 | CAT II
default r_wn25_so_000350 := false
r_wn25_so_000350 if {
	input.registry["HKLM\\SOFTWARE\\Policies\\Microsoft\\Cryptography"]["ForceKeyProtection"] == 2
}

finding_r_wn25_so_000350 := {
	"vuln_id": "V-278229",
	"stig_id": "WN25-SO-000350",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 users must be required to enter a password to access private keys stored on the computer.",
	"status": status_r_wn25_so_000350,
}
status_r_wn25_so_000350 := "Not_a_Finding" if r_wn25_so_000350
status_r_wn25_so_000350 := "Open" if not r_wn25_so_000350

# WN25-SO-000360 | V-278230 | CAT II
default r_wn25_so_000360 := false
r_wn25_so_000360 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\FIPSAlgorithmPolicy"]["Enabled"] == 1
}

finding_r_wn25_so_000360 := {
	"vuln_id": "V-278230",
	"stig_id": "WN25-SO-000360",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 must be configured to use FIPS-compliant algorithms for encryption, hashing, and signing.",
	"status": status_r_wn25_so_000360,
}
status_r_wn25_so_000360 := "Not_a_Finding" if r_wn25_so_000360
status_r_wn25_so_000360 := "Open" if not r_wn25_so_000360

# WN25-SO-000370 | V-278231 | CAT III
default r_wn25_so_000370 := false
r_wn25_so_000370 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager"]["ProtectionMode"] == 1
}

finding_r_wn25_so_000370 := {
	"vuln_id": "V-278231",
	"stig_id": "WN25-SO-000370",
	"severity": "CAT III",
	"rule_title": "Windows Server 2025 default permissions of global system objects must be strengthened.",
	"status": status_r_wn25_so_000370,
}
status_r_wn25_so_000370 := "Not_a_Finding" if r_wn25_so_000370
status_r_wn25_so_000370 := "Open" if not r_wn25_so_000370

# WN25-SO-000380 | V-278232 | CAT II
default r_wn25_so_000380 := false
r_wn25_so_000380 if {
	input.registry["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"]["FilterAdministratorToken"] == 1
}

finding_r_wn25_so_000380 := {
	"vuln_id": "V-278232",
	"stig_id": "WN25-SO-000380",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 User Account Control (UAC) approval mode for the built-in Administrator must be enabled.",
	"status": status_r_wn25_so_000380,
}
status_r_wn25_so_000380 := "Not_a_Finding" if r_wn25_so_000380
status_r_wn25_so_000380 := "Open" if not r_wn25_so_000380

# WN25-SO-000390 | V-278233 | CAT II
default r_wn25_so_000390 := false
r_wn25_so_000390 if {
	input.registry["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"]["EnableUIADesktopToggle"] == 0
}

finding_r_wn25_so_000390 := {
	"vuln_id": "V-278233",
	"stig_id": "WN25-SO-000390",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 UIAccess applications must not be allowed to prompt for elevation without using the secure desktop.",
	"status": status_r_wn25_so_000390,
}
status_r_wn25_so_000390 := "Not_a_Finding" if r_wn25_so_000390
status_r_wn25_so_000390 := "Open" if not r_wn25_so_000390

# WN25-SO-000400 | V-278234 | CAT II
default r_wn25_so_000400 := false
r_wn25_so_000400 if {
	input.registry["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"]["ConsentPromptBehaviorAdmin"] == 2
}

finding_r_wn25_so_000400 := {
	"vuln_id": "V-278234",
	"stig_id": "WN25-SO-000400",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 User Account Control (UAC) must, at a minimum, prompt administrators for consent on the secure desktop.",
	"status": status_r_wn25_so_000400,
}
status_r_wn25_so_000400 := "Not_a_Finding" if r_wn25_so_000400
status_r_wn25_so_000400 := "Open" if not r_wn25_so_000400

# WN25-SO-000410 | V-278235 | CAT II
default r_wn25_so_000410 := false
r_wn25_so_000410 if {
	input.registry["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"]["ConsentPromptBehaviorUser"] == 0
}

finding_r_wn25_so_000410 := {
	"vuln_id": "V-278235",
	"stig_id": "WN25-SO-000410",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 User Account Control (UAC) must automatically deny standard user requests for elevation.",
	"status": status_r_wn25_so_000410,
}
status_r_wn25_so_000410 := "Not_a_Finding" if r_wn25_so_000410
status_r_wn25_so_000410 := "Open" if not r_wn25_so_000410

# WN25-SO-000420 | V-278236 | CAT II
default r_wn25_so_000420 := false
r_wn25_so_000420 if {
	input.registry["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"]["EnableInstallerDetection"] == 1
}

finding_r_wn25_so_000420 := {
	"vuln_id": "V-278236",
	"stig_id": "WN25-SO-000420",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 User Account Control (UAC) must be configured to detect application installations and prompt for elevation.",
	"status": status_r_wn25_so_000420,
}
status_r_wn25_so_000420 := "Not_a_Finding" if r_wn25_so_000420
status_r_wn25_so_000420 := "Open" if not r_wn25_so_000420

# WN25-SO-000430 | V-278237 | CAT II
default r_wn25_so_000430 := false
r_wn25_so_000430 if {
	input.registry["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"]["EnableSecureUIAPaths"] == 1
}

finding_r_wn25_so_000430 := {
	"vuln_id": "V-278237",
	"stig_id": "WN25-SO-000430",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 User Account Control (UAC) must only elevate UIAccess applications that are installed in secure locations.",
	"status": status_r_wn25_so_000430,
}
status_r_wn25_so_000430 := "Not_a_Finding" if r_wn25_so_000430
status_r_wn25_so_000430 := "Open" if not r_wn25_so_000430

# WN25-SO-000440 | V-278238 | CAT II
default r_wn25_so_000440 := false
r_wn25_so_000440 if {
	input.registry["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"]["EnableLUA"] == 1
}

finding_r_wn25_so_000440 := {
	"vuln_id": "V-278238",
	"stig_id": "WN25-SO-000440",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 User Account Control (UAC) must run all administrators in Admin Approval Mode, enabling UAC.",
	"status": status_r_wn25_so_000440,
}
status_r_wn25_so_000440 := "Not_a_Finding" if r_wn25_so_000440
status_r_wn25_so_000440 := "Open" if not r_wn25_so_000440

# WN25-SO-000450 | V-278239 | CAT II
default r_wn25_so_000450 := false
r_wn25_so_000450 if {
	input.registry["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"]["EnableVirtualization"] == 1
}

finding_r_wn25_so_000450 := {
	"vuln_id": "V-278239",
	"stig_id": "WN25-SO-000450",
	"severity": "CAT II",
	"rule_title": "Windows Server 2025 User Account Control (UAC) must virtualize file and registry write failures to per-user locations.",
	"status": status_r_wn25_so_000450,
}
status_r_wn25_so_000450 := "Not_a_Finding" if r_wn25_so_000450
status_r_wn25_so_000450 := "Open" if not r_wn25_so_000450

findings := [
	finding_r_wn25_so_000020,
	finding_r_wn25_so_000050,
	finding_r_wn25_so_000060,
	finding_r_wn25_so_000070,
	finding_r_wn25_so_000080,
	finding_r_wn25_so_000090,
	finding_r_wn25_so_000100,
	finding_r_wn25_so_000110,
	finding_r_wn25_so_000120,
	finding_r_wn25_so_000130,
	finding_r_wn25_so_000140,
	finding_r_wn25_so_000150,
	finding_r_wn25_so_000160,
	finding_r_wn25_so_000170,
	finding_r_wn25_so_000190,
	finding_r_wn25_so_000200,
	finding_r_wn25_so_000220,
	finding_r_wn25_so_000230,
	finding_r_wn25_so_000240,
	finding_r_wn25_so_000250,
	finding_r_wn25_so_000260,
	finding_r_wn25_so_000270,
	finding_r_wn25_so_000280,
	finding_r_wn25_so_000290,
	finding_r_wn25_so_000310,
	finding_r_wn25_so_000320,
	finding_r_wn25_so_000330,
	finding_r_wn25_so_000340,
	finding_r_wn25_so_000350,
	finding_r_wn25_so_000360,
	finding_r_wn25_so_000370,
	finding_r_wn25_so_000380,
	finding_r_wn25_so_000390,
	finding_r_wn25_so_000400,
	finding_r_wn25_so_000410,
	finding_r_wn25_so_000420,
	finding_r_wn25_so_000430,
	finding_r_wn25_so_000440,
	finding_r_wn25_so_000450,
]

default compliant := false

compliant if count([f | some f in findings; f.status == "Open"]) == 0
