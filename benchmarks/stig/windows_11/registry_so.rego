package stig.windows_11.registry_so

# DISA STIG — Microsoft Windows 11 Security Technical Implementation Guide
# V2R8 | Release: 8 Benchmark Date: 01 Jul 2026
# Auto-derived registry checks (36 rules) — value expectations
# taken verbatim from the XCCDF check-content (July 2026 library).
# Input contract: input.registry["HKLM\\Path"]["ValueName"] = number|string

import rego.v1

# WN11-SO-000015 | V-253434 | CAT II
default r_wn11_so_000015 := false
r_wn11_so_000015 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa"]["LimitBlankPasswordUse"] == 1
}

finding_r_wn11_so_000015 := {
	"vuln_id": "V-253434",
	"stig_id": "WN11-SO-000015",
	"severity": "CAT II",
	"rule_title": "Local accounts with blank passwords must be restricted to prevent access from the network.",
	"status": status_r_wn11_so_000015,
}
status_r_wn11_so_000015 := "Not_a_Finding" if r_wn11_so_000015
status_r_wn11_so_000015 := "Open" if not r_wn11_so_000015

# WN11-SO-000030 | V-253437 | CAT II
default r_wn11_so_000030 := false
r_wn11_so_000030 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa"]["SCENoApplyLegacyAuditPolicy"] == 1
}

finding_r_wn11_so_000030 := {
	"vuln_id": "V-253437",
	"stig_id": "WN11-SO-000030",
	"severity": "CAT II",
	"rule_title": "Audit policy using subcategories must be enabled.",
	"status": status_r_wn11_so_000030,
}
status_r_wn11_so_000030 := "Not_a_Finding" if r_wn11_so_000030
status_r_wn11_so_000030 := "Open" if not r_wn11_so_000030

# WN11-SO-000035 | V-253438 | CAT II
default r_wn11_so_000035 := false
r_wn11_so_000035 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters"]["RequireSignOrSeal"] == 1
}

finding_r_wn11_so_000035 := {
	"vuln_id": "V-253438",
	"stig_id": "WN11-SO-000035",
	"severity": "CAT II",
	"rule_title": "Outgoing secure channel traffic must be encrypted or signed.",
	"status": status_r_wn11_so_000035,
}
status_r_wn11_so_000035 := "Not_a_Finding" if r_wn11_so_000035
status_r_wn11_so_000035 := "Open" if not r_wn11_so_000035

# WN11-SO-000040 | V-253439 | CAT II
default r_wn11_so_000040 := false
r_wn11_so_000040 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters"]["SealSecureChannel"] == 1
}

finding_r_wn11_so_000040 := {
	"vuln_id": "V-253439",
	"stig_id": "WN11-SO-000040",
	"severity": "CAT II",
	"rule_title": "Outgoing secure channel traffic must be encrypted.",
	"status": status_r_wn11_so_000040,
}
status_r_wn11_so_000040 := "Not_a_Finding" if r_wn11_so_000040
status_r_wn11_so_000040 := "Open" if not r_wn11_so_000040

# WN11-SO-000045 | V-253440 | CAT II
default r_wn11_so_000045 := false
r_wn11_so_000045 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters"]["SignSecureChannel"] == 1
}

finding_r_wn11_so_000045 := {
	"vuln_id": "V-253440",
	"stig_id": "WN11-SO-000045",
	"severity": "CAT II",
	"rule_title": "Outgoing secure channel traffic must be signed.",
	"status": status_r_wn11_so_000045,
}
status_r_wn11_so_000045 := "Not_a_Finding" if r_wn11_so_000045
status_r_wn11_so_000045 := "Open" if not r_wn11_so_000045

# WN11-SO-000050 | V-253441 | CAT III
default r_wn11_so_000050 := false
r_wn11_so_000050 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters"]["DisablePasswordChange"] == 0
}

finding_r_wn11_so_000050 := {
	"vuln_id": "V-253441",
	"stig_id": "WN11-SO-000050",
	"severity": "CAT III",
	"rule_title": "The computer account password must not be prevented from being reset.",
	"status": status_r_wn11_so_000050,
}
status_r_wn11_so_000050 := "Not_a_Finding" if r_wn11_so_000050
status_r_wn11_so_000050 := "Open" if not r_wn11_so_000050

# WN11-SO-000055 | V-253442 | CAT III
default r_wn11_so_000055 := false
r_wn11_so_000055 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters"]["MaximumPasswordAge"] == 30
}

finding_r_wn11_so_000055 := {
	"vuln_id": "V-253442",
	"stig_id": "WN11-SO-000055",
	"severity": "CAT III",
	"rule_title": "The maximum age for machine account passwords must be configured to 30 days or less.",
	"status": status_r_wn11_so_000055,
}
status_r_wn11_so_000055 := "Not_a_Finding" if r_wn11_so_000055
status_r_wn11_so_000055 := "Open" if not r_wn11_so_000055

# WN11-SO-000060 | V-253443 | CAT II
default r_wn11_so_000060 := false
r_wn11_so_000060 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters"]["RequireStrongKey"] == 1
}

finding_r_wn11_so_000060 := {
	"vuln_id": "V-253443",
	"stig_id": "WN11-SO-000060",
	"severity": "CAT II",
	"rule_title": "The system must be configured to require a strong session key.",
	"status": status_r_wn11_so_000060,
}
status_r_wn11_so_000060 := "Not_a_Finding" if r_wn11_so_000060
status_r_wn11_so_000060 := "Open" if not r_wn11_so_000060

# WN11-SO-000070 | V-253444 | CAT II
default r_wn11_so_000070 := false
r_wn11_so_000070 if {
	input.registry["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"]["InactivityTimeoutSecs"] == 900
}

finding_r_wn11_so_000070 := {
	"vuln_id": "V-253444",
	"stig_id": "WN11-SO-000070",
	"severity": "CAT II",
	"rule_title": "The machine inactivity limit must be set to 15 minutes, locking the system with the screensaver.",
	"status": status_r_wn11_so_000070,
}
status_r_wn11_so_000070 := "Not_a_Finding" if r_wn11_so_000070
status_r_wn11_so_000070 := "Open" if not r_wn11_so_000070

# WN11-SO-000075 | V-253445 | CAT II
default r_wn11_so_000075 := false
r_wn11_so_000075 if {
	input.registry["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"]["LegalNoticeText"] == "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only."
}

finding_r_wn11_so_000075 := {
	"vuln_id": "V-253445",
	"stig_id": "WN11-SO-000075",
	"severity": "CAT II",
	"rule_title": "The required legal notice must be configured to display before console logon.",
	"status": status_r_wn11_so_000075,
}
status_r_wn11_so_000075 := "Not_a_Finding" if r_wn11_so_000075
status_r_wn11_so_000075 := "Open" if not r_wn11_so_000075

# WN11-SO-000080 | V-253446 | CAT III
default r_wn11_so_000080 := false
r_wn11_so_000080 if {
	input.registry["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"]["LegalNoticeCaption"] == "See message title above"
}

finding_r_wn11_so_000080 := {
	"vuln_id": "V-253446",
	"stig_id": "WN11-SO-000080",
	"severity": "CAT III",
	"rule_title": "The Windows message title for the legal notice must be configured.",
	"status": status_r_wn11_so_000080,
}
status_r_wn11_so_000080 := "Not_a_Finding" if r_wn11_so_000080
status_r_wn11_so_000080 := "Open" if not r_wn11_so_000080

# WN11-SO-000085 | V-253447 | CAT III
default r_wn11_so_000085 := false
r_wn11_so_000085 if {
	input.registry["HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"]["CachedLogonsCount"] == "10 (or less)"
}

finding_r_wn11_so_000085 := {
	"vuln_id": "V-253447",
	"stig_id": "WN11-SO-000085",
	"severity": "CAT III",
	"rule_title": "Caching of logon credentials must be limited.",
	"status": status_r_wn11_so_000085,
}
status_r_wn11_so_000085 := "Not_a_Finding" if r_wn11_so_000085
status_r_wn11_so_000085 := "Open" if not r_wn11_so_000085

# WN11-SO-000095 | V-253448 | CAT II
default r_wn11_so_000095 := false
r_wn11_so_000095 if {
	input.registry["HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"]["SCRemoveOption"] == "1 (Lock Workstation) or 2 (Force Logoff)"
}

finding_r_wn11_so_000095 := {
	"vuln_id": "V-253448",
	"stig_id": "WN11-SO-000095",
	"severity": "CAT II",
	"rule_title": "The Smart Card removal option must be configured to Force Logoff or Lock Workstation.",
	"status": status_r_wn11_so_000095,
}
status_r_wn11_so_000095 := "Not_a_Finding" if r_wn11_so_000095
status_r_wn11_so_000095 := "Open" if not r_wn11_so_000095

# WN11-SO-000100 | V-253449 | CAT II
default r_wn11_so_000100 := false
r_wn11_so_000100 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters"]["RequireSecuritySignature"] == 1
}

finding_r_wn11_so_000100 := {
	"vuln_id": "V-253449",
	"stig_id": "WN11-SO-000100",
	"severity": "CAT II",
	"rule_title": "The Windows SMB client must be configured to always perform SMB packet signing.",
	"status": status_r_wn11_so_000100,
}
status_r_wn11_so_000100 := "Not_a_Finding" if r_wn11_so_000100
status_r_wn11_so_000100 := "Open" if not r_wn11_so_000100

# WN11-SO-000110 | V-253450 | CAT II
default r_wn11_so_000110 := false
r_wn11_so_000110 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters"]["EnablePlainTextPassword"] == 0
}

finding_r_wn11_so_000110 := {
	"vuln_id": "V-253450",
	"stig_id": "WN11-SO-000110",
	"severity": "CAT II",
	"rule_title": "Unencrypted passwords must not be sent to third-party SMB Servers.",
	"status": status_r_wn11_so_000110,
}
status_r_wn11_so_000110 := "Not_a_Finding" if r_wn11_so_000110
status_r_wn11_so_000110 := "Open" if not r_wn11_so_000110

# WN11-SO-000120 | V-253451 | CAT II
default r_wn11_so_000120 := false
r_wn11_so_000120 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters"]["RequireSecuritySignature"] == 1
}

finding_r_wn11_so_000120 := {
	"vuln_id": "V-253451",
	"stig_id": "WN11-SO-000120",
	"severity": "CAT II",
	"rule_title": "The Windows SMB server must be configured to always perform SMB packet signing.",
	"status": status_r_wn11_so_000120,
}
status_r_wn11_so_000120 := "Not_a_Finding" if r_wn11_so_000120
status_r_wn11_so_000120 := "Open" if not r_wn11_so_000120

# WN11-SO-000145 | V-253453 | CAT I
default r_wn11_so_000145 := false
r_wn11_so_000145 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa"]["RestrictAnonymousSAM"] == 1
}

finding_r_wn11_so_000145 := {
	"vuln_id": "V-253453",
	"stig_id": "WN11-SO-000145",
	"severity": "CAT I",
	"rule_title": "Anonymous enumeration of SAM accounts must not be allowed.",
	"status": status_r_wn11_so_000145,
}
status_r_wn11_so_000145 := "Not_a_Finding" if r_wn11_so_000145
status_r_wn11_so_000145 := "Open" if not r_wn11_so_000145

# WN11-SO-000150 | V-253454 | CAT I
default r_wn11_so_000150 := false
r_wn11_so_000150 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa"]["RestrictAnonymous"] == 1
}

finding_r_wn11_so_000150 := {
	"vuln_id": "V-253454",
	"stig_id": "WN11-SO-000150",
	"severity": "CAT I",
	"rule_title": "Anonymous enumeration of shares must be restricted.",
	"status": status_r_wn11_so_000150,
}
status_r_wn11_so_000150 := "Not_a_Finding" if r_wn11_so_000150
status_r_wn11_so_000150 := "Open" if not r_wn11_so_000150

# WN11-SO-000160 | V-253455 | CAT II
default r_wn11_so_000160 := false
r_wn11_so_000160 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa"]["EveryoneIncludesAnonymous"] == 0
}

finding_r_wn11_so_000160 := {
	"vuln_id": "V-253455",
	"stig_id": "WN11-SO-000160",
	"severity": "CAT II",
	"rule_title": "The system must be configured to prevent anonymous users from having the same rights as the Everyone group.",
	"status": status_r_wn11_so_000160,
}
status_r_wn11_so_000160 := "Not_a_Finding" if r_wn11_so_000160
status_r_wn11_so_000160 := "Open" if not r_wn11_so_000160

# WN11-SO-000165 | V-253456 | CAT I
default r_wn11_so_000165 := false
r_wn11_so_000165 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters"]["RestrictNullSessAccess"] == 1
}

finding_r_wn11_so_000165 := {
	"vuln_id": "V-253456",
	"stig_id": "WN11-SO-000165",
	"severity": "CAT I",
	"rule_title": "Anonymous access to Named Pipes and Shares must be restricted.",
	"status": status_r_wn11_so_000165,
}
status_r_wn11_so_000165 := "Not_a_Finding" if r_wn11_so_000165
status_r_wn11_so_000165 := "Open" if not r_wn11_so_000165

# WN11-SO-000167 | V-253457 | CAT II
default r_wn11_so_000167 := false
r_wn11_so_000167 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa"]["RestrictRemoteSAM"] == "O:BAG:BAD:(A;;RC;;;BA)"
}

finding_r_wn11_so_000167 := {
	"vuln_id": "V-253457",
	"stig_id": "WN11-SO-000167",
	"severity": "CAT II",
	"rule_title": "Remote calls to the Security Account Manager (SAM) must be restricted to Administrators.",
	"status": status_r_wn11_so_000167,
}
status_r_wn11_so_000167 := "Not_a_Finding" if r_wn11_so_000167
status_r_wn11_so_000167 := "Open" if not r_wn11_so_000167

# WN11-SO-000180 | V-253458 | CAT II
default r_wn11_so_000180 := false
r_wn11_so_000180 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Control\\LSA\\MSV1_0"]["allownullsessionfallback"] == 0
}

finding_r_wn11_so_000180 := {
	"vuln_id": "V-253458",
	"stig_id": "WN11-SO-000180",
	"severity": "CAT II",
	"rule_title": "NTLM must be prevented from falling back to a Null session.",
	"status": status_r_wn11_so_000180,
}
status_r_wn11_so_000180 := "Not_a_Finding" if r_wn11_so_000180
status_r_wn11_so_000180 := "Open" if not r_wn11_so_000180

# WN11-SO-000185 | V-253459 | CAT II
default r_wn11_so_000185 := false
r_wn11_so_000185 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Control\\LSA\\pku2u"]["AllowOnlineID"] == 0
}

finding_r_wn11_so_000185 := {
	"vuln_id": "V-253459",
	"stig_id": "WN11-SO-000185",
	"severity": "CAT II",
	"rule_title": "PKU2U authentication using online identities must be prevented.",
	"status": status_r_wn11_so_000185,
}
status_r_wn11_so_000185 := "Not_a_Finding" if r_wn11_so_000185
status_r_wn11_so_000185 := "Open" if not r_wn11_so_000185

# WN11-SO-000190 | V-253460 | CAT II
default r_wn11_so_000190 := false
r_wn11_so_000190 if {
	input.registry["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters"]["SupportedEncryptionTypes"] == 2147483640
}

finding_r_wn11_so_000190 := {
	"vuln_id": "V-253460",
	"stig_id": "WN11-SO-000190",
	"severity": "CAT II",
	"rule_title": "Kerberos encryption types must be configured to prevent the use of DES and RC4 encryption suites.",
	"status": status_r_wn11_so_000190,
}
status_r_wn11_so_000190 := "Not_a_Finding" if r_wn11_so_000190
status_r_wn11_so_000190 := "Open" if not r_wn11_so_000190

# WN11-SO-000195 | V-253461 | CAT I
default r_wn11_so_000195 := false
r_wn11_so_000195 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa"]["NoLMHash"] == 1
}

finding_r_wn11_so_000195 := {
	"vuln_id": "V-253461",
	"stig_id": "WN11-SO-000195",
	"severity": "CAT I",
	"rule_title": "The system must be configured to prevent the storage of the LAN Manager hash of passwords.",
	"status": status_r_wn11_so_000195,
}
status_r_wn11_so_000195 := "Not_a_Finding" if r_wn11_so_000195
status_r_wn11_so_000195 := "Open" if not r_wn11_so_000195

# WN11-SO-000205 | V-253462 | CAT I
default r_wn11_so_000205 := false
r_wn11_so_000205 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa"]["LmCompatibilityLevel"] == 5
}

finding_r_wn11_so_000205 := {
	"vuln_id": "V-253462",
	"stig_id": "WN11-SO-000205",
	"severity": "CAT I",
	"rule_title": "The LanMan authentication level must be set to send NTLMv2 response only, and to refuse LM and NTLM.",
	"status": status_r_wn11_so_000205,
}
status_r_wn11_so_000205 := "Not_a_Finding" if r_wn11_so_000205
status_r_wn11_so_000205 := "Open" if not r_wn11_so_000205

# WN11-SO-000210 | V-253463 | CAT II
default r_wn11_so_000210 := false
r_wn11_so_000210 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Services\\LDAP"]["LDAPClientIntegrity"] == 1
}

finding_r_wn11_so_000210 := {
	"vuln_id": "V-253463",
	"stig_id": "WN11-SO-000210",
	"severity": "CAT II",
	"rule_title": "The system must be configured to the required LDAP client signing level.",
	"status": status_r_wn11_so_000210,
}
status_r_wn11_so_000210 := "Not_a_Finding" if r_wn11_so_000210
status_r_wn11_so_000210 := "Open" if not r_wn11_so_000210

# WN11-SO-000215 | V-253464 | CAT II
default r_wn11_so_000215 := false
r_wn11_so_000215 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0"]["NTLMMinClientSec"] == 537395200
}

finding_r_wn11_so_000215 := {
	"vuln_id": "V-253464",
	"stig_id": "WN11-SO-000215",
	"severity": "CAT II",
	"rule_title": "The system must be configured to meet the minimum session security requirement for NTLM SSP based clients.",
	"status": status_r_wn11_so_000215,
}
status_r_wn11_so_000215 := "Not_a_Finding" if r_wn11_so_000215
status_r_wn11_so_000215 := "Open" if not r_wn11_so_000215

# WN11-SO-000220 | V-253465 | CAT II
default r_wn11_so_000220 := false
r_wn11_so_000220 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0"]["NTLMMinServerSec"] == 537395200
}

finding_r_wn11_so_000220 := {
	"vuln_id": "V-253465",
	"stig_id": "WN11-SO-000220",
	"severity": "CAT II",
	"rule_title": "The system must be configured to meet the minimum session security requirement for NTLM SSP based servers.",
	"status": status_r_wn11_so_000220,
}
status_r_wn11_so_000220 := "Not_a_Finding" if r_wn11_so_000220
status_r_wn11_so_000220 := "Open" if not r_wn11_so_000220

# WN11-SO-000240 | V-253467 | CAT III
default r_wn11_so_000240 := false
r_wn11_so_000240 if {
	input.registry["HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager"]["ProtectionMode"] == 1
}

finding_r_wn11_so_000240 := {
	"vuln_id": "V-253467",
	"stig_id": "WN11-SO-000240",
	"severity": "CAT III",
	"rule_title": "The default permissions of global system objects must be increased.",
	"status": status_r_wn11_so_000240,
}
status_r_wn11_so_000240 := "Not_a_Finding" if r_wn11_so_000240
status_r_wn11_so_000240 := "Open" if not r_wn11_so_000240

# WN11-SO-000245 | V-253468 | CAT II
default r_wn11_so_000245 := false
r_wn11_so_000245 if {
	input.registry["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"]["FilterAdministratorToken"] == 1
}

finding_r_wn11_so_000245 := {
	"vuln_id": "V-253468",
	"stig_id": "WN11-SO-000245",
	"severity": "CAT II",
	"rule_title": "User Account Control approval mode for the built-in Administrator must be enabled.",
	"status": status_r_wn11_so_000245,
}
status_r_wn11_so_000245 := "Not_a_Finding" if r_wn11_so_000245
status_r_wn11_so_000245 := "Open" if not r_wn11_so_000245

# WN11-SO-000255 | V-253471 | CAT II
default r_wn11_so_000255 := false
r_wn11_so_000255 if {
	input.registry["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"]["ConsentPromptBehaviorUser"] == 0
}

finding_r_wn11_so_000255 := {
	"vuln_id": "V-253471",
	"stig_id": "WN11-SO-000255",
	"severity": "CAT II",
	"rule_title": "User Account Control must automatically deny elevation requests for standard users.",
	"status": status_r_wn11_so_000255,
}
status_r_wn11_so_000255 := "Not_a_Finding" if r_wn11_so_000255
status_r_wn11_so_000255 := "Open" if not r_wn11_so_000255

# WN11-SO-000260 | V-253472 | CAT II
default r_wn11_so_000260 := false
r_wn11_so_000260 if {
	input.registry["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"]["EnableInstallerDetection"] == 1
}

finding_r_wn11_so_000260 := {
	"vuln_id": "V-253472",
	"stig_id": "WN11-SO-000260",
	"severity": "CAT II",
	"rule_title": "User Account Control must be configured to detect application installations and prompt for elevation.",
	"status": status_r_wn11_so_000260,
}
status_r_wn11_so_000260 := "Not_a_Finding" if r_wn11_so_000260
status_r_wn11_so_000260 := "Open" if not r_wn11_so_000260

# WN11-SO-000265 | V-253473 | CAT II
default r_wn11_so_000265 := false
r_wn11_so_000265 if {
	input.registry["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"]["EnableSecureUIAPaths"] == 1
}

finding_r_wn11_so_000265 := {
	"vuln_id": "V-253473",
	"stig_id": "WN11-SO-000265",
	"severity": "CAT II",
	"rule_title": "User Account Control must only elevate UIAccess applications that are installed in secure locations.",
	"status": status_r_wn11_so_000265,
}
status_r_wn11_so_000265 := "Not_a_Finding" if r_wn11_so_000265
status_r_wn11_so_000265 := "Open" if not r_wn11_so_000265

# WN11-SO-000270 | V-253474 | CAT II
default r_wn11_so_000270 := false
r_wn11_so_000270 if {
	input.registry["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"]["EnableLUA"] == 1
}

finding_r_wn11_so_000270 := {
	"vuln_id": "V-253474",
	"stig_id": "WN11-SO-000270",
	"severity": "CAT II",
	"rule_title": "User Account Control must run all administrators in Admin Approval Mode, enabling UAC.",
	"status": status_r_wn11_so_000270,
}
status_r_wn11_so_000270 := "Not_a_Finding" if r_wn11_so_000270
status_r_wn11_so_000270 := "Open" if not r_wn11_so_000270

# WN11-SO-000275 | V-253475 | CAT II
default r_wn11_so_000275 := false
r_wn11_so_000275 if {
	input.registry["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"]["EnableVirtualization"] == 1
}

finding_r_wn11_so_000275 := {
	"vuln_id": "V-253475",
	"stig_id": "WN11-SO-000275",
	"severity": "CAT II",
	"rule_title": "User Account Control must virtualize file and registry write failures to per-user locations.",
	"status": status_r_wn11_so_000275,
}
status_r_wn11_so_000275 := "Not_a_Finding" if r_wn11_so_000275
status_r_wn11_so_000275 := "Open" if not r_wn11_so_000275

findings := [
	finding_r_wn11_so_000015,
	finding_r_wn11_so_000030,
	finding_r_wn11_so_000035,
	finding_r_wn11_so_000040,
	finding_r_wn11_so_000045,
	finding_r_wn11_so_000050,
	finding_r_wn11_so_000055,
	finding_r_wn11_so_000060,
	finding_r_wn11_so_000070,
	finding_r_wn11_so_000075,
	finding_r_wn11_so_000080,
	finding_r_wn11_so_000085,
	finding_r_wn11_so_000095,
	finding_r_wn11_so_000100,
	finding_r_wn11_so_000110,
	finding_r_wn11_so_000120,
	finding_r_wn11_so_000145,
	finding_r_wn11_so_000150,
	finding_r_wn11_so_000160,
	finding_r_wn11_so_000165,
	finding_r_wn11_so_000167,
	finding_r_wn11_so_000180,
	finding_r_wn11_so_000185,
	finding_r_wn11_so_000190,
	finding_r_wn11_so_000195,
	finding_r_wn11_so_000205,
	finding_r_wn11_so_000210,
	finding_r_wn11_so_000215,
	finding_r_wn11_so_000220,
	finding_r_wn11_so_000240,
	finding_r_wn11_so_000245,
	finding_r_wn11_so_000255,
	finding_r_wn11_so_000260,
	finding_r_wn11_so_000265,
	finding_r_wn11_so_000270,
	finding_r_wn11_so_000275,
]

default compliant := false

compliant if count([f | some f in findings; f.status == "Open"]) == 0
