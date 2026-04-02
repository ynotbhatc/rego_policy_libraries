package stig.windows_server_2022.services_audit

# DISA STIG for Windows Server 2022 - Services and Audit Module
# STIG Version: V2R2 | Released: October 2024
# Covers: Disabled services, audit policy configuration

import rego.v1

default compliant := false

svc_disabled(svc) if { input.services[svc] == "Disabled" }
svc_disabled(svc) if { input.services[svc] == "Stopped" }
svc_disabled(svc) if { not input.services[svc] }

# =============================================================================
# CAT I
# =============================================================================

# WN22-00-000100 | V-254260 | CAT I - Telnet client must not be installed
default no_telnet := false
no_telnet if { input.windows_features.TelnetClient.installed == false }
no_telnet if { not input.windows_features.TelnetClient }

status_wn22_000100 := "Not_a_Finding" if { no_telnet } else := "Open"
finding_wn22_000100 := {
	"vuln_id": "V-254260",
	"stig_id": "WN22-00-000100",
	"severity": "CAT I",
	"rule_title": "Windows Server 2022 must not have the Telnet Client installed",
	"status": status_wn22_000100,
	"fix_text": "Uninstall Telnet Client: Remove-WindowsFeature -Name Telnet-Client",
}

# WN22-00-000110 | V-254261 | CAT I - SNMP service must not be installed
default no_snmp := false
no_snmp if { input.windows_features.SNMP.installed == false }
no_snmp if { not input.windows_features.SNMP }

status_wn22_000110 := "Not_a_Finding" if { no_snmp } else := "Open"
finding_wn22_000110 := {
	"vuln_id": "V-254261",
	"stig_id": "WN22-00-000110",
	"severity": "CAT I",
	"rule_title": "Windows Server 2022 must not have the SNMP service installed unless required",
	"status": status_wn22_000110,
	"fix_text": "Remove SNMP: Remove-WindowsFeature -Name SNMP-Service",
}

# WN22-00-000120 | V-254262 | CAT I - IIS must not be installed unless required
default iis_controlled := false
iis_controlled if { input.windows_features.Web_Server.installed == false }
iis_controlled if { input.windows_features.Web_Server.required == true }

status_wn22_000120 := "Not_a_Finding" if { iis_controlled } else := "Open"
finding_wn22_000120 := {
	"vuln_id": "V-254262",
	"stig_id": "WN22-00-000120",
	"severity": "CAT I",
	"rule_title": "Windows Server 2022 must not have IIS installed on a non-application server",
	"status": status_wn22_000120,
	"fix_text": "Remove IIS: Remove-WindowsFeature -Name Web-Server",
}

# =============================================================================
# CAT II - Audit Policy
# =============================================================================

# WN22-AU-000010 | V-254270 | CAT II - Credential Validation must be audited
default audit_credential_validation := false
audit_credential_validation if {
	input.audit_policy.CredentialValidation == "Success and Failure"
}
audit_credential_validation if {
	input.audit_policy.CredentialValidation == "Success, Failure"
}

status_wn22_au_000010 := "Not_a_Finding" if { audit_credential_validation } else := "Open"
finding_wn22_au_000010 := {
	"vuln_id": "V-254270",
	"stig_id": "WN22-AU-000010",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 must audit Credential Validation successes and failures",
	"status": status_wn22_au_000010,
	"fix_text": "Configure Audit Credential Validation: Success and Failure",
}

# WN22-AU-000020 | V-254271 | CAT II - Logon/Logoff must be audited
default audit_logon := false
audit_logon if { input.audit_policy.Logon == "Success and Failure" }
audit_logon if { input.audit_policy.Logon == "Success, Failure" }

status_wn22_au_000020 := "Not_a_Finding" if { audit_logon } else := "Open"
finding_wn22_au_000020 := {
	"vuln_id": "V-254271",
	"stig_id": "WN22-AU-000020",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 must audit Logon/Logoff successes",
	"status": status_wn22_au_000020,
	"fix_text": "Configure Audit Logon/Logoff: Success and Failure",
}

# WN22-AU-000030 | V-254272 | CAT II - Object Access must be audited
default audit_object_access := false
audit_object_access if { input.audit_policy.ObjectAccess == "Success and Failure" }
audit_object_access if { input.audit_policy.ObjectAccess == "Failure" }

status_wn22_au_000030 := "Not_a_Finding" if { audit_object_access } else := "Open"
finding_wn22_au_000030 := {
	"vuln_id": "V-254272",
	"stig_id": "WN22-AU-000030",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 must audit Object Access failures",
	"status": status_wn22_au_000030,
	"fix_text": "Configure Audit Object Access: Failure",
}

# WN22-AU-000040 | V-254273 | CAT II - Policy Change must be audited
default audit_policy_change := false
audit_policy_change if { input.audit_policy.PolicyChange == "Success" }
audit_policy_change if { input.audit_policy.PolicyChange == "Success and Failure" }

status_wn22_au_000040 := "Not_a_Finding" if { audit_policy_change } else := "Open"
finding_wn22_au_000040 := {
	"vuln_id": "V-254273",
	"stig_id": "WN22-AU-000040",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 must audit Policy Change successes",
	"status": status_wn22_au_000040,
	"fix_text": "Configure Audit Policy Change: Success",
}

# WN22-AU-000050 | V-254274 | CAT II - Privilege Use must be audited
default audit_privilege_use := false
audit_privilege_use if { input.audit_policy.PrivilegeUse == "Success and Failure" }
audit_privilege_use if { input.audit_policy.PrivilegeUse == "Failure" }

status_wn22_au_000050 := "Not_a_Finding" if { audit_privilege_use } else := "Open"
finding_wn22_au_000050 := {
	"vuln_id": "V-254274",
	"stig_id": "WN22-AU-000050",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 must audit Privilege Use failures",
	"status": status_wn22_au_000050,
	"fix_text": "Configure Audit Privilege Use: Failure",
}

# WN22-AU-000060 | V-254275 | CAT II - System events must be audited
default audit_system := false
audit_system if { input.audit_policy.System == "Success and Failure" }

status_wn22_au_000060 := "Not_a_Finding" if { audit_system } else := "Open"
finding_wn22_au_000060 := {
	"vuln_id": "V-254275",
	"stig_id": "WN22-AU-000060",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 must audit System events",
	"status": status_wn22_au_000060,
	"fix_text": "Configure Audit System: Success and Failure",
}

# WN22-AU-000070 | V-254276 | CAT II - Account Management must be audited
default audit_account_mgmt := false
audit_account_mgmt if { input.audit_policy.AccountManagement == "Success and Failure" }

status_wn22_au_000070 := "Not_a_Finding" if { audit_account_mgmt } else := "Open"
finding_wn22_au_000070 := {
	"vuln_id": "V-254276",
	"stig_id": "WN22-AU-000070",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 must audit Account Management",
	"status": status_wn22_au_000070,
	"fix_text": "Configure Audit Account Management: Success and Failure",
}

# WN22-AU-000080 | V-254277 | CAT II - Process Creation must be audited
default audit_process_creation := false
audit_process_creation if { input.audit_policy.ProcessCreation == "Success" }
audit_process_creation if { input.audit_policy.ProcessCreation == "Success and Failure" }

status_wn22_au_000080 := "Not_a_Finding" if { audit_process_creation } else := "Open"
finding_wn22_au_000080 := {
	"vuln_id": "V-254277",
	"stig_id": "WN22-AU-000080",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 must audit Process Creation",
	"status": status_wn22_au_000080,
	"fix_text": "Configure Audit Process Creation: Success",
}

# WN22-AU-000090 | V-254278 | CAT II - Directory Service Access must be audited
default audit_directory_access := false
audit_directory_access if { input.audit_policy.DirectoryServiceAccess == "Success and Failure" }
audit_directory_access if { input.audit_policy.DirectoryServiceAccess == "Failure" }
audit_directory_access if { not input.system_info.is_domain_controller }  # Only required on DCs

status_wn22_au_000090 := "Not_a_Finding" if { audit_directory_access } else := "Open"
finding_wn22_au_000090 := {
	"vuln_id": "V-254278",
	"stig_id": "WN22-AU-000090",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 must audit Directory Service Access (domain controllers only)",
	"status": status_wn22_au_000090,
	"fix_text": "Configure Audit Directory Service Access: Failure",
}

# WN22-SO-000040 | V-254285 | CAT II - Event log size: Security (196608 KB)
default security_log_size := false
security_log_size if {
	input.event_logs.Security.max_size >= 196608
}

status_wn22_so_000040 := "Not_a_Finding" if { security_log_size } else := "Open"
finding_wn22_so_000040 := {
	"vuln_id": "V-254285",
	"stig_id": "WN22-SO-000040",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 Security event log maximum size must be at least 196608 KB",
	"status": status_wn22_so_000040,
	"fix_text": "Set Security log size to at least 196608 KB in Event Log policy",
}

# WN22-SO-000050 | V-254286 | CAT II - Event log size: Application (32768 KB)
default application_log_size := false
application_log_size if {
	input.event_logs.Application.max_size >= 32768
}

status_wn22_so_000050 := "Not_a_Finding" if { application_log_size } else := "Open"
finding_wn22_so_000050 := {
	"vuln_id": "V-254286",
	"stig_id": "WN22-SO-000050",
	"severity": "CAT II",
	"rule_title": "Windows Server 2022 Application event log maximum size must be at least 32768 KB",
	"status": status_wn22_so_000050,
	"fix_text": "Set Application log size to at least 32768 KB",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

cat_i_findings := [
	finding_wn22_000100,
	finding_wn22_000110,
	finding_wn22_000120,
]

cat_ii_findings := [
	finding_wn22_au_000010,
	finding_wn22_au_000020,
	finding_wn22_au_000030,
	finding_wn22_au_000040,
	finding_wn22_au_000050,
	finding_wn22_au_000060,
	finding_wn22_au_000070,
	finding_wn22_au_000080,
	finding_wn22_au_000090,
	finding_wn22_so_000040,
	finding_wn22_so_000050,
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
	"module": "services_audit",
	"total_findings": count(findings),
	"open_findings": count(violations),
	"cat_i_open": count(open_cat_i),
	"findings": findings,
	"compliant": compliant,
}
