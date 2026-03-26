package stig.windows_11

# DISA STIG for windows 11 - Simplified Complete Assessment
# Version: V2R1 (Released: March 2024)
# This is a streamlined implementation for OPA validation

import rego.v1

# =============================================================================
# SAMPLE CRITICAL FINDINGS (CAT I)
# =============================================================================

finding_v_254238_dod_root_ca := {
	"vuln_id": "V-253270",
	"stig_id": "WN11-PK-000010",
	"severity": "CAT I",
	"rule_title": "Windows 11 must have the DoD Root CA certificates installed",
	"status": dod_root_ca_status,
}

dod_root_ca_status := "Open" if {
	not input.certificates.dod_root_ca_installed
} else := "Not_a_Finding"

finding_v_254241_guest_account := {
	"vuln_id": "V-253273",
	"stig_id": "WN11-SO-000030",
	"severity": "CAT I",
	"rule_title": "The built-in guest account must be disabled",
	"status": guest_account_status,
}

guest_account_status := "Open" if {
	input.local_accounts.guest.enabled == true
} else := "Not_a_Finding"

finding_v_254243_antivirus := {
	"vuln_id": "V-253275",
	"stig_id": "WN11-00-000020",
	"severity": "CAT I",
	"rule_title": "The Windows 11 system must use an antivirus program",
	"status": antivirus_status,
}

antivirus_status := "Open" if {
	not input.windows_defender.antivirus_enabled
} else := "Not_a_Finding"

# =============================================================================
# SAMPLE HIGH FINDINGS (CAT II)
# =============================================================================

finding_v_254247_password_history := {
	"vuln_id": "V-253279",
	"stig_id": "WN11-AC-000010",
	"severity": "CAT II",
	"rule_title": "Password history must be configured to 24 or more passwords",
	"status": password_history_status,
}

password_history_status := "Open" if {
	input.password_policy.password_history_size < 24
} else := "Not_a_Finding"

finding_v_254250_password_length := {
	"vuln_id": "V-253282",
	"stig_id": "WN11-AC-000040",
	"severity": "CAT II",
	"rule_title": "Minimum password length must be configured to 14 characters or more",
	"status": password_length_status,
}

password_length_status := "Open" if {
	input.password_policy.minimum_password_length < 14
} else := "Not_a_Finding"

# =============================================================================
# AGGREGATE ALL FINDINGS
# =============================================================================

all_findings := [
	finding_v_254238_dod_root_ca,
	finding_v_254241_guest_account,
	finding_v_254243_antivirus,
	finding_v_254247_password_history,
	finding_v_254250_password_length,
]

open_findings := [f | some f in all_findings; f.status == "Open"]

compliant := true if {
	count(open_findings) == 0
} else := false

# =============================================================================
# STIG COMPLIANCE ASSESSMENT REPORT
# =============================================================================

stig_assessment := {
	"assessment_metadata": {
		"stig_title": "Windows 11 Security Technical Implementation Guide",
		"stig_version": "Version 2, Release 1",
		"classification": "UNCLASSIFIED",
		"hostname": input.system_info.hostname,
	},
	"compliance_summary": {
		"overall_status": compliance_status,
		"compliant": compliant,
		"total_checks": count(all_findings),
		"open_findings": count(open_findings),
	},
	"open_findings_details": open_findings,
}

compliance_status := "Compliant" if compliant else := "Non-Compliant"
