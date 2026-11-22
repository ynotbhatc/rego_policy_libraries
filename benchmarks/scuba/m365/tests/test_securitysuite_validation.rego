# Unit tests for scuba_m365.securitysuite (MS.SECURITYSUITE.* — CISA SCuBA M365,
# ScubaGear v2.0.0). One test per violation rule (each firing exactly that
# rule), a compliant case, boundary cases for the numeric and list policies,
# and a populated-report-on-empty-input case.
package scuba_m365.securitysuite_test

import data.scuba_m365.securitysuite
import rego.v1

compliant_input := {"scuba": {"securitysuite": {
	"malware": {
		"click_to_run_blocked": true,
		"post_delivery_scan": true,
		"quarantine_or_drop": true,
	},
	"safe_attachments": {"spo_odb_teams_enabled": true},
	"impersonation": {
		"user_protection_sensitive": true,
		"domain_protection_owned": true,
		"domain_protection_partners": true,
		"user_warnings": true,
	},
	"dlp": {
		"custom_pii_policy": true,
		"applied_all_workloads": true,
		"block_everyone_action": true,
		"user_notifications": true,
		"restricted_apps_blocked": true,
	},
	"alerts": {
		"enabled": [
			"Suspicious email sending patterns detected",
			"Suspicious Connector Activity",
			"Suspicious Email Forwarding Activity",
			"Messages have been delayed",
			"Tenant restricted from sending unprovisioned email",
			"Tenant restricted from sending email",
			"A potentially malicious URL click was detected",
		],
		"routed_to_monitored_target": true,
	},
	"audit": {
		"unified_logging_enabled": true,
		"searchable_retention_days": 90,
		"retrievable_retention_days": 365,
	},
	"antispam": {
		"spam_phish_not_in_inbox": true,
		"no_allowed_domains": true,
	},
	"links": {
		"url_blocklist_enabled": true,
		"download_links_scanned": true,
		"click_tracking_enabled": true,
	},
	"allow_lists": {
		"no_ip_allow_list": true,
		"safe_list_disabled": true,
	},
}}}

_set(path, value) := json.patch(compliant_input, [{"op": "replace", "path": path, "value": value}])

# Takes the violation set, bound in the test with `with input as`, so this
# helper body carries no `with` (CI rejects that in helper functions).
_only(v, id) if {
	count(v) == 1
	some m in v
	contains(m, id)
}

test_compliant_when_all_facts_satisfied if {
	securitysuite.compliant with input as compliant_input
	count(securitysuite.violations) == 0 with input as compliant_input
}

# Each boolean fact, flipped false, fires exactly its own policy.

test_ss_1_1_click_to_run_blocked if {
	v := securitysuite.violations with input as _set("/scuba/securitysuite/malware/click_to_run_blocked", false)
	_only(v, "MS.SECURITYSUITE.1.1v1")
}

test_ss_1_2_post_delivery_scan if {
	v := securitysuite.violations with input as _set("/scuba/securitysuite/malware/post_delivery_scan", false)
	_only(v, "MS.SECURITYSUITE.1.2v1")
}

test_ss_1_3_quarantine_or_drop if {
	v := securitysuite.violations with input as _set("/scuba/securitysuite/malware/quarantine_or_drop", false)
	_only(v, "MS.SECURITYSUITE.1.3v1")
}

test_ss_1_4_spo_odb_teams_enabled if {
	v := securitysuite.violations with input as _set("/scuba/securitysuite/safe_attachments/spo_odb_teams_enabled", false)
	_only(v, "MS.SECURITYSUITE.1.4v1")
}

test_ss_2_1_user_protection_sensitive if {
	v := securitysuite.violations with input as _set("/scuba/securitysuite/impersonation/user_protection_sensitive", false)
	_only(v, "MS.SECURITYSUITE.2.1v1")
}

test_ss_2_2_domain_protection_owned if {
	v := securitysuite.violations with input as _set("/scuba/securitysuite/impersonation/domain_protection_owned", false)
	_only(v, "MS.SECURITYSUITE.2.2v1")
}

test_ss_2_3_domain_protection_partners if {
	v := securitysuite.violations with input as _set("/scuba/securitysuite/impersonation/domain_protection_partners", false)
	_only(v, "MS.SECURITYSUITE.2.3v1")
}

test_ss_2_4_user_warnings if {
	v := securitysuite.violations with input as _set("/scuba/securitysuite/impersonation/user_warnings", false)
	_only(v, "MS.SECURITYSUITE.2.4v1")
}

test_ss_3_1_custom_pii_policy if {
	v := securitysuite.violations with input as _set("/scuba/securitysuite/dlp/custom_pii_policy", false)
	_only(v, "MS.SECURITYSUITE.3.1v1")
}

test_ss_3_2_applied_all_workloads if {
	v := securitysuite.violations with input as _set("/scuba/securitysuite/dlp/applied_all_workloads", false)
	_only(v, "MS.SECURITYSUITE.3.2v1")
}

test_ss_3_3_block_everyone_action if {
	v := securitysuite.violations with input as _set("/scuba/securitysuite/dlp/block_everyone_action", false)
	_only(v, "MS.SECURITYSUITE.3.3v1")
}

test_ss_3_4_user_notifications if {
	v := securitysuite.violations with input as _set("/scuba/securitysuite/dlp/user_notifications", false)
	_only(v, "MS.SECURITYSUITE.3.4v1")
}

test_ss_3_5_restricted_apps_blocked if {
	v := securitysuite.violations with input as _set("/scuba/securitysuite/dlp/restricted_apps_blocked", false)
	_only(v, "MS.SECURITYSUITE.3.5v1")
}

test_ss_4_2_routed_to_monitored_target if {
	v := securitysuite.violations with input as _set("/scuba/securitysuite/alerts/routed_to_monitored_target", false)
	_only(v, "MS.SECURITYSUITE.4.2v1")
}

test_ss_5_1_unified_logging_enabled if {
	v := securitysuite.violations with input as _set("/scuba/securitysuite/audit/unified_logging_enabled", false)
	_only(v, "MS.SECURITYSUITE.5.1v1")
}

test_ss_6_1_spam_phish_not_in_inbox if {
	v := securitysuite.violations with input as _set("/scuba/securitysuite/antispam/spam_phish_not_in_inbox", false)
	_only(v, "MS.SECURITYSUITE.6.1v1")
}

test_ss_6_2_no_allowed_domains if {
	v := securitysuite.violations with input as _set("/scuba/securitysuite/antispam/no_allowed_domains", false)
	_only(v, "MS.SECURITYSUITE.6.2v1")
}

test_ss_7_1_url_blocklist_enabled if {
	v := securitysuite.violations with input as _set("/scuba/securitysuite/links/url_blocklist_enabled", false)
	_only(v, "MS.SECURITYSUITE.7.1v1")
}

test_ss_7_2_download_links_scanned if {
	v := securitysuite.violations with input as _set("/scuba/securitysuite/links/download_links_scanned", false)
	_only(v, "MS.SECURITYSUITE.7.2v1")
}

test_ss_7_3_click_tracking_enabled if {
	v := securitysuite.violations with input as _set("/scuba/securitysuite/links/click_tracking_enabled", false)
	_only(v, "MS.SECURITYSUITE.7.3v1")
}

test_ss_8_1_no_ip_allow_list if {
	v := securitysuite.violations with input as _set("/scuba/securitysuite/allow_lists/no_ip_allow_list", false)
	_only(v, "MS.SECURITYSUITE.8.1v1")
}

test_ss_8_2_safe_list_disabled if {
	v := securitysuite.violations with input as _set("/scuba/securitysuite/allow_lists/safe_list_disabled", false)
	_only(v, "MS.SECURITYSUITE.8.2v1")
}

# A string "true" is not evidence.
test_string_true_is_not_evidence if {
	v := securitysuite.violations with input as _set("/scuba/securitysuite/malware/click_to_run_blocked", "true")
	_only(v, "MS.SECURITYSUITE.1.1v1")
}

# 4.1: every one of the seven alerts must be enabled.
test_4_1_one_alert_missing_fires_and_names_it if {
	inp := json.patch(compliant_input, [{"op": "remove", "path": "/scuba/securitysuite/alerts/enabled/6"}])
	v := securitysuite.violations with input as inp
	_only(v, "MS.SECURITYSUITE.4.1v1")
	some m in securitysuite.violations with input as inp
	contains(m, "A potentially malicious URL click was detected")
}

test_4_1_alerts_not_a_list_fires if {
	v := securitysuite.violations with input as _set("/scuba/securitysuite/alerts/enabled", "all")
	_only(v, "MS.SECURITYSUITE.4.1v1")
}

test_4_1_extra_alerts_pass if {
	inp := json.patch(compliant_input, [{"op": "add", "path": "/scuba/securitysuite/alerts/enabled/-", "value": "Custom alert"}])
	count(securitysuite.violations) == 0 with input as inp
}

# 5.2: searchable >= 90 days and retrievable >= 365 days, numbers only.
test_5_2_searchable_89_days_fires if {
	v := securitysuite.violations with input as _set("/scuba/securitysuite/audit/searchable_retention_days", 89)
	_only(v, "MS.SECURITYSUITE.5.2v1")
}

test_5_2_retrievable_364_days_fires if {
	v := securitysuite.violations with input as _set("/scuba/securitysuite/audit/retrievable_retention_days", 364)
	_only(v, "MS.SECURITYSUITE.5.2v1")
}

test_5_2_string_days_fire if {
	v := securitysuite.violations with input as _set("/scuba/securitysuite/audit/retrievable_retention_days", "365")
	_only(v, "MS.SECURITYSUITE.5.2v1")
}

test_5_2_longer_retention_passes if {
	inp := json.patch(compliant_input, [
		{"op": "replace", "path": "/scuba/securitysuite/audit/searchable_retention_days", "value": 180},
		{"op": "replace", "path": "/scuba/securitysuite/audit/retrievable_retention_days", "value": 3650},
	])
	count(securitysuite.violations) == 0 with input as inp
}

# Fail-closed: empty input fires all 24 policies (9 SHALL, 15 SHOULD) and still
# yields a populated report object.
test_report_populated_on_empty_input if {
	r := securitysuite.compliance_report with input as {}
	r.compliant == false
	r.violation_count == 24
	r.controls_evaluated == 24
	r.shall_violation_count == 9
	r.should_violation_count == 15
	r.baseline == "MS.SECURITYSUITE"
}

# The old Defender namespace is not read: Defender-era facts alone do not pass.
test_defender_namespace_not_read if {
	r := securitysuite.compliance_report with input as {"scuba": {"defender": {"audit": {"unified_logging_enabled": true}}}}
	r.violation_count == 24
}
