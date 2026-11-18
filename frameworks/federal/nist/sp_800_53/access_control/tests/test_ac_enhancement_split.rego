package nist.sp800_53.access_control_split_test

# A base control must not fail on an enhancement's requirement; each enhancement is its own finding.
# Also: facts not in the Rev 5 statement (AC-5 monitored_compliance, AC-10 per_device_limits, AC-12
# administrative_termination, AC-18 monitored_usage, AC-21 security_attributes_preserved) are not required.

import data.nist.sp800_53.access_control as ac
import rego.v1

_finding(r, id) := [v | some v in r.violations; startswith(v, concat("", ["NIST ", id, ":"]))]

_ac(x) := r if {
	r := ac.compliance_report with input as {"ac_controls": x}
}

# [base id, enhancement id, base-only input, enhancement-only input]
_cases := [
	["AC-2", "AC-2(1)", {"account_management": {"approval_process": true, "regular_reviews": true, "timely_removal": true, "automated_tools": false}}, {"account_management": {"automated_tools": true}}],
	["AC-4", "AC-4(1)", {"information_flow": {"flow_control_policies": true, "automated_enforcement": true, "security_labels": false}}, {"information_flow": {"security_labels": true}}],
	["AC-6", "AC-6(1)", {"least_privilege": {"minimum_access_granted": true, "privileged_functions_authorized": false}}, {"least_privilege": {"privileged_functions_authorized": true}}],
	["AC-6", "AC-6(2)", {"least_privilege": {"minimum_access_granted": true, "non_privileged_access_default": false}}, {"least_privilege": {"non_privileged_access_default": true}}],
	["AC-9", "AC-9(1)", {"logon_notification": {"timestamp_displayed": true, "unsuccessful_attempts_displayed": false}}, {"logon_notification": {"unsuccessful_attempts_displayed": true}}],
	["AC-9", "AC-9(4)", {"logon_notification": {"timestamp_displayed": true, "location_displayed": false}}, {"logon_notification": {"location_displayed": true}}],
	["AC-12", "AC-12(1)", {"session_termination": {"automatic_termination": true, "user_initiated": false}}, {"session_termination": {"user_initiated": true}}],
	["AC-17", "AC-17(1)", {"remote_access": {"authorized_only": true, "monitored_controlled": false}}, {"remote_access": {"monitored_controlled": true}}],
	["AC-17", "AC-17(2)", {"remote_access": {"authorized_only": true, "encrypted_connections": false}}, {"remote_access": {"encrypted_connections": true}}],
	["AC-18", "AC-18(1)", {"wireless_access": {"authorized_only": true, "encrypted_authentication": false}}, {"wireless_access": {"encrypted_authentication": true}}],
]

test_base_passes_without_enhancement if {
	every c in _cases {
		r := _ac(c[2])
		count(_finding(r, c[0])) == 0
		count(_finding(r, c[1])) == 1
	}
}

test_enhancement_passes_without_base if {
	every c in _cases {
		r := _ac(c[3])
		count(_finding(r, c[1])) == 0
		count(_finding(r, c[0])) == 1
	}
}

test_missing_evidence_fails_base_and_enhancement if {
	r := _ac({})
	every c in _cases {
		count(_finding(r, c[0])) == 1
		count(_finding(r, c[1])) == 1
	}
}

test_enhancements_are_evaluated_ids if {
	every c in _cases {
		c[1] in ac.evaluated_controls
	}
	count(ac.evaluated_controls) == 34
}

test_facts_outside_the_statement_not_required if {
	r := _ac({
		"separation_duties": {"critical_functions_divided": true, "documented_assignments": true, "monitored_compliance": false},
		"session_control": {"limits_configured": true, "per_account_limits": true, "per_device_limits": false},
		"session_termination": {"automatic_termination": true, "administrative_termination": false},
		"wireless_access": {"authorized_only": true, "monitored_usage": false},
		"information_sharing": {"user_discretion_limited": true, "automated_guidance": true, "security_attributes_preserved": false},
	})
	every id in ["AC-5", "AC-10", "AC-12", "AC-18", "AC-21"] {
		count(_finding(r, id)) == 0
	}
}

test_ac5_still_fails_on_its_own_facts if {
	count(_finding(_ac({"separation_duties": {"critical_functions_divided": true, "documented_assignments": false}}), "AC-5")) == 1
}
