package nist.sp800_53.access_control_test

import rego.v1

# Generated smoke test for frameworks/federal/nist/sp_800_53/access_control/ac_controls.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_ac_controls_loads_on_empty_input if {
	m := data.nist.sp800_53.access_control with input as {}
	is_object(m)
}

test_ac_controls_report_wellformed_on_empty_input if {
	report := data.nist.sp800_53.access_control.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_ac_controls_fail_closed_on_empty_input if {
	report := data.nist.sp800_53.access_control.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

# semantic review 2026-11-13: AC-15/16/21/23/24/25 must reach the violation set.
test_review_unattested_controls_raise_violations if {
	r := data.nist.sp800_53.access_control.compliance_report with input as {}
	every id in ["AC-15", "AC-16", "AC-21", "AC-23", "AC-24", "AC-25"] {
		some v in r.violations
		startswith(v, concat("", ["NIST ", id, ":"]))
	}
}

test_review_reference_monitor_failure_alone_is_noncompliant if {
	good := {
		"policy": {"documented": true, "disseminated": true, "reviewed_updated": true},
		"procedures": {"implementation_documented": true},
		"automated_marking": {"security_labels": true, "classification_marking": true, "handling_caveats": true},
		"security_attributes": {"attribute_binding": true, "attribute_association": true, "transmission_preservation": true},
		"information_sharing": {"user_discretion_limited": true, "automated_guidance": true, "security_attributes_preserved": true},
		"data_mining": {"detection_techniques": true, "warning_notifications": true, "response_procedures": true},
		"decisions": {"security_attributes_used": true, "consistent_enforcement": true, "documented_criteria": true},
		"reference_monitor": {"tamper_proof": false, "always_invoked": true, "small_verifiable": true},
	}
	r := data.nist.sp800_53.access_control.compliance_report with input as {"ac_controls": good}
	some v in r.violations
	startswith(v, "NIST AC-25:")
}
