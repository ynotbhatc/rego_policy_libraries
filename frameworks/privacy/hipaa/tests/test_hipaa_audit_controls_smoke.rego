package hipaa.audit_controls_test

import rego.v1

import data.hipaa.test_fixtures as fx

# Generated smoke test for frameworks/privacy/hipaa/hipaa_audit_controls.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_hipaa_audit_controls_loads_on_empty_input if {
	m := data.hipaa.audit_controls with input as {}
	is_object(m)
}

test_hipaa_audit_controls_report_wellformed_on_empty_input if {
	report := data.hipaa.audit_controls.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_hipaa_audit_controls_fail_closed_on_empty_input if {
	report := data.hipaa.audit_controls.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_hipaa_audit_controls_violations_on_empty_input if {
	v := data.hipaa.audit_controls.violations with input as {}
	count(v) > 0
}

test_semrev_baseline_clean if {
	count(data.hipaa.audit_controls.violations) == 0 with input as fx.full_input
}

test_semrev_audit_retention_400_days_fails if {
	inp := object.union(fx.full_input, {"audit_logging": {"retention_days": 400}})
	v := data.hipaa.audit_controls.violations with input as inp
	count(v) > 0
}

test_semrev_audit_retention_missing_fails if {
	inp := object.union(object.remove(fx.full_input, ["audit_logging"]), {"audit_logging": object.remove(fx.full_input.audit_logging, ["retention_days"])})
	v := data.hipaa.audit_controls.violations with input as inp
	count(v) > 0
}

test_semrev_audit_review_frequency_missing_fails if {
	inp := object.union(object.remove(fx.full_input, ["monitoring"]), {"monitoring": object.remove(fx.full_input.monitoring, ["audit_review_frequency_days"])})
	v := data.hipaa.audit_controls.violations with input as inp
	count(v) > 0
}
