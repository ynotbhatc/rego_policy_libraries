package digital_sovereignty.operational_sovereignty_test

import rego.v1

# Generated smoke test for frameworks/sovereignty/digital_sovereignty/operational_sovereignty.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_operational_sovereignty_loads_on_empty_input if {
	m := data.digital_sovereignty.operational_sovereignty with input as {}
	is_object(m)
}

test_operational_sovereignty_report_wellformed_on_empty_input if {
	report := data.digital_sovereignty.operational_sovereignty.report with input as {}
	is_object(report)
	count(report) > 0
}

test_operational_sovereignty_fail_closed_on_empty_input if {
	report := data.digital_sovereignty.operational_sovereignty.report with input as {}
	not object.get(report, "compliant", false) == true
}

test_operational_sovereignty_violations_on_empty_input if {
	v := data.digital_sovereignty.operational_sovereignty.violations with input as {}
	count(v) > 0
}

# Semantic review 2026-11-13: report stays defined when controls fail; every gate has a finding.
test_report_defined_when_personnel_unvetted if {
	inp := {"approved_jurisdictions": ["DE"], "personnel": [{"person_id": "p1", "role": "dba", "access_level": "admin", "vetting_current": false, "location_country": "DE"}]}
	r := data.digital_sovereignty.operational_sovereignty.report with input as inp
	r.controls["OS-001_privileged_personnel_vetted"] == false
	some x in r.violations
	x.control == "OS-001"
}

test_unlogged_vendor_session_raises_finding if {
	inp := {"approved_jurisdictions": ["DE"], "vendor_access": [{"vendor_id": "v1", "vendor_name": "V", "data_classification_accessed": "public", "sessions_logged": false}]}
	not data.digital_sovereignty.operational_sovereignty.compliant with input as inp
	v := data.digital_sovereignty.operational_sovereignty.violations with input as inp
	some x in v
	x.control == "OS-011"
}

test_missing_person_id_does_not_drop_finding if {
	inp := {"approved_jurisdictions": ["DE"], "personnel": [{"access_level": "admin", "vetting_current": false, "location_country": "DE"}]}
	v := data.digital_sovereignty.operational_sovereignty.violations with input as inp
	some x in v
	x.control == "OS-001"
}

test_every_failing_gate_has_a_violation_rule if {
	inp := {"approved_jurisdictions": ["DE"], "support_contracts": [{"vendor_id": "v1", "support_personnel_location": "US", "right_to_refuse_foreign_access": true, "foreign_government_disclosure_clause": false}]}
	v := data.digital_sovereignty.operational_sovereignty.violations with input as inp
	some a in v
	a.control == "OS-014"
	some b in v
	b.control == "OS-015"
	some c in v
	c.control == "OS-016"
}
