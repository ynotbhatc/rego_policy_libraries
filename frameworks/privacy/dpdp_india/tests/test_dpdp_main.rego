# Tests for dpdp.main — India DPDP Act 2023 + Rules 2025.
package dpdp.main_test

import rego.v1

import data.dpdp.main

_all(t) := {k: true | some k, _ in t}

_base := {
	"processes_childrens_data": false,
	"is_significant_data_fiduciary": false,
	"uses_data_processors": false,
	"in_third_schedule_class": false,
	"lawful_basis": _all(main._lawful_basis),
	"notice": _all(main._notice),
	"consent": _all(main._consent),
	"obligations": _all(main._obligations),
	"security": _all(main._security),
	"breach": _all(main._breach),
	"retention": _all(main._retention),
	"rights": _all(main._rights),
	"transfers": _all(main._transfers),
	"government_requests": _all(main._government),
}

test_empty_input_fails_closed if {
	r := main.compliance_report with input as {}
	r.compliant == false
	r.scope.processes_childrens_data == "undeclared"

	# 4 flags + 2 + 8 + 8 + 6 + 6 + 4 + 2 + 5 + 2 + 2 = 49
	r.violation_count == 49
}

test_plain_fiduciary_with_full_evidence_is_compliant if {
	main.compliant with input as {"dpdp": _base}
}

test_undeclared_flag_is_a_violation if {
	inp := {"dpdp": object.remove(_base, {"uses_data_processors"})}
	v := main.violations with input as inp
	count(v) == 1
	some msg in v
	contains(msg, "uses_data_processors undeclared")
}

test_processor_flag_adds_contract_and_erasure_duties if {
	inp := {"dpdp": object.union(_base, {"uses_data_processors": true})}
	r := main.compliance_report with input as inp
	r.violation_count == 3
	some msg in r.violations
	contains(msg, "s.8(2)")
}

test_children_flag_adds_six_duties if {
	inp := {"dpdp": object.union(_base, {"processes_childrens_data": true})}
	r := main.compliance_report with input as inp
	r.violation_count == 6
	ok := object.union(inp.dpdp, {"children": _all(main._children_checks)})
	main.compliant with input as {"dpdp": ok}
}

test_sdf_flag_adds_six_duties if {
	inp := {"dpdp": object.union(_base, {"is_significant_data_fiduciary": true})}
	r := main.compliance_report with input as inp
	r.violation_count == 6
	some msg in r.violations
	contains(msg, "twelve months")
}

test_third_schedule_adds_erasure_duties if {
	inp := {"dpdp": object.union(_base, {"in_third_schedule_class": true})}
	r := main.compliance_report with input as inp
	r.violation_count == 2
	some msg in r.violations
	contains(msg, "forty-eight hours")
}

test_breach_72_hour_report_is_checked if {
	inp := {"dpdp": json.patch(_base, [{"op": "replace", "path": "/breach/board_detailed_report_within_72_hours", "value": false}])}
	v := main.violations with input as inp
	count(v) == 1
	some msg in v
	contains(msg, "seventy-two hours")
}

test_string_true_is_not_an_attestation if {
	inp := {"dpdp": json.patch(_base, [{"op": "replace", "path": "/security/encryption_obfuscation_masking_or_tokens", "value": "true"}])}
	v := main.violations with input as inp
	count(v) == 1
	some msg in v
	contains(msg, "Rule 6(1)(a)")
}

test_report_carries_commencement_dates if {
	r := main.compliance_report with input as {"dpdp": _base}
	r.rules_commencement.rules_3_5_to_16_22_23 == "2027-05-13"
	r.penalty_tiers_inr_crore.security_safeguards_s8_5 == 250
}
