# Tests for dfars_7012.main — DFARS 252.204-7012 (MAY 2024).
package dfars_7012.main_test

import rego.v1

import data.dfars_7012.main

_all := {id: true | some id, _ in main.obligations}

_flags_on := {k: true | some k, _ in main._flags}

_flags_off := {k: false | some k, _ in main._flags}

_ungated := {id: true | some id, c in main.obligations; count(c.gates) == 0}

test_table_counts if {
	count(main.obligations) == 25
	count(_ungated) == 12
	count(main._flags) == 7
}

test_every_gate_is_a_declared_flag if {
	count({g | some _, c in main.obligations; some g in c.gates; not main._flags[g]}) == 0
}

test_every_obligation_has_a_known_section if {
	count({id | some id, c in main.obligations; not main.sections[c.s]}) == 0
}

test_empty_input_fails_closed if {
	r := main.compliance_report with input as {}
	r.compliant == false
	r.flags.uses_external_cloud_service_provider == "undeclared"

	# FAIL-CLOSED (no facts) + 7 undeclared flags + 12 ungated obligations
	r.violation_count == 20
	some v in r.violations
	contains(v, "undeclared")
	some f in r.violations
	contains(f, "FAIL-CLOSED")
}

test_all_true_is_compliant if {
	inp := {"dfars_7012": object.union(_flags_on, {"obligations": _all})}
	main.compliant with input as inp
	r := main.compliance_report with input as inp
	r.obligations_evaluated == 25
	r.obligations_attested == 25
	r.violation_count == 0
}

test_flags_off_needs_only_ungated if {
	inp := {"dfars_7012": object.union(_flags_off, {"obligations": _ungated})}
	main.compliant with input as inp
	r := main.compliance_report with input as inp
	r.obligations_evaluated == 12
	r.sections.m.obligations == 0
}

test_one_false_is_named if {
	inp := {"dfars_7012": object.union(_flags_on, {"obligations": object.union(_all, {"c.1.ii": false})})}
	not main.compliant with input as inp
	r := main.compliance_report with input as inp
	r.violation_count == 1
	r.sections.c.gaps == ["c.1.ii"]
	some v in r.violations
	startswith(v, "DFARS 252.204-7012(c)(1)(ii)")
	contains(v, "72 hours")
}

test_unknown_id_is_a_violation if {
	inp := {"dfars_7012": object.union(_flags_on, {"obligations": object.union(_all, {"i.1": true})})}
	not main.compliant with input as inp
	some v in main.violations with input as inp
	contains(v, "unknown id i.1")
}

test_malformed_container_is_a_violation if {
	inp := {"dfars_7012": object.union(_flags_off, {"obligations": ["c.1.ii"]})}
	some v in main.violations with input as inp
	contains(v, "must be an object")
}

test_external_csp_flag_opens_both_d_rows if {
	inp := {"dfars_7012": object.union(_flags_off, {"uses_external_cloud_service_provider": true, "obligations": _ungated})}
	r := main.compliance_report with input as inp
	r.sections.b.gaps == ["b.2.ii.D-c-g", "b.2.ii.D-fedramp"]
}

test_pre_2017_notice_needs_both_flags if {
	inp := {"dfars_7012": object.union(_flags_off, {"contract_awarded_before_2017_10_01": true, "obligations": _ungated})}
	r := main.compliance_report with input as inp
	r.sections.b.gaps == []
	inp2 := {"dfars_7012": object.union(_flags_off, {"contract_awarded_before_2017_10_01": true, "has_systems_not_operated_for_government": true, "obligations": _ungated})}
	r2 := main.compliance_report with input as inp2
	r2.sections.b.gaps == ["b.2.i", "b.2.ii.A", "b.2.ii.A-notice"]
}

test_dated_windows_carried if {
	r := main.compliance_report with input as {}
	r.dated_windows.rapid_report_hours_from_discovery == 72
	r.dated_windows.media_preservation_days_from_report == 90
	r.out_of_scope["(i)"]
}

test_string_true_is_not_attested if {
	inp := {"dfars_7012": object.union(_flags_on, {"obligations": object.union(_all, {"e": "true"})})}
	not main.compliant with input as inp
}
