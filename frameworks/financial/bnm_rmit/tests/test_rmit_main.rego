# Tests for bnm_rmit.main — BNM Risk Management in Technology (September 2026).
package bnm_rmit.main_test

import rego.v1

import data.bnm_rmit.main

_all := {id: true | some id, _ in main.standards}

_ungated := {id: true | some id, c in main.standards; c.gate == ""}

_flags_off := {"uses_cloud_services": false, "engages_third_party_service_providers": false, "designated_ncii_entity": false, "provides_digital_services": false}

test_table_counts if {
	count(main.standards) == 99
	count(_ungated) == 80
	count({id | some id, c in main.standards; c.s == "12"}) == 9
}

test_every_gate_is_a_declared_flag if {
	count({id | some id, c in main.standards; c.gate != ""; not main._flags[c.gate]}) == 0
}

test_every_standard_has_a_known_section_and_matching_prefix if {
	count({id | some id, c in main.standards; not main.sections[c.s]}) == 0
	count({id | some id, c in main.standards; not startswith(id, concat("", [c.s, "."]))}) == 0
}

test_empty_input_fails_closed if {
	r := main.compliance_report with input as {}
	r.compliant == false
	r.flags.uses_cloud_services == "undeclared"

	# 4 flags + 80 ungated standards
	r.violation_count == 84
}

test_institution_with_flags_off_needs_80 if {
	inp := {"bnm_rmit": object.union(_flags_off, {"standards": _ungated})}
	main.compliant with input as inp
	r := main.compliance_report with input as inp
	r.standards_evaluated == 80
	r.sections["12"].standards == 0
}

test_digital_services_flag_opens_section_12_and_10_31_10_35 if {
	inp := {"bnm_rmit": object.union(_flags_off, {"provides_digital_services": true, "standards": _ungated})}
	r := main.compliance_report with input as inp
	r.sections["12"].standards == 9
	r.sections["10"].gaps == ["10.31", "10.35"]
	r.violation_count == 11
}

test_third_party_flag_opens_five if {
	inp := {"bnm_rmit": object.union(_flags_off, {"engages_third_party_service_providers": true, "standards": _ungated})}
	r := main.compliance_report with input as inp
	r.sections["10"].gaps == ["10.12", "10.46", "10.47", "10.48", "10.49"]
}

test_cloud_and_ncii_flags if {
	inp := {"bnm_rmit": object.union(_flags_off, {"uses_cloud_services": true, "designated_ncii_entity": true, "standards": _ungated})}
	r := main.compliance_report with input as inp
	r.sections["10"].gaps == ["10.50", "10.52"]
	r.sections["11"].gaps == ["11.4"]
}

test_full_attestation_all_flags_is_compliant if {
	inp := {"bnm_rmit": {"uses_cloud_services": true, "engages_third_party_service_providers": true, "designated_ncii_entity": true, "provides_digital_services": true, "standards": _all}}
	main.compliant with input as inp
}

test_string_true_rejected_and_unknown_id_flagged if {
	inp := {"bnm_rmit": object.union(_flags_off, {"standards": object.union(_ungated, {"10.55": "true", "16.1": true})})}
	v := main.violations with input as inp
	count(v) == 2
	some m1 in v
	contains(m1, "RMiT S 10.55")
	some m2 in v
	contains(m2, "unknown paragraph 16.1")
}

test_report_carries_dates_and_availability_targets if {
	r := main.compliance_report with input as {"bnm_rmit": object.union(_flags_off, {"standards": _ungated})}
	r.dated_obligations["10.31_early_warning_and_stand_in_processing"] == "2027-09-30"
	r.availability_targets.max_tolerable_downtime_minutes_per_incident == 120
}
