# Tests for hkma_trm.main — HKMA TM-G-1 + TM-C-1.
package hkma_trm.main_test

import rego.v1

import data.hkma_trm.main

_all := {id: true | some id, _ in main.controls}

_ungated := {id: true | some id, c in main.controls; c.gate == ""}

_flags_off := {"uses_wireless_lan": false, "outsources_technology_services": false, "relies_on_overseas_offices_for_it": false}

test_table_counts if {
	count(main.controls) == 67
	count({id | some id, c in main.controls; c.s == "C"}) == 5
	{id | some id, c in main.controls; c.gate != ""} == {"2.6.1", "6.3.1", "6.3.2", "7.1.1"}
}

test_every_gate_is_a_declared_flag if {
	count({id | some id, c in main.controls; c.gate != ""; not main._flags[c.gate]}) == 0
}

test_empty_input_fails_closed if {
	r := main.compliance_report with input as {}
	r.compliant == false
	r.flags.uses_wireless_lan == "undeclared"

	# 3 flags + 63 ungated controls
	r.violation_count == 66
}

test_ai_with_flags_off_needs_63 if {
	inp := {"hkma_trm": object.union(_flags_off, {"controls": _ungated})}
	main.compliant with input as inp
	r := main.compliance_report with input as inp
	r.controls_evaluated == 63
}

test_outsourcing_flag_opens_7_1_1 if {
	inp := {"hkma_trm": object.union(_flags_off, {"outsources_technology_services": true, "controls": _ungated})}
	r := main.compliance_report with input as inp
	r.violation_count == 1
	r.sections["7"].gaps == ["7.1.1"]
}

test_wlan_flag_opens_two if {
	inp := {"hkma_trm": object.union(_flags_off, {"uses_wireless_lan": true, "controls": _ungated})}
	r := main.compliance_report with input as inp
	r.sections["6"].gaps == ["6.3.1", "6.3.2"]
}

test_full_attestation_with_all_flags_is_compliant if {
	inp := {"hkma_trm": {"uses_wireless_lan": true, "outsources_technology_services": true, "relies_on_overseas_offices_for_it": true, "controls": _all}}
	main.compliant with input as inp
}

test_string_true_rejected if {
	inp := {"hkma_trm": object.union(_flags_off, {"controls": object.union(_ungated, {"C.2.4": "true"})})}
	v := main.violations with input as inp
	count(v) == 1
	some msg in v
	contains(msg, "C.2.4")
}

test_unknown_id_flagged if {
	inp := {"hkma_trm": object.union(_flags_off, {"controls": object.union(_ungated, {"8.1.1": true})})}
	v := main.violations with input as inp
	count(v) == 1
	some msg in v
	contains(msg, "unknown paragraph 8.1.1")
}
