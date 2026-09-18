# Tests for the CIS Controls v8.1 master orchestrator.
package cis_controls_v8.main_test

import rego.v1

import data.cis_controls_v8.main

# Build a fully-attested input from the framework's own safeguard set.
all_true := {"cis_controls": {"safeguards": {id: true | some id, _ in main.all_safeguards}}}

test_empty_input_all_safeguards_gap if {
	r := main.compliance_report with input as {}
	is_object(r)
	r.controls_evaluated == 18
	r.total_safeguards == 153
	r.violation_count == 153
	r.compliant == false

	# every IG is fully gapped on empty input
	r.implementation_groups.ig1.gaps == r.implementation_groups.ig1.safeguards
	r.implementation_groups.ig3.gaps == r.implementation_groups.ig3.safeguards
}

test_fully_attested_is_compliant if {
	r := main.compliance_report with input as all_true
	r.violation_count == 0
	r.compliant == true
	r.implementation_groups.ig1.compliant == true
	r.implementation_groups.ig2.compliant == true
	r.implementation_groups.ig3.compliant == true
}

test_implementation_groups_are_cumulative if {
	r := main.compliance_report with input as {}
	ig1 := r.implementation_groups.ig1.safeguards
	ig2 := r.implementation_groups.ig2.safeguards
	ig3 := r.implementation_groups.ig3.safeguards
	ig1 < ig2
	ig2 < ig3
	ig3 == r.total_safeguards # IG3 = every safeguard
}

test_single_gap_counts_one_violation if {
	# attest everything, then drop one safeguard -> exactly one violation
	dropped := {"cis_controls": {"safeguards": object.remove(all_true.cis_controls.safeguards, {"1.1"})}}
	r := main.compliance_report with input as dropped
	r.violation_count == 1
	r.compliant == false
}
