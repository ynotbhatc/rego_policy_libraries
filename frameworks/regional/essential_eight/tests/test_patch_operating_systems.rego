package essential_eight.patch_operating_systems_test

import rego.v1

import data.essential_eight.patch_operating_systems

# Build an input where every requirement is attested true.
all_attested := {"essential_eight": {"patch_operating_systems": {"requirements": all_true}}}

all_true[id] := true if some id, _ in patch_operating_systems.requirements

# ---- empty input: every requirement fires, not compliant ----
test_empty_input_all_violations if {
	count(patch_operating_systems.violation) == count(patch_operating_systems.requirements) with input as {}
	not patch_operating_systems.strategy_compliant with input as {}
}

# ---- all attested: no violations, compliant ----
test_all_attested_compliant if {
	count(patch_operating_systems.violation) == 0 with input as all_attested
	patch_operating_systems.strategy_compliant with input as all_attested
}

# ---- single flip: exactly one violation naming its id ----
test_single_flip_one_violation if {
	flipped := object.remove(all_true, {"POS-ML1-5"})
	subject := {"essential_eight": {"patch_operating_systems": {"requirements": flipped}}}
	count(patch_operating_systems.violation) == 1 with input as subject
	some msg in patch_operating_systems.violation with input as subject
	contains(msg, "POS-ML1-5") with input as subject
	not patch_operating_systems.strategy_compliant with input as subject
}

# ---- report populated even on empty input ----
test_report_populated_on_empty if {
	report := patch_operating_systems.compliance_report with input as {}
	report.strategy == "Patch Operating Systems"
	report.requirements_evaluated == count(patch_operating_systems.requirements)
	report.violation_count == count(patch_operating_systems.requirements)
	report.compliant == false
}
