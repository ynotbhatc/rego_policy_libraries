package essential_eight.restrict_admin_privileges_test

import rego.v1

import data.essential_eight.restrict_admin_privileges

# Build an input where every requirement is attested true.
all_attested := {"essential_eight": {"restrict_admin_privileges": {"requirements": all_true}}}

all_true[id] := true if some id, _ in restrict_admin_privileges.requirements

# ---- empty input: every requirement fires, not compliant ----
test_empty_input_all_violations if {
	count(restrict_admin_privileges.violation) == count(restrict_admin_privileges.requirements) with input as {}
	not restrict_admin_privileges.strategy_compliant with input as {}
}

# ---- all attested: no violations, compliant ----
test_all_attested_compliant if {
	count(restrict_admin_privileges.violation) == 0 with input as all_attested
	restrict_admin_privileges.strategy_compliant with input as all_attested
}

# ---- single flip: exactly one violation naming its id ----
test_single_flip_one_violation if {
	flipped := object.remove(all_true, {"RAP-ML1-1"})
	subject := {"essential_eight": {"restrict_admin_privileges": {"requirements": flipped}}}
	count(restrict_admin_privileges.violation) == 1 with input as subject
	some msg in restrict_admin_privileges.violation with input as subject
	contains(msg, "RAP-ML1-1") with input as subject
	not restrict_admin_privileges.strategy_compliant with input as subject
}

# ---- report populated even on empty input ----
test_report_populated_on_empty if {
	report := restrict_admin_privileges.compliance_report with input as {}
	report.strategy == "Restrict Administrative Privileges"
	report.requirements_evaluated == count(restrict_admin_privileges.requirements)
	report.violation_count == count(restrict_admin_privileges.requirements)
	report.compliant == false
}
