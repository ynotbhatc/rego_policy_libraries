package zero_trust.applications_workloads_test

import rego.v1

import data.zero_trust.applications_workloads

# All twelve criterion ids, used to build a fully-attested input.
all_ids := {id | some id, _ in applications_workloads.criteria}

# An input that attests every criterion as true.
all_attested := {"zero_trust": {"applications_workloads": {"criteria": {id: true | some id in all_ids}}}}

# Empty attestation -> every criterion fires as a violation, not compliant.
test_empty_input_all_fire if {
	count(applications_workloads.violation) == count(applications_workloads.criteria) with input as {"zero_trust": {"applications_workloads": {"criteria": {}}}}
}

test_empty_input_not_compliant if {
	not applications_workloads.pillar_compliant with input as {"zero_trust": {"applications_workloads": {"criteria": {}}}}
}

# Fully attested -> no violations, compliant.
test_all_attested_no_violations if {
	count(applications_workloads.violation) == 0 with input as all_attested
}

test_all_attested_compliant if {
	applications_workloads.pillar_compliant with input as all_attested
}

# Flip a single criterion off -> exactly one violation, and it names that id.
test_single_flip_one_violation if {
	partial := {"zero_trust": {"applications_workloads": {"criteria": {id: true | some id in all_ids; id != "APP-7"}}}}
	count(applications_workloads.violation) == 1 with input as partial
}

test_single_flip_names_id if {
	partial := {"zero_trust": {"applications_workloads": {"criteria": {id: true | some id in all_ids; id != "APP-7"}}}}
	some msg in applications_workloads.violation with input as partial
	contains(msg, "APP-7")
}

# Report is populated on empty input.
test_report_populated_on_empty if {
	report := applications_workloads.compliance_report with input as {"zero_trust": {"applications_workloads": {"criteria": {}}}}
	report.pillar == "Applications & Workloads"
	report.criteria_evaluated == count(applications_workloads.criteria)
	report.violation_count == count(applications_workloads.criteria)
	report.compliant == false
}
