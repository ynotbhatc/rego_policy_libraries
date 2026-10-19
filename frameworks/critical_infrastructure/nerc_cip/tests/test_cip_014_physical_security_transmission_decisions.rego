package nerc_cip.cip_014_test

import rego.v1

import data.nerc_cip.cip_014 as c

# decisions 2026-10-19: the 60-day post-change assessment gates compliant and yields a violation.

test_unassessed_topology_change_violation if {
	i := {"transmission_topology_changes": [{"assessment_triggered": false}]}
	not c.assessment_updated_after_changes with input as i
	count([v | some v in c.violations with input as i; contains(v.description, "60 days")]) == 1
	not c.compliant with input as i
}

test_assessed_topology_change_passes if {
	i := {"transmission_topology_changes": [{"assessment_triggered": true, "change_date": 0, "assessment_completion_date": 86400000000000}]}
	c.assessment_updated_after_changes with input as i
}

test_undeclared_topology_changes_violation if {
	count([v | some v in c.violations with input as {}; contains(v.description, "60 days")]) == 1
}
