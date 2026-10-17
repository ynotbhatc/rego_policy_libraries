package soc2.infrastructure.storage_test

import rego.v1

# Validation fix pass 2026-10-17: a failing control must not make the score or findings undefined.

test_storage_infrastructure_score_defined_when_every_control_fails if {
	s := data.soc2.infrastructure.storage.storage_infrastructure_score with input as {}
	s == 0
}

test_storage_infrastructure_findings_fully_populated_when_every_control_fails if {
	r := data.soc2.infrastructure.storage.storage_infrastructure_findings with input as {}
	r.overall_score == 0
	leaves := [v | walk(r, [path, v]); not is_object(v); path != ["overall_score"]]
	count(leaves) > 1
	every v in leaves {
		v == false
	}
}
