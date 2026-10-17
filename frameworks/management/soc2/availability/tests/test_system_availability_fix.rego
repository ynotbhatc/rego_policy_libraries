package soc2.availability.system_availability_test

import rego.v1

# Validation fix pass 2026-10-17: a failing control must not make the score or findings undefined.

test_system_availability_score_defined_when_every_control_fails if {
	s := data.soc2.availability.system_availability.availability_score with input as {}
	s == 0
}

test_system_availability_findings_fully_populated_when_every_control_fails if {
	r := data.soc2.availability.system_availability.availability_findings with input as {}
	r.overall_score == 0
	leaves := [v | walk(r, [path, v]); not is_object(v); path != ["overall_score"]]
	count(leaves) > 1
	every v in leaves {
		v == false
	}
}

test_empty_workload_list_does_not_pass_workload_controls if {
	inp := {"openshift": {"workloads": [], "resource_management": {"quotas": {"enabled": true}, "limit_ranges": {"enabled": true}}}}
	not data.soc2.availability.system_availability.resource_limits_enforced with input as inp
	not data.soc2.availability.system_availability.health_checks_configured with input as inp
}

test_workload_controls_pass_with_compliant_workloads if {
	w := {"resources": {"requests": {"defined": true}, "limits": {"defined": true}}, "health_checks": {"readiness_probe": {"configured": true}, "liveness_probe": {"configured": true}}}
	inp := {"openshift": {"workloads": [w], "resource_management": {"quotas": {"enabled": true}, "limit_ranges": {"enabled": true}}}}
	data.soc2.availability.system_availability.resource_limits_enforced with input as inp
	data.soc2.availability.system_availability.health_checks_configured with input as inp
}
