# Tests for the Zero Trust (CISA ZTMM v2.0) master orchestrator.
package zero_trust.main_test

import rego.v1

import data.zero_trust.main

# Fully-attested input built from every pillar's own criteria set.
all_true := {"zero_trust": {
	"identity": {"criteria": {id: true | some id, _ in data.zero_trust.identity.criteria}},
	"devices": {"criteria": {id: true | some id, _ in data.zero_trust.devices.criteria}},
	"networks": {"criteria": {id: true | some id, _ in data.zero_trust.networks.criteria}},
	"applications_workloads": {"criteria": {id: true | some id, _ in data.zero_trust.applications_workloads.criteria}},
	"data": {"criteria": {id: true | some id, _ in data.zero_trust.data.criteria}},
	"visibility_analytics": {"criteria": {id: true | some id, _ in data.zero_trust.visibility_analytics.criteria}},
	"automation_orchestration": {"criteria": {id: true | some id, _ in data.zero_trust.automation_orchestration.criteria}},
	"governance": {"criteria": {id: true | some id, _ in data.zero_trust.governance.criteria}},
}}

test_empty_input_all_gaps if {
	r := main.compliance_report with input as {}
	is_object(r)
	r.pillars_evaluated == 8
	count(r.pillars) == 8
	r.total_criteria > 0
	r.violation_count == r.total_criteria # every criterion is a gap on empty input
	r.criteria_met == 0
	r.compliant == false
}

test_fully_attested_is_compliant if {
	r := main.compliance_report with input as all_true
	r.violation_count == 0
	r.compliant == true
	r.criteria_met == r.total_criteria
}

test_maturity_stage_coverage_present if {
	r := main.compliance_report with input as {}

	# at least the initial/advanced/optimal stages the pillars use
	count(r.maturity_by_stage) > 0

	# on empty input every stage is fully unmet
	every _, s in r.maturity_by_stage {
		s.met == 0
		s.total > 0
	}
}

test_single_pillar_gap_propagates if {
	# fully attested, then drop one Identity criterion -> exactly one aggregate gap
	dropped := json.patch(all_true, [{"op": "remove", "path": "/zero_trust/identity/criteria/ID-1"}])
	r := main.compliance_report with input as dropped
	r.violation_count == 1
	r.compliant == false
	r.pillars.Identity.compliant == false
}
