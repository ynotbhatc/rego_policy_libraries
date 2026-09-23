# Tests for the IRS Publication 1075 master orchestrator.
package irs_1075.main_test

import rego.v1

import data.irs_1075.main

_areas := {
	"recordkeeping": data.irs_1075.recordkeeping.requirements,
	"secure_storage": data.irs_1075.secure_storage.requirements,
	"restricting_access": data.irs_1075.restricting_access.requirements,
	"other_safeguards": data.irs_1075.other_safeguards.requirements,
	"reporting": data.irs_1075.reporting.requirements,
	"disposal": data.irs_1075.disposal.requirements,
	"computer_security": data.irs_1075.computer_security.requirements,
	"incident_response": data.irs_1075.incident_response.requirements,
}

# Fully-attested input built from every area's own requirement set.
all_true := {"irs_1075": {area: {"requirements": {id: true | some id, _ in reqs}} |
	some area, reqs in _areas
}}

test_empty_input_all_gaps if {
	r := main.compliance_report with input as {}
	r.areas_evaluated == 8
	count(r.safeguard_areas) == 8
	r.total_requirements > 0
	r.violation_count == r.total_requirements
	r.requirements_met == 0
	r.compliant == false
}

test_fully_attested_is_compliant if {
	r := main.compliance_report with input as all_true
	r.violation_count == 0
	r.compliant == true
	r.requirements_met == r.total_requirements
}

# A non-object requirements payload must not shrink total_requirements —
# every id stays counted (as unmet) and the report stays self-consistent.
test_malformed_attestation_keeps_totals if {
	expected := sum([count(reqs) | some _, reqs in _areas])
	malformed := {"irs_1075": {"computer_security": {"requirements": "all attested"}}}
	r := main.compliance_report with input as malformed
	r.total_requirements == expected
	r.requirements_met == 0
	r.violation_count == expected
	r.compliant == false
}

test_single_area_gap_propagates if {
	# fully attested, then drop one Secure Storage requirement
	dropped := json.patch(all_true, [{"op": "remove", "path": "/irs_1075/secure_storage/requirements/SS-1"}])
	r := main.compliance_report with input as dropped
	r.violation_count == 1
	r.requirements_met == r.total_requirements - 1
	r.compliant == false
	r.safeguard_areas["Secure Storage"].compliant == false
}
