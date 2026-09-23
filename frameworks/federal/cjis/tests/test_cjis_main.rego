# Tests for the FBI CJIS Security Policy master orchestrator.
package cjis.main_test

import rego.v1

import data.cjis.main

_areas := {
	"information_exchange": data.cjis.information_exchange.requirements,
	"security_awareness_training": data.cjis.security_awareness_training.requirements,
	"incident_response": data.cjis.incident_response.requirements,
	"auditing_accountability": data.cjis.auditing_accountability.requirements,
	"access_control": data.cjis.access_control.requirements,
	"identification_authentication": data.cjis.identification_authentication.requirements,
	"configuration_management": data.cjis.configuration_management.requirements,
	"media_protection": data.cjis.media_protection.requirements,
	"physical_protection": data.cjis.physical_protection.requirements,
	"systems_communications_protection": data.cjis.systems_communications_protection.requirements,
	"formal_audits": data.cjis.formal_audits.requirements,
	"personnel_security": data.cjis.personnel_security.requirements,
	"mobile_devices": data.cjis.mobile_devices.requirements,
}

# Fully-attested input built from every area's own requirement set.
all_true := {"cjis": {area: {"requirements": {id: true | some id, _ in reqs}} |
	some area, reqs in _areas
}}

test_empty_input_all_gaps if {
	r := main.compliance_report with input as {}
	r.policy_areas_evaluated == 13
	count(r.policy_areas) == 13
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

test_single_area_gap_propagates if {
	# fully attested, then drop one Access Control requirement
	dropped := json.patch(all_true, [{"op": "remove", "path": "/cjis/access_control/requirements/AC-1"}])
	r := main.compliance_report with input as dropped
	r.violation_count == 1
	r.compliant == false
	r.policy_areas["Access Control"].compliant == false
}

# A non-object requirements payload must not shrink total_requirements —
# every id stays counted (as unmet) and the report stays self-consistent.
test_malformed_attestation_keeps_totals if {
	expected := sum([count(reqs) | some reqs in _areas])
	malformed := {"cjis": {"access_control": {"requirements": "all attested"}}}
	r := main.compliance_report with input as malformed
	r.total_requirements == expected
	r.requirements_met == 0
	r.violation_count == expected
	r.compliant == false
}
