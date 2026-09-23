# Tests for the BSI C5:2020 master orchestrator.
package bsi_c5.main_test

import rego.v1

import data.bsi_c5.main

_domains := {
	"organisation_information_security": data.bsi_c5.organisation_information_security.requirements,
	"security_policies": data.bsi_c5.security_policies.requirements,
	"personnel": data.bsi_c5.personnel.requirements,
	"asset_management": data.bsi_c5.asset_management.requirements,
	"physical_security": data.bsi_c5.physical_security.requirements,
	"operations": data.bsi_c5.operations.requirements,
	"identity_access_management": data.bsi_c5.identity_access_management.requirements,
	"cryptography": data.bsi_c5.cryptography.requirements,
	"communication_security": data.bsi_c5.communication_security.requirements,
	"portability_interoperability": data.bsi_c5.portability_interoperability.requirements,
	"system_development": data.bsi_c5.system_development.requirements,
	"supplier_control": data.bsi_c5.supplier_control.requirements,
	"incident_management": data.bsi_c5.incident_management.requirements,
	"business_continuity": data.bsi_c5.business_continuity.requirements,
	"compliance_audit": data.bsi_c5.compliance_audit.requirements,
	"government_inquiries": data.bsi_c5.government_inquiries.requirements,
	"product_security": data.bsi_c5.product_security.requirements,
}

# Fully-attested input built from every domain's own requirement set.
all_true := {"bsi_c5": {domain: {"requirements": {id: true | some id, _ in reqs}} |
	some domain, reqs in _domains
}}

test_empty_input_all_gaps if {
	r := main.compliance_report with input as {}
	r.domains_evaluated == 17
	count(r.criteria_domains) == 17
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
	expected := sum([count(reqs) | some reqs in _domains])
	malformed := {"bsi_c5": {"cryptography": {"requirements": "all attested"}}}
	r := main.compliance_report with input as malformed
	r.total_requirements == expected
	r.requirements_met == 0
	r.violation_count == expected
	r.compliant == false
}

# A truthy-but-not-true attestation ("yes", 1) is unmet, and the two counters
# (requirements_met from the orchestrator, violation_count from the modules)
# stay in agreement — pins the == true contract on both paths.
test_truthy_attestation_not_met if {
	truthy := json.patch(all_true, [{"op": "replace", "path": "/bsi_c5/cryptography/requirements/CRY-3", "value": "yes"}])
	r := main.compliance_report with input as truthy
	r.requirements_met == r.total_requirements - 1
	r.violation_count == 1
	r.compliant == false
}

test_single_domain_gap_propagates if {
	# fully attested, then drop one Identity and Access Management requirement
	dropped := json.patch(all_true, [{"op": "remove", "path": "/bsi_c5/identity_access_management/requirements/IDM-5"}])
	r := main.compliance_report with input as dropped
	r.violation_count == 1
	r.requirements_met == r.total_requirements - 1
	r.compliant == false
	r.criteria_domains["Identity and Access Management"].compliant == false
}
