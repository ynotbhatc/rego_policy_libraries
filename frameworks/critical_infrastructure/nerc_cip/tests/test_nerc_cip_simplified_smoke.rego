package nerc.cip.simplified_test

import rego.v1

# Generated smoke test for frameworks/critical_infrastructure/nerc_cip/nerc_cip_simplified.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_nerc_cip_simplified_loads_on_empty_input if {
	m := data.nerc.cip.simplified with input as {}
	is_object(m)
}

# Semantic review 2026-11-13: absence of perimeter/access/personnel records is a finding.
_good_base := {
	"bes_cyber_systems": [{"system_id": "s1", "system_name": "EMS", "impact_categorization": "high"}],
	"categorization_documentation": {"criteria_defined": true, "methodology_documented": true, "rationale_provided": true},
	"cybersecurity_organization": {
		"senior_manager": {"designated": true, "authority_documented": true, "responsibilities_defined": true},
		"policies": {"documented": true, "approved": true},
	},
}

_good_full := object.union(_good_base, {
	"electronic_security_perimeters": {"s1": {"documented": true}},
	"physical_security_perimeters": {"s1": {"boundary_defined": true}},
	"electronic_access_points": [{"access_control": {"enabled": true}, "monitoring": {"enabled": true}}],
	"physical_access_controls": [{"authentication_required": true, "monitoring_enabled": true}],
	"personnel": [{"access_level": "authorized_electronic_access", "risk_assessment": {"completed": true}, "cybersecurity_training": {"completed": true}}],
})

test_high_impact_without_records_not_compliant if {
	not data.nerc.cip.simplified.nerc_cip_compliant with input as _good_base
	data.nerc.cip.simplified.nerc_cip_compliance_score < 100 with input as _good_base
}

test_high_impact_without_esp_entry_not_compliant if {
	inp := object.remove(_good_full, ["electronic_security_perimeters"])
	not data.nerc.cip.simplified.electronic_security_perimeter_compliant with input as inp
}

test_high_impact_without_psp_entry_not_compliant if {
	inp := object.remove(_good_full, ["physical_security_perimeters"])
	not data.nerc.cip.simplified.physical_security_compliant with input as inp
}

test_high_impact_without_personnel_not_compliant if {
	inp := object.remove(_good_full, ["personnel"])
	not data.nerc.cip.simplified.personnel_risk_assessment_compliant with input as inp
}

test_high_impact_full_evidence_compliant if {
	data.nerc.cip.simplified.nerc_cip_compliant with input as _good_full
}
