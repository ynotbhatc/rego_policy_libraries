package cra.authorised_representative_test

import rego.v1

# Validation fixes 2026-10-17: an appointed representative always needs a written mandate.

m := data.cra.authorised_representative

# decisions 2026-10-19: (name kept for test discovery) undeclared applicability is no longer a pass.
test_cra_art18_undeclared_applicability_is_documented_pass if {
	not m.compliant with input as {}
	"CRA Art.18: applicability not determined — manufacturer_outside_eu not declared" in m.violation with input as {}
}

test_cra_art18_applicability_violation_only_when_undeclared if {
	not "CRA Art.18: applicability not determined — manufacturer_outside_eu not declared" in m.violation with input as {"authorised_representative": {"manufacturer_outside_eu": false}}
}

test_cra_art18_declared_not_applicable_is_compliant if {
	m.compliant with input as {"authorised_representative": {"manufacturer_outside_eu": false}}
}

test_cra_art18_appointed_without_written_mandate_is_violation_even_if_required_absent if {
	i := {"authorised_representative": {"manufacturer_outside_eu": true, "appointed": true}}
	"CRA Art.18(1): Written mandate from the manufacturer to the authorised representative not in place" in m.violation with input as i
}

test_cra_art18_non_eu_not_appointed_is_violation if {
	i := {"authorised_representative": {"manufacturer_outside_eu": true}}
	not m.compliant with input as i
}

test_cra_art18_fully_compliant_non_eu if {
	i := {"authorised_representative": {
		"manufacturer_outside_eu": true, "appointed": true, "written_mandate_in_place": true,
		"mandate_enables_required_tasks": true, "contact_in_user_info": true,
		"tasks": {"keeps_declaration_of_conformity": true, "keeps_technical_documentation": true, "retention_10_years": true, "provide_info_on_request": true, "cooperate_on_cyber_risk_action": true},
	}}
	m.compliant with input as i
}

test_cra_art18_report_populated_on_failure if {
	i := {"authorised_representative": {"manufacturer_outside_eu": true}}
	r := m.compliance_report with input as i
	r.compliant == false
	r.violation_count > 0
	r.controls_evaluated == 13
}
