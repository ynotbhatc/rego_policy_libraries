package nerc_cip.cip_011_test

import rego.v1

import data.nerc_cip.cip_011 as c

# decisions 2026-10-19: R2 redeployment clearing and R6 third-party agreements feed
# compliant and violations; an absent list fails closed, an explicit false is N/A.

test_redeployment_not_cleared_violation if {
	i := {"system_redeployments": [{"bcsi_cleared": false, "clearing_method_documented": true}]}
	not c.redeployment_bcsi_cleared with input as i
	count([v | some v in c.violations with input as i; contains(v.description, "redeployment")]) == 1
	not c.compliant with input as i
}

test_redeployment_cleared_passes if {
	i := {"system_redeployments": [{"bcsi_cleared": true, "clearing_method_documented": true}]}
	c.redeployment_bcsi_cleared with input as i
}

test_redeployment_explicit_false_not_applicable if {
	c.redeployment_bcsi_cleared with input as {"system_redeployments": false}
}

test_redeployment_undeclared_fails_closed if {
	not c.redeployment_bcsi_cleared with input as {}
}

test_third_party_without_agreement_violation if {
	i := {"bcsi_third_party_sharing": [{"nda_or_agreement_in_place": false}]}
	not c.third_party_bcsi_agreements with input as i
	count([v | some v in c.violations with input as i; contains(v.description, "third party")]) == 1
	not c.compliant with input as i
}

test_third_party_explicit_false_not_applicable if {
	c.third_party_bcsi_agreements with input as {"bcsi_third_party_sharing": false}
}

test_third_party_undeclared_fails_closed if {
	not c.third_party_bcsi_agreements with input as {}
}

test_report_includes_new_requirements if {
	r := c.report with input as {}
	r.requirements.R2_redeployment_bcsi_cleared == false
	r.requirements.R_third_party_agreements == false
}
