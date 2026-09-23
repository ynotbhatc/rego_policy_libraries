# Tests for the UK Cyber Essentials master orchestrator.
package cyber_essentials.main_test

import rego.v1

import data.cyber_essentials.main

_themes := {
	"firewalls": data.cyber_essentials.firewalls.requirements,
	"secure_configuration": data.cyber_essentials.secure_configuration.requirements,
	"security_update_management": data.cyber_essentials.security_update_management.requirements,
	"user_access_control": data.cyber_essentials.user_access_control.requirements,
	"malware_protection": data.cyber_essentials.malware_protection.requirements,
}

# Fully-attested input built from every theme's own requirement set.
all_true := {"cyber_essentials": {theme: {"requirements": {id: true | some id, _ in reqs}} |
	some theme, reqs in _themes
}}

test_empty_input_all_gaps if {
	r := main.compliance_report with input as {}
	r.themes_evaluated == 5
	count(r.control_themes) == 5
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
	expected := sum([count(reqs) | some reqs in _themes])
	malformed := {"cyber_essentials": {"user_access_control": {"requirements": "all attested"}}}
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
	truthy := json.patch(all_true, [{"op": "replace", "path": "/cyber_essentials/firewalls/requirements/FW-1", "value": "yes"}])
	r := main.compliance_report with input as truthy
	r.requirements_met == r.total_requirements - 1
	r.violation_count == 1
	r.compliant == false
}

test_single_theme_gap_propagates if {
	# fully attested, then drop one Firewalls requirement
	dropped := json.patch(all_true, [{"op": "remove", "path": "/cyber_essentials/firewalls/requirements/FW-1"}])
	r := main.compliance_report with input as dropped
	r.violation_count == 1
	r.requirements_met == r.total_requirements - 1
	r.compliant == false
	r.control_themes.Firewalls.compliant == false
}
