package zero_trust.networks_test

import rego.v1

import data.zero_trust.networks

# Every criterion id in the module, used to build a fully-attested input.
all_ids := {id | some id, _ in networks.criteria}

# Helper: an input that attests the given set of ids as true.
attest(ids) := {"zero_trust": {"networks": {"criteria": {id: true | some id in ids}}}}

# Empty input -> every criterion fires, pillar is not compliant.
test_empty_input_all_fire if {
	report := networks.compliance_report with input as {"zero_trust": {"networks": {"criteria": {}}}}
	report.violation_count == count(networks.criteria)
	report.compliant == false
	not networks.pillar_compliant with input as {"zero_trust": {"networks": {"criteria": {}}}}
}

# Fully absent input (no zero_trust key at all) -> all fire.
test_missing_input_all_fire if {
	count(networks.violation) == count(networks.criteria) with input as {}
}

# All criteria attested -> no violations, pillar compliant.
test_all_attested_compliant if {
	inp := attest(all_ids)
	count(networks.violation) == 0 with input as inp
	networks.pillar_compliant with input as inp
}

# Flip a single criterion off -> exactly one violation, naming that id.
test_single_flip_one_violation if {
	missing := "NET-7"
	inp := attest(all_ids - {missing})
	viols := networks.violation with input as inp
	count(viols) == 1
	some msg in viols
	contains(msg, missing)
}

# Report is populated on empty input.
test_report_populated_on_empty if {
	report := networks.compliance_report with input as {"zero_trust": {"networks": {"criteria": {}}}}
	report.pillar == "Networks"
	report.criteria_evaluated == count(networks.criteria)
	report.criteria_evaluated > 0
	report.violation_count == count(networks.criteria)
	report.compliant == false
}
