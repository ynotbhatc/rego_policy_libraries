package cis_m365_v7.control_findings_test

import rego.v1

# Hand-written (issue #309): control_results rows carry `findings`, the messages that cite the row's
# recommendation id ("CIS 2.1.8/2.1.9/2.1.10: " cites three), so a pass and a failure are both reported per
# control. Out-of-profile rows carry none: the violations do not depend on input.cis_profile, the rows do.
# Fixtures come from the hand-written contract test (cis_m365_v7.control_results_test).

FAILING := {"fail", "evidence_missing", "not_attested"}

_cites(m, id) if {
	ms := regex.find_all_string_submatch_n(`^CIS ([0-9]+(?:\.[0-9]+)+(?:/[0-9]+(?:\.[0-9]+)+)*): `, m, 1)
	id in split(ms[0][1], "/")
}

test_findings_empty_input_no_row_passes_and_every_row_has_messages if {
	r := data.cis_m365_v7.main.compliance_report with input as {}
	count([c | some c in r.control_results; c.status == "pass"]) == 0
	every c in r.control_results {
		count(c.findings) > 0
		every m in c.findings { _cites(m, c.id) }
	}
	sum([n | some n in r.control_result_counts]) == count(r.control_results)
}

test_findings_out_of_profile_rows_carry_none if {
	r := data.cis_m365_v7.main.compliance_report with input as {"cis_profile": {"licence": "E3", "level": 1}}
	na := [c | some c in r.control_results; c.status == "not_applicable"]
	count(na) == 60
	every c in na { c.findings == [] }
	every c in r.control_results {
		has_findings := count(c.findings) > 0
		not_a_pass := c.status in FAILING
		has_findings == not_a_pass
	}
}

test_findings_compliant_fixture_every_row_passes_with_no_findings if {
	r := data.cis_m365_v7.main.compliance_report with input as data.cis_m365_v7.control_results_test.fixture_compliant
	every c in r.control_results {
		c.status == "pass"
		c.findings == []
	}
}

test_findings_one_failing_fact_flips_exactly_its_row if {
	fx := object.union(data.cis_m365_v7.control_results_test.fixture_compliant, {"teams": {"client_configuration": {"AllowEmailIntoChannel": true}}})
	r := data.cis_m365_v7.main.compliance_report with input as fx
	[c.id | some c in r.control_results; c.status != "pass"] == ["8.1.2"]
	some c in r.control_results
	c.id == "8.1.2"
	c.status == "fail"
	count(c.findings) == 1
	startswith(c.findings[0], "CIS 8.1.2: ")
	r.control_result_counts.pass == 159
	r.control_result_counts.fail == 1
	sum([n | some n in r.control_result_counts]) == count(r.control_results)
}
