package cis_rhel9.control_findings_test

import rego.v1

# Hand-written (issue #309): control_results rows carry `findings`, the violation messages that cite the row's
# recommendation id, so a pass and a failure are both reported per control with the message that explains a
# non-pass. Fixtures come from the generated contract test (cis_rhel9.control_results_test).

FAILING := {"fail", "evidence_missing", "not_attested"}

test_findings_empty_input_every_non_pass_row_has_its_messages if {
	r := data.cis_rhel9.main.compliance_report with input as {"profile": "level2_server"}
	count([c | some c in r.control_results; c.status == "pass"]) == 0
	every c in r.control_results {
		c.in_scope
		count(c.findings) > 0
		every m in c.findings { startswith(m, concat("", [c.id, ": "])) }
	}
}

test_findings_out_of_profile_rows_carry_none if {
	r := data.cis_rhel9.main.compliance_report with input as {"profile": "level1_server"}
	na := [c | some c in r.control_results; c.status == "not_applicable"]
	count(na) == 89
	every c in na { c.findings == [] }
}

test_findings_compliant_fixture_every_row_passes_with_no_findings if {
	r := data.cis_rhel9.main.compliance_report with input as object.union(data.cis_rhel9.control_results_test.fixture_compliant, {"profile": "level2_server"})
	every c in r.control_results {
		c.status == "pass"
		c.findings == []
		count(c.evidence) > 0
	}
	sum([n | some n in r.control_result_counts]) == count(r.control_results)
}

test_findings_one_failing_fact_flips_exactly_its_row if {
	fx := object.union(data.cis_rhel9.control_results_test.fixture_compliant, {"profile": "level2_server", "user_group": {"duplicate_uids": {"1001": ["alice", "bob"]}}})
	r := data.cis_rhel9.main.compliance_report with input as fx
	[c.id | some c in r.control_results; c.status != "pass"] == ["7.2.4"]
	some c in r.control_results
	c.id == "7.2.4"
	c.status == "fail"
	count(c.findings) == 1
	startswith(c.findings[0], "7.2.4: not met")
	r.control_result_counts.pass == 351
	r.control_result_counts.fail == 1
	sum([n | some n in r.control_result_counts]) == count(r.control_results)
}

test_findings_counts_sum_to_rows_empty_input if {
	r := data.cis_rhel9.main.compliance_report with input as {}
	sum([n | some n in r.control_result_counts]) == count(r.control_results)
	every c in r.control_results {
		has_findings := count(c.findings) > 0
		not_a_pass := c.status in FAILING
		has_findings == not_a_pass
	}
}
