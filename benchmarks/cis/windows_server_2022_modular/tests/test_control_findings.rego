package cis_windows_server_2022.control_findings_test

import rego.v1

# Hand-written (issue #309): control_results rows carry `findings`, the violation messages that cite the row's
# recommendation id ("CIS <id>: ... -- found: <observed value>" for a fail), so a pass and a failure are both
# reported per control. Fixtures come from the generated fixtures test (cis_windows_server_2022.fixtures_test).

FAILING := {"fail", "evidence_missing", "not_attested"}

test_findings_empty_input_no_row_passes_and_every_failing_row_has_messages if {
	r := data.cis_windows_server_2022.main.compliance_report with input as {}
	count([c | some c in r.control_results; c.status == "pass"]) == 0
	every c in r.control_results {
		has_findings := count(c.findings) > 0
		not_a_pass := c.status in FAILING
		has_findings == not_a_pass
		every m in c.findings { startswith(m, concat("", ["CIS ", c.id, ": "])) }
	}
	sum([n | some n in r.control_result_counts]) == count(r.control_results)
}

test_findings_compliant_fixture_every_in_scope_row_passes_with_no_findings if {
	r := data.cis_windows_server_2022.main.compliance_report with input as data.cis_windows_server_2022.fixtures_test.fixture_ms
	every c in r.control_results {
		c.status in {"pass", "not_applicable"}
		c.findings == []
	}
	r.control_result_counts.pass == r.total_controls
	sum([n | some n in r.control_result_counts]) == count(r.control_results)
}

test_findings_one_failing_fact_flips_exactly_its_row if {
	fx := object.union(data.cis_windows_server_2022.fixtures_test.fixture_ms, {"secedit": {"system_access": {"PasswordHistorySize": 1}}})
	r := data.cis_windows_server_2022.main.compliance_report with input as fx
	[c.id | some c in r.control_results; c.status in FAILING] == ["1.1.1"]
	some c in r.control_results
	c.id == "1.1.1"
	c.status == "fail"
	count(c.findings) == 1
	startswith(c.findings[0], "CIS 1.1.1: ")
	contains(c.findings[0], " -- found: 1")
	r.control_result_counts.fail == 1
	r.control_result_counts.pass == r.total_controls - 1
}
