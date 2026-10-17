package cis_cisco_ios_test

import rego.v1

three := ["aaa new-model", "no service finger", "no ip source-route"]

test_three_lines_not_compliant if {
	not data.cis_cisco_ios.compliant with input as {"cisco_config": three}
}

test_compliant_is_false_not_undefined if {
	data.cis_cisco_ios.compliant == false with input as {}
}

test_missing_config_is_evidence_violation if {
	v := data.cis_cisco_ios.violations with input as {}
	"0.0: evidence missing — cisco_config not collected" in v
}

test_unwired_controls_now_evaluated if {
	v := data.cis_cisco_ios.violations with input as {"cisco_config": three}
	"UNMAPPED-CISCO-1.22: Ensure logging on is configured" in v
	"UNMAPPED-CISCO-1.19: Ensure ssh version 2 is configured" in v
	"UNMAPPED-CISCO-2.2: Ensure service pad is disabled" in v
}

test_present_line_clears_violation if {
	inp := {"cisco_config": array.concat(three, ["logging on", "ip ssh version 2", "no service pad"])}
	v := data.cis_cisco_ios.violations with input as inp
	not "UNMAPPED-CISCO-1.22: Ensure logging on is configured" in v
	not "UNMAPPED-CISCO-1.19: Ensure ssh version 2 is configured" in v
	not "UNMAPPED-CISCO-2.2: Ensure service pad is disabled" in v
}

test_report_populated_when_failing if {
	r := data.cis_cisco_ios.compliance_summary with input as {"cisco_config": three}
	r.failing_controls > 0
	r.sections.management_plane.violations > 0
}
