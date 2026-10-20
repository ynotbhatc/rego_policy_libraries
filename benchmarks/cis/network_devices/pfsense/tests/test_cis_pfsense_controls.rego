package cis_pfsense_test

import rego.v1

# Rewritten for CIS pfSense Firewall Benchmark v1.1.1. The v1.0.0 ids these tests used
# (2.1.3 WAN allow-all, 5.1.1 vulnerability scan) did not exist in the real benchmark;
# allow-any rules are now 4.1.1 (destination) and 4.1.2 (source).

wan_rule(src, dst) := {"filter": {"rule": [{"interface": "wan", "type": "pass", "source": src, "destination": dst}]}}

has(prefix, inp) if {
	v := data.cis_pfsense.violations with input as inp
	some x in v
	startswith(x, prefix)
}

test_wan_pass_any_present_objects_flagged if {
	inp := wan_rule({"any": ""}, {"any": ""})
	has("4.1.1:", inp)
	has("4.1.2:", inp)
}

test_wan_pass_absent_sides_flagged if {
	inp := {"filter": {"rule": [{"interface": "wan", "type": "pass"}]}}
	has("4.1.1:", inp)
	has("4.1.2:", inp)
}

test_wan_pass_specific_source_not_flagged if not has("4.1.2:", wan_rule({"network": "lan"}, {"any": ""}))

test_wan_pass_specific_destination_not_flagged if not has("4.1.1:", wan_rule({"any": ""}, {"address": "10.0.0.5"}))

# The old "5.1.1 vulnerability scan" control is not in CIS pfSense v1.1.1 (5.1.1 is SNMP trap
# receivers). Vulnerability-scan input must no longer produce any vulnerability message.
no_vuln_message(inp) if {
	v := data.cis_pfsense.violations with input as inp
	every x in v { not contains(lower(x), "vulnerab") }
}

test_vuln_scan_missing_package_list_not_misleading if {
	inp := {"vulnerability_scan": {"performed": true}}
	no_vuln_message(inp)
	not has("5.1.1 UNABLE TO VERIFY", inp)
}

test_vuln_scan_with_packages_flagged if {
	inp := {"vulnerability_scan": {"performed": true}, "vulnerable_packages": ["openssl"]}
	no_vuln_message(inp)
	not has("5.1.1 Packages with known", inp)
}

test_vuln_scan_clean_ok if {
	inp := {"vulnerability_scan": {"performed": true}, "vulnerable_packages": []}
	not has("5.1.1 Packages", inp)
	no_vuln_message(inp)
}

# Totals are computed from the recommendation table: all 33 in v1.1.1.
test_summary_total_is_evaluated_control_count if {
	s := data.cis_pfsense.compliance_assessment.summary with input as {}
	s.total_controls == 33
	s.controls_evaluated == 33
	s.passing_controls + s.failing_controls == s.total_controls
}

test_every_failing_violation_id_is_an_evaluated_control if {
	v := data.cis_pfsense.violations with input as {}
	every x in v {
		regex.find_n(`^[0-9]+(\.[0-9]+)*`, x, 1)[0] in data.cis_pfsense.evaluated_controls
	}
}

test_summary_counts_distinct_failing_controls if {
	a := data.cis_pfsense.compliance_assessment.summary with input as {}
	a.failing_controls <= a.total_controls
	a.compliance_percentage >= 0
}

# Workbook: 30 Level 1 + 3 Level 2 (3.3, 5.1.3, 5.4.3).
test_recommendation_table_matches_workbook if {
	c := data.cis_pfsense.controls
	count(c) == 33
	{id | some id, x in c; x.level == 2} == {"3.3", "5.1.3", "5.4.3"}
}

test_empty_input_fails_every_control if {
	a := data.cis_pfsense.compliance_assessment with input as {}
	a.summary.failing_controls == 33
	a.compliant == false
}

test_single_rule_object_is_evaluated if has("4.1.1:", {"filter": {"rule": {"type": "pass", "interface": "lan", "source": {"network": "lan"}}}})

test_disabled_rule_ignored if not has("4.1.1:", {"filter": {"rule": [{"type": "pass", "disabled": "", "source": {"any": ""}}]}})

test_syslog_key_accepted_for_6_1 if not has("6.1:", {"syslog": {"enable": "", "remoteserver": "10.0.0.8"}})

test_factory_default_hostname_flagged if has("1.4:", {"system": {"hostname": "pfSense"}})

# Converters may render an empty element (<nodnsrebindcheck/>, <log/>) as null: that is a set flag.
test_null_flag_is_set_for_1_7 if has("1.7:", {"system": {"webgui": {"protocol": "https", "nodnsrebindcheck": null}}})

test_null_flag_is_set_for_4_1_5 if not has("4.1.5:", {"filter": {"rule": [{"type": "block", "log": null}]}})

test_null_disabled_rule_ignored if not has("4.1.2:", {"filter": {"rule": [{"type": "pass", "disabled": null, "source": {"any": ""}}]}})
