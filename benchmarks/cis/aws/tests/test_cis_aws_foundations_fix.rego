package cis_aws_test

import rego.v1

# Validation fix pass 2026-10-17.

test_root_two_access_keys_flagged if {
	v := data.cis_aws.violations with input as {"aws_account_summary": {"account_access_keys_present": 2}}
	"1.1: Avoid the use of 'root' account" in v
}

test_cis_filter_pattern_accepted_for_4_1 if {
	inp := {
		"cloudwatch_alarms": [{"metric_name": "m"}],
		"cloudwatch_log_metric_filters": [{"metric_name": "m", "filter_pattern": "{ ($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\") }"}],
	}
	v := data.cis_aws.violations with input as inp
	not "4.1: Ensure a log metric filter and alarm exist for unauthorized API calls" in v
}

test_4_7_cmk_deletion_violation_reported if {
	v := data.cis_aws.violations with input as {}
	"4.7: Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer managed keys" in v
	"4.3: Ensure a log metric filter and alarm exist for usage of the root account" in v
}

test_4_7_passes_when_alarm_present if {
	inp := {
		"cloudwatch_alarms": [{"metric_name": "k"}],
		"cloudwatch_log_metric_filters": [{"metric_name": "k", "filter_pattern": "DisableKey ScheduleKeyDeletion"}],
	}
	v := data.cis_aws.violations with input as inp
	not "4.7: Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer managed keys" in v
}

test_nacl_allow_all_protocol_without_port_range_flagged if {
	inp := {"network_acls": [{"entries": [{"rule_action": "allow", "cidr_block": "0.0.0.0/0", "protocol": "-1"}]}]}
	v := data.cis_aws.violations with input as inp
	some msg in v
	startswith(msg, "5.1:")
}

test_compliant_false_not_undefined if {
	data.cis_aws.compliant == false with input as {}
}
