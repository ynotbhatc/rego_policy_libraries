package cis.network.cisco_test

import rego.v1

# Validation 2026-10-17: list-shaped cisco_config, anchored matching, defaulted report.

test_list_config_aaa_new_model if {
	data.cis.network.cisco.aaa_new_model_configured with input as {"cisco_config": ["aaa new-model", "logging on"]}
	data.cis.network.cisco.logging_enabled with input as {"cisco_config": ["aaa new-model", "logging on"]}
}

test_string_config_aaa_new_model if {
	data.cis.network.cisco.aaa_new_model_configured with input as {"cisco_config": "hostname r1\naaa new-model\n"}
	data.cis.network.cisco.aaa_authentication_configured with input as {"cisco_config": "aaa new-model\naaa authentication login default group tacacs+"}
}

test_negated_logging_console_not_satisfying if {
	not data.cis.network.cisco.logging_console_configured with input as {"cisco_config": ["no logging console critical"]}
	data.cis.network.cisco.logging_console_configured with input as {"cisco_config": ["logging console critical"]}
}

test_missing_config_fails_closed if {
	not data.cis.network.cisco.aaa_new_model_configured with input as {}
	not data.cis.network.cisco.cisco_device_compliant with input as {}
}

test_report_defined_when_check_fails if {
	r := data.cis.network.cisco.cisco_device_compliance with input as {"cisco_config": ["aaa new-model"]}
	r.aaa_new_model_configured == true
	r.logging_enabled == false
	r.overall_compliant == false
	count(r) == 45
}
