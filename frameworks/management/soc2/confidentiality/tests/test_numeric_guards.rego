package soc2.confidentiality.data_confidentiality_numeric_guards_test

import rego.v1

# "1" sorts above every number: a string retention period passed `>= 365`.
test_string_confidential_data_access_logged_is_false if {
	not data.soc2.confidentiality.data_confidentiality.confidential_data_access_logged with input as {"access_logging": {"confidential_data": {"enabled": true, "detailed": true, "real_time_monitoring": true, "retention_period": "1"}}}
}

test_null_confidential_data_access_logged_is_false if {
	not data.soc2.confidentiality.data_confidentiality.confidential_data_access_logged with input as {"access_logging": {"confidential_data": {"enabled": true, "detailed": true, "real_time_monitoring": true, "retention_period": null}}}
}

test_text_confidential_data_access_logged_is_false if {
	not data.soc2.confidentiality.data_confidentiality.confidential_data_access_logged with input as {"access_logging": {"confidential_data": {"enabled": true, "detailed": true, "real_time_monitoring": true, "retention_period": "x"}}}
}

test_numeric_confidential_data_access_logged_unchanged if {
	data.soc2.confidentiality.data_confidentiality.confidential_data_access_logged with input as {"access_logging": {"confidential_data": {"enabled": true, "detailed": true, "real_time_monitoring": true, "retention_period": 400}}}
}
