package cis.apache_2_4_numeric_guards_test

import rego.v1

# #300 type traps: a non-number must not pass r_6_4.
test_r_6_4_number_type_traps if {
	data.cis.apache_2_4.r_6_4 with input as {"apache": {"log_rotation": {"covers_configured_logs": true, "vhost_logs_included": true, "retention_weeks": 13}}}
	not data.cis.apache_2_4.r_6_4 with input as {"apache": {"log_rotation": {"covers_configured_logs": true, "vhost_logs_included": true, "retention_weeks": "1"}}}
	not data.cis.apache_2_4.r_6_4 with input as {"apache": {"log_rotation": {"covers_configured_logs": true, "vhost_logs_included": true, "retention_weeks": null}}}
	not data.cis.apache_2_4.r_6_4 with input as {"apache": {"log_rotation": {"covers_configured_logs": true, "vhost_logs_included": true, "retention_weeks": "not-a-number"}}}
}
