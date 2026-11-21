package soc2.availability.system_availability_numeric_guards_test

import rego.v1

# null sorts below every number: a null response-time threshold passed `<= 2000`.
test_string_performance_thresholds_defined_is_false if {
	not data.soc2.availability.system_availability.performance_thresholds_defined with input as {"performance": {"thresholds": {"response_time_ms": "1", "error_rate_percent": 0.5, "cpu_utilization_percent": 70}}}
}

test_null_performance_thresholds_defined_is_false if {
	not data.soc2.availability.system_availability.performance_thresholds_defined with input as {"performance": {"thresholds": {"response_time_ms": null, "error_rate_percent": 0.5, "cpu_utilization_percent": 70}}}
}

test_text_performance_thresholds_defined_is_false if {
	not data.soc2.availability.system_availability.performance_thresholds_defined with input as {"performance": {"thresholds": {"response_time_ms": "x", "error_rate_percent": 0.5, "cpu_utilization_percent": 70}}}
}

test_numeric_performance_thresholds_defined_unchanged if {
	data.soc2.availability.system_availability.performance_thresholds_defined with input as {"performance": {"thresholds": {"response_time_ms": 500, "error_rate_percent": 0.5, "cpu_utilization_percent": 70}}}
}

# "1" sorts above every number: a string zone count passed `>= 2`.
test_string_multi_zone_deployment_is_false if {
	not data.soc2.availability.system_availability.multi_zone_deployment with input as {"infrastructure": {"zones": {"count": "1"}, "load_balancing": {"cross_zone": true}, "data_replication": {"cross_zone": true}}}
}

test_null_multi_zone_deployment_is_false if {
	not data.soc2.availability.system_availability.multi_zone_deployment with input as {"infrastructure": {"zones": {"count": null}, "load_balancing": {"cross_zone": true}, "data_replication": {"cross_zone": true}}}
}

test_text_multi_zone_deployment_is_false if {
	not data.soc2.availability.system_availability.multi_zone_deployment with input as {"infrastructure": {"zones": {"count": "x"}, "load_balancing": {"cross_zone": true}, "data_replication": {"cross_zone": true}}}
}

test_numeric_multi_zone_deployment_unchanged if {
	data.soc2.availability.system_availability.multi_zone_deployment with input as {"infrastructure": {"zones": {"count": 3}, "load_balancing": {"cross_zone": true}, "data_replication": {"cross_zone": true}}}
}
