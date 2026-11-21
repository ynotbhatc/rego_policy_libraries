package security.crypto_miner_detection_numeric_guards_test

import rego.v1

# "1" sorts above every number: a string cpu_percent was listed as a high-CPU process.
test_string_cpu_not_high if {
	count(data.security.crypto_miner_detection.high_cpu_processes) == 0 with input as {"running_processes": [{"name": "app", "cmdline": "app", "cpu_percent": "1", "running_time_minutes": 60}]}
}

test_null_runtime_not_high if {
	count(data.security.crypto_miner_detection.high_cpu_processes) == 0 with input as {"running_processes": [{"name": "app", "cmdline": "app", "cpu_percent": 95, "running_time_minutes": null}]}
}

test_text_cpu_not_high if {
	count(data.security.crypto_miner_detection.high_cpu_processes) == 0 with input as {"running_processes": [{"name": "app", "cmdline": "app", "cpu_percent": "x", "running_time_minutes": 60}]}
}

test_numeric_cpu_unchanged if {
	count(data.security.crypto_miner_detection.high_cpu_processes) == 1 with input as {"running_processes": [{"name": "app", "cmdline": "app", "cpu_percent": 95, "running_time_minutes": 60}]}
}
