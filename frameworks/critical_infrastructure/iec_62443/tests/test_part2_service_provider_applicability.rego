package iec_62443.part2_4_test

import rego.v1

test_absent_flag_with_empty_provider_not_compliant if {
	not data.iec_62443.part2_4.compliant with input as {"service_provider": {}}
	v := data.iec_62443.part2_4.violations with input as {"service_provider": {}}
	"IEC 62443-2-4 SP.01: evidence missing - input.is_iacs_service_provider not provided; applicability of the service provider requirements cannot be determined" in v
}

test_explicit_false_is_not_applicable if {
	data.iec_62443.part2_4.compliant with input as {"is_iacs_service_provider": false, "service_provider": {}}
}

test_true_with_empty_provider_flagged if {
	not data.iec_62443.part2_4.compliant with input as {"is_iacs_service_provider": true, "service_provider": {}}
}
