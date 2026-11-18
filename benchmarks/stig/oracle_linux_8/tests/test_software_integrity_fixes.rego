package stig.oracle_linux_8.software_integrity_test

import rego.v1

# Validation fixes 2026-10-17: a module with no facts collected is not compliant.

test_software_integrity_empty_input_not_compliant if {
	not data.stig.oracle_linux_8.software_integrity.compliant with input as {}
}
