package stig.oracle_linux_8.numeric_guards_test

import rego.v1

# Type traps (#300): pwquality values that are not decimal integers (or numbers) must not pass.
# A decimal-integer string such as "15" is the collector's form and is converted by _pwq.

test_minlen_numbers_pass if {
	data.stig.oracle_linux_8.account_auth.status_ol08_00_020230 == "Not_a_Finding" with input as {"pwquality_values": {"minlen": [15]}}
	data.stig.oracle_linux_8.account_auth.status_ol08_00_020230 == "Not_a_Finding" with input as {"pwquality_values": {"minlen": ["15"]}}
}

test_minlen_type_traps_are_open if {
	every v in ["1", null, "x", true] {
		data.stig.oracle_linux_8.account_auth.status_ol08_00_020230 == "Open" with input as {"pwquality_values": {"minlen": [v]}}
	}
}

test_credit_type_traps_are_open if {
	every v in ["1", null, "x", true] {
		data.stig.oracle_linux_8.account_auth.status_ol08_00_020110 == "Open" with input as {"pwquality_values": {"ucredit": [v]}}
		data.stig.oracle_linux_8.account_auth.status_ol08_00_020120 == "Open" with input as {"pwquality_values": {"lcredit": [v]}}
		data.stig.oracle_linux_8.account_auth.status_ol08_00_020130 == "Open" with input as {"pwquality_values": {"dcredit": [v]}}
		data.stig.oracle_linux_8.account_auth.status_ol08_00_020280 == "Open" with input as {"pwquality_values": {"ocredit": [v]}}
	}
}

test_credit_numbers_pass if {
	data.stig.oracle_linux_8.account_auth.status_ol08_00_020110 == "Not_a_Finding" with input as {"pwquality_values": {"ucredit": [-1]}}
}
