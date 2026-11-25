package stig.oracle_linux_8.numeric_guards_test

import rego.v1

# Type traps (#300): pwquality values are whole JSON numbers. A value sent as text ("15", " 15 ") is not read (the
# collector converts the configured text): the finding is Open with "evidence invalid", naming the entry and the type.

test_minlen_numbers_pass if {
	data.stig.oracle_linux_8.account_auth.status_ol08_00_020230 == "Not_a_Finding" with input as {"pwquality_values": {"minlen": [15]}}
	data.stig.oracle_linux_8.account_auth.status_ol08_00_020230 == "Not_a_Finding" with input as {"pwquality_values": {"minlen": [15, 15]}}
}

test_numbers_as_text_are_evidence_invalid if {
	every v in ["15", " 15 ", "15\n"] {
		f := data.stig.oracle_linux_8.account_auth.finding_ol08_00_020230 with input as {"pwquality_values": {"minlen": [v]}}
		f.status == "Open"
		f.detail == "OL08-00-020230: evidence invalid — pwquality_values.minlen[0] is not a number (got string)"
	}
	f := data.stig.oracle_linux_8.account_auth.finding_ol08_00_020110 with input as {"pwquality_values": {"ucredit": [-1, "-1"]}}
	f.status == "Open"
	f.detail == "OL08-00-020110: evidence invalid — pwquality_values.ucredit[1] is not a number (got string)"
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
