package finops.tagging_numeric_guards_test

import rego.v1

# A string budget makes `budget * 1.1` undefined, so the overspend rules would not fire; it is a finding.
test_string_budget_is_a_finding if {
	vs := data.finops.tagging.violations with input as {"budget_registry": {"cc1": "100"}, "current_spend": {"cc1": 500}}
	some v in vs
	contains(v, "is not a number")
}

test_string_spend_is_a_finding if {
	vs := data.finops.tagging.violations with input as {"budget_registry": {"cc1": 100}, "current_spend": {"cc1": "500"}}
	some v in vs
	contains(v, "is not a number")
}

test_numeric_budget_no_type_finding if {
	vs := data.finops.tagging.violations with input as {"budget_registry": {"cc1": 100}, "current_spend": {"cc1": 50}}
	every v in vs {
		not contains(v, "is not a number")
	}
}
