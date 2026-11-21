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

# "8" sorts above every number and null below it: an untagged resource with a non-numeric age is evidence missing.
test_string_age_days_is_evidence_missing if {
	vs := data.finops.tagging.violations with input as {"resources": [{"id": "r1", "type": "aws_instance", "age_days": "1", "tags": {"team": "a"}}]}
	some v in vs
	contains(v, "age_days is not a number (evidence missing)")
}

test_null_age_days_is_evidence_missing if {
	vs := data.finops.tagging.violations with input as {"resources": [{"id": "r1", "type": "aws_instance", "age_days": null, "tags": {"team": "a"}}]}
	some v in vs
	contains(v, "age_days is not a number (evidence missing)")
}

test_text_age_days_is_evidence_missing if {
	vs := data.finops.tagging.violations with input as {"resources": [{"id": "r1", "type": "aws_instance", "age_days": "x", "tags": {"team": "a"}}]}
	some v in vs
	contains(v, "age_days is not a number (evidence missing)")
}

test_numeric_age_days_unchanged if {
	vs := data.finops.tagging.violations with input as {"resources": [{"id": "r1", "type": "aws_instance", "age_days": 30, "tags": {"team": "a"}}]}
	some v in vs
	contains(v, "was created more than 7 days ago")
	every w in vs {
		not contains(w, "evidence missing")
	}
}
