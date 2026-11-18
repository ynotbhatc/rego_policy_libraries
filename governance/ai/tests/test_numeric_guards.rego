package ai_governance.authorization_numeric_guards_test

import rego.v1

# "1" sorts above every number in Rego: an approvers_count sent as a string must not satisfy the count.
test_string_approvers_count_not_obtained if {
	not data.ai_governance.authorization.approval_obtained with input as {
		"action": "update_inventory",
		"approval": {"obtained": true, "approvers_count": "1"},
	}
}

test_null_approvers_count_not_obtained if {
	not data.ai_governance.authorization.approval_obtained with input as {
		"action": "update_inventory",
		"approval": {"obtained": true, "approvers_count": null},
	}
}

test_numeric_approvers_count_still_obtained if {
	data.ai_governance.authorization.approval_obtained with input as {
		"action": "update_inventory",
		"approval": {"obtained": true, "approvers_count": 1},
	}
}
