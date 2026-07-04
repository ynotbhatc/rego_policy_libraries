# Phase 1 contract smoke test — OIDC token validation summary.
# This endpoint returns a decision/summary object (not a compliance_report).
# Contract: data.governance.oidc.summary must return a well-formed, non-empty
# object with its key field(s) on empty input (never the default -> {} collapse).
package governance.oidc_test

import rego.v1

import data.governance.oidc

todo_test_report_wellformed_on_empty_input if {
	result := oidc.summary with input as {}
	is_object(result)
	count(result) > 0
	is_boolean(result.authorized)
}
