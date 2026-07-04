# Phase 1 contract smoke test — AI governance aggregate decision response.
# Contract: data.ai_governance.governance_response must return a well-formed,
# non-empty decision object on empty input (never undefined -> {}).
package ai_governance_test

import rego.v1

import data.ai_governance

test_report_wellformed_on_empty_input if {
	result := ai_governance.governance_response with input as {}
	is_object(result)
	count(result) > 0
	is_string(result.decision)
}
