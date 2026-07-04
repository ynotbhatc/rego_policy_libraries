# Phase 1 contract smoke test — MCP governance decision response.
# This endpoint returns a decision object (not a compliance_report).
# Contract: data.ai_governance.mcp.response must return a well-formed,
# non-empty object with a decision field on empty input (never undefined -> {}).
package ai_governance.mcp_test

import rego.v1

import data.ai_governance.mcp

test_report_wellformed_on_empty_input if {
	result := mcp.response with input as {}
	is_object(result)
	count(result) > 0
	is_string(result.decision)
}
