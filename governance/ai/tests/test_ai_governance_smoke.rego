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

# Regression: empty input is NOT sufficient coverage.
#
# `requires_approval` and `requires_justification` only fire for medium/high and
# high/critical respectively. On empty input `action_risk_level` defaults to
# "high", so both fired and the object resolved — the test above passed while a
# realistic low-risk request collapsed classification_report, and with it the
# whole governance_response, to {}. Exercise a genuinely low-risk action too.
test_report_wellformed_on_read_only_action if {
	result := ai_governance.governance_response with input as {
		"action": "view_compliance_report",
		"ai_system": {"id": "claude-code-v1", "role": "ai_reader", "enabled": true},
		"context": {"environment": "development"},
	}
	is_object(result)
	count(result) > 0
	is_string(result.decision)
	is_object(result.classification)
	count(result.classification) > 0
}

# The defaults must not weaken the control: a critical action still demands
# approval and justification.
test_critical_action_still_requires_approval if {
	report := ai_governance.classification.classification_report with input as {
		"action": "delete_project",
		"ai_system": {"id": "c", "role": "ai_operator", "enabled": true},
		"context": {"environment": "production"},
	}
	report.requires_approval == true
	report.requires_justification == true
}
