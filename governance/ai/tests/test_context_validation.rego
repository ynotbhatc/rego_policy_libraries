# Unit tests for AI Governance — Context Validation (governance/ai/context_validation.rego)
# Closes issue #82.
#
# Module package: ai_governance.context
# The module exposes boolean DECISION rules (no violation/deny message rules) plus
# a context_report object. within_time_window / scope_valid / rate_limit_ok are
# fail-CLOSED: a declared-but-violated requirement denies (rule is false), and an
# absent requirement passes. These tests assert that fail-closed behavior.
#
# No lab IPs — RFC 5737 documentation block (192.0.2.x) / localhost only.

package ai_governance.context_test

import rego.v1

import data.ai_governance.context

# ---------------------------------------------------------------------------
# environment_allowed  (default false)
# ---------------------------------------------------------------------------

test_environment_allowed_nonprod if {
	context.environment_allowed == true with input as {"context": {"environment": "development"}}
}

test_environment_allowed_production_with_access if {
	context.environment_allowed == true with input as {
		"context": {"environment": "production"},
		"ai_system": {"production_access": true},
	}
}

test_environment_not_allowed_production_without_access if {
	context.environment_allowed == false with input as {"context": {"environment": "production"}}
}

test_environment_not_allowed_unknown_environment if {
	context.environment_allowed == false with input as {"context": {"environment": "narnia"}}
}

# ---------------------------------------------------------------------------
# within_time_window  (default false, fail-closed)
# ---------------------------------------------------------------------------

test_within_time_window_when_not_required if {
	context.within_time_window == true with input as {"context": {}}
}

test_within_time_window_when_required_and_active if {
	context.within_time_window == true with input as {"context": {"require_maintenance_window": true, "maintenance_window_active": true}}
}

# Fail-closed: window required but NOT active -> denied.
test_within_time_window_denied_when_required_but_inactive if {
	context.within_time_window == false with input as {"context": {"require_maintenance_window": true, "maintenance_window_active": false}}
}

# Fail-closed: window required, active flag absent -> denied.
test_within_time_window_denied_when_required_flag_absent if {
	context.within_time_window == false with input as {"context": {"require_maintenance_window": true}}
}

# ---------------------------------------------------------------------------
# scope_valid  (default false, fail-closed)
# ---------------------------------------------------------------------------

test_scope_valid_when_no_limit if {
	context.scope_valid == true with input as {"context": {}}
}

test_scope_valid_when_within_limit if {
	context.scope_valid == true with input as {"context": {"scope_limit": 5, "target_hosts": ["192.0.2.10", "192.0.2.11"]}}
}

# Fail-closed: host count exceeds the declared scope_limit -> denied.
test_scope_valid_denied_when_over_limit if {
	context.scope_valid == false with input as {"context": {"scope_limit": 1, "target_hosts": ["192.0.2.10", "192.0.2.11"]}}
}

# Fail-closed: scope_limit declared but no target_hosts to check -> denied.
test_scope_valid_denied_when_target_hosts_absent if {
	context.scope_valid == false with input as {"context": {"scope_limit": 5}}
}

# ---------------------------------------------------------------------------
# rate_limit_ok  (default false, fail-closed)
# ---------------------------------------------------------------------------

test_rate_limit_ok_when_no_limit if {
	context.rate_limit_ok == true with input as {"context": {}}
}

test_rate_limit_ok_when_under_limit if {
	context.rate_limit_ok == true with input as {"context": {"rate_limit": 10, "actions_in_window": 3}}
}

# Fail-closed: actions meet/exceed the rate_limit -> denied.
test_rate_limit_ok_denied_when_over_limit if {
	context.rate_limit_ok == false with input as {"context": {"rate_limit": 5, "actions_in_window": 10}}
}

# Fail-closed: rate_limit declared but actions_in_window absent -> denied.
test_rate_limit_ok_denied_when_actions_absent if {
	context.rate_limit_ok == false with input as {"context": {"rate_limit": 5}}
}

# ---------------------------------------------------------------------------
# operation_blocked  (default false)
# ---------------------------------------------------------------------------

test_operation_blocked_when_action_in_blocklist if {
	context.operation_blocked == true with input as {
		"action": "delete_all",
		"context": {"blocked_operations": ["delete_all", "wipe"]},
	}
}

test_operation_not_blocked_when_action_absent_from_blocklist if {
	context.operation_blocked == false with input as {
		"action": "read",
		"context": {"blocked_operations": ["delete_all"]},
	}
}

# ---------------------------------------------------------------------------
# context_valid  (default false — requires ALL four sub-checks)
# ---------------------------------------------------------------------------

test_context_valid_true_when_all_checks_pass if {
	context.context_valid == true with input as {"context": {"environment": "development"}}
}

# Fail-closed on empty input: environment_allowed is false, so context_valid is false.
test_context_valid_false_on_empty_input if {
	context.context_valid == false with input as {}
}

# A single failing sub-check (required-but-inactive window) denies the whole context,
# even in an otherwise-permitted non-production environment.
test_context_valid_false_when_one_subcheck_fails if {
	context.context_valid == false with input as {"context": {
		"environment": "development",
		"require_maintenance_window": true,
		"maintenance_window_active": false,
	}}
}

# ---------------------------------------------------------------------------
# context_report  (must be a populated object, never {} — CLAUDE.md rule #5)
# ---------------------------------------------------------------------------

test_context_report_populated_on_empty_input if {
	result := context.context_report with input as {}
	is_object(result)
	count(result) == 8
	result.context_valid == false
}

test_context_report_reflects_valid_context if {
	result := context.context_report with input as {"context": {"environment": "development"}}
	result.context_valid == true
	result.environment == "development"
}
