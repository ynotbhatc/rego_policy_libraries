# AI Governance - Context Validation Policy
# Validates the context in which AI actions are being executed
#
# Context Checks:
#   - Environment restrictions (prod, staging, dev)
#   - Time-based restrictions (maintenance windows)
#   - Scope limitations (specific hosts, inventories)
#   - Rate limiting

package ai_governance.context

import rego.v1

# Environment risk levels
environment_risk := {
    "production": "high",
    "staging": "medium",
    "development": "low",
    "test": "low",
    "sandbox": "low"
}

# Default: context invalid if not explicitly valid
default context_valid := false

# Context is valid if all checks pass
context_valid if {
    environment_allowed
    within_time_window
    scope_valid
    rate_limit_ok
}

# Environment checks
default environment_allowed := false

environment_allowed if {
    input.context.environment
    env_risk := environment_risk[input.context.environment]
    env_risk != ""

    # Non-production environments allow all AI operations
    input.context.environment != "production"
}

environment_allowed if {
    input.context.environment == "production"

    # Production requires explicit production_access flag
    input.ai_system.production_access == true
}

# Time window checks (for maintenance operations)
# Fail closed: if a maintenance window is required but not active, neither clause
# fires and the rule is false (denied). A `default := true` here would fail OPEN —
# a required-but-inactive window would fall back to true and never be enforced.
default within_time_window := false

within_time_window if {
    not input.context.require_maintenance_window
}

within_time_window if {
    input.context.require_maintenance_window
    input.context.maintenance_window_active == true
}

# Scope validation
# Fail closed: if a scope_limit is declared but the target host count exceeds it
# (or target_hosts is absent), neither clause fires and the rule is false. A
# `default := true` would fail OPEN — an over-limit scope would fall back to true.
default scope_valid := false

scope_valid if {
    not input.context.scope_limit
}

scope_valid if {
    input.context.scope_limit
    input.context.target_hosts
    count(input.context.target_hosts) <= input.context.scope_limit
}

# Rate limiting
# Fail closed: if a rate_limit is declared but actions_in_window meets or exceeds
# it (or actions_in_window is absent), neither clause fires and the rule is false.
# A `default := true` would fail OPEN — an over-limit rate would fall back to true.
default rate_limit_ok := false

rate_limit_ok if {
    not input.context.rate_limit
}

rate_limit_ok if {
    input.context.rate_limit
    input.context.actions_in_window
    input.context.actions_in_window < input.context.rate_limit
}

# Blocked operations check
default operation_blocked := false

operation_blocked if {
    input.context.blocked_operations
    input.action in input.context.blocked_operations
}

# Context validation report
context_report := {
    "environment": object.get(input, ["context", "environment"], "unknown"),
    "environment_risk": object.get(environment_risk, object.get(input, ["context", "environment"], ""), "unknown"),
    "environment_allowed": environment_allowed,
    "within_time_window": within_time_window,
    "scope_valid": scope_valid,
    "rate_limit_ok": rate_limit_ok,
    "context_valid": context_valid,
    "operation_blocked": operation_blocked
}
