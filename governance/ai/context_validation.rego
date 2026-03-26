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
default within_time_window := true

within_time_window if {
    not input.context.require_maintenance_window
}

within_time_window if {
    input.context.require_maintenance_window
    input.context.maintenance_window_active == true
}

# Scope validation
default scope_valid := true

scope_valid if {
    not input.context.scope_limit
}

scope_valid if {
    input.context.scope_limit
    input.context.target_hosts
    count(input.context.target_hosts) <= input.context.scope_limit
}

# Rate limiting
default rate_limit_ok := true

rate_limit_ok if {
    not input.context.rate_limit
}

rate_limit_ok if {
    input.context.rate_limit
    input.context.actions_in_window
    input.context.actions_in_window < input.context.rate_limit
}

# Blocked operations check
operation_blocked if {
    input.context.blocked_operations
    input.action in input.context.blocked_operations
}

# Context validation report
context_report := {
    "environment": input.context.environment,
    "environment_risk": environment_risk[input.context.environment],
    "environment_allowed": environment_allowed,
    "within_time_window": within_time_window,
    "scope_valid": scope_valid,
    "rate_limit_ok": rate_limit_ok,
    "context_valid": context_valid,
    "operation_blocked": operation_blocked
}
