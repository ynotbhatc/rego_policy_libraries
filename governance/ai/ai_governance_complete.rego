# AI Governance - Master Policy
# Aggregates all governance modules and provides unified decision
#
# Decision Types:
#   - allow: Action permitted, execute immediately
#   - allow_with_logging: Action permitted, must be logged
#   - pending_approval: Action requires human approval first
#   - deny: Action not permitted
#
# Usage:
#   POST http://localhost:8181/v1/data/ai_governance/governance_response
#   {
#     "input": {
#       "action": "remediate_low_severity",
#       "ai_system": {
#         "id": "claude-code-v1",
#         "role": "ai_operator",
#         "enabled": true
#       },
#       "context": {
#         "environment": "staging"
#       },
#       "trace_id": "uuid-here",
#       "approval": {
#         "obtained": false
#       },
#       "justification": ""
#     }
#   }

package ai_governance

import rego.v1
import data.ai_governance.classification
import data.ai_governance.authorization
import data.ai_governance.context

# Main governance decision
default decision := "deny"

# Allow without logging for read-only operations
decision := "allow" if {
    authorization.authorized
    context.context_valid
    classification.action_risk_level == "read_only"
}

# Allow with logging for low-risk operations
decision := "allow_with_logging" if {
    authorization.authorized
    context.context_valid
    classification.action_risk_level == "low"
}

# Allow with logging for medium/high/critical if approval obtained
decision := "allow_with_logging" if {
    authorization.authorized
    context.context_valid
    classification.action_risk_level in ["medium", "high", "critical"]
    authorization.approval_obtained
    authorization.justification_valid
}

# Pending approval for medium/high/critical without approval
decision := "pending_approval" if {
    authorization.authorized
    context.context_valid
    classification.action_risk_level in ["medium", "high", "critical"]
    not authorization.approval_obtained
}

# Deny reasons
deny_reasons contains "AI system not authorized for this action" if {
    not authorization.authorized
}

deny_reasons contains "Context validation failed" if {
    not context.context_valid
}

deny_reasons contains "Operation is blocked in current context" if {
    context.operation_blocked
}

deny_reasons contains "Justification required but not provided" if {
    authorization.approval_requirements.justification_required
    not authorization.justification_valid
}

deny_reasons contains "AI system is disabled" if {
    input.ai_system.enabled == false
}

# Full governance response
governance_response := {
    "decision": decision,
    "action": input.action,
    "risk_level": classification.action_risk_level,
    "ai_system": {
        "id": input.ai_system.id,
        "role": input.ai_system.role
    },
    "approval_requirements": authorization.approval_requirements,
    "context": {
        "environment": input.context.environment,
        "valid": context.context_valid
    },
    "deny_reasons": deny_reasons,
    "trace_id": input.trace_id,
    "timestamp": time.now_ns(),
    "classification": classification.classification_report,
    "authorization": authorization.authorization_report,
    "context_validation": context.context_report
}

# Simplified decision response (for quick checks)
simple_response := {
    "decision": decision,
    "risk_level": classification.action_risk_level,
    "approval_required": authorization.approval_requirements.required,
    "trace_id": input.trace_id
}

# Audit log entry (for compliance tracking)
audit_entry := {
    "timestamp": time.now_ns(),
    "trace_id": input.trace_id,
    "ai_system_id": input.ai_system.id,
    "ai_system_role": input.ai_system.role,
    "action": input.action,
    "risk_level": classification.action_risk_level,
    "decision": decision,
    "environment": input.context.environment,
    "approval_obtained": authorization.approval_obtained,
    "deny_reasons": deny_reasons
}
