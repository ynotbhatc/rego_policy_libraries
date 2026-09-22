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
    authorization.emergency_ok
    context.context_valid
    classification.action_risk_level == "read_only"
}

# Allow with logging for low-risk operations
decision := "allow_with_logging" if {
    authorization.authorized
    authorization.emergency_ok
    context.context_valid
    classification.action_risk_level == "low"
}

# Allow with logging for medium/high/critical if approval obtained.
# Jewel actions (business rules / data) additionally require the jewel
# constraints: dual control minimum + justification — no lone-approver or
# lone-emergency path to the jewels.
decision := "allow_with_logging" if {
    authorization.authorized
    authorization.emergency_ok
    context.context_valid
    classification.action_risk_level in ["medium", "high", "critical"]
    authorization.approval_valid
    authorization.justification_valid
    authorization.jewel_constraints_met
}

# Pending approval for medium/high/critical without approval
decision := "pending_approval" if {
    authorization.authorized
    authorization.emergency_ok
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

deny_reasons contains "Emergency access window expired or never granted" if {
    not authorization.emergency_ok
}

deny_reasons contains "Approval expired or not yet valid (timestamp outside its window)" if {
    authorization.approval_obtained
    not authorization.approval_valid
}

deny_reasons contains msg if {
    classification.is_jewel_action
    not authorization.jewel_constraints_met
    authorization.approval_obtained
    msg := sprintf("Crown-jewel action (%v) requires dual-control approval (>=2 approvers) and justification", [classification.jewel_class])
}

# Full governance response
governance_response := {
    "decision": decision,
    "action": object.get(input, ["action"], ""),
    "risk_level": classification.action_risk_level,
    "jewel_class": classification.jewel_class,
    "ai_system": {
        "id": object.get(input, ["ai_system", "id"], "unknown"),
        "role": object.get(input, ["ai_system", "role"], "unknown")
    },
    "approval_requirements": authorization.approval_requirements,
    "context": {
        "environment": object.get(input, ["context", "environment"], "unknown"),
        "valid": context.context_valid
    },
    "deny_reasons": deny_reasons,
    "trace_id": object.get(input, ["trace_id"], ""),
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
    "jewel_class": classification.jewel_class,
    "decision": decision,
    "environment": input.context.environment,
    "approval_obtained": authorization.approval_obtained,
    "deny_reasons": deny_reasons
}
