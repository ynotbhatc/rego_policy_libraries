# AI Governance - Authorization Policy
# Role-based access control for AI systems
#
# AI System Roles:
#   - ai_reader: Read-only access
#   - ai_analyst: Read + low-risk operations
#   - ai_operator: Read + low + medium operations
#   - ai_admin: Full access except critical
#   - ai_emergency: Full access including critical (time-limited)

package ai_governance.authorization

import rego.v1
import data.ai_governance.classification

# AI system roles and their permitted risk levels
ai_role_permissions := {
    "ai_reader": ["read_only"],
    "ai_analyst": ["read_only", "low"],
    "ai_operator": ["read_only", "low", "medium"],
    "ai_admin": ["read_only", "low", "medium", "high"],
    "ai_emergency": ["read_only", "low", "medium", "high", "critical"]
}

# Default: not authorized
default authorized := false

# Check if AI system is authorized for the action
authorized if {
    ai_role := input.ai_system.role
    action_risk := classification.action_risk_level
    ai_role_permissions[ai_role]
    action_risk in ai_role_permissions[ai_role]
}

# Check if AI system exists and is enabled
ai_system_valid if {
    input.ai_system.id != ""
    input.ai_system.enabled == true
}

# Check if emergency access is within time window (24 hours max)
emergency_access_valid if {
    input.ai_system.role == "ai_emergency"
    input.ai_system.emergency_granted_at
    time.now_ns() - input.ai_system.emergency_granted_at < 86400000000000  # 24 hours in nanoseconds
}

# Approval configuration by risk level
approval_config := {
    "read_only": {
        "required": false,
        "approvers": 0,
        "log_required": false,
        "timeout_hours": 0
    },
    "low": {
        "required": false,
        "approvers": 0,
        "log_required": true,
        "timeout_hours": 0
    },
    "medium": {
        "required": true,
        "approvers": 1,
        "log_required": true,
        "timeout_hours": 24,
        "approval_roles": ["compliance_admin", "security_admin", "it_manager"]
    },
    "high": {
        "required": true,
        "approvers": 2,
        "log_required": true,
        "timeout_hours": 4,
        "justification_required": true,
        "approval_roles": ["security_admin", "ciso", "it_director"]
    },
    "critical": {
        "required": true,
        "approvers": 3,
        "log_required": true,
        "timeout_hours": 1,
        "justification_required": true,
        "escalation": true,
        "approval_roles": ["ciso", "cio", "security_director"]
    }
}

# Get approval requirements for current action
approval_requirements := approval_config[classification.action_risk_level]

# Check if approval has been obtained
approval_obtained if {
    input.approval.obtained == true
    input.approval.approvers_count >= approval_requirements.approvers
}

# Check if approval is still valid (not expired)
approval_valid if {
    approval_obtained
    input.approval.approved_at
    hours_since_approval := (time.now_ns() - input.approval.approved_at) / 3600000000000
    hours_since_approval < approval_requirements.timeout_hours
}

# Check if justification is provided when required
justification_valid if {
    not approval_requirements.justification_required
}

justification_valid if {
    approval_requirements.justification_required
    input.justification != ""
    count(input.justification) >= 20  # Minimum 20 characters
}

# Authorization report
authorization_report := {
    "ai_system_id": input.ai_system.id,
    "ai_system_role": input.ai_system.role,
    "authorized": authorized,
    "ai_system_valid": ai_system_valid,
    "approval_requirements": approval_requirements,
    "approval_obtained": approval_obtained,
    "justification_valid": justification_valid
}
