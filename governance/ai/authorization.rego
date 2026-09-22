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
default ai_system_valid := false

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

# The emergency role is only usable inside its granted window. Previously
# emergency_access_valid was computed but consumed by nothing — an ai_emergency
# system worked forever. Non-emergency roles pass trivially.
default emergency_ok := false

emergency_ok if {
    object.get(input, ["ai_system", "role"], "") != "ai_emergency"
}

emergency_ok if {
    input.ai_system.role == "ai_emergency"
    emergency_access_valid
}

# Crown-jewels constraint: a jewel action (business rules or data — see
# classification.jewel_class) requires obtained approval with DUAL CONTROL at
# minimum, and a justification, regardless of role. There is no lone-approver
# and no lone-emergency path to the jewels.
default jewel_constraints_met := false

jewel_constraints_met if {
    classification.jewel_class == "none"
}

jewel_constraints_met if {
    classification.jewel_class != "none"
    approval_obtained
    input.approval.approvers_count >= 2
    justification_valid
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
default approval_obtained := false

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
default justification_valid := false

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
    "ai_system_id": object.get(input, ["ai_system", "id"], "unknown"),
    "ai_system_role": object.get(input, ["ai_system", "role"], "unknown"),
    "authorized": authorized,
    "ai_system_valid": ai_system_valid,
    "emergency_ok": emergency_ok,
    "jewel_constraints_met": jewel_constraints_met,
    "approval_requirements": approval_requirements,
    "approval_obtained": approval_obtained,
    "justification_valid": justification_valid
}
