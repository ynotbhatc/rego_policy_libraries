# AI Governance - Action Classification Policy
# Classifies AI actions by risk level for governance decisions
#
# Risk Levels:
#   - read_only: No approval needed, always allowed
#   - low: Allowed with logging
#   - medium: Requires single approval
#   - high: Requires approval + justification
#   - critical: Requires multi-level approval

package ai_governance.classification

import rego.v1

# Risk levels for AI actions
risk_levels := ["read_only", "low", "medium", "high", "critical"]

# Default risk level if action not classified
default action_risk_level := "high"

# Action classification rules
action_risk_level := "read_only" if {
    input.action in read_only_actions
}

action_risk_level := "low" if {
    input.action in low_risk_actions
}

action_risk_level := "medium" if {
    input.action in medium_risk_actions
}

action_risk_level := "high" if {
    input.action in high_risk_actions
}

action_risk_level := "critical" if {
    input.action in critical_actions
}

# Read-only actions (always allowed, no approval needed)
read_only_actions := {
    "view_compliance_report",
    "query_system_facts",
    "list_violations",
    "generate_report",
    "analyze_trends",
    "view_inventory",
    "list_hosts",
    "get_job_status",
    "view_dashboard",
    "export_report_readonly"
}

# Low risk actions (allowed with logging)
low_risk_actions := {
    "create_assessment_job",
    "schedule_compliance_scan",
    "export_evidence",
    "run_readonly_playbook",
    "trigger_fact_collection",
    "generate_audit_report"
}

# Medium risk actions (requires single approval)
medium_risk_actions := {
    "remediate_low_severity",
    "update_inventory",
    "modify_job_schedule",
    "add_host_to_inventory",
    "run_remediation_playbook",
    "update_host_variables"
}

# High risk actions (requires approval + justification)
high_risk_actions := {
    "remediate_medium_severity",
    "modify_policy",
    "change_credentials",
    "update_production_inventory",
    "delete_host",
    "modify_job_template",
    "update_project_credentials"
}

# Critical actions (requires multi-level approval)
critical_actions := {
    "remediate_critical_severity",
    "modify_security_policy",
    "disable_control",
    "emergency_change",
    "delete_audit_data",
    "delete_inventory",
    "delete_project",
    "modify_authentication",
    "bulk_remediation",
    "production_emergency_access"
}

# Helper to check if action requires approval
requires_approval if {
    action_risk_level in ["medium", "high", "critical"]
}

# Helper to check if action requires justification
requires_justification if {
    action_risk_level in ["high", "critical"]
}

# Helper to check if action requires multi-level approval
requires_multi_approval if {
    action_risk_level == "critical"
}

# Classification report
classification_report := {
    "action": input.action,
    "risk_level": action_risk_level,
    "requires_approval": requires_approval,
    "requires_justification": requires_justification,
    "requires_multi_approval": requires_multi_approval
}
