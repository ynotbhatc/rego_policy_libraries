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

# No explicit "high" rule: high_risk_actions (and any unclassified action)
# resolve through `default action_risk_level := "high"` — assigning the
# default explicitly is redundant (regal bugs/rule-assigns-default). The
# high_risk_actions set remains the documented catalog of known-high actions.

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

# ---------------------------------------------------------------------------
# Crown jewels — the two artifact classes the governance plane exists to
# protect: the BUSINESS RULES (the logic that runs the business, including the
# governance plane's own policies) and the DATA. Jewel actions are critical by
# classification and additionally tagged with jewel_class so downstream
# authorization (dual control, no lone-emergency bypass) and the decision-log
# analytics (jewel-touching activity ranks first) can key on them.
# ---------------------------------------------------------------------------

# New jewel action names (disjoint from the legacy sets above)
business_rules_jewel_actions := {
    "modify_business_rules",
    "modify_governance_policy",
    "reload_governance_policy",
    "modify_policy_data",
    "register_governed_automation",
    "modify_decision_logic"
}

data_jewel_actions := {
    "delete_dataset",
    "bulk_export_data",
    "modify_data_pipeline",
    "grant_data_access",
    "modify_data_classification",
    "restore_data_from_backup"
}

action_risk_level := "critical" if {
    input.action in business_rules_jewel_actions
}

action_risk_level := "critical" if {
    input.action in data_jewel_actions
}

# jewel_class also covers the legacy critical actions that are jewels by nature
default jewel_class := "none"

jewel_class := "business_rules" if {
    input.action in business_rules_jewel_actions
}

jewel_class := "business_rules" if {
    input.action in {"modify_security_policy", "disable_control", "modify_authentication"}
}

jewel_class := "data" if {
    input.action in data_jewel_actions
}

jewel_class := "data" if {
    input.action == "delete_audit_data"
}

default is_jewel_action := false

is_jewel_action if jewel_class != "none"

# Helper to check if action requires approval
# `default` is required: this rule only fires for medium/high/critical, so for a
# read_only or low action it would otherwise be undefined — and one undefined
# field collapses the whole classification_report object to {}.
default requires_approval := false

requires_approval if {
    action_risk_level in ["medium", "high", "critical"]
}

# Helper to check if action requires justification
# Same reason as above: undefined for anything below high risk without this.
default requires_justification := false

requires_justification if {
    action_risk_level in ["high", "critical"]
}

# Helper to check if action requires multi-level approval
default requires_multi_approval := false

requires_multi_approval if {
    action_risk_level == "critical"
}

# Classification report
classification_report := {
    "action": object.get(input, ["action"], ""),
    "risk_level": action_risk_level,
    "jewel_class": jewel_class,
    "is_jewel_action": is_jewel_action,
    "requires_approval": requires_approval,
    "requires_justification": requires_justification,
    "requires_multi_approval": requires_multi_approval
}
