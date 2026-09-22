# Crown-jewels tier + emergency time-box tests for the action layer.
package ai_governance_test

import rego.v1

import data.ai_governance
import data.ai_governance.authorization
import data.ai_governance.classification

_base := {
	"ai_system": {"id": "agent-1", "role": "ai_emergency", "enabled": true, "production_access": true},
	"context": {"environment": "development"},
	"trace_id": "00000000-0000-0000-0000-000000000001",
	"approval": {"obtained": false},
	"justification": "",
}

# --- Classification: jewel actions are critical and tagged.

test_governance_policy_modification_is_business_rules_jewel if {
	classification.action_risk_level == "critical" with input as {"action": "modify_governance_policy"}
	classification.jewel_class == "business_rules" with input as {"action": "modify_governance_policy"}
}

test_bulk_export_is_data_jewel if {
	classification.jewel_class == "data" with input as {"action": "bulk_export_data"}
	classification.action_risk_level == "critical" with input as {"action": "bulk_export_data"}
}

test_legacy_delete_audit_data_is_data_jewel if {
	classification.jewel_class == "data" with input as {"action": "delete_audit_data"}
}

test_ordinary_action_is_not_jewel if {
	classification.jewel_class == "none" with input as {"action": "remediate_low_severity"}
	classification.is_jewel_action == false with input as {"action": "remediate_low_severity"}
}

# --- Jewel constraints: dual control minimum, justification, no lone path.

test_jewel_constraints_met_with_dual_control if {
	inp := object.union(_base, {
		"action": "modify_governance_policy",
		"approval": {"obtained": true, "approvers_count": 3},
		"justification": "change record CHG-1234 approved by review board",
	})
	authorization.jewel_constraints_met with input as inp
}

test_jewel_constraints_not_met_single_approver if {
	inp := object.union(_base, {
		"action": "modify_governance_policy",
		"approval": {"obtained": true, "approvers_count": 1},
		"justification": "change record CHG-1234 approved by review board",
	})
	not authorization.jewel_constraints_met with input as inp
}

test_non_jewel_constraints_trivially_met if {
	inp := object.union(_base, {"action": "remediate_low_severity"})
	authorization.jewel_constraints_met with input as inp
}

# --- Aggregate decision: jewel action without approval pends; with full
# --- multi-approval + justification it allows with logging.

test_jewel_without_approval_pends if {
	inp := object.union(_base, {
		"action": "modify_governance_policy",
		"ai_system": object.union(_base.ai_system, {"emergency_granted_at": 1000}),
	})
	d := ai_governance.decision with input as inp with time.now_ns as 2000
	d == "pending_approval"
}

test_jewel_with_multi_approval_allows_with_logging if {
	inp := object.union(_base, {
		"action": "modify_governance_policy",
		"ai_system": object.union(_base.ai_system, {"emergency_granted_at": 1000}),
		"approval": {"obtained": true, "approvers_count": 3, "approved_at": 1500},
		"justification": "change record CHG-1234 approved by review board",
	})
	d := ai_governance.decision with input as inp with time.now_ns as 2000
	d == "allow_with_logging"
}

# --- Emergency time-box: computed-but-unconsumed no more.

test_emergency_role_denied_outside_window if {
	inp := object.union(_base, {
		"action": "view_compliance_report",
		"ai_system": object.union(_base.ai_system, {"emergency_granted_at": 0}),
	})

	# 25 hours after grant — window is 24h
	d := ai_governance.decision with input as inp with time.now_ns as 90000000000000
	d == "deny"
	reasons := ai_governance.deny_reasons with input as inp with time.now_ns as 90000000000000
	"Emergency access window expired or never granted" in reasons
}

test_emergency_role_allowed_inside_window if {
	inp := object.union(_base, {
		"action": "view_compliance_report",
		"ai_system": object.union(_base.ai_system, {"emergency_granted_at": 1000}),
	})
	d := ai_governance.decision with input as inp with time.now_ns as 2000
	d == "allow"
}

test_non_emergency_role_unaffected_by_window if {
	inp := object.union(_base, {
		"action": "view_compliance_report",
		"ai_system": {"id": "agent-2", "role": "ai_reader", "enabled": true},
	})
	d := ai_governance.decision with input as inp
	d == "allow"
}
