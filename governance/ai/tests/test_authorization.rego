# Unit tests for governance/ai/authorization.rego
# Package under test: ai_governance.authorization
#
# Notes on dependencies:
#   - authorization imports data.ai_governance.classification. Its
#     action_risk_level DEFAULTS to "high" when input.action is unset/unknown,
#     so approval_requirements defaults to approval_config["high"]
#     (2 approvers, 4h timeout, justification_required=true).
#   - Time-window rules (emergency_access_valid, approval_valid) call
#     time.now_ns(). To fire them deterministically regardless of wall-clock,
#     the "granted/approved" timestamp is set far in the future so that
#     (now - ts) is negative and therefore below every threshold.

package ai_governance.authorization_test

import rego.v1

import data.ai_governance.authorization

# --- authorized ------------------------------------------------------------

# ai_reader may perform a read_only action -> authorized
test_authorized_reader_readonly if {
	authorization.authorized with input as {
		"ai_system": {"role": "ai_reader"},
		"action": "view_compliance_report",
	}
}

# ai_admin is permitted up to "high" risk -> authorized for a high action
test_authorized_admin_high if {
	authorization.authorized with input as {
		"ai_system": {"role": "ai_admin"},
		"action": "modify_policy",
	}
}

# ai_emergency is the only role permitted "critical" -> authorized
test_authorized_emergency_critical if {
	authorization.authorized with input as {
		"ai_system": {"role": "ai_emergency"},
		"action": "emergency_change",
	}
}

# default authorized := false: reader attempting a high-risk action is denied
test_not_authorized_reader_high_action if {
	not authorization.authorized with input as {
		"ai_system": {"role": "ai_reader"},
		"action": "modify_policy",
	}
}

# ai_admin is NOT permitted "critical" -> not authorized
test_not_authorized_admin_critical if {
	not authorization.authorized with input as {
		"ai_system": {"role": "ai_admin"},
		"action": "emergency_change",
	}
}

# --- ai_system_valid -------------------------------------------------------

test_ai_system_valid_true if {
	authorization.ai_system_valid with input as {"ai_system": {"id": "ai-001", "enabled": true}}
}

# default ai_system_valid := false: disabled system
test_ai_system_valid_false_disabled if {
	not authorization.ai_system_valid with input as {"ai_system": {"id": "ai-001", "enabled": false}}
}

# default ai_system_valid := false: empty id
test_ai_system_valid_false_empty_id if {
	not authorization.ai_system_valid with input as {"ai_system": {"id": "", "enabled": true}}
}

# --- emergency_access_valid ------------------------------------------------

# emergency grant within the 24h window (future ts -> negative delta -> valid)
test_emergency_access_valid_true if {
	authorization.emergency_access_valid with input as {"ai_system": {
		"role": "ai_emergency",
		"emergency_granted_at": 99999999999999999999,
	}}
}

# emergency grant older than 24h (epoch 0) -> rule does not fire
test_emergency_access_valid_false_expired if {
	not authorization.emergency_access_valid with input as {"ai_system": {
		"role": "ai_emergency",
		"emergency_granted_at": 0,
	}}
}

# --- approval_obtained -----------------------------------------------------

# medium action requires 1 approver; count meets it -> obtained
test_approval_obtained_true_medium if {
	authorization.approval_obtained with input as {
		"action": "update_inventory",
		"approval": {"obtained": true, "approvers_count": 1},
	}
}

# default approval_obtained := false: too few approvers for a medium action
test_approval_obtained_false_insufficient if {
	not authorization.approval_obtained with input as {
		"action": "update_inventory",
		"approval": {"obtained": true, "approvers_count": 0},
	}
}

# --- approval_valid --------------------------------------------------------

# obtained + approved within the medium 24h timeout (future ts) -> valid
test_approval_valid_true_medium if {
	authorization.approval_valid with input as {
		"action": "update_inventory",
		"approval": {
			"obtained": true,
			"approvers_count": 1,
			"approved_at": 99999999999999999999,
		},
	}
}

# --- justification_valid ---------------------------------------------------

# medium risk has no justification_required key -> justification not required
test_justification_valid_not_required_medium if {
	authorization.justification_valid with input as {"action": "update_inventory"}
}

# high risk requires justification; >=20 chars provided -> valid
test_justification_valid_high_with_text if {
	authorization.justification_valid with input as {
		"action": "modify_policy",
		"justification": "Emergency security patch required for CVE remediation",
	}
}

# default justification_valid := false: high risk, no justification supplied
test_justification_valid_false_high_no_text if {
	not authorization.justification_valid with input as {"action": "modify_policy"}
}

# --- fully-authorized (compliant) scenario ---------------------------------

# A valid, enabled operator performing a medium action it is permitted for,
# with the single approval it needs: authorized AND ai_system_valid.
test_fully_authorized_scenario if {
	req := {
		"ai_system": {"id": "ai-op-7", "role": "ai_operator", "enabled": true},
		"action": "update_inventory",
		"approval": {"obtained": true, "approvers_count": 1},
	}
	authorization.authorized with input as req
	authorization.ai_system_valid with input as req
	authorization.approval_obtained with input as req
}

# --- authorization_report --------------------------------------------------

# The report object must be POPULATED (not {}) even on empty input {}.
test_authorization_report_populated_on_empty_input if {
	report := authorization.authorization_report with input as {}
	is_object(report)
	count(report) == 9
	report.emergency_ok == true
	report.jewel_constraints_met == true
	report.ai_system_id == "unknown"
	report.ai_system_role == "unknown"
	report.authorized == false
	report.ai_system_valid == false
	report.approval_obtained == false
	report.justification_valid == false
	is_object(report.approval_requirements)
}
