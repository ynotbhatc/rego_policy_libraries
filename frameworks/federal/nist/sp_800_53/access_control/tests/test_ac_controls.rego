package nist.sp800_53.access_control_logic_test

# Behaviour tests for the AC checks changed after the 2026-11-17 audit: AC-3 (any approved model),
# AC-7 / AC-11 / AC-14 (organization-defined parameters), AC-11(1), and AC-15 (withdrawn, never a finding).

import data.nist.sp800_53.access_control as ac
import rego.v1

_finding(r, id) := [v | some v in r.violations; startswith(v, concat("", ["NIST ", id, ":"]))]

_ac(x) := r if {
	r := ac.compliance_report with input as {"ac_controls": x}
}

# --- AC-3 -------------------------------------------------------------------

test_ac3_rbac_alone_passes if {
	count(_finding(_ac({"access_enforcement": {"role_based_access_control": true}}), "AC-3")) == 0
}

test_ac3_abac_alone_passes if {
	count(_finding(_ac({"access_enforcement": {"attribute_based_access_control": true}}), "AC-3")) == 0
}

test_ac3_mac_without_dac_or_rbac_passes if {
	r := _ac({"access_enforcement": {"mandatory_access_control": true, "discretionary_access_control": false}})
	count(_finding(r, "AC-3")) == 0
}

test_ac3_no_model_enforced_fails if {
	r := _ac({"access_enforcement": {"mandatory_access_control": false, "role_based_access_control": false}})
	count(_finding(r, "AC-3")) == 1
}

test_ac3_missing_evidence_fails if {
	f := _finding(_ac({}), "AC-3")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_ac3_string_true_is_not_evidence if {
	count(_finding(_ac({"access_enforcement": {"role_based_access_control": "true"}}), "AC-3")) == 1
}

# --- AC-7 -------------------------------------------------------------------

_ac7(x) := _ac({"logon_attempts": x})

test_ac7_within_org_limit_passes if {
	r := _ac7({"lockout_configured": true, "maximum_attempts": 10, "lockout_duration": 30, "odp": {"max_attempts": 10, "lockout_duration": 30}})
	count(_finding(r, "AC-7")) == 0
}

test_ac7_org_limit_not_nist_fixed_five if {
	# 8 attempts would have failed the old hard-coded "max 5"; the organisation defined 10.
	r := _ac7({"lockout_configured": true, "maximum_attempts": 8, "odp": {"max_attempts": 10}})
	count(_finding(r, "AC-7")) == 0
}

test_ac7_above_org_limit_fails if {
	r := _ac7({"lockout_configured": true, "maximum_attempts": 6, "odp": {"max_attempts": 3}})
	count(_finding(r, "AC-7")) == 1
}

test_ac7_lockout_shorter_than_org_period_fails if {
	r := _ac7({"lockout_configured": true, "maximum_attempts": 3, "lockout_duration": 5, "odp": {"max_attempts": 3, "lockout_duration": 30}})
	count(_finding(r, "AC-7")) == 1
}

test_ac7_no_lockout_action_fails if {
	r := _ac7({"lockout_configured": false, "maximum_attempts": 3, "odp": {"max_attempts": 3}})
	count(_finding(r, "AC-7")) == 1
}

test_ac7_missing_odp_is_missing_evidence if {
	f := _finding(_ac7({"lockout_configured": true, "maximum_attempts": 3, "lockout_duration": 30}), "AC-7")
	count(f) == 1
	contains(f[0], "evidence missing")
	contains(f[0], "odp.max_attempts")
}

test_ac7_missing_configured_value_is_missing_evidence if {
	f := _finding(_ac7({"lockout_configured": true, "odp": {"max_attempts": 3}}), "AC-7")
	count(f) == 1
	contains(f[0], "maximum_attempts")
}

# --- AC-11 / AC-11(1) -------------------------------------------------------

_ac11(x) := _ac({"session_lock": x})

test_ac11_within_org_period_passes if {
	r := _ac11({"inactivity_timeout": 1800, "authentication_required": true, "pattern_hiding": true, "odp": {"inactivity_timeout": 1800}})
	count(_finding(r, "AC-11")) == 0
	count(_finding(r, "AC-11(1)")) == 0
}

test_ac11_longer_than_org_period_fails if {
	r := _ac11({"inactivity_timeout": 1800, "authentication_required": true, "odp": {"inactivity_timeout": 900}})
	count(_finding(r, "AC-11")) == 1
}

test_ac11_lock_not_retained_until_reauth_fails if {
	r := _ac11({"inactivity_timeout": 600, "authentication_required": false, "odp": {"inactivity_timeout": 900}})
	count(_finding(r, "AC-11")) == 1
}

test_ac11_missing_odp_is_missing_evidence if {
	f := _finding(_ac11({"inactivity_timeout": 600, "authentication_required": true}), "AC-11")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_ac11_pattern_hiding_is_its_own_enhancement if {
	r := _ac11({"inactivity_timeout": 600, "authentication_required": true, "pattern_hiding": false, "odp": {"inactivity_timeout": 900}})
	count(_finding(r, "AC-11")) == 0
	count(_finding(r, "AC-11(1)")) == 1
}

test_ac11_1_missing_evidence_fails if {
	count(_finding(_ac({}), "AC-11(1)")) == 1
}

# --- AC-14 ------------------------------------------------------------------

_ac14(x) := _ac({"permitted_actions": x})

test_ac14_org_approved_list_passes if {
	r := _ac14({"unauthenticated_functions": ["status_page", "password_reset_start", "docs"], "organization_approved_functions": ["status_page", "password_reset_start", "docs"], "rationale_documented": true})
	count(_finding(r, "AC-14")) == 0
}

test_ac14_unapproved_function_fails if {
	r := _ac14({"unauthenticated_functions": ["status_page", "admin_console"], "organization_approved_functions": ["status_page"], "rationale_documented": true})
	f := _finding(r, "AC-14")
	count(f) == 1
	contains(f[0], "admin_console")
}

test_ac14_rationale_not_documented_fails if {
	r := _ac14({"unauthenticated_functions": [], "organization_approved_functions": [], "rationale_documented": false})
	count(_finding(r, "AC-14")) == 1
}

test_ac14_missing_approved_list_is_missing_evidence if {
	f := _finding(_ac14({"unauthenticated_functions": ["system_status"], "rationale_documented": true}), "AC-14")
	count(f) == 1
	contains(f[0], "evidence missing")
}

# --- AC-15 withdrawn ----------------------------------------------------------

test_ac15_withdrawn_never_a_finding if {
	count(_finding(_ac({}), "AC-15")) == 0
	r := ac.compliance_report with input as {}
	every v in r.violations {
		not contains(v, "AC-15")
	}
	not "AC-15" in ac.evaluated_controls
}

# --- report contract ---------------------------------------------------------

test_ac_one_finding_per_evaluated_id_on_empty_input if {
	r := ac.compliance_report with input as {}
	r.controls_evaluated == 24
	count(r.violations) == 24
	every id in ac.evaluated_controls {
		count(_finding(r, id)) == 1
	}
}
