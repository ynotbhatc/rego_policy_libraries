# Unit tests for scuba_m365.defender (MS.DEFENDER.* — CISA SCuBA M365).
# One test per violation rule (each firing exactly that rule), a compliant
# case, and a populated-report-on-empty-input case. v2.0.0 test hardening.
package scuba_m365.defender_test

import data.scuba_m365.defender
import rego.v1

# Fully-compliant input — every boolean fact the module reads set true, so
# zero violations fire. Each violation test flips exactly one field false via
# json.patch and asserts only that rule fires.
compliant_input := {"scuba": {"defender": {
	"presets": {
		"standard_strict_enabled": true,
		"eop_all_users": true,
		"atp_all_users": true,
		"eop_sensitive_strict": true,
		"atp_sensitive_strict": true,
	},
	"impersonation": {
		"user_protection_sensitive": true,
		"domain_protection_owned": true,
		"domain_protection_partners": true,
	},
	"safe_attachments": {"spo_odb_teams_enabled": true},
	"dlp": {
		"custom_pii_policy": true,
		"applied_all_workloads": true,
		"block_everyone_action": true,
		"user_notifications": true,
		"restricted_apps_list": true,
		"restricted_apps_blocked": true,
	},
	"alerts": {
		"required_exo_alerts_enabled": true,
		"routed_to_monitored_target": true,
	},
	"audit": {
		"unified_logging_enabled": true,
		"retention_meets_m2131": true,
	},
}}}

# Set exactly one nested field false against the compliant baseline.
_flip(path) := json.patch(compliant_input, [{"op": "replace", "path": path, "value": false}])

# ── Compliant baseline ───────────────────────────────────────────────────────

test_compliant_when_all_fields_true if {
	defender.compliant with input as compliant_input
	count(defender.violations) == 0 with input as compliant_input
}

# ── Group 1 — Preset Security Profiles ───────────────────────────────────────

test_defender_1_1_standard_strict if {
	v := defender.violations with input as _flip("/scuba/defender/presets/standard_strict_enabled")
	count(v) == 1
	some m in v
	contains(m, "MS.DEFENDER.1.1v1")
}

test_defender_1_2_eop_all_users if {
	v := defender.violations with input as _flip("/scuba/defender/presets/eop_all_users")
	count(v) == 1
	some m in v
	contains(m, "MS.DEFENDER.1.2v1")
}

test_defender_1_3_atp_all_users if {
	v := defender.violations with input as _flip("/scuba/defender/presets/atp_all_users")
	count(v) == 1
	some m in v
	contains(m, "MS.DEFENDER.1.3v1")
}

test_defender_1_4_eop_sensitive_strict if {
	v := defender.violations with input as _flip("/scuba/defender/presets/eop_sensitive_strict")
	count(v) == 1
	some m in v
	contains(m, "MS.DEFENDER.1.4v1")
}

test_defender_1_5_atp_sensitive_strict if {
	v := defender.violations with input as _flip("/scuba/defender/presets/atp_sensitive_strict")
	count(v) == 1
	some m in v
	contains(m, "MS.DEFENDER.1.5v1")
}

# ── Group 2 — Impersonation Protection ───────────────────────────────────────

test_defender_2_1_user_protection_sensitive if {
	v := defender.violations with input as _flip("/scuba/defender/impersonation/user_protection_sensitive")
	count(v) == 1
	some m in v
	contains(m, "MS.DEFENDER.2.1v1")
}

test_defender_2_2_domain_protection_owned if {
	v := defender.violations with input as _flip("/scuba/defender/impersonation/domain_protection_owned")
	count(v) == 1
	some m in v
	contains(m, "MS.DEFENDER.2.2v1")
}

test_defender_2_3_domain_protection_partners if {
	v := defender.violations with input as _flip("/scuba/defender/impersonation/domain_protection_partners")
	count(v) == 1
	some m in v
	contains(m, "MS.DEFENDER.2.3v1")
}

# ── Group 3 — Safe Attachments ───────────────────────────────────────────────

test_defender_3_1_safe_attachments if {
	v := defender.violations with input as _flip("/scuba/defender/safe_attachments/spo_odb_teams_enabled")
	count(v) == 1
	some m in v
	contains(m, "MS.DEFENDER.3.1v1")
}

# ── Group 4 — Data Loss Prevention ───────────────────────────────────────────

test_defender_4_1_custom_pii_policy if {
	v := defender.violations with input as _flip("/scuba/defender/dlp/custom_pii_policy")
	count(v) == 1
	some m in v
	contains(m, "MS.DEFENDER.4.1v2")
}

test_defender_4_2_applied_all_workloads if {
	v := defender.violations with input as _flip("/scuba/defender/dlp/applied_all_workloads")
	count(v) == 1
	some m in v
	contains(m, "MS.DEFENDER.4.2v1")
}

test_defender_4_3_block_everyone_action if {
	v := defender.violations with input as _flip("/scuba/defender/dlp/block_everyone_action")
	count(v) == 1
	some m in v
	contains(m, "MS.DEFENDER.4.3v1")
}

test_defender_4_4_user_notifications if {
	v := defender.violations with input as _flip("/scuba/defender/dlp/user_notifications")
	count(v) == 1
	some m in v
	contains(m, "MS.DEFENDER.4.4v1")
}

test_defender_4_5_restricted_apps_list if {
	v := defender.violations with input as _flip("/scuba/defender/dlp/restricted_apps_list")
	count(v) == 1
	some m in v
	contains(m, "MS.DEFENDER.4.5v1")
}

test_defender_4_6_restricted_apps_blocked if {
	v := defender.violations with input as _flip("/scuba/defender/dlp/restricted_apps_blocked")
	count(v) == 1
	some m in v
	contains(m, "MS.DEFENDER.4.6v1")
}

# ── Group 5 — Alerts ─────────────────────────────────────────────────────────

test_defender_5_1_required_exo_alerts if {
	v := defender.violations with input as _flip("/scuba/defender/alerts/required_exo_alerts_enabled")
	count(v) == 1
	some m in v
	contains(m, "MS.DEFENDER.5.1v1")
}

test_defender_5_2_routed_to_monitored_target if {
	v := defender.violations with input as _flip("/scuba/defender/alerts/routed_to_monitored_target")
	count(v) == 1
	some m in v
	contains(m, "MS.DEFENDER.5.2v1")
}

# ── Group 6 — Audit Logging ──────────────────────────────────────────────────

test_defender_6_1_unified_logging if {
	v := defender.violations with input as _flip("/scuba/defender/audit/unified_logging_enabled")
	count(v) == 1
	some m in v
	contains(m, "MS.DEFENDER.6.1v1")
}

test_defender_6_3_retention_meets_m2131 if {
	v := defender.violations with input as _flip("/scuba/defender/audit/retention_meets_m2131")
	count(v) == 1
	some m in v
	contains(m, "MS.DEFENDER.6.3v1")
}

# ── Report shape ─────────────────────────────────────────────────────────────

# Fail-closed: empty input fires all 19 policies and still yields a populated
# report object (not {} — every field is sourced through defaulted helpers).
test_report_populated_on_empty_input if {
	r := defender.compliance_report with input as {}
	r.compliant == false
	r.violation_count == 19
	r.controls_evaluated == 19
	r.product == "Microsoft Defender for Office 365"
	count(r.violations) == 19
}
