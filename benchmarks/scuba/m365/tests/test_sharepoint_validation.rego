# Unit tests for benchmarks/scuba/m365/sharepoint_validation.rego
# (package scuba_m365.sharepoint) — CISA SCuBA SharePoint Online / OneDrive.
# One test per violation rule (MS.SHAREPOINT.1.1–3.3), plus a compliant case
# and an empty-input report-populated case. Rego v1.

package scuba_m365.sharepoint_test

import data.scuba_m365.sharepoint
import rego.v1

# Fully compliant input — every SHALL satisfied. Each single-rule test below
# starts from this and breaks exactly one field.
compliant_input := {"scuba": {"sharepoint": {
	"external_sharing": {
		"spo_restricted": true,
		"odb_restricted": true,
		"domain_allowlist": true,
	},
	"default_sharing": {
		"scope_specific_people": true,
		"permission_view_only": true,
	},
	"anyone_links": {
		"expiration_days": 30,
		"view_only": true,
	},
	"verification_code_reauth_days": 30,
}}}

# Assert exactly one violation fires and its message contains the control id.
one_violation_matching(in_val, control_id) if {
	v := sharepoint.violations with input as in_val
	count(v) == 1
	some msg in v
	contains(msg, control_id)
}

# ── MS.SHAREPOINT.1.1 — SPO external sharing restricted ──────────────────────
test_sharepoint_1_1_spo_external_sharing if {
	i := json.patch(compliant_input, [{"op": "replace", "path": "/scuba/sharepoint/external_sharing/spo_restricted", "value": false}])
	one_violation_matching(i, "MS.SHAREPOINT.1.1")
}

# ── MS.SHAREPOINT.1.2 — OneDrive external sharing restricted ──────────────────
test_sharepoint_1_2_odb_external_sharing if {
	i := json.patch(compliant_input, [{"op": "replace", "path": "/scuba/sharepoint/external_sharing/odb_restricted", "value": false}])
	one_violation_matching(i, "MS.SHAREPOINT.1.2")
}

# ── MS.SHAREPOINT.1.3 — external sharing domain allowlist ─────────────────────
test_sharepoint_1_3_domain_allowlist if {
	i := json.patch(compliant_input, [{"op": "replace", "path": "/scuba/sharepoint/external_sharing/domain_allowlist", "value": false}])
	one_violation_matching(i, "MS.SHAREPOINT.1.3")
}

# ── MS.SHAREPOINT.2.1 — default sharing scope 'Specific people' ───────────────
test_sharepoint_2_1_default_scope if {
	i := json.patch(compliant_input, [{"op": "replace", "path": "/scuba/sharepoint/default_sharing/scope_specific_people", "value": false}])
	one_violation_matching(i, "MS.SHAREPOINT.2.1")
}

# ── MS.SHAREPOINT.2.2 — default sharing permission view-only ──────────────────
test_sharepoint_2_2_default_permission if {
	i := json.patch(compliant_input, [{"op": "replace", "path": "/scuba/sharepoint/default_sharing/permission_view_only", "value": false}])
	one_violation_matching(i, "MS.SHAREPOINT.2.2")
}

# ── MS.SHAREPOINT.3.1 — anyone-link expiration <= 30 days ─────────────────────
test_sharepoint_3_1_anyone_link_expiration if {
	i := json.patch(compliant_input, [{"op": "replace", "path": "/scuba/sharepoint/anyone_links/expiration_days", "value": 60}])
	one_violation_matching(i, "MS.SHAREPOINT.3.1")
}

# ── MS.SHAREPOINT.3.2 — anyone-link view-only ─────────────────────────────────
test_sharepoint_3_2_anyone_link_view_only if {
	i := json.patch(compliant_input, [{"op": "replace", "path": "/scuba/sharepoint/anyone_links/view_only", "value": false}])
	one_violation_matching(i, "MS.SHAREPOINT.3.2")
}

# ── MS.SHAREPOINT.3.3 — verification-code reauth <= 30 days ────────────────────
test_sharepoint_3_3_verification_reauth if {
	i := json.patch(compliant_input, [{"op": "replace", "path": "/scuba/sharepoint/verification_code_reauth_days", "value": 90}])
	one_violation_matching(i, "MS.SHAREPOINT.3.3")
}

# ── Compliant input — zero violations, compliant true ─────────────────────────
test_sharepoint_compliant_input_no_violations if {
	r := sharepoint.compliance_report with input as compliant_input
	r.compliant == true
	r.violation_count == 0
	count(r.violations) == 0
}

# ── Empty input {} — report is a populated object, fails closed ──────────────
test_sharepoint_empty_input_report_populated if {
	r := sharepoint.compliance_report with input as {}
	r.compliant == false
	r.violation_count == 8
	count(r.violations) == 8
	r.baseline == "MS.SHAREPOINT"
	r.controls_evaluated == 8
}
