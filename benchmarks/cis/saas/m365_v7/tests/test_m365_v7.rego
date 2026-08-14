package cis_m365_v7_test

import data.cis_m365_v7.admin_center
import data.cis_m365_v7.defender
import data.cis_m365_v7.entra
import data.cis_m365_v7.exchange
import data.cis_m365_v7.main
import data.cis_m365_v7.purview
import data.cis_m365_v7.sharepoint
import rego.v1

# ── Fail-closed behaviour ─────────────────────────────────────────────
# The defect class this library exists to avoid is a green result that was
# never actually established. Absent facts must produce a violation and a
# false `compliant`, never silence.

test_admin_center_absent_facts_is_not_a_pass if {
	r := admin_center.compliance_report with input as {}
	r.compliant == false
	r.facts_present == false
	count(r.violations) == 1
}

test_defender_absent_facts_is_not_a_pass if {
	r := defender.compliance_report with input as {}
	r.compliant == false
	count(r.violations) == 1
}

test_entra_absent_facts_is_not_a_pass if {
	r := entra.compliance_report with input as {}
	r.compliant == false
}

test_sharepoint_unreachable_settings_is_not_a_pass if {
	r := sharepoint.compliance_report with input as {"sharepoint": {"settings_reachable": false}}
	r.compliant == false
}

test_reports_never_collapse_to_empty_object if {
	# A single undefined field turns the whole object into {} at the OPA
	# endpoint. Assert every report is populated under empty input.
	count(admin_center.compliance_report) > 0 with input as {}
	count(defender.compliance_report) > 0 with input as {}
	count(purview.compliance_report) > 0 with input as {}
	count(entra.compliance_report) > 0 with input as {}
	count(exchange.compliance_report) > 0 with input as {}
	count(sharepoint.compliance_report) > 0 with input as {}
	count(main.compliance_report) > 0 with input as {}
}

# ── CIS 1.1.3 -- between two and four global admins ───────────────────

admins(n) := {"identity": {"global_admins": [{"id": sprintf("u%d", [i])} | some i in numbers.range(1, n)]}}

test_1_1_3_too_few_global_admins if {
	r := admin_center.compliance_report with input as admins(1)
	r.compliant == false
	some v in r.violations
	contains(v, "CIS 1.1.3")
}

test_1_1_3_too_many_global_admins if {
	r := admin_center.compliance_report with input as admins(6)
	r.compliant == false
}

test_1_1_3_three_global_admins_passes if {
	r := admin_center.compliance_report with input as admins(3)
	r.compliant == true
	count(r.violations) == 0
}

# ── CIS 2.1.8 / 2.1.9 / 2.1.10 -- SPF, DKIM, DMARC ────────────────────

domains(spf, dkim, dmarc) := {"exchange": {"verified_domains": [{
	"id": "example.com",
	"spf_present": spf,
	"dkim_present": dkim,
	"dmarc_present": dmarc,
}]}}

test_2_1_8_missing_spf if {
	r := defender.compliance_report with input as domains(false, true, true)
	some v in r.violations
	contains(v, "CIS 2.1.8")
}

test_2_1_9_missing_dkim if {
	r := defender.compliance_report with input as domains(true, false, true)
	some v in r.violations
	contains(v, "CIS 2.1.9")
}

test_2_1_10_missing_dmarc if {
	r := defender.compliance_report with input as domains(true, true, false)
	some v in r.violations
	contains(v, "CIS 2.1.10")
}

test_all_mail_auth_present_passes if {
	r := defender.compliance_report with input as domains(true, true, true)
	r.compliant == true
}

# ── CIS 3.1.1 -- unified audit log ────────────────────────────────────

test_3_1_1_audit_log_unavailable if {
	r := purview.compliance_report with input as {"purview": {"audit_log_accessible": false}}
	r.compliant == false
	some v in r.violations
	contains(v, "CIS 3.1.1")
}

test_3_1_1_audit_log_available_passes if {
	r := purview.compliance_report with input as {"purview": {"audit_log_accessible": true}}
	r.compliant == true
}

# ── CIS 5.2.2.x / 5.3.1 -- Conditional Access and PIM ─────────────────

ca_tenant(policies, pim) := {"identity": {
	"conditional_access_policies": policies,
	"pim_available": pim,
}}

mfa_all_users := {
	"id": "p1",
	"state": "enabled",
	"conditions": {"users": {"includeUsers": ["All"], "includeRoles": []}, "clientAppTypes": ["all"]},
	"grant_controls": {"builtInControls": ["mfa"]},
}

mfa_admins := {
	"id": "p2",
	"state": "enabled",
	"conditions": {"users": {"includeUsers": [], "includeRoles": ["62e90394-role"]}, "clientAppTypes": ["all"]},
	"grant_controls": {"builtInControls": ["mfa"]},
}

block_legacy := {
	"id": "p3",
	"state": "enabled",
	"conditions": {"users": {"includeUsers": ["All"], "includeRoles": []}, "clientAppTypes": ["exchangeActiveSync", "other"]},
	"grant_controls": {"builtInControls": ["block"]},
}

test_5_2_2_2_no_mfa_for_all_users if {
	r := entra.compliance_report with input as ca_tenant([mfa_admins, block_legacy], true)
	some v in r.violations
	contains(v, "CIS 5.2.2.2")
}

test_5_2_2_3_legacy_auth_not_blocked if {
	r := entra.compliance_report with input as ca_tenant([mfa_all_users, mfa_admins], true)
	some v in r.violations
	contains(v, "CIS 5.2.2.3")
}

test_5_3_1_pim_not_in_use if {
	r := entra.compliance_report with input as ca_tenant([mfa_all_users, mfa_admins, block_legacy], false)
	some v in r.violations
	contains(v, "CIS 5.3.1")
}

test_entra_fully_configured_passes if {
	r := entra.compliance_report with input as ca_tenant([mfa_all_users, mfa_admins, block_legacy], true)
	r.compliant == true
	count(r.violations) == 0
}

# A policy that is present but disabled must not satisfy the control.
test_disabled_policy_does_not_satisfy_control if {
	disabled := object.union(mfa_all_users, {"state": "disabled"})
	r := entra.compliance_report with input as ca_tenant([disabled], true)
	some v in r.violations
	contains(v, "CIS 5.2.2.2")
}

# ── CIS 6.1.1 -- mailbox auditing ─────────────────────────────────────

test_6_1_1_audit_disabled_on_sampled_mailboxes if {
	r := exchange.compliance_report with input as {"exchange": {"mailbox_audit_summary": {
		"sampled": 10, "audit_enabled": 7, "audit_disabled": 3, "evaluable": true,
	}}}
	r.compliant == false
	some v in r.violations
	contains(v, "CIS 6.1.1")
}

test_6_1_1_all_audited_passes if {
	r := exchange.compliance_report with input as {"exchange": {"mailbox_audit_summary": {
		"sampled": 10, "audit_enabled": 10, "audit_disabled": 0, "evaluable": true,
	}}}
	r.compliant == true
}

test_6_1_1_declares_proxy_evidence if {
	# The collection limit must stay visible in the report -- a reader has
	# to be able to see that this is weaker than a PowerShell-sourced result.
	r := exchange.compliance_report with input as {}
	contains(r.evidence_strength["6.1.1"], "proxy")
}

# ── CIS 7.2.x -- SharePoint sharing ───────────────────────────────────

sp(cap, link, perm, legacy) := {"sharepoint": {
	"settings_reachable": true,
	"sharing_capability": cap,
	"default_sharing_link_type": link,
	"default_link_permission": perm,
	"legacy_auth_protocols_enabled": legacy,
}}

test_7_2_1_legacy_auth_enabled if {
	r := sharepoint.compliance_report with input as sp("Disabled", "Internal", "View", true)
	some v in r.violations
	contains(v, "CIS 7.2.1")
}

test_7_2_6_most_permissive_sharing if {
	r := sharepoint.compliance_report with input as sp("ExternalUserAndGuestSharing", "Internal", "View", false)
	some v in r.violations
	contains(v, "CIS 7.2.6")
}

test_7_2_7_anonymous_default_link if {
	r := sharepoint.compliance_report with input as sp("Disabled", "AnonymousAccess", "View", false)
	some v in r.violations
	contains(v, "CIS 7.2.7")
}

test_7_2_11_default_link_permission_edit if {
	r := sharepoint.compliance_report with input as sp("Disabled", "Internal", "Edit", false)
	some v in r.violations
	contains(v, "CIS 7.2.11")
}

test_sharepoint_hardened_passes if {
	r := sharepoint.compliance_report with input as sp("Disabled", "Internal", "View", false)
	r.compliant == true
}

# ── Orchestrator accounting ───────────────────────────────────────────

test_orchestrator_reports_partial_coverage_honestly if {
	r := main.compliance_report with input as {}
	r.benchmark_total_controls == 160
	r.controls_evaluated == 14
	r.controls_not_evaluated == 146
	count(r.sections_not_evaluated) == 3
}

test_orchestrator_exposes_no_bare_compliant_field if {
	# Reading `compliant` from a 14-of-160 assessment would be misleading,
	# so the orchestrator must not offer one. Assert on the key set --
	# referencing a statically-absent field is a compile error, not a test.
	r := main.compliance_report with input as {}
	not "compliant" in object.keys(r)
	"assessed_controls_compliant" in object.keys(r)
}

test_orchestrator_scopes_its_verdict_to_evaluated_controls if {
	r := main.compliance_report with input as {}
	r.assessed_controls_compliant == false
	contains(r.interpretation, "partial assessment")
}

test_every_evaluated_id_is_reported if {
	r := main.compliance_report with input as {}
	count(r.evaluated_control_ids) == r.controls_evaluated
}
