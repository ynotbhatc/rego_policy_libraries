# Unit tests for scuba_m365.exo (Exchange Online — MS.EXO baseline).
# One test per violation rule (fires exactly that rule), a compliant test,
# and an empty-input populated-report test. Rego v1. Part of v2.0.0 hardening.

package scuba_m365.exo_test

import data.scuba_m365.exo
import rego.v1

# Fully-compliant Exchange Online facts — every control passes.
compliant_input := {"scuba": {"exo": {
	"auto_forwarding_disabled": true,
	"spf_fail_policy_all_domains": true,
	"dkim_enabled_all_domains": true,
	"dmarc": {
		"published_all_domains": true,
		"policy_reject": true,
		"rua_includes_cisa": true,
		"agency_poc_included": true,
	},
	"smtp_auth_disabled": true,
	"sharing": {
		"contacts_not_all_domains": true,
		"calendar_not_all_domains": true,
	},
	"external_sender_warnings": true,
	"mailbox_auditing_enabled": true,
}}}

# Compliant base minus exactly one control (JSON pointer path set to false).
one_off(path) := json.patch(compliant_input, [{"op": "replace", "path": path, "value": false}])

# ── Compliant input: no violations ───────────────────────────────────────────

test_compliant_input_no_violations if {
	r := exo.compliance_report with input as compliant_input
	r.compliant == true
	r.violation_count == 0
}

# ── One test per violation rule ──────────────────────────────────────────────

test_exo_1_1_auto_forwarding if {
	i := one_off("/scuba/exo/auto_forwarding_disabled")
	exo.compliant == false with input as i
	count(exo.violations) == 1 with input as i
	some msg in exo.violations with input as i
	contains(msg, "MS.EXO.1.1")
}

test_exo_2_2_spf if {
	i := one_off("/scuba/exo/spf_fail_policy_all_domains")
	count(exo.violations) == 1 with input as i
	some msg in exo.violations with input as i
	contains(msg, "MS.EXO.2.2")
}

test_exo_3_1_dkim if {
	i := one_off("/scuba/exo/dkim_enabled_all_domains")
	count(exo.violations) == 1 with input as i
	some msg in exo.violations with input as i
	contains(msg, "MS.EXO.3.1")
}

test_exo_4_1_dmarc_published if {
	i := one_off("/scuba/exo/dmarc/published_all_domains")
	count(exo.violations) == 1 with input as i
	some msg in exo.violations with input as i
	contains(msg, "MS.EXO.4.1")
}

test_exo_4_2_dmarc_reject if {
	i := one_off("/scuba/exo/dmarc/policy_reject")
	count(exo.violations) == 1 with input as i
	some msg in exo.violations with input as i
	contains(msg, "MS.EXO.4.2")
}

test_exo_4_3_dmarc_rua_cisa if {
	i := one_off("/scuba/exo/dmarc/rua_includes_cisa")
	count(exo.violations) == 1 with input as i
	some msg in exo.violations with input as i
	contains(msg, "MS.EXO.4.3")
}

test_exo_4_4_dmarc_agency_poc if {
	i := one_off("/scuba/exo/dmarc/agency_poc_included")
	count(exo.violations) == 1 with input as i
	some msg in exo.violations with input as i
	contains(msg, "MS.EXO.4.4")
}

test_exo_5_1_smtp_auth if {
	i := one_off("/scuba/exo/smtp_auth_disabled")
	count(exo.violations) == 1 with input as i
	some msg in exo.violations with input as i
	contains(msg, "MS.EXO.5.1")
}

test_exo_6_1_contacts_sharing if {
	i := one_off("/scuba/exo/sharing/contacts_not_all_domains")
	count(exo.violations) == 1 with input as i
	some msg in exo.violations with input as i
	contains(msg, "MS.EXO.6.1")
}

test_exo_6_2_calendar_sharing if {
	i := one_off("/scuba/exo/sharing/calendar_not_all_domains")
	count(exo.violations) == 1 with input as i
	some msg in exo.violations with input as i
	contains(msg, "MS.EXO.6.2")
}

test_exo_7_1_external_sender_warnings if {
	i := one_off("/scuba/exo/external_sender_warnings")
	count(exo.violations) == 1 with input as i
	some msg in exo.violations with input as i
	contains(msg, "MS.EXO.7.1")
}

test_exo_13_1_mailbox_auditing if {
	i := one_off("/scuba/exo/mailbox_auditing_enabled")
	count(exo.violations) == 1 with input as i
	some msg in exo.violations with input as i
	contains(msg, "MS.EXO.13.1")
}

# ── Report is a populated object on EMPTY input (fail-closed) ─────────────────

test_compliance_report_populated_on_empty_input if {
	r := exo.compliance_report with input as {}
	r.product == "Exchange Online"
	r.baseline == "MS.EXO"
	r.controls_evaluated == 12
	r.compliant == false
	r.violation_count == 12
	count(r.violations) == 12
}
