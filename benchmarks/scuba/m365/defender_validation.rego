# DEPRECATED compatibility shim — CISA SCuBA Microsoft Defender for Office
# 365 baseline (MS.DEFENDER.*, 19 policies). ScubaGear v2.0.0 (2026-10-22)
# removed this baseline upstream and replaced it with the Security Suite
# baseline, implemented in scuba_m365.securitysuite
# (securitysuite_validation.rego, input scuba.securitysuite.*). This package
# keeps /v1/data/scuba_m365/defender/compliance_report and the
# scuba.defender.* input working for one release so existing collectors and
# callers do not break; it is removed in the next minor release. It is not
# part of the scuba_m365.main orchestrator totals.
#
# How it evaluates:
#   - The 11 policies whose Security Suite successor reads the same fact
#     (one-to-one field) are evaluated by scuba_m365.securitysuite on the
#     translated input (as_securitysuite_input) and reported under the old
#     MS.DEFENDER id with the successor id noted:
#       MS.DEFENDER.2.1-2.3  -> MS.SECURITYSUITE.2.1-2.3
#       MS.DEFENDER.3.1      -> MS.SECURITYSUITE.1.4
#       MS.DEFENDER.4.1-4.4  -> MS.SECURITYSUITE.3.1-3.4
#       MS.DEFENDER.4.6      -> MS.SECURITYSUITE.3.5
#       MS.DEFENDER.5.2      -> MS.SECURITYSUITE.4.2
#       MS.DEFENDER.6.1      -> MS.SECURITYSUITE.5.1
#   - The 8 policies without a one-to-one successor keep their original
#     rule on the original fact: MS.DEFENDER.1.1-1.5 (preset policies,
#     reworked upstream into malware facts), 4.5 (removed upstream, not
#     automatable), 5.1 (a single boolean vs the seven named alerts of
#     MS.SECURITYSUITE.4.1) and 6.3 (M-21-31 boolean vs the 90/365-day
#     thresholds of MS.SECURITYSUITE.5.2).
#
# Input contract — input.scuba.defender.* (unchanged; absence fails closed):
#
#   presets.{standard_strict_enabled, eop_all_users, atp_all_users,
#            eop_sensitive_strict, atp_sensitive_strict}   MS.DEFENDER.1.1-1.5
#   impersonation.{user_protection_sensitive, domain_protection_owned,
#            domain_protection_partners}                   MS.DEFENDER.2.1-2.3
#   safe_attachments.spo_odb_teams_enabled                 MS.DEFENDER.3.1
#   dlp.{custom_pii_policy, applied_all_workloads, block_everyone_action,
#        user_notifications, restricted_apps_list,
#        restricted_apps_blocked}                          MS.DEFENDER.4.1-4.6
#   alerts.{required_exo_alerts_enabled, routed_to_monitored_target}
#                                                          MS.DEFENDER.5.1-5.2
#   audit.{unified_logging_enabled, retention_meets_m2131}
#                                                          MS.DEFENDER.6.1,6.3
#
# OPA query path (module, deprecated): /v1/data/scuba_m365/defender/compliance_report

# METADATA
# title: "DEPRECATED — CISA SCuBA Microsoft Defender for Office 365 baseline (MS.DEFENDER.*, 19 policies), compatibility shim over scuba_m365.securitysuite; removed upstream in ScubaGear v2.0.0"
# custom:
#   class: security
#   framework: scuba_m365
#   source: cisa
#   domains: [saas, m365]
#   deprecated: "MS.DEFENDER baseline removed upstream in ScubaGear v2.0.0; use scuba_m365.securitysuite; this shim is removed in the next minor release"
#   coverage:
#     checks: 19
#     cited: 19
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package scuba_m365.defender

import data.scuba_m365.securitysuite
import rego.v1

DEPRECATION_NOTICE := "MS.DEFENDER baseline removed upstream in ScubaGear v2.0.0; use scuba_m365.securitysuite; this shim is removed in the next minor release"

default compliant := false

compliant if {
	count(violations) == 0
}

_d := object.get(input, ["scuba", "defender"], {})

_fact(path) := object.get(_d, path, false)

# The one-to-one facts, projected to their scuba.securitysuite.* paths (the
# field names are the same). Facts with no one-to-one successor are left
# out, so the Security Suite policies that need them fail closed.
as_securitysuite_input := {
	"safe_attachments": {"spo_odb_teams_enabled": _fact(["safe_attachments", "spo_odb_teams_enabled"])},
	"impersonation": {
		"user_protection_sensitive": _fact(["impersonation", "user_protection_sensitive"]),
		"domain_protection_owned": _fact(["impersonation", "domain_protection_owned"]),
		"domain_protection_partners": _fact(["impersonation", "domain_protection_partners"]),
	},
	"dlp": {
		"custom_pii_policy": _fact(["dlp", "custom_pii_policy"]),
		"applied_all_workloads": _fact(["dlp", "applied_all_workloads"]),
		"block_everyone_action": _fact(["dlp", "block_everyone_action"]),
		"user_notifications": _fact(["dlp", "user_notifications"]),
		"restricted_apps_blocked": _fact(["dlp", "restricted_apps_blocked"]),
	},
	"alerts": {"routed_to_monitored_target": _fact(["alerts", "routed_to_monitored_target"])},
	"audit": {"unified_logging_enabled": _fact(["audit", "unified_logging_enabled"])},
}

# Old id -> [Security Suite successor id, original MS.DEFENDER message].
one_to_one := {
	"MS.DEFENDER.2.1v1": ["MS.SECURITYSUITE.2.1v1", "SCuBA MS.DEFENDER.2.1v1 (SHOULD): User impersonation protection is not enabled for sensitive accounts in the preset policies"],
	"MS.DEFENDER.2.2v1": ["MS.SECURITYSUITE.2.2v1", "SCuBA MS.DEFENDER.2.2v1 (SHOULD): Domain impersonation protection is not enabled for agency-owned domains in the preset policies"],
	"MS.DEFENDER.2.3v1": ["MS.SECURITYSUITE.2.3v1", "SCuBA MS.DEFENDER.2.3v1 (SHOULD): Domain impersonation protection is not configured for key suppliers and partners"],
	"MS.DEFENDER.3.1v1": ["MS.SECURITYSUITE.1.4v1", "SCuBA MS.DEFENDER.3.1v1 (SHOULD): Safe Attachments is not enabled for SharePoint, OneDrive, and Microsoft Teams"],
	"MS.DEFENDER.4.1v2": ["MS.SECURITYSUITE.3.1v1", "SCuBA MS.DEFENDER.4.1v2 (SHALL): No custom DLP policy protects PII/sensitive information (at minimum credit card numbers and U.S. TINs/SSNs)"],
	"MS.DEFENDER.4.2v1": ["MS.SECURITYSUITE.3.2v1", "SCuBA MS.DEFENDER.4.2v1 (SHOULD): Custom DLP policy is not applied to Exchange, OneDrive, SharePoint, Teams chat, and Devices"],
	"MS.DEFENDER.4.3v1": ["MS.SECURITYSUITE.3.3v1", "SCuBA MS.DEFENDER.4.3v1 (SHOULD): Custom DLP policy action is not set to block sharing sensitive information with everyone"],
	"MS.DEFENDER.4.4v1": ["MS.SECURITYSUITE.3.4v1", "SCuBA MS.DEFENDER.4.4v1 (SHOULD): User notifications on sensitive-information handling are not enabled in the custom DLP policy"],
	"MS.DEFENDER.4.6v1": ["MS.SECURITYSUITE.3.5v1", "SCuBA MS.DEFENDER.4.6v1 (SHOULD): Custom DLP policy does not block restricted apps and unwanted Bluetooth applications from sensitive information"],
	"MS.DEFENDER.5.2v1": ["MS.SECURITYSUITE.4.2v1", "SCuBA MS.DEFENDER.5.2v1 (SHOULD): Alerts are not sent to a monitored address or SIEM"],
	"MS.DEFENDER.6.1v1": ["MS.SECURITYSUITE.5.1v1", "SCuBA MS.DEFENDER.6.1v1 (SHALL): Unified audit logging is not enabled"],
}

# Ids kept on their original rule (no one-to-one Security Suite successor).
legacy_only := {
	"MS.DEFENDER.1.1v1", "MS.DEFENDER.1.2v1", "MS.DEFENDER.1.3v1",
	"MS.DEFENDER.1.4v1", "MS.DEFENDER.1.5v1", "MS.DEFENDER.4.5v1",
	"MS.DEFENDER.5.1v1", "MS.DEFENDER.6.3v1",
}

_ss_violations := v if {
	v := securitysuite.violations with input.scuba.securitysuite as as_securitysuite_input
}

# ── One-to-one policies, evaluated by the Security Suite module ──────────────

violations contains msg if {
	some entry in one_to_one
	successor := entry[0]
	some v in _ss_violations
	startswith(v, sprintf("SCuBA %s ", [successor]))
	msg := sprintf("%s [evaluated as %s]", [entry[1], successor])
}

# ── Group 1 — Preset Security Profiles (no one-to-one successor) ─────────────

violations contains msg if {
	not _d.presets.standard_strict_enabled == true
	msg := "SCuBA MS.DEFENDER.1.1v1 (SHALL): Standard and strict preset security policies are not enabled"
}

violations contains msg if {
	not _d.presets.eop_all_users == true
	msg := "SCuBA MS.DEFENDER.1.2v1 (SHALL): Not all users are covered by Exchange Online Protection in a preset security policy"
}

violations contains msg if {
	not _d.presets.atp_all_users == true
	msg := "SCuBA MS.DEFENDER.1.3v1 (SHALL): Not all users are covered by Defender for Office 365 protection in a preset security policy"
}

violations contains msg if {
	not _d.presets.eop_sensitive_strict == true
	msg := "SCuBA MS.DEFENDER.1.4v1 (SHALL): Sensitive accounts are not in Exchange Online Protection under the strict preset policy"
}

violations contains msg if {
	not _d.presets.atp_sensitive_strict == true
	msg := "SCuBA MS.DEFENDER.1.5v1 (SHALL): Sensitive accounts are not in Defender for Office 365 protection under the strict preset policy"
}

# ── MS.DEFENDER.4.5 — removed upstream, no successor ─────────────────────────

violations contains msg if {
	not _d.dlp.restricted_apps_list == true
	msg := "SCuBA MS.DEFENDER.4.5v1 (SHOULD): No list of apps restricted from accessing DLP-protected files is defined"
}

# ── MS.DEFENDER.5.1 and 6.3 — successor reads different facts ────────────────

violations contains msg if {
	not _d.alerts.required_exo_alerts_enabled == true
	msg := "SCuBA MS.DEFENDER.5.1v1 (SHALL): Alerts required by the Exchange Online baseline are not enabled"
}

violations contains msg if {
	not _d.audit.retention_meets_m2131 == true
	msg := "SCuBA MS.DEFENDER.6.3v1 (SHALL): Audit logs are not retained for the minimum duration required by OMB M-21-31"
}

# ── Report ───────────────────────────────────────────────────────────────────

shall_violations := [v | some v in violations; contains(v, "(SHALL)")]

should_violations := [v | some v in violations; contains(v, "(SHOULD)")]

successor_map := object.union(
	{old: entry[0] | some old, entry in one_to_one},
	{old: null | some old in legacy_only},
)

compliance_report := {
	"product": "Microsoft Defender for Office 365",
	"baseline": "MS.DEFENDER",
	"deprecated": DEPRECATION_NOTICE,
	"successor": "scuba_m365.securitysuite",
	"successor_ids": successor_map,
	"controls_evaluated": 19,
	"compliant": compliant,
	"violations": violations,
	"violation_count": count(violations),
	"shall_violation_count": count(shall_violations),
	"should_violation_count": count(should_violations),
}
