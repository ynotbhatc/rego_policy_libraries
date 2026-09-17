# CISA SCuBA — Secure Configuration Baseline for Microsoft Defender for
# Office 365 — 19 policies (MS.DEFENDER.*), per cisagov/ScubaGear
# (TLP:CLEAR). MS.DEFENDER.6.2 was removed upstream and is absent here.
#
# Input contract — input.scuba.defender.* (sources: Exchange Online /
# Security & Compliance PowerShell — Get-EOPProtectionPolicyRule,
# Get-ATPProtectionPolicyRule, Get-AntiPhishPolicy, Get-DlpCompliancePolicy,
# Get-ProtectionAlert, Get-AdminAuditLogConfig; a collector projects them
# to the fields below — absence fails closed):
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
# OPA query path (module): /v1/data/scuba_m365/defender/compliance_report

package scuba_m365.defender

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

# ── Group 1 — Preset Security Profiles ───────────────────────────────────────

violations contains msg if {
	not input.scuba.defender.presets.standard_strict_enabled
	msg := "SCuBA MS.DEFENDER.1.1v1 (SHALL): Standard and strict preset security policies are not enabled"
}

violations contains msg if {
	not input.scuba.defender.presets.eop_all_users
	msg := "SCuBA MS.DEFENDER.1.2v1 (SHALL): Not all users are covered by Exchange Online Protection in a preset security policy"
}

violations contains msg if {
	not input.scuba.defender.presets.atp_all_users
	msg := "SCuBA MS.DEFENDER.1.3v1 (SHALL): Not all users are covered by Defender for Office 365 protection in a preset security policy"
}

violations contains msg if {
	not input.scuba.defender.presets.eop_sensitive_strict
	msg := "SCuBA MS.DEFENDER.1.4v1 (SHALL): Sensitive accounts are not in Exchange Online Protection under the strict preset policy"
}

violations contains msg if {
	not input.scuba.defender.presets.atp_sensitive_strict
	msg := "SCuBA MS.DEFENDER.1.5v1 (SHALL): Sensitive accounts are not in Defender for Office 365 protection under the strict preset policy"
}

# ── Group 2 — Impersonation Protection ───────────────────────────────────────

violations contains msg if {
	not input.scuba.defender.impersonation.user_protection_sensitive
	msg := "SCuBA MS.DEFENDER.2.1v1 (SHOULD): User impersonation protection is not enabled for sensitive accounts in the preset policies"
}

violations contains msg if {
	not input.scuba.defender.impersonation.domain_protection_owned
	msg := "SCuBA MS.DEFENDER.2.2v1 (SHOULD): Domain impersonation protection is not enabled for agency-owned domains in the preset policies"
}

violations contains msg if {
	not input.scuba.defender.impersonation.domain_protection_partners
	msg := "SCuBA MS.DEFENDER.2.3v1 (SHOULD): Domain impersonation protection is not configured for key suppliers and partners"
}

# ── Group 3 — Safe Attachments ───────────────────────────────────────────────

violations contains msg if {
	not input.scuba.defender.safe_attachments.spo_odb_teams_enabled
	msg := "SCuBA MS.DEFENDER.3.1v1 (SHOULD): Safe Attachments is not enabled for SharePoint, OneDrive, and Microsoft Teams"
}

# ── Group 4 — Data Loss Prevention ───────────────────────────────────────────

violations contains msg if {
	not input.scuba.defender.dlp.custom_pii_policy
	msg := "SCuBA MS.DEFENDER.4.1v2 (SHALL): No custom DLP policy protects PII/sensitive information (at minimum credit card numbers and U.S. TINs/SSNs)"
}

violations contains msg if {
	not input.scuba.defender.dlp.applied_all_workloads
	msg := "SCuBA MS.DEFENDER.4.2v1 (SHOULD): Custom DLP policy is not applied to Exchange, OneDrive, SharePoint, Teams chat, and Devices"
}

violations contains msg if {
	not input.scuba.defender.dlp.block_everyone_action
	msg := "SCuBA MS.DEFENDER.4.3v1 (SHOULD): Custom DLP policy action is not set to block sharing sensitive information with everyone"
}

violations contains msg if {
	not input.scuba.defender.dlp.user_notifications
	msg := "SCuBA MS.DEFENDER.4.4v1 (SHOULD): User notifications on sensitive-information handling are not enabled in the custom DLP policy"
}

violations contains msg if {
	not input.scuba.defender.dlp.restricted_apps_list
	msg := "SCuBA MS.DEFENDER.4.5v1 (SHOULD): No list of apps restricted from accessing DLP-protected files is defined"
}

violations contains msg if {
	not input.scuba.defender.dlp.restricted_apps_blocked
	msg := "SCuBA MS.DEFENDER.4.6v1 (SHOULD): Custom DLP policy does not block restricted apps and unwanted Bluetooth applications from sensitive information"
}

# ── Group 5 — Alerts ─────────────────────────────────────────────────────────

violations contains msg if {
	not input.scuba.defender.alerts.required_exo_alerts_enabled
	msg := "SCuBA MS.DEFENDER.5.1v1 (SHALL): Alerts required by the Exchange Online baseline are not enabled"
}

violations contains msg if {
	not input.scuba.defender.alerts.routed_to_monitored_target
	msg := "SCuBA MS.DEFENDER.5.2v1 (SHOULD): Alerts are not sent to a monitored address or SIEM"
}

# ── Group 6 — Audit Logging ──────────────────────────────────────────────────

violations contains msg if {
	not input.scuba.defender.audit.unified_logging_enabled
	msg := "SCuBA MS.DEFENDER.6.1v1 (SHALL): Unified audit logging is not enabled"
}

violations contains msg if {
	not input.scuba.defender.audit.retention_meets_m2131
	msg := "SCuBA MS.DEFENDER.6.3v1 (SHALL): Audit logs are not retained for the minimum duration required by OMB M-21-31"
}

# ── Report ───────────────────────────────────────────────────────────────────

shall_violations := [v | some v in violations; contains(v, "(SHALL)")]

should_violations := [v | some v in violations; contains(v, "(SHOULD)")]

compliance_report := {
	"product": "Microsoft Defender for Office 365",
	"baseline": "MS.DEFENDER",
	"controls_evaluated": 19,
	"compliant": compliant,
	"violations": violations,
	"violation_count": count(violations),
	"shall_violation_count": count(shall_violations),
	"should_violation_count": count(should_violations),
}
