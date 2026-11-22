# CISA SCuBA — M365 Secure Configuration Security Suite Baseline — 24
# policies (MS.SECURITYSUITE.*), per cisagov/ScubaGear v2.0.0 (TLP:CLEAR).
#
# ScubaGear v2.0.0 (2026-10-22) removed the Defender baseline (MS.DEFENDER.*)
# and replaced it with this one, which unifies the Defender, Purview, Exchange
# Online and Teams security functions. The functions may be met with Defender
# and Purview or with comparable third-party tools; the facts below describe
# the function, not the product. Rework per removedpolicies.md:
#   MS.DEFENDER.1.1-1.5 (preset policies)  -> MS.SECURITYSUITE.1.1-1.4
#   MS.DEFENDER.2.1-2.3 (impersonation)    -> MS.SECURITYSUITE.2.1-2.3
#   MS.DEFENDER.3.1 (Safe Attachments)     -> MS.SECURITYSUITE.1.4
#   MS.DEFENDER.4.1-4.4, 4.6 (DLP)         -> MS.SECURITYSUITE.3.1-3.5
#   MS.DEFENDER.4.5                        removed (not automatable)
#   MS.DEFENDER.5.1-5.2 (alerts)           -> MS.SECURITYSUITE.4.1-4.2
#   MS.DEFENDER.6.1, 6.3 (audit logging)   -> MS.SECURITYSUITE.5.1-5.2
# Groups 6-8 (anti-spam, link protection, IP allow lists) and 2.4 are new.
#
# Input contract — input.scuba.securitysuite.* (sources, when Defender and
# Purview are used: Get-MalwareFilterPolicy, Get-AntiPhishPolicy,
# Get-HostedContentFilterPolicy, Get-HostedConnectionFilterPolicy,
# Get-SafeLinksPolicy, Get-AtpPolicyForO365, Get-DlpCompliancePolicy /
# Get-DlpComplianceRule, Get-ProtectionAlert, Get-AdminAuditLogConfig;
# a collector projects them to the fields below — absence fails closed):
#
#   malware.{click_to_run_blocked, post_delivery_scan,
#            quarantine_or_drop}                       MS.SECURITYSUITE.1.1-1.3
#   safe_attachments.spo_odb_teams_enabled             MS.SECURITYSUITE.1.4
#   impersonation.{user_protection_sensitive, domain_protection_owned,
#            domain_protection_partners, user_warnings}
#                                                      MS.SECURITYSUITE.2.1-2.4
#   dlp.{custom_pii_policy, applied_all_workloads, block_everyone_action,
#        user_notifications, restricted_apps_blocked}  MS.SECURITYSUITE.3.1-3.5
#   alerts.enabled            list of enabled alert policy names
#   alerts.routed_to_monitored_target                  MS.SECURITYSUITE.4.1-4.2
#   audit.unified_logging_enabled                      MS.SECURITYSUITE.5.1
#   audit.{searchable_retention_days,
#          retrievable_retention_days}  numbers        MS.SECURITYSUITE.5.2
#   antispam.{spam_phish_not_in_inbox, no_allowed_domains}
#                                                      MS.SECURITYSUITE.6.1-6.2
#   links.{url_blocklist_enabled, download_links_scanned,
#          click_tracking_enabled}                     MS.SECURITYSUITE.7.1-7.3
#   allow_lists.{no_ip_allow_list, safe_list_disabled} MS.SECURITYSUITE.8.1-8.2
#
# OPA query path (module): /v1/data/scuba_m365/securitysuite/compliance_report

# METADATA
# title: "CISA SCuBA — M365 Secure Configuration Security Suite Baseline — 24 policies (MS.SECURITYSUITE.*), per cisagov/ScubaGear v2.0.0"
# custom:
#   class: security
#   framework: scuba_m365
#   source: cisa
#   domains: [saas, m365]
#   coverage:
#     checks: 24
#     cited: 24
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package scuba_m365.securitysuite

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

_ss := object.get(input, ["scuba", "securitysuite"], {})

# ── Group 1 — Malware Protection ─────────────────────────────────────────────

violations contains msg if {
	not _ss.malware.click_to_run_blocked == true
	msg := "SCuBA MS.SECURITYSUITE.1.1v1 (SHALL): Emails with click-to-run file attachments (at a minimum .exe, .cmd and .vbe) are not blocked"
}

violations contains msg if {
	not _ss.malware.post_delivery_scan == true
	msg := "SCuBA MS.SECURITYSUITE.1.2v1 (SHALL): Email scanning cannot review emails after delivery"
}

violations contains msg if {
	not _ss.malware.quarantine_or_drop == true
	msg := "SCuBA MS.SECURITYSUITE.1.3v1 (SHALL): Emails identified as containing malware are not quarantined or dropped"
}

violations contains msg if {
	not _ss.safe_attachments.spo_odb_teams_enabled == true
	msg := "SCuBA MS.SECURITYSUITE.1.4v1 (SHOULD): SharePoint, OneDrive and Teams message attachments are not scanned for malware"
}

# ── Group 2 — Impersonation Protection ───────────────────────────────────────

violations contains msg if {
	not _ss.impersonation.user_protection_sensitive == true
	msg := "SCuBA MS.SECURITYSUITE.2.1v1 (SHOULD): User impersonation protection is not enabled for sensitive accounts"
}

violations contains msg if {
	not _ss.impersonation.domain_protection_owned == true
	msg := "SCuBA MS.SECURITYSUITE.2.2v1 (SHOULD): Domain impersonation protection is not enabled for domains owned by the agency"
}

violations contains msg if {
	not _ss.impersonation.domain_protection_partners == true
	msg := "SCuBA MS.SECURITYSUITE.2.3v1 (SHOULD): Domain impersonation protection is not added for key suppliers and partners"
}

violations contains msg if {
	not _ss.impersonation.user_warnings == true
	msg := "SCuBA MS.SECURITYSUITE.2.4v1 (SHOULD): User warnings comparable to the EOP user safety tips are not displayed"
}

# ── Group 3 — Data Loss Prevention ───────────────────────────────────────────

violations contains msg if {
	not _ss.dlp.custom_pii_policy == true
	msg := "SCuBA MS.SECURITYSUITE.3.1v1 (SHALL): No DLP policy protects PII and sensitive information, blocking at a minimum credit card numbers, U.S. ITINs and U.S. SSNs"
}

violations contains msg if {
	not _ss.dlp.applied_all_workloads == true
	msg := "SCuBA MS.SECURITYSUITE.3.2v1 (SHOULD): The DLP policy is not applied to Exchange, OneDrive, SharePoint, Teams chat and Devices"
}

violations contains msg if {
	not _ss.dlp.block_everyone_action == true
	msg := "SCuBA MS.SECURITYSUITE.3.3v1 (SHOULD): The DLP policy action is not set to block sharing sensitive information with everyone"
}

violations contains msg if {
	not _ss.dlp.user_notifications == true
	msg := "SCuBA MS.SECURITYSUITE.3.4v1 (SHOULD): User notifications on the proper use of sensitive information are not enabled in the DLP policy"
}

violations contains msg if {
	not _ss.dlp.restricted_apps_blocked == true
	msg := "SCuBA MS.SECURITYSUITE.3.5v1 (SHOULD): The DLP policy does not block access to sensitive information by restricted applications and unwanted Bluetooth applications"
}

# ── Group 4 — Alerts ─────────────────────────────────────────────────────────

# The seven alerts MS.SECURITYSUITE.4.1v1 names, matched by alert policy name.
required_alerts := {
	"Suspicious email sending patterns detected",
	"Suspicious Connector Activity",
	"Suspicious Email Forwarding Activity",
	"Messages have been delayed",
	"Tenant restricted from sending unprovisioned email",
	"Tenant restricted from sending email",
	"A potentially malicious URL click was detected",
}

_enabled_alerts := {a | some a in _ss.alerts.enabled; is_string(a)} if {
	is_array(_ss.alerts.enabled)
} else := set()

missing_alerts := required_alerts - _enabled_alerts

violations contains msg if {
	count(missing_alerts) > 0
	msg := sprintf("SCuBA MS.SECURITYSUITE.4.1v1 (SHALL): Required alerts are not enabled (missing: %s)", [concat(", ", sort(missing_alerts))])
}

violations contains msg if {
	not _ss.alerts.routed_to_monitored_target == true
	msg := "SCuBA MS.SECURITYSUITE.4.2v1 (SHOULD): Alerts are not sent to a monitored address or incorporated into a SIEM"
}

# ── Group 5 — Audit Logging ──────────────────────────────────────────────────

violations contains msg if {
	not _ss.audit.unified_logging_enabled == true
	msg := "SCuBA MS.SECURITYSUITE.5.1v1 (SHALL): Unified audit logging is not enabled"
}

# 3 months searchable = 90 days; 12 months retrievable = 365 days.
default audit_retention_ok := false

audit_retention_ok if {
	is_number(_ss.audit.searchable_retention_days)
	is_number(_ss.audit.retrievable_retention_days)
	_ss.audit.searchable_retention_days >= 90
	_ss.audit.retrievable_retention_days >= 365
}

violations contains msg if {
	not audit_retention_ok
	msg := "SCuBA MS.SECURITYSUITE.5.2v1 (SHALL): Audit logs are not retained and searchable for at least 3 months (90 days) and retrievable for at least 12 months (365 days)"
}

# ── Group 6 — Inbound Anti-Spam Protections ──────────────────────────────────

violations contains msg if {
	not _ss.antispam.spam_phish_not_in_inbox == true
	msg := "SCuBA MS.SECURITYSUITE.6.1v1 (SHALL): Emails detected as spam or phishing can be delivered to the user's inbox"
}

violations contains msg if {
	not _ss.antispam.no_allowed_domains == true
	msg := "SCuBA MS.SECURITYSUITE.6.2v1 (SHALL): Allowed domains are added to inbound anti-spam protection policies"
}

# ── Group 7 — Link Protection ────────────────────────────────────────────────

violations contains msg if {
	not _ss.links.url_blocklist_enabled == true
	msg := "SCuBA MS.SECURITYSUITE.7.1v1 (SHOULD): URL comparison with a block-list is not enabled for URLs in emails, Teams messages and Office documents"
}

violations contains msg if {
	not _ss.links.download_links_scanned == true
	msg := "SCuBA MS.SECURITYSUITE.7.2v1 (SHOULD): Direct download links are not scanned for malware"
}

violations contains msg if {
	not _ss.links.click_tracking_enabled == true
	msg := "SCuBA MS.SECURITYSUITE.7.3v1 (SHOULD): User click tracking is not enabled"
}

# ── Group 8 — IP Allow Lists ─────────────────────────────────────────────────

violations contains msg if {
	not _ss.allow_lists.no_ip_allow_list == true
	msg := "SCuBA MS.SECURITYSUITE.8.1v1 (SHOULD): An IP allow list is created"
}

violations contains msg if {
	not _ss.allow_lists.safe_list_disabled == true
	msg := "SCuBA MS.SECURITYSUITE.8.2v1 (SHOULD): Safe lists are enabled"
}

# ── Report ───────────────────────────────────────────────────────────────────

shall_violations := [v | some v in violations; contains(v, "(SHALL)")]

should_violations := [v | some v in violations; contains(v, "(SHOULD)")]

compliance_report := {
	"product": "M365 Security Suite (Defender for Office 365, Purview, Exchange Online, Teams or comparable tools)",
	"baseline": "MS.SECURITYSUITE",
	"controls_evaluated": 24,
	"compliant": compliant,
	"violations": violations,
	"violation_count": count(violations),
	"shall_violation_count": count(shall_violations),
	"should_violation_count": count(should_violations),
}
