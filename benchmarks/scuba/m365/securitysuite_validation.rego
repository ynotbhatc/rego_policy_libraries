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

# ── Evidence wording ─────────────────────────────────────────────────────────
# Only the boolean true satisfies a yes/no fact. false is the finding as written. A fact that was not collected,
# and a fact of another type ("true", "false", 0, 1, null), fail the policy too and say so under the same policy id,
# so a collection problem is never reported as a configuration finding and never passes.
_finding(text, path) := text if object.get(input, path, null) == false

_finding(text, path) := sprintf("%s evidence missing — input.%s not collected", [_policy(text), concat(".", path)]) if {
	not _collected(path)
}

_finding(text, path) := sprintf("%s evidence invalid — input.%s must be true or false, got %s", [_policy(text), concat(".", path), json.marshal(v)]) if {
	_collected(path)
	v := object.get(input, path, null)
	not is_boolean(v)
}

# present, including present as null
_collected(path) if {
	parent := object.get(input, array.slice(path, 0, count(path) - 1), null)
	is_object(parent)
	path[count(path) - 1] in object.keys(parent)
}

# "SCuBA MS.X.1.1v1 (SHALL):" from the finding text
_policy(text) := concat("", [split(text, "): ")[0], "):"])

_ss := object.get(input, ["scuba", "securitysuite"], {})

# ── Group 1 — Malware Protection ─────────────────────────────────────────────

violations contains msg if {
	not _ss.malware.click_to_run_blocked == true
	text := "SCuBA MS.SECURITYSUITE.1.1v1 (SHALL): Emails with click-to-run file attachments (at a minimum .exe, .cmd and .vbe) are not blocked"
	msg := _finding(text, ["scuba", "securitysuite", "malware", "click_to_run_blocked"])
}

violations contains msg if {
	not _ss.malware.post_delivery_scan == true
	text := "SCuBA MS.SECURITYSUITE.1.2v1 (SHALL): Email scanning cannot review emails after delivery"
	msg := _finding(text, ["scuba", "securitysuite", "malware", "post_delivery_scan"])
}

violations contains msg if {
	not _ss.malware.quarantine_or_drop == true
	text := "SCuBA MS.SECURITYSUITE.1.3v1 (SHALL): Emails identified as containing malware are not quarantined or dropped"
	msg := _finding(text, ["scuba", "securitysuite", "malware", "quarantine_or_drop"])
}

violations contains msg if {
	not _ss.safe_attachments.spo_odb_teams_enabled == true
	text := "SCuBA MS.SECURITYSUITE.1.4v1 (SHOULD): SharePoint, OneDrive and Teams message attachments are not scanned for malware"
	msg := _finding(text, ["scuba", "securitysuite", "safe_attachments", "spo_odb_teams_enabled"])
}

# ── Group 2 — Impersonation Protection ───────────────────────────────────────

violations contains msg if {
	not _ss.impersonation.user_protection_sensitive == true
	text := "SCuBA MS.SECURITYSUITE.2.1v1 (SHOULD): User impersonation protection is not enabled for sensitive accounts"
	msg := _finding(text, ["scuba", "securitysuite", "impersonation", "user_protection_sensitive"])
}

violations contains msg if {
	not _ss.impersonation.domain_protection_owned == true
	text := "SCuBA MS.SECURITYSUITE.2.2v1 (SHOULD): Domain impersonation protection is not enabled for domains owned by the agency"
	msg := _finding(text, ["scuba", "securitysuite", "impersonation", "domain_protection_owned"])
}

violations contains msg if {
	not _ss.impersonation.domain_protection_partners == true
	text := "SCuBA MS.SECURITYSUITE.2.3v1 (SHOULD): Domain impersonation protection is not added for key suppliers and partners"
	msg := _finding(text, ["scuba", "securitysuite", "impersonation", "domain_protection_partners"])
}

violations contains msg if {
	not _ss.impersonation.user_warnings == true
	text := "SCuBA MS.SECURITYSUITE.2.4v1 (SHOULD): User warnings comparable to the EOP user safety tips are not displayed"
	msg := _finding(text, ["scuba", "securitysuite", "impersonation", "user_warnings"])
}

# ── Group 3 — Data Loss Prevention ───────────────────────────────────────────

violations contains msg if {
	not _ss.dlp.custom_pii_policy == true
	text := "SCuBA MS.SECURITYSUITE.3.1v1 (SHALL): No DLP policy protects PII and sensitive information, blocking at a minimum credit card numbers, U.S. ITINs and U.S. SSNs"
	msg := _finding(text, ["scuba", "securitysuite", "dlp", "custom_pii_policy"])
}

violations contains msg if {
	not _ss.dlp.applied_all_workloads == true
	text := "SCuBA MS.SECURITYSUITE.3.2v1 (SHOULD): The DLP policy is not applied to Exchange, OneDrive, SharePoint, Teams chat and Devices"
	msg := _finding(text, ["scuba", "securitysuite", "dlp", "applied_all_workloads"])
}

violations contains msg if {
	not _ss.dlp.block_everyone_action == true
	text := "SCuBA MS.SECURITYSUITE.3.3v1 (SHOULD): The DLP policy action is not set to block sharing sensitive information with everyone"
	msg := _finding(text, ["scuba", "securitysuite", "dlp", "block_everyone_action"])
}

violations contains msg if {
	not _ss.dlp.user_notifications == true
	text := "SCuBA MS.SECURITYSUITE.3.4v1 (SHOULD): User notifications on the proper use of sensitive information are not enabled in the DLP policy"
	msg := _finding(text, ["scuba", "securitysuite", "dlp", "user_notifications"])
}

violations contains msg if {
	not _ss.dlp.restricted_apps_blocked == true
	text := "SCuBA MS.SECURITYSUITE.3.5v1 (SHOULD): The DLP policy does not block access to sensitive information by restricted applications and unwanted Bluetooth applications"
	msg := _finding(text, ["scuba", "securitysuite", "dlp", "restricted_apps_blocked"])
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
	text := "SCuBA MS.SECURITYSUITE.4.2v1 (SHOULD): Alerts are not sent to a monitored address or incorporated into a SIEM"
	msg := _finding(text, ["scuba", "securitysuite", "alerts", "routed_to_monitored_target"])
}

# ── Group 5 — Audit Logging ──────────────────────────────────────────────────

violations contains msg if {
	not _ss.audit.unified_logging_enabled == true
	text := "SCuBA MS.SECURITYSUITE.5.1v1 (SHALL): Unified audit logging is not enabled"
	msg := _finding(text, ["scuba", "securitysuite", "audit", "unified_logging_enabled"])
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
	text := "SCuBA MS.SECURITYSUITE.6.1v1 (SHALL): Emails detected as spam or phishing can be delivered to the user's inbox"
	msg := _finding(text, ["scuba", "securitysuite", "antispam", "spam_phish_not_in_inbox"])
}

violations contains msg if {
	not _ss.antispam.no_allowed_domains == true
	text := "SCuBA MS.SECURITYSUITE.6.2v1 (SHALL): Allowed domains are added to inbound anti-spam protection policies"
	msg := _finding(text, ["scuba", "securitysuite", "antispam", "no_allowed_domains"])
}

# ── Group 7 — Link Protection ────────────────────────────────────────────────

violations contains msg if {
	not _ss.links.url_blocklist_enabled == true
	text := "SCuBA MS.SECURITYSUITE.7.1v1 (SHOULD): URL comparison with a block-list is not enabled for URLs in emails, Teams messages and Office documents"
	msg := _finding(text, ["scuba", "securitysuite", "links", "url_blocklist_enabled"])
}

violations contains msg if {
	not _ss.links.download_links_scanned == true
	text := "SCuBA MS.SECURITYSUITE.7.2v1 (SHOULD): Direct download links are not scanned for malware"
	msg := _finding(text, ["scuba", "securitysuite", "links", "download_links_scanned"])
}

violations contains msg if {
	not _ss.links.click_tracking_enabled == true
	text := "SCuBA MS.SECURITYSUITE.7.3v1 (SHOULD): User click tracking is not enabled"
	msg := _finding(text, ["scuba", "securitysuite", "links", "click_tracking_enabled"])
}

# ── Group 8 — IP Allow Lists ─────────────────────────────────────────────────

violations contains msg if {
	not _ss.allow_lists.no_ip_allow_list == true
	text := "SCuBA MS.SECURITYSUITE.8.1v1 (SHOULD): An IP allow list is created"
	msg := _finding(text, ["scuba", "securitysuite", "allow_lists", "no_ip_allow_list"])
}

violations contains msg if {
	not _ss.allow_lists.safe_list_disabled == true
	text := "SCuBA MS.SECURITYSUITE.8.2v1 (SHOULD): Safe lists are enabled"
	msg := _finding(text, ["scuba", "securitysuite", "allow_lists", "safe_list_disabled"])
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
