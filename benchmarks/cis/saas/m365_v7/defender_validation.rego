# CIS Microsoft 365 Foundations Benchmark v7.0.0
# Section 2 -- Microsoft Defender
#
# NOTE ON PLACEMENT: SPF / DKIM / DMARC are section 2 controls in v7.0.0,
# not Exchange controls. The pre-v7 library evaluated them under its own
# "Exchange" module, which was one of the reasons its control numbers did
# not correspond to the benchmark.
#
# Input contract (from the aac.m365 collection):
#   input.exchange.verified_domains[] - {id, is_default, is_initial,
#                                        spf_present, dkim_present,
#                                        dmarc_present}
#
# The policy controls (Safe Links, Safe Attachments, anti-phishing,
# anti-spam, connection filtering) come from Exchange Online PowerShell
# via aac.m365.m365_defender_ps_facts. That REPLACES the Microsoft Secure
# Score wrapper the pre-v7 library used: Secure Score is Microsoft's own
# scoring model with its own control set, and an implementationStatus
# from it does not establish a CIS recommendation.
#
# NOT EVALUATED: 2.2.1, 2.4.3 and 2.4.5. CIS marks all three Manual with
# no PowerShell audit procedure; they are reported as unresolved by the
# attestation module.
#
# Input contract (aac.m365.m365_defender_ps_facts) -- see that module for
# the control-to-cmdlet mapping. input.defender.unavailable records any
# cmdlet the tenant does not expose (a tenant without Defender for Office
# 365 lacks the ATP cmdlets entirely), so those controls report as
# unevaluable rather than compliant.

package cis_m365_v7.defender

import rego.v1

default compliant := false

default facts_present := false

facts_present if {
	is_array(input.exchange.verified_domains)
}

# CIS 2.1.8 -- SPF records published for all Exchange domains.
violation contains msg if {
	some d in input.exchange.verified_domains
	not d.spf_present
	msg := sprintf("CIS 2.1.8: no SPF record published for domain '%s' -- receivers cannot distinguish legitimate senders from spoofed mail", [d.id])
}

# CIS 2.1.9 -- DKIM enabled for all Exchange Online domains.
violation contains msg if {
	some d in input.exchange.verified_domains
	not d.dkim_present
	msg := sprintf("CIS 2.1.9: DKIM not enabled for domain '%s' -- outbound mail carries no cryptographic origin signature", [d.id])
}

# CIS 2.1.10 -- DMARC records published for all Exchange Online domains.
violation contains msg if {
	some d in input.exchange.verified_domains
	not d.dmarc_present
	msg := sprintf("CIS 2.1.10: no DMARC record published for domain '%s' -- SPF and DKIM failures have no enforcement disposition", [d.id])
}

violation contains msg if {
	not facts_present
	msg := "CIS 2.1.8: verified-domain facts not collected -- SPF, DKIM and DMARC controls could not be evaluated (this is not a pass)"
}


# ── Defender policy controls (Exchange Online PowerShell) ─────────────

default defender_unavailable := {}

defender_unavailable := input.defender.unavailable

default defender_collected := false

defender_collected if {
	input.defender.collected == true
}

policy_available(key) if {
	defender_collected
	not defender_unavailable[key]
}

# CIS 2.1.1 -- Safe Links for Office applications.
violation contains msg if {
	policy_available("safe_links_policies")
	some p in input.defender.safe_links_policies
	p.EnableSafeLinksForOffice == false
	msg := sprintf("CIS 2.1.1: Safe Links policy '%s' does not enable Safe Links for Office applications, so links in documents are not rewritten or checked at click time", [p.Name])
}

# CIS 2.1.2 -- Common Attachment Types Filter.
violation contains msg if {
	policy_available("malware_filter_policies")
	some p in input.defender.malware_filter_policies
	p.EnableFileFilter == false
	msg := sprintf("CIS 2.1.2: malware filter policy '%s' has the common attachment types filter disabled, so executable attachment types are not blocked by type", [p.Identity])
}

# CIS 2.1.3 -- notify internal senders of malware.
violation contains msg if {
	policy_available("malware_filter_policies")
	some p in input.defender.malware_filter_policies
	p.EnableInternalSenderAdminNotifications == false
	msg := sprintf("CIS 2.1.3: malware filter policy '%s' does not send notifications for internal users sending malware, so a compromised internal mailbox goes unnoticed", [p.Identity])
}

# CIS 2.1.4 -- Safe Attachments policy enabled.
violation contains msg if {
	policy_available("safe_attachment_policies")
	count(input.defender.safe_attachment_policies) == 0
	msg := "CIS 2.1.4: no Safe Attachments policy is enabled, so attachments are not detonated before delivery"
}

violation contains msg if {
	policy_available("safe_attachment_policies")
	some p in input.defender.safe_attachment_policies
	p.Enable == false
	msg := sprintf("CIS 2.1.4: Safe Attachments policy '%s' exists but is not enabled", [p.Name])
}

# CIS 2.1.5 -- Safe Attachments for SharePoint, OneDrive and Teams.
violation contains msg if {
	policy_available("atp_policy_for_o365")
	input.defender.atp_policy_for_o365.EnableATPForSPOTeamsODB == false
	msg := "CIS 2.1.5: Safe Attachments for SharePoint, OneDrive and Microsoft Teams is not enabled, so files stored there are not detonated"
}

# CIS 2.1.6 -- spam policies notify administrators.
violation contains msg if {
	policy_available("outbound_spam_policies")
	some p in input.defender.outbound_spam_policies
	p.NotifyOutboundSpam == false
	msg := sprintf("CIS 2.1.6: Exchange Online spam policy '%s' is not set to notify administrators when outbound spam is detected", [p.Name])
}

# CIS 2.1.7 -- an anti-phishing policy exists.
violation contains msg if {
	policy_available("anti_phish_policies")
	count(input.defender.anti_phish_policies) == 0
	msg := "CIS 2.1.7: no anti-phishing policy has been created, so impersonation and spoof protection are at their defaults"
}

violation contains msg if {
	policy_available("anti_phish_policies")
	some p in input.defender.anti_phish_policies
	p.Enabled == false
	msg := sprintf("CIS 2.1.7: anti-phishing policy '%s' has been created but is not enabled", [p.Name])
}

# CIS 2.1.11 -- comprehensive attachment filtering.
MIN_FILTERED_FILE_TYPES := 100

violation contains msg if {
	policy_available("malware_filter_policies")
	some p in input.defender.malware_filter_policies
	count(object.get(p, "FileTypeFilter", [])) < MIN_FILTERED_FILE_TYPES
	msg := sprintf("CIS 2.1.11: malware filter policy '%s' filters %d file types; comprehensive attachment filtering expects at least %d", [p.Identity, count(object.get(p, "FileTypeFilter", [])), MIN_FILTERED_FILE_TYPES])
}

# CIS 2.1.12 / 2.1.13 -- connection filter.
violation contains msg if {
	policy_available("connection_filter_policies")
	some p in input.defender.connection_filter_policies
	count(object.get(p, "IPAllowList", [])) > 0
	msg := sprintf("CIS 2.1.12: connection filter policy '%s' uses an IP allow list, which bypasses spam and phishing evaluation for those senders", [p.Name])
}

violation contains msg if {
	policy_available("connection_filter_policies")
	some p in input.defender.connection_filter_policies
	p.EnableSafeList == true
	msg := sprintf("CIS 2.1.13: connection filter policy '%s' has the safe list on, which trusts a third-party sender list wholesale", [p.Name])
}

# CIS 2.1.14 -- inbound anti-spam allow lists.
violation contains msg if {
	policy_available("content_filter_policies")
	some p in input.defender.content_filter_policies
	count(object.get(p, "AllowedSenderDomains", [])) > 0
	msg := sprintf("CIS 2.1.14: inbound anti-spam policy '%s' contains allowed sender domains; a spoofed sender in an allowed domain is delivered unfiltered", [p.Name])
}

# CIS 2.1.15 -- outbound spam message limits.
violation contains msg if {
	policy_available("outbound_spam_policies")
	some p in input.defender.outbound_spam_policies
	object.get(p, "RecipientLimitExternalPerHour", 0) == 0
	msg := sprintf("CIS 2.1.15: outbound spam policy '%s' has no external recipient-per-hour limit, so a compromised mailbox can send without a throttle", [p.Name])
}

# CIS 2.4.2 -- strict protection for priority accounts.
violation contains msg if {
	policy_available("eop_protection_rules")
	count(input.defender.eop_protection_rules) == 0
	msg := "CIS 2.4.2: no EOP protection policy rule exists, so priority accounts do not have strict protection applied"
}

# CIS 2.4.4 -- zero-hour auto purge for Teams.
violation contains msg if {
	policy_available("teams_protection_policy")
	input.defender.teams_protection_policy.ZapEnabled == false
	msg := "CIS 2.4.4: zero-hour auto purge for Microsoft Teams is off, so malicious messages already delivered to Teams are not retracted"
}

# Fail closed on every Defender cmdlet the tenant did not expose.
DEFENDER_FACT_CONTROLS := {
	"safe_links_policies": "2.1.1",
	"malware_filter_policies": "2.1.2",
	"safe_attachment_policies": "2.1.4",
	"atp_policy_for_o365": "2.1.5",
	"outbound_spam_policies": "2.1.6",
	"anti_phish_policies": "2.1.7",
	"connection_filter_policies": "2.1.12",
	"content_filter_policies": "2.1.14",
	"eop_protection_rules": "2.4.2",
	"teams_protection_policy": "2.4.4",
}

violation contains msg if {
	some key, reason in defender_unavailable
	control := object.get(DEFENDER_FACT_CONTROLS, key, "2.1.1")
	msg := sprintf("CIS %s: could not be evaluated -- %s (this is not a pass)", [control, reason])
}

violation contains msg if {
	not defender_collected
	msg := "CIS 2.1.1: Defender policy facts were not collected, so whether Safe Links for Office applications is enabled could not be established (this is not a pass)"
}

compliant if {
	facts_present
	count(violation) == 0
}

compliance_report := {
	"benchmark": "CIS Microsoft 365 Foundations Benchmark",
	"benchmark_version": "7.0.0",
	"section": "2",
	"name": "Microsoft Defender",
	"section_total_controls": 21,
	"controls_evaluated": 17,
	"controls": [
		"2.1.1", "2.1.2", "2.1.3", "2.1.4", "2.1.5", "2.1.6", "2.1.7",
		"2.1.8", "2.1.9", "2.1.10", "2.1.11", "2.1.12", "2.1.13",
		"2.1.14", "2.1.15", "2.4.2", "2.4.4",
	],
	"facts_present": facts_present,
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}
