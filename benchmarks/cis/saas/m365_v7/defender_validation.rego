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

# METADATA
# title: "CIS Microsoft 365 Foundations Benchmark v7.0.0"
# custom:
#   class: security
#   framework: cis_saas
#   source: cis
#   domains: [saas, m365]
#   coverage:
#     checks: 31
#     cited: 18
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package cis_m365_v7.defender

import rego.v1

default compliant := false

# Every rule below compares a field only when the field has the type the rule
# expects, and iterates a list only when it is a list. A missing field or a
# wrong shape is never read as a pass and never as a failure: the control is
# left out of `decidable` and the evidence rules at the end of the file report
# it by id as evidence missing.

default facts_present := false

facts_present if {
	is_array(input.exchange.verified_domains)
}

# The Microsoft-managed *initial* domain (…onmicrosoft.com, `is_initial`) is
# excluded from these controls -- the tenant cannot publish DNS for it, so
# Microsoft's own SPF/DKIM/DMARC posture is not the customer's to remediate.
# (Without this, an initial domain whose records are empty or unqueryable would
# raise three false violations.) An absent is_initial reads as a customer domain.
#
# A domain whose DNS records could not be queried (e.g. a permission error on
# serviceConfigurationRecords) carries `dns_unavailable`. Its SPF/DKIM/DMARC
# state is unknown, NOT absent -- the collector must not report a missing record
# as false, and the rules below must not read its absence as a definite failure.
# Those domains are reported as not-evaluated instead (see the catch below).
customer_domains contains d if {
	facts_present
	some d in input.exchange.verified_domains
	object.get(d, "is_initial", false) != true
}

_dns_known(d) if not d.dns_unavailable

# CIS 2.1.8 -- SPF records published for all customer Exchange domains.
violation contains msg if {
	some d in customer_domains
	_dns_known(d)
	d.spf_present == false
	msg := sprintf("CIS 2.1.8: no SPF record published for domain '%s' -- receivers cannot distinguish legitimate senders from spoofed mail", [object.get(d, "id", "(unnamed)")])
}

# CIS 2.1.9 -- DKIM enabled for all customer Exchange Online domains. A
# published selector CNAME is necessary but does not show that Exchange Online
# signs the domain's mail, so the signing configuration is read as well:
# input.defender.dkim_signing_configs[] (Get-DkimSigningConfig: Domain or Name,
# Enabled, Status). A customer domain without a signing configuration, or with
# one that is disabled, or whose Status is reported and is not "Valid", fails;
# without the signing configurations the control is evidence missing.
# https://learn.microsoft.com/en-us/powershell/module/exchange/get-dkimsigningconfig
# https://learn.microsoft.com/en-us/powershell/module/exchange/set-dkimsigningconfig
violation contains msg if {
	some d in customer_domains
	_dns_known(d)
	d.dkim_present == false
	msg := sprintf("CIS 2.1.9: DKIM not enabled for domain '%s' -- no DKIM selector record is published, so outbound mail carries no verifiable origin signature", [object.get(d, "id", "(unnamed)")])
}

_dkim_domain(c) := lower(c.Domain) if is_string(c.Domain)

_dkim_domain(c) := lower(c.Name) if {
	not is_string(object.get(c, "Domain", null))
	is_string(c.Name)
}

_dkim_configs(name) := [c |
	some c in _list("dkim_signing_configs")
	_dkim_domain(c) == lower(name)
]

violation contains msg if {
	some d in customer_domains
	is_string(d.id)
	is_array(_list("dkim_signing_configs"))
	count(_dkim_configs(d.id)) == 0
	msg := sprintf("CIS 2.1.9: DKIM not enabled for domain '%s' -- no DKIM signing configuration exists for it, so Exchange Online does not sign its mail", [object.get(d, "id", "(unnamed)")])
}

violation contains msg if {
	some d in customer_domains
	is_string(d.id)
	some c in _dkim_configs(d.id)
	c.Enabled == false
	msg := sprintf("CIS 2.1.9: DKIM not enabled for domain '%s' -- its DKIM signing configuration is disabled", [object.get(d, "id", "(unnamed)")])
}

violation contains msg if {
	some d in customer_domains
	is_string(d.id)
	some c in _dkim_configs(d.id)
	c.Enabled == true
	is_string(c.Status)
	c.Status != "Valid"
	msg := sprintf("CIS 2.1.9: DKIM signing for domain '%s' is enabled but its status is '%s', not Valid, so mail is not signed", [object.get(d, "id", "(unnamed)"), c.Status])
}

# CIS 2.1.10 -- DMARC records published for all customer Exchange Online domains.
violation contains msg if {
	some d in customer_domains
	_dns_known(d)
	d.dmarc_present == false
	msg := sprintf("CIS 2.1.10: no DMARC record published for domain '%s' -- SPF and DKIM failures have no enforcement disposition", [object.get(d, "id", "(unnamed)")])
}

# Customer domain whose DNS records could not be queried -- not a pass, not a
# definite violation; SPF/DKIM/DMARC could not be evaluated for it.
violation contains msg if {
	some d in customer_domains
	d.dns_unavailable
	some pair in [["2.1.8", "SPF"], ["2.1.9", "DKIM"], ["2.1.10", "DMARC"]]
	[id, record] := pair
	msg := sprintf("CIS %s: evidence missing -- the %s record of domain '%s' could not be evaluated: %v (this is not a pass)", [id, record, object.get(d, "id", "(unnamed)"), d.dns_unavailable])
}

# ── Defender policy controls (Exchange Online PowerShell) ─────────────

default defender_unavailable := {}

defender_unavailable := input.defender.unavailable if is_object(input.defender.unavailable)

default defender_collected := false

defender_collected if {
	input.defender.collected == true
}

policy_available(key) if {
	defender_collected
	not defender_unavailable[key]
}

# a collected list; undefined when the fact is unavailable or is not a list (a
# list sent as an object must not be iterated: its values are not policies)
_list(key) := input.defender[key] if {
	policy_available(key)
	is_array(input.defender[key])
}

# a collected single object
_object(key) := input.defender[key] if {
	policy_available(key)
	is_object(input.defender[key])
}

# CIS 2.1.1 -- Safe Links for Office applications.
violation contains msg if {
	some p in _list("safe_links_policies")
	p.EnableSafeLinksForOffice == false
	msg := sprintf("CIS 2.1.1: Safe Links policy '%s' does not enable Safe Links for Office applications, so links in documents are not rewritten or checked at click time", [object.get(p, "Name", "(unnamed)")])
}

# CIS 2.1.2 -- Common Attachment Types Filter.
violation contains msg if {
	some p in _list("malware_filter_policies")
	p.EnableFileFilter == false
	msg := sprintf("CIS 2.1.2: malware filter policy '%s' has the common attachment types filter disabled, so executable attachment types are not blocked by type", [object.get(p, "Identity", "(unnamed)")])
}

# CIS 2.1.3 -- notify internal senders of malware.
violation contains msg if {
	some p in _list("malware_filter_policies")
	p.EnableInternalSenderAdminNotifications == false
	msg := sprintf("CIS 2.1.3: malware filter policy '%s' does not send notifications for internal users sending malware, so a compromised internal mailbox goes unnoticed", [object.get(p, "Identity", "(unnamed)")])
}

# CIS 2.1.4 -- Safe Attachments policy enabled.
violation contains msg if {
	count(_list("safe_attachment_policies")) == 0
	msg := "CIS 2.1.4: no Safe Attachments policy is enabled, so attachments are not detonated before delivery"
}

violation contains msg if {
	some p in _list("safe_attachment_policies")
	p.Enable == false
	msg := sprintf("CIS 2.1.4: Safe Attachments policy '%s' exists but is not enabled", [object.get(p, "Name", "(unnamed)")])
}

# CIS 2.1.5 -- Safe Attachments for SharePoint, OneDrive and Teams.
violation contains msg if {
	_object("atp_policy_for_o365").EnableATPForSPOTeamsODB == false
	msg := "CIS 2.1.5: Safe Attachments for SharePoint, OneDrive and Microsoft Teams is not enabled, so files stored there are not detonated"
}

# CIS 2.1.6 -- spam policies notify administrators.
violation contains msg if {
	some p in _list("outbound_spam_policies")
	p.NotifyOutboundSpam == false
	msg := sprintf("CIS 2.1.6: Exchange Online spam policy '%s' is not set to notify administrators when outbound spam is detected", [object.get(p, "Name", "(unnamed)")])
}

# CIS 2.1.7 -- an anti-phishing policy exists.
violation contains msg if {
	count(_list("anti_phish_policies")) == 0
	msg := "CIS 2.1.7: no anti-phishing policy has been created, so impersonation and spoof protection are at their defaults"
}

violation contains msg if {
	some p in _list("anti_phish_policies")
	p.Enabled == false
	msg := sprintf("CIS 2.1.7: anti-phishing policy '%s' has been created but is not enabled", [object.get(p, "Name", "(unnamed)")])
}

# CIS 2.1.11 -- comprehensive attachment filtering. The Exchange property is
# FileTypes (Set-MalwareFilterPolicy -FileTypes <String[]>); FileTypeFilter, the
# name this module used to read, is accepted only as a fallback when FileTypes
# is absent. https://learn.microsoft.com/en-us/powershell/module/exchange/set-malwarefilterpolicy
# The benchmark's own extension list is not reproduced; the size threshold below
# is this library's approximation of it.
MIN_FILTERED_FILE_TYPES := 100

_file_types(p) := p.FileTypes if is_array(p.FileTypes)

_file_types(p) := p.FileTypeFilter if {
	not "FileTypes" in object.keys(p)
	is_array(p.FileTypeFilter)
}

violation contains msg if {
	some p in _list("malware_filter_policies")
	n := count(_file_types(p))
	n < MIN_FILTERED_FILE_TYPES
	msg := sprintf("CIS 2.1.11: malware filter policy '%s' filters %d file types; comprehensive attachment filtering expects at least %d", [object.get(p, "Identity", "(unnamed)"), n, MIN_FILTERED_FILE_TYPES])
}

violation contains msg if {
	some p in _list("malware_filter_policies")
	p.EnableFileFilter == false
	is_array(_file_types(p))
	msg := sprintf("CIS 2.1.11: malware filter policy '%s' lists file types but its attachment filtering is off, so the list does not block anything", [object.get(p, "Identity", "(unnamed)")])
}

# CIS 2.1.12 / 2.1.13 -- connection filter.
violation contains msg if {
	some p in _list("connection_filter_policies")
	is_array(p.IPAllowList)
	count(p.IPAllowList) > 0
	msg := sprintf("CIS 2.1.12: connection filter policy '%s' uses an IP allow list, which bypasses spam and phishing evaluation for those senders", [object.get(p, "Name", "(unnamed)")])
}

violation contains msg if {
	some p in _list("connection_filter_policies")
	p.EnableSafeList == true
	msg := sprintf("CIS 2.1.13: connection filter policy '%s' has the safe list on, which trusts a third-party sender list wholesale", [object.get(p, "Name", "(unnamed)")])
}

# CIS 2.1.14 -- inbound anti-spam allow lists.
violation contains msg if {
	some p in _list("content_filter_policies")
	is_array(p.AllowedSenderDomains)
	count(p.AllowedSenderDomains) > 0
	msg := sprintf("CIS 2.1.14: inbound anti-spam policy '%s' contains allowed sender domains; a spoofed sender in an allowed domain is delivered unfiltered", [object.get(p, "Name", "(unnamed)")])
}

# CIS 2.1.15 -- outbound spam message limits. Each limit must be set (0 means
# no limit of the policy's own) and no higher than the value below, the
# over-limit action must block the user, and a recipient must be notified.
OUTBOUND_LIMITS := {
	"RecipientLimitExternalPerHour": 500,
	"RecipientLimitInternalPerHour": 1000,
	"RecipientLimitPerDay": 1000,
}

violation contains msg if {
	some p in _list("outbound_spam_policies")
	some field, limit in OUTBOUND_LIMITS
	v := p[field]
	is_number(v)
	_over_limit(v, limit)
	msg := sprintf("CIS 2.1.15: outbound spam policy '%s' sets %s to %v; a limit above 0 and no higher than %d is expected, so a compromised mailbox is not throttled", [object.get(p, "Name", "(unnamed)"), field, v, limit])
}

_over_limit(v, _) if v == 0

_over_limit(v, limit) if v > limit

violation contains msg if {
	some p in _list("outbound_spam_policies")
	is_string(p.ActionWhenThresholdReached)
	p.ActionWhenThresholdReached != "BlockUser"
	msg := sprintf("CIS 2.1.15: outbound spam policy '%s' takes the action '%s' when a message limit is reached, so the sender is not restricted from sending mail", [object.get(p, "Name", "(unnamed)"), p.ActionWhenThresholdReached])
}

violation contains msg if {
	some p in _list("outbound_spam_policies")
	is_array(p.NotifyOutboundSpamRecipients)
	count(p.NotifyOutboundSpamRecipients) == 0
	msg := sprintf("CIS 2.1.15: outbound spam policy '%s' notifies nobody when a sender exceeds the message limits", [object.get(p, "Name", "(unnamed)")])
}

# CIS 2.4.2 -- strict protection for priority accounts. The Strict preset
# security policy is applied by two rules, one in EOP (Get-EOPProtectionPolicyRule)
# and one in Defender for Office 365 (Get-ATPProtectionPolicyRule), both named
# "Strict Preset Security Policy". Each must exist, be in State Enabled and
# name its recipients (SentTo, SentToMemberOf or RecipientDomainIs).
# https://learn.microsoft.com/en-us/powershell/module/exchange/get-eopprotectionpolicyrule
STRICT_PRESET := "Strict Preset Security Policy"

STRICT_RULE_FACTS := {
	"eop_protection_rules": "EOP",
	"atp_protection_rules": "Defender for Office 365",
}

RECIPIENT_FIELDS := ["SentTo", "SentToMemberOf", "RecipientDomainIs"]

_rule_name(r) := r.Name if is_string(r.Name)

_rule_name(r) := r.Identity if {
	not is_string(object.get(r, "Name", null))
	is_string(r.Identity)
}

_strict_rules(key) := [r |
	some r in _list(key)
	_rule_name(r) == STRICT_PRESET
]

# a recipient condition is set: a non-empty list or string (null = not set)
_names_recipients(r) if {
	some f in RECIPIENT_FIELDS
	_populated(r[f])
}

_populated(v) if {
	is_array(v)
	count(v) > 0
}

_populated(v) if {
	is_string(v)
	trim_space(v) != ""
}

_recipients_readable(r) if {
	every f in RECIPIENT_FIELDS {
		_recipient_field_readable(object.get(r, f, false))
	}
}

_recipient_field_readable(v) if v == null

_recipient_field_readable(v) if is_array(v)

_recipient_field_readable(v) if is_string(v)

violation contains msg if {
	some key, label in STRICT_RULE_FACTS
	every r in _list(key) {
		is_string(_rule_name(r))
	}
	count(_strict_rules(key)) == 0
	msg := sprintf("CIS 2.4.2: no %s rule for the Strict preset security policy exists, so priority accounts do not have strict protection applied", [label])
}

violation contains msg if {
	some key, label in STRICT_RULE_FACTS
	some r in _strict_rules(key)
	is_string(r.State)
	r.State != "Enabled"
	msg := sprintf("CIS 2.4.2: the %s rule of the Strict preset security policy is '%s', so strict protection is not applied", [label, r.State])
}

violation contains msg if {
	some key, label in STRICT_RULE_FACTS
	some r in _strict_rules(key)
	_recipients_readable(r)
	not _names_recipients(r)
	msg := sprintf("CIS 2.4.2: the %s rule of the Strict preset security policy names no recipients (SentTo, SentToMemberOf, RecipientDomainIs), so no priority account receives strict protection", [label])
}

# CIS 2.4.4 -- zero-hour auto purge for Teams.
violation contains msg if {
	_object("teams_protection_policy").ZapEnabled == false
	msg := "CIS 2.4.4: zero-hour auto purge for Microsoft Teams is off, so malicious messages already delivered to Teams are not retracted"
}

# ── CIS 2.4.1 -- priority account protection ──────────────────────────
# The only compound control in this section. CIS requires all three:
#
#   EnablePriorityAccountProtection is true                (Exchange)
#   a passing alert policy with ThreatType Phish           (Purview)
#   a passing alert policy with ThreatType Malware         (Purview)
#
# "Passing" is CIS's own list: severity High, inbound mail direction,
# tagged to priority accounts, notification enabled with a recipient, and
# not disabled. A tenant with the toggle on and no alerts configured is
# not compliant -- the toggle alone tags accounts, it does not watch them.
# RecipientTags, Filter and NotifyUser may arrive as a list or as a single
# string; both are read.

violation contains msg if {
	_object("email_tenant_settings").EnablePriorityAccountProtection == false
	msg := "CIS 2.4.1: priority account protection is not enabled for the tenant, so accounts tagged as priority receive no differentiated protection"
}

_texts(v) := [v] if is_string(v)

_texts(v) := [s | some s in v; is_string(s)] if is_array(v)

_has_text(v, s) if {
	some t in _texts(v)
	contains(t, s)
}

passing_alert(threat) if {
	some a in _list("priority_account_alerts")
	a.ThreatType == threat
	a.Severity == "High"
	a.Disabled == false
	a.NotificationEnabled == true
	count(_texts(a.NotifyUser)) > 0
	_has_text(a.RecipientTags, "Priority account")
	_has_text(a.Filter, "Inbound")
}

# every field the passing test reads has a type it can read
_alert_readable(a) if {
	is_string(a.ThreatType)
	is_string(a.Severity)
	is_boolean(a.Disabled)
	is_boolean(a.NotificationEnabled)
	_texts(a.NotifyUser)
	_texts(a.RecipientTags)
	_texts(a.Filter)
}

_alerts_readable if {
	every a in _list("priority_account_alerts") {
		_alert_readable(a)
	}
}

ALERT_THREATS := {
	"Phish": "phishing email detected at delivery",
	"Malware": "detected malware in email",
}

violation contains msg if {
	some threat, subject in ALERT_THREATS
	_alerts_readable
	not passing_alert(threat)
	msg := sprintf("CIS 2.4.1: no alert policy monitors priority accounts for %s -- a high-severity, inbound, priority-tagged alert with a notification recipient is required", [subject])
}

# ── Per-control results ──────────────────────────────────────────────
# `decidable` holds the controls of this section whose facts were all
# collected; CONTROL_EVIDENCE names the input paths each one reads ("[]"
# = every element of a list). A control that is not decidable is reported
# by id as evidence missing (rules at the end of the file) and the main
# report marks it "evidence_missing": an absent fact must never read as a
# pass. Each gate restates the condition of its rule above; change them
# together.
CONTROL_EVIDENCE := {
	"2.1.1": ["defender.safe_links_policies[].EnableSafeLinksForOffice"],
	"2.1.2": ["defender.malware_filter_policies[].EnableFileFilter"],
	"2.1.3": ["defender.malware_filter_policies[].EnableInternalSenderAdminNotifications"],
	"2.1.4": ["defender.safe_attachment_policies[].Enable"],
	"2.1.5": ["defender.atp_policy_for_o365.EnableATPForSPOTeamsODB"],
	"2.1.6": ["defender.outbound_spam_policies[].NotifyOutboundSpam"],
	"2.1.7": ["defender.anti_phish_policies[].Enabled"],
	"2.1.8": ["exchange.verified_domains[].dns_unavailable", "exchange.verified_domains[].is_initial", "exchange.verified_domains[].spf_present"],
	"2.1.9": ["defender.dkim_signing_configs[].Domain", "defender.dkim_signing_configs[].Enabled", "defender.dkim_signing_configs[].Status", "exchange.verified_domains[].dkim_present", "exchange.verified_domains[].dns_unavailable", "exchange.verified_domains[].is_initial"],
	"2.1.10": ["exchange.verified_domains[].dmarc_present", "exchange.verified_domains[].dns_unavailable", "exchange.verified_domains[].is_initial"],
	"2.1.11": ["defender.malware_filter_policies[].EnableFileFilter", "defender.malware_filter_policies[].FileTypes"],
	"2.1.12": ["defender.connection_filter_policies[].IPAllowList"],
	"2.1.13": ["defender.connection_filter_policies[].EnableSafeList"],
	"2.1.14": ["defender.content_filter_policies[].AllowedSenderDomains"],
	"2.1.15": ["defender.outbound_spam_policies[].ActionWhenThresholdReached", "defender.outbound_spam_policies[].NotifyOutboundSpamRecipients", "defender.outbound_spam_policies[].RecipientLimitExternalPerHour", "defender.outbound_spam_policies[].RecipientLimitInternalPerHour", "defender.outbound_spam_policies[].RecipientLimitPerDay"],
	"2.4.1": ["defender.email_tenant_settings.EnablePriorityAccountProtection", "defender.priority_account_alerts[].Disabled", "defender.priority_account_alerts[].Filter", "defender.priority_account_alerts[].NotificationEnabled", "defender.priority_account_alerts[].NotifyUser", "defender.priority_account_alerts[].RecipientTags", "defender.priority_account_alerts[].Severity", "defender.priority_account_alerts[].ThreatType"],
	"2.4.2": ["defender.atp_protection_rules[].Name", "defender.atp_protection_rules[].RecipientDomainIs", "defender.atp_protection_rules[].SentTo", "defender.atp_protection_rules[].SentToMemberOf", "defender.atp_protection_rules[].State", "defender.eop_protection_rules[].Name", "defender.eop_protection_rules[].RecipientDomainIs", "defender.eop_protection_rules[].SentTo", "defender.eop_protection_rules[].SentToMemberOf", "defender.eop_protection_rules[].State"],
	"2.4.4": ["defender.teams_protection_policy.ZapEnabled"],
}

# every listed policy carries the boolean its rule compares: a policy
# without the field would never match "== false" and so read as a pass
_policies_carry(key, field) if {
	every p in _list(key) {
		is_boolean(p[field])
	}
}

# every listed policy carries a list in `field` (an absent list is not an empty one)
_policies_list(key, field) if {
	every p in _list(key) {
		is_array(p[field])
	}
}

_domain_flag_readable(d, _) if d.dns_unavailable

_domain_flag_readable(d, flag) if {
	_dns_known(d)
	is_boolean(d[flag])
}

_domains_readable(flag) if {
	facts_present
	every d in input.exchange.verified_domains {
		is_object(d)
		is_boolean(object.get(d, "is_initial", false))
	}
	every d in customer_domains {
		_domain_flag_readable(d, flag)
	}
}

decidable contains "2.1.8" if _domains_readable("spf_present")

decidable contains "2.1.10" if _domains_readable("dmarc_present")

# no customer domain: nothing to sign, so no signing configuration is needed
decidable contains "2.1.9" if {
	_domains_readable("dkim_present")
	count(customer_domains) == 0
}

# the DKIM signing configurations must be collected and readable for every
# customer domain, whatever the CNAME evidence says
decidable contains "2.1.9" if {
	_domains_readable("dkim_present")
	every c in _list("dkim_signing_configs") {
		is_string(_dkim_domain(c))
		is_boolean(c.Enabled)
		is_string(object.get(c, "Status", ""))
	}
	every d in customer_domains {
		is_string(d.id)
	}
}

decidable contains "2.1.1" if _policies_carry("safe_links_policies", "EnableSafeLinksForOffice")

decidable contains "2.1.2" if _policies_carry("malware_filter_policies", "EnableFileFilter")

decidable contains "2.1.3" if _policies_carry("malware_filter_policies", "EnableInternalSenderAdminNotifications")

decidable contains "2.1.4" if _policies_carry("safe_attachment_policies", "Enable")

decidable contains "2.1.5" if is_boolean(_object("atp_policy_for_o365").EnableATPForSPOTeamsODB)

decidable contains "2.1.6" if _policies_carry("outbound_spam_policies", "NotifyOutboundSpam")

decidable contains "2.1.7" if _policies_carry("anti_phish_policies", "Enabled")

decidable contains "2.1.11" if {
	_policies_carry("malware_filter_policies", "EnableFileFilter")
	every p in _list("malware_filter_policies") {
		is_array(_file_types(p))
	}
}

decidable contains "2.1.12" if _policies_list("connection_filter_policies", "IPAllowList")

decidable contains "2.1.13" if _policies_carry("connection_filter_policies", "EnableSafeList")

decidable contains "2.1.14" if _policies_list("content_filter_policies", "AllowedSenderDomains")

decidable contains "2.1.15" if {
	_policies_list("outbound_spam_policies", "NotifyOutboundSpamRecipients")
	every p in _list("outbound_spam_policies") {
		is_string(p.ActionWhenThresholdReached)
		every field, _ in OUTBOUND_LIMITS {
			is_number(p[field])
		}
	}
}

decidable contains "2.4.1" if {
	is_boolean(_object("email_tenant_settings").EnablePriorityAccountProtection)
	_alerts_readable
}

decidable contains "2.4.2" if {
	every key, _ in STRICT_RULE_FACTS {
		_strict_rules_readable(key)
	}
}

_strict_rules_readable(key) if {
	every r in _list(key) {
		is_string(_rule_name(r))
	}
	every r in _strict_rules(key) {
		is_string(r.State)
		_recipients_readable(r)
	}
}

decidable contains "2.4.4" if is_boolean(_object("teams_protection_policy").ZapEnabled)

# ── Evidence gaps, reported by control id ─────────────────────────────
# A gap names every control it blocks (the malware filter gap names 2.1.2, 2.1.3 and 2.1.11), so the
# per-control results and an exporter reading the ids agree on what was not
# evaluated. Each unavailable key maps to the controls that read it; a key this
# module does not know is reported on its own, attributed to no control.
FACT_CONTROLS := {
	"safe_links_policies": ["2.1.1"],
	"malware_filter_policies": ["2.1.2", "2.1.3", "2.1.11"],
	"safe_attachment_policies": ["2.1.4"],
	"atp_policy_for_o365": ["2.1.5"],
	"outbound_spam_policies": ["2.1.6", "2.1.15"],
	"anti_phish_policies": ["2.1.7"],
	"connection_filter_policies": ["2.1.12", "2.1.13"],
	"content_filter_policies": ["2.1.14"],
	"eop_protection_rules": ["2.4.2"],
	"atp_protection_rules": ["2.4.2"],
	"teams_protection_policy": ["2.4.4"],
	"email_tenant_settings": ["2.4.1"],
	"priority_account_alerts": ["2.4.1"],
	"dkim_signing_configs": ["2.1.9"],
}

# the controls that read a defender.* fact
_defender_controls := _natural_sort({id |
	some id, paths in CONTROL_EVIDENCE
	some p in paths
	startswith(p, "defender.")
})

# ids in benchmark order (2.1.2 before 2.1.11)
_natural_sort(ids) := [pair[1] | some pair in sort([[key, id] |
	some id in ids
	parts := split(id, ".")
	key := concat(".", [sprintf("%03d", [to_number(x)]) | some x in parts])
])]

_gap(ids, why) := sprintf("CIS %s: evidence missing -- %s (this is not a pass)", [concat("/", ids), why])

_source_gaps contains [_defender_controls, "Defender policy facts were not collected (defender.collected is not true)"] if not defender_collected

_source_gaps contains [FACT_CONTROLS[key], sprintf("defender.unavailable.%s: %v", [key, reason])] if {
	defender_collected
	some key, reason in defender_unavailable
}

_gap_ids contains id if {
	some g in _source_gaps
	some id in g[0]
}

# a source gap names each control it leaves undecided in a message of its own, so the
# violation count is never smaller than the number of controls that are not a pass
_evidence_gaps contains _gap([id], concat("; ", sort(whys))) if {
	some id in _gap_ids
	not id in decidable
	whys := {g[1] | some g in _source_gaps; id in g[0]}
}

_evidence_gaps contains msg if {
	some key, reason in defender_unavailable
	not FACT_CONTROLS[key]
	msg := sprintf("M365 section 2 (Defender): unrecognised unavailable key '%s' (%v) -- this module reads no fact of that name, so it is attributed to no control (this is not a pass)", [key, reason])
}

_evidence_gaps contains _gap([id], why) if {
	some id, paths in CONTROL_EVIDENCE
	not id in decidable
	not id in _gap_ids
	why := sprintf("%s not collected or not of the expected type", [concat(", ", paths)])
}

violation contains msg if some msg in _evidence_gaps

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
	"controls_evaluated": 18,
	"controls": [
		"2.1.1", "2.1.2", "2.1.3", "2.1.4", "2.1.5", "2.1.6", "2.1.7",
		"2.1.8", "2.1.9", "2.1.10", "2.1.11", "2.1.12", "2.1.13",
		"2.1.14", "2.1.15", "2.4.1", "2.4.2", "2.4.4",
	],
	"facts_present": facts_present,
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}
