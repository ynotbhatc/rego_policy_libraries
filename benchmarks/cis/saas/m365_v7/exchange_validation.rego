# CIS Microsoft 365 Foundations Benchmark v7.0.0
# Section 6 -- Exchange admin center
#
# All 13 of section 6's recommendations are audited through Exchange
# Online PowerShell; Microsoft exposes no REST equivalent. Facts come from
# aac.m365.m365_exchange_ps_facts running in the aac-m365-ee execution
# environment.
#
# EVIDENCE UPGRADE: 6.1.1 was previously a proxy. Graph v1.0 does not
# expose the tenant-wide AuditDisabled flag, so the earlier collector
# sampled per-user mailbox settings and could only ever be indicative.
# Get-OrganizationConfig reads the flag directly, which is what the
# benchmark's own audit procedure does. The control is now measured, not
# inferred.
#
# Input contract (aac.m365.m365_exchange_ps_facts):
#   input.exchange.organization_config       - {AuditDisabled, OAuth2ClientProfileEnabled,
#                                               MailTipsAllTipsEnabled, RejectDirectSend, ...}
#   input.exchange.transport_config          - {SmtpClientAuthenticationDisabled}
#   input.exchange.transport_rules[]         - {Name, State, SetSCL, SenderDomainIs, ...}
#   input.exchange.outbound_spam_policies[]  - {Name, AutoForwardingMode, IsDefault}
#   input.exchange.external_in_outlook[]     - {Identity, Enabled}
#   input.exchange.role_assignment_policies[] - {Name, IsDefault, AssignedRoles}
#   input.exchange.owa_mailbox_policies[]    - {Name, IsDefault, AdditionalStorageProvidersAvailable,
#                                               PersonalAccountsEnabled, PersonalAccountCalendarsEnabled}
#   input.exchange.audit_bypass_associations[] - mailboxes with bypass ENABLED
#   input.exchange.mailbox_audit             - {sampled, sample_limit, audit_disabled[]}
#   input.exchange.unavailable               - {fact_key: reason}

# METADATA
# title: "CIS Microsoft 365 Foundations Benchmark v7.0.0"
# custom:
#   class: security
#   framework: cis_saas
#   source: cis
#   domains: [saas, m365]
#   coverage:
#     checks: 15
#     cited: 13
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package cis_m365_v7.exchange

import rego.v1

default compliant := false

# Every rule below compares a field only when it has the type the rule expects
# and iterates a list only when it is a list; a missing field or a wrong shape
# leaves the control out of `decidable`, and the evidence rules at the end of
# the file report it by id. It is never read as a pass or as a failure.

default unavailable := {}

unavailable := input.exchange.unavailable if is_object(input.exchange.unavailable)

default collected := false

collected if {
	input.exchange.collected == true
}

available(key) if {
	collected
	not unavailable[key]
}

_list(key) := input.exchange[key] if {
	available(key)
	is_array(input.exchange[key])
}

_object(key) := input.exchange[key] if {
	available(key)
	is_object(input.exchange[key])
}

# ── Get-OrganizationConfig -- four controls ───────────────────────────

violation contains msg if {
	_object("organization_config").AuditDisabled == true
	msg := "CIS 6.1.1: AuditDisabled is True organizationally, so mailbox auditing is off tenant-wide and mailbox actions are not recorded"
}

violation contains msg if {
	_object("organization_config").OAuth2ClientProfileEnabled == false
	msg := "CIS 6.5.1: modern authentication for Exchange Online is not enabled; legacy authentication bypasses Conditional Access and multifactor requirements"
}

violation contains msg if {
	_object("organization_config").MailTipsAllTipsEnabled == false
	msg := "CIS 6.5.2: MailTips are not enabled for end users, removing the warning shown before mail is sent to external recipients"
}

violation contains msg if {
	_object("organization_config").RejectDirectSend == false
	msg := "CIS 6.5.5: Direct Send submissions are not rejected, so unauthenticated mail can be submitted to the tenant as an internal sender"
}

# ── Other single-cmdlet controls ──────────────────────────────────────

violation contains msg if {
	_object("transport_config").SmtpClientAuthenticationDisabled == false
	msg := "CIS 6.5.4: SMTP AUTH is not disabled; the legacy SMTP client submission path authenticates with a password alone"
}

violation contains msg if {
	some a in _list("audit_bypass_associations")
	msg := sprintf("CIS 6.1.3: AuditBypassEnabled is set on '%s', so actions against that mailbox are excluded from the audit record", [object.get(a, "Identity", "(unnamed)")])
}

_audit_disabled := input.exchange.mailbox_audit.audit_disabled if {
	is_array(_object("mailbox_audit").audit_disabled)
}

violation contains msg if {
	some m in _audit_disabled
	msg := sprintf("CIS 6.1.2: mailbox audit actions are not configured for '%s' -- auditing is off for that mailbox", [object.get(m, "user_principal_name", "(unnamed)")])
}

violation contains msg if {
	some p in _list("outbound_spam_policies")
	is_string(p.AutoForwardingMode)
	p.AutoForwardingMode != "Off"
	msg := sprintf("CIS 6.2.1: outbound spam policy '%s' has AutoForwardingMode '%s'; automatic mail forwarding to external recipients should be blocked", [object.get(p, "Name", "(unnamed)"), p.AutoForwardingMode])
}

# Transport rule predicates and actions that are not set come back as null from
# Get-TransportRule; null (or absent) is read as "not set". State must be known.
_rule_list(r, field) := v if {
	v := object.get(r, field, null)
	is_array(v)
}

_rule_list(r, field) := [] if object.get(r, field, null) == null

_enabled_rules contains r if {
	some r in _list("transport_rules")
	r.State == "Enabled"
}

violation contains msg if {
	some r in _enabled_rules
	count(_rule_list(r, "RedirectMessageTo")) > 0
	msg := sprintf("CIS 6.2.1: transport rule '%s' redirects mail to another recipient, which is a form of forwarding the benchmark requires be blocked", [object.get(r, "Name", "(unnamed)")])
}

violation contains msg if {
	some r in _enabled_rules
	r.SetSCL == -1
	count(_rule_list(r, "SenderDomainIs")) > 0
	msg := sprintf("CIS 6.2.2: transport rule '%s' whitelists specific sender domains by bypassing spam filtering (SCL -1); a spoofed sender in that domain is delivered unfiltered", [object.get(r, "Name", "(unnamed)")])
}

violation contains msg if {
	some e in _list("external_in_outlook")
	e.Enabled == false
	msg := "CIS 6.2.3: email from external senders is not identified in Outlook, removing the visual cue users rely on to spot impersonation"
}

violation contains msg if {
	some p in _list("role_assignment_policies")
	is_array(p.AssignedRoles)
	some r in p.AssignedRoles
	r in {"My Custom Apps", "My Marketplace Apps", "My ReadWriteMailboxApps"}
	msg := sprintf("CIS 6.3.1: role assignment policy '%s' grants '%s', which allows users installing Outlook add-ins", [object.get(p, "Name", "(unnamed)"), r])
}

violation contains msg if {
	some p in _list("owa_mailbox_policies")
	p.AdditionalStorageProvidersAvailable == true
	msg := sprintf("CIS 6.5.3: OWA mailbox policy '%s' leaves additional storage providers available in Outlook on the web, so attachments can be saved to third-party storage", [object.get(p, "Name", "(unnamed)")])
}

# CIS 6.3.2 -- users cannot add personal accounts in Outlook. CIS evaluates the
# default OWA mailbox policy only (IsDefault): PersonalAccountsEnabled and
# PersonalAccountCalendarsEnabled must both be False. This module used to read
# AdditionalStorageProvidersAvailable here, which is the property of 6.5.3.
# https://learn.microsoft.com/en-us/powershell/module/exchange/set-owamailboxpolicy
PERSONAL_ACCOUNT_FIELDS := ["PersonalAccountsEnabled", "PersonalAccountCalendarsEnabled"]

_default_owa_policies contains p if {
	some p in _list("owa_mailbox_policies")
	p.IsDefault == true
}

violation contains msg if {
	some p in _default_owa_policies
	some field in PERSONAL_ACCOUNT_FIELDS
	p[field] == true
	msg := sprintf("CIS 6.3.2: the default OWA mailbox policy '%s' has %s True, so users can add personal accounts to Outlook alongside their work mailbox", [object.get(p, "Name", "(unnamed)"), field])
}

default mailboxes_sampled := 0

mailboxes_sampled := input.exchange.mailbox_audit.sampled

default mailbox_sample_limit := 0

mailbox_sample_limit := input.exchange.mailbox_audit.sample_limit

compliant if {
	collected
	count(violation) == 0
}

compliance_report := {
	"benchmark": "CIS Microsoft 365 Foundations Benchmark",
	"benchmark_version": "7.0.0",
	"section": "6",
	"name": "Exchange admin center",
	"section_total_controls": 13,
	"controls_evaluated": 13,
	"controls": [
		"6.1.1", "6.1.2", "6.1.3",
		"6.2.1", "6.2.2", "6.2.3",
		"6.3.1", "6.3.2",
		"6.5.1", "6.5.2", "6.5.3", "6.5.4", "6.5.5",
	],
	"facts_present": collected,
	"unavailable_facts": unavailable,
	"evidence_strength": {"6.1.2": sprintf("sampled -- %v of at most %v mailboxes inspected; the control is about configuration, but a clean result does not prove every mailbox", [mailboxes_sampled, mailbox_sample_limit])},
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
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
	"6.1.1": ["exchange.organization_config.AuditDisabled"],
	"6.1.2": ["exchange.mailbox_audit.audit_disabled", "exchange.mailbox_audit.sample_limit", "exchange.mailbox_audit.sampled"],
	"6.1.3": ["exchange.audit_bypass_associations"],
	"6.2.1": ["exchange.outbound_spam_policies[].AutoForwardingMode", "exchange.transport_rules[].RedirectMessageTo", "exchange.transport_rules[].State"],
	"6.2.2": ["exchange.transport_rules[].SenderDomainIs", "exchange.transport_rules[].SetSCL", "exchange.transport_rules[].State"],
	"6.2.3": ["exchange.external_in_outlook[].Enabled"],
	"6.3.1": ["exchange.role_assignment_policies[].AssignedRoles"],
	"6.3.2": ["exchange.owa_mailbox_policies[].IsDefault", "exchange.owa_mailbox_policies[].PersonalAccountCalendarsEnabled", "exchange.owa_mailbox_policies[].PersonalAccountsEnabled"],
	"6.5.1": ["exchange.organization_config.OAuth2ClientProfileEnabled"],
	"6.5.2": ["exchange.organization_config.MailTipsAllTipsEnabled"],
	"6.5.3": ["exchange.owa_mailbox_policies[].AdditionalStorageProvidersAvailable"],
	"6.5.4": ["exchange.transport_config.SmtpClientAuthenticationDisabled"],
	"6.5.5": ["exchange.organization_config.RejectDirectSend"],
}

_org_carries(field) if is_boolean(_object("organization_config")[field])

_every_carries(key, field) if {
	every p in _list(key) {
		is_boolean(p[field])
	}
}

decidable contains "6.1.1" if _org_carries("AuditDisabled")

decidable contains "6.5.1" if _org_carries("OAuth2ClientProfileEnabled")

decidable contains "6.5.2" if _org_carries("MailTipsAllTipsEnabled")

decidable contains "6.5.5" if _org_carries("RejectDirectSend")

decidable contains "6.5.4" if is_boolean(_object("transport_config").SmtpClientAuthenticationDisabled)

decidable contains "6.1.3" if is_array(_list("audit_bypass_associations"))

# 6.1.2 is a sampled control: how many mailboxes were inspected, and the limit, are part of the evidence (the
# report states them as its strength), so both must be numbers
decidable contains "6.1.2" if {
	is_array(_audit_disabled)
	is_number(_object("mailbox_audit").sampled)
	is_number(_object("mailbox_audit").sample_limit)
}

# a transport rule field that is not set is null or absent; anything else must be a list
_rule_field_readable(r, field) if object.get(r, field, null) == null

_rule_field_readable(r, field) if is_array(r[field])

_rules_readable(fields) if {
	every r in _list("transport_rules") {
		is_string(r.State)
		every f in fields {
			_rule_field_readable(r, f)
		}
	}
}

decidable contains "6.2.1" if {
	every p in _list("outbound_spam_policies") {
		is_string(p.AutoForwardingMode)
	}
	_rules_readable(["RedirectMessageTo"])
}

decidable contains "6.2.2" if {
	_rules_readable(["SenderDomainIs"])
	every r in _list("transport_rules") {
		_scl_readable(object.get(r, "SetSCL", null))
	}
}

_scl_readable(v) if v == null

_scl_readable(v) if is_number(v)

decidable contains "6.2.3" if _every_carries("external_in_outlook", "Enabled")

decidable contains "6.3.1" if {
	every p in _list("role_assignment_policies") {
		is_array(p.AssignedRoles)
	}
}

# the default policy must be identifiable and carry both properties
decidable contains "6.3.2" if {
	_every_carries("owa_mailbox_policies", "IsDefault")
	count(_default_owa_policies) > 0
	every p in _default_owa_policies {
		every field in PERSONAL_ACCOUNT_FIELDS {
			is_boolean(p[field])
		}
	}
}

decidable contains "6.5.3" if _every_carries("owa_mailbox_policies", "AdditionalStorageProvidersAvailable")

# ── Evidence gaps, reported by control id ─────────────────────────────
# A gap names every control it blocks, so the per-control results and an
# exporter reading the ids agree on what was not evaluated. Keys read by
# other sections (1.2.2, 1.3.3) are reported there; a key no section knows
# is reported on its own, attributed to no control.
FACT_CONTROLS := {
	"organization_config": ["6.1.1", "6.5.1", "6.5.2", "6.5.5"],
	"transport_config": ["6.5.4"],
	"transport_rules": ["6.2.1", "6.2.2"],
	"outbound_spam_policies": ["6.2.1"],
	"external_in_outlook": ["6.2.3"],
	"role_assignment_policies": ["6.3.1"],
	"owa_mailbox_policies": ["6.3.2", "6.5.3"],
	"audit_bypass_associations": ["6.1.3"],
	"mailbox_audit": ["6.1.2"],
}

# Exchange facts that section 1 (admin_center) reads and reports itself
OTHER_SECTION_KEYS := {"sharing_policies", "shared_mailboxes"}

_section_controls := _natural_sort(object.keys(CONTROL_EVIDENCE))

# ids in benchmark order
_natural_sort(ids) := [pair[1] | some pair in sort([[key, id] |
	some id in ids
	parts := split(id, ".")
	key := concat(".", [sprintf("%03d", [to_number(x)]) | some x in parts])
])]

_gap(ids, why) := sprintf("CIS %s: evidence missing -- %s (this is not a pass)", [concat("/", ids), why])

_source_gaps contains [_section_controls, "Exchange Online facts were not collected (exchange.collected is not true)"] if not collected

_source_gaps contains [FACT_CONTROLS[key], sprintf("exchange.unavailable.%s: %v", [key, reason])] if {
	collected
	some key, reason in unavailable
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
	some key, reason in unavailable
	not FACT_CONTROLS[key]
	not key in OTHER_SECTION_KEYS
	msg := sprintf("M365 section 6 (Exchange): unrecognised unavailable key '%s' (%v) -- no section reads a fact of that name, so it is attributed to no control (this is not a pass)", [key, reason])
}

_evidence_gaps contains _gap([id], why) if {
	some id, paths in CONTROL_EVIDENCE
	not id in decidable
	not id in _gap_ids
	why := sprintf("%s not collected or not of the expected type", [concat(", ", paths)])
}

violation contains msg if some msg in _evidence_gaps
