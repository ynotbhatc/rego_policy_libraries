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
#   input.exchange.owa_mailbox_policies[]    - {Name, AdditionalStorageProvidersAvailable}
#   input.exchange.audit_bypass_associations[] - mailboxes with bypass ENABLED
#   input.exchange.mailbox_audit             - {sampled, sample_limit, audit_disabled[]}
#   input.exchange.unavailable               - {fact_key: reason}

package cis_m365_v7.exchange

import rego.v1

default compliant := false

default unavailable := {}

unavailable := input.exchange.unavailable

default collected := false

collected if {
	input.exchange.collected == true
}

available(key) if {
	collected
	not unavailable[key]
}

# ── Get-OrganizationConfig -- four controls ───────────────────────────

# CIS 6.1.1 -- AuditDisabled must be False organizationally.
violation contains msg if {
	available("organization_config")
	input.exchange.organization_config.AuditDisabled == true
	msg := "CIS 6.1.1: AuditDisabled is True organizationally, so mailbox auditing is off tenant-wide and mailbox actions are not recorded"
}

# CIS 6.5.1 -- modern authentication for Exchange Online.
violation contains msg if {
	available("organization_config")
	input.exchange.organization_config.OAuth2ClientProfileEnabled == false
	msg := "CIS 6.5.1: modern authentication for Exchange Online is not enabled; legacy authentication bypasses Conditional Access and multifactor requirements"
}

# CIS 6.5.2 -- MailTips enabled for end users.
violation contains msg if {
	available("organization_config")
	input.exchange.organization_config.MailTipsAllTipsEnabled == false
	msg := "CIS 6.5.2: MailTips are not enabled for end users, removing the warning shown before mail is sent to external recipients"
}

# CIS 6.5.5 -- Direct Send submissions rejected.
violation contains msg if {
	available("organization_config")
	input.exchange.organization_config.RejectDirectSend == false
	msg := "CIS 6.5.5: Direct Send submissions are not rejected, so unauthenticated mail can be submitted to the tenant as an internal sender"
}

# ── Other single-cmdlet controls ──────────────────────────────────────

# CIS 6.5.4 -- SMTP AUTH disabled.
violation contains msg if {
	available("transport_config")
	input.exchange.transport_config.SmtpClientAuthenticationDisabled == false
	msg := "CIS 6.5.4: SMTP AUTH is not disabled; the legacy SMTP client submission path authenticates with a password alone"
}

# CIS 6.1.3 -- AuditBypassEnabled must not be set on any mailbox.
violation contains msg if {
	available("audit_bypass_associations")
	some a in input.exchange.audit_bypass_associations
	msg := sprintf("CIS 6.1.3: AuditBypassEnabled is set on '%s', so actions against that mailbox are excluded from the audit record", [a.Identity])
}

# CIS 6.1.2 -- mailbox audit actions configured.
violation contains msg if {
	available("mailbox_audit")
	some m in input.exchange.mailbox_audit.audit_disabled
	msg := sprintf("CIS 6.1.2: mailbox audit actions are not configured for '%s' -- auditing is off for that mailbox", [m.user_principal_name])
}

# CIS 6.2.1 -- mail forwarding blocked.
violation contains msg if {
	available("outbound_spam_policies")
	some p in input.exchange.outbound_spam_policies
	p.AutoForwardingMode != "Off"
	msg := sprintf("CIS 6.2.1: outbound spam policy '%s' has AutoForwardingMode '%s'; automatic mail forwarding to external recipients should be blocked", [p.Name, p.AutoForwardingMode])
}

violation contains msg if {
	available("transport_rules")
	some r in input.exchange.transport_rules
	r.State == "Enabled"
	count(object.get(r, "RedirectMessageTo", [])) > 0
	msg := sprintf("CIS 6.2.1: transport rule '%s' redirects mail to another recipient, which is a form of forwarding the benchmark requires be blocked", [r.Name])
}

# CIS 6.2.2 -- transport rules must not whitelist specific domains.
violation contains msg if {
	available("transport_rules")
	some r in input.exchange.transport_rules
	r.State == "Enabled"
	r.SetSCL == -1
	count(object.get(r, "SenderDomainIs", [])) > 0
	msg := sprintf("CIS 6.2.2: transport rule '%s' whitelists specific sender domains by bypassing spam filtering (SCL -1); a spoofed sender in that domain is delivered unfiltered", [r.Name])
}

# CIS 6.2.3 -- external senders identified.
violation contains msg if {
	available("external_in_outlook")
	some e in input.exchange.external_in_outlook
	e.Enabled == false
	msg := "CIS 6.2.3: email from external senders is not identified in Outlook, removing the visual cue users rely on to spot impersonation"
}

# CIS 6.3.1 -- users must not be able to install Outlook add-ins.
violation contains msg if {
	available("role_assignment_policies")
	some p in input.exchange.role_assignment_policies
	some r in p.AssignedRoles
	r in {"My Custom Apps", "My Marketplace Apps", "My ReadWriteMailboxApps"}
	msg := sprintf("CIS 6.3.1: role assignment policy '%s' grants '%s', which allows users installing Outlook add-ins", [p.Name, r])
}

# CIS 6.5.3 / 6.3.2 -- additional storage providers in Outlook on the web.
violation contains msg if {
	available("owa_mailbox_policies")
	some p in input.exchange.owa_mailbox_policies
	p.AdditionalStorageProvidersAvailable == true
	msg := sprintf("CIS 6.5.3: OWA mailbox policy '%s' leaves additional storage providers available in Outlook on the web, so attachments can be saved to third-party storage", [p.Name])
}

violation contains msg if {
	available("owa_mailbox_policies")
	some p in input.exchange.owa_mailbox_policies
	p.AdditionalStorageProvidersAvailable == true
	msg := sprintf("CIS 6.3.2: OWA mailbox policy '%s' permits adding personal accounts and third-party storage in Outlook on the web", [p.Name])
}

# Sampling figures for the 6.1.2 evidence note. Defaulted because a bare
# object.get(input, ...) is undefined when no input is supplied at all, and
# an undefined field collapses compliance_report to {} at the endpoint.
default mailboxes_sampled := 0

mailboxes_sampled := input.exchange.mailbox_audit.sampled

default mailbox_sample_limit := 0

mailbox_sample_limit := input.exchange.mailbox_audit.sample_limit

# ── Fail closed ───────────────────────────────────────────────────────
FACT_CONTROLS := {
	"organization_config": "6.1.1",
	"transport_config": "6.5.4",
	"transport_rules": "6.2.2",
	"outbound_spam_policies": "6.2.1",
	"external_in_outlook": "6.2.3",
	"role_assignment_policies": "6.3.1",
	"owa_mailbox_policies": "6.5.3",
	"audit_bypass_associations": "6.1.3",
	"mailbox_audit": "6.1.2",
}

violation contains msg if {
	some key, reason in unavailable
	control := object.get(FACT_CONTROLS, key, "6.1.1")
	msg := sprintf("CIS %s: could not be evaluated -- %s (this is not a pass)", [control, reason])
}

violation contains msg if {
	not collected
	msg := "CIS 6.1.1: Exchange Online facts were not collected, so whether AuditDisabled is organizationally False could not be established -- section 6 was not evaluated (this is not a pass)"
}

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
	"evidence_strength": {
		"6.1.2": sprintf("sampled -- %v of at most %v mailboxes inspected; the control is about configuration, but a clean result does not prove every mailbox", [mailboxes_sampled, mailbox_sample_limit]),
	},
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}
