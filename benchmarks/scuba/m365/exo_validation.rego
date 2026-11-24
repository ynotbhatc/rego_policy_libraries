# CISA SCuBA — Secure Configuration Baseline for Exchange Online — 12
# policies (MS.EXO.*), per cisagov/ScubaGear (TLP:CLEAR). Removed groups
# (MS.EXO.2.1, MS.EXO.8-12) are absent by design; IDs are never reused.
#
# Input contract — input.scuba.exo.* (sources: Exchange Online PowerShell
# — Get-RemoteDomain, Get-TransportConfig, Get-SharingPolicy,
# Get-OrganizationConfig — plus public DNS lookups for SPF/DKIM/DMARC;
# a collector projects them to the fields below — absence fails closed):
#
#   auto_forwarding_disabled                       MS.EXO.1.1
#   spf_fail_policy_all_domains                    MS.EXO.2.2
#   dkim_enabled_all_domains                       MS.EXO.3.1
#   dmarc.{published_all_domains, policy_reject,
#          rua_includes_cisa, agency_poc_included}  MS.EXO.4.1-4.4
#   smtp_auth_disabled                             MS.EXO.5.1
#   sharing.{contacts_not_all_domains,
#            calendar_not_all_domains}             MS.EXO.6.1-6.2
#   external_sender_warnings                       MS.EXO.7.1
#   mailbox_auditing_enabled                       MS.EXO.13.1
#
# OPA query path (module): /v1/data/scuba_m365/exo/compliance_report

# METADATA
# title: "CISA SCuBA — Secure Configuration Baseline for Exchange Online — 12"
# custom:
#   class: security
#   framework: scuba_m365
#   source: cisa
#   domains: [saas, m365]
#   coverage:
#     checks: 12
#     cited: 12
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package scuba_m365.exo

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

# ── Group 1 — Automatic Forwarding ───────────────────────────────────────────

violations contains msg if {
	not input.scuba.exo.auto_forwarding_disabled == true
	text := "SCuBA MS.EXO.1.1v2 (SHALL): Automatic forwarding to external domains is not disabled"
	msg := _finding(text, ["scuba", "exo", "auto_forwarding_disabled"])
}

# ── Group 2 — SPF ────────────────────────────────────────────────────────────

violations contains msg if {
	not input.scuba.exo.spf_fail_policy_all_domains == true
	text := "SCuBA MS.EXO.2.2v3 (SHALL): An SPF policy failing all non-approved senders is not published for every domain"
	msg := _finding(text, ["scuba", "exo", "spf_fail_policy_all_domains"])
}

# ── Group 3 — DKIM ───────────────────────────────────────────────────────────

violations contains msg if {
	not input.scuba.exo.dkim_enabled_all_domains == true
	text := "SCuBA MS.EXO.3.1v1 (SHOULD): DKIM is not enabled for all domains"
	msg := _finding(text, ["scuba", "exo", "dkim_enabled_all_domains"])
}

# ── Group 4 — DMARC ──────────────────────────────────────────────────────────

violations contains msg if {
	not input.scuba.exo.dmarc.published_all_domains == true
	text := "SCuBA MS.EXO.4.1v1 (SHALL): A DMARC policy is not published for every second-level domain"
	msg := _finding(text, ["scuba", "exo", "dmarc", "published_all_domains"])
}

violations contains msg if {
	not input.scuba.exo.dmarc.policy_reject == true
	text := "SCuBA MS.EXO.4.2v1 (SHALL): DMARC message rejection option is not p=reject"
	msg := _finding(text, ["scuba", "exo", "dmarc", "policy_reject"])
}

violations contains msg if {
	not input.scuba.exo.dmarc.rua_includes_cisa == true
	text := "SCuBA MS.EXO.4.3v1 (SHALL): DMARC aggregate-report contacts do not include reports@dmarc.cyber.dhs.gov"
	msg := _finding(text, ["scuba", "exo", "dmarc", "rua_includes_cisa"])
}

violations contains msg if {
	not input.scuba.exo.dmarc.agency_poc_included == true
	text := "SCuBA MS.EXO.4.4v1 (SHOULD): No agency point of contact is included for DMARC aggregate and failure reports"
	msg := _finding(text, ["scuba", "exo", "dmarc", "agency_poc_included"])
}

# ── Group 5 — SMTP AUTH ──────────────────────────────────────────────────────

violations contains msg if {
	not input.scuba.exo.smtp_auth_disabled == true
	text := "SCuBA MS.EXO.5.1v1 (SHALL): SMTP AUTH is not disabled"
	msg := _finding(text, ["scuba", "exo", "smtp_auth_disabled"])
}

# ── Group 6 — Calendar and Contact Sharing ───────────────────────────────────

violations contains msg if {
	not input.scuba.exo.sharing.contacts_not_all_domains == true
	text := "SCuBA MS.EXO.6.1v1 (SHALL): Contact folders are shared with all domains"
	msg := _finding(text, ["scuba", "exo", "sharing", "contacts_not_all_domains"])
}

violations contains msg if {
	not input.scuba.exo.sharing.calendar_not_all_domains == true
	text := "SCuBA MS.EXO.6.2v1 (SHALL): Calendar details are shared with all domains"
	msg := _finding(text, ["scuba", "exo", "sharing", "calendar_not_all_domains"])
}

# ── Group 7 — External Sender Warnings ───────────────────────────────────────

violations contains msg if {
	not input.scuba.exo.external_sender_warnings == true
	text := "SCuBA MS.EXO.7.1v1 (SHALL): External sender warnings are not implemented"
	msg := _finding(text, ["scuba", "exo", "external_sender_warnings"])
}

# ── Group 13 — Mailbox Auditing ──────────────────────────────────────────────

violations contains msg if {
	not input.scuba.exo.mailbox_auditing_enabled == true
	text := "SCuBA MS.EXO.13.1v1 (SHALL): Mailbox auditing is not enabled"
	msg := _finding(text, ["scuba", "exo", "mailbox_auditing_enabled"])
}

# ── Report ───────────────────────────────────────────────────────────────────

shall_violations := [v | some v in violations; contains(v, "(SHALL)")]

should_violations := [v | some v in violations; contains(v, "(SHOULD)")]

compliance_report := {
	"product": "Exchange Online",
	"baseline": "MS.EXO",
	"controls_evaluated": 12,
	"compliant": compliant,
	"violations": violations,
	"violation_count": count(violations),
	"shall_violation_count": count(shall_violations),
	"should_violation_count": count(should_violations),
}
