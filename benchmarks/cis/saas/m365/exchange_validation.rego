# CIS Microsoft 365 Foundations Benchmark — Section 4 (Microsoft Exchange)
#
# Evaluates the facts emitted by aac.m365.m365_exchange_facts.
#
# Input shape (see module RETURN block for the canonical version):
#   {
#     "verified_domains": [
#       {"id": "example.com", "is_default": true,
#        "spf_present": bool, "dmarc_present": bool, "dkim_present": bool}
#     ],
#     "mailbox_audit_summary": {
#       "sampled": int, "audit_enabled": int,
#       "audit_disabled": int, "evaluable": bool
#     },
#     "secure_score_controls": [
#       {"id": "...", "implementation_status": "Implemented|NotImplemented|..."}
#     ],
#     "org_settings": {...}
#   }

package cis_m365.exchange

import rego.v1

default compliant := false


# ── 4.1.1 — Mailbox auditing enabled tenant-wide ───────────────────

# The Graph v1.0 surface lets us probe per-user mailboxAuditEnabled.
# If ANY sampled user has it disabled, the tenant-wide default is
# almost certainly off (the per-user setting inherits the tenant
# default unless explicitly overridden).
violation_4_1_1 contains msg if {
    input.mailbox_audit_summary.evaluable
    input.mailbox_audit_summary.audit_disabled > 0
    msg := sprintf("CIS 4.1.1: %d of %d sampled mailboxes have audit disabled; enable tenant-wide mailbox audit", [
        input.mailbox_audit_summary.audit_disabled,
        input.mailbox_audit_summary.sampled,
    ])
}

# When we couldn't evaluate (no mailboxAuditEnabled in any sampled
# response), surface that explicitly rather than silently passing.
violation_4_1_1 contains msg if {
    not input.mailbox_audit_summary.evaluable
    input.mailbox_audit_summary.sampled > 0
    msg := "CIS 4.1.1: mailbox audit state not evaluable via Graph; verify tenant-wide setting via Exchange admin center"
}


# ── 4.5.1 — SPF record on every verified non-Microsoft domain ──────

# Microsoft's onmicrosoft.com domain auto-publishes SPF via Microsoft
# itself; we only check customer-owned domains.

customer_domains contains d if {
    some d in input.verified_domains
    not d.is_initial
}

violation_4_5_1 contains msg if {
    some d in customer_domains
    not d.spf_present
    msg := sprintf("CIS 4.5.1: domain %q has no SPF record published; spoofed mail will not be rejected", [d.id])
}


# ── 4.6.1 — DKIM signing for every verified non-Microsoft domain ──

violation_4_6_1 contains msg if {
    some d in customer_domains
    not d.dkim_present
    msg := sprintf("CIS 4.6.1: domain %q has no DKIM CNAME selectors; outbound mail can't be cryptographically authenticated", [d.id])
}


# ── 4.7.1 — DMARC policy for every verified non-Microsoft domain ──

violation_4_7_1 contains msg if {
    some d in customer_domains
    not d.dmarc_present
    msg := sprintf("CIS 4.7.1: domain %q has no DMARC record; recipients have no policy guidance on what to do with failed SPF/DKIM", [d.id])
}


# ── 4.8.1 — External sender tagging enabled ─────────────────────────

# Read from Secure Score. If the relevant control row exists and is
# anything other than "Implemented", flag it. If the row is missing
# entirely, fall back to a softer "not evaluable" warning so the
# operator knows we couldn't see the setting.

external_tag_control := c if {
    some c in input.secure_score_controls
    c.id == "ExternalSenderTagging"
}

violation_4_8_1 contains msg if {
    external_tag_control
    external_tag_control.implementation_status != "Implemented"
    msg := "CIS 4.8.1: External sender tagging is not enabled; users won't see the visual cue distinguishing external from internal mail"
}


# ── 4.11.1 — SMTP AUTH disabled tenant-wide ────────────────────────

smtp_auth_control := c if {
    some c in input.secure_score_controls
    c.id == "SMTPAuthDisabled"
}

violation_4_11_1 contains msg if {
    smtp_auth_control
    smtp_auth_control.implementation_status != "Implemented"
    msg := "CIS 4.11.1: SMTP AUTH is enabled at the tenant level; legacy basic auth on SMTP submission permits credential-stuffing attacks"
}


# ── Roll-up ─────────────────────────────────────────────────────────

violations contains v if { some v in violation_4_1_1 }
violations contains v if { some v in violation_4_5_1 }
violations contains v if { some v in violation_4_6_1 }
violations contains v if { some v in violation_4_7_1 }
violations contains v if { some v in violation_4_8_1 }
violations contains v if { some v in violation_4_11_1 }

compliant if { count(violations) == 0 }

compliance_report := {
    "section": "4",
    "name": "Microsoft Exchange",
    "controls_evaluated": 6,
    "violations": violations,
    "violation_count": count(violations),
    "compliant": compliant,
}
