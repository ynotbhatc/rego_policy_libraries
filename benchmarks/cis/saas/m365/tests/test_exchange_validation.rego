# Rego tests for cis_m365.exchange. Pin each violation rule's
# positive and negative path; pin the customer-vs-initial domain
# filter.

package cis_m365.exchange_test

import rego.v1
import data.cis_m365.exchange


# Baseline that should pass cleanly.
base_input := {
    "verified_domains": [
        {
            "id": "acme.onmicrosoft.com",
            "is_default": false,
            "is_initial": true,
            "spf_present": false,    # don't care — initial domain
            "dmarc_present": false,
            "dkim_present": false,
        },
        {
            "id": "acme.com",
            "is_default": true,
            "is_initial": false,
            "spf_present": true,
            "dmarc_present": true,
            "dkim_present": true,
        },
    ],
    "mailbox_audit_summary": {
        "sampled": 10,
        "audit_enabled": 10,
        "audit_disabled": 0,
        "evaluable": true,
    },
    "secure_score_controls": [
        {"id": "ExternalSenderTagging", "implementation_status": "Implemented"},
        {"id": "SMTPAuthDisabled", "implementation_status": "Implemented"},
    ],
    "org_settings": {"display_name": "Acme", "tenant_type": "AAD", "verified_domain_count": 2},
}


# ── Clean baseline is compliant ────────────────────────────────────

test_clean_baseline_is_compliant if {
    exchange.compliant with input as base_input
}


# ── 4.1.1 — Mailbox auditing ────────────────────────────────────────

test_4_1_1_violation_when_any_mailbox_audit_disabled if {
    inp := json.patch(base_input, [
        {"op": "replace", "path": "/mailbox_audit_summary/audit_disabled", "value": 1},
    ])
    some msg in exchange.violation_4_1_1 with input as inp
    contains(msg, "audit disabled")
}

test_4_1_1_violation_when_not_evaluable if {
    inp := json.patch(base_input, [
        {"op": "replace", "path": "/mailbox_audit_summary/evaluable", "value": false},
    ])
    some msg in exchange.violation_4_1_1 with input as inp
    contains(msg, "not evaluable")
}


# ── 4.5.1 — SPF on customer domains, NOT on .onmicrosoft.com ───────

test_4_5_1_violation_when_customer_domain_missing_spf if {
    inp := json.patch(base_input, [
        {"op": "replace", "path": "/verified_domains/1/spf_present", "value": false},
    ])
    some msg in exchange.violation_4_5_1 with input as inp
    contains(msg, "acme.com")
}

test_4_5_1_no_violation_for_initial_domain_even_without_spf if {
    # The acme.onmicrosoft.com row already has spf_present=false in
    # the baseline; it should NOT generate a violation.
    count(exchange.violation_4_5_1) == 0 with input as base_input
}


# ── 4.6.1 — DKIM ───────────────────────────────────────────────────

test_4_6_1_violation_when_customer_domain_missing_dkim if {
    inp := json.patch(base_input, [
        {"op": "replace", "path": "/verified_domains/1/dkim_present", "value": false},
    ])
    some msg in exchange.violation_4_6_1 with input as inp
    contains(msg, "DKIM")
}


# ── 4.7.1 — DMARC ──────────────────────────────────────────────────

test_4_7_1_violation_when_customer_domain_missing_dmarc if {
    inp := json.patch(base_input, [
        {"op": "replace", "path": "/verified_domains/1/dmarc_present", "value": false},
    ])
    some msg in exchange.violation_4_7_1 with input as inp
    contains(msg, "DMARC")
}


# ── 4.8.1 — External sender tagging ─────────────────────────────────

test_4_8_1_violation_when_external_tag_not_implemented if {
    inp := json.patch(base_input, [
        {"op": "replace", "path": "/secure_score_controls/0/implementation_status", "value": "NotImplemented"},
    ])
    some msg in exchange.violation_4_8_1 with input as inp
    contains(msg, "External sender tagging")
}


# ── 4.11.1 — SMTP AUTH disabled ────────────────────────────────────

test_4_11_1_violation_when_smtp_auth_not_disabled if {
    inp := json.patch(base_input, [
        {"op": "replace", "path": "/secure_score_controls/1/implementation_status", "value": "NotImplemented"},
    ])
    some msg in exchange.violation_4_11_1 with input as inp
    contains(msg, "SMTP AUTH")
}


# ── Roll-up sanity ─────────────────────────────────────────────────

test_violation_count_roughly_matches_rule_failures if {
    inp := json.patch(base_input, [
        {"op": "replace", "path": "/verified_domains/1/spf_present", "value": false},
        {"op": "replace", "path": "/verified_domains/1/dmarc_present", "value": false},
        {"op": "replace", "path": "/secure_score_controls/0/implementation_status", "value": "NotImplemented"},
    ])
    not exchange.compliant with input as inp
    exchange.compliance_report.violation_count >= 3 with input as inp
}
