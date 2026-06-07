# Rego tests for cis_m365.identity. Pin the violation rules.

package cis_m365.identity_test

import rego.v1
import data.cis_m365.identity


# Convenience builders so the test cases stay legible.

base_input := {
    "security_defaults_enabled": false,
    "global_admins": [
        {"display_name": "alice", "has_strong_mfa": true},
        {"display_name": "bob", "has_strong_mfa": true},
    ],
    "conditional_access_policies": [
        {
            "id": "ca-1",
            "display_name": "Require MFA for all users",
            "state": "enabled",
            "grant_controls": {"builtInControls": ["mfa"]},
        },
    ],
    "pim_available": true,
    "pim_role_assignments": [],
}


# ── 1.1.1 — Security Defaults + CA collision ────────────────────────

test_1_1_1_violation_when_security_defaults_on_with_ca if {
    inp := json.patch(base_input, [{"op": "replace", "path": "/security_defaults_enabled", "value": true}])
    some msg in identity.violation_1_1_1 with input as inp
    contains(msg, "Security Defaults is enabled")
}

test_1_1_1_no_violation_when_security_defaults_off if {
    count(identity.violation_1_1_1) == 0 with input as base_input
}

test_1_1_1_no_violation_when_ca_disabled_even_if_sd_on if {
    inp := json.patch(base_input, [
        {"op": "replace", "path": "/security_defaults_enabled", "value": true},
        {"op": "replace", "path": "/conditional_access_policies/0/state", "value": "disabled"},
    ])
    count(identity.violation_1_1_1) == 0 with input as inp
}


# ── 1.1.2 — Global admin count ──────────────────────────────────────

test_1_1_2_violation_when_under_two_admins if {
    inp := json.patch(base_input, [{"op": "replace", "path": "/global_admins", "value": [
        {"display_name": "alice", "has_strong_mfa": true},
    ]}])
    some msg in identity.violation_1_1_2 with input as inp
    contains(msg, "at least 2")
}

test_1_1_2_violation_when_over_four_admins if {
    inp := json.patch(base_input, [{"op": "replace", "path": "/global_admins", "value": [
        {"display_name": "u1", "has_strong_mfa": true},
        {"display_name": "u2", "has_strong_mfa": true},
        {"display_name": "u3", "has_strong_mfa": true},
        {"display_name": "u4", "has_strong_mfa": true},
        {"display_name": "u5", "has_strong_mfa": true},
    ]}])
    some msg in identity.violation_1_1_2 with input as inp
    contains(msg, "too many")
}


# ── 1.1.3 — Strong MFA on every Global Admin ────────────────────────

test_1_1_3_violation_when_admin_lacks_strong_mfa if {
    inp := json.patch(base_input, [{"op": "replace", "path": "/global_admins/0/has_strong_mfa", "value": false}])
    some msg in identity.violation_1_1_3 with input as inp
    contains(msg, "alice")
}


# ── 1.1.4 — User MFA enforced via CA ────────────────────────────────

test_1_1_4_violation_when_no_ca_requires_mfa if {
    inp := json.patch(base_input, [{"op": "replace", "path": "/conditional_access_policies/0/grant_controls/builtInControls", "value": ["block"]}])
    some msg in identity.violation_1_1_4 with input as inp
    contains(msg, "No enabled Conditional Access policy requires MFA")
}


# ── 1.1.5 — PIM available ───────────────────────────────────────────

test_1_1_5_violation_when_pim_unavailable if {
    inp := json.patch(base_input, [{"op": "replace", "path": "/pim_available", "value": false}])
    some msg in identity.violation_1_1_5 with input as inp
    contains(msg, "Privileged Identity Management")
}


# ── Roll-up ─────────────────────────────────────────────────────────

test_clean_tenant_is_compliant if {
    identity.compliant with input as base_input
}

test_violation_count_matches_rule_count if {
    inp := json.patch(base_input, [
        {"op": "replace", "path": "/security_defaults_enabled", "value": true},
        {"op": "replace", "path": "/pim_available", "value": false},
    ])
    not identity.compliant with input as inp
    identity.compliance_report.violation_count >= 2 with input as inp
}
