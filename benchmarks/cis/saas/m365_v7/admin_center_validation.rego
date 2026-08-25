# CIS Microsoft 365 Foundations Benchmark v7.0.0
# Section 1 -- Microsoft 365 admin center
#
# 11 of section 1's 15 recommendations are evaluated here, via Microsoft
# Graph and Exchange Online PowerShell. The other four are carried by the
# ledger in attestation_validation.rego, never dropped:
#
#   1.1.2, 1.3.8    unresolved      collectability not yet established
#   1.2.2, 1.3.3    not_implemented automatable; the collector does not
#                                   make the call yet
#
# Keep this list accurate. Section 1 previously described itself as
# "9 of 15" with 1.3.6 and 1.3.9 unimplemented long after both were built,
# and 1.2.2 was named nowhere at all -- which is how it came to be missing
# from the report entirely.
#
# Every control id below is verified against the benchmark by
# scripts/check_cis_ids.py, which fails CI if an id does not exist or if
# the message does not correspond to the control that id names.
#
# Input contract (aac.m365.m365_admin_center_facts):
#   input.admin_center.global_admins[]      - {id, display_name,
#                                              on_premises_sync_enabled, licenses[]}
#   input.admin_center.global_admin_count   - int
#   input.admin_center.public_groups[]      - {id, display_name}
#   input.admin_center.domains[]            - {id, is_verified,
#                                              password_validity_period_in_days}
#   input.admin_center.activity_based_timeout_policies[]
#   input.admin_center.user_owned_apps_and_services - {is_office_store_enabled, ...}
#   input.admin_center.forms                - {is_internal_phishing_protection_enabled}
#   input.admin_center.third_party_storage_service_principals[]
#   input.admin_center.unavailable          - {fact_key: reason} -- see below
#
# FAIL-CLOSED CONTRACT: the collector records every endpoint it could not
# read in `unavailable` rather than defaulting the value. Each control
# below checks its own fact's availability first, so a permission gap
# produces "could not be evaluated", never a pass.

package cis_m365_v7.admin_center

import rego.v1

default compliant := false

# Graph reports "never expires" as this sentinel rather than a null.
PASSWORD_NEVER_EXPIRES := 2147483647

# Idle session timeout must be 3 hours or less; the benchmark's unit is hours.
MAX_IDLE_SESSION_HOURS := 3

# `default` matters here: with no input at all (a bare `opa eval`, or a
# collector that never ran) a top-level object.get(input, ...) is
# undefined, which collapses compliance_report to {} at the endpoint.
default unavailable := {}

unavailable := input.admin_center.unavailable

default collected := false

collected if {
	input.admin_center.collected == true
}

# A fact is usable only when the collector did not record a gap for it.
available(key) if {
	collected
	not unavailable[key]
}

# ── CIS 1.1.1 -- administrative accounts must be cloud-only ───────────
violation contains msg if {
	available("global_admins")
	some a in input.admin_center.global_admins
	a.on_premises_sync_enabled == true
	msg := sprintf("CIS 1.1.1: administrative account '%s' is synced from on-premises, not cloud-only -- an on-prem compromise reaches this privileged account", [a.user_principal_name])
}

# ── CIS 1.1.3 -- between two and four global admins ──────────────────
violation contains msg if {
	available("global_admins")
	input.admin_center.global_admin_count < 2
	msg := sprintf("CIS 1.1.3: only %d global admin(s) designated; fewer than two risks lockout with no second administrator", [input.admin_center.global_admin_count])
}

violation contains msg if {
	available("global_admins")
	input.admin_center.global_admin_count > 4
	msg := sprintf("CIS 1.1.3: %d global admins designated; more than four widens standing privilege beyond what the benchmark permits", [input.admin_center.global_admin_count])
}

# ── CIS 1.1.4 -- admin accounts on reduced-footprint licences ─────────
# The benchmark's intent: a privileged account should not also carry the
# mail/Teams/SharePoint application surface an attacker can phish.
BROAD_LICENSE_MARKERS := {"ENTERPRISEPACK", "ENTERPRISEPREMIUM", "SPE_E3", "SPE_E5", "O365_BUSINESS_PREMIUM"}

violation contains msg if {
	available("global_admins")
	some a in input.admin_center.global_admins
	some l in a.licenses
	l.sku_part_number in BROAD_LICENSE_MARKERS
	msg := sprintf("CIS 1.1.4: administrative account '%s' holds licenses '%s', which is not a reduced application footprint -- privileged accounts should not carry the full productivity surface", [a.user_principal_name, l.sku_part_number])
}

# ── CIS 1.2.1 -- only approved public groups ─────────────────────────
violation contains msg if {
	available("groups")
	some g in input.admin_center.public_groups
	msg := sprintf("CIS 1.2.1: group '%s' is Public, so any member of the organizationally managed directory can join and read its content -- confirm it is approved or set it to Private", [g.display_name])
}

# ── CIS 1.3.1 -- password expiration set to never expire ─────────────
violation contains msg if {
	available("domains")
	some d in input.admin_center.domains
	d.is_verified == true
	d.password_validity_period_in_days != PASSWORD_NEVER_EXPIRES
	msg := sprintf("CIS 1.3.1: domain '%s' expires passwords after %v days; the recommended policy is to set passwords to never expire, because forced rotation drives weaker secrets", [d.id, d.password_validity_period_in_days])
}

# ── CIS 1.3.2 -- idle session timeout ────────────────────────────────
violation contains msg if {
	available("activity_based_timeout")
	count(input.admin_center.activity_based_timeout_policies) == 0
	msg := sprintf("CIS 1.3.2: no idle session timeout policy is configured; the benchmark requires %d hours or less for unmanaged devices", [MAX_IDLE_SESSION_HOURS])
}

# ── CIS 1.3.4 -- user owned apps and services restricted ─────────────
violation contains msg if {
	available("apps_and_services")
	input.admin_center.user_owned_apps_and_services.is_office_store_enabled == true
	msg := "CIS 1.3.4: 'User owned apps and services' is not restricted -- users can acquire Office Store add-ins that read mailbox and document content"
}

# ── CIS 1.3.5 -- internal phishing protection for Forms ──────────────
violation contains msg if {
	available("forms")
	input.admin_center.forms.is_internal_phishing_protection_enabled == false
	msg := "CIS 1.3.5: internal phishing protection for Forms is not enabled -- Forms is a common internal credential-harvesting vector"
}

# ── CIS 1.3.7 -- third-party storage services restricted ─────────────
violation contains msg if {
	available("service_principals")
	some s in input.admin_center.third_party_storage_service_principals
	s.account_enabled == true
	msg := sprintf("CIS 1.3.7: third-party storage service '%s' is enabled in Microsoft 365 on the web -- corporate documents can be saved outside the tenant", [s.display_name])
}

# ── Fail closed on every gap the collector recorded ───────────────────
# One violation per unreadable fact, naming the control it blocks, so the
# report distinguishes "measured and clean" from "never measured".
FACT_CONTROLS := {
	"global_admins": "1.1.1",
	"admin_licenses": "1.1.4",
	"admin_sync_state": "1.1.1",
	"groups": "1.2.1",
	"domains": "1.3.1",
	"activity_based_timeout": "1.3.2",
	"apps_and_services": "1.3.4",
	"forms": "1.3.5",
	"service_principals": "1.3.7",
}

violation contains msg if {
	some key, reason in unavailable
	control := object.get(FACT_CONTROLS, key, "1.1.1")
	msg := sprintf("CIS %s: could not be evaluated -- %s (this is not a pass)", [control, reason])
}

violation contains msg if {
	not collected
	msg := "CIS 1.1.1: administrative accounts were not collected, so whether they are cloud-only could not be established -- section 1 was not evaluated (this is not a pass)"
}


# ── Section 1 controls sourced from Exchange Online PowerShell ────────
# 1.3.6 and 1.3.9 are section 1 controls whose settings live on
# Get-OrganizationConfig, which the Exchange collector already fetches.
# Reading them from input.exchange rather than issuing a second Exchange
# session for two fields is deliberate; the coupling is documented here so
# it is not mistaken for a stray dependency.

default exchange_org_available := false

exchange_org_available if {
	input.exchange.collected == true
	not input.exchange.unavailable.organization_config
	_ := input.exchange.organization_config
}

# CIS 1.3.6 -- customer lockbox.
violation contains msg if {
	exchange_org_available
	input.exchange.organization_config.CustomerLockBoxEnabled == false
	msg := "CIS 1.3.6: the customer lockbox feature is not enabled, so Microsoft support can access tenant content without explicit per-request approval"
}

# CIS 1.3.9 -- shared bookings pages.
violation contains msg if {
	exchange_org_available
	input.exchange.organization_config.BookingsEnabled == true
	input.exchange.organization_config.BookingsAuthEnabled == false
	msg := "CIS 1.3.9: shared bookings pages are not restricted to select users -- Bookings is enabled without requiring authentication, so pages are reachable anonymously"
}

violation contains msg if {
	input.exchange.collected == true
	input.exchange.unavailable.organization_config
	msg := sprintf("CIS 1.3.6: whether the customer lockbox feature is enabled could not be evaluated -- %s (this is not a pass)", [input.exchange.unavailable.organization_config])
}

compliant if {
	collected
	count(violation) == 0
}

compliance_report := {
	"benchmark": "CIS Microsoft 365 Foundations Benchmark",
	"benchmark_version": "7.0.0",
	"section": "1",
	"name": "Microsoft 365 admin center",
	"section_total_controls": 15,
	"controls_evaluated": 11,
	"controls": ["1.1.1", "1.1.3", "1.1.4", "1.2.1", "1.3.1", "1.3.2", "1.3.4", "1.3.5", "1.3.6", "1.3.7", "1.3.9"],
	"facts_present": collected,
	"unavailable_facts": unavailable,
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}
