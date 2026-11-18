# CIS Microsoft 365 Foundations Benchmark v7.0.0
# Section 1 -- Microsoft 365 admin center
#
# 13 of section 1's 15 recommendations are evaluated here, via Microsoft
# Graph and Exchange Online PowerShell. The other two -- 1.1.2 and 1.3.8 --
# are carried as `unresolved` by the ledger in attestation_validation.rego,
# never dropped.
#
# 1.2.2 and 1.3.3 joined this module on 2026-08-25. Both are section 1
# controls whose facts come from Exchange, and 1.2.2 additionally needs
# the Graph sign-in state -- CIS's own procedure for it is a join across
# both surfaces.
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
#   input.admin_center.activity_based_timeout_policies[] - {id, display_name,
#                                              definition[] (JSON strings), is_organization_default}
#   input.admin_center.user_owned_apps_and_services - {is_office_store_enabled, ...}
#   input.admin_center.forms                - {is_internal_phishing_protection_enabled}
#   input.admin_center.third_party_storage_service_principals[]
#   input.admin_center.unavailable          - {fact_key: reason} -- see below
#
# FAIL-CLOSED CONTRACT: the collector records every endpoint it could not
# read in `unavailable` rather than defaulting the value. Each control
# below checks its own fact's availability first, so a permission gap
# produces "could not be evaluated", never a pass.

# METADATA
# title: "CIS Microsoft 365 Foundations Benchmark v7.0.0"
# custom:
#   class: security
#   framework: cis_saas
#   source: cis
#   domains: [saas, m365]
#   coverage:
#     checks: 35
#     cited: 26
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package cis_m365_v7.admin_center

import rego.v1

default compliant := false

# Graph reports "never expires" as this sentinel rather than a null.
PASSWORD_NEVER_EXPIRES := 2147483647

# Idle session timeout must be 3 hours or less; the benchmark's unit is hours.
MAX_IDLE_SESSION_HOURS := 3

# Every rule below compares a field only when it has the type the rule expects
# and iterates a list only when it is a list; a missing field or a wrong shape
# leaves the control out of `decidable`, and the evidence rules at the end of
# the file report it by id. It is never read as a pass or as a failure.

default unavailable := {}

unavailable := input.admin_center.unavailable if is_object(input.admin_center.unavailable)

default collected := false

collected if {
	input.admin_center.collected == true
}

available(key) if {
	collected
	not unavailable[key]
}

# an admin_center list behind an availability key; undefined when the key is
# unavailable or the value is not a list
_list(key, field) := input.admin_center[field] if {
	available(key)
	is_array(input.admin_center[field])
}

_object(key, field) := input.admin_center[field] if {
	available(key)
	is_object(input.admin_center[field])
}

# the global administrators, once their sync state and licences are both readable
_admins := _list("global_admins", "global_admins")

# CIS 1.1.1 -- administrative accounts cloud-only.
violation contains msg if {
	available("admin_sync_state")
	some a in _admins
	a.on_premises_sync_enabled == true
	msg := sprintf("CIS 1.1.1: administrative account '%s' is synced from on-premises, not cloud-only -- an on-prem compromise reaches this privileged account", [object.get(a, "user_principal_name", "(unnamed)")])
}

# CIS 1.1.3 -- between two and four global admins.
_admin_count := input.admin_center.global_admin_count if {
	available("global_admins")
	is_number(input.admin_center.global_admin_count)
}

violation contains msg if {
	_admin_count < 2
	msg := sprintf("CIS 1.1.3: only %d global admin(s) designated; fewer than two risks lockout with no second administrator", [_admin_count])
}

violation contains msg if {
	_admin_count > 4
	msg := sprintf("CIS 1.1.3: %d global admins designated; more than four widens standing privilege beyond what the benchmark permits", [_admin_count])
}

# CIS 1.1.4 -- administrative accounts use reduced licences.
BROAD_LICENSE_MARKERS := {"ENTERPRISEPACK", "ENTERPRISEPREMIUM", "SPE_E3", "SPE_E5", "O365_BUSINESS_PREMIUM"}

violation contains msg if {
	available("admin_licenses")
	some a in _admins
	is_array(a.licenses)
	some l in a.licenses
	l.sku_part_number in BROAD_LICENSE_MARKERS
	msg := sprintf("CIS 1.1.4: administrative account '%s' holds licenses '%s', which is not a reduced application footprint -- privileged accounts should not carry the full productivity surface", [object.get(a, "user_principal_name", "(unnamed)"), l.sku_part_number])
}

# CIS 1.2.1 -- only organisationally managed / approved public groups.
violation contains msg if {
	some g in _list("groups", "public_groups")
	msg := sprintf("CIS 1.2.1: group '%s' is Public, so any member of the organizationally managed directory can join and read its content -- confirm it is approved or set it to Private", [object.get(g, "display_name", "(unnamed)")])
}

# CIS 1.3.1 -- password expiration policy set to never expire.
violation contains msg if {
	some d in _list("domains", "domains")
	d.is_verified == true
	is_number(d.password_validity_period_in_days)
	d.password_validity_period_in_days != PASSWORD_NEVER_EXPIRES
	msg := sprintf("CIS 1.3.1: domain '%s' expires passwords after %v days; the recommended policy is to set passwords to never expire, because forced rotation drives weaker secrets", [object.get(d, "id", "(unnamed)"), d.password_validity_period_in_days])
}

# CIS 1.3.2 -- idle session timeout for Microsoft 365 web apps, 3 hours or less,
# backed by the Conditional Access policy that makes unmanaged browser sessions
# use app enforced restrictions. Two requirements:
#
#   1. an activityBasedTimeoutPolicy that is the organisation default
#      (is_organization_default; only that policy is active) whose definition
#      sets WebSessionIdleTimeout for ApplicationId "default" to 3 hours or less.
#      definition is a list of JSON strings; durations are "[d.]hh:mm:ss".
#      https://learn.microsoft.com/en-us/graph/api/resources/activitybasedtimeoutpolicy?view=graph-rest-1.0
#   2. an enabled Conditional Access policy for all users, Office 365 as the only
#      application, the browser as the only client app type, with the session
#      control applicationEnforcedRestrictions enabled (read from
#      input.entra.conditional_access_policies, which section 5 already reads).
MAX_IDLE_SESSION_SECONDS := (MAX_IDLE_SESSION_HOURS * 60) * 60

_timeout_policies := _list("activity_based_timeout", "activity_based_timeout_policies")

# seconds of the "default" application's idle timeout in one policy; undefined
# when the definition cannot be read
_idle_seconds(p) := secs if {
	is_array(p.definition)
	some raw in p.definition
	is_string(raw)
	json.is_valid(raw)
	doc := json.unmarshal(raw)
	some ap in doc.ActivityBasedTimeoutPolicy.ApplicationPolicies
	ap.ApplicationId == "default"
	secs := _duration_seconds(ap.WebSessionIdleTimeout)
}

_duration_seconds(s) := secs if {
	is_string(s)
	ms := regex.find_all_string_submatch_n(`^(?:([0-9]+)\.)?([0-9]{1,2}):([0-9]{2}):([0-9]{2})(?:\.[0-9]+)?$`, s, 1)
	count(ms) == 1
	m := ms[0]
	days := _days(m[1])
	h := to_number(m[2])
	mi := to_number(m[3])
	sec := to_number(m[4])
	secs := (((((days * 24) + h) * 60) + mi) * 60) + sec
}

_days(s) := 0 if s == ""

_days(s) := to_number(s) if s != ""

# a policy whose activity flag and definition can both be read
_timeout_readable(p) if {
	is_boolean(p.is_organization_default)
	is_number(_idle_seconds(p))
}

_timeout_readable(p) if p.is_organization_default == false

_timeout_compliant(p) if {
	p.is_organization_default == true
	_idle_seconds(p) <= MAX_IDLE_SESSION_SECONDS
}

violation contains msg if {
	count(_timeout_policies) == 0
	msg := sprintf("CIS 1.3.2: no idle session timeout policy is configured; the benchmark requires %d hours or less for unmanaged devices", [MAX_IDLE_SESSION_HOURS])
}

violation contains msg if {
	count(_timeout_policies) > 0
	every p in _timeout_policies {
		_timeout_readable(p)
		not _timeout_compliant(p)
	}
	msg := sprintf("CIS 1.3.2: no active idle session timeout policy signs users out of Microsoft 365 web apps within %d hours (the organisation-default policy is absent or its timeout is longer)", [MAX_IDLE_SESSION_HOURS])
}

default _entra_ca_available := false

_entra_ca_available if {
	input.entra.collected == true
	not _entra_unavailable.conditional_access_policies
	is_array(input.entra.conditional_access_policies)
}

default _entra_unavailable := {}

_entra_unavailable := input.entra.unavailable if is_object(input.entra.unavailable)

_app_restricted_browser_policy(p) if {
	p.state == "enabled"
	"All" in object.get(p, ["conditions", "users", "includeUsers"], [])
	object.get(p, ["conditions", "applications", "includeApplications"], []) == ["Office365"]
	object.get(p, ["conditions", "clientAppTypes"], []) == ["browser"]
	object.get(p, ["session_controls", "applicationEnforcedRestrictions", "isEnabled"], false) == true
}

violation contains msg if {
	_entra_ca_available
	not _some_app_restricted_policy
	msg := "CIS 1.3.2: no enabled Conditional Access policy applies app enforced restrictions to browser sessions of Office 365 for all users, so the idle session timeout does not reach unmanaged devices"
}

_some_app_restricted_policy if {
	some p in input.entra.conditional_access_policies
	_app_restricted_browser_policy(p)
}

# CIS 1.3.4 -- user owned apps and services restricted.
violation contains msg if {
	_object("apps_and_services", "user_owned_apps_and_services").is_office_store_enabled == true
	msg := "CIS 1.3.4: 'User owned apps and services' is not restricted -- users can acquire Office Store add-ins that read mailbox and document content"
}

# CIS 1.3.5 -- internal phishing protection for Forms.
violation contains msg if {
	_object("forms", "forms").is_internal_phishing_protection_enabled == false
	msg := "CIS 1.3.5: internal phishing protection for Forms is not enabled -- Forms is a common internal credential-harvesting vector"
}

# CIS 1.3.7 -- third-party storage services restricted.
violation contains msg if {
	some s in _list("service_principals", "third_party_storage_service_principals")
	s.account_enabled == true
	msg := sprintf("CIS 1.3.7: third-party storage service '%s' is enabled in Microsoft 365 on the web -- corporate documents can be saved outside the tenant", [object.get(s, "display_name", "(unnamed)")])
}

# ── Section 1 controls read from Exchange Online facts ────────────────
default _exchange_unavailable := {}

_exchange_unavailable := input.exchange.unavailable if is_object(input.exchange.unavailable)

default exchange_collected := false

exchange_collected if input.exchange.collected == true

_exchange(key) := input.exchange[key] if {
	exchange_collected
	not _exchange_unavailable[key]
}

default exchange_org_available := false

exchange_org_available if is_object(_exchange("organization_config"))

# CIS 1.3.6 -- customer lockbox enabled.
violation contains msg if {
	_exchange("organization_config").CustomerLockBoxEnabled == false
	msg := "CIS 1.3.6: the customer lockbox feature is not enabled, so Microsoft support can access tenant content without explicit per-request approval"
}

# CIS 1.3.9 -- shared bookings pages restricted.
violation contains msg if {
	org := _exchange("organization_config")
	org.BookingsEnabled == true
	org.BookingsAuthEnabled == false
	msg := "CIS 1.3.9: shared bookings pages are not restricted to select users -- Bookings is enabled without requiring authentication, so pages are reachable anonymously"
}

_sharing_policies := _exchange("sharing_policies") if is_array(_exchange("sharing_policies"))

# CIS 1.3.3 -- external calendar sharing not available.
violation contains msg if {
	some policy in _sharing_policies
	policy.Enabled == true
	msg := sprintf("CIS 1.3.3: external sharing of calendars is available -- sharing policy '%s' is enabled, so users can share calendars with people outside the organization", [object.get(policy, "Name", "(unnamed)")])
}

# CIS 1.2.2 -- sign-in to shared mailboxes blocked. CIS's procedure joins the
# Exchange shared mailbox list to the Entra account of each mailbox.
_shared_mailboxes := _exchange("shared_mailboxes") if is_array(_exchange("shared_mailboxes"))

sign_in_state := input.admin_center.user_sign_in_state if {
	available("user_sign_in_state")
	is_object(input.admin_center.user_sign_in_state)
}

violation contains msg if {
	some mailbox in _shared_mailboxes
	sign_in_state[mailbox.ExternalDirectoryObjectId].account_enabled == true
	msg := sprintf("CIS 1.2.2: sign-in to shared mailbox '%s' is not blocked -- its Entra account is enabled, so it can be signed into directly rather than only accessed through delegation", [object.get(mailbox, "UserPrincipalName", "(unnamed)")])
}

violation contains msg if {
	is_object(sign_in_state)
	some mailbox in _shared_mailboxes
	is_string(mailbox.ExternalDirectoryObjectId)
	not sign_in_state[mailbox.ExternalDirectoryObjectId]
	msg := sprintf("CIS 1.2.2: whether sign-in to shared mailbox '%s' is blocked could not be evaluated -- no directory account matched its object id (this is not a pass)", [object.get(mailbox, "UserPrincipalName", "(unnamed)")])
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
	"controls_evaluated": 13,
	"controls": ["1.1.1", "1.2.1", "1.2.2", "1.1.3", "1.1.4", "1.3.1", "1.3.2", "1.3.3", "1.3.4", "1.3.5", "1.3.6", "1.3.7", "1.3.9"],
	"facts_present": collected,
	"unavailable_facts": unavailable,
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
	"1.1.1": ["admin_center.global_admins[].on_premises_sync_enabled"],
	"1.1.3": ["admin_center.global_admin_count"],
	"1.1.4": ["admin_center.global_admins[].licenses[].sku_part_number"],
	"1.2.1": ["admin_center.public_groups"],
	"1.2.2": ["admin_center.user_sign_in_state", "exchange.shared_mailboxes[].ExternalDirectoryObjectId"],
	"1.3.1": ["admin_center.domains[].is_verified", "admin_center.domains[].password_validity_period_in_days"],
	"1.3.2": ["admin_center.activity_based_timeout_policies[].definition", "admin_center.activity_based_timeout_policies[].is_organization_default", "entra.conditional_access_policies"],
	"1.3.3": ["exchange.sharing_policies[].Enabled"],
	"1.3.4": ["admin_center.user_owned_apps_and_services.is_office_store_enabled"],
	"1.3.5": ["admin_center.forms.is_internal_phishing_protection_enabled"],
	"1.3.6": ["exchange.organization_config.CustomerLockBoxEnabled"],
	"1.3.7": ["admin_center.third_party_storage_service_principals[].account_enabled"],
	"1.3.9": ["exchange.organization_config.BookingsAuthEnabled", "exchange.organization_config.BookingsEnabled"],
}

decidable contains "1.1.1" if {
	available("admin_sync_state")
	every a in _admins {
		is_boolean(a.on_premises_sync_enabled)
	}
}

decidable contains "1.1.4" if {
	available("admin_licenses")
	every a in _admins {
		is_array(a.licenses)
		every l in a.licenses {
			is_string(l.sku_part_number)
		}
	}
}

decidable contains "1.1.3" if is_number(_admin_count)

decidable contains "1.2.1" if is_array(_list("groups", "public_groups"))

decidable contains "1.3.1" if {
	every d in _list("domains", "domains") {
		_domain_decidable(d)
	}
}

_domain_decidable(d) if d.is_verified == false

_domain_decidable(d) if {
	d.is_verified == true
	is_number(d.password_validity_period_in_days)
}

# the active policy decides; with none compliant, every policy must be readable
decidable contains "1.3.2" if {
	_timeout_step_decidable
	_entra_ca_available
}

_timeout_step_decidable if {
	some p in _timeout_policies
	_timeout_compliant(p)
}

_timeout_step_decidable if {
	every p in _timeout_policies {
		_timeout_readable(p)
	}
}

decidable contains "1.3.4" if is_boolean(_object("apps_and_services", "user_owned_apps_and_services").is_office_store_enabled)

decidable contains "1.3.5" if is_boolean(_object("forms", "forms").is_internal_phishing_protection_enabled)

decidable contains "1.3.7" if {
	every s in _list("service_principals", "third_party_storage_service_principals") {
		is_boolean(s.account_enabled)
	}
}

decidable contains "1.3.6" if is_boolean(_exchange("organization_config").CustomerLockBoxEnabled)

decidable contains "1.3.9" if _exchange("organization_config").BookingsEnabled == false

decidable contains "1.3.9" if {
	org := _exchange("organization_config")
	org.BookingsEnabled == true
	is_boolean(org.BookingsAuthEnabled)
}

decidable contains "1.3.3" if {
	every policy in _sharing_policies {
		is_boolean(policy.Enabled)
	}
}

# every shared mailbox names its directory object, and every matched account
# reports a boolean account_enabled (an unmatched one has its own evidence message)
decidable contains "1.2.2" if {
	is_object(sign_in_state)
	every mailbox in _shared_mailboxes {
		is_string(mailbox.ExternalDirectoryObjectId)
		_sign_in_readable(mailbox.ExternalDirectoryObjectId)
	}
}

_sign_in_readable(oid) if not sign_in_state[oid]

_sign_in_readable(oid) if is_boolean(sign_in_state[oid].account_enabled)

# ── Evidence gaps, reported by control id ─────────────────────────────
# A gap names every control it blocks, so the per-control results and an
# exporter reading the ids agree on what was not evaluated. A key this module
# does not know is reported on its own, attributed to no control.
FACT_CONTROLS := {
	"global_admins": ["1.1.1", "1.1.3", "1.1.4"],
	"admin_licenses": ["1.1.4"],
	"admin_sync_state": ["1.1.1"],
	"groups": ["1.2.1"],
	"domains": ["1.3.1"],
	"activity_based_timeout": ["1.3.2"],
	"apps_and_services": ["1.3.4"],
	"forms": ["1.3.5"],
	"service_principals": ["1.3.7"],
	"user_sign_in_state": ["1.2.2"],
}

# the Exchange and Entra facts this section reads, and the controls each blocks
EXCHANGE_FACT_CONTROLS := {
	"organization_config": ["1.3.6", "1.3.9"],
	"sharing_policies": ["1.3.3"],
	"shared_mailboxes": ["1.2.2"],
}

_controls_reading(prefix) := _natural_sort({id |
	some id, paths in CONTROL_EVIDENCE
	some p in paths
	startswith(p, prefix)
})

# ids in benchmark order (1.3.2 before 1.3.10)
_natural_sort(ids) := [pair[1] | some pair in sort([[key, id] |
	some id in ids
	parts := split(id, ".")
	key := concat(".", [sprintf("%03d", [to_number(x)]) | some x in parts])
])]

_gap(ids, why) := sprintf("CIS %s: evidence missing -- %s (this is not a pass)", [concat("/", ids), why])

# [controls, reason] for every source-level gap
_source_gaps contains [_controls_reading("admin_center."), "Microsoft 365 admin center facts were not collected (admin_center.collected is not true)"] if not collected

_source_gaps contains [FACT_CONTROLS[key], sprintf("admin_center.unavailable.%s: %v", [key, reason])] if {
	collected
	some key, reason in unavailable
}

_source_gaps contains [_controls_reading("exchange."), "Exchange facts were not collected (exchange.collected is not true)"] if not exchange_collected

_source_gaps contains [EXCHANGE_FACT_CONTROLS[key], sprintf("exchange.unavailable.%s: %v", [key, reason])] if {
	exchange_collected
	some key, reason in _exchange_unavailable
}

_source_gaps contains [["1.3.2"], "Entra facts were not collected (entra.collected is not true)"] if not input.entra.collected == true

_source_gaps contains [["1.3.2"], sprintf("entra.unavailable.conditional_access_policies: %v", [reason])] if {
	input.entra.collected == true
	reason := _entra_unavailable.conditional_access_policies
}

_gap_ids contains id if {
	some g in _source_gaps
	some id in g[0]
}

# a source gap names the controls it leaves undecided
_evidence_gaps contains _gap(ids, g[1]) if {
	some g in _source_gaps
	ids := [id | some id in g[0]; not id in decidable]
	count(ids) > 0
}

_evidence_gaps contains msg if {
	some key, reason in unavailable
	not FACT_CONTROLS[key]
	msg := sprintf("M365 section 1 (admin center): unrecognised unavailable key '%s' (%v) -- this module reads no fact of that name, so it is attributed to no control (this is not a pass)", [key, reason])
}

_evidence_gaps contains _gap([id], why) if {
	some id, paths in CONTROL_EVIDENCE
	not id in decidable
	not id in _gap_ids
	why := sprintf("%s not collected or not of the expected type", [concat(", ", paths)])
}

violation contains msg if some msg in _evidence_gaps
