# Hand-written for the field- and shape-level fail-closed rules (CIS Microsoft 365 Foundations v7.0.0).
#
# Each case starts from the compliant fixture of test_control_results.rego, changes one fact, and states the
# status the control must get: "fail" (a violation names it and is not an evidence message), "evidence_missing"
# (it is not decidable, or an evidence message names it -- and some message must name it) or "pass". The cases
# cover, for every rule whose reading changed, a failing value, a passing value and a missing field or wrong
# shape.
package cis_m365_v7.field_evidence_test

import data.cis_m365_v7.control_results_test.fixture_compliant as F
import rego.v1

_cited(vs, id) := {_kind(v) |
	some v in vs
	is_string(v)
	ms := regex.find_all_string_submatch_n(`^CIS ([0-9]+(?:\.[0-9]+)+(?:/[0-9]+(?:\.[0-9]+)+)*): `, v, 1)
	count(ms) == 1
	ids := split(ms[0][1], "/")
	id in ids
}

_kind(v) := "evidence" if contains(v, "(this is not a pass)")

_kind(v) := "fail" if not contains(v, "(this is not a pass)")

_status(vs, _, id) := "fail" if "fail" in _cited(vs, id)

_status(vs, _, id) := "evidence_missing" if {
	not "fail" in _cited(vs, id)
	"evidence" in _cited(vs, id)
}

# not decidable and named by no message would be a silent gap: no status, the case fails
_status(vs, dec, id) := "pass" if {
	count(_cited(vs, id)) == 0
	id in dec
}

_input(c) := json.remove(object.union(F, object.get(c, "patch", {})), object.get(c, "remove", []))

_check(c) if {
	inp := _input(c)
	vs := data.cis_m365_v7[c.pkg].violation with input as inp
	dec := data.cis_m365_v7[c.pkg].decidable with input as inp
	_status(vs, dec, c.id) == c.expect
}

_strict := {"Name": "Strict Preset Security Policy", "State": "Enabled", "SentTo": ["ceo@contoso.example"], "SentToMemberOf": null, "RecipientDomainIs": null}

_alert(threat, extra) := object.union({"Disabled": false, "Filter": ["Mail.Direction -eq 'Inbound'"], "Name": threat, "NotificationEnabled": true, "NotifyUser": ["secops@contoso.example"], "RecipientTags": ["Priority account", "Finance"], "Severity": "High", "ThreatType": threat}, extra)

_mf(extra) := {"defender": {"malware_filter_policies": [object.union({"Identity": "Default", "EnableFileFilter": true, "EnableInternalSenderAdminNotifications": true}, extra)]}}

_types(n) := [sprintf("ext%d", [i]) | some i in numbers.range(1, n)]

_out(extra) := {"defender": {"outbound_spam_policies": [object.union({"Name": "Default", "NotifyOutboundSpam": true, "RecipientLimitExternalPerHour": 500, "RecipientLimitInternalPerHour": 1000, "RecipientLimitPerDay": 1000, "ActionWhenThresholdReached": "BlockUser", "NotifyOutboundSpamRecipients": ["secops@contoso.example"]}, extra)]}}

DEFENDER_CASES := [
	# D1: a list sent as an object
	{"pkg": "defender", "id": "2.1.1", "expect": "evidence_missing", "patch": {"defender": {"safe_links_policies": {"Name": "Default", "EnableSafeLinksForOffice": false}}}},
	{"pkg": "defender", "id": "2.1.1", "expect": "fail", "patch": {"defender": {"safe_links_policies": [{"Name": "Default", "EnableSafeLinksForOffice": false}]}}},
	{"pkg": "defender", "id": "2.1.1", "expect": "evidence_missing", "patch": {"defender": {"safe_links_policies": [{"Name": "Default"}]}}},
	# D3: FileTypes is the property; FileTypeFilter only as a fallback
	{"pkg": "defender", "id": "2.1.11", "expect": "fail", "patch": _mf({"FileTypes": ["exe"]})},
	{"pkg": "defender", "id": "2.1.11", "expect": "pass", "patch": _mf({"FileTypes": _types(120)})},
	{"pkg": "defender", "id": "2.1.11", "expect": "pass", "patch": _mf({"FileTypeFilter": _types(120)})},
	{"pkg": "defender", "id": "2.1.11", "expect": "evidence_missing", "patch": _mf({"FileTypeFilter": null})},
	{"pkg": "defender", "id": "2.1.11", "expect": "evidence_missing", "patch": _mf({})},
	{"pkg": "defender", "id": "2.1.11", "expect": "fail", "patch": _mf({"FileTypes": _types(120), "EnableFileFilter": false})},
	# 2.1.12 / 2.1.14: an absent list is not an empty one
	{"pkg": "defender", "id": "2.1.12", "expect": "fail", "patch": {"defender": {"connection_filter_policies": [{"Name": "Default", "EnableSafeList": false, "IPAllowList": ["192.0.2.1"]}]}}},
	{"pkg": "defender", "id": "2.1.12", "expect": "evidence_missing", "patch": {"defender": {"connection_filter_policies": [{"Name": "Default", "EnableSafeList": false}]}}},
	{"pkg": "defender", "id": "2.1.14", "expect": "evidence_missing", "patch": {"defender": {"content_filter_policies": [{"Name": "Default"}]}}},
	# 2.1.15: every limit set and bounded, BlockUser, a notified recipient
	{"pkg": "defender", "id": "2.1.15", "expect": "pass", "patch": _out({})},
	{"pkg": "defender", "id": "2.1.15", "expect": "fail", "patch": _out({"RecipientLimitExternalPerHour": 0})},
	{"pkg": "defender", "id": "2.1.15", "expect": "fail", "patch": _out({"RecipientLimitPerDay": 5000})},
	{"pkg": "defender", "id": "2.1.15", "expect": "fail", "patch": _out({"ActionWhenThresholdReached": "Alert"})},
	{"pkg": "defender", "id": "2.1.15", "expect": "fail", "patch": _out({"NotifyOutboundSpamRecipients": []})},
	{"pkg": "defender", "id": "2.1.15", "expect": "evidence_missing", "patch": _out({"RecipientLimitInternalPerHour": "1000"})},
	# 2.4.1: RecipientTags / Filter / NotifyUser as lists or strings
	{"pkg": "defender", "id": "2.4.1", "expect": "pass", "patch": {"defender": {"priority_account_alerts": [_alert("Phish", {}), _alert("Malware", {"RecipientTags": "Priority account", "Filter": "Mail.Direction -eq 'Inbound'", "NotifyUser": "secops@contoso.example"})]}}},
	{"pkg": "defender", "id": "2.4.1", "expect": "fail", "patch": {"defender": {"priority_account_alerts": [_alert("Phish", {}), _alert("Malware", {"RecipientTags": ["Finance"]})]}}},
	{"pkg": "defender", "id": "2.4.1", "expect": "evidence_missing", "patch": {"defender": {"priority_account_alerts": [_alert("Phish", {}), _alert("Malware", {"Severity": 3})]}}},
	# 2.4.2: the Strict preset rule in EOP and in Defender for Office 365, enabled, with recipients
	{"pkg": "defender", "id": "2.4.2", "expect": "fail", "patch": {"defender": {"eop_protection_rules": [object.union(_strict, {"State": "Disabled"})]}}},
	{"pkg": "defender", "id": "2.4.2", "expect": "fail", "patch": {"defender": {"eop_protection_rules": [object.union(_strict, {"Name": "Standard Preset Security Policy"})]}}},
	{"pkg": "defender", "id": "2.4.2", "expect": "fail", "patch": {"defender": {"atp_protection_rules": [object.union(_strict, {"SentTo": null})]}}},
	{"pkg": "defender", "id": "2.4.2", "expect": "evidence_missing", "patch": {"defender": {"eop_protection_rules": [{"Name": "Strict Preset Security Policy"}]}}},
	{"pkg": "defender", "id": "2.4.2", "expect": "evidence_missing", "remove": ["defender/atp_protection_rules"]},
	# D8: the DKIM signing configuration decides 2.1.9
	{"pkg": "defender", "id": "2.1.9", "expect": "fail", "patch": {"defender": {"dkim_signing_configs": [{"Domain": "contoso.example", "Enabled": false, "Status": "Valid"}]}}},
	{"pkg": "defender", "id": "2.1.9", "expect": "fail", "patch": {"defender": {"dkim_signing_configs": [{"Domain": "contoso.example", "Enabled": true, "Status": "CnameMissing"}]}}},
	{"pkg": "defender", "id": "2.1.9", "expect": "fail", "patch": {"defender": {"dkim_signing_configs": [{"Domain": "other.example", "Enabled": true, "Status": "Valid"}]}}},
	{"pkg": "defender", "id": "2.1.9", "expect": "pass", "patch": {"defender": {"dkim_signing_configs": [{"Name": "CONTOSO.example", "Enabled": true}]}}},
	{"pkg": "defender", "id": "2.1.9", "expect": "evidence_missing", "remove": ["defender/dkim_signing_configs"]},
	{"pkg": "defender", "id": "2.1.9", "expect": "evidence_missing", "patch": {"defender": {"unavailable": {"dkim_signing_configs": "Get-DkimSigningConfig denied"}}}},
	{"pkg": "defender", "id": "2.1.9", "expect": "evidence_missing", "patch": {"defender": {"dkim_signing_configs": [{"Domain": "contoso.example", "Enabled": "yes"}]}}},
	# SPF / DMARC flags of the wrong type are not a pass
	{"pkg": "defender", "id": "2.1.8", "expect": "evidence_missing", "patch": {"exchange": {"verified_domains": [{"id": "contoso.example", "is_initial": false, "spf_present": "yes", "dkim_present": true, "dmarc_present": true}]}}},
	{"pkg": "defender", "id": "2.1.10", "expect": "fail", "patch": {"exchange": {"verified_domains": [{"id": "contoso.example", "is_initial": false, "spf_present": true, "dkim_present": true, "dmarc_present": false}]}}},
]

test_defender_field_cases if {
	every c in DEFENDER_CASES {
		_check(c)
	}
}

_timeout(span, org_default) := {"admin_center": {"activity_based_timeout_policies": [{"id": "idle", "display_name": "idle", "is_organization_default": org_default, "definition": [sprintf(`{"ActivityBasedTimeoutPolicy":{"Version":1,"ApplicationPolicies":[{"ApplicationId":"default","WebSessionIdleTimeout":"%s"}]}}`, [span])]}]}}

ADMIN_CASES := [
	# 1.3.2: the timeout value is compared, and only the active (organisation default) policy counts
	{"pkg": "admin_center", "id": "1.3.2", "expect": "pass", "patch": _timeout("01:00:00", true)},
	{"pkg": "admin_center", "id": "1.3.2", "expect": "fail", "patch": _timeout("04:00:00", true)},
	{"pkg": "admin_center", "id": "1.3.2", "expect": "fail", "patch": _timeout("1.00:00:00", true)},
	{"pkg": "admin_center", "id": "1.3.2", "expect": "fail", "patch": _timeout("01:00:00", false)},
	{"pkg": "admin_center", "id": "1.3.2", "expect": "evidence_missing", "patch": {"admin_center": {"activity_based_timeout_policies": [{"id": "idle", "display_name": "idle", "is_organization_default": true}]}}},
	{"pkg": "admin_center", "id": "1.3.2", "expect": "evidence_missing", "patch": _timeout("three hours", true)},
	{"pkg": "admin_center", "id": "1.3.2", "expect": "fail", "patch": {"admin_center": {"activity_based_timeout_policies": []}}},
	{"pkg": "admin_center", "id": "1.3.2", "expect": "fail", "patch": {"entra": {"conditional_access_policies": []}}},
	{"pkg": "admin_center", "id": "1.3.2", "expect": "evidence_missing", "patch": {"entra": {"unavailable": {"conditional_access_policies": "denied"}}}},
	# typed comparisons
	{"pkg": "admin_center", "id": "1.1.3", "expect": "evidence_missing", "patch": {"admin_center": {"global_admin_count": "2"}}},
	{"pkg": "admin_center", "id": "1.1.3", "expect": "fail", "patch": {"admin_center": {"global_admin_count": 5}}},
	{"pkg": "admin_center", "id": "1.1.1", "expect": "evidence_missing", "patch": {"admin_center": {"global_admins": [{"licenses": [], "user_principal_name": "ga1@contoso.example"}]}}},
	{"pkg": "admin_center", "id": "1.1.1", "expect": "evidence_missing", "patch": {"admin_center": {"unavailable": {"admin_sync_state": "denied"}}}},
	{"pkg": "admin_center", "id": "1.2.2", "expect": "evidence_missing", "patch": {"admin_center": {"user_sign_in_state": {"00000000-0000-0000-0000-000000000001": {"account_enabled": "no"}}}}},
	{"pkg": "admin_center", "id": "1.2.2", "expect": "fail", "patch": {"admin_center": {"user_sign_in_state": {"00000000-0000-0000-0000-000000000001": {"account_enabled": true}}}}},
	{"pkg": "admin_center", "id": "1.3.9", "expect": "evidence_missing", "patch": {"exchange": {"unavailable": {"organization_config": "denied"}}}},
]

test_admin_center_field_cases if {
	every c in ADMIN_CASES {
		_check(c)
	}
}

_owa(extra) := {"exchange": {"owa_mailbox_policies": [object.union({"Name": "OwaMailboxPolicy-Default", "IsDefault": true, "AdditionalStorageProvidersAvailable": false, "PersonalAccountsEnabled": false, "PersonalAccountCalendarsEnabled": false}, extra)]}}

EXCHANGE_CASES := [
	# D4: 6.3.2 reads PersonalAccountsEnabled / PersonalAccountCalendarsEnabled of the default policy
	{"pkg": "exchange", "id": "6.3.2", "expect": "fail", "patch": _owa({"PersonalAccountsEnabled": true})},
	{"pkg": "exchange", "id": "6.3.2", "expect": "fail", "patch": _owa({"PersonalAccountCalendarsEnabled": true})},
	{"pkg": "exchange", "id": "6.3.2", "expect": "pass", "patch": _owa({"AdditionalStorageProvidersAvailable": true})},
	{"pkg": "exchange", "id": "6.5.3", "expect": "fail", "patch": _owa({"AdditionalStorageProvidersAvailable": true})},
	{"pkg": "exchange", "id": "6.3.2", "expect": "pass", "patch": {"exchange": {"owa_mailbox_policies": [
		{"Name": "OwaMailboxPolicy-Default", "IsDefault": true, "AdditionalStorageProvidersAvailable": false, "PersonalAccountsEnabled": false, "PersonalAccountCalendarsEnabled": false},
		{"Name": "Other", "IsDefault": false, "AdditionalStorageProvidersAvailable": false, "PersonalAccountsEnabled": true},
	]}}},
	{"pkg": "exchange", "id": "6.3.2", "expect": "evidence_missing", "patch": {"exchange": {"owa_mailbox_policies": [{"Name": "OwaMailboxPolicy-Default", "IsDefault": true, "AdditionalStorageProvidersAvailable": false}]}}},
	{"pkg": "exchange", "id": "6.3.2", "expect": "evidence_missing", "patch": {"exchange": {"owa_mailbox_policies": [{"Name": "OwaMailboxPolicy-Default", "AdditionalStorageProvidersAvailable": false, "PersonalAccountsEnabled": false, "PersonalAccountCalendarsEnabled": false}]}}},
	# transport rules: State must be known; unset actions are null
	{"pkg": "exchange", "id": "6.2.1", "expect": "fail", "patch": {"exchange": {"transport_rules": [{"Name": "fwd", "State": "Enabled", "RedirectMessageTo": ["x@external.example"], "SetSCL": null, "SenderDomainIs": null}]}}},
	{"pkg": "exchange", "id": "6.2.1", "expect": "pass", "patch": {"exchange": {"transport_rules": [{"Name": "tag", "State": "Enabled", "RedirectMessageTo": null}]}}},
	{"pkg": "exchange", "id": "6.2.1", "expect": "evidence_missing", "patch": {"exchange": {"transport_rules": [{"Name": "fwd", "RedirectMessageTo": ["x@external.example"]}]}}},
	{"pkg": "exchange", "id": "6.2.2", "expect": "fail", "patch": {"exchange": {"transport_rules": [{"Name": "allow", "State": "Enabled", "SetSCL": -1, "SenderDomainIs": ["partner.example"]}]}}},
	{"pkg": "exchange", "id": "6.2.2", "expect": "evidence_missing", "patch": {"exchange": {"transport_rules": [{"Name": "allow", "State": "Enabled", "SetSCL": "-1", "SenderDomainIs": ["partner.example"]}]}}},
	{"pkg": "exchange", "id": "6.1.2", "expect": "evidence_missing", "patch": {"exchange": {"mailbox_audit": {"audit_disabled": {"user_principal_name": "u@contoso.example"}}}}},
]

test_exchange_field_cases if {
	every c in EXCHANGE_CASES {
		_check(c)
	}
}

OTHER_CASES := [
	# D2: a meeting policy without the field each control compares
	{"pkg": "teams", "id": "8.5.8", "expect": "evidence_missing", "patch": {"teams": {"meeting_policies": [{"Identity": "Global"}]}}},
	{"pkg": "teams", "id": "8.5.3", "expect": "evidence_missing", "patch": {"teams": {"meeting_policies": [{"Identity": "Global"}]}}},
	{"pkg": "teams", "id": "8.5.6", "expect": "evidence_missing", "patch": {"teams": {"meeting_policies": [{"Identity": "Global", "DesignatedPresenterRoleMode": 2}]}}},
	{"pkg": "teams", "id": "8.2.4", "expect": "evidence_missing", "patch": {"teams": {"federation_configuration": {"ExternalAccessWithTrialTenants": 1}}}},
	# D6: only the self-consent policies are user consent
	{"pkg": "entra", "id": "5.1.5.1", "expect": "pass", "patch": {"entra": {"authorization_policy": {"permission_grant_policy_ids_assigned": ["ManagePermissionGrantsForOwnedResource.DeveloperConsent"]}}}},
	{"pkg": "entra", "id": "5.1.5.1", "expect": "fail", "patch": {"entra": {"authorization_policy": {"permission_grant_policy_ids_assigned": ["ManagePermissionGrantsForSelf.microsoft-user-default-low"]}}}},
	{"pkg": "entra", "id": "5.1.5.1", "expect": "evidence_missing", "patch": {"entra": {"authorization_policy": {"permission_grant_policy_ids_assigned": "ManagePermissionGrantsForSelf.microsoft-user-default-low"}}}},
	{"pkg": "entra", "id": "5.1.6.3", "expect": "evidence_missing", "remove": ["entra/authorization_policy/allow_invites_from"]},
	{"pkg": "entra", "id": "5.1.6.3", "expect": "fail", "patch": {"entra": {"authorization_policy": {"allow_invites_from": "everyone"}}}},
	{"pkg": "entra", "id": "5.1.4.2", "expect": "fail", "patch": {"entra": {"device_registration": {"user_device_quota": "50"}}}},
	{"pkg": "entra", "id": "5.1.4.2", "expect": "evidence_missing", "patch": {"entra": {"device_registration": {"user_device_quota": "unlimited"}}}},
	{"pkg": "entra", "id": "5.2.3.8", "expect": "evidence_missing", "patch": {"entra": {"lockout": {"threshold": "ten"}}}},
	{"pkg": "entra", "id": "5.2.3.8", "expect": "fail", "patch": {"entra": {"lockout": {"threshold": "50"}}}},
	{"pkg": "entra", "id": "5.2.3.3", "expect": "evidence_missing", "patch": {"entra": {"password_protection": {"on_premises_check_enabled": "maybe"}}}},
	{"pkg": "entra", "id": "5.2.3.6", "expect": "evidence_missing", "remove": ["entra/system_preferred_mfa_state"]},
	# D9: transferMethods is one comma-separated string in Graph
	{"pkg": "entra", "id": "5.2.2.12", "expect": "pass", "patch": {"entra": {"conditional_access_policies": [{"state": "enabled", "conditions": {"authenticationFlows": {"transferMethods": "deviceCodeFlow,authenticationTransfer"}}, "grant_controls": {"builtInControls": ["block"]}}]}}},
	{"pkg": "entra", "id": "5.2.2.17", "expect": "pass", "patch": {"entra": {"conditional_access_policies": [{"state": "enabled", "conditions": {"authenticationFlows": {"transferMethods": "deviceCodeFlow,authenticationTransfer"}}, "grant_controls": {"builtInControls": ["block"]}}]}}},
	{"pkg": "entra", "id": "5.2.2.17", "expect": "fail", "patch": {"entra": {"conditional_access_policies": [{"state": "enabled", "conditions": {"authenticationFlows": {"transferMethods": "deviceCodeFlow"}}, "grant_controls": {"builtInControls": ["block"]}}]}}},
	{"pkg": "entra", "id": "5.2.2.1", "expect": "evidence_missing", "patch": {"entra": {"conditional_access_policies": {"state": "enabled"}}}},
	# purview: an absent Mode no longer counts as enforcing
	{"pkg": "purview", "id": "3.2.1", "expect": "evidence_missing", "patch": {"purview_ps": {"dlp_policies": [{"Enabled": true, "Name": "dlp", "TeamsLocation": ["All"], "Workload": "Exchange"}]}}},
	{"pkg": "purview", "id": "3.2.1", "expect": "fail", "patch": {"purview_ps": {"dlp_policies": [{"Enabled": true, "Mode": "TestWithNotifications", "Name": "dlp", "TeamsLocation": ["All"], "Workload": "Exchange"}]}}},
	{"pkg": "purview", "id": "3.2.3", "expect": "pass", "patch": {"purview_ps": {"dlp_policies": [{"Enabled": true, "Mode": "Enable", "Name": "dlp", "TeamsLocation": null, "Workload": ["Exchange", "CopilotExperiences"]}]}}},
	{"pkg": "purview", "id": "3.2.2", "expect": "fail", "patch": {"purview_ps": {"dlp_policies": [{"Enabled": true, "Mode": "Enable", "Name": "dlp", "TeamsLocation": null, "Workload": "Exchange"}]}}},
	# fabric, sharepoint, intune
	{"pkg": "fabric", "id": "9.1.6", "expect": "evidence_missing", "patch": {"fabric": {"settings": {"EimInformationProtectionEdit": {"enabled": null}}}}},
	{"pkg": "fabric", "id": "9.1.4", "expect": "evidence_missing", "patch": {"fabric": {"settings": {"PublishToWeb": {"enabled": "false"}}}}},
	{"pkg": "fabric", "id": "9.1.4", "expect": "fail", "patch": {"fabric": {"settings": {"PublishToWeb": {"enabled": true}}}}},
	{"pkg": "sharepoint", "id": "7.2.6", "expect": "evidence_missing", "patch": {"sharepoint": {"tenant": {"SharingCapability": 2}}}},
	{"pkg": "sharepoint", "id": "7.2.6", "expect": "evidence_missing", "patch": {"sharepoint": {"unavailable": {"SharingCapability": "denied"}}}},
	{"pkg": "sharepoint", "id": "7.2.6", "expect": "fail", "patch": {"sharepoint": {"tenant": {"SharingCapability": "ExternalUserAndGuestSharing"}}}},
	{"pkg": "intune", "id": "4.2", "expect": "evidence_missing", "patch": {"intune": {"enrollment_platform_restrictions": [{"display_name": "default", "platforms": ["windows"]}]}}},
]

test_other_section_field_cases if {
	every c in OTHER_CASES {
		_check(c)
	}
}

# D7: a gap names every control it blocks; an unknown key is attributed to none
test_gap_names_every_blocked_control if {
	vs := data.cis_m365_v7.defender.violation with input as {"defender": {"collected": true, "unavailable": {"malware_filter_policies": "denied"}}}
	every id in ["2.1.2", "2.1.3", "2.1.11"] {
		some v in vs
		startswith(v, sprintf("CIS %s: evidence missing -- defender.unavailable.malware_filter_policies: denied", [id]))
		contains(v, "(this is not a pass)")
	}
}

# the product derives passed = total_controls - violation_count: every control that is not a pass must
# add at least one violation, or a gap would be counted as a pass
test_violation_count_never_below_failed_controls if {
	every inp in [
		{},
		json.remove(F, ["defender"]),
		json.remove(F, ["entra", "teams", "attestations"]),
		object.union(F, {"defender": {"unavailable": {"malware_filter_policies": "denied"}}}),
		object.union(F, {"sharepoint": {"unavailable": {"tenant": "denied"}}}),
		object.union(F, {"exchange": {"verified_domains": [{"id": "contoso.example", "dns_unavailable": "denied"}]}}),
	] {
		r := data.cis_m365_v7.main.compliance_report with input as inp
		r.violation_count >= r.failed_controls
	}
}

test_unknown_unavailable_key_is_not_attributed_to_a_control if {
	every pkg in ["admin_center", "defender", "entra", "exchange", "fabric", "intune", "sharepoint", "teams"] {
		inp := object.union(F, {pkg: {"unavailable": {"no_such_fact": "renamed upstream"}}})
		vs := data.cis_m365_v7[pkg].violation with input as inp
		some v in vs
		startswith(v, "M365 section")
		contains(v, "'no_such_fact'")
		every w in vs { not _cites_any(w) }
	}
}

_cites_any(v) if regex.match(`^CIS [0-9]`, v)
