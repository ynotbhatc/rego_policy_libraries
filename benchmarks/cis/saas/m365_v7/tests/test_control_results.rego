# Hand-written with the per-control results in cis_m365_v7_complete.rego (CIS Microsoft 365 Foundations v7.0.0).
#
# control_results: every one of the 160 recommendations in natural order; statuses agree with the violations
# wherever a violation names the control. The module has no total_controls / failed_controls, so the counts are
# checked against benchmark_total_controls and control_result_counts. Several rules are silent when the fact
# they read is missing (each section reports one "section not evaluated" message for the whole section); those
# controls are evidence_missing without a violation that names them, and the exact sets are pinned below so a
# change to either side is seen.
package cis_m365_v7.control_results_test

import rego.v1

# a tenant that meets every evaluated recommendation, with all 16 ledger recommendations attested
fixture_compliant := {"admin_center": {"activity_based_timeout_policies": [{"display_name": "idle session timeout", "id": "idle"}], "collected": true, "domains": [{"id": "contoso.example", "is_verified": true, "password_validity_period_in_days": 2147483647}], "forms": {"is_internal_phishing_protection_enabled": true}, "global_admin_count": 2, "global_admins": [{"licenses": [], "on_premises_sync_enabled": false, "user_principal_name": "ga1@contoso.example"}, {"licenses": [], "on_premises_sync_enabled": false, "user_principal_name": "ga2@contoso.example"}], "public_groups": [], "third_party_storage_service_principals": [], "unavailable": {}, "user_owned_apps_and_services": {"is_app_and_services_trial_enabled": false, "is_office_store_enabled": false}, "user_sign_in_state": {"00000000-0000-0000-0000-000000000001": {"account_enabled": false}}}, "attestations": [{"attested_by": "auditor", "attested_on": "2026-11-18", "control_id": "1.1.2", "evidence_ref": "ticket-1"}, {"attested_by": "auditor", "attested_on": "2026-11-18", "control_id": "1.3.8", "evidence_ref": "ticket-1"}, {"attested_by": "auditor", "attested_on": "2026-11-18", "control_id": "2.2.1", "evidence_ref": "ticket-1"}, {"attested_by": "auditor", "attested_on": "2026-11-18", "control_id": "2.4.3", "evidence_ref": "ticket-1"}, {"attested_by": "auditor", "attested_on": "2026-11-18", "control_id": "2.4.5", "evidence_ref": "ticket-1"}, {"attested_by": "auditor", "attested_on": "2026-11-18", "control_id": "5.1.2.4", "evidence_ref": "ticket-1"}, {"attested_by": "auditor", "attested_on": "2026-11-18", "control_id": "5.1.2.5", "evidence_ref": "ticket-1"}, {"attested_by": "auditor", "attested_on": "2026-11-18", "control_id": "5.1.2.6", "evidence_ref": "ticket-1"}, {"attested_by": "auditor", "attested_on": "2026-11-18", "control_id": "5.1.3.2", "evidence_ref": "ticket-1"}, {"attested_by": "auditor", "attested_on": "2026-11-18", "control_id": "5.1.3.3", "evidence_ref": "ticket-1"}, {"attested_by": "auditor", "attested_on": "2026-11-18", "control_id": "5.2.4.1", "evidence_ref": "ticket-1"}, {"attested_by": "auditor", "attested_on": "2026-11-18", "control_id": "5.2.4.2", "evidence_ref": "ticket-1"}, {"attested_by": "auditor", "attested_on": "2026-11-18", "control_id": "5.2.4.3", "evidence_ref": "ticket-1"}, {"attested_by": "auditor", "attested_on": "2026-11-18", "control_id": "5.2.4.4", "evidence_ref": "ticket-1"}, {"attested_by": "auditor", "attested_on": "2026-11-18", "control_id": "5.2.4.5", "evidence_ref": "ticket-1"}, {"attested_by": "auditor", "attested_on": "2026-11-18", "control_id": "8.4.1", "evidence_ref": "ticket-1"}], "defender": {"anti_phish_policies": [{"Enabled": true, "Name": "anti-phish"}], "atp_policy_for_o365": {"EnableATPForSPOTeamsODB": true}, "collected": true, "connection_filter_policies": [{"EnableSafeList": false, "IPAllowList": [], "Name": "Default"}], "content_filter_policies": [{"AllowedSenderDomains": [], "Name": "Default"}], "email_tenant_settings": {"EnablePriorityAccountProtection": true}, "eop_protection_rules": [{"Name": "Strict Preset Security Policy"}], "malware_filter_policies": [{"EnableFileFilter": true, "EnableInternalSenderAdminNotifications": true, "FileTypeFilter": ["ext0", "ext1", "ext2", "ext3", "ext4", "ext5", "ext6", "ext7", "ext8", "ext9", "ext10", "ext11", "ext12", "ext13", "ext14", "ext15", "ext16", "ext17", "ext18", "ext19", "ext20", "ext21", "ext22", "ext23", "ext24", "ext25", "ext26", "ext27", "ext28", "ext29", "ext30", "ext31", "ext32", "ext33", "ext34", "ext35", "ext36", "ext37", "ext38", "ext39", "ext40", "ext41", "ext42", "ext43", "ext44", "ext45", "ext46", "ext47", "ext48", "ext49", "ext50", "ext51", "ext52", "ext53", "ext54", "ext55", "ext56", "ext57", "ext58", "ext59", "ext60", "ext61", "ext62", "ext63", "ext64", "ext65", "ext66", "ext67", "ext68", "ext69", "ext70", "ext71", "ext72", "ext73", "ext74", "ext75", "ext76", "ext77", "ext78", "ext79", "ext80", "ext81", "ext82", "ext83", "ext84", "ext85", "ext86", "ext87", "ext88", "ext89", "ext90", "ext91", "ext92", "ext93", "ext94", "ext95", "ext96", "ext97", "ext98", "ext99"], "Identity": "Default", "Name": "Default"}], "outbound_spam_policies": [{"Name": "Default", "NotifyOutboundSpam": true, "RecipientLimitExternalPerHour": 500}], "priority_account_alerts": [{"Disabled": false, "Filter": "Mail.Direction -eq 'Inbound'", "Name": "priority Phish", "NotificationEnabled": true, "NotifyUser": ["secops@contoso.example"], "RecipientTags": "Priority account", "Severity": "High", "ThreatType": "Phish"}, {"Disabled": false, "Filter": "Mail.Direction -eq 'Inbound'", "Name": "priority Malware", "NotificationEnabled": true, "NotifyUser": ["secops@contoso.example"], "RecipientTags": "Priority account", "Severity": "High", "ThreatType": "Malware"}], "safe_attachment_policies": [{"Enable": true, "Name": "safe attachments"}], "safe_links_policies": [{"EnableSafeLinksForOffice": true, "Name": "safe links"}], "teams_protection_policy": {"ZapEnabled": true}, "unavailable": {}}, "entra": {"access_reviews": [{"scope_query": "/users?$filter=(userType eq 'Guest')"}, {"scope_query": "/roleManagement/directory/roleAssignmentScheduleInstances"}], "admin_consent_workflow_enabled": true, "app_management": {"key_credentials": [{"restrictionType": "asymmetricKeyLifetime", "state": "enabled"}], "password_credentials": [{"restrictionType": "passwordAddition", "state": "enabled"}, {"restrictionType": "passwordLifetime", "state": "enabled"}, {"restrictionType": "symmetricKeyAddition", "state": "enabled"}]}, "authenticator": {"companion_app_allowed_state": "disabled", "number_matching_state": "enabled", "show_app_information_state": "enabled", "show_geographic_location_state": "enabled", "state": "enabled"}, "authorization_policy": {"allow_invites_from": "adminsAndGuestInviters", "allowed_to_create_apps": false, "allowed_to_create_security_groups": false, "allowed_to_create_tenants": false, "allowed_to_read_bitlocker_keys_for_owned_device": false, "guest_user_role_id": "2af84b1e-32c8-42b7-82bc-daa82404023b", "permission_grant_policy_ids_assigned": []}, "b2b_management_policy": {"allowed_domains_present": true, "blocked_domains_present": false, "policy_present": true}, "collected": true, "conditional_access_policies": [{"conditions": {"clientAppTypes": ["all"], "users": {"includeRoles": ["62e90394-69f5-4237-9190-012177145e10"], "includeUsers": []}}, "displayName": "admins", "grant_controls": {"authenticationStrength": {"displayName": "Phishing-resistant MFA"}, "builtInControls": ["mfa"]}, "session_controls": {}, "state": "enabled"}, {"conditions": {"clientAppTypes": ["all"], "users": {"includeRoles": [], "includeUsers": ["All"]}}, "displayName": "all users", "grant_controls": {"builtInControls": ["mfa", "compliantDevice"]}, "session_controls": {"persistentBrowser": {"mode": "never"}, "secureSignInSession": {"isEnabled": true}, "signInFrequency": {"frequencyInterval": "timeBased", "isEnabled": true}}, "state": "enabled"}, {"conditions": {"clientAppTypes": ["exchangeActiveSync", "other"], "users": {"includeRoles": [], "includeUsers": ["All"]}}, "displayName": "legacy", "grant_controls": {"builtInControls": ["block"]}, "session_controls": {}, "state": "enabled"}, {"conditions": {"clientAppTypes": ["all"], "userRiskLevels": ["high"], "users": {"includeRoles": [], "includeUsers": ["All"]}}, "displayName": "user risk", "grant_controls": {"builtInControls": ["mfa"]}, "session_controls": {}, "state": "enabled"}, {"conditions": {"clientAppTypes": ["all"], "signInRiskLevels": ["high", "medium"], "users": {"includeRoles": [], "includeUsers": ["All"]}}, "displayName": "sign-in risk", "grant_controls": {"builtInControls": ["block"]}, "session_controls": {}, "state": "enabled"}, {"conditions": {"applications": {"includeUserActions": ["urn:user:registersecurityinfo"]}, "clientAppTypes": ["all"], "users": {"includeRoles": [], "includeUsers": ["All"]}}, "displayName": "security info", "grant_controls": {"builtInControls": ["compliantDevice"]}, "session_controls": {}, "state": "enabled"}, {"conditions": {"clientAppTypes": ["all"], "users": {"includeRoles": [], "includeUsers": ["All"]}}, "displayName": "intune enrolment", "grant_controls": {"builtInControls": ["mfa"]}, "session_controls": {"signInFrequency": {"frequencyInterval": "everyTime", "isEnabled": true}}, "state": "enabled"}, {"conditions": {"authenticationFlows": {"transferMethods": ["deviceCodeFlow", "authenticationTransfer"]}, "clientAppTypes": ["all"], "users": {"includeRoles": [], "includeUsers": ["All"]}}, "displayName": "flows", "grant_controls": {"builtInControls": ["block"]}, "session_controls": {}, "state": "enabled"}], "device_registration": {"azure_ad_join_allowed_to_join": "selected", "local_admin_global_admins_enabled": false, "local_admin_registering_user_enabled": "none", "user_device_quota": 10}, "email_otp_state": "disabled", "group_creation": {"allowed_group_id": "", "enabled": "false", "settings_present": true}, "laps_enabled": true, "lockout": {"duration_seconds": 60, "settings_present": true, "threshold": 10}, "mfa_registration": {"members_not_mfa_capable": []}, "named_locations": [{"display_name": "offices", "is_trusted": true}, {"countries_and_regions": ["US"], "display_name": "countries"}], "on_premises_sync": {"configured": false}, "password_protection": {"custom_banned_list": "contoso", "on_premises_check_enabled": "True"}, "per_user_mfa": {"legacy_per_user_mfa": []}, "pim_approval_62e90394-69f5-4237-9190-012177145e10": {"is_approval_required": true, "primary_approver_count": 1}, "pim_approval_e8611ab8-c189-46e8-94e1-60213ab1f814": {"is_approval_required": true, "primary_approver_count": 1}, "pim_available": true, "system_preferred_mfa_state": "enabled", "unavailable": {}, "weak_methods_enabled": []}, "exchange": {"audit_bypass_associations": [], "collected": true, "external_in_outlook": [{"Enabled": true, "Identity": "default"}], "mailbox_audit": {"audit_disabled": [], "sample_limit": 100, "sampled": 1}, "organization_config": {"AuditDisabled": false, "BookingsEnabled": false, "CustomerLockBoxEnabled": true, "MailTipsAllTipsEnabled": true, "OAuth2ClientProfileEnabled": true, "RejectDirectSend": true}, "outbound_spam_policies": [{"AutoForwardingMode": "Off", "Name": "Default"}], "owa_mailbox_policies": [{"AdditionalStorageProvidersAvailable": false, "Name": "OwaMailboxPolicy-Default"}], "role_assignment_policies": [{"AssignedRoles": ["MyBaseOptions"], "Name": "Default Role Assignment Policy"}], "shared_mailboxes": [{"ExternalDirectoryObjectId": "00000000-0000-0000-0000-000000000001", "Identity": "shared"}], "sharing_policies": [{"Enabled": false, "Name": "Default Sharing Policy"}], "transport_config": {"SmtpClientAuthenticationDisabled": true}, "transport_rules": [], "unavailable": {}, "verified_domains": [{"dkim_present": true, "dmarc_present": true, "id": "contoso.example", "is_initial": false, "spf_present": true}, {"id": "contoso.onmicrosoft.com", "is_initial": true}]}, "fabric": {"collected": true, "settings": {"AllowGuestUserToAccessSharedContent": {"enabled": false}, "AllowServicePrincipalsCreateAndUseProfiles": {"enabled": false}, "BlockResourceKeyAuthentication": {"enabled": true}, "EimInformationProtectionEdit": {"enabled": true}, "ElevatedGuestsTenant": {"enabled": false}, "EnableDatasetInPlaceSharing": {"enabled": false}, "ExternalSharingV2": {"enabled": false}, "PublishToWeb": {"enabled": false}, "RScriptVisual": {"enabled": false}, "ServicePrincipalAccessGlobalAPIs": {"enabled": false}, "ServicePrincipalAccessPermissionAPIs": {"enabled": false}, "ShareLinkToEntireOrg": {"enabled": false}}, "unavailable": {}}, "intune": {"collected": true, "enrollment_platform_restrictions": [{"display_name": "default", "platforms": {"windows": {"personal_device_enrollment_blocked": true}}}], "secure_by_default": true, "unavailable": {}}, "purview": {"audit_log_accessible": true}, "purview_ps": {"collected": true, "dlp_policies": [{"Enabled": true, "Mode": "Enable", "Name": "dlp", "TeamsLocation": ["All"], "Workload": "Exchange, Teams, CopilotExperiences"}], "label_policies": [{"Enabled": true, "Name": "labels"}], "unavailable": {}}, "sharepoint": {"collected": true, "missing_properties": [], "tenant": {"DefaultLinkPermission": "View", "DefaultSharingLinkType": "Direct", "DisallowInfectedFileDownload": true, "EmailAttestationRequired": true, "EnableAzureADB2BIntegration": true, "ExternalUserExpirationRequired": true, "LegacyAuthProtocolsEnabled": false, "OneDriveSharingCapability": "Disabled", "PreventExternalUsersFromResharing": true, "SharingCapability": "ExistingExternalUserSharingOnly", "SharingDomainRestrictionMode": "AllowList"}, "unavailable": {}}, "teams": {"client_configuration": {"AllowBox": false, "AllowDropBox": false, "AllowEgnyte": false, "AllowEmailIntoChannel": false, "AllowGoogleDrive": false, "AllowShareFile": false}, "collected": true, "federation_configuration": {"AllowFederatedUsers": true, "AllowTeamsConsumer": false, "AllowTeamsConsumerInbound": false, "AllowedDomains": ["partner.example"], "ExternalAccessWithTrialTenants": "Blocked"}, "meeting_policies": [{"AllowAnonymousUsersToJoinMeeting": false, "AllowAnonymousUsersToStartMeeting": false, "AllowCloudRecording": false, "AllowExternalNonTrustedMeetingChat": false, "AllowExternalParticipantGiveRequestControl": false, "AllowPSTNUsersToBypassLobby": false, "AutoAdmittedUsers": "EveryoneInCompanyExcludingGuests", "DesignatedPresenterRoleMode": "OrganizerOnlyUserOverride", "Identity": "Global", "MeetingChatEnabledType": "EnabledExceptAnonymous"}], "messaging_policies": [{"AllowSecurityEndUserReporting": true, "Identity": "Global"}], "unavailable": {}}}

LEDGER_UNRESOLVED := ["1.1.2", "1.3.8", "2.2.1", "2.4.3", "2.4.5", "5.1.2.5", "5.1.2.6", "5.1.3.2", "5.1.3.3", "8.4.1"]

FAILING := {"fail", "evidence_missing", "not_attested"}

_kind(v) := "evidence" if contains(v, "(this is not a pass)")

_kind(v) := "fail" if not contains(v, "(this is not a pass)")

# [id, kind] for every violation that cites recommendation ids ("CIS 2.1.8/2.1.9/2.1.10: " cites three)
cited(vs) := {[id, k] |
	some v in vs
	is_string(v)
	ms := regex.find_all_string_submatch_n(`^CIS ([0-9]+(?:\.[0-9]+)+(?:/[0-9]+(?:\.[0-9]+)+)*): `, v, 1)
	count(ms) == 1
	cited_ids := split(ms[0][1], "/")
	some id in cited_ids
	k := _kind(v)
}

cited_ids(vs) := {p[0] | some p in cited(vs)}

test_control_results_are_exactly_the_benchmark_ids_in_order if {
	r := data.cis_m365_v7.main.compliance_report with input as {}
	[c.id | some c in r.control_results] == ["1.1.1", "1.1.2", "1.1.3", "1.1.4", "1.2.1", "1.2.2", "1.3.1", "1.3.2", "1.3.3", "1.3.4", "1.3.5", "1.3.6", "1.3.7", "1.3.8", "1.3.9", "2.1.1", "2.1.2", "2.1.3", "2.1.4", "2.1.5", "2.1.6", "2.1.7", "2.1.8", "2.1.9", "2.1.10", "2.1.11", "2.1.12", "2.1.13", "2.1.14", "2.1.15", "2.2.1", "2.4.1", "2.4.2", "2.4.3", "2.4.4", "2.4.5", "3.1.1", "3.2.1", "3.2.2", "3.2.3", "3.3.1", "4.1", "4.2", "5.1.2.1", "5.1.2.2", "5.1.2.3", "5.1.2.4", "5.1.2.5", "5.1.2.6", "5.1.3.1", "5.1.3.2", "5.1.3.3", "5.1.3.4", "5.1.4.1", "5.1.4.2", "5.1.4.3", "5.1.4.4", "5.1.4.5", "5.1.4.6", "5.1.5.1", "5.1.5.2", "5.1.5.3", "5.1.5.4", "5.1.5.5", "5.1.5.6", "5.1.6.1", "5.1.6.2", "5.1.6.3", "5.1.8.1", "5.2.2.1", "5.2.2.2", "5.2.2.3", "5.2.2.4", "5.2.2.5", "5.2.2.6", "5.2.2.7", "5.2.2.8", "5.2.2.9", "5.2.2.10", "5.2.2.11", "5.2.2.12", "5.2.2.13", "5.2.2.14", "5.2.2.15", "5.2.2.16", "5.2.2.17", "5.2.3.1", "5.2.3.2", "5.2.3.3", "5.2.3.4", "5.2.3.5", "5.2.3.6", "5.2.3.7", "5.2.3.8", "5.2.3.9", "5.2.3.10", "5.2.4.1", "5.2.4.2", "5.2.4.3", "5.2.4.4", "5.2.4.5", "5.3.1", "5.3.2", "5.3.3", "5.3.4", "5.3.5", "6.1.1", "6.1.2", "6.1.3", "6.2.1", "6.2.2", "6.2.3", "6.3.1", "6.3.2", "6.5.1", "6.5.2", "6.5.3", "6.5.4", "6.5.5", "7.2.1", "7.2.2", "7.2.3", "7.2.4", "7.2.5", "7.2.6", "7.2.7", "7.2.8", "7.2.9", "7.2.10", "7.2.11", "7.3.1", "8.1.1", "8.1.2", "8.2.1", "8.2.2", "8.2.3", "8.2.4", "8.4.1", "8.5.1", "8.5.2", "8.5.3", "8.5.4", "8.5.5", "8.5.6", "8.5.7", "8.5.8", "8.5.9", "8.6.1", "9.1.1", "9.1.2", "9.1.3", "9.1.4", "9.1.5", "9.1.6", "9.1.7", "9.1.8", "9.1.9", "9.1.10", "9.1.11", "9.1.12"]
}

test_control_results_fields if {
	r := data.cis_m365_v7.main.compliance_report with input as {}
	every c in r.control_results {
		c.status in {"pass", "fail", "evidence_missing", "not_attested", "not_applicable"}
		c.basis in {"evidence", "attestation"}
		c.in_scope == c.status != "not_applicable"
		count(c.profile) > 0
		every k in object.keys(c) { k in {"id", "status", "basis", "in_scope", "profile", "evidence"} }
	}
	sum([n | some n in r.control_result_counts]) == r.benchmark_total_controls
	count([c | some c in r.control_results; c.in_scope]) == r.benchmark_total_controls
}

# every control names the paths its decision reads (the attestation list for the sixteen ledger controls)
test_control_results_evidence_paths_known if {
	r := data.cis_m365_v7.main.compliance_report with input as {}
	every c in r.control_results {
		_evidence_known(c)
	}
}

_evidence_known(c) if count(object.get(c, "evidence", [])) > 0

test_control_results_empty_input_nothing_passes if {
	r := data.cis_m365_v7.main.compliance_report with input as {}
	r.control_result_counts == {"pass": 0, "fail": 0, "evidence_missing": 144, "not_attested": 16, "not_applicable": 0}
	every c in r.control_results {
		_ledger_unattested(c)
	}
}

# a cited control is failing with the message's kind; an evidence message never yields fail or pass
test_control_results_cited_controls_match_their_messages_empty_input if {
	r := data.cis_m365_v7.main.compliance_report with input as {}
	_cited_agree(r)
}

test_control_results_cited_controls_match_their_messages_mixed_input if {
	r := data.cis_m365_v7.main.compliance_report with input as object.union(json.remove(fixture_compliant, ["sharepoint/tenant/SharingCapability", "intune/secure_by_default", "attestations"]), {"teams": {"client_configuration": {"AllowEmailIntoChannel": true}}, "attestations": [a | some a in fixture_compliant.attestations; not a.control_id in {"5.2.4.1", "1.1.2"}]})
	_cited_agree(r)
}

_cited_agree(r) if {
	st := {c.id: c.status | some c in r.control_results}
	every p in cited(r.violations) {
		_agrees(p[1], st[p[0]])
	}
	failed := {c.id | some c in r.control_results; c.status == "fail"}
	failed == {p[0] | some p in cited(r.violations); p[1] == "fail"}
}

_agrees("fail", "fail")

_agrees("evidence", s) if s in {"evidence_missing", "not_attested", "fail"}

# failing controls no violation names: only ever evidence_missing, and exactly these
test_control_results_uncited_gaps_empty_input if {
	r := data.cis_m365_v7.main.compliance_report with input as {}
	gaps := {c.id | some c in r.control_results; c.status in FAILING; not c.id in cited_ids(r.violations)}
	every id in gaps { id in {c.id | some c in r.control_results; c.status == "evidence_missing"} }
	gaps == {x | some x in ["1.1.3", "1.1.4", "1.2.1", "1.3.1", "1.3.2", "1.3.4", "1.3.5", "1.3.7", "2.1.10", "2.1.11", "2.1.12", "2.1.13", "2.1.14", "2.1.15", "2.1.2", "2.1.3", "2.1.4", "2.1.5", "2.1.6", "2.1.7", "2.1.9", "2.4.1", "2.4.2", "2.4.4", "3.2.2", "3.2.3", "3.3.1", "4.2", "5.1.2.1", "5.1.2.3", "5.1.3.1", "5.1.3.4", "5.1.4.1", "5.1.4.2", "5.1.4.3", "5.1.4.4", "5.1.4.5", "5.1.4.6", "5.1.5.1", "5.1.5.2", "5.1.5.3", "5.1.5.4", "5.1.5.5", "5.1.5.6", "5.1.6.1", "5.1.6.2", "5.1.6.3", "5.1.8.1", "5.2.2.1", "5.2.2.10", "5.2.2.11", "5.2.2.12", "5.2.2.13", "5.2.2.14", "5.2.2.15", "5.2.2.16", "5.2.2.17", "5.2.2.2", "5.2.2.3", "5.2.2.4", "5.2.2.5", "5.2.2.6", "5.2.2.7", "5.2.2.8", "5.2.2.9", "5.2.3.1", "5.2.3.10", "5.2.3.2", "5.2.3.3", "5.2.3.4", "5.2.3.5", "5.2.3.6", "5.2.3.7", "5.2.3.8", "5.2.3.9", "5.3.1", "5.3.2", "5.3.3", "5.3.4", "5.3.5", "6.1.2", "6.1.3", "6.2.1", "6.2.2", "6.2.3", "6.3.1", "6.3.2", "6.5.1", "6.5.2", "6.5.3", "6.5.4", "6.5.5", "7.2.10", "7.2.11", "7.2.2", "7.2.3", "7.2.4", "7.2.5", "7.2.6", "7.2.7", "7.2.8", "7.2.9", "7.3.1", "8.1.2", "8.2.1", "8.2.2", "8.2.3", "8.2.4", "8.5.1", "8.5.2", "8.5.3", "8.5.4", "8.5.5", "8.5.6", "8.5.7", "8.5.8", "8.5.9", "8.6.1", "9.1.10", "9.1.11", "9.1.12", "9.1.2", "9.1.3", "9.1.4", "9.1.5", "9.1.6", "9.1.7", "9.1.8", "9.1.9"]}
}

test_control_results_mixed_input if {
	r := data.cis_m365_v7.main.compliance_report with input as object.union(json.remove(fixture_compliant, ["sharepoint/tenant/SharingCapability", "intune/secure_by_default", "attestations"]), {"teams": {"client_configuration": {"AllowEmailIntoChannel": true}}, "attestations": [a | some a in fixture_compliant.attestations; not a.control_id in {"5.2.4.1", "1.1.2"}]})
	r.control_result_counts == {"pass": 154, "fail": 1, "evidence_missing": 3, "not_attested": 2, "not_applicable": 0}
	gaps := {c.id | some c in r.control_results; c.status in FAILING; not c.id in cited_ids(r.violations)}
	gaps == {"4.1", "7.2.6"}
	st := {c.id: c.status | some c in r.control_results}
	st["8.1.2"] == "fail"
	st["7.2.3"] == "evidence_missing"
	st["5.2.4.1"] == "not_attested"
	st["1.1.2"] == "not_attested"
}

test_control_results_compliant_fixture_every_recommendation_passes if {
	r := data.cis_m365_v7.main.compliance_report with input as fixture_compliant
	count(r.violations) == 0
	r.control_result_counts.pass == 160
	every c in r.control_results { c.status == "pass" }
	every id in LEDGER_UNRESOLVED {
		some c in r.control_results
		c.id == id
		c.basis == "attestation"
	}
}

test_control_results_licence_tiers_scope if {
	e3l1 := data.cis_m365_v7.main.compliance_report with input as {"cis_profile": {"licence": "E3", "level": 1}}
	e3l2 := data.cis_m365_v7.main.compliance_report with input as {"cis_profile": {"licence": "E3", "level": 2}}
	e5l1 := data.cis_m365_v7.main.compliance_report with input as {"cis_profile": {"licence": "E5", "level": 1}}
	e5l2 := data.cis_m365_v7.main.compliance_report with input as {"cis_profile": {"licence": "E5", "level": 2}}
	count([c | some c in e3l1.control_results; c.in_scope]) == 100
	count([c | some c in e3l2.control_results; c.in_scope]) == 137
	count([c | some c in e5l1.control_results; c.in_scope]) == 114
	count([c | some c in e5l2.control_results; c.in_scope]) == 160
	e3l1.control_results_profile.defaulted == false
	every c in e3l1.control_results {
		_scope_follows_tag(c, "E3 Level 1")
	}
}

test_control_results_compliant_fixture_under_e3_level_1 if {
	r := data.cis_m365_v7.main.compliance_report with input as object.union(fixture_compliant, {"cis_profile": {"licence": "E3", "level": 1}})
	r.control_result_counts == {"pass": 100, "fail": 0, "evidence_missing": 0, "not_attested": 0, "not_applicable": 60}
}

test_control_results_profile_defaults_to_every_recommendation if {
	r := data.cis_m365_v7.main.compliance_report with input as {"cis_profile": {"licence": "E7"}}
	r.control_results_profile == {"licence": "E5", "level": 2, "defaulted": true, "input": r.control_results_profile.input}
	count([c | some c in r.control_results; c.in_scope]) == 160
}

_scope_follows_tag(c, tag) if {
	c.in_scope
	tag in c.profile
}

_scope_follows_tag(c, tag) if {
	not c.in_scope
	not tag in c.profile
}

# on empty input the sixteen ledger controls, and only they, are not_attested, by attestation
_ledger_unattested(c) if {
	c.status == "not_attested"
	c.basis == "attestation"
	c.evidence == ["attestations"]
}

_ledger_unattested(c) if {
	c.status != "not_attested"
	c.basis == "evidence"
}
