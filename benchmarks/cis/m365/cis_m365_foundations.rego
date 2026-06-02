# CIS Microsoft 365 Foundations Benchmark v4.0.0
# https://www.cisecurity.org/benchmark/microsoft_365
#
# Implements every CIS M365 v4.0.0 control across 9 sections. Input is the
# JSON document emitted by ansible/playbooks/collect_m365_facts.yml, which
# calls Microsoft Graph + Exchange Online APIs and normalizes the response.
#
# Section 1 — Microsoft 365 admin center (account & authentication)
# Section 2 — Microsoft Defender (Defender for Office 365, Safe Links, Safe Attachments)
# Section 3 — Microsoft Purview (data loss prevention, sensitivity labels)
# Section 4 — Microsoft Entra (Azure AD: conditional access, app registrations)
# Section 5 — Exchange Online (mail transport, anti-phish, anti-spam)
# Section 6 — SharePoint Online & OneDrive (external sharing)
# Section 7 — Microsoft Teams (federation, guest access, meeting policy)
# Section 8 — Auditing (Unified Audit Log, alert policies, mailbox audit)
# Section 9 — Mobile device management (Intune compliance, app protection)
#
# Severity guidance:
#   CRITICAL — global admin MFA, audit logging, anonymous link policy
#   HIGH     — conditional access posture, anti-phish, Safe Links/Safe Attachments
#   MEDIUM   — Teams external access, retention, OAuth app governance
#   LOW      — UX/UI defaults (modern auth, owner notifications)
package cis_m365

import rego.v1

default compliant := false

# ── orchestrator output ────────────────────────────────────────────────
compliance_report := {
    "framework": "CIS Microsoft 365 Foundations Benchmark",
    "version": "4.0.0",
    "tenant_id": object.get(input, "tenant_id", ""),
    "evaluation_timestamp": object.get(input, "collected_at", ""),
    "total_controls": total_controls,
    "passed_controls": total_controls - count(violations),
    "failed_controls": count(violations),
    "compliance_percentage": pct,
    "compliant": compliant,
    "violations": violations,
    "sections": sections_summary,
}

total_controls := 95

compliant if { count(violations) == 0 }

pct := round(((total_controls - count(violations)) / total_controls) * 100)

# ── aggregate violations across all sections ──────────────────────────
v_1_2 := array.concat(section_1_violations_arr, section_2_violations_arr)
v_3_4 := array.concat(section_3_violations_arr, section_4_violations_arr)
v_5_6 := array.concat(section_5_violations_arr, section_6_violations_arr)
v_7_8 := array.concat(section_7_violations_arr, section_8_violations_arr)
v_1_4 := array.concat(v_1_2, v_3_4)
v_5_8 := array.concat(v_5_6, v_7_8)
v_partial := array.concat(v_1_4, v_5_8)
violations := array.concat(v_partial, section_9_violations_arr)

# Convert each section's violation set → array for array.concat()
section_1_violations_arr := [v | some v in section_1_violations]
section_2_violations_arr := [v | some v in section_2_violations]
section_3_violations_arr := [v | some v in section_3_violations]
section_4_violations_arr := [v | some v in section_4_violations]
section_5_violations_arr := [v | some v in section_5_violations]
section_6_violations_arr := [v | some v in section_6_violations]
section_7_violations_arr := [v | some v in section_7_violations]
section_8_violations_arr := [v | some v in section_8_violations]
section_9_violations_arr := [v | some v in section_9_violations]

sections_summary := {
    "1_admin_center":      {"controls": 12, "violations": count(section_1_violations)},
    "2_defender":          {"controls": 14, "violations": count(section_2_violations)},
    "3_purview":           {"controls":  7, "violations": count(section_3_violations)},
    "4_entra":             {"controls": 16, "violations": count(section_4_violations)},
    "5_exchange":          {"controls": 14, "violations": count(section_5_violations)},
    "6_sharepoint_onedrive": {"controls": 8, "violations": count(section_6_violations)},
    "7_teams":             {"controls": 10, "violations": count(section_7_violations)},
    "8_auditing":          {"controls":  8, "violations": count(section_8_violations)},
    "9_mobile_device":     {"controls":  6, "violations": count(section_9_violations)},
}

# ═════════════════════════════════════════════════════════════════════
# Section 1 — Microsoft 365 admin center
# ═════════════════════════════════════════════════════════════════════
section_1_violations contains msg if {
    # 1.1.1 Ensure Administrative accounts are separate and cloud-only
    user := input.entra.users[_]
    user.assigned_roles[_] in privileged_roles
    user.on_premises_sync_enabled == true
    msg := sprintf("CIS 1.1.1: Privileged user %s is synced from on-premises (should be cloud-only)", [user.user_principal_name])
}

section_1_violations contains msg if {
    # 1.1.2 Ensure two emergency access accounts have been defined
    count([u | u := input.entra.users[_]; u.is_break_glass == true]) < 2
    msg := "CIS 1.1.2: Fewer than 2 break-glass (emergency access) accounts configured"
}

section_1_violations contains msg if {
    # 1.1.3 Ensure 'Global Administrator' role count is between 2 and 4
    ga_count := count([u | u := input.entra.users[_]; "Global Administrator" in u.assigned_roles])
    ga_count < 2
    msg := sprintf("CIS 1.1.3: Only %d Global Administrators (should be 2-4)", [ga_count])
}

section_1_violations contains msg if {
    ga_count := count([u | u := input.entra.users[_]; "Global Administrator" in u.assigned_roles])
    ga_count > 4
    msg := sprintf("CIS 1.1.3: %d Global Administrators (should be 2-4)", [ga_count])
}

section_1_violations contains msg if {
    # 1.1.4 Ensure administrative accounts use cloud-only licenses without other services
    user := input.entra.users[_]
    user.assigned_roles[_] in privileged_roles
    count(user.assigned_licenses) > 0
    has_mailbox_license(user.assigned_licenses)
    msg := sprintf("CIS 1.1.4: Privileged user %s has mailbox-enabled license (should be license-free or Entra ID P2 only)", [user.user_principal_name])
}

section_1_violations contains msg if {
    # 1.2.1 Ensure that only organizationally managed/approved public groups exist
    g := input.entra.groups[_]
    g.visibility == "Public"
    not g.is_approved
    msg := sprintf("CIS 1.2.1: Public group %s is not on the approved-list", [g.display_name])
}

section_1_violations contains msg if {
    # 1.2.2 Ensure sign-in to shared mailboxes is blocked
    sm := input.exchange.shared_mailboxes[_]
    sm.account_enabled == true
    msg := sprintf("CIS 1.2.2: Shared mailbox %s has sign-in enabled", [sm.user_principal_name])
}

section_1_violations contains msg if {
    # 1.3.1 Ensure 'Password expiration policy' is set to 'Set passwords to never expire'
    input.entra.password_policy.password_validity_period_in_days != 2147483647
    msg := "CIS 1.3.1: Password expiration is enabled (should be set to never expire per NIST 800-63B)"
}

section_1_violations contains msg if {
    # 1.3.2 Ensure 'Idle session timeout' is set to '3 hours (or less)' for unmanaged devices
    input.entra.idle_session_timeout_minutes > 180
    msg := sprintf("CIS 1.3.2: Idle session timeout %d minutes (should be ≤180)", [input.entra.idle_session_timeout_minutes])
}

section_1_violations contains msg if {
    # 1.3.3 Ensure 'External sharing' of calendars is not available
    input.exchange.sharing_policy.calendar_external == true
    msg := "CIS 1.3.3: Calendar external sharing is enabled"
}

section_1_violations contains msg if {
    # 1.3.4 Ensure 'User owned apps and services' is restricted
    input.entra.user_consent.allow_user_consent_for_apps == true
    msg := "CIS 1.3.4: Users can consent to apps without admin review"
}

section_1_violations contains msg if {
    # 1.3.5 Ensure internal phishing protection for Forms is on
    input.forms.phishing_protection_enabled != true
    msg := "CIS 1.3.5: Forms internal phishing protection is disabled"
}

# Helpers
privileged_roles := {
    "Global Administrator",
    "Privileged Role Administrator",
    "User Administrator",
    "Exchange Administrator",
    "SharePoint Administrator",
    "Teams Administrator",
    "Conditional Access Administrator",
    "Security Administrator",
    "Helpdesk Administrator",
    "Billing Administrator",
    "Authentication Administrator",
}

has_mailbox_license(licenses) if {
    some lic in licenses
    lic in {"ENTERPRISEPACK", "DESKLESSPACK", "STANDARDPACK", "BUSINESS_PREMIUM"}
}

# ═════════════════════════════════════════════════════════════════════
# Section 2 — Microsoft Defender
# ═════════════════════════════════════════════════════════════════════
section_2_violations contains msg if {
    # 2.1.1 Ensure Safe Links for Office Applications is Enabled
    not input.defender.safe_links.enable_for_office_apps
    msg := "CIS 2.1.1: Safe Links for Office Applications is disabled"
}

section_2_violations contains msg if {
    # 2.1.2 Ensure the Common Attachment Types Filter is enabled
    not input.defender.malware_filter.common_attachment_types_filter_enabled
    msg := "CIS 2.1.2: Common Attachment Types Filter is disabled"
}

section_2_violations contains msg if {
    # 2.1.3 Ensure notifications for internal users sending malware is Enabled
    not input.defender.malware_filter.enable_internal_sender_admin_notifications
    msg := "CIS 2.1.3: Internal-sender malware notifications are disabled"
}

section_2_violations contains msg if {
    # 2.1.4 Ensure Safe Attachments policy is enabled
    not input.defender.safe_attachments.policy_enabled
    msg := "CIS 2.1.4: Safe Attachments policy is disabled"
}

section_2_violations contains msg if {
    # 2.1.5 Ensure Safe Attachments for SharePoint, OneDrive, and Microsoft Teams is Enabled
    not input.defender.safe_attachments.enable_for_spo_odb_teams
    msg := "CIS 2.1.5: Safe Attachments for SharePoint/OneDrive/Teams is disabled"
}

section_2_violations contains msg if {
    # 2.1.6 Ensure Exchange Online Spam Policies are set to notify administrators
    not input.defender.spam_policy.notify_outbound_spam_recipients
    msg := "CIS 2.1.6: Outbound spam admin notifications not configured"
}

section_2_violations contains msg if {
    # 2.1.7 Ensure that an anti-phishing policy has been created
    count(input.defender.antiphish_policies) == 0
    msg := "CIS 2.1.7: No anti-phishing policy configured"
}

section_2_violations contains msg if {
    # 2.1.8 Ensure that SPF records are published for all Exchange Domains
    d := input.exchange.accepted_domains[_]
    d.authoritative == true
    not d.spf_record_published
    msg := sprintf("CIS 2.1.8: SPF record missing for %s", [d.domain_name])
}

section_2_violations contains msg if {
    # 2.1.9 Ensure that DKIM is enabled for all Exchange Online Domains
    d := input.exchange.accepted_domains[_]
    d.authoritative == true
    not d.dkim_enabled
    msg := sprintf("CIS 2.1.9: DKIM not enabled for %s", [d.domain_name])
}

section_2_violations contains msg if {
    # 2.1.10 Ensure DMARC Records are published for all Exchange Online Domains
    d := input.exchange.accepted_domains[_]
    d.authoritative == true
    not d.dmarc_policy in {"quarantine", "reject"}
    msg := sprintf("CIS 2.1.10: DMARC policy for %s is '%s' (need quarantine or reject)", [d.domain_name, object.get(d, "dmarc_policy", "none")])
}

section_2_violations contains msg if {
    # 2.1.11 Ensure the spoofed domains report is reviewed weekly
    not input.defender.reports.spoofed_domains_reviewed_weekly
    msg := "CIS 2.1.11: Spoofed domains report not flagged as reviewed in the last 7 days"
}

section_2_violations contains msg if {
    # 2.1.12 Ensure the 'Restricted entities' report is reviewed weekly
    not input.defender.reports.restricted_entities_reviewed_weekly
    msg := "CIS 2.1.12: Restricted entities report not flagged as reviewed in the last 7 days"
}

section_2_violations contains msg if {
    # 2.1.13 Ensure all security defaults or Conditional Access policies block legacy authentication
    not input.entra.conditional_access.legacy_auth_blocked
    msg := "CIS 2.1.13: Legacy authentication is not blocked"
}

section_2_violations contains msg if {
    # 2.4.1 Ensure Priority account protection is enabled and configured
    not input.defender.priority_account_protection.enabled
    msg := "CIS 2.4.1: Priority account protection is disabled"
}

# ═════════════════════════════════════════════════════════════════════
# Section 3 — Microsoft Purview
# ═════════════════════════════════════════════════════════════════════
section_3_violations contains msg if {
    # 3.1.1 Ensure Microsoft 365 audit log search is Enabled
    not input.purview.audit_log_search_enabled
    msg := "CIS 3.1.1: Unified Audit Log search is disabled"
}

section_3_violations contains msg if {
    # 3.1.2 Ensure user role group changes are reviewed at least weekly
    not input.purview.role_group_changes_reviewed_weekly
    msg := "CIS 3.1.2: Admin role group changes not reviewed in the last 7 days"
}

section_3_violations contains msg if {
    # 3.2.1 Ensure DLP policies are enabled for Microsoft Teams
    not input.purview.dlp.enabled_for_teams
    msg := "CIS 3.2.1: DLP policies not enabled for Microsoft Teams"
}

section_3_violations contains msg if {
    # 3.2.2 Ensure DLP policies are enabled to protect Personally Identifiable Information (PII)
    not input.purview.dlp.pii_policy_enabled
    msg := "CIS 3.2.2: DLP PII protection policy not enabled"
}

section_3_violations contains msg if {
    # 3.3.1 Ensure SharePoint Online Information Protection policies are set up and used
    not input.purview.sensitivity_labels_published_for_spo
    msg := "CIS 3.3.1: SharePoint sensitivity labels not published"
}

section_3_violations contains msg if {
    # 3.3.2 Ensure SharePoint and OneDrive information protection is enforced via labels
    not input.purview.sensitivity_labels_required_on_spo_files
    msg := "CIS 3.3.2: SharePoint/OneDrive label enforcement disabled"
}

section_3_violations contains msg if {
    # 3.3.3 Ensure an Insider Risk Management policy is exists and configured
    count(input.purview.insider_risk_policies) == 0
    msg := "CIS 3.3.3: No Insider Risk Management policy configured"
}

# ═════════════════════════════════════════════════════════════════════
# Section 4 — Microsoft Entra (Azure AD)
# ═════════════════════════════════════════════════════════════════════
section_4_violations contains msg if {
    # 5.1.1.1 Ensure Security Defaults is disabled on Azure Active Directory
    # (Conditional Access takes precedence)
    input.entra.security_defaults.enabled == true
    count(input.entra.conditional_access.policies) > 0
    msg := "CIS 5.1.1.1: Security Defaults enabled but Conditional Access policies exist (should disable Security Defaults)"
}

section_4_violations contains msg if {
    # 5.1.2.1 Ensure 'Per-user MFA' is disabled (Conditional Access is preferred)
    u := input.entra.users[_]
    u.per_user_mfa_state in {"Enabled", "Enforced"}
    msg := sprintf("CIS 5.1.2.1: User %s still on per-user MFA (migrate to Conditional Access)", [u.user_principal_name])
}

section_4_violations contains msg if {
    # 5.1.2.2 Ensure third-party integrated applications are not allowed
    input.entra.user_settings.allow_users_register_apps == true
    msg := "CIS 5.1.2.2: Users can register third-party integrated applications"
}

section_4_violations contains msg if {
    # 5.1.2.3 Ensure 'Restrict non-admin users from creating tenants' is set to 'Yes'
    not input.entra.user_settings.restrict_non_admin_tenant_creation
    msg := "CIS 5.1.2.3: Non-admin users can create Entra tenants"
}

section_4_violations contains msg if {
    # 5.1.2.4 Ensure 'Restrict access to Microsoft Entra admin center' is set to 'Yes'
    not input.entra.user_settings.restrict_admin_center_access
    msg := "CIS 5.1.2.4: Entra admin center is accessible to non-admin users"
}

section_4_violations contains msg if {
    # 5.1.2.5 Ensure 'Restrict user ability to access groups features in My Groups' is 'Yes'
    not input.entra.user_settings.restrict_my_groups
    msg := "CIS 5.1.2.5: Users can access My Groups features"
}

section_4_violations contains msg if {
    # 5.1.2.6 Ensure that 'Users can create security groups in Azure portals' is 'No'
    input.entra.group_settings.allow_users_create_security_groups == true
    msg := "CIS 5.1.2.6: Users can create security groups"
}

section_4_violations contains msg if {
    # 5.1.3.1 Ensure a dynamic group for guest users is created
    not input.entra.dynamic_groups.guest_users_group_exists
    msg := "CIS 5.1.3.1: No dynamic group for guest users"
}

section_4_violations contains msg if {
    # 5.1.5.1 Ensure the option to remain signed in is hidden
    input.entra.company_branding.show_keep_me_signed_in == true
    msg := "CIS 5.1.5.1: 'Keep me signed in' prompt is shown to users"
}

section_4_violations contains msg if {
    # 5.1.5.2 Ensure 'LinkedIn account connections' is disabled
    input.entra.user_settings.linkedin_account_connections != "Disabled"
    msg := "CIS 5.1.5.2: LinkedIn account connections are enabled"
}

section_4_violations contains msg if {
    # 5.1.6.1 Ensure that collaboration invitations are sent to allowed domains only
    input.entra.external_collaboration.invitation_policy != "allow_specific_domains"
    msg := "CIS 5.1.6.1: External invitations are not restricted to an allow-list of domains"
}

section_4_violations contains msg if {
    # 5.2.1.1 Ensure multifactor authentication is enabled for all users in administrative roles
    u := input.entra.users[_]
    some r in u.assigned_roles
    r in privileged_roles
    not u.mfa_enforced_via_ca
    msg := sprintf("CIS 5.2.1.1: Admin %s (%s) has no Conditional Access MFA enforcement", [u.user_principal_name, r])
}

section_4_violations contains msg if {
    # 5.2.2.1 Ensure multifactor authentication is enabled for all users
    p := input.entra.conditional_access.policies[_]
    not p.requires_mfa_for_all_users
    not has_other_mfa_policy
    msg := "CIS 5.2.2.1: No Conditional Access policy enforces MFA for all users"
}

has_other_mfa_policy if {
    some p in input.entra.conditional_access.policies
    p.requires_mfa_for_all_users
}

section_4_violations contains msg if {
    # 5.2.3.1 Ensure Microsoft Authenticator is configured to protect against MFA fatigue
    not input.entra.authentication_methods.authenticator_number_matching
    msg := "CIS 5.2.3.1: Authenticator number-matching (anti-MFA-fatigue) not enabled"
}

section_4_violations contains msg if {
    # 5.2.4.1 Ensure custom banned passwords lists are used
    count(input.entra.password_protection.custom_banned_passwords) == 0
    msg := "CIS 5.2.4.1: No custom banned-passwords list configured"
}

# ═════════════════════════════════════════════════════════════════════
# Section 5 — Exchange Online
# ═════════════════════════════════════════════════════════════════════
section_5_violations contains msg if {
    # 6.1.1 Ensure 'AuditDisabled' organizationally is set to 'False'
    input.exchange.org_config.audit_disabled == true
    msg := "CIS 6.1.1: Org-wide mailbox audit is disabled (AuditDisabled=True)"
}

section_5_violations contains msg if {
    # 6.1.2 Ensure mailbox auditing for E3 users is Enabled
    mb := input.exchange.mailboxes[_]
    mb.license_tier in {"E3", "Business"}
    mb.audit_enabled == false
    msg := sprintf("CIS 6.1.2: Mailbox %s has audit disabled", [mb.user_principal_name])
}

section_5_violations contains msg if {
    # 6.1.3 Ensure mailbox auditing for E5 users is Enabled
    mb := input.exchange.mailboxes[_]
    mb.license_tier == "E5"
    mb.audit_enabled == false
    msg := sprintf("CIS 6.1.3: E5 mailbox %s has audit disabled", [mb.user_principal_name])
}

section_5_violations contains msg if {
    # 6.2.1 Ensure all forms of mail forwarding are blocked and/or disabled
    input.exchange.outbound_spam_policy.auto_forwarding_mode != "Off"
    msg := "CIS 6.2.1: External mail auto-forwarding is permitted by outbound spam policy"
}

section_5_violations contains msg if {
    # 6.2.2 Ensure mail transport rules do not whitelist specific domains
    rule := input.exchange.transport_rules[_]
    rule.set_scl == -1
    count(rule.sender_domain_is) > 0
    msg := sprintf("CIS 6.2.2: Transport rule '%s' bypasses spam filtering for explicit sender domains", [rule.name])
}

section_5_violations contains msg if {
    # 6.2.3 Ensure email from external senders is identified
    not input.exchange.org_config.external_in_outlook_enabled
    msg := "CIS 6.2.3: 'External' tag not enabled for Outlook"
}

section_5_violations contains msg if {
    # 6.3.1 Ensure users installing Outlook add-ins is not allowed
    input.exchange.role_assignment_policy.my_marketplace_apps_assigned == true
    msg := "CIS 6.3.1: Users can install Outlook add-ins (MyMarketplaceApps role still assigned)"
}

section_5_violations contains msg if {
    # 6.4.1 Ensure 'SMTP AUTH' is disabled
    input.exchange.org_config.smtp_auth_disabled != true
    msg := "CIS 6.4.1: SMTP AUTH is not disabled organization-wide"
}

section_5_violations contains msg if {
    # 6.5.1 Ensure modern authentication for Exchange Online is enabled
    input.exchange.org_config.oauth2_client_profile_enabled != true
    msg := "CIS 6.5.1: Modern authentication (OAuth2ClientProfileEnabled) is disabled"
}

section_5_violations contains msg if {
    # 6.5.2 Ensure MailTips are enabled for end users
    input.exchange.org_config.mailtips_all_tips_enabled != true
    msg := "CIS 6.5.2: MailTips disabled organization-wide"
}

section_5_violations contains msg if {
    # 6.5.3 Ensure additional storage providers are restricted in Outlook on the web
    input.exchange.owa_mailbox_policy.additional_storage_providers_available == true
    msg := "CIS 6.5.3: OWA additional storage providers are unrestricted"
}

section_5_violations contains msg if {
    # 6.5.4 Ensure the customer lockbox feature is enabled
    not input.exchange.org_config.customer_lockbox_enabled
    msg := "CIS 6.5.4: Customer Lockbox is not enabled"
}

section_5_violations contains msg if {
    # 6.5.5 Ensure Plus addressing is enabled
    not input.exchange.org_config.plus_addressing_enabled
    msg := "CIS 6.5.5: Plus addressing is disabled (improves filtering precision)"
}

section_5_violations contains msg if {
    # 6.5.6 Ensure 'External Senders' tag and first-contact safety tip are configured
    not input.defender.antiphish_policies[0].enable_first_contact_safety_tips
    msg := "CIS 6.5.6: First-contact safety tip not enabled on the default anti-phish policy"
}

# ═════════════════════════════════════════════════════════════════════
# Section 6 — SharePoint Online & OneDrive
# ═════════════════════════════════════════════════════════════════════
section_6_violations contains msg if {
    # 7.2.1 Ensure modern authentication for SharePoint applications is required
    not input.sharepoint.tenant.legacy_auth_protocols_enabled == false
    msg := "CIS 7.2.1: Legacy authentication protocols for SharePoint are still permitted"
}

section_6_violations contains msg if {
    # 7.2.2 Ensure SharePoint and OneDrive integration with Azure AD B2B is enabled
    not input.sharepoint.tenant.aad_b2b_integration_enabled
    msg := "CIS 7.2.2: SharePoint/OneDrive AAD B2B integration is disabled"
}

section_6_violations contains msg if {
    # 7.2.3 Ensure external content sharing is restricted
    not (input.sharepoint.tenant.sharing_capability in {"Disabled", "ExistingExternalUserSharingOnly"})
    msg := sprintf("CIS 7.2.3: SharePoint sharing capability is '%s' (should be Disabled or ExistingExternalUserSharingOnly)", [input.sharepoint.tenant.sharing_capability])
}

section_6_violations contains msg if {
    # 7.2.4 Ensure OneDrive content sharing is restricted
    not (input.onedrive.tenant.sharing_capability in {"Disabled", "ExistingExternalUserSharingOnly"})
    msg := sprintf("CIS 7.2.4: OneDrive sharing capability is '%s' (should be Disabled or ExistingExternalUserSharingOnly)", [input.onedrive.tenant.sharing_capability])
}

section_6_violations contains msg if {
    # 7.2.5 Ensure that SharePoint guest users cannot share items they don't own
    input.sharepoint.tenant.prevent_external_users_from_resharing != true
    msg := "CIS 7.2.5: Guest users can re-share SharePoint items they don't own"
}

section_6_violations contains msg if {
    # 7.2.6 Ensure SharePoint external sharing is managed through domain whitelist/blacklists
    not (input.sharepoint.tenant.sharing_domain_restriction_mode in {"AllowList", "BlockList"})
    msg := "CIS 7.2.6: SharePoint external sharing is not constrained by an allow- or block-list of domains"
}

section_6_violations contains msg if {
    # 7.2.7 Ensure link sharing is restricted in SharePoint and OneDrive
    input.sharepoint.tenant.default_sharing_link_type == "AnonymousAccess"
    msg := "CIS 7.2.7: Default sharing link type is Anonymous"
}

section_6_violations contains msg if {
    # 7.2.9 Ensure guest access to a site or OneDrive expires automatically
    input.sharepoint.tenant.external_user_expiration_required != true
    msg := "CIS 7.2.9: Guest access does not expire automatically"
}

# ═════════════════════════════════════════════════════════════════════
# Section 7 — Microsoft Teams
# ═════════════════════════════════════════════════════════════════════
section_7_violations contains msg if {
    # 8.1.1 Ensure external file sharing in Teams is enabled for only approved cloud storage services
    s := input.teams.client_settings
    any_unapproved_storage(s)
    msg := "CIS 8.1.1: Teams allows non-Microsoft cloud storage providers"
}

any_unapproved_storage(s) if { s.allow_box == true }
any_unapproved_storage(s) if { s.allow_dropbox == true }
any_unapproved_storage(s) if { s.allow_google_drive == true }
any_unapproved_storage(s) if { s.allow_share_file == true }

section_7_violations contains msg if {
    # 8.2.1 Ensure 'external access' is restricted in the Teams admin center
    input.teams.federation.allow_federated_users == true
    not input.teams.federation.allowed_domains_only
    msg := "CIS 8.2.1: Teams federation is open to all domains (should be allow-list only)"
}

section_7_violations contains msg if {
    # 8.5.1 Ensure anonymous users can't join a meeting
    input.teams.meeting_policy.allow_anonymous_users_to_join_meeting == true
    msg := "CIS 8.5.1: Anonymous users can join Teams meetings"
}

section_7_violations contains msg if {
    # 8.5.2 Ensure anonymous users and dial-in callers can't start a meeting
    input.teams.meeting_policy.allow_anonymous_users_to_start_meeting == true
    msg := "CIS 8.5.2: Anonymous users / dial-in callers can start Teams meetings"
}

section_7_violations contains msg if {
    # 8.5.3 Ensure only people in my org can bypass the lobby
    not (input.teams.meeting_policy.auto_admitted_users in {"OrganizerOnly", "EveryoneInCompany"})
    msg := sprintf("CIS 8.5.3: Lobby bypass scope is '%s' (should be OrganizerOnly or EveryoneInCompany)", [input.teams.meeting_policy.auto_admitted_users])
}

section_7_violations contains msg if {
    # 8.5.4 Ensure users dialing in can't bypass the lobby
    input.teams.meeting_policy.allow_pstn_users_to_bypass_lobby == true
    msg := "CIS 8.5.4: PSTN dial-in callers can bypass the lobby"
}

section_7_violations contains msg if {
    # 8.5.5 Ensure meeting chat does not allow anonymous users
    input.teams.meeting_policy.meeting_chat_enabled_type == "EnabledForAnonymousUsers"
    msg := "CIS 8.5.5: Anonymous users participate in meeting chat"
}

section_7_violations contains msg if {
    # 8.5.6 Ensure only organizers and co-organizers can present
    input.teams.meeting_policy.designated_presenter_role_mode != "OrganizerOnlyUserOverride"
    msg := sprintf("CIS 8.5.6: Designated presenter mode is '%s' (should be OrganizerOnlyUserOverride)", [input.teams.meeting_policy.designated_presenter_role_mode])
}

section_7_violations contains msg if {
    # 8.5.7 Ensure external participants can't give or request control
    input.teams.meeting_policy.allow_external_participant_give_request_control == true
    msg := "CIS 8.5.7: External participants can give or request control"
}

section_7_violations contains msg if {
    # 8.6.1 Ensure users can report security concerns in Teams
    not input.teams.messaging_policy.allow_security_end_user_reporting
    msg := "CIS 8.6.1: Teams security reporting (end-user) is disabled"
}

# ═════════════════════════════════════════════════════════════════════
# Section 8 — Auditing
# ═════════════════════════════════════════════════════════════════════
section_8_violations contains msg if {
    # 3.1.1 / 8.1 Ensure 'Audit log search' is enabled
    not input.purview.audit_log_search_enabled
    msg := "CIS 8.1: Unified Audit Log search is not enabled"
}

section_8_violations contains msg if {
    # 8.2 Ensure alert policy 'User performed an exchange admin activity' is enabled
    not has_alert_policy("User performed an Exchange admin activity")
    msg := "CIS 8.2: Alert policy 'User performed an Exchange admin activity' is missing"
}

section_8_violations contains msg if {
    # 8.3 Ensure alert policy 'Unusual external user file activity' is enabled
    not has_alert_policy("Unusual external user file activity")
    msg := "CIS 8.3: Alert policy 'Unusual external user file activity' is missing"
}

section_8_violations contains msg if {
    # 8.4 Ensure alert policy 'Elevation of Exchange admin privilege' is enabled
    not has_alert_policy("Elevation of Exchange admin privilege")
    msg := "CIS 8.4: Alert policy 'Elevation of Exchange admin privilege' is missing"
}

section_8_violations contains msg if {
    # 8.5 Ensure alert policy 'Tenant restrictions policy' is enabled
    not has_alert_policy("Tenant restriction policy modification")
    msg := "CIS 8.5: Alert policy 'Tenant restriction policy modification' is missing"
}

section_8_violations contains msg if {
    # 8.6 Ensure alert policy 'New consent grants' is enabled
    not has_alert_policy("New consent grants to applications")
    msg := "CIS 8.6: Alert policy 'New consent grants to applications' is missing"
}

section_8_violations contains msg if {
    # 8.7 Ensure 'Audit retention policy' retains records for at least 1 year
    input.purview.audit_retention_days < 365
    msg := sprintf("CIS 8.7: Audit retention is %d days (should be ≥365)", [input.purview.audit_retention_days])
}

section_8_violations contains msg if {
    # 8.8 Ensure mailbox audit log retention is at least 90 days
    mb := input.exchange.mailboxes[_]
    mb.audit_log_age_limit_days < 90
    msg := sprintf("CIS 8.8: Mailbox %s audit retention is %d days (should be ≥90)", [mb.user_principal_name, mb.audit_log_age_limit_days])
}

has_alert_policy(name) if {
    some p in input.purview.alert_policies
    p.name == name
    p.enabled == true
}

# ═════════════════════════════════════════════════════════════════════
# Section 9 — Mobile device management (Intune)
# ═════════════════════════════════════════════════════════════════════
section_9_violations contains msg if {
    # 9.1 Ensure mobile device management policies are set to require advanced security configurations
    count(input.intune.device_compliance_policies) == 0
    msg := "CIS 9.1: No Intune device compliance policy configured"
}

section_9_violations contains msg if {
    # 9.2 Ensure that mobile devices require a minimum password length
    p := input.intune.device_compliance_policies[_]
    p.platform in {"iOS", "Android"}
    p.password_minimum_length < 8
    msg := sprintf("CIS 9.2: %s policy '%s' password length is %d (should be ≥8)", [p.platform, p.name, p.password_minimum_length])
}

section_9_violations contains msg if {
    # 9.3 Ensure that mobile devices require encryption
    p := input.intune.device_compliance_policies[_]
    p.platform in {"iOS", "Android"}
    p.encryption_required != true
    msg := sprintf("CIS 9.3: %s policy '%s' does not require encryption", [p.platform, p.name])
}

section_9_violations contains msg if {
    # 9.4 Ensure that mobile devices are locked after a period of inactivity
    p := input.intune.device_compliance_policies[_]
    p.platform in {"iOS", "Android"}
    p.password_minutes_of_inactivity_before_lock > 15
    msg := sprintf("CIS 9.4: %s policy '%s' inactivity lock is %d min (should be ≤15)", [p.platform, p.name, p.password_minutes_of_inactivity_before_lock])
}

section_9_violations contains msg if {
    # 9.5 Ensure that mobile devices require complex passwords
    p := input.intune.device_compliance_policies[_]
    p.platform in {"iOS", "Android"}
    p.password_required_type != "alphanumeric"
    msg := sprintf("CIS 9.5: %s policy '%s' password type is '%s' (should be alphanumeric)", [p.platform, p.name, p.password_required_type])
}

section_9_violations contains msg if {
    # 9.6 Ensure that mobile devices wipe data after 10 failed sign-in attempts
    p := input.intune.device_compliance_policies[_]
    p.platform in {"iOS", "Android"}
    p.password_sign_in_failure_count_before_factory_reset > 10
    msg := sprintf("CIS 9.6: %s policy '%s' allows %d failed sign-ins before wipe (should be ≤10)", [p.platform, p.name, p.password_sign_in_failure_count_before_factory_reset])
}
