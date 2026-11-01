# METADATA
# title: "CIS Microsoft Azure Foundations Benchmark"
# custom:
#   class: security
#   framework: cis_cloud
#   source: cis
#   domains: [cloud, azure]
#   coverage:
#     checks: 24
#     cited: 0
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: none
#     guard: n/a
#     as_of: v2.4.2
package cis.azure.iam

import rego.v1

# CIS Microsoft Azure Foundations Benchmark
# Section 1: Identity and Access Management

mfa_ok(user) if user.mfa_enabled == true

# CIS 1.1 - multi-factor authentication must be turned on for all privileged users
default mfa_enabled_privileged_users := false

mfa_enabled_privileged_users if {
    is_array(input.privileged_users)
    count([user | some user in input.privileged_users; not mfa_ok(user)]) == 0
}

# CIS 1.2 - multi-factor authentication must be turned on for all non-privileged users
default mfa_enabled_non_privileged_users := false

mfa_enabled_non_privileged_users if {
    is_array(input.non_privileged_users)
    count([user | some user in input.non_privileged_users; not mfa_ok(user)]) == 0
}

# CIS 1.3 - there must be no guest users
default no_guest_users := false

no_guest_users if {
    count(input.guest_users) == 0
}

# CIS 1.4 - required value of 'Allow users to remember multi-factor authentication on devices they trust' is 'Disabled'
default mfa_remember_disabled := false

mfa_remember_disabled if {
    input.mfa_settings.allow_users_to_remember_mfa == false
}

# CIS 1.5 - required value of 'Number of methods required to reset' is '2'
default password_reset_methods := false

password_reset_methods if {
    input.password_reset_policy.methods_required >= 2
}

# CIS 1.6 - 'Number of days before users are asked to re-confirm their authentication information' must not be '0'
default reconfirm_auth_info_days := false

reconfirm_auth_info_days if {
    input.password_reset_policy.reconfirm_days > 0
    input.password_reset_policy.reconfirm_days <= 180
}

# CIS 1.7 - required value of 'Notify users on password resets?' is 'Yes'
default notify_password_resets := false

notify_password_resets if {
    input.password_reset_policy.notify_users == true
}

# CIS 1.8 - required value of 'Notify all admins when other admins reset their password?' is 'Yes'
default notify_admins_password_resets := false

notify_admins_password_resets if {
    input.password_reset_policy.notify_all_admins == true
}

# CIS 1.9 - required value of 'Users can consent to apps accessing company data on their behalf' is 'No'
default user_consent_disabled := false

user_consent_disabled if {
    input.consent_settings.users_can_consent_apps == false
}

# CIS 1.10 - required value of 'Users can add gallery apps to their Access Panel' is 'No'
default users_add_gallery_apps_disabled := false

users_add_gallery_apps_disabled if {
    input.consent_settings.users_can_add_gallery_apps == false
}

# CIS 1.11 - required value of 'Users can register applications' is 'No'
default users_register_apps_disabled := false

users_register_apps_disabled if {
    input.app_registration_settings.users_can_register_apps == false
}

# CIS 1.12 - required value of 'Guest users permissions are limited' is 'Yes'
default guest_permissions_limited := false

guest_permissions_limited if {
    input.guest_settings.permissions_limited == true
}

# CIS 1.13 - required value of 'Members can invite' is 'No'
default members_cannot_invite := false

members_cannot_invite if {
    input.guest_settings.members_can_invite == false
}

# CIS 1.14 - required value of 'Guests can invite' is 'No'
default guests_cannot_invite := false

guests_cannot_invite if {
    input.guest_settings.guests_can_invite == false
}

# CIS 1.15 - required value of 'Restrict access to Azure AD administration portal' is 'Yes'
default restrict_admin_portal_access := false

restrict_admin_portal_access if {
    input.admin_settings.restrict_admin_portal_access == true
}

# CIS 1.16 - required value of 'Users can create security groups' is 'No'
default users_cannot_create_security_groups := false

users_cannot_create_security_groups if {
    input.group_settings.users_can_create_security_groups == false
}

# CIS 1.17 - required value of 'Users can create Office 365 groups' is 'No'
default users_cannot_create_office365_groups := false

users_cannot_create_office365_groups if {
    input.group_settings.users_can_create_office365_groups == false
}

# CIS 1.18 - required value of 'Require Multi-Factor Auth to join devices' is 'Yes'
default mfa_required_join_devices := false

mfa_required_join_devices if {
    input.device_settings.require_mfa_to_join == true
}

# CIS 1.19 - required value of 'Maximum number of devices per user' is '50' or lower
default max_devices_per_user := false

max_devices_per_user if {
    input.device_settings.max_devices_per_user <= 50
}

# CIS 1.20 - required value of 'Guests can access to properties and memberships of objects' is 'No'
default guests_limited_object_access := false

guests_limited_object_access if {
    input.guest_settings.can_access_properties_memberships == false
}

# CIS 1.21 - required value of 'Users can create tenants' is 'No'
default users_cannot_create_tenants := false

users_cannot_create_tenants if {
    input.tenant_settings.users_can_create_tenants == false
}

# CIS 1.22 - required value of 'Subscription leaving AAD Tenant' is 'Permit no one'
default subscription_leaving_restricted := false

subscription_leaving_restricted if {
    input.subscription_settings.leaving_tenant_policy == "permit_no_one"
}

# CIS 1.23 - no custom subscription owner roles must be created
default no_custom_subscription_owner_roles := false

no_custom_subscription_owner_roles if {
    count([role | some role in input.custom_roles; has_dangerous_permissions(role)]) == 0
}

# Custom role validation helper. permissions may be a string or an array of strings.
role_permissions(role) := [role.permissions] if is_string(role.permissions)

role_permissions(role) := role.permissions if is_array(role.permissions)

has_dangerous_permissions(role) if {
    some perm in role_permissions(role)
    is_dangerous(perm)
}

is_dangerous(perm) if perm == "*"

is_dangerous(perm) if contains(perm, "*/write")

# CIS 1.24 - required value of 'Subscription owners should not have elevated access to all subscriptions and management groups' is 'false'
default subscription_owners_not_elevated := false

subscription_owners_not_elevated if {
    input.subscription_settings.owners_elevated_access == false
}

# Aggregate Azure IAM compliance
default azure_iam_compliant := false

azure_iam_compliant if {
    mfa_enabled_privileged_users
    mfa_enabled_non_privileged_users
    no_guest_users
    mfa_remember_disabled
    password_reset_methods
    reconfirm_auth_info_days
    notify_password_resets
    notify_admins_password_resets
    user_consent_disabled
    users_add_gallery_apps_disabled
    users_register_apps_disabled
    guest_permissions_limited
    members_cannot_invite
    guests_cannot_invite
    restrict_admin_portal_access
    users_cannot_create_security_groups
    users_cannot_create_office365_groups
    mfa_required_join_devices
    max_devices_per_user
    guests_limited_object_access
    users_cannot_create_tenants
    subscription_leaving_restricted
    no_custom_subscription_owner_roles
    subscription_owners_not_elevated
}

# Detailed Azure IAM compliance report
azure_iam_compliance := {
    "mfa_enabled_privileged_users": mfa_enabled_privileged_users,
    "mfa_enabled_non_privileged_users": mfa_enabled_non_privileged_users,
    "no_guest_users": no_guest_users,
    "mfa_remember_disabled": mfa_remember_disabled,
    "password_reset_methods": password_reset_methods,
    "reconfirm_auth_info_days": reconfirm_auth_info_days,
    "notify_password_resets": notify_password_resets,
    "notify_admins_password_resets": notify_admins_password_resets,
    "user_consent_disabled": user_consent_disabled,
    "users_add_gallery_apps_disabled": users_add_gallery_apps_disabled,
    "users_register_apps_disabled": users_register_apps_disabled,
    "guest_permissions_limited": guest_permissions_limited,
    "members_cannot_invite": members_cannot_invite,
    "guests_cannot_invite": guests_cannot_invite,
    "restrict_admin_portal_access": restrict_admin_portal_access,
    "users_cannot_create_security_groups": users_cannot_create_security_groups,
    "users_cannot_create_office365_groups": users_cannot_create_office365_groups,
    "mfa_required_join_devices": mfa_required_join_devices,
    "max_devices_per_user": max_devices_per_user,
    "guests_limited_object_access": guests_limited_object_access,
    "users_cannot_create_tenants": users_cannot_create_tenants,
    "subscription_leaving_restricted": subscription_leaving_restricted,
    "no_custom_subscription_owner_roles": no_custom_subscription_owner_roles,
    "subscription_owners_not_elevated": subscription_owners_not_elevated,
    "overall_compliant": azure_iam_compliant
}