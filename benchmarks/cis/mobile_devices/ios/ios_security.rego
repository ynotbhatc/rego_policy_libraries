# METADATA
# title: "CIS Apple iOS Benchmark"
# custom:
#   class: security
#   framework: cis_mobile_devices
#   source: cis
#   domains: [mobile, ios]
#   coverage:
#     checks: 24
#     cited: 0
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: none
#     guard: n/a
#     as_of: v2.4.2
package cis.mobile.ios

import rego.v1

# Every rule used as a value in the report object needs a neutral default,
# otherwise a single failing check leaves the whole report undefined.
default passcode_enabled := false
default passcode_min_length := false
default passcode_alphanumeric := false
default passcode_complex_characters := false
default passcode_max_age := false
default passcode_history := false
default max_failed_attempts := false
default auto_lock_enabled := false
default encrypted_backups_enabled := false
default icloud_backup_disabled := false
default icloud_keychain_disabled := false
default icloud_drive_disabled := false
default siri_disabled_when_locked := false
default spotlight_suggestions_disabled := false
default notification_previews_disabled_when_locked := false
default app_installation_restricted := false
default untrusted_tls_blocked := false
default safari_secure := false
default airdrop_disabled := false
default device_supervised := false
default mdm_removal_restricted := false
default diagnostic_data_disabled := false
default location_services_configured := false
default advertising_tracking_disabled := false
default ios_device_compliant := false

# CIS Apple iOS Benchmark
# Mobile Device Security Configuration

# CIS 1.1 - a passcode must be set
passcode_enabled if {
    input.device_config.passcode_enabled == true
}

# CIS 1.2 - required value of the minimum passcode length is 6 or greater
passcode_min_length if {
    input.device_config.passcode_min_length >= 6
}

# CIS 1.3 - passcode must be alphanumeric
passcode_alphanumeric if {
    input.device_config.passcode_requires_alphanumeric == true
}

# CIS 1.4 - required value of the minimum number of complex characters is 1 or greater
passcode_complex_characters if {
    input.device_config.passcode_min_complex_chars >= 1
}

# CIS 1.5 - required value of the maximum passcode age is 365 days or less
passcode_max_age if {
    input.device_config.passcode_max_age_days <= 365
}

# CIS 1.6 - required value of passcode history is 5 or greater
passcode_history if {
    input.device_config.passcode_history_count >= 5
}

# CIS 1.7 - required value of the maximum number of failed passcode attempts is 10 or less
max_failed_attempts if {
    input.device_config.max_failed_passcode_attempts <= 10
}

# CIS 1.8 - auto-lock must be turned on and set to 5 minutes or less
auto_lock_enabled if {
    input.device_config.auto_lock_enabled == true
    input.device_config.auto_lock_timeout_minutes <= 5
}

# CIS 2.1 - encrypted backups to iTunes must be turned on
encrypted_backups_enabled if {
    input.device_config.require_encrypted_backup == true
}

# CIS 2.2 - iCloud backup must be turned off
icloud_backup_disabled if {
    input.device_config.allow_icloud_backup == false
}

# CIS 2.3 - iCloud Keychain must be turned off
icloud_keychain_disabled if {
    input.device_config.allow_icloud_keychain == false
}

# CIS 2.4 - iCloud Drive must be turned off
icloud_drive_disabled if {
    input.device_config.allow_icloud_drive == false
}

# CIS 3.1 - Siri must be turned off when device is locked
siri_disabled_when_locked if {
    input.device_config.allow_siri_when_locked == false
}

# CIS 3.2 - Spotlight suggestions must be turned off
spotlight_suggestions_disabled if {
    input.device_config.allow_spotlight_internet_results == false
}

# CIS 3.3 - notification previews must be turned off when device is locked
notification_previews_disabled_when_locked if {
    input.device_config.notification_settings.show_previews_when_locked == false
}

# CIS 4.1 - app installation must be restricted
app_installation_restricted if {
    input.device_config.allow_app_installation == false
}

# CIS 4.2 - untrusted TLS certificates must be blocked
untrusted_tls_blocked if {
    input.device_config.allow_untrusted_tls_prompt == false
}

# CIS 4.3 - Safari must be turned off or configured securely
safari_secure if {
    input.device_config.safari_settings.allow_safari == false
}

safari_secure if {
    input.device_config.safari_settings.allow_safari == true
    input.device_config.safari_settings.block_popups == true
    input.device_config.safari_settings.accept_cookies == "from_visited"
    input.device_config.safari_settings.force_fraud_warning == true
}

# CIS 4.4 - AirDrop must be turned off
airdrop_disabled if {
    input.device_config.allow_airdrop == false
}

# CIS 5.1 - device enrollment must be explicitly configured to require supervision
device_supervised if {
    input.device_config.is_supervised == true
}

# CIS 5.2 - mobile device management profile removal must be restricted
mdm_removal_restricted if {
    input.device_config.allow_profile_removal == false
}

# CIS 5.3 - diagnostic data collection must be turned off
diagnostic_data_disabled if {
    input.device_config.allow_diagnostic_submission == false
}

# CIS 6.1 - location services must be explicitly configured appropriately
location_services_configured if {
    input.device_config.location_services.enabled == true
    input.device_config.location_services.system_services.location_analytics == false
    input.device_config.location_services.system_services.popular_near_me == false
    input.device_config.location_services.system_services.routing_traffic == false
}

# CIS 6.2 - advertising tracking must be turned off
advertising_tracking_disabled if {
    input.device_config.limit_ad_tracking == true
}

# Aggregate iOS device compliance
ios_device_compliant if {
    passcode_enabled
    passcode_min_length
    passcode_alphanumeric
    passcode_complex_characters
    passcode_max_age
    passcode_history
    max_failed_attempts
    auto_lock_enabled
    encrypted_backups_enabled
    icloud_backup_disabled
    icloud_keychain_disabled
    icloud_drive_disabled
    siri_disabled_when_locked
    spotlight_suggestions_disabled
    notification_previews_disabled_when_locked
    app_installation_restricted
    untrusted_tls_blocked
    safari_secure
    airdrop_disabled
    device_supervised
    mdm_removal_restricted
    diagnostic_data_disabled
    location_services_configured
    advertising_tracking_disabled
}

# Detailed iOS device compliance report
ios_device_compliance := {
    "passcode_enabled": passcode_enabled,
    "passcode_min_length": passcode_min_length,
    "passcode_alphanumeric": passcode_alphanumeric,
    "passcode_complex_characters": passcode_complex_characters,
    "passcode_max_age": passcode_max_age,
    "passcode_history": passcode_history,
    "max_failed_attempts": max_failed_attempts,
    "auto_lock_enabled": auto_lock_enabled,
    "encrypted_backups_enabled": encrypted_backups_enabled,
    "icloud_backup_disabled": icloud_backup_disabled,
    "icloud_keychain_disabled": icloud_keychain_disabled,
    "icloud_drive_disabled": icloud_drive_disabled,
    "siri_disabled_when_locked": siri_disabled_when_locked,
    "spotlight_suggestions_disabled": spotlight_suggestions_disabled,
    "notification_previews_disabled_when_locked": notification_previews_disabled_when_locked,
    "app_installation_restricted": app_installation_restricted,
    "untrusted_tls_blocked": untrusted_tls_blocked,
    "safari_secure": safari_secure,
    "airdrop_disabled": airdrop_disabled,
    "device_supervised": device_supervised,
    "mdm_removal_restricted": mdm_removal_restricted,
    "diagnostic_data_disabled": diagnostic_data_disabled,
    "location_services_configured": location_services_configured,
    "advertising_tracking_disabled": advertising_tracking_disabled,
    "overall_compliant": ios_device_compliant
}