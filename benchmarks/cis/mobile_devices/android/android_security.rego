package cis.mobile.android

import rego.v1

# CIS Google Android Benchmark
# Mobile Device Security Configuration

# CIS 1.1 - Ensure screen lock is enabled
screen_lock_enabled if {
    input.device_config.screen_lock.enabled == true
    input.device_config.screen_lock.type in ["pattern", "pin", "password", "fingerprint", "face"]
}

# CIS 1.2 - Ensure minimum password length is set to 6 or greater
password_min_length if {
    input.device_config.password_policy.min_length >= 6
}

# CIS 1.3 - Ensure password complexity requirements are enabled
password_complexity if {
    input.device_config.password_policy.require_alphabetic == true
    input.device_config.password_policy.require_numeric == true
    input.device_config.password_policy.require_symbols == true
    input.device_config.password_policy.require_uppercase == true
    input.device_config.password_policy.require_lowercase == true
}

# CIS 1.4 - Ensure maximum failed password attempts is set to 10 or less
max_failed_password_attempts if {
    input.device_config.password_policy.max_failed_attempts <= 10
    input.device_config.password_policy.max_failed_attempts > 0
}

# CIS 1.5 - Ensure auto-lock timeout is set to 5 minutes or less
auto_lock_timeout if {
    input.device_config.screen_lock.timeout_minutes <= 5
    input.device_config.screen_lock.timeout_minutes > 0
}

# CIS 1.6 - Ensure password history is enabled
password_history if {
    input.device_config.password_policy.history_length >= 4
}

# CIS 1.7 - Ensure password expiration is set to 90 days or less
password_expiration if {
    input.device_config.password_policy.expiration_days <= 90
    input.device_config.password_policy.expiration_days > 0
}

# CIS 2.1 - Ensure device encryption is enabled
device_encryption_enabled if {
    input.device_config.encryption.device_encrypted == true
    input.device_config.encryption.encryption_algorithm in ["AES-256", "AES-128"]
}

# CIS 2.2 - Ensure SD card encryption is enabled
sd_card_encryption if {
    input.device_config.encryption.sd_card_encrypted == true
}

sd_card_encryption if {
    # If no SD card is present, this control passes
    input.device_config.sd_card_present == false
}

# CIS 2.3 - Ensure backup encryption is enabled
backup_encryption if {
    input.device_config.backup_settings.encryption_enabled == true
}

# CIS 3.1 - Ensure unknown sources installation is disabled
unknown_sources_disabled if {
    input.device_config.app_settings.allow_unknown_sources == false
}

# CIS 3.2 - Ensure app verification is enabled
app_verification_enabled if {
    input.device_config.app_settings.verify_apps == true
}

# CIS 3.3 - Ensure installation of apps from unknown sources is logged
unknown_sources_logging if {
    input.device_config.app_settings.log_unknown_sources == true
}

# CIS 3.4 - Ensure Google Play Protect is enabled
play_protect_enabled if {
    input.device_config.google_services.play_protect_enabled == true
    input.device_config.google_services.play_protect_scan_apps == true
}

# CIS 3.5 - Ensure app permissions are reviewed regularly
app_permissions_reviewed if {
    input.device_config.app_settings.permission_review_enabled == true
}

# CIS 4.1 - Ensure developer options are disabled
developer_options_disabled if {
    input.device_config.developer_settings.enabled == false
}

# CIS 4.2 - Ensure USB debugging is disabled
usb_debugging_disabled if {
    input.device_config.developer_settings.usb_debugging == false
}

# CIS 4.3 - Ensure ADB over network is disabled
adb_over_network_disabled if {
    input.device_config.developer_settings.adb_over_network == false
}

# CIS 4.4 - Ensure mock locations are disabled
mock_locations_disabled if {
    input.device_config.developer_settings.allow_mock_locations == false
}

# CIS 5.1 - Ensure location services are configured appropriately
location_services_configured if {
    input.device_config.location_settings.enabled == true
    input.device_config.location_settings.high_accuracy_mode == false
    input.device_config.location_settings.google_location_history == false
    input.device_config.location_settings.google_location_sharing == false
}

# CIS 5.2 - Ensure Bluetooth is configured securely
bluetooth_secure if {
    input.device_config.bluetooth_settings.enabled == true
    input.device_config.bluetooth_settings.discoverable == false
    input.device_config.bluetooth_settings.auto_pair == false
}

bluetooth_secure if {
    # If Bluetooth is disabled, this is also secure
    input.device_config.bluetooth_settings.enabled == false
}

# CIS 5.3 - Ensure Wi-Fi is configured securely
wifi_secure if {
    input.device_config.wifi_settings.auto_connect_open_networks == false
    input.device_config.wifi_settings.wifi_scanning_always_on == false
    input.device_config.wifi_settings.network_notification == false
}

# CIS 5.4 - Ensure NFC is disabled when not needed
nfc_configured if {
    input.device_config.nfc_settings.enabled == false
}

nfc_configured if {
    # If NFC is enabled, ensure secure usage
    input.device_config.nfc_settings.enabled == true
    input.device_config.nfc_settings.android_beam == false
    input.device_config.nfc_settings.secure_element_access == true
}

# CIS 6.1 - Ensure remote wipe capability is enabled
remote_wipe_enabled if {
    input.device_config.mdm_settings.remote_wipe_enabled == true
}

# CIS 6.2 - Ensure device administrator apps are controlled
device_admin_controlled if {
    every admin in input.device_config.device_administrators {
        admin.authorized == true
    }
}

# CIS 6.3 - Ensure Google account two-factor authentication is enabled
google_account_2fa if {
    input.device_config.google_account.two_factor_enabled == true
}

# CIS 6.4 - Ensure automatic updates are enabled
automatic_updates_enabled if {
    input.device_config.update_settings.auto_download == true
    input.device_config.update_settings.auto_install_security == true
}

# CIS 6.5 - Ensure Google Safe Browsing is enabled
safe_browsing_enabled if {
    input.device_config.browser_settings.safe_browsing == true
}

# CIS 7.1 - Ensure device compliance with organizational policies
organizational_compliance if {
    input.device_config.mdm_settings.enrolled == true
    input.device_config.mdm_settings.policy_compliant == true
}

# CIS 7.2 - Ensure privacy settings are configured appropriately
privacy_settings_configured if {
    input.device_config.privacy_settings.ad_personalization == false
    input.device_config.privacy_settings.usage_reporting == false
    input.device_config.privacy_settings.crash_reporting == false
}

# CIS 7.3 - Ensure biometric authentication is configured securely
biometric_auth_secure if {
    input.device_config.biometric_settings.fallback_enabled == true
    input.device_config.biometric_settings.require_confirmation == true
}

biometric_auth_secure if {
    # If biometric auth is not used, this passes
    input.device_config.biometric_settings.enabled == false
}

# Aggregate Android device compliance
android_device_compliant if {
    screen_lock_enabled
    password_min_length
    password_complexity
    max_failed_password_attempts
    auto_lock_timeout
    password_history
    password_expiration
    device_encryption_enabled
    sd_card_encryption
    backup_encryption
    unknown_sources_disabled
    app_verification_enabled
    unknown_sources_logging
    play_protect_enabled
    app_permissions_reviewed
    developer_options_disabled
    usb_debugging_disabled
    adb_over_network_disabled
    mock_locations_disabled
    location_services_configured
    bluetooth_secure
    wifi_secure
    nfc_configured
    remote_wipe_enabled
    device_admin_controlled
    google_account_2fa
    automatic_updates_enabled
    safe_browsing_enabled
    organizational_compliance
    privacy_settings_configured
    biometric_auth_secure
}

# Detailed Android device compliance report
android_device_compliance := {
    "screen_lock_enabled": screen_lock_enabled,
    "password_min_length": password_min_length,
    "password_complexity": password_complexity,
    "max_failed_password_attempts": max_failed_password_attempts,
    "auto_lock_timeout": auto_lock_timeout,
    "password_history": password_history,
    "password_expiration": password_expiration,
    "device_encryption_enabled": device_encryption_enabled,
    "sd_card_encryption": sd_card_encryption,
    "backup_encryption": backup_encryption,
    "unknown_sources_disabled": unknown_sources_disabled,
    "app_verification_enabled": app_verification_enabled,
    "unknown_sources_logging": unknown_sources_logging,
    "play_protect_enabled": play_protect_enabled,
    "app_permissions_reviewed": app_permissions_reviewed,
    "developer_options_disabled": developer_options_disabled,
    "usb_debugging_disabled": usb_debugging_disabled,
    "adb_over_network_disabled": adb_over_network_disabled,
    "mock_locations_disabled": mock_locations_disabled,
    "location_services_configured": location_services_configured,
    "bluetooth_secure": bluetooth_secure,
    "wifi_secure": wifi_secure,
    "nfc_configured": nfc_configured,
    "remote_wipe_enabled": remote_wipe_enabled,
    "device_admin_controlled": device_admin_controlled,
    "google_account_2fa": google_account_2fa,
    "automatic_updates_enabled": automatic_updates_enabled,
    "safe_browsing_enabled": safe_browsing_enabled,
    "organizational_compliance": organizational_compliance,
    "privacy_settings_configured": privacy_settings_configured,
    "biometric_auth_secure": biometric_auth_secure,
    "overall_compliant": android_device_compliant
}