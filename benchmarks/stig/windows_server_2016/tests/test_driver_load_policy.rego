package stig.windows_server_2016.driver_load_policy_test

import data.stig.windows_server_2016.registry_cc
import rego.v1

# WN16-CC-000140 (V-224924): 1, 3 and 8 pass, 7 is a finding, an absent value is
# not a finding once registry facts exist, and no registry facts at all is open.
_with(v) := {"registry": {"HKLM\\SYSTEM\\CurrentControlSet\\Policies\\EarlyLaunch": {"DriverLoadPolicy": v}}}

_other := {"registry": {"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System": {"EnableSmartScreen": 1}}}

test_accepted_values_pass if {
	every v in [1, 3, 8] {
		registry_cc.r_wn16_cc_000140 with input as _with(v)
	}
}

test_all_drivers_is_a_finding if {
	not registry_cc.r_wn16_cc_000140 with input as _with(7)
	registry_cc.status_r_wn16_cc_000140 == "Open" with input as _with(7)
}

test_unexpected_value_is_open if {
	not registry_cc.r_wn16_cc_000140 with input as _with(0)
}

test_absent_value_with_registry_facts_passes if {
	registry_cc.r_wn16_cc_000140 with input as _other
}

test_no_registry_facts_is_open if {
	not registry_cc.r_wn16_cc_000140 with input as {}
	not registry_cc.r_wn16_cc_000140 with input as {"registry": {}}
}

# Semantic review 2026-11-13 (group D): generator derivation defects.

test_legal_notice_real_banner_is_not_a_finding if {
	data.stig.windows_server_2016.registry_so.r_wn16_so_000150 == true with input as {"registry": {"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System": {"LegalNoticeText": "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.\n\nBy using this IS (which includes any device attached to this IS), you consent to the following conditions:"}}}
}

test_legal_notice_missing_is_open if {
	data.stig.windows_server_2016.registry_so.r_wn16_so_000150 == false with input as {"registry": {"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System": {}}}
}

test_legal_notice_blank_is_open if {
	data.stig.windows_server_2016.registry_so.r_wn16_so_000150 == false with input as {"registry": {"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System": {"LegalNoticeText": "  "}}}
}

test_legal_caption_org_title_is_not_a_finding if {
	data.stig.windows_server_2016.registry_so.r_wn16_so_000160 == true with input as {"registry": {"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System": {"LegalNoticeCaption": "DoD Notice and Consent Banner"}}}
}

test_legal_caption_missing_is_open if {
	data.stig.windows_server_2016.registry_so.r_wn16_so_000160 == false with input as {"registry": {"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System": {}}}
}

test_uac_admin_prompt_credentials_secure_desktop_passes if {
	data.stig.windows_server_2016.registry_so.r_wn16_so_000480 == true with input as {"registry": {"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System": {"ConsentPromptBehaviorAdmin": 1}}}
}

test_uac_admin_prompt_without_secure_desktop_is_open if {
	data.stig.windows_server_2016.registry_so.r_wn16_so_000480 == false with input as {"registry": {"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System": {"ConsentPromptBehaviorAdmin": 5}}}
}

test_script_block_logging_clean_path_passes if {
	data.stig.windows_server_2016.registry_cc.r_wn16_cc_000490 == true with input as {"registry": {"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging": {"EnableScriptBlockLogging": 1}}}
}
