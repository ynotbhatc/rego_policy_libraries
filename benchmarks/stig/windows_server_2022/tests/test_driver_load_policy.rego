package stig.windows_server_2022.driver_load_policy_test

import data.stig.windows_server_2022.registry_cc
import rego.v1

# WN22-CC-000130 (V-254344): 1, 3 and 8 pass, 7 is a finding, an absent value is
# not a finding once registry facts exist, and no registry facts at all is open.
_with(v) := {"registry": {"HKLM\\SYSTEM\\CurrentControlSet\\Policies\\EarlyLaunch": {"DriverLoadPolicy": v}}}

_other := {"registry": {"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System": {"EnableSmartScreen": 1}}}

test_accepted_values_pass if {
	every v in [1, 3, 8] {
		registry_cc.r_wn22_cc_000130 with input as _with(v)
	}
}

test_all_drivers_is_a_finding if {
	not registry_cc.r_wn22_cc_000130 with input as _with(7)
	registry_cc.status_r_wn22_cc_000130 == "Open" with input as _with(7)
}

test_unexpected_value_is_open if {
	not registry_cc.r_wn22_cc_000130 with input as _with(0)
}

test_absent_value_with_registry_facts_passes if {
	registry_cc.r_wn22_cc_000130 with input as _other
}

test_no_registry_facts_is_open if {
	not registry_cc.r_wn22_cc_000130 with input as {}
	not registry_cc.r_wn22_cc_000130 with input as {"registry": {}}
}
