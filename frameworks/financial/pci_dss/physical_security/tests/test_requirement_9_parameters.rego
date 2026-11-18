package pci_dss.physical_security.requirement_9_test

import rego.v1

import data.pci_dss.physical_security.requirement_9 as r9

# Audit 2026-11-17 follow-up (SAQ D rows 9.2.1.1, 9.3.4, 9.5.1.2.1).

_areas(extra) := {"pci": {"physical_access": {"sensitive_areas": object.union(
	{"access_controls_implemented": true, "entry_logs": {"maintained": true}},
	extra,
)}}}

test_9_2_1_1_access_control_mechanisms_instead_of_cameras_pass if {
	r9.physical_access_controls with input as _areas({"access_control_mechanisms": {"monitor_entry_exit": true, "data_retained_days": 90}})
}

test_9_2_1_1_cameras_90_days_pass if {
	r9.physical_access_controls with input as _areas({"cameras": {"installed": true, "footage_retained_days": 90}})
}

test_9_2_1_1_cameras_60_days_fail if {
	not r9.physical_access_controls with input as _areas({"cameras": {"installed": true, "footage_retained_days": 60}})
}

test_9_2_1_1_no_monitoring_fails if not r9.physical_access_controls with input as _areas({})

_poi(actual, defined) := {"pci": {"poi_devices": {
	"in_scope": true, "inventory": {"maintained": true},
	"inspection": {"periodic": true, "frequency_days": actual, "tra_defined_frequency_days": defined},
	"tampering": {"training_for_personnel": true}, "serial_numbers": {"verified": true},
	"substitution": {"procedures_for_detecting": true},
}}}

test_9_5_1_2_1_tra_defined_frequency_passes if r9.poi_device_protection with input as _poi(270, 365)

test_9_5_1_2_1_beyond_tra_frequency_fails if not r9.poi_device_protection with input as _poi(270, 180)

test_9_5_1_2_1_tra_frequency_missing_fails if not r9.poi_device_protection with input as _poi(30, null)
