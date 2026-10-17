package iec_62443.fr3_test

import rego.v1

has(prefix, inp) if {
	v := data.iec_62443.fr3.violations with input as inp
	some x in v
	startswith(x, prefix)
}

test_absent_firmware_check_flagged if has("IEC 62443 SR 3.4 (SI): ICS system 'plc1' does not verify firmware", {"target_sl": 1, "ics_systems": [{"name": "plc1"}]})
test_firmware_check_true_ok if not has("IEC 62443 SR 3.4 (SI): ICS system 'plc1' does not verify firmware", {"target_sl": 1, "ics_systems": [{"name": "plc1", "firmware_integrity_checking": true}]})

test_absent_patch_delay_flagged if has("IEC 62443 SR 3.4 (SI): Critical IACS patches are delayed", {"patch_management": {"process_documented": true}})
test_long_patch_delay_flagged if has("IEC 62443 SR 3.4 (SI): Critical IACS patches are delayed", {"patch_management": {"process_documented": true, "max_patch_delay_days": 200}})
test_ok_patch_delay_not_flagged if not has("IEC 62443 SR 3.4 (SI): Critical IACS patches are delayed", {"patch_management": {"process_documented": true, "max_patch_delay_days": 30}})
