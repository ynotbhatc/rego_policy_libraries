package iec_62443.fr4_test

import rego.v1

has(prefix, inp) if {
	v := data.iec_62443.fr4.violations with input as inp
	some x in v
	startswith(x, prefix)
}

test_empty_ics_systems_fail_closed if {
	inp := {"ics_systems": [], "target_sl": 4}
	not data.iec_62443.fr4.compliant with input as inp
	has("IEC 62443 SR 4.1 (DC): FAIL-CLOSED", inp)
}

test_fail_closed_message_has_no_format_verb if {
	v := data.iec_62443.fr4.violations with input as {}
	every x in v {
		not contains(x, "%v")
	}
}

test_unflagged_transmission_still_checked_at_sl2 if {
	inp := {"target_sl": 2, "ics_systems": [{"name": "plc1", "data_encrypted_in_transit": false}]}
	has("IEC 62443 SR 4.1 SL2 (DC): ICS system 'plc1' transmits", inp)
}

test_explicit_no_sensitive_transmission_exempt if {
	inp := {"target_sl": 2, "ics_systems": [{"name": "plc1", "sensitive_data_transmitted": false}]}
	not has("IEC 62443 SR 4.1 SL2 (DC): ICS system 'plc1' transmits", inp)
}

test_encrypted_in_transit_ok if {
	inp := {"target_sl": 2, "ics_systems": [{"name": "plc1", "data_encrypted_in_transit": true}]}
	not has("IEC 62443 SR 4.1 SL2 (DC): ICS system 'plc1' transmits", inp)
}

test_missing_target_sl_flagged if has("IEC 62443 SR 4.1 (DC): evidence missing", {"ics_systems": [{"name": "plc1"}]})
