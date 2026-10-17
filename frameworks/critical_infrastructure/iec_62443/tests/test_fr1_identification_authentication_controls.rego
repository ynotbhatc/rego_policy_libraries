package iec_62443.fr1_test

import rego.v1

has(prefix, inp) if {
	v := data.iec_62443.fr1.violations with input as inp
	some x in v
	startswith(x, prefix)
}

sys(extra) := {"target_sl": 1, "ics_systems": [object.union({"name": "plc1", "unique_identification": true}, extra)]}

test_absent_password_length_flagged if has("IEC 62443 SR 1.7 (IAC): ICS system 'plc1' has minimum", sys({}))
test_short_password_flagged if has("IEC 62443 SR 1.7 (IAC): ICS system 'plc1' has minimum", sys({"password_min_length": 6}))
test_ok_password_not_flagged if not has("IEC 62443 SR 1.7 (IAC): ICS system 'plc1' has minimum", sys({"password_min_length": 12}))

test_absent_lockout_flagged if has("IEC 62443 SR 1.11 (IAC): ICS system 'plc1' allows", sys({}))
test_high_lockout_flagged if has("IEC 62443 SR 1.11 (IAC): ICS system 'plc1' allows", sys({"account_lockout_threshold": 20}))
test_disabled_lockout_flagged if has("IEC 62443 SR 1.11 (IAC): ICS system 'plc1' allows", sys({"account_lockout_threshold": 0}))
test_ok_lockout_not_flagged if not has("IEC 62443 SR 1.11 (IAC): ICS system 'plc1' allows", sys({"account_lockout_threshold": 5}))

test_absent_feedback_flag_flagged if has("IEC 62443 SR 1.10 (IAC)", sys({}))
test_obscured_feedback_ok if not has("IEC 62443 SR 1.10 (IAC)", sys({"authenticator_feedback_obscured": true}))

test_missing_target_sl_flagged if has("IEC 62443 FR 1 (IAC): evidence missing", {"ics_systems": []})
test_target_sl_present_not_flagged if not has("IEC 62443 FR 1 (IAC): evidence missing", {"target_sl": 2, "ics_systems": []})

# A violation of SR 1.12 must not also count SR 1.1 as failing (substring match).
test_sr_1_12_does_not_fail_sr_1_1 if {
	n := data.iec_62443.fr1.fr1_passing_srs with data.iec_62443.fr1.violations as {"IEC 62443 SR 1.12 (IAC): banner"}
	n == 12
}

test_sr_1_1_still_counted_failing if {
	n := data.iec_62443.fr1.fr1_passing_srs with data.iec_62443.fr1.violations as {"IEC 62443 SR 1.1 RE 1 SL2 (IAC): mfa"}
	n == 12
}
