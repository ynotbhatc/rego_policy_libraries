package nist.sp800_53.identification_authentication_logic_test

# IA-5(1) is one enhancement: one finding naming whichever password protections are missing.

import data.nist.sp800_53.identification_authentication as ia
import rego.v1

_finding(r, id) := [v | some v in r.violations; startswith(v, concat("", ["NIST ", id, ":"]))]

_ia(x) := r if {
	r := ia.compliance_report with input as {"ia_controls": {"authenticator_management": x}}
}

test_ia5_1_both_protections_pass if {
	count(_finding(_ia({"encrypted_in_transit": true, "encrypted_at_rest": true}), "IA-5(1)")) == 0
}

test_ia5_1_storage_gap_fails_once if {
	f := _finding(_ia({"encrypted_in_transit": true, "encrypted_at_rest": false}), "IA-5(1)")
	count(f) == 1
	contains(f[0], "encrypted_at_rest")
	not contains(f[0], "encrypted_in_transit")
}

test_ia5_1_missing_evidence_one_finding if {
	f := _finding(_ia({}), "IA-5(1)")
	count(f) == 1
	contains(f[0], "encrypted_in_transit")
	contains(f[0], "encrypted_at_rest")
}

test_ia_one_finding_per_evaluated_id_on_empty_input if {
	r := ia.compliance_report with input as {}
	r.controls_evaluated == 11
	count(r.violations) == 11
}
