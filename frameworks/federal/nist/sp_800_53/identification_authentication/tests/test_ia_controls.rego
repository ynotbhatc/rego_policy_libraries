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

# IA-7: applicable standard is the organisation's input; FIPS is not hard-required.
_ia7(x) := r if {
	r := ia.compliance_report with input as {"ia_controls": {"cryptographic_module_auth": x}}
}

test_ia7_applicable_standard_met_passes if {
	count(_finding(_ia7({"odp": {"required_standards": ["FIPS 140-3"]}, "standards_met": ["FIPS 140-3", "SP 800-63B AAL2"]}), "IA-7")) == 0
}

test_ia7_unmet_fails if {
	f := _finding(_ia7({"odp": {"required_standards": ["FIPS 140-3"]}, "standards_met": []}), "IA-7")
	count(f) == 1
	not contains(f[0], "evidence missing")
}

test_ia7_old_fips_boolean_is_missing_evidence if {
	f := _finding(_ia7({"fips_validated": true}), "IA-7")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_ia7_empty_required_list_is_missing_evidence if {
	f := _finding(_ia7({"odp": {"required_standards": []}, "standards_met": ["x"]}), "IA-7")
	count(f) == 1
	contains(f[0], "evidence missing")
}
