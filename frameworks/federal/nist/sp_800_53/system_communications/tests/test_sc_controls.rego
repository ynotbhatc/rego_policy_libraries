package nist.sp800_53.system_communications_logic_test

# Behaviour tests for the SC checks changed after the 2026-11-17 audit: SC-8 / SC-8(1) (organization
# selection of confidentiality and/or integrity; cryptography is the enhancement), SC-19 (withdrawn),
# SC-20 / SC-21 (one finding each), SC-28 / SC-28(1) (encryption is the enhancement, not the base).

import data.nist.sp800_53.system_communications as sc
import rego.v1

_finding(r, id) := [v | some v in r.violations; startswith(v, concat("", ["NIST ", id, ":"]))]

_sc(x) := r if {
	r := sc.compliance_report with input as {"sc_controls": x}
}

# --- SC-8 / SC-8(1) -----------------------------------------------------------

test_sc8_both_protected_crypto_passes if {
	r := _sc({"transmission_confidentiality": {"encrypted": true}, "transmission_integrity": {"protected": true, "cryptographic": true}})
	count(_finding(r, "SC-8")) == 0
	count(_finding(r, "SC-8(1)")) == 0
}

test_sc8_integrity_only_selection_passes_base if {
	r := _sc({"transmission_protection": {"odp": {"properties": ["integrity"]}}, "transmission_integrity": {"protected": true}})
	count(_finding(r, "SC-8")) == 0
}

test_sc8_selected_property_unprotected_fails if {
	r := _sc({"transmission_protection": {"odp": {"properties": ["confidentiality"]}}, "transmission_integrity": {"protected": true}})
	f := _finding(r, "SC-8")
	count(f) == 1
	contains(f[0], "confidentiality")
}

test_sc8_no_selection_requires_both if {
	r := _sc({"transmission_confidentiality": {"encrypted": true}})
	f := _finding(r, "SC-8")
	count(f) == 1
	contains(f[0], "integrity")
}

test_sc8_missing_evidence_fails if {
	count(_finding(_sc({}), "SC-8")) == 1
}

test_sc8_1_is_crypto_not_integrity_label if {
	# integrity protected by a non-cryptographic mechanism satisfies SC-8, not SC-8(1)
	r := _sc({"transmission_confidentiality": {"encrypted": true}, "transmission_integrity": {"protected": true}})
	count(_finding(r, "SC-8")) == 0
	f := _finding(r, "SC-8(1)")
	count(f) == 1
	contains(f[0], "Cryptographic protection")
	not contains(f[0], "Transmission integrity not protected")
}

test_sc8_1_follows_selection if {
	r := _sc({"transmission_protection": {"odp": {"properties": ["confidentiality"]}}, "transmission_confidentiality": {"encrypted": true}})
	count(_finding(r, "SC-8(1)")) == 0
}

test_sc8_invalid_selection_falls_back_to_both if {
	r := _sc({"transmission_protection": {"odp": {"properties": ["availability"]}}, "transmission_integrity": {"protected": true}})
	count(_finding(r, "SC-8")) == 1
}

# --- SC-19 withdrawn ----------------------------------------------------------

test_sc19_withdrawn_never_a_finding if {
	r := sc.compliance_report with input as {}
	every v in r.violations {
		not contains(v, "SC-19")
	}
	not "SC-19" in sc.evaluated_controls
}

# --- SC-20 / SC-21 ------------------------------------------------------------

test_sc20_sc21_separate_findings_when_missing if {
	r := _sc({})
	count(_finding(r, "SC-20")) == 1
	count(_finding(r, "SC-21")) == 1
}

test_sc20_sc21_pass_with_dnssec if {
	r := _sc({"secure_dns": {"dnssec_enforced": true}})
	count(_finding(r, "SC-20")) == 0
	count(_finding(r, "SC-21")) == 0
}

# --- SC-28 / SC-28(1) ---------------------------------------------------------

test_sc28_non_crypto_protection_passes_base if {
	r := _sc({"protection_of_info_at_rest": {"protected": true, "encrypted": false}})
	count(_finding(r, "SC-28")) == 0
	count(_finding(r, "SC-28(1)")) == 1
}

test_sc28_encryption_satisfies_base_and_enhancement if {
	r := _sc({"protection_of_info_at_rest": {"encrypted": true}})
	count(_finding(r, "SC-28")) == 0
	count(_finding(r, "SC-28(1)")) == 0
}

test_sc28_unprotected_fails if {
	r := _sc({"protection_of_info_at_rest": {"protected": false, "encrypted": false}})
	count(_finding(r, "SC-28")) == 1
}

test_sc28_missing_evidence_fails if {
	f := _finding(_sc({}), "SC-28")
	count(f) == 1
	contains(f[0], "evidence missing")
	not contains(f[0], "via encryption")
}

# --- report contract ---------------------------------------------------------

test_sc_one_finding_per_evaluated_id_on_empty_input if {
	r := sc.compliance_report with input as {}
	r.controls_evaluated == 18
	count(r.violations) == 18
	every id in sc.evaluated_controls {
		count(_finding(r, id)) == 1
	}
}
