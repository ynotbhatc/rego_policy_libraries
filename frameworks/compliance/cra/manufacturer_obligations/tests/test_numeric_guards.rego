package cra.manufacturer_obligations_numeric_guards_test

import rego.v1

test_non_number_support_years_is_evidence_missing if {
	every v in ["1", null, "x"] {
		msgs := data.cra.manufacturer_obligations.violation with input as {"manufacturer": {"support_period": {"declared": true, "years": v}}}
		"CRA Art.13(8): evidence missing — support_period.years is not a number; the declared support period cannot be verified" in msgs
		not data.cra.manufacturer_obligations.compliant with input as {"manufacturer": {"support_period": {"declared": true, "years": v}}}
	}
}

test_numeric_support_years_below_minimum if {
	msgs := data.cra.manufacturer_obligations.violation with input as {"manufacturer": {"support_period": {"declared": true, "years": 3}}}
	"CRA Art.13(8): Declared support period (3 years) is below the 5-year minimum" in msgs
	not "CRA Art.13(8): evidence missing — support_period.years is not a number; the declared support period cannot be verified" in msgs
}

test_numeric_support_years_at_minimum if {
	msgs := data.cra.manufacturer_obligations.violation with input as {"manufacturer": {"support_period": {"declared": true, "years": 5}}}
	every m in msgs {
		not startswith(m, "CRA Art.13(8)")
	}
}
