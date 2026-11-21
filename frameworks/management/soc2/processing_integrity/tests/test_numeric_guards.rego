package soc2.processing_integrity.data_processing_numeric_guards_test

import rego.v1

# null sorts below every number: a null reconciliation frequency passed `<= 24`.
test_string_transaction_completeness_verified_is_false if {
	not data.soc2.processing_integrity.data_processing.transaction_completeness_verified with input as {"data_processing": {"transactions": {"sequence_checking": true, "batch_totals": true, "reconciliation": {"enabled": true, "frequency_hours": "1"}}}}
}

test_null_transaction_completeness_verified_is_false if {
	not data.soc2.processing_integrity.data_processing.transaction_completeness_verified with input as {"data_processing": {"transactions": {"sequence_checking": true, "batch_totals": true, "reconciliation": {"enabled": true, "frequency_hours": null}}}}
}

test_text_transaction_completeness_verified_is_false if {
	not data.soc2.processing_integrity.data_processing.transaction_completeness_verified with input as {"data_processing": {"transactions": {"sequence_checking": true, "batch_totals": true, "reconciliation": {"enabled": true, "frequency_hours": "x"}}}}
}

test_numeric_transaction_completeness_verified_unchanged if {
	data.soc2.processing_integrity.data_processing.transaction_completeness_verified with input as {"data_processing": {"transactions": {"sequence_checking": true, "batch_totals": true, "reconciliation": {"enabled": true, "frequency_hours": 12}}}}
}
