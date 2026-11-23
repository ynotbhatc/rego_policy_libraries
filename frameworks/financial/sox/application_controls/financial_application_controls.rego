# METADATA
# title: "SOX Application Controls for Financial Systems"
# custom:
#   class: compliance
#   framework: sox
#   source: us-federal
#   domains: [financial, public-company]
#   coverage:
#     checks: 29
#     cited: 0
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: none
#     guard: n/a
#     as_of: v2.4.2
package sox.application_controls

import rego.v1

# SOX Application Controls for Financial Systems
# Controls specific to financial applications and data processing

# Overall Application Controls Compliance
default application_controls_compliant := false

application_controls_compliant if {
	input_controls_effective
	processing_controls_accurate
	output_controls_complete
	data_integrity_maintained
	error_handling_robust
	transaction_logging_complete

	# application_controls_score includes this family, so the verdict must too
	financial_application_controls_effective
}

# Input Controls
default input_controls_effective := false

input_controls_effective if {
	data.sox.application_controls.input_validation.comprehensive == true
	input_validation_comprehensive
	data_entry_controls_adequate
	authorization_controls_proper
	input_completeness_verified
}

default input_validation_comprehensive := false

input_validation_comprehensive if {
	data.sox.input_validation.data_type_validation.enforced == true
	data.sox.input_validation.format_validation.comprehensive == true
	data.sox.input_validation.range_validation.implemented == true
	data.sox.input_validation.business_rule_validation.active == true
	data.sox.input_validation.cross_field_validation.configured == true
}

default data_entry_controls_adequate := false

data_entry_controls_adequate if {
	data.sox.data_entry.mandatory_field_validation.enforced == true
	data.sox.data_entry.duplicate_detection.automated == true
	data.sox.data_entry.real_time_validation.enabled == true
	data.sox.data_entry.error_highlighting.implemented == true
	data.sox.data_entry.confirmation_screens.required == true
}

default authorization_controls_proper := false

authorization_controls_proper if {
	data.sox.authorization.transaction_authorization.required == true
	data.sox.authorization.authorization_limits.enforced == true
	data.sox.authorization.maker_checker.implemented == true
	data.sox.authorization.authorization_matrix.current == true
	data.sox.authorization.override_controls.restricted == true
}

default input_completeness_verified := false

input_completeness_verified if {
	data.sox.input_completeness.batch_totals.verified == true
	data.sox.input_completeness.record_counts.validated == true
	data.sox.input_completeness.hash_totals.checked == true
	data.sox.input_completeness.missing_data.identified == true
}

# Processing Controls
default processing_controls_accurate := false

processing_controls_accurate if {
	data.sox.application_controls.processing_controls.accurate == true
	calculation_controls_reliable
	sequence_controls_maintained
	processing_completeness_ensured
	exception_processing_controlled
}

default calculation_controls_reliable := false

calculation_controls_reliable if {
	data.sox.calculation_controls.arithmetic_accuracy.verified == true
	data.sox.calculation_controls.rounding_rules.consistent == true
	data.sox.calculation_controls.formula_validation.automated == true
	data.sox.calculation_controls.calculation_logs.maintained == true
	data.sox.calculation_controls.recalculation_procedures.documented == true
}

default sequence_controls_maintained := false

sequence_controls_maintained if {
	data.sox.sequence_controls.transaction_sequencing.verified == true
	data.sox.sequence_controls.batch_sequencing.controlled == true
	data.sox.sequence_controls.missing_sequences.detected == true
	data.sox.sequence_controls.duplicate_sequences.prevented == true
}

default processing_completeness_ensured := false

processing_completeness_ensured if {
	data.sox.processing_completeness.all_records_processed.verified == true
	data.sox.processing_completeness.processing_totals.reconciled == true
	data.sox.processing_completeness.incomplete_processing.detected == true
	data.sox.processing_completeness.reprocessing_controls.implemented == true
}

default exception_processing_controlled := false

exception_processing_controlled if {
	data.sox.exception_processing.exception_identification.automated == true
	data.sox.exception_processing.exception_handling.documented == true
	data.sox.exception_processing.exception_resolution.tracked == true
	data.sox.exception_processing.exception_reporting.comprehensive == true
}

# Output Controls
default output_controls_complete := false

output_controls_complete if {
	data.sox.application_controls.output_controls.complete == true
	output_distribution_controlled
	output_completeness_verified
	output_accuracy_validated
	output_authorization_required
}

default output_distribution_controlled := false

output_distribution_controlled if {
	data.sox.output_distribution.authorized_recipients.verified == true
	data.sox.output_distribution.distribution_lists.current == true
	data.sox.output_distribution.sensitive_output.protected == true
	data.sox.output_distribution.transmission_security.enforced == true
}

default output_completeness_verified := false

output_completeness_verified if {
	data.sox.output_completeness.output_totals.reconciled == true
	data.sox.output_completeness.page_numbering.sequential == true
	data.sox.output_completeness.record_counts.verified == true
	data.sox.output_completeness.missing_output.detected == true
}

default output_accuracy_validated := false

output_accuracy_validated if {
	data.sox.output_accuracy.format_validation.automated == true
	data.sox.output_accuracy.content_validation.performed == true
	data.sox.output_accuracy.cross_reference_checks.completed == true
	data.sox.output_accuracy.reasonableness_tests.conducted == true
}

default output_authorization_required := false

output_authorization_required if {
	data.sox.output_authorization.report_approval.required == true
	data.sox.output_authorization.release_authorization.documented == true
	data.sox.output_authorization.approval_matrix.current == true
	data.sox.output_authorization.authorization_logs.maintained == true
}

# Data Integrity Controls
default data_integrity_maintained := false

data_integrity_maintained if {
	data.sox.application_controls.data_integrity.maintained == true
	database_integrity_controls_active
	data_transmission_integrity_protected
	data_storage_integrity_verified
	referential_integrity_enforced
}

default database_integrity_controls_active := false

database_integrity_controls_active if {
	data.sox.database_integrity.constraint_enforcement.active == true
	data.sox.database_integrity.trigger_validation.implemented == true
	data.sox.database_integrity.stored_procedure_controls.enforced == true
	data.sox.database_integrity.transaction_rollback.automatic == true
	data.sox.database_integrity.deadlock_resolution.automated == true
}

default data_transmission_integrity_protected := false

data_transmission_integrity_protected if {
	data.sox.transmission_integrity.checksum_validation.implemented == true
	data.sox.transmission_integrity.encryption_in_transit.enforced == true
	data.sox.transmission_integrity.transmission_logs.comprehensive == true
	data.sox.transmission_integrity.retransmission_controls.automated == true
}

default data_storage_integrity_verified := false

data_storage_integrity_verified if {
	data.sox.storage_integrity.data_corruption_detection.active == true
	data.sox.storage_integrity.backup_integrity_verification.automated == true
	data.sox.storage_integrity.storage_monitoring.continuous == true
	data.sox.storage_integrity.integrity_reporting.regular == true
}

default referential_integrity_enforced := false

referential_integrity_enforced if {
	data.sox.referential_integrity.foreign_key_constraints.enforced == true
	data.sox.referential_integrity.cascade_operations.controlled == true
	data.sox.referential_integrity.orphaned_records.prevented == true
	data.sox.referential_integrity.integrity_checks.automated == true
}

# Error Handling and Logging
default error_handling_robust := false

error_handling_robust if {
	data.sox.application_controls.error_handling.robust == true
	error_detection_comprehensive
	error_reporting_detailed
	error_correction_controlled
	error_prevention_proactive
}

default error_detection_comprehensive := false

error_detection_comprehensive if {
	data.sox.error_detection.real_time_validation.enabled == true
	data.sox.error_detection.batch_validation.comprehensive == true
	data.sox.error_detection.cross_system_validation.implemented == true
	data.sox.error_detection.business_rule_validation.active == true
}

default error_reporting_detailed := false

error_reporting_detailed if {
	data.sox.error_reporting.error_classification.detailed == true
	data.sox.error_reporting.error_severity.assigned == true
	data.sox.error_reporting.error_tracking.comprehensive == true
	data.sox.error_reporting.error_escalation.automated == true
}

default error_correction_controlled := false

error_correction_controlled if {
	data.sox.error_correction.correction_authorization.required == true
	data.sox.error_correction.correction_validation.enforced == true
	data.sox.error_correction.correction_logging.complete == true
	data.sox.error_correction.correction_approval.documented == true
}

default error_prevention_proactive := false

error_prevention_proactive if {
	data.sox.error_prevention.preventive_controls.implemented == true
	data.sox.error_prevention.trend_analysis.performed == true
	data.sox.error_prevention.root_cause_analysis.conducted == true
	data.sox.error_prevention.process_improvement.continuous == true
}

# Transaction Logging and Audit Trails
default transaction_logging_complete := false

transaction_logging_complete if {
	data.sox.application_controls.transaction_logging.complete == true
	audit_trail_comprehensive
	transaction_traceability_maintained
	log_integrity_protected
	log_retention_compliant
}

default audit_trail_comprehensive := false

audit_trail_comprehensive if {
	data.sox.audit_trail.transaction_logging.complete == true
	data.sox.audit_trail.user_activity_logging.comprehensive == true
	data.sox.audit_trail.system_event_logging.detailed == true
	data.sox.audit_trail.data_change_logging.tracked == true
	data.sox.audit_trail.access_logging.monitored == true
}

default transaction_traceability_maintained := false

transaction_traceability_maintained if {
	data.sox.transaction_traceability.unique_transaction_ids.assigned == true
	data.sox.transaction_traceability.transaction_timeline.maintained == true
	data.sox.transaction_traceability.source_documentation.linked == true
	data.sox.transaction_traceability.approval_trail.documented == true
}

default log_integrity_protected := false

log_integrity_protected if {
	data.sox.log_integrity.log_tampering_prevention.implemented == true
	data.sox.log_integrity.log_encryption.enforced == true
	data.sox.log_integrity.log_backup.automated == true
	data.sox.log_integrity.log_verification.periodic == true
}

default log_retention_compliant := false

log_retention_compliant if {
	data.sox.log_retention.retention_period.compliant == true
	data.sox.log_retention.archive_procedures.documented == true
	data.sox.log_retention.retrieval_procedures.tested == true
	data.sox.log_retention.disposal_procedures.secure == true
}

# Financial Application-Specific Controls
default financial_application_controls_effective := false

financial_application_controls_effective if {
	general_ledger_controls_adequate
	accounts_payable_controls_robust
	accounts_receivable_controls_complete
	payroll_controls_comprehensive
	treasury_controls_secure
}

# General Ledger Controls
default general_ledger_controls_adequate := false

general_ledger_controls_adequate if {
	data.sox.general_ledger.journal_entry_controls.enforced == true
	data.sox.general_ledger.chart_of_accounts.maintained == true
	data.sox.general_ledger.period_end_controls.automated == true
	data.sox.general_ledger.reconciliation_controls.comprehensive == true
	data.sox.general_ledger.reporting_controls.accurate == true
}

# Accounts Payable Controls
default accounts_payable_controls_robust := false

accounts_payable_controls_robust if {
	data.sox.accounts_payable.three_way_matching.enforced == true
	data.sox.accounts_payable.vendor_master_controls.maintained == true
	data.sox.accounts_payable.duplicate_payment_prevention.automated == true
	data.sox.accounts_payable.payment_authorization.required == true
	data.sox.accounts_payable.cash_disbursement_controls.secure == true
}

# Accounts Receivable Controls
default accounts_receivable_controls_complete := false

accounts_receivable_controls_complete if {
	data.sox.accounts_receivable.invoice_generation_controls.automated == true
	data.sox.accounts_receivable.credit_limit_controls.enforced == true
	data.sox.accounts_receivable.collection_controls.managed == true
	data.sox.accounts_receivable.bad_debt_controls.documented == true
	data.sox.accounts_receivable.cash_receipt_controls.secure == true
}

# Payroll Controls
default payroll_controls_comprehensive := false

payroll_controls_comprehensive if {
	data.sox.payroll.employee_master_controls.maintained == true
	data.sox.payroll.time_recording_controls.accurate == true
	data.sox.payroll.payroll_calculation_controls.verified == true
	data.sox.payroll.payroll_authorization_controls.enforced == true
	data.sox.payroll.payroll_distribution_controls.secure == true
}

# Treasury Controls
default treasury_controls_secure := false

treasury_controls_secure if {
	data.sox.treasury.cash_management_controls.comprehensive == true
	data.sox.treasury.investment_controls.authorized == true
	data.sox.treasury.bank_reconciliation_controls.automated == true
	data.sox.treasury.foreign_exchange_controls.managed == true
	data.sox.treasury.debt_management_controls.monitored == true
}

# Application Controls Scoring
application_controls_score := score if {
	components := [
		input_controls_score,
		processing_controls_score,
		output_controls_score,
		data_integrity_score,
		error_handling_score,
		transaction_logging_score,
		financial_application_score,
	]
	score := (sum(components) / count(components)) * 100
}

# The family scores are defined with their check lists below.

# Application Controls Risk Assessment
application_controls_risk_level := "LOW" if {
	is_number(application_controls_score)
	application_controls_score >= 90
}

application_controls_risk_level := "MEDIUM" if {
	is_number(application_controls_score)
	application_controls_score >= 75
	application_controls_score < 90
}

application_controls_risk_level := "HIGH" if {
	is_number(application_controls_score)
	application_controls_score >= 60
	application_controls_score < 75
}

application_controls_risk_level := "CRITICAL" if {
	is_number(application_controls_score)
	application_controls_score < 60
}

# Application Controls Effectiveness Summary
application_controls_effectiveness := effectiveness if {
	effectiveness := {
		"overall_score": application_controls_score,
		"risk_level": application_controls_risk_level,
		"control_categories": {
			"input_controls": {
				"score": input_controls_score * 100,
				"effectiveness": _get_effectiveness_rating(input_controls_score),
				"key_findings": get_input_control_findings,
			},
			"processing_controls": {
				"score": processing_controls_score * 100,
				"effectiveness": _get_effectiveness_rating(processing_controls_score),
				"key_findings": get_processing_control_findings,
			},
			"output_controls": {
				"score": output_controls_score * 100,
				"effectiveness": _get_effectiveness_rating(output_controls_score),
				"key_findings": get_output_control_findings,
			},
			"data_integrity": {
				"score": data_integrity_score * 100,
				"effectiveness": _get_effectiveness_rating(data_integrity_score),
				"key_findings": get_data_integrity_findings,
			},
			"error_handling": {
				"score": error_handling_score * 100,
				"effectiveness": _get_effectiveness_rating(error_handling_score),
				"key_findings": get_error_handling_findings,
			},
			"transaction_logging": {
				"score": transaction_logging_score * 100,
				"effectiveness": _get_effectiveness_rating(transaction_logging_score),
				"key_findings": get_transaction_logging_findings,
			},
			"financial_applications": {
				"score": financial_application_score * 100,
				"effectiveness": _get_effectiveness_rating(financial_application_score),
				"key_findings": get_financial_application_findings,
			},
		},
	}
}

# Helper function for effectiveness rating
_get_effectiveness_rating(score) := "EFFECTIVE" if {
	is_number(score)
	score >= 0.9
}

_get_effectiveness_rating(score) := "PARTIALLY_EFFECTIVE" if {
	is_number(score)
	score >= 0.7
	score < 0.9
}

_get_effectiveness_rating(score) := "INEFFECTIVE" if {
	is_number(score)
	score < 0.7
}

# Findings functions
default _input_control_attested := false

_input_control_attested if data.sox.application_controls.input_validation.comprehensive == true

_input_control_checks := [
	{"check": _input_control_attested, "message": "Input controls are not attested as in place (data.sox.application_controls.input_validation.comprehensive)"},
	{"check": input_validation_comprehensive, "message": "Input validation controls need comprehensive implementation"},
	{"check": data_entry_controls_adequate, "message": "Data entry controls require enhancement"},
	{"check": authorization_controls_proper, "message": "Authorization controls need proper implementation"},
	{"check": input_completeness_verified, "message": "Input completeness verification is inadequate"},
]

input_controls_score := _score(_input_control_checks)

get_input_control_findings := _failed_messages(_input_control_checks)

default _processing_control_attested := false

_processing_control_attested if data.sox.application_controls.processing_controls.accurate == true

_processing_control_checks := [
	{"check": _processing_control_attested, "message": "Processing controls are not attested as in place (data.sox.application_controls.processing_controls.accurate)"},
	{"check": calculation_controls_reliable, "message": "Calculation controls reliability needs improvement"},
	{"check": sequence_controls_maintained, "message": "Sequence controls maintenance is inadequate"},
	{"check": processing_completeness_ensured, "message": "Processing completeness assurance is insufficient"},
	{"check": exception_processing_controlled, "message": "Exception processing controls need strengthening"},
]

processing_controls_score := _score(_processing_control_checks)

get_processing_control_findings := _failed_messages(_processing_control_checks)

default _output_control_attested := false

_output_control_attested if data.sox.application_controls.output_controls.complete == true

_output_control_checks := [
	{"check": _output_control_attested, "message": "Output controls are not attested as in place (data.sox.application_controls.output_controls.complete)"},
	{"check": output_distribution_controlled, "message": "Output distribution controls need enhancement"},
	{"check": output_completeness_verified, "message": "Output completeness verification is inadequate"},
	{"check": output_accuracy_validated, "message": "Output accuracy validation needs improvement"},
	{"check": output_authorization_required, "message": "Output authorization requirements are insufficient"},
]

output_controls_score := _score(_output_control_checks)

get_output_control_findings := _failed_messages(_output_control_checks)

default _data_integrity_attested := false

_data_integrity_attested if data.sox.application_controls.data_integrity.maintained == true

_data_integrity_checks := [
	{"check": _data_integrity_attested, "message": "Data integrity controls are not attested as in place (data.sox.application_controls.data_integrity.maintained)"},
	{"check": database_integrity_controls_active, "message": "Database integrity controls need activation"},
	{"check": data_transmission_integrity_protected, "message": "Data transmission integrity protection is inadequate"},
	{"check": data_storage_integrity_verified, "message": "Data storage integrity verification needs improvement"},
	{"check": referential_integrity_enforced, "message": "Referential integrity enforcement is insufficient"},
]

data_integrity_score := _score(_data_integrity_checks)

get_data_integrity_findings := _failed_messages(_data_integrity_checks)

default _error_handling_attested := false

_error_handling_attested if data.sox.application_controls.error_handling.robust == true

_error_handling_checks := [
	{"check": _error_handling_attested, "message": "Error handling controls are not attested as in place (data.sox.application_controls.error_handling.robust)"},
	{"check": error_detection_comprehensive, "message": "Error detection capabilities need comprehensive implementation"},
	{"check": error_reporting_detailed, "message": "Error reporting detail level is inadequate"},
	{"check": error_correction_controlled, "message": "Error correction controls need strengthening"},
	{"check": error_prevention_proactive, "message": "Proactive error prevention measures are insufficient"},
]

error_handling_score := _score(_error_handling_checks)

get_error_handling_findings := _failed_messages(_error_handling_checks)

default _transaction_logging_attested := false

_transaction_logging_attested if data.sox.application_controls.transaction_logging.complete == true

_transaction_logging_checks := [
	{"check": _transaction_logging_attested, "message": "Transaction logging controls are not attested as in place (data.sox.application_controls.transaction_logging.complete)"},
	{"check": audit_trail_comprehensive, "message": "Comprehensive audit trail implementation is needed"},
	{"check": transaction_traceability_maintained, "message": "Transaction traceability maintenance is inadequate"},
	{"check": log_integrity_protected, "message": "Log integrity protection needs enhancement"},
	{"check": log_retention_compliant, "message": "Log retention compliance is insufficient"},
]

transaction_logging_score := _score(_transaction_logging_checks)

get_transaction_logging_findings := _failed_messages(_transaction_logging_checks)

_financial_application_checks := [
	{"check": general_ledger_controls_adequate, "message": "General ledger controls need improvement"},
	{"check": accounts_payable_controls_robust, "message": "Accounts payable controls require strengthening"},
	{"check": accounts_receivable_controls_complete, "message": "Accounts receivable controls need completion"},
	{"check": payroll_controls_comprehensive, "message": "Payroll controls need comprehensive implementation"},
	{"check": treasury_controls_secure, "message": "Treasury controls security needs enhancement"},
]

financial_application_score := _score(_financial_application_checks)

get_financial_application_findings := _failed_messages(_financial_application_checks)

# ---------------------------------------------------------------------------
# One list of checks per family feeds that family's score and its findings, and the lists together feed the
# counts, so passed + failed = total on every input. A check passes only when it is true; a fact that is
# absent, null or not the boolean true fails it.
# ---------------------------------------------------------------------------

_score(checks) := count([check | some check in checks; check.check == true]) / count(checks)

_failed_messages(checks) := [check.message | some check in checks; check.check != true]

_all_checks := [check |
	some family in [
		_input_control_checks,
		_processing_control_checks,
		_output_control_checks,
		_data_integrity_checks,
		_error_handling_checks,
		_transaction_logging_checks,
		_financial_application_checks,
	]
	some check in family
]

control_counts := {
	"total_controls": count(_all_checks),
	"passed_controls": count([check | some check in _all_checks; check.check == true]),
	"failed_controls": count(_failed_messages(_all_checks)),
}
