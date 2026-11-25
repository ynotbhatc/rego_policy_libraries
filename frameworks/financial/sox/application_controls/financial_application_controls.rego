# METADATA
# title: "SOX Application Controls for Financial Systems"
# custom:
#   class: compliance
#   framework: sox
#   source: us-federal
#   domains: [financial, public-company]
#   coverage:
#     checks: 35
#     cited: 0
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: none
#     guard: n/a
#     as_of: v2.5.0
package sox.application_controls

import rego.v1

# SOX Application Controls for Financial Systems
# Controls specific to financial applications and data processing
#
# Facts are read from input.sox.<...>, the input document the caller posts (the fact paths are listed in _facts).
# When the input has no "sox" key, facts loaded as data.sox.<...> are read instead (the older way to feed this
# module). The two are never merged and input.sox always wins; control_counts states which one was read in
# evidence_source ("input", "data" or "none") and sets data_sox_ignored when both were present. Only the boolean
# true passes a fact; evidence_problems names every fact that is absent, null or not a boolean.

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
	_input_control_attested
	input_validation_comprehensive
	data_entry_controls_adequate
	authorization_controls_proper
	input_completeness_verified
}

default input_validation_comprehensive := false

input_validation_comprehensive if _all_true(_facts.input_validation_comprehensive)

default data_entry_controls_adequate := false

data_entry_controls_adequate if _all_true(_facts.data_entry_controls_adequate)

default authorization_controls_proper := false

authorization_controls_proper if _all_true(_facts.authorization_controls_proper)

default input_completeness_verified := false

input_completeness_verified if _all_true(_facts.input_completeness_verified)

# Processing Controls
default processing_controls_accurate := false

processing_controls_accurate if {
	_processing_control_attested
	calculation_controls_reliable
	sequence_controls_maintained
	processing_completeness_ensured
	exception_processing_controlled
}

default calculation_controls_reliable := false

calculation_controls_reliable if _all_true(_facts.calculation_controls_reliable)

default sequence_controls_maintained := false

sequence_controls_maintained if _all_true(_facts.sequence_controls_maintained)

default processing_completeness_ensured := false

processing_completeness_ensured if _all_true(_facts.processing_completeness_ensured)

default exception_processing_controlled := false

exception_processing_controlled if _all_true(_facts.exception_processing_controlled)

# Output Controls
default output_controls_complete := false

output_controls_complete if {
	_output_control_attested
	output_distribution_controlled
	output_completeness_verified
	output_accuracy_validated
	output_authorization_required
}

default output_distribution_controlled := false

output_distribution_controlled if _all_true(_facts.output_distribution_controlled)

default output_completeness_verified := false

output_completeness_verified if _all_true(_facts.output_completeness_verified)

default output_accuracy_validated := false

output_accuracy_validated if _all_true(_facts.output_accuracy_validated)

default output_authorization_required := false

output_authorization_required if _all_true(_facts.output_authorization_required)

# Data Integrity Controls
default data_integrity_maintained := false

data_integrity_maintained if {
	_data_integrity_attested
	database_integrity_controls_active
	data_transmission_integrity_protected
	data_storage_integrity_verified
	referential_integrity_enforced
}

default database_integrity_controls_active := false

database_integrity_controls_active if _all_true(_facts.database_integrity_controls_active)

default data_transmission_integrity_protected := false

data_transmission_integrity_protected if _all_true(_facts.data_transmission_integrity_protected)

default data_storage_integrity_verified := false

data_storage_integrity_verified if _all_true(_facts.data_storage_integrity_verified)

default referential_integrity_enforced := false

referential_integrity_enforced if _all_true(_facts.referential_integrity_enforced)

# Error Handling and Logging
default error_handling_robust := false

error_handling_robust if {
	_error_handling_attested
	error_detection_comprehensive
	error_reporting_detailed
	error_correction_controlled
	error_prevention_proactive
}

default error_detection_comprehensive := false

error_detection_comprehensive if _all_true(_facts.error_detection_comprehensive)

default error_reporting_detailed := false

error_reporting_detailed if _all_true(_facts.error_reporting_detailed)

default error_correction_controlled := false

error_correction_controlled if _all_true(_facts.error_correction_controlled)

default error_prevention_proactive := false

error_prevention_proactive if _all_true(_facts.error_prevention_proactive)

# Transaction Logging and Audit Trails
default transaction_logging_complete := false

transaction_logging_complete if {
	_transaction_logging_attested
	audit_trail_comprehensive
	transaction_traceability_maintained
	log_integrity_protected
	log_retention_compliant
}

default audit_trail_comprehensive := false

audit_trail_comprehensive if _all_true(_facts.audit_trail_comprehensive)

default transaction_traceability_maintained := false

transaction_traceability_maintained if _all_true(_facts.transaction_traceability_maintained)

default log_integrity_protected := false

log_integrity_protected if _all_true(_facts.log_integrity_protected)

default log_retention_compliant := false

log_retention_compliant if _all_true(_facts.log_retention_compliant)

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

general_ledger_controls_adequate if _all_true(_facts.general_ledger_controls_adequate)

# Accounts Payable Controls
default accounts_payable_controls_robust := false

accounts_payable_controls_robust if _all_true(_facts.accounts_payable_controls_robust)

# Accounts Receivable Controls
default accounts_receivable_controls_complete := false

accounts_receivable_controls_complete if _all_true(_facts.accounts_receivable_controls_complete)

# Payroll Controls
default payroll_controls_comprehensive := false

payroll_controls_comprehensive if _all_true(_facts.payroll_controls_comprehensive)

# Treasury Controls
default treasury_controls_secure := false

treasury_controls_secure if _all_true(_facts.treasury_controls_secure)

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
				"evidence_problems": _evidence_problems(_input_control_checks),
			},
			"processing_controls": {
				"score": processing_controls_score * 100,
				"effectiveness": _get_effectiveness_rating(processing_controls_score),
				"key_findings": get_processing_control_findings,
				"evidence_problems": _evidence_problems(_processing_control_checks),
			},
			"output_controls": {
				"score": output_controls_score * 100,
				"effectiveness": _get_effectiveness_rating(output_controls_score),
				"key_findings": get_output_control_findings,
				"evidence_problems": _evidence_problems(_output_control_checks),
			},
			"data_integrity": {
				"score": data_integrity_score * 100,
				"effectiveness": _get_effectiveness_rating(data_integrity_score),
				"key_findings": get_data_integrity_findings,
				"evidence_problems": _evidence_problems(_data_integrity_checks),
			},
			"error_handling": {
				"score": error_handling_score * 100,
				"effectiveness": _get_effectiveness_rating(error_handling_score),
				"key_findings": get_error_handling_findings,
				"evidence_problems": _evidence_problems(_error_handling_checks),
			},
			"transaction_logging": {
				"score": transaction_logging_score * 100,
				"effectiveness": _get_effectiveness_rating(transaction_logging_score),
				"key_findings": get_transaction_logging_findings,
				"evidence_problems": _evidence_problems(_transaction_logging_checks),
			},
			"financial_applications": {
				"score": financial_application_score * 100,
				"effectiveness": _get_effectiveness_rating(financial_application_score),
				"key_findings": get_financial_application_findings,
				"evidence_problems": _evidence_problems(_financial_application_checks),
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

_input_control_attested if _all_true(_facts._input_control_attested)

_input_control_checks := [
	{"check": _input_control_attested, "rule": "_input_control_attested", "message": "Input controls are not attested as in place (sox.application_controls.input_validation.comprehensive)"},
	{"check": input_validation_comprehensive, "rule": "input_validation_comprehensive", "message": "Input validation controls need comprehensive implementation"},
	{"check": data_entry_controls_adequate, "rule": "data_entry_controls_adequate", "message": "Data entry controls require enhancement"},
	{"check": authorization_controls_proper, "rule": "authorization_controls_proper", "message": "Authorization controls need proper implementation"},
	{"check": input_completeness_verified, "rule": "input_completeness_verified", "message": "Input completeness verification is inadequate"},
]

input_controls_score := _score(_input_control_checks)

get_input_control_findings := _failed_messages(_input_control_checks)

default _processing_control_attested := false

_processing_control_attested if _all_true(_facts._processing_control_attested)

_processing_control_checks := [
	{"check": _processing_control_attested, "rule": "_processing_control_attested", "message": "Processing controls are not attested as in place (sox.application_controls.processing_controls.accurate)"},
	{"check": calculation_controls_reliable, "rule": "calculation_controls_reliable", "message": "Calculation controls reliability needs improvement"},
	{"check": sequence_controls_maintained, "rule": "sequence_controls_maintained", "message": "Sequence controls maintenance is inadequate"},
	{"check": processing_completeness_ensured, "rule": "processing_completeness_ensured", "message": "Processing completeness assurance is insufficient"},
	{"check": exception_processing_controlled, "rule": "exception_processing_controlled", "message": "Exception processing controls need strengthening"},
]

processing_controls_score := _score(_processing_control_checks)

get_processing_control_findings := _failed_messages(_processing_control_checks)

default _output_control_attested := false

_output_control_attested if _all_true(_facts._output_control_attested)

_output_control_checks := [
	{"check": _output_control_attested, "rule": "_output_control_attested", "message": "Output controls are not attested as in place (sox.application_controls.output_controls.complete)"},
	{"check": output_distribution_controlled, "rule": "output_distribution_controlled", "message": "Output distribution controls need enhancement"},
	{"check": output_completeness_verified, "rule": "output_completeness_verified", "message": "Output completeness verification is inadequate"},
	{"check": output_accuracy_validated, "rule": "output_accuracy_validated", "message": "Output accuracy validation needs improvement"},
	{"check": output_authorization_required, "rule": "output_authorization_required", "message": "Output authorization requirements are insufficient"},
]

output_controls_score := _score(_output_control_checks)

get_output_control_findings := _failed_messages(_output_control_checks)

default _data_integrity_attested := false

_data_integrity_attested if _all_true(_facts._data_integrity_attested)

_data_integrity_checks := [
	{"check": _data_integrity_attested, "rule": "_data_integrity_attested", "message": "Data integrity controls are not attested as in place (sox.application_controls.data_integrity.maintained)"},
	{"check": database_integrity_controls_active, "rule": "database_integrity_controls_active", "message": "Database integrity controls need activation"},
	{"check": data_transmission_integrity_protected, "rule": "data_transmission_integrity_protected", "message": "Data transmission integrity protection is inadequate"},
	{"check": data_storage_integrity_verified, "rule": "data_storage_integrity_verified", "message": "Data storage integrity verification needs improvement"},
	{"check": referential_integrity_enforced, "rule": "referential_integrity_enforced", "message": "Referential integrity enforcement is insufficient"},
]

data_integrity_score := _score(_data_integrity_checks)

get_data_integrity_findings := _failed_messages(_data_integrity_checks)

default _error_handling_attested := false

_error_handling_attested if _all_true(_facts._error_handling_attested)

_error_handling_checks := [
	{"check": _error_handling_attested, "rule": "_error_handling_attested", "message": "Error handling controls are not attested as in place (sox.application_controls.error_handling.robust)"},
	{"check": error_detection_comprehensive, "rule": "error_detection_comprehensive", "message": "Error detection capabilities need comprehensive implementation"},
	{"check": error_reporting_detailed, "rule": "error_reporting_detailed", "message": "Error reporting detail level is inadequate"},
	{"check": error_correction_controlled, "rule": "error_correction_controlled", "message": "Error correction controls need strengthening"},
	{"check": error_prevention_proactive, "rule": "error_prevention_proactive", "message": "Proactive error prevention measures are insufficient"},
]

error_handling_score := _score(_error_handling_checks)

get_error_handling_findings := _failed_messages(_error_handling_checks)

default _transaction_logging_attested := false

_transaction_logging_attested if _all_true(_facts._transaction_logging_attested)

_transaction_logging_checks := [
	{"check": _transaction_logging_attested, "rule": "_transaction_logging_attested", "message": "Transaction logging controls are not attested as in place (sox.application_controls.transaction_logging.complete)"},
	{"check": audit_trail_comprehensive, "rule": "audit_trail_comprehensive", "message": "Comprehensive audit trail implementation is needed"},
	{"check": transaction_traceability_maintained, "rule": "transaction_traceability_maintained", "message": "Transaction traceability maintenance is inadequate"},
	{"check": log_integrity_protected, "rule": "log_integrity_protected", "message": "Log integrity protection needs enhancement"},
	{"check": log_retention_compliant, "rule": "log_retention_compliant", "message": "Log retention compliance is insufficient"},
]

transaction_logging_score := _score(_transaction_logging_checks)

get_transaction_logging_findings := _failed_messages(_transaction_logging_checks)

_financial_application_checks := [
	{"check": general_ledger_controls_adequate, "rule": "general_ledger_controls_adequate", "message": "General ledger controls need improvement"},
	{"check": accounts_payable_controls_robust, "rule": "accounts_payable_controls_robust", "message": "Accounts payable controls require strengthening"},
	{"check": accounts_receivable_controls_complete, "rule": "accounts_receivable_controls_complete", "message": "Accounts receivable controls need completion"},
	{"check": payroll_controls_comprehensive, "rule": "payroll_controls_comprehensive", "message": "Payroll controls need comprehensive implementation"},
	{"check": treasury_controls_secure, "rule": "treasury_controls_secure", "message": "Treasury controls security needs enhancement"},
]

financial_application_score := _score(_financial_application_checks)

get_financial_application_findings := _failed_messages(_financial_application_checks)

# ---------------------------------------------------------------------------
# One list of checks per family feeds that family's score and its findings, and the lists together feed the
# counts, so passed + failed = total on every input. A check passes only when every fact it names in _facts is
# the boolean true; a fact that is absent, null or not a boolean fails it and is named in evidence_problems.
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
	"evidence_source": evidence_source,
	"data_sox_ignored": data_sox_ignored,
}

# The facts each check requires (dotted paths below sox). The rules above and the evidence problems read this
# one list.
_facts := {
	"input_validation_comprehensive": [
		"input_validation.data_type_validation.enforced",
		"input_validation.format_validation.comprehensive",
		"input_validation.range_validation.implemented",
		"input_validation.business_rule_validation.active",
		"input_validation.cross_field_validation.configured",
	],
	"data_entry_controls_adequate": [
		"data_entry.mandatory_field_validation.enforced",
		"data_entry.duplicate_detection.automated",
		"data_entry.real_time_validation.enabled",
		"data_entry.error_highlighting.implemented",
		"data_entry.confirmation_screens.required",
	],
	"authorization_controls_proper": [
		"authorization.transaction_authorization.required",
		"authorization.authorization_limits.enforced",
		"authorization.maker_checker.implemented",
		"authorization.authorization_matrix.current",
		"authorization.override_controls.restricted",
	],
	"input_completeness_verified": [
		"input_completeness.batch_totals.verified",
		"input_completeness.record_counts.validated",
		"input_completeness.hash_totals.checked",
		"input_completeness.missing_data.identified",
	],
	"calculation_controls_reliable": [
		"calculation_controls.arithmetic_accuracy.verified",
		"calculation_controls.rounding_rules.consistent",
		"calculation_controls.formula_validation.automated",
		"calculation_controls.calculation_logs.maintained",
		"calculation_controls.recalculation_procedures.documented",
	],
	"sequence_controls_maintained": [
		"sequence_controls.transaction_sequencing.verified",
		"sequence_controls.batch_sequencing.controlled",
		"sequence_controls.missing_sequences.detected",
		"sequence_controls.duplicate_sequences.prevented",
	],
	"processing_completeness_ensured": [
		"processing_completeness.all_records_processed.verified",
		"processing_completeness.processing_totals.reconciled",
		"processing_completeness.incomplete_processing.detected",
		"processing_completeness.reprocessing_controls.implemented",
	],
	"exception_processing_controlled": [
		"exception_processing.exception_identification.automated",
		"exception_processing.exception_handling.documented",
		"exception_processing.exception_resolution.tracked",
		"exception_processing.exception_reporting.comprehensive",
	],
	"output_distribution_controlled": [
		"output_distribution.authorized_recipients.verified",
		"output_distribution.distribution_lists.current",
		"output_distribution.sensitive_output.protected",
		"output_distribution.transmission_security.enforced",
	],
	"output_completeness_verified": [
		"output_completeness.output_totals.reconciled",
		"output_completeness.page_numbering.sequential",
		"output_completeness.record_counts.verified",
		"output_completeness.missing_output.detected",
	],
	"output_accuracy_validated": [
		"output_accuracy.format_validation.automated",
		"output_accuracy.content_validation.performed",
		"output_accuracy.cross_reference_checks.completed",
		"output_accuracy.reasonableness_tests.conducted",
	],
	"output_authorization_required": [
		"output_authorization.report_approval.required",
		"output_authorization.release_authorization.documented",
		"output_authorization.approval_matrix.current",
		"output_authorization.authorization_logs.maintained",
	],
	"database_integrity_controls_active": [
		"database_integrity.constraint_enforcement.active",
		"database_integrity.trigger_validation.implemented",
		"database_integrity.stored_procedure_controls.enforced",
		"database_integrity.transaction_rollback.automatic",
		"database_integrity.deadlock_resolution.automated",
	],
	"data_transmission_integrity_protected": [
		"transmission_integrity.checksum_validation.implemented",
		"transmission_integrity.encryption_in_transit.enforced",
		"transmission_integrity.transmission_logs.comprehensive",
		"transmission_integrity.retransmission_controls.automated",
	],
	"data_storage_integrity_verified": [
		"storage_integrity.data_corruption_detection.active",
		"storage_integrity.backup_integrity_verification.automated",
		"storage_integrity.storage_monitoring.continuous",
		"storage_integrity.integrity_reporting.regular",
	],
	"referential_integrity_enforced": [
		"referential_integrity.foreign_key_constraints.enforced",
		"referential_integrity.cascade_operations.controlled",
		"referential_integrity.orphaned_records.prevented",
		"referential_integrity.integrity_checks.automated",
	],
	"error_detection_comprehensive": [
		"error_detection.real_time_validation.enabled",
		"error_detection.batch_validation.comprehensive",
		"error_detection.cross_system_validation.implemented",
		"error_detection.business_rule_validation.active",
	],
	"error_reporting_detailed": [
		"error_reporting.error_classification.detailed",
		"error_reporting.error_severity.assigned",
		"error_reporting.error_tracking.comprehensive",
		"error_reporting.error_escalation.automated",
	],
	"error_correction_controlled": [
		"error_correction.correction_authorization.required",
		"error_correction.correction_validation.enforced",
		"error_correction.correction_logging.complete",
		"error_correction.correction_approval.documented",
	],
	"error_prevention_proactive": [
		"error_prevention.preventive_controls.implemented",
		"error_prevention.trend_analysis.performed",
		"error_prevention.root_cause_analysis.conducted",
		"error_prevention.process_improvement.continuous",
	],
	"audit_trail_comprehensive": [
		"audit_trail.transaction_logging.complete",
		"audit_trail.user_activity_logging.comprehensive",
		"audit_trail.system_event_logging.detailed",
		"audit_trail.data_change_logging.tracked",
		"audit_trail.access_logging.monitored",
	],
	"transaction_traceability_maintained": [
		"transaction_traceability.unique_transaction_ids.assigned",
		"transaction_traceability.transaction_timeline.maintained",
		"transaction_traceability.source_documentation.linked",
		"transaction_traceability.approval_trail.documented",
	],
	"log_integrity_protected": [
		"log_integrity.log_tampering_prevention.implemented",
		"log_integrity.log_encryption.enforced",
		"log_integrity.log_backup.automated",
		"log_integrity.log_verification.periodic",
	],
	"log_retention_compliant": [
		"log_retention.retention_period.compliant",
		"log_retention.archive_procedures.documented",
		"log_retention.retrieval_procedures.tested",
		"log_retention.disposal_procedures.secure",
	],
	"general_ledger_controls_adequate": [
		"general_ledger.journal_entry_controls.enforced",
		"general_ledger.chart_of_accounts.maintained",
		"general_ledger.period_end_controls.automated",
		"general_ledger.reconciliation_controls.comprehensive",
		"general_ledger.reporting_controls.accurate",
	],
	"accounts_payable_controls_robust": [
		"accounts_payable.three_way_matching.enforced",
		"accounts_payable.vendor_master_controls.maintained",
		"accounts_payable.duplicate_payment_prevention.automated",
		"accounts_payable.payment_authorization.required",
		"accounts_payable.cash_disbursement_controls.secure",
	],
	"accounts_receivable_controls_complete": [
		"accounts_receivable.invoice_generation_controls.automated",
		"accounts_receivable.credit_limit_controls.enforced",
		"accounts_receivable.collection_controls.managed",
		"accounts_receivable.bad_debt_controls.documented",
		"accounts_receivable.cash_receipt_controls.secure",
	],
	"payroll_controls_comprehensive": [
		"payroll.employee_master_controls.maintained",
		"payroll.time_recording_controls.accurate",
		"payroll.payroll_calculation_controls.verified",
		"payroll.payroll_authorization_controls.enforced",
		"payroll.payroll_distribution_controls.secure",
	],
	"treasury_controls_secure": [
		"treasury.cash_management_controls.comprehensive",
		"treasury.investment_controls.authorized",
		"treasury.bank_reconciliation_controls.automated",
		"treasury.foreign_exchange_controls.managed",
		"treasury.debt_management_controls.monitored",
	],
	"_input_control_attested": [
		"application_controls.input_validation.comprehensive",
	],
	"_processing_control_attested": [
		"application_controls.processing_controls.accurate",
	],
	"_output_control_attested": [
		"application_controls.output_controls.complete",
	],
	"_data_integrity_attested": [
		"application_controls.data_integrity.maintained",
	],
	"_error_handling_attested": [
		"application_controls.error_handling.robust",
	],
	"_transaction_logging_attested": [
		"application_controls.transaction_logging.complete",
	],
}

_all_true(paths) if {
	every path in paths {
		_fact(path) == true
	}
}

# Named evidence problems for the facts of the checks that do not pass.
_evidence_problems(checks) := [problem |
	some check in checks
	check.check != true
	some path in _facts[check.rule]
	problem := _problem(path)
]

evidence_problems := _evidence_problems(_all_checks)

# ---------------------------------------------------------------------------
# Evidence source. Facts are posted as the input document, under input.sox, like every other module in
# this library. A caller that still loads them as the data document data.sox is served only when the
# input has no "sox" key at all. The two are never merged: once input.sox is posted (even as null, or
# with one fact), nothing is read from data.sox, so loaded data cannot override or fill in posted input.
# ---------------------------------------------------------------------------

default _input_has_sox := false

_input_has_sox if {
	is_object(input)
	"sox" in object.keys(input)
}

# The data.sox areas this module reads, each by a ground reference (data.sox also holds the sox packages,
# so it is never read whole). An area that is not loaded has no entry.
_data_area["input_validation"] := data.sox.input_validation

_data_area["data_entry"] := data.sox.data_entry

_data_area["authorization"] := data.sox.authorization

_data_area["input_completeness"] := data.sox.input_completeness

_data_area["calculation_controls"] := data.sox.calculation_controls

_data_area["sequence_controls"] := data.sox.sequence_controls

_data_area["processing_completeness"] := data.sox.processing_completeness

_data_area["exception_processing"] := data.sox.exception_processing

_data_area["output_distribution"] := data.sox.output_distribution

_data_area["output_completeness"] := data.sox.output_completeness

_data_area["output_accuracy"] := data.sox.output_accuracy

_data_area["output_authorization"] := data.sox.output_authorization

_data_area["database_integrity"] := data.sox.database_integrity

_data_area["transmission_integrity"] := data.sox.transmission_integrity

_data_area["storage_integrity"] := data.sox.storage_integrity

_data_area["referential_integrity"] := data.sox.referential_integrity

_data_area["error_detection"] := data.sox.error_detection

_data_area["error_reporting"] := data.sox.error_reporting

_data_area["error_correction"] := data.sox.error_correction

_data_area["error_prevention"] := data.sox.error_prevention

_data_area["audit_trail"] := data.sox.audit_trail

_data_area["transaction_traceability"] := data.sox.transaction_traceability

_data_area["log_integrity"] := data.sox.log_integrity

_data_area["log_retention"] := data.sox.log_retention

_data_area["general_ledger"] := data.sox.general_ledger

_data_area["accounts_payable"] := data.sox.accounts_payable

_data_area["accounts_receivable"] := data.sox.accounts_receivable

_data_area["payroll"] := data.sox.payroll

_data_area["treasury"] := data.sox.treasury

_data_area["application_controls.input_validation"] := data.sox.application_controls.input_validation

_data_area["application_controls.processing_controls"] := data.sox.application_controls.processing_controls

_data_area["application_controls.output_controls"] := data.sox.application_controls.output_controls

_data_area["application_controls.data_integrity"] := data.sox.application_controls.data_integrity

_data_area["application_controls.error_handling"] := data.sox.application_controls.error_handling

_data_area["application_controls.transaction_logging"] := data.sox.application_controls.transaction_logging

default _data_sox_loaded := false

_data_sox_loaded if count(_data_area) > 0

_nest([area], value) := {area: value}

_nest([package_name, area], value) := {package_name: {area: value}}

_data_sox := object.union_n([_nest(split(key, "."), value) | some key, value in _data_area])

# "input", "data" or "none" (nothing posted and nothing loaded).
evidence_source := "input" if {
	_input_has_sox
} else := "data" if {
	_data_sox_loaded
} else := "none"

# True when data.sox is loaded and was not read because input.sox was posted.
default data_sox_ignored := false

data_sox_ignored if {
	_input_has_sox
	_data_sox_loaded
}

# An input.sox that is not an object (null, a string) reads as empty: every fact is missing evidence.
_sox := input.sox if {
	_input_has_sox
	is_object(input.sox)
} else := {} if {
	_input_has_sox
} else := _data_sox

_source_document := "data" if {
	evidence_source == "data"
} else := "input"

# A fact by its dotted path below sox; null when it is absent or its parent is not an object.
_fact(path) := object.get(_sox, split(path, "."), null)

# The fact's full name in the document it was read from, for findings.
_ref(path) := sprintf("%s.sox.%s", [_source_document, path])

# Only the booleans are evidence. Anything else is named as an evidence problem.
_problem(path) := sprintf("evidence missing: %s not collected", [_ref(path)]) if {
	_fact(path) == null
}

_problem(path) := sprintf("%s is not a boolean (got %s)", [_ref(path), type_name(_fact(path))]) if {
	_fact(path) != null
	not is_boolean(_fact(path))
}
