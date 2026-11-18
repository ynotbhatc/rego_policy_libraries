# METADATA
# title: "NIST SP 800-53 Rev 5 — Audit and Accountability (AU) Family"
# custom:
#   class: compliance
#   framework: nist_sp_800_53
#   source: nist
#   domains: [us-federal, security-controls]
#   coverage:
#     checks: 12
#     cited: 12
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package nist.sp800_53.audit_accountability

import rego.v1

# NIST SP 800-53 Rev 5 — Audit and Accountability (AU) Family
# Generation, protection, review, and analysis of audit records.

default compliant := false

violation contains msg if {
	not input.au_controls.policy.documented
	msg := "NIST AU-1: Audit and accountability policy not documented"
}

violation contains msg if {
	not input.au_controls.event_logging.enabled
	msg := "NIST AU-2: Event types for logging not identified or event logging not enabled"
}

violation contains msg if {
	not input.au_controls.content_of_records.adequate
	msg := "NIST AU-3: Audit record content lacks who/what/when/where/source/outcome"
}

violation contains msg if {
	not input.au_controls.storage_capacity.adequate
	msg := "NIST AU-4: Audit record storage capacity insufficient for required retention"
}

violation contains msg if {
	not input.au_controls.response_to_failures.alerting
	msg := "NIST AU-5: Audit logging failure does not alert appropriate personnel"
}

violation contains msg if {
	not input.au_controls.review_and_analysis.regular
	msg := "NIST AU-6: Audit records not regularly reviewed or analyzed"
}

violation contains msg if {
	not input.au_controls.reduction_and_reporting.tools_available
	msg := "NIST AU-7: Audit record reduction/report-generation tooling unavailable"
}

violation contains msg if {
	not input.au_controls.time_stamps.synchronized
	msg := "NIST AU-8: Audit record time stamps not synchronized to authoritative source"
}

violation contains msg if {
	not input.au_controls.protection_of_records.tamper_resistant
	msg := "NIST AU-9: Audit records not protected against unauthorized modification/deletion"
}

violation contains msg if {
	not input.au_controls.non_repudiation.implemented
	msg := "NIST AU-10: Non-repudiation of actions by individuals not implemented"
}

# AU-11 Audit Record Retention: "Retain audit records for [ODP time period] ...". NIST fixes no period;
# the organisation supplies it as input.au_controls.odp.retention_period_days. Either value missing is
# reported as missing evidence.
_au11_retained := object.get(input, ["au_controls", "retention_period_days"], null)

_au11_odp := object.get(input, ["au_controls", "odp", "retention_period_days"], null)

_au11_missing contains "input.au_controls.retention_period_days" if not is_number(_au11_retained)

_au11_missing contains "input.au_controls.odp.retention_period_days (organization-defined period)" if not is_number(_au11_odp)

violation contains msg if {
	count(_au11_missing) > 0
	msg := sprintf("NIST AU-11: evidence missing — %s not collected", [concat(", ", sort(_au11_missing))])
}

violation contains msg if {
	count(_au11_missing) == 0
	_au11_retained < _au11_odp
	msg := sprintf(
		"NIST AU-11: Audit record retention %v days is below the organization-defined %v days",
		[_au11_retained, _au11_odp],
	)
}

violation contains msg if {
	not input.au_controls.generation.required_events_captured
	msg := "NIST AU-12: Audit record generation does not capture all required events"
}

compliant if count(violation) == 0

# The control and enhancement ids this family evaluates; each has exactly one finding when it fails.
evaluated_controls := {"AU-1", "AU-2", "AU-3", "AU-4", "AU-5", "AU-6", "AU-7", "AU-8", "AU-9", "AU-10", "AU-11", "AU-12"}

compliance_report := {
	"family": "AU",
	"name": "Audit and Accountability",
	"controls_evaluated": count(evaluated_controls),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}
