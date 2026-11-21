# METADATA
# title: "NIST SP 800-53 Rev 5 — PII Processing and Transparency (PT) Family"
# custom:
#   class: compliance
#   framework: nist_sp_800_53
#   source: nist
#   domains: [us-federal, security-controls]
#   coverage:
#     checks: 13
#     cited: 13
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package nist.sp800_53.pii_processing_transparency

import rego.v1

# NIST SP 800-53 Rev 5 — Personally Identifiable Information Processing and Transparency (PT) Family: the
# eight active base controls PT-1 to PT-8 and the Privacy-baseline enhancements PT-5(2), PT-6(1), PT-6(2), PT-7(1)
# and PT-7(2). Each enhancement is its own finding; a base control never fails on an enhancement's requirement. Facts live under input.pt_controls.

default compliant := false

_root := "pt_controls"

# ---------------------------------------------------------------------------------------------------------
# Evidence helpers. Every value is read with object.get(..., null), so an absent key, null, or a value of
# the wrong type ("true", "1") lands in the "missing" set and the control fails closed. Each control builds
# one set of missing paths and one set of unmet requirements and has exactly one rule, so it can produce at
# most one finding.
# ---------------------------------------------------------------------------------------------------------

_val(path) := object.get(input, array.concat([_root], path), null)

_p(path) := concat(".", array.concat(["input", _root], path))

# Booleans: reqs maps a fact key to the text reported when that fact is false. Only `true` passes.
_bool_missing(sec, reqs) := {_p(array.concat(sec, [k])) | some k, _ in reqs; not is_boolean(_val(array.concat(sec, [k])))}

_bool_unmet(sec, reqs) := {d | some k, d in reqs; _val(array.concat(sec, [k])) == false}

# Organization-defined frequency: observed <sec>.days_since_last against <sec>.odp.frequency_days.
_freq_keys := [["days_since_last"], ["odp", "frequency_days"]]

_freq_missing(sec) := {_p(array.concat(sec, k)) | some k in _freq_keys; not is_number(_val(array.concat(sec, k)))}

_freq_unmet(sec, what) := {d |
	obs := _val(array.concat(sec, ["days_since_last"]))
	odp := _val(array.concat(sec, ["odp", "frequency_days"]))
	is_number(obs)
	is_number(odp)
	obs > odp
	d := sprintf("%s last %v days ago; the organization-defined frequency is %v days", [what, obs, odp])
}

# Counts that must be zero (e.g. overdue remediations). A value that is not a non-negative whole number is missing evidence.
# A count: a non-negative whole number. Anything else (absent, null, "1", a negative or a fractional number) is
# evidence missing.
_count_ok(x) if {
	is_number(x)
	x >= 0
	floor(x) == x
}

_zero_missing(sec, k) := {_p(array.concat(sec, [k])) | not _count_ok(_val(array.concat(sec, [k])))}

_zero_unmet(sec, k, what) := {d |
	n := _val(array.concat(sec, [k]))
	is_number(n)
	_count_ok(n)
	n > 0
	d := sprintf("%v %s", [n, what])
}

# Attestation for organizational controls: {"attested": true, "by": <non-empty string>, "date": <non-empty string>}.
_att_ok(a) if {
	a.attested == true
	is_string(a.by)
	trim_space(a.by) != ""
	is_string(a.date)
	trim_space(a.date) != ""
}

_att_detail(sec, what) := d if {
	not _att_ok(_val(array.concat(sec, ["attestation"])))
	d := sprintf("evidence missing — no valid attestation at %s (needs attested: true and a non-empty by and date); not attested: this organizational control is evidenced by attestation only: %s", [_p(array.concat(sec, ["attestation"])), what])
}

# Policy and procedures (the -1 control of the family).
_pp_bools := {"documented": "policy not documented", "official_designated": "no official designated to manage the policy and procedures"}

_pp_missing := ((_bool_missing(["policy"], _pp_bools) | _bool_missing(["procedures"], {"documented": ""})) | _freq_missing(["policy"])) | _freq_missing(["procedures"])

_pp_unmet := ((_bool_unmet(["policy"], _pp_bools) | _bool_unmet(["procedures"], {"documented": "procedures not documented"})) | _freq_unmet(["policy"], "policy reviewed")) | _freq_unmet(["procedures"], "procedures reviewed")

# One finding text: the missing evidence first, then every unmet requirement.
_mpart(m) := [] if {
	count(m) == 0
} else := [sprintf("evidence missing — %s not collected", [concat(", ", sort(m))])]

_detail(m, u) := concat("; ", array.concat(_mpart(m), sort(u)))

# ---------------------------------------------------------------------------------------------------------
# Controls
# ---------------------------------------------------------------------------------------------------------

# PT-1 Policy and Procedures: input.pt_controls.policy.{documented, official_designated, days_since_last,
# odp.frequency_days} and input.pt_controls.procedures.{documented, days_since_last, odp.frequency_days}.
violation contains msg if {
	count(_pp_missing) + count(_pp_unmet) > 0
	msg := sprintf("NIST PT-1: PII processing and transparency policy and procedures: %s", [_detail(_pp_missing, _pp_unmet)])
}

# PT-2 Authority to Process PII: input.pt_controls.processing_authority.{authority_documented,
# processing_restricted_to_authorized}.
_pt2 := {
	"authority_documented": "the authority that permits the processing of PII is not determined and documented",
	"processing_restricted_to_authorized": "PII processing is not restricted to what is authorized",
}

violation contains msg if {
	m := _bool_missing(["processing_authority"], _pt2)
	u := _bool_unmet(["processing_authority"], _pt2)
	count(m) + count(u) > 0
	msg := sprintf("NIST PT-2: %s", [_detail(m, u)])
}

# PT-3 PII Processing Purposes: input.pt_controls.processing_purposes.{purposes_documented,
# described_in_public_notices, processing_restricted_to_purposes, changes_monitored}.
_pt3 := {
	"purposes_documented": "the purposes for processing PII are not identified and documented",
	"described_in_public_notices": "the purposes are not described in the public privacy notices and policies",
	"processing_restricted_to_purposes": "PII processing is not restricted to what is compatible with the identified purposes",
	"changes_monitored": "changes in PII processing are not monitored and controlled through the organization-defined mechanisms",
}

violation contains msg if {
	m := _bool_missing(["processing_purposes"], _pt3)
	u := _bool_unmet(["processing_purposes"], _pt3)
	count(m) + count(u) > 0
	msg := sprintf("NIST PT-3: %s", [_detail(m, u)])
}

# PT-4 Consent: input.pt_controls.consent.{mechanism_implemented, obtained_before_collection}.
_pt4 := {
	"mechanism_implemented": "no tool or mechanism for individuals to consent to the processing of their PII",
	"obtained_before_collection": "consent is not obtained before PII is collected",
}

violation contains msg if {
	m := _bool_missing(["consent"], _pt4)
	u := _bool_unmet(["consent"], _pt4)
	count(m) + count(u) > 0
	msg := sprintf("NIST PT-4: %s", [_detail(m, u)])
}

# PT-5 Privacy Notice: input.pt_controls.privacy_notice.{available_at_first_interaction, plain_language,
# identifies_authority, identifies_purposes, days_since_last, odp.frequency_days}. days_since_last is the age of
# the last notice provided after first interaction, against the organization-defined frequency.
_pt5 := {
	"available_at_first_interaction": "the privacy notice is not available when individuals first interact with the organization",
	"plain_language": "the privacy notice is not clear and in plain language",
	"identifies_authority": "the privacy notice does not identify the authority for processing PII",
	"identifies_purposes": "the privacy notice does not identify the purposes for processing PII",
}

violation contains msg if {
	sec := ["privacy_notice"]
	m := _bool_missing(sec, _pt5) | _freq_missing(sec)
	u := _bool_unmet(sec, _pt5) | _freq_unmet(sec, "privacy notice provided")
	count(m) + count(u) > 0
	msg := sprintf("NIST PT-5: %s", [_detail(m, u)])
}

# PT-6 System of Records Notice: input.pt_controls.system_of_records_notice.attestation. The control applies only
# to systems that maintain a Privacy Act system of records, so the attestation covers either the notices being
# drafted, reviewed, published and kept current, or the system not maintaining a system of records.
violation contains msg if {
	d := _att_detail(["system_of_records_notice"], "system of records notices are submitted for OMB and congressional review, published in the Federal Register and kept current, or the system maintains no Privacy Act system of records")
	msg := sprintf("NIST PT-6: %s", [d])
}

# PT-7 Specific Categories of PII: input.pt_controls.specific_categories.attestation (organizational).
violation contains msg if {
	d := _att_detail(["specific_categories"], "the organization-defined processing conditions are applied to specific categories of PII")
	msg := sprintf("NIST PT-7: %s", [d])
}

# PT-8 Computer Matching Requirements: input.pt_controls.computer_matching.attestation. The control applies only
# when a matching program is run, so the attestation covers either the matching requirements being met or no
# matching program being conducted.
violation contains msg if {
	d := _att_detail(["computer_matching"], "matching programs have Data Integrity Board approval, a matching agreement, a published notice, independent verification and notice with an opportunity to contest before adverse action, or no matching program is conducted")
	msg := sprintf("NIST PT-8: %s", [d])
}

compliant if count(violation) == 0

# ---------------------------------------------------------------------------------------------------------
# NIST SP 800-53B Privacy-baseline enhancements. Each is its own requirement; its base control never fails for it.
# ---------------------------------------------------------------------------------------------------------

# PT-5(2) Privacy Act Statements: forms that collect information maintained in a Privacy Act system of records
# carry a Privacy Act statement (or one is provided on a separate form individuals can keep).
# Facts: input.pt_controls.privacy_notice.privacy_act_statements.forms_without_statement (count of such forms with
# neither; 0 when the system collects nothing into a system of records).
violation contains msg if {
	sec := ["privacy_notice", "privacy_act_statements"]
	m := _zero_missing(sec, "forms_without_statement")
	u := _zero_unmet(sec, "forms_without_statement", "forms collecting information for a Privacy Act system of records have no Privacy Act statement")
	count(m) + count(u) > 0
	msg := sprintf("NIST PT-5(2): %s", [_detail(m, u)])
}

# PT-6(1) Routine Uses: the routine uses published in the system of records notice are reviewed at the
# organization-defined frequency for accuracy and compatibility with the purpose of collection.
# Facts (input.pt_controls.system_of_records_notice.routine_uses): days_since_last + odp.frequency_days (the last
# review); compatible_with_collection_purpose (boolean, the review's outcome).
violation contains msg if {
	sec := ["system_of_records_notice", "routine_uses"]
	b := {"compatible_with_collection_purpose": "the last review found published routine uses inaccurate or not compatible with the purpose of collection"}
	m := _bool_missing(sec, b) | _freq_missing(sec)
	u := _bool_unmet(sec, b) | _freq_unmet(sec, "routine uses reviewed")
	count(m) + count(u) > 0
	msg := sprintf("NIST PT-6(1): %s", [_detail(m, u)])
}

# PT-6(2) Exemption Rules: the Privacy Act exemptions claimed for the system of records are reviewed at the
# organization-defined frequency: still appropriate and necessary, promulgated as regulations, and accurately
# described in the notice.
# Facts (input.pt_controls.system_of_records_notice.exemptions): days_since_last + odp.frequency_days (the last
# review); remain_necessary, promulgated_as_regulations, accurately_described (booleans, the review's outcome).
_pt6_2 := {
	"remain_necessary": "claimed Privacy Act exemptions are no longer appropriate and necessary in accordance with law",
	"promulgated_as_regulations": "claimed Privacy Act exemptions have not been promulgated as regulations",
	"accurately_described": "claimed Privacy Act exemptions are not accurately described in the system of records notice",
}

violation contains msg if {
	sec := ["system_of_records_notice", "exemptions"]
	m := _bool_missing(sec, _pt6_2) | _freq_missing(sec)
	u := _bool_unmet(sec, _pt6_2) | _freq_unmet(sec, "Privacy Act exemptions reviewed")
	count(m) + count(u) > 0
	msg := sprintf("NIST PT-6(2): %s", [_detail(m, u)])
}

# PT-7(1) Social Security Numbers: input.pt_controls.specific_categories.social_security_numbers.attestation
# (organizational: unnecessary SSN use eliminated and alternatives explored, no right or benefit denied for refusing
# to disclose one, and individuals told whether disclosure is mandatory, under what authority and for what uses).
violation contains msg if {
	d := _att_detail(["specific_categories", "social_security_numbers"], "unnecessary collection, maintenance and use of Social Security numbers is eliminated, no individual is denied a right, benefit or privilege for refusing to disclose one, and individuals asked for one are told whether disclosure is mandatory, by what authority it is solicited and how it will be used")
	msg := sprintf("NIST PT-7(1): %s", [d])
}

# PT-7(2) First Amendment Information: input.pt_controls.specific_categories.first_amendment.attestation
# (organizational: information describing how an individual exercises First Amendment rights is not processed
# unless authorized by statute or the individual, or within an authorized law enforcement activity).
violation contains msg if {
	d := _att_detail(["specific_categories", "first_amendment"], "information describing how any individual exercises rights guaranteed by the First Amendment is not processed unless expressly authorized by statute or by the individual, or pertinent to and within the scope of an authorized law enforcement activity")
	msg := sprintf("NIST PT-7(2): %s", [d])
}

# The base control ids this family evaluates; each has exactly one finding when it fails.
evaluated_controls := {"PT-1", "PT-2", "PT-3", "PT-4", "PT-5", "PT-6", "PT-7", "PT-8", "PT-5(2)", "PT-6(1)", "PT-6(2)", "PT-7(1)", "PT-7(2)"}

compliance_report := {
	"family": "PT",
	"name": "Personally Identifiable Information Processing and Transparency",
	"controls_evaluated": count(evaluated_controls),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}
