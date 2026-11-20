# METADATA
# title: "NIST SP 800-53 Rev 5 — Media Protection (MP) Family"
# custom:
#   class: compliance
#   framework: nist_sp_800_53
#   source: nist
#   domains: [us-federal, security-controls]
#   coverage:
#     checks: 17
#     cited: 11
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package nist.sp800_53.media_protection

import rego.v1

# NIST SP 800-53 Rev 5 — Media Protection (MP) Family, base controls MP-1 to MP-8 and the NIST / FedRAMP High
# enhancements MP-6(1), MP-6(2), MP-6(3) (11 ids).
# Facts live under input.mp_controls. Every control fails closed: a fact that is missing or of the wrong type is
# reported as missing evidence. Booleans pass only on true; numbers are checked with is_number before comparing.

default compliant := false

# ---------------------------------------------------------------------------------------------------------------
# Helpers. Paths are dotted and relative to input.mp_controls.
# ---------------------------------------------------------------------------------------------------------------

_get(path) := object.get(input, array.concat(["mp_controls"], split(path, ".")), null)

_path(p) := concat("", ["input.mp_controls.", p])

# Required booleans that are absent or not a boolean ("true", 1 and null are not evidence).
_bool_missing(paths) := {_path(p) |
	some p in paths
	not is_boolean(_get(p))
}

# Required booleans that are present and false.
_bool_false(paths) := {sprintf("%s is false", [_path(p)]) |
	some p in paths
	_get(p) == false
}

# Organization-defined frequency (IR-2/IR-3 shape): <base>.days_since_last against <base>.odp.frequency_days.
_freq_missing(base) := {_path(concat(".", [base, k])) |
	some k in ["days_since_last", "odp.frequency_days"]
	not is_number(_get(concat(".", [base, k])))
}

_overdue(base, what) := msg if {
	obs := _get(concat(".", [base, "days_since_last"]))
	odp := _get(concat(".", [base, "odp.frequency_days"]))
	is_number(obs)
	is_number(odp)
	obs > odp
	msg := sprintf("%s last done %v days ago; the organization-defined frequency is %v days", [what, obs, odp])
}

# Organizational controls with no machine-checkable evidence: {"attested": true, "by": "...", "date": "..."}.
_attested(name) if {
	a := _get(concat(".", [name, "attestation"]))
	a.attested == true
	is_string(a.by)
	trim_space(a.by) != ""
	is_string(a.date)
	trim_space(a.date) != ""
}

_missing_msg(id, paths) := sprintf("NIST %s: evidence missing — %s not collected", [id, concat(", ", sort(paths))])

# ---------------------------------------------------------------------------------------------------------------
# MP-1 Policy and Procedures
# Facts: policy.documented, procedures.documented, policy.official_designated (booleans);
#        policy.review.days_since_last + policy.review.odp.frequency_days;
#        procedures.review.days_since_last + procedures.review.odp.frequency_days.
# One finding listing every unmet element.
# ---------------------------------------------------------------------------------------------------------------

_mp1_bools := ["policy.documented", "procedures.documented", "policy.official_designated"]

_mp1_missing := (_bool_missing(_mp1_bools) | _freq_missing("policy.review")) | _freq_missing("procedures.review")

_mp1_overdue := {m | m := _overdue("policy.review", "Policy review")} | {m | m := _overdue("procedures.review", "Procedures review")}

_mp1_unmet := ({sprintf("evidence missing: %s not collected", [p]) | some p in _mp1_missing} | _bool_false(_mp1_bools)) | _mp1_overdue

violation contains msg if {
	count(_mp1_unmet) > 0
	msg := sprintf("NIST MP-1: Media protection policy and procedures requirements not met — %s", [concat("; ", sort(_mp1_unmet))])
}

# ---------------------------------------------------------------------------------------------------------------
# MP-2 Media Access
# Facts (booleans) under media_access: digital_restricted, non_digital_restricted — access to the
#   organization-defined digital and non-digital media types is restricted to the organization-defined roles.
# ---------------------------------------------------------------------------------------------------------------

_mp2_bools := ["media_access.digital_restricted", "media_access.non_digital_restricted"]

_mp2_missing := _bool_missing(_mp2_bools)

violation contains msg if {
	count(_mp2_missing) > 0
	msg := _missing_msg("MP-2", _mp2_missing)
}

violation contains msg if {
	count(_mp2_missing) == 0
	failed := _bool_false(_mp2_bools)
	count(failed) > 0
	msg := sprintf("NIST MP-2: Access to system media not restricted to authorized roles — %s", [concat("; ", sort(failed))])
}

# ---------------------------------------------------------------------------------------------------------------
# MP-3 Media Marking — organizational control, no machine-checkable evidence.
# Facts: media_marking.attestation {"attested": true, "by": <name>, "date": <date>}.
# ---------------------------------------------------------------------------------------------------------------

violation contains msg if {
	not _attested("media_marking")
	msg := "NIST MP-3: Marking of system media with distribution limitations, handling caveats and security markings not attested — input.mp_controls.media_marking.attestation needs attested: true, by and date (organizational control, no machine-checkable evidence)"
}

# ---------------------------------------------------------------------------------------------------------------
# MP-4 Media Storage — organizational control, no machine-checkable evidence.
# Facts: media_storage.attestation {"attested": true, "by": <name>, "date": <date>}.
# ---------------------------------------------------------------------------------------------------------------

violation contains msg if {
	not _attested("media_storage")
	msg := "NIST MP-4: Physical control and secure storage of system media in controlled areas not attested — input.mp_controls.media_storage.attestation needs attested: true, by and date (organizational control, no machine-checkable evidence)"
}

# ---------------------------------------------------------------------------------------------------------------
# MP-5 Media Transport — organizational control, no machine-checkable evidence.
# Facts: media_transport.attestation {"attested": true, "by": <name>, "date": <date>}.
# ---------------------------------------------------------------------------------------------------------------

violation contains msg if {
	not _attested("media_transport")
	msg := "NIST MP-5: Protection, accountability, documentation and authorized handling of media in transport not attested — input.mp_controls.media_transport.attestation needs attested: true, by and date (organizational control, no machine-checkable evidence)"
}

# ---------------------------------------------------------------------------------------------------------------
# MP-6 Media Sanitization
# Facts: media_sanitization.unsanitized_releases (number of media disposed of, released or reused without a
#        sanitization record, from asset-disposal records; must be 0);
#        media_sanitization.techniques_per_odp, media_sanitization.mechanisms_commensurate (booleans: the
#        organization-defined techniques are used and their strength matches the information's category).
# ---------------------------------------------------------------------------------------------------------------

_mp6_bools := ["media_sanitization.techniques_per_odp", "media_sanitization.mechanisms_commensurate"]

_mp6_releases := _get("media_sanitization.unsanitized_releases")

_mp6_missing := _bool_missing(_mp6_bools) | {_path("media_sanitization.unsanitized_releases") | not is_number(_mp6_releases)}

violation contains msg if {
	count(_mp6_missing) > 0
	msg := _missing_msg("MP-6", _mp6_missing)
}

violation contains msg if {
	count(_mp6_missing) == 0
	failed := _bool_false(_mp6_bools) | {sprintf("%v media released without a sanitization record", [_mp6_releases]) | _mp6_releases > 0}
	count(failed) > 0
	msg := sprintf("NIST MP-6: Media not sanitized before disposal, release or reuse — %s", [concat("; ", sort(failed))])
}

# ---------------------------------------------------------------------------------------------------------------
# MP-7 Media Use
# Facts (booleans) under media_use: use_restricted_per_odp (the organization-defined restriction or prohibition
#   on the organization-defined media types is enforced on the organization-defined systems, e.g. device
#   control), ownerless_portable_devices_prohibited.
# ---------------------------------------------------------------------------------------------------------------

_mp7_bools := ["media_use.use_restricted_per_odp", "media_use.ownerless_portable_devices_prohibited"]

_mp7_missing := _bool_missing(_mp7_bools)

violation contains msg if {
	count(_mp7_missing) > 0
	msg := _missing_msg("MP-7", _mp7_missing)
}

violation contains msg if {
	count(_mp7_missing) == 0
	failed := _bool_false(_mp7_bools)
	count(failed) > 0
	msg := sprintf("NIST MP-7: Use of system media not restricted — %s", [concat("; ", sort(failed))])
}

# ---------------------------------------------------------------------------------------------------------------
# MP-8 Media Downgrading — organizational control, no machine-checkable evidence.
# Facts: media_downgrading.attestation {"attested": true, "by": <name>, "date": <date>}.
# ---------------------------------------------------------------------------------------------------------------

violation contains msg if {
	not _attested("media_downgrading")
	msg := "NIST MP-8: Media downgrading process (established, verified, media identified and downgraded) not attested — input.mp_controls.media_downgrading.attestation needs attested: true, by and date (organizational control, no machine-checkable evidence)"
}

# ---------------------------------------------------------------------------------------------------------------
# NIST / FedRAMP High-baseline enhancements of MP-6. Each is its own finding; MP-6 never fails for them.
# ---------------------------------------------------------------------------------------------------------------

# Counts that must be zero: a non-number or a negative number is missing evidence.
_count_missing(paths) := {_path(p) |
	some p in paths
	not _count_ok(_get(p))
}

_count_ok(x) if {
	is_number(x)
	x >= 0
}

_nonzero(p, fmt) := {sprintf(fmt, [n]) |
	n := _get(p)
	is_number(n)
	_count_ok(n)
	n > 0
}

_list_missing(paths) := {concat("", [_path(p), " (non-empty list)"]) |
	some p in paths
	not _nonempty_list(_get(p))
}

_nonempty_list(x) if {
	is_array(x)
	count(x) > 0
}

# MP-6(1) Review, Approve, Track, Document, and Verify: media sanitization and disposal actions are reviewed,
# approved, tracked, documented and verified.
# Facts (input.mp_controls.media_sanitization.tracking): tracked_in_system (boolean: actions are recorded in a
# tracking system); actions_without_complete_record (count of sanitization or disposal actions in the review
# period whose record lacks the review, approval, documentation or verification step).
_mp6_1_bools := ["media_sanitization.tracking.tracked_in_system"]

_mp6_1_missing := _bool_missing(_mp6_1_bools) | _count_missing(["media_sanitization.tracking.actions_without_complete_record"])

violation contains msg if {
	count(_mp6_1_missing) > 0
	msg := _missing_msg("MP-6(1)", _mp6_1_missing)
}

violation contains msg if {
	count(_mp6_1_missing) == 0
	failed := _bool_false(_mp6_1_bools) | _nonzero("media_sanitization.tracking.actions_without_complete_record", "%v sanitization or disposal actions without a reviewed, approved, documented and verified record")
	count(failed) > 0
	msg := sprintf("NIST MP-6(1): Media sanitization and disposal actions not reviewed, approved, tracked, documented and verified — %s", [concat("; ", sort(failed))])
}

# MP-6(2) Equipment Testing: sanitization equipment and sanitization procedures are each tested at the
# organization-defined frequency.
# Facts (input.mp_controls.media_sanitization): equipment_testing.days_since_last + equipment_testing.odp.frequency_days;
# procedure_testing.days_since_last + procedure_testing.odp.frequency_days; equipment_testing.last_test_passed
# (boolean: the last test confirmed the intended sanitization was achieved).
_mp6_2_bools := ["media_sanitization.equipment_testing.last_test_passed"]

_mp6_2_missing := (_bool_missing(_mp6_2_bools) | _freq_missing("media_sanitization.equipment_testing")) | _freq_missing("media_sanitization.procedure_testing")

violation contains msg if {
	count(_mp6_2_missing) > 0
	msg := _missing_msg("MP-6(2)", _mp6_2_missing)
}

violation contains msg if {
	count(_mp6_2_missing) == 0
	overdue := {m | m := _overdue("media_sanitization.equipment_testing", "Sanitization equipment testing")} | {m | m := _overdue("media_sanitization.procedure_testing", "Sanitization procedure testing")}
	failed := _bool_false(_mp6_2_bools) | overdue
	count(failed) > 0
	msg := sprintf("NIST MP-6(2): Sanitization equipment and procedures not tested as required — %s", [concat("; ", sort(failed))])
}

# MP-6(3) Nondestructive Techniques: portable storage devices are sanitized with nondestructive techniques before
# they are connected to the system under the organization-defined circumstances.
# Facts (input.mp_controls.media_sanitization.nondestructive): odp.circumstances (non-empty list);
# devices_connected_without_sanitization (count of portable storage devices connected under those circumstances
# with no sanitization record, e.g. from device-control and kiosk logs).
_mp6_3_missing := _list_missing(["media_sanitization.nondestructive.odp.circumstances"]) | _count_missing(["media_sanitization.nondestructive.devices_connected_without_sanitization"])

violation contains msg if {
	count(_mp6_3_missing) > 0
	msg := _missing_msg("MP-6(3)", _mp6_3_missing)
}

violation contains msg if {
	count(_mp6_3_missing) == 0
	failed := _nonzero("media_sanitization.nondestructive.devices_connected_without_sanitization", "%v portable storage devices connected without nondestructive sanitization")
	count(failed) > 0
	msg := sprintf("NIST MP-6(3): Portable storage devices not sanitized before connection — %s", [concat("; ", sort(failed))])
}

compliant if count(violation) == 0

# The control and enhancement ids this family evaluates; each has exactly one finding when it fails.
evaluated_controls := {"MP-1", "MP-2", "MP-3", "MP-4", "MP-5", "MP-6", "MP-6(1)", "MP-6(2)", "MP-6(3)", "MP-7", "MP-8"}

compliance_report := {
	"family": "MP",
	"name": "Media Protection",
	"controls_evaluated": count(evaluated_controls),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}
