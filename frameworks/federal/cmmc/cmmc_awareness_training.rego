# METADATA
# title: "CMMC 2.0 — Domain 3.2: Awareness & Training"
# custom:
#   class: compliance
#   framework: cmmc
#   source: dod
#   domains: [us-federal, defense]
#   coverage:
#     checks: 17
#     cited: 3
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package cmmc.awareness_training

import rego.v1

# Organisation-defined parameters. Where NIST SP 800-171 R2 leaves a period,
# frequency or count to the organisation ("a defined period", "periodically",
# "a specified number"; NIST SP 800-171A objectives "... is defined"), the
# organisation's value is read from input.org_defined.<name> and the observed
# value is compared with it. Either one missing, or not a number, is a finding.
# is_number guards every comparison: OPA orders null below numbers and strings
# above them.
_odp(name) := v if {
	v := input.org_defined[name]
	is_number(v)
}

_actual(path) := v if {
	v := object.get(input, path, null)
	is_number(v)
}

_at_most(path, name) if _actual(path) <= _odp(name)

_at_least(path, name) if _actual(path) >= _odp(name)

# 32 CFR 170.14(d): "periodically" means an organisation-defined interval of no
# more than one year.
_periodic_ok(name) if _odp(name) <= 365

# =============================================================================
# CMMC 2.0 — Domain 3.2: Awareness & Training
# NIST SP 800-171 Rev 2 — 3 Practices
# =============================================================================

# ---------------------------------------------------------------------------
# 3.2.1 — Ensure that managers, systems administrators, and users of
#          organizational systems are made aware of the security risks
#          associated with their activities. (L2)
# ---------------------------------------------------------------------------

default compliant_3_2_1 := false

compliant_3_2_1 if {
	input.training.security_awareness_program == true
	input.training.all_users_trained == true
	_at_most(["training", "training_frequency_days"], "awareness_training_interval_days")
}

violation_3_2_1 contains msg if {
	not input.training.security_awareness_program
	msg := "3.2.1: No organizational security awareness program established"
}

violation_3_2_1 contains msg if {
	not input.training.all_users_trained
	msg := "3.2.1: Not all users have completed security awareness training"
}

violation_3_2_1 contains "3.2.1: evidence missing - input.org_defined.awareness_training_interval_days (organisation-defined value, NIST SP 800-171A (R2 3.2.1 names no period)) not supplied or not a number" if {
	not _odp("awareness_training_interval_days")
}

violation_3_2_1 contains "3.2.1: evidence missing - input.training.training_frequency_days not collected or not a number" if {
	not _actual(["training", "training_frequency_days"])
}

violation_3_2_1 contains msg if {
	_actual(["training", "training_frequency_days"]) > _odp("awareness_training_interval_days")
	msg := sprintf("3.2.1: security awareness delivered every %v days, beyond the organisation-defined interval of %v days", [_actual(["training", "training_frequency_days"]), _odp("awareness_training_interval_days")])
}

# ---------------------------------------------------------------------------
# 3.2.2 — Ensure that personnel are trained to carry out their assigned
#          information security responsibilities. (L2)
# ---------------------------------------------------------------------------

default compliant_3_2_2 := false

compliant_3_2_2 if {
	input.training.role_based_training == true
	input.training.privileged_user_training == true
	input.training.training_records_maintained == true
}

violation_3_2_2 contains msg if {
	not input.training.role_based_training
	msg := "3.2.2: Role-based security training is not implemented"
}

violation_3_2_2 contains msg if {
	not input.training.privileged_user_training
	msg := "3.2.2: Privileged users have not received specialized security training"
}

violation_3_2_2 contains msg if {
	not input.training.training_records_maintained
	msg := "3.2.2: Training completion records are not maintained"
}

# ---------------------------------------------------------------------------
# 3.2.3 — Provide security awareness training on recognizing and reporting
#          potential threats, such as social engineering and phishing. (L2)
# ---------------------------------------------------------------------------

default compliant_3_2_3 := false

compliant_3_2_3 if {
	input.training.phishing_awareness_training == true
	input.training.social_engineering_training == true
	input.training.insider_threat_training == true
}

violation_3_2_3 contains msg if {
	not input.training.phishing_awareness_training
	msg := "3.2.3: Phishing awareness training is not included in security program"
}

violation_3_2_3 contains msg if {
	not input.training.social_engineering_training
	msg := "3.2.3: Social engineering recognition training is not provided"
}

violation_3_2_3 contains msg if {
	not input.training.insider_threat_training
	msg := "3.2.3: Insider threat awareness training is not provided"
}

# ---------------------------------------------------------------------------
# Aggregate compliance
# ---------------------------------------------------------------------------

base_violations := array.concat(
	[v | some v in violation_3_2_1],
	array.concat(
		[v | some v in violation_3_2_2],
		[v | some v in violation_3_2_3],
	),
)

# ---------------------------------------------------------------------------
# Unmet practices without a specific finding (fail closed)
#   A practice whose compliant_N rule is false because a required fact is
#   missing or failing must surface a violation, so that the domain verdict
#   (count(all_violations) == 0) can never be true while a practice fails.
# ---------------------------------------------------------------------------

violation_unmet contains msg if {
	not compliant_3_2_1
	count(violation_3_2_1) == 0
	msg := "3.2.1: evidence missing or requirement not met — all facts required by this practice must be present and passing"
}

violation_unmet contains msg if {
	not compliant_3_2_2
	count(violation_3_2_2) == 0
	msg := "3.2.2: evidence missing or requirement not met — all facts required by this practice must be present and passing"
}

violation_unmet contains msg if {
	not compliant_3_2_3
	count(violation_3_2_3) == 0
	msg := "3.2.3: evidence missing or requirement not met — all facts required by this practice must be present and passing"
}

all_violations := array.concat(base_violations, [m | some m in violation_unmet])

practices := [
	{"id": "3.2.1", "level": 2, "compliant": compliant_3_2_1},
	{"id": "3.2.2", "level": 2, "compliant": compliant_3_2_2},
	{"id": "3.2.3", "level": 2, "compliant": compliant_3_2_3},
]

passing_count := count([p | some p in practices; p.compliant == true])

default compliant := false

compliant if count(all_violations) == 0

compliance_report := {
	"domain": "Awareness & Training",
	"domain_id": "3.2",
	"total_practices": 3,
	"passing": passing_count,
	"failing": 3 - passing_count,
	"compliant": compliant,
	"violations": all_violations,
	"practices": practices,
}
