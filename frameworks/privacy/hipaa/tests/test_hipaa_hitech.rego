# Tests for hipaa.hitech - 45 CFR Part 164 Subpart D keyed to CFR citations, plus the HITECH statutory checks.
package hipaa.hitech_test

import rego.v1

import data.hipaa.hitech as ht
import data.hipaa.test_fixtures as fx

test_counts_pinned if {
	count(ht.breach_notification_rule) == 17
	count({id | some id, r in ht.breach_notification_rule; r.status == "standard"}) == 4
	count({id | some id, r in ht.breach_notification_rule; r.status == "implementation specification"}) == 9
	count({id | some id, r in ht.breach_notification_rule; r.status == "obligation"}) == 4
	count(ht.fact_basis) == 9
	count({id | some id, _ in ht.fact_basis; not ht.breach_notification_rule[id]}) == 0
}

test_empty_input_fails_closed if {
	r := ht.report with input as {}
	r.compliant == false
	some v in r.violations
	contains(v, "FAIL-CLOSED - attestations 'input.hipaa.subpart_d'")

	# 4 scope flags + no role + missing container + 3 rows binding any entity + 4 HITECH statutory checks
	# (CAP readiness and the two CMS EHR-incentive checks are advisories since the 2026-11-17 audit follow-up)
	r.applicable == 3
	r.violation_count == 13
	count(r.advisories) == 3
}

test_all_green_is_compliant if {
	r := ht.report with input as fx.full_input
	r.compliant == true
	r.satisfied == 17
	r.violation_count == 0
}

test_one_attestation_false_is_named if {
	inp := object.union(fx.full_input, {"hipaa": {"subpart_d": {"164.412(b)": false}}})
	v := ht.violations with input as inp
	count(v) == 1
	some m in v
	startswith(m, "HIPAA 164.412(b) ")
}

test_unknown_id_is_a_violation if {
	inp := object.union(fx.full_input, {"hipaa": {"subpart_d": {"164.416": true}}})
	v := ht.violations with input as inp
	count(v) == 1
	some m in v
	contains(m, "unknown id 164.416")
}

test_breach_fact_lands_on_its_citation if {
	inp := object.union(fx.full_input, {"hitech": {"breach_notification": {"individuals": {"within_60_days": false}}}})
	v := ht.violations with input as inp
	count(v) == 1
	some m in v
	startswith(m, "HIPAA 164.404(b) ")
}

test_statutory_check_still_gates if {
	inp := object.union(fx.full_input, {"hitech": {"patient_rights": {"out_of_pocket": {"restriction_honored": false}}}})
	v := ht.violations with input as inp
	count(v) == 1
	some m in v
	startswith(m, "HITECH 42 U.S.C. §17935: the out-of-pocket restriction")
}

# Audit 2026-11-17 follow-up: CMS EHR-incentive measures and CAP readiness are not HIPAA obligations.
test_ehr_incentive_and_cap_checks_are_advisories_only if {
	inp := object.union(fx.full_input, {"hitech": {
		"meaningful_use": {"security_updates": {"implemented": false}},
		"ehr": {"encryption": {"at_rest": false}},
		"enforcement": {"cap_template": {"available": false}},
	}})
	count(ht.violations) == 0 with input as inp
	count(ht.advisories) == 3 with input as inp
	ht.compliant with input as inp
}

test_business_associate_only_scope if {
	inp := object.union(fx.full_input, {"hipaa": {"scope": object.union(fx.scope_none, {"business_associate": true})}})
	r := ht.report with input as inp
	r.applicable == 6
	r.sections["164.410"].applicable == 3
	r.sections["164.404"].applicable == 0
}
