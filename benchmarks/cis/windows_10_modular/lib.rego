# Written into benchmarks/cis/windows_10_modular/lib.rego by tools/cis_generators/gen_windows_10.py from
# tools/cis_generators/windows_lib.rego.tmpl, with the workstation profile model and two more comparisons
# substituted (LIB_CHANGES in the generator) -- edit those, not this copy.
#
# The evaluator every CIS Windows 10 Enterprise section shares. A section is a `controls` table whose rows carry a
# `kind`; this file says what each kind means against the facts. The fact contract is the one the Windows STIG
# modules read (input.registry[<HKLM path>][<value name>]), so one collector feeds both; the full contract is in
# data/collector_manifest.json.
#
# Each in-scope row resolves to exactly one of pass, fail or not_assessed. Not assessed means the facts that row
# reads were not collected; the report counts it as failed.

# METADATA
# title: "CIS Microsoft Windows 10 Enterprise Benchmark v5.0.0 - shared evaluator"
# custom:
#   class: security
#   framework: cis_windows_10_modular
#   source: cis
#   domains: [windows]
#   coverage:
#     checks: 3
#     cited: 0
#     density: section
#     basis: role
#     tested: true
#     entrypoint: none
#     guard: n/a
#     as_of: v2.4.2
package cis_windows_10.lib

import rego.v1

# ---------------------------------------------------------------------------------------------------------------
# Profile. Level defaults to 2, the stricter selection (Level 2 includes Level 1), so a missing level never
# narrows the assessment. BitLocker and Next Generation Windows Security are opt-in: CIS publishes each as a
# separate profile added to Level 1 or Level 2.
# ---------------------------------------------------------------------------------------------------------------

# defaulted so the report stays defined when OPA is queried with no input document at all
default _cis_profile := {}

_cis_profile := p if {
	p := input.cis_profile
	is_object(p)
}

default level := 2

level := l if {
	l := _cis_profile.level
	l in {1, 2}
}

default level_defaulted := true

level_defaulted := false if _cis_profile.level in {1, 2}

default bitlocker := false

bitlocker if _cis_profile.bitlocker == true

default next_generation := false

next_generation if _cis_profile.next_generation == true

# The opt-in tiers and the selector that turns each on.
TIER_SELECTOR := {"BL": "bitlocker", "NG": "next_generation"}

profile := {
	"level": level,
	"level_defaulted": level_defaulted,
	"bitlocker": bitlocker,
	"next_generation": next_generation,
}

_tier_decided(tier) if tier == "L1"

_tier_decided(tier) if {
	tier == "L2"
	is_number(level)
	level >= 2
}

_tier_decided(tier) if {
	tier == "BL"
	bitlocker
}

_tier_decided(tier) if {
	tier == "NG"
	next_generation
}

# A selector that is supplied but is not a boolean ("true", 1, null), or a cis_profile that is not an object,
# decides nothing: only `true` opts a tier in and only `false` or an absent selector leaves it out. Its tier's
# rows are then in scope and not assessed (counted as failed), as a role-specific row is when no role is given,
# so a mistyped selector can never shrink the assessment into a pass.
_profile_malformed if {
	p := input.cis_profile
	not is_object(p)
}

_selectors := {key | some _, key in TIER_SELECTOR}

_selector_problem(key) := sprintf("input.cis_profile is not an object (got %s)", [type_name(input.cis_profile)]) if {
	key in _selectors
	_profile_malformed
}

_selector_problem(key) := sprintf("input.cis_profile.%s is not a boolean (got %s)", [key, type_name(v)]) if {
	key in _selectors
	not _profile_malformed
	v := _cis_profile[key]
	not is_boolean(v)
}

_tier_undecided(tier) if _selector_problem(TIER_SELECTOR[tier])

_tier_selected(tier) if _tier_decided(tier)

_tier_selected(tier) if _tier_undecided(tier)

_tier(p) := split(p, "_")[0]

_any_tier_decided(profiles) if {
	some p in profiles
	_tier_decided(_tier(p))
}

# in scope only through a tier whose selector decides nothing
_selector_undecided(profiles) if {
	some p in profiles
	_tier_undecided(_tier(p))
	not _any_tier_decided(profiles)
}

_selector_problems(profiles) := sort({_selector_problem(TIER_SELECTOR[_tier(p)]) |
	some p in profiles
	_tier_undecided(_tier(p))
})

in_scope(profiles) if {
	some p in profiles
	_tier_selected(p)
}

# ---------------------------------------------------------------------------------------------------------------
# Facts
# ---------------------------------------------------------------------------------------------------------------

# The facts each kind reads. A kind counts as collected only when its own sub-document is present and non-empty:
# user rights judged against a secedit export that carried no [Privilege Rights] would pass every "No One" row.
INPUT_PATH := {
	"reg": ["registry"],
	"reg_all": ["registry"],
	"reg_absent": ["registry"],
	"ureg": ["registry_users"],
	"secedit": ["secedit", "system_access"],
	"rights": ["secedit", "privilege_rights"],
	"auditpol": ["audit_policy"],
	"reg_key_values": ["registry"],
}

INPUT_KEY := {kind: concat(".", path) | some kind, path in INPUT_PATH}

# Only real user profiles carry user policy. HKU also holds .DEFAULT, the service accounts (S-1-5-18/19/20) and
# each user's _Classes hive; those are dropped rather than failing section 19 on every host.
_user_hives := {sid: hive |
	some sid, hive in object.get(input, "registry_users", {})
	regex.match(`^S-1-5-21-[0-9]+(-[0-9]+)*$`, sid)
}

_collected("ureg") if count(_user_hives) > 0

_collected(kind) if {
	kind != "ureg"
	v := object.get(input, INPUT_PATH[kind], null)
	is_object(v)
	count(v) > 0
}

_assessable(c) if {
	not _selector_undecided(c.profiles)
	_collected(c.kind)
}

# A number is a JSON number. A REG_DWORD, an auditpol setting value and a numeric secedit key arrive as numbers,
# so a string in their place ("1" for 1) is a collector fault, not a setting: the row fails and its finding says
# the value is not a number.
_num(v) := v if is_number(v)

_digits(v) if {
	is_string(v)
	regex.match(`^\s*-?[0-9]+\s*$`, v)
}

# How a row's value arrives, by the registry type its audit procedure states (the row's "vtype"; a fifth element
# on a reg_all item). No vtype: REG_DWORD, compared as collected. "sz": a REG_SZ holding a number
# (CachedLogonsCount, ScRemoveOption), so the string is read as its number and a JSON number, which is not what
# the registry holds, is left undefined and fails the row. "any": the audit procedure states no type, or both,
# and either representation is accepted.
_vtype(c) := object.get(c, "vtype", "dword")

_item_vtype(i) := "dword" if count(i) < 5

_item_vtype(i) := i[4] if count(i) >= 5

_as(v, "dword") := v

_as(v, vtype) := to_number(trim_space(v)) if {
	vtype in {"sz", "any"}
	_digits(v)
}

_as(v, "sz") := v if {
	not _digits(v)
	not is_number(v)
}

_as(v, "any") := v if not _digits(v)

_cmp(v, "eq", want) if _num(v) == _num(want)

# secedit exports names in double quotes (NewAdministratorName = "Administrator"); compare without them
_str(v) := lower(trim(trim_space(v), "\""))

_cmp(v, "eq", want) if {
	is_string(want)
	not _num(want)
	is_string(v)
	_str(v) == lower(want)
}

_cmp(v, "ne", want) if {
	is_string(want)
	is_string(v)
	_str(v) != ""
	_str(v) != lower(want)
}

# a configured number that must be anything other than the one the benchmark rules out
_cmp(v, "ne", want) if {
	is_number(want)
	_num(v) != want
}

# "Disabled or Not Installed": a service that is not installed has no Start value at all, which is as compliant
# as Start = 4. Only used by rows whose title says "or Not Installed"; the facts must still have been collected.
_cmp(v, "eq_or_absent", want) if _num(v) == _num(want)

_cmp(v, "eq_or_absent", _) if _empty(v)

# the audit procedure lists every accepted value ("`1` or `2`")
_cmp(v, "in", want) if _num(v) in {x | some x in want}

_cmp(v, "ge", want) if _num(v) >= want

_cmp(v, "ge_or_forever", want) if _num(v) >= want

# 0 (the workbook: "locked out until an administrator manually unlocks them") and -1 (the same, as some
# exports write it) are both stricter than any number of minutes
_cmp(v, "ge_or_forever", _) if _num(v) in {0, -1}

_cmp(v, "le", want) if _num(v) <= want

_cmp(v, "le_not0", want) if {
	n := _num(v)
	n > 0
	n <= want
}

_cmp(v, "range", want) if {
	n := _num(v)
	n >= want[0]
	n <= want[1]
}

_cmp(v, "nonempty", _) if {
	is_string(v)
	trim_space(v) != ""
}

_cmp(v, "set", want) if {
	is_array(v)
	{lower(trim_space(x)) | some x in v; trim_space(x) != ""} == {lower(x) | some x in want}
}

_cmp(v, "has_all", flags) if {
	is_string(v)
	have := {lower(replace(f, " ", "")) | some f in split(v, ",")}
	every f in flags {
		lower(replace(f, " ", "")) in have
	}
}

_value(hive, path, name) := object.get(object.get(hive, path, {}), name, null)

_empty(null) := true

_empty("") := true

_empty([]) := true

_passes(c) if {
	c.kind == "reg"
	_cmp(_as(_value(input.registry, c.path, c.name), _vtype(c)), c.op, c.value)
}

_passes(c) if {
	c.kind == "reg_all"
	every i in c.items {
		_cmp(_as(_value(input.registry, i[0], i[1]), _item_vtype(i)), i[2], i[3])
	}
}

_passes(c) if {
	c.kind == "reg_absent"
	_empty(_value(input.registry, c.path, c.name))
}

# per-user policy: every loaded user hive must comply
_passes(c) if {
	c.kind == "ureg"
	every _, hive in _user_hives {
		_cmp(_as(_value(hive, c.path, c.name), _vtype(c)), c.op, c.value)
	}
}

_passes(c) if {
	c.kind == "secedit"
	_cmp(object.get(object.get(input.secedit, "system_access", {}), c.key, null), c.op, c.value)
}

_holders(privilege) := {upper(trim_left(s, "*")) |
	some s in object.get(object.get(input.secedit, "privilege_rights", {}), privilege, [])
}

# secedit omits a right nobody holds, so an absent right is an empty list. A right that is present must be a
# list of SID strings: a string or null in its place would read as "nobody holds it" and pass every "No One" row.
_holders_typed(privilege) if {
	v := object.get(object.get(input.secedit, "privilege_rights", {}), privilege, [])
	is_array(v)
	every s in v {
		is_string(s)
	}
}

_passes(c) if {
	c.kind == "rights"
	c.mode == "none"
	_holders_typed(c.privilege)
	count(_holders(c.privilege)) == 0
}

# "is set to": no principal beyond those the benchmark names may hold the right. A named principal that is
# absent (the Hyper-V group on a host without Hyper-V) is narrower, never weaker, so it passes.
_passes(c) if {
	c.kind == "rights"
	c.mode == "only"
	_holders_typed(c.privilege)
	count(_holders(c.privilege) - {upper(s) | some s in c.sids}) == 0
}

# "to include": every principal the benchmark names must hold the right (the deny rights).
_passes(c) if {
	c.kind == "rights"
	c.mode == "include"
	_holders_typed(c.privilege)
	count({upper(s) | some s in c.sids} - _holders(c.privilege)) == 0
}

# numbered values under one key (DenyDeviceClasses\1, \2, ...): every listed string must be among them
_key_values(path) := {lower(trim_space(v)) |
	some _, v in object.get(input.registry, path, {})
	is_string(v)
}

_passes(c) if {
	c.kind == "reg_key_values"
	every x in c.values {
		lower(x) in _key_values(c.path)
	}
}

# auditpol /backup Setting Value: 1 success, 2 failure, 3 both. The benchmark's setting is a minimum.
_passes(c) if {
	c.kind == "auditpol"
	v := _num(object.get(input.audit_policy, c.guid, null))
	bits.and(v, c.bits) == c.bits
}

# ---------------------------------------------------------------------------------------------------------------
# Status and the section report
# ---------------------------------------------------------------------------------------------------------------

status(c) := "not_applicable" if not in_scope(c.profiles)

status(c) := "not_assessed" if {
	in_scope(c.profiles)
	not _assessable(c)
}

status(c) := "pass" if {
	in_scope(c.profiles)
	_assessable(c)
	_passes(c)
}

status(c) := "fail" if {
	in_scope(c.profiles)
	_assessable(c)
	not _passes(c)
}

_found(c) := sprintf("%v", [_value(input.registry, c.path, c.name)]) if c.kind in {"reg", "reg_absent"}

_found(c) := sprintf("%v", [[_value(input.registry, i[0], i[1]) | some i in c.items]]) if c.kind == "reg_all"

_found(c) := sprintf("%v", [{sid: _value(hive, c.path, c.name) | some sid, hive in _user_hives}]) if c.kind == "ureg"

_found(c) := sprintf("%v", [object.get(object.get(input.secedit, "system_access", {}), c.key, null)]) if c.kind == "secedit"

_found(c) := sprintf("%v", [sort(_holders(c.privilege))]) if c.kind == "rights"

_found(c) := sprintf("%v", [object.get(input.audit_policy, c.guid, null)]) if c.kind == "auditpol"

_found(c) := sprintf("%v", [sort(_key_values(c.path))]) if c.kind == "reg_key_values"

# Every value a row compares, as [input path, value as collected, vtype, comparison, required value]: what the
# finding names when a value is of the wrong type for its setting.
_reads(c) := [[sprintf("registry.%s.%s", [c.path, c.name]), _value(input.registry, c.path, c.name), _vtype(c), c.op, c.value]] if c.kind == "reg"

_reads(c) := [[sprintf("registry.%s.%s", [i[0], i[1]]), _value(input.registry, i[0], i[1]), _item_vtype(i), i[2], i[3]] | some i in c.items] if c.kind == "reg_all"

_reads(c) := [[sprintf("registry_users.%s.%s.%s", [sid, c.path, c.name]), _value(hive, c.path, c.name), _vtype(c), c.op, c.value] | some sid, hive in _user_hives] if c.kind == "ureg"

_reads(c) := [[sprintf("secedit.system_access.%s", [c.key]), object.get(object.get(input.secedit, "system_access", {}), c.key, null), "dword", c.op, c.value]] if c.kind == "secedit"

_reads(c) := [[sprintf("audit_policy.%s", [c.guid]), object.get(input.audit_policy, c.guid, null), "dword", "bits", c.bits]] if c.kind == "auditpol"

_reads(c) := [] if not c.kind in {"reg", "reg_all", "ureg", "secedit", "auditpol"}

_wants_number(op, _) if op in {"ge", "ge_or_forever", "le", "le_not0", "range", "in", "bits"}

_wants_number(op, want) if {
	op in {"eq", "eq_or_absent", "ne"}
	is_number(want)
}

_wants_string(op, _) if op in {"nonempty", "has_all"}

_wants_string(op, want) if {
	op in {"eq", "ne"}
	is_string(want)
}

# a missing value is reported as found: null, not as a type problem
_type_problem(r) := sprintf("%s is not a number (got %s)", [r[0], type_name(r[1])]) if {
	_wants_number(r[3], r[4])
	r[2] in {"dword", "any"}
	not _empty(r[1])
	not is_number(_as(r[1], r[2]))
}

_type_problem(r) := sprintf("%s is not a string holding a number (got %s)", [r[0], type_name(r[1])]) if {
	_wants_number(r[3], r[4])
	r[2] == "sz"
	not _empty(r[1])
	not _digits(r[1])
}

_type_problem(r) := sprintf("%s is not a string (got %s)", [r[0], type_name(r[1])]) if {
	_wants_string(r[3], r[4])
	r[1] != null
	not is_string(r[1])
}

_type_problem(r) := sprintf("%s is not a list (got %s)", [r[0], type_name(r[1])]) if {
	r[3] == "set"
	r[1] != null
	not is_array(r[1])
}

_rights_problems(c) := [sprintf("secedit.privilege_rights.%s is not a list of SID strings (got %s)", [c.privilege, type_name(input.secedit.privilege_rights[c.privilege])])] if {
	c.kind == "rights"
	not _holders_typed(c.privilege)
}

_rights_problems(c) := [] if {
	c.kind == "rights"
	_holders_typed(c.privilege)
}

_rights_problems(c) := [] if c.kind != "rights"

_type_problems(c) := array.concat([_type_problem(r) | some r in _reads(c)], _rights_problems(c))

# appended to a failing row's finding: empty unless a value is of the wrong type for its setting
_type_note(c) := "" if count(_type_problems(c)) == 0

_type_note(c) := sprintf(" -- evidence: %s", [concat("; ", _type_problems(c))]) if count(_type_problems(c)) > 0

_why_not_assessed(c) := sprintf("input.%s was not collected (for registry_users: no S-1-5-21 user hive)", [INPUT_KEY[c.kind]]) if not _selector_undecided(c.profiles)

_why_not_assessed(c) := sprintf("%s, so the profile cannot place this recommendation", [concat("; ", _selector_problems(c.profiles))]) if _selector_undecided(c.profiles)

_section_report(section, controls) := r if {
	results := {cid: status(c) | some cid, c in controls}
	r := {
		"section": section.section,
		"name": section.name,
		"section_total_controls": section.section_total_controls,
		"results": results,
		"in_scope": [cid | some cid; s := results[cid]; s != "not_applicable"],
		"assessed": [cid | some cid; s := results[cid]; s in {"pass", "fail"}],
		"passed": [cid | some cid; s := results[cid]; s == "pass"],
		"failed": [cid | some cid; s := results[cid]; s == "fail"],
		"not_assessed": [cid | some cid; s := results[cid]; s == "not_assessed"],
		"missing_inputs": sort({INPUT_KEY[c.kind] |
			some cid
			c := controls[cid]
			results[cid] == "not_assessed"
			not _selector_undecided(c.profiles)
		}),
		"violations": array.concat(
			[sprintf("%s -- found: %s%s", [c.msg, _found(c), _type_note(c)]) | some cid; c := controls[cid]; results[cid] == "fail"],
			[sprintf("%s -- NOT ASSESSED: %s (counted as failed)", [c.msg, _why_not_assessed(c)]) |
				some cid
				c := controls[cid]
				results[cid] == "not_assessed"
			],
		),
	}
}

# ---------------------------------------------------------------------------------------------------------------
# Every section's rows, evaluated here. The sections read these rules rather than calling a function in this file:
# the repository's pre-commit hook runs `opa check` one file at a time, and a call to a function defined in
# another file does not type-check that way, while a reference to another package's rule does.
# ---------------------------------------------------------------------------------------------------------------

_sections := {
	"account_policies": data.cis_windows_10.account_policies.SECTION,
	"local_policies": data.cis_windows_10.local_policies.SECTION,
	"system_services": data.cis_windows_10.system_services.SECTION,
	"firewall": data.cis_windows_10.firewall.SECTION,
	"advanced_audit": data.cis_windows_10.advanced_audit.SECTION,
	"admin_templates_computer": data.cis_windows_10.admin_templates_computer.SECTION,
	"admin_templates_user": data.cis_windows_10.admin_templates_user.SECTION,
}

_tables := {
	"account_policies": data.cis_windows_10.account_policies.controls,
	"local_policies": data.cis_windows_10.local_policies.controls,
	"system_services": data.cis_windows_10.system_services.controls,
	"firewall": data.cis_windows_10.firewall.controls,
	"advanced_audit": data.cis_windows_10.advanced_audit.controls,
	"admin_templates_computer": data.cis_windows_10.admin_templates_computer.controls,
	"admin_templates_user": data.cis_windows_10.admin_templates_user.controls,
}

# A partial object: looking up one id (results["2.2.1"]) evaluates that row alone, which the per-recommendation
# tests rely on to stay fast; iterating it evaluates every row.
results[cid] := status(c) if {
	some t in _tables
	c := t[cid]
}

section_reports[name] := _section_report(_sections[name], _tables[name]) if some name, _ in _tables

attestation_in_scope_ids := {cid |
	some cid
	profiles := data.cis_windows_10.attestation.PROFILES[cid]
	in_scope(profiles)
}
