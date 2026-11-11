# METADATA
# title: "DISA STIG for RHEL 8 - File Permissions Module"
# custom:
#   class: security
#   framework: stig_rhel_8
#   source: disa
#   domains: [linux, rhel]
#   coverage:
#     checks: 4
#     cited: 3
#     density: section
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package stig.rhel_8.file_permissions

# DISA STIG for RHEL 8 - File Permissions Module
# STIG Version: V2R8 | Released: 01 Jul 2026
# Rule ids, vuln ids, severities and titles stamped from the October 2026 SRG-STIG library XCCDF on 2026-11-10
# (tools/stig_generators/stamp_catalog.py); each finding is keyed on the fact its logic checks.

import rego.v1

default compliant := false

# Parse an octal permission string ("644", "0644", "0o644") to an integer; undefined if not octal.
octal(s) := n if {
	t := trim_prefix(lower(trim_space(sprintf("%v", [s]))), "0o")
	regex.match(`^[0-7]{1,4}$`, t)
	p := concat("", [substring("0000", 0, 4 - count(t)), t])
	ds := [to_number(substring(p, i, 1)) | some i in numbers.range(0, 3)]
	n := ((ds[0] * 512) + (ds[1] * 64)) + ((ds[2] * 8) + ds[3])
}

# true when mode grants nothing beyond max (both octal strings)
mode_within(mode, max) if bits.and(octal(mode), bits.and(bits.negate(octal(max)), 4095)) == 0

# =============================================================================
# CAT I
# =============================================================================

# Offender lists: an absent list is missing evidence (no collector emits file_permissions.*),
# so a rule only passes when the list is present and empty.

# =============================================================================
# CAT II - MEDIUM SEVERITY
# =============================================================================

# RHEL-08-010780 | V-230326 | CAT II - No unowned files
default no_unowned := false

no_unowned if count(input.file_permissions.unowned_files) == 0

status_rhel_08_010780 := "Not_a_Finding" if no_unowned

else := "Open"

finding_rhel_08_010780 := {
	"vuln_id": "V-230326",
	"stig_id": "RHEL-08-010780",
	"severity": "CAT II",
	"rule_title": "All RHEL 8 local files and directories must have a valid owner.",
	"status": status_rhel_08_010780,
	"fix_text": "find / -nouser -xdev",
}

# RHEL-08-010330 | V-230260 | CAT II - Library files permissions 0755
default lib_perms := false

lib_perms if input.file_permissions.library_files_ok == true

status_rhel_08_010330 := "Not_a_Finding" if lib_perms

else := "Open"

finding_rhel_08_010330 := {
	"vuln_id": "V-230260",
	"stig_id": "RHEL-08-010330",
	"severity": "CAT II",
	"rule_title": "RHEL 8 library files must have mode 755 or less permissive.",
	"status": status_rhel_08_010330,
	"fix_text": "find /lib /lib64 /usr/lib -perm /022 -exec chmod 755 {} \\;",
}

# RHEL-08-010730 | V-230321 | CAT II - Home directory permissions
default home_perms := false

home_perms if count(input.file_permissions.insecure_home_dirs) == 0

status_rhel_08_010730 := "Not_a_Finding" if home_perms

else := "Open"

finding_rhel_08_010730 := {
	"vuln_id": "V-230321",
	"stig_id": "RHEL-08-010730",
	"severity": "CAT II",
	"rule_title": "All RHEL 8 local interactive user home directories must have mode 0750 or less permissive.",
	"status": status_rhel_08_010730,
	"fix_text": "chmod 0750 /home/<username>",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

# No CAT I rule in this module. array.concat rather than the literal `[]`: OPA >= 1.22 types a literal
# empty array as having no members and rejects iterating it (scripts/check_per_file_load.py).
cat_i_findings := array.concat([], [])

cat_ii_findings := [
	finding_rhel_08_010780,
	finding_rhel_08_010330,
	finding_rhel_08_010730,
]

# No CAT III rule in this module. array.concat rather than the literal `[]`: OPA >= 1.22 types a literal
# empty array as having no members and rejects iterating it (scripts/check_per_file_load.py).
cat_iii_findings := array.concat([], [])

findings := array.concat(cat_i_findings, array.concat(cat_ii_findings, cat_iii_findings))

violations contains finding.stig_id if {
	some finding in findings
	finding.status == "Open"
}

open_cat_i contains f if {
	some f in cat_i_findings
	f.status == "Open"
}

# `compliant`: no open finding at ANY category (CAT I, II or III).
# `cat_i_compliant`: the former CAT-I-only meaning, for gating on the critical subset.
default cat_i_compliant := false

open_all_findings := [f | some f in findings; f.status == "Open"]

compliant if {
	count(open_all_findings) == 0
}

cat_i_compliant if {
	count(open_cat_i) == 0
}

compliance_report := {
	"module": "file_permissions",
	"total_findings": count(findings),
	"open_findings": count(violations),
	"cat_i_open": count(open_cat_i),
	"findings": findings,
	"compliant": compliant,
	"cat_i_compliant": cat_i_compliant,
}
