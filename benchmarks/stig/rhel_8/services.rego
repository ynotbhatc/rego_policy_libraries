# METADATA
# title: "DISA STIG for RHEL 8 - Services Module"
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
package stig.rhel_8.services

# DISA STIG for RHEL 8 - Services Module
# STIG Version: V2R8 | Released: 01 Jul 2026
# Rule ids, vuln ids, severities and titles stamped from the October 2026 SRG-STIG library XCCDF on 2026-11-10
# (tools/stig_generators/stamp_catalog.py); each finding is keyed on the fact its logic checks.

import rego.v1

default compliant := false

service_disabled(svc) if input.services[svc] == "inactive"
service_disabled(svc) if input.services[svc] == "masked"

# A service or package missing from the collected inventory counts as disabled / not
# installed only when an inventory was actually collected. An absent or empty
# inventory is missing evidence, not a pass.
service_disabled(svc) if {
	count(input.services) > 0
	not input.services[svc]
}

pkg_absent(pkg) if input.packages[pkg] == false

pkg_absent(pkg) if {
	count(input.packages) > 0
	not input.packages[pkg]
}

# =============================================================================
# CAT I
# =============================================================================

# =============================================================================
# CAT I - HIGH SEVERITY
# =============================================================================

# RHEL-08-040000 | V-230487 | CAT I - telnet-server must not be installed
default no_telnet_server := false

no_telnet_server if pkg_absent("telnet-server")

status_rhel_08_040000 := "Not_a_Finding" if no_telnet_server

else := "Open"

finding_rhel_08_040000 := {
	"vuln_id": "V-230487",
	"stig_id": "RHEL-08-040000",
	"severity": "CAT I",
	"rule_title": "RHEL 8 must not have the telnet-server package installed.",
	"status": status_rhel_08_040000,
	"fix_text": "dnf remove telnet-server -y",
}

# RHEL-08-040190 | V-230533 | CAT I - tftp-server must not be installed
default no_tftp_server := false

no_tftp_server if pkg_absent("tftp-server")

status_rhel_08_040190 := "Not_a_Finding" if no_tftp_server

else := "Open"

finding_rhel_08_040190 := {
	"vuln_id": "V-230533",
	"stig_id": "RHEL-08-040190",
	"severity": "CAT I",
	"rule_title": "The Trivial File Transfer Protocol (TFTP) server package must not be installed if not required for RHEL 8 operational support.",
	"status": status_rhel_08_040190,
	"fix_text": "dnf remove tftp-server -y",
}

# =============================================================================
# CAT II - MEDIUM SEVERITY
# =============================================================================

# RHEL-08-040070 | V-230502 | CAT II - autofs must be disabled
default autofs_disabled := false

autofs_disabled if service_disabled("autofs")

status_rhel_08_040070 := "Not_a_Finding" if autofs_disabled

else := "Open"

finding_rhel_08_040070 := {
	"vuln_id": "V-230502",
	"stig_id": "RHEL-08-040070",
	"severity": "CAT II",
	"rule_title": "The RHEL 8 file system automounter must be disabled.",
	"status": status_rhel_08_040070,
	"fix_text": "systemctl disable --now autofs",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

cat_i_findings := [
	finding_rhel_08_040000,
	finding_rhel_08_040190,
]

cat_ii_findings := [finding_rhel_08_040070]

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
	"module": "services",
	"total_findings": count(findings),
	"open_findings": count(violations),
	"cat_i_open": count(open_cat_i),
	"findings": findings,
	"compliant": compliant,
	"cat_i_compliant": cat_i_compliant,
}
