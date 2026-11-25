# METADATA
# title: "DISA STIG for RHEL 8 - Configuration Management Module"
# custom:
#   class: security
#   framework: stig_rhel_8
#   source: disa
#   domains: [linux, rhel]
#   coverage:
#     checks: 17
#     cited: 16
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package stig.rhel_8.configuration_management

# DISA STIG for RHEL 8 - Configuration Management Module
# STIG Version: V2R9 | Released: 30 Sep 2026
# Rule ids, vuln ids, severities and titles stamped from the October 2026 SRG-STIG library XCCDF on 2026-11-10
# (tools/stig_generators/stamp_catalog.py); each finding is keyed on the fact its logic checks. Re-checked
# 2026-11-21 against DISA's standalone U_RHEL_8_V2R9_STIG.zip XCCDF and its revision history.
# Covers: System settings, kernel params, banners, SELinux, GRUB

import rego.v1

default compliant := false

# a fact the collector supplied (any non-null value)
_collected(path) if object.get(input, path, null) != null

# the value at path as a trimmed string; undefined unless it is a string
_str(path) := trim_space(v) if {
	v := object.get(input, path, null)
	is_string(v)
}

# the value at path as a number: a whole JSON number only; undefined otherwise. A number sent as text ("3072") is
# not read: the collector converts the configured text, and the finding says "evidence invalid"
_num(path) := v if {
	v := object.get(input, path, null)
	_whole_number(v)
}

_whole_number(v) if {
	is_number(v)
	v == floor(v)
}

# what was received where a whole JSON number is required: the JSON type, or "a fraction"
_got(v) := "a fraction" if is_number(v)

_got(v) := type_name(v) if not is_number(v)

# text with every run of whitespace collapsed to one space and the ends trimmed
_squash(s) := regex.replace(trim_space(s), `\s+`, " ")

# the Standard Mandatory DoW Notice and Consent Banner, from the RHEL-08-010060 check text (whitespace-normalised)
dod_banner := "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions: -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations. -At any time, the USG may inspect and seize data stored on this IS. -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose. -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy. -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

# the seven hash algorithms the RHEL-08-010020 check text requires in CURRENT.pol
fips_policy_hashes := {"SHA2-256", "SHA2-384", "SHA2-512", "SHA2-224", "SHA3-256", "SHA3-384", "SHA3-512"}

# a hash the RHEL-08-010020 check rejects: anything with SHA1, or a digest size below 224
_weak_hash(h) if not is_string(h)

_weak_hash(h) if {
	is_string(h)
	contains(upper(h), "SHA1")
}

_weak_hash(h) if {
	is_string(h)
	m := regex.find_all_string_submatch_n(`-([0-9]+)$`, h, 1)
	bits := to_number(m[0][1])
	bits < 224
}

# =============================================================================
# CAT I - HIGH SEVERITY
# =============================================================================

# =============================================================================
# CAT I - HIGH SEVERITY
# =============================================================================

# RHEL-08-010020 | V-230223 | CAT I - systemwide crypto policy FIPS (V2R9: no subpolicies)
# update-crypto-policies --show must be exactly FIPS (V2R9 removed the subpolicy allowance); CURRENT.pol hash must
# include the seven listed algorithms, none with SHA1 or below 224 bits; min_rsa_size must be at least 2048.
missing_rhel_08_010020 := [concat(".", p) |
	some p in [["crypto_policy"], ["crypto_policy_state", "hash"], ["crypto_policy_state", "min_rsa_size"]]
	not _collected(p)
]

invalid_rhel_08_010020 := [sprintf("crypto_policy_state.min_rsa_size is not a number (got %s)", [_got(v)]) |
	v := object.get(input, ["crypto_policy_state", "min_rsa_size"], null)
	v != null
	not _whole_number(v)
]

default crypto_policy_fips := false

crypto_policy_fips if {
	count(missing_rhel_08_010020) == 0
	_str(["crypto_policy"]) == "FIPS"
	hashes := input.crypto_policy_state.hash
	is_array(hashes)
	every h in fips_policy_hashes {
		h in hashes
	}
	count([h | some h in hashes; _weak_hash(h)]) == 0
	_num(["crypto_policy_state", "min_rsa_size"]) >= 2048
}

status_rhel_08_010020 := "Not_a_Finding" if crypto_policy_fips

else := "Open"

detail_rhel_08_010020 := "RHEL-08-010020: Not_a_Finding" if crypto_policy_fips

else := sprintf("%s: evidence missing — %s not collected", ["RHEL-08-010020", concat(", ", missing_rhel_08_010020)]) if count(missing_rhel_08_010020) > 0

else := sprintf("%s: evidence invalid — %s", ["RHEL-08-010020", concat(", ", invalid_rhel_08_010020)]) if count(invalid_rhel_08_010020) > 0

else := "RHEL-08-010020: check failed — crypto policy must be FIPS (no subpolicy), CURRENT.pol hash must include SHA2-256 SHA2-384 SHA2-512 SHA2-224 SHA3-256 SHA3-384 SHA3-512 with nothing SHA1 or below 224 bits, min_rsa_size at least 2048"

finding_rhel_08_010020 := {
	"vuln_id": "V-230223",
	"stig_id": "RHEL-08-010020",
	"severity": "CAT I",
	"rule_title": "RHEL 8 must implement a FIPS 140-3-compliant systemwide cryptographic policy.",
	"status": status_rhel_08_010020,
	"detail": detail_rhel_08_010020,
	"fix_text": "Set the FIPS policy: update-crypto-policies --set FIPS, then reboot",
}

# RHEL-08-010293 | V-288829 | CAT I - OpenSSL includes the crypto-policies back-end (added in V2R9)
# the lines of /etc/pki/tls/openssl.cnf must include /etc/crypto-policies/back-ends/opensslcnf.config
missing_rhel_08_010293 := [concat(".", p) | some p in [["openssl_cnf", "lines"]]; not is_array(object.get(input, p, null))]

default openssl_includes_crypto_policy := false

openssl_includes_crypto_policy if {
	count(missing_rhel_08_010293) == 0
	some l in input.openssl_cnf.lines
	is_string(l)
	regex.match(`^\s*\.include\s*=?\s*/etc/crypto-policies/back-ends/opensslcnf\.config\s*$`, l)
}

status_rhel_08_010293 := "Not_a_Finding" if openssl_includes_crypto_policy

else := "Open"

detail_rhel_08_010293 := "RHEL-08-010293: Not_a_Finding" if openssl_includes_crypto_policy

else := sprintf("%s: evidence missing — %s not collected", ["RHEL-08-010293", concat(", ", missing_rhel_08_010293)]) if count(missing_rhel_08_010293) > 0

else := "RHEL-08-010293: check failed — /etc/pki/tls/openssl.cnf must include /etc/crypto-policies/back-ends/opensslcnf.config (uncommented)"

finding_rhel_08_010293 := {
	"vuln_id": "V-288829",
	"stig_id": "RHEL-08-010293",
	"severity": "CAT I",
	"rule_title": "RHEL 8 must implement DoW-approved encryption in the OpenSSL package.",
	"status": status_rhel_08_010293,
	"detail": detail_rhel_08_010293,
	"fix_text": "Add .include = /etc/crypto-policies/back-ends/opensslcnf.config to /etc/pki/tls/openssl.cnf",
}

# RHEL-08-010150 | V-230235 | CAT I - GRUB password required
default grub_password := false

grub_password if input.grub_config.password_set == true

status_rhel_08_010150 := "Not_a_Finding" if grub_password

else := "Open"

finding_rhel_08_010150 := {
	"vuln_id": "V-230235",
	"stig_id": "RHEL-08-010150",
	"severity": "CAT I",
	"rule_title": "RHEL 8 operating systems booted with a BIOS must require authentication upon booting into single-user and maintenance modes.",
	"status": status_rhel_08_010150,
	"fix_text": "Configure bootloader password: grub2-setpassword",
}

# RHEL-08-040170 | V-230529 | CAT I - Ctrl-Alt-Delete must be disabled
default ctrl_alt_del := false

ctrl_alt_del if input.services["ctrl-alt-del.target"] == "masked"

status_rhel_08_040170 := "Not_a_Finding" if ctrl_alt_del

else := "Open"

finding_rhel_08_040170 := {
	"vuln_id": "V-230529",
	"stig_id": "RHEL-08-040170",
	"severity": "CAT I",
	"rule_title": "The x86 Ctrl-Alt-Delete key sequence must be disabled on RHEL 8.",
	"status": status_rhel_08_040170,
	"fix_text": "Disable Ctrl-Alt-Del: systemctl mask ctrl-alt-del.target",
}

# =============================================================================
# CAT II - MEDIUM SEVERITY
# =============================================================================

# RHEL-08-010170 | V-230240 | CAT II - SELinux must be enforcing
default selinux_enforcing := false

selinux_enforcing if input.selinux.status == "enforcing"

status_rhel_08_010170 := "Not_a_Finding" if selinux_enforcing

else := "Open"

finding_rhel_08_010170 := {
	"vuln_id": "V-230240",
	"stig_id": "RHEL-08-010170",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must use a Linux Security Module configured to enforce limits on system services.",
	"status": status_rhel_08_010170,
	"fix_text": "Set SELINUX=enforcing in /etc/selinux/config",
}

# RHEL-08-010450 | V-230282 | CAT II - SELinux policy must be targeted
default selinux_targeted := false

selinux_targeted if input.selinux.policy == "targeted"

status_rhel_08_010450 := "Not_a_Finding" if selinux_targeted

else := "Open"

finding_rhel_08_010450 := {
	"vuln_id": "V-230282",
	"stig_id": "RHEL-08-010450",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must enable the SELinux targeted policy.",
	"status": status_rhel_08_010450,
	"fix_text": "Set SELINUXTYPE=targeted in /etc/selinux/config",
}

# RHEL-08-010090 | V-230229 | CAT II - DoD Root CA must be installed
default dod_root_ca := false

dod_root_ca if input.certificates.dod_root_ca_installed == true

status_rhel_08_010090 := "Not_a_Finding" if dod_root_ca

else := "Open"

finding_rhel_08_010090 := {
	"vuln_id": "V-230229",
	"stig_id": "RHEL-08-010090",
	"severity": "CAT II",
	"rule_title": "RHEL 8, for PKI-based authentication, must validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor.",
	"status": status_rhel_08_010090,
	"fix_text": "Install DoW Root CAs: trust anchor --store DoD_PKE_CA_chain.pem",
}

# RHEL-08-010060 | V-230227 | CAT II - /etc/issue carries the DoW banner exactly
# (until 2026-11-21 this block carried RHEL-08-010040, the ssh banner rule; the two ids were crossed)
missing_rhel_08_010060 := [concat(".", p) | some p in [["login_banner", "issue"]]; not _collected(p)]

default login_banner := false

login_banner if {
	count(missing_rhel_08_010060) == 0
	s := _str(["login_banner", "issue"])
	_squash(s) == dod_banner
}

status_rhel_08_010060 := "Not_a_Finding" if login_banner

else := "Open"

detail_rhel_08_010060 := "RHEL-08-010060: Not_a_Finding" if login_banner

else := sprintf("%s: evidence missing — %s not collected", ["RHEL-08-010060", concat(", ", missing_rhel_08_010060)]) if count(missing_rhel_08_010060) > 0

else := "RHEL-08-010060: check failed — /etc/issue must contain exactly the Standard Mandatory DoW Notice and Consent Banner (whitespace aside)"

finding_rhel_08_010060 := {
	"vuln_id": "V-230227",
	"stig_id": "RHEL-08-010060",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must display the Standard Mandatory DoW Notice and Consent Banner before granting local or remote access to the system via a command line user logon.",
	"status": status_rhel_08_010060,
	"detail": detail_rhel_08_010060,
	"fix_text": "Replace /etc/issue with the Standard Mandatory DoW Notice and Consent Banner text",
}

# RHEL-08-010430 | V-230280 | CAT II - ASLR must be enabled
default aslr_enabled := false

aslr_enabled if input.kernel_params["kernel.randomize_va_space"] == "2"

status_rhel_08_010430 := "Not_a_Finding" if aslr_enabled

else := "Open"

finding_rhel_08_010430 := {
	"vuln_id": "V-230280",
	"stig_id": "RHEL-08-010430",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must implement address space layout randomization (ASLR) to protect its memory from unauthorized code execution.",
	"status": status_rhel_08_010430,
	"fix_text": "Set kernel.randomize_va_space=2 in /etc/sysctl.d/99-stig.conf",
}

# RHEL-08-040080 | V-230503 | CAT II - USB storage must be disabled
default usb_storage_disabled := false

usb_storage_disabled if input.kernel_modules["usb-storage"].blacklisted == true
usb_storage_disabled if input.kernel_modules["usb-storage"].status == "disabled"

status_rhel_08_040080 := "Not_a_Finding" if usb_storage_disabled

else := "Open"

finding_rhel_08_040080 := {
	"vuln_id": "V-230503",
	"stig_id": "RHEL-08-040080",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must be configured to disable USB mass storage.",
	"status": status_rhel_08_040080,
	"fix_text": "Disable USB storage: echo 'install usb-storage /bin/false' >> /etc/modprobe.d/usb-storage.conf",
}

# RHEL-08-010359 | V-251710 | CAT II - AIDE must be installed
default aide_installed := false

aide_installed if input.packages.aide == true

status_rhel_08_010359 := "Not_a_Finding" if aide_installed

else := "Open"

finding_rhel_08_010359 := {
	"vuln_id": "V-251710",
	"stig_id": "RHEL-08-010359",
	"severity": "CAT II",
	"rule_title": "The RHEL 8 operating system must use a file integrity tool to verify correct operation of all security functions.",
	"status": status_rhel_08_010359,
	"fix_text": "Install AIDE: dnf install aide -y && aide --init",
}

# RHEL-08-010360 | V-230263 | CAT II - AIDE cron job must exist
default aide_cron := false

aide_cron if input.aide_config.cron_job == true

status_rhel_08_010360 := "Not_a_Finding" if aide_cron

else := "Open"

finding_rhel_08_010360 := {
	"vuln_id": "V-230263",
	"stig_id": "RHEL-08-010360",
	"severity": "CAT II",
	"rule_title": "The RHEL 8 file integrity tool must notify the system administrator when changes to the baseline configuration or anomalies in the operation of any security functions are discovered within an organizationally defined frequency.",
	"status": status_rhel_08_010360,
	"fix_text": "Configure AIDE cron job: echo '0 5 * * * root /usr/sbin/aide --check' > /etc/cron.d/aide",
}

# RHEL-08-010543 | V-230295 | CAT II - /tmp must be separate partition
default tmp_separate := false

tmp_separate if {
	some mount in input.filesystem_mounts
	mount.mount == "/tmp"
}

status_rhel_08_010543 := "Not_a_Finding" if tmp_separate

else := "Open"

finding_rhel_08_010543 := {
	"vuln_id": "V-230295",
	"stig_id": "RHEL-08-010543",
	"severity": "CAT II",
	"rule_title": "A separate RHEL 8 filesystem must be used for the /tmp directory.",
	"status": status_rhel_08_010543,
	"fix_text": "Configure /tmp as a separate partition",
}

# =============================================================================
# CAT III - LOW SEVERITY
# =============================================================================

# RHEL-08-010375 | V-230269 | CAT III - dmesg restrict must be 1
default dmesg_restrict := false

dmesg_restrict if input.kernel_params["kernel.dmesg_restrict"] == "1"

status_rhel_08_010375 := "Not_a_Finding" if dmesg_restrict

else := "Open"

finding_rhel_08_010375 := {
	"vuln_id": "V-230269",
	"stig_id": "RHEL-08-010375",
	"severity": "CAT III",
	"rule_title": "RHEL 8 must restrict access to the kernel message buffer.",
	"status": status_rhel_08_010375,
	"fix_text": "Set kernel.dmesg_restrict=1 in /etc/sysctl.d/99-stig.conf",
}

# RHEL-08-010541 | V-230293 | CAT III - /var/log must be separate partition
default var_log_separate := false

var_log_separate if {
	some mount in input.filesystem_mounts
	mount.mount == "/var/log"
}

status_rhel_08_010541 := "Not_a_Finding" if var_log_separate

else := "Open"

finding_rhel_08_010541 := {
	"vuln_id": "V-230293",
	"stig_id": "RHEL-08-010541",
	"severity": "CAT III",
	"rule_title": "RHEL 8 must use a separate file system for /var/log.",
	"status": status_rhel_08_010541,
	"fix_text": "Configure /var/log as a separate partition",
}

# RHEL-08-010542 | V-230294 | CAT III - /var/log/audit must be separate
default var_log_audit_separate := false

var_log_audit_separate if {
	some mount in input.filesystem_mounts
	mount.mount == "/var/log/audit"
}

status_rhel_08_010542 := "Not_a_Finding" if var_log_audit_separate

else := "Open"

finding_rhel_08_010542 := {
	"vuln_id": "V-230294",
	"stig_id": "RHEL-08-010542",
	"severity": "CAT III",
	"rule_title": "RHEL 8 must use a separate file system for the system audit data path.",
	"status": status_rhel_08_010542,
	"fix_text": "Configure /var/log/audit as a separate partition",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

cat_i_findings := [
	finding_rhel_08_010020,
	finding_rhel_08_010293,
	finding_rhel_08_010150,
	finding_rhel_08_040170,
]

cat_ii_findings := [
	finding_rhel_08_010170,
	finding_rhel_08_010450,
	finding_rhel_08_010090,
	finding_rhel_08_010060,
	finding_rhel_08_010430,
	finding_rhel_08_040080,
	finding_rhel_08_010359,
	finding_rhel_08_010360,
	finding_rhel_08_010543,
]

cat_iii_findings := [
	finding_rhel_08_010375,
	finding_rhel_08_010541,
	finding_rhel_08_010542,
]

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
	"module": "configuration_management",
	"total_findings": count(findings),
	"open_findings": count(violations),
	"cat_i_open": count(open_cat_i),
	"findings": findings,
	"compliant": compliant,
	"cat_i_compliant": cat_i_compliant,
}
