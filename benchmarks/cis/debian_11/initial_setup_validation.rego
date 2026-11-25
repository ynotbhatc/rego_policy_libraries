# METADATA
# title: "DERIVED from CIS Ubuntu Linux 20.04 LTS Benchmark v3.0.0 — applied to Debian 11 (provenance: see README) - Sections 1.2, 1.7, 1.8:..."
# custom:
#   class: security
#   framework: cis_debian_11
#   source: cis
#   domains: [linux, debian]
#   coverage:
#     checks: 34
#     cited: 22
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: report
#     guard: self
#     as_of: v2.5.0
package cis_debian_11.initial_setup

# DERIVED from CIS Ubuntu Linux 20.04 LTS Benchmark v3.0.0 — applied to Debian 11 (provenance: see README) - Sections 1.2, 1.7, 1.8: Initial System Setup

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

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

has_key(obj, k) if {
	_ = obj[k]
}

# Missing evidence fails closed: every fact below must be collected.
violations contains msg if {
	some k in ["enabled_repos", "gpg_keys", "grub_config_mode", "motd_owner", "issue_owner", "issue_net_owner"]
	not has_key(object.get(input, "initial_setup", {}), k)
	msg := sprintf("CIS 1.x: evidence missing — initial_setup.%s not collected", [k])
}

# a file that exists needs its mode collected
violations contains msg if {
	some f in ["motd", "issue", "issue_net"]
	input.initial_setup[sprintf("%s_exists", [f])] == true
	not has_key(input.initial_setup, sprintf("%s_mode", [f]))
	msg := sprintf("CIS 1.7.x: evidence missing — initial_setup.%s_mode not collected", [f])
}

violations contains msg if {
	input.initial_setup.gdm_installed == true
	input.initial_setup.gui_required == true
	input.initial_setup.gdm_screen_lock_enabled == true
	number_missing(["initial_setup", "gdm_idle_delay"])
	msg := "CIS 1.8.4: evidence missing — initial_setup.gdm_idle_delay not collected"
}

# CIS 1.2: Configure Software Updates (Ubuntu uses apt)

# CIS 1.2.1: package manager repositories must be explicitly configured
violations contains msg if {
	count(input.initial_setup.enabled_repos) == 0
	msg := "CIS 1.2.1: No apt package repositories are enabled"
}

# CIS 1.2.2: APT GPG keys must be explicitly configured
violations contains msg if {
	count(input.initial_setup.gpg_keys) == 0
	msg := "CIS 1.2.2: No GPG keys configured for apt package verification"
}

# CIS 1.3: Filesystem Integrity Checking (AIDE)
violations contains msg if {
	input.initial_setup.aide_installed == false
	msg := "CIS 1.3.1: AIDE is not installed"
}

violations contains msg if {
	input.initial_setup.aide_installed == true
	input.initial_setup.aide_cron_configured == false
	msg := "CIS 1.3.2: AIDE is not configured to run on a schedule (cron job missing)"
}

# CIS 1.4: Secure Boot Settings (GRUB)
violations contains msg if {
	input.initial_setup.grub_password_configured == false
	msg := "CIS 1.4.1: GRUB boot loader password is not configured"
}

violations contains msg if {
	not mode_within(input.initial_setup.grub_config_mode, "0600")
	msg := sprintf("CIS 1.4.2: GRUB configuration file has mode %s, should be 0400 or 0600", [input.initial_setup.grub_config_mode])
}

violations contains msg if {
	input.initial_setup.grub_owner_root == false
	msg := "CIS 1.4.2: GRUB configuration file is not owned by root"
}

# CIS 1.5: Additional Process Hardening
violations contains msg if {
	input.initial_setup.core_dumps_enabled == true
	msg := "CIS 1.5.1: Core dumps are not restricted (hard limit should be 0)"
}

violations contains msg if {
	input.initial_setup.aslr_enabled == false
	msg := "CIS 1.5.2: Address Space Layout Randomization (ASLR) is not enabled"
}

violations contains msg if {
	input.initial_setup.prelink_installed == true
	msg := "CIS 1.5.3: prelink is installed (disables ASLR effectiveness)"
}

violations contains msg if {
	input.initial_setup.ptrace_scope_restricted == false
	msg := "CIS 1.5.4: ptrace scope is not restricted (kernel.yama.ptrace_scope should be >= 1)"
}

# CIS 1.7: Command Line Warning Banners
violations contains msg if {
	input.initial_setup.motd_exists == false
	msg := "CIS 1.7.1: /etc/motd does not exist"
}

violations contains msg if {
	input.initial_setup.motd_exists == true
	not mode_within(input.initial_setup.motd_mode, "0644")
	msg := sprintf("CIS 1.7.1: /etc/motd has mode %s, should be 0644", [input.initial_setup.motd_mode])
}

violations contains msg if {
	input.initial_setup.motd_contains_sensitive_info == true
	msg := "CIS 1.7.1: /etc/motd contains sensitive system information"
}

violations contains msg if {
	input.initial_setup.issue_exists == false
	msg := "CIS 1.7.2: /etc/issue does not exist"
}

violations contains msg if {
	input.initial_setup.issue_exists == true
	not mode_within(input.initial_setup.issue_mode, "0644")
	msg := sprintf("CIS 1.7.2: /etc/issue has mode %s, should be 0644", [input.initial_setup.issue_mode])
}

violations contains msg if {
	input.initial_setup.issue_contains_sensitive_info == true
	msg := "CIS 1.7.2: /etc/issue contains sensitive system information"
}

violations contains msg if {
	input.initial_setup.issue_net_exists == false
	msg := "CIS 1.7.3: /etc/issue.net does not exist"
}

violations contains msg if {
	input.initial_setup.issue_net_exists == true
	not mode_within(input.initial_setup.issue_net_mode, "0644")
	msg := sprintf("CIS 1.7.3: /etc/issue.net has mode %s, should be 0644", [input.initial_setup.issue_net_mode])
}

violations contains msg if {
	input.initial_setup.issue_net_contains_sensitive_info == true
	msg := "CIS 1.7.3: /etc/issue.net contains sensitive system information"
}

violations contains msg if {
	input.initial_setup.motd_owner != "root"
	msg := sprintf("CIS 1.7.4: /etc/motd owned by %s, should be root", [input.initial_setup.motd_owner])
}

violations contains msg if {
	input.initial_setup.issue_owner != "root"
	msg := sprintf("CIS 1.7.5: /etc/issue owned by %s, should be root", [input.initial_setup.issue_owner])
}

violations contains msg if {
	input.initial_setup.issue_net_owner != "root"
	msg := sprintf("CIS 1.7.6: /etc/issue.net owned by %s, should be root", [input.initial_setup.issue_net_owner])
}

# CIS 1.8: GNOME Display Manager
violations contains msg if {
	input.initial_setup.gdm_installed == true
	input.initial_setup.server_environment == true
	input.initial_setup.gui_required == false
	msg := "CIS 1.8.1: GNOME Display Manager (GDM) installed on server without GUI requirement"
}

violations contains msg if {
	input.initial_setup.gdm_installed == true
	input.initial_setup.gui_required == true
	input.initial_setup.gdm_banner_configured == false
	msg := "CIS 1.8.2: GDM login banner is not configured"
}

violations contains msg if {
	input.initial_setup.gdm_installed == true
	input.initial_setup.gui_required == true
	input.initial_setup.gdm_screen_lock_enabled == false
	msg := "CIS 1.8.3: GDM automatic screen lock is not enabled"
}

violations contains msg if {
	input.initial_setup.gdm_installed == true
	input.initial_setup.gui_required == true
	input.initial_setup.gdm_screen_lock_enabled == true
	is_number(input.initial_setup.gdm_idle_delay)
	input.initial_setup.gdm_idle_delay > 900
	msg := sprintf("CIS 1.8.4: GDM idle delay is %d seconds, should be 900 or less", [input.initial_setup.gdm_idle_delay])
}

violations contains msg if {
	input.initial_setup.gdm_installed == true
	input.initial_setup.gui_required == true
	input.initial_setup.gdm_screen_lock_enabled == true
	not is_number(object.get(input, ["initial_setup", "gdm_idle_delay"], 0))
	msg := "CIS 1.8.4: evidence missing — initial_setup.gdm_idle_delay is not a number"
}

# ---------------------------------------------------------------------------
# Evidence rule: a yes/no fact is answered only by a JSON boolean. A missing fact, null, a string
# ("true", "false", "no") or a number is an evidence problem: the control fails and the finding names it.
# ---------------------------------------------------------------------------
flag_problem(path) := "not collected" if is_null(object.get(input, path, null))

flag_problem(path) := sprintf("is not a boolean (got %s)", [type_name(v)]) if {
	v := object.get(input, path, null)
	not is_null(v)
	not is_boolean(v)
}

flag_evidence(prefix, path) := sprintf("%s: evidence missing — %s %s", [prefix, concat(".", path), flag_problem(path)])

# a number that must be collected: missing and null are "not collected" (a wrong type is reported by the rule that reads it)
number_missing(path) if is_null(object.get(input, path, null))

# yes/no facts read unconditionally: [finding prefix, input path]
required_flags := [
	["CIS 1.3.1", ["initial_setup", "aide_installed"]],
	["CIS 1.4.1", ["initial_setup", "grub_password_configured"]],
	["CIS 1.4.2", ["initial_setup", "grub_owner_root"]],
	["CIS 1.5.1", ["initial_setup", "core_dumps_enabled"]],
	["CIS 1.5.2", ["initial_setup", "aslr_enabled"]],
	["CIS 1.5.3", ["initial_setup", "prelink_installed"]],
	["CIS 1.5.4", ["initial_setup", "ptrace_scope_restricted"]],
	["CIS 1.7.1", ["initial_setup", "motd_exists"]],
	["CIS 1.7.1", ["initial_setup", "motd_contains_sensitive_info"]],
	["CIS 1.7.2", ["initial_setup", "issue_exists"]],
	["CIS 1.7.2", ["initial_setup", "issue_contains_sensitive_info"]],
	["CIS 1.7.3", ["initial_setup", "issue_net_exists"]],
	["CIS 1.7.3", ["initial_setup", "issue_net_contains_sensitive_info"]],
]

violations contains msg if {
	some [prefix, path] in required_flags
	msg := flag_evidence(prefix, path)
}

# Facts judged only where they apply. "Does not apply" is the gate fact sent as the boolean false
# (gdm_installed: false on a host without GDM); a missing gate fact is an evidence problem, reported
# by required_flags.
gated_flags := [
	["CIS 1.3.2", ["initial_setup", "aide_cron_configured"], [["initial_setup", "aide_installed"]]],
	["CIS 1.8.1", ["initial_setup", "server_environment"], [["initial_setup", "gdm_installed"]]],
	["CIS 1.8.1", ["initial_setup", "gui_required"], [["initial_setup", "gdm_installed"]]],
	["CIS 1.8.2", ["initial_setup", "gdm_banner_configured"], [["initial_setup", "gdm_installed"], ["initial_setup", "gui_required"]]],
	["CIS 1.8.3", ["initial_setup", "gdm_screen_lock_enabled"], [["initial_setup", "gdm_installed"], ["initial_setup", "gui_required"]]],
]

# yes/no facts read only when every gate fact is the boolean true: [finding prefix, input path, gate paths]
violations contains msg if {
	some [prefix, path, gates] in gated_flags
	every gate in gates {
		object.get(input, gate, null) == true
	}
	msg := flag_evidence(prefix, path)
}

violations contains msg if {
	msg := flag_evidence("CIS 1.8.1", ["initial_setup", "gdm_installed"])
}

report := {
	"compliant": compliant,
	"total_violations": count(violations),
	"violations": violations,
	"controls_checked": 24,
	"section": "1.2-1.8 Initial System Setup",
	"benchmark": "DERIVED from CIS Ubuntu Linux 20.04 LTS Benchmark v3.0.0 (applied to Debian 11)",
}
