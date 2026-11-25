# METADATA
# title: "DERIVED from CIS Ubuntu Linux 20.04 LTS Benchmark v3.0.0 — applied to Debian 11 (provenance: see README) - Sections 1.3-1.5: Boot..."
# custom:
#   class: security
#   framework: cis_debian_11
#   source: cis
#   domains: [linux, debian]
#   coverage:
#     checks: 25
#     cited: 11
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: report
#     guard: self
#     as_of: v2.4.2
package cis_debian_11.boot_security

# DERIVED from CIS Ubuntu Linux 20.04 LTS Benchmark v3.0.0 — applied to Debian 11 (provenance: see README) - Sections 1.3-1.5: Boot Security and Process Hardening

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

violations := array.concat(
	array.concat([v | some v in aide_violations], [v | some v in grub_violations]),
	array.concat([v | some v in process_hardening_violations], [v | some v in apparmor_boot_violations]),
)

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

# CIS 1.3.1: AIDE installed
aide_violations contains msg if {
	input.aide.installed == false
	msg := "CIS 1.3.1: AIDE (Advanced Intrusion Detection Environment) is not installed"
}

# CIS 1.3.2: AIDE scheduled
aide_violations contains msg if {
	input.aide.installed == true
	not aide_scheduled
	some key in aide_schedule_facts
	input.aide[key] == false
	msg := "CIS 1.3.2: AIDE is not scheduled to run regularly (no cron job or systemd timer)"
}

aide_violations contains msg if {
	input.aide.installed == true
	input.aide.database_exists == false
	msg := "CIS 1.3.1: AIDE database has not been initialized (run aideinit)"
}

# CIS 1.4.1: GRUB boot loader password
grub_violations contains msg if {
	input.grub.password_configured == false
	msg := "CIS 1.4.1: GRUB boot loader password is not configured"
}

# CIS 1.4.2: GRUB config file permissions
grub_violations contains msg if {
	not has_key(object.get(input, "grub", {}), "config_mode")
	msg := "CIS 1.4.2: evidence missing — grub.config_mode not collected"
}

grub_violations contains msg if {
	mode := input.grub.config_mode
	not mode_within(mode, "0600")
	msg := sprintf("CIS 1.4.2: GRUB configuration file has mode %s, should be 0400 or 0600", [mode])
}

grub_violations contains msg if {
	not has_key(object.get(input, "grub", {}), "config_owner")
	msg := "CIS 1.4.2: evidence missing — grub.config_owner not collected"
}

grub_violations contains msg if {
	input.grub.config_owner != "root"
	msg := sprintf("CIS 1.4.2: GRUB configuration file is owned by %s, should be root", [input.grub.config_owner])
}

# CIS 1.4.3: Single user mode authentication
grub_violations contains msg if {
	input.grub.sulogin_configured == false
	msg := "CIS 1.4.3: Single user mode does not require authentication (sulogin not configured)"
}

has_key(obj, k) if {
	_ = obj[k]
}

# CIS 1.5: evidence for each process-hardening fact must be collected
process_hardening_violations contains msg if {
	some k in ["fs_suid_dumpable"]
	not has_key(object.get(input, "process_hardening", {}), k)
	msg := sprintf("CIS 1.5: evidence missing — process_hardening.%s not collected", [k])
}

# CIS 1.5.1: Core dumps restricted
process_hardening_violations contains msg if {
	input.process_hardening.core_dumps_enabled == true
	msg := "CIS 1.5.1: Core dumps are not restricted (/etc/security/limits.conf * hard core 0 missing)"
}

process_hardening_violations contains msg if {
	v := input.process_hardening.fs_suid_dumpable
	sprintf("%v", [v]) != "0"
	msg := sprintf("CIS 1.5.1: fs.suid_dumpable is %v, should be 0", [v])
}

# CIS 1.5.2: ASLR enabled
process_hardening_violations contains msg if {
	input.process_hardening.aslr_enabled == false
	msg := "CIS 1.5.2: Address Space Layout Randomization (ASLR) is not enabled (kernel.randomize_va_space != 2)"
}

# CIS 1.5.3: prelink disabled
process_hardening_violations contains msg if {
	input.process_hardening.prelink_installed == true
	msg := "CIS 1.5.3: prelink is installed - remove it as it can reduce ASLR effectiveness"
}

# CIS 1.5.4: ptrace scope
process_hardening_violations contains msg if {
	input.process_hardening.ptrace_scope_restricted == false
	msg := "CIS 1.5.4: ptrace scope is not restricted (kernel.yama.ptrace_scope should be >= 1)"
}

# AppArmor boot configuration (Ubuntu-specific)
apparmor_boot_violations contains msg if {
	input.apparmor.bootloader_enabled == false
	msg := "CIS 1.6.1.2: AppArmor is not enabled in bootloader configuration"
}

apparmor_boot_violations contains msg if {
	input.apparmor.bootloader_enabled == true
	not contains(input.apparmor.grub_cmdline, "security=apparmor")
	msg := "CIS 1.6.1.2: AppArmor security= parameter not set in bootloader"
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

# yes/no facts read unconditionally: [finding prefix, input path]
required_flags_aide_violations := [
	["CIS 1.3.1", ["aide", "installed"]],
]

aide_violations contains msg if {
	some [prefix, path] in required_flags_aide_violations
	msg := flag_evidence(prefix, path)
}

# yes/no facts read unconditionally: [finding prefix, input path]
required_flags_grub_violations := [
	["CIS 1.4.1", ["grub", "password_configured"]],
	["CIS 1.4.3", ["grub", "sulogin_configured"]],
]

grub_violations contains msg if {
	some [prefix, path] in required_flags_grub_violations
	msg := flag_evidence(prefix, path)
}

# yes/no facts read unconditionally: [finding prefix, input path]
required_flags_process_hardening_violations := [
	["CIS 1.5.1", ["process_hardening", "core_dumps_enabled"]],
	["CIS 1.5.2", ["process_hardening", "aslr_enabled"]],
	["CIS 1.5.3", ["process_hardening", "prelink_installed"]],
	["CIS 1.5.4", ["process_hardening", "ptrace_scope_restricted"]],
]

process_hardening_violations contains msg if {
	some [prefix, path] in required_flags_process_hardening_violations
	msg := flag_evidence(prefix, path)
}

# yes/no facts read unconditionally: [finding prefix, input path]
required_flags_apparmor_boot_violations := [
	["CIS 1.6.1.2", ["apparmor", "bootloader_enabled"]],
]

apparmor_boot_violations contains msg if {
	some [prefix, path] in required_flags_apparmor_boot_violations
	msg := flag_evidence(prefix, path)
}

# AIDE schedule and database are judged only on a host where AIDE is installed (aide.installed is the boolean true)
gated_flags := [["CIS 1.3.1", ["aide", "database_exists"], [["aide", "installed"]]]]

# 1.3.2 is met by a cron job or by a systemd timer: one boolean true is the answer, and the other fact
# may then be left out. A fact that is sent must still be a boolean, and with neither true each fact
# that was not collected is named.
aide_schedule_facts := ["cron_configured", "systemd_timer_configured"]

aide_scheduled if {
	some key in aide_schedule_facts
	input.aide[key] == true
}

aide_violations contains msg if {
	input.aide.installed == true
	some key in aide_schedule_facts
	v := object.get(input, ["aide", key], null)
	not is_null(v)
	not is_boolean(v)
	msg := flag_evidence("CIS 1.3.2", ["aide", key])
}

aide_violations contains msg if {
	input.aide.installed == true
	not aide_scheduled
	some key in aide_schedule_facts
	is_null(object.get(input, ["aide", key], null))
	msg := flag_evidence("CIS 1.3.2", ["aide", key])
}

# yes/no facts read only when every gate fact is the boolean true: [finding prefix, input path, gate paths]
aide_violations contains msg if {
	some [prefix, path, gates] in gated_flags
	every gate in gates {
		object.get(input, gate, null) == true
	}
	msg := flag_evidence(prefix, path)
}

# the kernel command line is what 1.6.1.2 reads once the bootloader flag says AppArmor is on
apparmor_boot_violations contains msg if {
	input.apparmor.bootloader_enabled == true
	not is_string(object.get(input, ["apparmor", "grub_cmdline"], null))
	msg := "CIS 1.6.1.2: evidence missing — apparmor.grub_cmdline not collected"
}

report := {
	"compliant": compliant,
	"total_violations": count(violations),
	"violations": violations,
	"aide_violations": count(aide_violations),
	"grub_violations": count(grub_violations),
	"process_hardening_violations": count(process_hardening_violations),
	"controls_checked": 12,
	"section": "1.3-1.5 Boot Security and Process Hardening",
	"benchmark": "DERIVED from CIS Ubuntu Linux 20.04 LTS Benchmark v3.0.0 (applied to Debian 11)",
}
