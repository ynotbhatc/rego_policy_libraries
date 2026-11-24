# METADATA
# title: "CIS Ubuntu 20.04 LTS Benchmark v3.0.0 - Section 1.6: Mandatory Access Controls"
# custom:
#   class: security
#   framework: cis_ubuntu_20_04
#   source: cis
#   domains: [linux, ubuntu]
#   coverage:
#     checks: 17
#     cited: 4
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: report
#     guard: self
#     as_of: v2.5.0
package cis_ubuntu_20_04.apparmor

# CIS Ubuntu 20.04 LTS Benchmark v3.0.0 - Section 1.6: Mandatory Access Controls
# Ubuntu uses AppArmor instead of SELinux

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

violations := array.concat(
	[v | some v in install_violations],
	array.concat([v | some v in service_violations], [v | some v in profile_violations]),
)

# CIS 1.6.1.1: AppArmor must be present
install_violations contains msg if {
	input.apparmor.installed == false
	msg := "CIS 1.6.1.1: AppArmor is not installed"
}

install_violations contains msg if {
	input.apparmor.utils_installed == false
	msg := "CIS 1.6.1.1: apparmor-utils is not installed"
}

# CIS 1.6.1.2: AppArmor must be turned on in the bootloader configuration
service_violations contains msg if {
	input.apparmor.bootloader_enabled == false
	msg := "CIS 1.6.1.2: AppArmor is not enabled in bootloader (apparmor=1 security=apparmor missing from GRUB_CMDLINE_LINUX)"
}

service_violations contains msg if {
	input.apparmor.bootloader_enabled == true
	not contains(input.apparmor.grub_cmdline, "security=apparmor")
	msg := "CIS 1.6.1.2: AppArmor security= parameter not set to apparmor in bootloader"
}

# CIS 1.6.1.3: all AppArmor Profiles must be in enforce or complain mode
profile_violations contains "CIS 1.6.1.3: evidence missing - apparmor.unloaded_profiles (or apparmor.profiles) not collected" if {
	object.get(input, ["apparmor", "unloaded_profiles"], null) == null
	not is_array(object.get(input, ["apparmor", "profiles"], null))
}

profile_violations contains msg if {
	is_number(input.apparmor.unloaded_profiles)
	input.apparmor.unloaded_profiles > 0
	msg := sprintf("CIS 1.6.1.3: %d AppArmor profiles are not loaded", [input.apparmor.unloaded_profiles])
}

profile_violations contains msg if {
	not is_number(object.get(input, ["apparmor", "unloaded_profiles"], 0))
	msg := "CIS 1.6.1.3: evidence missing — apparmor.unloaded_profiles is not a number"
}

profile_violations contains msg if {
	some profile in input.apparmor.profiles
	profile.mode == "unloaded"
	msg := sprintf("CIS 1.6.1.3: AppArmor profile '%s' is not loaded", [profile.name])
}

# CIS 1.6.1.4: all AppArmor Profiles must be enforcing
profile_violations contains "CIS 1.6.1.4: evidence missing - apparmor.complain_profiles (or apparmor.profiles) not collected" if {
	object.get(input, ["apparmor", "complain_profiles"], null) == null
	not is_array(object.get(input, ["apparmor", "profiles"], null))
}

profile_violations contains msg if {
	is_number(input.apparmor.complain_profiles)
	input.apparmor.complain_profiles > 0
	msg := sprintf("CIS 1.6.1.4: %d AppArmor profiles are in complain mode (should be enforce)", [input.apparmor.complain_profiles])
}

profile_violations contains msg if {
	not is_number(object.get(input, ["apparmor", "complain_profiles"], 0))
	msg := "CIS 1.6.1.4: evidence missing — apparmor.complain_profiles is not a number"
}

profile_violations contains msg if {
	some profile in input.apparmor.profiles
	profile.mode == "complain"
	msg := sprintf("CIS 1.6.1.4: AppArmor profile '%s' is in complain mode, should be enforce", [profile.name])
}

# AppArmor service must be active
service_violations contains msg if {
	input.apparmor.service_active == false
	msg := "CIS 1.6.1.2: AppArmor service is not active"
}

service_violations contains msg if {
	input.apparmor.service_enabled == false
	msg := "CIS 1.6.1.2: AppArmor service is not enabled"
}

# AppArmor status
apparmor_status := {
	"installed": object.get(input, ["apparmor", "installed"], null),
	"service_active": object.get(input, ["apparmor", "service_active"], null),
	"enforce_profiles": object.get(input, ["apparmor", "enforce_profiles"], null),
	"complain_profiles": object.get(input, ["apparmor", "complain_profiles"], null),
	"unloaded_profiles": object.get(input, ["apparmor", "unloaded_profiles"], null),
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
required_flags_install_violations := [
	["CIS 1.6.1.1", ["apparmor", "installed"]],
	["CIS 1.6.1.1", ["apparmor", "utils_installed"]],
]

install_violations contains msg if {
	some [prefix, path] in required_flags_install_violations
	msg := flag_evidence(prefix, path)
}

# yes/no facts read unconditionally: [finding prefix, input path]
required_flags_service_violations := [
	["CIS 1.6.1.2", ["apparmor", "bootloader_enabled"]],
	["CIS 1.6.1.2", ["apparmor", "service_active"]],
	["CIS 1.6.1.2", ["apparmor", "service_enabled"]],
]

service_violations contains msg if {
	some [prefix, path] in required_flags_service_violations
	msg := flag_evidence(prefix, path)
}

# the kernel command line is what 1.6.1.2 reads once the bootloader flag says AppArmor is on
service_violations contains msg if {
	input.apparmor.bootloader_enabled == true
	not is_string(object.get(input, ["apparmor", "grub_cmdline"], null))
	msg := "CIS 1.6.1.2: evidence missing — apparmor.grub_cmdline not collected"
}

report := {
	"compliant": compliant,
	"total_violations": count(violations),
	"violations": violations,
	"install_violations": count(install_violations),
	"service_violations": count(service_violations),
	"profile_violations": count(profile_violations),
	"apparmor_status": apparmor_status,
	"controls_checked": 4,
	"section": "1.6 Mandatory Access Controls (AppArmor)",
	"benchmark": "CIS Ubuntu 20.04 v3.0.0",
}
