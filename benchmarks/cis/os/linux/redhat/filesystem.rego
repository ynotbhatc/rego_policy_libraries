# METADATA
# title: "CIS Benchmark - Initial Setup and Filesystem Configuration"
# custom:
#   class: security
#   framework: cis_os
#   source: cis
#   domains: [linux]
#   coverage:
#     checks: 11
#     cited: 0
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: none
#     guard: n/a
#     as_of: v2.4.2
package cis.filesystem

import rego.v1

# CIS Benchmark - Initial Setup and Filesystem Configuration
# Section 1: Initial Setup

# Loaded kernel modules as a set. The fact may be an array of names or
# whitespace/comma separated text. Absent evidence leaves this undefined, so every
# *_disabled check below fails closed.
loaded_module_set := mods if {
	is_array(input.loaded_modules)
	mods := {m | some m in input.loaded_modules}
} else := mods if {
	is_string(input.loaded_modules)
	mods := {m | some m in regex.split(`[\s,]+`, input.loaded_modules); m != ""}
}

# CIS 1.1.1 - mounting of cramfs filesystems must be turned off
default cramfs_disabled := false

cramfs_disabled if {
	modules := loaded_module_set
	not "cramfs" in modules
}

# CIS 1.1.2 - mounting of freevxfs filesystems must be turned off
default freevxfs_disabled := false

freevxfs_disabled if {
	modules := loaded_module_set
	not "freevxfs" in modules
}

# CIS 1.1.3 - mounting of jffs2 filesystems must be turned off
default jffs2_disabled := false

jffs2_disabled if {
	modules := loaded_module_set
	not "jffs2" in modules
}

# CIS 1.1.4 - mounting of hfs filesystems must be turned off
default hfs_disabled := false

hfs_disabled if {
	modules := loaded_module_set
	not "hfs" in modules
}

# CIS 1.1.5 - mounting of hfsplus filesystems must be turned off
default hfsplus_disabled := false

hfsplus_disabled if {
	modules := loaded_module_set
	not "hfsplus" in modules
}

# CIS 1.1.6 - mounting of squashfs filesystems must be turned off
default squashfs_disabled := false

squashfs_disabled if {
	modules := loaded_module_set
	not "squashfs" in modules
}

# CIS 1.1.7 - mounting of udf filesystems must be turned off
default udf_disabled := false

udf_disabled if {
	modules := loaded_module_set
	not "udf" in modules
}

# CIS 1.1.8 - /tmp must be explicitly configured
default tmp_configured := false

tmp_configured if {
	input.mounts["/tmp"]
}

# CIS 1.1.9 - /tmp must be mounted with the nodev option
default tmp_nodev := false

tmp_nodev if {
	"nodev" in input.mounts["/tmp"].options
}

# CIS 1.1.10 - /tmp must be mounted with the nosuid option
default tmp_nosuid := false

tmp_nosuid if {
	"nosuid" in input.mounts["/tmp"].options
}

# CIS 1.1.11 - /tmp must be mounted with the noexec option
default tmp_noexec := false

tmp_noexec if {
	"noexec" in input.mounts["/tmp"].options
}

# Aggregate filesystem compliance
default filesystem_compliant := false

filesystem_compliant if {
	cramfs_disabled
	freevxfs_disabled
	jffs2_disabled
	hfs_disabled
	hfsplus_disabled
	squashfs_disabled
	udf_disabled
	tmp_configured
	tmp_nodev
	tmp_nosuid
	tmp_noexec
}

# Detailed compliance report
filesystem_compliance := {
	"cramfs_disabled": cramfs_disabled,
	"freevxfs_disabled": freevxfs_disabled,
	"jffs2_disabled": jffs2_disabled,
	"hfs_disabled": hfs_disabled,
	"hfsplus_disabled": hfsplus_disabled,
	"squashfs_disabled": squashfs_disabled,
	"udf_disabled": udf_disabled,
	"tmp_configured": tmp_configured,
	"tmp_nodev": tmp_nodev,
	"tmp_nosuid": tmp_nosuid,
	"tmp_noexec": tmp_noexec,
	"overall_compliant": filesystem_compliant,
}
