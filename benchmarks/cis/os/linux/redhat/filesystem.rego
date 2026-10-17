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
#     as_of: v2.4.1
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

# CIS 1.1.1 - Ensure mounting of cramfs filesystems is disabled
default cramfs_disabled := false

cramfs_disabled if {
    modules := loaded_module_set
    not "cramfs" in modules
}

# CIS 1.1.2 - Ensure mounting of freevxfs filesystems is disabled  
default freevxfs_disabled := false

freevxfs_disabled if {
    modules := loaded_module_set
    not "freevxfs" in modules
}

# CIS 1.1.3 - Ensure mounting of jffs2 filesystems is disabled
default jffs2_disabled := false

jffs2_disabled if {
    modules := loaded_module_set
    not "jffs2" in modules
}

# CIS 1.1.4 - Ensure mounting of hfs filesystems is disabled
default hfs_disabled := false

hfs_disabled if {
    modules := loaded_module_set
    not "hfs" in modules
}

# CIS 1.1.5 - Ensure mounting of hfsplus filesystems is disabled
default hfsplus_disabled := false

hfsplus_disabled if {
    modules := loaded_module_set
    not "hfsplus" in modules
}

# CIS 1.1.6 - Ensure mounting of squashfs filesystems is disabled
default squashfs_disabled := false

squashfs_disabled if {
    modules := loaded_module_set
    not "squashfs" in modules
}

# CIS 1.1.7 - Ensure mounting of udf filesystems is disabled
default udf_disabled := false

udf_disabled if {
    modules := loaded_module_set
    not "udf" in modules
}

# CIS 1.1.8 - Ensure /tmp is configured
default tmp_configured := false

tmp_configured if {
    input.mounts["/tmp"]
}

# CIS 1.1.9 - Ensure nodev option set on /tmp partition
default tmp_nodev := false

tmp_nodev if {
    "nodev" in input.mounts["/tmp"].options
}

# CIS 1.1.10 - Ensure nosuid option set on /tmp partition
default tmp_nosuid := false

tmp_nosuid if {
    "nosuid" in input.mounts["/tmp"].options
}

# CIS 1.1.11 - Ensure noexec option set on /tmp partition
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
    "overall_compliant": filesystem_compliant
}