package cis.filesystem

import rego.v1

# CIS Benchmark - Initial Setup and Filesystem Configuration
# Section 1: Initial Setup

# CIS 1.1.1 - Ensure mounting of cramfs filesystems is disabled
cramfs_disabled if {
    not "cramfs" in input.loaded_modules
}

# CIS 1.1.2 - Ensure mounting of freevxfs filesystems is disabled  
freevxfs_disabled if {
    not contains(input.loaded_modules, "freevxfs")
}

# CIS 1.1.3 - Ensure mounting of jffs2 filesystems is disabled
jffs2_disabled if {
    not contains(input.loaded_modules, "jffs2")
}

# CIS 1.1.4 - Ensure mounting of hfs filesystems is disabled
hfs_disabled if {
    not contains(input.loaded_modules, "hfs")
}

# CIS 1.1.5 - Ensure mounting of hfsplus filesystems is disabled
hfsplus_disabled if {
    not contains(input.loaded_modules, "hfsplus")
}

# CIS 1.1.6 - Ensure mounting of squashfs filesystems is disabled
squashfs_disabled if {
    not contains(input.loaded_modules, "squashfs")
}

# CIS 1.1.7 - Ensure mounting of udf filesystems is disabled
udf_disabled if {
    not contains(input.loaded_modules, "udf")
}

# CIS 1.1.8 - Ensure /tmp is configured
tmp_configured if {
    input.mounts["/tmp"]
}

# CIS 1.1.9 - Ensure nodev option set on /tmp partition
tmp_nodev if {
    "nodev" in input.mounts["/tmp"].options
}

# CIS 1.1.10 - Ensure nosuid option set on /tmp partition
tmp_nosuid if {
    "nosuid" in input.mounts["/tmp"].options
}

# CIS 1.1.11 - Ensure noexec option set on /tmp partition
tmp_noexec if {
    "noexec" in input.mounts["/tmp"].options
}

# Aggregate filesystem compliance
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