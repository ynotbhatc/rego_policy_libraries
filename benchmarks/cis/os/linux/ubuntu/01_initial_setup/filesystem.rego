package cis.ubuntu.initial_setup

import rego.v1

# CIS Ubuntu Linux Benchmark
# Section 1.1: Filesystem Configuration

# CIS 1.1.1.1 - Ensure mounting of cramfs filesystems is disabled
cramfs_disabled if {
    not contains(input.loaded_modules, "cramfs")
    contains(input.blacklisted_modules, "cramfs")
}

# CIS 1.1.1.2 - Ensure mounting of freevxfs filesystems is disabled
freevxfs_disabled if {
    not contains(input.loaded_modules, "freevxfs")
    contains(input.blacklisted_modules, "freevxfs")
}

# CIS 1.1.1.3 - Ensure mounting of jffs2 filesystems is disabled
jffs2_disabled if {
    not contains(input.loaded_modules, "jffs2")
    contains(input.blacklisted_modules, "jffs2")
}

# CIS 1.1.1.4 - Ensure mounting of hfs filesystems is disabled
hfs_disabled if {
    not contains(input.loaded_modules, "hfs")
    contains(input.blacklisted_modules, "hfs")
}

# CIS 1.1.1.5 - Ensure mounting of hfsplus filesystems is disabled
hfsplus_disabled if {
    not contains(input.loaded_modules, "hfsplus")
    contains(input.blacklisted_modules, "hfsplus")
}

# CIS 1.1.1.6 - Ensure mounting of udf filesystems is disabled
udf_disabled if {
    not contains(input.loaded_modules, "udf")
    contains(input.blacklisted_modules, "udf")
}

# CIS 1.1.2 - Ensure /tmp is configured
tmp_partition_configured if {
    input.mounts["/tmp"]
    input.mounts["/tmp"].filesystem_type in ["tmpfs", "ext4", "xfs"]
}

# CIS 1.1.3 - Ensure nodev option set on /tmp partition
tmp_nodev if {
    contains(input.mounts["/tmp"].options, "nodev")
}

# CIS 1.1.4 - Ensure nosuid option set on /tmp partition
tmp_nosuid if {
    contains(input.mounts["/tmp"].options, "nosuid")
}

# CIS 1.1.5 - Ensure noexec option set on /tmp partition
tmp_noexec if {
    contains(input.mounts["/tmp"].options, "noexec")
}

# CIS 1.1.6 - Ensure separate partition exists for /var
var_partition_configured if {
    input.mounts["/var"]
    input.mounts["/var"].device != input.mounts["/"].device
}

# CIS 1.1.7 - Ensure separate partition exists for /var/tmp
var_tmp_partition_configured if {
    input.mounts["/var/tmp"]
    input.mounts["/var/tmp"].device != input.mounts["/var"].device
}

# CIS 1.1.8 - Ensure nodev option set on /var/tmp partition
var_tmp_nodev if {
    contains(input.mounts["/var/tmp"].options, "nodev")
}

# CIS 1.1.9 - Ensure nosuid option set on /var/tmp partition
var_tmp_nosuid if {
    contains(input.mounts["/var/tmp"].options, "nosuid")
}

# CIS 1.1.10 - Ensure noexec option set on /var/tmp partition
var_tmp_noexec if {
    contains(input.mounts["/var/tmp"].options, "noexec")
}

# CIS 1.1.11 - Ensure separate partition exists for /var/log
var_log_partition_configured if {
    input.mounts["/var/log"]
    input.mounts["/var/log"].device != input.mounts["/var"].device
}

# CIS 1.1.12 - Ensure separate partition exists for /var/log/audit
var_log_audit_partition_configured if {
    input.mounts["/var/log/audit"]
    input.mounts["/var/log/audit"].device != input.mounts["/var/log"].device
}

# CIS 1.1.13 - Ensure separate partition exists for /home
home_partition_configured if {
    input.mounts["/home"]
    input.mounts["/home"].device != input.mounts["/"].device
}

# CIS 1.1.14 - Ensure nodev option set on /home partition
home_nodev if {
    contains(input.mounts["/home"].options, "nodev")
}

# CIS 1.1.15 - Ensure nodev option set on /dev/shm partition
dev_shm_nodev if {
    contains(input.mounts["/dev/shm"].options, "nodev")
}

# CIS 1.1.16 - Ensure nosuid option set on /dev/shm partition
dev_shm_nosuid if {
    contains(input.mounts["/dev/shm"].options, "nosuid")
}

# CIS 1.1.17 - Ensure noexec option set on /dev/shm partition
dev_shm_noexec if {
    contains(input.mounts["/dev/shm"].options, "noexec")
}

# CIS 1.1.18 - Ensure nodev option set on removable media partitions
removable_media_nodev if {
    every mount in input.removable_media_mounts {
        contains(mount.options, "nodev")
    }
}

# CIS 1.1.19 - Ensure nosuid option set on removable media partitions
removable_media_nosuid if {
    every mount in input.removable_media_mounts {
        contains(mount.options, "nosuid")
    }
}

# CIS 1.1.20 - Ensure noexec option set on removable media partitions
removable_media_noexec if {
    every mount in input.removable_media_mounts {
        contains(mount.options, "noexec")
    }
}

# CIS 1.1.21 - Ensure sticky bit is set on all world-writable directories
sticky_bit_set if {
    every dir in input.world_writable_directories {
        dir.sticky_bit == true
    }
}

# CIS 1.1.22 - Disable Automounting
automounting_disabled if {
    input.services["autofs"].enabled == false
    input.services["autofs"].running == false
}

# CIS 1.1.23 - Disable USB Storage
usb_storage_disabled if {
    not contains(input.loaded_modules, "usb-storage")
    contains(input.blacklisted_modules, "usb-storage")
}

# Aggregate Ubuntu filesystem compliance
ubuntu_filesystem_compliant if {
    cramfs_disabled
    freevxfs_disabled
    jffs2_disabled
    hfs_disabled
    hfsplus_disabled
    udf_disabled
    tmp_partition_configured
    tmp_nodev
    tmp_nosuid
    tmp_noexec
    var_partition_configured
    var_tmp_partition_configured
    var_tmp_nodev
    var_tmp_nosuid
    var_tmp_noexec
    var_log_partition_configured
    var_log_audit_partition_configured
    home_partition_configured
    home_nodev
    dev_shm_nodev
    dev_shm_nosuid
    dev_shm_noexec
    removable_media_nodev
    removable_media_nosuid
    removable_media_noexec
    sticky_bit_set
    automounting_disabled
    usb_storage_disabled
}

# Detailed Ubuntu filesystem compliance report
ubuntu_filesystem_compliance := {
    "cramfs_disabled": cramfs_disabled,
    "freevxfs_disabled": freevxfs_disabled,
    "jffs2_disabled": jffs2_disabled,
    "hfs_disabled": hfs_disabled,
    "hfsplus_disabled": hfsplus_disabled,
    "udf_disabled": udf_disabled,
    "tmp_partition_configured": tmp_partition_configured,
    "tmp_nodev": tmp_nodev,
    "tmp_nosuid": tmp_nosuid,
    "tmp_noexec": tmp_noexec,
    "var_partition_configured": var_partition_configured,
    "var_tmp_partition_configured": var_tmp_partition_configured,
    "var_tmp_nodev": var_tmp_nodev,
    "var_tmp_nosuid": var_tmp_nosuid,
    "var_tmp_noexec": var_tmp_noexec,
    "var_log_partition_configured": var_log_partition_configured,
    "var_log_audit_partition_configured": var_log_audit_partition_configured,
    "home_partition_configured": home_partition_configured,
    "home_nodev": home_nodev,
    "dev_shm_nodev": dev_shm_nodev,
    "dev_shm_nosuid": dev_shm_nosuid,
    "dev_shm_noexec": dev_shm_noexec,
    "removable_media_nodev": removable_media_nodev,
    "removable_media_nosuid": removable_media_nosuid,
    "removable_media_noexec": removable_media_noexec,
    "sticky_bit_set": sticky_bit_set,
    "automounting_disabled": automounting_disabled,
    "usb_storage_disabled": usb_storage_disabled,
    "overall_compliant": ubuntu_filesystem_compliant
}