# METADATA
# title: "CIS Ubuntu Linux Benchmark"
# custom:
#   class: security
#   framework: cis_os
#   source: cis
#   domains: [linux]
#   coverage:
#     checks: 28
#     cited: 0
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: none
#     guard: n/a
#     as_of: v2.4.2
package cis.ubuntu.initial_setup

import rego.v1

# CIS Ubuntu Linux Benchmark
# Section 1.1: Filesystem Configuration

# Mount options and module lists arrive as arrays or as comma/space separated text.
# Absent evidence leaves the helper undefined, so the dependent check fails closed.
as_set(v) := {x | some x in v} if is_array(v)

as_set(v) := {x | some x in regex.split(`[\s,]+`, v); x != ""} if is_string(v)

# CIS 1.1.1.1 - Ensure mounting of cramfs filesystems is disabled
default cramfs_disabled := false

cramfs_disabled if {
    loaded := as_set(input.loaded_modules)
    not "cramfs" in loaded
    "cramfs" in as_set(input.blacklisted_modules)
}

# CIS 1.1.1.2 - Ensure mounting of freevxfs filesystems is disabled
default freevxfs_disabled := false

freevxfs_disabled if {
    loaded := as_set(input.loaded_modules)
    not "freevxfs" in loaded
    "freevxfs" in as_set(input.blacklisted_modules)
}

# CIS 1.1.1.3 - Ensure mounting of jffs2 filesystems is disabled
default jffs2_disabled := false

jffs2_disabled if {
    loaded := as_set(input.loaded_modules)
    not "jffs2" in loaded
    "jffs2" in as_set(input.blacklisted_modules)
}

# CIS 1.1.1.4 - Ensure mounting of hfs filesystems is disabled
default hfs_disabled := false

hfs_disabled if {
    loaded := as_set(input.loaded_modules)
    not "hfs" in loaded
    "hfs" in as_set(input.blacklisted_modules)
}

# CIS 1.1.1.5 - Ensure mounting of hfsplus filesystems is disabled
default hfsplus_disabled := false

hfsplus_disabled if {
    loaded := as_set(input.loaded_modules)
    not "hfsplus" in loaded
    "hfsplus" in as_set(input.blacklisted_modules)
}

# CIS 1.1.1.6 - Ensure mounting of udf filesystems is disabled
default udf_disabled := false

udf_disabled if {
    loaded := as_set(input.loaded_modules)
    not "udf" in loaded
    "udf" in as_set(input.blacklisted_modules)
}

# CIS 1.1.2 - Ensure /tmp is configured
default tmp_partition_configured := false

tmp_partition_configured if {
    input.mounts["/tmp"]
    input.mounts["/tmp"].filesystem_type in ["tmpfs", "ext4", "xfs"]
}

# CIS 1.1.3 - Ensure nodev option set on /tmp partition
default tmp_nodev := false

tmp_nodev if {
    "nodev" in as_set(input.mounts["/tmp"].options)
}

# CIS 1.1.4 - Ensure nosuid option set on /tmp partition
default tmp_nosuid := false

tmp_nosuid if {
    "nosuid" in as_set(input.mounts["/tmp"].options)
}

# CIS 1.1.5 - Ensure noexec option set on /tmp partition
default tmp_noexec := false

tmp_noexec if {
    "noexec" in as_set(input.mounts["/tmp"].options)
}

# CIS 1.1.6 - Ensure separate partition exists for /var
default var_partition_configured := false

var_partition_configured if {
    input.mounts["/var"]
    input.mounts["/var"].device != input.mounts["/"].device
}

# CIS 1.1.7 - Ensure separate partition exists for /var/tmp
default var_tmp_partition_configured := false

var_tmp_partition_configured if {
    input.mounts["/var/tmp"]
    input.mounts["/var/tmp"].device != input.mounts["/var"].device
}

# CIS 1.1.8 - Ensure nodev option set on /var/tmp partition
default var_tmp_nodev := false

var_tmp_nodev if {
    "nodev" in as_set(input.mounts["/var/tmp"].options)
}

# CIS 1.1.9 - Ensure nosuid option set on /var/tmp partition
default var_tmp_nosuid := false

var_tmp_nosuid if {
    "nosuid" in as_set(input.mounts["/var/tmp"].options)
}

# CIS 1.1.10 - Ensure noexec option set on /var/tmp partition
default var_tmp_noexec := false

var_tmp_noexec if {
    "noexec" in as_set(input.mounts["/var/tmp"].options)
}

# CIS 1.1.11 - Ensure separate partition exists for /var/log
default var_log_partition_configured := false

var_log_partition_configured if {
    input.mounts["/var/log"]
    input.mounts["/var/log"].device != input.mounts["/var"].device
}

# CIS 1.1.12 - Ensure separate partition exists for /var/log/audit
default var_log_audit_partition_configured := false

var_log_audit_partition_configured if {
    input.mounts["/var/log/audit"]
    input.mounts["/var/log/audit"].device != input.mounts["/var/log"].device
}

# CIS 1.1.13 - Ensure separate partition exists for /home
default home_partition_configured := false

home_partition_configured if {
    input.mounts["/home"]
    input.mounts["/home"].device != input.mounts["/"].device
}

# CIS 1.1.14 - Ensure nodev option set on /home partition
default home_nodev := false

home_nodev if {
    "nodev" in as_set(input.mounts["/home"].options)
}

# CIS 1.1.15 - Ensure nodev option set on /dev/shm partition
default dev_shm_nodev := false

dev_shm_nodev if {
    "nodev" in as_set(input.mounts["/dev/shm"].options)
}

# CIS 1.1.16 - Ensure nosuid option set on /dev/shm partition
default dev_shm_nosuid := false

dev_shm_nosuid if {
    "nosuid" in as_set(input.mounts["/dev/shm"].options)
}

# CIS 1.1.17 - Ensure noexec option set on /dev/shm partition
default dev_shm_noexec := false

dev_shm_noexec if {
    "noexec" in as_set(input.mounts["/dev/shm"].options)
}

# CIS 1.1.18 - Ensure nodev option set on removable media partitions
default removable_media_nodev := false

removable_media_nodev if {
    every mount in input.removable_media_mounts {
        "nodev" in as_set(mount.options)
    }
}

# CIS 1.1.19 - Ensure nosuid option set on removable media partitions
default removable_media_nosuid := false

removable_media_nosuid if {
    every mount in input.removable_media_mounts {
        "nosuid" in as_set(mount.options)
    }
}

# CIS 1.1.20 - Ensure noexec option set on removable media partitions
default removable_media_noexec := false

removable_media_noexec if {
    every mount in input.removable_media_mounts {
        "noexec" in as_set(mount.options)
    }
}

# CIS 1.1.21 - Ensure sticky bit is set on all world-writable directories
default sticky_bit_set := false

sticky_bit_set if {
    every dir in input.world_writable_directories {
        dir.sticky_bit == true
    }
}

# CIS 1.1.22 - Disable Automounting
default automounting_disabled := false

automounting_disabled if {
    input.services["autofs"].enabled == false
    input.services["autofs"].running == false
}

# CIS 1.1.23 - Disable USB Storage
default usb_storage_disabled := false

usb_storage_disabled if {
    loaded := as_set(input.loaded_modules)
    not "usb-storage" in loaded
    "usb-storage" in as_set(input.blacklisted_modules)
}

# Aggregate Ubuntu filesystem compliance
default ubuntu_filesystem_compliant := false

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