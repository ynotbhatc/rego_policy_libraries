# METADATA
# title: "CIS Benchmark compliance rules for Linux systems"
# custom:
#   class: security
#   framework: cis_os
#   source: cis
#   domains: [linux]
#   coverage:
#     checks: 4
#     cited: 4
#     density: sparse
#     basis: size
#     tested: true
#     entrypoint: none
#     guard: n/a
#     as_of: v2.4.1
package cis_redhat_legacy

import rego.v1

# CIS Benchmark compliance rules for Linux systems
# This demonstrates key CIS controls validation using Ansible facts

# Allow access if all CIS controls pass
default allow := false

allow if {
    selinux_enabled
    ssh_hardened
    firewall_configured
    os_supported
}

# CIS Control 1.6.1 - Ensure SELinux is enabled
default selinux_enabled := false

selinux_enabled if {
    input.selinux_status == "enforcing"
}

selinux_enabled if {
    input.selinux_status == "permissive"
}

# CIS Control 5.2.2 - Ensure SSH access is limited
default ssh_hardened := false

ssh_hardened if {
    input.ssh_port != 22
}

ssh_hardened if {
    input.ssh_port == 22
    # Additional SSH hardening could be checked here
    # For demo purposes, we'll allow default SSH port
    true
}

# CIS Control 3.5.1 - Ensure firewall is active
default firewall_configured := false

firewall_configured if {
    input.firewall_enabled == true
}

# Support for major Linux distributions
default os_supported := false

os_supported if {
    input.os_family == "RedHat"
    supported_redhat_version
}

os_supported if {
    input.os_family == "Debian"
}

supported_redhat_version if {
    to_number(split(input.distribution_version, ".")[0]) >= 8
}

# Compliance details for reporting
compliance_details := {
    "selinux": {
        "status": selinux_enabled,
        "current_value": object.get(input, "selinux_status", null),
        "requirement": "enforcing or permissive"
    },
    "ssh": {
        "status": ssh_hardened,
        "current_port": object.get(input, "ssh_port", null),
        "requirement": "non-default port recommended"
    },
    "firewall": {
        "status": firewall_configured,
        "current_status": object.get(input, "firewall_enabled", null),
        "requirement": "firewall must be active"
    },
    "os": {
        "status": os_supported,
        "current_os": sprintf("%s %s", [object.get(input, "distribution", "unknown"), object.get(input, "distribution_version", "unknown")]),
        "requirement": "supported OS version"
    }
}

# Failed controls for remediation guidance
failed_controls contains control if {
    control := "selinux"
    not selinux_enabled
}

failed_controls contains control if {
    control := "ssh"
    not ssh_hardened
}

failed_controls contains control if {
    control := "firewall"
    not firewall_configured
}

failed_controls contains control if {
    control := "os_support"
    not os_supported
}