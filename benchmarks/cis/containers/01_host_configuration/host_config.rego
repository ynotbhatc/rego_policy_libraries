package cis.docker.host

import rego.v1

# CIS Docker Benchmark
# Section 1: Host Configuration

# CIS 1.1 - Ensure a separate partition for containers has been created
separate_partition_for_containers if {
    input.docker_partition.exists == true
    input.docker_partition.mount_point == "/var/lib/docker"
}

# CIS 1.2 - Ensure only trusted users are allowed to control Docker daemon
trusted_docker_users if {
    count([user | user := input.docker_group_members[_]; not user in input.trusted_users]) == 0
}

# CIS 1.3 - Ensure auditing is configured for the Docker daemon
docker_daemon_auditing if {
    "/usr/bin/dockerd" in input.audit_rules
}

# CIS 1.4 - Ensure auditing is configured for Docker files and directories
docker_files_auditing if {
    every path in [
        "/var/lib/docker",
        "/etc/docker",
        "/lib/systemd/system/docker.service",
        "/lib/systemd/system/docker.socket",
        "/etc/default/docker",
        "/etc/sysconfig/docker",
        "/usr/bin/docker-containerd",
        "/usr/bin/docker-runc"
    ] {
        path in input.audit_rules
    }
}

# CIS 1.5 - Ensure auditing is configured for /etc/default/docker
default_docker_auditing if {
    "/etc/default/docker" in input.audit_rules
}

# CIS 1.6 - Ensure auditing is configured for /etc/sysconfig/docker
sysconfig_docker_auditing if {
    "/etc/sysconfig/docker" in input.audit_rules
}

# CIS 1.7 - Ensure auditing is configured for /etc/docker/daemon.json
daemon_json_auditing if {
    "/etc/docker/daemon.json" in input.audit_rules
}

# CIS 1.8 - Ensure auditing is configured for /usr/bin/docker-containerd
containerd_auditing if {
    "/usr/bin/docker-containerd" in input.audit_rules
}

# CIS 1.9 - Ensure auditing is configured for /usr/bin/docker-runc
runc_auditing if {
    "/usr/bin/docker-runc" in input.audit_rules
}

# CIS 1.10 - Ensure auditing is configured for /usr/bin/docker
docker_binary_auditing if {
    "/usr/bin/docker" in input.audit_rules
}

# CIS 1.11 - Ensure auditing is configured for /var/lib/docker
docker_lib_auditing if {
    "/var/lib/docker" in input.audit_rules
}

# CIS 1.12 - Ensure auditing is configured for /etc/docker
docker_etc_auditing if {
    "/etc/docker" in input.audit_rules
}

# CIS 1.13 - Ensure auditing is configured for docker.service
docker_service_auditing if {
    some path in input.audit_rules
    contains(path, "docker.service")
}

# CIS 1.14 - Ensure auditing is configured for docker.socket
docker_socket_auditing if {
    some path in input.audit_rules
    contains(path, "docker.socket")
}

# Aggregate Docker host compliance
docker_host_compliant if {
    separate_partition_for_containers
    trusted_docker_users
    docker_daemon_auditing
    docker_files_auditing
    default_docker_auditing
    sysconfig_docker_auditing
    daemon_json_auditing
    containerd_auditing
    runc_auditing
    docker_binary_auditing
    docker_lib_auditing
    docker_etc_auditing
    docker_service_auditing
    docker_socket_auditing
}

# Detailed Docker host compliance report
docker_host_compliance := {
    "separate_partition_for_containers": separate_partition_for_containers,
    "trusted_docker_users": trusted_docker_users,
    "docker_daemon_auditing": docker_daemon_auditing,
    "docker_files_auditing": docker_files_auditing,
    "default_docker_auditing": default_docker_auditing,
    "sysconfig_docker_auditing": sysconfig_docker_auditing,
    "daemon_json_auditing": daemon_json_auditing,
    "containerd_auditing": containerd_auditing,
    "runc_auditing": runc_auditing,
    "docker_binary_auditing": docker_binary_auditing,
    "docker_lib_auditing": docker_lib_auditing,
    "docker_etc_auditing": docker_etc_auditing,
    "docker_service_auditing": docker_service_auditing,
    "docker_socket_auditing": docker_socket_auditing,
    "overall_compliant": docker_host_compliant
}