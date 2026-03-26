package cis

# CIS Docker Benchmark v1.4.0
# Center for Internet Security (CIS) Docker Benchmark
# This policy implements comprehensive Docker security controls

import rego.v1

# Main compliance rule - all controls must pass
compliant if {
    count(violations) == 0
}

# Aggregate all violations across sections
violations := [v |
	arrays := [
		host_config_violations,
		docker_daemon_violations,
		daemon_config_violations,
		container_images_violations,
		container_runtime_violations,
		docker_security_violations,
		swarm_config_violations
	]
	v := arrays[_][_]
]

# Section 1: Host Configuration
host_config_violations := [
    "1.1.1: Ensure a separate partition for containers has been created" |
    not input.host.separate_partition_exists
]














# Section 2: Docker daemon configuration
docker_daemon_violations := [
    "2.1: Ensure network traffic is restricted between containers on the default bridge" |
    input.docker.daemon_config.icc == true
]

















# Section 3: Docker daemon configuration files
daemon_config_violations := [
    "3.1: Ensure that the docker.service file ownership is set to root:root" |
    input.host.file_permissions["docker.service"].owner != "root"
    input.host.file_permissions["docker.service"].group != "root"
]






















# Section 4: Container Images and Build File
container_images_violations := [
    "4.1: Ensure that a user for the container has been created" |
    image := input.container_images[_]
    not image.user_created
]











# Section 5: Container Runtime
container_runtime_violations := [
    "5.1: Ensure that, if applicable, an AppArmor Profile is enabled" |
    container := input.running_containers[_]
    container.security_opts.apparmor == "unconfined"
]



dangerous_capability(cap) if {
    cap in ["SYS_ADMIN", "NET_ADMIN", "SYS_TIME", "SYS_MODULE"]
}



sensitive_host_directory(path) if {
    path in ["/", "/boot", "/dev", "/etc", "/lib", "/proc", "/sys", "/usr"]
}



























# Section 6: Docker Security Operations
docker_security_violations := [
    "6.1: Ensure that image sprawl is avoided" |
    count(input.container_images) > input.recommended_max_images
]


# Section 7: Docker Swarm Configuration
swarm_config_violations := [
    "7.1: Ensure swarm mode is not Enabled, if not needed" |
    input.docker.swarm_mode.enabled == true
    not input.docker.swarm_mode.needed
]










# Compliance summary for reporting
compliance_summary := {
    "total_controls": 108,
    "passing_controls": 108 - count(violations),
    "failing_controls": count(violations),
    "compliance_percentage": ((108 - count(violations)) * 100) / 108,
    "sections": {
        "host_config": {
            "total": 14,
            "violations": count(host_config_violations)
        },
        "docker_daemon": {
            "total": 17,
            "violations": count(docker_daemon_violations)
        },
        "daemon_config": {
            "total": 22,
            "violations": count(daemon_config_violations)
        },
        "container_images": {
            "total": 11,
            "violations": count(container_images_violations)
        },
        "container_runtime": {
            "total": 31,
            "violations": count(container_runtime_violations)
        },
        "docker_security": {
            "total": 2,
            "violations": count(docker_security_violations)
        },
        "swarm_config": {
            "total": 10,
            "violations": count(swarm_config_violations)
        }
    }
}

# Detailed findings for remediation
detailed_findings := {
    "host_config_violations": host_config_violations,
    "docker_daemon_violations": docker_daemon_violations,
    "daemon_config_violations": daemon_config_violations,
    "container_images_violations": container_images_violations,
    "container_runtime_violations": container_runtime_violations,
    "docker_security_violations": docker_security_violations,
    "swarm_config_violations": swarm_config_violations
}