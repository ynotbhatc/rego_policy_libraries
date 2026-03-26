# Crypto Miner Detection Policy
# Detects indicators of unauthorized cryptocurrency mining software
# Part of Ansible Automated Compliance (AAC) security controls

package security.crypto_miner_detection

import rego.v1

# =============================================================================
# KNOWN CRYPTO MINER INDICATORS
# =============================================================================

# Common crypto miner process names
known_miner_processes := [
    "xmrig", "xmr-stak", "minerd", "cgminer", "bfgminer", "cpuminer",
    "ethminer", "claymore", "phoenixminer", "t-rex", "nbminer", "gminer",
    "lolminer", "teamredminer", "nanominer", "srbminer", "wildrig",
    "cryptonight", "stratum", "nicehash", "minergate", "coinhive",
    "kryptex", "honeyminer", "cudo", "awesome-miner", "easyminer"
]

# Known mining pool domains/patterns
known_mining_pools := [
    "pool.minexmr.com", "xmrpool.eu", "supportxmr.com", "nanopool.org",
    "2miners.com", "f2pool.com", "antpool.com", "poolin.com", "btc.com",
    "slushpool.com", "nicehash.com", "ethermine.org", "flexpool.io",
    "hiveon.net", "sparkpool.com", "miningpoolhub.com", "prohashing.com",
    "zpool.ca", "mining-dutch.nl", "hashvault.pro"
]

# Suspicious ports commonly used by miners
suspicious_ports := [3333, 4444, 5555, 7777, 8888, 9999, 14444, 45700]

# =============================================================================
# PROCESS DETECTION
# =============================================================================

# Check for known miner processes
miner_process_detected contains process if {
    some process in input.running_processes
    some miner in known_miner_processes
    contains(lower(process.name), miner)
}

miner_process_detected contains process if {
    some process in input.running_processes
    some miner in known_miner_processes
    contains(lower(process.cmdline), miner)
}

# High CPU usage processes (potential mining indicator)
high_cpu_processes contains process if {
    some process in input.running_processes
    process.cpu_percent > 80
    process.running_time_minutes > 30
}

# =============================================================================
# PACKAGE DETECTION
# =============================================================================

# Check for miner packages installed
miner_package_detected contains pkg if {
    some pkg in input.installed_packages
    some miner in known_miner_processes
    contains(lower(pkg.name), miner)
}

# =============================================================================
# NETWORK DETECTION
# =============================================================================

# Check for connections to known mining pools
mining_pool_connection contains conn if {
    some conn in input.network_connections
    some pool in known_mining_pools
    contains(lower(conn.remote_host), pool)
}

# Check for connections on suspicious ports
suspicious_port_connection contains conn if {
    some conn in input.network_connections
    some port in suspicious_ports
    conn.remote_port == port
    conn.state == "ESTABLISHED"
}

# Stratum protocol detection (common mining protocol)
stratum_connection contains conn if {
    some conn in input.network_connections
    conn.remote_port == 3333
}

stratum_connection contains conn if {
    some conn in input.network_connections
    contains(conn.remote_host, "stratum")
}

# =============================================================================
# FILE SYSTEM DETECTION
# =============================================================================

# Check for miner configuration files
miner_config_detected contains file if {
    some file in input.suspicious_files
    some miner in known_miner_processes
    contains(lower(file.path), miner)
}

miner_config_detected contains file if {
    some file in input.suspicious_files
    endswith(lower(file.path), "config.json")
    contains(lower(file.content), "pool")
    contains(lower(file.content), "wallet")
}

# =============================================================================
# SYSTEMD/SERVICE DETECTION
# =============================================================================

# Check for miner services
miner_service_detected contains svc if {
    some svc in input.systemd_services
    some miner in known_miner_processes
    contains(lower(svc.name), miner)
}

miner_service_detected contains svc if {
    some svc in input.systemd_services
    some miner in known_miner_processes
    contains(lower(svc.exec_start), miner)
}

# =============================================================================
# CRON JOB DETECTION
# =============================================================================

# Check for miner cron jobs
miner_cron_detected contains job if {
    some job in input.cron_jobs
    some miner in known_miner_processes
    contains(lower(job.command), miner)
}

# =============================================================================
# COMPLIANCE VIOLATIONS
# =============================================================================

violations contains msg if {
    count(miner_process_detected) > 0
    some process in miner_process_detected
    msg := sprintf("CRITICAL: Crypto miner process detected - %s (PID: %v)", [process.name, process.pid])
}

violations contains msg if {
    count(miner_package_detected) > 0
    some pkg in miner_package_detected
    msg := sprintf("HIGH: Crypto miner package installed - %s", [pkg.name])
}

violations contains msg if {
    count(mining_pool_connection) > 0
    some conn in mining_pool_connection
    msg := sprintf("CRITICAL: Connection to mining pool detected - %s:%v", [conn.remote_host, conn.remote_port])
}

violations contains msg if {
    count(suspicious_port_connection) > 0
    some conn in suspicious_port_connection
    msg := sprintf("MEDIUM: Suspicious connection on mining port - %s:%v", [conn.remote_host, conn.remote_port])
}

violations contains msg if {
    count(miner_service_detected) > 0
    some svc in miner_service_detected
    msg := sprintf("CRITICAL: Crypto miner systemd service detected - %s", [svc.name])
}

violations contains msg if {
    count(miner_cron_detected) > 0
    some job in miner_cron_detected
    msg := sprintf("HIGH: Crypto miner cron job detected - %s", [job.command])
}

violations contains msg if {
    count(miner_config_detected) > 0
    some file in miner_config_detected
    msg := sprintf("MEDIUM: Crypto miner configuration file detected - %s", [file.path])
}

# =============================================================================
# COMPLIANCE STATUS
# =============================================================================

default compliant := true

compliant := false if {
    count(violations) > 0
}

# Risk level based on findings - using helper booleans to avoid recursion
has_critical_findings if {
    count(miner_process_detected) > 0
}

has_critical_findings if {
    count(mining_pool_connection) > 0
}

has_critical_findings if {
    count(miner_service_detected) > 0
}

has_high_findings if {
    count(miner_package_detected) > 0
}

has_high_findings if {
    count(miner_cron_detected) > 0
}

has_medium_findings if {
    count(suspicious_port_connection) > 0
}

has_medium_findings if {
    count(miner_config_detected) > 0
}

# Calculate risk level without recursion
risk_level := "critical" if {
    has_critical_findings
}

risk_level := "high" if {
    not has_critical_findings
    has_high_findings
}

risk_level := "medium" if {
    not has_critical_findings
    not has_high_findings
    has_medium_findings
}

risk_level := "low" if {
    not has_critical_findings
    not has_high_findings
    not has_medium_findings
}

# =============================================================================
# COMPLIANCE ASSESSMENT
# =============================================================================

compliance_assessment := {
    "policy": "Crypto Miner Detection",
    "version": "1.0.0",
    "compliant": compliant,
    "risk_level": risk_level,
    "total_violations": count(violations),
    "violations": violations,
    "findings": {
        "miner_processes": miner_process_detected,
        "miner_packages": miner_package_detected,
        "mining_pool_connections": mining_pool_connection,
        "suspicious_connections": suspicious_port_connection,
        "miner_services": miner_service_detected,
        "miner_cron_jobs": miner_cron_detected,
        "miner_config_files": miner_config_detected,
        "high_cpu_processes": high_cpu_processes,
    },
    "recommendation": recommendation,
}

recommendation := "No crypto mining indicators detected. System is compliant." if {
    compliant
}

recommendation := "IMMEDIATE ACTION REQUIRED: Crypto mining software detected. Initiate remediation playbook to remove unauthorized mining software." if {
    not compliant
}
