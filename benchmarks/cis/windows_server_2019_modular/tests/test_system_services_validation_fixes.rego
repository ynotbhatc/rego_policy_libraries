package cis_windows_server_2019.system_services_test

import rego.v1

# Regression tests for the 2026-10-17 validation pass.

all_services := [
	"BTAGService", "bthserv", "Browser", "MapsBroker", "lfsvc", "IISADMIN", "irmon", "SharedAccess",
	"lltdsvc", "LxssManager", "FTPSVC", "MSiSCSI", "sshd", "PNRPsvc", "p2psvc", "SessionEnv",
	"RpcLocator", "RemoteRegistry", "RemoteAccess", "simptcp", "SNMP", "TlntSvr", "tftpd", "W3SVC",
	"XblAuthManager",
]

disabled_all := object.union({s: {"start_type": "Disabled", "state": "Stopped"} | some s in all_services}, {"smb1_enabled": false})

test_services_unrelated_services_only_not_compliant if {
	i := {"services": {"Other": {"start_type": "Disabled"}}}
	not data.cis_windows_server_2019.system_services.compliant with input as i
}

test_services_unrelated_services_reports_missing if {
	i := {"services": {"Other": {"start_type": "Disabled"}}}
	v := data.cis_windows_server_2019.system_services.violations with input as i
	count([m | some m in v; contains(m, "evidence missing")]) == 26
}

test_services_all_disabled_compliant if {
	data.cis_windows_server_2019.system_services.compliant with input as {"services": disabled_all}
}

test_services_not_installed_is_acceptable if {
	svcs := object.union(disabled_all, {"Browser": {"not_installed": true}, "tftpd": {"not_installed": true}})
	data.cis_windows_server_2019.system_services.compliant with input as {"services": svcs}
}

test_services_enabled_service_still_flagged if {
	svcs := object.union(disabled_all, {"bthserv": {"start_type": "Automatic"}})
	not data.cis_windows_server_2019.system_services.compliant with input as {"services": svcs}
}

test_services_smb1_flag_missing_flagged if {
	svcs := object.remove(disabled_all, ["smb1_enabled"])
	not data.cis_windows_server_2019.system_services.compliant with input as {"services": svcs}
}
