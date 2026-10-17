# METADATA
# title: "Cis Openshift 4"
# custom:
#   class: security
#   framework: cis_openshift
#   source: cis
#   domains: [kubernetes, openshift, container]
#   coverage:
#     checks: 156
#     cited: 156
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: none
#     guard: self
#     as_of: v2.4.2
package cis_openshift_4

import rego.v1

default compliant := false

# Permission checks compare octal bit masks, never decimal numbers.
# perm_max: collected-permission path under input.openshift -> maximum allowed mode.
# These are rules, not functions: a function in this package would make
# data.cis_openshift_4 untypeable as an object for callers using object.get.
perm_max := {
    "master_node.api_server.permissions": 420, # 0644
    "master_node.controller_manager.permissions": 420, # 0644
    "master_node.scheduler.permissions": 420, # 0644
    "master_node.etcd.permissions": 420, # 0644
    "master_node.cni.permissions": 420, # 0644
    "master_node.etcd_data.permissions": 448, # 0700
    "master_node.admin_conf.permissions": 420, # 0644
    "master_node.scheduler_conf.permissions": 420, # 0644
    "master_node.controller_manager_conf.permissions": 420, # 0644
    "master_node.pki.cert_permissions": 420, # 0644
    "master_node.pki.key_permissions": 384, # 0600
    "worker_node.kubelet_service.permissions": 420, # 0644
    "worker_node.proxy_kubeconfig.permissions": 420, # 0644
    "worker_node.kubelet_conf.permissions": 420, # 0644
    "worker_node.ca.permissions": 420, # 0644
    "worker_node.kubelet_config.permissions": 420, # 0644
}

# Paths whose collected mode (number 644 or string "0644") is octal and grants nothing beyond the maximum.
perm_ok contains key if {
    some key, max in perm_max
    raw := object.get(input.openshift, split(key, "."), null)
    raw != null
    t := trim_prefix(lower(trim_space(sprintf("%v", [raw]))), "0o")
    regex.match(`^[0-7]{1,4}$`, t)
    padded := concat("", [substring("0000", 0, 4 - count(t)), t])
    ds := [to_number(d) | some d in split(padded, "")]
    mode := ((ds[0] * 512) + (ds[1] * 64)) + ((ds[2] * 8) + ds[3])
    bits.and(mode, bits.and(bits.negate(max), 4095)) == 0
}

violations := array.concat(
    master_node_violations,
    array.concat(
        etcd_violations,
        array.concat(
            control_plane_violations,
            array.concat(
                worker_node_violations,
                array.concat(
                    kubernetes_policies_violations,
                    array.concat(
                        network_policies_violations,
                        array.concat(
                            authentication_violations,
                            array.concat(
                                authorization_violations,
                                array.concat(
                                    logging_violations,
                                    secrets_management_violations
                                )
                            )
                        )
                    )
                )
            )
        )
    )
)

compliant if {
    # fail-closed: no facts, no compliance
    count(object.get(input, "openshift", {})) > 0
    count(violations) == 0
}

master_node_violations := [msg |
    msgs := [
        {"msg": "1.1.1 Ensure that the API server pod specification file permissions are set to 644 or more restrictive", "condition": api_server_permissions_secure},
        {"msg": "1.1.2 Ensure that the API server pod specification file ownership is set to root:root", "condition": api_server_ownership_secure},
        {"msg": "1.1.3 Ensure that the controller manager pod specification file permissions are set to 644 or more restrictive", "condition": controller_manager_permissions_secure},
        {"msg": "1.1.4 Ensure that the controller manager pod specification file ownership is set to root:root", "condition": controller_manager_ownership_secure},
        {"msg": "1.1.5 Ensure that the scheduler pod specification file permissions are set to 644 or more restrictive", "condition": scheduler_permissions_secure},
        {"msg": "1.1.6 Ensure that the scheduler pod specification file ownership is set to root:root", "condition": scheduler_ownership_secure},
        {"msg": "1.1.7 Ensure that the etcd pod specification file permissions are set to 644 or more restrictive", "condition": etcd_permissions_secure},
        {"msg": "1.1.8 Ensure that the etcd pod specification file ownership is set to root:root", "condition": etcd_ownership_secure},
        {"msg": "1.1.9 Ensure that the Container Network Interface file permissions are set to 644 or more restrictive", "condition": cni_permissions_secure},
        {"msg": "1.1.10 Ensure that the Container Network Interface file ownership is set to root:root", "condition": cni_ownership_secure},
        {"msg": "1.1.11 Ensure that the etcd data directory permissions are set to 700 or more restrictive", "condition": etcd_data_permissions_secure},
        {"msg": "1.1.12 Ensure that the etcd data directory ownership is set to etcd:etcd", "condition": etcd_data_ownership_secure},
        {"msg": "1.1.13 Ensure that the admin.conf file permissions are set to 644 or more restrictive", "condition": admin_conf_permissions_secure},
        {"msg": "1.1.14 Ensure that the admin.conf file ownership is set to root:root", "condition": admin_conf_ownership_secure},
        {"msg": "1.1.15 Ensure that the scheduler.conf file permissions are set to 644 or more restrictive", "condition": scheduler_conf_permissions_secure},
        {"msg": "1.1.16 Ensure that the scheduler.conf file ownership is set to root:root", "condition": scheduler_conf_ownership_secure},
        {"msg": "1.1.17 Ensure that the controller-manager.conf file permissions are set to 644 or more restrictive", "condition": controller_manager_conf_permissions_secure},
        {"msg": "1.1.18 Ensure that the controller-manager.conf file ownership is set to root:root", "condition": controller_manager_conf_ownership_secure},
        {"msg": "1.1.19 Ensure that the OpenShift PKI directory and file ownership is set to root:root", "condition": pki_ownership_secure},
        {"msg": "1.1.20 Ensure that the OpenShift PKI certificate file permissions are set to 644 or more restrictive", "condition": pki_cert_permissions_secure},
        {"msg": "1.1.21 Ensure that the OpenShift PKI key file permissions are set to 600", "condition": pki_key_permissions_secure}
    ]
    m := msgs[_]
    not m.condition
    msg := m.msg
]

etcd_violations := [msg |
    msgs := [
        {"msg": "2.1 Ensure that the --cert-file and --key-file arguments are set as appropriate", "condition": etcd_cert_key_configured},
        {"msg": "2.2 Ensure that the --client-cert-auth argument is set to true", "condition": etcd_client_cert_auth},
        {"msg": "2.3 Ensure that the --auto-tls argument is not set to true", "condition": etcd_auto_tls_disabled},
        {"msg": "2.4 Ensure that the --peer-cert-file and --peer-key-file arguments are set as appropriate", "condition": etcd_peer_cert_configured},
        {"msg": "2.5 Ensure that the --peer-client-cert-auth argument is set to true", "condition": etcd_peer_client_cert_auth},
        {"msg": "2.6 Ensure that the --peer-auto-tls argument is not set to true", "condition": etcd_peer_auto_tls_disabled},
        {"msg": "2.7 Ensure that a unique Certificate Authority is used for etcd", "condition": etcd_unique_ca}
    ]
    m := msgs[_]
    not m.condition
    msg := m.msg
]

control_plane_violations := [msg |
    msgs := [
        {"msg": "3.1.1 Ensure that the --anonymous-auth argument is set to false", "condition": anonymous_auth_disabled},
        {"msg": "3.1.2 Ensure that the --basic-auth-file argument is not set", "condition": basic_auth_disabled},
        {"msg": "3.1.3 Ensure that the --token-auth-file parameter is not set", "condition": token_auth_disabled},
        {"msg": "3.1.4 Ensure that the --kubelet-https argument is set to true", "condition": kubelet_https_enabled},
        {"msg": "3.1.5 Ensure that the --kubelet-client-certificate and --kubelet-client-key arguments are set as appropriate", "condition": kubelet_client_cert_configured},
        {"msg": "3.1.6 Ensure that the --kubelet-certificate-authority argument is set as appropriate", "condition": kubelet_ca_configured},
        {"msg": "3.1.7 Ensure that the --authorization-mode argument is not set to AlwaysAllow", "condition": authorization_mode_secure},
        {"msg": "3.1.8 Ensure that the --authorization-mode argument includes Node", "condition": authorization_mode_includes_node},
        {"msg": "3.1.9 Ensure that the --authorization-mode argument includes RBAC", "condition": authorization_mode_includes_rbac},
        {"msg": "3.1.10 Ensure that the admission control plugin EventRateLimit is set", "condition": event_rate_limit_enabled},
        {"msg": "3.1.11 Ensure that the admission control plugin AlwaysAdmit is not set", "condition": always_admit_disabled},
        {"msg": "3.1.12 Ensure that the admission control plugin AlwaysPullImages is set", "condition": always_pull_images_enabled},
        {"msg": "3.1.13 Ensure that the admission control plugin SecurityContextDeny is set if PodSecurityPolicy is not used", "condition": security_context_deny_configured},
        {"msg": "3.1.14 Ensure that the admission control plugin ServiceAccount is set", "condition": service_account_admission_enabled},
        {"msg": "3.1.15 Ensure that the admission control plugin NamespaceLifecycle is set", "condition": namespace_lifecycle_enabled},
        {"msg": "3.1.16 Ensure that the admission control plugin PodSecurityPolicy is set", "condition": pod_security_policy_enabled},
        {"msg": "3.1.17 Ensure that the admission control plugin NodeRestriction is set", "condition": node_restriction_enabled},
        {"msg": "3.1.18 Ensure that the --insecure-bind-address argument is not set", "condition": insecure_bind_address_disabled},
        {"msg": "3.1.19 Ensure that the --insecure-port argument is set to 0", "condition": insecure_port_disabled},
        {"msg": "3.1.20 Ensure that the --secure-port argument is not set to 0", "condition": secure_port_enabled},
        {"msg": "3.1.21 Ensure that the --profiling argument is set to false", "condition": profiling_disabled},
        {"msg": "3.1.22 Ensure that the --audit-log-path argument is set", "condition": audit_log_path_configured},
        {"msg": "3.1.23 Ensure that the --audit-log-maxage argument is set to 30 or as appropriate", "condition": audit_log_maxage_configured},
        {"msg": "3.1.24 Ensure that the --audit-log-maxbackup argument is set to 10 or as appropriate", "condition": audit_log_maxbackup_configured},
        {"msg": "3.1.25 Ensure that the --audit-log-maxsize argument is set to 100 or as appropriate", "condition": audit_log_maxsize_configured},
        {"msg": "3.1.26 Ensure that the --request-timeout argument is set as appropriate", "condition": request_timeout_configured},
        {"msg": "3.1.27 Ensure that the --service-account-lookup argument is set to true", "condition": service_account_lookup_enabled},
        {"msg": "3.1.28 Ensure that the --service-account-key-file argument is set as appropriate", "condition": service_account_key_configured},
        {"msg": "3.1.29 Ensure that the --etcd-certfile and --etcd-keyfile arguments are set as appropriate", "condition": etcd_cert_configured},
        {"msg": "3.1.30 Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate", "condition": tls_cert_configured},
        {"msg": "3.1.31 Ensure that the --client-ca-file argument is set as appropriate", "condition": client_ca_configured},
        {"msg": "3.1.32 Ensure that the --etcd-cafile argument is set as appropriate", "condition": etcd_ca_configured},
        {"msg": "3.1.33 Ensure that the --encryption-provider-config argument is set as appropriate", "condition": encryption_provider_configured},
        {"msg": "3.1.34 Ensure encryption providers are appropriately configured", "condition": encryption_providers_secure},
        {"msg": "3.1.35 Ensure that the API Server only makes use of Strong Cryptographic Ciphers", "condition": strong_crypto_ciphers}
    ]
    m := msgs[_]
    not m.condition
    msg := m.msg
]

worker_node_violations := [msg |
    msgs := [
        {"msg": "4.1.1 Ensure that the kubelet service file permissions are set to 644 or more restrictive", "condition": kubelet_service_permissions_secure},
        {"msg": "4.1.2 Ensure that the kubelet service file ownership is set to root:root", "condition": kubelet_service_ownership_secure},
        {"msg": "4.1.3 Ensure that the proxy kubeconfig file permissions are set to 644 or more restrictive", "condition": proxy_kubeconfig_permissions_secure},
        {"msg": "4.1.4 Ensure that the proxy kubeconfig file ownership is set to root:root", "condition": proxy_kubeconfig_ownership_secure},
        {"msg": "4.1.5 Ensure that the kubelet.conf file permissions are set to 644 or more restrictive", "condition": kubelet_conf_permissions_secure},
        {"msg": "4.1.6 Ensure that the kubelet.conf file ownership is set to root:root", "condition": kubelet_conf_ownership_secure},
        {"msg": "4.1.7 Ensure that the certificate authorities file permissions are set to 644 or more restrictive", "condition": ca_permissions_secure},
        {"msg": "4.1.8 Ensure that the client certificate authorities file ownership is set to root:root", "condition": ca_ownership_secure},
        {"msg": "4.1.9 Ensure that the kubelet configuration file has permissions set to 644 or more restrictive", "condition": kubelet_config_permissions_secure},
        {"msg": "4.1.10 Ensure that the kubelet configuration file ownership is set to root:root", "condition": kubelet_config_ownership_secure},
        {"msg": "4.2.1 Ensure that the anonymous-auth argument is set to false", "condition": kubelet_anonymous_auth_disabled},
        {"msg": "4.2.2 Ensure that the --authorization-mode argument is not set to AlwaysAllow", "condition": kubelet_authorization_secure},
        {"msg": "4.2.3 Ensure that the --client-ca-file argument is set as appropriate", "condition": kubelet_client_ca_configured},
        {"msg": "4.2.4 Ensure that the --read-only-port argument is set to 0", "condition": kubelet_readonly_port_disabled},
        {"msg": "4.2.5 Ensure that the --streaming-connection-idle-timeout argument is not set to 0", "condition": kubelet_streaming_timeout_configured},
        {"msg": "4.2.6 Ensure that the --protect-kernel-defaults argument is set to true", "condition": kubelet_protect_kernel_defaults},
        {"msg": "4.2.7 Ensure that the --make-iptables-util-chains argument is set to true", "condition": kubelet_iptables_util_chains},
        {"msg": "4.2.8 Ensure that the --hostname-override argument is not set", "condition": kubelet_hostname_override_disabled},
        {"msg": "4.2.9 Ensure that the --event-qps argument is set to 0 or a level which ensures appropriate event capture", "condition": kubelet_event_qps_configured},
        {"msg": "4.2.10 Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate", "condition": kubelet_tls_configured},
        {"msg": "4.2.11 Ensure that the --rotate-certificates argument is not set to false", "condition": kubelet_rotate_certificates_enabled},
        {"msg": "4.2.12 Ensure that the RotateKubeletServerCertificate argument is set to true", "condition": kubelet_rotate_server_certs},
        {"msg": "4.2.13 Ensure that the Kubelet only makes use of Strong Cryptographic Ciphers", "condition": kubelet_strong_crypto_ciphers}
    ]
    m := msgs[_]
    not m.condition
    msg := m.msg
]

kubernetes_policies_violations := [msg |
    msgs := [
        {"msg": "5.1.1 Ensure that the cluster-admin role is only used where required", "condition": cluster_admin_role_restricted},
        {"msg": "5.1.2 Minimize access to secrets", "condition": secrets_access_minimized},
        {"msg": "5.1.3 Minimize wildcard use in Roles and ClusterRoles", "condition": wildcard_usage_minimized},
        {"msg": "5.1.4 Minimize access to create pods", "condition": pod_creation_access_minimized},
        {"msg": "5.1.5 Ensure that default service accounts are not actively used", "condition": default_service_accounts_restricted},
        {"msg": "5.1.6 Ensure that Service Account Tokens are only mounted where necessary", "condition": service_account_tokens_restricted},
        {"msg": "5.2.1 Minimize the admission of privileged containers", "condition": privileged_containers_minimized},
        {"msg": "5.2.2 Minimize the admission of containers wishing to share the host process ID namespace", "condition": host_pid_sharing_minimized},
        {"msg": "5.2.3 Minimize the admission of containers wishing to share the host IPC namespace", "condition": host_ipc_sharing_minimized},
        {"msg": "5.2.4 Minimize the admission of containers wishing to share the host network namespace", "condition": host_network_sharing_minimized},
        {"msg": "5.2.5 Minimize the admission of containers with allowPrivilegeEscalation", "condition": privilege_escalation_minimized},
        {"msg": "5.2.6 Minimize the admission of root containers", "condition": root_containers_minimized},
        {"msg": "5.2.7 Minimize the admission of containers with the NET_RAW capability", "condition": net_raw_capability_minimized},
        {"msg": "5.2.8 Minimize the admission of containers with added capabilities", "condition": added_capabilities_minimized},
        {"msg": "5.2.9 Minimize the admission of containers with capabilities assigned", "condition": capabilities_assignment_minimized},
        {"msg": "5.3.1 Ensure that the CNI in use supports Network Policies", "condition": cni_network_policies_supported},
        {"msg": "5.3.2 Ensure that all Namespaces have Network Policies defined", "condition": namespace_network_policies_defined},
        {"msg": "5.4.1 Prefer using secrets as files over secrets as environment variables", "condition": secrets_as_files_preferred},
        {"msg": "5.4.2 Consider external secret storage", "condition": external_secret_storage_considered},
        {"msg": "5.5.1 Configure Image Provenance using ImagePolicyWebhook admission controller", "condition": image_provenance_configured},
        {"msg": "5.7.1 Create administrative boundaries between resources using namespaces", "condition": administrative_boundaries_configured},
        {"msg": "5.7.2 Ensure that the seccomp profile is set to docker/default in your pod definitions", "condition": seccomp_profile_configured},
        {"msg": "5.7.3 Apply Security Context to Your Pods and Containers", "condition": security_context_applied},
        {"msg": "5.7.4 The default namespace should not be used", "condition": default_namespace_avoided}
    ]
    m := msgs[_]
    not m.condition
    msg := m.msg
]

network_policies_violations := [msg |
    msgs := [
        {"msg": "6.1.1 Ensure that OpenShift Network Policies are in place", "condition": openshift_network_policies_configured},
        {"msg": "6.1.2 Ensure that network segmentation is applied", "condition": network_segmentation_applied},
        {"msg": "6.1.3 Ensure that traffic between nodes and masters is encrypted", "condition": node_master_traffic_encrypted},
        {"msg": "6.1.4 Ensure that traffic between pods is encrypted when required", "condition": pod_traffic_encryption_configured},
        {"msg": "6.2.1 Ensure that Ingress Controllers have appropriate security configurations", "condition": ingress_controllers_secure},
        {"msg": "6.2.2 Ensure that Routes have appropriate security configurations", "condition": routes_security_configured},
        {"msg": "6.2.3 Ensure that external traffic is properly controlled", "condition": external_traffic_controlled},
        {"msg": "6.3.1 Ensure that Service Mesh is configured securely when used", "condition": service_mesh_secure},
        {"msg": "6.3.2 Ensure that sidecar injection is properly configured", "condition": sidecar_injection_configured}
    ]
    m := msgs[_]
    not m.condition
    msg := m.msg
]

authentication_violations := [msg |
    msgs := [
        {"msg": "7.1.1 Ensure that OpenShift identity providers are properly configured", "condition": identity_providers_configured},
        {"msg": "7.1.2 Ensure that LDAP/Active Directory integration is secure", "condition": ldap_integration_secure},
        {"msg": "7.1.3 Ensure that OAuth configuration is secure", "condition": oauth_configuration_secure},
        {"msg": "7.1.4 Ensure that service account authentication is properly configured", "condition": service_account_auth_configured},
        {"msg": "7.2.1 Ensure that multi-factor authentication is enabled where possible", "condition": mfa_enabled},
        {"msg": "7.2.2 Ensure that strong password policies are enforced", "condition": strong_password_policies},
        {"msg": "7.2.3 Ensure that session timeouts are appropriately configured", "condition": session_timeouts_configured},
        {"msg": "7.3.1 Ensure that certificate-based authentication is used where appropriate", "condition": cert_based_auth_configured},
        {"msg": "7.3.2 Ensure that certificate rotation is properly configured", "condition": cert_rotation_configured}
    ]
    m := msgs[_]
    not m.condition
    msg := m.msg
]

authorization_violations := [msg |
    msgs := [
        {"msg": "8.1.1 Ensure that RBAC is properly configured", "condition": rbac_properly_configured},
        {"msg": "8.1.2 Ensure that role bindings are reviewed regularly", "condition": role_bindings_reviewed},
        {"msg": "8.1.3 Ensure that cluster role bindings are minimized", "condition": cluster_role_bindings_minimized},
        {"msg": "8.2.1 Ensure that Security Context Constraints are properly configured", "condition": scc_properly_configured},
        {"msg": "8.2.2 Ensure that custom SCCs follow security best practices", "condition": custom_scc_secure},
        {"msg": "8.2.3 Ensure that privileged SCCs are restricted", "condition": privileged_scc_restricted},
        {"msg": "8.3.1 Ensure that admission controllers are properly configured", "condition": admission_controllers_configured},
        {"msg": "8.3.2 Ensure that custom admission controllers are secure", "condition": custom_admission_controllers_secure}
    ]
    m := msgs[_]
    not m.condition
    msg := m.msg
]

logging_violations := [msg |
    msgs := [
        {"msg": "9.1.1 Ensure that audit logging is enabled", "condition": audit_logging_enabled},
        {"msg": "9.1.2 Ensure that audit log retention is configured appropriately", "condition": audit_log_retention_configured},
        {"msg": "9.1.3 Ensure that audit logs are stored securely", "condition": audit_logs_stored_securely},
        {"msg": "9.2.1 Ensure that application logging is properly configured", "condition": application_logging_configured},
        {"msg": "9.2.2 Ensure that log aggregation is properly configured", "condition": log_aggregation_configured},
        {"msg": "9.2.3 Ensure that sensitive information is not logged", "condition": sensitive_info_logging_prevented},
        {"msg": "9.3.1 Ensure that log monitoring and alerting is configured", "condition": log_monitoring_configured},
        {"msg": "9.3.2 Ensure that security events are properly logged and alerted", "condition": security_events_monitored},
        {"msg": "9.4.1 Ensure that logs are backed up regularly", "condition": logs_backed_up},
        {"msg": "9.4.2 Ensure that log integrity is maintained", "condition": log_integrity_maintained}
    ]
    m := msgs[_]
    not m.condition
    msg := m.msg
]

secrets_management_violations := [msg |
    msgs := [
        {"msg": "10.1.1 Ensure that secrets are not stored in container images", "condition": secrets_not_in_images},
        {"msg": "10.1.2 Ensure that secrets are properly encrypted at rest", "condition": secrets_encrypted_at_rest},
        {"msg": "10.1.3 Ensure that secrets are encrypted in transit", "condition": secrets_encrypted_in_transit},
        {"msg": "10.2.1 Ensure that secret rotation is properly configured", "condition": secret_rotation_configured},
        {"msg": "10.2.2 Ensure that secret access is logged and monitored", "condition": secret_access_monitored},
        {"msg": "10.2.3 Ensure that secret lifecycle management is implemented", "condition": secret_lifecycle_managed},
        {"msg": "10.3.1 Ensure that external secret management systems are used when appropriate", "condition": external_secret_management},
        {"msg": "10.3.2 Ensure that secret injection is done securely", "condition": secure_secret_injection},
        {"msg": "10.4.1 Ensure that certificate management is automated", "condition": automated_cert_management},
        {"msg": "10.4.2 Ensure that certificate expiration monitoring is configured", "condition": cert_expiration_monitoring}
    ]
    m := msgs[_]
    not m.condition
    msg := m.msg
]

default api_server_permissions_secure := false

api_server_permissions_secure if {
    "master_node.api_server.permissions" in perm_ok
}

default api_server_ownership_secure := false

api_server_ownership_secure if {
    input.openshift.master_node.api_server.owner == "root"
    input.openshift.master_node.api_server.group == "root"
}

default controller_manager_permissions_secure := false

controller_manager_permissions_secure if {
    "master_node.controller_manager.permissions" in perm_ok
}

default controller_manager_ownership_secure := false

controller_manager_ownership_secure if {
    input.openshift.master_node.controller_manager.owner == "root"
    input.openshift.master_node.controller_manager.group == "root"
}

default scheduler_permissions_secure := false

scheduler_permissions_secure if {
    "master_node.scheduler.permissions" in perm_ok
}

default scheduler_ownership_secure := false

scheduler_ownership_secure if {
    input.openshift.master_node.scheduler.owner == "root"
    input.openshift.master_node.scheduler.group == "root"
}

default etcd_permissions_secure := false

etcd_permissions_secure if {
    "master_node.etcd.permissions" in perm_ok
}

default etcd_ownership_secure := false

etcd_ownership_secure if {
    input.openshift.master_node.etcd.owner == "root"
    input.openshift.master_node.etcd.group == "root"
}

default cni_permissions_secure := false

cni_permissions_secure if {
    "master_node.cni.permissions" in perm_ok
}

default cni_ownership_secure := false

cni_ownership_secure if {
    input.openshift.master_node.cni.owner == "root"
    input.openshift.master_node.cni.group == "root"
}

default etcd_data_permissions_secure := false

etcd_data_permissions_secure if {
    "master_node.etcd_data.permissions" in perm_ok
}

default etcd_data_ownership_secure := false

etcd_data_ownership_secure if {
    input.openshift.master_node.etcd_data.owner == "etcd"
    input.openshift.master_node.etcd_data.group == "etcd"
}

default admin_conf_permissions_secure := false

admin_conf_permissions_secure if {
    "master_node.admin_conf.permissions" in perm_ok
}

default admin_conf_ownership_secure := false

admin_conf_ownership_secure if {
    input.openshift.master_node.admin_conf.owner == "root"
    input.openshift.master_node.admin_conf.group == "root"
}

default scheduler_conf_permissions_secure := false

scheduler_conf_permissions_secure if {
    "master_node.scheduler_conf.permissions" in perm_ok
}

default scheduler_conf_ownership_secure := false

scheduler_conf_ownership_secure if {
    input.openshift.master_node.scheduler_conf.owner == "root"
    input.openshift.master_node.scheduler_conf.group == "root"
}

default controller_manager_conf_permissions_secure := false

controller_manager_conf_permissions_secure if {
    "master_node.controller_manager_conf.permissions" in perm_ok
}

default controller_manager_conf_ownership_secure := false

controller_manager_conf_ownership_secure if {
    input.openshift.master_node.controller_manager_conf.owner == "root"
    input.openshift.master_node.controller_manager_conf.group == "root"
}

default pki_ownership_secure := false

pki_ownership_secure if {
    input.openshift.master_node.pki.owner == "root"
    input.openshift.master_node.pki.group == "root"
}

default pki_cert_permissions_secure := false

pki_cert_permissions_secure if {
    "master_node.pki.cert_permissions" in perm_ok
}

default pki_key_permissions_secure := false

pki_key_permissions_secure if {
    "master_node.pki.key_permissions" in perm_ok
}

default etcd_cert_key_configured := false

etcd_cert_key_configured if {
    input.openshift.etcd.cert_file != ""
    input.openshift.etcd.key_file != ""
}

default etcd_client_cert_auth := false

etcd_client_cert_auth if {
    input.openshift.etcd.client_cert_auth == true
}

default etcd_auto_tls_disabled := false

etcd_auto_tls_disabled if {
    input.openshift.etcd.auto_tls != true
}

default etcd_peer_cert_configured := false

etcd_peer_cert_configured if {
    input.openshift.etcd.peer_cert_file != ""
    input.openshift.etcd.peer_key_file != ""
}

default etcd_peer_client_cert_auth := false

etcd_peer_client_cert_auth if {
    input.openshift.etcd.peer_client_cert_auth == true
}

default etcd_peer_auto_tls_disabled := false

etcd_peer_auto_tls_disabled if {
    input.openshift.etcd.peer_auto_tls != true
}

default etcd_unique_ca := false

etcd_unique_ca if {
    input.openshift.etcd.unique_ca == true
}

default anonymous_auth_disabled := false

anonymous_auth_disabled if {
    input.openshift.control_plane.anonymous_auth == false
}

default basic_auth_disabled := false

basic_auth_disabled if {
    input.openshift.control_plane.basic_auth_file == ""
}

default token_auth_disabled := false

token_auth_disabled if {
    input.openshift.control_plane.token_auth_file == ""
}

default kubelet_https_enabled := false

kubelet_https_enabled if {
    input.openshift.control_plane.kubelet_https == true
}

default kubelet_client_cert_configured := false

kubelet_client_cert_configured if {
    input.openshift.control_plane.kubelet_client_certificate != ""
    input.openshift.control_plane.kubelet_client_key != ""
}

default kubelet_ca_configured := false

kubelet_ca_configured if {
    input.openshift.control_plane.kubelet_certificate_authority != ""
}

# --authorization-mode may arrive as a list or as the comma-separated flag value.
authorization_modes := modes if {
    raw := input.openshift.control_plane.authorization_mode
    is_array(raw)
    modes := {m | some m in raw}
} else := modes if {
    raw := input.openshift.control_plane.authorization_mode
    is_string(raw)
    modes := {trim_space(m) | some m in split(raw, ",")}
}

default authorization_mode_secure := false

authorization_mode_secure if {
    modes := authorization_modes
    not "AlwaysAllow" in modes
}

default authorization_mode_includes_node := false

authorization_mode_includes_node if {
    "Node" in authorization_modes
}

default authorization_mode_includes_rbac := false

authorization_mode_includes_rbac if {
    "RBAC" in authorization_modes
}

default event_rate_limit_enabled := false

event_rate_limit_enabled if {
    "EventRateLimit" in input.openshift.control_plane.admission_plugins
}

default always_admit_disabled := false

always_admit_disabled if {
    not "AlwaysAdmit" in input.openshift.control_plane.admission_plugins
}

default always_pull_images_enabled := false

always_pull_images_enabled if {
    "AlwaysPullImages" in input.openshift.control_plane.admission_plugins
}

default security_context_deny_configured := false

security_context_deny_configured if {
    input.openshift.control_plane.security_context_deny_configured == true
}

default service_account_admission_enabled := false

service_account_admission_enabled if {
    "ServiceAccount" in input.openshift.control_plane.admission_plugins
}

default namespace_lifecycle_enabled := false

namespace_lifecycle_enabled if {
    "NamespaceLifecycle" in input.openshift.control_plane.admission_plugins
}

default pod_security_policy_enabled := false

pod_security_policy_enabled if {
    "PodSecurityPolicy" in input.openshift.control_plane.admission_plugins
}

default node_restriction_enabled := false

node_restriction_enabled if {
    "NodeRestriction" in input.openshift.control_plane.admission_plugins
}

default insecure_bind_address_disabled := false

insecure_bind_address_disabled if {
    input.openshift.control_plane.insecure_bind_address == ""
}

default insecure_port_disabled := false

insecure_port_disabled if {
    input.openshift.control_plane.insecure_port == 0
}

default secure_port_enabled := false

secure_port_enabled if {
    input.openshift.control_plane.secure_port != 0
}

default profiling_disabled := false

profiling_disabled if {
    input.openshift.control_plane.profiling == false
}

default audit_log_path_configured := false

audit_log_path_configured if {
    input.openshift.control_plane.audit_log_path != ""
}

default audit_log_maxage_configured := false

audit_log_maxage_configured if {
    input.openshift.control_plane.audit_log_maxage >= 30
}

default audit_log_maxbackup_configured := false

audit_log_maxbackup_configured if {
    input.openshift.control_plane.audit_log_maxbackup >= 10
}

default audit_log_maxsize_configured := false

audit_log_maxsize_configured if {
    input.openshift.control_plane.audit_log_maxsize >= 100
}

default request_timeout_configured := false

request_timeout_configured if {
    input.openshift.control_plane.request_timeout > 0
    input.openshift.control_plane.request_timeout <= 300
}

default service_account_lookup_enabled := false

service_account_lookup_enabled if {
    input.openshift.control_plane.service_account_lookup == true
}

default service_account_key_configured := false

service_account_key_configured if {
    input.openshift.control_plane.service_account_key_file != ""
}

default etcd_cert_configured := false

etcd_cert_configured if {
    input.openshift.control_plane.etcd_certfile != ""
    input.openshift.control_plane.etcd_keyfile != ""
}

default tls_cert_configured := false

tls_cert_configured if {
    input.openshift.control_plane.tls_cert_file != ""
    input.openshift.control_plane.tls_private_key_file != ""
}

default client_ca_configured := false

client_ca_configured if {
    input.openshift.control_plane.client_ca_file != ""
}

default etcd_ca_configured := false

etcd_ca_configured if {
    input.openshift.control_plane.etcd_cafile != ""
}

default encryption_provider_configured := false

encryption_provider_configured if {
    input.openshift.control_plane.encryption_provider_config != ""
}

default encryption_providers_secure := false

encryption_providers_secure if {
    input.openshift.control_plane.encryption_providers_secure == true
}

default strong_crypto_ciphers := false

strong_crypto_ciphers if {
    input.openshift.control_plane.strong_crypto_ciphers == true
}

default kubelet_service_permissions_secure := false

kubelet_service_permissions_secure if {
    "worker_node.kubelet_service.permissions" in perm_ok
}

default kubelet_service_ownership_secure := false

kubelet_service_ownership_secure if {
    input.openshift.worker_node.kubelet_service.owner == "root"
    input.openshift.worker_node.kubelet_service.group == "root"
}

default proxy_kubeconfig_permissions_secure := false

proxy_kubeconfig_permissions_secure if {
    "worker_node.proxy_kubeconfig.permissions" in perm_ok
}

default proxy_kubeconfig_ownership_secure := false

proxy_kubeconfig_ownership_secure if {
    input.openshift.worker_node.proxy_kubeconfig.owner == "root"
    input.openshift.worker_node.proxy_kubeconfig.group == "root"
}

default kubelet_conf_permissions_secure := false

kubelet_conf_permissions_secure if {
    "worker_node.kubelet_conf.permissions" in perm_ok
}

default kubelet_conf_ownership_secure := false

kubelet_conf_ownership_secure if {
    input.openshift.worker_node.kubelet_conf.owner == "root"
    input.openshift.worker_node.kubelet_conf.group == "root"
}

default ca_permissions_secure := false

ca_permissions_secure if {
    "worker_node.ca.permissions" in perm_ok
}

default ca_ownership_secure := false

ca_ownership_secure if {
    input.openshift.worker_node.ca.owner == "root"
    input.openshift.worker_node.ca.group == "root"
}

default kubelet_config_permissions_secure := false

kubelet_config_permissions_secure if {
    "worker_node.kubelet_config.permissions" in perm_ok
}

default kubelet_config_ownership_secure := false

kubelet_config_ownership_secure if {
    input.openshift.worker_node.kubelet_config.owner == "root"
    input.openshift.worker_node.kubelet_config.group == "root"
}

default kubelet_anonymous_auth_disabled := false

kubelet_anonymous_auth_disabled if {
    input.openshift.worker_node.kubelet.anonymous_auth == false
}

default kubelet_authorization_secure := false

kubelet_authorization_secure if {
    input.openshift.worker_node.kubelet.authorization_mode != "AlwaysAllow"
}

default kubelet_client_ca_configured := false

kubelet_client_ca_configured if {
    input.openshift.worker_node.kubelet.client_ca_file != ""
}

default kubelet_readonly_port_disabled := false

kubelet_readonly_port_disabled if {
    input.openshift.worker_node.kubelet.read_only_port == 0
}

default kubelet_streaming_timeout_configured := false

kubelet_streaming_timeout_configured if {
    input.openshift.worker_node.kubelet.streaming_connection_idle_timeout != 0
}

default kubelet_protect_kernel_defaults := false

kubelet_protect_kernel_defaults if {
    input.openshift.worker_node.kubelet.protect_kernel_defaults == true
}

default kubelet_iptables_util_chains := false

kubelet_iptables_util_chains if {
    input.openshift.worker_node.kubelet.make_iptables_util_chains == true
}

default kubelet_hostname_override_disabled := false

kubelet_hostname_override_disabled if {
    input.openshift.worker_node.kubelet.hostname_override == ""
}

default kubelet_event_qps_configured := false

kubelet_event_qps_configured if {
    input.openshift.worker_node.kubelet.event_qps >= 0
}

default kubelet_tls_configured := false

kubelet_tls_configured if {
    input.openshift.worker_node.kubelet.tls_cert_file != ""
    input.openshift.worker_node.kubelet.tls_private_key_file != ""
}

default kubelet_rotate_certificates_enabled := false

kubelet_rotate_certificates_enabled if {
    input.openshift.worker_node.kubelet.rotate_certificates != false
}

default kubelet_rotate_server_certs := false

kubelet_rotate_server_certs if {
    input.openshift.worker_node.kubelet.rotate_kubelet_server_certificate == true
}

default kubelet_strong_crypto_ciphers := false

kubelet_strong_crypto_ciphers if {
    input.openshift.worker_node.kubelet.strong_crypto_ciphers == true
}

default cluster_admin_role_restricted := false

cluster_admin_role_restricted if {
    input.openshift.kubernetes_policies.cluster_admin_restricted == true
}

default secrets_access_minimized := false

secrets_access_minimized if {
    input.openshift.kubernetes_policies.secrets_access_minimized == true
}

default wildcard_usage_minimized := false

wildcard_usage_minimized if {
    input.openshift.kubernetes_policies.wildcard_minimized == true
}

default pod_creation_access_minimized := false

pod_creation_access_minimized if {
    input.openshift.kubernetes_policies.pod_creation_minimized == true
}

default default_service_accounts_restricted := false

default_service_accounts_restricted if {
    input.openshift.kubernetes_policies.default_sa_restricted == true
}

default service_account_tokens_restricted := false

service_account_tokens_restricted if {
    input.openshift.kubernetes_policies.sa_tokens_restricted == true
}

default privileged_containers_minimized := false

privileged_containers_minimized if {
    input.openshift.kubernetes_policies.privileged_containers_minimized == true
}

default host_pid_sharing_minimized := false

host_pid_sharing_minimized if {
    input.openshift.kubernetes_policies.host_pid_minimized == true
}

default host_ipc_sharing_minimized := false

host_ipc_sharing_minimized if {
    input.openshift.kubernetes_policies.host_ipc_minimized == true
}

default host_network_sharing_minimized := false

host_network_sharing_minimized if {
    input.openshift.kubernetes_policies.host_network_minimized == true
}

default privilege_escalation_minimized := false

privilege_escalation_minimized if {
    input.openshift.kubernetes_policies.privilege_escalation_minimized == true
}

default root_containers_minimized := false

root_containers_minimized if {
    input.openshift.kubernetes_policies.root_containers_minimized == true
}

default net_raw_capability_minimized := false

net_raw_capability_minimized if {
    input.openshift.kubernetes_policies.net_raw_minimized == true
}

default added_capabilities_minimized := false

added_capabilities_minimized if {
    input.openshift.kubernetes_policies.added_capabilities_minimized == true
}

default capabilities_assignment_minimized := false

capabilities_assignment_minimized if {
    input.openshift.kubernetes_policies.capabilities_minimized == true
}

default cni_network_policies_supported := false

cni_network_policies_supported if {
    input.openshift.kubernetes_policies.cni_network_policies == true
}

default namespace_network_policies_defined := false

namespace_network_policies_defined if {
    input.openshift.kubernetes_policies.namespace_network_policies == true
}

default secrets_as_files_preferred := false

secrets_as_files_preferred if {
    input.openshift.kubernetes_policies.secrets_as_files == true
}

default external_secret_storage_considered := false

external_secret_storage_considered if {
    input.openshift.kubernetes_policies.external_secret_storage == true
}

default image_provenance_configured := false

image_provenance_configured if {
    input.openshift.kubernetes_policies.image_provenance == true
}

default administrative_boundaries_configured := false

administrative_boundaries_configured if {
    input.openshift.kubernetes_policies.admin_boundaries == true
}

default seccomp_profile_configured := false

seccomp_profile_configured if {
    input.openshift.kubernetes_policies.seccomp_profile == true
}

default security_context_applied := false

security_context_applied if {
    input.openshift.kubernetes_policies.security_context == true
}

default default_namespace_avoided := false

default_namespace_avoided if {
    input.openshift.kubernetes_policies.default_namespace_avoided == true
}

default openshift_network_policies_configured := false

openshift_network_policies_configured if {
    input.openshift.network_policies.openshift_policies == true
}

default network_segmentation_applied := false

network_segmentation_applied if {
    input.openshift.network_policies.segmentation == true
}

default node_master_traffic_encrypted := false

node_master_traffic_encrypted if {
    input.openshift.network_policies.node_master_encryption == true
}

default pod_traffic_encryption_configured := false

pod_traffic_encryption_configured if {
    input.openshift.network_policies.pod_encryption == true
}

default ingress_controllers_secure := false

ingress_controllers_secure if {
    input.openshift.network_policies.ingress_controllers_secure == true
}

default routes_security_configured := false

routes_security_configured if {
    input.openshift.network_policies.routes_secure == true
}

default external_traffic_controlled := false

external_traffic_controlled if {
    input.openshift.network_policies.external_traffic_control == true
}

default service_mesh_secure := false

service_mesh_secure if {
    input.openshift.network_policies.service_mesh_secure == true
}

default sidecar_injection_configured := false

sidecar_injection_configured if {
    input.openshift.network_policies.sidecar_injection == true
}

default identity_providers_configured := false

identity_providers_configured if {
    input.openshift.authentication.identity_providers == true
}

default ldap_integration_secure := false

ldap_integration_secure if {
    input.openshift.authentication.ldap_secure == true
}

default oauth_configuration_secure := false

oauth_configuration_secure if {
    input.openshift.authentication.oauth_secure == true
}

default service_account_auth_configured := false

service_account_auth_configured if {
    input.openshift.authentication.service_account_auth == true
}

default mfa_enabled := false

mfa_enabled if {
    input.openshift.authentication.mfa_enabled == true
}

default strong_password_policies := false

strong_password_policies if {
    input.openshift.authentication.strong_passwords == true
}

default session_timeouts_configured := false

session_timeouts_configured if {
    input.openshift.authentication.session_timeouts == true
}

default cert_based_auth_configured := false

cert_based_auth_configured if {
    input.openshift.authentication.cert_based_auth == true
}

default cert_rotation_configured := false

cert_rotation_configured if {
    input.openshift.authentication.cert_rotation == true
}

default rbac_properly_configured := false

rbac_properly_configured if {
    input.openshift.authorization.rbac_configured == true
}

default role_bindings_reviewed := false

role_bindings_reviewed if {
    input.openshift.authorization.role_bindings_reviewed == true
}

default cluster_role_bindings_minimized := false

cluster_role_bindings_minimized if {
    input.openshift.authorization.cluster_role_bindings_minimized == true
}

default scc_properly_configured := false

scc_properly_configured if {
    input.openshift.authorization.scc_configured == true
}

default custom_scc_secure := false

custom_scc_secure if {
    input.openshift.authorization.custom_scc_secure == true
}

default privileged_scc_restricted := false

privileged_scc_restricted if {
    input.openshift.authorization.privileged_scc_restricted == true
}

default admission_controllers_configured := false

admission_controllers_configured if {
    input.openshift.authorization.admission_controllers == true
}

default custom_admission_controllers_secure := false

custom_admission_controllers_secure if {
    input.openshift.authorization.custom_admission_secure == true
}

default audit_logging_enabled := false

audit_logging_enabled if {
    input.openshift.logging.audit_enabled == true
}

default audit_log_retention_configured := false

audit_log_retention_configured if {
    input.openshift.logging.audit_retention == true
}

default audit_logs_stored_securely := false

audit_logs_stored_securely if {
    input.openshift.logging.audit_storage_secure == true
}

default application_logging_configured := false

application_logging_configured if {
    input.openshift.logging.application_logging == true
}

default log_aggregation_configured := false

log_aggregation_configured if {
    input.openshift.logging.log_aggregation == true
}

default sensitive_info_logging_prevented := false

sensitive_info_logging_prevented if {
    input.openshift.logging.sensitive_info_prevented == true
}

default log_monitoring_configured := false

log_monitoring_configured if {
    input.openshift.logging.log_monitoring == true
}

default security_events_monitored := false

security_events_monitored if {
    input.openshift.logging.security_events_monitored == true
}

default logs_backed_up := false

logs_backed_up if {
    input.openshift.logging.logs_backed_up == true
}

default log_integrity_maintained := false

log_integrity_maintained if {
    input.openshift.logging.log_integrity == true
}

default secrets_not_in_images := false

secrets_not_in_images if {
    input.openshift.secrets_management.secrets_not_in_images == true
}

default secrets_encrypted_at_rest := false

secrets_encrypted_at_rest if {
    input.openshift.secrets_management.encryption_at_rest == true
}

default secrets_encrypted_in_transit := false

secrets_encrypted_in_transit if {
    input.openshift.secrets_management.encryption_in_transit == true
}

default secret_rotation_configured := false

secret_rotation_configured if {
    input.openshift.secrets_management.rotation_configured == true
}

default secret_access_monitored := false

secret_access_monitored if {
    input.openshift.secrets_management.access_monitored == true
}

default secret_lifecycle_managed := false

secret_lifecycle_managed if {
    input.openshift.secrets_management.lifecycle_managed == true
}

default external_secret_management := false

external_secret_management if {
    input.openshift.secrets_management.external_management == true
}

default secure_secret_injection := false

secure_secret_injection if {
    input.openshift.secrets_management.secure_injection == true
}

default automated_cert_management := false

automated_cert_management if {
    input.openshift.secrets_management.automated_cert_mgmt == true
}

default cert_expiration_monitoring := false

cert_expiration_monitoring if {
    input.openshift.secrets_management.cert_expiration_monitoring == true
}

findings := [
    {
        "title": "OpenShift 4.x Security Configuration Assessment",
        "description": "Comprehensive security assessment of OpenShift 4.x cluster configuration covering master nodes, etcd, control plane, worker nodes, Kubernetes policies, network policies, authentication, authorization, logging, and secrets management",
        "severity": "HIGH",
        "details": sprintf("Found %d configuration violations across OpenShift security domains", [count(violations)]),
        "violations": violations,
        "remediation": "Review and implement the recommended OpenShift security configurations including proper file permissions and ownership, secure etcd configuration, hardened control plane settings, secure worker node configuration, appropriate Kubernetes policies, network security controls, strong authentication and authorization mechanisms, comprehensive logging, and secure secrets management"
    }
]