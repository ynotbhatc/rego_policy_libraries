package cis.kubernetes.master

import rego.v1

# CIS Kubernetes Benchmark
# Section 1: Master Node Security Configuration

# CIS 1.1.1 - Ensure that the API server pod specification file permissions are set to 644 or more restrictive
api_server_pod_file_permissions if {
    input.file_permissions["/etc/kubernetes/manifests/kube-apiserver.yaml"].mode == "644"
}

# CIS 1.1.2 - Ensure that the API server pod specification file ownership is set to root:root
api_server_pod_file_ownership if {
    input.file_permissions["/etc/kubernetes/manifests/kube-apiserver.yaml"].owner == "root"
    input.file_permissions["/etc/kubernetes/manifests/kube-apiserver.yaml"].group == "root"
}

# CIS 1.1.3 - Ensure that the controller manager pod specification file permissions are set to 644 or more restrictive
controller_manager_pod_file_permissions if {
    input.file_permissions["/etc/kubernetes/manifests/kube-controller-manager.yaml"].mode == "644"
}

# CIS 1.1.4 - Ensure that the controller manager pod specification file ownership is set to root:root
controller_manager_pod_file_ownership if {
    input.file_permissions["/etc/kubernetes/manifests/kube-controller-manager.yaml"].owner == "root"
    input.file_permissions["/etc/kubernetes/manifests/kube-controller-manager.yaml"].group == "root"
}

# CIS 1.1.5 - Ensure that the scheduler pod specification file permissions are set to 644 or more restrictive
scheduler_pod_file_permissions if {
    input.file_permissions["/etc/kubernetes/manifests/kube-scheduler.yaml"].mode == "644"
}

# CIS 1.1.6 - Ensure that the scheduler pod specification file ownership is set to root:root
scheduler_pod_file_ownership if {
    input.file_permissions["/etc/kubernetes/manifests/kube-scheduler.yaml"].owner == "root"
    input.file_permissions["/etc/kubernetes/manifests/kube-scheduler.yaml"].group == "root"
}

# CIS 1.1.7 - Ensure that the etcd pod specification file permissions are set to 644 or more restrictive
etcd_pod_file_permissions if {
    input.file_permissions["/etc/kubernetes/manifests/etcd.yaml"].mode == "644"
}

# CIS 1.1.8 - Ensure that the etcd pod specification file ownership is set to root:root
etcd_pod_file_ownership if {
    input.file_permissions["/etc/kubernetes/manifests/etcd.yaml"].owner == "root"
    input.file_permissions["/etc/kubernetes/manifests/etcd.yaml"].group == "root"
}

# CIS 1.2.1 - Ensure that the --anonymous-auth argument is set to false
anonymous_auth_disabled if {
    contains(input.kube_apiserver_args, "--anonymous-auth=false")
}

# CIS 1.2.2 - Ensure that the --basic-auth-file argument is not set
basic_auth_file_not_set if {
    not regex.match("--basic-auth-file", input.kube_apiserver_args)
}

# CIS 1.2.3 - Ensure that the --token-auth-file argument is not set
token_auth_file_not_set if {
    not regex.match("--token-auth-file", input.kube_apiserver_args)
}

# CIS 1.2.4 - Ensure that the --kubelet-https argument is set to true
kubelet_https_enabled if {
    contains(input.kube_apiserver_args, "--kubelet-https=true")
}

kubelet_https_enabled if {
    # Default is true if not specified
    not regex.match("--kubelet-https", input.kube_apiserver_args)
}

# CIS 1.2.5 - Ensure that the --kubelet-client-certificate and --kubelet-client-key arguments are set as appropriate
kubelet_client_cert_configured if {
    regex.match("--kubelet-client-certificate=", input.kube_apiserver_args)
    regex.match("--kubelet-client-key=", input.kube_apiserver_args)
}

# CIS 1.2.6 - Ensure that the --kubelet-certificate-authority argument is set as appropriate
kubelet_certificate_authority_set if {
    regex.match("--kubelet-certificate-authority=", input.kube_apiserver_args)
}

# CIS 1.2.7 - Ensure that the --authorization-mode argument is not set to AlwaysAllow
authorization_mode_not_always_allow if {
    not contains(input.kube_apiserver_args, "--authorization-mode=AlwaysAllow")
}

# CIS 1.2.8 - Ensure that the --authorization-mode argument includes Node
authorization_mode_includes_node if {
    regex.match("--authorization-mode=.*Node", input.kube_apiserver_args)
}

# CIS 1.2.9 - Ensure that the --authorization-mode argument includes RBAC
authorization_mode_includes_rbac if {
    regex.match("--authorization-mode=.*RBAC", input.kube_apiserver_args)
}

# CIS 1.2.10 - Ensure that the admission control plugin EventRateLimit is set
admission_control_event_rate_limit if {
    regex.match("--enable-admission-plugins=.*EventRateLimit", input.kube_apiserver_args)
}

# CIS 1.2.11 - Ensure that the admission control plugin AlwaysAdmit is not set
admission_control_not_always_admit if {
    not regex.match("--enable-admission-plugins=.*AlwaysAdmit", input.kube_apiserver_args)
}

# CIS 1.2.12 - Ensure that the admission control plugin AlwaysPullImages is set
admission_control_always_pull_images if {
    regex.match("--enable-admission-plugins=.*AlwaysPullImages", input.kube_apiserver_args)
}

# CIS 1.2.13 - Ensure that the admission control plugin SecurityContextDeny is set, if PodSecurityPolicy is not used
admission_control_security_context_deny if {
    regex.match("--enable-admission-plugins=.*SecurityContextDeny", input.kube_apiserver_args)
}

admission_control_security_context_deny if {
    # Alternative: PodSecurityPolicy is used
    regex.match("--enable-admission-plugins=.*PodSecurityPolicy", input.kube_apiserver_args)
}

# CIS 1.2.14 - Ensure that the admission control plugin ServiceAccount is set
admission_control_service_account if {
    regex.match("--enable-admission-plugins=.*ServiceAccount", input.kube_apiserver_args)
}

admission_control_service_account if {
    # Default behavior if not explicitly disabled
    not regex.match("--disable-admission-plugins=.*ServiceAccount", input.kube_apiserver_args)
}

# CIS 1.2.15 - Ensure that the admission control plugin NamespaceLifecycle is set
admission_control_namespace_lifecycle if {
    regex.match("--enable-admission-plugins=.*NamespaceLifecycle", input.kube_apiserver_args)
}

admission_control_namespace_lifecycle if {
    # Default behavior if not explicitly disabled
    not regex.match("--disable-admission-plugins=.*NamespaceLifecycle", input.kube_apiserver_args)
}

# Aggregate Kubernetes master node compliance
kubernetes_master_compliant if {
    api_server_pod_file_permissions
    api_server_pod_file_ownership
    controller_manager_pod_file_permissions
    controller_manager_pod_file_ownership
    scheduler_pod_file_permissions
    scheduler_pod_file_ownership
    etcd_pod_file_permissions
    etcd_pod_file_ownership
    anonymous_auth_disabled
    basic_auth_file_not_set
    token_auth_file_not_set
    kubelet_https_enabled
    kubelet_client_cert_configured
    kubelet_certificate_authority_set
    authorization_mode_not_always_allow
    authorization_mode_includes_node
    authorization_mode_includes_rbac
    admission_control_event_rate_limit
    admission_control_not_always_admit
    admission_control_always_pull_images
    admission_control_security_context_deny
    admission_control_service_account
    admission_control_namespace_lifecycle
}

# Detailed Kubernetes master node compliance report
kubernetes_master_compliance := {
    "api_server_pod_file_permissions": api_server_pod_file_permissions,
    "api_server_pod_file_ownership": api_server_pod_file_ownership,
    "controller_manager_pod_file_permissions": controller_manager_pod_file_permissions,
    "controller_manager_pod_file_ownership": controller_manager_pod_file_ownership,
    "scheduler_pod_file_permissions": scheduler_pod_file_permissions,
    "scheduler_pod_file_ownership": scheduler_pod_file_ownership,
    "etcd_pod_file_permissions": etcd_pod_file_permissions,
    "etcd_pod_file_ownership": etcd_pod_file_ownership,
    "anonymous_auth_disabled": anonymous_auth_disabled,
    "basic_auth_file_not_set": basic_auth_file_not_set,
    "token_auth_file_not_set": token_auth_file_not_set,
    "kubelet_https_enabled": kubelet_https_enabled,
    "kubelet_client_cert_configured": kubelet_client_cert_configured,
    "kubelet_certificate_authority_set": kubelet_certificate_authority_set,
    "authorization_mode_not_always_allow": authorization_mode_not_always_allow,
    "authorization_mode_includes_node": authorization_mode_includes_node,
    "authorization_mode_includes_rbac": authorization_mode_includes_rbac,
    "admission_control_event_rate_limit": admission_control_event_rate_limit,
    "admission_control_not_always_admit": admission_control_not_always_admit,
    "admission_control_always_pull_images": admission_control_always_pull_images,
    "admission_control_security_context_deny": admission_control_security_context_deny,
    "admission_control_service_account": admission_control_service_account,
    "admission_control_namespace_lifecycle": admission_control_namespace_lifecycle,
    "overall_compliant": kubernetes_master_compliant
}