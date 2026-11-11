# METADATA
# title: "CIS Kubernetes Benchmark"
# custom:
#   class: security
#   framework: cis_containers
#   source: cis
#   domains: [container, kubernetes]
#   coverage:
#     checks: 23
#     cited: 0
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: none
#     guard: n/a
#     as_of: v2.4.2
package cis.kubernetes.master

import rego.v1

# CIS Kubernetes Benchmark
# Section 1: Master Node Security Configuration

# Parse an octal permission string ("644", "0644", "0o644") to an integer; undefined if not octal.
octal(s) := n if {
	t := trim_prefix(lower(trim_space(sprintf("%v", [s]))), "0o")
	regex.match(`^[0-7]{1,4}$`, t)
	p := concat("", [substring("0000", 0, 4 - count(t)), t])
	ds := [to_number(substring(p, i, 1)) | some i in numbers.range(0, 3)]
	n := ((ds[0] * 512) + (ds[1] * 64)) + ((ds[2] * 8) + ds[3])
}

# true when mode grants nothing beyond max (both octal strings)
mode_within(mode, max) if bits.and(octal(mode), bits.and(bits.negate(octal(max)), 4095)) == 0

# CIS 1.1.1 - the API server pod specification file permissions must be set to 644 or more restrictive
default api_server_pod_file_permissions := false

api_server_pod_file_permissions if {
	mode_within(input.file_permissions["/etc/kubernetes/manifests/kube-apiserver.yaml"].mode, "0644")
}

# CIS 1.1.2 - required value of the API server pod specification file ownership is root:root
default api_server_pod_file_ownership := false

api_server_pod_file_ownership if {
	input.file_permissions["/etc/kubernetes/manifests/kube-apiserver.yaml"].owner == "root"
	input.file_permissions["/etc/kubernetes/manifests/kube-apiserver.yaml"].group == "root"
}

# CIS 1.1.3 - the controller manager pod specification file permissions must be set to 644 or more restrictive
default controller_manager_pod_file_permissions := false

controller_manager_pod_file_permissions if {
	mode_within(input.file_permissions["/etc/kubernetes/manifests/kube-controller-manager.yaml"].mode, "0644")
}

# CIS 1.1.4 - required value of the controller manager pod specification file ownership is root:root
default controller_manager_pod_file_ownership := false

controller_manager_pod_file_ownership if {
	input.file_permissions["/etc/kubernetes/manifests/kube-controller-manager.yaml"].owner == "root"
	input.file_permissions["/etc/kubernetes/manifests/kube-controller-manager.yaml"].group == "root"
}

# CIS 1.1.5 - the scheduler pod specification file permissions must be set to 644 or more restrictive
default scheduler_pod_file_permissions := false

scheduler_pod_file_permissions if {
	mode_within(input.file_permissions["/etc/kubernetes/manifests/kube-scheduler.yaml"].mode, "0644")
}

# CIS 1.1.6 - required value of the scheduler pod specification file ownership is root:root
default scheduler_pod_file_ownership := false

scheduler_pod_file_ownership if {
	input.file_permissions["/etc/kubernetes/manifests/kube-scheduler.yaml"].owner == "root"
	input.file_permissions["/etc/kubernetes/manifests/kube-scheduler.yaml"].group == "root"
}

# CIS 1.1.7 - the etcd pod specification file permissions must be set to 644 or more restrictive
default etcd_pod_file_permissions := false

etcd_pod_file_permissions if {
	mode_within(input.file_permissions["/etc/kubernetes/manifests/etcd.yaml"].mode, "0644")
}

# CIS 1.1.8 - required value of the etcd pod specification file ownership is root:root
default etcd_pod_file_ownership := false

etcd_pod_file_ownership if {
	input.file_permissions["/etc/kubernetes/manifests/etcd.yaml"].owner == "root"
	input.file_permissions["/etc/kubernetes/manifests/etcd.yaml"].group == "root"
}

# CIS 1.2.1 - required value of the --anonymous-auth argument is false
default anonymous_auth_disabled := false

anonymous_auth_disabled if {
	contains(input.kube_apiserver_args, "--anonymous-auth=false")
}

# CIS 1.2.2 - the --basic-auth-file argument must be unset
default basic_auth_file_not_set := false

basic_auth_file_not_set if {
	is_string(input.kube_apiserver_args)
	not regex.match("--basic-auth-file", input.kube_apiserver_args)
}

# CIS 1.2.3 - the --token-auth-file argument must be unset
default token_auth_file_not_set := false

token_auth_file_not_set if {
	is_string(input.kube_apiserver_args)
	not regex.match("--token-auth-file", input.kube_apiserver_args)
}

# CIS 1.2.4 - required value of the --kubelet-https argument is true
default kubelet_https_enabled := false

kubelet_https_enabled if {
	contains(input.kube_apiserver_args, "--kubelet-https=true")
}

kubelet_https_enabled if {
	# Default is true if not specified
	is_string(input.kube_apiserver_args)
	not regex.match("--kubelet-https", input.kube_apiserver_args)
}

# CIS 1.2.5 - the --kubelet-client-certificate and --kubelet-client-key arguments must be set as appropriate
default kubelet_client_cert_configured := false

kubelet_client_cert_configured if {
	regex.match("--kubelet-client-certificate=", input.kube_apiserver_args)
	regex.match("--kubelet-client-key=", input.kube_apiserver_args)
}

# CIS 1.2.6 - the --kubelet-certificate-authority argument must be set as appropriate
default kubelet_certificate_authority_set := false

kubelet_certificate_authority_set if {
	regex.match("--kubelet-certificate-authority=", input.kube_apiserver_args)
}

# CIS 1.2.7 - the --authorization-mode argument must not be AlwaysAllow
default authorization_mode_not_always_allow := false

authorization_mode_not_always_allow if {
	is_string(input.kube_apiserver_args)
	not contains(input.kube_apiserver_args, "--authorization-mode=AlwaysAllow")
}

# CIS 1.2.8 - checked condition — the --authorization-mode argument includes Node
default authorization_mode_includes_node := false

authorization_mode_includes_node if {
	regex.match("--authorization-mode=.*Node", input.kube_apiserver_args)
}

# CIS 1.2.9 - checked condition — the --authorization-mode argument includes RBAC
default authorization_mode_includes_rbac := false

authorization_mode_includes_rbac if {
	regex.match("--authorization-mode=.*RBAC", input.kube_apiserver_args)
}

# CIS 1.2.10 - the admission control plugin EventRateLimit must be set
default admission_control_event_rate_limit := false

admission_control_event_rate_limit if {
	regex.match("--enable-admission-plugins=.*EventRateLimit", input.kube_apiserver_args)
}

# CIS 1.2.11 - the admission control plugin AlwaysAdmit must be unset
default admission_control_not_always_admit := false

admission_control_not_always_admit if {
	is_string(input.kube_apiserver_args)
	not regex.match("--enable-admission-plugins=.*AlwaysAdmit", input.kube_apiserver_args)
}

# CIS 1.2.12 - the admission control plugin AlwaysPullImages must be set
default admission_control_always_pull_images := false

admission_control_always_pull_images if {
	regex.match("--enable-admission-plugins=.*AlwaysPullImages", input.kube_apiserver_args)
}

# CIS 1.2.13 - the admission control plugin SecurityContextDeny must be set, if PodSecurityPolicy is not used
default admission_control_security_context_deny := false

admission_control_security_context_deny if {
	regex.match("--enable-admission-plugins=.*SecurityContextDeny", input.kube_apiserver_args)
}

admission_control_security_context_deny if {
	# Alternative: PodSecurityPolicy is used
	regex.match("--enable-admission-plugins=.*PodSecurityPolicy", input.kube_apiserver_args)
}

# CIS 1.2.14 - the admission control plugin ServiceAccount must be set
default admission_control_service_account := false

admission_control_service_account if {
	regex.match("--enable-admission-plugins=.*ServiceAccount", input.kube_apiserver_args)
}

admission_control_service_account if {
	# Default behavior if not explicitly disabled
	is_string(input.kube_apiserver_args)
	not regex.match("--disable-admission-plugins=.*ServiceAccount", input.kube_apiserver_args)
}

# CIS 1.2.15 - the admission control plugin NamespaceLifecycle must be set
default admission_control_namespace_lifecycle := false

admission_control_namespace_lifecycle if {
	regex.match("--enable-admission-plugins=.*NamespaceLifecycle", input.kube_apiserver_args)
}

admission_control_namespace_lifecycle if {
	# Default behavior if not explicitly disabled
	is_string(input.kube_apiserver_args)
	not regex.match("--disable-admission-plugins=.*NamespaceLifecycle", input.kube_apiserver_args)
}

# Aggregate Kubernetes master node compliance
default kubernetes_master_compliant := false

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
	"overall_compliant": kubernetes_master_compliant,
}
