package stig.kubernetes_test

import rego.v1
import data.stig.kubernetes

test_report_wellformed_on_empty_input if {
	report := kubernetes.stig_assessment with input as {}
	is_object(report)
	report.summary.total_findings > 0
}

green_fixture := {
	 "scheduler": {
	  "flags": {
	   "tls-min-version": "VersionTLS12"
	  }
	 },
	 "api_server": {
	  "flags": {
	   "tls-min-version": "VersionTLS12",
	   "anonymous-auth": "false",
	   "tls-cert-file": "/etc/kubernetes/pki/apiserver.crt",
	   "tls-private-key-file": "/etc/kubernetes/pki/apiserver.key"
	  },
	  "admission_plugins": [
	   "ValidatingAdmissionWebhook",
	   "PodSecurity"
	  ]
	 },
	 "controller_manager": {
	  "flags": {
	   "use-service-account-credentials": "true"
	  }
	 },
	 "namespaces": {
	  "user_resources_in_dedicated": true
	 },
	 "kubelet": {
	  "config": {
	   "readOnlyPort": 0,
	   "authentication_anonymous_enabled": false,
	   "authorization_mode": "Webhook",
	   "protectKernelDefaults": true
	  }
	 },
	 "secrets": {
	  "env_var_usage_count": 0,
	  "sensitive_data_in_secrets_only": true
	 },
	 "etcd": {
	  "encryption_provider_configured": true,
	  "flags": {
	   "peer-client-cert-auth": "true"
	  }
	 },
	 "pod_security": {
	  "policy_enforced": true,
	  "admission_config_file_set": true
	 },
	 "manifests": {
	  "owned_by_root": true
	 }
	}

test_fully_compliant_on_green_fixture if {
	report := kubernetes.stig_assessment with input as green_fixture
	report.summary.fully_compliant == true
}
