package gcp.default_service_account

test_denies_default_sa_with_cloud_platform_short_scope if {
	msgs := deny with input as {"resource": {"google_compute_instance": {"web": [{"service_account": [{"scopes": ["cloud-platform"]}]}]}}}
	count(msgs) == 1
}

test_denies_explicit_default_sa_with_full_url_scope if {
	msgs := deny with input as {"resource": {"google_compute_instance": {"web": [{"service_account": [{
		"email": "123456789-compute@developer.gserviceaccount.com",
		"scopes": ["https://www.googleapis.com/auth/cloud-platform"],
	}]}]}}}
	count(msgs) == 1
}

test_allows_custom_sa_with_cloud_platform_scope if {
	msgs := deny with input as {"resource": {"google_compute_instance": {"web": [{"service_account": [{
		"email": "app@example-project.iam.gserviceaccount.com",
		"scopes": ["cloud-platform"],
	}]}]}}}
	count(msgs) == 0
}

test_allows_default_sa_with_narrow_scopes if {
	msgs := deny with input as {"resource": {"google_compute_instance": {"web": [{"service_account": [{"scopes": ["logging-write", "monitoring-write"]}]}]}}}
	count(msgs) == 0
}

test_allows_instance_without_service_account_block if {
	msgs := deny with input as {"resource": {"google_compute_instance": {"web": [{"name": "v"}]}}}
	count(msgs) == 0
}

test_allows_input_without_instances if {
	msgs := deny with input as {"resource": {"google_compute_network": {"main": [{"name": "n"}]}}}
	count(msgs) == 0
}
