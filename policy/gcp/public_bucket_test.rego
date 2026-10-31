package gcp.public_bucket

test_denies_all_users_member if {
	msgs := deny with input as {"resource": {"google_storage_bucket_iam_member": {"public_read": [{
		"bucket": "b",
		"role": "roles/storage.objectViewer",
		"member": "allUsers",
	}]}}}
	count(msgs) == 1
}

test_denies_all_authenticated_users_member if {
	msgs := deny with input as {"resource": {"google_storage_bucket_iam_member": {"shared": [{
		"bucket": "b",
		"role": "roles/storage.objectViewer",
		"member": "allAuthenticatedUsers",
	}]}}}
	count(msgs) == 1
}

test_denies_public_principal_in_binding if {
	msgs := deny with input as {"resource": {"google_storage_bucket_iam_binding": {"public_read": [{
		"bucket": "b",
		"role": "roles/storage.objectViewer",
		"members": ["user:dev@example.com", "allUsers"],
	}]}}}
	count(msgs) == 1
}

test_allows_specific_member if {
	msgs := deny with input as {"resource": {"google_storage_bucket_iam_member": {"reader": [{
		"bucket": "b",
		"role": "roles/storage.objectViewer",
		"member": "user:dev@example.com",
	}]}}}
	count(msgs) == 0
}

test_allows_binding_with_specific_members if {
	msgs := deny with input as {"resource": {"google_storage_bucket_iam_binding": {"readers": [{
		"bucket": "b",
		"role": "roles/storage.objectViewer",
		"members": ["user:dev@example.com", "group:team@example.com"],
	}]}}}
	count(msgs) == 0
}

test_allows_input_without_bucket_iam if {
	msgs := deny with input as {"resource": {"google_compute_network": {"main": [{"name": "n"}]}}}
	count(msgs) == 0
}
