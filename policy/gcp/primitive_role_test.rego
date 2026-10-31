package gcp.primitive_role

test_denies_editor_member if {
	msgs := deny with input as {"resource": {"google_project_iam_member": {"dev": [{
		"project": "p",
		"role": "roles/editor",
		"member": "user:dev@example.com",
	}]}}}
	count(msgs) == 1
}

test_denies_owner_member if {
	msgs := deny with input as {"resource": {"google_project_iam_member": {"boss": [{
		"project": "p",
		"role": "roles/owner",
		"member": "user:boss@example.com",
	}]}}}
	count(msgs) == 1
}

test_denies_viewer_binding if {
	msgs := deny with input as {"resource": {"google_project_iam_binding": {"all": [{
		"project": "p",
		"role": "roles/viewer",
		"members": ["group:team@example.com"],
	}]}}}
	count(msgs) == 1
}

test_allows_predefined_role if {
	msgs := deny with input as {"resource": {"google_project_iam_member": {"obj": [{
		"project": "p",
		"role": "roles/storage.objectViewer",
		"member": "user:dev@example.com",
	}]}}}
	count(msgs) == 0
}

test_allows_input_without_project_iam if {
	msgs := deny with input as {"resource": {"google_compute_network": {"main": [{"name": "n"}]}}}
	count(msgs) == 0
}
