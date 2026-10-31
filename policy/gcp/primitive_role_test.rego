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

test_denies_editor_on_folder_member if {
	msgs := deny with input as {"resource": {"google_folder_iam_member": {"dev": [{
		"folder": "folders/123",
		"role": "roles/editor",
		"member": "user:dev@example.com",
	}]}}}
	count(msgs) == 1
}

test_denies_owner_on_organization_binding if {
	msgs := deny with input as {"resource": {"google_organization_iam_binding": {"admins": [{
		"org_id": "456",
		"role": "roles/owner",
		"members": ["group:admins@example.com"],
	}]}}}
	count(msgs) == 1
}

test_denies_viewer_on_organization_member if {
	msgs := deny with input as {"resource": {"google_organization_iam_member": {"all": [{
		"org_id": "456",
		"role": "roles/viewer",
		"member": "group:team@example.com",
	}]}}}
	count(msgs) == 1
}

test_allows_predefined_role_on_folder if {
	msgs := deny with input as {"resource": {"google_folder_iam_member": {"dev": [{
		"folder": "folders/123",
		"role": "roles/resourcemanager.folderViewer",
		"member": "user:dev@example.com",
	}]}}}
	count(msgs) == 0
}
