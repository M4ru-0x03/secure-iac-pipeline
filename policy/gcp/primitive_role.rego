package gcp.primitive_role

# Project-level IAM must not use the primitive roles (owner, editor, viewer);
# use predefined or custom roles scoped to what the identity needs.
# Scope: project-level resources only (not folder or organization).

primitive_roles := {"roles/owner", "roles/editor", "roles/viewer"}

deny contains msg if {
	some name, instances in input.resource.google_project_iam_member
	some instance in instances
	instance.role in primitive_roles
	msg := sprintf("google_project_iam_member.%s uses primitive role %s; use a predefined or custom role", [name, instance.role])
}

deny contains msg if {
	some name, instances in input.resource.google_project_iam_binding
	some instance in instances
	instance.role in primitive_roles
	msg := sprintf("google_project_iam_binding.%s uses primitive role %s; use a predefined or custom role", [name, instance.role])
}
