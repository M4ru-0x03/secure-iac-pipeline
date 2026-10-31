package gcp.primitive_role

# IAM at project, folder and organization level must not use the primitive
# roles (owner, editor, viewer); use predefined or custom roles scoped to what
# the identity needs. Covers the *_iam_member and *_iam_binding resources.

primitive_roles := {"roles/owner", "roles/editor", "roles/viewer"}

member_types := {
	"google_project_iam_member",
	"google_folder_iam_member",
	"google_organization_iam_member",
}

binding_types := {
	"google_project_iam_binding",
	"google_folder_iam_binding",
	"google_organization_iam_binding",
}

deny contains msg if {
	some type in (member_types | binding_types)
	some name, instances in input.resource[type]
	some instance in instances
	instance.role in primitive_roles
	msg := sprintf("%s.%s uses primitive role %s; use a predefined or custom role", [type, name, instance.role])
}
