package gcp.public_bucket

# Cloud Storage buckets must not grant access to the public internet.
# Covers google_storage_bucket_iam_member (single member) and
# google_storage_bucket_iam_binding (list of members).

public_principals := {"allUsers", "allAuthenticatedUsers"}

deny contains msg if {
	some name, instances in input.resource.google_storage_bucket_iam_member
	some instance in instances
	instance.member in public_principals
	msg := sprintf("google_storage_bucket_iam_member.%s grants access to %s; buckets must not be public", [name, instance.member])
}

deny contains msg if {
	some name, instances in input.resource.google_storage_bucket_iam_binding
	some instance in instances
	some member in instance.members
	member in public_principals
	msg := sprintf("google_storage_bucket_iam_binding.%s grants access to %s; buckets must not be public", [name, member])
}
