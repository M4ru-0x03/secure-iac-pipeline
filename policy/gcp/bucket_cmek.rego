package gcp.bucket_cmek

# Cloud Storage buckets must be encrypted with a customer-managed key (CMEK):
# an encryption block with a non-empty default_kms_key_name.

has_cmek(bucket) if {
	some encryption in bucket.encryption
	encryption.default_kms_key_name != ""
}

deny contains msg if {
	some name, buckets in input.resource.google_storage_bucket
	some bucket in buckets
	not has_cmek(bucket)
	msg := sprintf("google_storage_bucket.%s has no default_kms_key_name; use a customer-managed encryption key", [name])
}
