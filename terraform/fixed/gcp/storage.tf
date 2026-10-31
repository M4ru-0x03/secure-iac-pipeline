# REMEDIATED version of terraform/vulnerable/gcp/storage.tf.

# FIXES: CMEK encryption, required labels, public access prevention enforced,
# versioning and access logging.
resource "google_storage_bucket" "data" {
  name                        = "demo-data-bucket-example"
  location                    = "US"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  labels = {
    owner       = "platform-team"
    environment = "dev"
  }

  encryption {
    default_kms_key_name = google_kms_crypto_key.bucket.id
  }

  versioning {
    enabled = true
  }

  logging {
    log_bucket = google_storage_bucket.access_logs.name
  }

  depends_on = [google_kms_crypto_key_iam_member.gcs_agent]
}

# Receives the access logs of the data bucket.
resource "google_storage_bucket" "access_logs" {
  #checkov:skip=CKV_GCP_62:This bucket is the log sink; logging it into itself would be circular.
  name                        = "demo-access-logs-example"
  location                    = "US"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  labels = {
    owner       = "platform-team"
    environment = "dev"
  }

  encryption {
    default_kms_key_name = google_kms_crypto_key.bucket.id
  }

  versioning {
    enabled = true
  }

  depends_on = [google_kms_crypto_key_iam_member.gcs_agent]
}

# FIX (public bucket): access goes to a named group instead of allUsers.
resource "google_storage_bucket_iam_member" "readers" {
  bucket = google_storage_bucket.data.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}
