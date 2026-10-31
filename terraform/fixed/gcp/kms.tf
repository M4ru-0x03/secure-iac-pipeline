# Customer-managed key used to encrypt the data bucket (policy: bucket_cmek).

resource "google_kms_key_ring" "main" {
  name     = "demo-key-ring"
  location = "us"
}

resource "google_kms_crypto_key" "bucket" {
  name            = "demo-bucket-key"
  key_ring        = google_kms_key_ring.main.id
  rotation_period = "7776000s" # 90 days

  lifecycle {
    prevent_destroy = true
  }
}

# Cloud Storage encrypts and decrypts through its per-project service agent,
# which needs permission on the key.
data "google_storage_project_service_account" "gcs" {}

resource "google_kms_crypto_key_iam_member" "gcs_agent" {
  crypto_key_id = google_kms_crypto_key.bucket.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${data.google_storage_project_service_account.gcs.email_address}"
}
