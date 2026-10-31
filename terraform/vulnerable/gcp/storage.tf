# INTENTIONALLY VULNERABLE: every flaw below is a test case for a policy.

# FLAWS: no CMEK (no encryption block with a KMS key), and no labels.
resource "google_storage_bucket" "data" {
  name                        = "demo-data-bucket-example"
  location                    = "US"
  uniform_bucket_level_access = true
}

# FLAW (public bucket): anyone on the internet can read the objects.
resource "google_storage_bucket_iam_member" "public_read" {
  bucket = google_storage_bucket.data.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}
