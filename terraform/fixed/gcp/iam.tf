# REMEDIATED version of terraform/vulnerable/gcp/iam.tf.

# FIX (primitive role): a predefined role scoped to what the developer needs
# replaces roles/editor.
resource "google_project_iam_member" "dev_logging" {
  project = "example-project"
  role    = "roles/logging.viewer"
  member  = "user:dev@example.com"
}
