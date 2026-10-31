# INTENTIONALLY VULNERABLE: every flaw below is a test case for a policy.

# FLAW (primitive role): roles/editor grants broad write access across the project.
resource "google_project_iam_member" "dev_editor" {
  project = "example-project"
  role    = "roles/editor"
  member  = "user:dev@example.com"
}
