terraform {
  required_version = ">= 1.5"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 8.9"
    }
  }
}

# Static analysis only: no real project or credentials are ever used.
provider "google" {
  project = "example-project"
  region  = "us-central1"
}
