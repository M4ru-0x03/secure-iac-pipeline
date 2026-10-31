# REMEDIATED version of terraform/vulnerable/gcp/network.tf.

resource "google_compute_network" "main" {
  name                    = "demo-network"
  auto_create_subnetworks = false
}

# FIX (flow logs): log_config enables VPC flow logs; private Google access
# lets VMs without external IPs reach Google APIs.
resource "google_compute_subnetwork" "main" {
  name                     = "demo-subnet"
  ip_cidr_range            = "10.0.0.0/24"
  region                   = "us-central1"
  network                  = google_compute_network.main.id
  private_ip_google_access = true

  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

# FIX (open firewall): SSH is only reachable through Identity-Aware Proxy
# TCP forwarding. 35.235.240.0/20 is the range Google documents for IAP TCP
# forwarding (VMs with IPv6 use a separate range, see the IAP documentation).
resource "google_compute_firewall" "allow_ssh_from_iap" {
  name      = "allow-ssh-from-iap"
  network   = google_compute_network.main.name
  direction = "INGRESS"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["35.235.240.0/20"]
}
