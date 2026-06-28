provider "google" {
  project = var.project_id          
  region  = var.region
  zone    = var.zone
}

### NETWORK

resource "google_compute_network" "honeypot_vpc" {
  name                    = "honeypot-vpc"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "lab_subnet" {
  name          = "lab-subnet"
  ip_cidr_range = "10.0.0.0/24"
  region        = var.region
  network       = google_compute_network.honeypot_vpc.id
}

### FIREWALL

# Rule 1: Allow you to SSH into the Attacker VM
resource "google_compute_firewall" "lab_firewall" {
  name    = "allow-management-ssh"
  network = google_compute_network.honeypot_vpc.id

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  # Replace with YOUR physical Wi-Fi public IP address
  source_ranges = ["84.173.29.142/32"] 
  target_tags   = ["attacker-vm"]
}

# Rule 2: Allow the Attacker VM to hit the Honeypot VM
resource "google_compute_firewall" "allow_lab_traffic" {
  name    = "allow-lab-traffic"
  network = google_compute_network.honeypot_vpc.id

  allow {
    protocol = "tcp"
    ports    = ["22", "23", "80"] 
  }

  # Strictly the internal IP of the Attacker VM
  source_ranges = ["10.0.0.2/32"] 
  target_tags   = ["honeypot-node"] 
}

### INSTANCES 

# The Victim (No Public IP)
resource "google_compute_instance" "honeypot_vm" {
  name         = "honeypot-vm"
  machine_type = "e2-small"
  tags         = ["honeypot-node"] 

  boot_disk {
    initialize_params {
      size  = 100
      image = "ubuntu-os-cloud/ubuntu-2404-lts-amd64"
    }
  }

  network_interface {
    network    = google_compute_network.honeypot_vpc.id
    subnetwork = google_compute_subnetwork.lab_subnet.id
    network_ip = "10.0.0.3" 
    
  }
}

# The Attacker (Has Public IP)
resource "google_compute_instance" "attacker_vm" {
  name         = "attacker-vm"
  machine_type = "e2-small"
  tags         = ["attacker-vm"]

  boot_disk {
    initialize_params {
      size  = 100
      image = "ubuntu-os-cloud/ubuntu-2404-lts-amd64"
    }
  }

  network_interface {
    network    = google_compute_network.honeypot_vpc.id
    subnetwork = google_compute_subnetwork.lab_subnet.id
    network_ip = "10.0.0.2" 

    access_config {
     
    }
  }
  metadata ={
    ssh-keys = "labuser:${file(pathexpand("~/.ssh/lab_shared_key.pub"))}"
  }
}

### OUTPUTS

output "attacker_public_ip" {
  value       = google_compute_instance.attacker_vm.network_interface[0].access_config[0].nat_ip
  description = "SSH into this IP"
}