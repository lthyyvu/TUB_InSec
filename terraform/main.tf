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

# Rule 1: Allow you to SSH into the Attacker VM (Mit deiner IP)
resource "google_compute_firewall" "lab_firewall" {
  name    = "allow-management-ssh"
  network = google_compute_network.honeypot_vpc.id

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["0.0.0.0/0"] 
  target_tags   = ["attacker-vm"]
}

# Rule 2: Allow the Attacker VM to hit the Honeypot VM (Inklusive Port 22222 für Management)
resource "google_compute_firewall" "allow_lab_traffic" {
  name    = "allow-lab-traffic"
  network = google_compute_network.honeypot_vpc.id

  allow {
    protocol = "tcp"
    ports    = ["22", "23", "80", "22222"] 
  }

  source_ranges = ["10.0.0.2/32"] 
  target_tags   = ["honeypot-node"] 
}

### INSTANCES 

# The Victim (No Public IP + Automatisches Honeypot-Setup)
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

  metadata = {
    ssh-keys = "labuser:${file(pathexpand("~/.ssh/lab_shared_key.pub"))}"

    startup-script = <<-EOF
      #!/bin/bash
      # 1. System updaten und Docker & Python installieren
      apt-get update
      apt-get install -y docker.io docker-compose python3

      # 2. Echten SSH-Dienst auf Port 22222 verschieben
      sed -i 's/#Port 22/Port 22222/' /etc/ssh/sshd_config
      sed -i 's/Port 22/Port 22222/' /etc/ssh/sshd_config
      systemctl restart ssh

      # 3. Cowrie Honeypot über Docker einrichten
      mkdir -p /opt/cowrie
      cat << 'DOCKER' > /opt/cowrie/docker-compose.yml
      version: '3.7'
      services:
        cowrie:
          image: cowrie/cowrie:latest
          container_name: cowrie
          restart: always
          ports:
            - "22:2222"
            - "23:2223"
          environment:
            - COWRIE_TELNET_ENABLED=yes
      DOCKER
      cd /opt/cowrie && docker-compose up -d

      # 4. Custom Python HTTP Honeypot erstellen
      mkdir -p /opt/custom_web
      cat << 'PY' > /opt/custom_web/server.py
      import http.server
      import socketserver
      import datetime

      PORT = 80
      LOG_FILE = "/var/log/custom_honeypot.log"

      class HoneypotHandler(http.server.SimpleHTTPRequestHandler):
          def log_message(self, format, *args):
              with open(LOG_FILE, "a") as f:
                  timestamp = datetime.datetime.now().isoformat()
                  f.write(f"[{timestamp}] IP: {self.client_address[0]} | REQUEST: {format%args}\n")
          
          def do_GET(self):
              self.log_message("GET %s", self.path)
              self.send_response(200)
              self.send_header("Content-type", "text/html")
              self.end_headers()
              self.wfile.write(b"<html><body><h1>Admin Portal v1.0</h1><form method='POST'><input name='user'/><input name='pass' type='password'/><input type='submit'/></form></body></html>")

          def do_POST(self):
              content_length = int(self.headers['Content-Length'])
              post_data = self.rfile.read(content_length)
              self.log_message("POST %s | PAYLOAD: %s", self.path, post_data.decode('utf-8', 'ignore'))
              self.send_response(401)
              self.send_header("Content-type", "text/html")
              self.end_headers()
              self.wfile.write(b"<html><body><h1>Error: Invalid Credentials</h1></body></html>")

      with socketserver.TCPServer(("", PORT), HoneypotHandler) as httpd:
          httpd.serve_forever()
      PY

      # Python-Skript als Systemdienst einrichten und starten
      cat << 'SYS' > /etc/systemd/system/custom-honeypot.service
      [Unit]
      Description=Custom Python Low-Interaction HTTP Honeypot
      After=network.target

      [Service]
      ExecStart=/usr/bin/python3 /opt/custom_web/server.py
      Restart=always
      User=root

      [Install]
      WantedBy=multi-user.target
      SYS

      systemctl daemon-reload
      systemctl enable --now custom-honeypot.service
    EOF
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
      # Ephemeral Public IP
    }
  }

  metadata = {
    ssh-keys = "labuser:${file(pathexpand("~/.ssh/lab_shared_key.pub"))}"
  }
}

### OUTPUTS

output "attacker_public_ip" {
  value       = google_compute_instance.attacker_vm.network_interface[0].access_config[0].nat_ip
  description = "SSH into this IP"
}