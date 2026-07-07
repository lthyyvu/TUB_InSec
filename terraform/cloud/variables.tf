variable "project_id" {
  description = "The ID of your Google Cloud project"
  type        = string
  default     = "honeypots-501606"
}

variable "region" {
  description = "The Google Cloud region"
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "The Google Cloud zone"
  type        = string
  default     = "us-central1-a"
}

variable "admin_cidr" {
  description = "CIDR range allowed to reach the public honeypot's real admin SSH port (22222). Restrict this to your own IP, e.g. \"203.0.113.5/32\"."
  type        = string
}
