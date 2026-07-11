variable "project_id" {
  description = "The ID of your Google Cloud project"
  type        = string
  default     = "honeypots-501606"
}

# NOTE: an org policy (constraints/gcp.resourceLocations) restricts this project to
# US locations only - europe-* is denied. us-east4 is within the allowed set.
variable "region" {
  description = "The Google Cloud region (must be US - org policy restricted)"
  type        = string
  default     = "us-east4"
}

variable "zone" {
  description = "The Google Cloud zone (must be US - org policy restricted)"
  type        = string
  default     = "us-east4-a"
}

variable "admin_cidr" {
  description = "CIDR range allowed to SSH into the T-Pot host (port 22). Restrict this to your own IP, e.g. \"203.0.113.5/32\"."
  type        = string
}
