variable "project_id" {
  description = "The ID of your Google Cloud project"
  type        = string
  default     = "peak-sorter-460917-b8"
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