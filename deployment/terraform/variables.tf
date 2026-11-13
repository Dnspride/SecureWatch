# ==============================================================================
# SecureWatch 100% Docker Terraform Variables
# ==============================================================================

variable "aws_region" {
  description = "Target AWS deployment region"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment (production/staging/dev)"
  type        = string
  default     = "production"
}

variable "project_name" {
  description = "Project identifier"
  type        = string
  default     = "securewatch"
}

variable "vpc_cidr" {
  description = "CIDR block for the isolated VPC"
  type        = string
  default     = "10.100.0.0/16"
}

variable "app_instance_type" {
  description = "EC2 instance size for Docker host (Min recommended: t3.xlarge or t4g.xlarge with 16GB RAM)"
  type        = string
  default     = "t3.xlarge"
}

variable "ec2_key_name" {
  description = "Name of existing EC2 Key Pair for SSH access (e.g. your-key.pem)"
  type        = string
  default     = ""
}

variable "admin_ssh_cidr" {
  description = "CIDR block permitted for SSH access (e.g. your IP/32 or 0.0.0.0/0)"
  type        = string
  default     = "0.0.0.0/0"
}
