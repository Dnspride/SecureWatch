# ==============================================================================
# SecureWatch – 100% Docker on AWS EC2 Infrastructure
# Deploys a dedicated Docker host running all 8 microservices via Docker Compose:
# (Frontend Nginx, FastAPI Backend, Celery, PostgreSQL 15, Redis 7, OpenSearch 2.11)
# ==============================================================================

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "Terraform"
      Stack       = "Docker-Compose-Complete"
    }
  }
}

# ------------------------------------------------------------------------------
# 1. Base AMI: Ubuntu 22.04 LTS (x86_64)
# ------------------------------------------------------------------------------
data "aws_ami" "ubuntu" {
  most_recent = true
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
  owners = ["099720109477"] # Canonical
}

# ------------------------------------------------------------------------------
# 2. Virtual Private Cloud (VPC) & Networking
# ------------------------------------------------------------------------------
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "${var.project_name}-vpc"
  }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${var.project_name}-igw" }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.100.1.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true

  tags = { Name = "${var.project_name}-public-subnet" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = { Name = "${var.project_name}-public-rt" }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# ------------------------------------------------------------------------------
# 3. Security Group (Firewall Rules)
# ------------------------------------------------------------------------------
resource "aws_security_group" "docker_host" {
  name        = "${var.project_name}-docker-host-sg"
  description = "Security rules for SecureWatch Docker EC2 Node"
  vpc_id      = aws_vpc.main.id

  # Port 80: Web UI
  ingress {
    description = "HTTP Web Portal"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Port 443: HTTPS Web UI
  ingress {
    description = "HTTPS Web Portal"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Port 3000: Frontend Alternative Port
  ingress {
    description = "Frontend Port 3000"
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Port 8000: Backend API & Endpoint Agent Telemetry
  ingress {
    description = "FastAPI Backend & Agent Telemetry Ingestion"
    from_port   = 8000
    to_port     = 8000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Port 5601: OpenSearch Dashboards (SOC Analytics)
  ingress {
    description = "OpenSearch Dashboards UI"
    from_port   = 5601
    to_port     = 5601
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Port 22: SSH Admin Access
  ingress {
    description = "SSH Administration"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_ssh_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-docker-host-sg"
  }
}

# ------------------------------------------------------------------------------
# 4. EC2 Instance (100% Docker Host)
# ------------------------------------------------------------------------------
resource "aws_instance" "docker_host" {
  ami                         = data.aws_ami.ubuntu.id
  instance_type               = var.app_instance_type
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.docker_host.id]
  associate_public_ip_address = true
  key_name                    = var.ec2_key_name != "" ? var.ec2_key_name : null

  # High-performance 100 GB gp3 volume for persistent Docker volumes
  root_block_device {
    volume_size           = 100
    volume_type           = "gp3"
    delete_on_termination = false
    tags = {
      Name = "${var.project_name}-docker-host-disk"
    }
  }

  # Automated Docker & Docker Compose installation
  user_data = <<-EOF
              #!/bin/bash
              set -e
              apt-get update -y
              apt-get install -y ca-certificates curl gnupg lsb-release git ufw fail2ban

              # Install Docker
              mkdir -m 0755 -p /etc/apt/keyrings
              curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
              echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
              apt-get update -y
              apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

              # Enable Docker daemon
              systemctl enable docker
              systemctl start docker
              usermod -aG docker ubuntu

              # Configure system virtual memory for OpenSearch
              sysctl -w vm.max_map_count=262144
              echo "vm.max_map_count=262144" >> /etc/sysctl.conf
              EOF

  tags = {
    Name = "${var.project_name}-docker-host"
    Role = "Full-Stack-Docker-Host"
  }
}

# ------------------------------------------------------------------------------
# 5. Static Elastic IP (Guarantees public IP never changes)
# ------------------------------------------------------------------------------
resource "aws_eip" "docker_host" {
  instance = aws_instance.docker_host.id
  domain   = "vpc"

  tags = {
    Name = "${var.project_name}-static-ip"
  }
}
