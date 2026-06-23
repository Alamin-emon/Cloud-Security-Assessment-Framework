############################################################
#  ICT Risk Assessment Lab — Intentionally Misconfigured AWS
#  WARNING: This environment contains DELIBERATE misconfigs.
#           Deploy ONLY in an isolated sandbox account.
############################################################

terraform {
  required_version = ">= 1.3"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

resource "random_id" "suffix" {
  byte_length = 4
}

locals {
  prefix = "ict-lab-${random_id.suffix.hex}"
}

############################################################
# 1. S3 BUCKET — PUBLIC READ (MISCONFIGURATION #1)
############################################################

resource "aws_s3_bucket" "lab_bucket" {
  bucket        = "${local.prefix}-data"
  force_destroy = true

  tags = {
    Name        = "ICT-Lab-Public-Bucket"
    Environment = "sandbox"
    Purpose     = "security-research"
  }
}

# MISCONFIGURATION: disable the public access block
resource "aws_s3_bucket_public_access_block" "lab_bucket_pab" {
  bucket = aws_s3_bucket.lab_bucket.id

  block_public_acls       = false   # ← MISCONFIGURATION
  block_public_policy     = false   # ← MISCONFIGURATION
  ignore_public_acls      = false   # ← MISCONFIGURATION
  restrict_public_buckets = false   # ← MISCONFIGURATION
}

# MISCONFIGURATION: public-read ACL
resource "aws_s3_bucket_acl" "lab_bucket_acl" {
  depends_on = [aws_s3_bucket_public_access_block.lab_bucket_pab]
  bucket     = aws_s3_bucket.lab_bucket.id
  acl        = "public-read"  # ← MISCONFIGURATION
}

# Upload a fake "sensitive" file so the exposure is real
resource "aws_s3_object" "sensitive_file" {
  bucket  = aws_s3_bucket.lab_bucket.id
  key     = "credentials/db_config.txt"
  content = "DB_HOST=internal-db.corp\nDB_PASS=SuperSecret123\nAPI_KEY=sk-fake-key-for-lab"
}

# MISCONFIGURATION: no versioning, no encryption
# (intentionally omitting aws_s3_bucket_versioning and
#  aws_s3_bucket_server_side_encryption_configuration)

############################################################
# 2. VPC + SECURITY GROUP — OPEN SSH (MISCONFIGURATION #2)
############################################################

resource "aws_vpc" "lab_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true

  tags = { Name = "${local.prefix}-vpc" }
}

resource "aws_subnet" "lab_subnet" {
  vpc_id                  = aws_vpc.lab_vpc.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true  # ← MISCONFIGURATION: instances get public IPs

  tags = { Name = "${local.prefix}-subnet" }
}

resource "aws_internet_gateway" "lab_igw" {
  vpc_id = aws_vpc.lab_vpc.id
  tags   = { Name = "${local.prefix}-igw" }
}

resource "aws_route_table" "lab_rt" {
  vpc_id = aws_vpc.lab_vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.lab_igw.id
  }
}

resource "aws_route_table_association" "lab_rta" {
  subnet_id      = aws_subnet.lab_subnet.id
  route_table_id = aws_route_table.lab_rt.id
}

# MISCONFIGURATION: SSH and ALL TCP open to the world
resource "aws_security_group" "open_sg" {
  name        = "${local.prefix}-open-sg"
  description = "LAB ONLY - intentionally open security group"
  vpc_id      = aws_vpc.lab_vpc.id

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # ← MISCONFIGURATION
  }

  ingress {
    description = "All TCP from anywhere"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # ← MISCONFIGURATION
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${local.prefix}-open-sg" }
}

############################################################
# 3. IAM — OVER-PERMISSIVE ROLES & POLICIES (MISCONFIG #3)
############################################################

# --- Admin user without MFA enforcement ---
resource "aws_iam_user" "admin_user" {
  name = "${local.prefix}-admin"
  tags = { Role = "admin" }
}

# MISCONFIGURATION: AdministratorAccess to an IAM user
resource "aws_iam_user_policy_attachment" "admin_full" {
  user       = aws_iam_user.admin_user.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# --- Developer user with overly broad S3 access ---
resource "aws_iam_user" "dev_user" {
  name = "${local.prefix}-dev"
  tags = { Role = "developer" }
}

resource "aws_iam_policy" "s3_star_policy" {
  name        = "${local.prefix}-s3-star"
  description = "LAB: Over-permissive S3 policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "S3FullAccessAllBuckets"
      Effect   = "Allow"
      Action   = "s3:*"           # ← MISCONFIGURATION: wildcard action
      Resource = "*"              # ← MISCONFIGURATION: all resources
    }]
  })
}

resource "aws_iam_user_policy_attachment" "dev_s3_star" {
  user       = aws_iam_user.dev_user.name
  policy_arn = aws_iam_policy.s3_star_policy.arn
}

# --- Read-only user (correctly configured — for contrast) ---
resource "aws_iam_user" "readonly_user" {
  name = "${local.prefix}-readonly"
  tags = { Role = "readonly" }
}

resource "aws_iam_user_policy_attachment" "readonly_attach" {
  user       = aws_iam_user.readonly_user.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# --- EC2 role with wildcard S3 access (MISCONFIGURATION #4) ---
resource "aws_iam_role" "ec2_role" {
  name = "${local.prefix}-ec2-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "ec2_s3_star" {
  name = "${local.prefix}-ec2-s3-star"
  role = aws_iam_role.ec2_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "s3:*"     # ← MISCONFIGURATION
      Resource = "*"        # ← MISCONFIGURATION
    }]
  })
}

resource "aws_iam_instance_profile" "ec2_profile" {
  name = "${local.prefix}-ec2-profile"
  role = aws_iam_role.ec2_role.name
}

# MISCONFIGURATION: no account password policy configured
# (intentionally omitting aws_iam_account_password_policy)

############################################################
# 4. EC2 INSTANCE — PUBLIC, OPEN SG (MISCONFIGURATION #5)
############################################################

data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
}

resource "aws_instance" "lab_ec2" {
  ami                         = data.aws_ami.amazon_linux.id
  instance_type               = "t2.micro"
  subnet_id                   = aws_subnet.lab_subnet.id
  vpc_security_group_ids      = [aws_security_group.open_sg.id]
  iam_instance_profile        = aws_iam_instance_profile.ec2_profile.name
  associate_public_ip_address = true  # ← MISCONFIGURATION

  # MISCONFIGURATION: no encrypted EBS root volume
  root_block_device {
    encrypted = false  # ← MISCONFIGURATION
  }

  # MISCONFIGURATION: IMDSv1 allowed (metadata service not locked down)
  metadata_options {
    http_tokens                 = "optional"  # ← MISCONFIGURATION (should be "required")
    http_put_response_hop_limit = 2           # ← MISCONFIGURATION (should be 1)
  }

  user_data = <<-EOF
    #!/bin/bash
    yum update -y
    echo "ICT Security Lab EC2" > /var/www/html/index.html
  EOF

  tags = {
    Name        = "${local.prefix}-lab-ec2"
    Environment = "sandbox"
  }
}

############################################################
# 5. CLOUDTRAIL — DISABLED (MISCONFIGURATION #6)
############################################################

# CloudTrail is intentionally NOT created here.
# This means API calls are not logged — a critical finding
# that both Prowler and ZeusCloud should detect.

############################################################
# OUTPUTS
############################################################

output "bucket_name" {
  value       = aws_s3_bucket.lab_bucket.bucket
  description = "S3 bucket name (publicly readable)"
}

output "ec2_public_ip" {
  value       = aws_instance.lab_ec2.public_ip
  description = "EC2 public IP (SSH open to world)"
}

output "ec2_instance_id" {
  value       = aws_instance.lab_ec2.id
}

output "admin_user_name" {
  value = aws_iam_user.admin_user.name
}

output "misconfigurations_summary" {
  value = <<-EOT
    ┌─────────────────────────────────────────────────────────┐
    │  INTENTIONAL MISCONFIGURATIONS DEPLOYED                 │
    ├─────────────────────────────────────────────────────────┤
    │  #1  S3 bucket with public-read ACL                     │
    │  #2  S3 bucket — no versioning, no encryption           │
    │  #3  Security group: SSH + all TCP open to 0.0.0.0/0   │
    │  #4  IAM user with AdministratorAccess (no MFA)         │
    │  #5  IAM role with s3:* on all resources                │
    │  #6  EC2 with public IP + IMDSv1 enabled                │
    │  #7  CloudTrail not enabled                             │
    │  #8  EBS root volume not encrypted                      │
    └─────────────────────────────────────────────────────────┘
  EOT
}
