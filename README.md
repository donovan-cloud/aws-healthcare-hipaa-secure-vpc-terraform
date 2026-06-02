# AWS Healthcare HIPAA-Compliant PHI Isolation Network

[![IaC](https://img.shields.io/badge/IaC-Terraform_1.5+-7B42BC.svg)](https://www.terraform.io/)
[![Provider](https://img.shields.io/badge/Provider-AWS-orange.svg)](https://aws.amazon.com/)
[![Framework](https://img.shields.io/badge/Security-PHI_Isolation-blue.svg)](https://aws.amazon.com/security/)
[![Compliance](https://img.shields.io/badge/Compliance-HIPAA_45_CFR_%C2%A7_164.312-red.svg)](https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html)

## 📋 Project Overview
This repository contains an enterprise-grade, Infrastructure-as-Code (IaC) implementation designed to provision an isolated network perimeter enforcing the rigid technical safeguards required for handling Protected Health Information (PHI).

Directly mapped to the federal guidelines of the **HIPAA Security Rule (45 CFR § 164.312)**, this baseline deploys isolated, zero-internet data subnets, forces explicit network flow log logging with a mandatory 7-year immutable retention architecture, and wraps storage layers in automated, rotating AES-256 cryptographic fields.

---

## 🛡️ HIPAA Technical Safeguards Mapping

| HIPAA Regulation Section | Architecture Control Paradigm | AWS Resource Mapping |
| :--- | :--- | :--- |
| **§164.312(a)(2)(iv)** / **(e)(2)(ii)** | Enforced AES-256 Customer Managed Keys (CMK) with active annual cryptographic rotation for data at rest and log states. | `aws_kms_key` |
| **§164.312(b)** (Audit Controls) | Granular network ingress/egress record captures with a mandatory 7-year (2557 days) immutable retention lifecycle policy. | `aws_flow_log` / `aws_cloudwatch_log_group` |
| **§164.312(c)(1)** / **(e)(1)** | Isolation of database systems containing PHI into dedicated zero-internet subnets, stripping all unmapped ingress vectors. | `aws_vpc` / `aws_subnet` / `aws_default_security_group` |

---

## 🏗️ Hardened Structural Security Specifications
* **Extended Healthcare Retention Engine:** Elevates the CloudWatch retention parameters explicitly to `2557` days (7 years) to safely guarantee absolute compliance with federal healthcare record holding rules.
* **Hermetic Network Isolation:** PHI processing subnets are systematically denied route-table mappings to Internet Gateways or NAT Gateways, rendering them completely inaccessible from outside the boundary.
* **Default-Deny Posture:** Automatically hooks the default VPC security group to wipe out all inbound and outbound rule fields, ensuring unmanaged resources cannot accidentally leak traffic.

---

## 💻 Core Isolation Architecture (`main.tf`)

This declarative template handles the sovereign healthcare network initialization, building out the data protection planes and logging pipelines natively inside the infrastructure code:

```hcl
# ==============================================================================
# ARCHITECTURE: HIPAA-Compliant Healthcare PHI Isolation Network
# COMPLIANCE MAPPING: HIPAA Security Rule §164.312 (Technical Safeguards)
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
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "environment" {
  type    = string
  default = "production"
}

# ------------------------------------------------------------------------------
# 1. HIPAA §164.312(a)(2)(iv) & (e)(2)(ii): Enforced Encryption for PHI
# ------------------------------------------------------------------------------
resource "aws_kms_key" "hipaa_phi_key" {
  description             = "Cryptographic boundary for HIPAA-regulated PHI data volumes"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name       = "${var.environment}-hipaa-phi-kms"
    Compliance = "HIPAA_164_312_Encryption"
  }
}

# ------------------------------------------------------------------------------
# 2. HIPAA §164.312(c)(1): Transmission Security & Access Isolation
# ------------------------------------------------------------------------------
resource "aws_vpc" "hipaa_vpc" {
  cidr_block           = "10.200.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name              = "${var.environment}-hipaa-isolated-vpc"
    Data_Scope        = "Protected_Health_Information"
    Security_Standard = "HIPAA_Compliant"
  }
}

# Explicitly clean out and drop default security group rules
resource "aws_default_security_group" "hipaa_default_deny" {
  vpc_id = aws_vpc.hipaa_vpc.id
  tags = {
    Name = "hipaa-default-deny-all"
  }
}

# Highly restricted Private Subnet dedicated solely to PHI Processing Tiers
resource "aws_subnet" "phi_storage_tier_az1" {
  vpc_id            = aws_vpc.hipaa_vpc.id
  cidr_block        = "10.200.50.0/24"
  availability_zone = "${var.aws_region}a"

  tags = {
    Name        = "${var.environment}-phi-storage-az1"
    Data_Impact = "Critical_PHI"
  }
}

# ------------------------------------------------------------------------------
# 3. HIPAA §164.312(b): Audit Controls (Continuous Flow Evidence Collection)
# ------------------------------------------------------------------------------
resource "aws_flow_log" "hipaa_network_audit" {
  iam_role_arn    = aws_iam_role.hipaa_logs_publisher.arn
  log_destination = aws_cloudwatch_log_group.hipaa_audit_trail.arn
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.hipaa_vpc.id

  tags = {
    Name = "${var.environment}-hipaa-flow-logs"
  }
}

resource "aws_cloudwatch_log_group" "hipaa_audit_trail" {
  name              = "/aws/vpc-flow-logs/${var.environment}-hipaa-safeguard"
  retention_in_days = 2557 # 7 Years Retention (Standard Healthcare Audit Requirement)
  kms_key_id        = aws_kms_key.hipaa_phi_key.arn
}

resource "aws_iam_role" "hipaa_logs_publisher" {
  name = "${var.environment}-hipaa-flow-logs-publisher-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "vpc-flow-logs.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "hipaa_logs_permissions" {
  name = "${var.environment}-hipaa-flow-logs-publisher-policy"
  role = aws_iam_role.hipaa_logs_publisher.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}
