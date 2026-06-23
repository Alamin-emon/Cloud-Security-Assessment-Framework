#!/usr/bin/env python3
"""
Mock AWS Environment Generator
================================
Simulates a Prowler scan output and a ZeusCloud findings export
for the intentionally misconfigured lab environment.

Run this if you do NOT yet have an AWS account.
Output goes to:
  ../results/prowler_output.json
  ../results/zeuscloud_output.json

Usage:
  python generate_mock_environment.py
"""

import json
import random
import datetime
import os

RESULTS_DIR = os.path.join(os.path.dirname(__file__), "..", "results")
os.makedirs(RESULTS_DIR, exist_ok=True)

ACCOUNT_ID  = "123456789012"
REGION      = "eu-west-1"
BUCKET_NAME = "ict-lab-a3f2c1d4-data"
EC2_ID      = "i-0abc123def456789"
EC2_IP      = "54.74.123.45"

# ──────────────────────────────────────────────────────────────────────────────
#  PROWLER MOCK FINDINGS
#  Each finding mirrors the real Prowler JSON schema (v3/v4 compatible)
# ──────────────────────────────────────────────────────────────────────────────

def ts():
    return datetime.datetime.utcnow().isoformat() + "Z"

PROWLER_FINDINGS = [
    # ── S3 ────────────────────────────────────────────────────────────────────
    {
        "CheckID":       "s3_bucket_public_access_block_account_enabled",
        "CheckTitle":    "S3 Account-Level Public Access Block Not Enabled",
        "ServiceName":   "s3",
        "Status":        "FAIL",
        "Severity":      "Critical",
        "Region":        REGION,
        "ResourceArn":   f"arn:aws:s3:::{BUCKET_NAME}",
        "ResourceId":    BUCKET_NAME,
        "Description":   "The S3 bucket does not have public access block settings enabled at the account level.",
        "Risk":          "Anyone on the internet can read objects from this bucket.",
        "Remediation":   "Enable S3 Block Public Access at account level and per-bucket.",
        "Compliance":    ["CIS-AWS-Foundations-Benchmark v1.5.0 2.1.5", "AWS-Foundational-Security-Best-Practices S3.1"],
        "Timestamp":     ts(),
    },
    {
        "CheckID":       "s3_bucket_acl_public_access",
        "CheckTitle":    "S3 Bucket ACL Allows Public Read Access",
        "ServiceName":   "s3",
        "Status":        "FAIL",
        "Severity":      "Critical",
        "Region":        REGION,
        "ResourceArn":   f"arn:aws:s3:::{BUCKET_NAME}",
        "ResourceId":    BUCKET_NAME,
        "Description":   "S3 bucket ACL is set to 'public-read', exposing all objects to unauthenticated users.",
        "Risk":          "Sensitive data including db_config.txt containing credentials is publicly accessible.",
        "Remediation":   "Change the bucket ACL to private and use bucket policies for controlled access.",
        "Compliance":    ["CIS-AWS-Foundations-Benchmark v1.5.0 2.1.1", "PCI-DSS v3.2.1 1.3"],
        "Timestamp":     ts(),
    },
    {
        "CheckID":       "s3_bucket_versioning_enabled",
        "CheckTitle":    "S3 Bucket Versioning Not Enabled",
        "ServiceName":   "s3",
        "Status":        "FAIL",
        "Severity":      "Low",
        "Region":        REGION,
        "ResourceArn":   f"arn:aws:s3:::{BUCKET_NAME}",
        "ResourceId":    BUCKET_NAME,
        "Description":   "Bucket versioning is disabled. Accidental deletions or overwrites cannot be recovered.",
        "Risk":          "Data loss from accidental or malicious deletion cannot be reversed.",
        "Remediation":   "Enable versioning on the S3 bucket.",
        "Compliance":    ["CIS-AWS-Foundations-Benchmark v1.5.0 2.1.3"],
        "Timestamp":     ts(),
    },
    {
        "CheckID":       "s3_bucket_default_encryption",
        "CheckTitle":    "S3 Bucket Server-Side Encryption Not Enabled",
        "ServiceName":   "s3",
        "Status":        "FAIL",
        "Severity":      "Medium",
        "Region":        REGION,
        "ResourceArn":   f"arn:aws:s3:::{BUCKET_NAME}",
        "ResourceId":    BUCKET_NAME,
        "Description":   "Default server-side encryption (SSE) is not configured for this S3 bucket.",
        "Risk":          "Data at rest is stored in plaintext and could be exposed if physically compromised.",
        "Remediation":   "Enable SSE-S3 or SSE-KMS as the default encryption for the bucket.",
        "Compliance":    ["CIS-AWS-Foundations-Benchmark v1.5.0 2.1.1", "ISO27001 A.10.1.1"],
        "Timestamp":     ts(),
    },

    # ── IAM ───────────────────────────────────────────────────────────────────
    {
        "CheckID":       "iam_user_with_administrator_access",
        "CheckTitle":    "IAM User Has AdministratorAccess Policy",
        "ServiceName":   "iam",
        "Status":        "FAIL",
        "Severity":      "High",
        "Region":        "global",
        "ResourceArn":   f"arn:aws:iam::{ACCOUNT_ID}:user/ict-lab-a3f2c1d4-admin",
        "ResourceId":    "ict-lab-a3f2c1d4-admin",
        "Description":   "IAM user 'ict-lab-a3f2c1d4-admin' has AdministratorAccess managed policy attached.",
        "Risk":          "Compromise of this account grants full control over the AWS environment.",
        "Remediation":   "Apply least privilege. Restrict permissions to only those required for the user's role.",
        "Compliance":    ["CIS-AWS-Foundations-Benchmark v1.5.0 1.16", "SOC2 CC6.3"],
        "Timestamp":     ts(),
    },
    {
        "CheckID":       "iam_user_mfa_enabled_console_access",
        "CheckTitle":    "IAM User Console Access Without MFA",
        "ServiceName":   "iam",
        "Status":        "FAIL",
        "Severity":      "High",
        "Region":        "global",
        "ResourceArn":   f"arn:aws:iam::{ACCOUNT_ID}:user/ict-lab-a3f2c1d4-admin",
        "ResourceId":    "ict-lab-a3f2c1d4-admin",
        "Description":   "IAM user with console access does not have MFA enabled.",
        "Risk":          "Account takeover via credential stuffing or phishing without MFA protection.",
        "Remediation":   "Enable MFA for all IAM users with console access, especially privileged accounts.",
        "Compliance":    ["CIS-AWS-Foundations-Benchmark v1.5.0 1.10", "PCI-DSS v3.2.1 8.3"],
        "Timestamp":     ts(),
    },
    {
        "CheckID":       "iam_password_policy_minimum_length_14",
        "CheckTitle":    "IAM Account Password Policy Minimum Length < 14",
        "ServiceName":   "iam",
        "Status":        "FAIL",
        "Severity":      "Medium",
        "Region":        "global",
        "ResourceArn":   f"arn:aws:iam::{ACCOUNT_ID}:root",
        "ResourceId":    ACCOUNT_ID,
        "Description":   "The IAM account password policy does not require a minimum length of 14 characters.",
        "Risk":          "Weak passwords increase susceptibility to brute-force attacks.",
        "Remediation":   "Set minimum password length to 14 or more in the IAM account password policy.",
        "Compliance":    ["CIS-AWS-Foundations-Benchmark v1.5.0 1.8", "ISO27001 A.9.4.3"],
        "Timestamp":     ts(),
    },
    {
        "CheckID":       "iam_policy_attached_only_to_groups_or_roles",
        "CheckTitle":    "IAM Policy Directly Attached to User",
        "ServiceName":   "iam",
        "Status":        "FAIL",
        "Severity":      "Low",
        "Region":        "global",
        "ResourceArn":   f"arn:aws:iam::{ACCOUNT_ID}:user/ict-lab-a3f2c1d4-dev",
        "ResourceId":    "ict-lab-a3f2c1d4-dev",
        "Description":   "An IAM policy (s3:* on all resources) is directly attached to a user instead of a group/role.",
        "Risk":          "Difficult to audit and manage; over-broad permissions granted directly to user.",
        "Remediation":   "Attach policies to IAM groups or roles; remove direct user policy attachments.",
        "Compliance":    ["CIS-AWS-Foundations-Benchmark v1.5.0 1.15"],
        "Timestamp":     ts(),
    },
    {
        "CheckID":       "iam_root_account_no_access_keys",
        "CheckTitle":    "Root Account Has Active Access Keys",
        "ServiceName":   "iam",
        "Status":        "PASS",
        "Severity":      "Critical",
        "Region":        "global",
        "ResourceArn":   f"arn:aws:iam::{ACCOUNT_ID}:root",
        "ResourceId":    "root",
        "Description":   "Root account does not have active access keys. PASS.",
        "Risk":          "N/A",
        "Remediation":   "N/A",
        "Compliance":    ["CIS-AWS-Foundations-Benchmark v1.5.0 1.4"],
        "Timestamp":     ts(),
    },

    # ── EC2 ───────────────────────────────────────────────────────────────────
    {
        "CheckID":       "ec2_securitygroup_allow_ingress_from_internet_to_ssh_port_22",
        "CheckTitle":    "Security Group Allows SSH Ingress from 0.0.0.0/0",
        "ServiceName":   "ec2",
        "Status":        "FAIL",
        "Severity":      "High",
        "Region":        REGION,
        "ResourceArn":   f"arn:aws:ec2:{REGION}:{ACCOUNT_ID}:security-group/sg-0abc123",
        "ResourceId":    "sg-0abc123",
        "Description":   "Security group 'ict-lab-open-sg' allows unrestricted SSH (port 22) from 0.0.0.0/0.",
        "Risk":          "Exposes EC2 instances to brute-force attacks and unauthorised SSH access from the internet.",
        "Remediation":   "Restrict SSH access to known IP ranges or use AWS Systems Manager Session Manager.",
        "Compliance":    ["CIS-AWS-Foundations-Benchmark v1.5.0 5.2", "PCI-DSS v3.2.1 1.3.1"],
        "Timestamp":     ts(),
    },
    {
        "CheckID":       "ec2_securitygroup_allow_ingress_from_internet_to_all_ports",
        "CheckTitle":    "Security Group Allows All TCP Ingress from 0.0.0.0/0",
        "ServiceName":   "ec2",
        "Status":        "FAIL",
        "Severity":      "Critical",
        "Region":        REGION,
        "ResourceArn":   f"arn:aws:ec2:{REGION}:{ACCOUNT_ID}:security-group/sg-0abc123",
        "ResourceId":    "sg-0abc123",
        "Description":   "Security group allows all TCP ports (0-65535) from 0.0.0.0/0.",
        "Risk":          "Any service running on the instance is exposed to the entire internet.",
        "Remediation":   "Remove the all-TCP ingress rule. Define explicit rules only for required ports.",
        "Compliance":    ["CIS-AWS-Foundations-Benchmark v1.5.0 5.1"],
        "Timestamp":     ts(),
    },
    {
        "CheckID":       "ec2_instance_imdsv2_enabled",
        "CheckTitle":    "EC2 Instance Metadata Service v2 Not Enforced",
        "ServiceName":   "ec2",
        "Status":        "FAIL",
        "Severity":      "Medium",
        "Region":        REGION,
        "ResourceArn":   f"arn:aws:ec2:{REGION}:{ACCOUNT_ID}:instance/{EC2_ID}",
        "ResourceId":    EC2_ID,
            "Description":   "EC2 instance allows IMDSv1 (http_tokens=optional). IMDSv1 is vulnerable to SSRF attacks.",
        "Risk":          "SSRF vulnerability in application code can leak IAM role credentials via IMDSv1.",
        "Remediation":   "Set http_tokens=required to enforce IMDSv2.",
        "Compliance":    ["AWS-Foundational-Security-Best-Practices EC2.8"],
        "Timestamp":     ts(),
    },
    {
        "CheckID":       "ec2_ebs_volume_encryption",
        "CheckTitle":    "EBS Root Volume Not Encrypted",
        "ServiceName":   "ec2",
        "Status":        "FAIL",
        "Severity":      "Medium",
        "Region":        REGION,
        "ResourceArn":   f"arn:aws:ec2:{REGION}:{ACCOUNT_ID}:volume/vol-0abc123",
        "ResourceId":    "vol-0abc123",
        "Description":   "The root EBS volume of EC2 instance is not encrypted at rest.",
        "Risk":          "Data on the EBS volume is stored in plaintext. Physical compromise exposes data.",
        "Remediation":   "Enable EBS volume encryption. Use AWS KMS for key management.",
        "Compliance":    ["CIS-AWS-Foundations-Benchmark v1.5.0 2.2.1"],
        "Timestamp":     ts(),
    },
    {
        "CheckID":       "ec2_instance_public_ip",
        "CheckTitle":    "EC2 Instance Has Public IP Address Assigned",
        "ServiceName":   "ec2",
        "Status":        "FAIL",
        "Severity":      "Medium",
        "Region":        REGION,
        "ResourceArn":   f"arn:aws:ec2:{REGION}:{ACCOUNT_ID}:instance/{EC2_ID}",
        "ResourceId":    EC2_ID,
        "Description":   f"EC2 instance has public IP {EC2_IP} assigned and is directly reachable from the internet.",
        "Risk":          "Direct internet exposure increases attack surface.",
        "Remediation":   "Use NAT Gateway + private subnets. Access via bastion or SSM Session Manager.",
        "Compliance":    ["AWS-Foundational-Security-Best-Practices EC2.9"],
        "Timestamp":     ts(),
    },

    # ── CloudTrail ────────────────────────────────────────────────────────────
    {
        "CheckID":       "cloudtrail_enabled",
        "CheckTitle":    "CloudTrail Not Enabled in All Regions",
        "ServiceName":   "cloudtrail",
        "Status":        "FAIL",
        "Severity":      "High",
        "Region":        "global",
        "ResourceArn":   f"arn:aws:cloudtrail:{REGION}:{ACCOUNT_ID}:trail",
        "ResourceId":    ACCOUNT_ID,
        "Description":   "No CloudTrail trails are configured. AWS API calls are not being logged.",
        "Risk":          "Without CloudTrail, security incidents cannot be investigated. Attacker activity leaves no trace.",
        "Remediation":   "Enable CloudTrail with multi-region support and log file validation.",
        "Compliance":    ["CIS-AWS-Foundations-Benchmark v1.5.0 3.1", "SOC2 CC7.2", "PCI-DSS v3.2.1 10.1"],
        "Timestamp":     ts(),
    },
    {
        "CheckID":       "cloudtrail_log_file_validation_enabled",
        "CheckTitle":    "CloudTrail Log File Validation Not Enabled",
        "ServiceName":   "cloudtrail",
        "Status":        "FAIL",
        "Severity":      "Low",
        "Region":        "global",
        "ResourceArn":   f"arn:aws:cloudtrail:{REGION}:{ACCOUNT_ID}:trail",
        "ResourceId":    ACCOUNT_ID,
        "Description":   "CloudTrail does not have log file integrity validation enabled.",
        "Risk":          "Log files could be tampered with after the fact without detection.",
        "Remediation":   "Enable log file validation when creating or updating CloudTrail.",
        "Compliance":    ["CIS-AWS-Foundations-Benchmark v1.5.0 3.2"],
        "Timestamp":     ts(),
    },

    # ── GuardDuty ─────────────────────────────────────────────────────────────
    {
        "CheckID":       "guardduty_is_enabled",
        "CheckTitle":    "Amazon GuardDuty Not Enabled",
        "ServiceName":   "guardduty",
        "Status":        "FAIL",
        "Severity":      "High",
        "Region":        REGION,
        "ResourceArn":   f"arn:aws:guardduty:{REGION}:{ACCOUNT_ID}:detector",
        "ResourceId":    ACCOUNT_ID,
        "Description":   "Amazon GuardDuty is not enabled in this region.",
        "Risk":          "Threat detection for malicious activity (port scans, crypto mining, exfiltration) is absent.",
        "Remediation":   "Enable GuardDuty in all active regions.",
        "Compliance":    ["CIS-AWS-Foundations-Benchmark v1.5.0 2.7", "AWS-Foundational-Security-Best-Practices GuardDuty.1"],
        "Timestamp":     ts(),
    },
]

# ──────────────────────────────────────────────────────────────────────────────
#  ZEUSCLOUD MOCK FINDINGS
#  Mirrors the ZeusCloud findings export format
# ──────────────────────────────────────────────────────────────────────────────

ZEUSCLOUD_FINDINGS = [
    {
        "FindingID":    "ZC-ATK-001",
        "Title":        "Full Internet-to-Data Exfiltration Path",
        "Type":         "AttackPath",
        "Severity":     "Critical",
        "RiskScore":    9.8,
        "PathDepth":    5,
        "Nodes": [
            {"id": "internet",    "type": "ExternalActor",  "label": "Internet (0.0.0.0/0)"},
            {"id": "sg-0abc123",  "type": "SecurityGroup",  "label": "Open SG (SSH+ALL TCP)"},
            {"id": EC2_ID,        "type": "EC2Instance",    "label": f"EC2 {EC2_IP} (public)"},
            {"id": "ec2-role",    "type": "IAMRole",        "label": "ec2-role (s3:* on *)"},
            {"id": BUCKET_NAME,   "type": "S3Bucket",       "label": f"s3://{BUCKET_NAME} (public-read)"},
            {"id": "credentials", "type": "S3Object",       "label": "credentials/db_config.txt"},
        ],
        "Edges": [
            {"from": "internet",   "to": "sg-0abc123", "label": "allowed by SG ingress 0.0.0.0/0:22"},
            {"from": "sg-0abc123", "to": EC2_ID,       "label": "SSH access to instance"},
            {"from": EC2_ID,       "to": "ec2-role",   "label": "assumes IAM role via instance profile"},
            {"from": "ec2-role",   "to": BUCKET_NAME,  "label": "s3:* permission on all buckets"},
            {"from": BUCKET_NAME,  "to": "credentials","label": "GetObject — publicly readable"},
        ],
        "Description": (
            "An unauthenticated attacker on the internet can reach the EC2 instance via SSH "
            "(open security group), execute code, assume the EC2 IAM role with s3:* permissions, "
            "and exfiltrate sensitive credentials from the publicly readable S3 bucket. "
            "This is a complete 5-hop attack chain from internet to credential exfiltration."
        ),
        "AffectedResources": [EC2_ID, "sg-0abc123", "ec2-role", BUCKET_NAME],
        "Timestamp": ts(),
    },
    {
        "FindingID":    "ZC-ATK-002",
        "Title":        "Public S3 Bucket Direct Credential Exposure",
        "Type":         "AttackPath",
        "Severity":     "Critical",
        "RiskScore":    9.5,
        "PathDepth":    2,
        "Nodes": [
            {"id": "internet",    "type": "ExternalActor", "label": "Internet (anonymous)"},
            {"id": BUCKET_NAME,   "type": "S3Bucket",      "label": f"s3://{BUCKET_NAME} (public-read ACL)"},
            {"id": "credentials", "type": "S3Object",      "label": "credentials/db_config.txt (DB_PASS + API_KEY)"},
        ],
        "Edges": [
            {"from": "internet",  "to": BUCKET_NAME,   "label": "HTTP GET (no auth required — public ACL)"},
            {"from": BUCKET_NAME, "to": "credentials", "label": "Object accessible without credentials"},
        ],
        "Description": (
            "Without any prior access, an attacker can directly download "
            f"https://{BUCKET_NAME}.s3.amazonaws.com/credentials/db_config.txt "
            "and obtain database credentials and API keys. No authentication required."
        ),
        "AffectedResources": [BUCKET_NAME],
        "Timestamp": ts(),
    },
    {
        "FindingID":    "ZC-ATK-003",
        "Title":        "No-MFA Admin Account Takeover Path",
        "Type":         "AttackPath",
        "Severity":     "Critical",
        "RiskScore":    9.2,
        "PathDepth":    3,
        "Nodes": [
            {"id": "internet",   "type": "ExternalActor", "label": "Attacker / Phishing"},
            {"id": "admin-user", "type": "IAMUser",       "label": "ict-lab-admin (AdministratorAccess, no MFA)"},
            {"id": "all-aws",    "type": "AWSEnvironment","label": "Full AWS environment control"},
        ],
        "Edges": [
            {"from": "internet",   "to": "admin-user", "label": "credential phishing / brute-force (no MFA protection)"},
            {"from": "admin-user", "to": "all-aws",    "label": "AdministratorAccess policy — unrestricted"},
        ],
        "Description": (
            "The IAM user 'ict-lab-admin' has AdministratorAccess and no MFA. "
            "A phishing attack or credential leak gives the attacker full control "
            "over the entire AWS account — all services, all regions, all data."
        ),
        "AffectedResources": ["ict-lab-a3f2c1d4-admin"],
        "Timestamp": ts(),
    },
    {
        "FindingID":    "ZC-ATK-004",
        "Title":        "SSRF via IMDSv1 to IAM Role Credential Theft",
        "Type":         "AttackPath",
        "Severity":     "High",
        "RiskScore":    8.1,
        "PathDepth":    4,
        "Nodes": [
            {"id": "attacker",   "type": "ExternalActor", "label": "Attacker exploiting SSRF vulnerability"},
            {"id": EC2_ID,       "type": "EC2Instance",   "label": f"EC2 {EC2_IP} (IMDSv1 enabled)"},
            {"id": "imds",       "type": "MetadataService","label": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"},
            {"id": "ec2-role",   "type": "IAMRole",        "label": "ec2-role credentials (AccessKey + SecretKey + Token)"},
            {"id": BUCKET_NAME,  "type": "S3Bucket",       "label": f"s3://{BUCKET_NAME} and all S3 buckets"},
        ],
        "Edges": [
            {"from": "attacker",  "to": EC2_ID,      "label": "SSRF in web app triggers internal HTTP request"},
            {"from": EC2_ID,      "to": "imds",      "label": "IMDSv1 — no token required"},
            {"from": "imds",      "to": "ec2-role",  "label": "returns temporary AWS credentials"},
            {"from": "ec2-role",  "to": BUCKET_NAME, "label": "use stolen credentials for s3:* access"},
        ],
        "Description": (
            "If a web application running on the EC2 instance has an SSRF vulnerability, "
            "the attacker can query the IMDSv1 metadata endpoint (no session token required) "
            "and retrieve the ec2-role temporary credentials. These credentials grant s3:* "
            "access to all S3 buckets in the account."
        ),
        "AffectedResources": [EC2_ID, "ec2-role"],
        "Timestamp": ts(),
    },
    {
        "FindingID":    "ZC-FIND-005",
        "Title":        "CloudTrail Disabled — No Audit Trail",
        "Type":         "Finding",
        "Severity":     "High",
        "RiskScore":    7.5,
        "PathDepth":    1,
        "Nodes": [
            {"id": "cloudtrail", "type": "AWSService", "label": "CloudTrail (not enabled)"},
        ],
        "Edges": [],
        "Description": (
            "CloudTrail is not enabled. All attack paths described above would be executed "
            "with no audit log. The attacker's API calls, data access, and privilege escalation "
            "would leave no evidence for forensic investigation."
        ),
        "AffectedResources": [ACCOUNT_ID],
        "Timestamp": ts(),
    },
]

# ──────────────────────────────────────────────────────────────────────────────
#  WRITE OUTPUT FILES
# ──────────────────────────────────────────────────────────────────────────────

prowler_out = os.path.join(RESULTS_DIR, "prowler_output.json")
with open(prowler_out, "w") as f:
    json.dump(PROWLER_FINDINGS, f, indent=2)
print(f"[OK] Prowler mock output  → {prowler_out}")

zeuscloud_out = os.path.join(RESULTS_DIR, "zeuscloud_output.json")
with open(zeuscloud_out, "w") as f:
    json.dump(ZEUSCLOUD_FINDINGS, f, indent=2)
print(f"[OK] ZeusCloud mock output → {zeuscloud_out}")

print(f"\nProwler findings  : {len(PROWLER_FINDINGS)} ({sum(1 for f in PROWLER_FINDINGS if f['Status']=='FAIL')} FAIL)")
print(f"ZeusCloud findings: {len(ZEUSCLOUD_FINDINGS)} (attack paths + findings)")
