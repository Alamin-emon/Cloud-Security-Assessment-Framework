# Cloud Security Assessment Framework

A cloud security assessment and analysis framework that automates infrastructure deployment, security scanning, and findings analysis using Terraform, ZeusCloud, Prowler, and Python.

## Features

- Infrastructure provisioning with Terraform
- Mock environment generation for testing
- Security posture assessment with Prowler
- Cloud security analysis using Python scripts
- Docker support via ZeusCloud
- Environment configuration through `.env` files

## Project Structure

```
experiment_source_code/
├── analysis/
│   └── analyze.py
├── mock_data/
│   └── generate_mock_environment.py
├── prowler/
│   └── run_prowler.sh
├── terraform/
│   ├── main.tf
│   └── variables.tf
├── zeuscloud/
│   ├── docker-compose.yml
│   └── .env.example
└── README.md
└── Report.pdf
```

## Technologies Used

- Python
- Terraform
- Docker
- ZeusCloud
- Prowler

## Installation

Clone the repository:

```bash
git clone https://github.com/<username>/<repository>.git
cd <repository>
```

Install Python dependencies:

```bash
pip install -r requirements.txt
```

Configure environment variables:

```bash
cp zeuscloud/.env.example zeuscloud/.env
```

## Usage

### Generate Mock Data

```bash
python mock_data/generate_mock_environment.py
```

### Provision Infrastructure

```bash
cd terraform
terraform init
terraform plan
terraform apply
```

### Run Security Scans

```bash
./prowler/run_prowler.sh
```

### Analyze Results

```bash
python analysis/analyze.py
```

## Purpose

This project demonstrates an end-to-end workflow for cloud security assessment by:

1. Creating or simulating infrastructure.
2. Running automated security scans.
3. Collecting findings.
4. Analyzing and reporting security issues.

## Future Improvements

- Dashboard for visualization
- CI/CD integration
- Support for multiple cloud providers
- Automated reporting
- AI-assisted findings analysis
