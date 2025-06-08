# Multi-Cloud Security Posture Assessment Tool

A comprehensive security scanning tool that assesses AWS, Azure, and GCP environments for common misconfigurations and security vulnerabilities.

## Features

- **Multi-Cloud Support**: Scan AWS, Azure, and Google Cloud Platform
- **Comprehensive Checks**: 20+ security checks across different services
- **Risk Assessment**: Automated risk scoring and prioritization
- **Multiple Output Formats**: JSON, HTML, and CSV reports
- **Configurable**: Customizable security checks and thresholds
- **CLI Interface**: Easy-to-use command-line interface

## Quick Start

### Installation

```bash
git clone https://github.com/yourusername/cloud-security-scanner.git
cd cloud-security-scanner
pip install -r requirements.txt
```

### Configuration

Configure your cloud provider credentials:

```bash
python src/main.py configure
```

### Usage

Scan all configured cloud providers:
```bash
python src/main.py scan
```

Scan specific provider:
```bash
python src/main.py scan --provider aws
```

Generate HTML report:
```bash
python src/main.py scan --output-format html --output-file report.html
```

## Security Checks

### AWS
- S3 bucket public access and encryption
- IAM overly permissive policies
- Security groups with open access
- RDS public accessibility and encryption
- EC2 instances without security patches

### Azure
- Storage account public access
- Network security groups configuration
- Key Vault access policies
- SQL Database encryption and access

### GCP
- Cloud Storage bucket permissions
- Compute Engine firewall rules
- Cloud SQL instance configuration
- IAM policy analysis

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

MIT License - see LICENSE file for details