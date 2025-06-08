#!/usr/bin/env python3
"""
Multi-Cloud Security Posture Assessment Tool
Main entry point for the security scanner
"""

import click
import json
import sys
from pathlib import Path
from typing import Dict, List, Any

from scanner.aws_scanner import AWSScanner
from scanner.azure_scanner import AzureScanner
from scanner.gcp_scanner import GCPScanner
from reporters.json_reporter import JSONReporter
from reporters.html_reporter import HTMLReporter
from reporters.csv_reporter import CSVReporter
from utils.risk_calculator import RiskCalculator

@click.group()
@click.version_option(version='1.0.0')
def cli():
    """Multi-Cloud Security Posture Assessment Tool"""
    pass

@cli.command()
@click.option('--provider', type=click.Choice(['aws', 'azure', 'gcp', 'all']), 
              default='all', help='Cloud provider to scan')
@click.option('--output-format', type=click.Choice(['json', 'html', 'csv']), 
              default='json', help='Output format')
@click.option('--output-file', type=str, help='Output file path')
@click.option('--config-dir', type=str, default='config', 
              help='Configuration directory path')
@click.option('--severity', type=click.Choice(['low', 'medium', 'high', 'critical']), 
              help='Minimum severity level to report')
def scan(provider, output_format, output_file, config_dir, severity):
    """Perform security posture assessment"""
    
    results = {}
    scanners = []
    
    # Initialize scanners based on provider selection
    if provider in ['aws', 'all']:
        try:
            aws_scanner = AWSScanner(config_dir)
            scanners.append(('aws', aws_scanner))
        except Exception as e:
            click.echo(f"Warning: AWS scanner initialization failed: {e}", err=True)
    
    if provider in ['azure', 'all']:
        try:
            azure_scanner = AzureScanner(config_dir)
            scanners.append(('azure', azure_scanner))
        except Exception as e:
            click.echo(f"Warning: Azure scanner initialization failed: {e}", err=True)
    
    if provider in ['gcp', 'all']:
        try:
            gcp_scanner = GCPScanner(config_dir)
            scanners.append(('gcp', gcp_scanner))
        except Exception as e:
            click.echo(f"Warning: GCP scanner initialization failed: {e}", err=True)
    
    if not scanners:
        click.echo("Error: No scanners could be initialized", err=True)
        sys.exit(1)
    
    # Perform scans
    click.echo("Starting security posture assessment...")
    
    for provider_name, scanner in scanners:
        click.echo(f"Scanning {provider_name.upper()}...")
        try:
            scan_results = scanner.scan()
            results[provider_name] = scan_results
            click.echo(f"✓ {provider_name.upper()} scan completed")
        except Exception as e:
            click.echo(f"✗ {provider_name.upper()} scan failed: {e}", err=True)
            results[provider_name] = {"error": str(e), "findings": []}
    
    # Calculate overall risk score
    risk_calc = RiskCalculator()
    overall_score = risk_calc.calculate_overall_risk(results)
    
    # Filter by severity if specified
    if severity:
        results = filter_by_severity(results, severity)
    
    # Generate report
    report_data = {
        "scan_metadata": {
            "timestamp": click.DateTime().convert(None, None, None),
            "providers_scanned": list(results.keys()),
            "overall_risk_score": overall_score
        },
        "results": results
    }
    
    # Output results
    if output_format == 'json':
        reporter = JSONReporter()
    elif output_format == 'html':
        reporter = HTMLReporter()
    elif output_format == 'csv':
        reporter = CSVReporter()
    
    if output_file:
        reporter.generate_report(report_data, output_file)
        click.echo(f"Report generated: {output_file}")
    else:
        output = reporter.generate_report(report_data)
        click.echo(output)

def filter_by_severity(results: Dict, min_severity: str) -> Dict:
    """Filter results by minimum severity level"""
    severity_levels = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
    min_level = severity_levels[min_severity]
    
    filtered_results = {}
    for provider, data in results.items():
        if 'findings' in data:
            filtered_findings = [
                finding for finding in data['findings']
                if severity_levels.get(finding.get('severity', 'low'), 1) >= min_level
            ]
            filtered_results[provider] = {**data, 'findings': filtered_findings}
        else:
            filtered_results[provider] = data
    
    return filtered_results

@cli.command()
def configure():
    """Configure cloud provider credentials"""
    click.echo("Cloud Security Scanner Configuration")
    click.echo("====================================")
    
    # AWS Configuration
    if click.confirm("Configure AWS credentials?"):
        click.echo("Please ensure AWS CLI is configured or set environment variables:")
        click.echo("  - AWS_ACCESS_KEY_ID")
        click.echo("  - AWS_SECRET_ACCESS_KEY")
        click.echo("  - AWS_DEFAULT_REGION")
    
    # Azure Configuration
    if click.confirm("Configure Azure credentials?"):
        click.echo("Please ensure Azure CLI is logged in or set environment variables:")
        click.echo("  - AZURE_CLIENT_ID")
        click.echo("  - AZURE_CLIENT_SECRET")
        click.echo("  - AZURE_TENANT_ID")
    
    # GCP Configuration
    if click.confirm("Configure GCP credentials?"):
        click.echo("Please ensure GCP Application Default Credentials are set:")
        click.echo("  - Run: gcloud auth application-default login")
        click.echo("  - Or set GOOGLE_APPLICATION_CREDENTIALS environment variable")

if __name__ == '__main__':
    cli()