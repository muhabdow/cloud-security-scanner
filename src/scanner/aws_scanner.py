"""
AWS Security Scanner
Scans AWS resources for security misconfigurations
"""

import boto3
import json
from typing import Dict, List, Any
from botocore.exceptions import ClientError, NoCredentialsError
from .base_scanner import BaseScanner

class AWSScanner(BaseScanner):
    def __init__(self, config_dir: str):
        super().__init__(config_dir)
        try:
            self.session = boto3.Session()
            # Test credentials
            sts = self.session.client('sts')
            self.account_id = sts.get_caller_identity()['Account']
        except NoCredentialsError:
            raise Exception("AWS credentials not configured")
        except Exception as e:
            raise Exception(f"AWS authentication failed: {e}")
    
    def get_config_file(self) -> str:
        return "aws_checks.yaml"
    
    def scan(self) -> Dict[str, Any]:
        """Perform AWS security scan"""
        findings = []
        
        # Scan S3 buckets
        findings.extend(self.scan_s3_buckets())
        
        # Scan IAM policies
        findings.extend(self.scan_iam_policies())
        
        # Scan Security Groups
        findings.extend(self.scan_security_groups())
        
        # Scan RDS instances
        findings.extend(self.scan_rds_instances())
        
        return {
            "account_id": self.account_id,
            "region": self.session.region_name or "us-east-1",
            "findings": findings,
            "total_findings": len(findings)
        }
    
    def scan_s3_buckets(self) -> List[Dict]:
        """Scan S3 buckets for security issues"""
        findings = []
        
        try:
            s3_client = self.session.client('s3')
            buckets = s3_client.list_buckets()['Buckets']
            
            for bucket in buckets:
                bucket_name = bucket['Name']
                
                # Check public read access
                try:
                    acl = s3_client.get_bucket_acl(Bucket=bucket_name)
                    for grant in acl.get('Grants', []):
                        grantee = grant.get('Grantee', {})
                        if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                            findings.append(self.create_finding(
                                check_id="S3_PUBLIC_READ",
                                resource_id=bucket_name,
                                resource_type="S3Bucket",
                                severity="high",
                                description=f"S3 bucket {bucket_name} allows public read access",
                                remediation="Remove public read permissions from bucket ACL"
                            ))
                except ClientError:
                    pass
                
                # Check encryption
                try:
                    encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
                except ClientError:
                    findings.append(self.create_finding(
                        check_id="S3_ENCRYPTION_DISABLED",
                        resource_id=bucket_name,
                        resource_type="S3Bucket",
                        severity="medium",
                        description=f"S3 bucket {bucket_name} does not have encryption enabled",
                        remediation="Enable default encryption for the bucket"
                    ))
        
        except Exception as e:
            findings.append(self.create_finding(
                check_id="S3_SCAN_ERROR",
                resource_id="N/A",
                resource_type="S3Service",
                severity="low",
                description=f"Failed to scan S3 buckets: {e}",
                remediation="Check AWS permissions and try again"
            ))
        
        return findings
    
    def scan_iam_policies(self) -> List[Dict]:
        """Scan IAM policies for overly permissive access"""
        findings = []
        
        try:
            iam_client = self.session.client('iam')
            
            # Check for policies with admin access
            policies = iam_client.list_policies(Scope='Local')['Policies']
            
            for policy in policies:
                policy_arn = policy['Arn']
                
                try:
                    policy_version = iam_client.get_policy_version(
                        PolicyArn=policy_arn,
                        VersionId=policy['DefaultVersionId']
                    )
                    
                    policy_doc = policy_version['PolicyVersion']['Document']
                    statements = policy_doc.get('Statement', [])
                    
                    for statement in statements:
                        if (statement.get('Effect') == 'Allow' and 
                            statement.get('Action') == '*' and 
                            statement.get('Resource') == '*'):
                            findings.append(self.create_finding(
                                check_id="IAM_ADMIN_POLICY",
                                resource_id=policy_arn,
                                resource_type="IAMPolicy",
                                severity="critical",
                                description=f"IAM policy {policy['PolicyName']} grants admin access (*:*)",
                                remediation="Apply principle of least privilege - restrict actions and resources"
                            ))
                
                except ClientError:
                    continue
        
        except Exception as e:
            findings.append(self.create_finding(
                check_id="IAM_SCAN_ERROR",
                resource_id="N/A",
                resource_type="IAMService",
                severity="low",
                description=f"Failed to scan IAM policies: {e}",
                remediation="Check AWS permissions and try again"
            ))
        
        return findings
    
    def scan_security_groups(self) -> List[Dict]:
        """Scan security groups for overly permissive rules"""
        findings = []
        
        try:
            ec2_client = self.session.client('ec2')
            security_groups = ec2_client.describe_security_groups()['SecurityGroups']
            
            for sg in security_groups:
                sg_id = sg['GroupId']
                
                # Check for 0.0.0.0/0 ingress rules
                for rule in sg.get('IpPermissions', []):
                    for ip_range in rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            port_range = f"{rule.get('FromPort', 'All')}"
                            if rule.get('ToPort') != rule.get('FromPort'):
                                port_range += f"-{rule.get('ToPort', 'All')}"
                            
                            severity = "critical" if rule.get('FromPort') == 22 else "high"
                            
                            findings.append(self.create_finding(
                                check_id="SG_OPEN_INGRESS",
                                resource_id=sg_id,
                                resource_type="SecurityGroup",
                                severity=severity,
                                description=f"Security group {sg_id} allows ingress from 0.0.0.0/0 on port {port_range}",
                                remediation="Restrict source IP ranges to specific addresses or ranges"
                            ))
        
        except Exception as e:
            findings.append(self.create_finding(
                check_id="SG_SCAN_ERROR",
                resource_id="N/A",
                resource_type="EC2Service",
                severity="low",
                description=f"Failed to scan security groups: {e}",
                remediation="Check AWS permissions and try again"
            ))
        
        return findings
    
    def scan_rds_instances(self) -> List[Dict]:
        """Scan RDS instances for security issues"""
        findings = []
        
        try:
            rds_client = self.session.client('rds')
            instances = rds_client.describe_db_instances()['DBInstances']
            
            for instance in instances:
                db_id = instance['DBInstanceIdentifier']
                
                # Check for public accessibility
                if instance.get('PubliclyAccessible', False):
                    findings.append(self.create_finding(
                        check_id="RDS_PUBLIC_ACCESS",
                        resource_id=db_id,
                        resource_type="RDSInstance",
                        severity="high",
                        description=f"RDS instance {db_id} is publicly accessible",
                        remediation="Disable public accessibility for the RDS instance"
                    ))
                
                # Check for encryption
                if not instance.get('StorageEncrypted', False):
                    findings.append(self.create_finding(
                        check_id="RDS_ENCRYPTION_DISABLED",
                        resource_id=db_id,
                        resource_type="RDSInstance",
                        severity="medium",
                        description=f"RDS instance {db_id} does not have storage encryption enabled",
                        remediation="Enable storage encryption for the RDS instance"
                    ))
        
        except Exception as e:
            findings.append(self.create_finding(
                check_id="RDS_SCAN_ERROR",
                resource_id="N/A",
                resource_type="RDSService",
                severity="low",
                description=f"Failed to scan RDS instances: {e}",
                remediation="Check AWS permissions and try again"
            ))
        
        return findings