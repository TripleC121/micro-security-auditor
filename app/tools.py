"""Security check tools for AWS infrastructure."""

import boto3
import logging
import time
from typing import Dict, List, Optional, Any
from app.sanitize import sanitize_finding

logger = logging.getLogger(__name__)

# Dangerous ports to check
DANGEROUS_PORTS = {
    22: "SSH",
    3389: "RDP", 
    5432: "PostgreSQL",
    3306: "MySQL",
    1433: "MSSQL",
    27017: "MongoDB",
    6379: "Redis",
    9200: "Elasticsearch"
}

def check_ec2_open_ports(mock_data: Optional[Dict] = None, run_id: Optional[str] = None) -> List[Dict]:
    """Check EC2 security groups for dangerous open ports.
    
    Args:
        mock_data: Optional dict with 'SecurityGroups' key for testing
        run_id: Optional run identifier for correlation
        
    Returns:
        List of finding dictionaries
    """
    start_time = time.perf_counter()
    
    logger.info(
        "Starting EC2 security check", 
        extra={'run_id': run_id, 'component': 'ec2_check'}
    )
    
    findings = []
    
    try:
        # Get security groups
        if mock_data:
            security_groups = mock_data.get('SecurityGroups', [])
        else:
            ec2 = boto3.client('ec2')
            response = ec2.describe_security_groups()
            security_groups = response['SecurityGroups']
        
        # Check each security group
        for sg in security_groups:
            sg_id = sg.get('GroupId', 'unknown')
            
            for rule in sg.get('IpPermissions', []):
                # Get port range
                from_port = rule.get('FromPort')
                to_port = rule.get('ToPort', from_port)
                
                if from_port is None:
                    continue
                    
                # Check if any dangerous ports are in range
                for dangerous_port, service in DANGEROUS_PORTS.items():
                    if from_port <= dangerous_port <= to_port:
                        # Check for IPv4 open to internet (0.0.0.0/0)
                        for ip_range in rule.get('IpRanges', []):
                            if ip_range.get('CidrIp') == '0.0.0.0/0':
                                finding = {
                                    'check': 'EC2_OPEN_PORT',
                                    'resource': sg_id,
                                    'severity': 'CRITICAL' if dangerous_port in [22, 3389] else 'HIGH',
                                    'description': f"{service} port {dangerous_port} open to internet (IPv4)",
                                    'details': {
                                        'port': dangerous_port,
                                        'service': service,
                                        'cidr': '0.0.0.0/0',
                                        'sg_name': sg.get('GroupName', 'unknown')
                                    }
                                }
                                findings.append(sanitize_finding(finding))
                        
                        # Check for IPv6 open to internet (::/0)
                        for ipv6_range in rule.get('Ipv6Ranges', []):
                            if ipv6_range.get('CidrIpv6') == '::/0':
                                finding = {
                                    'check': 'EC2_OPEN_PORT',
                                    'resource': sg_id,
                                    'severity': 'CRITICAL' if dangerous_port in [22, 3389] else 'HIGH',
                                    'description': f"{service} port {dangerous_port} open to internet (IPv6)",
                                    'details': {
                                        'port': dangerous_port,
                                        'service': service,
                                        'cidr': '::/0',
                                        'sg_name': sg.get('GroupName', 'unknown')
                                    }
                                }
                                findings.append(sanitize_finding(finding))
    
    except Exception as e:
        logger.error(f"Error checking EC2 security groups: {e}", extra={'run_id': run_id})
        raise
    
    finally:
        # Log metrics
        duration = time.perf_counter() - start_time
        logger.info(
            "EC2 check complete",
            extra={
                'run_id': run_id,
                'component': 'ec2_check',
                'resources_scanned': len(security_groups),
                'findings_count': len(findings),
                'duration_seconds': round(duration, 3)
            }
        )
    
    return findings

def check_s3_public_buckets(mock_data: Optional[Dict] = None, run_id: Optional[str] = None) -> List[Dict]:
    """Check S3 buckets for public access.
    
    Args:
        mock_data: Optional dict with 'Buckets' key for testing
        run_id: Optional run identifier for correlation
        
    Returns:
        List of finding dictionaries
    """
    start_time = time.perf_counter()
    
    logger.info(
        "Starting S3 public access check",
        extra={'run_id': run_id, 'component': 's3_check'}
    )
    
    findings = []
    buckets_scanned = 0
    
    try:
        if mock_data:
            buckets = mock_data.get('Buckets', [])
        else:
            s3 = boto3.client('s3')
            response = s3.list_buckets()
            buckets = response.get('Buckets', [])
        
        for bucket in buckets:
            bucket_name = bucket.get('Name', bucket) if isinstance(bucket, dict) else bucket
            buckets_scanned += 1
            
            # Check bucket ACL
            if mock_data:
                # Mock data should include ACL info
                bucket_data = mock_data.get('BucketDetails', {}).get(bucket_name, {})
                acl = bucket_data.get('ACL', {})
                public_access_block = bucket_data.get('PublicAccessBlock', {})
            else:
                s3 = boto3.client('s3')
                try:
                    acl = s3.get_bucket_acl(Bucket=bucket_name)
                    public_access_block = s3.get_public_access_block(Bucket=bucket_name)
                except:
                    # Bucket might not exist or we lack permissions
                    continue
            
            # Check for public ACLs
            for grant in acl.get('Grants', []):
                grantee = grant.get('Grantee', {})
                if grantee.get('Type') == 'Group':
                    uri = grantee.get('URI', '')
                    if 'AllUsers' in uri or 'AuthenticatedUsers' in uri:
                        finding = {
                            'check': 'S3_PUBLIC_BUCKET',
                            'resource': bucket_name,
                            'severity': 'HIGH',
                            'description': f"Bucket has public {grant.get('Permission', 'UNKNOWN')} access",
                            'details': {
                                'bucket': bucket_name,
                                'permission': grant.get('Permission', 'UNKNOWN'),
                                'grantee': 'AllUsers' if 'AllUsers' in uri else 'AuthenticatedUsers'
                            }
                        }
                        findings.append(sanitize_finding(finding))
            
            # Check if public access is blocked
            if public_access_block:
                config = public_access_block.get('PublicAccessBlockConfiguration', {})
                if not all([
                    config.get('BlockPublicAcls', False),
                    config.get('BlockPublicPolicy', False),
                    config.get('IgnorePublicAcls', False),
                    config.get('RestrictPublicBuckets', False)
                ]):
                    finding = {
                        'check': 'S3_PUBLIC_ACCESS_NOT_BLOCKED',
                        'resource': bucket_name,
                        'severity': 'MEDIUM',
                        'description': "Bucket does not block all public access",
                        'details': {
                            'bucket': bucket_name,
                            'block_public_acls': config.get('BlockPublicAcls', False),
                            'block_public_policy': config.get('BlockPublicPolicy', False)
                        }
                    }
                    findings.append(sanitize_finding(finding))
    
    except Exception as e:
        logger.error(f"Error checking S3 buckets: {e}", extra={'run_id': run_id})
        raise
    
    finally:
        duration = time.perf_counter() - start_time
        logger.info(
            "S3 check complete",
            extra={
                'run_id': run_id,
                'component': 's3_check',
                'resources_scanned': buckets_scanned,
                'findings_count': len(findings),
                'duration_seconds': round(duration, 3)
            }
        )
    
    return findings

def check_iam_wildcards(mock_data: Optional[Dict] = None, run_id: Optional[str] = None) -> List[Dict]:
    """Check IAM policies for wildcard permissions.
    
    Args:
        mock_data: Optional dict with 'Policies' key for testing
        run_id: Optional run identifier for correlation
        
    Returns:
        List of finding dictionaries
    """
    start_time = time.perf_counter()
    
    logger.info(
        "Starting IAM wildcard check",
        extra={'run_id': run_id, 'component': 'iam_check'}
    )
    
    findings = []
    policies_scanned = 0
    
    try:
        if mock_data:
            policies = mock_data.get('Policies', [])
        else:
            iam = boto3.client('iam')
            # Get customer managed policies
            response = iam.list_policies(Scope='Local')
            policies = response.get('Policies', [])
        
        for policy in policies:
            policy_name = policy.get('PolicyName', 'unknown')
            policies_scanned += 1
            
            # Get policy document
            if mock_data:
                # Mock data should include the document
                document = policy.get('Document', {})
            else:
                iam = boto3.client('iam')
                try:
                    version_response = iam.get_policy_version(
                        PolicyArn=policy['Arn'],
                        VersionId=policy['DefaultVersionId']
                    )
                    document = version_response['PolicyVersion']['Document']
                except:
                    continue
            
            # Check statements for wildcards
            for statement in document.get('Statement', []):
                if statement.get('Effect') != 'Allow':
                    continue
                
                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                
                resources = statement.get('Resource', [])
                if isinstance(resources, str):
                    resources = [resources]
                
                # Check for dangerous wildcards
                has_wildcard_action = any('*' in action for action in actions)
                has_wildcard_resource = any('*' == resource for resource in resources)
                
                if has_wildcard_action and has_wildcard_resource:
                    severity = 'CRITICAL'
                    description = "Policy allows all actions on all resources"
                elif has_wildcard_action:
                    severity = 'HIGH'
                    description = "Policy allows all actions"
                elif has_wildcard_resource:
                    severity = 'HIGH'
                    description = "Policy applies to all resources"
                else:
                    continue
                
                finding = {
                    'check': 'IAM_WILDCARD',
                    'resource': policy_name,
                    'severity': severity,
                    'description': description,
                    'details': {
                        'policy': policy_name,
                        'actions': actions[:5],  # Limit to first 5
                        'resources': resources[:5],  # Limit to first 5
                        'statement_id': statement.get('Sid', 'no-sid')
                    }
                }
                findings.append(sanitize_finding(finding))
    
    except Exception as e:
        logger.error(f"Error checking IAM policies: {e}", extra={'run_id': run_id})
        raise
    
    finally:
        duration = time.perf_counter() - start_time
        logger.info(
            "IAM check complete",
            extra={
                'run_id': run_id,
                'component': 'iam_check',
                'resources_scanned': policies_scanned,
                'findings_count': len(findings),
                'duration_seconds': round(duration, 3)
            }
        )
    
    return findings