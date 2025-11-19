"""Tests for security check tools."""

import pytest
from app.tools import check_ec2_open_ports, check_s3_public_buckets, check_iam_wildcards

def test_ec2_secure_config():
    """No open ports should return empty findings."""
    mock_data = {
        'SecurityGroups': [
            {
                'GroupId': 'sg-test-secure',
                'GroupName': 'secure-group',
                'IpPermissions': [
                    {
                        'FromPort': 443,
                        'ToPort': 443,
                        'IpRanges': [{'CidrIp': '10.0.0.0/8'}]  # Private IP range
                    }
                ]
            }
        ]
    }
    
    findings = check_ec2_open_ports(mock_data)
    assert len(findings) == 0, "Secure config should have no findings"

def test_ec2_single_open_port():
    """Single open SSH port should be detected."""
    mock_data = {
        'SecurityGroups': [
            {
                'GroupId': 'sg-test-open',
                'GroupName': 'open-ssh',
                'IpPermissions': [
                    {
                        'FromPort': 22,
                        'ToPort': 22,
                        'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                    }
                ]
            }
        ]
    }
    
    findings = check_ec2_open_ports(mock_data)
    assert len(findings) == 1, "Should find exactly one open port"
    assert findings[0]['check'] == 'EC2_OPEN_PORT'
    assert findings[0]['severity'] == 'CRITICAL'  # SSH is critical
    assert findings[0]['details']['port'] == 22

def test_ec2_multiple_open_ports():
    """Multiple open ports should all be detected (catches loop bugs)."""
    mock_data = {
        'SecurityGroups': [
            {
                'GroupId': 'sg-test-multiple',
                'GroupName': 'multiple-open',
                'IpPermissions': [
                    {
                        'FromPort': 22,
                        'ToPort': 22,
                        'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                    },
                    {
                        'FromPort': 3389,
                        'ToPort': 3389,
                        'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                    },
                    {
                        'FromPort': 3306,
                        'ToPort': 3306,
                        'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                    }
                ]
            }
        ]
    }
    
    findings = check_ec2_open_ports(mock_data)
    assert len(findings) == 3, "Should find all three open ports"
    
    # Check we found each port
    found_ports = {f['details']['port'] for f in findings}
    assert 22 in found_ports, "Should find SSH port"
    assert 3389 in found_ports, "Should find RDP port"
    assert 3306 in found_ports, "Should find MySQL port"

def test_s3_public_bucket():
    """Test S3 public bucket detection."""
    mock_data = {
        'Buckets': [{'Name': 'test-bucket'}],
        'BucketDetails': {
            'test-bucket': {
                'ACL': {
                    'Grants': [
                        {
                            'Grantee': {
                                'Type': 'Group',
                                'URI': 'http://acs.amazonaws.com/groups/global/AllUsers'
                            },
                            'Permission': 'READ'
                        }
                    ]
                },
                'PublicAccessBlock': {
                    'PublicAccessBlockConfiguration': {
                        'BlockPublicAcls': False,
                        'BlockPublicPolicy': False,
                        'IgnorePublicAcls': False,
                        'RestrictPublicBuckets': False
                    }
                }
            }
        }
    }
    
    findings = check_s3_public_buckets(mock_data)
    assert len(findings) >= 1, "Should find public bucket"
    
    # Should find at least the public ACL
    public_acl = [f for f in findings if f['check'] == 'S3_PUBLIC_BUCKET']
    assert len(public_acl) > 0, "Should detect public ACL"

def test_iam_wildcard_detection():
    """Test IAM wildcard permission detection."""
    mock_data = {
        'Policies': [
            {
                'PolicyName': 'AdminPolicy',
                'Document': {
                    'Statement': [
                        {
                            'Effect': 'Allow',
                            'Action': '*',
                            'Resource': '*'
                        }
                    ]
                }
            },
            {
                'PolicyName': 'SafePolicy',
                'Document': {
                    'Statement': [
                        {
                            'Effect': 'Allow',
                            'Action': 's3:GetObject',
                            'Resource': 'arn:aws:s3:::my-bucket/*'
                        }
                    ]
                }
            }
        ]
    }
    
    findings = check_iam_wildcards(mock_data)
    assert len(findings) == 1, "Should find only the dangerous policy"
    assert findings[0]['check'] == 'IAM_WILDCARD'
    assert findings[0]['severity'] == 'CRITICAL'
    assert findings[0]['resource'] == 'AdminPolicy'

def test_sanitization():
    """Test that findings are properly sanitized."""
    mock_data = {
        'SecurityGroups': [
            {
                'GroupId': 'sg-123456789012-test',  # Contains account-like ID
                'GroupName': 'test-group',
                'IpPermissions': [
                    {
                        'FromPort': 22,
                        'ToPort': 22,
                        'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                    }
                ]
            }
        ]
    }
    
    findings = check_ec2_open_ports(mock_data)
    assert len(findings) == 1
    
    # Check that account ID is masked
    resource = findings[0]['resource']
    assert 'ACCOUNT_MASKED' in resource or '123456789012' not in resource
    
    # Check that 0.0.0.0/0 is preserved (it's not an IP to sanitize)
    assert findings[0]['details']['cidr'] == '0.0.0.0/0'
