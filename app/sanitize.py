"""Sanitization helpers for security data.

All tools should use these functions to sanitize data before creating Finding objects.
This ensures consistent sanitization and prevents leaking sensitive information.
"""

import re


def mask_account_id(account_id: str) -> str:
    """Mask AWS account ID, keeping only last 4 digits.

    Args:
        account_id: AWS account ID (12 digits)

    Returns:
        Masked account ID like "ACCOUNT_****1234"

    Examples:
        >>> mask_account_id("123456789012")
        'ACCOUNT_****9012'
        >>> mask_account_id("aws:123456789012")
        'ACCOUNT_****9012'
    """
    digits = re.sub(r"\D", "", account_id)
    if len(digits) < 4:
        return "ACCOUNT_XXXX"
    return f"ACCOUNT_****{digits[-4:]}"


def label_ip(ip: str) -> str:
    """Label IP address as PUBLIC_IP or PRIVATE_IP.

    This prevents logging actual IP addresses while retaining
    information about whether the IP is public or private.

    Args:
        ip: IP address string

    Returns:
        "PUBLIC_IP" or "PRIVATE_IP"

    Examples:
        >>> label_ip("10.0.0.1")
        'PRIVATE_IP'
        >>> label_ip("192.168.1.1")
        'PRIVATE_IP'
        >>> label_ip("8.8.8.8")
        'PUBLIC_IP'
    """
    # Simple private range check
    # RFC 1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    if ip.startswith("10."):
        return "PRIVATE_IP"
    if ip.startswith("192.168."):
        return "PRIVATE_IP"
    if ip.startswith("172."):
        # Check if it's in 172.16.0.0/12
        parts = ip.split(".")
        if len(parts) >= 2:
            second_octet = int(parts[1])
            if 16 <= second_octet <= 31:
                return "PRIVATE_IP"
    if ip.startswith("127."):
        return "PRIVATE_IP"
    return "PUBLIC_IP"


def sanitize_sg_identifier(sg_id: str, account_id: str | None = None) -> str:
    """Create sanitized security group identifier.

    Args:
        sg_id: Security group ID (e.g. "sg-abc123")
        account_id: Optional account ID to include

    Returns:
        Sanitized identifier like "ACCOUNT_****1234:sg-abc123"

    Examples:
        >>> sanitize_sg_identifier("sg-abc123", "123456789012")
        'ACCOUNT_****9012:sg-abc123'
        >>> sanitize_sg_identifier("sg-abc123")
        'sg-abc123'
    """
    if account_id:
        account_label = mask_account_id(account_id)
        return f"{account_label}:{sg_id}"
    return sg_id


def sanitize_bucket_name(bucket: str) -> str:
    """Sanitize S3 bucket name.

    For MVP, we keep the full bucket name since it's required
    to take action. In production, you might want to hash or
    partially mask this.

    Args:
        bucket: S3 bucket name

    Returns:
        Bucket name (currently unchanged)

    Examples:
        >>> sanitize_bucket_name("my-important-bucket")
        'my-important-bucket'
    """
    # For MVP: keep full name
    # Could enhance to: hash, partial mask, or user-configurable
    return bucket


def sanitize_arn(arn: str) -> str:
    """Sanitize AWS ARN to show only service and resource type.

    Args:
        arn: Full ARN like "arn:aws:iam::123456789012:role/MyRole"

    Returns:
        Sanitized ARN like "arn:aws:iam::ACCOUNT_****9012:role/[REDACTED]"

    Examples:
        >>> sanitize_arn("arn:aws:iam::123456789012:role/MyRole")
        'arn:aws:iam::ACCOUNT_****9012:role/[REDACTED]'
    """
    parts = arn.split(":")
    if len(parts) < 6:
        return arn

    # ARN format: arn:partition:service:region:account-id:resource
    service = parts[2]
    account_id = parts[4] if parts[4] else None

    if account_id:
        masked = mask_account_id(account_id)
        parts[4] = masked

    # Redact the resource name
    resource = parts[5]
    if "/" in resource:
        resource_type = resource.split("/")[0]
        parts[5] = f"{resource_type}/[REDACTED]"

    return ":".join(parts)
