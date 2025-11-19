"""Security auditor agent with CLI interface.
VERsion 1.2"""

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime
from typing import Dict, List

from app.logging_config import setup_logging
from app.tools import (
    check_ec2_open_ports,
    check_s3_public_buckets,
    check_iam_wildcards,
)

logger = logging.getLogger(__name__)


def generate_run_id() -> str:
    """Generate a unique run identifier."""
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return f"run-{timestamp}"


def load_mock_data() -> Dict:
    """Load mock data for demo mode."""
    # Default mock data if no fixtures available
    all_users_uri = "http://acs.amazonaws.com/groups/global/AllUsers"
    mock_data = {
        "SecurityGroups": [
            {
                "GroupId": "sg-mock-001",
                "GroupName": "web-server",
                "IpPermissions": [
                    {
                        "FromPort": 80,
                        "ToPort": 80,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    },
                    {
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    },
                ],
            }
        ],
        "Buckets": [{"Name": "my-test-bucket"}],
        "BucketDetails": {
            "my-test-bucket": {
                "ACL": {
                    "Grants": [
                        {
                            "Grantee": {
                                "Type": "Group",
                                "URI": all_users_uri,
                            },
                            "Permission": "READ",
                        }
                    ]
                },
                "PublicAccessBlock": {
                    "PublicAccessBlockConfiguration": {
                        "BlockPublicAcls": False,
                        "BlockPublicPolicy": False,
                        "IgnorePublicAcls": False,
                        "RestrictPublicBuckets": False,
                    }
                },
            }
        },
        "Policies": [
            {
                "PolicyName": "DangerousPolicy",
                "Document": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "*",
                            "Resource": "*",
                        }
                    ]
                },
            }
        ],
    }

    # Try to load from fixtures if available
    try:
        import random

        scenario_num = random.randint(1, 3)
        fixture_path = f"fixtures/scenario_{scenario_num}.json"
        if os.path.exists(fixture_path):
            with open(fixture_path, "r") as f:
                loaded_data = json.load(f)
                if "mock_data" in loaded_data:
                    mock_data = loaded_data["mock_data"]
                else:
                    mock_data = loaded_data
    except (
        IOError,
        json.JSONDecodeError,
        KeyError,
    ) as e:
        # Use default mock data if loading fails
        logger.debug(f"Using default mock data: {e}")

    return mock_data


def generate_summary(findings: List[Dict], use_llm: bool = True) -> str:
    """Generate a summary of findings.

    Args:
        findings: List of finding dictionaries
        use_llm: Whether to use Gemini for summarization

    Returns:
        Human-readable summary string
    """
    if not findings:
        return "✅ No security issues found. Infrastructure appears secure!"

    # Try to use Gemini if available and requested
    if use_llm and os.getenv("GEMINI_API_KEY"):
        try:
            import google.generativeai as genai

            genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
            model = genai.GenerativeModel("gemini-pro")

            prompt = (
                "Summarize these AWS security findings in a clear, "
                "actionable format:\n\n"
                f"{json.dumps(findings, indent=2)}\n\n"
                "Provide a brief executive summary followed by "
                "top priorities for remediation."
            )

            response = model.generate_content(prompt)
            return response.text

        except Exception as e:
            logger.warning(f"Gemini summarization failed, using fallback: {e}")

    # Fallback to simple Python summary
    summary_lines = [f"⚠️  Found {len(findings)} security issue(s):\n"]

    # Group by severity
    by_severity = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
    for finding in findings:
        severity = finding.get("severity", "MEDIUM")
        by_severity[severity].append(finding)

    # Report by severity
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if by_severity[severity]:
            count = len(by_severity[severity])
            summary_lines.append(f"\n{severity} ({count} issues):")
            # Show first 3
            for finding in by_severity[severity][:3]:
                desc = finding["description"]
                resource = finding["resource"]
                summary_lines.append(f"  - {desc} [{resource}]")
            if count > 3:
                remaining = count - 3
                summary_lines.append(f"  ... and {remaining} more")

    summary_lines.append("\n🔧 Recommended Actions:")
    if by_severity["CRITICAL"]:
        summary_lines.append("  1. IMMEDIATELY address CRITICAL issues")
    if by_severity["HIGH"]:
        summary_lines.append("  2. Fix HIGH severity issues within 24 hours")
    if by_severity["MEDIUM"]:
        summary_lines.append("  3. Plan remediation for MEDIUM issues")

    return "\n".join(summary_lines)


def run_audit(mock: bool = False, no_llm: bool = False) -> Dict:
    """Run the security audit.

    Args:
        mock: Use mock data instead of real AWS
        no_llm: Skip LLM summarization

    Returns:
        Dictionary with findings and metadata
    """
    run_id = generate_run_id()
    start_time = time.perf_counter()

    logger.info(
        "Starting security audit",
        extra={
            "run_id": run_id,
            "mode": "mock" if mock else "real",
            "use_llm": not no_llm,
        },
    )

    all_findings = []
    mock_data = load_mock_data() if mock else None

    # Run all checks
    try:
        # EC2 check
        ec2_findings = check_ec2_open_ports(mock_data, run_id)
        all_findings.extend(ec2_findings)

        # S3 check
        s3_findings = check_s3_public_buckets(mock_data, run_id)
        all_findings.extend(s3_findings)

        # IAM check
        iam_findings = check_iam_wildcards(mock_data, run_id)
        all_findings.extend(iam_findings)

    except Exception as e:
        logger.error(f"Audit failed: {e}", extra={"run_id": run_id})
        return {"success": False, "error": str(e), "run_id": run_id}

    # Generate summary
    summary = generate_summary(all_findings, use_llm=not no_llm)

    # Log run summary
    duration = time.perf_counter() - start_time
    logger.info(
        "Security audit complete",
        extra={
            "run_id": run_id,
            "mode": "mock" if mock else "real",
            "total_findings": len(all_findings),
            "duration_seconds": round(duration, 3),
        },
    )

    return {
        "success": True,
        "run_id": run_id,
        "findings": all_findings,
        "summary": summary,
        "duration_seconds": round(duration, 3),
    }


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="AWS Security Auditor - Check for common misconfigurations"
    )
    parser.add_argument(
        "--mock",
        action="store_true",
        help="Use mock data instead of real AWS (for demos)",
    )
    parser.add_argument(
        "--no-llm",
        action="store_true",
        help="Skip LLM summarization",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output findings as JSON",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Set logging level",
    )

    args = parser.parse_args()

    # Setup logging
    setup_logging(getattr(logging, args.log_level))

    # Run audit
    result = run_audit(mock=args.mock, no_llm=args.no_llm)

    if not result["success"]:
        error = result.get("error", "Unknown error")
        print(f"❌ Audit failed: {error}")
        sys.exit(1)

    # Output results
    if args.json:
        print(
            json.dumps(
                {
                    "run_id": result["run_id"],
                    "findings": result["findings"],
                    "duration_seconds": result["duration_seconds"],
                },
                indent=2,
            )
        )
    else:
        print(f"\n{'=' * 60}")
        print(f"Security Audit Report - {result['run_id']}")
        print(f"{'=' * 60}")
        print(result["summary"])
        duration = result["duration_seconds"]
        print(f"\n⏱️  Scan completed in {duration:.2f} seconds")
        print(f"📊 Total findings: {len(result['findings'])}")

    sys.exit(0)


if __name__ == "__main__":
    main()
