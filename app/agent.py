"""Security auditor agent with CLI interface.
Version 1.3 - Added solo-dev focus and security scoring"""

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime
from typing import Dict, List, Tuple

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


def calculate_security_score(findings: List[Dict]) -> Tuple[int, Dict[str, Dict]]:
    """Calculate security score (0-100) based on findings.
    
    Args:
        findings: List of finding dictionaries with 'severity' and 'check' fields
        
    Returns:
        Tuple of (score, breakdown) where breakdown is:
        {
            'EC2': {'points': -10, 'count': 1, 'severity': 'HIGH'},
            'S3': {'points': -5, 'count': 1, 'severity': 'MEDIUM'},
            'IAM': {'points': -20, 'count': 1, 'severity': 'CRITICAL'}
        }
    """
    # Point deductions per severity
    SEVERITY_POINTS = {
        'CRITICAL': -20,
        'HIGH': -10,
        'MEDIUM': -5,
        'LOW': -1
    }
    
    # Group findings by category
    categories = {
        'EC2': [],
        'S3': [],
        'IAM': []
    }
    
    for finding in findings:
        check = finding.get('check', '')
        if check.startswith('EC2_'):
            categories['EC2'].append(finding)
        elif check.startswith('S3_'):
            categories['S3'].append(finding)
        elif check.startswith('IAM_'):
            categories['IAM'].append(finding)
    
    # Calculate deductions per category
    breakdown = {}
    total_deduction = 0
    
    for category, cat_findings in categories.items():
        if not cat_findings:
            continue
        
        # Calculate points for this category
        category_points = sum(
            SEVERITY_POINTS.get(f.get('severity', 'LOW'), -1) 
            for f in cat_findings
        )
        total_deduction += category_points
        
        # Find highest severity in this category
        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        highest_severity = 'LOW'
        for sev in severity_order:
            if any(f.get('severity') == sev for f in cat_findings):
                highest_severity = sev
                break
        
        breakdown[category] = {
            'points': category_points,
            'count': len(cat_findings),
            'severity': highest_severity
        }
    
    # Calculate final score (0-100)
    score = max(0, min(100, 100 + total_deduction))
    
    return score, breakdown


def format_security_score(score: int, breakdown: Dict[str, Dict], 
                         json_mode: bool = False) -> str:
    """Format security score for display.
    
    Args:
        score: Security score (0-100)
        breakdown: Category breakdown from calculate_security_score
        json_mode: If True, omit emoji and use plain text
        
    Returns:
        Formatted string for display
    """
    if json_mode:
        # Plain text for JSON mode
        lines = [f"Security Score: {score}/100"]
        if breakdown:
            lines.append("\nBreakdown:")
            for category, data in sorted(breakdown.items()):
                count = data['count']
                severity = data['severity']
                points = data['points']
                plural = "finding" if count == 1 else "findings"
                lines.append(
                    f"  {category}: {points} pts "
                    f"({count} {severity} {plural})"
                )
        return "\n".join(lines)
    else:
        # Formatted output with emoji
        lines = [f"🏆 Security Score: {score}/100"]
        
        if breakdown:
            lines.append("\nBreakdown:")
            for category, data in sorted(breakdown.items()):
                count = data['count']
                severity = data['severity']
                points = data['points']
                plural = "finding" if count == 1 else "findings"
                lines.append(
                    f"  {category}: {points} pts "
                    f"({count} {severity} {plural})"
                )
        
        # Encouragement message based on score
        lines.append("")
        if score >= 90:
            lines.append(
                "🎉 Excellent! Your security posture is stronger than "
                "most solo setups!"
            )
        elif score >= 75:
            lines.append(
                "👍 You're doing better than most solo setups! "
                "Address the issues above to get even stronger."
            )
        elif score >= 60:
            lines.append(
                "⚠️  You have some important security gaps. "
                "Focus on CRITICAL and HIGH findings first."
            )
        else:
            lines.append(
                "🚨 Your infrastructure has significant security risks. "
                "Start with the CRITICAL findings immediately."
            )
        
        return "\n".join(lines)


def generate_summary(findings: List[Dict], score: int, breakdown: Dict[str, Dict],
                    use_llm: bool = True) -> str:
    """Generate a summary of findings with solo-dev focus.

    Args:
        findings: List of finding dictionaries
        score: Security score (0-100)
        breakdown: Category breakdown
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

            prompt = f"""You are advising a solo developer or small team (1-5 people) 
who manages their own AWS infrastructure without a dedicated security team.

Security Score: {score}/100

Findings breakdown:
{json.dumps(findings, indent=2)}

Provide:
1. A 2-sentence executive summary
2. The ONE thing they should fix first and why
3. For each finding: a specific remediation step they can do in under 10 minutes
4. What they can safely ignore for now (if anything)

Be direct and practical. No enterprise jargon. Use "you" not "the organization".
Focus on actions they can take right now from the AWS console or CLI."""

            response = model.generate_content(prompt)
            return response.text

        except Exception as e:
            logger.warning(f"Gemini summarization failed, using fallback: {e}")

    # Fallback to simple Python summary with solo-dev focus
    summary_lines = [f"⚠️  Found {len(findings)} security issue(s):\n"]

    # Group by severity
    by_severity = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
    for finding in findings:
        severity = finding.get("severity", "MEDIUM")
        by_severity[severity].append(finding)

    # Report by severity with actionable advice
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

    # Solo-dev focused action plan
    summary_lines.append("\n🔧 Your Action Plan:")
    
    if by_severity["CRITICAL"]:
        summary_lines.append(
            "  1. FIX FIRST: Address CRITICAL issues NOW "
            "(these are actively dangerous)"
        )
        first_critical = by_severity["CRITICAL"][0]
        if "SSH" in first_critical["description"] or "RDP" in first_critical["description"]:
            summary_lines.append(
                "     → Restrict SSH/RDP to your IP in AWS Console: "
                "EC2 > Security Groups"
            )
        elif "IAM" in first_critical["check"]:
            summary_lines.append(
                "     → Replace wildcard IAM policies with specific permissions"
            )
    
    if by_severity["HIGH"]:
        summary_lines.append(
            "  2. Fix HIGH severity issues within 24 hours"
        )
        if any("database" in f["description"].lower() for f in by_severity["HIGH"]):
            summary_lines.append(
                "     → Lock down database ports to app tier only"
            )
    
    if by_severity["MEDIUM"]:
        summary_lines.append(
            "  3. Plan remediation for MEDIUM issues this week"
        )
    
    if by_severity["LOW"]:
        summary_lines.append(
            f"  4. LOW issues ({len(by_severity['LOW'])}) can wait - "
            "focus on the above first"
        )

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

    # Calculate security score
    score, breakdown = calculate_security_score(all_findings)

    # Generate summary
    summary = generate_summary(all_findings, score, breakdown, 
                              use_llm=not no_llm)

    # Log run summary
    duration = time.perf_counter() - start_time
    logger.info(
        "Security audit complete",
        extra={
            "run_id": run_id,
            "mode": "mock" if mock else "real",
            "total_findings": len(all_findings),
            "security_score": score,
            "duration_seconds": round(duration, 3),
        },
    )

    return {
        "success": True,
        "run_id": run_id,
        "findings": all_findings,
        "summary": summary,
        "security_score": score,
        "score_breakdown": breakdown,
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
                    "security_score": result["security_score"],
                    "score_breakdown": result["score_breakdown"],
                    "findings": result["findings"],
                    "duration_seconds": result["duration_seconds"],
                },
                indent=2,
            )
        )
    else:
        print(f"\n{'=' * 60}")
        print(f"Security Audit Report - {result['run_id']}")
        print(f"{'=' * 60}\n")
        
        # Display security score
        score_display = format_security_score(
            result["security_score"],
            result["score_breakdown"],
            json_mode=False
        )
        print(score_display)
        print(f"\n{'=' * 60}\n")
        
        # Display summary
        print(result["summary"])
        
        duration = result["duration_seconds"]
        print(f"\n⏱️  Scan completed in {duration:.2f} seconds")
        print(f"📊 Total findings: {len(result['findings'])}")

    sys.exit(0)


if __name__ == "__main__":
    main()