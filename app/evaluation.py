"""Evaluation framework for security audit agent.

Loads test scenarios, runs security checks, computes metrics
(TP/FN/FP, precision, recall), and generates evaluation reports.
"""

import json
import time
from pathlib import Path
from typing import Dict, List

from app.tools import (
    check_ec2_open_ports,
    check_s3_public_buckets,
    check_iam_wildcards,
)


def load_scenario(scenario_path: Path) -> Dict:
    """Load a test scenario from JSON file."""
    with open(scenario_path) as f:
        return json.load(f)


def run_checks(mock_data: Dict, run_id: str) -> List[Dict]:
    """Run all security checks on mock data and return combined findings."""
    findings = []
    findings.extend(check_ec2_open_ports(mock_data, run_id))
    findings.extend(check_s3_public_buckets(mock_data, run_id))
    findings.extend(check_iam_wildcards(mock_data, run_id))
    return findings


def findings_match(actual: Dict, expected: Dict) -> bool:
    """Check if an actual finding matches an expected finding.

    Match criteria: check type + resource ID must match.
    """
    return (
        actual["check"] == expected["check"]
        and actual["resource"] == expected["resource"]
    )


def compute_metrics(actual_findings: List[Dict], expected_findings: List[Dict]) -> Dict:
    """Compute TP, FN, FP, precision, recall for a scenario.

    Args:
        actual_findings: Findings detected by the tools
        expected_findings: Ground truth findings from scenario

    Returns:
        Dict with tp, fn, fp, precision, recall
    """
    # Find true positives - actual findings that match expected
    tp = 0
    matched_expected = set()

    for actual in actual_findings:
        for i, expected in enumerate(expected_findings):
            if i not in matched_expected and findings_match(actual, expected):
                tp += 1
                matched_expected.add(i)
                break

    # False negatives - expected findings we missed
    fn = len(expected_findings) - tp

    # False positives - actual findings that don't match any expected
    fp = len(actual_findings) - tp

    # Calculate precision and recall
    precision = (tp / (tp + fp) * 100) if (tp + fp) > 0 else 0.0
    recall = (tp / (tp + fn) * 100) if (tp + fn) > 0 else 0.0

    return {
        "tp": tp,
        "fn": fn,
        "fp": fp,
        "precision": round(precision, 1),
        "recall": round(recall, 1),
    }


def evaluate_scenario(scenario_path: Path) -> Dict:
    """Evaluate a single scenario and return metrics.

    Returns:
        Dict with scenario name, metrics, and latency
    """
    scenario = load_scenario(scenario_path)

    # Time the execution
    start_time = time.perf_counter()

    # Run checks
    run_id = f"eval-{scenario_path.stem}"
    actual_findings = run_checks(scenario["mock_data"], run_id)

    # Calculate latency
    latency_ms = round((time.perf_counter() - start_time) * 1000)

    # Compute metrics
    metrics = compute_metrics(actual_findings, scenario["expected_findings"])

    return {
        "scenario": scenario["name"],
        "description": scenario["description"],
        "latency_ms": latency_ms,
        **metrics,
    }


def write_results_json(results: List[Dict], output_path: Path):
    """Write raw evaluation results to JSON file."""
    output_path.parent.mkdir(exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(
            {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "scenarios": results,
            },
            f,
            indent=2,
        )


def write_evaluation_markdown(results: List[Dict], output_path: Path):
    """Write evaluation results as a markdown table."""
    output_path.parent.mkdir(exist_ok=True)

    with open(output_path, "w") as f:
        f.write("# Agent Evaluation Results\n\n")
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"**Evaluation Date:** {timestamp}\n\n")
        f.write("## Metrics by Scenario\n\n")

        # Table header
        header = "| Scenario | TP | FN | FP | Precision | Recall | Latency |\n"
        separator = "|----------|----|----|----|-----------|---------|---------|\n"  # noqa: E501
        f.write(header)
        f.write(separator)

        # Table rows
        for result in results:
            scenario_name = result["scenario"].replace("Scenario ", "")
            f.write(f"| {scenario_name} | ")
            f.write(f"{result['tp']} | ")
            f.write(f"{result['fn']} | ")
            f.write(f"{result['fp']} | ")
            f.write(f"{result['precision']}% | ")
            f.write(f"{result['recall']}% | ")
            f.write(f"{result['latency_ms']}ms |\n")

        # Summary section
        f.write("\n## Summary\n\n")
        total_tp = sum(r["tp"] for r in results)
        total_fn = sum(r["fn"] for r in results)
        total_fp = sum(r["fp"] for r in results)
        total_latency = sum(r["latency_ms"] for r in results)
        avg_latency = round(total_latency / len(results))

        overall_precision = (
            (total_tp / (total_tp + total_fp) * 100)
            if (total_tp + total_fp) > 0
            else 0.0
        )
        overall_recall = (
            (total_tp / (total_tp + total_fn) * 100)
            if (total_tp + total_fn) > 0
            else 0.0
        )

        f.write(f"- **Overall Precision:** {overall_precision:.1f}%\n")
        f.write(f"- **Overall Recall:** {overall_recall:.1f}%\n")
        f.write(f"- **Average Latency:** {avg_latency}ms\n")
        f.write(f"- **Total Test Cases:** {len(results)}\n")

        # Scenario descriptions
        f.write("\n## Scenario Descriptions\n\n")
        for result in results:
            f.write(f"**{result['scenario']}:** {result['description']}\n\n")


def main():
    """Run evaluation on all scenarios and generate reports."""
    print("Starting evaluation...")

    # Find all scenario files
    fixtures_dir = Path(__file__).parent.parent / "fixtures"
    scenario_files = sorted(fixtures_dir.glob("scenario_*.json"))

    if not scenario_files:
        print("Error: No scenario files found in fixtures/")
        return 1

    print(f"Found {len(scenario_files)} scenarios to evaluate")

    # Evaluate each scenario
    results = []
    for scenario_file in scenario_files:
        print(f"  Evaluating {scenario_file.name}...")
        result = evaluate_scenario(scenario_file)
        results.append(result)
        print(
            f"    ✓ TP={result['tp']}, FN={result['fn']}, "
            f"FP={result['fp']}, Precision={result['precision']}%, "
            f"Recall={result['recall']}%, Latency={result['latency_ms']}ms"
        )

    # Write results
    docs_dir = Path(__file__).parent.parent / "docs"

    print("\nWriting results...")
    write_results_json(results, docs_dir / "results.json")
    print(f"  ✓ {docs_dir / 'results.json'}")

    write_evaluation_markdown(results, docs_dir / "EVALUATION.md")
    print(f"  ✓ {docs_dir / 'EVALUATION.md'}")

    print("\nEvaluation complete! 🎉")
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
