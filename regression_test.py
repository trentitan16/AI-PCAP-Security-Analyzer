from __future__ import annotations

import os
import sys
from contextlib import redirect_stdout
from pathlib import Path

from analyzer import analyze_pcap


TEST_CASES = [
    {
        "name": "Benign",
        "filename": "ctu-idseval-6-benign-user-traffic-1.pcap",
        "score": 0,
        "assessment": "LIKELY NORMAL",
        "categories": [],
    },
    {
        "name": "Malware 1",
        "filename": "ctu-idseval-6-malicious-malware-1.pcap",
        "score": 95,
        "assessment": "HIGH RISK",
        "categories": [
            "CORRELATED REPEATED OUTBOUND ACTIVITY",
            "SUSPICIOUS DNS BEHAVIOR",
        ],
    },
    {
        "name": "Malware 2",
        "filename": "ctu-idseval-6-malicious-malware-2.pcap",
        "score": 100,
        "assessment": "HIGH RISK",
        "categories": [
            "PORT SCAN",
            "CORRELATED REPEATED OUTBOUND ACTIVITY",
        ],
    },
    {
        "name": "Portscan 1",
        "filename": "ctu-idseval-6-malicious-portscan-1.pcap",
        "score": 60,
        "assessment": "SUSPICIOUS",
        "categories": [
            "PORT SCAN",
        ],
    },
    {
        "name": "Portscan 2",
        "filename": "ctu-idseval-6-malicious-portscan-2.pcap",
        "score": 50,
        "assessment": "SUSPICIOUS",
        "categories": [
            "PORT SCAN",
        ],
    },
    {
        "name": "Portscan 3",
        "filename": "ctu-idseval-6-malicious-portscan-3.pcap",
        "score": 60,
        "assessment": "SUSPICIOUS",
        "categories": [
            "PORT SCAN",
        ],
    },
]


def resolve_capture_directory() -> Path:
    if len(sys.argv) > 1:
        return Path(sys.argv[1]).expanduser().resolve()

    return Path.cwd()


def format_categories(categories: list[str]) -> str:
    if not categories:
        return "None"

    return ", ".join(categories)


def make_progress_callback(test_name: str):
    last_percent = {"value": -1}

    def progress(processed: int, total: int | None):
        if not total:
            return

        percent = int((processed / total) * 100)
        percent = min(max(percent, 0), 100)

        # Update at 10% intervals so large captures show progress
        # without flooding the terminal.
        display_percent = (percent // 10) * 10

        if (
            display_percent != last_percent["value"]
            and display_percent <= 100
        ):
            last_percent["value"] = display_percent
            sys.__stdout__.write(
                f"\r  {test_name}: {display_percent:3d}%"
            )
            sys.__stdout__.flush()

    return progress


def validate_backend_sections(report: dict, expected_findings: bool) -> list[str]:
    errors = []

    required_sections = [
        "finding_investigation",
        "visual_analysis",
        "network_map",
        "threat_hunt",
        "hosts",
    ]

    for section in required_sections:
        if section not in report:
            errors.append(
                f"missing backend section: {section}"
            )

    finding_backend = report.get(
        "finding_investigation",
        {}
    )

    findings = finding_backend.get(
        "findings",
        []
    )

    if expected_findings and not findings:
        errors.append(
            "expected at least one structured finding"
        )

    if not expected_findings and findings:
        errors.append(
            "benign capture unexpectedly produced structured findings"
        )

    threat_hunt = report.get(
        "threat_hunt",
        {}
    )

    if threat_hunt.get("host_count", 0) <= 0:
        errors.append(
            "Threat Hunt index contains no hosts"
        )

    return errors


def run_test(case: dict, capture_directory: Path) -> dict:
    pcap_path = capture_directory / case["filename"]

    result = {
        "name": case["name"],
        "filename": case["filename"],
        "passed": False,
        "errors": [],
        "actual_score": None,
        "actual_assessment": None,
        "actual_categories": [],
    }

    if not pcap_path.exists():
        result["errors"].append(
            f"file not found: {pcap_path}"
        )
        return result

    print(
        f"\n[{case['name']}] {case['filename']}"
    )

    progress_callback = make_progress_callback(
        case["name"]
    )

    try:
        # Suppress the analyzer's long normal console report during
        # automated testing. The progress callback still writes to the
        # real terminal through sys.__stdout__.
        with open(os.devnull, "w", encoding="utf-8") as null_output:
            with redirect_stdout(null_output):
                report = analyze_pcap(
                    pcap_file=str(pcap_path),
                    interactive=False,
                    generate_ai=False,
                    save_reports=False,
                    progress_callback=progress_callback,
                )

        sys.__stdout__.write("\r")
        sys.__stdout__.flush()

    except Exception as error:
        result["errors"].append(
            f"analysis crashed: {type(error).__name__}: {error}"
        )
        print(
            f"  FAIL - analysis crashed: {error}"
        )
        return result

    summary = report.get(
        "summary",
        {}
    )

    actual_score = summary.get(
        "overall_risk_score"
    )
    actual_assessment = summary.get(
        "overall_assessment"
    )
    actual_categories = summary.get(
        "threat_categories",
        []
    )

    result["actual_score"] = actual_score
    result["actual_assessment"] = actual_assessment
    result["actual_categories"] = actual_categories

    if actual_score != case["score"]:
        result["errors"].append(
            f"risk score expected {case['score']}, got {actual_score}"
        )

    if actual_assessment != case["assessment"]:
        result["errors"].append(
            "assessment expected "
            f"{case['assessment']}, got {actual_assessment}"
        )

    for expected_category in case["categories"]:
        if expected_category not in actual_categories:
            result["errors"].append(
                f"missing threat category: {expected_category}"
            )

    if not case["categories"] and actual_categories:
        result["errors"].append(
            "expected no threat categories, got "
            f"{format_categories(actual_categories)}"
        )

    result["errors"].extend(
        validate_backend_sections(
            report,
            expected_findings=bool(
                case["categories"]
            ),
        )
    )

    result["passed"] = not result["errors"]

    if result["passed"]:
        print(
            "  PASS - "
            f"{actual_score}/100 {actual_assessment}"
        )
    else:
        print(
            "  FAIL - "
            f"{actual_score}/100 {actual_assessment}"
        )

        for error in result["errors"]:
            print(
                f"    - {error}"
            )

    return result


def print_summary(results: list[dict]):
    print(
        "\n"
        + "=" * 72
    )
    print(
        "AI PCAP SECURITY ANALYZER - AUTOMATED REGRESSION SUMMARY"
    )
    print(
        "=" * 72
    )

    passed = 0

    for result in results:
        status = (
            "PASS"
            if result["passed"]
            else "FAIL"
        )

        if result["passed"]:
            passed += 1

        score = result["actual_score"]

        if score is None:
            score_text = "N/A"
        else:
            score_text = f"{score}/100"

        assessment = (
            result["actual_assessment"]
            or "N/A"
        )

        print(
            f"{status:<4}  "
            f"{result['name']:<12}  "
            f"{score_text:<8}  "
            f"{assessment}"
        )

    print(
        "-" * 72
    )
    print(
        f"Passed: {passed}/{len(results)}"
    )

    if passed == len(results):
        print(
            "\nAll six CTU-IDSEVAL-6 regression tests passed."
        )
        print(
            "Expected risk scores, assessments, core threat categories, "
            "and v1.4 investigation backends remained stable."
        )
    else:
        print(
            "\nRegression failures were detected."
        )
        print(
            "Review the failed capture(s) before committing or releasing."
        )


def main():
    capture_directory = resolve_capture_directory()

    print(
        "\n=========================================="
    )
    print(
        " AI PCAP Security Analyzer Regression Test"
    )
    print(
        "=========================================="
    )
    print(
        f"\nCapture directory:\n  {capture_directory}"
    )
    print(
        "\nRunning six CTU-IDSEVAL-6 validation captures."
    )
    print(
        "AI explanations and report export are disabled."
    )
    print(
        "Large captures may take several minutes.\n"
    )

    results = []

    for case in TEST_CASES:
        results.append(
            run_test(
                case,
                capture_directory
            )
        )

    print_summary(results)

    all_passed = all(
        result["passed"]
        for result in results
    )

    # Exit code 0 means success. A nonzero exit code makes this useful
    # later in GitHub Actions or another automated CI workflow.
    raise SystemExit(
        0
        if all_passed
        else 1
    )


if __name__ == "__main__":
    main()
