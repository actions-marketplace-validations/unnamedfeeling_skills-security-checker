from __future__ import annotations

import os
import sys
from collections import OrderedDict
from pathlib import Path

from dotenv import load_dotenv
from openai import OpenAI

from src.auditor import audit_skill, load_prompt
from src.config import load_audit_config
from src.exporters import export_findings
from src.github_issues import create_github_security_issues
from src.models import AuditSummary, DirectoryAuditReport, DiscoveredSkill
from src.reporter import (
    emit_github_annotations,
    print_directory_summary,
    print_overall_summary,
    should_fail_build,
    write_step_summary,
)
from src.scanner import parse_target_directories, scan_skills


def main() -> None:
    load_dotenv()

    # Read configuration (supporting GitHub Actions inputs and local env variables)
    api_key = os.getenv("INPUT_API_KEY") or os.getenv("API_KEY") or ""
    endpoint = os.getenv("INPUT_ENDPOINT") or os.getenv("ENDPOINT") or "https://api.openai.com/v1"
    model = os.getenv("INPUT_MODEL") or os.getenv("MODEL") or "gpt-4o"

    raw_target_dirs = (
        os.getenv("INPUT_TARGET_DIRECTORIES")
        or os.getenv("TARGET_DIRECTORIES")
        or os.getenv("INPUT_TARGET_DIR")
        or os.getenv("TARGET_DIRECTORY")
        or "."
    )
    target_dirs = parse_target_directories(raw_target_dirs)

    fail_on_severity = (
        os.getenv("INPUT_FAIL_ON_SEVERITY") or os.getenv("FAIL_ON_SEVERITY") or "HIGH"
    )
    custom_prompt_path = os.getenv("INPUT_PROMPT_PATH") or os.getenv("PROMPT_PATH")
    finding_levels_raw = os.getenv("INPUT_FINDING_LEVELS") or os.getenv("FINDING_LEVELS")
    aws_types_mapping_raw = os.getenv("INPUT_AWS_TYPES_MAPPING") or os.getenv("AWS_TYPES_MAPPING")
    sarif_rules_raw = os.getenv("INPUT_SARIF_RULES") or os.getenv("SARIF_RULES")
    config_file = os.getenv("INPUT_CONFIG_FILE") or os.getenv("CONFIG_FILE")

    show_attribution_str = (
        os.getenv("INPUT_SHOW_ATTRIBUTION") or os.getenv("SHOW_ATTRIBUTION") or "true"
    )
    show_attribution = show_attribution_str.strip().lower() not in ("false", "0", "no")

    sarif_file = os.getenv("INPUT_SARIF_FILE") or os.getenv("SARIF_FILE")
    aws_findings_file = os.getenv("INPUT_AWS_FINDINGS_FILE") or os.getenv("AWS_FINDINGS_FILE")
    export_formats_raw = os.getenv("INPUT_EXPORT_FORMATS") or os.getenv("EXPORT_FORMATS")
    export_output_dir = (
        os.getenv("INPUT_EXPORT_OUTPUT_DIR") or os.getenv("EXPORT_OUTPUT_DIR") or "."
    )

    github_token = (
        os.getenv("INPUT_GITHUB_TOKEN") or os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN") or ""
    )
    create_issues_str = os.getenv("INPUT_CREATE_ISSUES") or os.getenv("CREATE_ISSUES") or "false"
    create_issues = create_issues_str.strip().lower() in ("true", "1", "yes")
    issue_labels_raw = (
        os.getenv("INPUT_ISSUE_LABELS") or os.getenv("ISSUE_LABELS") or "security, automated-audit"
    )
    issue_min_severity = (
        os.getenv("INPUT_ISSUE_MIN_SEVERITY") or os.getenv("ISSUE_MIN_SEVERITY") or "HIGH"
    )

    if not api_key:
        print("::error::Missing required API key. Please provide 'api-key' input or set API_KEY.")
        sys.exit(1)

    # Load resolved audit configuration (merging defaults with config file and input overrides)
    config = load_audit_config(
        config_file=config_file,
        prompt_path=custom_prompt_path,
        finding_levels=finding_levels_raw,
        aws_types_mapping=aws_types_mapping_raw,
        sarif_rules=sarif_rules_raw,
    )

    print(
        f"::notice::Auditing targets: {', '.join(target_dirs)} using model '{model}' at '{endpoint}'..."
    )

    # Initialize OpenAI-compatible client and system prompt
    client = OpenAI(base_url=endpoint, api_key=api_key)
    system_prompt = load_prompt(
        prompt_type="system",
        custom_prompt_path=config.prompt_path,
    )

    # Root summary across all directories
    summary = AuditSummary()

    # Discover and group all items across provided paths
    # Deeply traverses each provided path and groups by specific skill/prompt directory
    for target_path in target_dirs:
        print(f"\n🔍 Deep scanning: '{target_path}'...")
        discovered_items = scan_skills(target_path)

        dir_groups: OrderedDict[str, list[DiscoveredSkill]] = OrderedDict()
        if not discovered_items:
            dir_groups[target_path] = []
        else:
            for item in discovered_items:
                dir_groups.setdefault(item.directory_path, []).append(item)

        # Audit each discovered directory group
        for dir_path, items in dir_groups.items():
            dir_report = DirectoryAuditReport(
                directory=dir_path,
                scanned_count=len(items),
            )

            if not items:
                print(f"::notice::No skills or prompt files discovered in '{dir_path}'.")
                summary.directories.append(dir_report)
                continue

            print(f"\n📂 Auditing directory: '{dir_path}' ({len(items)} item(s))...")

            for item in items:
                print(f"  → Auditing '{item.name}' ({item.main_file})...")
                report = audit_skill(
                    skill=item,
                    client=client,
                    model=model,
                    system_prompt_override=system_prompt,
                )
                dir_report.reports.append(report)
                dir_report.risk_score = max(dir_report.risk_score, report.risk_score)

                if report.status == "PASS":
                    dir_report.passed_count += 1
                elif report.status == "WARN":
                    dir_report.warned_count += 1
                elif report.status == "FAIL":
                    dir_report.failed_count += 1

                dir_report.total_vulnerabilities += len(report.vulnerabilities)

            # Determine directory status
            if dir_report.failed_count > 0:
                dir_report.status = "FAIL"
            elif dir_report.warned_count > 0:
                dir_report.status = "WARN"
            else:
                dir_report.status = "PASS"

            # Print per-directory report
            print_directory_summary(dir_report)

            # Aggregate into global summary
            summary.directories.append(dir_report)
            summary.reports.extend(dir_report.reports)
            summary.scanned_skills_count += dir_report.scanned_count
            summary.passed_skills_count += dir_report.passed_count
            summary.warned_skills_count += dir_report.warned_count
            summary.failed_skills_count += dir_report.failed_count
            summary.total_vulnerabilities += dir_report.total_vulnerabilities

    # Compute overall run verdict
    if summary.failed_skills_count > 0:
        summary.status = "FAIL"
    elif summary.warned_skills_count > 0:
        summary.status = "WARN"
    else:
        summary.status = "PASS"

    # Print overall summary of the whole run
    print_overall_summary(summary)

    # Emit GitHub Actions outputs
    emit_github_annotations(summary.reports, annotation_levels=config.annotation_levels)
    write_step_summary(summary, show_attribution=show_attribution)

    # Export findings to external schemas if configured
    if sarif_file:
        out_sarif = export_findings(
            summary,
            "sarif",
            sarif_file,
            rules=config.sarif_rules,
            severity_map=config.sarif_levels,
        )
        print(f"::notice::Exported SARIF findings to '{out_sarif}'.")

    if aws_findings_file:
        out_aws = export_findings(
            summary,
            "aws",
            aws_findings_file,
            types_mapping=config.aws_types_mapping,
            severity_mapping=config.aws_severity_levels,
        )
        print(f"::notice::Exported AWS ASFF findings to '{out_aws}'.")

    if export_formats_raw:
        requested_formats = [f.strip().lower() for f in export_formats_raw.split(",") if f.strip()]
        for fmt in requested_formats:
            ext = "sarif" if fmt == "sarif" else "json"
            out_path = Path(export_output_dir) / f"skills-security-{fmt}.{ext}"
            if fmt == "sarif":
                export_findings(
                    summary,
                    fmt,
                    out_path,
                    rules=config.sarif_rules,
                    severity_map=config.sarif_levels,
                )
            elif fmt == "aws":
                export_findings(
                    summary,
                    fmt,
                    out_path,
                    types_mapping=config.aws_types_mapping,
                    severity_mapping=config.aws_severity_levels,
                )
            else:
                export_findings(summary, fmt, out_path)
            print(f"::notice::Exported {fmt.upper()} findings to '{out_path}'.")

    # Create GitHub Security Issues if enabled
    if create_issues:
        if not github_token:
            print(
                "::warning::'create-issues' is enabled but no 'github-token' was provided; skipping issue creation."
            )
        else:
            labels = [lbl.strip() for lbl in issue_labels_raw.split(",") if lbl.strip()]
            create_github_security_issues(
                summary=summary,
                token=github_token,
                labels=labels,
                min_severity=issue_min_severity,
            )

    # Determine CI exit code based on severity threshold
    if should_fail_build(summary.reports, fail_on_severity, severity_order=config.severity_order):
        print(
            f"::error::Audit failed: Vulnerabilities detected meeting or exceeding '{fail_on_severity}' threshold."
        )
        sys.exit(1)

    print("::notice::All skill security checks completed successfully.")
    sys.exit(0)


if __name__ == "__main__":
    main()
