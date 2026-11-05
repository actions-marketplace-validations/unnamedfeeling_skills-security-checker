from __future__ import annotations

import os
import sys
from collections import OrderedDict
from collections import OrderedDict
from dotenv import load_dotenv
from openai import OpenAI

from src.auditor import audit_skill, load_prompt
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
    show_attribution_str = (
        os.getenv("INPUT_SHOW_ATTRIBUTION") or os.getenv("SHOW_ATTRIBUTION") or "true"
    )
    show_attribution = show_attribution_str.strip().lower() not in ("false", "0", "no")

    if not api_key:
        print("::error::Missing required API key. Please provide 'api-key' input or set API_KEY.")
        sys.exit(1)

    print(
        f"::notice::Auditing targets: {', '.join(target_dirs)} using model '{model}' at '{endpoint}'..."
    )

    # Initialize OpenAI-compatible client and system prompt
    client = OpenAI(base_url=endpoint, api_key=api_key)
    system_prompt = load_prompt(prompt_type="system", custom_prompt_path=custom_prompt_path)

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
    emit_github_annotations(summary.reports)
    write_step_summary(summary, show_attribution=show_attribution)

    # Determine CI exit code based on severity threshold
    if should_fail_build(summary.reports, fail_on_severity):
        print(
            f"::error::Audit failed: Vulnerabilities detected meeting or exceeding '{fail_on_severity}' threshold."
        )
        sys.exit(1)

    print("::notice::All skill security checks completed successfully.")
    sys.exit(0)


if __name__ == "__main__":
    main()
