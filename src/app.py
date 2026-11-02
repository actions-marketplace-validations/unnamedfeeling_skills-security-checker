from __future__ import annotations

import os
import sys

from dotenv import load_dotenv
from openai import OpenAI

from src.auditor import audit_skill
from src.models import AuditSummary
from src.reporter import emit_github_annotations, should_fail_build, write_step_summary
from src.scanner import scan_skills


def main() -> None:
    load_dotenv()

    # Read configuration (supporting GitHub Actions inputs and local env variables)
    api_key = os.getenv("INPUT_API_KEY") or os.getenv("API_KEY") or ""
    endpoint = os.getenv("INPUT_ENDPOINT") or os.getenv("ENDPOINT") or "https://api.openai.com/v1"
    model = os.getenv("INPUT_MODEL") or os.getenv("MODEL") or "gpt-4o"
    target_dir = os.getenv("INPUT_TARGET_DIR") or os.getenv("TARGET_DIRECTORY") or "."
    fail_on_severity = (
        os.getenv("INPUT_FAIL_ON_SEVERITY") or os.getenv("FAIL_ON_SEVERITY") or "HIGH"
    )
    show_attribution_str = (
        os.getenv("INPUT_SHOW_ATTRIBUTION") or os.getenv("SHOW_ATTRIBUTION") or "true"
    )
    show_attribution = show_attribution_str.strip().lower() not in ("false", "0", "no")

    if not api_key:
        print("::error::Missing required API key. Please provide 'api-key' input or set API_KEY.")
        sys.exit(1)

    print(f"::notice::Auditing skills in '{target_dir}' using model '{model}' at '{endpoint}'...")

    # 1. Discover skills
    discovered_skills = scan_skills(target_dir)
    if not discovered_skills:
        print(f"::notice::No skills found in '{target_dir}'.")
        sys.exit(0)

    print(f"::notice::Discovered {len(discovered_skills)} skill(s) to assess.")

    # 2. Initialize OpenAI-compatible client
    client = OpenAI(base_url=endpoint, api_key=api_key)

    # 3. Audit each skill
    summary = AuditSummary(scanned_skills_count=len(discovered_skills))

    for skill in discovered_skills:
        print(f"Auditing '{skill.name}' at '{skill.directory_path}'...")
        report = audit_skill(skill=skill, client=client, model=model)
        summary.reports.append(report)

        if report.status == "PASS":
            summary.passed_skills_count += 1
        elif report.status == "WARN":
            summary.warned_skills_count += 1
        elif report.status == "FAIL":
            summary.failed_skills_count += 1

        summary.total_vulnerabilities += len(report.vulnerabilities)

    # 4. Emit GitHub Actions outputs
    emit_github_annotations(summary.reports)
    write_step_summary(summary, show_attribution=show_attribution)

    # 5. Determine CI exit code based on severity threshold
    if should_fail_build(summary.reports, fail_on_severity):
        print(
            f"::error::Audit failed: Vulnerabilities detected meeting or exceeding '{fail_on_severity}' threshold."
        )
        sys.exit(1)

    print("::notice::All skill security checks completed successfully.")
    sys.exit(0)


if __name__ == "__main__":
    main()
