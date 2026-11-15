from __future__ import annotations

import os
from typing import List, Union

from src.config import (
    DEFAULT_ANNOTATION_LEVELS,
    DEFAULT_SEVERITY_ORDER,
)
from src.models import AuditSummary, DirectoryAuditReport, SeverityLevel, SkillAuditReport

SEVERITY_ORDER: dict[str, int] = dict(DEFAULT_SEVERITY_ORDER)

SEVERITY_ICONS: dict[SeverityLevel, str] = {
    "CRITICAL": "🛑 CRITICAL",
    "HIGH": "🔴 HIGH",
    "MEDIUM": "⚠️ MEDIUM",
    "LOW": "ℹ️ LOW",
    "INFO": "📝 INFO",
}

STATUS_ICONS = {
    "PASS": "✅ PASS",
    "WARN": "⚠️ WARN",
    "FAIL": "❌ FAIL",
}


def emit_github_annotations(
    reports: List[SkillAuditReport],
    annotation_levels: dict[str, str] | None = None,
) -> None:
    """Emits GitHub Actions annotations to surface inline warnings and errors in PR diffs."""
    mapping = annotation_levels or DEFAULT_ANNOTATION_LEVELS
    for report in reports:
        for vuln in report.vulnerabilities:
            msg = f"[{vuln.category.upper()}] {vuln.title}: {vuln.description}"
            loc_parts = []
            if vuln.file_path:
                loc_parts.append(f"file={vuln.file_path}")
            if vuln.line_number:
                loc_parts.append(f"line={vuln.line_number}")
            loc_str = f" {','.join(loc_parts)}" if loc_parts else ""

            level = mapping.get(vuln.severity, "warning")
            if level == "error":
                cmd = f"::error{loc_str}::{msg}"
            elif level == "warning":
                cmd = f"::warning{loc_str}::{msg}"
            else:
                cmd = f"::notice{loc_str}::{msg}"

            print(cmd)


def print_directory_summary(dir_report: DirectoryAuditReport) -> None:
    """Prints a clear summary for a single directory's audit."""
    status_icon = STATUS_ICONS.get(dir_report.status, dir_report.status)
    print("\n" + "-" * 60)
    print(f"DIRECTORY REPORT: '{dir_report.directory}' [{status_icon}]")
    print(
        f"Items Scanned: {dir_report.scanned_count} | "
        f"Passed: {dir_report.passed_count} | "
        f"Warned: {dir_report.warned_count} | "
        f"Failed: {dir_report.failed_count} | "
        f"Max Risk Score: {dir_report.risk_score}/100"
    )
    print("-" * 60)
    for report in dir_report.reports:
        rep_icon = STATUS_ICONS.get(report.status, report.status)
        print(f"  • {report.skill_name} [{rep_icon}] (Risk: {report.risk_score}/100)")
        if report.vulnerabilities:
            for v in report.vulnerabilities:
                line_str = f":{v.line_number}" if v.line_number else ""
                print(f"      [{v.severity}] {v.title} ({v.file_path}{line_str})")


def print_overall_summary(summary: AuditSummary) -> None:
    """Prints a high-level summary of the entire scan across all directories."""
    status_icon = STATUS_ICONS.get(summary.status, summary.status)
    print("\n" + "=" * 60)
    print(f"OVERALL RUN SUMMARY [{status_icon}]")
    print("=" * 60)
    print(f"Directories Audited: {len(summary.directories)}")
    for d in summary.directories:
        d_icon = STATUS_ICONS.get(d.status, d.status)
        print(
            f"  - {d.directory:<25} [{d_icon}] Scanned: {d.scanned_count}, Failed: {d.failed_count}"
        )

    print("-" * 60)
    print(
        f"Total Items Scanned:  {summary.scanned_skills_count}\n"
        f"Total Passed:         {summary.passed_skills_count}\n"
        f"Total Warned:         {summary.warned_skills_count}\n"
        f"Total Failed:         {summary.failed_skills_count}\n"
        f"Total Findings:       {summary.total_vulnerabilities}"
    )
    print("=" * 60 + "\n")


def print_console_summary(summary_or_reports: Union[AuditSummary, List[SkillAuditReport]]) -> None:
    """Prints a clean human-readable summary to stdout for local executions."""
    if isinstance(summary_or_reports, AuditSummary):
        print_overall_summary(summary_or_reports)
    else:
        # Legacy list of reports fallback
        print("\n" + "=" * 60)
        print("SKILL SECURITY AUDIT SUMMARY")
        print("=" * 60)
        for report in summary_or_reports:
            print(
                f"\nSkill: {report.skill_name} [{report.status}] (Risk Score: {report.risk_score}/100)"
            )
            print(f"Path:  {report.skill_path}")
            print(f"Note:  {report.summary}")
            if not report.vulnerabilities:
                print("  No security vulnerabilities detected.")
            else:
                for v in report.vulnerabilities:
                    line_str = f":{v.line_number}" if v.line_number else ""
                    print(f"  - [{v.severity}] {v.title} ({v.file_path}{line_str})")
        print("\n" + "=" * 60)


def generate_step_summary(summary: AuditSummary, show_attribution: bool = True) -> str:
    """Generates Markdown for $GITHUB_STEP_SUMMARY with per-directory breakdowns and run summary."""
    status_badge = STATUS_ICONS.get(summary.status, summary.status)
    lines: List[str] = [
        f"## 🛡️ Skill Security Audit Report [{status_badge}]\n",
        f"**Directories Scanned:** {len(summary.directories)} | "
        f"**Total Items:** {summary.scanned_skills_count} | "
        f"**Passed:** {summary.passed_skills_count} | "
        f"**Warned:** {summary.warned_skills_count} | "
        f"**Failed:** {summary.failed_skills_count}\n",
    ]

    # Section 1: Directory Overview Table (if multiple directories or directory reports exist)
    if summary.directories:
        lines.append("### 📁 Directories Overview\n")
        lines.append("| Directory | Status | Scanned | Passed | Warned | Failed | Max Risk |")
        lines.append("| :--- | :---: | :---: | :---: | :---: | :---: | :---: |")
        for d in summary.directories:
            d_badge = STATUS_ICONS.get(d.status, d.status)
            lines.append(
                f"| `{d.directory}` | {d_badge} | {d.scanned_count} | {d.passed_count} | "
                f"{d.warned_count} | {d.failed_count} | **{d.risk_score}/100** |"
            )
        lines.append("")

    # Section 2: Per-Directory Details
    if summary.directories:
        for d in summary.directories:
            lines.append(f"### Directory: `{d.directory}`\n")
            if not d.reports:
                lines.append("> _No skills or prompt files discovered in this directory._\n")
                continue

            lines.append("| Item Name | Status | Risk Score | Findings | Summary |")
            lines.append("| :--- | :---: | :---: | :---: | :--- |")
            for report in d.reports:
                rep_badge = STATUS_ICONS.get(report.status, report.status)
                vuln_count = len(report.vulnerabilities)
                lines.append(
                    f"| `{report.skill_name}` | {rep_badge} | **{report.risk_score}/100** | {vuln_count} | {report.summary} |"
                )
            lines.append("")
    else:
        # Fallback if no directory grouping
        lines.append("| Skill Name | Status | Risk Score | Findings | Summary |")
        lines.append("| :--- | :---: | :---: | :---: | :--- |")
        for report in summary.reports:
            rep_badge = STATUS_ICONS.get(report.status, report.status)
            vuln_count = len(report.vulnerabilities)
            lines.append(
                f"| `{report.skill_name}` | {rep_badge} | **{report.risk_score}/100** | {vuln_count} | {report.summary} |"
            )
        lines.append("")

    # Section 3: Detailed Vulnerability Findings
    all_reports = (
        summary.reports if summary.reports else [r for d in summary.directories for r in d.reports]
    )
    has_any_findings = any(r.vulnerabilities for r in all_reports)
    if has_any_findings:
        lines.append("### 🔍 Detailed Vulnerability Findings\n")
        for report in all_reports:
            if not report.vulnerabilities:
                continue

            lines.append(f"#### `{report.skill_name}` (`{report.skill_path}`)\n")
            for v in report.vulnerabilities:
                sev_badge = SEVERITY_ICONS.get(v.severity, v.severity)
                loc = f"`{v.file_path}`" + (f" (Line {v.line_number})" if v.line_number else "")
                lines.append(f"<details><summary>{sev_badge} <b>{v.title}</b> in {loc}</summary>\n")
                lines.append(f"- **Category:** `{v.category}`")
                lines.append(f"- **Description:** {v.description}")
                if v.snippet:
                    lines.append(f"- **Snippet:**\n```\n{v.snippet}\n```")
                lines.append(f"- **Recommendation:** {v.recommendation}\n")
                lines.append("</details>\n")
    else:
        lines.append(
            "> [!NOTE]\n> All assessed skills and prompts passed security checks without findings."
        )

    if show_attribution:
        lines.append(
            "\n---\n*Security audit powered by [Skills Security Checker](https://github.com/unnamedfeeling/skills-security-checker) • Licensed under Apache-2.0 (Provided AS-IS without warranty).*"
        )

    return "\n".join(lines)


def write_step_summary(summary: AuditSummary, show_attribution: bool = True) -> None:
    """Writes the markdown summary to GITHUB_STEP_SUMMARY if the environment variable is set."""
    summary_path = os.getenv("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return

    markdown = generate_step_summary(summary, show_attribution=show_attribution)
    try:
        with open(summary_path, "a", encoding="utf-8") as f:
            f.write(markdown + "\n")
    except Exception as e:
        print(f"::warning::Failed to write step summary to {summary_path}: {e}")


def should_fail_build(
    reports: List[SkillAuditReport],
    threshold_str: str,
    severity_order: dict[str, int] | None = None,
) -> bool:
    """Evaluates whether any finding meets or exceeds the configured failure threshold."""
    order = severity_order or SEVERITY_ORDER
    norm_threshold = threshold_str.strip().upper()
    if norm_threshold == "NONE":
        return False

    threshold_level = order.get(norm_threshold, 4)  # default HIGH (4)

    for report in reports:
        for vuln in report.vulnerabilities:
            vuln_level = order.get(vuln.severity, 1)
            if vuln_level >= threshold_level:
                return True
    return False
