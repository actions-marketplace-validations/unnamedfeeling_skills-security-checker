from __future__ import annotations

import os
from typing import List

from src.models import AuditSummary, SeverityLevel, SkillAuditReport

SEVERITY_ORDER: dict[str, int] = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
}

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


def emit_github_annotations(reports: List[SkillAuditReport]) -> None:
    """Emits GitHub Actions annotations to surface inline warnings and errors in PR diffs."""
    is_github_actions = "GITHUB_ACTIONS" in os.environ

    for report in reports:
        for vuln in report.vulnerabilities:
            msg = f"[{vuln.category.upper()}] {vuln.title}: {vuln.description}"
            loc_parts = []
            if vuln.file_path:
                loc_parts.append(f"file={vuln.file_path}")
            if vuln.line_number:
                loc_parts.append(f"line={vuln.line_number}")
            loc_str = f" {','.join(loc_parts)}" if loc_parts else ""

            if vuln.severity in ("CRITICAL", "HIGH"):
                cmd = f"::error{loc_str}::{msg}"
            elif vuln.severity in ("MEDIUM", "LOW"):
                cmd = f"::warning{loc_str}::{msg}"
            else:
                cmd = f"::notice{loc_str}::{msg}"

            print(cmd)

    if not is_github_actions:
        # Also print a human-friendly console output when running locally
        print_console_summary(reports)


def print_console_summary(reports: List[SkillAuditReport]) -> None:
    """Prints a clean human-readable summary to standard out."""
    print("\n" + "=" * 60)
    print("SKILL SECURITY AUDIT SUMMARY")
    print("=" * 60)
    for report in reports:
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
                print(f"    Category: {v.category}")
                print(f"    Advice:   {v.recommendation}")
    print("\n" + "=" * 60)


def generate_step_summary(summary: AuditSummary, show_attribution: bool = True) -> str:
    """Generates Markdown for $GITHUB_STEP_SUMMARY."""
    lines: List[str] = [
        "## 🛡️ Skill Security Audit Report\n",
        f"**Audited Skills:** {summary.scanned_skills_count} | "
        f"**Passed:** {summary.passed_skills_count} | "
        f"**Warned:** {summary.warned_skills_count} | "
        f"**Failed:** {summary.failed_skills_count}\n",
        "| Skill Name | Status | Risk Score | Findings | Summary |",
        "| :--- | :---: | :---: | :---: | :--- |",
    ]

    for report in summary.reports:
        status_badge = STATUS_ICONS.get(report.status, report.status)
        vuln_count = len(report.vulnerabilities)
        lines.append(
            f"| `{report.skill_name}` | {status_badge} | **{report.risk_score}/100** | {vuln_count} | {report.summary} |"
        )

    # Detailed findings section
    has_any_findings = any(r.vulnerabilities for r in summary.reports)
    if has_any_findings:
        lines.append("\n### 🔍 Detailed Vulnerability Findings\n")
        for report in summary.reports:
            if not report.vulnerabilities:
                continue

            lines.append(f"#### Skill: `{report.skill_name}`\n")
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
        lines.append("\n> [!NOTE]\n> All assessed skills passed security checks without findings.")

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


def should_fail_build(reports: List[SkillAuditReport], threshold_str: str) -> bool:
    """Evaluates whether any finding meets or exceeds the configured failure threshold."""
    norm_threshold = threshold_str.strip().upper()
    if norm_threshold == "NONE":
        return False

    threshold_level = SEVERITY_ORDER.get(norm_threshold, 4)  # default HIGH (4)

    for report in reports:
        for vuln in report.vulnerabilities:
            vuln_level = SEVERITY_ORDER.get(vuln.severity, 1)
            if vuln_level >= threshold_level:
                return True
    return False
