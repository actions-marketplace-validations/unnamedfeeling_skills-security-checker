from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Set

from src.models import AuditSummary, SkillAuditReport, Vulnerability

SEVERITY_EMOJIS = {
    "CRITICAL": "🛑",
    "HIGH": "🔴",
    "MEDIUM": "⚠️",
    "LOW": "ℹ️",
    "INFO": "📝",
}


def _make_github_request(
    url: str,
    token: str,
    method: str = "GET",
    data: Optional[Dict[str, Any]] = None,
) -> Any:
    """Executes a request against the GitHub REST API using urllib."""
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "User-Agent": "skills-security-checker",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    payload = json.dumps(data).encode("utf-8") if data is not None else None
    if payload:
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=payload, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=15) as resp:
        res_body = resp.read().decode("utf-8")
        return json.loads(res_body) if res_body else {}


def get_existing_security_issue_markers(
    repo: str,
    token: str,
    api_url: str = "https://api.github.com",
) -> Set[str]:
    """Retrieves open issue markers to prevent duplicate issue creation."""
    url = f"{api_url}/repos/{repo}/issues?state=open&per_page=100"
    try:
        issues = _make_github_request(url, token)
        markers: Set[str] = set()
        if isinstance(issues, list):
            for issue in issues:
                body = issue.get("body", "") or ""
                # Look for our tracking comment marker in issue bodies
                for line in body.splitlines():
                    if "<!-- skills-security-checker:id=" in line and "-->" in line:
                        marker = (
                            line.split("<!-- skills-security-checker:id=")[1]
                            .split("-->")[0]
                            .strip()
                        )
                        markers.add(marker)
        return markers
    except urllib.error.HTTPError as e:
        print(f"::warning::Unable to fetch existing GitHub issues ({e.code}): {e.reason}")
        return set()
    except Exception as e:
        print(f"::warning::Failed to query existing GitHub issues: {e}")
        return set()


def format_issue_body(vuln: Vulnerability, report: SkillAuditReport) -> str:
    """Formats markdown body for a GitHub security issue."""
    sev_emoji = SEVERITY_EMOJIS.get(vuln.severity, "🛡️")
    line_info = f" (Line {vuln.line_number})" if vuln.line_number else ""

    lines = [
        f"## {sev_emoji} Security Vulnerability Detected in `{report.skill_name}`\n",
        "An automated security audit by **Skills Security Checker** identified a security vulnerability in this skill definition.\n",
        "### Finding Overview\n",
        "| Attribute | Value |",
        "| :--- | :--- |",
        f"| **Skill Name** | `{report.skill_name}` |",
        f"| **File Path** | `{vuln.file_path}`{line_info} |",
        f"| **Severity** | **`{vuln.severity}`** |",
        f"| **Category** | `{vuln.category}` |",
        f"| **Skill Risk Score** | `{report.risk_score}/100` |",
        f"| **Finding ID** | `{vuln.id}` |\n",
        "### Description",
        f"{vuln.description}\n",
    ]

    if vuln.snippet:
        lines.extend(
            [
                "### Evidence Snippet",
                "```",
                vuln.snippet,
                "```\n",
            ]
        )

    lines.extend(
        [
            "### Remediation Guidance",
            f"{vuln.recommendation}\n",
            "---",
            "*Automated security issue opened by [Skills Security Checker](https://github.com/skills-security-checker/skills-security-checker)*",
            f"<!-- skills-security-checker:id={report.skill_name}:{vuln.id} -->",
        ]
    )

    return "\n".join(lines)


def create_github_security_issues(
    summary: AuditSummary,
    token: str,
    repository: Optional[str] = None,
    api_url: Optional[str] = None,
    labels: Optional[List[str]] = None,
    min_severity: str = "HIGH",
) -> List[Dict[str, Any]]:
    """
    Creates GitHub Issues for security findings with deduplication and configurable labels.
    Returns list of created issue response objects.
    """
    repo = repository or os.getenv("GITHUB_REPOSITORY")
    if not repo:
        print("::warning::No GITHUB_REPOSITORY found; skipping GitHub Security Issues creation.")
        return []

    base_api = (api_url or os.getenv("GITHUB_API_URL") or "https://api.github.com").rstrip("/")
    issue_labels = labels or ["security", "automated-audit"]

    # Severity ordering for filtering
    severity_order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
    min_level = severity_order.get(min_severity.upper(), 4)

    # 1. Fetch existing open issue markers to avoid duplicates
    existing_markers = get_existing_security_issue_markers(repo=repo, token=token, api_url=base_api)

    created_issues: List[Dict[str, Any]] = []
    all_reports = (
        summary.reports if summary.reports else [r for d in summary.directories for r in d.reports]
    )

    for report in all_reports:
        for vuln in report.vulnerabilities:
            vuln_level = severity_order.get(vuln.severity, 1)
            if vuln_level < min_level:
                continue

            marker = f"{report.skill_name}:{vuln.id}"
            if marker in existing_markers:
                print(
                    f"::notice::Skipping duplicate issue for '{marker}'; open issue already exists."
                )
                continue

            sev_emoji = SEVERITY_EMOJIS.get(vuln.severity, "🛡️")
            title = f"{sev_emoji} [{vuln.severity}] {vuln.title} in `{report.skill_name}`"
            body = format_issue_body(vuln, report)
            specific_labels = list(set(issue_labels + [f"severity:{vuln.severity.lower()}"]))

            payload = {
                "title": title,
                "body": body,
                "labels": specific_labels,
            }

            post_url = f"{base_api}/repos/{repo}/issues"
            try:
                res = _make_github_request(post_url, token, method="POST", data=payload)
                issue_number = res.get("number")
                issue_url = res.get("html_url")
                print(
                    f"::notice::Created GitHub Security Issue #{issue_number}: {title} ({issue_url})"
                )
                existing_markers.add(marker)
                created_issues.append(res)
            except urllib.error.HTTPError as e:
                print(
                    f"::warning::Failed to create GitHub issue for '{title}' (HTTP {e.code}): {e.reason}"
                )
            except Exception as e:
                print(f"::warning::Unexpected error creating GitHub issue: {e}")

    return created_issues
