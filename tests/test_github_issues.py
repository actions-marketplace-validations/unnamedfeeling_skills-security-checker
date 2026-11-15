import urllib.error
from unittest.mock import MagicMock, patch

from src.github_issues import (
    create_github_security_issues,
    format_issue_body,
    get_existing_security_issue_markers,
)
from src.models import (
    AuditSummary,
    DirectoryAuditReport,
    SkillAuditReport,
    Vulnerability,
)


def create_sample_summary() -> AuditSummary:
    vuln_high = Vulnerability(
        id="SEC-001",
        title="Prompt override",
        severity="HIGH",
        category="prompt_injection",
        file_path="skills/malicious/SKILL.md",
        line_number=10,
        snippet="Ignore previous instructions",
        description="Jailbreak detected",
        recommendation="Remove override comment",
    )
    vuln_low = Vulnerability(
        id="SEC-002",
        title="Minor configuration note",
        severity="LOW",
        category="insecure_file_access",
        file_path="skills/safe/SKILL.md",
        line_number=2,
        snippet="tmp/",
        description="Temporary file path used",
        recommendation="Ensure tmp files are cleared",
    )

    rep1 = SkillAuditReport(
        skill_name="malicious-skill",
        skill_path="skills/malicious",
        status="FAIL",
        risk_score=85,
        summary="Contains prompt injection",
        vulnerabilities=[vuln_high],
    )
    rep2 = SkillAuditReport(
        skill_name="safe-skill",
        skill_path="skills/safe",
        status="WARN",
        risk_score=20,
        summary="Minor note",
        vulnerabilities=[vuln_low],
    )

    dir_report = DirectoryAuditReport(
        directory="skills",
        scanned_count=2,
        failed_count=1,
        reports=[rep1, rep2],
    )

    return AuditSummary(
        directories=[dir_report],
        reports=[rep1, rep2],
        scanned_skills_count=2,
        failed_skills_count=1,
        total_vulnerabilities=2,
    )


def test_format_issue_body():
    summary = create_sample_summary()
    rep = summary.reports[0]
    vuln = rep.vulnerabilities[0]

    body = format_issue_body(vuln, rep)
    assert "## 🔴 Security Vulnerability Detected in `malicious-skill`" in body
    assert "| **Skill Name** | `malicious-skill` |" in body
    assert "| **File Path** | `skills/malicious/SKILL.md` (Line 10) |" in body
    assert "Ignore previous instructions" in body
    assert "Remove override comment" in body
    assert "<!-- skills-security-checker:id=malicious-skill:SEC-001 -->" in body


@patch("src.github_issues._make_github_request")
def test_get_existing_security_issue_markers(mock_req):
    mock_req.return_value = [
        {
            "number": 1,
            "title": "Old Issue",
            "body": "Some body\n<!-- skills-security-checker:id=my-skill:SEC-001 -->\nfooter",
        },
        {
            "number": 2,
            "title": "Unrelated Issue",
            "body": "Normal issue without marker",
        },
    ]

    markers = get_existing_security_issue_markers(repo="owner/repo", token="ghp_test")
    assert "my-skill:SEC-001" in markers
    assert len(markers) == 1


@patch("src.github_issues._make_github_request")
def test_get_existing_security_issue_markers_error(mock_req):
    mock_req.side_effect = urllib.error.HTTPError(
        url="https://api.github.com",
        code=403,
        msg="Forbidden",
        hdrs=MagicMock(),
        fp=None,
    )
    markers = get_existing_security_issue_markers(repo="owner/repo", token="ghp_test")
    assert markers == set()


@patch("src.github_issues._make_github_request")
def test_create_github_security_issues_success(mock_req):
    summary = create_sample_summary()

    # First call: GET existing issues returns empty list
    # Second call: POST creates issue
    mock_req.side_effect = [
        [],  # GET existing issues
        {"number": 42, "html_url": "https://github.com/owner/repo/issues/42"},  # POST
    ]

    created = create_github_security_issues(
        summary=summary,
        token="ghp_test",
        repository="owner/repo",
        min_severity="HIGH",
    )

    assert len(created) == 1
    assert created[0]["number"] == 42

    # Check POST payload
    assert mock_req.call_count == 2
    post_args = mock_req.call_args_list[1]
    assert post_args[0][0] == "https://api.github.com/repos/owner/repo/issues"
    assert post_args[1]["method"] == "POST"
    payload = post_args[1]["data"]
    assert "🔴 [HIGH] Prompt override in `malicious-skill`" in payload["title"]
    assert "security" in payload["labels"]
    assert "severity:high" in payload["labels"]


@patch("src.github_issues._make_github_request")
def test_create_github_security_issues_deduplication(mock_req):
    summary = create_sample_summary()

    # GET existing issues returns an issue already containing the marker
    mock_req.return_value = [
        {
            "number": 10,
            "title": "Existing",
            "body": "<!-- skills-security-checker:id=malicious-skill:SEC-001 -->",
        }
    ]

    created = create_github_security_issues(
        summary=summary,
        token="ghp_test",
        repository="owner/repo",
        min_severity="HIGH",
    )

    # Should skip creating duplicate issue
    assert len(created) == 0
    assert mock_req.call_count == 1  # Only the GET call was made


def test_create_github_security_issues_no_repo(monkeypatch):
    monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
    summary = create_sample_summary()
    created = create_github_security_issues(summary=summary, token="ghp_test", repository=None)
    assert created == []
