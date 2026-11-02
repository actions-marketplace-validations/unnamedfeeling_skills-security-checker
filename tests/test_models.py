import pytest
from pydantic import ValidationError

from src.models import AuditSummary, SkillAuditReport, Vulnerability


def test_vulnerability_model_valid():
    vuln = Vulnerability(
        id="SEC-001",
        title="Command injection detected",
        severity="HIGH",
        category="command_injection",
        file_path="skills/cleaner/SKILL.md",
        line_number=12,
        snippet="rm -rf /",
        description="Destructive deletion of root directory",
        recommendation="Remove destructive command",
    )
    assert vuln.id == "SEC-001"
    assert vuln.severity == "HIGH"
    assert vuln.line_number == 12


def test_vulnerability_invalid_severity():
    with pytest.raises(ValidationError):
        Vulnerability(
            id="SEC-001",
            title="Bad severity",
            severity="SUPER_CRITICAL",  # type: ignore
            category="command_injection",
            file_path="file.md",
            snippet="snippet",
            description="desc",
            recommendation="fix",
        )


def test_skill_audit_report():
    report = SkillAuditReport(
        skill_name="test-skill",
        skill_path="/tmp/skill",
        status="PASS",
        risk_score=5,
        summary="Safe skill",
        vulnerabilities=[],
    )
    assert report.status == "PASS"
    assert report.risk_score == 5
    assert len(report.vulnerabilities) == 0


def test_audit_summary():
    summary = AuditSummary(
        scanned_skills_count=1,
        passed_skills_count=1,
        total_vulnerabilities=0,
    )
    assert summary.scanned_skills_count == 1
    assert summary.failed_skills_count == 0
