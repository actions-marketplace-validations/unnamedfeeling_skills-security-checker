from src.models import (
    AuditSummary,
    DirectoryAuditReport,
    SkillAuditReport,
    Vulnerability,
)
from src.reporter import emit_github_annotations, generate_step_summary, should_fail_build


def create_sample_report(severity="HIGH", status="FAIL", risk_score=85):
    vuln = Vulnerability(
        id="SEC-001",
        title="Prompt override",
        severity=severity,
        category="prompt_injection",
        file_path="skills/malicious/SKILL.md",
        line_number=10,
        snippet="Ignore previous instructions",
        description="Jailbreak detected",
        recommendation="Remove override comment",
    )
    return SkillAuditReport(
        skill_name="malicious-skill",
        skill_path="skills/malicious",
        status=status,
        risk_score=risk_score,
        summary="Contains prompt injection",
        vulnerabilities=[vuln],
    )


def test_should_fail_build_thresholds():
    high_report = create_sample_report(severity="HIGH")
    medium_report = create_sample_report(severity="MEDIUM", status="WARN", risk_score=30)

    # Threshold HIGH: high triggers fail, medium does not
    assert should_fail_build([high_report], threshold_str="HIGH") is True
    assert should_fail_build([medium_report], threshold_str="HIGH") is False

    # Threshold MEDIUM: both trigger fail
    assert should_fail_build([high_report], threshold_str="MEDIUM") is True
    assert should_fail_build([medium_report], threshold_str="MEDIUM") is True

    # Threshold CRITICAL: high does not trigger fail
    assert should_fail_build([high_report], threshold_str="CRITICAL") is False

    # Threshold NONE: never fails
    assert should_fail_build([high_report], threshold_str="NONE") is False


def test_should_fail_build_custom_order():
    medium_report = create_sample_report(severity="MEDIUM")
    custom_order = {"CRITICAL": 5, "MEDIUM": 4, "HIGH": 3}
    # With custom order where MEDIUM (4) >= threshold (4), it triggers fail
    assert (
        should_fail_build([medium_report], threshold_str="MEDIUM", severity_order=custom_order)
        is True
    )


def test_emit_github_annotations_custom_levels(capsys):
    report = create_sample_report(severity="MEDIUM")
    # Default: MEDIUM emits ::warning
    emit_github_annotations([report])
    captured = capsys.readouterr()
    assert "::warning file=" in captured.out

    # Custom override: map MEDIUM to error
    emit_github_annotations([report], annotation_levels={"MEDIUM": "error"})
    captured_custom = capsys.readouterr()
    assert "::error file=" in captured_custom.out


def test_generate_step_summary():
    report = create_sample_report()
    summary = AuditSummary(
        scanned_skills_count=1,
        failed_skills_count=1,
        total_vulnerabilities=1,
        reports=[report],
    )
    # Default: show_attribution is True
    md_default = generate_step_summary(summary)
    assert "## 🛡️ Skill Security Audit Report" in md_default
    assert "`malicious-skill`" in md_default
    assert "Prompt override" in md_default
    assert "Ignore previous instructions" in md_default
    assert "Security audit powered by [Skills Security Checker]" in md_default

    # Explicit False: hides attribution
    md_hidden = generate_step_summary(summary, show_attribution=False)
    assert "Security audit powered by [Skills Security Checker]" not in md_hidden
    assert "## 🛡️ Skill Security Audit Report" in md_hidden


def test_generate_step_summary_multiple_directories():
    report1 = create_sample_report()
    dir1 = DirectoryAuditReport(
        directory="skills",
        scanned_count=1,
        failed_count=1,
        reports=[report1],
    )
    dir2 = DirectoryAuditReport(
        directory=".copilot",
        scanned_count=0,
        passed_count=0,
        reports=[],
    )
    summary = AuditSummary(
        directories=[dir1, dir2],
        scanned_skills_count=1,
        failed_skills_count=1,
        total_vulnerabilities=1,
        reports=[report1],
    )
    md = generate_step_summary(summary)
    assert "### 📁 Directories Overview" in md
    assert "`skills`" in md
    assert "`.copilot`" in md
    assert "### Directory: `skills`" in md
    assert "### Directory: `.copilot`" in md


def test_emit_github_annotations(capsys):
    report = create_sample_report()
    emit_github_annotations([report])
    captured = capsys.readouterr().out
    assert "::error file=skills/malicious/SKILL.md,line=10::" in captured
    assert "[PROMPT_INJECTION] Prompt override: Jailbreak detected" in captured
