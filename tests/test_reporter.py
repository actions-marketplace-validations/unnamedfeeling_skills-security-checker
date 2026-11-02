from src.models import AuditSummary, SkillAuditReport, Vulnerability
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


def test_generate_step_summary():
    report = create_sample_report()
    summary = AuditSummary(
        scanned_skills_count=1,
        failed_skills_count=1,
        total_vulnerabilities=1,
        reports=[report],
    )
    md = generate_step_summary(summary)
    assert "## 🛡️ Skill Security Audit Report" in md
    assert "`malicious-skill`" in md
    assert "Prompt override" in md
    assert "Ignore previous instructions" in md


def test_emit_github_annotations(capsys):
    report = create_sample_report()
    emit_github_annotations([report])
    captured = capsys.readouterr().out
    assert "::error file=skills/malicious/SKILL.md,line=10::" in captured
    assert "[PROMPT_INJECTION] Prompt override: Jailbreak detected" in captured
