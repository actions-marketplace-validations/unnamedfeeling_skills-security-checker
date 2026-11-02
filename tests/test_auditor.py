from unittest.mock import MagicMock

from src.auditor import audit_skill
from src.models import DiscoveredSkill, SkillAuditReport


def test_audit_skill_success():
    skill = DiscoveredSkill(
        name="test-skill",
        directory_path="skills/test",
        main_file="skills/test/SKILL.md",
        content="Safe instructions",
    )

    mock_client = MagicMock()
    mock_choice = MagicMock()
    mock_choice.message.parsed = SkillAuditReport(
        skill_name="test-skill",
        skill_path="skills/test",
        status="PASS",
        risk_score=0,
        summary="No security issues found.",
        vulnerabilities=[],
    )
    mock_client.beta.chat.completions.parse.return_value.choices = [mock_choice]

    report = audit_skill(skill, mock_client, model="gpt-4o")
    assert report.status == "PASS"
    assert report.risk_score == 0
    assert report.skill_name == "test-skill"
    assert report.skill_path == "skills/test"


def test_audit_skill_handles_exception():
    skill = DiscoveredSkill(
        name="failing-skill",
        directory_path="skills/fail",
        main_file="skills/fail/SKILL.md",
        content="Some content",
    )

    mock_client = MagicMock()
    mock_client.beta.chat.completions.parse.side_effect = Exception("API rate limited")
    mock_client.chat.completions.create.side_effect = Exception("API connection error")

    report = audit_skill(skill, mock_client, model="gpt-4o")
    assert report.status == "WARN"
    assert "API connection error" in report.summary
