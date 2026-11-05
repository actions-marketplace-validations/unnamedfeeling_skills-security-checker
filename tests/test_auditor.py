from unittest.mock import MagicMock

from src.auditor import audit_skill, load_prompt, load_system_prompt
from src.models import DiscoveredSkill, SkillAuditReport


def test_load_prompt_default():
    prompt = load_prompt(prompt_type="system")
    assert "# AI Agent Skill Security Auditor" in prompt
    assert "prompt_injection" in prompt
    assert "command_injection" in prompt


def test_load_prompt_custom(tmp_path):
    custom_file = tmp_path / "custom_prompt.md"
    custom_file.write_text("Custom security instructions for organization")

    loaded = load_prompt(prompt_type="system", custom_prompt_path=custom_file)
    assert loaded == "Custom security instructions for organization"


def test_load_prompt_fallback():
    prompt = load_prompt(prompt_type="system", custom_prompt_path="/path/that/does/not/exist.md")
    assert "# AI Agent Skill Security Auditor" in prompt


def test_load_prompt_user_fallback():
    # If user prompt file doesn't exist, returns fallback (empty string or fallback dict)
    prompt = load_prompt(prompt_type="unknown_type")
    assert prompt == ""


def test_load_system_prompt_alias():
    prompt = load_system_prompt()
    assert "# AI Agent Skill Security Auditor" in prompt


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
