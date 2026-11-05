from pathlib import Path

import pytest

from src.scanner import _extract_name_from_frontmatter, parse_target_directories, scan_skills


def test_parse_target_directories():
    # Comma-separated
    assert parse_target_directories("skills, prompts, .copilot") == [
        "skills",
        "prompts",
        ".copilot",
    ]

    # Multiline
    multiline = """
    skills
    prompts
    .copilot
    """
    assert parse_target_directories(multiline) == ["skills", "prompts", ".copilot"]

    # Empty or None raises SystemExit
    with pytest.raises(SystemExit):
        parse_target_directories("")
    with pytest.raises(SystemExit):
        parse_target_directories(None)


def test_scan_skills_discovers_standalone_prompts(tmp_path):
    copilot_dir = tmp_path / ".copilot"
    copilot_dir.mkdir()
    instruction_file = copilot_dir / "instructions.md"
    instruction_file.write_text("# Copilot Instructions\nBe helpful and concise.")

    items = scan_skills(copilot_dir)
    assert len(items) == 1
    assert items[0].name == "instructions"
    assert "Copilot Instructions" in items[0].content


def test_extract_name_from_frontmatter():
    content = """---
name: my-sample-skill
description: A sample skill
---
# Instructions
"""
    assert _extract_name_from_frontmatter(content) == "my-sample-skill"

    # With quotes
    content_quoted = """---
name: "quoted-skill"
---
"""
    assert _extract_name_from_frontmatter(content_quoted) == "quoted-skill"

    # Missing frontmatter
    assert _extract_name_from_frontmatter("# No frontmatter") is None


def test_scan_skills_discovers_fixtures():
    fixtures_dir = Path(__file__).parent / "fixtures" / "skills"
    skills = scan_skills(fixtures_dir)

    assert len(skills) == 4
    skill_names = {s.name for s in skills}
    assert "safe-translator" in skill_names
    assert "text-summarizer" in skill_names
    assert "environment-cleaner" in skill_names
    assert "analytics-reporter" in skill_names


def test_scan_skills_deep_nested(tmp_path):
    deep_skill_dir = tmp_path / "hub" / "category" / "subcat" / "my-skill"
    deep_skill_dir.mkdir(parents=True)
    (deep_skill_dir / "SKILL.md").write_text("---\nname: nested-skill\n---\n# Nested Instructions")
    (deep_skill_dir / "helper.py").write_text("print('helper')")

    skills = scan_skills(tmp_path / "hub")
    assert len(skills) == 1
    assert skills[0].name == "nested-skill"
    assert "helper.py" in skills[0].companion_files


def test_scan_skills_nonexistent_directory():
    assert scan_skills("/non/existent/path/xyz") == []
