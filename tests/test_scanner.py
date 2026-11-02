from pathlib import Path

from src.scanner import _extract_name_from_frontmatter, scan_skills


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


def test_scan_skills_nonexistent_directory():
    assert scan_skills("/non/existent/path/xyz") == []
