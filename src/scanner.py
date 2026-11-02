from __future__ import annotations

import os
import re
from pathlib import Path
from typing import List, Optional

from src.models import DiscoveredSkill

IGNORED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
}

TEXT_EXTENSIONS = {
    ".md",
    ".txt",
    ".py",
    ".sh",
    ".bash",
    ".js",
    ".ts",
    ".json",
    ".yaml",
    ".yml",
}


def _extract_name_from_frontmatter(content: str) -> Optional[str]:
    """Attempt to parse the 'name' field from YAML frontmatter without requiring heavy dependencies."""
    match = re.search(r"^---\s*\n(.*?)\n---", content, re.DOTALL | re.MULTILINE)
    if not match:
        return None
    frontmatter = match.group(1)
    name_match = re.search(r"^name:\s*([^\n\r]+)", frontmatter, re.MULTILINE)
    if name_match:
        return name_match.group(1).strip().strip("'\"")
    return None


def scan_skills(target_dir: str | Path) -> List[DiscoveredSkill]:
    """
    Recursively scans the target directory for skills.
    A skill is identified by a SKILL.md file inside its directory.
    """
    root = Path(target_dir).resolve()
    if not root.exists():
        return []

    discovered: List[DiscoveredSkill] = []
    seen_dirs = set()

    for dirpath, dirnames, filenames in os.walk(root):
        # Exclude ignored directories in-place to prevent traversing them
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS and not d.startswith(".git")]

        current_path = Path(dirpath)
        skill_file = None
        for fname in filenames:
            if fname.lower() == "skill.md":
                skill_file = current_path / fname
                break

        if skill_file and skill_file.is_file() and dirpath not in seen_dirs:
            seen_dirs.add(dirpath)
            try:
                content = skill_file.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            name = _extract_name_from_frontmatter(content) or current_path.name

            # Read companion files in the skill directory (e.g. scripts/, resources/)
            companion_files: dict[str, str] = {}
            for item in current_path.rglob("*"):
                if (
                    item.is_file()
                    and item != skill_file
                    and item.suffix.lower() in TEXT_EXTENSIONS
                    and not any(part in IGNORED_DIRS for part in item.parts)
                ):
                    try:
                        rel_path = str(item.relative_to(current_path))
                        # Limit individual file size to 100KB to prevent context blowup
                        if item.stat().st_size <= 100_000:
                            companion_files[rel_path] = item.read_text(
                                encoding="utf-8", errors="replace"
                            )
                    except Exception:
                        pass

            discovered.append(
                DiscoveredSkill(
                    name=name,
                    directory_path=str(current_path),
                    main_file=str(skill_file),
                    content=content,
                    companion_files=companion_files,
                )
            )

    return discovered
