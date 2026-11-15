from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import List, Optional, Set

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

PROMPT_EXTENSIONS = {
    ".md",
    ".prompt",
    ".prompt.md",
    ".txt",
}


def parse_target_directories(raw_input: str | None) -> List[str]:
    """
    Parses comma- or newline-separated directory paths.
    Returns a deduplicated list of cleaned directory strings.
    """
    if not raw_input or not raw_input.strip():
        print(
            "::error::No target directories specified. Please provide 'target-directories' input or set TARGET_DIRECTORIES."
        )
        sys.exit(1)

    entries = re.split(r"[\n,]+", raw_input)
    cleaned: List[str] = []
    for entry in entries:
        d = entry.strip()
        if d and d not in cleaned:
            cleaned.append(d)

    return cleaned or ["."]


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


def _to_relative_path_str(path: Path) -> str:
    """Returns a clean relative path string relative to current working directory if possible."""
    try:
        rel = path.resolve().relative_to(Path.cwd().resolve())
        return str(rel) if str(rel) != "." else str(path)
    except ValueError:
        return str(path)


def scan_skills(target_dir: str | Path) -> List[DiscoveredSkill]:
    """
    Recursively scans the target directory for skills and prompt files.
    Identifies:
    1. Skill directories containing a SKILL.md file.
    2. Standalone instruction/prompt files (.md, .prompt) in prompt directories (.copilot, .codex, prompts).
    """
    root = Path(target_dir).resolve()
    if not root.exists():
        return []

    discovered: List[DiscoveredSkill] = []
    seen_skill_dirs: Set[str] = set()
    discovered_files: Set[Path] = set()

    # Step 1: Scan for standard skill directories containing SKILL.md
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS and not d.startswith(".git")]

        current_path = Path(dirpath)
        skill_file = None
        for fname in filenames:
            if fname.lower() == "skill.md":
                skill_file = current_path / fname
                break

        if skill_file and skill_file.is_file() and dirpath not in seen_skill_dirs:
            seen_skill_dirs.add(dirpath)
            discovered_files.add(skill_file)
            try:
                content = skill_file.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            name = _extract_name_from_frontmatter(content) or current_path.name

            # Collect companion files in the skill directory
            companion_files: dict[str, str] = {}
            for item in current_path.rglob("*"):
                if (
                    item.is_file()
                    and item != skill_file
                    and item.suffix.lower() in TEXT_EXTENSIONS
                    and not any(part in IGNORED_DIRS for part in item.parts)
                ):
                    discovered_files.add(item)
                    try:
                        rel_path = str(item.relative_to(current_path))
                        if item.stat().st_size <= 100_000:
                            companion_files[rel_path] = item.read_text(
                                encoding="utf-8", errors="replace"
                            )
                    except Exception:
                        pass

            discovered.append(
                DiscoveredSkill(
                    name=name,
                    directory_path=_to_relative_path_str(current_path),
                    main_file=_to_relative_path_str(skill_file),
                    content=content,
                    companion_files=companion_files,
                )
            )

    # Step 2: Discover standalone prompt / instruction files outside of skill folders
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d
            for d in dirnames
            if d not in IGNORED_DIRS
            and not d.startswith(".git")
            and str(Path(dirpath) / d) not in seen_skill_dirs
        ]

        current_path = Path(dirpath)
        if str(current_path) in seen_skill_dirs:
            continue

        for fname in filenames:
            file_path = current_path / fname
            if file_path in discovered_files:
                continue

            suffix = file_path.suffix.lower()
            if (
                suffix in PROMPT_EXTENSIONS
                and file_path.is_file()
                and not any(part in IGNORED_DIRS for part in file_path.parts)
            ):
                try:
                    # Ignore very small or empty files (< 20 bytes) or large non-prompt files
                    if file_path.stat().st_size < 20 or file_path.stat().st_size > 200_000:
                        continue
                    content = file_path.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    continue

                discovered_files.add(file_path)
                name = _extract_name_from_frontmatter(content) or file_path.stem

                discovered.append(
                    DiscoveredSkill(
                        name=name,
                        directory_path=_to_relative_path_str(current_path),
                        main_file=_to_relative_path_str(file_path),
                        content=content,
                        companion_files={},
                    )
                )

    return discovered
