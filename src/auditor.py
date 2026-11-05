from __future__ import annotations

import json
from pathlib import Path

from openai import OpenAI

from src.models import DiscoveredSkill, SkillAuditReport

PROMPTS_DIR = Path(__file__).resolve().parent.parent / "prompts"

FALLBACK_PROMPTS: dict[str, str] = {
    "system": (
        "You are an expert AI Security Auditor specialized in evaluating AI Agent Skills "
        "for malicious actions, prompt injections, and unsafe commands.\n"
        "Analyze the provided skill definition against prompt_injection, command_injection, "
        "privilege_escalation, data_exfiltration, insecure_file_access, and obfuscation.\n"
        "Return valid JSON matching the SkillAuditReport schema with status PASS, WARN, or FAIL.\n"
    )
}


def load_prompt(
    prompt_type: str = "system",
    custom_prompt_path: str | Path | None = None,
) -> str:
    """
    Loads a prompt from a custom path if provided,
    otherwise resolves and loads the matching file from the prompts directory
    (e.g. '{type}_audit.md' or '{type}.md'), falling back to a minimal prompt if unavailable.
    """
    if custom_prompt_path:
        path = Path(custom_prompt_path)
        if path.is_file():
            return path.read_text(encoding="utf-8")
        print(f"::warning::Custom prompt file not found at '{custom_prompt_path}'. Using default.")

    # Search candidates in prompts directory
    candidates = [
        PROMPTS_DIR / f"{prompt_type}_audit.md",
        PROMPTS_DIR / f"{prompt_type}.md",
        PROMPTS_DIR / f"{prompt_type}.txt",
    ]
    for candidate_path in candidates:
        if candidate_path.is_file():
            return candidate_path.read_text(encoding="utf-8")

    return FALLBACK_PROMPTS.get(prompt_type, "")


def load_system_prompt(custom_prompt_path: str | Path | None = None) -> str:
    """Convenience alias for loading the 'system' level prompt."""
    return load_prompt(prompt_type="system", custom_prompt_path=custom_prompt_path)


def _format_skill_for_audit(skill: DiscoveredSkill) -> str:
    """Formats the discovered skill and companion files into an analysis context."""
    sections = [
        f"=== SKILL NAME: {skill.name} ===",
        f"=== DIRECTORY: {skill.directory_path} ===",
        f"=== MAIN FILE ({skill.main_file}) ===\n{skill.content}",
    ]

    if skill.companion_files:
        sections.append("=== COMPANION FILES ===")
        for rel_path, file_content in skill.companion_files.items():
            sections.append(f"--- File: {rel_path} ---\n{file_content}\n")

    return "\n\n".join(sections)


def audit_skill(
    skill: DiscoveredSkill,
    client: OpenAI,
    model: str = "gpt-4o",
    system_prompt_override: str | None = None,
) -> SkillAuditReport:
    """
    Audits a single skill using the specified OpenAI-compatible client and model.
    Uses structured output parsing into SkillAuditReport.
    """
    system_prompt = system_prompt_override or load_prompt(prompt_type="system")
    user_prompt = _format_skill_for_audit(skill)

    try:
        # First attempt OpenAI structured parse
        completion = client.beta.chat.completions.parse(
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            response_format=SkillAuditReport,
        )
        report = completion.choices[0].message.parsed
        if report is not None:
            # Ensure skill path and name match the actual discovered skill
            report.skill_name = skill.name
            report.skill_path = skill.directory_path
            return report

    except Exception:
        # Fallback to standard chat completions with JSON mode for generic OpenAI-compatible proxies
        pass

    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {
                    "role": "system",
                    "content": f"{system_prompt}\n\nRespond with valid JSON matching the SkillAuditReport schema.",
                },
                {"role": "user", "content": user_prompt},
            ],
            response_format={"type": "json_object"},
        )
        content = response.choices[0].message.content or "{}"
        parsed_dict = json.loads(content)
        report = SkillAuditReport.model_validate(parsed_dict)
        report.skill_name = skill.name
        report.skill_path = skill.directory_path
        return report

    except Exception as e:
        # Fallback graceful error report rather than crashing CI
        return SkillAuditReport(
            skill_name=skill.name,
            skill_path=skill.directory_path,
            status="WARN",
            risk_score=50,
            summary=f"Audit failed due to error: {str(e)}",
            vulnerabilities=[],
        )
