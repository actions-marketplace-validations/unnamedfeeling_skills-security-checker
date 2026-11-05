from __future__ import annotations

from typing import List, Literal, Optional

from pydantic import BaseModel, Field

SeverityLevel = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

VulnerabilityCategory = Literal[
    "prompt_injection",
    "command_injection",
    "data_exfiltration",
    "insecure_file_access",
    "privilege_escalation",
    "obfuscation",
    "other",
]


class Vulnerability(BaseModel):
    """Represents an identified security vulnerability in a skill."""

    id: str = Field(description="Unique short identifier for the finding (e.g. SEC-001)")
    title: str = Field(description="Concise description of the vulnerability")
    severity: SeverityLevel = Field(description="Severity classification")
    category: VulnerabilityCategory = Field(description="Attack vector classification")
    file_path: str = Field(description="Path to the file where the vulnerability was detected")
    line_number: Optional[int] = Field(
        default=None, description="Line number where the suspicious code or instruction occurs"
    )
    snippet: str = Field(
        description="Relevant code or prompt excerpt demonstrating the vulnerability"
    )
    description: str = Field(description="Detailed explanation of the potential risk or exploit")
    recommendation: str = Field(description="Guidance on how to resolve or mitigate the issue")


class SkillAuditReport(BaseModel):
    """Assessment results for an individual skill."""

    skill_name: str = Field(description="Name of the audited skill")
    skill_path: str = Field(description="Directory path of the audited skill")
    status: Literal["PASS", "WARN", "FAIL"] = Field(
        description="Overall verdict: PASS (clean), WARN (low/medium findings), FAIL (high/critical)"
    )
    risk_score: int = Field(
        ge=0, le=100, description="Risk rating from 0 (completely safe) to 100 (critical danger)"
    )
    summary: str = Field(description="High-level evaluation summary of the skill")
    vulnerabilities: List[Vulnerability] = Field(default_factory=list)


class DirectoryAuditReport(BaseModel):
    """Assessment results for a specific target directory."""

    directory: str = Field(description="Scanned directory path")
    status: Literal["PASS", "WARN", "FAIL"] = Field(
        default="PASS", description="Directory-level verdict"
    )
    risk_score: int = Field(
        default=0, ge=0, le=100, description="Highest risk score among items in this directory"
    )
    scanned_count: int = 0
    passed_count: int = 0
    warned_count: int = 0
    failed_count: int = 0
    total_vulnerabilities: int = 0
    reports: List[SkillAuditReport] = Field(default_factory=list)


class AuditSummary(BaseModel):
    """Cumulative assessment results across all scanned directories and skills."""

    directories: List[DirectoryAuditReport] = Field(default_factory=list)
    scanned_skills_count: int = 0
    passed_skills_count: int = 0
    warned_skills_count: int = 0
    failed_skills_count: int = 0
    total_vulnerabilities: int = 0
    reports: List[SkillAuditReport] = Field(default_factory=list)
    status: Literal["PASS", "WARN", "FAIL"] = "PASS"


class DiscoveredSkill(BaseModel):
    """A discovered skill ready for analysis."""

    name: str
    directory_path: str
    main_file: str
    content: str
    companion_files: dict[str, str] = Field(
        default_factory=dict, description="Relative paths mapped to file contents"
    )
