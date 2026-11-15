import json
from pathlib import Path

import pytest

from src.exporters import (
    AwsSecurityHubExporter,
    BaseExporter,
    ExporterRegistry,
    SarifExporter,
    export_findings,
)
from src.models import (
    AuditSummary,
    DirectoryAuditReport,
    SkillAuditReport,
    Vulnerability,
)


def create_sample_summary() -> AuditSummary:
    vuln1 = Vulnerability(
        id="SEC-001",
        title="Prompt override attempt",
        severity="HIGH",
        category="prompt_injection",
        file_path="skills/malicious/SKILL.md",
        line_number=14,
        snippet="Ignore previous instructions",
        description="Adversarial prompt injection detected",
        recommendation="Remove unauthorized prompt override",
    )
    vuln2 = Vulnerability(
        id="SEC-002",
        title="Excessive permissions",
        severity="MEDIUM",
        category="privilege_escalation",
        file_path="skills/builder/SKILL.md",
        line_number=22,
        snippet="docker run --privileged",
        description="Container runs in privileged mode",
        recommendation="Drop privileged flag",
    )

    report1 = SkillAuditReport(
        skill_name="malicious-skill",
        skill_path="skills/malicious",
        status="FAIL",
        risk_score=85,
        summary="Contains critical prompt injection",
        vulnerabilities=[vuln1],
    )
    report2 = SkillAuditReport(
        skill_name="builder-skill",
        skill_path="skills/builder",
        status="WARN",
        risk_score=40,
        summary="Contains privilege escalation",
        vulnerabilities=[vuln2],
    )

    dir_report = DirectoryAuditReport(
        directory="skills",
        scanned_count=2,
        failed_count=1,
        warned_count=1,
        reports=[report1, report2],
    )

    return AuditSummary(
        directories=[dir_report],
        reports=[report1, report2],
        scanned_skills_count=2,
        failed_skills_count=1,
        warned_skills_count=1,
        total_vulnerabilities=2,
    )


def test_exporter_registry():
    formats = ExporterRegistry.available_formats()
    assert "sarif" in formats
    assert "aws" in formats

    sarif_exp = ExporterRegistry.get("sarif")
    assert isinstance(sarif_exp, SarifExporter)

    aws_exp = ExporterRegistry.get("aws")
    assert isinstance(aws_exp, AwsSecurityHubExporter)

    with pytest.raises(ValueError, match="Unsupported export format"):
        ExporterRegistry.get("nonexistent_format")


def test_exporter_registry_extension():
    @ExporterRegistry.register
    class CustomJsonExporter(BaseExporter):
        format_name = "custom_test"

        def export(self, summary: AuditSummary):
            return {"custom": True, "count": summary.total_vulnerabilities}

    assert "custom_test" in ExporterRegistry.available_formats()
    custom_exp = ExporterRegistry.get("custom_test")
    res = custom_exp.export(create_sample_summary())
    assert res["custom"] is True
    assert res["count"] == 2


def test_sarif_export():
    summary = create_sample_summary()
    exporter = SarifExporter()
    sarif = exporter.export(summary)

    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert len(sarif["runs"]) == 1

    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "skills-security-checker"

    results = run["results"]
    assert len(results) == 2

    # Check high severity mapped to error
    res1 = results[0]
    assert res1["level"] == "error"
    assert res1["ruleId"] == "SEC-001"
    assert "Prompt override attempt" in res1["message"]["text"]
    assert (
        res1["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        == "skills/malicious/SKILL.md"
    )
    assert res1["locations"][0]["physicalLocation"]["region"]["startLine"] == 14

    # Check medium severity mapped to warning
    res2 = results[1]
    assert res2["level"] == "warning"
    assert res2["ruleId"] == "SEC-002"


def test_sarif_export_empty():
    empty_summary = AuditSummary()
    exporter = SarifExporter()
    sarif = exporter.export(empty_summary)

    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"] == []


def test_aws_asff_export():
    summary = create_sample_summary()
    exporter = AwsSecurityHubExporter(account_id="123456789012", region="us-west-2")
    asff = exporter.export(summary)

    assert "Findings" in asff
    findings = asff["Findings"]
    assert len(findings) == 2

    f1 = findings[0]
    assert f1["SchemaVersion"] == "2018-10-08"
    assert f1["AwsAccountId"] == "123456789012"
    assert "us-west-2" in f1["ProductArn"]
    assert f1["Severity"]["Label"] == "HIGH"
    assert f1["Title"] == "[PROMPT_INJECTION] Prompt override attempt"
    assert f1["Resources"][0]["Id"] == "skills/malicious/SKILL.md"
    assert f1["ProductFields"]["skills-security-checker/SkillName"] == "malicious-skill"
    assert f1["ProductFields"]["skills-security-checker/Category"] == "prompt_injection"
    assert "TTPs/Initial Access" in f1["Types"]


def test_aws_asff_export_empty():
    empty_summary = AuditSummary()
    exporter = AwsSecurityHubExporter()
    asff = exporter.export(empty_summary)

    assert asff == {"Findings": []}


def test_export_to_file(tmp_path: Path):
    summary = create_sample_summary()
    sarif_file = tmp_path / "reports" / "results.sarif"
    aws_file = tmp_path / "reports" / "findings.asff.json"

    export_findings(summary, "sarif", sarif_file)
    assert sarif_file.is_file()
    sarif_data = json.loads(sarif_file.read_text(encoding="utf-8"))
    assert sarif_data["version"] == "2.1.0"

    export_findings(summary, "aws", aws_file)
    assert aws_file.is_file()
    aws_data = json.loads(aws_file.read_text(encoding="utf-8"))
    assert "Findings" in aws_data


def test_sarif_export_with_custom_rules_and_levels():
    summary = create_sample_summary()
    custom_rules = {
        "prompt_injection": {
            "id": "CORP-RULE-001",
            "name": "CorporatePromptGuard",
            "shortDescription": {"text": "Custom corporate description"},
        }
    }
    custom_severity_map = {"HIGH": "warning", "MEDIUM": "error"}

    exporter = SarifExporter(rules=custom_rules, severity_map=custom_severity_map)
    sarif = exporter.export(summary)

    # Verify custom rule registration
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    corp_rule = next(r for r in rules if r["id"] == "CORP-RULE-001")
    assert corp_rule["name"] == "CorporatePromptGuard"
    assert corp_rule["shortDescription"]["text"] == "Custom corporate description"

    # Verify customized severity levels
    results = sarif["runs"][0]["results"]
    assert results[0]["level"] == "warning"  # HIGH mapped to warning
    assert results[1]["level"] == "error"  # MEDIUM mapped to error


def test_aws_asff_export_with_custom_types_and_levels():
    summary = create_sample_summary()
    custom_types = {
        "prompt_injection": ["Custom/PromptInjectionAttack"],
    }
    custom_severities = {
        "HIGH": "MEDIUM",
        "MEDIUM": "CRITICAL",
    }

    exporter = AwsSecurityHubExporter(
        types_mapping=custom_types,
        severity_mapping=custom_severities,
    )
    asff = exporter.export(summary)
    findings = asff["Findings"]

    # Prompt injection has custom types and severity mapped from HIGH to MEDIUM
    f1 = findings[0]
    assert f1["Types"] == ["Custom/PromptInjectionAttack"]
    assert f1["Severity"]["Label"] == "MEDIUM"

    # Privilege escalation retains default types, severity mapped from MEDIUM to CRITICAL
    f2 = findings[1]
    assert "TTPs/Privilege Escalation" in f2["Types"]
    assert f2["Severity"]["Label"] == "CRITICAL"
