from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, ClassVar, Dict, List

from src.config import (
    DEFAULT_AWS_SEVERITY_MAPPING,
    DEFAULT_AWS_TYPES_MAPPING,
)
from src.exporters.base import BaseExporter, ExporterRegistry
from src.models import AuditSummary, SeverityLevel, SkillAuditReport, Vulnerability

# Retain module-level default references for backward compatibility
AWS_SEVERITY_MAPPING: Dict[SeverityLevel, str] = dict(DEFAULT_AWS_SEVERITY_MAPPING)  # type: ignore[assignment]
AWS_TYPES_MAPPING: Dict[str, List[str]] = dict(DEFAULT_AWS_TYPES_MAPPING)


@ExporterRegistry.register
class AwsSecurityHubExporter(BaseExporter):
    """Exports audit findings in AWS Security Finding Format (ASFF) for AWS Security Hub ingest."""

    format_name: ClassVar[str] = "aws"

    def __init__(
        self,
        account_id: str | None = None,
        region: str | None = None,
        types_mapping: Dict[str, List[str]] | None = None,
        severity_mapping: Dict[str, str] | None = None,
    ) -> None:
        self.account_id = account_id or os.getenv("AWS_ACCOUNT_ID") or "000000000000"
        self.region = (
            region or os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or "us-east-1"
        )
        self.types_mapping = dict(DEFAULT_AWS_TYPES_MAPPING)
        if types_mapping:
            self.types_mapping.update(types_mapping)

        self.severity_mapping = dict(DEFAULT_AWS_SEVERITY_MAPPING)
        if severity_mapping:
            self.severity_mapping.update(severity_mapping)

    def export(self, summary: AuditSummary) -> Dict[str, Any]:
        """Converts AuditSummary into AWS Security Finding Format (ASFF) batch import format."""
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        findings: List[Dict[str, Any]] = []

        all_reports = (
            summary.reports
            if summary.reports
            else [r for d in summary.directories for r in d.reports]
        )

        for report in all_reports:
            for vuln in report.vulnerabilities:
                finding = self._build_asff_finding(vuln, report, now_iso)
                findings.append(finding)

        return {"Findings": findings}

    def _build_asff_finding(
        self,
        vuln: Vulnerability,
        report: SkillAuditReport,
        timestamp_iso: str,
    ) -> Dict[str, Any]:
        product_arn = (
            f"arn:aws:securityhub:{self.region}:{self.account_id}:product/skills-security-checker"
        )
        finding_id = f"{product_arn}/{report.skill_name}/{vuln.id}"
        types = self.types_mapping.get(
            vuln.category,
            self.types_mapping.get("other", ["Software and Configuration Checks/Vulnerabilities"]),
        )
        severity_label = self.severity_mapping.get(vuln.severity, "INFORMATIONAL")

        product_fields: Dict[str, str] = {
            "skills-security-checker/SkillName": report.skill_name,
            "skills-security-checker/Category": vuln.category,
            "skills-security-checker/RiskScore": str(report.risk_score),
        }
        if vuln.snippet:
            product_fields["skills-security-checker/Snippet"] = vuln.snippet[:1000]
        if vuln.line_number:
            product_fields["skills-security-checker/LineNumber"] = str(vuln.line_number)

        return {
            "SchemaVersion": "2018-10-08",
            "Id": finding_id,
            "ProductArn": product_arn,
            "GeneratorId": f"skills-security-checker/{vuln.category}",
            "AwsAccountId": self.account_id,
            "Types": types,
            "FirstObservedAt": timestamp_iso,
            "LastObservedAt": timestamp_iso,
            "CreatedAt": timestamp_iso,
            "UpdatedAt": timestamp_iso,
            "Severity": {
                "Label": severity_label,
                "Original": vuln.severity,
            },
            "Title": f"[{vuln.category.upper()}] {vuln.title}",
            "Description": vuln.description[:1024],
            "Remediation": {
                "Recommendation": {
                    "Text": vuln.recommendation[:512],
                }
            },
            "ProductFields": product_fields,
            "Resources": [
                {
                    "Type": "Other",
                    "Id": vuln.file_path,
                    "Partition": "aws",
                    "Region": self.region,
                    "Details": {
                        "Other": {
                            "SkillPath": report.skill_path,
                            "FilePath": vuln.file_path,
                            "Line": str(vuln.line_number or 1),
                        }
                    },
                }
            ],
            "RecordState": "ACTIVE",
            "Workflow": {
                "Status": "NEW",
            },
        }
