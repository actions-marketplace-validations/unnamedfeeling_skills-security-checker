from __future__ import annotations

from typing import Any, ClassVar, Dict, List

from src.config import (
    DEFAULT_SARIF_RULES,
    DEFAULT_SEVERITY_TO_SARIF_LEVEL,
)
from src.exporters.base import BaseExporter, ExporterRegistry
from src.models import AuditSummary, SeverityLevel, Vulnerability

SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)

# Retain module-level default references for backward compatibility
SEVERITY_TO_SARIF_LEVEL: Dict[SeverityLevel, str] = dict(DEFAULT_SEVERITY_TO_SARIF_LEVEL)  # type: ignore[assignment]
DEFAULT_RULES: Dict[str, Dict[str, Any]] = dict(DEFAULT_SARIF_RULES)


@ExporterRegistry.register
class SarifExporter(BaseExporter):
    """Exports audit findings in OASIS SARIF v2.1.0 format for GitHub Code Scanning and IDEs."""

    format_name: ClassVar[str] = "sarif"

    def __init__(
        self,
        rules: Dict[str, Dict[str, Any]] | None = None,
        severity_map: Dict[str, str] | None = None,
    ) -> None:
        self.custom_rules = rules
        self.severity_map = dict(DEFAULT_SEVERITY_TO_SARIF_LEVEL)
        if severity_map:
            self.severity_map.update(severity_map)

    def export(self, summary: AuditSummary) -> Dict[str, Any]:
        rules_map: Dict[str, Dict[str, Any]] = dict(DEFAULT_RULES)
        if self.custom_rules:
            for cat, custom_rule in self.custom_rules.items():
                if cat in rules_map:
                    rules_map[cat] = {**rules_map[cat], **custom_rule}
                else:
                    rules_map[cat] = custom_rule

        results: List[Dict[str, Any]] = []

        all_reports = (
            summary.reports
            if summary.reports
            else [r for d in summary.directories for r in d.reports]
        )

        for report in all_reports:
            for vuln in report.vulnerabilities:
                rule_info = rules_map.get(
                    vuln.category, rules_map.get("other", DEFAULT_RULES["other"])
                )
                rule_id = vuln.id if vuln.id else rule_info.get("id", "SEC-GENERIC")
                finding_level = self.severity_map.get(vuln.severity, "warning")

                # Ensure custom rule IDs are registered in rules array
                if rule_id not in [r.get("id") for r in rules_map.values()]:
                    rules_map[rule_id] = {
                        "id": rule_id,
                        "name": vuln.title.replace(" ", ""),
                        "shortDescription": {"text": vuln.title},
                        "fullDescription": {"text": vuln.description},
                        "defaultConfiguration": {"level": finding_level},
                        "help": {"text": vuln.recommendation},
                    }

                sarif_result: Dict[str, Any] = {
                    "ruleId": rule_id,
                    "level": finding_level,
                    "message": {
                        "text": f"{vuln.title}: {vuln.description}\nRecommendation: {vuln.recommendation}"
                    },
                    "locations": [self._format_location(vuln)],
                }
                results.append(sarif_result)

        return {
            "$schema": SARIF_SCHEMA,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "skills-security-checker",
                            "version": "0.1.0",
                            "informationUri": "https://github.com/skills-security-checker/skills-security-checker",
                            "rules": list(rules_map.values()),
                        }
                    },
                    "results": results,
                }
            ],
        }

    def _format_location(self, vuln: Vulnerability) -> Dict[str, Any]:
        start_line = vuln.line_number if vuln.line_number and vuln.line_number > 0 else 1
        region: Dict[str, Any] = {"startLine": start_line}
        if vuln.snippet:
            region["snippet"] = {"text": vuln.snippet}

        return {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": vuln.file_path,
                    "uriBaseId": "%SRCROOT%",
                },
                "region": region,
            }
        }
