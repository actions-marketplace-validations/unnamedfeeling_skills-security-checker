from __future__ import annotations

from typing import Any, ClassVar, Dict, List

from src.exporters.base import BaseExporter, ExporterRegistry
from src.models import AuditSummary, SeverityLevel, Vulnerability

SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)

SEVERITY_TO_SARIF_LEVEL: Dict[SeverityLevel, str] = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}

DEFAULT_RULES = {
    "prompt_injection": {
        "id": "SEC-PROMPT-INJECTION",
        "name": "PromptInjection",
        "shortDescription": {"text": "Indirect prompt injection or system override detected"},
        "fullDescription": {
            "text": "The skill definition contains adversarial prompt overrides, hidden instructions, or jailbreak attempts."
        },
        "defaultConfiguration": {"level": "error"},
        "help": {"text": "Remove instructions overriding system constraints or developer rules."},
    },
    "command_injection": {
        "id": "SEC-COMMAND-INJECTION",
        "name": "CommandInjection",
        "shortDescription": {"text": "Arbitrary or destructive shell command execution detected"},
        "fullDescription": {
            "text": "The skill definition or companion scripts execute dangerous shell commands or pipe untrusted streams."
        },
        "defaultConfiguration": {"level": "error"},
        "help": {
            "text": "Sanitize and avoid dangerous shell operations like 'rm -rf' or 'curl | bash'."
        },
    },
    "data_exfiltration": {
        "id": "SEC-DATA-EXFILTRATION",
        "name": "DataExfiltration",
        "shortDescription": {"text": "Unauthorized secret access or external network transmission"},
        "fullDescription": {
            "text": "The skill attempts to access sensitive files (~/.ssh, ~/.aws, .env) or transmit credentials externally."
        },
        "defaultConfiguration": {"level": "error"},
        "help": {
            "text": "Eliminate access to sensitive credential stores and unsolicited network requests."
        },
    },
    "insecure_file_access": {
        "id": "SEC-FILE-ACCESS",
        "name": "InsecureFileAccess",
        "shortDescription": {"text": "File tampering outside workspace boundaries"},
        "fullDescription": {
            "text": "The skill modifies or overwrites files outside permitted working directories."
        },
        "defaultConfiguration": {"level": "warning"},
        "help": {
            "text": "Restrict all file writes strictly to designated workspace subdirectories."
        },
    },
    "privilege_escalation": {
        "id": "SEC-PRIVILEGE-ESCALATION",
        "name": "PrivilegeEscalation",
        "shortDescription": {
            "text": "Unauthorized root escalation or excessive permission requests"
        },
        "fullDescription": {
            "text": "The skill attempts to invoke sudo or requests unbounded permissions not justified by its scope."
        },
        "defaultConfiguration": {"level": "error"},
        "help": {
            "text": "Follow the principle of least privilege and avoid sudo or root requirements."
        },
    },
    "obfuscation": {
        "id": "SEC-OBFUSCATION",
        "name": "Obfuscation",
        "shortDescription": {"text": "Encoded or obfuscated payload detected"},
        "fullDescription": {
            "text": "The skill hides instructions or commands using Base64, hex, or steganography."
        },
        "defaultConfiguration": {"level": "error"},
        "help": {
            "text": "Keep all skill instructions and companion scripts in readable plaintext."
        },
    },
    "other": {
        "id": "SEC-GENERIC",
        "name": "GenericSecurityRisk",
        "shortDescription": {"text": "Unclassified security issue detected"},
        "fullDescription": {
            "text": "A potential security vulnerability was flagged by the security auditor."
        },
        "defaultConfiguration": {"level": "warning"},
        "help": {"text": "Review the finding recommendation and verify safe execution."},
    },
}


@ExporterRegistry.register
class SarifExporter(BaseExporter):
    """Exports audit findings in OASIS SARIF v2.1.0 format for GitHub Code Scanning and IDEs."""

    format_name: ClassVar[str] = "sarif"

    def export(self, summary: AuditSummary) -> Dict[str, Any]:
        rules_map: Dict[str, Dict[str, Any]] = dict(DEFAULT_RULES)
        results: List[Dict[str, Any]] = []

        all_reports = (
            summary.reports
            if summary.reports
            else [r for d in summary.directories for r in d.reports]
        )

        for report in all_reports:
            for vuln in report.vulnerabilities:
                rule_info = rules_map.get(vuln.category, rules_map["other"])
                rule_id = vuln.id if vuln.id else rule_info["id"]

                # Ensure custom rule IDs are registered in rules array
                if rule_id not in [r["id"] for r in rules_map.values()]:
                    rules_map[rule_id] = {
                        "id": rule_id,
                        "name": vuln.title.replace(" ", ""),
                        "shortDescription": {"text": vuln.title},
                        "fullDescription": {"text": vuln.description},
                        "defaultConfiguration": {
                            "level": SEVERITY_TO_SARIF_LEVEL.get(vuln.severity, "warning")
                        },
                        "help": {"text": vuln.recommendation},
                    }

                sarif_result: Dict[str, Any] = {
                    "ruleId": rule_id,
                    "level": SEVERITY_TO_SARIF_LEVEL.get(vuln.severity, "warning"),
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
