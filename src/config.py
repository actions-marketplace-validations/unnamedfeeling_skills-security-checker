from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List

DEFAULT_SEVERITY_ORDER: Dict[str, int] = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
}

DEFAULT_SEVERITY_TO_SARIF_LEVEL: Dict[str, str] = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}

DEFAULT_AWS_SEVERITY_MAPPING: Dict[str, str] = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "INFO": "INFORMATIONAL",
}

DEFAULT_ANNOTATION_LEVELS: Dict[str, str] = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "warning",
    "INFO": "notice",
}

DEFAULT_AWS_TYPES_MAPPING: Dict[str, List[str]] = {
    "prompt_injection": [
        "TTPs/Initial Access",
        "Software and Configuration Checks/Vulnerabilities/Adversarial",
    ],
    "command_injection": [
        "TTPs/Execution",
        "Software and Configuration Checks/Vulnerabilities/Command Injection",
    ],
    "data_exfiltration": [
        "TTPs/Exfiltration",
        "Effects/Data Exposure",
    ],
    "privilege_escalation": [
        "TTPs/Privilege Escalation",
    ],
    "insecure_file_access": [
        "TTPs/Defense Evasion",
    ],
    "obfuscation": [
        "TTPs/Defense Evasion/Obfuscated Files or Information",
    ],
    "other": [
        "Software and Configuration Checks/Vulnerabilities",
    ],
}

DEFAULT_SARIF_RULES: Dict[str, Dict[str, Any]] = {
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


def parse_json_or_file(source: str | Path | None) -> dict[str, Any] | None:
    """
    Parses a dictionary from either an existing JSON file path or an inline JSON string.
    Returns None if source is empty or unparseable.
    """
    if not source:
        return None

    # Check if source is an existing file path
    path = Path(source)
    if path.is_file():
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data
                print(f"::warning::File '{source}' did not contain a JSON object.")
                return None
        except Exception as e:
            print(f"::warning::Failed to parse JSON file '{source}': {e}")
            return None

    # Try parsing as inline JSON string
    src_str = str(source).strip()
    if (src_str.startswith("{") and src_str.endswith("}")) or (
        src_str.startswith("[") and src_str.endswith("]")
    ):
        try:
            data = json.loads(src_str)
            if isinstance(data, dict):
                return data
            print(f"::warning::Inline JSON configuration was not a JSON object: {src_str[:80]}")
            return None
        except Exception as e:
            print(f"::warning::Failed to parse inline JSON configuration: {e}")
            return None

    # If it was a non-empty string that wasn't valid inline JSON and not a file, check if it looks like a path
    if "/" in src_str or "\\" in src_str or src_str.endswith(".json"):
        print(f"::warning::Configuration file not found at '{source}'. Using defaults.")

    return None


@dataclass
class AuditConfig:
    """Configuration container holding main prompt path, finding level mappings, AWS types, and SARIF rules."""

    prompt_path: str | None = None
    severity_order: Dict[str, int] = field(default_factory=lambda: dict(DEFAULT_SEVERITY_ORDER))
    sarif_levels: Dict[str, str] = field(
        default_factory=lambda: dict(DEFAULT_SEVERITY_TO_SARIF_LEVEL)
    )
    aws_severity_levels: Dict[str, str] = field(
        default_factory=lambda: dict(DEFAULT_AWS_SEVERITY_MAPPING)
    )
    annotation_levels: Dict[str, str] = field(
        default_factory=lambda: dict(DEFAULT_ANNOTATION_LEVELS)
    )
    aws_types_mapping: Dict[str, List[str]] = field(
        default_factory=lambda: dict(DEFAULT_AWS_TYPES_MAPPING)
    )
    sarif_rules: Dict[str, Dict[str, Any]] = field(
        default_factory=lambda: dict(DEFAULT_SARIF_RULES)
    )

    def merge_finding_levels(self, data: Dict[str, Any]) -> None:
        """Merges external finding levels and severity mappings, preserving unmentioned defaults."""
        if "order" in data and isinstance(data["order"], dict):
            self.severity_order.update({str(k).upper(): int(v) for k, v in data["order"].items()})

        if "sarif_levels" in data and isinstance(data["sarif_levels"], dict):
            self.sarif_levels.update(
                {str(k).upper(): str(v).lower() for k, v in data["sarif_levels"].items()}
            )

        if "aws_levels" in data and isinstance(data["aws_levels"], dict):
            self.aws_severity_levels.update(
                {str(k).upper(): str(v).upper() for k, v in data["aws_levels"].items()}
            )
        elif "aws_severity_levels" in data and isinstance(data["aws_severity_levels"], dict):
            self.aws_severity_levels.update(
                {str(k).upper(): str(v).upper() for k, v in data["aws_severity_levels"].items()}
            )

        if "annotation_levels" in data and isinstance(data["annotation_levels"], dict):
            self.annotation_levels.update(
                {str(k).upper(): str(v).lower() for k, v in data["annotation_levels"].items()}
            )

        # Also support flat dictionary format e.g. {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning"}
        for k, v in data.items():
            if k not in (
                "order",
                "sarif_levels",
                "aws_levels",
                "aws_severity_levels",
                "annotation_levels",
            ):
                sev_key = str(k).upper()
                val_str = str(v).lower()
                if val_str in ("error", "warning", "note", "none"):
                    self.sarif_levels[sev_key] = val_str
                    self.annotation_levels[sev_key] = "notice" if val_str == "note" else val_str
                elif val_str.upper() in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"):
                    self.aws_severity_levels[sev_key] = val_str.upper()

    def merge_aws_types_mapping(self, data: Dict[str, Any]) -> None:
        """Merges external AWS Security Hub finding types, preserving unmentioned defaults."""
        for cat, types in data.items():
            cat_key = str(cat).lower()
            if isinstance(types, list):
                self.aws_types_mapping[cat_key] = [str(t) for t in types]
            elif isinstance(types, str):
                self.aws_types_mapping[cat_key] = [types]

    def merge_sarif_rules(self, data: Dict[str, Any]) -> None:
        """Merges external SARIF rule definitions, preserving unmentioned defaults."""
        for cat, rule in data.items():
            cat_key = str(cat).lower()
            if isinstance(rule, dict):
                if cat_key in self.sarif_rules:
                    merged = dict(self.sarif_rules[cat_key])
                    merged.update(rule)
                    self.sarif_rules[cat_key] = merged
                else:
                    self.sarif_rules[cat_key] = rule


def load_audit_config(
    config_file: str | Path | None = None,
    prompt_path: str | Path | None = None,
    finding_levels: str | Path | Dict[str, Any] | None = None,
    aws_types_mapping: str | Path | Dict[str, Any] | None = None,
    sarif_rules: str | Path | Dict[str, Any] | None = None,
) -> AuditConfig:
    """
    Loads and resolves AuditConfig from an optional configuration file,
    environment variables, or discrete parameter overrides.
    """
    config = AuditConfig()

    # 1. Resolve unified configuration file (if specified or auto-discovered)
    resolved_config_file: Path | None = None
    if config_file:
        p = Path(config_file)
        if p.is_file():
            resolved_config_file = p
        else:
            print(f"::warning::Specified config file '{config_file}' was not found.")
    else:
        for candidate in [Path(".skills-security.json"), Path("skills-security-config.json")]:
            if candidate.is_file():
                resolved_config_file = candidate
                print(f"::notice::Loaded configuration from auto-discovered '{candidate}'.")
                break

    if resolved_config_file:
        try:
            with open(resolved_config_file, "r", encoding="utf-8") as f:
                file_data = json.load(f)
            if isinstance(file_data, dict):
                if "prompt_path" in file_data:
                    config.prompt_path = str(file_data["prompt_path"])
                if "finding_levels" in file_data and isinstance(file_data["finding_levels"], dict):
                    config.merge_finding_levels(file_data["finding_levels"])
                if "aws_types_mapping" in file_data and isinstance(
                    file_data["aws_types_mapping"], dict
                ):
                    config.merge_aws_types_mapping(file_data["aws_types_mapping"])
                if "sarif_rules" in file_data and isinstance(file_data["sarif_rules"], dict):
                    config.merge_sarif_rules(file_data["sarif_rules"])
        except Exception as e:
            print(f"::warning::Error loading config file '{resolved_config_file}': {e}")

    # 2. Apply discrete overrides (take precedence over config file)
    if prompt_path:
        config.prompt_path = str(prompt_path)

    parsed_levels = (
        finding_levels if isinstance(finding_levels, dict) else parse_json_or_file(finding_levels)
    )
    if parsed_levels:
        config.merge_finding_levels(parsed_levels)

    parsed_aws = (
        aws_types_mapping
        if isinstance(aws_types_mapping, dict)
        else parse_json_or_file(aws_types_mapping)
    )
    if parsed_aws:
        config.merge_aws_types_mapping(parsed_aws)

    parsed_sarif = sarif_rules if isinstance(sarif_rules, dict) else parse_json_or_file(sarif_rules)
    if parsed_sarif:
        config.merge_sarif_rules(parsed_sarif)

    return config
