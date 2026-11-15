import json
from pathlib import Path

from src.config import (
    DEFAULT_ANNOTATION_LEVELS,
    DEFAULT_AWS_SEVERITY_MAPPING,
    DEFAULT_AWS_TYPES_MAPPING,
    DEFAULT_SARIF_RULES,
    DEFAULT_SEVERITY_ORDER,
    DEFAULT_SEVERITY_TO_SARIF_LEVEL,
    AuditConfig,
    load_audit_config,
    parse_json_or_file,
)


def test_audit_config_defaults():
    config = AuditConfig()
    assert config.severity_order == DEFAULT_SEVERITY_ORDER
    assert config.sarif_levels == DEFAULT_SEVERITY_TO_SARIF_LEVEL
    assert config.aws_severity_levels == DEFAULT_AWS_SEVERITY_MAPPING
    assert config.annotation_levels == DEFAULT_ANNOTATION_LEVELS
    assert config.aws_types_mapping == DEFAULT_AWS_TYPES_MAPPING
    assert config.sarif_rules == DEFAULT_SARIF_RULES


def test_parse_json_or_file_inline_json():
    data = parse_json_or_file('{"CRITICAL": "error", "HIGH": "warning"}')
    assert data == {"CRITICAL": "error", "HIGH": "warning"}


def test_parse_json_or_file_file(tmp_path: Path):
    file_path = tmp_path / "custom.json"
    file_path.write_text(json.dumps({"custom_key": "custom_val"}), encoding="utf-8")
    data = parse_json_or_file(str(file_path))
    assert data == {"custom_key": "custom_val"}


def test_parse_json_or_file_invalid():
    assert parse_json_or_file(None) is None
    assert parse_json_or_file("") is None
    assert parse_json_or_file("{invalid_json") is None
    assert parse_json_or_file("/non/existent/path/file.json") is None


def test_merge_finding_levels():
    config = AuditConfig()
    custom_levels = {
        "order": {"BLOCKER": 6, "CRITICAL": 5},
        "sarif_levels": {"MEDIUM": "error"},
        "aws_levels": {"INFO": "LOW"},
        "annotation_levels": {"LOW": "error"},
    }
    config.merge_finding_levels(custom_levels)
    assert config.severity_order["BLOCKER"] == 6
    assert config.severity_order["HIGH"] == 4  # Retained default
    assert config.sarif_levels["MEDIUM"] == "error"
    assert config.sarif_levels["CRITICAL"] == "error"  # Retained default
    assert config.aws_severity_levels["INFO"] == "LOW"
    assert config.annotation_levels["LOW"] == "error"


def test_merge_finding_levels_flat_dict():
    config = AuditConfig()
    flat_levels = {"HIGH": "warning", "MEDIUM": "note", "LOW": "none"}
    config.merge_finding_levels(flat_levels)
    assert config.sarif_levels["HIGH"] == "warning"
    assert config.sarif_levels["MEDIUM"] == "note"
    assert config.annotation_levels["HIGH"] == "warning"
    assert config.annotation_levels["MEDIUM"] == "notice"


def test_merge_aws_types_mapping():
    config = AuditConfig()
    custom_mapping = {
        "prompt_injection": ["Custom/PromptInjection"],
        "new_category": ["TTPs/NewCategory"],
    }
    config.merge_aws_types_mapping(custom_mapping)
    assert config.aws_types_mapping["prompt_injection"] == ["Custom/PromptInjection"]
    assert config.aws_types_mapping["new_category"] == ["TTPs/NewCategory"]
    # Verify unmentioned defaults are retained
    assert "command_injection" in config.aws_types_mapping
    assert "TTPs/Execution" in config.aws_types_mapping["command_injection"]


def test_merge_sarif_rules():
    config = AuditConfig()
    custom_rules = {
        "prompt_injection": {
            "id": "CORP-SEC-001",
            "name": "OrgPromptPolicy",
        },
        "custom_vector": {
            "id": "CORP-SEC-999",
            "name": "CustomVector",
            "defaultConfiguration": {"level": "warning"},
        },
    }
    config.merge_sarif_rules(custom_rules)
    assert config.sarif_rules["prompt_injection"]["id"] == "CORP-SEC-001"
    assert config.sarif_rules["prompt_injection"]["name"] == "OrgPromptPolicy"
    # Deep merge preserved unmentioned default fields:
    assert "fullDescription" in config.sarif_rules["prompt_injection"]
    # New custom rule registered:
    assert config.sarif_rules["custom_vector"]["id"] == "CORP-SEC-999"
    # Other default rules retained:
    assert config.sarif_rules["command_injection"]["id"] == "SEC-COMMAND-INJECTION"


def test_load_audit_config_from_file(tmp_path: Path):
    cfg_file = tmp_path / "skills-security-config.json"
    content = {
        "prompt_path": "prompts/custom.md",
        "aws_types_mapping": {
            "command_injection": ["TTPs/CustomExecution"],
        },
        "sarif_rules": {
            "obfuscation": {"id": "CORP-OBF-01"},
        },
    }
    cfg_file.write_text(json.dumps(content), encoding="utf-8")

    config = load_audit_config(config_file=str(cfg_file))
    assert config.prompt_path == "prompts/custom.md"
    assert config.aws_types_mapping["command_injection"] == ["TTPs/CustomExecution"]
    assert config.sarif_rules["obfuscation"]["id"] == "CORP-OBF-01"
    # Defaults retained
    assert "data_exfiltration" in config.aws_types_mapping


def test_load_audit_config_discrete_overrides_precedence(tmp_path: Path):
    cfg_file = tmp_path / "skills-security.json"
    cfg_file.write_text(
        json.dumps(
            {
                "prompt_path": "prompts/base.md",
                "finding_levels": {"sarif_levels": {"HIGH": "warning"}},
            }
        ),
        encoding="utf-8",
    )

    # Specific parameter override should take precedence
    config = load_audit_config(
        config_file=str(cfg_file),
        prompt_path="prompts/override.md",
        finding_levels='{"sarif_levels": {"HIGH": "error"}}',
    )
    assert config.prompt_path == "prompts/override.md"
    assert config.sarif_levels["HIGH"] == "error"
