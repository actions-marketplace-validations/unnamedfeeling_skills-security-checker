"""Exporters package for converting security audit findings into industry-standard schemas."""

from pathlib import Path
from typing import Any

from src.exporters.aws import AwsSecurityHubExporter
from src.exporters.base import BaseExporter, ExporterRegistry
from src.exporters.sarif import SarifExporter
from src.models import AuditSummary


def export_findings(
    summary: AuditSummary,
    format_name: str,
    output_path: str | Path,
    **kwargs: Any,
) -> Path:
    """Exports audit findings using the specified format to a target file path."""
    exporter = ExporterRegistry.get(format_name, **kwargs)
    return exporter.export_to_file(summary, output_path)


__all__ = [
    "BaseExporter",
    "ExporterRegistry",
    "SarifExporter",
    "AwsSecurityHubExporter",
    "export_findings",
]
