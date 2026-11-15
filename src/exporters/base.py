from __future__ import annotations

import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, ClassVar, Dict, List, Type

from src.models import AuditSummary


class BaseExporter(ABC):
    """Abstract base class for security findings exporters."""

    format_name: ClassVar[str]

    @abstractmethod
    def export(self, summary: AuditSummary) -> Dict[str, Any]:
        """Convert the audit summary into the target schema structure."""
        pass

    def export_to_file(self, summary: AuditSummary, output_path: str | Path) -> Path:
        """Serializes the export data as JSON to a file on disk."""
        data = self.export(summary)
        path = Path(output_path).resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return path


class ExporterRegistry:
    """Registry allowing dynamic discovery, registration, and extension of exporters."""

    _registry: Dict[str, Type[BaseExporter]] = {}

    @classmethod
    def register(cls, exporter_cls: Type[BaseExporter]) -> Type[BaseExporter]:
        """Decorator or class method to register an exporter implementation."""
        if not hasattr(exporter_cls, "format_name") or not exporter_cls.format_name:
            raise ValueError(f"Exporter class {exporter_cls.__name__} must define a 'format_name'.")
        cls._registry[exporter_cls.format_name.lower()] = exporter_cls
        return exporter_cls

    @classmethod
    def get(cls, format_name: str, **kwargs: Any) -> BaseExporter:
        """Instantiates an exporter by its registered format name."""
        key = format_name.strip().lower()
        if key not in cls._registry:
            supported = ", ".join(sorted(cls._registry.keys()))
            raise ValueError(
                f"Unsupported export format '{format_name}'. Available formats: {supported}"
            )
        return cls._registry[key](**kwargs)

    @classmethod
    def available_formats(cls) -> List[str]:
        """Returns all registered format names."""
        return sorted(list(cls._registry.keys()))
