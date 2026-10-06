"""Read the plugin's settings block from Hermes' ``config.yaml`` without the host.

Inside Hermes the host resolves ``plugins.entries.<id>.settings`` for us. The
fallback path (unit tests, CLI runs outside a session) has no ``ctx``, so this
module reads the same file directly — the settings a lint uses must be the
settings the tool it predicts would use.

The file is parsed as data only. Nothing in it is executed or treated as
instructions.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def config_path() -> Path:
    """Hermes' config.yaml, honouring ``$HERMES_HOME`` like the host does."""
    home = os.environ.get("HERMES_HOME", "").strip()
    base = Path(home) if home else Path.home() / ".hermes"
    return base / "config.yaml"


@dataclass
class ConfigFile:
    path: Path
    found: bool = False
    settings: dict[str, Any] = field(default_factory=dict)
    warning: str = ""


def load(plugin_id: str, path: Path | None = None) -> ConfigFile:
    """Load ``plugins.entries.<plugin_id>.settings`` from ``path``.

    Never raises. A missing file is normal (``found=False``, no warning); a
    file that exists but cannot be used sets ``warning`` so callers can say so
    instead of silently running on defaults.
    """
    resolved = Path(path) if path else config_path()
    result = ConfigFile(path=resolved)

    try:
        text = resolved.read_text(encoding="utf-8")
    except FileNotFoundError:
        return result
    except OSError as exc:
        result.warning = (
            f"config.yaml unreadable ({exc.__class__.__name__}); plugin defaults in use"
        )
        return result

    result.found = True
    data = _parse_yaml(text)
    if data is None:
        result.warning = (
            "config.yaml could not be parsed (missing PyYAML or invalid YAML); "
            "plugin defaults in use"
        )
        return result

    settings = _dig(plugin_id, data)
    if settings is None:
        result.warning = (
            f"plugins.entries.{plugin_id}.settings is not a mapping; plugin defaults in use"
        )
        return result

    result.settings = settings
    return result


def _parse_yaml(text: str) -> dict[str, Any] | None:
    try:
        import yaml  # type: ignore
    except ImportError:  # pragma: no cover - PyYAML ships via pyproject
        logger.debug("PyYAML unavailable; cannot read config.yaml")
        return None
    try:
        data = yaml.safe_load(text)
    except Exception:
        logger.debug("config.yaml failed to parse", exc_info=True)
        return None
    return data if isinstance(data, dict) else None


def _dig(plugin_id: str, data: dict[str, Any]) -> dict[str, Any] | None:
    node: Any = data
    for key in ("plugins", "entries", plugin_id, "settings"):
        if not isinstance(node, dict) or key not in node:
            return {}
        node = node[key]
    return node if isinstance(node, dict) else None
