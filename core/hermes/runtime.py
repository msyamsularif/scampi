"""Plugin-scoped runtime access: settings, durable state, and the host context.

Hermes hands ``register(ctx)`` a ``PluginContext`` once at startup, but tool
handlers and hook callbacks only receive ``(args, **kwargs)``. This module is
the single place that bridges the two, and it degrades gracefully when used
outside Hermes (unit tests, CLI scripts) by reading the same settings from the
profile's ``config.yaml`` and keeping state in a fallback directory.

Resolution order for a setting: host (``ctx.get_config``) -> ``config.yaml``
-> ``SCAMPI_<KEY>`` environment variable -> default.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import threading
from pathlib import Path
from typing import Any

from ..config import config_file

logger = logging.getLogger(__name__)

#: The plugin's own id — the manifest's ``name``, the install directory, and
#: the name this plugin's data is filed under. One literal, defined here.
PLUGIN_ID = "scampi"

_lock = threading.RLock()
_ctx: Any = None

#: Last ``config.yaml`` read, keyed by ``(path, mtime_ns, size)`` so a tool call
#: resolving ~15 settings does not re-read the file 15 times.
_config_file_cache: Any | None = None


def bind(ctx: Any) -> None:
    """Remember the host plugin context. Called once from ``register(ctx)``."""
    global _ctx
    with _lock:
        _ctx = ctx


def context() -> Any:
    """The bound ``PluginContext``, or ``None`` when running outside Hermes."""
    return _ctx


def has_context() -> bool:
    return _ctx is not None


# --------------------------------------------------------------------------- #
# Paths (fallback when the host provides no data root)
# --------------------------------------------------------------------------- #

def fallback_root() -> Path:
    """Where dev/test runs keep state when Hermes' storage helpers are absent."""
    env = os.environ.get("SCAMPI_HOME", "").strip()
    return Path(env) if env else Path.home() / ".scampi"


def data_dir() -> Path:
    """The profile-scoped data root for this plugin.

    Inside Hermes this is ``<HERMES_HOME>/plugin-data/scampi`` (managed by the
    host and preserved across plugin updates). Outside it, the fallback root.
    """
    try:
        from plugins.plugin_storage import plugin_data_dir  # type: ignore

        resolved = Path(plugin_data_dir(PLUGIN_ID))
        if str(resolved):
            return resolved
    except Exception:  # pragma: no cover - host helper not importable
        logger.debug("plugin_storage unavailable; using fallback data root", exc_info=True)
    return fallback_root()


def db_path() -> Path:
    """Path of the plugin's SQLite database (``SCAMPI_DB_PATH`` wins in tests)."""
    env = os.environ.get("SCAMPI_DB_PATH", "").strip()
    if env:
        return Path(env)
    return data_dir() / "scampi.db"


def evidence_dir() -> Path:
    """Directory holding report evidence references' files, when any exist."""
    return data_dir() / "evidence"


# --------------------------------------------------------------------------- #
# Settings
# --------------------------------------------------------------------------- #

def get_setting(key: str, default: Any = None) -> Any:
    """Read a plugin setting, tolerating any host-side failure.

    Resolution: ``plugins.entries.<id>.settings.<key>`` (via ``ctx.get_config``
    inside Hermes, or read from ``config.yaml`` when there is no host context)
    -> environment variable -> ``default``.
    """
    ctx = _ctx
    if ctx is not None:
        try:
            value = ctx.get_config(key, default=None)
        except Exception:  # pragma: no cover - defensive
            logger.debug("ctx.get_config(%r) failed", key, exc_info=True)
            value = None
        if value not in (None, "", [], {}):
            return value

    value = config_file_settings().get(key)
    if value not in (None, "", [], {}):
        return value

    env_key = f"SCAMPI_{key.upper().replace('.', '_')}"
    env_value = os.environ.get(env_key, "")
    if env_value != "":
        return env_value
    return default


def setting_bool(key: str, default: bool) -> bool:
    value = get_setting(key)
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on", "y"}
    return bool(value)


def setting_int(key: str, default: int) -> int:
    value = get_setting(key)
    if value is None or value == "":
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        logger.warning("scampi: setting %r is not an integer (%r); using %s", key, value, default)
        return default


def setting_float(key: str, default: float) -> float:
    value = get_setting(key)
    if value is None or value == "":
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        logger.warning("scampi: setting %r is not a number (%r); using %s", key, value, default)
        return default


# --------------------------------------------------------------------------- #
# Durable state (audit trail, secrets that must survive restarts)
# --------------------------------------------------------------------------- #

_STATE_FILE = "state.json"


def _state_path() -> Path:
    return fallback_root() / _STATE_FILE


def state_get(key: str, default: Any = None) -> Any:
    ctx = _ctx
    if ctx is not None:
        try:
            return ctx.state.get(key, default=default)
        except TypeError:  # pragma: no cover - older host signature
            try:
                return ctx.state.get(key)
            except Exception:
                logger.debug("ctx.state.get(%r) failed", key, exc_info=True)
        except Exception:  # pragma: no cover - defensive
            logger.debug("ctx.state.get(%r) failed", key, exc_info=True)
    return _read_state_file().get(key, default)


def state_set(key: str, value: Any) -> None:
    ctx = _ctx
    if ctx is not None:
        try:
            ctx.state.set(key, value)
            return
        except Exception:  # pragma: no cover - defensive
            logger.debug("ctx.state.set(%r) failed", key, exc_info=True)
    with _lock:
        data = _read_state_file()
        data[key] = value
        _write_state_file(data)


def _read_state_file() -> dict[str, Any]:
    path = _state_path()
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return {}
    except (OSError, json.JSONDecodeError):
        logger.warning("scampi: state file %s is unreadable; starting fresh", path)
        with contextlib.suppress(OSError):
            path.replace(path.with_suffix(".json.bad"))
        return {}
    return data if isinstance(data, dict) else {}


def _write_state_file(data: dict[str, Any]) -> None:
    path = _state_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
        os.replace(tmp, path)
    except OSError:  # pragma: no cover - disk failure
        logger.warning("scampi: could not persist plugin state to %s", path, exc_info=True)


# --------------------------------------------------------------------------- #
# config.yaml fallback reading (cached until the file changes)
# --------------------------------------------------------------------------- #

def _read_config_file() -> config_file.ConfigFile:
    global _config_file_cache

    path = config_file.config_path()
    try:
        stat = path.stat()
        stamp = (str(path), stat.st_mtime_ns, stat.st_size)
    except OSError:
        with _lock:
            _config_file_cache = None
        return config_file.ConfigFile(path=path)

    with _lock:
        if _config_file_cache is not None and _config_file_cache[0] == stamp:
            return _config_file_cache[1]
        result = config_file.load(PLUGIN_ID, path=path)
        _config_file_cache = (stamp, result)
    if result.warning:
        logger.warning("scampi settings: %s", result.warning)
    return result


def config_file_settings() -> dict[str, Any]:
    """``plugins.entries.<id>.settings`` from Hermes' ``config.yaml``."""
    return dict(_read_config_file().settings)


def settings_source() -> dict[str, Any]:
    """Where settings are coming from, for the status command."""
    path = config_file.config_path()
    if _ctx is not None:
        return {"source": "host", "path": str(path), "warning": ""}
    result = _read_config_file()
    if not result.found:
        return {"source": "defaults", "path": str(path), "warning": ""}
    return {
        "source": "config_file" if not result.warning else "defaults",
        "path": str(path),
        "settings": len(result.settings),
        "warning": result.warning,
    }
