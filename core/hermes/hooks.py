"""Lifecycle hooks and middleware.

``pre_llm_call``
    Points the agent at the bundled skill when a turn looks like a scam check.
    Plugin skills are namespaced and kept out of the skill index, so without
    this the model would never learn ``scampi:scampi`` exists.
``post_tool_call``
    Audit trail for scampi tool calls — in the log and in plugin state — so
    "what did this thing actually answer?" is answerable without reading the
    model's transcript.
``on_llm_request`` (middleware)
    Strips OTPs, PINs, NIKs, and card numbers from outgoing model payloads,
    so a secret a user pasted never leaves the machine. Best-effort by
    design: it walks whatever message-shaped structure the host sends and
    only rewrites the string fields that hold conversation text.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from ..checks import redaction
from . import runtime

logger = logging.getLogger(__name__)

PLUGIN_ID = runtime.PLUGIN_ID

#: The bundled skill's namespaced id. Exported for registration and tests.
SKILL_ID = f"{PLUGIN_ID}:{PLUGIN_ID}"

_AUDIT_KEY = "run_audit"
_AUDIT_LIMIT = 50
_WATCHED_TOOLS = {"scampi_check", "scampi_report", "scampi_feedback"}

#: Phrases that make a turn a scam check. Deliberately specific: the pointer
#: is appended to every matching turn for the rest of the session, so a false
#: positive is a standing tax, not a one-off.
_TRIGGERS = (
    "scam",
    "penipuan",
    "tipu",
    "phishing",
    "cek dulu",
    "cek link",
    "cek nomor",
    "cek rekening",
    "link ini",
    "pesan ini",
    "chat ini",
    "undangan",
    "kurir",
    "paket gagal",
    "hadiah",
    "pinjol",
    "investasi",
    "otp",
    "diblokir",
    "rekening ini",
    "apk",
    "diteruskan",
    "forward",
)

_SKILL_POINTER = (
    f"[{PLUGIN_ID}] This turn looks like a scam check (Indonesian). Load the plugin's "
    f'bundled skill before answering: skill_view("{SKILL_ID}"). '
    "The verdict, reasons, and actions must come from the scampi_check tool output — "
    "never from the model's own judgement."
)

#: String fields in a provider payload that carry conversation text.
_TEXT_KEYS = frozenset({"content", "text", "prompt", "user_message"})


def on_pre_llm_call(user_message: str = "", **kwargs: Any) -> dict[str, str] | None:
    if not runtime.setting_bool("announce_skill", True):
        return None
    if not _looks_like_our_work(user_message):
        return None
    return {"context": _SKILL_POINTER}


def on_post_tool_call(
    tool_name: str = "",
    args: dict[str, Any] | None = None,
    result: str = "",
    duration_ms: int = 0,
    **kwargs: Any,
) -> None:
    if tool_name not in _WATCHED_TOOLS:
        return

    args = args or {}
    parsed = _parse(result)
    outcome = str(parsed.get("verdict") or parsed.get("status") or ("ok" if parsed.get("ok") else "error"))

    logger.info(
        "audit %s outcome=%s ok=%s duration_ms=%s",
        tool_name,
        outcome,
        parsed.get("ok"),
        duration_ms,
    )
    _append_audit(
        {
            "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "tool": tool_name,
            "outcome": outcome,
            "ok": parsed.get("ok"),
            "score": parsed.get("score"),
            "entity_type": args.get("entity_type"),
            "duration_ms": duration_ms,
        }
    )


def on_llm_request(request: Any = None, original_request: Any = None, **kwargs: Any) -> dict[str, Any] | None:
    """Middleware entry point: redact secrets before the provider call."""
    if not runtime.setting_bool("redact_before_llm", True):
        return None
    if not isinstance(request, dict):
        return None
    changed, redacted = _redact_structure(request)
    if not changed:
        return None
    return {"request": redacted, "source": PLUGIN_ID, "reason": "redact secrets before LLM"}


# --------------------------------------------------------------------------- #
# Internals
# --------------------------------------------------------------------------- #

def _looks_like_our_work(user_message: str) -> bool:
    if not user_message:
        return False
    lowered = user_message.lower()
    return any(trigger in lowered for trigger in _TRIGGERS)


def _redact_structure(obj: Any) -> tuple[bool, Any]:
    if isinstance(obj, dict):
        changed = False
        out: dict[str, Any] = {}
        for key, value in obj.items():
            if isinstance(value, str) and key in _TEXT_KEYS:
                result = redaction.redact_text(value)
                changed = changed or result.changed
                out[key] = result.text
            elif isinstance(value, (dict, list)):
                child_changed, child = _redact_structure(value)
                changed = changed or child_changed
                out[key] = child
            else:
                out[key] = value
        return changed, out

    if isinstance(obj, list):
        changed = False
        out_list = []
        for item in obj:
            if isinstance(item, (dict, list)):
                child_changed, child = _redact_structure(item)
                changed = changed or child_changed
                out_list.append(child)
            else:
                out_list.append(item)
        return changed, out_list

    return False, obj


def _parse(result: Any) -> dict[str, Any]:
    if isinstance(result, dict):
        return result
    try:
        parsed = json.loads(result or "{}")
    except (json.JSONDecodeError, TypeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _append_audit(entry: dict[str, Any]) -> None:
    try:
        history = runtime.state_get(_AUDIT_KEY, default=[])
        if not isinstance(history, list):
            history = []
        history.append(entry)
        runtime.state_set(_AUDIT_KEY, history[-_AUDIT_LIMIT:])
    except Exception:  # pragma: no cover - auditing must never break the tool loop
        logger.debug("scampi: could not persist audit entry", exc_info=True)
