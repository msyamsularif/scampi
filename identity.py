"""Resolve who is asking, for rate limits and report deduplication.

Tool handlers receive keyword context from Hermes (``task_id``, ``session_id``,
``user_task``, ...). Whether a stable platform user id is among those keywords
varies by host version and platform, so this module resolves the most stable
identity it can find, states the scope it achieved, and falls back gracefully
(per-session, then a shared anonymous bucket) instead of failing a check.

The same key drives two things: rate limiting and the reporter hash used for
"distinct reporters" counting. An older host that surfaces a better field only
changes future rows, never breaks storage.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import re
import secrets
from typing import Any, NamedTuple

from . import runtime

logger = logging.getLogger(__name__)

#: Keyword names a host may use for the platform user id, best first.
_USER_KEYS = (
    "platform_user_id",
    "sender_id",
    "from_user_id",
    "user_id",
    "user_key",
)

#: Gateway platform names that appear inside session keys
#: (e.g. ``agent:main:telegram:dm:123456789``).
_PLATFORMS = frozenset(
    {
        "telegram",
        "discord",
        "slack",
        "whatsapp",
        "signal",
        "matrix",
        "teams",
        "irc",
        "email",
        "sms",
        "ntfy",
        "wecom",
        "weixin",
        "feishu",
        "line",
    }
)

_NON_ROUTE_SEGMENTS = frozenset({"dm", "group", "channel", "topic", "main", "agent"})


class Identity(NamedTuple):
    key: str
    scope: str  # "user" | "session" | "anonymous"


def resolve(kwargs: dict[str, Any]) -> Identity:
    """Best-effort stable identity for the current tool call."""
    kwargs = kwargs or {}

    for key_name in _USER_KEYS:
        value = kwargs.get(key_name)
        if value not in (None, ""):
            return Identity(key=f"user:{value}", scope="user")

    session_key = str(kwargs.get("session_key") or "")
    parsed = _from_session_key(session_key)
    if parsed:
        return parsed

    platform = str(kwargs.get("platform") or "").strip().lower()
    session_id = str(kwargs.get("session_id") or "").strip()
    if platform and session_id:
        return Identity(key=f"{platform}:session:{session_id}", scope="session")
    if session_id:
        return Identity(key=f"session:{session_id}", scope="session")

    return Identity(key="anonymous", scope="anonymous")


def _from_session_key(session_key: str) -> Identity | None:
    if not session_key:
        return None
    segments = [seg for seg in re.split(r"[:|]", session_key) if seg]
    for index, segment in enumerate(segments):
        if segment.lower() not in _PLATFORMS:
            continue
        tail = [seg for seg in segments[index + 1 :] if seg.lower() not in _NON_ROUTE_SEGMENTS]
        if not tail:
            continue
        candidate = tail[-1]
        if re.fullmatch(r"[\w.@+-]{2,64}", candidate):
            return Identity(key=f"{segment.lower()}:{candidate}", scope="session")
    return None


# --------------------------------------------------------------------------- #
# Reporter hashing
# --------------------------------------------------------------------------- #

_SECRET_STATE_KEY = "reporter_secret"


def _secret() -> bytes:
    secret = runtime.state_get(_SECRET_STATE_KEY)
    if not isinstance(secret, str) or len(secret) < 32:
        secret = secrets.token_hex(32)
        runtime.state_set(_SECRET_STATE_KEY, secret)
    return secret.encode("utf-8")


def reporter_hash(identity_key: str) -> str:
    """Stable pseudonym for a reporter. The raw identity is never stored."""
    digest = hmac.new(_secret(), identity_key.encode("utf-8"), hashlib.sha256)
    return digest.hexdigest()[:32]
