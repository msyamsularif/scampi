"""Scampi — Hermes plugin registration.

    register(ctx)  ->  three tools, two hooks, one middleware, one slash
                       command, one CLI command tree, one bundled skill

The bundle is the unit of installation. ``hermes plugins install`` is the only
command a user runs: the skill is registered from here rather than published
to a skills hub, so there is no second copy to install, update, or let drift.

Tools
-----
``scampi_check``
    The deterministic verdict: extraction, allowlist/typosquat checks,
    blocklists, domain age, pattern matching, community reports -> score.
``scampi_report``
    Community report submission (dedup, reporter hash, evidence refs).
``scampi_feedback``
    Verdict-accuracy feedback for curation.

Hooks
-----
``pre_llm_call``
    Points the agent at the bundled skill when a turn looks like a scam check.
``post_tool_call``
    Audit trail for scampi tool calls.
``llm_request`` middleware
    Redacts OTPs/PINs/NIKs/card numbers before payloads reach the model.

Command
-------
``/scampi status`` — service health for humans, without spending a model turn.
"""

from __future__ import annotations

import logging
from pathlib import Path

from .core.about import __version__
from .core.hermes import commands, hooks, schemas, tools

logger = logging.getLogger(__name__)

TOOLSET = "scampi"

#: In-session slash command. Shorter than the plugin id because it is typed.
COMMAND_NAME = "scampi"

#: Skills bundled with the plugin, each a directory under ``skills/`` holding
#: a ``SKILL.md``. Hermes exposes it as ``<plugin-id>:<directory-name>``.
BUNDLED_SKILLS = ("scampi",)


def register(ctx) -> None:  # noqa: ANN001 - PluginContext is host-provided
    """Wire tools, hooks, middleware, commands, and the bundled skill.

    Called exactly once at startup. Any exception here disables the plugin but
    leaves Hermes itself running.
    """
    from .core.hermes import runtime

    runtime.bind(ctx)

    ctx.register_tool(
        name="scampi_check",
        toolset=TOOLSET,
        schema=schemas.SCAMPI_CHECK,
        handler=tools.scampi_check,
    )
    ctx.register_tool(
        name="scampi_report",
        toolset=TOOLSET,
        schema=schemas.SCAMPI_REPORT,
        handler=tools.scampi_report,
    )
    ctx.register_tool(
        name="scampi_feedback",
        toolset=TOOLSET,
        schema=schemas.SCAMPI_FEEDBACK,
        handler=tools.scampi_feedback,
    )

    ctx.register_hook("pre_llm_call", hooks.on_pre_llm_call)
    ctx.register_hook("post_tool_call", hooks.on_post_tool_call)

    register_middleware = getattr(ctx, "register_middleware", None)
    if callable(register_middleware):
        try:
            register_middleware("llm_request", hooks.on_llm_request)
        except Exception:  # pragma: no cover - older host without middleware kinds
            logger.warning("scampi: llm_request middleware not registered", exc_info=True)
    else:
        logger.warning("scampi: host has no middleware support; pre-LLM redaction inactive")

    ctx.register_command(
        COMMAND_NAME,
        handler=commands.handle,
        description="Scampi: status layanan cek penipuan",
        args_hint="[status|help]",
    )

    ctx.register_cli_command(
        name=COMMAND_NAME,
        help="Scampi scam-detector utilities (status, patterns, reports, retention, eval)",
        setup_fn=commands.setup_cli,
        handler_fn=commands.handle_cli,
    )

    skills_dir = Path(__file__).resolve().parent / "skills"
    for name in BUNDLED_SKILLS:
        skill_md = skills_dir / name / "SKILL.md"
        if skill_md.exists():
            ctx.register_skill(name, skill_md)
        else:
            logger.warning("scampi: bundled skill %s missing at %s", name, skill_md)

    logger.info(
        "scampi %s ready (tools: scampi_check, scampi_report, scampi_feedback; skill: %s; command: /%s)",
        __version__,
        hooks.SKILL_ID,
        COMMAND_NAME,
    )
