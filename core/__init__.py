"""Scampi implementation package.

The public plugin surface stays at the repository root (``scampi``); everything
here is the implementation, grouped by concern:

- :mod:`scampi.core.checks` — the deterministic detection engine.
- :mod:`scampi.core.config` — settings resolution.
- :mod:`scampi.core.hermes` — host glue (tools, hooks, commands, runtime).
- :mod:`scampi.core.store` — SQLite persistence and community reports.
"""
