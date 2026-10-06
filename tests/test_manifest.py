"""Manifest and registration-surface consistency."""

from __future__ import annotations

from pathlib import Path

import yaml
from scampi import settings as settings_mod

ROOT = Path(__file__).resolve().parents[1]


def _manifest():
    with open(ROOT / "plugin.yaml", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def test_manifest_identity():
    manifest = _manifest()
    assert manifest["manifest_version"] == 2
    assert manifest["api_version"] == 1
    assert manifest["name"] == "scampi"
    assert manifest["license"] == "MIT"


def test_manifest_declares_tools_and_hooks():
    manifest = _manifest()
    assert set(manifest["provides_tools"]) == {"scampi_check", "scampi_report", "scampi_feedback"}
    assert {"pre_llm_call", "post_tool_call"} <= set(manifest["provides_hooks"])


def test_config_schema_covers_every_runtime_setting():
    manifest = _manifest()
    declared = set(manifest["config_schema"].keys())
    resolved = set(settings_mod.load().keys())
    assert resolved <= declared


def test_provider_keys_are_optional():
    manifest = _manifest()
    assert manifest.get("requires_env") in (None, [])
    optional = {entry["name"] for entry in manifest.get("optional_env", [])}
    assert {"SAFE_BROWSING_API_KEY", "URLHAUS_AUTH_KEY"} <= optional


def test_register_wires_everything():
    calls = {"tools": [], "hooks": [], "commands": [], "cli": [], "skills": [], "middleware": []}

    class FakeCtx:
        def register_tool(self, name, toolset, schema, handler):
            calls["tools"].append((name, toolset, schema["name"], callable(handler)))

        def register_hook(self, kind, handler):
            calls["hooks"].append((kind, callable(handler)))

        def register_command(self, name, handler, description="", args_hint=""):
            calls["commands"].append(name)

        def register_cli_command(self, name, help, setup_fn, handler_fn):
            calls["cli"].append((name, callable(setup_fn), callable(handler_fn)))

        def register_skill(self, name, path):
            calls["skills"].append((name, Path(path).is_file()))

        def register_middleware(self, kind, handler):
            calls["middleware"].append((kind, callable(handler)))

    import scampi

    scampi.register(FakeCtx())

    assert [tool[0] for tool in calls["tools"]] == ["scampi_check", "scampi_report", "scampi_feedback"]
    assert all(tool[1] == "scampi" for tool in calls["tools"])
    assert all(tool[2] in {"scampi_check", "scampi_report", "scampi_feedback"} for tool in calls["tools"])
    assert all(tool[3] for tool in calls["tools"])

    hook_kinds = {hook[0] for hook in calls["hooks"]}
    assert hook_kinds == {"pre_llm_call", "post_tool_call"}
    assert calls["commands"] == ["scampi"]
    assert calls["cli"][0][0] == "scampi"
    assert calls["skills"] == [("scampi", True)]
    assert calls["middleware"][0][0] == "llm_request"
