"""Slash status and operator CLI."""

from __future__ import annotations

import argparse

from scampi import commands


def test_status_text_mentions_health_and_counts():
    text = commands.status_text()
    assert "Scampi" in text
    assert "Pola penipuan aktif" in text
    assert "Google Safe Browsing" in text


def test_slash_command_default_and_help():
    assert "Scampi" in commands.handle("")
    assert "Perintah" in commands.handle("bogus")
    assert "Perintah" in commands.handle("help")


def test_patterns_validate_all_shipped(capsys):
    assert commands._patterns_validate() == 0
    out = capsys.readouterr().out
    assert "pola valid" in out


def test_patterns_list(capsys):
    assert commands._patterns_cli("list") == 0
    out = capsys.readouterr().out
    assert "undangan-pernikahan-apk" in out


def test_reports_cli_empty(capsys):
    args = argparse.Namespace(scampi_command="reports", reports_command="list", status=None, limit=5)
    assert commands.handle_cli(args) == 0
    assert "Tidak ada laporan" in capsys.readouterr().out


def test_retention_purge(capsys):
    args = argparse.Namespace(scampi_command="retention", retention_command="purge", days=30)
    assert commands.handle_cli(args) == 0
    assert "Purge" in capsys.readouterr().out


def test_eval_cli_runs_offline(capsys, corpus_dir):
    args = argparse.Namespace(
        scampi_command="eval",
        eval_command="run",
        dataset=str(corpus_dir / "legit_messages.jsonl"),
        limit=5,
        network=False,
    )
    assert commands.handle_cli(args) == 0
    out = capsys.readouterr().out
    assert "Scampi eval" in out
    assert "False positives" in out


def test_unknown_subcommand():
    assert commands.handle_cli(argparse.Namespace()) == 1
