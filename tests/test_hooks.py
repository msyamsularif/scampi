"""Skill pointer, audit trail, and pre-LLM redaction middleware."""

from __future__ import annotations

from scampi import hooks, runtime


def test_trigger_detection():
    assert hooks._looks_like_our_work("cek dong ini penipuan bukan?")
    assert hooks._looks_like_our_work("link ini diteruskan dari mama")
    assert not hooks._looks_like_our_work("halo apa kabar")


def test_pre_llm_call_injects_skill_pointer():
    result = hooks.on_pre_llm_call(user_message="link ini scam ya?")
    assert result is not None
    assert "scampi:scampi" in result["context"]
    assert hooks.on_pre_llm_call(user_message="halo") is None


def test_pre_llm_call_disabled_by_setting(monkeypatch):
    monkeypatch.setenv("SCAMPI_ANNOUNCE_SKILL", "false")
    assert hooks.on_pre_llm_call(user_message="ini scam") is None


def test_audit_trail_only_watches_own_tools():
    hooks.on_post_tool_call(
        tool_name="scampi_check",
        args={"text": "x"},
        result='{"ok": true, "verdict": "caution", "score": 4.0}',
        duration_ms=12,
    )
    hooks.on_post_tool_call(tool_name="other_tool", args={}, result="{}")
    audit = runtime.state_get("run_audit", default=[])
    assert len(audit) == 1
    assert audit[0]["tool"] == "scampi_check"
    assert audit[0]["outcome"] == "caution"


def test_llm_request_redacts_string_content():
    request = {"messages": [{"role": "user", "content": "kode otp saya 445566"}]}
    result = hooks.on_llm_request(request=request)
    assert result is not None
    assert result["request"]["messages"][0]["content"] == "kode otp saya [REDACTED_OTP]"


def test_llm_request_redacts_block_content():
    request = {"messages": [{"role": "user", "content": [{"type": "text", "text": "otp 112233"}]}]}
    result = hooks.on_llm_request(request=request)
    assert result is not None
    assert "112233" not in result["request"]["messages"][0]["content"][0]["text"]


def test_llm_request_no_change_returns_none():
    request = {"messages": [{"role": "user", "content": "halo"}]}
    assert hooks.on_llm_request(request=request) is None
    assert hooks.on_llm_request(request="not a dict") is None


def test_llm_request_disabled_by_setting(monkeypatch):
    monkeypatch.setenv("SCAMPI_REDACT_BEFORE_LLM", "false")
    request = {"messages": [{"role": "user", "content": "kode otp saya 445566"}]}
    assert hooks.on_llm_request(request=request) is None
