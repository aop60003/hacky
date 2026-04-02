"""Tests for LLMClient and supporting types (no litellm/network required)."""
from __future__ import annotations

import pytest
from vibee_hacker.llm.llm import LLM, LLMResponse, RequestStats
from vibee_hacker.llm.config import LLMConfig


def make_unconfigured_llm() -> LLM:
    config = LLMConfig(model_name="")
    return LLM(config)


def make_configured_llm(model: str = "gpt-4o") -> LLM:
    config = LLMConfig(model_name=model, api_key="sk-test-dummy")
    # Patch compressor init to avoid any side effects
    from unittest.mock import patch
    with patch.object(LLM, '_init_compressor'):
        llm = LLM(config)
        llm._compressor = None
    return llm


def test_llm_unavailable_when_not_configured():
    llm = make_unconfigured_llm()
    assert llm.is_available is False


def test_llm_unavailable_when_litellm_missing(monkeypatch):
    import sys
    # Temporarily block litellm import
    original = sys.modules.get("litellm")
    sys.modules["litellm"] = None  # type: ignore
    try:
        llm = make_configured_llm()
        assert llm.is_available is False
    finally:
        if original is None:
            del sys.modules["litellm"]
        else:
            sys.modules["litellm"] = original


def test_set_system_prompt():
    llm = make_unconfigured_llm()
    assert llm._system_prompt is None
    llm.set_system_prompt("You are a pentester.")
    assert llm._system_prompt == "You are a pentester."


def test_request_stats_initialization():
    stats = RequestStats()
    assert stats.input_tokens == 0
    assert stats.output_tokens == 0
    assert stats.cached_tokens == 0
    assert stats.cost == 0.0
    assert stats.requests == 0


def test_request_stats_accumulation():
    stats = RequestStats()
    other = RequestStats(input_tokens=100, output_tokens=50, cost=0.002, requests=1)
    stats.add(other)
    assert stats.input_tokens == 100
    assert stats.output_tokens == 50
    assert stats.cost == pytest.approx(0.002)
    assert stats.requests == 1

    stats.add(other)
    assert stats.input_tokens == 200
    assert stats.requests == 2


def test_request_stats_to_summary():
    stats = RequestStats(input_tokens=500, output_tokens=200, cost=0.005, requests=2)
    summary = stats.to_summary()
    assert "$" in summary
    assert "2 requests" in summary
    assert "700 tokens" in summary


def test_llm_response_model():
    resp = LLMResponse(content="hello", finished=True)
    assert resp.content == "hello"
    assert resp.finished is True
    assert resp.thinking_blocks is None


def test_should_retry_rate_limit():
    assert LLM._should_retry(Exception("rate_limit exceeded")) is True
    assert LLM._should_retry(Exception("429 Too Many Requests")) is True
    assert LLM._should_retry(Exception("overloaded")) is True


def test_should_retry_non_retryable():
    import asyncio
    assert LLM._should_retry(asyncio.TimeoutError()) is False
    assert LLM._should_retry(ValueError("bad input")) is False


def test_is_anthropic_model():
    llm = make_configured_llm("claude-3-5-sonnet-20241022")
    assert llm._is_anthropic_model() is True

    llm2 = make_configured_llm("gpt-4o")
    assert llm2._is_anthropic_model() is False


def test_get_chunk_content_missing_attr():
    # Should not raise, should return empty string
    result = LLM._get_chunk_content(object())
    assert result == ""
