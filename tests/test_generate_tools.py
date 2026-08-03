from __future__ import annotations

import pytest
from fastapi import Response

import generate_tools
import web_app


def test_llm_config_requires_explicit_remote_endpoint() -> None:
    with pytest.raises(RuntimeError, match="LLM_BASE_URL"):
        generate_tools.load_llm_config(
            {
                "LLM_API_KEY": "secret",
                "LLM_MODEL": "test-model",
            }
        )


def test_llm_config_uses_generic_openai_compatible_settings() -> None:
    config = generate_tools.load_llm_config(
        {
            "LLM_PROVIDER": "openai_compatible",
            "LLM_API_KEY": "secret",
            "LLM_BASE_URL": "https://llm.example.test/v1",
            "LLM_MODEL": "test-model",
            "LLM_TEMPERATURE": "0.2",
            "LLM_TIMEOUT": "90",
            "LLM_MAX_RETRIES": "4",
        }
    )

    assert config.base_url == "https://llm.example.test/v1"
    assert config.model == "test-model"
    assert config.temperature == 0.2
    assert config.timeout == 90
    assert config.max_retries == 4


def test_llm_offline_blocks_model_configuration() -> None:
    with pytest.raises(RuntimeError, match="禁止外部模型请求"):
        generate_tools.load_llm_config({"LLM_OFFLINE": "true"})


def test_legacy_deepseek_variables_remain_migration_aliases() -> None:
    config = generate_tools.load_llm_config(
        {
            "DEEPSEEK_API_KEY": "legacy-secret",
            "DEEPSEEK_BASE_URL": "https://legacy.example.test/v1",
            "DEEPSEEK_MODEL": "legacy-model",
        }
    )

    assert config.api_key == "legacy-secret"
    assert config.base_url == "https://legacy.example.test/v1"
    assert config.model == "legacy-model"


def test_web_runtime_reports_sanitized_generic_model_configuration(
    monkeypatch,
) -> None:
    monkeypatch.setenv("LLM_API_KEY", "must-not-be-returned")
    monkeypatch.setenv("LLM_BASE_URL", "https://llm.example.test/v1")
    monkeypatch.setenv("LLM_MODEL", "test-model")
    monkeypatch.setattr(
        web_app,
        "check_suricata_runtime",
        lambda: {
            "ok": True,
            "error_code": None,
            "message": None,
        },
    )

    result = web_app.runtime_status(Response())

    assert result["model"] == {
        "configured": True,
        "provider": "openai_compatible",
        "endpoint_host": "llm.example.test",
        "name": "test-model",
        "offline": False,
    }
    assert "must-not-be-returned" not in str(result)
