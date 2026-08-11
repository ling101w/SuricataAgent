"""固定工作流所需的运行时依赖工厂。"""

from __future__ import annotations

import os
from dataclasses import dataclass
from collections.abc import Mapping
from pathlib import Path

from dotenv import load_dotenv
from langchain_openai import ChatOpenAI


PROJECT_DIR = Path(__file__).resolve().parent
load_dotenv(PROJECT_DIR / ".env", override=False)


@dataclass(frozen=True, slots=True)
class LLMConfig:
    provider: str
    api_key: str
    base_url: str
    model: str
    temperature: float
    timeout: float
    max_retries: int


def load_llm_config(environ: Mapping[str, str] | None = None) -> LLMConfig:
    """Load explicit OpenAI-compatible settings without a remote default."""
    values = os.environ if environ is None else environ
    if _truthy(values.get("LLM_OFFLINE")):
        raise RuntimeError("LLM_OFFLINE 已启用，禁止外部模型请求")

    provider = values.get("LLM_PROVIDER", "openai_compatible").strip().casefold()
    if provider != "openai_compatible":
        raise RuntimeError("LLM_PROVIDER 当前仅支持 openai_compatible")

    api_key = _required(values, "LLM_API_KEY", "DEEPSEEK_API_KEY")
    base_url = _required(values, "LLM_BASE_URL", "DEEPSEEK_BASE_URL")
    model = _required(values, "LLM_MODEL", "DEEPSEEK_MODEL")
    temperature = _float_setting(values, "LLM_TEMPERATURE", 0.1, minimum=0.0, maximum=2.0)
    timeout = _float_setting(values, "LLM_TIMEOUT", 60.0, minimum=1.0, maximum=600.0)
    max_retries = _int_setting(values, "LLM_MAX_RETRIES", 2, minimum=0, maximum=10)
    return LLMConfig(
        provider=provider,
        api_key=api_key,
        base_url=base_url,
        model=model,
        temperature=temperature,
        timeout=timeout,
        max_retries=max_retries,
    )


def create_chat_model() -> ChatOpenAI:
    """Create the explicitly configured OpenAI-compatible chat model lazily."""
    config = load_llm_config()

    return ChatOpenAI(
        model=config.model,
        api_key=config.api_key,
        base_url=config.base_url,
        temperature=config.temperature,
        timeout=config.timeout,
        max_retries=config.max_retries,
    )


def _required(values: Mapping[str, str], name: str, legacy_name: str) -> str:
    value = values.get(name, "").strip() or values.get(legacy_name, "").strip()
    if not value:
        raise RuntimeError(f"请设置 {name}")
    return value


def _truthy(value: str | None) -> bool:
    return bool(value and value.strip().casefold() in {"1", "true", "yes", "on"})


def _float_setting(
    values: Mapping[str, str],
    name: str,
    default: float,
    *,
    minimum: float,
    maximum: float,
) -> float:
    raw = values.get(name, "").strip()
    try:
        value = float(raw) if raw else default
    except ValueError as exc:
        raise RuntimeError(f"{name} 必须是数字") from exc
    if not minimum <= value <= maximum:
        raise RuntimeError(f"{name} 必须在 {minimum} 到 {maximum} 之间")
    return value


def _int_setting(
    values: Mapping[str, str],
    name: str,
    default: int,
    *,
    minimum: int,
    maximum: int,
) -> int:
    raw = values.get(name, "").strip()
    try:
        value = int(raw) if raw else default
    except ValueError as exc:
        raise RuntimeError(f"{name} 必须是整数") from exc
    if not minimum <= value <= maximum:
        raise RuntimeError(f"{name} 必须在 {minimum} 到 {maximum} 之间")
    return value


__all__ = ["LLMConfig", "create_chat_model", "load_llm_config"]
