"""固定工作流所需的运行时依赖工厂。"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv
from langchain_openai import ChatOpenAI


PROJECT_DIR = Path(__file__).resolve().parent
load_dotenv(PROJECT_DIR / ".env", override=False)


def create_chat_model() -> ChatOpenAI:
    """延迟创建兼容 OpenAI 接口的 DeepSeek 对话模型。"""
    api_key = os.getenv("DEEPSEEK_API_KEY")
    if not api_key:
        raise RuntimeError("请先设置 DEEPSEEK_API_KEY")

    return ChatOpenAI(
        model=os.getenv("DEEPSEEK_MODEL", "gpt-5.5"),
        api_key=api_key,
        base_url=os.getenv("DEEPSEEK_BASE_URL", "https://api.wushuang233.com/v1"),
        temperature=0.1,
        timeout=60,
        max_retries=2,
    )
