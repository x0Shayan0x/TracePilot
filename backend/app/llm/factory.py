import os

from app.llm.base import LLMProvider
from app.llm.mock_provider import MockProvider
from app.llm.openai_provider import OpenAIProvider
from app.llm.gemini_provider import GeminiProvider

def create_llm_provider() -> LLMProvider:
    provider = os.getenv(
        "LLM_PROVIDER",
        "mock",
    ).strip().lower()
    
    if provider == "gemini":
        return GeminiProvider()

    if provider_name == "mock":
        return MockProvider()

    if provider_name == "openai":
        return OpenAIProvider()

    raise ValueError(
        f"Unsupported LLM provider: {provider_name}"
    )
