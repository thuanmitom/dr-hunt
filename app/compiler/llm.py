"""Provider abstraction. Gemini is the default; anything implementing ``LLMProvider`` works
(a local model for air-gapped use, or a fake in tests)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class LLMResult:
    text: str
    model: str
    prompt_tokens: int = 0
    output_tokens: int = 0


class LLMProvider(Protocol):
    name: str
    model: str

    async def generate_json(self, *, system: str, user: str, json_schema: dict) -> LLMResult: ...


class GeminiProvider:
    name = "gemini"

    def __init__(self, api_key: str, model: str, *, max_output_tokens: int = 8192) -> None:
        from google import genai

        self._client = genai.Client(api_key=api_key)
        self.model = model
        self._max_out = max_output_tokens

    async def generate_json(self, *, system: str, user: str, json_schema: dict) -> LLMResult:
        from google.genai import types

        response = await self._client.aio.models.generate_content(
            model=self.model,
            contents=user,
            config=types.GenerateContentConfig(
                system_instruction=system,
                response_mime_type="application/json",
                response_json_schema=json_schema,
                temperature=0.0,
                max_output_tokens=self._max_out,
            ),
        )
        usage = response.usage_metadata
        return LLMResult(
            text=response.text or "",
            model=response.model_version or self.model,
            prompt_tokens=(usage.prompt_token_count or 0) if usage else 0,
            output_tokens=(usage.candidates_token_count or 0) if usage else 0,
        )
