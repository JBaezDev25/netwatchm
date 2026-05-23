"""Thin Ollama /api/chat client with tool-calling support.

Uses stdlib urllib only (no new dependency). Ollama serves a local HTTP API
at http://127.0.0.1:11434 by default. Models like qwen3:14b, gpt-oss, and
llama3.1 support native tool calling through this endpoint.
"""
from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("netwatchm.agent.llm")


@dataclass
class LlmResponse:
    content: str
    tool_calls: list[dict] = field(default_factory=list)
    raw: dict = field(default_factory=dict)


class OllamaClient:
    def __init__(
        self,
        *,
        base_url: str = "http://127.0.0.1:11434",
        model: str = "qwen3:14b",
        timeout: int = 120,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout

    def chat(
        self,
        *,
        messages: list[dict],
        tools: list[dict] | None = None,
        temperature: float = 0.2,
        max_tokens: int = 512,
        think: bool = False,
    ) -> LlmResponse:
        """Send a chat completion request. Synchronous — call from a thread
        if used inside an asyncio loop.

        ``think`` defaults to False to disable the reasoning-trace mode used
        by Qwen3 / DeepSeek-R1 / etc — without this, those models pour all
        their output into a separate ``thinking`` field and leave ``content``
        empty, which makes them appear to hang from the caller's perspective.
        ``max_tokens`` caps generation to keep per-tick latency bounded on CPU.
        """
        body: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "think": think,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }
        if tools:
            body["tools"] = tools

        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}/api/chat",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
            payload = json.loads(resp.read().decode("utf-8"))

        msg = payload.get("message", {}) or {}
        return LlmResponse(
            content=str(msg.get("content") or ""),
            tool_calls=list(msg.get("tool_calls") or []),
            raw=payload,
        )
