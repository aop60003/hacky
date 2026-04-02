"""LLM client with streaming, retry logic, and cost tracking.

Follows Strix's LLM pattern using litellm for multi-provider support.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, AsyncIterator, Dict, List, Optional

from pydantic import BaseModel

from vibee_hacker.llm.config import LLMConfig

logger = logging.getLogger(__name__)


class LLMResponse(BaseModel):
    """Response from LLM generation."""
    content: str = ""
    finished: bool = False
    thinking_blocks: Optional[List[Dict[str, Any]]] = None


class RequestStats(BaseModel):
    """Token usage and cost tracking."""
    input_tokens: int = 0
    output_tokens: int = 0
    cached_tokens: int = 0
    cost: float = 0.0
    requests: int = 0

    def add(self, other: "RequestStats") -> None:
        """Accumulate stats from another request."""
        self.input_tokens += other.input_tokens
        self.output_tokens += other.output_tokens
        self.cached_tokens += other.cached_tokens
        self.cost += other.cost
        self.requests += other.requests

    def to_summary(self) -> str:
        """Human-readable summary."""
        return (
            f"LLM cost: ${self.cost:.4f} "
            f"({self.requests} requests, "
            f"{self.input_tokens + self.output_tokens} tokens)"
        )


class LLM:
    """LLM client with streaming and retry support.

    Uses litellm for multi-provider compatibility (OpenAI, Anthropic, Google, etc.).
    """

    def __init__(self, config: LLMConfig):
        self.config = config
        self.stats = RequestStats()
        self._system_prompt: Optional[str] = None
        self._compressor: Optional[Any] = None
        self._init_compressor()

    def _init_compressor(self) -> None:
        """Initialize memory compressor if LLM is configured."""
        if self.config.is_configured:
            from vibee_hacker.llm.memory_compressor import MemoryCompressor
            self._compressor = MemoryCompressor(
                model_name=self.config.model_name,
                api_key=self.config.api_key,
                api_base=self.config.api_base,
            )

    @property
    def is_available(self) -> bool:
        """Check if LLM is configured and litellm is installed."""
        if not self.config.is_configured:
            return False
        try:
            import litellm  # noqa: F401
            return True
        except ImportError:
            return False

    def set_system_prompt(self, prompt: str) -> None:
        """Set the system prompt for all subsequent calls."""
        self._system_prompt = prompt

    async def generate(
        self,
        messages: List[Dict[str, Any]],
        temperature: float = 0.3,
        max_tokens: int = 4096,
    ) -> AsyncIterator[LLMResponse]:
        """Stream LLM responses with retry logic.

        Yields LLMResponse objects as chunks arrive.
        The final response has finished=True.
        """
        try:
            from litellm import acompletion, completion_cost
        except ImportError:
            logger.error("litellm not installed. Run: pip install litellm")
            yield LLMResponse(content="Error: litellm not installed", finished=True)
            return

        # Build messages with optional system prompt
        full_messages: List[Dict[str, Any]] = []
        if self._system_prompt:
            sys_msg: Dict[str, Any] = {"role": "system", "content": self._system_prompt}
            # Anthropic prompt caching
            if self._is_anthropic_model():
                sys_msg["cache_control"] = {"type": "ephemeral"}
            full_messages.append(sys_msg)
        full_messages.extend(messages)

        # Memory compression: condense history if exceeding token limits
        if self._compressor and len(full_messages) > 20:
            full_messages = self._compressor.compress(full_messages)

        # Build completion kwargs
        kwargs = self.config.to_litellm_kwargs()
        kwargs["messages"] = full_messages
        kwargs["temperature"] = temperature
        kwargs["max_tokens"] = max_tokens

        # Reasoning model support
        if self.config.reasoning_effort and self._supports_reasoning():
            kwargs["reasoning_effort"] = self.config.reasoning_effort

        max_retries = self.config.max_retries
        for attempt in range(max_retries + 1):
            try:
                accumulated = ""
                chunks: List[Any] = []

                response = await acompletion(**kwargs)

                async for chunk in response:
                    chunks.append(chunk)
                    delta = self._get_chunk_content(chunk)
                    if delta:
                        accumulated += delta
                        yield LLMResponse(content=accumulated)

                # Track usage
                self._track_usage(chunks)
                self.stats.requests += 1

                thinking = self._extract_thinking(chunks)
                yield LLMResponse(
                    content=accumulated,
                    finished=True,
                    thinking_blocks=thinking if thinking else None,
                )
                return

            except Exception as e:
                if attempt >= max_retries or not self._should_retry(e):
                    logger.error("LLM generation failed: %s", e)
                    yield LLMResponse(
                        content=f"Error: {e}", finished=True
                    )
                    return
                wait = min(90, 2 * (2 ** attempt))
                logger.warning(
                    "LLM request failed (attempt %d/%d), retrying in %ds: %s",
                    attempt + 1, max_retries, wait, e,
                )
                await asyncio.sleep(wait)

    async def complete(
        self,
        prompt: str,
        temperature: float = 0.3,
        max_tokens: int = 4096,
    ) -> str:
        """Simple completion: send prompt, get full response string."""
        messages = [{"role": "user", "content": prompt}]
        result = ""
        async for response in self.generate(messages, temperature, max_tokens):
            if response.finished:
                result = response.content
        return result

    @staticmethod
    def _get_chunk_content(chunk: Any) -> str:
        """Extract text content from a streaming chunk."""
        try:
            choices = getattr(chunk, "choices", None)
            if choices and len(choices) > 0:
                delta = getattr(choices[0], "delta", None)
                if delta:
                    return getattr(delta, "content", "") or ""
        except (AttributeError, IndexError):
            pass
        return ""

    def _track_usage(self, chunks: List[Any]) -> None:
        """Track token usage from response chunks."""
        if not chunks:
            return

        # Get usage from last chunk with usage info
        for chunk in reversed(chunks):
            usage = getattr(chunk, "usage", None)
            if usage:
                self.stats.input_tokens += getattr(usage, "prompt_tokens", 0)
                self.stats.output_tokens += getattr(usage, "completion_tokens", 0)
                break

        # Try to calculate cost via litellm
        try:
            from litellm import completion_cost
            cost = completion_cost(completion_response=chunks[-1])
            self.stats.cost += cost
        except Exception:
            pass

    @staticmethod
    def _should_retry(error: Exception) -> bool:
        """Determine if an error is retryable (API-level, not local errors)."""
        if isinstance(error, (asyncio.TimeoutError, asyncio.CancelledError)):
            return False
        error_str = str(error).lower()
        retryable = ["rate_limit", "ratelimit", "overloaded", "503", "529", "429"]
        return any(keyword in error_str for keyword in retryable)

    def _is_anthropic_model(self) -> bool:
        """Check if current model is Anthropic (for prompt caching)."""
        model = self.config.model_name.lower()
        return any(k in model for k in ("claude", "anthropic"))

    def _supports_reasoning(self) -> bool:
        """Check if current model supports reasoning/thinking."""
        model = self.config.model_name.lower()
        return any(k in model for k in ("o1", "o3", "claude-3-5", "claude-sonnet-4", "claude-opus"))

    @staticmethod
    def _extract_thinking(chunks: List[Any]) -> List[Dict[str, Any]]:
        """Extract thinking/reasoning blocks from response chunks."""
        thinking_blocks: List[Dict[str, Any]] = []
        current_thinking = ""
        in_thinking = False

        for chunk in chunks:
            choices = getattr(chunk, "choices", None)
            if not choices:
                continue
            delta = getattr(choices[0], "delta", None)
            if not delta:
                continue

            # Check for thinking content (Anthropic extended thinking)
            thinking_content = getattr(delta, "reasoning_content", None)
            if thinking_content:
                in_thinking = True
                current_thinking += thinking_content
            elif in_thinking and getattr(delta, "content", None):
                # Transition from thinking to content
                if current_thinking:
                    thinking_blocks.append({
                        "type": "thinking",
                        "content": current_thinking,
                    })
                    current_thinking = ""
                in_thinking = False

        # Capture any remaining thinking
        if current_thinking:
            thinking_blocks.append({
                "type": "thinking",
                "content": current_thinking,
            })

        return thinking_blocks
