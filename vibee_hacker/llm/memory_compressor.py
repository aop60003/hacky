"""Memory compressor for LLM conversation history.

Condenses older messages into summaries to stay within token limits
while preserving security-critical context. Follows Strix's pattern.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

MAX_TOTAL_TOKENS = 100_000
MIN_RECENT_MESSAGES = 15

SUMMARY_PROMPT = """You are performing context condensation for a security scanning agent.
Compress the following conversation while preserving ALL operationally critical information.

PRESERVE:
- Discovered vulnerabilities and attack vectors
- Scan results with key findings (URLs, paths, parameters, payloads)
- Authentication details, tokens, credentials found
- System architecture insights and weak points
- Failed attempts and dead ends (to avoid re-testing)
- Decisions made about testing approach
- Exact error messages indicating vulnerabilities

COMPRESS:
- Verbose tool outputs → key findings only
- Repetitive similar findings → consolidated form
- Routine status updates → progress summary

CONVERSATION TO SUMMARIZE:
{conversation}

Provide a technically precise summary preserving all operational security context."""


def _estimate_tokens(text: str, model: Optional[str] = None) -> int:
    """Estimate token count. Uses litellm if available, else rough estimate."""
    if model:
        try:
            import litellm
            count = litellm.token_counter(model=model, text=text)
            return int(count)
        except Exception:
            pass
    # Rough estimate: ~4 chars per token for English
    return len(text) // 4


def _get_message_tokens(msg: Dict[str, Any], model: Optional[str] = None) -> int:
    """Count tokens in a message."""
    content = msg.get("content", "")
    if isinstance(content, str):
        return _estimate_tokens(content, model)
    if isinstance(content, list):
        total = 0
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                total += _estimate_tokens(item.get("text", ""), model)
        return total
    return 0


def _extract_text(msg: Dict[str, Any]) -> str:
    """Extract text content from a message."""
    content = msg.get("content", "")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, dict):
                if item.get("type") == "text":
                    parts.append(item.get("text", ""))
                elif item.get("type") == "image_url":
                    parts.append("[IMAGE]")
        return " ".join(parts)
    return str(content)


def _summarize_messages(
    messages: List[Dict[str, Any]],
    model: str,
    api_key: Optional[str] = None,
    api_base: Optional[str] = None,
    timeout: int = 30,
) -> Dict[str, Any]:
    """Summarize a chunk of messages using LLM."""
    if not messages:
        return {
            "role": "user",
            "content": "<context_summary count='0'>No messages to summarize</context_summary>",
        }

    formatted = []
    for msg in messages:
        role = msg.get("role", "unknown")
        text = _extract_text(msg)
        formatted.append(f"{role}: {text}")

    conversation = "\n".join(formatted)
    prompt = SUMMARY_PROMPT.format(conversation=conversation)

    try:
        import litellm
        kwargs: Dict[str, Any] = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "timeout": timeout,
        }
        if api_key:
            kwargs["api_key"] = api_key
        if api_base:
            kwargs["api_base"] = api_base

        response = litellm.completion(**kwargs)
        summary = response.choices[0].message.content or ""
        if not summary.strip():
            return messages[0]

        return {
            "role": "user",
            "content": f"<context_summary count='{len(messages)}'>{summary}</context_summary>",
        }
    except Exception:
        logger.warning("Memory compression failed, keeping first message of chunk")
        return messages[0]


class MemoryCompressor:
    """Compresses conversation history to stay within token limits.

    Strategy:
    1. Keep all system messages unchanged
    2. Keep MIN_RECENT_MESSAGES most recent messages intact
    3. Summarize older messages in chunks when total tokens exceed limit
    """

    def __init__(
        self,
        model_name: Optional[str] = None,
        api_key: Optional[str] = None,
        api_base: Optional[str] = None,
        timeout: int = 30,
        max_tokens: int = MAX_TOTAL_TOKENS,
    ):
        self.model_name = model_name
        self.api_key = api_key
        self.api_base = api_base
        self.timeout = timeout
        self.max_tokens = max_tokens

    def compress(
        self,
        messages: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Compress conversation history if it exceeds token limits.

        Returns the original messages if within limits, otherwise
        returns system_msgs + compressed_old + recent_msgs.
        """
        if not messages:
            return messages

        # Separate system messages from conversation
        system_msgs: List[Dict[str, Any]] = []
        regular_msgs: List[Dict[str, Any]] = []
        for msg in messages:
            if msg.get("role") == "system":
                system_msgs.append(msg)
            else:
                regular_msgs.append(msg)

        # Check if compression is needed
        total_tokens = sum(
            _get_message_tokens(msg, self.model_name)
            for msg in messages
        )

        if total_tokens <= self.max_tokens * 0.9:
            return messages  # Within limits, no compression needed

        # Split into old (to compress) and recent (to keep)
        recent = regular_msgs[-MIN_RECENT_MESSAGES:]
        old = regular_msgs[:-MIN_RECENT_MESSAGES]

        if not old:
            return messages  # Not enough messages to compress

        if not self.model_name:
            # No LLM available — simple truncation: keep system + recent only
            logger.warning("No LLM configured for memory compression, truncating old messages")
            return system_msgs + recent

        # Compress old messages in chunks
        compressed: List[Dict[str, Any]] = []
        chunk_size = 10
        for i in range(0, len(old), chunk_size):
            chunk = old[i:i + chunk_size]
            summary = _summarize_messages(
                chunk, self.model_name, self.api_key, self.api_base, self.timeout
            )
            compressed.append(summary)

        logger.info(
            "Memory compressed: %d messages → %d summaries + %d recent (tokens: %d → ~%d)",
            len(regular_msgs), len(compressed), len(recent),
            total_tokens,
            sum(_get_message_tokens(m, self.model_name) for m in system_msgs + compressed + recent),
        )

        return system_msgs + compressed + recent
