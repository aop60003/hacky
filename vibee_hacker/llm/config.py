"""LLM configuration for VIBEE-Hacker."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from vibee_hacker.config import Config


class LLMConfig(BaseModel):
    """Configuration for LLM provider."""

    model_name: str = ""
    api_key: Optional[str] = Field(default=None, repr=False)
    api_base: Optional[str] = None
    timeout: int = 300
    max_retries: int = 5
    reasoning_effort: str = "high"
    skills: List[str] = Field(default_factory=list)
    enable_prompt_caching: bool = True

    @classmethod
    def from_config(cls) -> "LLMConfig":
        """Create LLMConfig from the global Config system."""
        model = Config.get("vibee_llm") or ""
        return cls(
            model_name=model,
            api_key=Config.get("vibee_llm_api_key"),
            api_base=Config.get("vibee_llm_api_base"),
            timeout=Config.get_int("vibee_llm_timeout", 300),
            max_retries=Config.get_int("vibee_llm_max_retries", 5),
            reasoning_effort=Config.get("vibee_reasoning_effort") or "high",
        )

    @property
    def is_configured(self) -> bool:
        """Check if LLM is configured with a model name."""
        return bool(self.model_name)

    def to_litellm_kwargs(self) -> Dict[str, Any]:
        """Convert to litellm.acompletion keyword arguments."""
        kwargs: Dict[str, Any] = {
            "model": self.model_name,
            "timeout": self.timeout,
            "stream": True,
        }
        if self.api_key:
            kwargs["api_key"] = self.api_key
        if self.api_base:
            kwargs["api_base"] = self.api_base
        return kwargs
