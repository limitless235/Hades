"""Runtime configuration for the Hades lab."""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class DefenseLevel(str, Enum):
    D0 = "D0"
    D1 = "D1"
    D2 = "D2"
    D3 = "D3"
    D4 = "D4"
    D5 = "D5"
    D6 = "D6"
    D7 = "D7"  # alias: all layers enabled


class LLMBackend(str, Enum):
    MOCK = "mock"
    OLLAMA = "ollama"


# Layers enabled at each defense level (inclusive).
LEVEL_FEATURES: dict[DefenseLevel, set[str]] = {
    DefenseLevel.D0: set(),
    DefenseLevel.D1: {"input_gateway"},
    DefenseLevel.D2: {"input_gateway", "dlp"},
    DefenseLevel.D3: {"input_gateway", "dlp", "retrieval_acl"},
    DefenseLevel.D4: {"input_gateway", "dlp", "retrieval_acl", "output_filter"},
    DefenseLevel.D5: {
        "input_gateway",
        "dlp",
        "retrieval_acl",
        "output_filter",
        "tool_authz",
    },
    DefenseLevel.D6: {
        "input_gateway",
        "dlp",
        "retrieval_acl",
        "output_filter",
        "tool_authz",
        "telemetry",
    },
    DefenseLevel.D7: {
        "input_gateway",
        "dlp",
        "retrieval_acl",
        "output_filter",
        "tool_authz",
        "telemetry",
    },
}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="HADES_", env_file=".env", extra="ignore")

    defense_level: DefenseLevel = DefenseLevel.D0
    llm_backend: LLMBackend = LLMBackend.MOCK
    ollama_base_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "huihui_ai/qwen3.5-abliterated:4b"
    jwt_secret: str = "hades-lab-only-not-for-production"
    jwt_algorithm: str = "HS256"
    jwt_ttl_seconds: int = 3600
    data_dir: Path = Field(default_factory=lambda: Path("datasets/aperture"))
    runtime_dir: Path = Field(default_factory=lambda: Path("data/runtime"))
    telemetry_path: Path = Field(default_factory=lambda: Path("data/runtime/telemetry.jsonl"))
    alerts_path: Path = Field(default_factory=lambda: Path("data/runtime/alerts.jsonl"))
    allow_unsafe_sql: bool = False
    top_k: int = 5
    host: str = "127.0.0.1"
    port: int = 8080

    def features(self) -> set[str]:
        return set(LEVEL_FEATURES[self.defense_level])

    def enabled(self, feature: str) -> bool:
        return feature in self.features()


_settings: Optional[Settings] = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def reset_settings(settings: Optional[Settings] = None) -> Settings:
    global _settings
    _settings = settings or Settings()
    return _settings
