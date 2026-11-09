"""Configuration management for Local AI-Assisted Bug Bounty Research Platform."""

import os
from pathlib import Path
from typing import Any, Dict, Optional
import yaml
from pydantic import BaseModel, Field, field_validator, model_validator


class HardwareConfig(BaseModel):
    """Hardware bounds and device allocation settings (AMD Ryzen 5 5600H / RTX 3050 4GB)."""
    cpu_cores: int = Field(default=6, ge=1, le=128)
    max_ram_gb: float = Field(default=24.0, gt=0.0)
    max_vram_gb: float = Field(default=4.0, gt=0.0)
    device: str = Field(default="cuda")
    ollama_vram_budget_mb: int = Field(default=3500, gt=0, le=4096)


class PipelineConfig(BaseModel):
    """Pipeline scheduling parameters enforcing strict phase synchronicity."""
    strict_phasing: bool = Field(default=True)
    phase_1_recon_cpu_percent: int = Field(default=100, ge=1, le=100)
    phase_2_indexing_cpu_percent: int = Field(default=100, ge=1, le=100)
    phase_3_inference_gpu_percent: int = Field(default=100, ge=1, le=100)
    allow_concurrent_phases: bool = Field(default=False)

    @model_validator(mode="after")
    def validate_strict_phasing(self) -> "PipelineConfig":
        if self.strict_phasing and self.allow_concurrent_phases:
            raise ValueError("allow_concurrent_phases cannot be True when strict_phasing is enabled")
        return self


class OllamaConfig(BaseModel):
    """Local Ollama serving parameters."""
    base_url: str = Field(default="http://127.0.0.1:11434")
    primary_model: str = Field(default="qwen2.5-coder:7b")
    lightweight_model: str = Field(default="qwen2.5-coder:3b")
    model_3b: Optional[str] = Field(default=None)
    model_7b: Optional[str] = Field(default=None)
    require_live_ollama: bool = Field(default=False)
    max_concurrent_inferences: int = Field(default=1, ge=1, le=4)
    embedding_model: str = Field(default="nomic-embed-text")
    embedding_num_gpu: int = Field(default=0, ge=0, description="Force embeddings to CPU to protect GPU VRAM")
    default_temperature: float = Field(default=0.0, ge=0.0, le=1.0)
    num_ctx_3b: int = Field(default=2048, ge=512, le=4096)
    num_ctx_7b: int = Field(default=4096, ge=512, le=8192)
    request_timeout_seconds: int = Field(default=30, gt=0)
    max_retries: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def sync_models(self) -> "OllamaConfig":
        if self.model_7b is not None:
            self.primary_model = self.model_7b
        else:
            self.model_7b = self.primary_model

        if self.model_3b is not None:
            self.lightweight_model = self.model_3b
        else:
            self.model_3b = self.lightweight_model
        return self


class DashboardConfig(BaseModel):
    """Local human review dashboard server configuration."""
    host: str = Field(default="127.0.0.1")
    port: int = Field(default=8000, ge=1, le=65535)
    allow_external: bool = Field(default=False)


class DatabaseConfig(BaseModel):
    """SQLite database configuration for evidence.db."""
    db_path: Path = Field(default=Path("data/evidence.db"))
    timeout_seconds: float = Field(default=30.0, gt=0.0)
    enable_foreign_keys: bool = Field(default=True)
    enable_wal_mode: bool = Field(default=True)

    @field_validator("db_path", mode="before")
    @classmethod
    def parse_path(cls, v: Any) -> Path:
        return Path(v)


class VectorstoreConfig(BaseModel):
    """Vector database configuration for dense retrieval."""
    persist_dir: Path = Field(default=Path("vectorstore"))
    collection_name: str = Field(default="evidence_chunks")
    distance_metric: str = Field(default="cosine")

    @field_validator("persist_dir", mode="before")
    @classmethod
    def parse_path(cls, v: Any) -> Path:
        return Path(v)


class RetrievalConfig(BaseModel):
    """Hybrid sparse/dense retrieval configuration."""
    hybrid_enabled: bool = Field(default=True)
    top_k: int = Field(default=5, ge=1, le=50)
    exact_parameter_gate: bool = Field(default=True)
    rrf_k: int = Field(default=60, ge=1)
    vector_weight: float = Field(default=0.5, ge=0.0, le=1.0)
    bm25_weight: float = Field(default=0.5, ge=0.0, le=1.0)


class LoggingConfig(BaseModel):
    """Logging and audit configuration."""
    log_level: str = Field(default="INFO")
    log_format: str = Field(default="json")
    log_file: Path = Field(default=Path("data/platform.log"))
    audit_log_file: Path = Field(default=Path("data/audit.log"))

    @field_validator("log_file", "audit_log_file", mode="before")
    @classmethod
    def parse_path(cls, v: Any) -> Path:
        return Path(v)


class ScopeConfig(BaseModel):
    """Scope enforcement configuration."""
    policy_file: Path = Field(default=Path("scope.yaml"))
    enforce_ip_pinning: bool = Field(default=True)
    fail_closed: bool = Field(default=True)
    allow_private_ranges: bool = Field(default=False)

    @field_validator("policy_file", mode="before")
    @classmethod
    def parse_path(cls, v: Any) -> Path:
        return Path(v)


class SafetyConfig(BaseModel):
    """Safety and sensitive data vault settings."""
    require_acknowledgment_for_state_changing: bool = Field(default=True)
    require_isolated_data_for_destructive: bool = Field(default=True)
    secret_vault_path: Optional[Path] = Field(default=None)

    @field_validator("secret_vault_path", mode="before")
    @classmethod
    def parse_path(cls, v: Any) -> Optional[Path]:
        return Path(v) if v is not None else None


class AppConfig(BaseModel):
    """Master application configuration."""
    environment: str = Field(default="development")
    project_root: Path = Field(default=Path("."))
    hardware: HardwareConfig = Field(default_factory=HardwareConfig)
    pipeline: PipelineConfig = Field(default_factory=PipelineConfig)
    ollama: OllamaConfig = Field(default_factory=OllamaConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    vectorstore: VectorstoreConfig = Field(default_factory=VectorstoreConfig)
    retrieval: RetrievalConfig = Field(default_factory=RetrievalConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    safety: SafetyConfig = Field(default_factory=SafetyConfig)
    dashboard: DashboardConfig = Field(default_factory=DashboardConfig)

    @field_validator("project_root", mode="before")
    @classmethod
    def parse_path(cls, v: Any) -> Path:
        return Path(v).resolve()

    def resolve_path(self, path: Path) -> Path:
        """Resolve a relative path against the project root."""
        if path.is_absolute():
            return path
        return (self.project_root / path).resolve()


def _deep_update(source: Dict[str, Any], overrides: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively update a dictionary."""
    for key, val in overrides.items():
        if isinstance(val, dict) and key in source and isinstance(source[key], dict):
            source[key] = _deep_update(source[key], val)
        else:
            source[key] = val
    return source


def _apply_env_overrides(config_dict: Dict[str, Any], prefix: str = "BBAI_") -> Dict[str, Any]:
    """
    Override nested config entries from environment variables.
    Format: BBAI_SECTION__SUBKEY=value (double underscore for nesting).
    """
    for env_key, env_val in os.environ.items():
        if not env_key.startswith(prefix):
            continue
        trimmed = env_key[len(prefix):].lower()
        parts = trimmed.split("__")
        current = config_dict
        for part in parts[:-1]:
            if part not in current or not isinstance(current[part], dict):
                current[part] = {}
            current = current[part]
        # Auto-cast simple types if possible
        val: Any = env_val
        if env_val.lower() in ("true", "1", "yes"):
            val = True
        elif env_val.lower() in ("false", "0", "no"):
            val = False
        else:
            try:
                if "." in env_val:
                    val = float(env_val)
                else:
                    val = int(env_val)
            except ValueError:
                val = env_val
        current[parts[-1]] = val
    return config_dict


def load_config(
    config_path: Optional[Path] = None,
    project_root: Optional[Path] = None,
    env_prefix: str = "BBAI_",
) -> AppConfig:
    """
    Load AppConfig from YAML file and apply environment variable overrides.
    If config_path is not specified, attempts to find config/default_config.yaml.
    """
    root = (project_root or Path(".")).resolve()
    target_config = config_path or (root / "config" / "default_config.yaml")

    raw_dict: Dict[str, Any] = {}
    if target_config.exists():
        with open(target_config, "r", encoding="utf-8") as f:
            raw_dict = yaml.safe_load(f) or {}

    if "project_root" not in raw_dict and project_root is not None:
        raw_dict["project_root"] = str(root)

    raw_dict = _apply_env_overrides(raw_dict, prefix=env_prefix)
    return AppConfig(**raw_dict)
