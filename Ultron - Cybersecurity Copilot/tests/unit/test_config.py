"""Unit tests for configuration loading and validation."""

import os
import pytest
from pathlib import Path
from src.core.config import (
    AppConfig,
    HardwareConfig,
    PipelineConfig,
    OllamaConfig,
    load_config,
)


def test_default_config_instantiation():
    """Verify that AppConfig instantiates with sound defaults."""
    config = AppConfig()
    assert config.hardware.cpu_cores == 6
    assert config.hardware.max_ram_gb == 24.0
    assert config.hardware.max_vram_gb == 4.0
    assert config.pipeline.strict_phasing is True
    assert config.pipeline.allow_concurrent_phases is False
    assert config.ollama.model_3b == "qwen2.5-coder:3b"
    assert config.ollama.model_7b == "qwen2.5-coder:7b"
    assert config.ollama.embedding_num_gpu == 0
    assert config.database.enable_foreign_keys is True


def test_load_config_from_yaml(tmp_path: Path):
    """Verify loading from a YAML file."""
    yaml_content = """
environment: test
hardware:
  cpu_cores: 8
  max_ram_gb: 32.0
ollama:
  model_3b: custom-3b
  embedding_num_gpu: 0
database:
  db_path: data/custom_evidence.db
"""
    yaml_file = tmp_path / "test_config.yaml"
    yaml_file.write_text(yaml_content, encoding="utf-8")

    config = load_config(config_path=yaml_file, project_root=tmp_path)
    assert config.environment == "test"
    assert config.hardware.cpu_cores == 8
    assert config.hardware.max_ram_gb == 32.0
    assert config.ollama.model_3b == "custom-3b"
    assert config.database.db_path == Path("data/custom_evidence.db")


def test_load_default_yaml_file():
    """Verify loading the repository's config/default_config.yaml."""
    root = Path(__file__).resolve().parents[2]
    config = load_config(project_root=root)
    assert config.pipeline.strict_phasing is True
    assert config.ollama.embedding_model == "nomic-embed-text"
    assert config.database.enable_wal_mode is True


def test_env_override(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Verify environment variable overrides with BBAI_ prefix."""
    yaml_file = tmp_path / "base.yaml"
    yaml_file.write_text("environment: base\n", encoding="utf-8")

    monkeypatch.setenv("BBAI_ENVIRONMENT", "production")
    monkeypatch.setenv("BBAI_HARDWARE__CPU_CORES", "12")
    monkeypatch.setenv("BBAI_OLLAMA__DEFAULT_TEMPERATURE", "0.2")

    config = load_config(config_path=yaml_file, project_root=tmp_path)
    assert config.environment == "production"
    assert config.hardware.cpu_cores == 12
    assert config.ollama.default_temperature == 0.2


def test_invalid_pipeline_config():
    """Verify that allowing concurrent phases with strict phasing raises validation error."""
    with pytest.raises(ValueError, match="allow_concurrent_phases cannot be True when strict_phasing is enabled"):
        PipelineConfig(strict_phasing=True, allow_concurrent_phases=True)


def test_path_resolution(tmp_path: Path):
    """Verify resolve_path handles relative and absolute paths accurately."""
    config = AppConfig(project_root=tmp_path)
    rel_path = Path("data/evidence.db")
    resolved = config.resolve_path(rel_path)
    assert resolved == (tmp_path / "data/evidence.db").resolve()

    abs_path = (tmp_path / "abs" / "file.txt").resolve()
    assert config.resolve_path(abs_path) == abs_path
