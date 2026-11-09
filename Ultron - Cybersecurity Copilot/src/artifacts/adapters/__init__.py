"""Adapters for Specialized Artifact Processing and Observation Extraction."""

from src.artifacts.adapters.android_adapter import AndroidArtifactAdapter
from src.artifacts.adapters.web_api_adapter import WebApiArtifactAdapter

__all__ = ["AndroidArtifactAdapter", "WebApiArtifactAdapter"]
