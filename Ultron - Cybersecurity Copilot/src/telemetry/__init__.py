"""M6 Passive Telemetry Ingestion and Normalization Package.

Provides parsers for HTTP, HAR, Burp/Caido proxy exports, DNS, TLS,
tool outputs (nmap, httpx, ffuf, semgrep), and mobile artifacts,
strictly enforcing the pipeline:
Parser -> Normalizer -> ScopeGate -> Evidence Store.
"""

from src.telemetry.normalizer import TelemetryIngestionPipeline
from src.telemetry.parsers import (
    HARParser,
    BurpCaidoParser,
    RawHTTPParser,
    DNSTLSParser,
    SecurityToolParser,
    MobileArtifactParser,
)

__all__ = [
    "TelemetryIngestionPipeline",
    "HARParser",
    "BurpCaidoParser",
    "RawHTTPParser",
    "DNSTLSParser",
    "SecurityToolParser",
    "MobileArtifactParser",
]
