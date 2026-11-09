"""Live 3B Triage Runner (Milestone M2, Phase 6).

Executes local high-throughput triage using qwen2.5-coder:3b.
Strict Architectural Boundaries:
  - 3B NEVER has scope authority, routing authority, confirmation authority,
    submission authority, OR canonical evidence authority (cannot alter, omit,
    or overwrite Channel A - Section 4.2).
  - Enforces the exact 15.0-second per-triage timeout ceiling (Section 6.3).
  - Tracks and separately reports all 5 Section 6.3 failure categories:
    parser failure, model unresponsiveness, timeout (>15.0s), OOM,
    infrastructure connection refusal.
  - Wraps untrusted target-controlled content in the Section 9.1/9.2 envelope.
  - Sets is_malformed exclusively via runner parser/schema check (Schema 2).
"""

import json
import re
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field

from src.evidence.cascade_models import (
    LosslessStructuralPack,
    RawTriageOutput,
)


# Pinned digest confirmed during Phase 0 Model Environment Validation
PINNED_3B_DIGEST = "f72c60cabf6237b07f6e632b2c48d533cef25eda2efbd34bed21c5e9c01e6225"
PINNED_3B_MODEL = "qwen2.5-coder:3b"
TRIAGE_TIMEOUT_CEILING_SECONDS = 15.0


def sanitize_untrusted_data(raw_str: str) -> str:
    """
    Deterministic Sanitization & Escaping per Section 9.1 / 9.2:
    1. Control Character Stripping: All ASCII control characters (0x00-0x1F, except \n, \r, \t) removed.
    2. Delimiter Neutralization: Any </untrusted_target_data> or ]]> is escaped.
    """
    if not raw_str:
        return ""
    # Strip control chars except newline, carriage return, tab
    cleaned = "".join(ch for ch in raw_str if ch in ("\n", "\r", "\t") or ord(ch) >= 32)
    # Delimiter neutralization
    cleaned = cleaned.replace("</untrusted_target_data>", "&lt;/untrusted_target_data&gt;")
    cleaned = cleaned.replace("]]>", "]]&gt;")
    return cleaned


class TriageExecutionMetrics(BaseModel):
    """Execution health and diagnostic metrics per Section 6.3."""
    n_attempted: int = 0
    n_failures: int = 0
    parser_failures: int = 0
    model_unresponsiveness: int = 0
    timeouts: int = 0
    oom_failures: int = 0
    connection_refusals: int = 0
    total_load_duration_s: float = 0.0
    total_infer_duration_s: float = 0.0

    @property
    def failure_rate(self) -> float:
        return (self.n_failures / self.n_attempted) if self.n_attempted > 0 else 0.0

    def to_summary_dict(self) -> Dict[str, Any]:
        return {
            "n_attempted": self.n_attempted,
            "n_failures": self.n_failures,
            "failure_rate": round(self.failure_rate, 4),
            "failure_rate_percent": f"{self.failure_rate * 100:.2f}%",
            "categories": {
                "parser_failure": self.parser_failures,
                "model_unresponsiveness": self.model_unresponsiveness,
                "timeout": self.timeouts,
                "oom": self.oom_failures,
                "connection_refusal": self.connection_refusals,
            },
            "timing": {
                "total_load_s": round(self.total_load_duration_s, 3),
                "total_infer_s": round(self.total_infer_duration_s, 3),
            },
        }


class Live3BTriageRunner:
    """
    Live 3B Triage Runner wrapping local Ollama qwen2.5-coder:3b instance.
    Produces advisory RawTriageOutput conforming to Schema 2 (v2.0.0).
    """

    def __init__(
        self,
        ollama_url: str = "http://127.0.0.1:11434",
        model_name: str = PINNED_3B_MODEL,
        expected_digest: str = PINNED_3B_DIGEST,
        timeout_seconds: float = TRIAGE_TIMEOUT_CEILING_SECONDS,
        keep_alive: str = "5m",
    ) -> None:
        self.ollama_url = ollama_url.rstrip("/")
        self.model_name = model_name
        self.expected_digest = expected_digest
        self.timeout_seconds = timeout_seconds
        self.keep_alive = keep_alive
        self.metrics = TriageExecutionMetrics()
        self.last_load_latency: float = 0.0
        self.last_infer_latency: float = 0.0

    def build_prompt(self, channel_a: LosslessStructuralPack) -> str:
        """Construct grammar-constrained 3B triage prompt from Channel A structural pack."""
        facts_text = ""
        for f in channel_a.observed_facts:
            fid = f.get("fact_id", "FACT-?")
            stmt = f.get("statement", "")
            facts_text += f"- [{fid}]: {stmt}\n"

        params_text = ""
        for p in channel_a.parameter_lineage:
            pid = p.get("param_id", p.get("param_name", "PARAM-?"))
            loc = p.get("location", "body")
            params_text += f"- [{pid}] ({loc})\n"

        untrusted_body = ""
        if channel_a.raw_body_sample:
            sanitized = sanitize_untrusted_data(channel_a.raw_body_sample[:1000])
            untrusted_body = (
                f"\n<untrusted_target_data>\n<![CDATA[\n{sanitized}\n]]>\n</untrusted_target_data>\n"
            )

        prompt = (
            "You are a high-throughput Preliminary Security Triage Engine.\n"
            "Analyze the target endpoint and verified facts below to identify potential authorization or security issues.\n\n"
            "=== TARGET ENDPOINT ===\n"
            f"Route: {channel_a.route_template} ({channel_a.http_method})\n"
            f"Application Mutability: {channel_a.application_mutability}\n"
            f"Privilege Delta Observed: {channel_a.has_privilege_level_delta}\n"
            f"Status Delta Observed: {channel_a.status_code_changed_under_different_role}\n"
            f"Unauthenticated Success: {channel_a.has_unauthenticated_success}\n"
            f"Cross-Identity Object Access: {channel_a.has_cross_identity_object_access_success}\n\n"
            "=== PARAMETER LINEAGE ===\n"
            f"{params_text or 'None'}\n"
            "=== VERIFIED STRUCTURAL FACTS ===\n"
            f"{facts_text or 'None'}"
            f"{untrusted_body}\n"
            "=== INSTRUCTION ===\n"
            "Output a JSON object matching this schema exactly:\n"
            "{\n"
            '  "schema_version": "2.0.0",\n'
            '  "decision": "BENIGN_NO_ISSUE" | "SUSPECTED_VULNERABILITY" | "INSUFFICIENT_EVIDENCE",\n'
            '  "suspected_category": "API-BOLA-001" | "API-BFLA-002" | "STATE-MACHINE-001" | "INFO-EXPOSURE-001" | null,\n'
            '  "triage_rationale": "<summary of reasoning, max 500 characters>",\n'
            '  "suggested_experiment_class": "ID_SWAP" | "ROLE_SWAP" | "STEP_SKIP" | "AUTH_DROP" | null,\n'
            '  "is_sensitive_category": false | true,\n'
            '  "candidate_security_property": "<optional hypothesis>" | null,\n'
            '  "cited_parameter_ids": ["<param_id>"] | null,\n'
            '  "cited_fact_ids": ["<fact_id>"] | null\n'
            "}\n"
            "Return strictly valid JSON only. Do not include markdown codeblocks or other commentary."
        )
        return prompt

    def run_triage(self, channel_a: LosslessStructuralPack) -> RawTriageOutput:
        """
        Execute live 3B triage against Ollama.
        Guarantees:
          - Never alters, omits, or mutates Channel A.
          - Enforces 15.0s timeout ceiling.
          - Emits RawTriageOutput with is_malformed=True on any failure.
          - Tracks failure categories rigorously.
        """
        self.metrics.n_attempted += 1
        prompt = self.build_prompt(channel_a)

        payload = {
            "model": self.model_name,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "keep_alive": self.keep_alive,
            "options": {
                "temperature": 0.0,
                "num_predict": 256,
            },
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            f"{self.ollama_url}/api/generate",
            data=data,
            headers={"Content-Type": "application/json"},
        )

        t_start = time.perf_counter()
        raw_response_text = ""
        load_duration_s = 0.0
        infer_duration_s = 0.0

        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                elapsed = time.perf_counter() - t_start
                if elapsed > self.timeout_seconds:
                    # Enforce strict 15.0s ceiling even if socket read completed slightly over
                    self.metrics.n_failures += 1
                    self.metrics.timeouts += 1
                    return self._create_malformed_fallback(
                        f"Triage execution exceeded timeout ceiling: {elapsed:.2f}s > {self.timeout_seconds:.1f}s"
                    )

                resp_data = json.loads(resp.read().decode("utf-8"))
                raw_response_text = resp_data.get("response", "")
                load_duration_s = resp_data.get("load_duration", 0) / 1e9
                total_dur_s = resp_data.get("total_duration", 0) / 1e9
                infer_duration_s = max(0.0, total_dur_s - load_duration_s)

        except urllib.error.URLError as e:
            elapsed = time.perf_counter() - t_start
            self.metrics.n_failures += 1
            err_str = str(e).lower()
            if "timed out" in err_str or elapsed >= self.timeout_seconds:
                self.metrics.timeouts += 1
                return self._create_malformed_fallback(f"3B invocation timed out: {e}")
            elif "connection refused" in err_str or "winerror 10061" in err_str:
                self.metrics.connection_refusals += 1
                return self._create_malformed_fallback(f"Ollama connection refused: {e}")
            elif "out of memory" in err_str or "oom" in err_str:
                self.metrics.oom_failures += 1
                return self._create_malformed_fallback(f"Ollama OOM error: {e}")
            else:
                self.metrics.model_unresponsiveness += 1
                return self._create_malformed_fallback(f"Ollama error: {e}")

        except TimeoutError:
            self.metrics.n_failures += 1
            self.metrics.timeouts += 1
            return self._create_malformed_fallback("3B invocation exceeded 15.0s timeout")

        except Exception as e:
            self.metrics.n_failures += 1
            err_str = str(e).lower()
            if "out of memory" in err_str or "oom" in err_str:
                self.metrics.oom_failures += 1
            else:
                self.metrics.model_unresponsiveness += 1
            return self._create_malformed_fallback(f"Unexpected triage failure: {e}")

        # Record latency decomposition
        self.last_load_latency = load_duration_s
        self.last_infer_latency = infer_duration_s
        self.metrics.total_load_duration_s += load_duration_s
        self.metrics.total_infer_duration_s += infer_duration_s

        # Validate response content
        if not raw_response_text or not raw_response_text.strip():
            self.metrics.n_failures += 1
            self.metrics.model_unresponsiveness += 1
            return self._create_malformed_fallback("3B model returned empty response")

        # Parse JSON and enforce Schema 2 constraints
        try:
            parsed = json.loads(raw_response_text)
            if not isinstance(parsed, dict):
                raise ValueError("Output root is not a JSON object")

            # Check decision field
            decision = parsed.get("decision")
            if decision not in ("BENIGN_NO_ISSUE", "SUSPECTED_VULNERABILITY", "INSUFFICIENT_EVIDENCE"):
                decision = "INSUFFICIENT_EVIDENCE"

            # Check triage_rationale
            rationale = str(parsed.get("triage_rationale", "No rationale provided"))[:500]

            # Enforce schema version
            parsed["schema_version"] = "2.0.0"
            parsed["decision"] = decision
            parsed["triage_rationale"] = rationale
            parsed["is_malformed"] = False

            # MUST NOT carry category_invalid
            parsed.pop("category_invalid", None)

            triage_output = RawTriageOutput(**parsed)
            return triage_output

        except Exception as e:
            self.metrics.n_failures += 1
            self.metrics.parser_failures += 1
            return self._create_malformed_fallback(f"Schema parsing error: {e}")

    def _create_malformed_fallback(self, reason: str) -> RawTriageOutput:
        """
        Create schema-compliant fallback RawTriageOutput with is_malformed=True.
        Set exclusively by the 3B runner parser/schema check.
        """
        return RawTriageOutput(
            schema_version="2.0.0",
            decision="INSUFFICIENT_EVIDENCE",
            triage_rationale=reason[:500],
            is_malformed=True,
        )
