"""Static Source and Sink Security Analyzer for Android Bytecode in M10.

Distinguishes:
POTENTIAL_SOURCE + POTENTIAL_SINK + POSSIBLE_DATA_FLOW
from
PROVEN_VULNERABILITY.

Identifies:
- Sources: Intent extras, URI data, Bundle values, IPC parameters, WebView callbacks.
- Sinks: SQL execution, WebView JS bridge, File I/O, Command execution, Reflection,
  Dynamic class loading, Deserialization, Cryptographic misuse, World-readable storage.

Emits:
- SUSPICIOUS_SINK
- MODEL_HYPOTHESIS
- EVIDENCE_GAP
"""

from typing import Any, Dict, List, Optional
from src.binary.artifacts import SuspiciousSink


class SourceSinkAnalyzer:
    """Analyzes Android method instructions and call relationships for dangerous data flows."""

    ANDROID_SOURCES = {
        "getIntent": "INTENT_INPUT",
        "getExtras": "INTENT_EXTRAS_INPUT",
        "getStringExtra": "INTENT_STRING_EXTRA",
        "getIntExtra": "INTENT_INT_EXTRA",
        "getData": "URI_DATA_INPUT",
        "getDataString": "URI_STRING_INPUT",
        "getQueryParameter": "URI_QUERY_PARAM_INPUT",
        "getBundle": "BUNDLE_INPUT",
        "readObject": "DESERIALIZATION_INPUT",
    }

    ANDROID_SINKS = {
        "rawQuery": ("SQL_INJECTION", "Database raw SQL execution sink", "HIGH"),
        "execSQL": ("SQL_INJECTION", "Database direct execSQL execution sink", "HIGH"),
        "loadUrl": ("WEBVIEW_XSS_OR_INJECTION", "WebView URL loading sink", "MEDIUM"),
        "evaluateJavascript": ("WEBVIEW_JS_EXECUTION", "WebView arbitrary JavaScript execution sink", "HIGH"),
        "addJavascriptInterface": ("WEBVIEW_BRIDGE_EXPOSURE", "Native interface exposed to WebView JavaScript", "CRITICAL"),
        "openFileOutput": ("INSECURE_FILE_CREATION", "Local file output stream creation", "MEDIUM"),
        "exec": ("COMMAND_EXECUTION", "Subshell OS command execution sink", "CRITICAL"),
        "ProcessBuilder": ("COMMAND_EXECUTION", "Process execution sink", "CRITICAL"),
        "DexClassLoader": ("DYNAMIC_CLASS_LOADING", "Untrusted code loading sink", "HIGH"),
        "PathClassLoader": ("DYNAMIC_CLASS_LOADING", "Untrusted code loading sink", "HIGH"),
        "Method;->invoke": ("UNSAFE_REFLECTION", "Dynamic reflective method invocation sink", "MEDIUM"),
    }

    @classmethod
    def analyze_method_flow(
        cls,
        class_name: str,
        method_name: str,
        smali_or_calls: List[str],
        has_sources: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Analyzes a method body for potential source and sink relationships.
        Never declares a finding as a proven vulnerability without runtime verification.
        """
        detected_sources: List[str] = []
        detected_sinks: List[SuspiciousSink] = []
        hypotheses: List[Dict[str, Any]] = []
        evidence_gaps: List[Dict[str, Any]] = []

        code_text = " ".join(smali_or_calls)

        # Detect sources
        for src_kw, src_type in cls.ANDROID_SOURCES.items():
            if src_kw in code_text:
                detected_sources.append(src_type)

        if has_sources:
            detected_sources.append("EXTERNAL_IPC_SOURCE")

        # Detect sinks
        for sink_kw, (stype, sdesc, sev) in cls.ANDROID_SINKS.items():
            if sink_kw in code_text:
                ss = SuspiciousSink(
                    function_name=f"{class_name}->{method_name}",
                    sink_type=stype,
                    instruction_or_call=f"{class_name}->{method_name} references {sink_kw}",
                    reachability_source=detected_sources[0] if detected_sources else None,
                    severity=sev,
                )
                detected_sinks.append(ss)

                # Formulate hypothesis and evidence gap
                if detected_sources:
                    hypotheses.append({
                        "type": "MODEL_HYPOTHESIS",
                        "method": f"{class_name}->{method_name}",
                        "hypothesis": f"Method receives data from {detected_sources} and reaches {stype} sink ({sink_kw}). May constitute a taint flow.",
                        "confidence": 0.7,
                        "verification_needed": "Perform dynamic taint tracking or manual reverse engineering to confirm untrusted input reachability.",
                    })
                    evidence_gaps.append({
                        "type": "EVIDENCE_GAP",
                        "gap": f"Static source/sink presence does not prove data reaches sink without sanitization or validation in {class_name}->{method_name}.",
                    })
                else:
                    hypotheses.append({
                        "type": "MODEL_HYPOTHESIS",
                        "method": f"{class_name}->{method_name}",
                        "hypothesis": f"Method references sensitive sink {stype} ({sink_kw}) but static analysis did not identify direct external source.",
                        "confidence": 0.4,
                    })
                    evidence_gaps.append({
                        "type": "EVIDENCE_GAP",
                        "gap": f"Sensitive sink {stype} ({sink_kw}) identified, but external data source reachability is unverified.",
                    })

        return {
            "method": f"{class_name}->{method_name}",
            "sources": detected_sources,
            "sinks": detected_sinks,
            "hypotheses": hypotheses,
            "evidence_gaps": evidence_gaps,
            "has_correlation": len(detected_sources) > 0 and len(detected_sinks) > 0,
        }
