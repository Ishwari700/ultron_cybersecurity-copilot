"""Dangerous Native API and Suspicious Sink Analyzer for M10.

Identifies security-sensitive API imports and calls:
- Unsafe memory: strcpy, strcat, sprintf, gets, scanf
- Process execution: system, popen, execve, execl, CreateProcess
- Dynamic code loading: dlopen, dlsym, LoadLibrary
- Memory protection modification: mprotect, VirtualProtect

Strict epistemic invariant:
Do NOT label every use as vulnerable. Emits SUSPICIOUS_SINK with supporting provenance (INV-M10-18).
"""

from typing import Any, Dict, List, Optional
from src.binary.artifacts import BinaryArtifact, SuspiciousSink


class DangerousApiAnalyzer:
    """Detects dangerous standard library and system API imports/calls."""

    DANGEROUS_APIS = {
        # Memory safety
        "strcpy": ("BUFFER_OVERFLOW", "Unbounded string copy into destination buffer", "HIGH"),
        "strcat": ("BUFFER_OVERFLOW", "Unbounded string concatenation", "HIGH"),
        "sprintf": ("BUFFER_OVERFLOW", "Unbounded formatted write into string buffer", "HIGH"),
        "vsprintf": ("BUFFER_OVERFLOW", "Unbounded va_list formatted string write", "HIGH"),
        "gets": ("BUFFER_OVERFLOW", "Inherently unsafe standard input read without bounds", "CRITICAL"),
        "scanf": ("BUFFER_OVERFLOW", "Format specifier read without explicit field width", "MEDIUM"),
        # Subshell execution
        "system": ("COMMAND_EXECUTION", "Subshell command execution sink", "CRITICAL"),
        "popen": ("COMMAND_EXECUTION", "Pipe-driven command execution sink", "CRITICAL"),
        "execve": ("PROCESS_EXECUTION", "Direct process execution sink", "HIGH"),
        "execl": ("PROCESS_EXECUTION", "Direct process execution sink", "HIGH"),
        "CreateProcessA": ("PROCESS_EXECUTION", "Windows process creation sink", "HIGH"),
        "CreateProcessW": ("PROCESS_EXECUTION", "Windows process creation sink", "HIGH"),
        # Dynamic loading
        "dlopen": ("DYNAMIC_LIBRARY_LOADING", "Dynamic shared object loading sink", "MEDIUM"),
        "dlsym": ("DYNAMIC_SYMBOL_RESOLUTION", "Dynamic runtime symbol lookup", "LOW"),
        "LoadLibraryA": ("DYNAMIC_LIBRARY_LOADING", "Dynamic DLL loading sink", "MEDIUM"),
        "LoadLibraryW": ("DYNAMIC_LIBRARY_LOADING", "Dynamic DLL loading sink", "MEDIUM"),
        # Memory permissions
        "mprotect": ("EXECUTABLE_MEMORY_ALLOCATION", "Memory protection modification (e.g. RWX)", "HIGH"),
        "VirtualProtect": ("EXECUTABLE_MEMORY_ALLOCATION", "Windows memory protection modification", "HIGH"),
    }

    @classmethod
    def scan_binary_sinks(
        cls,
        binary: BinaryArtifact,
    ) -> List[SuspiciousSink]:
        """Scans imports and symbols of a binary artifact for suspicious sinks."""
        sinks: List[SuspiciousSink] = []
        all_referenced = set(binary.imports + [f.name for f in binary.functions])

        for api_name, (stype, sdesc, sev) in cls.DANGEROUS_APIS.items():
            if api_name in all_referenced:
                sinks.append(SuspiciousSink(
                    function_name=api_name,
                    sink_type=stype,
                    instruction_or_call=f"Imported/referenced native API: {api_name} ({sdesc})",
                    reachability_source="UNKNOWN_STATIC_IMPORT",
                    severity=sev,
                ))

        return sinks

    @classmethod
    def evaluate_function_calls(
        cls,
        caller_name: str,
        callees: List[str],
    ) -> List[SuspiciousSink]:
        """Evaluates calls made inside a function for suspicious sinks."""
        sinks: List[SuspiciousSink] = []
        for callee in callees:
            if callee in cls.DANGEROUS_APIS:
                stype, sdesc, sev = cls.DANGEROUS_APIS[callee]
                sinks.append(SuspiciousSink(
                    function_name=caller_name,
                    sink_type=stype,
                    instruction_or_call=f"{caller_name} calls {callee} ({sdesc})",
                    reachability_source=caller_name,
                    severity=sev,
                ))
        return sinks
