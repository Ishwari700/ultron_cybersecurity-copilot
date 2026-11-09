"""Function Analyzer for Binary Reverse Engineering in M7.

Parses function descriptors, basic blocks, parameter signatures, and dangerous sinks.
"""

from typing import Any, Dict, List, Tuple
from src.binary.artifacts import FunctionArtifact, SuspiciousSink


class FunctionAnalyzer:
    """Analyzes function structures, basic blocks, and potential security sinks."""

    DANGEROUS_C_SINKS = {
        "strcpy": ("BUFFER_OVERFLOW", "Unbounded memory copy without bounds checking."),
        "sprintf": ("BUFFER_OVERFLOW", "Unbounded string formatting without length check."),
        "gets": ("BUFFER_OVERFLOW", "Inherently unsafe standard input reading."),
        "system": ("COMMAND_EXECUTION", "Subshell command execution sink."),
        "popen": ("COMMAND_EXECUTION", "Piped process execution sink."),
        "printf": ("FORMAT_STRING", "Format string vulnerability when user controls format."),
    }

    @classmethod
    def analyze_functions(
        cls, function_defs: List[Dict[str, Any]]
    ) -> Tuple[List[FunctionArtifact], List[SuspiciousSink]]:
        artifacts: List[FunctionArtifact] = []
        sinks: List[SuspiciousSink] = []

        for f in function_defs:
            name = f.get("name", "unknown_func")
            addr = f.get("address")
            params = f.get("parameters", [])
            ret_type = f.get("return_type", "void")
            bbs = f.get("basic_blocks", 1)
            is_exp = f.get("is_exported", False)

            artifacts.append(FunctionArtifact(
                name=name,
                address=addr,
                parameters=params,
                return_type=ret_type,
                basic_blocks=bbs,
                is_exported=is_exp,
            ))

            # Inspect calls made within function for dangerous sinks
            called_funcs = f.get("calls", [])
            for callee in called_funcs:
                if callee in cls.DANGEROUS_C_SINKS:
                    stype, sdesc = cls.DANGEROUS_C_SINKS[callee]
                    sinks.append(SuspiciousSink(
                        function_name=name,
                        sink_type=stype,
                        instruction_or_call=f"{name} -> {callee}",
                        severity="HIGH",
                    ))

        return artifacts, sinks
