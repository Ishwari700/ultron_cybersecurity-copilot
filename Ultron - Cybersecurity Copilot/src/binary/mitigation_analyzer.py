"""Native Binary Security Mitigation Analyzer for M10.

Evaluates binary exploit mitigations:
- NX / DEP (No-Execute / Data Execution Prevention)
- PIE (Position Independent Executable)
- RELRO (Relocation Read-Only: FULL, PARTIAL, NONE)
- Stack Canaries (__stack_chk_fail, __security_cookie)
- ASLR (Address Space Layout Randomization)
- Symbol Stripping (.symtab absence)
- Fortified functions (__*_chk)

Epistemic rule:
Emits OBSERVED_INDICATOR, never labels a missing mitigation as an automatic vulnerability (INV-M10-18).
"""

from typing import Any, Dict, List
from src.binary.artifacts import BinaryArtifact


class MitigationAnalyzer:
    """Analyzes compiled binary artifacts for active security hardening mitigations."""

    @classmethod
    def evaluate_mitigations(cls, binary: BinaryArtifact) -> Dict[str, Any]:
        """
        Assesses security mitigations on a parsed BinaryArtifact and produces
        structured observations and risk indicators.
        """
        indicators: List[Dict[str, Any]] = []
        hypotheses: List[Dict[str, Any]] = []

        # 1. NX / DEP
        if binary.nx_enabled is True:
            indicators.append({
                "type": "OBSERVED_INDICATOR",
                "subtype": "MITIGATION_NX_ENABLED",
                "description": "Non-Executable stack/heap (NX/DEP) is enabled.",
                "status": "PRESENT",
            })
        elif binary.nx_enabled is False:
            indicators.append({
                "type": "OBSERVED_INDICATOR",
                "subtype": "MITIGATION_NX_DISABLED",
                "description": "Executable stack permitted (NX/DEP is disabled). Stack buffer overflows could execute shellcode directly.",
                "status": "ABSENT",
                "severity": "HIGH",
            })
            hypotheses.append({
                "type": "MODEL_HYPOTHESIS",
                "hypothesis": "Binary lacks non-executable stack protection; classic memory corruptions could achieve direct instruction execution.",
                "verification_needed": "Confirm whether memory corruption primitive exists in reachable code paths.",
            })

        # 2. PIE / ASLR
        if binary.pie_enabled is True:
            indicators.append({
                "type": "OBSERVED_INDICATOR",
                "subtype": "MITIGATION_PIE_ENABLED",
                "description": "Position Independent Executable (PIE) enabled. Binary base randomized by ASLR.",
                "status": "PRESENT",
            })
        elif binary.pie_enabled is False:
            indicators.append({
                "type": "OBSERVED_INDICATOR",
                "subtype": "MITIGATION_PIE_DISABLED",
                "description": "PIE disabled. Executable loaded at fixed base address, facilitating ROP gadgets.",
                "status": "ABSENT",
                "severity": "MEDIUM",
            })

        # 3. RELRO
        if binary.relro_level == "FULL":
            indicators.append({
                "type": "OBSERVED_INDICATOR",
                "subtype": "MITIGATION_FULL_RELRO",
                "description": "Full RELRO enabled (GOT table is completely read-only after link).",
                "status": "PRESENT",
            })
        elif binary.relro_level == "PARTIAL":
            indicators.append({
                "type": "OBSERVED_INDICATOR",
                "subtype": "MITIGATION_PARTIAL_RELRO",
                "description": "Partial RELRO enabled (.got is non-writable, but .got.plt remains writable).",
                "status": "PARTIAL",
            })
        elif binary.relro_level == "NONE":
            indicators.append({
                "type": "OBSERVED_INDICATOR",
                "subtype": "MITIGATION_NO_RELRO",
                "description": "No RELRO protection. Global Offset Table (.got) is fully writable.",
                "status": "ABSENT",
                "severity": "MEDIUM",
            })

        # 4. Stack Canaries
        if binary.stack_canary_present is True:
            indicators.append({
                "type": "OBSERVED_INDICATOR",
                "subtype": "MITIGATION_CANARY_ENABLED",
                "description": "Stack protector canaries (__stack_chk_fail) detected in binary imports.",
                "status": "PRESENT",
            })
        elif binary.stack_canary_present is False:
            indicators.append({
                "type": "OBSERVED_INDICATOR",
                "subtype": "MITIGATION_CANARY_ABSENT",
                "description": "Stack protector canaries not detected in imports.",
                "status": "ABSENT",
                "severity": "MEDIUM",
            })

        # 5. Stripped Symbols
        if binary.symbols_stripped:
            indicators.append({
                "type": "OBSERVED_INDICATOR",
                "subtype": "SYMBOLS_STRIPPED",
                "description": "Symbol table (.symtab) is stripped.",
                "status": "STRIPPED",
            })
        else:
            indicators.append({
                "type": "OBSERVED_INDICATOR",
                "subtype": "SYMBOLS_PRESENT",
                "description": "Non-stripped binary (debug or static symbols present in .symtab).",
                "status": "NOT_STRIPPED",
            })

        # 6. Fortified functions
        if binary.fortified_functions_count > 0:
            indicators.append({
                "type": "OBSERVED_INDICATOR",
                "subtype": "MITIGATION_FORTIFY_SOURCE",
                "description": f"Source fortification detected with {binary.fortified_functions_count} fortified wrappers.",
                "status": "PRESENT",
            })

        return {
            "binary_name": binary.binary_name,
            "format": binary.format,
            "architecture": binary.architecture,
            "mitigations": {
                "nx": binary.nx_enabled,
                "pie": binary.pie_enabled,
                "relro": binary.relro_level,
                "canary": binary.stack_canary_present,
                "stripped": binary.symbols_stripped,
                "fortified_count": binary.fortified_functions_count,
            },
            "indicators": indicators,
            "hypotheses": hypotheses,
        }
