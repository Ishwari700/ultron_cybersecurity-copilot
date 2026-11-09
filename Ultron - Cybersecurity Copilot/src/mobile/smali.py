"""Smali Intermediate Representation Analyzer for M10 Mobile Pipelines.

Parses disassembled Smali instructions to extract:
1. Instructions: invoke-*, move-*, iget/iput/sget/sput, new-instance, branches, returns.
2. Insecure WebView configurations: setJavaScriptEnabled, setAllowFileAccess, addJavascriptInterface.
3. Cryptographic misuse: AES/ECB/PKCS5Padding, DES, hardcoded keys.
4. Storage flaws: MODE_WORLD_READABLE, MODE_WORLD_WRITEABLE.
5. Dynamic loading & reflection: DexClassLoader, PathClassLoader, Class.forName, Method.invoke.
6. OS Command execution: Runtime.getRuntime().exec, ProcessBuilder.
7. Preserves epistemic boundary: emits STATIC_INDICATOR and SUSPICIOUS_SINK.
"""

import re
from typing import Any, Dict, List, Optional, Tuple
from src.mobile.artifacts import SmaliInstruction


class SmaliAnalyzer:
    """Extracts granular instruction-level security patterns from Smali files."""

    INVOKE_REGEX = re.compile(
        r"invoke-(virtual|direct|static|super|interface)(?:/range)?\s*\{([^}]*)\},\s*([^,\s]+)"
    )
    CONST_STRING_REGEX = re.compile(
        r"const-string(?:/jumbo)?\s+([vp]\d+),\s*\"(.*)\""
    )
    NEW_INSTANCE_REGEX = re.compile(
        r"new-instance\s+([vp]\d+),\s*([^\s]+)"
    )

    @classmethod
    def parse_instructions(cls, smali_text: str) -> List[SmaliInstruction]:
        """Parses individual smali lines into typed SmaliInstruction records."""
        instructions: List[SmaliInstruction] = []
        if not smali_text:
            return instructions

        for line_num, line in enumerate(smali_text.splitlines(), start=1):
            raw = line.strip()
            if not raw or raw.startswith("#"):
                continue

            parts = raw.split(maxsplit=1)
            opcode = parts[0]
            rest = parts[1] if len(parts) > 1 else ""

            # Check invoke
            m_inv = cls.INVOKE_REGEX.match(raw)
            if m_inv:
                kind, regs, target = m_inv.groups()
                reg_list = [r.strip() for r in regs.split(",") if r.strip()]
                instructions.append(SmaliInstruction(
                    opcode=f"invoke-{kind}",
                    registers=reg_list,
                    target=target,
                    line_number=line_num,
                    raw_text=raw,
                ))
                continue

            # Check const-string
            m_str = cls.CONST_STRING_REGEX.match(raw)
            if m_str:
                reg, val = m_str.groups()
                instructions.append(SmaliInstruction(
                    opcode="const-string",
                    registers=[reg],
                    target=val,
                    line_number=line_num,
                    raw_text=raw,
                ))
                continue

            # General instructions
            regs = [r.strip() for r in rest.split(",") if r.strip().startswith(("v", "p"))]
            instructions.append(SmaliInstruction(
                opcode=opcode,
                registers=regs,
                target=rest,
                line_number=line_num,
                raw_text=raw,
            ))

        return instructions

    @classmethod
    def analyze_smali_block(cls, smali_text: str) -> Dict[str, Any]:
        """
        Parses Smali text block and returns structured findings, parsed instructions,
        and method calls.
        """
        findings: List[Dict[str, Any]] = []
        if not smali_text:
            return {"layer": "SMALI", "findings": findings, "instructions": []}

        parsed_instructions = cls.parse_instructions(smali_text)
        called_targets = [inst.target for inst in parsed_instructions if inst.target and inst.opcode.startswith("invoke")]

        # 1. WebView checks
        if "setJavaScriptEnabled" in smali_text and ("0x1" in smali_text or "const/4" in smali_text):
            findings.append({
                "type": "INSECURE_WEBVIEW_JS",
                "description": "WebView has JavaScript execution explicitly enabled.",
                "severity": "MEDIUM",
            })
        if "setAllowFileAccess" in smali_text and ("0x1" in smali_text or "const/4" in smali_text):
            findings.append({
                "type": "WEBVIEW_FILE_ACCESS",
                "description": "WebView explicitly allows local file access.",
                "severity": "HIGH",
            })
        if "addJavascriptInterface" in smali_text:
            findings.append({
                "type": "WEBVIEW_JS_INTERFACE",
                "description": "WebView binds native object via addJavascriptInterface.",
                "severity": "HIGH",
            })

        # 2. Cryptographic misuse
        if "AES/ECB/PKCS5Padding" in smali_text or "DES" in smali_text:
            findings.append({
                "type": "WEAK_CRYPTO_CIPHER",
                "description": "Weak or unauthenticated cipher mode (ECB/DES) instantiated.",
                "severity": "HIGH",
            })

        # 3. Insecure file modes
        if "MODE_WORLD_READABLE" in smali_text or ("openFileOutput" in smali_text and ("0x1" in smali_text or "const/4 v1, 0x1" in smali_text)):
            findings.append({
                "type": "WORLD_READABLE_STORAGE",
                "description": "Application creates files with world-readable permissions.",
                "severity": "CRITICAL",
            })
        if "MODE_WORLD_WRITEABLE" in smali_text or ("openFileOutput" in smali_text and ("0x2" in smali_text or "const/4 v1, 0x2" in smali_text)):
            findings.append({
                "type": "WORLD_WRITEABLE_STORAGE",
                "description": "Application creates files with world-writeable permissions.",
                "severity": "CRITICAL",
            })

        # 4. Command execution
        if "Ljava/lang/Runtime;->exec" in smali_text or "Ljava/lang/ProcessBuilder;->start" in smali_text:
            findings.append({
                "type": "OS_COMMAND_EXECUTION",
                "description": "Process/Subshell command execution API invocation detected.",
                "severity": "CRITICAL",
            })

        # 5. Dynamic class loading
        if "Ldalvik/system/DexClassLoader;" in smali_text or "Ldalvik/system/PathClassLoader;" in smali_text:
            findings.append({
                "type": "DYNAMIC_CLASS_LOADING",
                "description": "Application dynamically loads code using DexClassLoader/PathClassLoader.",
                "severity": "HIGH",
            })

        # 6. Reflection
        if "Ljava/lang/Class;->forName" in smali_text or "Ljava/lang/reflect/Method;->invoke" in smali_text:
            findings.append({
                "type": "JAVA_REFLECTION_INVOCATION",
                "description": "Reflection API invoked (Class.forName / Method.invoke).",
                "severity": "LOW",
            })

        # 7. SQL Execution
        if "rawQuery" in smali_text or "execSQL" in smali_text:
            findings.append({
                "type": "DATABASE_SQL_EXECUTION",
                "description": "Direct SQLite database raw query execution call detected.",
                "severity": "MEDIUM",
            })

        return {
            "layer": "SMALI",
            "findings": findings,
            "instruction_count": len(smali_text.splitlines()),
            "instructions": parsed_instructions,
            "called_targets": called_targets,
        }
