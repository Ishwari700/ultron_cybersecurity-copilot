"""Binary and Reverse Engineering Artifact Schemas for M10.

Models decompiled and disassembled binary artifacts from ELF, PE, Ghidra, JADX, radare2:
- BinaryArtifact, FunctionArtifact, ClassArtifact, MethodArtifact, StringArtifact,
  ImportArtifact, ExportArtifact, SectionArtifact, SymbolArtifact, RelocationArtifact,
  CallRelationship, ControlFlowRelationship, SuspiciousSink, DecompilationObservation.
"""

from datetime import datetime, timezone
import hashlib
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, ConfigDict


class FunctionArtifact(BaseModel):
    name: str
    address: Optional[str] = None
    parameters: List[str] = Field(default_factory=list)
    return_type: str = "void"
    basic_blocks: int = 1
    cyclomatic_complexity: int = 1
    is_exported: bool = False
    is_unresolved: bool = False
    decompiled_code: Optional[str] = None


class MethodArtifact(BaseModel):
    name: str
    return_type: str = "void"
    parameters: List[str] = Field(default_factory=list)
    is_static: bool = False
    is_virtual: bool = True
    address: Optional[str] = None


class ClassArtifact(BaseModel):
    name: str
    superclass: Optional[str] = None
    methods: List[MethodArtifact] = Field(default_factory=list)
    fields: List[str] = Field(default_factory=list)


class StringArtifact(BaseModel):
    value: str
    offset: Optional[int] = None
    section: Optional[str] = None
    encoding: str = "ascii"
    is_suspicious: bool = False
    context: Optional[str] = None


class ImportArtifact(BaseModel):
    symbol_name: str
    library: Optional[str] = None
    address: Optional[str] = None
    is_delayed: bool = False


class ExportArtifact(BaseModel):
    symbol_name: str
    address: Optional[str] = None
    ordinal: Optional[int] = None
    is_forwarded: bool = False


class SectionArtifact(BaseModel):
    name: str
    virtual_address: int = 0
    virtual_size: int = 0
    raw_size: int = 0
    permissions: str = "r-x"  # rwx string
    entropy: float = 0.0


class SymbolArtifact(BaseModel):
    name: str
    address: Optional[str] = None
    symbol_type: str = "FUNC"  # FUNC, OBJECT, NOTYPE, FILE
    binding: str = "GLOBAL"  # LOCAL, GLOBAL, WEAK
    visibility: str = "DEFAULT"
    section_index: Optional[int] = None


class RelocationArtifact(BaseModel):
    offset: int = 0
    symbol_name: str = ""
    relocation_type: str = ""
    addend: int = 0


class SuspiciousSink(BaseModel):
    function_name: str
    sink_type: str  # e.g. RCE, BUFFER_OVERFLOW, SQLI, FORMAT_STRING
    instruction_or_call: str
    reachability_source: Optional[str] = None
    severity: str = "HIGH"
    unresolved: bool = False


class CallRelationship(BaseModel):
    caller: str
    callee: str
    call_site_address: Optional[str] = None
    is_direct: bool = True
    is_unresolved: bool = False


class ControlFlowRelationship(BaseModel):
    source_block: str
    target_block: str
    edge_type: str = "UNCONDITIONAL"  # CONDITIONAL_TRUE, CONDITIONAL_FALSE, UNCONDITIONAL, CALL, RETURN


class DecompilationObservation(BaseModel):
    tool_name: str
    tool_version: Optional[str] = None
    target_symbol: str
    observation_type: str
    code_snippet: Optional[str] = None
    confidence: float = 1.0
    notes: Optional[str] = None
    provenance: Dict[str, Any] = Field(default_factory=dict)


class BinaryArtifact(BaseModel):
    """Aggregate model representing reverse-engineering artifacts from a compiled binary."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    binary_name: str
    architecture: str = "x86_64"  # x86, x86_64, arm64, arm, mips, dalvik
    format: str = "ELF"  # ELF, PE, Mach-O, DEX, APK
    bitness: int = 64
    endianness: str = "little"
    entry_point: Optional[str] = None
    functions: List[FunctionArtifact] = Field(default_factory=list)
    classes: List[ClassArtifact] = Field(default_factory=list)
    call_graph: List[CallRelationship] = Field(default_factory=list)
    sinks: List[SuspiciousSink] = Field(default_factory=list)
    imports: List[str] = Field(default_factory=list)
    exports: List[str] = Field(default_factory=list)
    import_records: List[ImportArtifact] = Field(default_factory=list)
    export_records: List[ExportArtifact] = Field(default_factory=list)
    sections: List[SectionArtifact] = Field(default_factory=list)
    symbols: List[SymbolArtifact] = Field(default_factory=list)
    relocations: List[RelocationArtifact] = Field(default_factory=list)
    string_artifacts: List[StringArtifact] = Field(default_factory=list)
    strings: List[str] = Field(default_factory=list)
    decompilation_observations: List[DecompilationObservation] = Field(default_factory=list)
    # Mitigations
    pie_enabled: Optional[bool] = None
    nx_enabled: Optional[bool] = None
    relro_level: str = "NONE"  # NONE, PARTIAL, FULL
    stack_canary_present: Optional[bool] = None
    symbols_stripped: bool = False
    aslr_compat: Optional[bool] = None
    fortified_functions_count: int = 0
    content_hash: str = ""
    analyzed_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def compute_hash(self) -> str:
        seed = f"{self.binary_name}:{self.architecture}:{len(self.functions)}:{len(self.sinks)}:{len(self.sections)}"
        self.content_hash = f"BIN-{hashlib.sha256(seed.encode('utf-8')).hexdigest()[:16]}"
        return self.content_hash
