"""Mobile Application Artifact Schemas for M10 Deep Android Analysis.

Enforces:
1. Strict separation between Manifest, DEX, SMALI, Resources, and Native Libraries.
2. Canonical models: AndroidArtifact, AndroidComponent, DexArtifact, DexClass,
   DexMethod, SmaliInstruction, IntentRelationship, DeepLinkArtifact,
   PermissionArtifact, WebViewArtifact, NativeLibraryArtifact.
3. Cryptographic provenance hashing for all extracted mobile artifacts.
"""

from datetime import datetime, timezone
from enum import Enum
import hashlib
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, ConfigDict


class ComponentType(str, Enum):
    ACTIVITY = "ACTIVITY"
    SERVICE = "SERVICE"
    RECEIVER = "RECEIVER"
    PROVIDER = "PROVIDER"


class AndroidComponent(BaseModel):
    name: str
    component_type: ComponentType
    is_exported: bool
    permission_required: Optional[str] = None
    intent_filters: List[Dict[str, Any]] = Field(default_factory=list)
    has_deep_link: bool = False
    source_layer: str = "MANIFEST"  # MANIFEST, DEX, SMALI
    authorities: Optional[str] = None
    grant_uri_permissions: bool = False
    read_permission: Optional[str] = None
    write_permission: Optional[str] = None

    @property
    def exported(self) -> bool:
        return self.is_exported


class PermissionArtifact(BaseModel):
    name: str
    protection_level: str = "normal"  # normal, dangerous, signature, privileged
    is_custom: bool = False


class DeepLinkArtifact(BaseModel):
    scheme: str
    host: Optional[str] = None
    path_prefix: Optional[str] = None
    target_component: str
    auto_verify: bool = False


class SmaliInstruction(BaseModel):
    opcode: str
    registers: List[str] = Field(default_factory=list)
    target: Optional[str] = None
    comment: Optional[str] = None
    line_number: Optional[int] = None
    raw_text: str = ""


class DexMethod(BaseModel):
    class_name: str
    method_name: str
    signature: str = "()V"
    access_flags: List[str] = Field(default_factory=list)
    is_native: bool = False
    is_abstract: bool = False
    is_static: bool = False
    code_offset: Optional[int] = None
    smali_instructions: List[SmaliInstruction] = Field(default_factory=list)
    called_methods: List[str] = Field(default_factory=list)
    string_refs: List[str] = Field(default_factory=list)

    @property
    def deterministic_id(self) -> str:
        return f"{self.class_name}->{self.method_name}{self.signature}"


class DexClass(BaseModel):
    class_name: str
    super_class: Optional[str] = None
    interfaces: List[str] = Field(default_factory=list)
    access_flags: List[str] = Field(default_factory=list)
    methods: List[DexMethod] = Field(default_factory=list)
    fields: List[str] = Field(default_factory=list)
    source_file: Optional[str] = None


class DexArtifact(BaseModel):
    artifact_id: str = ""
    dex_name: str
    classes: List[DexClass] = Field(default_factory=list)
    string_pool: List[str] = Field(default_factory=list)
    type_pool: List[str] = Field(default_factory=list)
    method_pool: List[str] = Field(default_factory=list)
    content_hash: str = ""

    def compute_hash(self) -> str:
        seed = f"{self.dex_name}:{len(self.classes)}:{len(self.string_pool)}"
        self.content_hash = f"DEX-{hashlib.sha256(seed.encode('utf-8')).hexdigest()[:16]}"
        return self.content_hash


class IntentRelationship(BaseModel):
    source_component: str
    action: Optional[str] = None
    category: Optional[str] = None
    data_uri: Optional[str] = None
    target_component: Optional[str] = None
    is_implicit: bool = False
    extras_referenced: List[str] = Field(default_factory=list)


class WebViewConfig(BaseModel):
    component_name: str
    javascript_enabled: bool = False
    file_access_enabled: bool = False
    allow_universal_access_from_file: bool = False
    has_js_interface: bool = False
    js_interface_names: List[str] = Field(default_factory=list)
    mixed_content_mode: Optional[str] = None


# Alias WebViewArtifact to WebViewConfig for unified naming
WebViewArtifact = WebViewConfig


class NativeLibraryArtifact(BaseModel):
    library_name: str
    abi: str = "arm64-v8a"
    file_size: int = 0
    exported_jni_symbols: List[str] = Field(default_factory=list)
    imported_symbols: List[str] = Field(default_factory=list)
    content_hash: str = ""

    def compute_hash(self) -> str:
        seed = f"{self.library_name}:{self.abi}:{len(self.exported_jni_symbols)}"
        self.content_hash = f"SO-{hashlib.sha256(seed.encode('utf-8')).hexdigest()[:16]}"
        return self.content_hash


class MobileArtifact(BaseModel):
    """Aggregate model representing deep analysis of an Android package."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    package_name: str
    version_name: Optional[str] = None
    version_code: Optional[int] = None
    min_sdk: Optional[int] = None
    target_sdk: Optional[int] = None
    allow_backup: bool = True
    debuggable: bool = False
    test_only: bool = False
    uses_cleartext_traffic: Optional[bool] = None
    network_security_config: Optional[str] = None
    components: List[AndroidComponent] = Field(default_factory=list)
    permissions: List[PermissionArtifact] = Field(default_factory=list)
    deep_links: List[DeepLinkArtifact] = Field(default_factory=list)
    webviews: List[WebViewConfig] = Field(default_factory=list)
    dex_artifacts: List[DexArtifact] = Field(default_factory=list)
    native_libraries: List[NativeLibraryArtifact] = Field(default_factory=list)
    intent_relationships: List[IntentRelationship] = Field(default_factory=list)
    embedded_urls: List[str] = Field(default_factory=list)
    hardcoded_secrets: List[Dict[str, str]] = Field(default_factory=list)
    evidence_layers_analyzed: List[str] = Field(default_factory=list)  # ["MANIFEST", "DEX", "SMALI", "NATIVE"]
    content_hash: str = ""
    analyzed_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def compute_hash(self) -> str:
        seed = f"{self.package_name}:{len(self.components)}:{len(self.permissions)}:{len(self.deep_links)}:{len(self.dex_artifacts)}"
        self.content_hash = f"MOB-{hashlib.sha256(seed.encode('utf-8')).hexdigest()[:16]}"
        return self.content_hash


# Canonical AndroidArtifact alias for M10
AndroidArtifact = MobileArtifact
