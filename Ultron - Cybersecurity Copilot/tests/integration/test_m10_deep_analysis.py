"""End-to-End Deep Android and Native Binary Integration Tests for M10.

Tests:
1. Complete Android pipeline: APK extraction -> Manifest -> Components -> DEX -> Smali -> Source/Sink.
2. Complete Native Binary pipeline: ELF parsing -> Mitigations -> Dangerous Sinks -> Native Call Graph.
3. Cross-Artifact Reasoning: Manifest component -> JNI Native Method -> .so Symbol -> Security Sink.
4. Tool Adapters: JADX, Ghidra, radare2 normalization and conflict detection.
5. Evaluation execution: Full 450-case benchmark and 8-track ablation validation.
"""

import io
import pytest
import zipfile

from src.analysis.artifact_graph import AndroidArtifactGraph, RelationType
from src.artifacts.metadata import (
    ArtifactRecord,
    ArtifactType,
    QuarantineReason,
    QuarantineStatus,
)
from src.artifacts.quarantine import ArtifactQuarantineManager
from src.assessment.models import (
    CanonicalObservation,
    ObservationType,
)
from src.binary.artifacts import (
    BinaryArtifact,
    FunctionArtifact,
    SuspiciousSink,
)
from src.binary.dangerous_api_analyzer import DangerousApiAnalyzer
from src.binary.elf_analyzer import ElfAnalyzer
from src.binary.mitigation_analyzer import MitigationAnalyzer
from src.binary.native_call_graph import NativeCallGraph
from src.binary.tool_adapters import (
    DecompilerFunction,
    GhidraAdapter,
    JadxAdapter,
    Radare2Adapter,
    ToolConflictDetector,
    ToolStatus,
)
from src.eval.m10_evaluator import M10Evaluator
from src.mobile.apk_processor import ApkProcessor
from src.mobile.artifacts import (
    AndroidArtifact,
    AndroidComponent,
    ComponentType,
)
from src.mobile.call_graph import AndroidCallGraph
from src.mobile.component_analyzer import ComponentSecurityAnalyzer
from src.mobile.dex_indexer import DexIndexer
from src.mobile.manifest import ManifestAnalyzer
from src.mobile.smali import SmaliAnalyzer
from src.mobile.source_sink_analyzer import SourceSinkAnalyzer


@pytest.fixture
def assessment_id():
    return "ASM-INT-M10-TEST"


def test_e2e_android_analysis_pipeline(assessment_id):
    """Verifies end-to-end static Android analysis on a synthetic APK package."""
    proc = ApkProcessor(assessment_id)

    manifest_xml = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.target.bank">
    <uses-sdk android:minSdkVersion="26" android:targetSdkVersion="33"/>
    <uses-permission android:name="android.permission.INTERNET"/>
    <application android:allowBackup="true" android:debuggable="false">
        <activity android:name="com.target.bank.TransferActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW"/>
                <data android:scheme="bank" android:host="transfer"/>
            </intent-filter>
        </activity>
        <provider android:name="com.target.bank.DataProvider"
                  android:exported="true"
                  android:authorities="com.target.bank.data"
                  android:grantUriPermissions="true"/>
    </application>
</manifest>"""

    smali_code = """
.class public Lcom/target/bank/TransferActivity;
.super Landroid/app/Activity;

.method public doTransfer()V
    .registers 4
    invoke-virtual {p0}, Lcom/target/bank/TransferActivity;->getIntent()Landroid/content/Intent;
    move-result-object v0
    const-string v1, "amount"
    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v2
    invoke-virtual {p0, v2}, Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;)Landroid/database/Cursor;
    return-void
.end method
"""

    # Build synthetic in-memory APK
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("AndroidManifest.xml", manifest_xml)
        zf.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 120)
        zf.writestr("lib/arm64-v8a/libcrypto.so", b"\x7fELF" + b"\x00" * 60)
    raw_apk = buf.getvalue()

    extracted = proc.process_apk_bytes(raw_apk, filename="bank.apk")
    assert extracted.quarantine_status == QuarantineStatus.VALIDATED
    assert "classes.dex" in extracted.dex_files
    assert "lib/arm64-v8a/libcrypto.so" in extracted.native_libs

    # Parse Manifest
    m_res = ManifestAnalyzer.parse_manifest_xml(manifest_xml)
    assert m_res["package_name"] == "com.target.bank"
    assert len(m_res["components"]) == 2
    assert len(m_res["deep_links"]) == 1

    # Security Component Analysis
    c_res = ComponentSecurityAnalyzer.analyze_components(m_res["components"])
    assert c_res["exported_count"] == 2
    assert any(i["subtype"] == "PROVIDER_GRANT_URI_PERMISSIONS" for i in c_res["indicators"])

    # Smali instruction analysis & source/sink
    s_res = SmaliAnalyzer.analyze_smali_block(smali_code)
    assert len(s_res["instructions"]) >= 7
    flow = SourceSinkAnalyzer.analyze_method_flow(
        class_name="Lcom/target/bank/TransferActivity;",
        method_name="doTransfer",
        smali_or_calls=["getIntent", "getStringExtra", "rawQuery"],
        has_sources=True,
    )
    assert flow["has_correlation"] is True
    assert len(flow["sinks"]) >= 1
    assert flow["sinks"][0].sink_type == "SQL_INJECTION"


def test_e2e_native_binary_pipeline(assessment_id):
    """Verifies end-to-end native binary analysis and call graph reachability."""
    # Synthetic ELF descriptor
    binary = BinaryArtifact(
        binary_name="libauth.so",
        architecture="arm64",
        format="ELF",
        nx_enabled=True,
        pie_enabled=True,
        relro_level="FULL",
        stack_canary_present=True,
        symbols_stripped=False,
        imports=["__stack_chk_fail", "system", "strcpy"],
        exports=["Java_com_example_NativeAuth_verifyKey"],
        functions=[
            FunctionArtifact(name="Java_com_example_NativeAuth_verifyKey", is_exported=True),
            FunctionArtifact(name="check_buffer"),
            FunctionArtifact(name="execute_cmd"),
        ],
    )

    mit = MitigationAnalyzer.evaluate_mitigations(binary)
    assert mit["mitigations"]["nx"] is True
    assert mit["mitigations"]["pie"] is True
    assert mit["mitigations"]["relro"] == "FULL"

    sinks = DangerousApiAnalyzer.scan_binary_sinks(binary)
    sink_types = {s.sink_type for s in sinks}
    assert "COMMAND_EXECUTION" in sink_types
    assert "BUFFER_OVERFLOW" in sink_types

    # Call graph reachability
    cg = NativeCallGraph()
    cg.add_call("Java_com_example_NativeAuth_verifyKey", "check_buffer")
    cg.add_call("check_buffer", "execute_cmd")
    cg.add_call("execute_cmd", "system")

    reach, path, unres = cg.is_reachable("Java_com_example_NativeAuth_verifyKey", "system")
    assert reach is True
    assert path == ["Java_com_example_NativeAuth_verifyKey", "check_buffer", "execute_cmd", "system"]
    assert len(unres) == 0


def test_cross_artifact_reasoning_and_provenance(assessment_id):
    """Verifies unified artifact graph correlation from Manifest to JNI to dangerous sink."""
    graph = AndroidArtifactGraph(assessment_id)

    # Add APK node
    graph.add_node("APK:com.sec.app", "APK", "com.sec.app.apk", artifact_id="ART-001")

    # Add Manifest Component
    graph.add_node("COMP:com.sec.app.AuthActivity", "COMPONENT", "AuthActivity", artifact_id="ART-001")

    # Add DEX Class & Method
    graph.add_node("CLASS:Lcom/sec/app/AuthActivity;", "DEX_CLASS", "AuthActivity")
    graph.add_node("METHOD:Lcom/sec/app/AuthActivity;->authNative()V", "METHOD", "authNative")

    # Add Native Library & Function
    graph.add_node("FUNC:libnative.so:Java_com_sec_app_AuthActivity_authNative", "FUNCTION", "Java_com_sec_app_AuthActivity_authNative")
    graph.add_node("SINK:system", "SINK", "system")

    # Connect Edges
    graph.add_edge("APK:com.sec.app", "COMP:com.sec.app.AuthActivity", RelationType.OBSERVED_RELATION, "CONTAINS")
    graph.correlate_manifest_to_dex("com.sec.app.AuthActivity", "Lcom/sec/app/AuthActivity;")
    graph.add_edge("CLASS:Lcom/sec/app/AuthActivity;", "METHOD:Lcom/sec/app/AuthActivity;->authNative()V", RelationType.OBSERVED_RELATION, "DECLARES")
    graph.correlate_jni_native_method("Lcom/sec/app/AuthActivity;->authNative()V", "Java_com_sec_app_AuthActivity_authNative", "libnative.so")
    graph.add_edge("FUNC:libnative.so:Java_com_sec_app_AuthActivity_authNative", "SINK:system", RelationType.OBSERVED_RELATION, "CALLS_SINK")

    # Trace attack path from Component to Sink
    has_path, nodes, unres = graph.find_path_to_sink("COMP:com.sec.app.AuthActivity", "SINK:system")
    assert has_path is True
    assert len(nodes) == 5
    assert len(unres) == 0


def test_tool_adapters_and_conflict_handling(assessment_id):
    """Verifies JADX, Ghidra, radare2 adapters and decompiler conflict handling."""
    jadx = JadxAdapter()
    ghidra = GhidraAdapter()
    r2 = Radare2Adapter()

    assert jadx.tool_name == "JADX"
    assert ghidra.tool_name == "GHIDRA"
    assert r2.tool_name == "RADARE2"

    # Test JADX JSON parsing
    jadx_json = '{"classes": [{"name": "com.test.Util", "super": "Object", "methods": [{"name": "calc", "return_type": "int", "code": "int calc() { return 1; }"}]}]}'
    classes, funcs = jadx.parse_jadx_json_export(jadx_json, artifact_hash="hash_j")
    assert len(classes) == 1
    assert len(funcs) == 1

    # Test Ghidra decompilation export parsing
    ghidra_json = '{"functions": [{"name": "com.test.Util->calc", "address": "0x1000", "return_type": "void*", "decompiled_c": "void* calc() { return 0; }"}]}'
    g_funcs = ghidra.parse_ghidra_decompilation_export(ghidra_json, artifact_hash="hash_g")
    assert len(g_funcs) == 1

    # Conflict detection between JADX and Ghidra
    conflict = ToolConflictDetector.compare_function_decompilations(funcs[0], g_funcs[0])
    assert conflict is not None
    assert conflict.conflict_type == "ATTRIBUTE_MISMATCH"


def test_m10_benchmark_and_ablation_evaluator():
    """Executes the full 450-case benchmark and 8-track ablation study."""
    evaluator = M10Evaluator()
    summary = evaluator.execute_and_export()

    assert summary["benchmark_summary"]["total_cases"] == 450
    assert summary["benchmark_summary"]["passed_cases"] == 450
    assert summary["benchmark_summary"]["failed_cases"] == 0
    assert summary["benchmark_summary"]["overall_accuracy"] == 1.0
    assert summary["benchmark_summary"]["adversarial_accuracy"] == 1.0
    assert len(summary["ablation_study"]) == 8
    assert summary["verdict"] == "PASSED"
