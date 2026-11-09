"""Unit tests for M7 Deep Mobile (Android) Pipeline and Mobile Analyst Agent.

Verifies:
1. Manifest parsing: exported components, dangerous permissions, deep links.
2. DEX bytecode analysis: class counts, embedded URLs, suspicious APIs.
3. Smali instruction analysis: insecure WebViews, weak ciphers, world-readable files.
4. Mobile evidence adapter: cryptographic hash and layer tracking.
5. Mobile Android Analyst Agent: generates hypotheses without declaring automatic confirmed findings.
6. Incremental analysis: reports which evidence layers were actually analyzed.
"""

import pytest
from src.agents.mobile import MobileAndroidAnalystAgent
from src.agents.schemas import AgentTask, AgentType
from src.assessment.models import EpistemicStatus
from src.mobile.dex import DexAnalyzer
from src.mobile.evidence import MobileEvidenceAdapter
from src.mobile.manifest import ManifestAnalyzer
from src.mobile.smali import SmaliAnalyzer


SAMPLE_MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.vulnerableapp">
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" />

    <application android:allowBackup="true" android:debuggable="true">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="myapp" android:host="deeplink" />
            </intent-filter>
        </activity>
        <service android:name=".SyncService" android:exported="false" />
        <receiver android:name=".PushReceiver" android:exported="true" />
    </application>
</manifest>
"""

SAMPLE_SMALI = """
.method public configureWebView(Landroid/webkit/WebView;)V
    .registers 3
    invoke-virtual {p1}, Landroid/webkit/WebView;->getSettings()Landroid/webkit/WebSettings;
    move-result-object v0
    const/4 v1, 0x1
    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
    const/4 v1, 0x1
    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setAllowFileAccess(Z)V
    return-void
.end method

.method public encryptData([B)V
    const-string v0, "AES/ECB/PKCS5Padding"
    invoke-static {v0}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;
    return-void
.end method
"""


def test_manifest_analyzer_components_and_deeplinks():
    parsed = ManifestAnalyzer.parse_manifest_xml(SAMPLE_MANIFEST)
    assert parsed["package_name"] == "com.example.vulnerableapp"
    assert len(parsed["permissions"]) == 2

    # Check exported components
    components = parsed["components"]
    exported_comps = [c for c in components if c.exported is True]
    assert len(exported_comps) == 2  # MainActivity and PushReceiver

    # Check deep link extraction
    deep_links = parsed["deep_links"]
    assert len(deep_links) >= 1
    assert deep_links[0].scheme == "myapp"
    assert deep_links[0].host == "deeplink"


def test_dex_analyzer():
    dex_data = {
        "classes": ["com.example.vulnerableapp.MainActivity", "com.example.vulnerableapp.Utils"],
        "strings": [
            "https://api.vulnerableapp.com/v1/auth",
            "Cipher.getInstance",
            "normal_string_123",
        ],
    }
    res = DexAnalyzer.analyze_dex_metadata(dex_data)
    assert res["layer"] == "DEX"
    assert res["class_count"] == 2
    assert "https://api.vulnerableapp.com/v1/auth" in res["embedded_urls"]
    assert any("Cipher.getInstance" in s for s in res["suspicious_apis"])


def test_smali_analyzer_insecure_webview_and_crypto():
    res = SmaliAnalyzer.analyze_smali_block(SAMPLE_SMALI)
    assert res["layer"] == "SMALI"
    findings = res["findings"]
    assert len(findings) >= 3

    types = [f["type"] for f in findings]
    assert "INSECURE_WEBVIEW_JS" in types
    assert "WEBVIEW_FILE_ACCESS" in types
    assert "WEAK_CRYPTO_CIPHER" in types


def test_mobile_evidence_adapter():
    obs = MobileEvidenceAdapter.create_mobile_observation(
        assessment_id="ASM-MOB-001",
        target_asset="app.apk",
        layer="MANIFEST",
        data={"package": "com.example.app", "exported": ["MainActivity"]},
    )
    assert obs.observation_id.startswith("OBS-")
    assert obs.assessment_id == "ASM-MOB-001"
    assert "sha256:" in obs.provenance.get("data_hash", "")


def test_mobile_android_analyst_agent_multi_layer():
    agent = MobileAndroidAnalystAgent(assessment_id="ASM-MOB-001")
    task = AgentTask(
        task_id="TASK-MOB-01",
        agent_type=AgentType.MOBILE,
        assessment_id="ASM-MOB-001",
        objective="Perform multi-layer Android static analysis",
        target_asset="vulnerableapp.apk",
        authorization_id="AUTH-001",
    )

    manifest_obs = MobileEvidenceAdapter.create_mobile_observation(
        assessment_id="ASM-MOB-001",
        target_asset="vulnerableapp.apk",
        layer="MANIFEST",
        data=ManifestAnalyzer.parse_manifest_xml(SAMPLE_MANIFEST),
    )
    smali_obs = MobileEvidenceAdapter.create_mobile_observation(
        assessment_id="ASM-MOB-001",
        target_asset="vulnerableapp.apk",
        layer="SMALI",
        data=SmaliAnalyzer.analyze_smali_block(SAMPLE_SMALI),
    )

    context = {
        "observations": [
            manifest_obs.model_dump(),
            smali_obs.model_dump(),
        ]
    }

    out = agent.run(task, context)
    assert out.agent_type == AgentType.MOBILE
    assert out.epistemic_status == EpistemicStatus.MODEL_HYPOTHESIS
    assert len(out.hypotheses) >= 2

    # Verify layer tracking in provenance
    layers_analyzed = out.provenance.get("layers_analyzed", [])
    assert "MANIFEST" in layers_analyzed
    assert "SMALI" in layers_analyzed
    assert "DEX" not in layers_analyzed  # Incremental: DEX was not in context!


def test_string_secret_analyzer_detection_and_redaction():
    from src.mobile.string_secret_analyzer import StringSecretAnalyzer

    strings = [
        "https://api.target.com/v1/auth",
        "https://my-bucket.s3.amazonaws.com/uploads",
        "api_key=AKIAIOSFODNN7EXAMPLE",
        "NORMAL_STRING_CONSTANT",
    ]
    res = StringSecretAnalyzer.analyze_strings(strings)
    assert "https://api.target.com/v1/auth" in res["endpoints"]
    assert any(c["type"] == "AWS_S3_BUCKET" for c in res["cloud_endpoints"])
    assert len(res["detected_secrets"]) >= 1
    # Check that secrets are redacted
    sec = res["detected_secrets"][0]
    assert "AKIAIOSFODNN7EXAMPLE" not in sec["raw_redacted"]
    assert "SECRET_REDACTED" in sec["raw_redacted"]

