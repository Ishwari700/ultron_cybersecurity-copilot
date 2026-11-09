"""Intentionally Vulnerable Lab Fixtures for M8 Local Security Research.

Covers:
1. IDOR/BOLA
2. Broken Access Control
3. Insecure Session Handling
4. SSRF-like behavior
5. Reflected XSS indicators
6. SQL Injection indicators
7. Insecure Android exported components
8. Insecure Android WebView
9. Insecure TLS configuration
10. Hardcoded secrets
11. Dangerous native C sinks
12. Path traversal
13. Insecure deserialization

INVARIANT: Distinguishes PATTERN_DETECTED from VULNERABILITY_CONFIRMED.
No fixture is confirmed without empirical evidence and human verification.
"""

from typing import Any, Dict, List
from pydantic import BaseModel, Field


class LabFixture(BaseModel):
    """Structured laboratory test case representing intentional vulnerability pattern."""
    fixture_id: str
    category: str
    target_asset: str
    telemetry_type: str
    telemetry_payload: Dict[str, Any]
    pattern_detected: str
    negative_control: str
    falsification_condition: str
    required_evidence_to_confirm: List[str]
    is_confirmed: bool = False  # Distinguishes PATTERN DETECTED from VULNERABILITY CONFIRMED


LAB_FIXTURES: List[LabFixture] = [
    # 1. BOLA / IDOR
    LabFixture(
        fixture_id="LAB-01-BOLA",
        category="BOLA_IDOR",
        target_asset="api.lab.local",
        telemetry_type="har",
        telemetry_payload={
            "log": {"entries": [{
                "request": {
                    "url": "https://api.lab.local/api/v1/accounts/1002/statement",
                    "method": "GET",
                    "headers": [{"name": "Authorization", "value": "Bearer token_user_1001"}],
                },
                "response": {"status": 200, "headers": []},
            }]}
        },
        pattern_detected="Account ID 1002 accessed using session belonging to user 1001.",
        negative_control="User 1002 token accessing Account 1002 must return 200; token 1001 accessing 1002 must return 403.",
        falsification_condition="If Account 1002 is a public sample account accessible to all authenticated users, BOLA is falsified.",
        required_evidence_to_confirm=["Differential response showing 403 on tenant boundary enforcement."],
    ),
    # 2. Broken Access Control
    LabFixture(
        fixture_id="LAB-02-BFLA",
        category="BROKEN_ACCESS_CONTROL",
        target_asset="admin.lab.local",
        telemetry_type="har",
        telemetry_payload={
            "log": {"entries": [{
                "request": {
                    "url": "https://admin.lab.local/admin/system/reboot",
                    "method": "POST",
                    "headers": [{"name": "X-User-Role", "value": "guest"}],
                },
                "response": {"status": 200, "headers": []},
            }]}
        },
        pattern_detected="Privileged action endpoint responded 200 to guest role header.",
        negative_control="Guest session must return 401/403; only verified admin role session receives 200.",
        falsification_condition="Endpoint operates in dry-run simulation mode without real state mutation.",
        required_evidence_to_confirm=["Proof of actual state mutation or execution of administrative command."],
    ),
    # 3. Insecure Session Handling
    LabFixture(
        fixture_id="LAB-03-SESSION",
        category="INSECURE_SESSION",
        target_asset="auth.lab.local",
        telemetry_type="har",
        telemetry_payload={
            "log": {"entries": [{
                "request": {
                    "url": "https://auth.lab.local/api/user/info",
                    "method": "GET",
                    "headers": [{"name": "Cookie", "value": "session_id=sess_post_logout_token"}],
                },
                "response": {"status": 200, "headers": []},
            }]}
        },
        pattern_detected="Session token reused after logout event returns 200 OK.",
        negative_control="Revoked session token must return 401 Unauthorized.",
        falsification_condition="Token belongs to a valid secondary concurrent session.",
        required_evidence_to_confirm=["Observation of explicit logout request timestamped prior to reuse attempt."],
    ),
    # 4. SSRF
    LabFixture(
        fixture_id="LAB-04-SSRF",
        category="SSRF",
        target_asset="webhook.lab.local",
        telemetry_type="har",
        telemetry_payload={
            "log": {"entries": [{
                "request": {
                    "url": "https://webhook.lab.local/fetch?target=http://169.254.169.254/latest/meta-data/",
                    "method": "GET",
                    "headers": [],
                },
                "response": {"status": 200, "headers": []},
            }]}
        },
        pattern_detected="Parameter accepted cloud metadata link-local address.",
        negative_control="Private or link-local IP requests must be blocked by egress firewall or validation filter.",
        falsification_condition="Response is a static mock response rather than live metadata.",
        required_evidence_to_confirm=["Proof of outbound connection from server to target IP."],
    ),
    # 5. Reflected XSS
    LabFixture(
        fixture_id="LAB-05-XSS",
        category="REFLECTED_XSS",
        target_asset="portal.lab.local",
        telemetry_type="har",
        telemetry_payload={
            "log": {"entries": [{
                "request": {
                    "url": "https://portal.lab.local/search?q=<script>alert(1)</script>",
                    "method": "GET",
                    "headers": [],
                },
                "response": {"status": 200, "headers": []},
            }]}
        },
        pattern_detected="Unencoded script tags in query parameter reflected in HTML body.",
        negative_control="Input parameter must be entity-encoded (e.g., &lt;script&gt;) or blocked by CSP.",
        falsification_condition="Content-Type is text/plain or CSP script-src 'none' blocks execution.",
        required_evidence_to_confirm=["HTML document context without script execution mitigation."],
    ),
    # 6. SQL Injection
    LabFixture(
        fixture_id="LAB-06-SQLI",
        category="SQL_INJECTION",
        target_asset="products.lab.local",
        telemetry_type="har",
        telemetry_payload={
            "log": {"entries": [{
                "request": {
                    "url": "https://products.lab.local/items?cat=electronics' OR 1=1--",
                    "method": "GET",
                    "headers": [],
                },
                "response": {"status": 200, "headers": []},
            }]}
        },
        pattern_detected="Boolean tautology in parameter altered item result count.",
        negative_control="Parameter must be parameterized via prepared statements; tautology treated as literal string.",
        falsification_condition="Backend uses document search engine (Elasticsearch) where quotes have search syntax meaning.",
        required_evidence_to_confirm=["Differential database error or parameterized query audit."],
    ),
    # 7. Android Exported Component
    LabFixture(
        fixture_id="LAB-07-ANDROID-EXPORTED",
        category="ANDROID_EXPORTED_COMPONENT",
        target_asset="com.lab.mobile.app",
        telemetry_type="xml",
        telemetry_payload={
            "filename": "AndroidManifest.xml",
            "content": """<manifest package="com.lab.mobile.app">
                <application>
                    <activity android:name=".SecretDebugActivity" android:exported="true">
                        <intent-filter>
                            <action android:name="android.intent.action.VIEW" />
                        </intent-filter>
                    </activity>
                </application>
            </manifest>""",
        },
        pattern_detected="Activity SecretDebugActivity is exported without android:permission requirement.",
        negative_control="Component must declare android:permission or exported='false'.",
        falsification_condition="Activity checks calling package identity via getCallingPackage() or signature check.",
        required_evidence_to_confirm=["Bytecode audit confirming absence of calling package check."],
    ),
    # 8. Android WebView Risk
    LabFixture(
        fixture_id="LAB-08-ANDROID-WEBVIEW",
        category="ANDROID_WEBVIEW",
        target_asset="com.lab.mobile.app",
        telemetry_type="smali",
        telemetry_payload={
            "filename": "WebBridge.smali",
            "content": """.method public initWebView()V
                invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
                invoke-virtual {v0, v2, v3}, Landroid/webkit/WebView;->addJavascriptInterface(Ljava/lang/Object;Ljava/lang/String;)V
                return-void
            .end method""",
        },
        pattern_detected="WebView enables JavaScript and registers JavascriptInterface bridge.",
        negative_control="Bridge methods should restrict domain to secure origin and avoid reflecting native capabilities.",
        falsification_condition="Only loads local asset file:///android_asset/ without external navigation.",
        required_evidence_to_confirm=["Proof that untrusted external URLs can be loaded into WebView."],
    ),
    # 9. Insecure TLS
    LabFixture(
        fixture_id="LAB-09-TLS",
        category="INSECURE_TLS",
        target_asset="secure.lab.local",
        telemetry_type="json",
        telemetry_payload={
            "protocols": ["TLSv1.0", "TLSv1.1"],
            "ciphers": ["TLS_RSA_WITH_RC4_128_SHA"],
            "certificate_valid": False,
        },
        pattern_detected="Service accepts obsolete TLS 1.0 protocol and weak RC4 cipher.",
        negative_control="Server must enforce minimum TLS 1.2 with AEAD ciphers.",
        falsification_condition="Port is a legacy internal telemetry endpoint isolated from user traffic.",
        required_evidence_to_confirm=["Proof that public internet clients negotiate TLS 1.0."],
    ),
    # 10. Hardcoded Secret
    LabFixture(
        fixture_id="LAB-10-SECRET",
        category="HARDCODED_SECRET",
        target_asset="config.lab.local",
        telemetry_type="text",
        telemetry_payload={
            "content": "const AWS_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE'; const AWS_SECRET = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';"
        },
        pattern_detected="Exposed AWS credential string in client script.",
        negative_control="Credentials must be stored in secret vault; client should use ephemeral STS tokens.",
        falsification_condition="Keys belong to local synthetic test mock (e.g. LocalStack dummy keys).",
        required_evidence_to_confirm=["Validation of credential status against target authority."],
    ),
    # 11. Dangerous Native Sink
    LabFixture(
        fixture_id="LAB-11-BINARY-SINK",
        category="DANGEROUS_NATIVE_SINK",
        target_asset="libnative_parser.so",
        telemetry_type="text",
        telemetry_payload={
            "sink": "strcpy",
            "entrypoint": "Java_com_lab_native_parseInput",
            "call_chain": ["Java_com_lab_native_parseInput", "parseHeader", "strcpy"],
        },
        pattern_detected="Direct call path from exported JNI function to unbounded strcpy sink.",
        negative_control="Bounds checking or use of safe strlcpy/strncpy function.",
        falsification_condition="Input length is pre-validated by caller prior to invoking native function.",
        required_evidence_to_confirm=["Proof of input exceeding destination buffer size reaches strcpy."],
    ),
    # 12. Path Traversal
    LabFixture(
        fixture_id="LAB-12-TRAVERSAL",
        category="PATH_TRAVERSAL",
        target_asset="docs.lab.local",
        telemetry_type="har",
        telemetry_payload={
            "log": {"entries": [{
                "request": {
                    "url": "https://docs.lab.local/read?file=../../../../etc/passwd",
                    "method": "GET",
                    "headers": [],
                },
                "response": {"status": 200, "headers": []},
            }]}
        },
        pattern_detected="File download endpoint accepted path traversal sequence.",
        negative_control="Path must be normalized and checked against base directory root.",
        falsification_condition="File parameter is looked up in an immutable whitelist dictionary.",
        required_evidence_to_confirm=["Response content containing actual root file content."],
    ),
    # 13. Insecure Deserialization
    LabFixture(
        fixture_id="LAB-13-DESERIALIZATION",
        category="INSECURE_DESERIALIZATION",
        target_asset="jobs.lab.local",
        telemetry_type="har",
        telemetry_payload={
            "log": {"entries": [{
                "request": {
                    "url": "https://jobs.lab.local/api/task/execute",
                    "method": "POST",
                    "headers": [{"name": "Content-Type", "value": "application/x-python-serialize"}],
                },
                "response": {"status": 200, "headers": []},
            }]}
        },
        pattern_detected="Endpoint accepts raw Python serialized payload.",
        negative_control="Use safe data interchange formats such as JSON or Protocol Buffers.",
        falsification_condition="Endpoint rejects unauthenticated payloads and enforces cryptographic HMAC.",
        required_evidence_to_confirm=["Arbitrary object instantiation demonstration."],
    ),
]
