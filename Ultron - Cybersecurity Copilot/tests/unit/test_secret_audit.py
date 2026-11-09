"""Unit tests auditing secret handling and verifying zero secret leakage (Priority 5)."""

import json
from pathlib import Path
from src.core.logging import AuditLogger
from src.engine.runner import ReasoningRunner
from src.eval.ablation import AblationFramework
from src.evidence.adapters.generic_http import GenericHttpAdapter
from src.evidence.vault import RedactionVault, VaultAccessContext, VaultReversalPurpose
from src.retrieval.vector_store import LocalVectorStore


def test_secrets_never_enter_canonical_evidence_prompts_vectors_or_logs(tmp_path):
    """
    Priority 5: Comprehensive audit verifying that raw secrets never enter:
    1. Canonical evidence statements
    2. Model prompts
    3. Vector store / ChromaDB embeddings
    4. Audit logs
    5. Evaluation outputs
    """
    raw_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwidXNlciI6ImFsaWNlIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    raw_aws = "AKIAIOSFODNN7EXAMPLE"
    raw_basic = "Basic dXNlcm5hbWU6c3VwZXJfc2VjcmV0X3Bhc3N3b3Jk"
    raw_secret_val = "SUPER_SECRET_PAYLOAD_TOKEN_XYZ123"

    vault = RedactionVault()
    adapter = GenericHttpAdapter(vault=vault)

    # Ingest HTTP interaction containing multiple raw secret types
    raw_traffic = {
        "method": "POST",
        "url": "https://api.target.com/v1/auth/login",
        "request_headers": {
            "Authorization": f"Bearer {raw_jwt}",
            "X-Api-Key": raw_aws,
            "Proxy-Authorization": raw_basic,
            "Content-Type": "application/json",
        },
        "request_body": json.dumps({"password": raw_secret_val, "username": "alice"}),
        "response_status": 200,
        "response_headers": {"Set-Cookie": f"session={raw_jwt}; HttpOnly"},
        "response_body": json.dumps({"token": raw_jwt, "aws_secret": raw_aws}),
        "source_tool": "test_suite",
    }

    evidence_items = adapter.ingest(raw_traffic)
    assert len(evidence_items) > 0
    ev = evidence_items[0]

    all_raw_secrets = [raw_jwt, raw_aws, raw_basic, raw_secret_val]

    # 1. Verify raw secrets NEVER enter CanonicalEvidence statements or summaries
    ev_dump = json.dumps(ev.model_dump())
    for secret in all_raw_secrets:
        assert secret not in ev_dump, f"Raw secret {secret[:10]} leaked into CanonicalEvidence!"

    # 2. Verify raw secrets NEVER enter prompts built by ReasoningRunner
    runner = ReasoningRunner()
    prompt = runner.build_prompt(
        target_asset={"asset_id": ev.asset_id, "host": ev.host, "normalized_path": ev.normalized_path, "method": ev.http_method},
        category_id="API-AUTH-001",
        retrieved_evidence=[ev.model_dump()],
    )
    for secret in all_raw_secrets:
        assert secret not in prompt, f"Raw secret {secret[:10]} leaked into ReasoningRunner prompt!"

    # 3. Verify raw secrets NEVER enter VectorStore chunks / ChromaDB
    vstore = LocalVectorStore()
    vstore.add_document(doc_id=ev.fact_id, text=ev.statement, metadata={"asset_id": ev.asset_id})
    vstore_dump = json.dumps(vstore._documents)
    for secret in all_raw_secrets:
        assert secret not in vstore_dump, f"Raw secret {secret[:10]} leaked into LocalVectorStore!"

    # 4. Verify raw secrets NEVER enter ordinary audit logs
    log_file = tmp_path / "audit.log"
    logger = AuditLogger(audit_file_path=log_file)
    logger.log_event(
        event_type="evidence_ingested",
        actor="generic_http",
        subject_id=ev.fact_id,
        details={"statement": ev.statement, "summary": ev.response_body_summary},
    )
    logger.log_event(
        event_type="reasoning_step",
        actor="qwen2.5-coder:3b",
        subject_id=ev.asset_id,
        new_state="HYPOTHESIS",
        evidence_ref=ev.fact_id,
        details={"category": "API-AUTH-001"},
    )

    log_contents = log_file.read_text(encoding="utf-8")
    for secret in all_raw_secrets:
        assert secret not in log_contents, f"Raw secret {secret[:10]} leaked into AuditLog!"


def test_typed_placeholders_preserve_correlation_without_exposing_secrets():
    """
    Priority 5: Verify that typed placeholders preserve useful correlation
    (equivalence across turns) while keeping raw secrets isolated in the vault.
    """
    vault = RedactionVault()

    token_tenant_a = "eyJhbGciOiJIUzI1NiJ9.tenantA_payload_1234567890.signatureA_abcdef"
    token_tenant_b = "eyJhbGciOiJIUzI1NiJ9.tenantB_payload_0987654321.signatureB_zyxwvu"

    # Redact Tenant A's token in Request 1
    text_1 = f"Authorization: Bearer {token_tenant_a}"
    redacted_1 = vault.redact_text(text_1)

    # Redact Tenant B's token in Request 2
    text_2 = f"Authorization: Bearer {token_tenant_b}"
    redacted_2 = vault.redact_text(text_2)

    # Redact Tenant A's token again in Request 3
    text_3 = f"X-Tenant-Auth: {token_tenant_a}"
    redacted_3 = vault.redact_text(text_3)

    # Verify distinct placeholders for different tokens
    assert redacted_1 != redacted_2
    assert "[REDACTED_JWT_1]" in redacted_1
    assert "[REDACTED_JWT_2]" in redacted_2

    # Verify identical placeholder for Tenant A's recurring token across turns
    assert "[REDACTED_JWT_1]" in redacted_3

    # Verify neither contains the raw JWT
    assert token_tenant_a not in redacted_1
    assert token_tenant_a not in redacted_3
    assert token_tenant_b not in redacted_2

    # Verify reversal is exact and restricted to the vault with authorized context
    test_ctx = VaultAccessContext(actor="test_runner", purpose=VaultReversalPurpose.AUTOMATED_TEST)
    assert vault.reverse_placeholder("[REDACTED_JWT_1]", context=test_ctx) == token_tenant_a
    assert vault.reverse_placeholder("[REDACTED_JWT_2]", context=test_ctx) == token_tenant_b
    assert vault.reverse_text(redacted_1, context=test_ctx) == text_1


def test_evaluation_outputs_do_not_leak_secrets():
    """
    Priority 5: Verify evaluation outputs from the ablation framework
    do not expose raw secret strings.
    """
    ablation = AblationFramework()
    results = ablation.run_all_ablations()
    results_dump = json.dumps({k: v.model_dump() for k, v in results.items()})

    forbidden_patterns = ["eyJ", "AKIA", "BEGIN RSA PRIVATE KEY", "password123"]
    for pat in forbidden_patterns:
        assert pat not in results_dump
