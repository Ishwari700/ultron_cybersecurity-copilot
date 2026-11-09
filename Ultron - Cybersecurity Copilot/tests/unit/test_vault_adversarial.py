"""Adversarial and correlation preservation tests for the Redaction Vault (Task 3)."""

from pathlib import Path
import pytest

from src.database.manager import DatabaseManager
from src.evidence.compressor import SemanticCompressor
from src.evidence.vault import RedactionVault, VaultAccessContext, VaultReversalPurpose
from src.retrieval.hybrid import HybridRetriever
from src.retrieval.vector_store import LocalVectorStore

TEST_CTX = VaultAccessContext(actor="test_runner", purpose=VaultReversalPurpose.AUTOMATED_TEST)


def test_typed_redaction_aws_secret_key():
    """Verify AWS Secret Access Key (40 chars) is redacted with stable typed placeholder."""
    vault = RedactionVault()
    text = 'aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
    redacted = vault.redact_text(text)

    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in redacted
    assert "[REDACTED_AWS_SECRET_1]" in redacted
    assert vault.reverse_text(redacted, context=TEST_CTX) == text


def test_typed_redaction_session_and_refresh_tokens():
    """Verify sessionToken, refreshToken, and session_id are redacted with typed placeholders."""
    vault = RedactionVault()
    text = (
        '{"sessionToken": "sess_tok_999888777666", '
        '"refreshToken": "ref_tok_111222333444", '
        '"session_id": "sid_555444333222"}'
    )
    redacted = vault.redact_text(text)

    assert "sess_tok_999888777666" not in redacted
    assert "ref_tok_111222333444" not in redacted
    assert "sid_555444333222" not in redacted

    assert "[REDACTED_SESSION_TOKEN_1]" in redacted
    assert "[REDACTED_REFRESH_TOKEN_1]" in redacted
    assert "[REDACTED_SESSION_TOKEN_2]" in redacted


def test_typed_redaction_cookie_headers():
    """Verify Cookie and Set-Cookie values are redacted while preserving standard attributes."""
    vault = RedactionVault()
    cookie_req = "Cookie: session_id=secret_sess_abc123; user_pref=dark_mode"
    redacted_req = vault.redact_text(cookie_req)

    assert "secret_sess_abc123" not in redacted_req
    assert "dark_mode" not in redacted_req
    assert "Cookie: session_id=[REDACTED_COOKIE_1]; user_pref=[REDACTED_COOKIE_2]" == redacted_req

    set_cookie_resp = "Set-Cookie: auth_token=jwt_val_xyz890; Path=/; Domain=.target.com; HttpOnly; Secure; SameSite=Lax"
    redacted_resp = vault.redact_text(set_cookie_resp)

    assert "jwt_val_xyz890" not in redacted_resp
    assert "Set-Cookie: auth_token=[REDACTED_COOKIE_3]; Path=/; Domain=.target.com; HttpOnly; Secure; SameSite=Lax" == redacted_resp


def test_preservation_of_ordinary_security_identifiers():
    """Verify legitimate security-testing identifiers and canonical IDs are NEVER over-redacted."""
    vault = RedactionVault()
    text = (
        "Researcher user_a executed cross-identity replay against user_b on asset ASSET-INVOICE-001. "
        "Evidence FACT-8819 indicates invoice INV-100 belonging to account ACC-404 was accessed. "
        "Parameter user_id=user_b was sent with status=ACTIVE."
    )
    redacted = vault.redact_text(text)

    # All security identifiers and canonical IDs must remain intact
    assert "user_a" in redacted
    assert "user_b" in redacted
    assert "ASSET-INVOICE-001" in redacted
    assert "FACT-8819" in redacted
    assert "INV-100" in redacted
    assert "ACC-404" in redacted
    assert "user_id" in redacted
    assert "status=ACTIVE" in redacted
    assert "[REDACTED_" not in redacted


def test_correlation_identical_secrets_map_to_identical_placeholders():
    """Verify that two identical secrets in different contexts map to the exact same placeholder."""
    vault = RedactionVault()
    secret_value = "super_secret_master_token_42"

    text1 = f'Turn 1 request headers: Authorization: Bearer {secret_value}'
    text2 = f'Turn 2 database row: token="{secret_value}"'

    redacted1 = vault.redact_text(text1)
    redacted2 = vault.redact_text(text2)

    assert secret_value not in redacted1
    assert secret_value not in redacted2

    # Extract placeholder from first text
    p1 = vault._raw_to_placeholder[secret_value]
    assert p1 in redacted1
    assert p1 in redacted2
    assert vault.reverse_text(redacted1, context=TEST_CTX) == text1
    assert vault.reverse_text(redacted2, context=TEST_CTX) == text2


def test_adversarial_pipeline_zero_raw_secret_leakage(tmp_path: Path):
    """
    Adversarial end-to-end pipeline test:
    secret -> redaction -> compression -> database -> retrieval -> prompt
    Proves raw secret NEVER leaks into database, embeddings, or prompts.
    """
    db_file = tmp_path / "adversarial_evidence.db"
    db = DatabaseManager(db_path=db_file)
    db.initialize_schema()

    vault = RedactionVault()
    compressor = SemanticCompressor(max_summary_chars=500)

    # 1. Adversarial raw evidence containing multiple secret classes
    raw_secret_aws = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    raw_secret_pass = "HostileP@ssw0rd!2026"
    raw_secret_cookie = "session_cookie_super_secret_val"

    raw_statement = (
        f"API response received: aws_secret_access_key='{raw_secret_aws}', "
        f"password='{raw_secret_pass}', "
        f"Cookie: session={raw_secret_cookie}; Path=/; HttpOnly"
    )

    # 2. Redaction step
    redacted_statement = vault.redact_text(raw_statement)
    assert raw_secret_aws not in redacted_statement
    assert raw_secret_pass not in redacted_statement
    assert raw_secret_cookie not in redacted_statement

    # 3. Compression step
    compressed_statement = compressor.compress(redacted_statement)
    assert raw_secret_aws not in compressed_statement
    assert raw_secret_pass not in compressed_statement
    assert raw_secret_cookie not in compressed_statement

    # 4. Database insertion
    fact_id = "FACT-ADV-001"
    db.insert_evidence_item({
        "fact_id": fact_id,
        "certainty": "OBSERVED",
        "source_tool": "burp",
        "statement": compressed_statement,
        "trust": "UNTRUSTED",
    })

    # Verify database content has no raw secret
    stored_fact = db.get_evidence_item(fact_id)
    assert stored_fact is not None
    assert raw_secret_aws not in stored_fact["statement"]
    assert raw_secret_pass not in stored_fact["statement"]
    assert raw_secret_cookie not in stored_fact["statement"]

    # 5. Retrieval step
    vector_store = LocalVectorStore()
    vector_store.add_document(doc_id=fact_id, text=compressed_statement)
    retriever = HybridRetriever(db_manager=db, vector_store=vector_store)
    retrieved_facts = retriever.retrieve("password session aws_secret", k=5)
    assert len(retrieved_facts) > 0

    # 6. Prompt generation
    prompt_snippet = "\n".join(f["statement"] for f in retrieved_facts)
    assert raw_secret_aws not in prompt_snippet
    assert raw_secret_pass not in prompt_snippet
    assert raw_secret_cookie not in prompt_snippet

    # Verify that placeholders ARE present and preserve structure
    assert "[REDACTED_AWS_SECRET_" in prompt_snippet
    assert "[REDACTED_SECRET_" in prompt_snippet
    assert "[REDACTED_COOKIE_" in prompt_snippet
