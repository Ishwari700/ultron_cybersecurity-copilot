"""Unit tests for the reversible secret redaction vault."""

from src.evidence.vault import RedactionVault, VaultAccessContext, VaultReversalPurpose


TEST_CTX = VaultAccessContext(actor="test_runner", purpose=VaultReversalPurpose.AUTOMATED_TEST)


def test_redact_jwt():
    """Verify standard JWT tokens are redacted with typed placeholders."""
    vault = RedactionVault()
    raw_jwt = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    text = f"User authenticated with Bearer {raw_jwt} successfully."

    redacted = vault.redact_text(text)
    assert raw_jwt not in redacted
    assert "[REDACTED_JWT_1]" in redacted

    # Verify placeholder stability across repeated appearances
    second_redacted = vault.redact_text(f"Refresh: {raw_jwt}")
    assert "[REDACTED_JWT_1]" in second_redacted

    # Verify reversal for human inspection
    reversed_text = vault.reverse_text(redacted, context=TEST_CTX)
    assert reversed_text == text


def test_redact_aws_key():
    """Verify AWS access keys are redacted."""
    vault = RedactionVault()
    raw_key = "AKIAIOSFODNN7EXAMPLE"
    text = f"AWS_KEY={raw_key}"

    redacted = vault.redact_text(text)
    assert raw_key not in redacted
    assert "[REDACTED_AWS_KEY_1]" in redacted
    assert vault.reverse_text(redacted, context=TEST_CTX) == text


def test_redact_dict_sensitive_keys():
    """Verify sensitive dictionary keys like password, token, api_key have values redacted."""
    vault = RedactionVault()
    data = {
        "username": "alice",
        "password": "SuperSecretPassword123!",
        "api_key": "secret_key_9999",
        "profile": {
            "token": "session_tok_abc",
            "bio": "Developer at Target Corp",
        },
    }

    clean = vault.redact_dict(data)
    assert clean["username"] == "alice"
    assert clean["password"] == "[REDACTED_SECRET_1]"
    assert clean["api_key"] == "[REDACTED_SECRET_2]"
    assert clean["profile"]["token"] == "[REDACTED_SECRET_3]"
    assert clean["profile"]["bio"] == "Developer at Target Corp"

    # Verify reversal
    assert vault.reverse_placeholder("[REDACTED_SECRET_1]", context=TEST_CTX) == "SuperSecretPassword123!"
    assert vault.reverse_placeholder("[REDACTED_SECRET_2]", context=TEST_CTX) == "secret_key_9999"
