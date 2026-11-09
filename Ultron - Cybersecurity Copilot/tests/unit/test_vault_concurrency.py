"""Deterministic concurrency tests for RedactionVault under multi-threaded contention."""

import concurrent.futures
import threading
from typing import List, Tuple
from src.evidence.vault import RedactionVault, VaultAccessContext, VaultReversalPurpose


def test_concurrent_distinct_secrets_no_collisions():
    """Verify concurrent redaction of 100 distinct secrets produces 100 distinct placeholders."""
    vault = RedactionVault()
    num_secrets = 100
    secrets = [f"custom_api_secret_key_{i}_{'x' * 20}" for i in range(num_secrets)]
    context = VaultAccessContext(actor="test_runner", purpose=VaultReversalPurpose.AUTOMATED_TEST)

    def worker(secret: str) -> str:
        text = f"api_key: {secret}"
        redacted = vault.redact_text(text)
        return redacted

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
        results = list(executor.map(worker, secrets))

    # All returned redacted strings must be unique
    assert len(set(results)) == num_secrets
    # Mappings in vault must strictly equal num_secrets
    assert len(vault._placeholder_to_raw) == num_secrets
    assert len(vault._raw_to_placeholder) == num_secrets

    # Verify every secret reverses correctly to its exact original value
    for secret, redacted in zip(secrets, results):
        reversed_text = vault.reverse_text(redacted, context=context)
        assert reversed_text == f"api_key: {secret}"


def test_concurrent_same_secret_multiple_threads():
    """Verify 50 threads redacting the exact same secret assign the exact same placeholder."""
    vault = RedactionVault()
    secret = "shared_super_secret_token_1234567890"
    num_threads = 50
    context = VaultAccessContext(actor="test_runner", purpose=VaultReversalPurpose.AUTOMATED_TEST)

    def worker(_: int) -> str:
        return vault.redact_text(f"Bearer {secret}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
        results = list(executor.map(worker, range(num_threads)))

    # All threads must receive the exact same placeholder
    unique_placeholders = set(results)
    assert len(unique_placeholders) == 1
    placeholder = list(unique_placeholders)[0]
    assert "[REDACTED_BEARER_TOKEN_1]" in placeholder

    # Vault must store exactly one entry
    assert len(vault._placeholder_to_raw) == 1
    assert len(vault._raw_to_placeholder) == 1

    reversed_val = vault.reverse_text(placeholder, context=context)
    assert reversed_val == f"Bearer {secret}"


def test_concurrent_multiple_categories():
    """Verify concurrent redaction across different secret categories preserves category counters."""
    vault = RedactionVault()
    items = []
    # 20 JWTs, 20 AWS keys, 20 Passwords
    for i in range(20):
        # Valid JWT structure eyJ...
        items.append(("JWT", f"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlVzZXIgeyBpIH0ifQ.abcdefghijklmnopqrstuvwxy{i:03d}"))
        items.append(("AWS_KEY", f"AKIA{i:012d}TESTKEY"))
        items.append(("SECRET", f"password: super_secret_pass_{i:03d}"))

    context = VaultAccessContext(actor="test_runner", purpose=VaultReversalPurpose.AUTOMATED_TEST)

    def worker(entry: Tuple[str, str]) -> str:
        _, raw = entry
        return vault.redact_text(raw)

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
        redacted_list = list(executor.map(worker, items))

    assert len(redacted_list) == len(items)
    # Total unique placeholders must match total distinct secrets (60)
    assert len(vault._placeholder_to_raw) == 60
    assert len(vault._secret_integrity) == 60

    # Ensure no cross-mapping or integrity failures on reversal
    for (_, raw), redacted in zip(items, redacted_list):
        reversed_text = vault.reverse_text(redacted, context=context)
        assert reversed_text == raw


def test_concurrent_interleaved_redaction_and_reversal():
    """Verify simultaneous redaction and reversal across threads never raises integrity or race errors."""
    vault = RedactionVault()
    context = VaultAccessContext(actor="test_runner", purpose=VaultReversalPurpose.AUTOMATED_TEST)
    errors: List[Exception] = []

    # Pre-seed some items
    pre_secrets = [f"pre_seeded_secret_{i}" for i in range(20)]
    pre_redacted = [vault.redact_text(f"token: {s}") for s in pre_secrets]

    stop_event = threading.Event()

    def reader():
        while not stop_event.is_set():
            try:
                for s, r in zip(pre_secrets, pre_redacted):
                    rev = vault.reverse_text(r, context=context)
                    assert rev == f"token: {s}"
            except Exception as e:
                errors.append(e)

    def writer(thread_id: int):
        for i in range(30):
            try:
                sec = f"dynamic_secret_{thread_id}_{i}"
                r = vault.redact_text(f"api_key: {sec}")
                rev = vault.reverse_text(r, context=context)
                assert rev == f"api_key: {sec}"
            except Exception as e:
                errors.append(e)

    reader_threads = [threading.Thread(target=reader) for _ in range(4)]
    writer_threads = [threading.Thread(target=writer, args=(t,)) for t in range(8)]

    for t in reader_threads + writer_threads:
        t.start()

    for t in writer_threads:
        t.join()

    stop_event.set()
    for t in reader_threads:
        t.join()

    assert len(errors) == 0, f"Encountered concurrency errors: {errors}"
