# M12 Privacy, Data Minimization & Secret Protection

## 1. Data Minimization Principles

1. **Pointers Over Duplication**: The memory subsystem strictly avoids duplicating large evidence payloads, network PCAPs, APK binaries, or full response bodies. Pointers (`EvidencePointer`) reference canonical records by content digest.
2. **Abstracted Shared Memory**: Any research memory promoted to team-visible or cross-assessment namespaces (`SHARED_RESEARCH`, `VERIFIED_PATTERN`) must be abstracted. Target hosts, internal IP ranges (RFC 1918), customer IDs, and session tokens are systematically scrubbed.
3. **No Hidden Chain-of-Thought**: Speculative scratchpads and raw model internal tokens are ephemeral and never persisted to the memory database.

---

## 2. Secret Redaction Integration

Candidate memories are automatically processed through the `MemorySanitizer`:
- Integration with `SecretRedactor` and `RedactionVault`.
- Bearer tokens, JWT signatures, session cookies, Basic auth credentials, API keys, and private SSH/RSA keys are automatically detected and replaced with vault placeholders.
- If raw unredactable credentials (such as AWS access key IDs `AKIA...` or private key headers `-----BEGIN PRIVATE KEY-----`) are present, candidate admission is rejected outright (`SecretPersistenceForbiddenError`).

---

## 3. Tombstoning & User Forgetting

When a user triggers `/api/memory/forget` or deletes a memory item:
1. Active entries in `memory_fts` (FTS5 lexical index) and `memory_embeddings` (dense vector store) are immediately purged.
2. The item is marked `LifecycleState.DELETED` with `is_tombstone=True`.
3. Minimal audit metadata (`tombstone_id`, `memory_id`, `deleted_by`, `deleted_at`, `content_hash`) is preserved in `memory_tombstones` to satisfy enterprise audit trail requirements without retaining confidential text.
4. Subsequent active search queries cannot retrieve the item under any circumstances.
