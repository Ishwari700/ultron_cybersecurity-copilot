# Architecture Design Note: Redaction Vault Persistence & Lifecycle

**Platform**: Local AI-Assisted Bug Bounty Research Platform (v6 Final)  
**Document**: `docs/VAULT_PERSISTENCE_DESIGN.md`  
**Author**: Systems & Security Engineering  
**Status**: Formal Architectural Assessment (Phase 0)  

---

## 1. Executive Recommendation

**Recommendation**: **DEFER** encrypted on-disk persistence of the Redaction Vault. Maintain an **ephemeral in-memory vault** for Phase 0 and Phase 1 research.

Attempting to implement encrypted disk persistence in Phase 0 would inevitably introduce:
1. **The Key Management Paradox**: Storing an encryption key alongside the encrypted vault file on local disk offers zero cryptographic security (security through obscurity).
2. **Unnecessary Attack Surface**: Writing raw secrets to disk (even encrypted) creates risk of key leakage, swap remnants, crash dumps, and uncoordinated file locks.
3. **Misalignment with Current Workflow**: The v6 platform executes strictly single-process, human-in-the-loop research sessions where raw secrets are ephemeral and only placeholders are required for downstream LLM reasoning, vector retrieval, and reporting.

---

## 2. Threat Model Analysis

### 2.1 Threat Actors & Capabilities
* **Local Malware / Unauthorized Local Processes**: An attacker executing code under the same OS user context. If malware can read `data/vault.enc`, it can also read any static key file, environment variable, or memory space of the Python process.
* **Accidental Exposure (Repository / Backup / Logs)**: Risk of committing secrets to Git or copying raw secrets into debug bundles.
* **Forensic Post-Mortem Inspection**: Risk of extracting plaintext secrets from unencrypted disk blocks after a system reboot or crash.
* **LLM / Third-Party Provider Exfiltration**: Risk of sending active session cookies or AWS keys into model context or vector embeddings.

### 2.2 Security Guarantees Required
* **Zero Leakage into Semantic Layer**: Raw secrets MUST NEVER enter SQLite `evidence.db`, ChromaDB embeddings, console/file logs, or LLM prompts.
* **Correlation Integrity**: Identical raw values MUST receive identical placeholders within the research session so cross-turn authorization reasoning remains sound.
* **Human Verification Support**: Human researchers must be able to inspect and reverse placeholders locally during report validation.

---

## 3. The Key Management Problem

Encrypted persistence requires an external root of trust for key storage:
1. **Static Passphrase / Hardcoded Key**: Cryptographically invalid. Providing a default password or local key file in `config/` gives the illusion of encryption while offering zero actual protection.
2. **Interactive Passphrase on Boot**: Prompts the user on every startup to derive an AES-GCM key via Argon2id / PBKDF2. This breaks non-interactive automation, headless testing, and benchmark execution.
3. **OS-Native Keystore Integration**:
   * Windows: DPAPI (`CryptProtectData`) / Windows Credential Manager
   * Linux: `libsecret` / Kernel Keyrings
   * macOS: Apple Keychain  
   * *Assessment*: Implementing platform-specific secure enclaves requires external C-extensions and platform bindings, adding significant architectural complexity without advancing the core research question.

---

## 4. Persistence Lifecycle & Current Single-Process Workflow

In the current single-process research workflow:
1. **Ingestion**: Raw HTTP traffic or OpenAPI specs enter via adapters. Secrets are intercepted immediately by `RedactionVault.redact_text()` / `redact_dict()`.
2. **Placeholder Assignment**: Stable typed placeholders (`[REDACTED_AWS_SECRET_1]`, `[REDACTED_COOKIE_1]`) are assigned and stored in an in-memory bijection table (`_raw_to_placeholder`, `_placeholder_to_raw`).
3. **Downstream Execution**: Normalization, invariant derivation, vector indexing, graph derivation, and LLM reasoning operate exclusively over typed placeholders.
4. **Session Completion**:
   * If a vulnerability hypothesis is confirmed, the human researcher verifies the traffic. The ephemeral vault in memory can reverse placeholders on demand for export.
   * If the process terminates, all raw credentials vanish from volatile RAM.
   * Canonical evidence statements and graph nodes in `evidence.db` contain ONLY placeholders, ensuring the database remains completely safe to store, archive, or commit.

---

## 5. Crash & Multi-Process Behavior

### 5.1 Crash Behavior
* **Ephemeral In-Memory Vault**: If the process crashes (e.g. `SIGKILL`, hardware fault), zero plaintext secrets linger on disk in swap or temporary files. The database contains only sanitized placeholders.
* **Encrypted On-Disk Vault**: If the process crashes mid-write, partial writes or corrupt SQLite WAL files could leave uncommitted buffers or corrupted ciphertexts, requiring transaction recovery and integrity validation.

### 5.2 Multi-Process Architecture (Future Considerations)
If the platform eventually evolves to a multi-process architecture (e.g., worker processes for continuous reconnaissance alongside an API server):
* File-based encrypted sharing would require inter-process synchronization (file locks, mutexes) and coordinated key access.
* The superior design for multi-process operation is a dedicated **Vault Daemon** exposed over a local UNIX domain socket or named pipe with IPC access controls, rather than shared encrypted files on disk.

---

## 6. Conclusion & Roadmap

| Phase | Vault Storage Architecture | Rationale |
| :--- | :--- | :--- |
| **Phase 0 (Current)** | **Ephemeral In-Memory Only** | Zero disk leakage risk, zero key management vulnerability, full correlation support, perfectly aligned with single-process research. |
| **Phase 1** | **Ephemeral In-Memory with Optional Session Export** | Support encrypted JSON export using an explicitly user-provided session passphrase for session migration. |
| **Phase 2+ (Production)** | **OS Keystore (DPAPI/Keyring) or Local Vault Daemon** | Production-grade OS-enforced access control when multi-process background services are introduced. |
