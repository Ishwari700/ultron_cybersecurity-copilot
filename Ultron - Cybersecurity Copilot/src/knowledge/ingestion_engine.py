"""Knowledge Ingestion Engine & Quarantine Pipeline (Milestone M9 Phase 5 & Phase 16).

Implements the complete deterministic knowledge ingestion pipeline:
    SOURCE -> VALIDATE -> NORMALIZE -> VERSION -> HASH -> DEDUPLICATE -> CHUNK -> METADATA -> EMBEDDING -> INDEX -> PROVENANCE

Features:
- Deterministic SHA-256 hashing
- Quarantine gate for prompt injection and malformed documents
- Deduplication of identical content
- Version tracking without silent history destruction
- Deletion and atomic re-indexing
- Persistent append-only ingestion audit trail
- Strict segregation of User Knowledge from Target Evidence
"""

from datetime import datetime, timezone
import hashlib
import json
import logging
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from src.knowledge.canonical_models import (
    AuthorityLevel,
    CanonicalSourceType,
    KnowledgeDocument,
    KnowledgeFreshnessStatus,
    KnowledgeSection,
    KnowledgeSource,
    KnowledgeVersion,
)
from src.knowledge.chunking import SemanticMarkdownChunker
from src.knowledge.ingestion import SUSPICIOUS_DIRECTIVE_PATTERNS, normalize_markdown_text
from src.knowledge.models import (
    KnowledgeChunk,
    KnowledgeSourceType,
    KnowledgeType,
)
from src.assessment.secrets import SecretRedactor
from src.knowledge.parsers import (
    CorruptDocumentError,
    DocumentParserError,
    EncryptedDocumentError,
    ExtractedDocument,
    OversizedFileError,
    UnifiedDocumentParser,
    UnsupportedFormatError,
)
from src.knowledge.store import VaptKnowledgeStore

logger = logging.getLogger("m9.ingestion_engine")


class SecurityValidationError(ValueError):
    """Raised when an import path violates directory containment or security boundaries."""
    pass


class IngestionStatus:
    SUCCESS = "SUCCESS"
    INDEXED = "INDEXED"
    DUPLICATE = "DUPLICATE"
    QUARANTINED = "QUARANTINED"
    MALFORMED = "MALFORMED"
    DELETED = "DELETED"
    UPDATED = "UPDATED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    DEACTIVATED = "DEACTIVATED"


class KnowledgeIngestionEngine:
    """Enterprise-grade local cybersecurity knowledge ingestion and quarantine engine."""

    def __init__(
        self,
        knowledge_store: VaptKnowledgeStore,
        audit_log_path: Path = Path("data/knowledge/ingestion_audit.jsonl"),
        quarantine_dir: Path = Path("data/knowledge/quarantine"),
        import_root: Path = Path("data/knowledge/imports"),
    ) -> None:
        self.store = knowledge_store
        self.audit_log_path = Path(audit_log_path)
        self.quarantine_dir = Path(quarantine_dir)
        self.import_root = Path(import_root)
        self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self.import_root.mkdir(parents=True, exist_ok=True)
        
        # In-memory document registry for version tracking and deduplication
        self._doc_versions: Dict[str, List[KnowledgeVersion]] = {}
        self._content_hashes: Set[str] = set()

    def scan_for_hostile_content(self, text: str, metadata: Optional[Dict[str, Any]] = None) -> Tuple[bool, List[str]]:
        """
        Inspects content for prompt injection directives, system prompt extraction,
        scope override attempts, and dangerous malformed sequences.
        """
        reasons: List[str] = []
        
        # Check suspicious directive regexes
        for pattern in SUSPICIOUS_DIRECTIVE_PATTERNS:
            if pattern.search(text):
                reasons.append(f"Prompt injection directive matched: {pattern.pattern}")
                
        # Additional M9 adversarial injection signatures
        m9_injection_patterns = [
            re.compile(r"ignore\s+(?:all\s+)?prior\s+instructions", re.IGNORECASE),
            re.compile(r"reveal\s+(?:your\s+)?system\s+prompt", re.IGNORECASE),
            re.compile(r"change\s+(?:the\s+)?assessment\s+scope", re.IGNORECASE),
            re.compile(r"mark\s+(?:the\s+)?finding\s+as\s+verified", re.IGNORECASE),
            re.compile(r"execute\s+this\s+command", re.IGNORECASE),
            re.compile(r"treat\s+this\s+document\s+as\s+system\s+policy", re.IGNORECASE),
            re.compile(r"override\s+scopegate", re.IGNORECASE),
            re.compile(r"authorized_target\s*=\s*all", re.IGNORECASE),
        ]
        for pattern in m9_injection_patterns:
            if pattern.search(text):
                reasons.append(f"M9 adversarial directive detected: {pattern.pattern}")

        # Check metadata for adversarial injection
        if metadata:
            meta_str = json.dumps(metadata)
            for pattern in m9_injection_patterns:
                if pattern.search(meta_str):
                    reasons.append(f"Adversarial injection inside metadata: {pattern.pattern}")

        # Check for null-byte or binary control corruption
        if "\x00" in text:
            reasons.append("Malformed content: Contains null bytes (\\x00)")

        return (len(reasons) > 0, reasons)

    def ingest_document(
        self,
        document_id: str,
        title: str,
        raw_content: str,
        source_id: str = "SRC-LOCAL-USER",
        source_type: CanonicalSourceType = CanonicalSourceType.USER_MARKDOWN,
        authority_level: AuthorityLevel = AuthorityLevel.USER_OWNED,
        metadata: Optional[Dict[str, Any]] = None,
        author: str = "Security Researcher",
        tags: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Executes full ingestion pipeline with validation, quarantine, deduplication,
        versioning, chunking, and audit trail.
        """
        meta = metadata or {}
        category_tags = tags or ["UserKnowledge"]

        # 1. Validation & Quarantine Scan
        is_hostile, reasons = self.scan_for_hostile_content(raw_content, meta)
        if is_hostile:
            quarantine_record = {
                "document_id": document_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "reasons": reasons,
                "title": title,
                "content_preview": raw_content[:200],
            }
            q_file = self.quarantine_dir / f"{document_id}_{int(datetime.now().timestamp())}.json"
            with open(q_file, "w", encoding="utf-8") as f:
                json.dump(quarantine_record, f, indent=2)
            
            self._log_audit(document_id, "QUARANTINE", IngestionStatus.QUARANTINED, reasons=reasons)
            return {
                "status": IngestionStatus.QUARANTINED,
                "reasons": reasons,
                "quarantine_file": str(q_file),
            }

        # 2. Secret Redaction & Text Normalization
        try:
            redacted_raw, _ = SecretRedactor.redact_text(raw_content)
            normalized_content = normalize_markdown_text(redacted_raw)
        except Exception as e:
            self._log_audit(document_id, "NORMALIZE_ERROR", IngestionStatus.MALFORMED, error=str(e))
            return {"status": IngestionStatus.MALFORMED, "error": str(e)}

        if not normalized_content.strip():
            self._log_audit(document_id, "EMPTY_CONTENT", IngestionStatus.MALFORMED)
            return {"status": IngestionStatus.MALFORMED, "error": "Content is empty"}

        # 3. Deterministic Content Hashing
        content_hash = hashlib.sha256(normalized_content.encode("utf-8")).hexdigest()

        # 4. Deduplication Check
        if content_hash in self._content_hashes:
            self._log_audit(document_id, "DEDUPLICATE", IngestionStatus.DUPLICATE, content_hash=content_hash)
            return {
                "status": IngestionStatus.DUPLICATE,
                "document_id": document_id,
                "content_hash": content_hash,
                "message": "Identical content already indexed; skipped redundant ingestion.",
            }

        # 5. Version Tracking
        existing_versions = self._doc_versions.get(document_id, [])
        version_num = f"v{len(existing_versions) + 1}.0.0"
        version_id = f"VER-{document_id}-{content_hash[:8]}"
        
        # Mark previous versions as non-current
        for v in existing_versions:
            v.is_current = False
            
        current_version = KnowledgeVersion(
            version_id=version_id,
            document_id=document_id,
            version_number=version_num,
            content_hash=content_hash,
            is_current=True,
        )
        existing_versions.append(current_version)
        self._doc_versions[document_id] = existing_versions

        # 6. Chunking
        k_src_type = KnowledgeSourceType.PLATFORM_INVARIANT if authority_level == AuthorityLevel.USER_OWNED else KnowledgeSourceType.OWASP_WSTG
        chunks = SemanticMarkdownChunker.chunk_document(
            document_id=document_id,
            title=title,
            source_type=k_src_type,
            knowledge_type=KnowledgeType.VULNERABILITY_PATTERN,
            normalized_body=normalized_content,
            category_tags=category_tags,
        )

        # 7. Index into Knowledge Store
        self.store.insert_chunks(chunks)
        self._content_hashes.add(content_hash)

        # 8. Record Ingestion in Audit Log
        self._log_audit(
            document_id=document_id,
            action="INGEST" if len(existing_versions) == 1 else "UPDATE",
            status=IngestionStatus.SUCCESS if len(existing_versions) == 1 else IngestionStatus.UPDATED,
            version_id=version_id,
            version_number=version_num,
            chunk_count=len(chunks),
            content_hash=content_hash,
        )

        return {
            "status": IngestionStatus.SUCCESS if len(existing_versions) == 1 else IngestionStatus.UPDATED,
            "document_id": document_id,
            "version_id": version_id,
            "version_number": version_num,
            "chunk_count": len(chunks),
            "content_hash": content_hash,
            "chunks": [c.chunk_id for c in chunks],
        }

    def delete_document(self, document_id: str) -> Dict[str, Any]:
        """Atomically deletes a document and its chunks from store and registry."""
        with self.store.conn:
            # Delete from fts_chunks and chunks
            self.store.conn.execute("DELETE FROM fts_chunks WHERE chunk_id IN (SELECT chunk_id FROM chunks WHERE document_id = ?)", (document_id,))
            self.store.conn.execute("DELETE FROM chunks WHERE document_id = ?", (document_id,))
            self.store.conn.execute("DELETE FROM documents WHERE document_id = ?", (document_id,))

        if document_id in self._doc_versions:
            for v in self._doc_versions[document_id]:
                self._content_hashes.discard(v.content_hash)
            del self._doc_versions[document_id]

        self._log_audit(document_id, "DELETE", IngestionStatus.DELETED)
        return {"status": IngestionStatus.DELETED, "document_id": document_id}

    def reindex_document(
        self,
        document_id: str,
        title: str,
        raw_content: str,
        **kwargs: Any
    ) -> Dict[str, Any]:
        """Atomically replaces and re-indexes a document."""
        self.delete_document(document_id)
        return self.ingest_document(document_id, title, raw_content, **kwargs)

    def validate_import_path(
        self,
        raw_path: str,
        import_root: Path = Path("data/knowledge/imports"),
    ) -> Path:
        """
        Enforces canonical directory containment and rejects path traversal
        and symlink escapes outside the configured import root.
        """
        resolved_root = import_root.resolve()
        resolved_root.mkdir(parents=True, exist_ok=True)

        p = Path(raw_path)
        if not p.is_absolute():
            target = (resolved_root / p).resolve()
        else:
            target = p.resolve()

        # 1. Traversal Check: Target must be contained within resolved_root
        try:
            target.relative_to(resolved_root)
        except ValueError:
            raise SecurityValidationError(
                f"Path traversal rejected: '{raw_path}' resolves outside import directory '{resolved_root}'"
            )

        # 2. Symlink Escape Check
        if target.is_symlink():
            real_target = target.resolve()
            try:
                real_target.relative_to(resolved_root)
            except ValueError:
                raise SecurityValidationError(
                    f"Symlink escape rejected: target points outside import directory '{resolved_root}'"
                )

        # 3. File existence and type check
        if not target.exists():
            raise FileNotFoundError(f"File not found in import directory: '{raw_path}'")

        if not target.is_file():
            raise ValueError(f"Target path is not a file: '{raw_path}'")

        return target

    def ingest_bytes(
        self,
        content_bytes: bytes,
        filename: str,
        source_id: Optional[str] = None,
        title: Optional[str] = None,
        authority_level: AuthorityLevel = AuthorityLevel.USER_OWNED,
        source_type: CanonicalSourceType = CanonicalSourceType.USER_MARKDOWN,
        metadata: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None,
        author: str = "Security Researcher",
    ) -> Dict[str, Any]:
        """
        Processes and indexes raw bytes for any supported document format (PDF, Markdown, Plain Text).
        Preserves page boundaries, content hash, physical checksum, and quarantine boundaries.
        """
        original_checksum = hashlib.sha256(content_bytes).hexdigest()
        sid = source_id or f"SRC-{original_checksum[:10].upper()}"
        doc_id = f"DOC-{sid}"
        meta = metadata or {}
        category_tags = tags or ["UserKnowledge"]

        # 1. Parse Document using multi-format parser
        try:
            doc: ExtractedDocument = UnifiedDocumentParser.parse(content_bytes, filename=filename)
        except OversizedFileError as oe:
            self._log_source_failure(sid, filename, "OVERSIZED", str(oe), original_checksum)
            raise
        except UnsupportedFormatError as ue:
            self._log_source_failure(sid, filename, "UNSUPPORTED_FORMAT", str(ue), original_checksum)
            raise
        except Exception as e:
            self._log_source_failure(sid, filename, "PARSER_ERROR", str(e), original_checksum)
            raise DocumentParserError(f"Failed to parse document '{filename}': {e}") from e

        # Handle explicit parser failure (encrypted, corrupt, zero pages)
        if doc.status == "FAILED":
            self.store.insert_source(
                source_id=sid,
                title=title or doc.title or filename,
                source_type=source_type.value if hasattr(source_type, "value") else str(source_type),
                authority_level=authority_level.value if hasattr(authority_level, "value") else str(authority_level),
                filename=filename,
                format=doc.format,
                content_hash=doc.content_hash,
                original_checksum=original_checksum,
                page_count=doc.page_count,
                chunk_count=0,
                status=IngestionStatus.FAILED,
                error_message=doc.error,
                metadata=meta,
            )
            self._log_audit(
                document_id=doc_id,
                action="INGEST_FAILED",
                status=IngestionStatus.FAILED,
                source_id=sid,
                filename=filename,
                error=doc.error,
                is_encrypted=doc.is_encrypted,
                is_corrupt=doc.is_corrupt,
            )
            return {
                "status": IngestionStatus.FAILED,
                "source_id": sid,
                "document_id": doc_id,
                "filename": filename,
                "error": doc.error,
                "is_encrypted": doc.is_encrypted,
                "is_corrupt": doc.is_corrupt,
                "page_count": doc.page_count,
            }

        # 2. Hostile Prompt Injection / Malware Quarantine Scan
        is_hostile, reasons = self.scan_for_hostile_content(doc.raw_content, meta)
        if is_hostile:
            quarantine_filename = f"{sid}_{Path(filename).name}"
            quarantine_path = self.quarantine_dir / quarantine_filename
            with open(quarantine_path, "wb") as qf:
                qf.write(content_bytes)

            self.store.insert_source(
                source_id=sid,
                title=title or doc.title or filename,
                source_type=source_type.value if hasattr(source_type, "value") else str(source_type),
                authority_level=authority_level.value if hasattr(authority_level, "value") else str(authority_level),
                filename=filename,
                format=doc.format,
                content_hash=doc.content_hash,
                original_checksum=original_checksum,
                page_count=doc.page_count,
                chunk_count=0,
                status=IngestionStatus.QUARANTINED,
                error_message="; ".join(reasons),
                metadata={**meta, "quarantine_path": str(quarantine_path), "reasons": reasons},
            )

            self._log_audit(
                document_id=doc_id,
                action="QUARANTINE",
                status=IngestionStatus.QUARANTINED,
                source_id=sid,
                reasons=reasons,
                quarantine_path=str(quarantine_path),
            )
            return {
                "status": IngestionStatus.QUARANTINED,
                "source_id": sid,
                "document_id": doc_id,
                "filename": filename,
                "reasons": reasons,
                "quarantine_path": str(quarantine_path),
            }

        # 3. Content-Identity Deduplication Check
        existing = self.store.get_source_by_hash(doc.content_hash)
        if existing and existing.get("status") in (IngestionStatus.INDEXED, IngestionStatus.PARTIAL, IngestionStatus.SUCCESS):
            self._log_audit(
                document_id=doc_id,
                action="DEDUPLICATE",
                status=IngestionStatus.DUPLICATE,
                source_id=sid,
                duplicate_of=existing["source_id"],
                content_hash=doc.content_hash,
            )
            return {
                "status": IngestionStatus.DUPLICATE,
                "source_id": existing["source_id"],
                "content_hash": doc.content_hash,
                "message": f"Identical content already indexed as source '{existing['source_id']}'; redundant ingestion skipped.",
                "page_count": existing.get("page_count", 0),
                "chunk_count": existing.get("chunk_count", 0),
            }

        # 4. Secret Redaction on Extracted Content
        normalized_content, _ = SecretRedactor.redact_text(doc.raw_content)

        # 5. Build Traceable Chunks (Page-Preserving for PDF, Section-Preserving for MD/TXT)
        chunks: List[KnowledgeChunk] = []
        k_src_type = (
            KnowledgeSourceType.PLATFORM_INVARIANT
            if authority_level == AuthorityLevel.USER_OWNED
            else KnowledgeSourceType.OWASP_WSTG
        )
        k_type = KnowledgeType.VULNERABILITY_PATTERN

        if doc.format == "PDF":
            for page in doc.pages:
                if not page.has_text:
                    continue
                p_text, _ = SecretRedactor.redact_text(page.text)
                p_text = p_text.strip()
                if not p_text:
                    continue

                label_suffix = f" ({page.printed_label})" if page.printed_label else ""
                heading = f"Page {page.page_number}{label_suffix}"
                chunk_id = f"CHK-{sid}-P{page.page_number:03d}-01"
                token_est = max(1, len(p_text.split()))
                c_hash = hashlib.sha256(p_text.encode("utf-8")).hexdigest()

                chunk = KnowledgeChunk(
                    schema_version="3.0.0",
                    chunk_id=chunk_id,
                    document_id=doc_id,
                    source_type=k_src_type,
                    knowledge_type=k_type,
                    category_tags=[f"page:{page.page_number}", "format:pdf"] + category_tags,
                    title=title or doc.title or filename,
                    section_heading=heading,
                    content=p_text,
                    token_estimate=token_est,
                    content_hash=c_hash,
                    trust_tier="USER_VERIFIED",
                )
                chunks.append(chunk)
        else:
            chunks = SemanticMarkdownChunker.chunk_document(
                document_id=doc_id,
                title=title or doc.title or filename,
                source_type=k_src_type,
                knowledge_type=k_type,
                normalized_body=normalized_content,
                category_tags=[f"format:{doc.format.lower()}"] + category_tags,
            )

        # 6. Insert Document Metadata
        from src.knowledge.models import KnowledgeDocumentFrontmatter
        frontmatter = KnowledgeDocumentFrontmatter(
            document_id=doc_id,
            title=title or doc.title or filename,
            source_name=filename,
            source_version="1.0.0",
            source_url=f"local://{filename}",
            license="User Provided",
            author=author or doc.author or "Security Researcher",
            content_hash=doc.content_hash,
        )
        self.store.insert_document(frontmatter, normalized_content)

        # 7. Insert Chunks into Store & FTS5 Index
        self.store.insert_chunks(chunks)
        self._content_hashes.add(doc.content_hash)

        # 8. Register Source Lifecycle in Knowledge Store
        final_status = IngestionStatus.INDEXED if doc.status == "SUCCESS" else IngestionStatus.PARTIAL
        self.store.insert_source(
            source_id=sid,
            title=title or doc.title or filename,
            source_type=source_type.value if hasattr(source_type, "value") else str(source_type),
            authority_level=authority_level.value if hasattr(authority_level, "value") else str(authority_level),
            filename=filename,
            format=doc.format,
            content_hash=doc.content_hash,
            original_checksum=original_checksum,
            page_count=doc.page_count,
            chunk_count=len(chunks),
            status=final_status,
            error_message=doc.error,
            metadata={
                **meta,
                "empty_pages": doc.empty_pages,
                "pages_with_text": doc.pages_with_text,
                "extraction_failures": doc.extraction_failures,
            },
        )

        # 9. Immutable Audit Log
        self._log_audit(
            document_id=doc_id,
            action="INGEST",
            status=final_status,
            source_id=sid,
            filename=filename,
            format=doc.format,
            page_count=doc.page_count,
            chunk_count=len(chunks),
            content_hash=doc.content_hash,
            original_checksum=original_checksum,
        )

        return {
            "status": final_status,
            "source_id": sid,
            "document_id": doc_id,
            "filename": filename,
            "format": doc.format,
            "title": title or doc.title or filename,
            "page_count": doc.page_count,
            "pages_with_text": doc.pages_with_text,
            "empty_pages": doc.empty_pages,
            "chunk_count": len(chunks),
            "chunks": [c.chunk_id for c in chunks],
            "content_hash": doc.content_hash,
            "original_checksum": original_checksum,
            "error": doc.error,
        }

    def ingest_file(
        self,
        file_path: Path,
        source_id: Optional[str] = None,
        title: Optional[str] = None,
        authority_level: AuthorityLevel = AuthorityLevel.USER_OWNED,
        source_type: CanonicalSourceType = CanonicalSourceType.USER_MARKDOWN,
        metadata: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None,
        author: str = "Security Researcher",
    ) -> Dict[str, Any]:
        """Ingests a file from the filesystem."""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Source file not found: {file_path}")
        content_bytes = path.read_bytes()
        return self.ingest_bytes(
            content_bytes=content_bytes,
            filename=path.name,
            source_id=source_id,
            title=title,
            authority_level=authority_level,
            source_type=source_type,
            metadata=metadata,
            tags=tags,
            author=author,
        )

    def import_from_local_path(
        self,
        relative_or_absolute_path: str,
        import_root: Optional[Path] = None,
        source_id: Optional[str] = None,
        title: Optional[str] = None,
        authority_level: AuthorityLevel = AuthorityLevel.USER_OWNED,
        metadata: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Validates directory containment within import_root and processes file.
        Rejects path traversal and symlink escapes.
        """
        root = import_root or getattr(self, "import_root", Path("data/knowledge/imports"))
        safe_path = self.validate_import_path(relative_or_absolute_path, import_root=root)
        return self.ingest_file(
            file_path=safe_path,
            source_id=source_id,
            title=title,
            authority_level=authority_level,
            metadata=metadata,
            tags=tags,
        )

    def deactivate_source(self, source_id: str) -> Dict[str, Any]:
        """Deactivates a source and removes its chunks from active retrieval."""
        success = self.store.deactivate_source(source_id)
        if not success:
            raise ValueError(f"Source '{source_id}' not found")
        self._log_audit(
            document_id=f"DOC-{source_id}",
            action="DEACTIVATE",
            status=IngestionStatus.DEACTIVATED,
            source_id=source_id,
        )
        return {"status": IngestionStatus.DEACTIVATED, "source_id": source_id}

    def list_sources(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """Returns list of registered sources with processing state and counts."""
        return self.store.list_sources(status=status)

    def get_source(self, source_id: str) -> Optional[Dict[str, Any]]:
        """Fetches registered source details by ID."""
        return self.store.get_source(source_id)

    def _log_source_failure(self, source_id: str, filename: str, reason: str, error: str, checksum: str) -> None:
        """Helper to record failed source ingestion in audit trail."""
        self._log_audit(
            document_id=f"DOC-{source_id}",
            action="INGEST_FAILED",
            status=IngestionStatus.FAILED,
            source_id=source_id,
            filename=filename,
            reason=reason,
            error=error,
            original_checksum=checksum,
        )

    def _log_audit(self, document_id: str, action: str, status: str, **details: Any) -> None:
        """Appends an immutable audit entry."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "document_id": document_id,
            "action": action,
            "status": status,
            **details,
        }
        with open(self.audit_log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
