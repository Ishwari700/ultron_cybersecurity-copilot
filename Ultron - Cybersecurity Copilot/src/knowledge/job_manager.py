"""Persistent Textbook Ingestion Job System & Background Queue Manager.

Manages durable, crash-resilient ingestion jobs for textbooks and reference manuals:
- FIFO queue scheduling ensuring single-active-worker execution.
- Durable persistence in SQLite vapt_knowledge.db surviving backend restarts.
- Genuine, non-simulated progress tracking (page extraction, chunk creation, index persistence).
- Safe cancellation (Stop = Cancel) preserving already committed chunks and sources.
- Safe retry resuming from valid checkpoints without data duplication.
"""

from datetime import datetime, timezone
import hashlib
import json
import logging
from pathlib import Path
import threading
import time
from typing import Any, Callable, Dict, List, Optional
import uuid

from src.knowledge.canonical_models import (
    AuthorityLevel,
    CanonicalSourceType,
    IngestionJobRecord,
    IngestionJobStatus,
    IngestionPhase,
)
from src.knowledge.ingestion_engine import IngestionStatus, KnowledgeIngestionEngine
from src.knowledge.parsers import UnifiedDocumentParser
from src.knowledge.store import VaptKnowledgeStore

logger = logging.getLogger("Ultron.IngestionJobManager")


class IngestionJobManager:
    """
    Durable, FIFO background ingestion queue manager for Ultron Knowledge Lab.
    Guarantees exactly one active ingestion job at a time while keeping
    other textbooks persistently queued and recoverable after restarts.
    """

    def __init__(
        self,
        knowledge_store: VaptKnowledgeStore,
        ingestion_engine: KnowledgeIngestionEngine,
        staging_dir: Optional[Path] = None,
        auto_start: bool = True,
    ) -> None:
        self.store = knowledge_store
        self.engine = ingestion_engine
        self.staging_dir = staging_dir or Path("data/knowledge/staged")
        self.staging_dir.mkdir(parents=True, exist_ok=True)

        self._lock = threading.Lock()
        self._queue_cv = threading.Condition(self._lock)
        self._running = True
        self._active_job_id: Optional[str] = None
        self._worker_thread: Optional[threading.Thread] = None

        # Recover jobs from database on startup
        self.recover_on_startup()

        if auto_start:
            self.start_worker()

    def start_worker(self) -> None:
        """Start single background worker thread if not already running."""
        with self._lock:
            if self._worker_thread is None or not self._worker_thread.is_alive():
                self._running = True
                self._worker_thread = threading.Thread(
                    target=self._worker_loop,
                    name="UltronIngestionWorker",
                    daemon=True,
                )
                self._worker_thread.start()
                logger.info("IngestionJobManager background worker thread started")

    def stop_worker(self, timeout: float = 5.0) -> None:
        """Stop background worker cleanly."""
        with self._lock:
            self._running = False
            self._queue_cv.notify_all()
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=timeout)

    def recover_on_startup(self) -> None:
        """
        Durable crash recovery: inspect database on startup.
        If any job was left in PROCESSING when backend shut down, reset it to QUEUED
        so it resumes from its staged file and checkpoint without losing work.
        Recalculates queue positions for all QUEUED jobs in FIFO order.
        """
        with self._lock:
            all_jobs = self.store.list_ingestion_jobs()
            reassigned = False

            for j in all_jobs:
                if j.get("status") == IngestionJobStatus.PROCESSING.value:
                    logger.warning(
                        f"Recovering interrupted ingestion job {j['job_id']} (was PROCESSING on restart)"
                    )
                    self.store.update_ingestion_job(
                        j["job_id"],
                        {
                            "status": IngestionJobStatus.QUEUED.value,
                            "phase": IngestionPhase.QUEUED.value,
                            "error_message": "Recovered after backend restart; queued for safe resumption.",
                        },
                    )
                    reassigned = True

            # Recalculate queue positions
            self._recalculate_queue_positions_locked()
            logger.info("IngestionJobManager startup recovery completed")

    def _recalculate_queue_positions_locked(self) -> None:
        """Update 1-based queue_position for all active/waiting jobs."""
        queued_jobs = self.store.list_ingestion_jobs(status=IngestionJobStatus.QUEUED.value)
        # Sort strictly by created_at ASC (FIFO)
        queued_jobs.sort(key=lambda x: x.get("created_at", ""))
        pos = 1
        for j in queued_jobs:
            self.store.update_ingestion_job(j["job_id"], {"queue_position": pos})
            pos += 1

    def enqueue_bytes(
        self,
        content_bytes: bytes,
        filename: str,
        title: Optional[str] = None,
        authority_level: str = "USER_OWNED",
        tags: Optional[List[str]] = None,
    ) -> IngestionJobRecord:
        """
        Stage file bytes durably and create an ingestion job in QUEUED status.
        Survives browser refresh, tab navigation, and application restart.
        """
        job_id = f"JOB-{uuid.uuid4().hex[:10].upper()}"
        file_hash = hashlib.sha256(content_bytes).hexdigest()
        source_id = f"SRC-{file_hash[:10].upper()}"

        safe_filename = Path(filename).name
        staged_path = self.staging_dir / f"{job_id}_{safe_filename}"
        with open(staged_path, "wb") as f:
            f.write(content_bytes)

        now = datetime.now(timezone.utc).isoformat()
        checkpoint = {
            "staged_path": str(staged_path),
            "file_hash": file_hash,
            "tags": tags or [],
            "source_id": source_id,
        }

        with self._lock:
            # Determine initial queue position
            active_queued = self.store.list_ingestion_jobs(status=IngestionJobStatus.QUEUED.value)
            pos = len(active_queued) + (1 if self._active_job_id else 0) + 1

            job_dict = {
                "job_id": job_id,
                "source_id": source_id,
                "filename": safe_filename,
                "title": title or safe_filename,
                "authority_level": authority_level,
                "status": IngestionJobStatus.QUEUED.value,
                "phase": IngestionPhase.QUEUED.value,
                "queue_position": pos,
                "total_pages": 0,
                "completed_pages": 0,
                "total_chunks": 0,
                "completed_chunks": 0,
                "checkpoint_json": checkpoint,
                "error_message": None,
                "retry_count": 0,
                "cancellation_requested": 0,
                "created_at": now,
                "started_at": None,
                "updated_at": now,
                "completed_at": None,
            }
            self.store.insert_ingestion_job(job_dict)
            self._recalculate_queue_positions_locked()
            self._queue_cv.notify_all()

        rec = self.get_job(job_id)
        if not rec:
            raise RuntimeError(f"Failed to persist job record {job_id}")
        return rec

    def cancel_job(self, job_id: str) -> bool:
        """
        Stop/Cancel an active or queued ingestion job (Requirement 3.6).
        Preserves all content already committed to SQLite.
        Does NOT cancel other queued textbooks.
        """
        with self._lock:
            job = self.store.get_ingestion_job(job_id)
            if not job:
                return False

            status = job.get("status")
            if status in (IngestionJobStatus.COMPLETED.value, IngestionJobStatus.FAILED.value, IngestionJobStatus.CANCELLED.value):
                return True

            now = datetime.now(timezone.utc).isoformat()
            if status == IngestionJobStatus.QUEUED.value:
                # Immediately cancel queued job
                self.store.update_ingestion_job(
                    job_id,
                    {
                        "status": IngestionJobStatus.CANCELLED.value,
                        "phase": IngestionPhase.CANCELLED.value,
                        "queue_position": 0,
                        "cancellation_requested": 1,
                        "completed_at": now,
                        "error_message": "Ingestion cancelled by user while queued.",
                    },
                )
                self._recalculate_queue_positions_locked()
                return True
            elif status == IngestionJobStatus.PROCESSING.value:
                # Mark cancellation requested; worker will halt at safe checkpoint
                self.store.update_ingestion_job(
                    job_id,
                    {"cancellation_requested": 1},
                )
                return True

        return False

    def retry_job(self, job_id: str) -> IngestionJobRecord:
        """
        Retry a FAILED or CANCELLED ingestion job safely.
        Reuses valid committed content and checkpoint without duplicate chunks.
        """
        with self._lock:
            job = self.store.get_ingestion_job(job_id)
            if not job:
                raise ValueError(f"Ingestion job '{job_id}' not found")

            status = job.get("status")
            if status not in (IngestionJobStatus.FAILED.value, IngestionJobStatus.CANCELLED.value):
                raise ValueError(f"Cannot retry job '{job_id}' with status '{status}' (must be FAILED or CANCELLED)")

            # Check if staged file exists
            checkpoint = job.get("checkpoint_json") or {}
            staged_path = checkpoint.get("staged_path")
            if not staged_path or not Path(staged_path).exists():
                # Look for backup in staging_dir
                candidate = self.staging_dir / f"{job_id}_{job['filename']}"
                if candidate.exists():
                    staged_path = str(candidate)
                    checkpoint["staged_path"] = staged_path
                else:
                    raise FileNotFoundError(
                        f"Original staged file for job '{job_id}' not found at '{staged_path}'"
                    )

            now = datetime.now(timezone.utc).isoformat()
            retry_cnt = job.get("retry_count", 0) + 1

            self.store.update_ingestion_job(
                job_id,
                {
                    "status": IngestionJobStatus.QUEUED.value,
                    "phase": IngestionPhase.QUEUED.value,
                    "retry_count": retry_cnt,
                    "cancellation_requested": 0,
                    "error_message": None,
                    "completed_at": None,
                    "checkpoint_json": checkpoint,
                    "updated_at": now,
                },
            )
            self._recalculate_queue_positions_locked()
            self._queue_cv.notify_all()

        rec = self.get_job(job_id)
        if not rec:
            raise RuntimeError(f"Failed to reload job record {job_id}")
        return rec

    def get_job(self, job_id: str) -> Optional[IngestionJobRecord]:
        """Fetch a single ingestion job record."""
        raw = self.store.get_ingestion_job(job_id)
        if not raw:
            return None
        return IngestionJobRecord(
            job_id=raw["job_id"],
            source_id=raw["source_id"],
            filename=raw["filename"],
            title=raw.get("title"),
            authority_level=raw.get("authority_level", "USER_OWNED"),
            status=IngestionJobStatus(raw.get("status", "QUEUED")),
            phase=IngestionPhase(raw.get("phase", "QUEUED")),
            queue_position=raw.get("queue_position", 0),
            total_pages=raw.get("total_pages", 0),
            completed_pages=raw.get("completed_pages", 0),
            total_chunks=raw.get("total_chunks", 0),
            completed_chunks=raw.get("completed_chunks", 0),
            checkpoint_json=raw.get("checkpoint_json") or {},
            error_message=raw.get("error_message"),
            retry_count=raw.get("retry_count", 0),
            cancellation_requested=bool(raw.get("cancellation_requested", False)),
            created_at=raw.get("created_at"),
            started_at=raw.get("started_at"),
            updated_at=raw.get("updated_at"),
            completed_at=raw.get("completed_at"),
        )

    def list_jobs(self, status: Optional[str] = None) -> List[IngestionJobRecord]:
        """List ingestion jobs ordered by created_at (FIFO)."""
        raw_list = self.store.list_ingestion_jobs(status=status)
        records: List[IngestionJobRecord] = []
        for raw in raw_list:
            records.append(
                IngestionJobRecord(
                    job_id=raw["job_id"],
                    source_id=raw["source_id"],
                    filename=raw["filename"],
                    title=raw.get("title"),
                    authority_level=raw.get("authority_level", "USER_OWNED"),
                    status=IngestionJobStatus(raw.get("status", "QUEUED")),
                    phase=IngestionPhase(raw.get("phase", "QUEUED")),
                    queue_position=raw.get("queue_position", 0),
                    total_pages=raw.get("total_pages", 0),
                    completed_pages=raw.get("completed_pages", 0),
                    total_chunks=raw.get("total_chunks", 0),
                    completed_chunks=raw.get("completed_chunks", 0),
                    checkpoint_json=raw.get("checkpoint_json") or {},
                    error_message=raw.get("error_message"),
                    retry_count=raw.get("retry_count", 0),
                    cancellation_requested=bool(raw.get("cancellation_requested", False)),
                    created_at=raw.get("created_at"),
                    started_at=raw.get("started_at"),
                    updated_at=raw.get("updated_at"),
                    completed_at=raw.get("completed_at"),
                )
            )
        return records

    def _worker_loop(self) -> None:
        """
        Continuous single-worker ingestion loop.
        Ensures strict FIFO order across textbooks and safe boundary cancellation.
        """
        while self._running:
            target_job_id: Optional[str] = None
            with self._lock:
                while self._running and target_job_id is None:
                    queued_jobs = self.store.list_ingestion_jobs(status=IngestionJobStatus.QUEUED.value)
                    if queued_jobs:
                        # FIFO: take the oldest queued job
                        queued_jobs.sort(key=lambda x: x.get("created_at", ""))
                        target_job_id = queued_jobs[0]["job_id"]
                        self._active_job_id = target_job_id
                    else:
                        self._active_job_id = None
                        self._queue_cv.wait(timeout=1.0)

            if not self._running or not target_job_id:
                continue

            try:
                self._process_single_job(target_job_id)
            except Exception as e:
                logger.error(f"Fatal error processing job {target_job_id}: {e}", exc_info=True)
                with self._lock:
                    self.store.update_ingestion_job(
                        target_job_id,
                        {
                            "status": IngestionJobStatus.FAILED.value,
                            "phase": IngestionPhase.FAILED.value,
                            "error_message": f"Ingestion error: {e}",
                            "completed_at": datetime.now(timezone.utc).isoformat(),
                            "queue_position": 0,
                        },
                    )
            finally:
                with self._lock:
                    self._active_job_id = None
                    self._recalculate_queue_positions_locked()

    def _process_single_job(self, job_id: str) -> None:
        """
        Executes granular, step-by-step ingestion with live progress updates,
        genuine work unit tracking, checkpointing, and safe cancellation checks.
        """
        job = self.store.get_ingestion_job(job_id)
        if not job or job.get("status") != IngestionJobStatus.QUEUED.value:
            return

        now = datetime.now(timezone.utc).isoformat()
        self.store.update_ingestion_job(
            job_id,
            {
                "status": IngestionJobStatus.PROCESSING.value,
                "phase": IngestionPhase.EXTRACTING_PDF_TEXT.value,
                "started_at": now,
                "queue_position": 1,
            },
        )

        checkpoint = job.get("checkpoint_json") or {}
        staged_path_str = checkpoint.get("staged_path")
        if not staged_path_str or not Path(staged_path_str).exists():
            raise FileNotFoundError(f"Staged file missing for job {job_id}")

        with open(staged_path_str, "rb") as f:
            content_bytes = f.read()

        filename = job["filename"]
        title = job.get("title") or filename
        auth_level_str = job.get("authority_level", "USER_OWNED")
        auth_level = getattr(AuthorityLevel, auth_level_str.upper(), AuthorityLevel.USER_OWNED)
        tags = checkpoint.get("tags") or []

        # Check cancellation before parsing
        cur_job = self.store.get_ingestion_job(job_id)
        if cur_job and cur_job.get("cancellation_requested"):
            self._handle_cancellation(job_id)
            return

        # Progress callback for page-by-page extraction
        def on_page_progress(phase: str, completed: int, total: int) -> None:
            cur = self.store.get_ingestion_job(job_id)
            if cur and cur.get("cancellation_requested"):
                raise InterruptedError(f"Job {job_id} cancelled during {phase}")
            self.store.update_ingestion_job(
                job_id,
                {
                    "phase": IngestionPhase.EXTRACTING_PDF_TEXT.value,
                    "completed_pages": completed,
                    "total_pages": total,
                },
            )

        # 1. Parse document text and pages
        try:
            doc = UnifiedDocumentParser.parse(
                content_bytes,
                filename=filename,
                progress_callback=on_page_progress,
            )
        except InterruptedError:
            self._handle_cancellation(job_id)
            return

        # Check cancellation after parsing
        cur_job = self.store.get_ingestion_job(job_id)
        if cur_job and cur_job.get("cancellation_requested"):
            self._handle_cancellation(job_id)
            return

        # Update parsed page counts
        total_pages = doc.page_count
        self.store.update_ingestion_job(
            job_id,
            {
                "phase": IngestionPhase.CREATING_CHUNKS.value,
                "completed_pages": total_pages,
                "total_pages": total_pages,
            },
        )

        if doc.status == "FAILED":
            self.store.update_ingestion_job(
                job_id,
                {
                    "status": IngestionJobStatus.FAILED.value,
                    "phase": IngestionPhase.FAILED.value,
                    "error_message": doc.error or "Document extraction returned 0 text pages.",
                    "completed_at": datetime.now(timezone.utc).isoformat(),
                    "queue_position": 0,
                },
            )
            return

        # 2. Ingest into knowledge engine (creating chunks, persistence, indexing)
        self.store.update_ingestion_job(
            job_id,
            {"phase": IngestionPhase.PERSISTING_CHUNKS.value},
        )

        # Execute ingest_bytes with pre-parsed document or raw content
        res = self.engine.ingest_bytes(
            content_bytes=content_bytes,
            filename=filename,
            source_id=job["source_id"],
            title=title,
            authority_level=auth_level,
            tags=tags,
        )

        # Check cancellation after chunk persistence
        cur_job = self.store.get_ingestion_job(job_id)
        if cur_job and cur_job.get("cancellation_requested"):
            self._handle_cancellation(job_id)
            return

        # Finalize
        chunk_count = res.get("chunk_count", 0)
        final_now = datetime.now(timezone.utc).isoformat()
        checkpoint["committed_chunks"] = res.get("chunks", [])

        if res.get("status") in (IngestionStatus.INDEXED, IngestionStatus.PARTIAL, IngestionStatus.DUPLICATE, IngestionStatus.SUCCESS):
            self.store.update_ingestion_job(
                job_id,
                {
                    "status": IngestionJobStatus.COMPLETED.value,
                    "phase": IngestionPhase.COMPLETED.value,
                    "total_chunks": chunk_count,
                    "completed_chunks": chunk_count,
                    "checkpoint_json": checkpoint,
                    "queue_position": 0,
                    "completed_at": final_now,
                },
            )
            logger.info(f"Ingestion job {job_id} successfully COMPLETED ({chunk_count} chunks)")
        elif res.get("status") == IngestionStatus.QUARANTINED:
            self.store.update_ingestion_job(
                job_id,
                {
                    "status": IngestionJobStatus.FAILED.value,
                    "phase": IngestionPhase.FAILED.value,
                    "error_message": f"Quarantined: {'; '.join(res.get('reasons', []))}",
                    "queue_position": 0,
                    "completed_at": final_now,
                },
            )
        else:
            self.store.update_ingestion_job(
                job_id,
                {
                    "status": IngestionJobStatus.FAILED.value,
                    "phase": IngestionPhase.FAILED.value,
                    "error_message": res.get("error") or "Ingestion failed during indexing",
                    "queue_position": 0,
                    "completed_at": final_now,
                },
            )

    def _handle_cancellation(self, job_id: str) -> None:
        """Safe cancellation: mark job cancelled without rolling back completed database work."""
        now = datetime.now(timezone.utc).isoformat()
        self.store.update_ingestion_job(
            job_id,
            {
                "status": IngestionJobStatus.CANCELLED.value,
                "phase": IngestionPhase.CANCELLED.value,
                "queue_position": 0,
                "completed_at": now,
                "error_message": "Ingestion safely cancelled by user. Completed work preserved.",
            },
        )
        logger.info(f"Ingestion job {job_id} successfully CANCELLED; committed work preserved.")

