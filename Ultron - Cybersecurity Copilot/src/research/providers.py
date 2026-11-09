"""External Research Provider Interfaces and Implementations (M4).

Defines:
1. ExternalResearchProvider (Abstract Base Class)
2. WebSearchProvider (Technical Documentation, Standards, Advisories)
3. GitHubProvider (Repository inspection, Commit SHAs, Code Snippets, Releases)
"""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
import hashlib
import re
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from src.research.models import (
    ExternalSource,
    ExternalSourceType,
    TrustTier,
)
from src.research.provenance import ResearchProvenanceTracker


class ExternalSearchResult(BaseModel):
    """Normalized search candidate returned by an external research provider."""
    result_id: str
    title: str
    url: str
    snippet: str
    source_type: ExternalSourceType = ExternalSourceType.UNKNOWN
    trust_tier: TrustTier = TrustTier.TIER_UNKNOWN
    publisher: Optional[str] = None
    author: Optional[str] = None
    score: float = 0.0
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ExternalResearchProvider(ABC):
    """Abstract base provider for external technical knowledge retrieval."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Unique identifier for this provider."""
        pass

    @abstractmethod
    def search(
        self,
        query: str,
        limit: int = 5,
        filters: Optional[Dict[str, Any]] = None,
    ) -> List[ExternalSearchResult]:
        """Executes a query and returns normalized search candidates."""
        pass

    @abstractmethod
    def fetch(self, result: ExternalSearchResult) -> ExternalSource:
        """Fetches full content, normalizes markdown, and computes cryptographic hash."""
        pass


class WebSearchProvider(ExternalResearchProvider):
    """
    Provider for official documentation, standards (RFC, OWASP, NIST),
    and vendor advisories.
    
    Includes a deterministic offline technical corpus for evaluation
    and reproducibility, with fallback hooks.
    """

    def __init__(
        self,
        offline_corpus: Optional[Dict[str, Dict[str, Any]]] = None,
        default_trust_tier: TrustTier = TrustTier.TIER_1,
    ) -> None:
        self._offline_corpus = offline_corpus or {}
        self._default_trust_tier = default_trust_tier

    @property
    def provider_name(self) -> str:
        return "web_search_provider"

    def register_document(
        self,
        url: str,
        title: str,
        content: str,
        source_type: ExternalSourceType = ExternalSourceType.OFFICIAL_DOCUMENTATION,
        trust_tier: TrustTier = TrustTier.TIER_1,
        publisher: Optional[str] = None,
        author: Optional[str] = None,
        keywords: Optional[List[str]] = None,
    ) -> None:
        """Registers a known verified document into the local knowledge buffer."""
        self._offline_corpus[url] = {
            "title": title,
            "content": content,
            "source_type": source_type,
            "trust_tier": trust_tier,
            "publisher": publisher,
            "author": author,
            "keywords": keywords or [],
        }

    def search(
        self,
        query: str,
        limit: int = 5,
        filters: Optional[Dict[str, Any]] = None,
    ) -> List[ExternalSearchResult]:
        """Matches query terms against registered documentation and standards."""
        query_terms = set(re.findall(r"\w+", query.lower()))
        results: List[ExternalSearchResult] = []

        for url, doc in self._offline_corpus.items():
            content_lower = doc["content"].lower()
            title_lower = doc["title"].lower()
            keywords = [k.lower() for k in doc.get("keywords", [])]

            matches = sum(1 for term in query_terms if term in title_lower or term in content_lower or any(term in k for k in keywords))
            if matches > 0:
                score = matches / max(len(query_terms), 1)
                snippet = doc["content"][:240].strip() + "..."
                results.append(
                    ExternalSearchResult(
                        result_id=f"WEB-{hashlib.sha256(url.encode()).hexdigest()[:8]}",
                        title=doc["title"],
                        url=url,
                        snippet=snippet,
                        source_type=doc.get("source_type", ExternalSourceType.OFFICIAL_DOCUMENTATION),
                        trust_tier=doc.get("trust_tier", self._default_trust_tier),
                        publisher=doc.get("publisher"),
                        author=doc.get("author"),
                        score=score,
                        metadata={"matched_terms": matches},
                    )
                )

        results.sort(key=lambda r: r.score, reverse=True)
        return results[:limit]

    def fetch(self, result: ExternalSearchResult) -> ExternalSource:
        """Retrieves and normalizes content from the verified document collection."""
        doc = self._offline_corpus.get(result.url)
        raw_text = doc["content"] if doc else result.snippet
        normalized_text = raw_text.strip().replace("\r\n", "\n")
        content_hash = ResearchProvenanceTracker.compute_source_content_hash(normalized_text)

        source_id = f"EXT-SRC-{hashlib.sha256(result.url.encode()).hexdigest()[:8]}"

        return ExternalSource(
            source_id=source_id,
            source_type=result.source_type,
            title=result.title,
            url=result.url,
            content_hash=content_hash,
            publisher=result.publisher,
            author=result.author,
            trust_tier=result.trust_tier,
            raw_content=raw_text,
            normalized_content=normalized_text,
        )


class GitHubProvider(ExternalResearchProvider):
    """
    Provider for GitHub repositories, security advisories, release metadata,
    and exact code snippet provenance.
    """

    def __init__(
        self,
        offline_repos: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> None:
        self._offline_repos = offline_repos or {}

    @property
    def provider_name(self) -> str:
        return "github_provider"

    def register_repo_file(
        self,
        repository: str,
        owner: str,
        path: str,
        content: str,
        commit_sha: str = "main",
        branch: str = "main",
        line_start: int = 1,
        source_type: ExternalSourceType = ExternalSourceType.GITHUB_CODE,
        trust_tier: TrustTier = TrustTier.TIER_1,
        title: Optional[str] = None,
    ) -> None:
        """Registers a GitHub repository file or snippet into the provider."""
        lines = content.splitlines()
        line_end = line_start + max(len(lines) - 1, 0)
        url = f"https://github.com/{owner}/{repository}/blob/{commit_sha}/{path}#L{line_start}-L{line_end}"

        self._offline_repos[url] = {
            "repository": repository,
            "owner": owner,
            "path": path,
            "content": content,
            "commit_sha": commit_sha,
            "branch": branch,
            "line_start": line_start,
            "line_end": line_end,
            "source_type": source_type,
            "trust_tier": trust_tier,
            "title": title or f"{repository}/{path}",
        }

    def search(
        self,
        query: str,
        limit: int = 5,
        filters: Optional[Dict[str, Any]] = None,
    ) -> List[ExternalSearchResult]:
        """Searches GitHub repositories, paths, and source code."""
        query_terms = set(re.findall(r"\w+", query.lower()))
        results: List[ExternalSearchResult] = []

        for url, item in self._offline_repos.items():
            content_lower = item["content"].lower()
            path_lower = item["path"].lower()
            repo_lower = item["repository"].lower()

            matches = sum(1 for term in query_terms if term in content_lower or term in path_lower or term in repo_lower)
            if matches > 0:
                score = matches / max(len(query_terms), 1)
                snippet = item["content"][:240].strip() + "..."
                results.append(
                    ExternalSearchResult(
                        result_id=f"GH-{hashlib.sha256(url.encode()).hexdigest()[:8]}",
                        title=item["title"],
                        url=url,
                        snippet=snippet,
                        source_type=item["source_type"],
                        trust_tier=item["trust_tier"],
                        publisher=item["owner"],
                        score=score,
                        metadata={
                            "repository": item["repository"],
                            "owner": item["owner"],
                            "commit_sha": item["commit_sha"],
                            "path": item["path"],
                            "line_start": item["line_start"],
                            "line_end": item["line_end"],
                        },
                    )
                )

        results.sort(key=lambda r: r.score, reverse=True)
        return results[:limit]

    def fetch(self, result: ExternalSearchResult) -> ExternalSource:
        """Retrieves snippet and constructs complete GitHub provenance."""
        item = self._offline_repos.get(result.url)
        raw_text = item["content"] if item else result.snippet
        normalized_text = raw_text.strip().replace("\r\n", "\n")
        content_hash = ResearchProvenanceTracker.compute_source_content_hash(normalized_text)

        meta = result.metadata
        source_id = f"EXT-SRC-{hashlib.sha256(result.url.encode()).hexdigest()[:8]}"

        return ExternalSource(
            source_id=source_id,
            source_type=result.source_type,
            title=result.title,
            url=result.url,
            content_hash=content_hash,
            publisher=meta.get("owner", result.publisher),
            repository=meta.get("repository"),
            commit_sha=meta.get("commit_sha"),
            path=meta.get("path"),
            line_start=meta.get("line_start"),
            line_end=meta.get("line_end"),
            trust_tier=result.trust_tier,
            raw_content=raw_text,
            normalized_content=normalized_text,
        )
