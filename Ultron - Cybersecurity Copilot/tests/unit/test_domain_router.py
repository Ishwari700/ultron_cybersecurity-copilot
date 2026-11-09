"""Unit Tests for Security Domain Router and Knowledge Registry."""

import pytest
from src.copilot.domain import DomainRouter, SecurityDomain
from src.copilot.registry import CoverageLevel, DomainKnowledgeRegistry


def test_domain_router_jwt_multi_domain():
    res = DomainRouter.classify_domain("Why does this JWT signature validation fail?")
    # Must identify Authentication or Cryptography as primary, with relevant secondary
    assert res.primary_domain in (SecurityDomain.AUTHENTICATION, SecurityDomain.CRYPTOGRAPHY, SecurityDomain.API_SECURITY)
    secondary_set = set(res.secondary_domains)
    assert len(secondary_set) >= 1
    assert res.confidence >= 0.70


def test_domain_router_cross_tenant():
    res = DomainRouter.classify_domain("Why can tenant B access tenant A's invoice?")
    assert res.primary_domain in (SecurityDomain.AUTHORIZATION, SecurityDomain.API_SECURITY, SecurityDomain.WEB_APPLICATION_SECURITY)


def test_domain_router_apk_manifest():
    res = DomainRouter.classify_domain("Analyze this APK manifest for exported broadcast receivers")
    assert res.primary_domain in (SecurityDomain.ANDROID_SECURITY, SecurityDomain.MOBILE_SECURITY)
    assert SecurityDomain.MOBILE_SECURITY in res.secondary_domains or res.primary_domain == SecurityDomain.ANDROID_SECURITY


def test_domain_router_tls_handshake():
    res = DomainRouter.classify_domain("Inspect the TLS cipher suite and SNI certificate during handshake")
    assert res.primary_domain in (SecurityDomain.TLS_SECURITY, SecurityDomain.NETWORK_SECURITY, SecurityDomain.NETWORK_PROTOCOLS)


def test_domain_router_fallback_general():
    res = DomainRouter.classify_domain("What is the basic philosophy behind digital risk management?")
    assert res.primary_domain == SecurityDomain.GENERAL_CYBERSECURITY
    assert res.confidence <= 0.60


def test_domain_knowledge_registry_all_26_domains_present():
    catalog = DomainKnowledgeRegistry.get_all_domains()
    assert len(catalog) == 26
    for dom in SecurityDomain:
        assert dom in catalog
        entry = catalog[dom]
        assert entry.domain == dom
        assert entry.coverage_level in (CoverageLevel.NONE, CoverageLevel.LIMITED, CoverageLevel.PARTIAL, CoverageLevel.GOOD, CoverageLevel.STRONG)
        assert entry.knowledge_chunk_count >= 0
        assert isinstance(entry.supported_task_types, list)


def test_domain_knowledge_registry_coverage_levels():
    # API and Authorization must have STRONG coverage in the local VAPT system
    assert DomainKnowledgeRegistry.get_coverage(SecurityDomain.API_SECURITY) == CoverageLevel.STRONG
    assert DomainKnowledgeRegistry.get_coverage(SecurityDomain.AUTHORIZATION) == CoverageLevel.STRONG

    # Unknown or niche domains like REVERSE_ENGINEERING or MALWARE_ANALYSIS have LIMITED or NONE coverage
    rev_cov = DomainKnowledgeRegistry.get_coverage(SecurityDomain.REVERSE_ENGINEERING)
    assert rev_cov in (CoverageLevel.NONE, CoverageLevel.LIMITED)
