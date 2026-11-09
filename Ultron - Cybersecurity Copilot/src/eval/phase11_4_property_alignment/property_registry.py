"""
Milestone M5 Phase 11.4: Authoritative Category-to-Security-Property Registry.

Version: 1.0.0
Maps each vulnerability category ID to its deterministic, bounded set of
authoritative security property domains verifiable via perturbation experiments.

Guarantees:
- Deterministic, versioned, auditable mapping.
- Strictly independent of ground-truth vulnerable/control annotations.
- Full compatibility with existing TUPLE_COMPATIBILITY_REGISTRY.
- Fail-closed behavior on unknown categories.
"""

from typing import Dict, List, Optional, Set
from pydantic import BaseModel, Field

from src.eval.phase11_2_polarity.attack_predicate import (
    CATEGORY_SECURITY_PROPERTY_MAP,
    SecurityPropertyDomain,
)

PROPERTY_REGISTRY_VERSION = "1.0.0"


def get_allowed_security_properties(category_id: Optional[str]) -> List[str]:
    """
    Returns the deterministic, sorted list of allowed security property names
    for a given vulnerability category.
    
    Fail-closed: Returns empty list if category_id is None, empty, or unknown.
    """
    if not category_id:
        return []
    cat = category_id.strip()
    if cat not in CATEGORY_SECURITY_PROPERTY_MAP:
        return []
    props = CATEGORY_SECURITY_PROPERTY_MAP[cat]
    return sorted([p.value for p in props])


def is_property_allowed_for_category(category_id: Optional[str], security_property: Optional[str]) -> bool:
    """Checks whether a security property string is permitted for a category."""
    if not category_id or not security_property:
        return False
    allowed = get_allowed_security_properties(category_id)
    return security_property.strip() in allowed


class CategoryPropertyRegistryManifest(BaseModel):
    """Audited export container for the Category -> Security Property registry."""
    registry_version: str = PROPERTY_REGISTRY_VERSION
    total_categories: int
    category_mappings: Dict[str, List[str]]


def export_registry_manifest() -> CategoryPropertyRegistryManifest:
    """Exports complete deterministic registry manifest for provenance tracking."""
    mappings = {
        cat: sorted([p.value for p in props])
        for cat, props in sorted(CATEGORY_SECURITY_PROPERTY_MAP.items())
    }
    return CategoryPropertyRegistryManifest(
        registry_version=PROPERTY_REGISTRY_VERSION,
        total_categories=len(mappings),
        category_mappings=mappings,
    )
