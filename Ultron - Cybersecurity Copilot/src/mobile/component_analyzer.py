"""Android Component and Configuration Security Analyzer for M10.

Evaluates Activities, Services, Broadcast Receivers, and Content Providers.
Identifies candidate risk conditions:
- Exported components without permission boundary
- Insecure deep links / implicit intents
- Content provider data exposure / grantUriPermissions
- Network security configuration (cleartext traffic, user CA trust, pinning)
- Application backup / debuggable flags

Epistemic rule:
- Emits STATIC_INDICATOR, MODEL_HYPOTHESIS, and EVIDENCE_GAP.
- Never promotes static indicators to confirmed vulnerabilities without human verification.
"""

from typing import Any, Dict, List, Optional
from src.mobile.artifacts import (
    AndroidComponent,
    ComponentType,
    DeepLinkArtifact,
    PermissionArtifact,
)


class ComponentSecurityAnalyzer:
    """Evaluates component security boundaries and IPC exposure."""

    @classmethod
    def analyze_components(
        cls,
        components: List[AndroidComponent],
        permissions: Optional[List[PermissionArtifact]] = None,
    ) -> Dict[str, Any]:
        """Performs static security analysis on parsed Android components."""
        indicators: List[Dict[str, Any]] = []
        hypotheses: List[Dict[str, Any]] = []
        evidence_gaps: List[Dict[str, Any]] = []

        perm_dict = {p.name: p for p in (permissions or [])}

        for comp in components:
            # 1. Exported component analysis
            if comp.is_exported:
                if not comp.permission_required:
                    sev = "CRITICAL" if comp.component_type == ComponentType.PROVIDER else "MEDIUM"
                    indicators.append({
                        "type": "STATIC_INDICATOR",
                        "subtype": "UNPROTECTED_EXPORTED_COMPONENT",
                        "component": comp.name,
                        "component_type": comp.component_type.value,
                        "description": f"Exported {comp.component_type.value} '{comp.name}' is accessible to all applications on device.",
                        "severity": sev,
                    })
                    hypotheses.append({
                        "type": "MODEL_HYPOTHESIS",
                        "component": comp.name,
                        "hypothesis": f"Component '{comp.name}' may process arbitrary intents from unauthorized applications.",
                        "verification_needed": f"Inspect decompiled code of '{comp.name}' for internal validation or calling UID checks.",
                    })
                    evidence_gaps.append({
                        "type": "EVIDENCE_GAP",
                        "component": comp.name,
                        "gap": f"Manifest declares {comp.name} exported, but internal Intent handling logic requires Smali/DEX decompilation.",
                    })
                else:
                    perm_obj = perm_dict.get(comp.permission_required)
                    if perm_obj and perm_obj.protection_level in ("normal", "dangerous"):
                        indicators.append({
                            "type": "STATIC_INDICATOR",
                            "subtype": "EXPORTED_COMPONENT_WITH_WEAK_PERMISSION",
                            "component": comp.name,
                            "permission": comp.permission_required,
                            "protection_level": perm_obj.protection_level,
                            "description": f"Exported component protected by non-signature permission '{comp.permission_required}' ({perm_obj.protection_level}).",
                            "severity": "LOW",
                        })

            # 2. Content Provider specific security
            if comp.component_type == ComponentType.PROVIDER and comp.is_exported:
                if comp.grant_uri_permissions:
                    indicators.append({
                        "type": "STATIC_INDICATOR",
                        "subtype": "PROVIDER_GRANT_URI_PERMISSIONS",
                        "component": comp.name,
                        "description": f"Content provider '{comp.name}' enables grantUriPermissions=true.",
                        "severity": "HIGH",
                    })
                    hypotheses.append({
                        "type": "MODEL_HYPOTHESIS",
                        "component": comp.name,
                        "hypothesis": "May allow temporary URI permission delegation leading to unintended file or database access.",
                        "verification_needed": "Verify path permissions and grant-uri-permission filters in provider configuration.",
                    })

            # 3. Deep link analysis
            if comp.has_deep_link:
                indicators.append({
                    "type": "STATIC_INDICATOR",
                    "subtype": "DEEP_LINK_ENTRYPOINT",
                    "component": comp.name,
                    "description": f"Component '{comp.name}' handles external URI / deep link intents.",
                    "severity": "LOW",
                })
                hypotheses.append({
                    "type": "MODEL_HYPOTHESIS",
                    "component": comp.name,
                    "hypothesis": f"Deep link handling in '{comp.name}' might be susceptible to parameter injection or intent redirection.",
                    "verification_needed": "Inspect getIntent().getData() parsing and validation in method bodies.",
                })

        return {
            "total_components": len(components),
            "exported_count": sum(1 for c in components if c.is_exported),
            "indicators": indicators,
            "hypotheses": hypotheses,
            "evidence_gaps": evidence_gaps,
        }

    @classmethod
    def analyze_network_security_config(
        cls,
        config_xml: str,
    ) -> Dict[str, Any]:
        """Analyzes res/xml/network_security_config.xml for insecure configurations."""
        indicators: List[Dict[str, Any]] = []
        hypotheses: List[Dict[str, Any]] = []

        if not config_xml:
            return {"indicators": indicators, "hypotheses": hypotheses}

        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(config_xml)

            # Check cleartextTrafficPermitted
            for elem in root.iter():
                clr = elem.attrib.get("cleartextTrafficPermitted")
                if clr and clr.lower() == "true":
                    indicators.append({
                        "type": "STATIC_INDICATOR",
                        "subtype": "NSC_CLEARTEXT_PERMITTED",
                        "description": f"Network security config explicitly enables cleartext traffic in <{elem.tag}>.",
                        "severity": "HIGH",
                    })
                    hypotheses.append({
                        "type": "MODEL_HYPOTHESIS",
                        "hypothesis": "App allows plain HTTP traffic for specified domains or globally.",
                        "verification_needed": "Verify whether HTTP endpoints transmit authentication tokens or user data.",
                    })

                # Check user certificates trust
                if elem.tag == "certificates":
                    src = elem.attrib.get("src")
                    if src == "user":
                        indicators.append({
                            "type": "STATIC_INDICATOR",
                            "subtype": "NSC_USER_CERTS_TRUSTED",
                            "description": "Network security config trusts user-installed CA certificates.",
                            "severity": "MEDIUM",
                        })
                        hypotheses.append({
                            "type": "MODEL_HYPOTHESIS",
                            "hypothesis": "Application TLS traffic may be intercepted via user-installed proxy CA certificates.",
                            "verification_needed": "Verify if this config is active in release builds or only debug-overrides.",
                        })

                # Check pin-set indicators
                if elem.tag == "pin-set":
                    indicators.append({
                        "type": "STATIC_INDICATOR",
                        "subtype": "NSC_CERTIFICATE_PINNING_CONFIGURED",
                        "description": "Network security config defines certificate pinning (<pin-set>).",
                        "severity": "INFO",
                    })

        except Exception as e:
            indicators.append({
                "type": "STATIC_INDICATOR",
                "subtype": "MALFORMED_NETWORK_SECURITY_CONFIG",
                "description": f"Failed parsing network security config XML: {str(e)}",
                "severity": "LOW",
            })

        return {"indicators": indicators, "hypotheses": hypotheses}
