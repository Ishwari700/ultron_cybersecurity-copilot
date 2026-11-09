"""Manifest Analyzer for Deep Android Security Analysis in M10.

Parses AndroidManifest.xml structures to extract:
1. Exported vs non-exported Activities, Services, Broadcast Receivers, Content Providers.
2. Standard, custom, and dangerous permissions with protection levels.
3. Intent filters (actions, categories, data schemes, hosts, path prefixes) and deep links.
4. Application configurations: allowBackup, debuggable, testOnly, usesCleartextTraffic,
   networkSecurityConfig, minSdk, targetSdk.
5. Emits structured STATIC_INDICATOR, MODEL_HYPOTHESIS, and EVIDENCE_GAP records
   without claiming automatic exploitability.
"""

import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional
from src.mobile.artifacts import (
    AndroidComponent,
    ComponentType,
    DeepLinkArtifact,
    PermissionArtifact,
)


class ManifestAnalyzer:
    """Extracts security-relevant components and configurations from AndroidManifest.xml."""

    NS = "{http://schemas.android.com/apk/res/android}"

    @classmethod
    def _get_android_attr(cls, elem: ET.Element, name: str) -> Optional[str]:
        return (
            elem.attrib.get(f"{cls.NS}{name}")
            or elem.attrib.get(f"android:{name}")
            or elem.attrib.get(name)
        )

    @classmethod
    def parse_manifest_xml(cls, xml_content: str) -> Dict[str, Any]:
        """
        Parses AndroidManifest.xml string and returns structured components and security indicators.
        Fails safely without raising fatal exceptions on malformed XML.
        """
        result: Dict[str, Any] = {
            "package_name": "",
            "version_name": None,
            "version_code": None,
            "min_sdk": None,
            "target_sdk": None,
            "allow_backup": True,
            "debuggable": False,
            "test_only": False,
            "uses_cleartext_traffic": None,
            "network_security_config": None,
            "components": [],
            "permissions": [],
            "deep_links": [],
            "indicators": [],
            "hypotheses": [],
            "evidence_gaps": [],
            "layer": "MANIFEST",
        }
        if not xml_content or not xml_content.strip():
            return result

        try:
            root = ET.fromstring(xml_content)
        except Exception as e:
            result["indicators"].append({
                "type": "STATIC_INDICATOR",
                "subtype": "MALFORMED_MANIFEST_XML",
                "description": f"Failed to parse manifest XML: {str(e)}",
                "severity": "LOW",
            })
            return result

        result["package_name"] = root.attrib.get("package", "unknown.package")
        result["version_name"] = cls._get_android_attr(root, "versionName")
        vcode_str = cls._get_android_attr(root, "versionCode")
        if vcode_str and vcode_str.isdigit():
            result["version_code"] = int(vcode_str)

        # Uses-SDK
        uses_sdk = root.find(".//uses-sdk")
        if uses_sdk is not None:
            min_sdk_str = cls._get_android_attr(uses_sdk, "minSdkVersion")
            target_sdk_str = cls._get_android_attr(uses_sdk, "targetSdkVersion")
            if min_sdk_str and min_sdk_str.isdigit():
                result["min_sdk"] = int(min_sdk_str)
            if target_sdk_str and target_sdk_str.isdigit():
                result["target_sdk"] = int(target_sdk_str)

        # Application level attributes
        app_elem = root.find(".//application")
        if app_elem is not None:
            bk = cls._get_android_attr(app_elem, "allowBackup")
            if bk is not None:
                result["allow_backup"] = bk.lower() == "true"

            dbg = cls._get_android_attr(app_elem, "debuggable")
            if dbg is not None:
                result["debuggable"] = dbg.lower() == "true"

            tst = cls._get_android_attr(app_elem, "testOnly")
            if tst is not None:
                result["test_only"] = tst.lower() == "true"

            clr = cls._get_android_attr(app_elem, "usesCleartextTraffic")
            if clr is not None:
                result["uses_cleartext_traffic"] = clr.lower() == "true"

            nsc = cls._get_android_attr(app_elem, "networkSecurityConfig")
            if nsc is not None:
                result["network_security_config"] = nsc

        # Configuration Indicators
        if result["debuggable"]:
            result["indicators"].append({
                "type": "STATIC_INDICATOR",
                "subtype": "APP_DEBUGGABLE",
                "description": "Application has android:debuggable enabled in manifest.",
                "severity": "HIGH",
            })
            result["hypotheses"].append({
                "type": "MODEL_HYPOTHESIS",
                "hypothesis": "Application may allow debugging and arbitrary code execution in userdebug/production environments if signed with debug keys.",
                "verification_needed": "Check release build signing key and whether release stripping removed debuggable flag.",
            })

        if result["allow_backup"]:
            result["indicators"].append({
                "type": "STATIC_INDICATOR",
                "subtype": "BACKUP_ENABLED",
                "description": "Application has android:allowBackup set to true or defaulted to true.",
                "severity": "LOW",
            })

        if result["uses_cleartext_traffic"] is True:
            result["indicators"].append({
                "type": "STATIC_INDICATOR",
                "subtype": "CLEARTEXT_TRAFFIC_PERMITTED",
                "description": "Application explicitly permits cleartext HTTP communication.",
                "severity": "MEDIUM",
            })
            result["hypotheses"].append({
                "type": "MODEL_HYPOTHESIS",
                "hypothesis": "Network communication might be susceptible to eavesdropping or MITM if sensitive data is transmitted over plain HTTP.",
                "verification_needed": "Inspect network traffic and endpoint URLs in bytecode.",
            })

        # Permissions
        for perm in root.findall(".//uses-permission"):
            name = cls._get_android_attr(perm, "name") or perm.attrib.get("name", "")
            if name:
                result["permissions"].append(PermissionArtifact(name=name))

        for perm_def in root.findall(".//permission"):
            name = cls._get_android_attr(perm_def, "name") or perm_def.attrib.get("name", "")
            prot = cls._get_android_attr(perm_def, "protectionLevel") or "normal"
            if name:
                result["permissions"].append(PermissionArtifact(name=name, protection_level=prot, is_custom=True))

        # Components
        comp_map = [
            ("activity", ComponentType.ACTIVITY),
            ("service", ComponentType.SERVICE),
            ("receiver", ComponentType.RECEIVER),
            ("provider", ComponentType.PROVIDER),
        ]

        for tag, c_type in comp_map:
            for elem in root.findall(f".//{tag}"):
                c_name = cls._get_android_attr(elem, "name") or elem.attrib.get("name", "")
                if not c_name:
                    continue

                intent_filters = elem.findall(".//intent-filter")
                has_filters = len(intent_filters) > 0

                exported_attr = cls._get_android_attr(elem, "exported")
                if exported_attr is not None:
                    is_exported = exported_attr.lower() == "true"
                else:
                    is_exported = has_filters  # Android legacy default

                perm_req = cls._get_android_attr(elem, "permission")

                # Parse detailed filter data
                filter_data_list = []
                for filter_elem in intent_filters:
                    actions = [cls._get_android_attr(a, "name") for a in filter_elem.findall(".//action") if cls._get_android_attr(a, "name")]
                    categories = [cls._get_android_attr(c, "name") for c in filter_elem.findall(".//category") if cls._get_android_attr(c, "name")]
                    datas = []
                    for data_elem in filter_elem.findall(".//data"):
                        scheme = cls._get_android_attr(data_elem, "scheme")
                        host = cls._get_android_attr(data_elem, "host")
                        prefix = cls._get_android_attr(data_elem, "pathPrefix")
                        mime = cls._get_android_attr(data_elem, "mimeType")
                        datas.append({"scheme": scheme, "host": host, "path_prefix": prefix, "mime_type": mime})
                        if scheme:
                            result["deep_links"].append(DeepLinkArtifact(
                                scheme=scheme,
                                host=host,
                                path_prefix=prefix,
                                target_component=c_name,
                            ))
                    filter_data_list.append({"actions": actions, "categories": categories, "data": datas})

                # Provider specifics
                authorities = None
                grant_uri = False
                read_p = None
                write_p = None
                if c_type == ComponentType.PROVIDER:
                    authorities = cls._get_android_attr(elem, "authorities")
                    gu = cls._get_android_attr(elem, "grantUriPermissions")
                    if gu is not None:
                        grant_uri = gu.lower() == "true"
                    read_p = cls._get_android_attr(elem, "readPermission")
                    write_p = cls._get_android_attr(elem, "writePermission")

                comp = AndroidComponent(
                    name=c_name,
                    component_type=c_type,
                    is_exported=is_exported,
                    permission_required=perm_req,
                    intent_filters=filter_data_list,
                    has_deep_link=any(d.target_component == c_name for d in result["deep_links"]),
                    source_layer="MANIFEST",
                    authorities=authorities,
                    grant_uri_permissions=grant_uri,
                    read_permission=read_p,
                    write_permission=write_p,
                )
                result["components"].append(comp)

                # Security Indicators for Exported Components
                if is_exported and not perm_req:
                    result["indicators"].append({
                        "type": "STATIC_INDICATOR",
                        "subtype": "EXPORTED_COMPONENT_WITHOUT_PERMISSION",
                        "component": c_name,
                        "component_type": c_type.value,
                        "description": f"Exported {c_type.value} '{c_name}' does not require any permission.",
                        "severity": "MEDIUM" if c_type != ComponentType.PROVIDER else "HIGH",
                    })
                    result["hypotheses"].append({
                        "type": "MODEL_HYPOTHESIS",
                        "hypothesis": f"Third-party apps may interact with {c_name} via IPC/Intents without authorization.",
                        "component": c_name,
                        "verification_needed": f"Verify whether internal validation or caller authentication exists in {c_name} bytecode.",
                    })
                    result["evidence_gaps"].append({
                        "type": "EVIDENCE_GAP",
                        "gap": f"Static manifest analysis cannot determine if {c_name} enforces runtime UID/signature checks in code.",
                        "component": c_name,
                    })

                if c_type == ComponentType.PROVIDER and is_exported and (grant_uri or not (read_p and write_p)):
                    result["indicators"].append({
                        "type": "STATIC_INDICATOR",
                        "subtype": "POTENTIALLY_EXPOSED_CONTENT_PROVIDER",
                        "component": c_name,
                        "description": f"Content Provider '{c_name}' is exported with grantUriPermissions={grant_uri} and authorities='{authorities}'.",
                        "severity": "HIGH",
                    })

        return result
