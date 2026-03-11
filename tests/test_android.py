"""
Revula Test Suite — Android RE module tests (pure Python logic).

Tests: APK parsing helpers, constants, tool registration, Shannon entropy.
"""

from __future__ import annotations

from typing import Any

from revula.server import _register_all_tools
from revula.tools import TOOL_REGISTRY

_register_all_tools()


# ---------------------------------------------------------------------------
# Android tool registration
# ---------------------------------------------------------------------------


class TestAndroidToolRegistration:
    """Verify Android-specific tools are registered."""

    def test_apk_parse_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_android_apk_parse") is not None

    def test_manifest_vulns_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_android_manifest_vulns") is not None

    def test_resources_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_android_resources") is not None

    def test_semgrep_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_android_semgrep") is not None

    def test_quark_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_android_quark") is not None

    def test_mobsf_registered(self) -> None:
        assert TOOL_REGISTRY.get("re_android_mobsf_scan") is not None

    def test_apk_parse_category(self) -> None:
        defn = TOOL_REGISTRY.get("re_android_apk_parse")
        assert defn is not None
        assert defn.category == "android"


# ---------------------------------------------------------------------------
# DANGEROUS_PERMISSIONS constant
# ---------------------------------------------------------------------------


class TestDangerousPermissions:
    """Verify DANGEROUS_PERMISSIONS set."""

    def test_non_empty(self) -> None:
        from revula.tools.android.apk_parse import DANGEROUS_PERMISSIONS

        assert isinstance(DANGEROUS_PERMISSIONS, set)
        assert len(DANGEROUS_PERMISSIONS) > 0

    def test_contains_camera(self) -> None:
        from revula.tools.android.apk_parse import DANGEROUS_PERMISSIONS

        assert "android.permission.CAMERA" in DANGEROUS_PERMISSIONS

    def test_contains_sms(self) -> None:
        from revula.tools.android.apk_parse import DANGEROUS_PERMISSIONS

        assert "android.permission.READ_SMS" in DANGEROUS_PERMISSIONS

    def test_contains_location(self) -> None:
        from revula.tools.android.apk_parse import DANGEROUS_PERMISSIONS

        assert "android.permission.ACCESS_FINE_LOCATION" in DANGEROUS_PERMISSIONS


# ---------------------------------------------------------------------------
# Shannon entropy helper
# ---------------------------------------------------------------------------


class TestShannonEntropy:
    """Test _shannon_entropy pure function."""

    def test_empty_data(self) -> None:
        from revula.tools.android.apk_parse import _shannon_entropy

        assert _shannon_entropy(b"") == 0.0

    def test_uniform_data(self) -> None:
        from revula.tools.android.apk_parse import _shannon_entropy

        data = bytes([0xAA] * 100)
        assert _shannon_entropy(data) == 0.0

    def test_two_byte_values(self) -> None:
        from revula.tools.android.apk_parse import _shannon_entropy

        data = bytes([0x00] * 50 + [0xFF] * 50)
        entropy = _shannon_entropy(data)
        assert abs(entropy - 1.0) < 0.01  # Should be exactly 1.0 bit

    def test_high_entropy(self) -> None:
        from revula.tools.android.apk_parse import _shannon_entropy

        data = bytes(range(256))
        entropy = _shannon_entropy(data)
        # 256 unique bytes → entropy = log2(256) = 8.0
        assert abs(entropy - 8.0) < 0.01

    def test_entropy_bounds(self) -> None:
        from revula.tools.android.apk_parse import _shannon_entropy

        data = bytes([0x41, 0x42, 0x43])
        entropy = _shannon_entropy(data)
        assert 0.0 <= entropy <= 8.0


# ---------------------------------------------------------------------------
# Security flags generator
# ---------------------------------------------------------------------------


class TestSecurityFlags:
    """Test _generate_security_flags pure function."""

    def test_debuggable_flag(self) -> None:
        from revula.tools.android.apk_parse import _generate_security_flags

        result: dict[str, Any] = {
            "manifest": {"debuggable": True, "allow_backup": False},
            "permissions": {"used": []},
            "components": {"activities": [], "services": [], "receivers": [], "providers": []},
        }
        flags = _generate_security_flags(result)
        assert any("debuggable" in f["finding"].lower() for f in flags)

    def test_allow_backup_flag(self) -> None:
        from revula.tools.android.apk_parse import _generate_security_flags

        result: dict[str, Any] = {
            "manifest": {"debuggable": False, "allow_backup": True},
            "permissions": {"used": []},
            "components": {"activities": [], "services": [], "receivers": [], "providers": []},
        }
        flags = _generate_security_flags(result)
        assert any("backup" in f["finding"].lower() for f in flags)

    def test_cleartext_traffic_flag(self) -> None:
        from revula.tools.android.apk_parse import _generate_security_flags

        result: dict[str, Any] = {
            "manifest": {
                "debuggable": False,
                "allow_backup": False,
                "uses_cleartext_traffic": True,
            },
            "permissions": {"used": []},
            "components": {"activities": [], "services": [], "receivers": [], "providers": []},
        }
        flags = _generate_security_flags(result)
        assert any("cleartext" in f["finding"].lower() for f in flags)

    def test_no_flags_for_clean_manifest(self) -> None:
        from revula.tools.android.apk_parse import _generate_security_flags

        result: dict[str, Any] = {
            "manifest": {
                "debuggable": False,
                "allow_backup": False,
                "uses_cleartext_traffic": False,
                "network_security_config": True,
            },
            "permissions": {"used": []},
            "components": {"activities": [], "services": [], "receivers": [], "providers": []},
        }
        flags = _generate_security_flags(result)
        assert len(flags) == 0

    def test_exported_component_flag(self) -> None:
        from revula.tools.android.apk_parse import _generate_security_flags

        result: dict[str, Any] = {
            "manifest": {"debuggable": False, "allow_backup": False},
            "permissions": {"used": []},
            "components": {
                "activities": [{"name": "com.test.Exported", "exported": True}],
                "services": [],
                "receivers": [],
                "providers": [],
            },
        }
        flags = _generate_security_flags(result)
        assert any("exported" in f["finding"].lower() for f in flags)

    def test_dangerous_permission_flag(self) -> None:
        from revula.tools.android.apk_parse import _generate_security_flags

        result: dict[str, Any] = {
            "manifest": {"debuggable": False, "allow_backup": False},
            "permissions": {
                "used": [{"name": "android.permission.CAMERA", "dangerous": True}],
            },
            "components": {"activities": [], "services": [], "receivers": [], "providers": []},
        }
        flags = _generate_security_flags(result)
        assert any("dangerous permission" in f["finding"].lower() for f in flags)
