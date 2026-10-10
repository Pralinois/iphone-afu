"""Tests du module security audit (IPA statique, AASA, scan, bypass) — sans device."""

import plistlib
import struct
import zipfile

import pytest

from iphone_afu import (
    _macho_slices,
    analyze_aasa,
    analyze_app_findings,
    analyze_binary_data,
    audit_app,
    build_bypass_script,
    extract_entitlements,
    load_app_bundle,
    scan_directory,
    summarize_keychain_items,
)

MH_FLAGS_PIE = 0x200000
LC_ENCRYPTION_INFO = 0x21
LC_CODE_SIGNATURE = 0x1D
ARM64 = 0x0100000C
ARM64E = 0x0100000C


def make_macho(*, pie=True, cryptid=None, cs_data=None,
               strings=b"__stack_chk_guard\x00objc_release\x00",
               cputype=ARM64, cpusubtype=0):
    """Fabrique un Mach-O 64-bit minimal avec load commands choisis."""
    cmds = b""
    ncmds = 0
    if cryptid is not None:
        cmds += struct.pack("<IIIII", LC_ENCRYPTION_INFO, 20, 0, 4096, cryptid)
        ncmds += 1
    if cs_data is not None:
        dataoff = 32 + 20 * (1 if cryptid is not None else 0) + 16 + len(strings)
        cmds += struct.pack("<IIII", LC_CODE_SIGNATURE, 16, dataoff, len(cs_data))
        ncmds += 1
    flags = MH_FLAGS_PIE if pie else 0
    hdr = struct.pack("<IIIIIIII", 0xFEEDFACF, cputype, cpusubtype, 2, ncmds, len(cmds), flags, 0)
    return hdr + cmds + strings + (cs_data or b"")


def make_fat(slices):
    """Fabrique un binaire FAT (big-endian) à partir de (cputype, cpusubtype, data)."""
    n = len(slices)
    entries = b""
    blobs = b""
    for cputype, cpusubtype, data in slices:
        entries += struct.pack(">IIIII", cputype, cpusubtype, 8 + 20 * n + len(blobs), len(data), 0)
        blobs += data
    return struct.pack(">II", 0xCAFEBABE, n) + entries + blobs


def make_cs_blob(ent_xml: bytes) -> bytes:
    """SuperBlob de signature contenant un blob entitlements XML (type 5)."""
    inner = struct.pack(">II", 0xFADE7171, 8 + len(ent_xml)) + ent_xml
    idx = struct.pack(">II", 5, 20)
    return struct.pack(">III", 0xFADE0CC0, 12 + 8 + len(inner), 1) + idx + inner


def make_ipa(tmp_path, info=None, bin_data=None, name="Test.ipa"):
    info = info or {
        "CFBundleExecutable": "Test",
        "CFBundleIdentifier": "com.test.app",
        "CFBundleName": "TestApp",
        "CFBundleShortVersionString": "1.0",
        "MinimumOSVersion": "17.0",
    }
    bin_data = bin_data if bin_data is not None else make_macho()
    ipa = tmp_path / name
    with zipfile.ZipFile(ipa, "w") as zf:
        zf.writestr("Payload/Test.app/Info.plist", plistlib.dumps(info))
        zf.writestr("Payload/Test.app/Test", bin_data)
    return ipa


# ─── Mach-O ──────────────────────────────────────────────────────────────────

def test_parse_thin_macho_protections():
    data = make_macho(pie=True, cryptid=1)
    r = analyze_binary_data(data)
    assert r["raw_ok"] is True
    assert r["archs"] == ["arm64"]
    assert r["pie"] is True
    assert r["cryptid"] == 1
    assert r["canary"] is True
    assert r["arc"] is True


def test_parse_macho_no_pie_no_canary():
    data = make_macho(pie=False, cryptid=None, strings=b"nothing-here\x00")
    r = analyze_binary_data(data)
    assert r["pie"] is False
    assert r["canary"] is False
    assert r["cryptid"] is None


def test_parse_fat_macho_arm64_and_arm64e():
    data = make_fat([
        (ARM64, 0, make_macho(cputype=ARM64, cpusubtype=0)),
        (ARM64E, 0x80000002, make_macho(cputype=ARM64E, cpusubtype=0x80000002)),
    ])
    chunks = _macho_slices(data)
    assert len(chunks) == 2
    r = analyze_binary_data(data)
    assert r["archs"] == ["arm64", "arm64e"]
    assert r["pie"] is True


def test_extract_entitlements_from_superblob():
    ent = plistlib.dumps({"get-task-allow": True, "application-identifier": "TEAM.com.test"})
    blob = make_cs_blob(ent)
    assert extract_entitlements(blob) == {
        "get-task-allow": True,
        "application-identifier": "TEAM.com.test",
    }
    assert extract_entitlements(b"not-a-blob") is None


def test_binary_with_embedded_entitlements():
    ent = plistlib.dumps({"get-task-allow": True})
    data = make_macho(cryptid=0, cs_data=make_cs_blob(ent))
    r = analyze_binary_data(data)
    assert r["entitlements"]["get-task-allow"] is True
    assert r["cryptid"] == 0


# ─── audit_app / findings ────────────────────────────────────────────────────

def test_audit_app_ipa_full_pipeline(tmp_path):
    info = {
        "CFBundleExecutable": "Test",
        "CFBundleIdentifier": "com.test.app",
        "CFBundleName": "TestApp",
        "CFBundleShortVersionString": "2.0",
        "MinimumOSVersion": "18.0",
        "CFBundleURLTypes": [{"CFBundleURLSchemes": ["testapp", "oauth-cb"]}],
        "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True},
    }
    ent = plistlib.dumps({"get-task-allow": True})
    ipa = make_ipa(tmp_path, info=info, bin_data=make_macho(cryptid=1, cs_data=make_cs_blob(ent)))
    report = audit_app(ipa)
    assert report["bundle"]["id"] == "com.test.app"
    assert report["bundle"]["schemes"] == ["testapp", "oauth-cb"]
    assert report["binary"]["archs"] == ["arm64"]
    ids = [f["id"] for f in report["findings"]]
    assert {"ats-arbitrary", "encrypted", "debuggable", "schemes-custom", "oauth-scheme"} <= set(ids)
    sev = {f["id"]: f["severity"] for f in report["findings"]}
    assert sev["ats-arbitrary"] == "HIGH"
    assert sev["debuggable"] == "HIGH"


def test_analyze_app_findings_missing_protections():
    findings = analyze_app_findings({}, {"raw_ok": True, "pie": False, "canary": False,
                                         "arc": True, "cryptid": 0, "entitlements": {}})
    ids = {f["id"]: f["severity"] for f in findings}
    assert ids.get("no-pie") == "HIGH"
    assert ids.get("no-canary") == "MEDIUM"
    assert "ats-arbitrary" not in ids


def test_load_app_bundle_from_app_dir(tmp_path):
    app = tmp_path / "Demo.app"
    app.mkdir()
    info = {"CFBundleExecutable": "Demo", "CFBundleIdentifier": "com.demo"}
    (app / "Info.plist").write_bytes(plistlib.dumps(info))
    (app / "Demo").write_bytes(make_macho())
    loaded_info, bin_data, exe = load_app_bundle(app)
    assert loaded_info["CFBundleIdentifier"] == "com.demo"
    assert exe == "Demo"
    assert bin_data[:4] == b"\xcf\xfa\xed\xfe"


def test_load_app_bundle_invalid_path(tmp_path):
    with pytest.raises(RuntimeError):
        load_app_bundle(tmp_path / "nothing.ipa")


# ─── AASA ────────────────────────────────────────────────────────────────────

def test_aasa_wildcard_paths_flagged():
    data = {"applinks": {"details": [{"appID": "TEAM.com.test", "components": [{"/": "/articles/*"}]}]}}
    findings = analyze_aasa(data, "application/json", 200)
    ids = {f["id"]: f["severity"] for f in findings}
    assert ids.get("aasa-wildcard") == "HIGH"


def test_aasa_missing_file():
    findings = analyze_aasa(None, "", 404)
    assert findings[0]["id"] == "aasa-missing"
    assert findings[0]["severity"] == "MEDIUM"


def test_aasa_content_type_and_legacy_paths():
    data = {"applinks": {"details": [{"appID": "TEAM.com.test", "paths": ["/products", "*"]}]}}
    findings = analyze_aasa(data, "text/plain", 200)
    ids = {f["id"]: f["severity"] for f in findings}
    assert ids.get("aasa-wildcard") == "HIGH"
    assert ids.get("aasa-content-type") == "MEDIUM"
    assert ids.get("aasa-appids") == "INFO"


# ─── scan ────────────────────────────────────────────────────────────────────

def test_scan_directory_finds_secrets(tmp_path):
    prefs = tmp_path / "Library" / "Preferences"
    prefs.mkdir(parents=True)
    (prefs / "com.x.plist").write_text(
        "<dict><key>password</key><string>hunter2secret</string>"
        "<key>t</key><string>eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U</string></dict>"
    )
    (tmp_path / "Notes.txt").write_text("api_key = sk_live_abc123456789")
    result = scan_directory(tmp_path)
    ids = {f["id"] for f in result["findings"]}
    assert "jwt" in ids
    assert "api-key" in ids
    assert "nsuserdefaults" in ids
    assert result["scanned_files"] >= 2
    assert all({"path", "severity", "title", "detail"} <= set(f) for f in result["findings"])


def test_scan_directory_empty(tmp_path):
    result = scan_directory(tmp_path)
    assert result["findings"] == []
    assert result["scanned_files"] == 0


def test_scan_directory_missing_raises(tmp_path):
    with pytest.raises(RuntimeError):
        scan_directory(tmp_path / "absent")


# ─── bypass Frida ────────────────────────────────────────────────────────────

def test_bypass_script_ssl_default():
    script = build_bypass_script()
    assert "SecTrustEvaluateWithError" in script
    assert "SecTrustEvaluate'" in script or "'SecTrustEvaluate'" in script
    assert "SSLHandshake" in script
    assert "fileExistsAtPath" not in script


def test_bypass_script_with_jailbreak():
    script = build_bypass_script(jailbreak=True)
    assert "fileExistsAtPath" in script
    assert "canOpenURL" in script
    assert "SSLHandshake" in script


def test_summarize_keychain_items():
    items = [
        {"class": "kSecClassGenericPassword", "data": "a"},
        {"class": "kSecClassGenericPassword", "data": "b"},
        {"class": "kSecClassInternetPassword", "data": "c"},
    ]
    summary = summarize_keychain_items(items)
    assert summary == {"kSecClassGenericPassword": 2, "kSecClassInternetPassword": 1}
