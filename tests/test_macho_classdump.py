"""Tests macho_analyzer + class_dumper (fixtures Mach-O synthétiques, sans device)."""

import json
import shutil

import pytest

from macho_fixtures import make_ipa, make_macho, make_objc_macho, default_info
from modules.class_dumper import (dump_objc_classes, extract_swift_symbols,
                                  materialize_binary, render_class_dump)
from modules.macho_analyzer import analyze_macho, render_macho_report


# ─── macho_analyzer ─────────────────────────────────────────────────────────

def test_analyze_macho_full_protections(tmp_path):
    path = tmp_path / "binary"
    path.write_bytes(make_macho(cryptid=1, entitlements={"get-task-allow": True}))
    r = analyze_macho(path)
    assert r.arch == ["arm64"]
    assert r.pie is True
    assert r.stack_canary is True
    assert r.arc is True
    assert r.encrypted is True
    assert r.cryptid == 1
    assert r.restrict is True
    assert r.rpath_count == 1
    assert r.get_task_allow is True
    assert r.entitlements["get-task-allow"] is True
    assert "ptrace" in r.anti_debug_apis
    assert any("FairPlay" in v for v in r.bypass_vectors)
    assert any("get-task-allow" in v for v in r.bypass_vectors)
    assert any("Anti-debug" in v for v in r.bypass_vectors)


def test_analyze_macho_minimal_binary(tmp_path):
    path = tmp_path / "binary"
    path.write_bytes(make_macho(pie=False, rpath=False, restrict=False,
                                canary=False, arc=False, anti_debug=False))
    r = analyze_macho(path)
    assert r.pie is False
    assert r.stack_canary is False
    assert r.arc is False
    assert r.restrict is False
    assert r.rpath_count == 0
    assert any("PIE absent" in v for v in r.bypass_vectors)
    assert any("canary absent" in v for v in r.bypass_vectors)
    assert any("__RESTRICT" in v for v in r.bypass_vectors)


def test_analyze_macho_ipa_with_infoplist(tmp_path):
    info = default_info(
        CFBundleURLTypes=[{"CFBundleURLSchemes": ["testapp", "oauth-cb"]}],
        NSAppTransportSecurity={"NSAllowsArbitraryLoads": True,
                                "NSExceptionDomains": {"legacy.test.com": {}}},
    )
    ipa = make_ipa(tmp_path, make_macho(), info)
    r = analyze_macho(ipa)
    assert r.url_schemes == ["testapp", "oauth-cb"]
    assert r.ats_allows_http is True
    assert r.ats_exceptions == ["legacy.test.com"]
    assert any("ATS" in v for v in r.bypass_vectors)
    assert any("testapp" in v for v in r.bypass_vectors)


def test_render_macho_report_and_json(tmp_path):
    binary = tmp_path / "binary"
    binary.write_bytes(make_macho(cryptid=0))
    r = analyze_macho(binary)
    json_out = tmp_path / "macho_report.json"
    text = render_macho_report(r, json_out, plain=True)
    assert "Mach-O Analysis" in text
    assert "Bypass vectors" in text
    assert "PIE (ASLR)" in text
    payload = json.loads(json_out.read_text(encoding="utf-8"))
    assert payload["arch"] == ["arm64"]
    assert "bypass_vectors" in payload
    assert "generated" in payload


def test_analyze_macho_missing_path(tmp_path):
    with pytest.raises(RuntimeError):
        analyze_macho(tmp_path / "absent")


# ─── class_dumper ───────────────────────────────────────────────────────────

def test_dump_objc_classes_full(tmp_path):
    binary = tmp_path / "binary"
    binary.write_bytes(make_objc_macho())
    classes = {c.name: c for c in dump_objc_classes(binary)}
    assert set(classes) == {"MyBase", "MyChild"}

    base = classes["MyBase"]
    assert base.superclass is None
    assert base.methods == ["doThing:", "sharedInstance"]
    assert base.protocols == ["NSCopying"]
    assert base.ivars == ["instanceVar1"]

    child = classes["MyChild"]
    assert child.superclass == "MyBase"
    assert child.methods == ["childMethod"]     # méthode en offset relatif (négatif)
    assert child.protocols == []
    assert child.ivars == []


def test_dump_objc_classes_encrypted_returns_empty(tmp_path):
    binary = tmp_path / "binary"
    binary.write_bytes(make_objc_macho(cryptid=1))
    assert dump_objc_classes(binary) == []


def test_extract_swift_symbols(tmp_path):
    binary = tmp_path / "binary"
    binary.write_bytes(make_objc_macho(with_symtab=True))
    symbols = extract_swift_symbols(binary)
    assert symbols, "au moins un symbole Swift attendu"
    if shutil.which("swift-demangle") is None:
        assert any("$s4Test3fooyyF" in s for s in symbols)


def test_render_class_dump_outputs(tmp_path):
    binary = tmp_path / "binary"
    binary.write_bytes(make_objc_macho())
    classes = dump_objc_classes(binary)
    out_txt = tmp_path / "classes.txt"
    out_json = tmp_path / "classes.json"
    text = render_class_dump(classes, [], output_path=out_txt, json_out=out_json)
    assert "@interface MyBase <NSCopying>" in text
    assert "@interface MyChild : MyBase" in text
    assert out_txt.read_text(encoding="utf-8") == text
    payload = json.loads(out_json.read_text(encoding="utf-8"))
    assert payload["classes"][1]["name"] == "MyChild"


def test_materialize_binary_ipa(tmp_path):
    ipa = make_ipa(tmp_path, make_objc_macho(), default_info())
    binary, tmpdir = materialize_binary(ipa)
    try:
        assert binary.exists()
        assert binary.name == "Test"
        classes = dump_objc_classes(binary)
        assert {c.name for c in classes} == {"MyBase", "MyChild"}
    finally:
        if tmpdir is not None:
            shutil.rmtree(tmpdir, ignore_errors=True)


def test_dump_objc_classes_not_macho(tmp_path):
    bad = tmp_path / "not_macho"
    bad.write_bytes(b"definitely not a mach-o" * 10)
    with pytest.raises(RuntimeError):
        dump_objc_classes(bad)
