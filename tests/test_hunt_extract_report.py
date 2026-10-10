"""Tests strings_hunter, plist_extractor, network_recon, report_builder, objection, proxy."""

import io
import json
import math
import sqlite3
import struct
import sys
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import macho_fixtures  # noqa: F401  (rend les fixtures importables si besoin)

from modules import objection_wrapper, proxy_setup
from modules.network_recon import (geoip_lookup, generate_network_report,
                                   parse_syslog_connections, resolve_domains)
from modules.plist_extractor import (extract_all_storage, extract_binary_cookies,
                                     extract_preferences, extract_sqlite_tables)
from modules.report_builder import build_html_report
from modules.strings_hunter import (compute_obfuscation_score, export_findings,
                                    scan_directory, scan_file, shannon_entropy)

from macho_fixtures import make_cookies_binary, make_syslog_text


# ─── strings_hunter ─────────────────────────────────────────────────────────

def test_shannon_entropy():
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"aaaa") == 0.0
    assert abs(shannon_entropy(b"ab") - 1.0) < 1e-9
    assert shannon_entropy(bytes(range(256))) == 8.0


def test_scan_file_finds_secrets(tmp_path):
    f = tmp_path / "notes.txt"
    f.write_text(
        "api_key = sk_live_ABC123456789abcdef\n"
        "Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456\n"
        "-----BEGIN RSA PRIVATE KEY-----\n"
    )
    findings = scan_file(f)
    patterns = {x.pattern for x in findings}
    assert "api_key" in patterns
    assert "bearer" in patterns
    assert "private_key" in patterns
    sev = {x.pattern: x.severity for x in findings}
    assert sev["private_key"] == "HIGH"


def test_scan_directory_extensions_and_skip(tmp_path):
    (tmp_path / "a.txt").write_text("password = 'hunter2secret'\n")
    (tmp_path / "b.bin").write_bytes(b"\x00\x01\x02")   # extension inconnue → ignoré
    (tmp_path / "c.db").write_bytes(b"aws = 'AKIAIOSFODNN7EXAMPLE'")
    findings = scan_directory(tmp_path)
    files = {Path(x.file).name for x in findings}
    assert "a.txt" in files
    assert "c.db" in files
    assert "b.bin" not in files


def test_scan_directory_missing_raises(tmp_path):
    with pytest.raises(RuntimeError):
        scan_directory(tmp_path / "absent")


def test_export_findings_formats(tmp_path):
    f = tmp_path / "x.txt"
    f.write_text("AKIAIOSFODNN7EXAMPLE\n")
    findings = scan_file(f)
    out = tmp_path / "exports"
    written = export_findings(findings, out)
    assert set(written) == {"json", "csv", "txt"}
    data = json.loads((out / "findings.json").read_text(encoding="utf-8"))
    assert data and {"file", "offset", "pattern", "severity", "entropy"} <= set(data[0])
    assert "aws_key" in (out / "findings.csv").read_text(encoding="utf-8")
    assert "=== " in (out / "findings.txt").read_text(encoding="utf-8")


def test_obfuscation_score_random_vs_text(tmp_path):
    text = tmp_path / "plain.txt"
    text.write_text("hello world this is a plain text file\n" * 50)
    rand = tmp_path / "packed.bin"
    rand.write_bytes(bytes((i * 197 + 13) % 256 for i in range(65536)))

    score_text = compute_obfuscation_score(text)
    score_rand = compute_obfuscation_score(rand)
    assert 0 <= score_text["score"] <= 100
    assert score_rand["score"] > score_text["score"]
    assert score_rand["verdict"]


# ─── plist_extractor ────────────────────────────────────────────────────────

def test_extract_binary_cookies(tmp_path):
    src = tmp_path / "Cookies.binarycookies"
    src.write_bytes(make_cookies_binary())
    cookies = extract_binary_cookies(src)
    assert len(cookies) == 2
    by_name = {c["name"]: c for c in cookies}
    assert by_name["session"]["value"] == "abc123"
    assert by_name["session"]["domain"] == ".test.com"
    assert by_name["token"]["path"] == "/api"
    assert by_name["session"]["expires"].startswith("2030-")


def test_extract_binary_cookies_invalid(tmp_path):
    bad = tmp_path / "bad.binarycookies"
    bad.write_bytes(b"nope")
    with pytest.raises(ValueError):
        extract_binary_cookies(bad)


def test_extract_preferences_xml_and_binary(tmp_path):
    import plistlib
    (tmp_path / "com.a.plist").write_bytes(plistlib.dumps({"k": "v"}))
    (tmp_path / "com.b.plist").write_bytes(
        plistlib.dumps({"token": "secret"}, fmt=plistlib.FMT_BINARY))
    prefs = extract_preferences(tmp_path)
    assert prefs["com.a"] == {"k": "v"}
    assert prefs["com.b"] == {"token": "secret"}


def test_extract_sqlite_tables(tmp_path):
    db = tmp_path / "model.sqlite"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE ZUSER (id INTEGER, name TEXT)")
    con.execute("INSERT INTO ZUSER VALUES (1, 'alice')")
    con.commit()
    con.close()
    tables = extract_sqlite_tables(db)
    assert tables["ZUSER"][0]["name"] == "alice"


def test_extract_all_storage(tmp_path):
    src = tmp_path / "backup"
    (src / "Library" / "Preferences").mkdir(parents=True)
    (src / "Library" / "Preferences" / "com.test.app.plist").write_bytes(
        __import__("plistlib").dumps({"flag": True}))
    (src / "Library" / "Cookies").mkdir(parents=True)
    (src / "Library" / "Cookies" / "Cookies.binarycookies").write_bytes(make_cookies_binary())
    (src / "Library" / "Caches" / "sub").mkdir(parents=True)
    (src / "Library" / "Caches" / "sub" / "blob.dat").write_bytes(b"x" * 10)

    out = tmp_path / "plist_out"
    summary = extract_all_storage(src, out)
    assert summary["NSUserDefaults"]["found"] is True
    assert summary["Cookies"]["found"] is True
    assert summary["Cookies"]["count"] == 2                     # 2 cookies parsés
    assert (out / "Cookies" / "cookies.json").exists()
    assert (out / "NSUserDefaults" / "preferences.json").exists()
    assert summary["Pasteboard"]["found"] is False              # runtime only
    assert (out / "storage_summary.json").exists()


def test_extract_all_storage_missing_source(tmp_path):
    with pytest.raises(RuntimeError):
        extract_all_storage(tmp_path / "absent", tmp_path / "out")


# ─── network_recon ──────────────────────────────────────────────────────────

def test_parse_syslog_connections(tmp_path):
    syslog = tmp_path / "syslog.txt"
    syslog.write_text(make_syslog_text())
    conn = parse_syslog_connections(syslog)
    assert "api.target.com" in conn["domains"]
    assert "telemetry.example.net" in conn["domains"]
    assert any(u.startswith("https://api.target.com/") for u in conn["urls"])
    assert conn["tcp_connections"] and conn["tcp_connections"][0]["dst_port"] == 443
    assert "api.target.com" in conn["dns_queries"]
    assert "10.0.0.7" in conn["ips"]
    assert "203.0.113.99" in conn["ips"]


def test_resolve_domains_with_mock():
    def fake(dom):
        if dom == "bad.test":
            raise __import__("socket").gaierror("nx")
        return "1.2.3.4"

    with patch("modules.network_recon.socket.gethostbyname", side_effect=fake):
        result = resolve_domains(["good.test", "bad.test"])
    assert result["good.test"] == "1.2.3.4"
    assert result["bad.test"] == "NXDOMAIN"


def test_geoip_lookup_mocked():
    payload = json.dumps([{"status": "success", "query": "93.184.216.34",
                           "country": "United States", "org": "Example",
                           "as": "AS15133"}]).encode()

    class FakeResp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    with patch("modules.network_recon.urllib.request.urlopen",
               return_value=FakeResp(payload)):
        geo = geoip_lookup(["93.184.216.34", "192.168.1.10"])
    assert geo["93.184.216.34"]["country"] == "United States"
    assert "192.168.1.10" not in geo      # privée → exclue


def test_generate_network_report(tmp_path):
    syslog = tmp_path / "syslog.txt"
    syslog.write_text(make_syslog_text())
    conn = parse_syslog_connections(syslog)
    out = tmp_path / "network"
    summary = generate_network_report(conn, {"api.target.com": "1.2.3.4"}, {}, out)
    assert summary["total_domains"] >= 3
    assert summary["top_5_domains"]
    assert (out / "network_report.json").exists()
    domains_txt = (out / "network_domains.txt").read_text(encoding="utf-8")
    assert "api.target.com" in domains_txt


# ─── report_builder ─────────────────────────────────────────────────────────

def test_build_html_report(tmp_path):
    auto = tmp_path / "auto_out"
    auto.mkdir()
    (auto / "device.json").write_text(json.dumps({"DeviceName": "iPhone 16 Pro",
                                                  "ProductVersion": "18.4"}))
    (auto / "findings.json").write_text(json.dumps(
        [{"severity": "HIGH", "pattern": "jwt", "file": "a.txt", "string": "ey..."}]))
    (auto / "auto_report.json").write_text(json.dumps({"ok": True, "stages": []}))
    (auto / "apps.json").write_text(json.dumps([{"bundle_id": "com.a", "name": "A"}]))

    out = build_html_report(auto, tmp_path / "report.html")
    html = out.read_text(encoding="utf-8")
    assert "iPhone 16 Pro" in html
    assert "sev-high" in html
    assert 'id="findings"' in html or 'id="strings_hunt"' in html
    assert "<style>" in html
    assert "http://" not in html and "https://" not in html   # standalone, zéro ressource externe


def test_build_html_report_empty_and_missing(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    out = build_html_report(empty, tmp_path / "r.html")
    assert "Aucune donnée" in out.read_text(encoding="utf-8")
    with pytest.raises(RuntimeError):
        build_html_report(tmp_path / "absent", tmp_path / "r2.html")


# ─── objection_wrapper ──────────────────────────────────────────────────────

def test_check_objection():
    with patch("modules.objection_wrapper.shutil.which", return_value="/usr/bin/objection"):
        assert objection_wrapper.check_objection() is True
    with patch("modules.objection_wrapper.shutil.which", return_value=None):
        assert objection_wrapper.check_objection() is False


def test_run_objection_preset_builds_command(tmp_path):
    proc = MagicMock(returncode=0, stdout="cookies output", stderr="")
    with patch("modules.objection_wrapper.check_objection", return_value=True), \
         patch("modules.objection_wrapper.subprocess.run", return_value=proc) as run_mock:
        out_file = tmp_path / "cookies.txt"
        result = objection_wrapper.run_objection_preset("com.test.app", "cookies",
                                                        output_path=out_file)
    argv = run_mock.call_args[0][0]
    assert argv[:3] == ["objection", "-g", "com.test.app"]
    assert "explore" in argv and "ios cookies get" in argv
    assert result["status"] == "success"
    assert out_file.read_text(encoding="utf-8").startswith("cookies output")


def test_run_objection_preset_errors(tmp_path):
    with patch("modules.objection_wrapper.check_objection", return_value=False):
        r = objection_wrapper.run_objection_preset("com.x", "cookies")
    assert r["status"] == "error" and "pip install objection" in r["error"]

    with patch("modules.objection_wrapper.check_objection", return_value=True), \
         patch("modules.objection_wrapper.subprocess.run",
               side_effect=FileNotFoundError("objection")):
        r = objection_wrapper.run_objection_preset("com.x", "cookies")
    assert r["status"] == "error"

    r = objection_wrapper.run_objection_preset("com.x", "unknown-preset")
    assert r["status"] == "error" and "inconnu" in r["error"]


def test_batch_recon(tmp_path):
    def fake_preset(bundle_id, preset, extra_arg=None, output_path=None, timeout=0):
        Path(output_path).write_text(f"{preset} data", encoding="utf-8")
        return {"status": "success", "output": f"{preset} data", "error": None}

    with patch("modules.objection_wrapper.run_objection_preset", side_effect=fake_preset):
        stats = objection_wrapper.batch_recon("com.test.app", tmp_path)
    assert stats["run"] == len(objection_wrapper.BATCH_PRESETS)
    assert stats["success"] == stats["run"]
    assert (tmp_path / "objection_report.json").exists()


# ─── proxy_setup ────────────────────────────────────────────────────────────

def test_get_host_ip():
    ip = proxy_setup.get_host_ip()
    assert isinstance(ip, str) and ip.count(".") == 3


def test_generate_mitmproxy_cert_existing(tmp_path):
    pem = tmp_path / "mitmproxy-ca-cert.pem"
    pem.write_bytes(b"-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----\n")
    assert proxy_setup.generate_mitmproxy_cert(tmp_path) == pem


def test_generate_mitmproxy_cert_no_mitmproxy(tmp_path):
    mitmproxy_installed = True
    try:
        import mitmproxy  # noqa: F401
    except ImportError:
        mitmproxy_installed = False
    if mitmproxy_installed:
        pytest.skip("mitmproxy installé — chemin d'erreur non testable")
    with pytest.raises(RuntimeError):
        proxy_setup.generate_mitmproxy_cert(tmp_path)


def test_build_mobileconfig(tmp_path):
    import plistlib
    pem = tmp_path / "ca.pem"
    pem.write_bytes(b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
    profile = proxy_setup.build_mobileconfig(pem)
    parsed = plistlib.loads(profile)
    assert parsed["PayloadType"] == "com.apple.security.root"
    assert parsed["PayloadContent"] == pem.read_bytes()
    assert parsed["PayloadIdentifier"].startswith("com.afu.mitm.")


def test_generate_and_inject_frida_bypass(tmp_path):
    script = proxy_setup.generate_frida_pinning_bypass(tmp_path / "bypass.js")
    content = script.read_text(encoding="utf-8")
    assert "SecTrustEvaluateWithError" in content
    assert "TSKPinningValidator" in content
    assert "Alamofire" in content

    with patch("modules.proxy_setup.subprocess.run",
               side_effect=FileNotFoundError("frida")):
        result = proxy_setup.inject_frida_script("com.test.app", script)
    assert result["status"] == "error"
    assert "frida" in result["error"]

    proc = MagicMock(returncode=0, stdout="", stderr="")
    with patch("modules.proxy_setup.subprocess.run", return_value=proc) as run_mock:
        result = proxy_setup.inject_frida_script("com.test.app", script)
    assert result["status"] == "success"
    argv = run_mock.call_args[0][0]
    assert argv[:4] == ["frida", "-U", "--no-pause", "-f"]


def test_start_mitmproxy_missing(tmp_path):
    with patch("modules.proxy_setup.shutil.which", return_value=None), \
         patch.dict(sys.modules, {"mitmproxy": None}):
        with pytest.raises(RuntimeError):
            proxy_setup.start_mitmproxy(8080)


def test_print_proxy_instructions(capsys):
    text = proxy_setup.print_proxy_instructions("192.168.1.10", 8080, False)
    assert "192.168.1.10" in text and "8080" in text
    assert "Configurer le proxy" in text
    captured = capsys.readouterr()
    assert "192.168.1.10" in captured.out
