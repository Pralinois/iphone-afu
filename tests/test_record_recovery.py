"""Tests record_finder : recherche, validation, test, installation (aucun device requis)."""

import plistlib
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from modules import record_finder
from modules.record_finder import (export_record, find_pairing_records,
                                   install_pairing_record, install_paths,
                                   validate_record)

_test_pairing_record = record_finder.test_pairing_record


# 1. find_pairing_records retourne [] si tous les chemins sont vides
def test_find_records_empty(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    assert find_pairing_records(roots=[empty, tmp_path / "absent"]) == []


# 2. find_pairing_records trouve un .plist valide dans un tmpdir
def test_find_records_valid_plist(valid_plist_record, tmp_path):
    plist_path, udid, _ = valid_plist_record
    records = find_pairing_records(roots=[tmp_path])
    assert len(records) == 1
    assert records[0].udid == udid
    assert records[0].valid is True
    assert records[0].path == plist_path


# 3. validate_record retourne valid=False si HostPrivateKey absent
def test_validate_record_missing_key(incomplete_plist_record):
    rec = validate_record(incomplete_plist_record)
    assert rec.valid is False
    assert rec.device_cert is True
    assert rec.host_private is False
    assert "HostPrivateKey" in (rec.error or "")


# 4. validate_record retourne valid=True si les 4 champs sont prÃ©sents
def test_validate_record_complete(valid_plist_record):
    plist_path, udid, _ = valid_plist_record
    rec = validate_record(plist_path)
    assert rec.valid is True
    assert rec.udid == udid
    assert rec.wifi_mac == "aa:bb:cc:dd:ee:ff"
    assert rec.host_id.startswith("AABBCCDD")


# 5. export_record copie le fichier et retourne le bon chemin
def test_export_record(valid_plist_record, tmp_path):
    plist_path, udid, _ = valid_plist_record
    rec = validate_record(plist_path)
    out_dir = tmp_path / "exports"
    dest = export_record(rec, out_dir)
    assert dest == out_dir / f"{udid}.plist"
    assert dest.exists()
    assert plistlib.loads(dest.read_bytes())["HostPrivateKey"] == b"FAKE_PRIVATE_KEY"

    explicit = export_record(rec, tmp_path / "copie.plist")
    assert explicit == tmp_path / "copie.plist"
    assert explicit.exists()


# 6. test_pairing_record step_1=False si plist corrompu
def test_test_record_corrupt_plist(tmp_path):
    bad = tmp_path / "bad.plist"
    bad.write_bytes(b"not a plist at all")
    result = _test_pairing_record(bad)
    assert result["step_1_parse"] is False
    assert result["step_2_load"] is False
    assert "parse" in (result["error"] or "")


def test_test_record_incomplete_fields(tmp_path, incomplete_plist_record):
    result = _test_pairing_record(incomplete_plist_record)
    assert result["step_1_parse"] is False
    assert "incomplet" in (result["error"] or "")


# 7. test_pairing_record step_2=False si pymobiledevice3 lÃ¨ve une exception
def test_test_record_lockdown_fail(valid_plist_record):
    plist_path, _, _ = valid_plist_record
    with patch.object(record_finder, "PMD3", True), \
         patch.object(record_finder, "create_using_usbmux",
                      side_effect=RuntimeError("usbmuxd down"), create=True):
        result = _test_pairing_record(plist_path)
    assert result["step_1_parse"] is True
    assert result["step_2_load"] is False
    assert "lockdown" in (result["error"] or "")


# 8. test_pairing_record step_4=True si AfcService.listdir("/") retourne []
def test_test_record_afc_ok(valid_plist_record):
    plist_path, _, _ = valid_plist_record
    ld = MagicMock()
    ld.get_value.return_value = "18.4"
    ld.display_name = "iPhone 16 Pro"
    ld.product_type = "iPhone17,1"
    ld.all_values = {"ServiceDiscovery": {"com.apple.afc": 1, "com.apple.mobilebackup2": 1}}
    afc_factory = MagicMock()
    with patch.object(record_finder, "PMD3", True), \
         patch.object(record_finder, "create_using_usbmux", return_value=ld, create=True), \
         patch.object(record_finder, "AfcService", afc_factory, create=True):
        result = _test_pairing_record(plist_path)
    assert result["step_1_parse"] and result["step_2_load"]
    assert result["step_3_afu"] is True
    assert result["step_4_afc"] is True
    assert result["device_info"]["ios"] == "18.4"
    assert "com.apple.afc" in result["step_5_services"]
    assert result["error"] is None


def test_test_record_afc_blocked(valid_plist_record):
    plist_path, _, _ = valid_plist_record
    ld = MagicMock()
    ld.get_value.return_value = "18.4"
    afc_factory = MagicMock(side_effect=RuntimeError("escrow bag missing"))
    with patch.object(record_finder, "PMD3", True), \
         patch.object(record_finder, "create_using_usbmux", return_value=ld, create=True), \
         patch.object(record_finder, "AfcService", afc_factory, create=True):
        result = _test_pairing_record(plist_path)
    assert result["step_3_afu"] is True
    assert result["step_4_afc"] is False
    assert "AFC" in (result["error"] or "")


def test_test_record_bfu(valid_plist_record):
    plist_path, _, _ = valid_plist_record
    ld = MagicMock()
    ld.get_value.side_effect = RuntimeError("UserDeniedPairing")
    with patch.object(record_finder, "PMD3", True), \
         patch.object(record_finder, "create_using_usbmux", return_value=ld, create=True):
        result = _test_pairing_record(plist_path)
    assert result["step_2_load"] is True
    assert result["step_3_afu"] is False
    assert "BFU" in (result["error"] or "")


# 9. install_pairing_record copie vers le bon chemin (Linux simulÃ©)
def test_install_record_linux(valid_plist_record, tmp_path):
    plist_path, udid, _ = valid_plist_record
    roots = [tmp_path / "var_lib_lockdown", tmp_path / "config_lockdown"]
    result = install_pairing_record(plist_path, roots=roots)
    assert result["error"] is None
    assert result["udid"] == udid
    assert len(result["installed_paths"]) == 2
    for installed in result["installed_paths"]:
        p = Path(installed)
        assert p.exists() and p.name == f"{udid}.plist"

    # chemins par dÃ©faut Linux (non utilisÃ©s pour l'Ã©criture ici)
    linux_defaults = install_paths("linux")
    assert linux_defaults[0] == Path("/var/lib/lockdown")
    assert linux_defaults[1].name == "lockdown"
    assert install_paths("mac")[0] == Path("/var/db/lockdown")
    assert "Apple" in str(install_paths("windows")[0])

    # record JSON â†’ resÃ©rialisÃ© en plist
    json_rec = tmp_path / "record.json"
    json_rec.write_text('{"DeviceCertificate": "A", "HostCertificate": "B", '
                        '"RootCertificate": "C", "HostPrivateKey": "D", "UDID": "UDID-JSON"}')
    res2 = install_pairing_record(json_rec, roots=[tmp_path / "json_root"])
    assert res2["installed_paths"], res2["error"]
    installed = plistlib.loads(Path(res2["installed_paths"][0]).read_bytes())
    assert installed["HostPrivateKey"] == "D"
    assert Path(res2["installed_paths"][0]).name == "UDID-JSON.plist"


# 10. install_pairing_record retourne error si permission denied (non-root)
def test_install_record_permission_denied(valid_plist_record, tmp_path):
    plist_path, _, _ = valid_plist_record
    blocked = tmp_path / "blocked"
    blocked.write_text("je suis un fichier, pas un rÃ©pertoire")
    result = install_pairing_record(plist_path, roots=[blocked / "lockdown"])
    assert result["installed_paths"] == []
    assert result["error"]

    # erreur de permission purement simulÃ©e
    with patch.object(record_finder.shutil, "copy2",
                      side_effect=PermissionError("[Errno 13] Permission denied")):
        res = install_pairing_record(plist_path, roots=[tmp_path / "perm"])
    assert res["installed_paths"] == []
    assert "Permission denied" in res["error"]


# â”€â”€â”€ complÃ©ments â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def test_search_paths_multi_os():
    assert any("lockdown" in str(p) for p in record_finder.search_paths("linux"))
    assert any("Library" in str(p) or "lockdown" in str(p)
               for p in record_finder.search_paths("mac"))
    win_paths = record_finder.search_paths("windows")
    assert any("Apple" in str(p) for p in win_paths)
    assert any("iMazing" in str(p) or "3uTools" in str(p) for p in win_paths)


def test_find_records_filters_udid(valid_plist_record, tmp_path):
    find_pairing_records(roots=[tmp_path])          # sanity
    assert find_pairing_records(target_udid="AUTRE-UDID", roots=[tmp_path]) == []
    assert find_pairing_records(target_udid="00008130-001234567890ABCD",
                                roots=[tmp_path])[0].valid is True


def test_find_records_sorts_valid_first(valid_plist_record, incomplete_plist_record, tmp_path):
    records = find_pairing_records(roots=[tmp_path])
    assert len(records) == 2
    assert records[0].valid is True
    assert records[1].valid is False
