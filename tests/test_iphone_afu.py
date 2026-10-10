"""Tests unitaires iphone_afu — aucun device requis (pymobiledevice3 mocké)."""

import json
from unittest.mock import MagicMock, patch

import pytest

import iphone_afu
from iphone_afu import (
    CRYPTO,
    _afc_retry,
    build_dcim_manifest,
    check_deps,
    decrypt_pairing_record,
    encrypt_pairing_record,
    extract_dcim,
    get_connected_devices,
    load_pairing_record,
    save_pairing_record,
)

EXPECTED_DEP_KEYS = {"usbmuxd", "idevice_id", "frida", "pymobiledevice3", "rich", "textual"}


# 1. check_deps retourne un dict avec les bonnes clés
def test_check_deps_keys():
    deps = check_deps()
    assert EXPECTED_DEP_KEYS <= set(deps)
    assert all(isinstance(v, bool) for v in deps.values())


# 2. get_connected_devices retourne [] si pymobiledevice3 lève une exception
def test_get_connected_devices_empty_on_error():
    with patch.object(iphone_afu, "PMD3", True), \
         patch.object(iphone_afu, "list_devices", side_effect=RuntimeError("usbmuxd absent"), create=True):
        assert get_connected_devices() == []


# 3. save_pairing_record écrit un JSON valide
def test_save_pairing_record_writes_json(mock_lockdown, tmp_path):
    out = tmp_path / "iphone_pair.json"
    assert save_pairing_record(mock_lockdown, out) is True
    assert json.loads(out.read_text()) == mock_lockdown.pair_record


# 4. load_pairing_record retourne None si fichier absent
def test_load_pairing_record_missing_file(tmp_path):
    assert load_pairing_record(tmp_path / "absent.json") is None


# 5. extract_dcim stats["files"] == 0 si AFC liste vide
def test_extract_dcim_empty_afc(mock_afc_factory, tmp_path):
    factory, _ = mock_afc_factory(listdir_result=[])
    with patch.object(iphone_afu, "AfcService", factory, create=True):
        stats = extract_dcim(MagicMock(), tmp_path / "out")
    assert stats["files"] == 0
    assert stats["bytes"] == 0
    assert stats["errors"] == []
    assert stats["retries"] == 0


# 6. extract_dcim stats["errors"] contient l'erreur si AFC plante
def test_extract_dcim_afc_error(mock_afc_factory, tmp_path):
    factory, _ = mock_afc_factory(listdir_error=RuntimeError("AFC dropped"))
    with patch.object(iphone_afu, "AfcService", factory, create=True), \
         patch.object(iphone_afu.time, "sleep", return_value=None):
        stats = extract_dcim(MagicMock(), tmp_path / "out")
    assert stats["files"] == 0
    assert any("AFC dropped" in e for e in stats["errors"])
    assert stats["retries"] == 2  # 3 tentatives → 2 retries


# 7. build_dcim_manifest retourne [] sur répertoire vide
def test_build_dcim_manifest_empty_dir(tmp_path):
    assert build_dcim_manifest(tmp_path) == []


# 8. encrypt/decrypt round-trip (si CRYPTO disponible)
@pytest.mark.skipif(not CRYPTO, reason="cryptography non installé")
def test_encrypt_decrypt_roundtrip():
    data = {"UDID": "00008030-000A1B2C3D4E5F6G", "HostID": "deadbeef"}
    blob = encrypt_pairing_record(data, "s3cret")
    assert isinstance(blob, bytes)
    assert blob != json.dumps(data).encode()
    assert decrypt_pairing_record(blob, "s3cret") == data


# 9. decrypt lève ValueError avec mauvais password
@pytest.mark.skipif(not CRYPTO, reason="cryptography non installé")
def test_decrypt_wrong_password():
    blob = encrypt_pairing_record({"UDID": "abc"}, "bon-mot-de-passe")
    with pytest.raises(ValueError):
        decrypt_pairing_record(blob, "mauvais-mot-de-passe")


# 10. _afc_retry retente 3 fois puis lève
def test_afc_retry_exhausted():
    fn = MagicMock(side_effect=RuntimeError("nope"))
    with patch.object(iphone_afu.time, "sleep", return_value=None):
        with pytest.raises(RuntimeError):
            _afc_retry(fn, retries=3, delay=1.5)
    assert fn.call_count == 3
