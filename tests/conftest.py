"""Fixtures partagées — aucun device connecté requis (pymobiledevice3 mocké)."""

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import iphone_afu  # noqa: E402


@pytest.fixture
def mock_lockdown():
    """LockdownClient factice avec un pairing record minimal."""
    ld = MagicMock()
    ld.pair_record = {
        "UDID": "00008030-000A1B2C3D4E5F6G",
        "HostID": "deadbeef",
        "SystemBUID": "cafebabe",
        "HostCertificate": "b64cert",
        "HostPrivateKey": "b64key",
    }
    ld.display_name = "iPhone 16 Pro"
    ld.product_version = "18.4"
    ld.product_type = "iPhone17,1"
    return ld


@pytest.fixture
def mock_afc_factory():
    """Fabrique un mock AfcService : listdir/get_file_contents/stat configurables."""
    def _make(listdir_result=None, listdir_error=None):
        afc = MagicMock()
        if listdir_error is not None:
            afc.listdir.side_effect = listdir_error
        else:
            afc.listdir.return_value = listdir_result if listdir_result is not None else []
        afc.stat.return_value = {"st_ifmt": "S_IFREG"}
        afc.get_file_contents.return_value = b"data"
        factory = MagicMock(return_value=afc)
        return factory, afc

    return _make


@pytest.fixture
def valid_plist_record(tmp_path):
    """Faux pairing record .plist avec les 4 champs requis (structure correcte)."""
    import plistlib

    record = {
        "DeviceCertificate": b"FAKE_DEVICE_CERT",
        "HostCertificate":   b"FAKE_HOST_CERT",
        "RootCertificate":   b"FAKE_ROOT_CERT",
        "HostPrivateKey":    b"FAKE_PRIVATE_KEY",
        "HostID":            "AABBCCDD-1122-3344-5566-778899AABBCC",
        "SystemBUID":        "DEADBEEF-DEAD-BEEF-DEAD-BEEFDEADBEEF",
        "WiFiMACAddress":    "aa:bb:cc:dd:ee:ff",
    }
    udid = "00008130-001234567890ABCD"
    plist_path = tmp_path / f"{udid}.plist"
    plistlib.dump(record, plist_path.open("wb"))
    return plist_path, udid, record


@pytest.fixture
def incomplete_plist_record(tmp_path):
    """Pairing record sans HostPrivateKey — invalid."""
    import plistlib

    record = {
        "DeviceCertificate": b"FAKE_DEVICE_CERT",
        "HostCertificate":   b"FAKE_HOST_CERT",
        "RootCertificate":   b"FAKE_ROOT_CERT",
        # HostPrivateKey manquant
        "HostID":            "AABBCCDD-1122-3344-5566-778899AABBCC",
    }
    plist_path = tmp_path / "incomplete.plist"
    plistlib.dump(record, plist_path.open("wb"))
    return plist_path
