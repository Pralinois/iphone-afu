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
